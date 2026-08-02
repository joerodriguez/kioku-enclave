//! Evidence-derived ADR-0016 release cases.
//!
//! Real release metrics must not be hand-authored counters. The private run
//! schema-v3 input contains opaque speaker/person/record identifiers, exact
//! reviewed source-artifact hashes, and
//! timing and per-hypothesis identity decisions exported by the production
//! pipeline. This module binds each identity case to the deterministic speaker
//! mapping used for diarization error, binds that input to the reviewed source
//! manifest, and emits a content-free corpus
//! whose derived fields can be recomputed by CI without access to media,
//! transcripts, names, embeddings, or raw similarity scores.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error::{EnclaveError, Result};

use super::voice_eval::{EvaluationCase, EvaluationCorpus, EvaluationManifest};

const MAX_RECORDINGS: usize = 10_000;
const MAX_CASES: usize = 100_000;
const MAX_TURNS_PER_RECORDING: usize = 10_000;
const MAX_SPEAKERS_PER_RECORDING: usize = 16;
const MAX_RECORDS_PER_CASE: usize = 10_000;
const MAX_RECORDING_MS: u64 = 86_400_000;

#[derive(Debug, Clone, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EvaluationRunMetadata {
    pub enclave_image_digest: String,
    pub evaluated_source_commit: String,
    pub vertex_model: String,
    pub voice_model_sha256: String,
    pub export_artifact_sha256: String,
    pub post_delete_scan_sha256: String,
    pub embedding_space: String,
    pub scorer_version: i64,
    pub quality_version: i64,
    pub match_threshold: f32,
    pub new_profile_threshold: f32,
    pub minimum_decision_margin: f32,
    pub outlier_similarity: f32,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DiarizationTurnEvidence {
    pub start_ms: u64,
    pub end_ms: u64,
    pub speaker_id: String,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DiarizationRecordingEvidence {
    pub id: String,
    pub source_id: String,
    pub media_artifact_id: Option<String>,
    pub labels_artifact_id: Option<String>,
    pub selected_item_id: Option<String>,
    pub slice: String,
    pub media_sha256: String,
    pub labels_sha256: String,
    pub reference_turns: Vec<DiarizationTurnEvidence>,
    pub predicted_turns: Vec<DiarizationTurnEvidence>,
    pub predicted_speaker_identities: Vec<PredictedSpeakerIdentityEvidence>,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PredictedSpeakerIdentityEvidence {
    pub speaker_id: String,
    pub predicted_person: Option<String>,
    pub name_binding_state: String,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FactRunEvidence {
    pub id: String,
    pub status: String,
    pub evidence_id: Option<String>,
    pub source_record_id: Option<String>,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CaseRunEvidence {
    pub id: String,
    pub corpus_kind: String,
    pub slice: String,
    pub recording_id: String,
    pub reference_speaker_id: String,
    pub expected_person: String,
    pub predicted_person: Option<String>,
    pub name_binding_state: String,
    pub meeting_id: String,
    pub first_seen_meeting_id: Option<String>,
    pub prior_high_quality_sample_count: u32,
    pub display_name_collision_group: Option<String>,
    #[serde(default)]
    pub facts: Vec<FactRunEvidence>,
    #[serde(default)]
    pub created_record_ids: Vec<String>,
    #[serde(default)]
    pub exported_record_ids: Vec<String>,
    #[serde(default)]
    pub deleted_record_ids: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct EvaluationRunEvidence {
    schema_version: u32,
    corpus_id: String,
    run: EvaluationRunMetadata,
    diarization_error_baselines: BTreeMap<String, f64>,
    recordings: Vec<DiarizationRecordingEvidence>,
    cases: Vec<CaseRunEvidence>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct DiarizationMetrics {
    pub speech_ms: u64,
    pub error_ms: u64,
}

fn sha256_hex(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn valid_hash_prefixed_id(value: &str, prefix: &str) -> bool {
    let Some(digest) = value.strip_prefix(prefix) else {
        return false;
    };
    (16..=64).contains(&digest.len())
        && digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn valid_opaque_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

fn validate_run(run: &EvaluationRunMetadata) -> Result<()> {
    let image_hash = run
        .enclave_image_digest
        .strip_prefix("sha256:")
        .unwrap_or_default();
    let valid_commit = matches!(run.evaluated_source_commit.len(), 40 | 64)
        && run
            .evaluated_source_commit
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte));
    if !valid_sha256(image_hash)
        || !valid_commit
        || run.vertex_model.is_empty()
        || run.vertex_model.len() > 128
        || !valid_sha256(&run.voice_model_sha256)
        || !valid_sha256(&run.export_artifact_sha256)
        || !valid_sha256(&run.post_delete_scan_sha256)
        || run.embedding_space != super::voice_memory::EMBEDDING_SPACE
        || run.scorer_version != super::voice_quality::SCORER_VERSION
        || run.quality_version != super::voice_quality::QUALITY_VERSION
        || run.match_threshold != super::voice_memory::MATCH_THRESHOLD
        || run.new_profile_threshold != super::voice_memory::NEW_PROFILE_THRESHOLD
        || run.minimum_decision_margin != super::voice_memory::MIN_DECISION_MARGIN
        || run.outlier_similarity != super::voice_quality::OUTLIER_SIMILARITY
    {
        return Err(EnclaveError::InvalidRequest(
            "voice evaluation run metadata does not match the pinned production pipeline".into(),
        ));
    }
    Ok(())
}

fn validate_turns(turns: &[DiarizationTurnEvidence], label: &str) -> Result<Vec<String>> {
    if turns.len() > MAX_TURNS_PER_RECORDING {
        return Err(EnclaveError::InvalidRequest(format!(
            "{label} diarization turn count exceeds the release bound"
        )));
    }
    let mut speakers = BTreeSet::new();
    let mut by_speaker: HashMap<&str, Vec<(u64, u64)>> = HashMap::new();
    for turn in turns {
        if turn.start_ms >= turn.end_ms
            || turn.end_ms > MAX_RECORDING_MS
            || !valid_hash_prefixed_id(&turn.speaker_id, "speaker-")
        {
            return Err(EnclaveError::InvalidRequest(format!(
                "invalid {label} diarization interval"
            )));
        }
        speakers.insert(turn.speaker_id.clone());
        by_speaker
            .entry(&turn.speaker_id)
            .or_default()
            .push((turn.start_ms, turn.end_ms));
    }
    if speakers.len() > MAX_SPEAKERS_PER_RECORDING {
        return Err(EnclaveError::InvalidRequest(format!(
            "{label} diarization speaker count exceeds the release bound"
        )));
    }
    for intervals in by_speaker.values_mut() {
        intervals.sort_unstable();
        if intervals.windows(2).any(|pair| pair[0].1 > pair[1].0) {
            return Err(EnclaveError::InvalidRequest(format!(
                "one {label} speaker has overlapping self-intervals"
            )));
        }
    }
    Ok(speakers.into_iter().collect())
}

fn maximum_mapping_overlap(
    weights: &[Vec<u64>],
    hypothesis_count: usize,
) -> (u64, Vec<Option<usize>>) {
    fn visit(
        row: usize,
        used: u32,
        weights: &[Vec<u64>],
        hypothesis_count: usize,
        memo: &mut HashMap<(usize, u32), u64>,
    ) -> u64 {
        if row == weights.len() {
            return 0;
        }
        if let Some(value) = memo.get(&(row, used)) {
            return *value;
        }
        let mut best = visit(row + 1, used, weights, hypothesis_count, memo);
        for column in 0..hypothesis_count {
            let bit = 1_u32 << column;
            if used & bit == 0 {
                best = best.max(
                    weights[row][column]
                        + visit(row + 1, used | bit, weights, hypothesis_count, memo),
                );
            }
        }
        memo.insert((row, used), best);
        best
    }

    let mut memo = HashMap::new();
    let correct_ms = visit(0, 0, weights, hypothesis_count, &mut memo);
    let mut mapping = Vec::with_capacity(weights.len());
    let mut used = 0_u32;
    for row in 0..weights.len() {
        let target = visit(row, used, weights, hypothesis_count, &mut memo);
        let mut selected = None;
        for column in 0..hypothesis_count {
            let bit = 1_u32 << column;
            if used & bit == 0
                && weights[row][column] > 0
                && weights[row][column]
                    + visit(row + 1, used | bit, weights, hypothesis_count, &mut memo)
                    == target
            {
                selected = Some(column);
                used |= bit;
                break;
            }
        }
        if selected.is_none() {
            debug_assert_eq!(
                visit(row + 1, used, weights, hypothesis_count, &mut memo),
                target
            );
        }
        mapping.push(selected);
    }
    (correct_ms, mapping)
}

#[derive(Debug)]
struct DiarizationAnalysis {
    metrics: DiarizationMetrics,
    predicted_speakers: BTreeMap<String, Option<String>>,
}

impl DiarizationAnalysis {
    fn predicted_speaker_for(&self, reference_speaker: &str) -> Option<&str> {
        self.predicted_speakers
            .get(reference_speaker)
            .and_then(Option::as_deref)
    }
}

fn derive_diarization_analysis(
    recording: &DiarizationRecordingEvidence,
) -> Result<DiarizationAnalysis> {
    let reference_speakers = validate_turns(&recording.reference_turns, "reference")?;
    let predicted_speakers = validate_turns(&recording.predicted_turns, "predicted")?;
    if reference_speakers.is_empty() {
        return Err(EnclaveError::InvalidRequest(
            "real diarization recording has no reference speech".into(),
        ));
    }
    let reference_index = reference_speakers
        .iter()
        .enumerate()
        .map(|(index, id)| (id.as_str(), index))
        .collect::<HashMap<_, _>>();
    let predicted_index = predicted_speakers
        .iter()
        .enumerate()
        .map(|(index, id)| (id.as_str(), index))
        .collect::<HashMap<_, _>>();
    let mut boundaries = BTreeSet::new();
    for turn in recording
        .reference_turns
        .iter()
        .chain(&recording.predicted_turns)
    {
        boundaries.insert(turn.start_ms);
        boundaries.insert(turn.end_ms);
    }
    let boundaries = boundaries.into_iter().collect::<Vec<_>>();
    let mut weights = vec![vec![0_u64; predicted_speakers.len()]; reference_speakers.len()];
    let mut speech_ms = 0_u64;
    let mut maximum_active_ms = 0_u64;
    for interval in boundaries.windows(2) {
        let start = interval[0];
        let end = interval[1];
        let duration = end - start;
        let references = recording
            .reference_turns
            .iter()
            .filter(|turn| turn.start_ms <= start && turn.end_ms >= end)
            .map(|turn| reference_index[turn.speaker_id.as_str()])
            .collect::<Vec<_>>();
        let predictions = recording
            .predicted_turns
            .iter()
            .filter(|turn| turn.start_ms <= start && turn.end_ms >= end)
            .map(|turn| predicted_index[turn.speaker_id.as_str()])
            .collect::<Vec<_>>();
        speech_ms = speech_ms.saturating_add(duration.saturating_mul(references.len() as u64));
        maximum_active_ms = maximum_active_ms.saturating_add(
            duration.saturating_mul(references.len().max(predictions.len()) as u64),
        );
        for reference in &references {
            for prediction in &predictions {
                weights[*reference][*prediction] =
                    weights[*reference][*prediction].saturating_add(duration);
            }
        }
    }
    let (correct_ms, mapping) = maximum_mapping_overlap(&weights, predicted_speakers.len());
    let predicted_speakers = reference_speakers
        .into_iter()
        .enumerate()
        .map(|(index, reference)| {
            let predicted = mapping[index].map(|column| predicted_speakers[column].clone());
            (reference, predicted)
        })
        .collect();
    Ok(DiarizationAnalysis {
        metrics: DiarizationMetrics {
            speech_ms,
            error_ms: maximum_active_ms.saturating_sub(correct_ms),
        },
        predicted_speakers,
    })
}

pub(crate) fn derive_diarization_metrics(
    recording: &DiarizationRecordingEvidence,
) -> Result<DiarizationMetrics> {
    Ok(derive_diarization_analysis(recording)?.metrics)
}

fn validate_recording_shape(recording: &DiarizationRecordingEvidence) -> Result<()> {
    if !valid_hash_prefixed_id(&recording.id, "recording-")
        || !valid_opaque_id(&recording.source_id)
        || recording
            .media_artifact_id
            .as_deref()
            .is_some_and(|id| !valid_opaque_id(id))
        || recording
            .labels_artifact_id
            .as_deref()
            .is_some_and(|id| !valid_opaque_id(id))
        || recording
            .selected_item_id
            .as_deref()
            .is_some_and(|id| !valid_opaque_id(id))
        || !valid_opaque_id(&recording.slice)
        || !valid_sha256(&recording.media_sha256)
        || !valid_sha256(&recording.labels_sha256)
    {
        return Err(EnclaveError::InvalidRequest(
            "invalid voice evaluation recording binding".into(),
        ));
    }
    derive_diarization_metrics(recording)?;
    validate_predicted_speaker_identities(recording)?;
    Ok(())
}

fn valid_binding_state(value: &str) -> bool {
    matches!(
        value,
        "none"
            | "proposed"
            | "probationary"
            | "accepted"
            | "conflicting"
            | "rejected"
            | "superseded"
    )
}

fn validate_predicted_speaker_identities(
    recording: &DiarizationRecordingEvidence,
) -> Result<HashMap<&str, &PredictedSpeakerIdentityEvidence>> {
    let predicted_speakers = recording
        .predicted_turns
        .iter()
        .map(|turn| turn.speaker_id.as_str())
        .collect::<HashSet<_>>();
    let mut identities = HashMap::new();
    for identity in &recording.predicted_speaker_identities {
        if !valid_hash_prefixed_id(&identity.speaker_id, "speaker-")
            || identity
                .predicted_person
                .as_deref()
                .is_some_and(|person| !valid_hash_prefixed_id(person, "person-"))
            || !valid_binding_state(&identity.name_binding_state)
            || (identity.name_binding_state == "accepted" && identity.predicted_person.is_none())
            || identities
                .insert(identity.speaker_id.as_str(), identity)
                .is_some()
        {
            return Err(EnclaveError::InvalidRequest(
                "invalid predicted-speaker identity evidence".into(),
            ));
        }
    }
    if identities.len() != predicted_speakers.len()
        || predicted_speakers
            .iter()
            .any(|speaker| !identities.contains_key(speaker))
    {
        return Err(EnclaveError::InvalidRequest(
            "predicted-speaker identity evidence must exactly cover diarization hypotheses".into(),
        ));
    }
    Ok(identities)
}

fn validate_case_speaker_binding(
    recording: &DiarizationRecordingEvidence,
    evidence: &CaseRunEvidence,
) -> Result<()> {
    let analysis = derive_diarization_analysis(recording)?;
    if !analysis
        .predicted_speakers
        .contains_key(&evidence.reference_speaker_id)
    {
        return Err(EnclaveError::InvalidRequest(
            "voice evaluation case references an unknown reference speaker".into(),
        ));
    }
    let identities = validate_predicted_speaker_identities(recording)?;
    match analysis.predicted_speaker_for(&evidence.reference_speaker_id) {
        Some(predicted_speaker) => {
            let identity = identities.get(predicted_speaker).ok_or_else(|| {
                EnclaveError::InvalidRequest(
                    "mapped diarization hypothesis has no identity evidence".into(),
                )
            })?;
            if evidence.predicted_person != identity.predicted_person
                || evidence.name_binding_state != identity.name_binding_state
            {
                return Err(EnclaveError::InvalidRequest(
                    "voice evaluation identity decision is not bound to its mapped diarization hypothesis"
                        .into(),
                ));
            }
        }
        None => {
            if evidence.predicted_person.is_some() || evidence.name_binding_state != "none" {
                return Err(EnclaveError::InvalidRequest(
                    "unmapped reference speech must produce an identity abstention".into(),
                ));
            }
        }
    }
    Ok(())
}

fn validate_recording_bindings(
    manifest: &EvaluationManifest,
    recordings: &[DiarizationRecordingEvidence],
) -> Result<()> {
    let sources = manifest
        .sources
        .iter()
        .map(|source| (source.id.as_str(), source))
        .collect::<HashMap<_, _>>();
    let fixtures = manifest
        .owner_fixtures
        .iter()
        .map(|fixture| (fixture.id.as_str(), fixture))
        .collect::<HashMap<_, _>>();
    let mut ids = HashSet::new();
    for recording in recordings {
        validate_recording_shape(recording)?;
        if !ids.insert(recording.id.as_str()) {
            return Err(EnclaveError::InvalidRequest(
                "voice evaluation recording IDs must be unique".into(),
            ));
        }
        if let Some(fixture) = fixtures.get(recording.source_id.as_str()) {
            if recording.media_artifact_id.is_some()
                || recording.labels_artifact_id.is_some()
                || recording.selected_item_id.is_some()
                || recording.media_sha256 != fixture.media_sha256
                || recording.labels_sha256 != fixture.labels_sha256
                || !fixture.slices.contains(&recording.slice)
            {
                return Err(EnclaveError::InvalidRequest(
                    "owner recording does not match its reviewed media/label hashes and slices"
                        .into(),
                ));
            }
        } else if let Some(source) = sources.get(recording.source_id.as_str()) {
            let media_artifact = recording
                .media_artifact_id
                .as_deref()
                .and_then(|id| source.artifacts.iter().find(|artifact| artifact.id == id));
            let labels_artifact = recording
                .labels_artifact_id
                .as_deref()
                .and_then(|id| source.artifacts.iter().find(|artifact| artifact.id == id));
            if recording
                .selected_item_id
                .as_ref()
                .is_none_or(|item| !source.selected_item_ids.contains(item))
                || media_artifact
                    .is_none_or(|artifact| !matches!(artifact.kind.as_str(), "media" | "bundle"))
                || labels_artifact
                    .is_none_or(|artifact| !matches!(artifact.kind.as_str(), "labels" | "bundle"))
                || !source.slices.contains(&recording.slice)
            {
                return Err(EnclaveError::InvalidRequest(
                    "licensed recording does not match reviewed media/label artifacts, selected item, and slice"
                        .into(),
                ));
            }
        } else {
            return Err(EnclaveError::InvalidRequest(
                "voice evaluation recording references an unknown manifest source".into(),
            ));
        }
    }
    Ok(())
}

fn validate_record_ids(values: &[String], field: &str) -> Result<HashSet<String>> {
    if values.len() > MAX_RECORDS_PER_CASE
        || values
            .iter()
            .any(|value| !valid_hash_prefixed_id(value, "record-"))
    {
        return Err(EnclaveError::InvalidRequest(format!(
            "invalid bounded {field} record IDs"
        )));
    }
    let set = values.iter().cloned().collect::<HashSet<_>>();
    if set.len() != values.len() {
        return Err(EnclaveError::InvalidRequest(format!(
            "duplicate {field} record IDs"
        )));
    }
    Ok(set)
}

fn derive_case(evidence: CaseRunEvidence) -> Result<EvaluationCase> {
    if !valid_hash_prefixed_id(&evidence.id, "case-")
        || !matches!(
            evidence.corpus_kind.as_str(),
            "real_audio" | "synthetic_contract"
        )
        || !valid_opaque_id(&evidence.slice)
        || !valid_hash_prefixed_id(&evidence.recording_id, "recording-")
        || !valid_hash_prefixed_id(&evidence.reference_speaker_id, "speaker-")
        || !valid_hash_prefixed_id(&evidence.expected_person, "person-")
        || evidence
            .predicted_person
            .as_deref()
            .is_some_and(|person| !valid_hash_prefixed_id(person, "person-"))
        || !valid_hash_prefixed_id(&evidence.meeting_id, "meeting-")
        || evidence
            .first_seen_meeting_id
            .as_deref()
            .is_some_and(|meeting| !valid_hash_prefixed_id(meeting, "meeting-"))
        || evidence
            .display_name_collision_group
            .as_deref()
            .is_some_and(|group| !valid_hash_prefixed_id(group, "collision-"))
        || evidence.prior_high_quality_sample_count > 100_000
        || !valid_binding_state(&evidence.name_binding_state)
    {
        return Err(EnclaveError::InvalidRequest(
            "invalid voice evaluation case evidence".into(),
        ));
    }
    let accepted_name = evidence.name_binding_state == "accepted";
    if accepted_name && evidence.predicted_person.is_none() {
        return Err(EnclaveError::InvalidRequest(
            "accepted name evidence requires a predicted person".into(),
        ));
    }
    let mut fact_ids = HashSet::new();
    let mut fact_count = 0_u64;
    let mut facts_with_provenance = 0_u64;
    for fact in &evidence.facts {
        if !valid_hash_prefixed_id(&fact.id, "fact-")
            || !matches!(
                fact.status.as_str(),
                "accepted" | "rejected" | "superseded" | "conflicting"
            )
            || !fact_ids.insert(fact.id.as_str())
            || fact
                .evidence_id
                .as_deref()
                .is_some_and(|id| !valid_hash_prefixed_id(id, "evidence-"))
            || fact
                .source_record_id
                .as_deref()
                .is_some_and(|id| !valid_hash_prefixed_id(id, "record-"))
        {
            return Err(EnclaveError::InvalidRequest(
                "invalid voice evaluation fact evidence".into(),
            ));
        }
        if fact.status == "accepted" {
            fact_count += 1;
            if fact.evidence_id.is_some() && fact.source_record_id.is_some() {
                facts_with_provenance += 1;
            }
        }
    }
    let created = validate_record_ids(&evidence.created_record_ids, "created")?;
    let exported = validate_record_ids(&evidence.exported_record_ids, "exported")?;
    let deleted = validate_record_ids(&evidence.deleted_record_ids, "deleted")?;
    if !exported.is_subset(&created) || !deleted.is_subset(&created) {
        return Err(EnclaveError::InvalidRequest(
            "export/delete assertions may reference only records created by the case".into(),
        ));
    }
    let cross_meeting_link = evidence.predicted_person.is_some()
        && evidence
            .first_seen_meeting_id
            .as_ref()
            .is_some_and(|first| first != &evidence.meeting_id);
    Ok(EvaluationCase {
        id: evidence.id.clone(),
        corpus_kind: evidence.corpus_kind.clone(),
        slice: evidence.slice.clone(),
        expected_person: evidence.expected_person.clone(),
        predicted_person: evidence.predicted_person.clone(),
        accepted_name,
        cross_meeting_link,
        after_three_high_quality_samples: evidence.prior_high_quality_sample_count >= 3,
        speech_ms: 0,
        diarization_error_ms: 0,
        fact_count,
        facts_with_provenance,
        display_name_collision_group: evidence.display_name_collision_group.clone(),
        new_record_count: created.len() as u64,
        exported_new_record_count: exported.len() as u64,
        deleted_new_record_count: deleted.len() as u64,
        evidence: Some(evidence),
    })
}

pub fn build_cases_json(manifest_raw: &str, evidence_raw: &str) -> Result<String> {
    super::voice_eval::validate_manifest_json(manifest_raw)?;
    let manifest: EvaluationManifest = serde_json::from_str(manifest_raw)?;
    let evidence: EvaluationRunEvidence = serde_json::from_str(evidence_raw)?;
    if evidence.schema_version != 3
        || evidence.corpus_id != manifest.corpus_id
        || evidence.recordings.is_empty()
        || evidence.recordings.len() > MAX_RECORDINGS
        || evidence.cases.is_empty()
        || evidence.cases.len() > MAX_CASES
    {
        return Err(EnclaveError::InvalidRequest(
            "invalid bounded voice evaluation run evidence".into(),
        ));
    }
    validate_run(&evidence.run)?;
    validate_recording_bindings(&manifest, &evidence.recordings)?;
    let recordings_by_id = evidence
        .recordings
        .iter()
        .enumerate()
        .map(|(index, recording)| (recording.id.as_str(), index))
        .collect::<HashMap<_, _>>();
    let mut cases = Vec::with_capacity(evidence.cases.len());
    let mut global_record_ids = HashSet::new();
    let mut scored_reference_speakers = HashSet::new();
    for case_evidence in evidence.cases {
        let recording = recordings_by_id
            .get(case_evidence.recording_id.as_str())
            .map(|index| &evidence.recordings[*index])
            .ok_or_else(|| {
                EnclaveError::InvalidRequest(
                    "voice evaluation case references an unknown recording".into(),
                )
            })?;
        if recording.slice != case_evidence.slice {
            return Err(EnclaveError::InvalidRequest(
                "voice evaluation case does not match its recording slice".into(),
            ));
        }
        validate_case_speaker_binding(recording, &case_evidence)?;
        if !scored_reference_speakers.insert((
            case_evidence.recording_id.clone(),
            case_evidence.reference_speaker_id.clone(),
        )) {
            return Err(EnclaveError::InvalidRequest(
                "a reference speaker may support only one identity case per recording".into(),
            ));
        }
        for record_id in &case_evidence.created_record_ids {
            if !global_record_ids.insert(record_id.clone()) {
                return Err(EnclaveError::InvalidRequest(
                    "created record IDs must be unique across evaluation cases".into(),
                ));
            }
        }
        cases.push(derive_case(case_evidence)?);
    }
    for recording in &evidence.recordings {
        let reference_speakers = validate_turns(&recording.reference_turns, "reference")?;
        if reference_speakers.iter().any(|speaker| {
            !scored_reference_speakers.contains(&(recording.id.clone(), speaker.clone()))
        }) {
            return Err(EnclaveError::InvalidRequest(
                "every reference speaker must support exactly one identity case".into(),
            ));
        }
    }
    let corpus = EvaluationCorpus {
        schema_version: 3,
        corpus_id: evidence.corpus_id,
        source_manifest_sha256: sha256_hex(manifest_raw.as_bytes()),
        run_evidence_sha256: Some(sha256_hex(evidence_raw.as_bytes())),
        run: Some(evidence.run),
        diarization_error_baselines: evidence.diarization_error_baselines,
        diarization_recordings: evidence.recordings,
        cases,
    };
    validate_generated_corpus(&corpus)?;
    Ok(serde_json::to_string_pretty(&corpus)?)
}

pub(crate) fn validate_generated_corpus(corpus: &EvaluationCorpus) -> Result<()> {
    let Some(run) = corpus.run.as_ref() else {
        return Err(EnclaveError::InvalidRequest(
            "schema-v3 voice evaluation corpus is missing run metadata".into(),
        ));
    };
    validate_run(run)?;
    if corpus
        .run_evidence_sha256
        .as_deref()
        .is_none_or(|hash| !valid_sha256(hash))
        || corpus.diarization_recordings.is_empty()
        || corpus.diarization_recordings.len() > MAX_RECORDINGS
    {
        return Err(EnclaveError::InvalidRequest(
            "schema-v3 voice evaluation corpus is missing bounded evidence".into(),
        ));
    }
    let mut recordings_by_id = HashMap::new();
    for recording in &corpus.diarization_recordings {
        validate_recording_shape(recording)?;
        if recordings_by_id
            .insert(recording.id.as_str(), recording)
            .is_some()
        {
            return Err(EnclaveError::InvalidRequest(
                "schema-v3 diarization recording IDs must be unique".into(),
            ));
        }
    }
    let mut global_records = HashSet::new();
    let mut referenced_recordings = HashSet::new();
    let mut scored_reference_speakers = HashSet::new();
    let mut collision_people = HashMap::<String, HashSet<String>>::new();
    for case in &corpus.cases {
        let evidence = case.evidence.clone().ok_or_else(|| {
            EnclaveError::InvalidRequest(
                "schema-v3 voice evaluation case is missing derivation evidence".into(),
            )
        })?;
        let recording = recordings_by_id
            .get(evidence.recording_id.as_str())
            .copied()
            .ok_or_else(|| {
                EnclaveError::InvalidRequest("schema-v3 case recording binding is invalid".into())
            })?;
        if recording.slice != case.slice {
            return Err(EnclaveError::InvalidRequest(
                "schema-v3 case recording binding is invalid".into(),
            ));
        }
        validate_case_speaker_binding(recording, &evidence)?;
        if !scored_reference_speakers.insert((
            evidence.recording_id.clone(),
            evidence.reference_speaker_id.clone(),
        )) {
            return Err(EnclaveError::InvalidRequest(
                "schema-v3 reference speakers must have exactly one identity case".into(),
            ));
        }
        referenced_recordings.insert(evidence.recording_id.clone());
        if let Some(group) = &case.display_name_collision_group {
            collision_people
                .entry(group.clone())
                .or_default()
                .insert(case.expected_person.clone());
        }
        for record_id in &evidence.created_record_ids {
            if !global_records.insert(record_id.clone()) {
                return Err(EnclaveError::InvalidRequest(
                    "schema-v3 created record IDs are not globally unique".into(),
                ));
            }
        }
        let derived = derive_case(evidence)?;
        if case != &derived {
            return Err(EnclaveError::InvalidRequest(
                "schema-v3 voice evaluation derived fields were modified".into(),
            ));
        }
    }
    if referenced_recordings.len() != corpus.diarization_recordings.len()
        || corpus
            .diarization_recordings
            .iter()
            .any(|recording| !referenced_recordings.contains(&recording.id))
    {
        return Err(EnclaveError::InvalidRequest(
            "every schema-v3 diarization recording must support at least one scored case".into(),
        ));
    }
    for recording in &corpus.diarization_recordings {
        let reference_speakers = validate_turns(&recording.reference_turns, "reference")?;
        if reference_speakers.iter().any(|speaker| {
            !scored_reference_speakers.contains(&(recording.id.clone(), speaker.clone()))
        }) {
            return Err(EnclaveError::InvalidRequest(
                "every schema-v3 reference speaker must have exactly one identity case".into(),
            ));
        }
    }
    if !collision_people
        .values()
        .any(|expected_people| expected_people.len() >= 2)
    {
        return Err(EnclaveError::InvalidRequest(
            "schema-v3 release evidence must test two distinct people with the same display name"
                .into(),
        ));
    }
    Ok(())
}

pub(crate) fn validate_manifest_bindings(
    manifest_raw: &str,
    corpus: &EvaluationCorpus,
) -> Result<()> {
    let manifest: EvaluationManifest = serde_json::from_str(manifest_raw)?;
    validate_recording_bindings(&manifest, &corpus.diarization_recordings)
}

pub(crate) fn aggregate_diarization(
    corpus: &EvaluationCorpus,
) -> Result<BTreeMap<String, DiarizationMetrics>> {
    let mut totals = BTreeMap::<String, DiarizationMetrics>::new();
    for recording in &corpus.diarization_recordings {
        let metrics = derive_diarization_metrics(recording)?;
        let total = totals
            .entry(recording.slice.clone())
            .or_insert(DiarizationMetrics {
                speech_ms: 0,
                error_ms: 0,
            });
        total.speech_ms = total.speech_ms.saturating_add(metrics.speech_ms);
        total.error_ms = total.error_ms.saturating_add(metrics.error_ms);
    }
    Ok(totals)
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    const SLICES: &[&str] = &[
        "clean_remote_call",
        "three_plus_speakers",
        "overlap",
        "introduction",
        "repeated_meeting",
        "same_display_name",
        "similar_voices",
        "system_audio",
        "room_audio",
        "mac_microphone",
        "iphone_microphone",
        "bluetooth",
        "compression",
        "noise",
        "music",
        "echo",
        "french",
        "english",
        "mixed_language",
        "active_speaker_ui",
        "roster_only",
        "conflicting_evidence",
    ];

    #[test]
    fn evidence_builder_derives_release_fields_instead_of_trusting_counts() {
        let (manifest, evidence) = fixtures::passing_bundle();
        let generated = build_cases_json(&manifest, &evidence).unwrap();
        let corpus: EvaluationCorpus = serde_json::from_str(&generated).unwrap();

        assert_eq!(corpus.schema_version, 3);
        assert!(corpus.run_evidence_sha256.is_some());
        assert!(corpus.cases[0].accepted_name);
        assert_eq!(corpus.cases[0].fact_count, 1);
        assert_eq!(corpus.cases[0].facts_with_provenance, 1);
        assert_eq!(corpus.cases[0].new_record_count, 2);
        assert_eq!(corpus.cases[0].exported_new_record_count, 2);
        assert_eq!(corpus.cases[0].deleted_new_record_count, 2);
        assert!(super::super::voice_eval::score_json(&generated).is_ok());
    }

    #[test]
    fn evidence_derived_bundle_can_pass_the_release_gate() {
        let (manifest, evidence) = fixtures::passing_bundle();
        let cases = build_cases_json(&manifest, &evidence).unwrap();
        let report = super::super::voice_eval::score_json(&cases).unwrap();

        super::super::voice_eval::validate_release_bundle(&manifest, &cases, &report).unwrap();
    }

    #[test]
    fn diarization_error_uses_optimal_opaque_speaker_mapping_and_overlap() {
        let recording = fixtures::permuted_overlap_recording();
        let metrics = derive_diarization_metrics(&recording).unwrap();

        assert_eq!(metrics.speech_ms, 12_000);
        assert_eq!(metrics.error_ms, 0);
    }

    #[test]
    fn optimal_mapping_exposes_the_hypothesis_bound_to_each_reference_speaker() {
        let recording = fixtures::permuted_overlap_recording();
        let analysis = derive_diarization_analysis(&recording).unwrap();

        assert_eq!(
            analysis.predicted_speaker_for("speaker-aaaaaaaaaaaaaaaa"),
            Some("speaker-dddddddddddddddd")
        );
        assert_eq!(
            analysis.predicted_speaker_for("speaker-bbbbbbbbbbbbbbbb"),
            Some("speaker-cccccccccccccccc")
        );
    }

    #[test]
    fn diarization_counts_miss_false_alarm_and_confusion() {
        let mut recording = fixtures::permuted_overlap_recording();
        recording.predicted_turns = vec![DiarizationTurnEvidence {
            start_ms: 1_000,
            end_ms: 4_000,
            speaker_id: "speaker-cccccccccccccccc".into(),
        }];
        let metrics = derive_diarization_metrics(&recording).unwrap();

        assert_eq!(metrics.speech_ms, 12_000);
        assert_eq!(metrics.error_ms, 9_000);
    }

    #[test]
    fn tampered_derived_case_is_rejected() {
        let (manifest, evidence) = fixtures::passing_bundle();
        let generated = build_cases_json(&manifest, &evidence).unwrap();
        let mut value: serde_json::Value = serde_json::from_str(&generated).unwrap();
        value["cases"][0]["exported_new_record_count"] = json!(999);

        assert!(super::super::voice_eval::score_json(&value.to_string()).is_err());
    }

    #[test]
    fn evidence_cannot_pad_export_or_delete_with_unknown_records() {
        let (manifest, evidence) = fixtures::passing_bundle();
        let mut value: serde_json::Value = serde_json::from_str(&evidence).unwrap();
        value["cases"][0]["exported_record_ids"] = json!([
            "record-0000000000000000",
            "record-1000000000000000",
            "record-ffffffffffffffff"
        ]);

        assert!(build_cases_json(&manifest, &value.to_string()).is_err());
    }

    #[test]
    fn case_identity_must_match_the_globally_mapped_diarization_hypothesis() {
        let (manifest, evidence) = fixtures::passing_bundle();
        let mut value: serde_json::Value = serde_json::from_str(&evidence).unwrap();
        value["cases"][0]["predicted_person"] = json!("person-ffffffffffffffff");

        assert!(build_cases_json(&manifest, &value.to_string()).is_err());

        let mut value: serde_json::Value = serde_json::from_str(&evidence).unwrap();
        value["cases"][0]["name_binding_state"] = json!("probationary");

        assert!(build_cases_json(&manifest, &value.to_string()).is_err());
    }

    #[test]
    fn predicted_identity_rows_exactly_cover_diarization_hypotheses() {
        let (manifest, evidence) = fixtures::passing_bundle();
        let mut missing: serde_json::Value = serde_json::from_str(&evidence).unwrap();
        missing["recordings"][0]["predicted_speaker_identities"] = json!([]);
        assert!(build_cases_json(&manifest, &missing.to_string()).is_err());

        let mut extra: serde_json::Value = serde_json::from_str(&evidence).unwrap();
        extra["recordings"][0]["predicted_speaker_identities"]
            .as_array_mut()
            .unwrap()
            .push(json!({
                "speaker_id":"speaker-cccccccccccccccc",
                "predicted_person":null,
                "name_binding_state":"none"
            }));
        assert!(build_cases_json(&manifest, &extra.to_string()).is_err());
    }

    #[test]
    fn recordings_must_bind_the_exact_reviewed_media_and_label_artifacts() {
        let (manifest, evidence) = fixtures::passing_bundle();
        let mut unknown_media: serde_json::Value = serde_json::from_str(&evidence).unwrap();
        unknown_media["recordings"][0]["media_artifact_id"] = json!("unknown");
        assert!(build_cases_json(&manifest, &unknown_media.to_string()).is_err());

        let mut wrong_label_kind: serde_json::Value = serde_json::from_str(&evidence).unwrap();
        wrong_label_kind["recordings"][0]["labels_artifact_id"] = json!("media");
        assert!(build_cases_json(&manifest, &wrong_label_kind.to_string()).is_err());

        let owner_recording = SLICES
            .iter()
            .position(|slice| *slice == "system_audio")
            .unwrap();
        let mut owner_claims_archive: serde_json::Value = serde_json::from_str(&evidence).unwrap();
        owner_claims_archive["recordings"][owner_recording]["media_artifact_id"] = json!("media");
        assert!(build_cases_json(&manifest, &owner_claims_archive.to_string()).is_err());

        let mut legacy: serde_json::Value = serde_json::from_str(&evidence).unwrap();
        legacy["schema_version"] = json!(2);
        assert!(build_cases_json(&manifest, &legacy.to_string()).is_err());
    }

    #[test]
    fn unmapped_reference_speech_forces_identity_abstention() {
        let (manifest, evidence) = fixtures::passing_bundle();
        let mut value: serde_json::Value = serde_json::from_str(&evidence).unwrap();
        value["recordings"][0]["predicted_turns"] = json!([]);
        value["recordings"][0]["predicted_speaker_identities"] = json!([]);
        value["cases"][0]["predicted_person"] = serde_json::Value::Null;
        value["cases"][0]["name_binding_state"] = json!("none");

        let cases = build_cases_json(&manifest, &value.to_string()).unwrap();
        let corpus: EvaluationCorpus = serde_json::from_str(&cases).unwrap();
        assert_eq!(corpus.cases[0].predicted_person, None);
        assert!(!corpus.cases[0].accepted_name);

        value["cases"][0]["predicted_person"] = json!("person-0000000000000000");
        value["cases"][0]["name_binding_state"] = json!("accepted");
        assert!(build_cases_json(&manifest, &value.to_string()).is_err());
    }

    #[test]
    fn each_reference_speaker_supports_exactly_one_identity_case() {
        let (manifest, evidence) = fixtures::passing_bundle();
        let mut value: serde_json::Value = serde_json::from_str(&evidence).unwrap();
        let mut duplicate = value["cases"][0].clone();
        duplicate["id"] = json!("case-abababababababab");
        duplicate["created_record_ids"] = json!([]);
        duplicate["exported_record_ids"] = json!([]);
        duplicate["deleted_record_ids"] = json!([]);
        duplicate["facts"] = json!([]);
        value["cases"].as_array_mut().unwrap().push(duplicate);

        assert!(build_cases_json(&manifest, &value.to_string()).is_err());
    }

    #[test]
    fn media_and_label_hashes_must_match_the_reviewed_manifest() {
        let (manifest, evidence) = fixtures::passing_bundle();
        let mut value: serde_json::Value = serde_json::from_str(&evidence).unwrap();
        value["recordings"][7]["media_sha256"] = json!("f".repeat(64));

        assert!(build_cases_json(&manifest, &value.to_string()).is_err());
    }

    #[test]
    fn pipeline_versions_are_part_of_the_release_evidence() {
        let (manifest, evidence) = fixtures::passing_bundle();
        let mut value: serde_json::Value = serde_json::from_str(&evidence).unwrap();
        value["run"]["match_threshold"] = json!(0.01);

        assert!(build_cases_json(&manifest, &value.to_string()).is_err());
    }

    #[test]
    fn legacy_private_run_schema_cannot_authorize_a_release() {
        let (manifest, evidence) = fixtures::passing_bundle();
        let mut value: serde_json::Value = serde_json::from_str(&evidence).unwrap();
        value["schema_version"] = json!(1);

        assert!(build_cases_json(&manifest, &value.to_string()).is_err());
    }

    #[test]
    fn export_and_post_delete_artifacts_are_hash_bound() {
        let (manifest, evidence) = fixtures::passing_bundle();
        let mut value: serde_json::Value = serde_json::from_str(&evidence).unwrap();
        value["run"]["post_delete_scan_sha256"] = json!("not-a-hash");

        assert!(build_cases_json(&manifest, &value.to_string()).is_err());
    }

    #[test]
    fn same_display_name_gate_requires_two_distinct_people() {
        let (manifest, evidence) = fixtures::passing_bundle();
        let mut value: serde_json::Value = serde_json::from_str(&evidence).unwrap();
        value["cases"].as_array_mut().unwrap().pop();

        assert!(build_cases_json(&manifest, &value.to_string()).is_err());
    }

    #[test]
    fn evidence_contract_rejects_names_and_transcripts() {
        let (manifest, evidence) = fixtures::passing_bundle();
        let mut value: serde_json::Value = serde_json::from_str(&evidence).unwrap();
        value["cases"][0]["transcript"] = json!("My name is Private Person");

        assert!(build_cases_json(&manifest, &value.to_string()).is_err());
    }

    #[test]
    fn real_schema_v1_aggregate_cannot_authorize_a_release() {
        let corpus = fixtures::legacy_real_aggregate();
        let report = super::super::voice_eval::score(&corpus);
        assert!(!report.release_gates_pass);
    }

    mod fixtures {
        use super::*;

        fn turn(speaker: &str) -> serde_json::Value {
            json!({"start_ms":0,"end_ms":10_000,"speaker_id":speaker})
        }

        pub(super) fn passing_bundle() -> (String, String) {
            let sources = SLICES
                .iter()
                .enumerate()
                .map(|(index, slice)| {
                    json!({
                        "id": format!("source-{index}"),
                        "license_id":"CC0-1.0",
                        "license_url":"https://example.com/license",
                        "artifacts":[
                            {
                                "id":"media",
                                "kind":"media",
                                "url":format!("https://example.com/source-{index}.wav"),
                                "sha256":format!("{index:064x}")
                            },
                            {
                                "id":"labels",
                                "kind":"labels",
                                "url":format!("https://example.com/source-{index}.labels"),
                                "sha256":format!("{:064x}", index + 100)
                            }
                        ],
                        "selected_item_ids":[format!("item-{index}")],
                        "slices":[slice],
                        "derivation_command":"./derive --bounded"
                    })
                })
                .collect::<Vec<_>>();
            let owner_slices = [
                "system_audio",
                "mac_microphone",
                "iphone_microphone",
                "bluetooth",
                "active_speaker_ui",
                "same_display_name",
            ];
            let owner_fixtures = owner_slices
                .iter()
                .enumerate()
                .map(|(index, slice)| {
                    let capture_route = match *slice {
                        "system_audio" => "mac_system_audio",
                        "mac_microphone" => "mac_microphone",
                        "iphone_microphone" => "iphone_microphone",
                        "bluetooth" => "bluetooth",
                        "active_speaker_ui" | "same_display_name" => "screen_capture",
                        _ => unreachable!(),
                    };
                    json!({
                        "id":format!("owner-{index}"),
                        "media_sha256":format!("{:064x}", index + 1000),
                        "labels_sha256":format!("{:064x}", index + 2000),
                        "authorization_record_sha256":format!("{:064x}", index + 3000),
                        "physical_capture":true,
                        "capture_origin":"licensed_playback",
                        "derived_from_source_ids":["source-0"],
                        "capture_routes":[capture_route],
                        "slices":[slice]
                    })
                })
                .collect::<Vec<_>>();
            let manifest = json!({
                "schema_version":2,
                "corpus_id":"real-evidence-v2",
                "sources":sources,
                "owner_fixtures":owner_fixtures
            })
            .to_string();
            let mut recordings = SLICES
                .iter()
                .enumerate()
                .map(|(index, slice)| {
                    if let Some(owner_index) = owner_slices.iter().position(|owner| owner == slice)
                    {
                        json!({
                            "id":format!("recording-{index:016x}"),
                            "source_id":format!("owner-{owner_index}"),
                            "media_artifact_id":null,
                            "labels_artifact_id":null,
                            "selected_item_id":null,
                            "slice":slice,
                            "media_sha256":format!("{:064x}", owner_index + 1000),
                            "labels_sha256":format!("{:064x}", owner_index + 2000),
                            "reference_turns":[turn("speaker-aaaaaaaaaaaaaaaa")],
                            "predicted_turns":[turn("speaker-bbbbbbbbbbbbbbbb")],
                            "predicted_speaker_identities":[{
                                "speaker_id":"speaker-bbbbbbbbbbbbbbbb",
                                "predicted_person":format!("person-{index:016x}"),
                                "name_binding_state":"accepted"
                            }]
                        })
                    } else {
                        json!({
                            "id":format!("recording-{index:016x}"),
                            "source_id":format!("source-{index}"),
                            "media_artifact_id":"media",
                            "labels_artifact_id":"labels",
                            "selected_item_id":format!("item-{index}"),
                            "slice":slice,
                            "media_sha256":format!("{:064x}", index + 4000),
                            "labels_sha256":format!("{:064x}", index + 5000),
                            "reference_turns":[turn("speaker-aaaaaaaaaaaaaaaa")],
                            "predicted_turns":[turn("speaker-bbbbbbbbbbbbbbbb")],
                            "predicted_speaker_identities":[{
                                "speaker_id":"speaker-bbbbbbbbbbbbbbbb",
                                "predicted_person":format!("person-{index:016x}"),
                                "name_binding_state":"accepted"
                            }]
                        })
                    }
                })
                .collect::<Vec<_>>();
            recordings.push(json!({
                "id":"recording-ffffffffffffffff",
                "source_id":"owner-5",
                "media_artifact_id":null,
                "labels_artifact_id":null,
                "selected_item_id":null,
                "slice":"same_display_name",
                "media_sha256":format!("{:064x}", 1005),
                "labels_sha256":format!("{:064x}", 2005),
                "reference_turns":[turn("speaker-aaaaaaaaaaaaaaaa")],
                "predicted_turns":[turn("speaker-bbbbbbbbbbbbbbbb")],
                "predicted_speaker_identities":[{
                    "speaker_id":"speaker-bbbbbbbbbbbbbbbb",
                    "predicted_person":"person-eeeeeeeeeeeeeeee",
                    "name_binding_state":"accepted"
                }]
            }));
            let mut cases = SLICES
                .iter()
                .enumerate()
                .map(|(index, slice)| {
                    let created = vec![
                        format!("record-{index:015x}0"),
                        format!("record-{index:015x}1"),
                    ];
                    json!({
                        "id":format!("case-{index:016x}"),
                        "corpus_kind":"real_audio",
                        "slice":slice,
                        "recording_id":format!("recording-{index:016x}"),
                        "reference_speaker_id":"speaker-aaaaaaaaaaaaaaaa",
                        "expected_person":format!("person-{index:016x}"),
                        "predicted_person":format!("person-{index:016x}"),
                        "name_binding_state":"accepted",
                        "meeting_id":format!("meeting-{index:016x}"),
                        "first_seen_meeting_id":"meeting-ffffffffffffffff",
                        "prior_high_quality_sample_count":3,
                        "display_name_collision_group": if *slice == "same_display_name" { json!("collision-aaaaaaaaaaaaaaaa") } else { serde_json::Value::Null },
                        "facts":[{
                            "id":format!("fact-{index:016x}"),
                            "status":"accepted",
                            "evidence_id":format!("evidence-{index:016x}"),
                            "source_record_id":created[0]
                        }],
                        "created_record_ids":created,
                        "exported_record_ids":created,
                        "deleted_record_ids":created
                    })
                })
                .collect::<Vec<_>>();
            cases.push(json!({
                "id":"case-ffffffffffffffff",
                "corpus_kind":"real_audio",
                "slice":"same_display_name",
                "recording_id":"recording-ffffffffffffffff",
                "reference_speaker_id":"speaker-aaaaaaaaaaaaaaaa",
                "expected_person":"person-eeeeeeeeeeeeeeee",
                "predicted_person":"person-eeeeeeeeeeeeeeee",
                "name_binding_state":"accepted",
                "meeting_id":"meeting-eeeeeeeeeeeeeeee",
                "first_seen_meeting_id":"meeting-ffffffffffffffff",
                "prior_high_quality_sample_count":3,
                "display_name_collision_group":"collision-aaaaaaaaaaaaaaaa",
                "facts":[{
                    "id":"fact-eeeeeeeeeeeeeeee",
                    "status":"accepted",
                    "evidence_id":"evidence-eeeeeeeeeeeeeeee",
                    "source_record_id":"record-eeeeeeeeeeeeeee0"
                }],
                "created_record_ids":["record-eeeeeeeeeeeeeee0","record-eeeeeeeeeeeeeee1"],
                "exported_record_ids":["record-eeeeeeeeeeeeeee0","record-eeeeeeeeeeeeeee1"],
                "deleted_record_ids":["record-eeeeeeeeeeeeeee0","record-eeeeeeeeeeeeeee1"]
            }));
            let evidence = json!({
                "schema_version":3,
                "corpus_id":"real-evidence-v2",
                "run":{
                    "enclave_image_digest":format!("sha256:{}", "a".repeat(64)),
                    "evaluated_source_commit":"b".repeat(40),
                    "vertex_model":"gemini-flash",
                    "voice_model_sha256":"c".repeat(64),
                    "export_artifact_sha256":"d".repeat(64),
                    "post_delete_scan_sha256":"e".repeat(64),
                    "embedding_space":super::super::super::voice_memory::EMBEDDING_SPACE,
                    "scorer_version":super::super::super::voice_quality::SCORER_VERSION,
                    "quality_version":super::super::super::voice_quality::QUALITY_VERSION,
                    "match_threshold":super::super::super::voice_memory::MATCH_THRESHOLD,
                    "new_profile_threshold":super::super::super::voice_memory::NEW_PROFILE_THRESHOLD,
                    "minimum_decision_margin":super::super::super::voice_memory::MIN_DECISION_MARGIN,
                    "outlier_similarity":super::super::super::voice_quality::OUTLIER_SIMILARITY
                },
                "diarization_error_baselines":{"noise":0.1,"room_audio":0.1,"overlap":0.1},
                "recordings":recordings,
                "cases":cases
            })
            .to_string();
            (manifest, evidence)
        }

        pub(super) fn permuted_overlap_recording() -> DiarizationRecordingEvidence {
            DiarizationRecordingEvidence {
                id: "recording-aaaaaaaaaaaaaaaa".into(),
                source_id: "source-1".into(),
                media_artifact_id: Some("media".into()),
                labels_artifact_id: Some("labels".into()),
                selected_item_id: Some("item-1".into()),
                slice: "overlap".into(),
                media_sha256: "a".repeat(64),
                labels_sha256: "b".repeat(64),
                reference_turns: vec![
                    DiarizationTurnEvidence {
                        start_ms: 0,
                        end_ms: 6_000,
                        speaker_id: "speaker-aaaaaaaaaaaaaaaa".into(),
                    },
                    DiarizationTurnEvidence {
                        start_ms: 4_000,
                        end_ms: 10_000,
                        speaker_id: "speaker-bbbbbbbbbbbbbbbb".into(),
                    },
                ],
                predicted_turns: vec![
                    DiarizationTurnEvidence {
                        start_ms: 0,
                        end_ms: 6_000,
                        speaker_id: "speaker-dddddddddddddddd".into(),
                    },
                    DiarizationTurnEvidence {
                        start_ms: 4_000,
                        end_ms: 10_000,
                        speaker_id: "speaker-cccccccccccccccc".into(),
                    },
                ],
                predicted_speaker_identities: vec![
                    PredictedSpeakerIdentityEvidence {
                        speaker_id: "speaker-cccccccccccccccc".into(),
                        predicted_person: Some("person-cccccccccccccccc".into()),
                        name_binding_state: "accepted".into(),
                    },
                    PredictedSpeakerIdentityEvidence {
                        speaker_id: "speaker-dddddddddddddddd".into(),
                        predicted_person: Some("person-dddddddddddddddd".into()),
                        name_binding_state: "accepted".into(),
                    },
                ],
            }
        }

        pub(super) fn legacy_real_aggregate() -> EvaluationCorpus {
            EvaluationCorpus {
                schema_version: 1,
                corpus_id: "legacy-real".into(),
                source_manifest_sha256: "0".repeat(64),
                run_evidence_sha256: None,
                run: None,
                diarization_error_baselines: [
                    ("noise".into(), 1.0),
                    ("room_audio".into(), 1.0),
                    ("overlap".into(), 1.0),
                ]
                .into(),
                diarization_recordings: Vec::new(),
                cases: SLICES
                    .iter()
                    .enumerate()
                    .map(|(index, slice)| EvaluationCase {
                        id: format!("case-{index:016x}"),
                        corpus_kind: "real_audio".into(),
                        slice: (*slice).into(),
                        expected_person: format!("person-{index:016x}"),
                        predicted_person: Some(format!("person-{index:016x}")),
                        accepted_name: true,
                        cross_meeting_link: true,
                        after_three_high_quality_samples: true,
                        speech_ms: 10_000,
                        diarization_error_ms: 0,
                        fact_count: 1,
                        facts_with_provenance: 1,
                        display_name_collision_group: None,
                        new_record_count: 1,
                        exported_new_record_count: 1,
                        deleted_new_record_count: 1,
                        evidence: None,
                    })
                    .collect(),
            }
        }
    }
}
