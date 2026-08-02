//! Evidence-derived ADR-0016 release cases.
//!
//! Real release metrics must not be hand-authored counters. The private run
//! input contains opaque speaker/person/record identifiers, source hashes, and
//! timing decisions exported by the production pipeline. This module binds
//! that input to the reviewed source manifest and emits a content-free corpus
//! whose derived fields can be recomputed by CI without access to media,
//! transcripts, names, embeddings, or raw similarity scores.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error::{EnclaveError, Result};

use super::voice_eval::{EvaluationCase, EvaluationCorpus};

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
    pub selected_item_id: Option<String>,
    pub slice: String,
    pub media_sha256: String,
    pub labels_sha256: String,
    pub reference_turns: Vec<DiarizationTurnEvidence>,
    pub predicted_turns: Vec<DiarizationTurnEvidence>,
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

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct EvidenceManifest {
    schema_version: u32,
    corpus_id: String,
    sources: Vec<EvidenceSource>,
    owner_fixtures: Vec<EvidenceOwnerFixture>,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct EvidenceSource {
    id: String,
    archive_url: String,
    license_id: String,
    license_url: String,
    archive_sha256: String,
    selected_item_ids: Vec<String>,
    slices: Vec<String>,
    derivation_command: String,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct EvidenceOwnerFixture {
    id: String,
    media_sha256: String,
    labels_sha256: String,
    authorization_record_sha256: String,
    slices: Vec<String>,
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

fn maximum_mapping_overlap(weights: &[Vec<u64>], hypothesis_count: usize) -> u64 {
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

    visit(0, 0, weights, hypothesis_count, &mut HashMap::new())
}

pub(crate) fn derive_diarization_metrics(
    recording: &DiarizationRecordingEvidence,
) -> Result<DiarizationMetrics> {
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
    let correct_ms = maximum_mapping_overlap(&weights, predicted_speakers.len());
    Ok(DiarizationMetrics {
        speech_ms,
        error_ms: maximum_active_ms.saturating_sub(correct_ms),
    })
}

fn validate_recording_shape(recording: &DiarizationRecordingEvidence) -> Result<()> {
    if !valid_hash_prefixed_id(&recording.id, "recording-")
        || !valid_opaque_id(&recording.source_id)
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
    Ok(())
}

fn validate_recording_bindings(
    manifest: &EvidenceManifest,
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
            if recording.selected_item_id.is_some()
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
            if recording
                .selected_item_id
                .as_ref()
                .is_none_or(|item| !source.selected_item_ids.contains(item))
                || !source.slices.contains(&recording.slice)
            {
                return Err(EnclaveError::InvalidRequest(
                    "licensed recording does not match a reviewed selected item and slice".into(),
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
        || !matches!(
            evidence.name_binding_state.as_str(),
            "none"
                | "proposed"
                | "probationary"
                | "accepted"
                | "conflicting"
                | "rejected"
                | "superseded"
        )
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
    let manifest: EvidenceManifest = serde_json::from_str(manifest_raw)?;
    let evidence: EvaluationRunEvidence = serde_json::from_str(evidence_raw)?;
    if evidence.schema_version != 1
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
    let recording_slices = evidence
        .recordings
        .iter()
        .map(|recording| (recording.id.as_str(), recording.slice.as_str()))
        .collect::<HashMap<_, _>>();
    let mut cases = Vec::with_capacity(evidence.cases.len());
    let mut global_record_ids = HashSet::new();
    for case_evidence in evidence.cases {
        if recording_slices
            .get(case_evidence.recording_id.as_str())
            .is_none_or(|slice| *slice != case_evidence.slice)
        {
            return Err(EnclaveError::InvalidRequest(
                "voice evaluation case does not match its recording slice".into(),
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
    let corpus = EvaluationCorpus {
        schema_version: 2,
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
            "schema-v2 voice evaluation corpus is missing run metadata".into(),
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
            "schema-v2 voice evaluation corpus is missing bounded evidence".into(),
        ));
    }
    let mut recording_slices = HashMap::new();
    for recording in &corpus.diarization_recordings {
        validate_recording_shape(recording)?;
        if recording_slices
            .insert(recording.id.as_str(), recording.slice.as_str())
            .is_some()
        {
            return Err(EnclaveError::InvalidRequest(
                "schema-v2 diarization recording IDs must be unique".into(),
            ));
        }
    }
    let mut global_records = HashSet::new();
    let mut referenced_recordings = HashSet::new();
    let mut collision_people = HashMap::<String, HashSet<String>>::new();
    for case in &corpus.cases {
        let evidence = case.evidence.clone().ok_or_else(|| {
            EnclaveError::InvalidRequest(
                "schema-v2 voice evaluation case is missing derivation evidence".into(),
            )
        })?;
        if recording_slices
            .get(evidence.recording_id.as_str())
            .is_none_or(|slice| *slice != case.slice)
        {
            return Err(EnclaveError::InvalidRequest(
                "schema-v2 case recording binding is invalid".into(),
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
                    "schema-v2 created record IDs are not globally unique".into(),
                ));
            }
        }
        let derived = derive_case(evidence)?;
        if case != &derived {
            return Err(EnclaveError::InvalidRequest(
                "schema-v2 voice evaluation derived fields were modified".into(),
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
            "every schema-v2 diarization recording must support at least one scored case".into(),
        ));
    }
    if !collision_people
        .values()
        .any(|expected_people| expected_people.len() >= 2)
    {
        return Err(EnclaveError::InvalidRequest(
            "schema-v2 release evidence must test two distinct people with the same display name"
                .into(),
        ));
    }
    Ok(())
}

pub(crate) fn validate_manifest_bindings(
    manifest_raw: &str,
    corpus: &EvaluationCorpus,
) -> Result<()> {
    let manifest: EvidenceManifest = serde_json::from_str(manifest_raw)?;
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

        assert_eq!(corpus.schema_version, 2);
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
                        "archive_url": format!("https://example.com/source-{index}.tar"),
                        "license_id":"CC0-1.0",
                        "license_url":"https://example.com/license",
                        "archive_sha256": format!("{index:064x}"),
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
                    json!({
                        "id":format!("owner-{index}"),
                        "media_sha256":format!("{:064x}", index + 1000),
                        "labels_sha256":format!("{:064x}", index + 2000),
                        "authorization_record_sha256":format!("{:064x}", index + 3000),
                        "slices":[slice]
                    })
                })
                .collect::<Vec<_>>();
            let manifest = json!({
                "schema_version":1,
                "corpus_id":"real-evidence-v1",
                "sources":sources,
                "owner_fixtures":owner_fixtures
            })
            .to_string();
            let recordings = SLICES
                .iter()
                .enumerate()
                .map(|(index, slice)| {
                    if let Some(owner_index) = owner_slices.iter().position(|owner| owner == slice)
                    {
                        json!({
                            "id":format!("recording-{index:016x}"),
                            "source_id":format!("owner-{owner_index}"),
                            "selected_item_id":null,
                            "slice":slice,
                            "media_sha256":format!("{:064x}", owner_index + 1000),
                            "labels_sha256":format!("{:064x}", owner_index + 2000),
                            "reference_turns":[turn("speaker-aaaaaaaaaaaaaaaa")],
                            "predicted_turns":[turn("speaker-bbbbbbbbbbbbbbbb")]
                        })
                    } else {
                        json!({
                            "id":format!("recording-{index:016x}"),
                            "source_id":format!("source-{index}"),
                            "selected_item_id":format!("item-{index}"),
                            "slice":slice,
                            "media_sha256":format!("{:064x}", index + 4000),
                            "labels_sha256":format!("{:064x}", index + 5000),
                            "reference_turns":[turn("speaker-aaaaaaaaaaaaaaaa")],
                            "predicted_turns":[turn("speaker-bbbbbbbbbbbbbbbb")]
                        })
                    }
                })
                .collect::<Vec<_>>();
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
                "recording_id":"recording-0000000000000005",
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
                "schema_version":1,
                "corpus_id":"real-evidence-v1",
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
