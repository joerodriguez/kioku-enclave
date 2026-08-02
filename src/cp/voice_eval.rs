//! Public, content-free scoring harness for ADR-0016 voice/identity releases.

use std::collections::{BTreeMap, HashMap, HashSet};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error::{EnclaveError, Result};

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EvaluationCorpus {
    pub schema_version: u32,
    pub corpus_id: String,
    pub source_manifest_sha256: String,
    #[serde(default)]
    pub diarization_error_baselines: BTreeMap<String, f64>,
    pub cases: Vec<EvaluationCase>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EvaluationCase {
    pub id: String,
    pub corpus_kind: String,
    pub slice: String,
    pub expected_person: String,
    pub predicted_person: Option<String>,
    pub accepted_name: bool,
    pub cross_meeting_link: bool,
    pub after_three_high_quality_samples: bool,
    pub speech_ms: u64,
    pub diarization_error_ms: u64,
    pub fact_count: u64,
    pub facts_with_provenance: u64,
    pub display_name_collision_group: Option<String>,
    #[serde(default)]
    pub new_record_count: u64,
    #[serde(default)]
    pub exported_new_record_count: u64,
    #[serde(default)]
    pub deleted_new_record_count: u64,
}

#[derive(Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EvaluationReport {
    pub schema_version: u32,
    pub corpus_id: String,
    pub source_manifest_sha256: String,
    pub case_count: usize,
    pub real_case_count: usize,
    pub quality_case_count: usize,
    pub duplicate_case_ids: usize,
    pub unknown_corpus_kind_count: usize,
    pub accepted_name_decision_count: u64,
    pub accepted_name_precision: f64,
    pub wrong_person_accepted_binding_rate: f64,
    pub cross_meeting_link_count: u64,
    pub cross_meeting_link_precision: f64,
    pub after_three_sample_count: u64,
    pub recognition_recall_after_three: f64,
    pub clean_remote_speech_ms: u64,
    pub clean_remote_diarization_error: f64,
    pub diarization_error_by_slice: BTreeMap<String, f64>,
    pub missing_diarization_baselines: Vec<String>,
    pub invalid_diarization_baselines: Vec<String>,
    pub diarization_regressions: Vec<String>,
    pub same_display_name_merges: usize,
    pub fact_count: u64,
    pub facts_with_provenance: u64,
    pub fact_provenance_coverage: f64,
    pub new_record_count: u64,
    pub exported_new_record_count: u64,
    pub deleted_new_record_count: u64,
    pub export_coverage: f64,
    pub delete_coverage: f64,
    pub missing_metric_evidence: Vec<String>,
    pub missing_required_slices: Vec<String>,
    pub release_gates_pass: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct EvaluationManifest {
    schema_version: u32,
    corpus_id: String,
    sources: Vec<EvaluationSource>,
    owner_fixtures: Vec<OwnerFixture>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct EvaluationSource {
    id: String,
    archive_url: String,
    license_id: String,
    license_url: String,
    archive_sha256: String,
    selected_item_ids: Vec<String>,
    slices: Vec<String>,
    derivation_command: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct OwnerFixture {
    id: String,
    media_sha256: String,
    labels_sha256: String,
    authorization_record_sha256: String,
    slices: Vec<String>,
}

const REQUIRED_REAL_SLICES: &[&str] = &[
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

const REGRESSION_SLICES: &[&str] = &["noise", "room_audio", "overlap"];

const REQUIRED_OWNER_SLICES: &[&str] = &[
    "system_audio",
    "mac_microphone",
    "iphone_microphone",
    "bluetooth",
    "active_speaker_ui",
    "same_display_name",
];

fn sha256_hex(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 64
        && value
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

fn valid_hashed_id(value: &str, prefix: &str) -> bool {
    let Some(digest) = value.strip_prefix(prefix) else {
        return false;
    };
    (16..=64).contains(&digest.len())
        && digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn require_https_url(value: &str, field: &str) -> Result<()> {
    let parsed = reqwest::Url::parse(value)
        .map_err(|_| EnclaveError::InvalidRequest(format!("invalid manifest {field}")))?;
    if parsed.scheme() != "https"
        || parsed.host_str().is_none()
        || !parsed.username().is_empty()
        || parsed.password().is_some()
    {
        return Err(EnclaveError::InvalidRequest(format!(
            "manifest {field} must be an HTTPS URL without credentials"
        )));
    }
    Ok(())
}

fn validate_manifest(manifest: &EvaluationManifest) -> Result<()> {
    if manifest.schema_version != 1 || !valid_opaque_id(&manifest.corpus_id) {
        return Err(EnclaveError::InvalidRequest(
            "invalid voice evaluation manifest schema or corpus ID".into(),
        ));
    }
    if manifest.sources.is_empty() || manifest.sources.len() > 32 {
        return Err(EnclaveError::InvalidRequest(
            "voice evaluation manifest must contain 1 to 32 licensed sources".into(),
        ));
    }
    if manifest.owner_fixtures.is_empty() || manifest.owner_fixtures.len() > 64 {
        return Err(EnclaveError::InvalidRequest(
            "voice evaluation manifest must contain 1 to 64 owner fixtures".into(),
        ));
    }
    let allowed_slices = REQUIRED_REAL_SLICES.iter().copied().collect::<HashSet<_>>();
    let mut ids = HashSet::new();
    let mut covered_slices = HashSet::new();
    for source in &manifest.sources {
        if !valid_opaque_id(&source.id) || !ids.insert(source.id.as_str()) {
            return Err(EnclaveError::InvalidRequest(
                "manifest source IDs must be unique opaque identifiers".into(),
            ));
        }
        require_https_url(&source.archive_url, "archive_url")?;
        require_https_url(&source.license_url, "license_url")?;
        if source.license_id.is_empty()
            || source.license_id.len() > 128
            || !valid_sha256(&source.archive_sha256)
            || source.selected_item_ids.is_empty()
            || source.selected_item_ids.len() > 10_000
            || source.derivation_command.is_empty()
            || source.derivation_command.len() > 2_048
        {
            return Err(EnclaveError::InvalidRequest(
                "manifest source is missing bounded license, hash, selection, or derivation evidence"
                    .into(),
            ));
        }
        for selected in &source.selected_item_ids {
            if !valid_opaque_id(selected) {
                return Err(EnclaveError::InvalidRequest(
                    "manifest selected item IDs must be opaque identifiers".into(),
                ));
            }
        }
        for slice in &source.slices {
            if !allowed_slices.contains(slice.as_str()) {
                return Err(EnclaveError::InvalidRequest(format!(
                    "unknown manifest slice: {slice}"
                )));
            }
            covered_slices.insert(slice.as_str());
        }
    }
    let mut owner_slices = HashSet::new();
    for fixture in &manifest.owner_fixtures {
        if !valid_opaque_id(&fixture.id) || !ids.insert(fixture.id.as_str()) {
            return Err(EnclaveError::InvalidRequest(
                "manifest fixture IDs must be unique opaque identifiers".into(),
            ));
        }
        if !valid_sha256(&fixture.media_sha256)
            || !valid_sha256(&fixture.labels_sha256)
            || !valid_sha256(&fixture.authorization_record_sha256)
            || fixture.slices.is_empty()
        {
            return Err(EnclaveError::InvalidRequest(
                "owner fixture must bind media, labels, authorization, and slices".into(),
            ));
        }
        for slice in &fixture.slices {
            if !allowed_slices.contains(slice.as_str()) {
                return Err(EnclaveError::InvalidRequest(format!(
                    "unknown owner fixture slice: {slice}"
                )));
            }
            covered_slices.insert(slice.as_str());
            owner_slices.insert(slice.as_str());
        }
    }
    let missing = REQUIRED_REAL_SLICES
        .iter()
        .filter(|slice| !covered_slices.contains(**slice))
        .copied()
        .collect::<Vec<_>>();
    if !missing.is_empty() {
        return Err(EnclaveError::InvalidRequest(format!(
            "voice evaluation manifest is missing slices: {}",
            missing.join(", ")
        )));
    }
    let missing_owner = REQUIRED_OWNER_SLICES
        .iter()
        .filter(|slice| !owner_slices.contains(**slice))
        .copied()
        .collect::<Vec<_>>();
    if !missing_owner.is_empty() {
        return Err(EnclaveError::InvalidRequest(format!(
            "owner-controlled evaluation fixtures are missing slices: {}",
            missing_owner.join(", ")
        )));
    }
    Ok(())
}

fn validate_corpus(corpus: &EvaluationCorpus) -> Result<()> {
    if corpus.schema_version != 1
        || !valid_opaque_id(&corpus.corpus_id)
        || !valid_sha256(&corpus.source_manifest_sha256)
        || corpus.cases.is_empty()
        || corpus.cases.len() > 100_000
    {
        return Err(EnclaveError::InvalidRequest(
            "invalid bounded voice evaluation corpus header".into(),
        ));
    }
    let allowed_slices = REQUIRED_REAL_SLICES.iter().copied().collect::<HashSet<_>>();
    for (slice, baseline) in &corpus.diarization_error_baselines {
        if !allowed_slices.contains(slice.as_str()) || !baseline.is_finite() || *baseline < 0.0 {
            return Err(EnclaveError::InvalidRequest(
                "invalid diarization slice baseline".into(),
            ));
        }
    }
    for case in &corpus.cases {
        if !valid_hashed_id(&case.id, "case-")
            || !valid_hashed_id(&case.expected_person, "person-")
            || case
                .predicted_person
                .as_deref()
                .is_some_and(|person| !valid_hashed_id(person, "person-"))
            || case
                .display_name_collision_group
                .as_deref()
                .is_some_and(|group| !valid_hashed_id(group, "collision-"))
            || !allowed_slices.contains(case.slice.as_str())
            || !matches!(
                case.corpus_kind.as_str(),
                "real_audio" | "synthetic_contract"
            )
        {
            return Err(EnclaveError::InvalidRequest(
                "voice evaluation case identifiers and slices must use the content-free contract"
                    .into(),
            ));
        }
        if (case.accepted_name || case.cross_meeting_link) && case.predicted_person.is_none() {
            return Err(EnclaveError::InvalidRequest(
                "accepted names and cross-meeting links require an opaque predicted person".into(),
            ));
        }
        if (case.corpus_kind == "real_audio" && case.speech_ms == 0)
            || case.speech_ms > 86_400_000
            || case.diarization_error_ms > 864_000_000
            || case.fact_count > 1_000_000
            || case.new_record_count > 1_000_000
            || case.facts_with_provenance > case.fact_count
            || case.exported_new_record_count > case.new_record_count
            || case.deleted_new_record_count > case.new_record_count
        {
            return Err(EnclaveError::InvalidRequest(
                "voice evaluation case timing or coverage counts are invalid".into(),
            ));
        }
    }
    Ok(())
}

fn ratio(numerator: u64, denominator: u64) -> f64 {
    if denominator == 0 {
        0.0
    } else {
        numerator as f64 / denominator as f64
    }
}

pub fn score(corpus: &EvaluationCorpus) -> EvaluationReport {
    let unique_case_ids = corpus
        .cases
        .iter()
        .map(|case| case.id.as_str())
        .collect::<HashSet<_>>()
        .len();
    let duplicate_case_ids = corpus.cases.len() - unique_case_ids;
    let real_cases = corpus
        .cases
        .iter()
        .filter(|case| case.corpus_kind == "real_audio")
        .collect::<Vec<_>>();
    // The synthetic contract remains useful before a licensed corpus exists,
    // but once real cases are present it cannot dilute or inflate release
    // metrics. A release still requires real coverage below.
    let quality_cases = if real_cases.is_empty() {
        corpus.cases.iter().collect::<Vec<_>>()
    } else {
        real_cases.clone()
    };
    let accepted = quality_cases
        .iter()
        .copied()
        .filter(|case| case.accepted_name);
    let accepted_count = accepted.clone().count() as u64;
    let correct_accepted = accepted
        .clone()
        .filter(|case| case.predicted_person.as_deref() == Some(case.expected_person.as_str()))
        .count() as u64;
    let wrong_accepted = accepted_count - correct_accepted;
    let cross = quality_cases
        .iter()
        .copied()
        .filter(|case| case.cross_meeting_link && case.predicted_person.is_some());
    let cross_count = cross.clone().count() as u64;
    let correct_cross = cross
        .filter(|case| case.predicted_person.as_deref() == Some(case.expected_person.as_str()))
        .count() as u64;
    let after_three = quality_cases
        .iter()
        .copied()
        .filter(|case| case.after_three_high_quality_samples);
    let after_three_count = after_three.clone().count() as u64;
    let recognized_after_three = after_three
        .filter(|case| case.predicted_person.as_deref() == Some(case.expected_person.as_str()))
        .count() as u64;
    let clean = quality_cases
        .iter()
        .copied()
        .filter(|case| case.slice == "clean_remote_call");
    let clean_speech = clean.clone().map(|case| case.speech_ms).sum::<u64>();
    let clean_error = clean.map(|case| case.diarization_error_ms).sum::<u64>();
    let facts = quality_cases
        .iter()
        .map(|case| case.fact_count)
        .sum::<u64>();
    let facts_with_provenance = quality_cases
        .iter()
        .map(|case| case.facts_with_provenance)
        .sum::<u64>();
    let new_records = quality_cases
        .iter()
        .map(|case| case.new_record_count)
        .sum::<u64>();
    let exported_new_records = quality_cases
        .iter()
        .map(|case| case.exported_new_record_count)
        .sum::<u64>();
    let deleted_new_records = quality_cases
        .iter()
        .map(|case| case.deleted_new_record_count)
        .sum::<u64>();
    let mut collision_predictions: HashMap<&str, HashMap<&str, HashSet<&str>>> = HashMap::new();
    for case in &quality_cases {
        if let (Some(group), Some(predicted)) = (
            case.display_name_collision_group.as_deref(),
            case.predicted_person.as_deref(),
        ) {
            collision_predictions
                .entry(group)
                .or_default()
                .entry(predicted)
                .or_default()
                .insert(&case.expected_person);
        }
    }
    let same_display_name_merges = collision_predictions
        .values()
        .flat_map(HashMap::values)
        .filter(|expected_people| expected_people.len() > 1)
        .count();
    let accepted_name_precision = ratio(correct_accepted, accepted_count);
    let wrong_person_accepted_binding_rate = ratio(wrong_accepted, accepted_count);
    let cross_meeting_link_precision = ratio(correct_cross, cross_count);
    let recognition_recall_after_three = ratio(recognized_after_three, after_three_count);
    let clean_remote_diarization_error = ratio(clean_error, clean_speech);
    let fact_provenance_coverage = ratio(facts_with_provenance, facts);
    let export_coverage = ratio(exported_new_records, new_records);
    let delete_coverage = ratio(deleted_new_records, new_records);
    let real_case_count = real_cases.len();
    let real_slices = real_cases
        .iter()
        .map(|case| case.slice.as_str())
        .collect::<HashSet<_>>();
    let missing_required_slices = REQUIRED_REAL_SLICES
        .iter()
        .filter(|slice| !real_slices.contains(**slice))
        .map(|slice| (*slice).to_string())
        .collect::<Vec<_>>();
    let mut slice_totals = BTreeMap::<String, (u64, u64)>::new();
    for case in &quality_cases {
        let totals = slice_totals.entry(case.slice.clone()).or_default();
        totals.0 = totals.0.saturating_add(case.diarization_error_ms);
        totals.1 = totals.1.saturating_add(case.speech_ms);
    }
    let diarization_error_by_slice = slice_totals
        .into_iter()
        .map(|(slice, (error, speech))| (slice, ratio(error, speech)))
        .collect::<BTreeMap<_, _>>();
    let missing_diarization_baselines = REGRESSION_SLICES
        .iter()
        .filter(|slice| !corpus.diarization_error_baselines.contains_key(**slice))
        .map(|slice| (*slice).to_string())
        .collect::<Vec<_>>();
    let invalid_diarization_baselines = corpus
        .diarization_error_baselines
        .iter()
        .filter(|(_, baseline)| !baseline.is_finite() || **baseline < 0.0)
        .map(|(slice, _)| slice.clone())
        .collect::<Vec<_>>();
    let diarization_regressions = REGRESSION_SLICES
        .iter()
        .filter(|slice| {
            match (
                diarization_error_by_slice.get(**slice),
                corpus.diarization_error_baselines.get(**slice),
            ) {
                (Some(current), Some(baseline)) => current > baseline,
                _ => false,
            }
        })
        .map(|slice| (*slice).to_string())
        .collect::<Vec<_>>();
    let mut missing_metric_evidence = Vec::new();
    for (missing, present) in [
        ("accepted_name_decisions", accepted_count > 0),
        ("cross_meeting_links", cross_count > 0),
        ("after_three_samples", after_three_count > 0),
        ("clean_remote_speech", clean_speech > 0),
        ("accepted_facts", facts > 0),
        ("new_records", new_records > 0),
    ] {
        if !present {
            missing_metric_evidence.push(missing.to_string());
        }
    }
    let unknown_corpus_kind_count = corpus
        .cases
        .iter()
        .filter(|case| {
            !matches!(
                case.corpus_kind.as_str(),
                "real_audio" | "synthetic_contract"
            )
        })
        .count();
    // Synthetic contract fixtures can exercise the scorer but can never make
    // a release quality claim by themselves.
    let release_gates_pass = corpus.schema_version == 1
        && duplicate_case_ids == 0
        && unknown_corpus_kind_count == 0
        && real_case_count > 0
        && missing_required_slices.is_empty()
        && missing_metric_evidence.is_empty()
        && missing_diarization_baselines.is_empty()
        && invalid_diarization_baselines.is_empty()
        && diarization_regressions.is_empty()
        && accepted_name_precision >= 0.995
        && wrong_person_accepted_binding_rate < 0.001
        && cross_meeting_link_precision >= 0.99
        && recognition_recall_after_three >= 0.85
        && clean_remote_diarization_error <= 0.15
        && same_display_name_merges == 0
        && facts_with_provenance == facts
        && exported_new_records == new_records
        && deleted_new_records == new_records;
    EvaluationReport {
        schema_version: corpus.schema_version,
        corpus_id: corpus.corpus_id.clone(),
        source_manifest_sha256: corpus.source_manifest_sha256.clone(),
        case_count: corpus.cases.len(),
        real_case_count,
        quality_case_count: quality_cases.len(),
        duplicate_case_ids,
        unknown_corpus_kind_count,
        accepted_name_decision_count: accepted_count,
        accepted_name_precision,
        wrong_person_accepted_binding_rate,
        cross_meeting_link_count: cross_count,
        cross_meeting_link_precision,
        after_three_sample_count: after_three_count,
        recognition_recall_after_three,
        clean_remote_speech_ms: clean_speech,
        clean_remote_diarization_error,
        diarization_error_by_slice,
        missing_diarization_baselines,
        invalid_diarization_baselines,
        diarization_regressions,
        same_display_name_merges,
        fact_count: facts,
        facts_with_provenance,
        fact_provenance_coverage,
        new_record_count: new_records,
        exported_new_record_count: exported_new_records,
        deleted_new_record_count: deleted_new_records,
        export_coverage,
        delete_coverage,
        missing_metric_evidence,
        missing_required_slices,
        release_gates_pass,
    }
}

pub fn score_json(raw: &str) -> Result<String> {
    let corpus: EvaluationCorpus = serde_json::from_str(raw)?;
    validate_corpus(&corpus)?;
    Ok(serde_json::to_string_pretty(&score(&corpus))?)
}

pub fn validate_release_report(corpus_raw: &str, report_raw: &str) -> Result<()> {
    let corpus: EvaluationCorpus = serde_json::from_str(corpus_raw)?;
    validate_corpus(&corpus)?;
    let checked_in: EvaluationReport = serde_json::from_str(report_raw)?;
    let computed = score(&corpus);
    if checked_in != computed {
        return Err(EnclaveError::InvalidRequest(
            "checked-in voice evaluation report is stale or does not match its aggregate cases"
                .into(),
        ));
    }
    if !computed.release_gates_pass {
        return Err(EnclaveError::InvalidRequest(
            "voice evaluation release gates did not pass".into(),
        ));
    }
    Ok(())
}

pub fn validate_manifest_json(manifest_raw: &str) -> Result<String> {
    let manifest: EvaluationManifest = serde_json::from_str(manifest_raw)?;
    validate_manifest(&manifest)?;
    Ok(sha256_hex(manifest_raw.as_bytes()))
}

pub fn validate_release_bundle(
    manifest_raw: &str,
    corpus_raw: &str,
    report_raw: &str,
) -> Result<()> {
    let manifest: EvaluationManifest = serde_json::from_str(manifest_raw)?;
    validate_manifest(&manifest)?;
    let corpus: EvaluationCorpus = serde_json::from_str(corpus_raw)?;
    if corpus.corpus_id != manifest.corpus_id {
        return Err(EnclaveError::InvalidRequest(
            "voice evaluation manifest and aggregate cases have different corpus IDs".into(),
        ));
    }
    if !valid_sha256(&corpus.source_manifest_sha256)
        || corpus.source_manifest_sha256 != sha256_hex(manifest_raw.as_bytes())
    {
        return Err(EnclaveError::InvalidRequest(
            "voice evaluation cases are not bound to the exact checked-in source manifest".into(),
        ));
    }
    validate_release_report(corpus_raw, report_raw)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SYNTHETIC: &str = include_str!("../../eval/voice/synthetic-contract-v1.json");

    #[test]
    fn public_fixture_scores_all_release_dimensions_but_cannot_claim_real_quality() {
        let corpus: EvaluationCorpus = serde_json::from_str(SYNTHETIC).unwrap();
        let report = score(&corpus);
        assert_eq!(report.case_count, 6);
        assert_eq!(report.real_case_count, 0);
        assert_eq!(report.accepted_name_precision, 1.0);
        assert_eq!(report.cross_meeting_link_precision, 1.0);
        assert!(report.recognition_recall_after_three >= 0.85);
        assert!(report.clean_remote_diarization_error <= 0.15);
        assert_eq!(report.same_display_name_merges, 0);
        assert_eq!(report.fact_provenance_coverage, 1.0);
        assert!(!report.missing_required_slices.is_empty());
        assert!(!report.release_gates_pass);
        assert!(score_json(SYNTHETIC)
            .unwrap()
            .contains("release_gates_pass"));
    }

    fn passing_real_corpus() -> EvaluationCorpus {
        let mut cases = REQUIRED_REAL_SLICES
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
                diarization_error_ms: if *slice == "clean_remote_call" {
                    1_000
                } else {
                    0
                },
                fact_count: 1,
                facts_with_provenance: 1,
                display_name_collision_group: None,
                new_record_count: 1,
                exported_new_record_count: 1,
                deleted_new_record_count: 1,
            })
            .collect::<Vec<_>>();
        cases.push(EvaluationCase {
            id: "case-ffffffffffffffff".into(),
            corpus_kind: "real_audio".into(),
            slice: "same_display_name".into(),
            expected_person: "person-eeeeeeeeeeeeeeee".into(),
            predicted_person: Some("person-eeeeeeeeeeeeeeee".into()),
            accepted_name: true,
            cross_meeting_link: true,
            after_three_high_quality_samples: true,
            speech_ms: 10_000,
            diarization_error_ms: 0,
            fact_count: 1,
            facts_with_provenance: 1,
            display_name_collision_group: Some("collision-aaaaaaaaaaaaaaaa".into()),
            new_record_count: 1,
            exported_new_record_count: 1,
            deleted_new_record_count: 1,
        });
        let first_alex = cases
            .iter_mut()
            .find(|case| case.slice == "same_display_name")
            .unwrap();
        first_alex.display_name_collision_group = Some("collision-aaaaaaaaaaaaaaaa".into());
        EvaluationCorpus {
            schema_version: 1,
            corpus_id: "real-release-v1".into(),
            source_manifest_sha256: "0".repeat(64),
            diarization_error_baselines: [
                ("noise".into(), 0.20),
                ("room_audio".into(), 0.20),
                ("overlap".into(), 0.20),
            ]
            .into(),
            cases,
        }
    }

    #[test]
    fn release_metrics_ignore_synthetic_contract_cases_when_real_cases_exist() {
        let mut corpus = passing_real_corpus();
        corpus.cases.push(EvaluationCase {
            id: "case-dddddddddddddddd".into(),
            corpus_kind: "synthetic_contract".into(),
            slice: "clean_remote_call".into(),
            expected_person: "person-aaaaaaaaaaaaaaaa".into(),
            predicted_person: Some("person-bbbbbbbbbbbbbbbb".into()),
            accepted_name: true,
            cross_meeting_link: true,
            after_three_high_quality_samples: true,
            speech_ms: 1,
            diarization_error_ms: 1,
            fact_count: 1,
            facts_with_provenance: 0,
            display_name_collision_group: None,
            new_record_count: 1,
            exported_new_record_count: 0,
            deleted_new_record_count: 0,
        });

        let report = score(&corpus);
        assert_eq!(report.quality_case_count, REQUIRED_REAL_SLICES.len() + 1);
        assert_eq!(report.accepted_name_precision, 1.0);
        assert_eq!(report.fact_provenance_coverage, 1.0);
        assert_eq!(report.export_coverage, 1.0);
        assert_eq!(report.delete_coverage, 1.0);
        assert!(report.release_gates_pass);
    }

    #[test]
    fn noisy_room_and_overlap_regressions_fail_closed() {
        let mut corpus = passing_real_corpus();
        let overlap = corpus
            .cases
            .iter_mut()
            .find(|case| case.slice == "overlap")
            .unwrap();
        overlap.diarization_error_ms = 2_001;
        corpus
            .diarization_error_baselines
            .insert("overlap".into(), 0.20);

        let report = score(&corpus);
        assert_eq!(report.diarization_regressions, vec!["overlap"]);
        assert!(!report.release_gates_pass);
    }

    #[test]
    fn missing_or_invalid_slice_baselines_fail_closed() {
        let mut corpus = passing_real_corpus();
        corpus.diarization_error_baselines.remove("noise");
        corpus
            .diarization_error_baselines
            .insert("room_audio".into(), -0.01);

        let report = score(&corpus);
        assert_eq!(report.missing_diarization_baselines, vec!["noise"]);
        assert_eq!(report.invalid_diarization_baselines, vec!["room_audio"]);
        assert!(!report.release_gates_pass);
    }

    #[test]
    fn export_and_delete_must_cover_every_new_record() {
        let mut corpus = passing_real_corpus();
        corpus.cases[0].exported_new_record_count = 0;
        corpus.cases[1].deleted_new_record_count = 0;

        let report = score(&corpus);
        assert!(report.export_coverage < 1.0);
        assert!(report.delete_coverage < 1.0);
        assert!(!report.release_gates_pass);
    }

    #[test]
    fn release_check_requires_a_matching_checked_in_passing_report() {
        let corpus = passing_real_corpus();
        let corpus_json = serde_json::to_string(&corpus).unwrap();
        let report_json = score_json(&corpus_json).unwrap();
        validate_release_report(&corpus_json, &report_json).unwrap();

        let mut stale: serde_json::Value = serde_json::from_str(&report_json).unwrap();
        stale["corpus_id"] = serde_json::Value::String("stale".into());
        assert!(validate_release_report(&corpus_json, &stale.to_string()).is_err());

        assert!(validate_release_report(SYNTHETIC, &score_json(SYNTHETIC).unwrap()).is_err());
    }

    fn passing_manifest_json() -> String {
        serde_json::json!({
            "schema_version": 1,
            "corpus_id": "real-release-v1",
            "sources": [{
                "id": "ami-eval-subset",
                "archive_url": "https://groups.inf.ed.ac.uk/ami/download/",
                "license_id": "CC-BY-4.0",
                "license_url": "https://groups.inf.ed.ac.uk/ami/corpus/license.shtml",
                "archive_sha256": "a".repeat(64),
                "selected_item_ids": ["meeting-001"],
                "slices": REQUIRED_REAL_SLICES,
                "derivation_command": "./eval/voice/derive.sh manifest.json"
            }],
            "owner_fixtures": [{
                "id": "owner-device-matrix-v1",
                "media_sha256": "b".repeat(64),
                "labels_sha256": "c".repeat(64),
                "authorization_record_sha256": "d".repeat(64),
                "slices": [
                    "system_audio", "mac_microphone", "iphone_microphone",
                    "bluetooth", "active_speaker_ui", "same_display_name"
                ]
            }]
        })
        .to_string()
    }

    #[test]
    fn release_bundle_binds_passing_report_to_a_valid_source_manifest() {
        let manifest = passing_manifest_json();
        let mut corpus = passing_real_corpus();
        corpus.source_manifest_sha256 = sha256_hex(manifest.as_bytes());
        let corpus_json = serde_json::to_string(&corpus).unwrap();
        let report_json = score_json(&corpus_json).unwrap();

        validate_release_bundle(&manifest, &corpus_json, &report_json).unwrap();

        let mut changed: serde_json::Value = serde_json::from_str(&manifest).unwrap();
        changed["sources"][0]["selected_item_ids"][0] =
            serde_json::Value::String("meeting-002".into());
        assert!(validate_release_bundle(&changed.to_string(), &corpus_json, &report_json).is_err());
    }

    #[test]
    fn release_bundle_requires_owner_device_ui_and_collision_fixtures() {
        let mut manifest: serde_json::Value =
            serde_json::from_str(&passing_manifest_json()).unwrap();
        manifest["owner_fixtures"][0]["slices"] =
            serde_json::json!(["system_audio", "mac_microphone"]);
        let manifest = manifest.to_string();
        let mut corpus = passing_real_corpus();
        corpus.source_manifest_sha256 = sha256_hex(manifest.as_bytes());
        let corpus_json = serde_json::to_string(&corpus).unwrap();
        let report_json = score_json(&corpus_json).unwrap();

        assert!(validate_release_bundle(&manifest, &corpus_json, &report_json).is_err());
    }

    #[test]
    fn manifest_validator_emits_raw_hash_and_rejects_url_credentials() {
        let manifest = passing_manifest_json();
        assert_eq!(
            validate_manifest_json(&manifest).unwrap(),
            sha256_hex(manifest.as_bytes())
        );

        let mut credentials: serde_json::Value = serde_json::from_str(&manifest).unwrap();
        credentials["sources"][0]["archive_url"] =
            serde_json::Value::String("https://user:password@example.com/archive".into());
        assert!(validate_manifest_json(&credentials.to_string()).is_err());
    }

    #[test]
    fn aggregate_cases_reject_names_and_per_case_coverage_overclaims() {
        let mut named = passing_real_corpus();
        named.cases[0].expected_person = "John Garcia".into();
        assert!(score_json(&serde_json::to_string(&named).unwrap()).is_err());

        let mut overclaim = passing_real_corpus();
        overclaim.cases[0].facts_with_provenance = 2;
        overclaim.cases[1].facts_with_provenance = 0;
        overclaim.cases[2].exported_new_record_count = 2;
        overclaim.cases[3].exported_new_record_count = 0;
        assert!(score_json(&serde_json::to_string(&overclaim).unwrap()).is_err());
    }

    #[test]
    fn accepted_names_and_cross_meeting_links_require_a_prediction() {
        let mut corpus = passing_real_corpus();
        corpus.cases[0].predicted_person = None;
        assert!(score_json(&serde_json::to_string(&corpus).unwrap()).is_err());
    }
}
