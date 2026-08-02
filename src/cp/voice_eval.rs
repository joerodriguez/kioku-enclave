//! Public, content-free scoring harness for ADR-0016 voice/identity releases.

use std::collections::{HashMap, HashSet};

use serde::{Deserialize, Serialize};

use crate::error::Result;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvaluationCorpus {
    pub schema_version: u32,
    pub corpus_id: String,
    pub cases: Vec<EvaluationCase>,
}

#[derive(Debug, Deserialize)]
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
}

#[derive(Debug, Serialize)]
pub struct EvaluationReport {
    pub schema_version: u32,
    pub corpus_id: String,
    pub case_count: usize,
    pub real_case_count: usize,
    pub duplicate_case_ids: usize,
    pub accepted_name_precision: f64,
    pub wrong_person_accepted_binding_rate: f64,
    pub cross_meeting_link_precision: f64,
    pub recognition_recall_after_three: f64,
    pub clean_remote_diarization_error: f64,
    pub same_display_name_merges: usize,
    pub fact_provenance_coverage: f64,
    pub missing_required_slices: Vec<&'static str>,
    pub release_gates_pass: bool,
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

fn ratio(numerator: u64, denominator: u64) -> f64 {
    if denominator == 0 {
        1.0
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
    let accepted = corpus.cases.iter().filter(|case| case.accepted_name);
    let accepted_count = accepted.clone().count() as u64;
    let correct_accepted = accepted
        .clone()
        .filter(|case| case.predicted_person.as_deref() == Some(case.expected_person.as_str()))
        .count() as u64;
    let wrong_accepted = accepted_count - correct_accepted;
    let cross = corpus
        .cases
        .iter()
        .filter(|case| case.cross_meeting_link && case.predicted_person.is_some());
    let cross_count = cross.clone().count() as u64;
    let correct_cross = cross
        .filter(|case| case.predicted_person.as_deref() == Some(case.expected_person.as_str()))
        .count() as u64;
    let after_three = corpus
        .cases
        .iter()
        .filter(|case| case.after_three_high_quality_samples);
    let after_three_count = after_three.clone().count() as u64;
    let recognized_after_three = after_three
        .filter(|case| case.predicted_person.as_deref() == Some(case.expected_person.as_str()))
        .count() as u64;
    let clean = corpus
        .cases
        .iter()
        .filter(|case| case.slice == "clean_remote_call");
    let clean_speech = clean.clone().map(|case| case.speech_ms).sum::<u64>();
    let clean_error = clean.map(|case| case.diarization_error_ms).sum::<u64>();
    let facts = corpus.cases.iter().map(|case| case.fact_count).sum::<u64>();
    let facts_with_provenance = corpus
        .cases
        .iter()
        .map(|case| case.facts_with_provenance)
        .sum::<u64>();
    let mut collision_predictions: HashMap<&str, HashMap<&str, HashSet<&str>>> = HashMap::new();
    for case in &corpus.cases {
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
    let real_case_count = corpus
        .cases
        .iter()
        .filter(|case| case.corpus_kind == "real_audio")
        .count();
    let real_slices = corpus
        .cases
        .iter()
        .filter(|case| case.corpus_kind == "real_audio")
        .map(|case| case.slice.as_str())
        .collect::<HashSet<_>>();
    let missing_required_slices = REQUIRED_REAL_SLICES
        .iter()
        .filter(|slice| !real_slices.contains(**slice))
        .copied()
        .collect::<Vec<_>>();
    // Synthetic contract fixtures can exercise the scorer but can never make
    // a release quality claim by themselves.
    let release_gates_pass = corpus.schema_version == 1
        && duplicate_case_ids == 0
        && real_case_count > 0
        && missing_required_slices.is_empty()
        && accepted_name_precision >= 0.995
        && wrong_person_accepted_binding_rate < 0.001
        && cross_meeting_link_precision >= 0.99
        && recognition_recall_after_three >= 0.85
        && clean_remote_diarization_error <= 0.15
        && same_display_name_merges == 0
        && fact_provenance_coverage == 1.0;
    EvaluationReport {
        schema_version: corpus.schema_version,
        corpus_id: corpus.corpus_id.clone(),
        case_count: corpus.cases.len(),
        real_case_count,
        duplicate_case_ids,
        accepted_name_precision,
        wrong_person_accepted_binding_rate,
        cross_meeting_link_precision,
        recognition_recall_after_three,
        clean_remote_diarization_error,
        same_display_name_merges,
        fact_provenance_coverage,
        missing_required_slices,
        release_gates_pass,
    }
}

pub fn score_json(raw: &str) -> Result<String> {
    let corpus: EvaluationCorpus = serde_json::from_str(raw)?;
    Ok(serde_json::to_string_pretty(&score(&corpus))?)
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
}
