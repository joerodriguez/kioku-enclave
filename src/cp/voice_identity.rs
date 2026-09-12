//! Pure Phase 1 acoustic-domain, binary-codec and conservative continuity rules.
use super::{
    voice_memory::{MATCH_THRESHOLD, MAX_TURN_SAMPLES, MIN_DECISION_MARGIN, NEW_PROFILE_THRESHOLD},
    voice_quality::{self, SampleDecision, OUTLIER_SIMILARITY},
};
use crate::error::{EnclaveError, Result};
pub(crate) const EMBEDDING_DIM: usize = 256;

pub(crate) fn encode_embedding(vector: &[f32]) -> Result<Vec<u8>> {
    validate_embedding(vector)?;
    Ok(vector
        .iter()
        .flat_map(|value| value.to_le_bytes())
        .collect())
}
pub(crate) fn decode_embedding(bytes: &[u8]) -> Result<Vec<f32>> {
    if bytes.len() != EMBEDDING_DIM * 4 {
        return Err(EnclaveError::Embedding(
            "voice embedding byte length is invalid".into(),
        ));
    }
    let values = bytes
        .chunks_exact(4)
        .map(|chunk| f32::from_le_bytes(chunk.try_into().expect("four-byte chunk")))
        .collect::<Vec<_>>();
    validate_embedding(&values)?;
    Ok(values)
}
fn validate_embedding(vector: &[f32]) -> Result<()> {
    let norm = vector.iter().map(|x| x * x).sum::<f32>();
    if vector.len() != EMBEDDING_DIM
        || vector.iter().any(|x| !x.is_finite())
        || (norm - 1.0).abs() > 0.01
    {
        return Err(EnclaveError::Embedding(
            "voice embedding dimensions or unit norm are invalid".into(),
        ));
    }
    Ok(())
}

/// Platform is fixed by capture stream. Remote system audio has its own route;
/// known microphone routes retain their names; unknown/missing route values get
/// isolated domains instead of being folded into a known acoustic domain.
pub(crate) fn channel_domain(
    stream_kind: &str,
    audio_role: Option<&str>,
    audio_route: Option<&str>,
) -> String {
    let platform = match stream_kind {
        "ios_mic" => "ios",
        "mic" | "system_audio" => "macos",
        _ => "unknown",
    };
    let route = if stream_kind == "system_audio" && audio_role == Some("remote_received") {
        "system_output".to_owned()
    } else {
        match audio_route {
            Some("builtin_mic" | "wired_headset" | "bluetooth_headset" | "system_output") => {
                audio_route.unwrap().to_owned()
            }
            Some(value) => format!("unknown-{value}"),
            None => "unknown".into(),
        }
    };
    format!("{platform}:{route}")
}

/// Reject reversed/negative/outside boundaries instead of indexing past decoded
/// media. Valid long turns are capped at the model's 30-second policy bound.
pub(crate) fn guarded_samples(samples: &[f32], start_ms: i64, end_ms: i64) -> Result<&[f32]> {
    if start_ms < 0 || end_ms <= start_ms {
        return Err(EnclaveError::Embedding(
            "voice source slice boundary is invalid".into(),
        ));
    }
    let start = usize::try_from(start_ms)
        .ok()
        .and_then(|v| v.checked_mul(16));
    let end = usize::try_from(end_ms).ok().and_then(|v| v.checked_mul(16));
    match (start, end) {
        (Some(start), Some(end)) if start < samples.len() && end <= samples.len() => {
            Ok(&samples[start..end.min(start.saturating_add(MAX_TURN_SAMPLES))])
        }
        _ => Err(EnclaveError::Embedding(
            "voice source slice exceeds decoded media".into(),
        )),
    }
}
#[derive(Debug, PartialEq)]
pub(crate) enum ContinuityDecision {
    Match(i64),
    Create,
    Abstain,
}
pub(crate) fn decide_continuity(
    scores: &[(i64, f32)],
    eligibility: SampleDecision,
) -> (ContinuityDecision, Option<f32>, Option<f32>) {
    if !matches!(
        eligibility,
        SampleDecision::Enroll | SampleDecision::MatchOnly
    ) {
        return (ContinuityDecision::Abstain, None, None);
    }
    let mut scores = scores
        .iter()
        .copied()
        .filter(|(_, value)| value.is_finite())
        .collect::<Vec<_>>();
    scores.sort_by(|a, b| b.1.total_cmp(&a.1).then(a.0.cmp(&b.0)));
    let Some(&(id, best)) = scores.first() else {
        return (
            if eligibility == SampleDecision::Enroll {
                ContinuityDecision::Create
            } else {
                ContinuityDecision::Abstain
            },
            None,
            None,
        );
    };
    let margin = best - scores.get(1).map_or(-1.0, |(_, score)| *score);
    let decision = if best >= MATCH_THRESHOLD && margin >= MIN_DECISION_MARGIN {
        ContinuityDecision::Match(id)
    } else if best < NEW_PROFILE_THRESHOLD && eligibility == SampleDecision::Enroll {
        ContinuityDecision::Create
    } else {
        ContinuityDecision::Abstain
    };
    (decision, Some(best), Some(margin))
}

/// Candidate scopes are complete or held, never truncated to choose a winner.
pub(crate) const MAX_CANDIDATE_PROFILES: usize = 512;
pub(crate) const MIN_STABLE_OBSERVATIONS: usize = 3;
pub(crate) const IDENTITY_DERIVATION_VERSION: i64 = 3;

/// Same-recording continuity has priority. If it cannot decide, compare the
/// complete union with account-wide stable candidates before creating anything.
/// A broader empty scope must never erase a narrower scope's ambiguity.
pub(crate) fn decide_scoped_continuity(
    session_scores: &[(i64, f32)],
    account_scores: &[(i64, f32)],
    eligibility: SampleDecision,
) -> (ContinuityDecision, Option<f32>, Option<f32>) {
    if session_scores.len() > MAX_CANDIDATE_PROFILES {
        return (ContinuityDecision::Abstain, None, None);
    }
    let session = decide_continuity(session_scores, eligibility);
    if matches!(session.0, ContinuityDecision::Match(_)) {
        return session;
    }
    if account_scores.len() > MAX_CANDIDATE_PROFILES {
        return (ContinuityDecision::Abstain, None, None);
    }
    let mut combined = std::collections::BTreeMap::new();
    for &(id, score) in session_scores.iter().chain(account_scores) {
        if !score.is_finite()
            || combined
                .insert(id, score)
                .is_some_and(|previous| previous != score)
        {
            return (ContinuityDecision::Abstain, None, None);
        }
    }
    if combined.len() > MAX_CANDIDATE_PROFILES {
        return (ContinuityDecision::Abstain, None, None);
    }
    decide_continuity(&combined.into_iter().collect::<Vec<_>>(), eligibility)
}

pub(crate) struct Representative {
    pub medoid_sample_id: i64,
    pub centroid: Vec<f32>,
    pub sample_count: i64,
    pub retained_sample_ids: Vec<i64>,
}
pub(crate) fn representative(samples: &[(i64, Vec<f32>)]) -> Result<Option<Representative>> {
    if samples.is_empty() {
        return Ok(None);
    }
    for (_, sample) in samples {
        validate_embedding(sample)?;
    }
    // Cosine medoid maximizes sum_j dot(x_i,x_j), which is exactly
    // dot(x_i,sum_j x_j) for unit vectors. Accumulate coordinates once to
    // avoid quadratic work as a capture session gains enrollment samples.
    let mut ordered = samples.iter().collect::<Vec<_>>();
    ordered.sort_by_key(|(id, _)| *id);
    let mut coordinate_sum = vec![0.0_f64; EMBEDDING_DIM];
    for (_, sample) in &ordered {
        for (sum, value) in coordinate_sum.iter_mut().zip(sample) {
            *sum += f64::from(*value);
        }
    }
    let score = |vector: &[f32]| {
        vector
            .iter()
            .zip(&coordinate_sum)
            .map(|(value, sum)| f64::from(*value) * sum)
            .sum::<f64>()
    };
    let medoid = ordered
        .iter()
        .copied()
        .max_by(|a, b| {
            score(&a.1)
                .total_cmp(&score(&b.1))
                .then_with(|| b.0.cmp(&a.0))
        })
        .expect("nonempty samples");
    let accepted = ordered
        .iter()
        .copied()
        .filter(|(_, embedding)| voice_quality::cosine(&medoid.1, embedding) >= OUTLIER_SIMILARITY)
        .collect::<Vec<_>>();
    let mut centroid = vec![0.0; EMBEDDING_DIM];
    for (_, sample) in &accepted {
        for (sum, value) in centroid.iter_mut().zip(sample) {
            *sum += value;
        }
    }
    voice_quality::normalize(&mut centroid)?;
    Ok(Some(Representative {
        medoid_sample_id: medoid.0,
        centroid,
        sample_count: accepted.len() as i64,
        retained_sample_ids: accepted.iter().map(|(id, _)| *id).collect(),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    fn axis(index: usize) -> Vec<f32> {
        let mut value = vec![0.; EMBEDDING_DIM];
        value[index] = 1.;
        value
    }
    #[test]
    fn byte_codec_is_little_endian_and_rejects_invalid_vectors() {
        let vector = axis(0);
        let bytes = encode_embedding(&vector).unwrap();
        assert_eq!(
            &bytes[..4],
            &1.0f32.to_le_bytes(),
            "voice codec must use little endian f32"
        );
        assert_eq!(decode_embedding(&bytes).unwrap(), vector);
        assert!(
            decode_embedding(&bytes[..1023]).is_err(),
            "voice codec must reject truncated vectors"
        );
        let mut bad = bytes;
        bad[..4].copy_from_slice(&f32::NAN.to_le_bytes());
        assert!(decode_embedding(&bad).is_err());
    }
    #[test]
    fn continuity_abstains_on_ambiguity_and_match_only_cannot_create() {
        assert_eq!(
            decide_continuity(&[(1, 0.7), (2, 0.66)], SampleDecision::Enroll).0,
            ContinuityDecision::Abstain,
            "ambiguous voices must remain unassigned"
        );
        assert_eq!(
            decide_continuity(&[(1, 0.7), (2, 0.5)], SampleDecision::Enroll).0,
            ContinuityDecision::Match(1)
        );
        assert_eq!(
            decide_continuity(&[(1, 0.44)], SampleDecision::Enroll).0,
            ContinuityDecision::Create
        );
        assert_eq!(
            decide_continuity(&[(1, 0.45)], SampleDecision::Enroll).0,
            ContinuityDecision::Abstain
        );
        assert_eq!(
            decide_continuity(&[], SampleDecision::MatchOnly).0,
            ContinuityDecision::Abstain,
            "match-only samples must not create profiles"
        );
    }
    #[test]
    fn scoped_continuity_checks_account_before_creation_and_keeps_earlier_ambiguity() {
        assert_eq!(
            decide_scoped_continuity(&[], &[(7, 0.75)], SampleDecision::Enroll).0,
            ContinuityDecision::Match(7),
            "a new recording must check the account before creating a duplicate voice"
        );
        assert_eq!(
            decide_scoped_continuity(&[(1, 0.7), (2, 0.66)], &[], SampleDecision::Enroll).0,
            ContinuityDecision::Abstain,
            "an empty global scope must preserve same-recording ambiguity"
        );
        assert_eq!(
            decide_scoped_continuity(&[(1, 0.7), (2, 0.66)], &[(3, 0.9)], SampleDecision::Enroll).0,
            ContinuityDecision::Match(3)
        );
        assert_eq!(
            decide_scoped_continuity(&[(1, 0.7)], &[(2, 0.99)], SampleDecision::Enroll).0,
            ContinuityDecision::Match(1),
            "confident same-recording continuity must retain scope priority"
        );
        assert_eq!(
            decide_scoped_continuity(&[(1, 0.44)], &[(1, 0.44), (2, 0.3)], SampleDecision::Enroll)
                .0,
            ContinuityDecision::Create
        );
        assert_eq!(
            decide_scoped_continuity(&[], &[], SampleDecision::MatchOnly).0,
            ContinuityDecision::Abstain
        );
    }

    #[test]
    fn scoped_continuity_holds_overflow_and_deduplicates_the_same_profile() {
        let overflow = (0..=MAX_CANDIDATE_PROFILES)
            .map(|i| (i as i64, 0.1))
            .collect::<Vec<_>>();
        assert_eq!(
            decide_scoped_continuity(&[], &overflow, SampleDecision::Enroll).0,
            ContinuityDecision::Abstain,
            "a partial account candidate population must not create a voice"
        );
        assert_eq!(
            decide_scoped_continuity(&overflow, &[], SampleDecision::Enroll).0,
            ContinuityDecision::Abstain,
            "a partial session candidate population must not create a voice"
        );
        assert_eq!(
            decide_scoped_continuity(&[(1, 0.55)], &[(1, 0.55), (2, 0.7)], SampleDecision::Enroll)
                .0,
            ContinuityDecision::Match(2)
        );
        assert_eq!(
            decide_scoped_continuity(&[(1, 0.55)], &[(1, 0.75)], SampleDecision::Enroll).0,
            ContinuityDecision::Abstain,
            "conflicting scores for one profile must hold the decision"
        );
    }

    #[test]
    fn representative_trims_outlier_and_breaks_medoid_ties_by_id() {
        let rep = representative(&[(2, axis(0)), (1, axis(0)), (3, axis(1))])
            .unwrap()
            .unwrap();
        assert_eq!(rep.medoid_sample_id, 1);
        assert_eq!(rep.centroid, axis(0));
        assert_eq!(
            rep.retained_sample_ids,
            vec![1, 2],
            "stability must use only the exact trimmed representative members"
        );
        assert_eq!(
            rep.sample_count, 2,
            "outliers must not contribute to centroid sample count"
        );
        assert!(representative(&[]).unwrap().is_none());
    }
    #[test]
    fn domains_isolate_platforms_and_unknown_routes() {
        assert_eq!(
            channel_domain("ios_mic", None, Some("builtin_mic")),
            "ios:builtin_mic"
        );
        assert_eq!(
            channel_domain("system_audio", Some("remote_received"), None),
            "macos:system_output"
        );
        assert_ne!(
            channel_domain("mic", None, Some("mystery")),
            channel_domain("mic", None, None)
        );
        assert_ne!(
            channel_domain("mic", None, Some("builtin_mic")),
            channel_domain("ios_mic", None, Some("builtin_mic"))
        );
    }
    #[test]
    fn source_slice_rejects_bad_offsets_without_panicking() {
        let samples = vec![0.; 16000];
        assert!(
            guarded_samples(&samples, 2000, 3000).is_err(),
            "out-of-range voice slices must fail without panic"
        );
        assert!(guarded_samples(&samples, 800, 500).is_err());
        assert!(guarded_samples(&samples, -1, 500).is_err());
        assert_eq!(guarded_samples(&samples, 100, 500).unwrap().len(), 6400);
    }
    #[test]
    fn linear_medoid_matches_pairwise_objective_and_is_permutation_stable() {
        let mut examples = (1..=9)
            .map(|id| {
                let mut vector = (0..EMBEDDING_DIM)
                    .map(|i| ((i * 7 + id * 11) as f32 / 19.0).sin())
                    .collect::<Vec<_>>();
                voice_quality::normalize(&mut vector).unwrap();
                (id as i64, vector)
            })
            .collect::<Vec<_>>();
        let pairwise_score = |value: &[f32]| {
            examples
                .iter()
                .map(|(_, other)| {
                    value
                        .iter()
                        .zip(other)
                        .map(|(a, b)| f64::from(*a) * f64::from(*b))
                        .sum::<f64>()
                })
                .sum::<f64>()
        };
        let expected = examples
            .iter()
            .max_by(|a, b| {
                pairwise_score(&a.1)
                    .total_cmp(&pairwise_score(&b.1))
                    .then_with(|| b.0.cmp(&a.0))
            })
            .unwrap()
            .0;
        let first = representative(&examples).unwrap().unwrap();
        assert_eq!(
            first.medoid_sample_id, expected,
            "linear medoid must preserve the pairwise cosine objective"
        );
        examples.reverse();
        let reversed = representative(&examples).unwrap().unwrap();
        assert_eq!(first.medoid_sample_id, reversed.medoid_sample_id);
        assert_eq!(
            first.centroid, reversed.centroid,
            "voice representative must not depend on sample ordering"
        );
        let tied = representative(&[(8, axis(0)), (3, axis(1))])
            .unwrap()
            .unwrap();
        assert_eq!(
            tied.medoid_sample_id, 3,
            "equal medoid scores must choose the smallest sample id"
        );
    }
}
