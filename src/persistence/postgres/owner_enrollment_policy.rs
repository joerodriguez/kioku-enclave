//! Deterministic enrollment dominance over the uncapped capture timeline.
use crate::persistence::VoiceEnrollmentReason;
use std::collections::{BTreeMap, BTreeSet};

pub(super) const MAX_ENROLLMENT_MS: i64 = 180_000;
pub(super) const POLICY_VERSION: i64 = 1;

#[derive(Clone, Debug)]
pub(super) struct Speech {
    pub observation: i64,
    pub group: Option<i64>,
    pub start: i64,
    pub end: i64,
    pub overlap: bool,
    pub sample: Option<i64>,
    pub enrollment_eligible: bool,
}
pub(super) struct Decision {
    pub group: i64,
    pub share: f64,
    pub samples: Vec<(i64, i64)>,
}

pub(super) fn decide(speech: &[Speech], start: i64) -> Result<Decision, VoiceEnrollmentReason> {
    let cutoff = start.saturating_add(MAX_ENROLLMENT_MS);
    let spans = speech
        .iter()
        .filter_map(|s| {
            let a = s.start.max(start);
            let b = s.end.min(cutoff);
            (b > a).then_some((s, a, b))
        })
        .collect::<Vec<_>>();
    let points = spans
        .iter()
        .flat_map(|(_, a, b)| [*a, *b])
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    let mut total = 0_i64;
    let mut by_group = BTreeMap::<i64, i64>::new();
    for pair in points.windows(2) {
        let active = spans
            .iter()
            .filter(|(_, a, b)| *a < pair[1] && *b > pair[0])
            .collect::<Vec<_>>();
        if active.is_empty() {
            continue;
        }
        let length = pair[1] - pair[0];
        total += length;
        let groups = active
            .iter()
            .map(|(s, _, _)| s.group)
            .collect::<BTreeSet<_>>();
        if groups.len() == 1 && !active.iter().any(|(s, _, _)| s.overlap) {
            if let Some(group) = groups.first().copied().flatten() {
                *by_group.entry(group).or_default() += length;
            }
        }
    }
    if total == 0 {
        return Err(VoiceEnrollmentReason::NoSpeech);
    }
    let Some((group, duration)) = by_group
        .into_iter()
        .max_by_key(|(id, duration)| (*duration, std::cmp::Reverse(*id)))
    else {
        return Err(VoiceEnrollmentReason::NoDominantVoice);
    };
    if i128::from(duration) * 100 < i128::from(total) * 90 {
        return Err(VoiceEnrollmentReason::NoDominantVoice);
    }
    let samples = spans
        .iter()
        .filter_map(|(s, a, b)| {
            let clean = !s.overlap
                && !spans
                    .iter()
                    .any(|(other, c, d)| other.observation != s.observation && a < d && b > c);
            (s.group == Some(group)
                && s.enrollment_eligible
                && s.start >= start
                && s.end <= cutoff
                && b - a >= 3000
                && clean)
                .then_some(s.sample.map(|sample| (s.observation, sample)))
                .flatten()
        })
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    if samples.is_empty() {
        return Err(
            if spans
                .iter()
                .any(|(s, _, _)| s.group == Some(group) && s.overlap)
            {
                VoiceEnrollmentReason::OverlappingSpeech
            } else {
                VoiceEnrollmentReason::NoEligibleSample
            },
        );
    }
    Ok(Decision {
        group,
        share: duration as f64 / total as f64,
        samples,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    fn speech(id: i64, group: Option<i64>, start: i64, end: i64) -> Speech {
        Speech {
            observation: id,
            group,
            start,
            end,
            overlap: false,
            sample: Some(id),
            enrollment_eligible: true,
        }
    }
    #[test]
    fn enrollment_policy_uses_all_uncapped_speech_and_exact_dominance_boundary() {
        let ninety = [
            speech(1, Some(1), 0, 90_000),
            speech(2, Some(2), 90_000, 100_000),
        ];
        assert_eq!(decide(&ninety,0).unwrap().group,1,"exactly ninety percent of full speech must enroll, irrespective of the model's thirty-second cap");
        let below = [
            speech(1, Some(1), 0, 89_999),
            speech(2, None, 89_999, 100_000),
        ];
        assert!(
            matches!(
                decide(&below, 0),
                Err(VoiceEnrollmentReason::NoDominantVoice)
            ),
            "unknown or failed speech must remain in the enrollment denominator"
        );
    }
    #[test]
    fn enrollment_policy_requires_clean_enrollment_sample_and_rejects_overlap() {
        let mut sample = speech(1, Some(1), 0, 10_000);
        sample.enrollment_eligible = false;
        assert!(
            matches!(
                decide(&[sample.clone()], 0),
                Err(VoiceEnrollmentReason::NoEligibleSample)
            ),
            "match-only speech must never enroll an owner"
        );
        sample.enrollment_eligible = true;
        sample.overlap = true;
        assert!(
            decide(&[sample], 0).is_err(),
            "overlapping speech must never create clean owner enrollment evidence"
        );
    }
    #[test]
    fn enrollment_policy_clips_first_three_minutes_and_is_order_independent() {
        let mut spans = vec![
            speech(1, Some(1), 0, 90_000),
            speech(2, Some(1), 90_000, 180_000),
            speech(3, Some(2), 180_000, 360_000),
        ];
        let before =
            decide(&spans, 0).expect("the first three minutes contain one eligible dominant voice");
        assert_eq!(
            (before.group, before.share, before.samples.clone()),
            (1, 1.0, vec![(1, 1), (2, 2)]),
            "only the complete first-three-minute window may contribute enrollment samples"
        );
        spans.reverse();
        let after = decide(&spans, 0).unwrap();
        assert_eq!(
            (before.group, before.share, before.samples),
            (after.group, after.share, after.samples),
            "arrival order and post-cutoff voices must not change enrollment"
        );
    }
    #[test]
    fn enrollment_policy_does_not_count_duplicate_time_twice() {
        let spans = [
            speech(1, Some(1), 0, 85_000),
            speech(1, Some(1), 0, 85_000),
            speech(2, Some(2), 85_000, 100_000),
        ];
        assert!(
            matches!(
                decide(&spans, 0),
                Err(VoiceEnrollmentReason::NoDominantVoice)
            ),
            "duplicated source spans must not manufacture ninety-percent dominance"
        );
    }
    #[test]
    fn enrollment_policy_never_enrolls_an_embedding_crossing_the_capture_cutoff() {
        let crossing = speech(2, Some(1), 175_000, 205_000);
        assert!(matches!(decide(std::slice::from_ref(&crossing),0),Err(VoiceEnrollmentReason::NoEligibleSample)),"a five-second clipped interval cannot enroll its thirty-second embedding that includes post-cutoff audio");
        let valid = speech(1, Some(1), 0, 10_000);
        assert_eq!(decide(&[valid,crossing],0).unwrap().samples,vec![(1,1)],"crossing speech belongs in dominance but its untrimmed embedding must stay outside enrollment evidence");
    }
}
