//! Pure acoustic reconciliation policy. Names never enter this policy.
use super::{
    voice_identity::{
        decide_continuity, representative, ContinuityDecision, MIN_STABLE_OBSERVATIONS,
    },
    voice_memory::{MATCH_THRESHOLD, MIN_DECISION_MARGIN, NEW_PROFILE_THRESHOLD},
    voice_quality::{cosine, SampleDecision},
};
use crate::error::Result;
use std::collections::BTreeSet;

/// Reciprocal stable merges and the name-snapshot commitment: unchanged.
pub(crate) const POLICY_VERSION: i64 = 1;
/// Tentative-fragment absorption proposals carry their own policy version.
pub(crate) const ABSORPTION_POLICY_VERSION: i64 = 2;
pub(crate) const MAX_PROFILES: usize = 64;
pub(crate) const MAX_SAMPLES: usize = 256;
pub(crate) const MAX_PROPOSALS: usize = 4;
/// Fragments examined per pass, newest first; the bound above applies to the
/// competitors they are judged against, never to the fragments themselves.
pub(crate) const MAX_FRAGMENTS: usize = 16;
pub(crate) const MERGE_REASON: &str = "mutual_clean_support";
pub(crate) const ABSORPTION_REASON: &str = "tentative_absorbed";

#[derive(Clone)]
pub(crate) struct Profile {
    pub id: i64,
    pub space: String,
    pub scorer: i64,
    pub domain: String,
    pub person: Option<i64>,
    pub person_status: Option<String>,
    pub centroid: Vec<f32>,
    // Complete clean enrollment support, with one row per source observation.
    pub samples: Vec<(i64, Vec<f32>)>,
    pub membership_complete: bool,
    /// The profile's durable status is `stable`: what account-wide matching
    /// would already have offered as a candidate.
    pub stable: bool,
    /// Every recording behind the profile's support has finished, so no later
    /// sample of the same recording can still make it stable on its own.
    pub settled: bool,
}
fn compatible(a: &Profile, b: &Profile) -> bool {
    a.space == b.space && a.scorer == b.scorer && a.domain == b.domain
}
fn owner(p: &Profile) -> bool {
    p.person_status.as_deref() == Some("owner")
}
fn named(p: &Profile) -> bool {
    p.person_status.as_deref() == Some("identified")
}
fn observations(p: &Profile) -> usize {
    p.samples.iter().map(|s| s.0).collect::<BTreeSet<_>>().len()
}
fn eligible(p: &Profile) -> bool {
    !owner(p)
        && p.person_status.as_deref() != Some("quarantined")
        && p.membership_complete
        && p.samples.len() <= MAX_SAMPLES
        && observations(p) >= MIN_STABLE_OBSERVATIONS
        && !has_distinct_modes(&p.samples).unwrap_or(true)
}
/// A non-owner profile short of stability: what a two-sentence appearance
/// leaves behind. Such profiles are never competitors for absorption, whether
/// or not they can be absorbed themselves.
fn fragment_like(p: &Profile) -> bool {
    !owner(p)
        && p.person_status.as_deref() != Some("quarantined")
        && !p.stable
        && !p.samples.is_empty()
        && observations(p) < MIN_STABLE_OBSERVATIONS
}
/// A fragment that may be absorbed: complete clean support from recordings
/// that have all finished, so no later sample of its own recording could still
/// have made it stable and only a reciprocal merge could then have joined it.
fn tentative(p: &Profile) -> bool {
    fragment_like(p) && p.membership_complete && p.settled && p.samples.len() <= MAX_SAMPLES
}

/// Three independent observations in each of two separated modes, with each
/// mode accounting for at least a quarter of the complete clean support. A few
/// outliers never trigger a split or name assignment.
pub(crate) fn has_distinct_modes(samples: &[(i64, Vec<f32>)]) -> Result<bool> {
    if samples.len() < MIN_STABLE_OBSERVATIONS * 2 {
        return Ok(false);
    }
    let Some(first) = representative(samples)? else {
        return Ok(false);
    };
    let rest = samples
        .iter()
        .filter(|s| !first.retained_sample_ids.contains(&s.0))
        .cloned()
        .collect::<Vec<_>>();
    let Some(second) = representative(&rest)? else {
        return Ok(false);
    };
    let enough =
        |count: i64| count >= MIN_STABLE_OBSERVATIONS as i64 && count * 4 >= samples.len() as i64;
    Ok(enough(first.sample_count)
        && enough(second.sample_count)
        && cosine(&first.centroid, &second.centroid) < NEW_PROFILE_THRESHOLD)
}

/// Every clean observation must pick the same other profile at the ordinary
/// threshold and margin. All compatible profiles remain competitors, including
/// owner or oversized profiles that cannot themselves be merged.
fn nearest(p: &Profile, profiles: &[Profile]) -> Option<(i64, f32, f32)> {
    if !eligible(p) {
        return None;
    }
    let mut winner = None;
    let mut minimum_score = 1.0_f32;
    let mut minimum_margin = 2.0_f32;
    for (_, sample) in &p.samples {
        let mut scores = profiles
            .iter()
            .filter(|other| other.id != p.id && compatible(p, other))
            .map(|other| (other.id, cosine(sample, &other.centroid)))
            .collect::<Vec<_>>();
        scores.sort_by(|a, b| b.1.total_cmp(&a.1).then(a.0.cmp(&b.0)));
        let &(id, score) = scores.first()?;
        let margin = score - scores.get(1).map_or(-1.0, |r| r.1);
        if !score.is_finite()
            || score < MATCH_THRESHOLD
            || margin < MIN_DECISION_MARGIN
            || winner.is_some_and(|previous| previous != id)
        {
            return None;
        }
        winner = Some(id);
        minimum_score = minimum_score.min(score);
        minimum_margin = minimum_margin.min(margin);
    }
    winner.map(|id| (id, minimum_score, minimum_margin))
}
#[derive(Debug, PartialEq)]
pub(crate) struct Merge {
    pub left: i64,
    pub right: i64,
    pub minimum_score: f32,
    pub minimum_margin: f32,
}
pub(crate) fn acoustic_pairs(profiles: &[Profile]) -> Vec<Merge> {
    if profiles.len() > MAX_PROFILES {
        return Vec::new();
    }
    let mut pairs = Vec::new();
    for left in profiles {
        let Some((right_id, score, margin)) = nearest(left, profiles) else {
            continue;
        };
        if left.id >= right_id {
            continue;
        }
        let Some(right) = profiles.iter().find(|p| p.id == right_id) else {
            continue;
        };
        if !eligible(right) {
            continue;
        }
        let Some((reverse, reverse_score, reverse_margin)) = nearest(right, profiles) else {
            continue;
        };
        if reverse != left.id {
            continue;
        }
        pairs.push(Merge {
            left: left.id,
            right: right.id,
            minimum_score: score.min(reverse_score),
            minimum_margin: margin.min(reverse_margin),
        });
    }
    pairs.sort_by_key(|pair| (pair.left, pair.right));
    pairs
}

fn name_compatible(profiles: &[Profile], pair: &Merge) -> bool {
    let left = profiles
        .iter()
        .find(|p| p.id == pair.left)
        .expect("acoustic member");
    let right = profiles
        .iter()
        .find(|p| p.id == pair.right)
        .expect("acoustic member");
    !(named(left) && named(right) && left.person != right.person)
}

/// Acoustic qualification remains visible to name-conflict handling; identity
/// permission is a separate filter and never changes the competitor population.
pub(crate) fn merge_pairs(profiles: &[Profile]) -> Vec<Merge> {
    acoustic_pairs(profiles)
        .into_iter()
        .filter(|pair| name_compatible(profiles, pair))
        .collect()
}

/// A tentative fragment is absorbed by the stable profile that every one of its
/// clean samples would have matched under the ordinary decision had that
/// profile existed when the sample arrived: the owner's profiles are tried
/// first exactly as the live matcher tries them (a sample the owner path would
/// claim holds the fragment), then the match threshold with the runner-up
/// margin against every compatible non-fragment profile — stable, owner or
/// quarantined — so an owner profile can block an absorption but never receive
/// one. Other fragments are runner-ups with tolerance rather than competitors:
/// one that beats the stable profile by more than the margin holds the decision
/// (the sample more likely belongs with that not-yet-stable voice), while the
/// fragments one voice leaves across short recordings, closer to each other
/// than to their stable profile by less than the margin, are absorbed one
/// proposal at a time instead of holding each other hostage. The target must
/// be merge-eligible and durably stable; a named fragment joins only a profile
/// already bound to the same person, so one sample never names a voice.
/// The profiles a fragment is judged against; the population bound counts
/// these and never the fragments themselves.
pub(crate) fn competitor_count(profiles: &[Profile]) -> usize {
    profiles.iter().filter(|p| !fragment_like(p)).count()
}

pub(crate) fn absorption_pairs(profiles: &[Profile]) -> Vec<Merge> {
    if competitor_count(profiles) > MAX_PROFILES {
        return Vec::new();
    }
    let mut pairs = Vec::new();
    for fragment in profiles.iter().filter(|p| tentative(p)) {
        let competitors = profiles
            .iter()
            .filter(|other| {
                other.id != fragment.id && compatible(fragment, other) && !fragment_like(other)
            })
            .collect::<Vec<_>>();
        let alternatives = profiles
            .iter()
            .filter(|other| {
                other.id != fragment.id && compatible(fragment, other) && fragment_like(other)
            })
            .collect::<Vec<_>>();
        let mut target = None;
        let mut minimum_score = 1.0_f32;
        let mut minimum_margin = 2.0_f32;
        let mut unanimous = true;
        for (_, sample) in &fragment.samples {
            let owner_scores = competitors
                .iter()
                .filter(|other| owner(other))
                .map(|other| (other.id, cosine(sample, &other.centroid)))
                .collect::<Vec<_>>();
            if matches!(
                decide_continuity(&owner_scores, SampleDecision::MatchOnly).0,
                ContinuityDecision::Match(_)
            ) {
                unanimous = false;
                break;
            }
            let mut scores = competitors
                .iter()
                .map(|other| (other.id, cosine(sample, &other.centroid)))
                .collect::<Vec<_>>();
            scores.sort_by(|a, b| b.1.total_cmp(&a.1).then(a.0.cmp(&b.0)));
            let Some(&(id, score)) = scores.first() else {
                unanimous = false;
                break;
            };
            let margin = score - scores.get(1).map_or(-1.0, |r| r.1);
            let closest_alternative = alternatives
                .iter()
                .map(|other| cosine(sample, &other.centroid))
                .fold(-1.0_f32, f32::max);
            if !score.is_finite()
                || score < MATCH_THRESHOLD
                || margin < MIN_DECISION_MARGIN
                || score + MIN_DECISION_MARGIN < closest_alternative
                || target.is_some_and(|previous| previous != id)
            {
                unanimous = false;
                break;
            }
            target = Some(id);
            minimum_score = minimum_score.min(score);
            minimum_margin = minimum_margin.min(margin);
        }
        if !unanimous {
            continue;
        }
        let Some(stable) = target.and_then(|id| profiles.iter().find(|p| p.id == id)) else {
            continue;
        };
        if !eligible(stable) || !stable.stable {
            continue;
        }
        if named(fragment) && !(named(stable) && stable.person == fragment.person) {
            continue;
        }
        let pair = Merge {
            left: fragment.id.min(stable.id),
            right: fragment.id.max(stable.id),
            minimum_score,
            minimum_margin,
        };
        if name_compatible(profiles, &pair) {
            pairs.push(pair);
        }
    }
    pairs.sort_by_key(|pair| (pair.left, pair.right));
    pairs
}

#[cfg(test)]
mod tests {
    use super::*;
    fn vector(a: f32, b: f32) -> Vec<f32> {
        let mut v = vec![0.; 256];
        v[0] = a;
        v[1] = b;
        v
    }
    fn profile(id: i64, a: f32, b: f32) -> Profile {
        Profile {
            id,
            space: "space".into(),
            scorer: 2,
            domain: "domain".into(),
            person: None,
            person_status: None,
            centroid: vector(a, b),
            samples: (1..=3).map(|i| (i, vector(a, b))).collect(),
            membership_complete: true,
            stable: true,
            settled: true,
        }
    }
    fn fragment_profile(id: i64, a: f32, b: f32, samples: usize) -> Profile {
        let mut p = profile(id, a, b);
        p.samples.truncate(samples);
        p.stable = false;
        p
    }
    #[test]
    fn merges_require_reciprocal_many_sample_support_and_complete_competitors() {
        let a = profile(1, 1., 0.);
        let b = profile(2, 0.8, 0.6);
        assert_eq!(
            merge_pairs(&[a, b]).len(),
            1,
            "mutually nearest clean voices must yield a proposal"
        );
        let mut b = profile(2, 0.8, 0.6);
        b.samples.truncate(2);
        assert!(
            merge_pairs(&[profile(1, 1., 0.), b]).is_empty(),
            "two samples must not establish a merge"
        );
        let mut b = profile(2, 0.8, 0.6);
        b.samples[2].1 = vector(0., 1.);
        assert!(
            merge_pairs(&[profile(1, 1., 0.), b]).is_empty(),
            "one-way or contradictory support must never merge"
        );
        assert!(
            merge_pairs(&[
                profile(1, 1., 0.),
                profile(2, 0.8, 0.6),
                profile(3, 0.8, 0.6)
            ])
            .iter()
            .all(|pair| pair.left != 1 && pair.right != 1),
            "a tied runner-up must hold the ambiguous voice"
        );
        let mut b = profile(2, 0.8, 0.6);
        b.membership_complete = false;
        assert!(
            merge_pairs(&[profile(1, 1., 0.), b]).is_empty(),
            "incomplete membership must never be applied as a full proposal"
        );
        let mut all = (1..=MAX_PROFILES as i64 + 1)
            .map(|id| {
                let mut p = profile(id, 0., 1.);
                p.domain = format!("domain-{id}");
                p
            })
            .collect::<Vec<_>>();
        all[0] = profile(1, 1., 0.);
        all[1] = profile(2, 0.8, 0.6);
        assert!(
            merge_pairs(&all).is_empty(),
            "candidate overflow must hold all merge decisions"
        );
    }
    #[test]
    fn identities_and_domains_are_independent_of_display_names() {
        for (left_status, right_status, left_person, right_person, expected) in [
            ("identified", "identified", Some(1), Some(2), 0),
            ("identified", "identified", Some(1), Some(1), 1),
            ("recurring", "recurring", Some(1), Some(2), 1),
            ("identified", "recurring", Some(1), Some(2), 1),
            ("owner", "recurring", Some(1), Some(2), 0),
        ] {
            let mut a = profile(1, 1., 0.);
            let mut b = profile(2, 0.8, 0.6);
            a.person_status = Some(left_status.into());
            b.person_status = Some(right_status.into());
            a.person = left_person;
            b.person = right_person;
            assert_eq!(
                merge_pairs(&[a, b]).len(),
                expected,
                "only compatible nonconflicting opaque identities may merge"
            );
        }
        let mut b = profile(2, 0.8, 0.6);
        b.domain = "other".into();
        assert!(
            merge_pairs(&[profile(1, 1., 0.), b]).is_empty(),
            "acoustic domains must never be compared for merging"
        );
        let mut b = profile(2, 0.8, 0.6);
        b.space = "other".into();
        assert!(
            merge_pairs(&[profile(1, 1., 0.), b]).is_empty(),
            "embedding spaces must never be compared for merging"
        );
        let mut b = profile(2, 0.8, 0.6);
        b.scorer = 3;
        assert!(
            merge_pairs(&[profile(1, 1., 0.), b]).is_empty(),
            "scorer versions must never be compared for merging"
        );
    }
    #[test]
    fn a_tentative_fragment_is_absorbed_only_by_the_stable_voice_every_sample_matches() {
        let stable = profile(1, 1., 0.);
        let fragment = fragment_profile(2, 0.95, 0.312, 1);
        assert!(
            merge_pairs(&[stable.clone(), fragment.clone()]).is_empty(),
            "a one-sample profile can never be a reciprocal merge partner"
        );
        let pairs = absorption_pairs(&[stable.clone(), fragment.clone()]);
        assert_eq!(pairs.len(), 1);
        assert_eq!((pairs[0].left, pairs[0].right), (1, 2));
        assert!(pairs[0].minimum_score >= MATCH_THRESHOLD);
        // A second stable voice close enough to erase the margin holds it.
        let rival = profile(3, 0.8, 0.6);
        assert!(
            absorption_pairs(&[stable.clone(), fragment.clone(), rival]).is_empty(),
            "an ambiguous fragment stays where it is"
        );
        // Another fragment of the same voice is a runner-up with tolerance, not
        // a competitor: both are proposed against the stable profile.
        let twin = fragment_profile(4, 0.95, 0.312, 2);
        let pairs = absorption_pairs(&[stable.clone(), fragment.clone(), twin]);
        assert_eq!(
            pairs.iter().map(|p| (p.left, p.right)).collect::<Vec<_>>(),
            vec![(1, 2), (1, 4)]
        );
        // A fragment much closer to another fragment than to the stable voice is
        // held: the sample more likely belongs with that not-yet-stable voice.
        let near_fragment = fragment_profile(6, 0.62, 0.785, 2);
        let drifting = fragment_profile(7, 0.62, 0.785, 1);
        assert!(
            absorption_pairs(&[stable.clone(), near_fragment, drifting]).is_empty(),
            "a closer fragment beyond the margin holds the decision"
        );
        // Two samples that disagree on the target hold.
        let mut split = fragment_profile(8, 0.95, 0.312, 2);
        split.samples[1].1 = vector(0.8, 0.6);
        let far_rival = profile(9, 0.6, 0.8);
        assert!(absorption_pairs(&[stable.clone(), far_rival, split]).is_empty());
        // The owner blocks and never receives; the owner path is tried first.
        let mut owner_profile = profile(5, 0.92, 0.39);
        owner_profile.person_status = Some("owner".into());
        owner_profile.person = Some(1);
        assert!(
            absorption_pairs(&[stable.clone(), fragment.clone(), owner_profile.clone()]).is_empty(),
            "a fragment nearest the owner's voice is held, never absorbed by it"
        );
        let mut owner_second = owner_profile.clone();
        owner_second.centroid = vector(0.8, 0.6);
        assert!(
            absorption_pairs(&[stable.clone(), fragment.clone(), owner_second]).is_empty(),
            "a sample the owner path would claim at the match threshold is held even when the stable voice scores higher"
        );
        let mut far_owner = owner_profile.clone();
        far_owner.centroid = vector(0., 1.);
        assert_eq!(
            absorption_pairs(&[stable.clone(), fragment.clone(), far_owner]).len(),
            1,
            "a distant owner profile does not block an unambiguous absorption"
        );
        // A quarantined target never receives, nor does a profile the account
        // still records as tentative, however many clean samples policy sees.
        let mut held = stable.clone();
        held.person_status = Some("quarantined".into());
        assert!(absorption_pairs(&[held, fragment.clone()]).is_empty());
        let mut not_yet_stable = stable.clone();
        not_yet_stable.stable = false;
        assert!(
            absorption_pairs(&[not_yet_stable, fragment.clone()]).is_empty(),
            "only a durably stable profile can receive a fragment"
        );
        // A named fragment joins only the same person; an unnamed stable voice
        // is never named by one sample. Incomplete or unsettled fragments are
        // not absorbed but still do not compete.
        let mut named_stable = stable.clone();
        named_stable.person_status = Some("identified".into());
        named_stable.person = Some(1);
        let mut named_fragment = fragment.clone();
        named_fragment.person_status = Some("identified".into());
        named_fragment.person = Some(2);
        assert!(absorption_pairs(&[named_stable.clone(), named_fragment.clone()]).is_empty());
        assert!(absorption_pairs(&[stable.clone(), named_fragment.clone()]).is_empty());
        named_fragment.person = Some(1);
        assert_eq!(absorption_pairs(&[named_stable, named_fragment]).len(), 1);
        let mut incomplete = fragment.clone();
        incomplete.membership_complete = false;
        assert!(absorption_pairs(&[stable.clone(), incomplete.clone()]).is_empty());
        let mut unsettled = fragment.clone();
        unsettled.settled = false;
        assert!(absorption_pairs(&[stable.clone(), unsettled.clone()]).is_empty());
        assert_eq!(
            absorption_pairs(&[stable.clone(), fragment.clone(), incomplete, unsettled]).len(),
            1,
            "fragments that cannot be absorbed never block one that can"
        );
        let mut weak = fragment.clone();
        weak.samples = vec![(2, vector(0.5, 0.866))];
        assert!(absorption_pairs(&[stable.clone(), weak]).is_empty());
        // The competitor bound counts non-fragments only.
        let mut crowd = (10..10 + MAX_PROFILES as i64)
            .map(|id| {
                let mut p = profile(id, 0., 1.);
                p.domain = format!("domain-{id}");
                p
            })
            .collect::<Vec<_>>();
        crowd.push(stable.clone());
        crowd.push(fragment.clone());
        assert!(
            absorption_pairs(&crowd).is_empty(),
            "competitor overflow holds"
        );
        crowd.pop();
        crowd.pop();
        crowd.pop();
        crowd.push(stable);
        crowd.extend((0..MAX_FRAGMENTS as i64).map(|n| fragment_profile(100 + n, 0.95, 0.312, 1)));
        assert_eq!(
            absorption_pairs(&crowd).len(),
            MAX_FRAGMENTS,
            "fragments never count toward the competitor bound"
        );
    }

    #[test]
    fn genuine_two_mode_profiles_are_held_without_splitting() {
        let mut samples = (1..=3).map(|id| (id, vector(1., 0.))).collect::<Vec<_>>();
        samples.extend((4..=6).map(|id| (id, vector(0., 1.))));
        assert!(
            has_distinct_modes(&samples).unwrap(),
            "three independent observations in each separated mode must quarantine matching"
        );
        samples.pop();
        assert!(
            !has_distinct_modes(&samples).unwrap(),
            "isolated outliers must not manufacture a second stable mode"
        );
        let clean = (1..=6).map(|id| (id, vector(1., 0.))).collect::<Vec<_>>();
        assert!(
            !has_distinct_modes(&clean).unwrap(),
            "one coherent voice must remain usable"
        );
    }

    #[test]
    fn pair_validity_is_independent_of_the_sweep_proposal_budget() {
        let profiles = (0..5)
            .flat_map(|pair| {
                let mut a = profile(pair * 2 + 1, 1., 0.);
                let mut b = profile(pair * 2 + 2, 0.8, 0.6);
                a.domain = format!("domain-{pair}");
                b.domain = a.domain.clone();
                [a, b]
            })
            .collect::<Vec<_>>();
        assert!(
            merge_pairs(&profiles)
                .iter()
                .any(|pair| pair.left == 9 && pair.right == 10),
            "an unchanged fifth pair must retain its validity beyond the scheduling budget"
        );
    }
}
