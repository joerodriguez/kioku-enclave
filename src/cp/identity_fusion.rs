//! Versioned reduction of grounded name evidence for one established voice.
//! Names can refine that voice's label; this module never compares two voices.
use std::collections::{BTreeMap, BTreeSet};

use crate::persistence::{names_form_refinement, semantic_name_parts};

pub(crate) const POLICY_VERSION: i64 = 1;
pub(crate) const MAX_INPUTS: usize = 4096;
pub(crate) const MAINTENANCE_PROFILES: i64 = 16;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Kind {
    SelfIntroduction,
    Screen,
    Vocative,
    Context,
    Mention,
}

#[derive(Clone, Debug)]
pub(crate) struct Input {
    pub id: i64,
    pub name: String,
    pub kind: Kind,
    pub confidence: f64,
    /// Canonical frame ID or addressing observation ID, never an extraction row.
    pub source: String,
    pub subject: i64,
    pub memories: BTreeSet<i64>,
    /// Current account-local voice/owner identity of the addressing speaker.
    pub voter: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Status {
    Unbound,
    Accepted,
    Quarantined,
}
impl Status {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Unbound => "unbound",
            Self::Accepted => "accepted",
            Self::Quarantined => "quarantined",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Candidate {
    pub name: String,
    pub accepted: bool,
    pub sources: BTreeSet<i64>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Decision {
    pub status: Status,
    pub name: Option<String>,
    pub candidates: Vec<Candidate>,
}

pub(crate) fn normalized_name(name: &str) -> String {
    name.split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .to_lowercase()
}

pub(crate) fn fuse(inputs: &[Input]) -> Decision {
    let unbound = || Decision {
        status: Status::Unbound,
        name: None,
        candidates: Vec::new(),
    };
    if inputs.len() > MAX_INPUTS {
        return unbound();
    }
    let admissible: Vec<_> = inputs
        .iter()
        .filter(|input| {
            !normalized_name(&input.name).is_empty()
                && input.confidence.is_finite()
                && (0.0..=1.0).contains(&input.confidence)
        })
        .collect();
    // A canonical source has one subject and one current voter. Conflicting
    // extraction copies abstain as a unit instead of contributing extra turns.
    let mut units = BTreeMap::<(Kind, &str), Vec<&Input>>::new();
    for input in admissible {
        units
            .entry((input.kind, &input.source))
            .or_default()
            .push(input);
    }
    let valid: Vec<_> = units
        .values()
        .filter_map(|copies| {
            let first = copies[0];
            if copies.iter().any(|copy| {
                copy.subject != first.subject
                    || copy.memories != first.memories
                    || copy.voter != first.voter
                    || normalized_name(&copy.name) != normalized_name(&first.name)
            }) {
                return None;
            }
            copies
                .iter()
                .copied()
                .min_by(|a, b| a.confidence.total_cmp(&b.confidence).then(a.id.cmp(&b.id)))
        })
        .collect();
    let all_screen: Vec<_> = valid
        .iter()
        .filter(|i| {
            i.kind == Kind::Screen
                && i.confidence >= 0.90
                && semantic_name_parts(&i.name).len() >= 2
        })
        .collect();
    let screen_conflict = all_screen.iter().enumerate().any(|(index, left)| {
        all_screen[index + 1..]
            .iter()
            .any(|right| !names_form_refinement(&left.name, &right.name))
    });
    let mut names = BTreeMap::<String, String>::new();
    for input in &valid {
        // A context full name can refine a probationary short vocative, but it
        // will still need an independent screen/vocative input below.
        if input.kind != Kind::Mention {
            names
                .entry(normalized_name(&input.name))
                .and_modify(|name| {
                    if input.name < *name {
                        *name = input.name.clone();
                    }
                })
                .or_insert_with(|| input.name.clone());
        }
    }
    let all_votes: BTreeSet<_> = valid
        .iter()
        .filter(|input| input.kind == Kind::Vocative && input.voter.is_some())
        .map(|input| &input.source)
        .collect();
    let mut candidates = Vec::new();
    for name in names.values() {
        let agrees = |input: &&Input| names_form_refinement(name, &input.name);
        let related: Vec<_> = valid.iter().copied().filter(agrees).collect();
        let names_candidate = |input: &&Input| {
            semantic_name_parts(&input.name).len() >= semantic_name_parts(name).len()
        };
        let self_identified = related.iter().any(|i| {
            i.kind == Kind::SelfIntroduction && i.confidence >= 0.90 && names_candidate(i)
        });
        let screen: Vec<_> = related
            .iter()
            .filter(|i| {
                i.kind == Kind::Screen
                    && i.confidence >= 0.90
                    && semantic_name_parts(&i.name).len() >= 2
            })
            .collect();
        let frames: BTreeSet<_> = screen.iter().map(|i| &i.source).collect();
        let screen_turns: BTreeSet<_> = screen.iter().map(|i| i.subject).collect();
        let screen_memories: BTreeSet<_> = screen.iter().flat_map(|i| i.memories.iter()).collect();
        let screened = !screen_conflict
            && frames.len() >= 3
            && (screen_turns.len() >= 2 || screen_memories.len() >= 2)
            && screen.iter().any(|input| names_candidate(input));
        let vocative: Vec<_> = related
            .iter()
            .filter(|i| i.kind == Kind::Vocative && i.voter.is_some())
            .collect();
        let votes: BTreeSet<_> = vocative.iter().map(|i| &i.source).collect();
        let voters: BTreeSet<_> = vocative.iter().filter_map(|i| i.voter.as_ref()).collect();
        let vote_memories: BTreeSet<_> = vocative.iter().flat_map(|i| i.memories.iter()).collect();
        let competing_votes = names
            .values()
            .filter(|other| !names_form_refinement(name, other))
            .any(|other| {
                let count = valid
                    .iter()
                    .filter(|i| {
                        i.kind == Kind::Vocative
                            && i.voter.is_some()
                            && names_form_refinement(other, &i.name)
                    })
                    .map(|i| &i.source)
                    .collect::<BTreeSet<_>>()
                    .len();
                count > 0 && 3 * count >= all_votes.len()
            });
        let addressed = votes.len() >= 3
            && voters.len() >= 2
            && vote_memories.len() >= 2
            && !competing_votes
            && vocative.iter().any(|input| names_candidate(input));
        let probationary = !screen.is_empty() || !vocative.is_empty();
        let context_memories: BTreeSet<_> = related
            .iter()
            .filter(|i| {
                i.kind == Kind::Context
                    && semantic_name_parts(&i.name).len() >= 2
                    && names_candidate(i)
            })
            .flat_map(|i| i.memories.iter())
            .collect();
        let competing_context = valid
            .iter()
            .any(|i| i.kind == Kind::Context && !names_form_refinement(name, &i.name));
        let corroborated = !screen_conflict
            && probationary
            && semantic_name_parts(name).len() >= 2
            && context_memories.len() >= 2
            && !competing_context
            && !competing_votes;
        if self_identified || probationary {
            candidates.push(Candidate {
                name: name.clone(),
                accepted: self_identified || screened || addressed || corroborated,
                sources: related
                    .iter()
                    .filter(|i| i.kind != Kind::Mention)
                    .map(|i| i.id)
                    .collect(),
            });
        }
    }
    let accepted: Vec<_> = candidates
        .iter()
        .filter(|candidate| candidate.accepted)
        .collect();
    let conflict = accepted.iter().enumerate().any(|(index, left)| {
        accepted[index + 1..]
            .iter()
            .any(|right| !names_form_refinement(&left.name, &right.name))
    });
    let name = if conflict {
        None
    } else {
        accepted
            .iter()
            .max_by_key(|candidate| (semantic_name_parts(&candidate.name).len(), &candidate.name))
            .map(|candidate| candidate.name.clone())
    };
    Decision {
        status: if conflict {
            Status::Quarantined
        } else if name.is_some() {
            Status::Accepted
        } else {
            Status::Unbound
        },
        name,
        candidates,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn input(id: i64, name: &str, kind: Kind, subject: i64, memory: i64) -> Input {
        Input {
            id,
            name: name.into(),
            kind,
            confidence: 0.95,
            source: id.to_string(),
            subject,
            memories: BTreeSet::from([memory]),
            voter: Some(format!("voice:{}", id % 2)),
        }
    }
    #[test]
    fn screen_requires_independent_frames_and_turns_and_converges() {
        let mut inputs = vec![
            input(1, "Sam Lee", Kind::Screen, 10, 1),
            input(2, "Sam Lee", Kind::Screen, 10, 1),
        ];
        assert_eq!(
            fuse(&inputs).status,
            Status::Unbound,
            "two screen frames must remain probationary"
        );
        inputs.push(input(3, "Sam Lee", Kind::Screen, 10, 1));
        assert_eq!(
            fuse(&inputs).status,
            Status::Unbound,
            "three frames from one turn and memory must remain probationary"
        );
        inputs[2].subject = 11;
        let expected = fuse(&inputs);
        assert_eq!(
            expected.name.as_deref(),
            Some("Sam Lee"),
            "three independent frames across two turns must accept the name"
        );
        inputs.reverse();
        assert_eq!(
            fuse(&inputs),
            expected,
            "source arrival order must not change the name decision"
        );
        inputs[0].source = inputs[1].source.clone();
        assert_eq!(
            fuse(&inputs).status,
            Status::Unbound,
            "repeated canonical frames must not fabricate independence"
        );
    }
    #[test]
    fn vocatives_need_independent_current_speakers_and_exact_competitor_boundary() {
        let mut inputs = vec![
            input(1, "Sam", Kind::Vocative, 10, 1),
            input(2, "Sam", Kind::Vocative, 10, 2),
            input(3, "Sam", Kind::Vocative, 10, 2),
        ];
        for i in &mut inputs {
            i.confidence = 0.63;
            i.voter = Some("voice:1".into());
        }
        assert_eq!(
            fuse(&inputs).status,
            Status::Unbound,
            "three votes from one current speaker must remain probationary"
        );
        inputs[0].voter = Some("voice:2".into());
        assert_eq!(
            fuse(&inputs).name.as_deref(),
            Some("Sam"),
            "three grounded votes from two memories and speakers must accept"
        );
        inputs.push(input(4, "Alex", Kind::Vocative, 10, 2));
        inputs.push(input(5, "Alex", Kind::Vocative, 10, 2));
        inputs.push(input(6, "Sam", Kind::Vocative, 10, 2));
        assert_eq!(
            fuse(&inputs).status,
            Status::Unbound,
            "a competing name with exactly one third of votes must block acceptance"
        );
        for i in &mut inputs[3..5] {
            i.kind = Kind::Mention;
        }
        assert_eq!(
            fuse(&inputs).name.as_deref(),
            Some("Sam"),
            "third-party mentions must never vote or inflate the denominator"
        );
    }
    #[test]
    fn context_only_corroborates_and_incompatible_accepted_names_quarantine() {
        let mut inputs = vec![
            input(1, "Sam Lee", Kind::Context, 10, 1),
            input(2, "Sam Lee", Kind::Context, 10, 2),
        ];
        assert_eq!(
            fuse(&inputs).status,
            Status::Unbound,
            "attendee context must never establish identity by itself"
        );
        inputs.push(input(3, "Sam", Kind::Vocative, 10, 1));
        assert_eq!(
            fuse(&inputs).name.as_deref(),
            Some("Sam Lee"),
            "two unambiguous attendee memories may corroborate a probationary candidate"
        );
        inputs.push(input(4, "Alex Jones", Kind::SelfIntroduction, 10, 1));
        assert_eq!(
            fuse(&inputs).status,
            Status::Quarantined,
            "incompatible accepted names must quarantine the binding rather than choose a score"
        );
        let first = vec![
            input(1, "Sam", Kind::SelfIntroduction, 10, 1),
            input(2, "Sam Lee", Kind::SelfIntroduction, 10, 2),
        ];
        assert_eq!(
            fuse(&first).name.as_deref(),
            Some("Sam Lee"),
            "fuller spelling must refine only the already established voice"
        );
    }
    #[test]
    fn screen_conflicts_cannot_be_pooled_through_a_short_name() {
        let mut inputs = vec![
            input(1, "Sam Lee", Kind::Screen, 10, 1),
            input(2, "Sam Lee", Kind::Screen, 11, 1),
            input(3, "Sam Lee", Kind::Screen, 11, 1),
            input(4, "Alex Jones", Kind::Screen, 12, 1),
        ];
        assert_eq!(
            fuse(&inputs).status,
            Status::Unbound,
            "a conflicting full screen name must hold automatic screen acceptance"
        );
        inputs = vec![
            input(1, "Sam Lee", Kind::Screen, 10, 1),
            input(2, "Sam Lee", Kind::Screen, 11, 1),
            input(3, "Sam Jones", Kind::Screen, 11, 1),
            input(4, "Sam", Kind::Vocative, 10, 1),
        ];
        assert_eq!(
            fuse(&inputs).status,
            Status::Unbound,
            "a short candidate must not pool incompatible full-name frames"
        );
        inputs.push(input(5, "Sam Lee", Kind::SelfIntroduction, 10, 1));
        assert_eq!(
            fuse(&inputs).name.as_deref(),
            Some("Sam Lee"),
            "probationary screen conflict must not erase an explicit own introduction"
        );
    }
    #[test]
    fn titles_and_single_context_cannot_supply_unearned_name_specificity() {
        let mut inputs = vec![
            input(1, "Sam Lee", Kind::SelfIntroduction, 10, 1),
            input(2, "Sir Sam", Kind::Context, 10, 1),
        ];
        assert_eq!(
            fuse(&inputs).name.as_deref(),
            Some("Sam Lee"),
            "an honorific must not displace a supported fuller name"
        );
        inputs = vec![
            input(1, "Sam", Kind::SelfIntroduction, 10, 1),
            input(2, "Sam Lee", Kind::Context, 10, 1),
        ];
        assert_eq!(
            fuse(&inputs).name.as_deref(),
            Some("Sam"),
            "one attendee context must not enrich an accepted short name"
        );
        inputs = vec![
            input(1, "Sir Sam", Kind::Screen, 10, 1),
            input(2, "Sir Sam", Kind::Screen, 11, 1),
            input(3, "Sir Sam", Kind::Screen, 11, 1),
        ];
        assert_eq!(
            fuse(&inputs).status,
            Status::Unbound,
            "an honorific and one name are not a full screen name"
        );
    }
    #[test]
    fn duplicate_sources_cannot_fabricate_voter_or_turn_independence() {
        let mut inputs = vec![
            input(1, "Sam Lee", Kind::Screen, 10, 1),
            input(2, "Sam Lee", Kind::Screen, 10, 1),
            input(3, "Sam Lee", Kind::Screen, 10, 1),
        ];
        let mut duplicate = inputs[0].clone();
        duplicate.id = 4;
        duplicate.subject = 11;
        inputs.push(duplicate);
        assert_eq!(
            fuse(&inputs).status,
            Status::Unbound,
            "conflicting copies of one frame must not create a second turn"
        );
        inputs = vec![
            input(1, "Sam", Kind::Vocative, 10, 1),
            input(2, "Sam", Kind::Vocative, 10, 2),
            input(3, "Sam", Kind::Vocative, 10, 2),
        ];
        for i in &mut inputs {
            i.voter = Some("voice:1".into());
        }
        let mut duplicate = inputs[0].clone();
        duplicate.id = 4;
        duplicate.voter = Some("voice:2".into());
        inputs.push(duplicate);
        assert_eq!(
            fuse(&inputs).status,
            Status::Unbound,
            "conflicting copies of one addressing turn must not create a second voter"
        );
    }
    #[test]
    fn every_corroborating_memory_must_support_the_full_candidate() {
        let inputs = vec![
            input(1, "Sam Lee", Kind::Screen, 10, 1),
            input(2, "Sam Lee", Kind::Screen, 11, 1),
            input(3, "Sam Lee", Kind::Screen, 11, 1),
            input(4, "Sam Lee Jones", Kind::Context, 10, 1),
            input(5, "Sam Lee", Kind::Context, 11, 2),
        ];
        assert_eq!(
            fuse(&inputs).name.as_deref(),
            Some("Sam Lee"),
            "one full-name context plus a shorter context must not supply two full-name memories"
        );
    }
}
