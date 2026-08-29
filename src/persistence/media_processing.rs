use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{cp::media::AudioTurn, error::Result};

fn semantic_name_parts(value: &str) -> Vec<String> {
    value
        .split_whitespace()
        .map(|part| {
            part.trim_matches(|character: char| !character.is_alphanumeric())
                .to_lowercase()
        })
        .filter(|part| {
            !part.is_empty()
                && !matches!(
                    part.as_str(),
                    "mr" | "mrs"
                        | "ms"
                        | "miss"
                        | "mx"
                        | "dr"
                        | "doctor"
                        | "prof"
                        | "professor"
                        | "sir"
                        | "dame"
                )
        })
        .collect()
}

fn is_ordered_name_subset(shorter: &[String], longer: &[String]) -> bool {
    let mut next = 0;
    for part in longer {
        if shorter.get(next) == Some(part) {
            next += 1;
        }
    }
    next == shorter.len()
}

/// This is only a spelling-enrichment predicate. Callers may apply it after
/// stronger evidence has already established one opaque person; they must
/// never use it to join otherwise distinct people by name.
pub(crate) fn names_form_refinement(left: &str, right: &str) -> bool {
    let left = semantic_name_parts(left);
    let right = semantic_name_parts(right);
    if left.is_empty() || right.is_empty() {
        return false;
    }
    if left.len() <= right.len() {
        is_ordered_name_subset(&left, &right)
    } else {
        is_ordered_name_subset(&right, &left)
    }
}

pub(crate) fn prefer_claimed_display_name(current: &str, claimed: &str) -> bool {
    names_form_refinement(current, claimed)
        && semantic_name_parts(claimed).len() > semantic_name_parts(current).len()
}

fn is_bare_name_evidence(evidence: &str, claimed_name: &str) -> bool {
    let evidence = semantic_name_parts(evidence);
    let claimed_name = semantic_name_parts(claimed_name);
    !claimed_name.is_empty() && evidence == claimed_name
}

fn is_explicit_self_identification(evidence: &str, claimed_name: &str) -> bool {
    let mut evidence = semantic_name_parts(evidence);
    let claimed_name = semantic_name_parts(claimed_name);
    if claimed_name.is_empty() {
        return false;
    }
    while evidence.first().is_some_and(|part| {
        matches!(
            part.as_str(),
            "hi" | "hello" | "hey" | "yes" | "yeah" | "yep" | "um" | "uh" | "well" | "actually"
        )
    }) {
        evidence.remove(0);
    }
    const PREFIXES: &[&[&str]] = &[
        &["my", "name", "is"],
        &["my", "full", "name", "is"],
        &["i", "am"],
        &["i'm"],
        &["i’m"],
        &["im"],
        &["call", "me"],
        &["i", "go", "by"],
        &["this", "is"],
        &["it's"],
        &["it’s"],
        &["the", "name", "is"],
    ];
    PREFIXES.iter().any(|prefix| {
        evidence.len() == prefix.len() + claimed_name.len()
            && evidence
                .iter()
                .take(prefix.len())
                .map(String::as_str)
                .eq(prefix.iter().copied())
            && evidence[prefix.len()..] == claimed_name
    }) || (evidence.len() == claimed_name.len() + 1
        && evidence[..claimed_name.len()] == claimed_name
        && evidence.last().is_some_and(|part| part == "speaking"))
}

fn is_name_request(text: &str) -> bool {
    let text = text.to_lowercase();
    let asks_question = text.contains('?')
        || text.starts_with("who ")
        || text.starts_with("what ")
        || text.starts_with("how ");
    asks_question
        && [
            "name",
            "called",
            "call you",
            "who are you",
            "nombre",
            "llamas",
            "nom",
            "appelles",
            "heiß",
            "heiss",
            "nome",
            "chiami",
            "名前",
            "お名前",
            "이름",
        ]
        .iter()
        .any(|needle| text.contains(needle))
}

pub(crate) fn is_supported_self_identification(turn: &AudioTurn, turns: &[AudioTurn]) -> bool {
    if turn.speaker_name_kind.as_deref() != Some("self_identification")
        || turn.speaker_name_subject_turn_id.as_deref() != Some(turn.turn_id.as_str())
        || turn.overlap
    {
        return false;
    }
    let (Some(name), Some(evidence), Some(confidence)) = (
        turn.speaker_name.as_deref(),
        turn.speaker_name_evidence.as_deref(),
        turn.speaker_name_confidence,
    ) else {
        return false;
    };
    if !confidence.is_finite() || confidence < 0.90 {
        return false;
    }
    if is_explicit_self_identification(evidence, name)
        || is_explicit_self_identification(&turn.text, name)
    {
        return true;
    }
    if !is_bare_name_evidence(evidence, name) {
        return false;
    }

    // A bare answer such as "Sarah" is direct identity evidence only when it
    // immediately answers another speaker's name request. In particular, a
    // later speaker repeating or expanding "Sarah Babetski" cannot become a
    // second self-identification merely because the model mislabeled it.
    turns
        .iter()
        .filter(|candidate| {
            candidate.speaker_local_id != turn.speaker_local_id
                && candidate.end_ms <= turn.start_ms
                && turn.start_ms - candidate.end_ms <= 8_000
                && !candidate.overlap
        })
        .max_by_key(|candidate| candidate.end_ms)
        .is_some_and(|candidate| is_name_request(&candidate.text))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum MediaProcessingClass {
    Audio,
    Screen,
}

impl MediaProcessingClass {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Audio => "audio",
            Self::Screen => "screen",
        }
    }

    pub(crate) const fn job_kind(self) -> &'static str {
        match self {
            Self::Audio => "gemini_audio",
            Self::Screen => "gemini_screen",
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct MediaProcessingJob {
    pub(crate) id: i64,
    pub(crate) event_id: String,
    pub(crate) job_kind: String,
    pub(crate) object_key: String,
    pub(crate) object_generation: i64,
    pub(crate) mime_type: String,
    pub(crate) codec: String,
    pub(crate) byte_length: i64,
    pub(crate) sample_rate: Option<i64>,
    pub(crate) channels: Option<i64>,
    pub(crate) width: Option<i64>,
    pub(crate) height: Option<i64>,
    pub(crate) sha256: String,
    pub(crate) started_at: String,
    pub(crate) ended_at: String,
    pub(crate) stream_kind: String,
    pub(crate) capture_session_id: String,
    pub(crate) stream_id: String,
    pub(crate) sequence: i64,
    pub(crate) context: Option<Value>,
    pub(crate) audio_role: Option<String>,
    pub(crate) audio_route: Option<String>,
    pub(crate) route_epoch: Option<i64>,
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct MediaProcessingClaim {
    pub(crate) account_id: String,
    pub(crate) work_unit_id: String,
    pub(crate) class: MediaProcessingClass,
    pub(crate) claim_token: String,
    pub(crate) claim_until: String,
    pub(crate) jobs: Vec<MediaProcessingJob>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub(crate) struct MediaPersonEvidence {
    pub(crate) name: String,
    pub(crate) evidence: String,
    pub(crate) confidence: f64,
    pub(crate) is_active_speaker: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub(crate) struct MediaScreenProjection {
    pub(crate) event_id: String,
    pub(crate) literal_description: String,
    pub(crate) screen_state: String,
    pub(crate) content_type: String,
    pub(crate) visible_text: String,
    pub(crate) salient_text: String,
    pub(crate) people: Vec<MediaPersonEvidence>,
}

#[derive(Debug, Clone)]
pub(crate) struct MediaUsageSettlement {
    pub(crate) claim: MediaProcessingClaim,
    pub(crate) usage: Value,
}

#[derive(Debug, Clone)]
pub(crate) struct AudioMediaSettlement {
    pub(crate) claim: MediaProcessingClaim,
    pub(crate) turns: Vec<AudioTurn>,
}

#[derive(Debug, Clone)]
pub(crate) struct ScreenMediaSettlement {
    pub(crate) claim: MediaProcessingClaim,
    pub(crate) results: Vec<MediaScreenProjection>,
}

#[async_trait]
pub(crate) trait MediaProcessingRepository: Send + Sync {
    async fn pending_classes(&self, account_id: &str, now: &str) -> Result<(bool, bool)>;

    async fn claim(
        &self,
        account_id: &str,
        class: MediaProcessingClass,
        claimed_at: &str,
        lease_seconds: i64,
        scan_limit: i64,
    ) -> Result<Option<MediaProcessingClaim>>;

    async fn candidate_name_vocabulary(&self, account_id: &str) -> Result<Vec<String>>;

    async fn record_reservation(
        &self,
        claim: &MediaProcessingClaim,
        reserved_output_tokens: i64,
        reserved_at: &str,
    ) -> Result<()>;

    async fn settle_usage(&self, command: MediaUsageSettlement) -> Result<()>;

    async fn settle_audio(&self, command: AudioMediaSettlement) -> Result<()>;

    async fn settle_screens(&self, command: ScreenMediaSettlement) -> Result<()>;

    async fn settle_failure(
        &self,
        claim: &MediaProcessingClaim,
        error_code: &str,
        failed_at: &str,
        max_attempts: i64,
        budget_retry_seconds: i64,
        resurrection_window_seconds: i64,
    ) -> Result<()>;

    async fn resurrect_recent_failures(
        &self,
        account_id: &str,
        now: &str,
        delay_seconds: i64,
        total_attempt_cap: i64,
        window_seconds: i64,
        limit: i64,
    ) -> Result<u64>;

    async fn span_has_recoverable_media(
        &self,
        account_id: &str,
        from: &str,
        to: &str,
        resurrection_window_start: &str,
        memory_hold_attempts: i64,
    ) -> Result<bool>;
}

#[cfg(test)]
mod tests {
    use super::{
        is_supported_self_identification, names_form_refinement, prefer_claimed_display_name,
    };
    use crate::cp::media::AudioTurn;

    fn turn(
        turn_id: &str,
        speaker: &str,
        start_ms: i64,
        end_ms: i64,
        text: &str,
        name: Option<&str>,
        evidence: Option<&str>,
    ) -> AudioTurn {
        AudioTurn {
            turn_id: turn_id.into(),
            start_ms,
            end_ms,
            speaker_local_id: speaker.into(),
            text: text.into(),
            language: Some("en".into()),
            speaker_name: name.map(str::to_owned),
            speaker_name_confidence: name.map(|_| 0.99),
            speaker_name_evidence: evidence.map(str::to_owned),
            speaker_name_kind: name.map(|_| "self_identification".into()),
            speaker_name_subject_turn_id: name.map(|_| turn_id.into()),
            speaker_name_target_turn_id: None,
            person_facts: Vec::new(),
            overlap: false,
            quality_flags: Vec::new(),
        }
    }

    #[test]
    fn question_answer_is_identity_but_other_speaker_name_expansion_is_not() {
        let turns = vec![
            turn(
                "question",
                "joseph",
                0,
                1_000,
                "What is your name?",
                None,
                None,
            ),
            turn(
                "answer",
                "sarah",
                1_100,
                1_900,
                "Sarah",
                Some("Sarah"),
                Some("Sarah"),
            ),
            turn(
                "expansion",
                "joseph",
                2_000,
                3_000,
                "Mrs. Sarah Babetski, including her last name",
                Some("Sarah Babetski"),
                Some("Mrs. Sarah Babetski, including her last name"),
            ),
        ];
        assert!(is_supported_self_identification(&turns[1], &turns));
        assert!(!is_supported_self_identification(&turns[2], &turns));
    }

    #[test]
    fn explicit_self_identification_does_not_need_a_prior_question() {
        let turns = vec![turn(
            "identity",
            "sarah",
            0,
            2_000,
            "My full name is Sarah Babetski",
            Some("Sarah Babetski"),
            Some("Sarah Babetski"),
        )];
        assert!(is_supported_self_identification(&turns[0], &turns));
    }

    #[test]
    fn third_party_relationship_statement_is_not_self_identification() {
        let turns = vec![turn(
            "mention",
            "joseph",
            0,
            2_000,
            "My wife is Sarah Babetski",
            Some("Sarah Babetski"),
            Some("My wife is Sarah Babetski"),
        )];
        assert!(!is_supported_self_identification(&turns[0], &turns));
    }

    #[test]
    fn fuller_name_is_a_same_person_spelling_upgrade_not_a_name_join() {
        assert!(names_form_refinement("Sarah", "Mrs. Sarah Babetski"));
        assert!(prefer_claimed_display_name("Sarah", "Sarah Babetski"));
        assert!(!prefer_claimed_display_name("Sarah Babetski", "Sarah"));
        assert!(!names_form_refinement("Sarah Jones", "Sarah Babetski"));
    }
}
