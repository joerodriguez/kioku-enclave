use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

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
    let opens_quote = |word: &str| {
        word.chars()
            .take_while(|character| !character.is_alphanumeric())
            .any(|character| matches!(character, '"' | '“' | '”' | '\'' | '‘' | '’'))
    };
    let mut raw = evidence.trim_start();
    while let Some((first, rest)) = raw.split_once(char::is_whitespace) {
        if opens_quote(first)
            || !matches!(
                semantic_name_parts(first).first().map(String::as_str),
                Some(
                    "hi" | "hello"
                        | "hey"
                        | "yes"
                        | "yeah"
                        | "yep"
                        | "um"
                        | "uh"
                        | "well"
                        | "actually"
                )
            )
        {
            break;
        }
        raw = rest.trim_start();
    }
    let evidence = semantic_name_parts(raw);
    let claimed_name = semantic_name_parts(claimed_name);
    if claimed_name.is_empty() {
        return false;
    }
    // Keep punctuation until the candidate introduction span has been checked:
    // removing greetings must not turn reported speech into the narrator's name.
    let unquoted_span = |word_count| {
        let mut seen = 0;
        for word in raw.split_whitespace() {
            if opens_quote(word) {
                return false;
            }
            seen += semantic_name_parts(word).len();
            if seen >= word_count {
                return true;
            }
        }
        false
    };
    const PREFIXES: &[&[&str]] = &[
        &["my", "name", "is"],
        &["my", "full", "name", "is"],
        &["i", "am"],
        &["i'm"],
        &["i’m"],
        &["im"],
        &["call", "me"],
        &["i", "go", "by"],
    ];
    PREFIXES.iter().any(|prefix| {
        evidence.len() >= prefix.len() + claimed_name.len()
            && unquoted_span(prefix.len() + claimed_name.len())
            && evidence
                .iter()
                .take(prefix.len())
                .map(String::as_str)
                .eq(prefix.iter().copied())
            && evidence[prefix.len()..prefix.len() + claimed_name.len()] == claimed_name
    }) || (evidence.len() == claimed_name.len() + 1
        && unquoted_span(evidence.len())
        && evidence[..claimed_name.len()] == claimed_name
        && evidence.last().is_some_and(|part| part == "speaking"))
}

fn is_name_request(text: &str) -> bool {
    let mut words = semantic_name_parts(text);
    while words
        .first()
        .is_some_and(|word| matches!(word.as_str(), "please" | "hi" | "hello"))
    {
        words.remove(0);
    }
    while words
        .last()
        .is_some_and(|word| matches!(word.as_str(), "please" | "again"))
    {
        words.pop();
    }
    matches!(
        words.join(" ").as_str(),
        "what is your name"
            | "what's your name"
            | "what’s your name"
            | "may i ask your name"
            | "can i have your name"
            | "could you tell me your name"
            | "what should i call you"
            | "how should i address you"
            | "who are you"
            | "cuál es tu nombre"
            | "cómo te llamas"
            | "quel est votre nom"
            | "quel est ton nom"
            | "comment vous appelez-vous"
            | "comment tu t'appelles"
            | "comment tu t’appelles"
            | "wie heißt du"
            | "wie heisst du"
            | "wie ist dein name"
            | "come ti chiami"
            | "qual è il tuo nome"
            | "qual é seu nome"
            | "お名前は"
            | "お名前は何ですか"
            | "이름이 뭐예요"
            | "성함이 어떻게 되세요"
    )
}

pub(crate) fn is_supported_self_identification(turn: &AudioTurn, turns: &[AudioTurn]) -> bool {
    if turn.speaker_name_kind.as_deref() != Some("self_identification")
        || turn.speaker_name_subject_turn_id.as_deref() != Some(turn.turn_id.as_str())
        || turn.overlap
        || turns.iter().any(|other| {
            other.turn_id != turn.turn_id
                && other.start_ms < turn.end_ms
                && other.end_ms > turn.start_ms
        })
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
    let literal = semantic_name_parts(&turn.text);
    let quoted = semantic_name_parts(evidence);
    if quoted.is_empty() || !literal.windows(quoted.len()).any(|words| words == quoted) {
        return false;
    }
    if is_explicit_self_identification(&turn.text, name) {
        return true;
    }
    if !is_bare_name_evidence(evidence, name) || !is_bare_name_evidence(&turn.text, name) {
        return false;
    }

    // A bare answer such as "Sarah" is direct identity evidence only when it
    // immediately answers another speaker's name request. In particular, a
    // later speaker repeating or expanding "Sarah Babetski" cannot become a
    // second self-identification merely because the model mislabeled it.
    turns
        .iter()
        .filter(|candidate| candidate.turn_id != turn.turn_id && candidate.end_ms <= turn.start_ms)
        .max_by_key(|candidate| (candidate.end_ms, candidate.start_ms))
        .is_some_and(|candidate| {
            candidate.speaker_local_id != turn.speaker_local_id
                && turn.start_ms - candidate.end_ms <= 8_000
                && !candidate.overlap
                && !turns.iter().any(|other| {
                    other.turn_id != candidate.turn_id
                        && other.start_ms < candidate.end_ms
                        && other.end_ms > candidate.start_ms
                })
                && is_name_request(&candidate.text)
        })
}

/// A single diarized speaker on an explicitly local-transmit source is the
/// account owner by source provenance. A spoken name may describe that owner,
/// but it must not turn the owner into a second attendee identity.
pub(crate) fn is_owner_source_audio(audio_role: Option<&str>, distinct_speakers: usize) -> bool {
    audio_role == Some("local_transmit") && distinct_speakers <= 1
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
    /// Caller-owned durable attempt number. It advances only after an exact
    /// prior attempt is durably confirmed not billed.
    pub(crate) provider_attempt_number: i64,
    /// A provider response staged by a prior owner. Reclaim must replay these
    /// exact bytes and must never send the request again.
    pub(crate) staged_response: Option<MediaProviderStagedResponse>,
}

pub(crate) const MAX_MEDIA_PROVIDER_ATTEMPTS: i64 = 16;
pub(crate) const MAX_MEDIA_PROVIDER_RESPONSE_BYTES: usize = 512 * 1024;
pub(crate) const MAX_MEDIA_PROVIDER_JOURNAL_BYTES: usize = 768 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct MediaProviderAttempt {
    pub(crate) number: i64,
    /// Frozen with the request: 1 is the original media contract; 2 requires
    /// scored audio facts. A staged response never infers this from its body.
    pub(crate) result_contract_version: u32,
    pub(crate) identity_sha256: [u8; 32],
    pub(crate) request_sha256: [u8; 32],
    pub(crate) event_id: String,
    pub(crate) requested_model: String,
    pub(crate) location: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct MediaProviderStagedResponse {
    pub(crate) attempt: MediaProviderAttempt,
    pub(crate) http_status: u16,
    pub(crate) response_sha256: [u8; 32],
    pub(crate) response_bytes: Vec<u8>,
    pub(crate) latency_ms: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum MediaFailureDisposition {
    /// Failure is proven to precede provider egress.
    RetryableBeforeEgress,
    /// Provider explicitly rejected the request before inference/billing.
    RetryableNotBilled,
    /// The request may have reached the provider and cannot be resent.
    AmbiguousTerminal,
    /// Exact staged response bytes were invalid and cannot be regenerated.
    ConfirmedInvalid,
}

pub(crate) fn media_provider_attempt_identity(
    account_id: &str,
    work_unit_id: &str,
    number: i64,
    request_sha256: &[u8; 32],
) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(b"kioku.media-provider-attempt.v1\0");
    digest.update(account_id.as_bytes());
    digest.update([0]);
    digest.update(work_unit_id.as_bytes());
    digest.update([0]);
    digest.update(number.to_be_bytes());
    digest.update(request_sha256);
    digest.finalize().into()
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
    pub(crate) provider_attempt: MediaProviderAttempt,
    pub(crate) usage: Value,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct MediaFailurePolicy {
    pub(crate) max_attempts: i64,
    pub(crate) budget_retry_seconds: i64,
    pub(crate) resurrection_window_seconds: i64,
}

#[derive(Debug, Clone)]
pub(crate) struct AudioMediaSettlement {
    pub(crate) claim: MediaProcessingClaim,
    pub(crate) provider_attempt: MediaProviderAttempt,
    pub(crate) turns: Vec<AudioTurn>,
}

#[derive(Debug, Clone)]
pub(crate) struct ScreenMediaSettlement {
    pub(crate) claim: MediaProcessingClaim,
    pub(crate) provider_attempt: MediaProviderAttempt,
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

    /// Final local egress fence. This must be the last awaited operation
    /// before the prepared HTTP request is sent.
    async fn authorize_provider_attempt(
        &self,
        claim: &MediaProcessingClaim,
        reserved_output_tokens: i64,
        attempt: &MediaProviderAttempt,
    ) -> Result<()>;

    /// Stage the exact bounded provider response before parsing or projection.
    async fn stage_provider_response(
        &self,
        claim: &MediaProcessingClaim,
        response: &MediaProviderStagedResponse,
    ) -> Result<()>;

    async fn settle_usage(&self, command: MediaUsageSettlement) -> Result<()>;

    async fn settle_audio(&self, command: AudioMediaSettlement) -> Result<()>;

    async fn settle_screens(&self, command: ScreenMediaSettlement) -> Result<()>;

    async fn settle_failure(
        &self,
        claim: &MediaProcessingClaim,
        provider_attempt: Option<&MediaProviderAttempt>,
        disposition: MediaFailureDisposition,
        error_code: &str,
        failed_at: &str,
        policy: MediaFailurePolicy,
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
        is_owner_source_audio, is_supported_self_identification, names_form_refinement,
        prefer_claimed_display_name,
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
    fn self_identification_requires_literal_own_nonoverlapping_evidence() {
        let mut turns = vec![turn(
            "intro",
            "sam",
            0,
            2_000,
            "We can start now",
            Some("Sam"),
            Some("My name is Sam"),
        )];
        assert!(
            !is_supported_self_identification(&turns[0], &turns),
            "fabricated introduction evidence must not name an unrelated spoken turn"
        );
        for reported in [
            "He said, \"My name is Sam\"",
            "\"My name is Sam\", she read",
            "Hello, \"My name is Sam\", she read",
            "Hello, My name is \"Sam\", she read",
            "Hello, (“My name is Sam”), she read",
        ] {
            turns[0].text = reported.into();
            assert!(
                !is_supported_self_identification(&turns[0], &turns),
                "reported or quoted introductions must not identify the narrator"
            );
        }
        for reported in [
            "This is Sam, my colleague",
            "It's Sam, my colleague",
            "The name is Sam, my colleague",
        ] {
            turns[0].text = reported.into();
            turns[0].speaker_name_evidence = Some("Sam".into());
            assert!(
                !is_supported_self_identification(&turns[0], &turns),
                "third-party presentations must not identify the introducing speaker"
            );
        }
        turns[0].speaker_name_evidence = Some("My name is Sam".into());
        turns[0].text = "My name is Sam".into();
        assert!(
            is_supported_self_identification(&turns[0], &turns),
            "literal own-turn introductions must remain accepted"
        );
        let mut other = turn("overlap", "alex", 1_000, 3_000, "Hello", None, None);
        other.overlap = true;
        turns.push(other);
        assert!(
            !is_supported_self_identification(&turns[0], &turns),
            "overlap on another turn must still prevent direct name acceptance"
        );
    }

    #[test]
    fn bare_name_answer_requires_the_immediate_question_about_its_speaker() {
        let mut turns = vec![
            turn(
                "question",
                "alex",
                0,
                1_000,
                "What is her name?",
                None,
                None,
            ),
            turn(
                "answer",
                "sam",
                1_100,
                2_000,
                "Sam",
                Some("Sam"),
                Some("Sam"),
            ),
        ];
        assert!(
            !is_supported_self_identification(&turns[1], &turns),
            "a third-party name question must not identify the answering speaker"
        );
        turns[0].text = "Did someone call you?".into();
        assert!(
            !is_supported_self_identification(&turns[1], &turns),
            "a question about a caller must not identify the answering speaker"
        );
        turns[0].text = "What is your name?".into();
        assert!(
            is_supported_self_identification(&turns[1], &turns),
            "a direct immediate own-name answer must remain accepted"
        );
        turns[1].text = "Sam is my friend".into();
        assert!(
            !is_supported_self_identification(&turns[1], &turns),
            "a name excerpt must not turn a third-party answer into self-identification"
        );
        turns[1].text = "Sam".into();
        turns.push(turn(
            "intervening",
            "sam",
            1_010,
            1_090,
            "One moment",
            None,
            None,
        ));
        assert!(
            !is_supported_self_identification(&turns[1], &turns),
            "intervening speech must break the immediate name-answer connection"
        );
    }

    #[test]
    fn fuller_name_is_a_same_person_spelling_upgrade_not_a_name_join() {
        assert!(names_form_refinement("Sarah", "Mrs. Sarah Babetski"));
        assert!(prefer_claimed_display_name("Sarah", "Sarah Babetski"));
        assert!(!prefer_claimed_display_name("Sarah Babetski", "Sarah"));
        assert!(!names_form_refinement("Sarah Jones", "Sarah Babetski"));
    }

    #[test]
    fn single_local_transmit_speaker_is_the_owner_not_a_named_attendee() {
        assert!(is_owner_source_audio(Some("local_transmit"), 1));
        assert!(!is_owner_source_audio(Some("local_transmit"), 2));
        assert!(!is_owner_source_audio(Some("mixed"), 1));
    }
}
