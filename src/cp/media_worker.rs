//! Durable PostgreSQL-backed raw-media processing worker.
//!
//! Capture admission records immutable object identity and queues structured
//! work in PostgreSQL. This worker claims bounded work units across the
//! horizontal fleet, opens only the claimed encrypted GCS generation inside
//! the enclave, sends bounded media to Vertex, settles usage, validates the
//! constrained response, and commits the projection with the same claim.

use std::collections::HashSet;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tokio::task::JoinSet;
use tracing::warn;

use crate::error::{EnclaveError, Result};
use crate::persistence::{
    AudioMediaSettlement, MediaFailureDisposition, MediaFailurePolicy, MediaPersonEvidence,
    MediaProcessingClaim, MediaProcessingClass, MediaProcessingJob, MediaProviderAttempt,
    MediaProviderStagedResponse, MediaScreenProjection, MediaUsageSettlement,
    ScreenMediaSettlement,
};

use super::media::parse_audio_result;
use super::media_planner::{self, SourceInterval, WorkClass};
use super::{isotime, vertex, CpState};

const WORKER_INTERVAL_SECONDS: u64 = 30;
const MAX_JOBS_PER_USER_PER_SWEEP: usize = 2;
const MAX_CONCURRENT_USER_SWEEPS: usize = 4;
const MAX_ATTEMPTS: i64 = 3;
pub(crate) const PROCESSOR_VERSION: i64 = 1;
const RESURRECTION_DELAY_SECONDS: i64 = 3_600;
pub(crate) const RESURRECTION_TOTAL_ATTEMPT_CAP: i64 = 9;
pub(crate) const RESURRECTION_WINDOW_SECONDS: f64 = 7.0 * 24.0 * 3_600.0;
const RESURRECTION_MAX_PER_SWEEP: i64 = 16;
pub(crate) const RESURRECTION_MEMORY_HOLD_TOTAL_ATTEMPTS: i64 = MAX_ATTEMPTS + 2;
const CLAIM_SCAN_LIMIT: i64 = 128;
const CLAIM_LEASE_SECONDS: i64 = 300;
const BUDGET_RETRY_SECONDS: i64 = 6 * 60 * 60;
pub(crate) const RESURRECTION_WINDOW_SECONDS_INTEGRAL: i64 = 7 * 24 * 3_600;
pub(crate) const TRANSCRIPT_TARGET_CONFLICT: &str = "transcript_target_conflict";
pub(crate) const NON_RESURRECTABLE_MEDIA_ERROR_CODES: [&str; 5] = [
    "media_integrity",
    TRANSCRIPT_TARGET_CONFLICT,
    "unplannable_media",
    "vertex_ambiguous",
    "invalid_model_output",
];

#[derive(Debug)]
struct MediaWorkFailure {
    error: EnclaveError,
    disposition: MediaFailureDisposition,
    provider_attempt: Option<MediaProviderAttempt>,
    preserve_staged_response: bool,
}

impl MediaWorkFailure {
    fn before_egress(error: EnclaveError) -> Self {
        Self {
            error,
            disposition: MediaFailureDisposition::RetryableBeforeEgress,
            provider_attempt: None,
            preserve_staged_response: false,
        }
    }

    fn provider(
        error: EnclaveError,
        disposition: MediaFailureDisposition,
        provider_attempt: MediaProviderAttempt,
    ) -> Self {
        Self {
            error,
            disposition,
            provider_attempt: Some(provider_attempt),
            preserve_staged_response: false,
        }
    }

    fn staged(error: EnclaveError, provider_attempt: MediaProviderAttempt) -> Self {
        Self {
            error,
            disposition: MediaFailureDisposition::AmbiguousTerminal,
            provider_attempt: Some(provider_attempt),
            preserve_staged_response: true,
        }
    }
}

impl From<EnclaveError> for MediaWorkFailure {
    fn from(error: EnclaveError) -> Self {
        Self::before_egress(error)
    }
}

impl From<serde_json::Error> for MediaWorkFailure {
    fn from(error: serde_json::Error) -> Self {
        Self::before_egress(error.into())
    }
}

#[derive(Debug, Clone)]
struct MediaJob {
    event_id: String,
    mime_type: String,
    started_at: String,
    ended_at: String,
    stream_kind: String,
}

#[derive(Debug, Clone)]
struct MediaWorkUnit {
    jobs: Vec<MediaJob>,
}

impl From<&MediaProcessingJob> for MediaJob {
    fn from(job: &MediaProcessingJob) -> Self {
        Self {
            event_id: job.event_id.clone(),
            mime_type: job.mime_type.clone(),
            started_at: job.started_at.clone(),
            ended_at: job.ended_at.clone(),
            stream_kind: job.stream_kind.clone(),
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ScreenResult {
    literal_description: String,
    screen_state: String,
    content_type: String,
    visible_text: String,
    salient_text: String,
    #[serde(default)]
    people: Vec<PersonEvidence>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoryboardResult {
    frames: Vec<StoryboardFrameResult>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoryboardFrameResult {
    frame_id: String,
    literal_description: String,
    screen_state: String,
    content_type: String,
    visible_text: String,
    salient_text: String,
    #[serde(default)]
    people: Vec<PersonEvidence>,
}

impl StoryboardFrameResult {
    fn into_screen_result(self) -> ScreenResult {
        ScreenResult {
            literal_description: self.literal_description,
            screen_state: self.screen_state,
            content_type: self.content_type,
            visible_text: self.visible_text,
            salient_text: self.salient_text,
            people: self.people,
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PersonEvidence {
    name: String,
    evidence: String,
    confidence: f64,
    is_active_speaker: bool,
}

fn now_iso() -> String {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64;
    isotime::format_epoch_millis(millis)
}

fn audio_schema() -> Value {
    json!({
        "type": "OBJECT",
        "properties": {
            "turns": {
                "type": "ARRAY",
                "items": {
                    "type": "OBJECT",
                    "properties": {
                        "turn_id": {"type":"STRING"},
                        "start_ms": {"type":"INTEGER"},
                        "end_ms": {"type":"INTEGER"},
                        "speaker_local_id": {"type":"STRING"},
                        "text": {"type":"STRING"},
                        "language": {"type":"STRING", "nullable":true},
                        "overlap": {"type":"BOOLEAN"},
                        "quality_flags": {"type":"ARRAY", "items":{"type":"STRING"}},
                        "speaker_name": {"type":"STRING", "nullable":true},
                        "speaker_name_confidence": {"type":"NUMBER", "nullable":true},
                        "speaker_name_evidence": {"type":"STRING", "nullable":true},
                        "speaker_name_kind": {"type":"STRING", "enum":["self_identification","vocative_address","third_party_mention"], "nullable":true},
                        "speaker_name_subject_turn_id": {"type":"STRING", "nullable":true},
                        "speaker_name_target_turn_id": {"type":"STRING", "nullable":true},
                        "person_facts": {
                            "type":"ARRAY",
                            "items": {
                                "type":"OBJECT",
                                "properties": {
                                    "predicate":{"type":"STRING","enum":["role","organization","relationship","preference","responsibility","contact","location","other"]},
                                    "value":{"type":"STRING"},
                                    "evidence":{"type":"STRING"}
                                },
                                "required":["predicate","value","evidence"]
                            }
                        }
                    },
                    "required": ["turn_id","start_ms","end_ms","speaker_local_id","text","overlap","quality_flags"]
                }
            }
        },
        "required": ["turns"]
    })
}

fn screen_schema() -> Value {
    json!({
        "type":"OBJECT",
        "properties": {
            "literal_description":{"type":"STRING"},
            "screen_state":{"type":"STRING","enum":[
                "content","blank","loading","error","transition",
                "locked_or_private","unknown"]},
            "content_type":{"type":"STRING","enum":[
                "document","presentation","web_page","code","terminal","chat",
                "meeting","media","system_ui","application_ui","unknown"]},
            "visible_text":{"type":"STRING"},
            "salient_text":{"type":"STRING"},
            "people": {
                "type":"ARRAY",
                "items": {
                    "type":"OBJECT",
                    "properties": {
                        "name":{"type":"STRING"},
                        "evidence":{"type":"STRING"},
                        "confidence":{"type":"NUMBER"},
                        "is_active_speaker":{"type":"BOOLEAN"}
                    },
                    "required":["name","evidence","confidence","is_active_speaker"]
                }
            }
        },
        "required":["literal_description","screen_state","content_type","visible_text","salient_text","people"]
    })
}

fn storyboard_schema() -> Value {
    let screen = screen_schema();
    let mut properties = screen["properties"].clone();
    properties["frame_id"] = json!({"type":"STRING"});
    let mut required = screen["required"].clone();
    required
        .as_array_mut()
        .expect("static screen schema required array")
        .insert(0, json!("frame_id"));
    json!({
        "type":"OBJECT",
        "properties": {
            "frames": {
                "type":"ARRAY",
                "items": {
                    "type":"OBJECT",
                    "properties": properties,
                    "required": required
                }
            }
        },
        "required":["frames"]
    })
}

fn validate_storyboard_result(
    raw: &str,
    expected_frame_ids: &[String],
) -> Result<Vec<(String, ScreenResult)>> {
    let result: StoryboardResult = serde_json::from_str(raw)?;
    if result.frames.len() != expected_frame_ids.len() {
        return Err(EnclaveError::InvalidRequest(
            "storyboard response does not cover every frame".into(),
        ));
    }
    let expected = expected_frame_ids.iter().collect::<HashSet<_>>();
    let mut seen = HashSet::new();
    let mut by_id = std::collections::HashMap::new();
    for frame in result.frames {
        if !expected.contains(&frame.frame_id) || !seen.insert(frame.frame_id.clone()) {
            return Err(EnclaveError::InvalidRequest(
                "storyboard response has an unknown or duplicate frame id".into(),
            ));
        }
        by_id.insert(frame.frame_id.clone(), frame.into_screen_result());
    }
    expected_frame_ids
        .iter()
        .map(|id| {
            by_id
                .remove(id)
                .map(|result| (id.clone(), result))
                .ok_or_else(|| {
                    EnclaveError::InvalidRequest("storyboard response is missing a frame id".into())
                })
        })
        .collect()
}
async fn load_job_media(
    state: &CpState,
    user_id: &str,
    job: &MediaProcessingJob,
) -> Result<Vec<u8>> {
    let stored = state
        .repositories
        .media_objects()
        .get_current_generation(&job.object_key, job.object_generation)
        .await?;
    if stored.generation != job.object_generation {
        return Err(EnclaveError::Crypto(
            "raw media generation changed after admission".into(),
        ));
    }
    let dek = crate::crypto::load_dek(state.kms.as_ref(), &stored.wrapped_dek_b64).await?;
    let context = crate::gcs::media_blob_context(user_id, &job.object_key);
    let media = crate::crypto::decrypt_bound_blob(&dek, &stored.ciphertext, &context)?.plaintext;
    if i64::try_from(media.len()).ok() != Some(job.byte_length)
        || !format!("{:x}", Sha256::digest(&media)).eq_ignore_ascii_case(&job.sha256)
    {
        return Err(EnclaveError::Crypto("raw media commitment mismatch".into()));
    }
    Ok(media)
}

fn media_usage(claim: &MediaProcessingClaim, generation: &vertex::MediaGeneration) -> Value {
    let reserved = match claim.class {
        MediaProcessingClass::Audio => vertex::MAX_MEDIA_OUTPUT_TOKENS,
        MediaProcessingClass::Screen => vertex::MAX_SCREEN_OUTPUT_TOKENS,
    };
    json!({
        "work_unit_id": claim.work_unit_id,
        "work_class": claim.class.as_str(),
        "member_count": claim.jobs.len(),
        "reservation_state": "reserved",
        "reserved_output_tokens": reserved,
        "actual_prompt_tokens": generation.metadata.usage.as_ref().and_then(|usage| usage.prompt_tokens),
        "actual_input_text_tokens": generation.metadata.usage.as_ref().and_then(|usage| usage.input_text_tokens),
        "actual_input_audio_tokens": generation.metadata.usage.as_ref().and_then(|usage| usage.input_audio_tokens),
        "actual_input_image_tokens": generation.metadata.usage.as_ref().and_then(|usage| usage.input_image_tokens),
        "actual_cached_input_tokens": generation.metadata.usage.as_ref().and_then(|usage| usage.cached_input_tokens),
        "actual_output_tokens": generation.metadata.usage.as_ref().and_then(|usage| usage.output_tokens),
        "actual_thought_tokens": generation.metadata.usage.as_ref().and_then(|usage| usage.thought_tokens),
        "actual_total_tokens": generation.metadata.usage.as_ref().and_then(|usage| usage.total_tokens),
        "returned_model": generation.metadata.model_version.as_deref(),
        "traffic_type": generation.metadata.traffic_type.as_deref(),
        "latency_ms": generation.latency_ms,
        "processor_version": PROCESSOR_VERSION,
        "outcome": "model_returned",
    })
}

async fn reserve_media_output(
    state: &CpState,
    user_id: &str,
    claim: &MediaProcessingClaim,
) -> Result<i64> {
    let (class, requested) = match claim.class {
        MediaProcessingClass::Audio => (
            super::limits::VertexWorkClass::Audio,
            i64::from(vertex::MAX_MEDIA_OUTPUT_TOKENS),
        ),
        MediaProcessingClass::Screen => (
            super::limits::VertexWorkClass::Screen,
            i64::from(vertex::MAX_SCREEN_OUTPUT_TOKENS),
        ),
    };
    let reserved = super::limits::reserve_vertex_output_tokens_for_class(
        &state.repositories,
        user_id,
        class,
        requested,
        state.config.quota_vertex_output_tokens_per_day,
    )
    .await?;
    if !reserved {
        return Err(EnclaveError::Config("vertex_daily_budget".into()));
    }
    Ok(requested)
}

fn mapped_provider_disposition(
    value: vertex::VertexGenerationFailureDisposition,
) -> MediaFailureDisposition {
    match value {
        vertex::VertexGenerationFailureDisposition::RetryableBeforeEgress => {
            MediaFailureDisposition::RetryableBeforeEgress
        }
        vertex::VertexGenerationFailureDisposition::RetryableNotBilled => {
            MediaFailureDisposition::RetryableNotBilled
        }
        vertex::VertexGenerationFailureDisposition::AmbiguousTerminal => {
            MediaFailureDisposition::AmbiguousTerminal
        }
        vertex::VertexGenerationFailureDisposition::ConfirmedInvalid => {
            MediaFailureDisposition::ConfirmedInvalid
        }
    }
}

async fn authorize_and_send_media(
    state: &CpState,
    user_id: &str,
    claim: &MediaProcessingClaim,
    reserved_output_tokens: i64,
    prepared: vertex::PreparedMediaRequest,
) -> std::result::Result<MediaProviderStagedResponse, MediaWorkFailure> {
    let attempt = prepared.attempt().clone();
    let repository = state.repositories.media_processing();
    match repository
        .authorize_provider_attempt(claim, reserved_output_tokens, &attempt)
        .await
    {
        Ok(()) => {
            // This is deliberately the first and only await after the final
            // authorization succeeds: it crosses the provider boundary.
            let response = prepared.send().await.map_err(|failure| {
                MediaWorkFailure::provider(
                    failure.into_error(),
                    MediaFailureDisposition::AmbiguousTerminal,
                    attempt.clone(),
                )
            })?;
            if let Err(error) = repository.stage_provider_response(claim, &response).await {
                let settlement = super::model_usage::settle_ambiguous_required(
                    state,
                    user_id,
                    &attempt.event_id,
                    Some(response.http_status),
                )
                .await;
                return Err(MediaWorkFailure::provider(
                    settlement.err().unwrap_or(error),
                    MediaFailureDisposition::AmbiguousTerminal,
                    attempt,
                ));
            }
            Ok(response)
        }
        Err(error) => {
            let settlement = super::model_usage::settle_pre_egress_not_billed_required(
                state,
                user_id,
                &attempt.event_id,
            )
            .await;
            match settlement {
                Ok(()) => Err(MediaWorkFailure::provider(
                    error,
                    MediaFailureDisposition::RetryableNotBilled,
                    attempt,
                )),
                Err(settlement_error) => {
                    let _ = super::model_usage::settle_ambiguous_required(
                        state,
                        user_id,
                        &attempt.event_id,
                        None,
                    )
                    .await;
                    Err(MediaWorkFailure::provider(
                        settlement_error,
                        MediaFailureDisposition::AmbiguousTerminal,
                        attempt,
                    ))
                }
            }
        }
    }
}

async fn settle_staged_media(
    state: &CpState,
    user_id: &str,
    claim: &MediaProcessingClaim,
    response: MediaProviderStagedResponse,
) -> std::result::Result<(), MediaWorkFailure> {
    let operation = match claim.class {
        MediaProcessingClass::Audio => vertex::VertexOperation::AudioWindow,
        MediaProcessingClass::Screen => vertex::VertexOperation::ScreenStoryboard,
    };
    let output_tokens = match claim.class {
        MediaProcessingClass::Audio => vertex::MAX_MEDIA_OUTPUT_TOKENS,
        MediaProcessingClass::Screen => vertex::MAX_SCREEN_OUTPUT_TOKENS,
    };
    let generation = match vertex::parse_staged_media_response(&response, operation, output_tokens)
    {
        Ok(generation) => generation,
        Err(failure) => {
            let disposition = mapped_provider_disposition(failure.disposition);
            let settlement = match disposition {
                MediaFailureDisposition::RetryableNotBilled => {
                    super::model_usage::settle_not_billed_required(
                        state,
                        user_id,
                        &response.attempt.event_id,
                        response.http_status,
                    )
                    .await
                }
                MediaFailureDisposition::AmbiguousTerminal
                | MediaFailureDisposition::ConfirmedInvalid => {
                    super::model_usage::settle_ambiguous_required(
                        state,
                        user_id,
                        &response.attempt.event_id,
                        Some(response.http_status),
                    )
                    .await
                }
                MediaFailureDisposition::RetryableBeforeEgress => Err(EnclaveError::Store(
                    "staged provider response was classified before egress".into(),
                )),
            };
            let error = settlement.err().unwrap_or_else(|| failure.into_error());
            return Err(MediaWorkFailure::provider(
                error,
                disposition,
                response.attempt,
            ));
        }
    };

    if let Err(error) = super::model_usage::settle_response_required(
        state,
        user_id,
        &generation.event_id,
        &generation.metadata,
    )
    .await
    {
        return Err(MediaWorkFailure::staged(error, response.attempt));
    }
    let repository = state.repositories.media_processing();
    if let Err(error) = repository
        .settle_usage(MediaUsageSettlement {
            claim: claim.clone(),
            provider_attempt: response.attempt.clone(),
            usage: media_usage(claim, &generation),
        })
        .await
    {
        return Err(MediaWorkFailure::staged(error, response.attempt));
    }

    if claim.class == MediaProcessingClass::Audio {
        let window_start = claim
            .jobs
            .iter()
            .filter_map(|job| isotime::parse_epoch_millis(&job.started_at))
            .min()
            .ok_or_else(|| {
                MediaWorkFailure::provider(
                    EnclaveError::InvalidRequest("audio window is empty".into()),
                    MediaFailureDisposition::ConfirmedInvalid,
                    response.attempt.clone(),
                )
            })?;
        let window_end = claim
            .jobs
            .iter()
            .filter_map(|job| isotime::parse_epoch_millis(&job.ended_at))
            .max()
            .ok_or_else(|| {
                MediaWorkFailure::provider(
                    EnclaveError::InvalidRequest("audio window is empty".into()),
                    MediaFailureDisposition::ConfirmedInvalid,
                    response.attempt.clone(),
                )
            })?;
        let turns = parse_audio_result(&generation.text, window_end.saturating_sub(window_start))
            .map_err(|error| {
            MediaWorkFailure::provider(
                error,
                MediaFailureDisposition::ConfirmedInvalid,
                response.attempt.clone(),
            )
        })?;
        repository
            .settle_audio(AudioMediaSettlement {
                claim: claim.clone(),
                provider_attempt: response.attempt.clone(),
                turns,
            })
            .await
            .map_err(|error| MediaWorkFailure::staged(error, response.attempt))
    } else {
        let expected = claim
            .jobs
            .iter()
            .map(|job| job.event_id.clone())
            .collect::<Vec<_>>();
        let results = validate_storyboard_result(&generation.text, &expected)
            .map_err(|error| {
                MediaWorkFailure::provider(
                    error,
                    MediaFailureDisposition::ConfirmedInvalid,
                    response.attempt.clone(),
                )
            })?
            .into_iter()
            .map(|(event_id, result)| MediaScreenProjection {
                event_id,
                literal_description: result.literal_description,
                screen_state: result.screen_state,
                content_type: result.content_type,
                visible_text: result.visible_text,
                salient_text: result.salient_text,
                people: result
                    .people
                    .into_iter()
                    .map(|person| MediaPersonEvidence {
                        name: person.name,
                        evidence: person.evidence,
                        confidence: person.confidence,
                        is_active_speaker: person.is_active_speaker,
                    })
                    .collect(),
            })
            .collect();
        repository
            .settle_screens(ScreenMediaSettlement {
                claim: claim.clone(),
                provider_attempt: response.attempt.clone(),
                results,
            })
            .await
            .map_err(|error| MediaWorkFailure::staged(error, response.attempt))
    }
}

async fn process_work_unit(
    state: &CpState,
    user_id: &str,
    claim: &MediaProcessingClaim,
) -> std::result::Result<(), MediaWorkFailure> {
    if let Some(response) = claim.staged_response.clone() {
        return settle_staged_media(state, user_id, claim, response).await;
    }
    let work = MediaWorkUnit {
        jobs: claim.jobs.iter().map(MediaJob::from).collect(),
    };
    let mut media = Vec::with_capacity(claim.jobs.len());
    for job in &claim.jobs {
        media.push(load_job_media(state, user_id, job).await?);
    }
    let repository = state.repositories.media_processing();
    let reserved_output_tokens = reserve_media_output(state, user_id, claim).await?;
    let prepared = if claim.class == MediaProcessingClass::Audio {
        let (window, _sources, _duration_ms) = assemble_audio_window(&work.jobs, &media)?;
        let candidate_names = repository.candidate_name_vocabulary(user_id).await?;
        let prompt = format!(
            "Transcribe this audio exactly. The source kind is {}. Return chronological speaker turns with millisecond offsets from the beginning. Keep stable speaker_local_id values within this entire asset. Prefer an existing local id whenever the voice remains acoustically consistent. Do not invent a new speaker solely because of a one-word interjection, a short phrase, a pause, changed volume or prosody, device movement, or background noise; create a new local id only when sustained acoustic evidence supports a different human voice. Mark overlap. Only populate speaker_name, speaker_name_confidence, and speaker_name_evidence when the audio itself explicitly supports the person's full or partial name; never guess from voice alone. When speaker_name is populated, you MUST set speaker_name_kind ('self_identification' when the speaker identifies themselves, 'vocative_address' when addressing someone, 'third_party_mention' when mentioning someone), speaker_name_subject_turn_id (the turn_id of the speaker who is identified or named), and speaker_name_target_turn_id (for vocative_address, the turn_id of the speaker being addressed). A bare name is self_identification only when it answers a preceding request for that speaker's name. Never mark a speaker as self_identification merely because they repeat, spell, correct, or expand another speaker's name: after A answers 'Sarah', if B says 'Sarah Babetski', B's statement is a third_party_mention whose speaker_name_subject_turn_id points to A's turn, not B's identity. For every turn, include only durable person_facts explicitly supported by that turn, with literal evidence; never infer sensitive traits or unstated facts. The following bounded names are spelling vocabulary only, not proof that anyone is present, speaking, or has any identity: {}",
            work.jobs[0].stream_kind,
            serde_json::to_string(&candidate_names)?
        );
        vertex::prepare_media_custom(
            state,
            user_id,
            &claim.work_unit_id,
            claim.provider_attempt_number,
            vertex::VertexOperation::AudioWindow,
            &prompt,
            "audio/wav",
            &window,
            audio_schema(),
            true,
        )
        .await
    } else {
        let prompt = "Inspect every labeled screenshot literally and return exactly one result for every supplied frame_id. Never invent, omit, merge, or duplicate a frame ID. Transcribe useful visible text, produce a compact salient-text projection and literal description, and classify screen_state/content_type per frame. List a person only when a visible name label supports it, preferring the complete first and last name. Set is_active_speaker true only for the specific frame where the meeting UI visibly marks that exact label as currently speaking; otherwise false. Evidence must quote or describe the visible label/highlight; never infer identity from a face.";
        let inputs = work
            .jobs
            .iter()
            .zip(&media)
            .map(|(job, bytes)| vertex::MediaInput::new(&job.event_id, &job.mime_type, bytes))
            .collect::<Vec<_>>();
        vertex::prepare_media_parts_custom(
            state,
            user_id,
            &claim.work_unit_id,
            claim.provider_attempt_number,
            vertex::VertexOperation::ScreenStoryboard,
            prompt,
            &inputs,
            storyboard_schema(),
            vertex::MAX_SCREEN_OUTPUT_TOKENS,
        )
        .await
    };
    let prepared = match prepared {
        Ok(vertex::PreparedMediaInvocation::Send(prepared)) => *prepared,
        Ok(vertex::PreparedMediaInvocation::ConfirmedNotBilled(attempt)) => {
            return Err(MediaWorkFailure::provider(
                EnclaveError::Conflict(
                    "media provider attempt was already confirmed not billed".into(),
                ),
                MediaFailureDisposition::RetryableNotBilled,
                attempt,
            ));
        }
        Ok(vertex::PreparedMediaInvocation::AmbiguousTerminal(attempt)) => {
            return Err(MediaWorkFailure::provider(
                EnclaveError::Conflict("media provider attempt cannot be safely resent".into()),
                MediaFailureDisposition::AmbiguousTerminal,
                attempt,
            ));
        }
        Err(failure) => return Err(MediaWorkFailure::before_egress(failure.into_error())),
    };
    let response =
        authorize_and_send_media(state, user_id, claim, reserved_output_tokens, prepared).await?;
    settle_staged_media(state, user_id, claim, response).await
}
fn assemble_audio_window(
    jobs: &[MediaJob],
    media: &[Vec<u8>],
) -> Result<(Vec<u8>, Vec<SourceInterval>, i64)> {
    if jobs.is_empty() || jobs.len() != media.len() {
        return Err(EnclaveError::InvalidRequest(
            "audio window members are invalid".into(),
        ));
    }
    let window_started_ms = isotime::parse_epoch_millis(&jobs[0].started_at)
        .ok_or_else(|| EnclaveError::InvalidRequest("audio window timestamp is invalid".into()))?;
    let window_ended_ms = jobs
        .iter()
        .filter_map(|job| isotime::parse_epoch_millis(&job.ended_at))
        .max()
        .ok_or_else(|| EnclaveError::InvalidRequest("audio window timestamp is invalid".into()))?;
    let duration_ms = window_ended_ms.saturating_sub(window_started_ms);
    if !(1..=media_planner::MAX_AUDIO_WINDOW_MS).contains(&duration_ms) {
        return Err(EnclaveError::InvalidRequest(
            "audio window duration is outside allowed bounds".into(),
        ));
    }
    let sample_count =
        ((duration_ms as u64 * super::voice_memory::TARGET_SAMPLE_RATE as u64) / 1_000) as usize;
    let mut samples = vec![0_f32; sample_count];
    let mut weights = vec![0_u8; sample_count];
    let mut sources = Vec::with_capacity(jobs.len());
    for (job, bytes) in jobs.iter().zip(media) {
        let started_ms = isotime::parse_epoch_millis(&job.started_at).ok_or_else(|| {
            EnclaveError::InvalidRequest("audio event timestamp is invalid".into())
        })?;
        let ended_ms = isotime::parse_epoch_millis(&job.ended_at).ok_or_else(|| {
            EnclaveError::InvalidRequest("audio event timestamp is invalid".into())
        })?;
        let source_start_ms = started_ms - window_started_ms;
        let source_end_ms = ended_ms - window_started_ms;
        sources.push(SourceInterval::new(
            &job.event_id,
            source_start_ms,
            source_end_ms,
        ));
        let decoded = super::voice_memory::decode_mono_16khz(bytes, &job.mime_type)?;
        let destination_start = ((source_start_ms.max(0) as u64
            * super::voice_memory::TARGET_SAMPLE_RATE as u64)
            / 1_000) as usize;
        let authoritative_len = (((source_end_ms - source_start_ms).max(0) as u64
            * super::voice_memory::TARGET_SAMPLE_RATE as u64)
            / 1_000) as usize;
        for (index, sample) in decoded.iter().take(authoritative_len).enumerate() {
            let destination = destination_start.saturating_add(index);
            if destination >= samples.len() {
                break;
            }
            let weight = weights[destination];
            samples[destination] = if weight == 0 {
                *sample
            } else {
                (samples[destination] * f32::from(weight) + *sample) / (f32::from(weight) + 1.0)
            };
            weights[destination] = weight.saturating_add(1);
        }
    }
    Ok((
        super::voice_memory::encode_mono_16khz_wav(&samples)?,
        sources,
        duration_ms,
    ))
}

async fn process_user(state: &CpState, user_id: &str) {
    let repository = state.repositories.media_processing();
    let now = now_iso();
    if let Err(error) = repository
        .resurrect_recent_failures(
            user_id,
            &now,
            RESURRECTION_DELAY_SECONDS,
            RESURRECTION_TOTAL_ATTEMPT_CAP,
            RESURRECTION_WINDOW_SECONDS_INTEGRAL,
            RESURRECTION_MAX_PER_SWEEP,
        )
        .await
    {
        warn!(user_id, error = %error, "media resurrection failed");
    }
    let (audio_pending, screen_pending) = match repository.pending_classes(user_id, &now).await {
        Ok(pending) => pending,
        Err(error) => {
            warn!(user_id, error = %error, "media class scan failed");
            return;
        }
    };
    let mut completed_work = false;
    for class in
        media_planner::schedule_classes(audio_pending, screen_pending, MAX_JOBS_PER_USER_PER_SWEEP)
    {
        let class = match class {
            WorkClass::Audio => MediaProcessingClass::Audio,
            WorkClass::Screen => MediaProcessingClass::Screen,
        };
        let claim = match repository
            .claim(
                user_id,
                class,
                &now_iso(),
                CLAIM_LEASE_SECONDS,
                CLAIM_SCAN_LIMIT,
            )
            .await
        {
            Ok(claim) => claim,
            Err(error) => {
                warn!(user_id, class = class.as_str(), error = %error, "media claim failed");
                continue;
            }
        };
        let Some(claim) = claim else {
            continue;
        };
        if let Err(failure) = process_work_unit(state, user_id, &claim).await {
            let error_code = match (&failure.disposition, &failure.error) {
                (MediaFailureDisposition::AmbiguousTerminal, _) => "vertex_ambiguous",
                (MediaFailureDisposition::ConfirmedInvalid, _) => "invalid_model_output",
                (MediaFailureDisposition::RetryableNotBilled, EnclaveError::Config(message))
                    if message == "quota" =>
                {
                    "vertex_quota"
                }
                (MediaFailureDisposition::RetryableNotBilled, _) => "vertex_not_billed",
                (_, error) => match error {
                    EnclaveError::Config(ref message) if message == "quota" => "vertex_quota",
                    EnclaveError::Config(ref message) if message == "vertex_daily_budget" => {
                        "vertex_daily_budget"
                    }
                    EnclaveError::Json(_) | EnclaveError::InvalidRequest(_) => {
                        "invalid_model_output"
                    }
                    EnclaveError::Crypto(_) => "media_integrity",
                    EnclaveError::Conflict(ref message)
                        if message == TRANSCRIPT_TARGET_CONFLICT =>
                    {
                        TRANSCRIPT_TARGET_CONFLICT
                    }
                    _ => "processing_error",
                },
            };
            warn!(
                user_id,
                work_unit_id = claim.work_unit_id,
                error_code,
                error = %failure.error,
                "media work unit failed"
            );
            if failure.preserve_staged_response {
                // Exact response bytes and usage identity are durable. Leave
                // the claim to expire so a new owner replays providerlessly.
                return;
            }
            if let Err(settle_error) = repository
                .settle_failure(
                    &claim,
                    failure.provider_attempt.as_ref(),
                    failure.disposition,
                    error_code,
                    &now_iso(),
                    MediaFailurePolicy {
                        max_attempts: MAX_ATTEMPTS,
                        budget_retry_seconds: BUDGET_RETRY_SECONDS,
                        resurrection_window_seconds: RESURRECTION_WINDOW_SECONDS_INTEGRAL,
                    },
                )
                .await
            {
                warn!(
                    user_id,
                    work_unit_id = claim.work_unit_id,
                    error = %settle_error,
                    "media failure settlement failed"
                );
                return;
            }
            if matches!(error_code, "vertex_quota" | "vertex_daily_budget") {
                return;
            }
        }
        completed_work = true;
    }
    if completed_work {
        super::summarizer::kick_session_settled(user_id);
    }
}
async fn sweep(state: &Arc<CpState>) {
    let users = match state.repositories.work().active_account_ids().await {
        Ok(users) => users,
        Err(error) => {
            warn!(error = %error, "media worker user listing failed");
            return;
        }
    };
    let mut tasks = JoinSet::new();
    for user_id in users {
        if tasks.len() >= MAX_CONCURRENT_USER_SWEEPS {
            if let Some(Err(error)) = tasks.join_next().await {
                warn!(error = %error, "media user worker task failed");
            }
        }
        let state = Arc::clone(state);
        tasks.spawn(async move {
            process_user(&state, &user_id).await;
        });
    }
    while let Some(result) = tasks.join_next().await {
        if let Err(error) = result {
            warn!(error = %error, "media user worker task failed");
        }
    }
}

pub fn spawn_scheduler(state: Arc<CpState>) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(WORKER_INTERVAL_SECONDS));
        loop {
            interval.tick().await;
            sweep(&state).await;
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    fn storyboard_json(ids: &[&str]) -> String {
        serde_json::to_string(&json!({
            "frames": ids.iter().map(|id| json!({
                "frame_id": id,
                "literal_description": "A document",
                "screen_state": "content",
                "content_type": "document",
                "visible_text": "visible",
                "salient_text": "salient",
                "people": []
            })).collect::<Vec<_>>()
        }))
        .unwrap()
    }

    #[test]
    fn inference_attempts_and_resurrection_are_bounded() {
        assert_eq!(MAX_JOBS_PER_USER_PER_SWEEP, 2);
        assert_eq!(MAX_ATTEMPTS, 3);
        assert_eq!(RESURRECTION_DELAY_SECONDS, 3_600);
        assert_eq!(RESURRECTION_TOTAL_ATTEMPT_CAP, 9);
        assert_eq!(RESURRECTION_WINDOW_SECONDS, 604_800.0);
        assert_eq!(RESURRECTION_MAX_PER_SWEEP, 16);
        assert_eq!(RESURRECTION_MEMORY_HOLD_TOTAL_ATTEMPTS, MAX_ATTEMPTS + 2);
    }

    #[test]
    fn storyboard_requires_exact_frame_coverage_and_restores_input_order() {
        let expected = vec!["frame-a".to_string(), "frame-b".to_string()];
        let ordered =
            validate_storyboard_result(&storyboard_json(&["frame-b", "frame-a"]), &expected)
                .unwrap();
        assert_eq!(
            ordered.into_iter().map(|(id, _)| id).collect::<Vec<_>>(),
            expected
        );
        assert!(validate_storyboard_result(&storyboard_json(&["frame-a"]), &expected).is_err());
        assert!(
            validate_storyboard_result(&storyboard_json(&["frame-a", "frame-a"]), &expected)
                .is_err()
        );
        assert!(
            validate_storyboard_result(&storyboard_json(&["frame-a", "unknown"]), &expected)
                .is_err()
        );
    }

    #[test]
    fn audio_window_preserves_exact_source_intervals() {
        let first = MediaJob {
            event_id: "event-a".into(),
            mime_type: "audio/wav".into(),
            started_at: "2026-08-28T12:00:00.000Z".into(),
            ended_at: "2026-08-28T12:00:01.000Z".into(),
            stream_kind: "mic".into(),
        };
        let second = MediaJob {
            event_id: "event-b".into(),
            mime_type: "audio/wav".into(),
            started_at: "2026-08-28T12:00:01.000Z".into(),
            ended_at: "2026-08-28T12:00:02.000Z".into(),
            stream_kind: "mic".into(),
        };
        let wav_a = super::super::voice_memory::encode_mono_16khz_wav(&vec![0.1; 16_000]).unwrap();
        let wav_b = super::super::voice_memory::encode_mono_16khz_wav(&vec![0.2; 16_000]).unwrap();
        let (_, sources, duration_ms) =
            assemble_audio_window(&[first, second], &[wav_a, wav_b]).unwrap();
        assert_eq!(duration_ms, 2_000);
        assert_eq!(
            sources,
            vec![
                SourceInterval::new("event-a", 0, 1_000),
                SourceInterval::new("event-b", 1_000, 2_000),
            ]
        );
    }

    #[test]
    fn provider_effects_follow_final_authorization_stage_and_usage_settlement() {
        let source = include_str!("media_worker.rs");
        let user_start = source.find("async fn process_user").unwrap();
        let user_end = source.find("async fn sweep").unwrap();
        let user = &source[user_start..user_end];
        assert!(user.find(".claim(").unwrap() < user.find("process_work_unit(").unwrap());

        let work_start = source.find("async fn process_work_unit").unwrap();
        let work_end = source.find("fn assemble_audio_window").unwrap();
        let work = &source[work_start..work_end];
        let reserve = work.find("reserve_media_output(").unwrap();
        let prepare = work.find("prepare_media_custom(").unwrap();
        let authorize_send = work.find("authorize_and_send_media(").unwrap();
        let settle_stage = work.rfind("settle_staged_media(").unwrap();
        assert!(reserve < prepare);
        assert!(prepare < authorize_send);
        assert!(authorize_send < settle_stage);
        assert_eq!(work.matches("reserve_media_output(").count(), 1);
        assert_eq!(work.matches("prepare_media_custom(").count(), 1);
        assert_eq!(work.matches("prepare_media_parts_custom(").count(), 1);

        let egress_start = source.find("async fn authorize_and_send_media").unwrap();
        let egress_end = source[egress_start..]
            .find("async fn settle_staged_media")
            .unwrap()
            + egress_start;
        let egress = &source[egress_start..egress_end];
        let authorize = egress.find(".authorize_provider_attempt(").unwrap();
        let send = egress.find("prepared.send().await").unwrap();
        let stage = egress.find("stage_provider_response(").unwrap();
        let authorized_arm = egress[authorize..send].find("Ok(()) =>").unwrap() + authorize;
        assert!(authorize < authorized_arm);
        assert!(authorized_arm < send);
        assert!(send < stage);
        assert!(!egress[authorized_arm..send].contains(".await"));

        let settle_start = source.find("async fn settle_staged_media").unwrap();
        let settle_end = source[settle_start..]
            .find("async fn process_work_unit")
            .unwrap()
            + settle_start;
        let settle = &source[settle_start..settle_end];
        let parse = settle.find("parse_staged_media_response(").unwrap();
        let required_usage = settle.find("settle_response_required(").unwrap();
        let durable_usage = settle.find(".settle_usage(").unwrap();
        let projection = settle.find(".settle_audio(").unwrap();
        assert!(parse < required_usage);
        assert!(required_usage < durable_usage);
        assert!(durable_usage < projection);
        assert_eq!(settle.matches("settle_response_required(").count(), 1);
        assert_eq!(settle.matches("&generation.event_id").count(), 1);
    }
}
