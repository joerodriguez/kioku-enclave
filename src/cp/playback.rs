//! Owner-only recording playback projections.
//!
//! The encrypted source M4A objects remain the authority. This module exposes
//! only opaque recording/track/segment identifiers, projects the existing
//! `speaker_observation_sources` coordinates onto a bounded memory timeline,
//! and follows the screenshot-content boundary when returning one complete
//! source segment: exact generation, owner/object AAD, DEK-envelope equality,
//! plaintext length, and SHA-256 are all revalidated inside the enclave.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::{Arc, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

use axum::{
    extract::{Path, Query, State},
    http::{header, HeaderValue, StatusCode},
    response::{IntoResponse, Json, Response},
    routing::get,
    Extension, Router,
};
use hmac::{Hmac, Mac};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};

use crate::error::{EnclaveError, Result};

use super::auth::AuthUser;
use super::CpState;

const PLAYBACK_MANIFEST_VERSION: u8 = 1;
const PLAYBACK_WINDOW_MS: i64 = 15 * 60 * 1_000;
const MAX_SEGMENTS_PER_WINDOW: usize = 128;
const MAX_UTTERANCES_PER_WINDOW: usize = 1_000;
const MAX_SOURCE_SPANS_PER_WINDOW: usize = 4_000;
pub(crate) const MAX_AUDIO_SEGMENT_BYTES: i64 = 20 * 1024 * 1024;
const SOURCE_CLOCK_TOLERANCE_MS: i64 = 2_000;
const PLAYBACK_CURSOR_TTL_SECONDS: i64 = 5 * 60;
const PEOPLE_MEMORIES_DEFAULT_LIMIT: usize = 25;
const PEOPLE_MEMORIES_MAX_LIMIT: usize = 100;

type HmacSha256 = Hmac<Sha256>;

fn manifest_limiter() -> &'static super::limits::RateLimiter {
    static LIMITER: OnceLock<super::limits::RateLimiter> = OnceLock::new();
    LIMITER.get_or_init(|| super::limits::RateLimiter::new(30.0, 3.0))
}

fn segment_limiter() -> &'static super::limits::RateLimiter {
    static LIMITER: OnceLock<super::limits::RateLimiter> = OnceLock::new();
    LIMITER.get_or_init(|| super::limits::RateLimiter::new(12.0, 2.0))
}

pub fn router() -> Router<Arc<CpState>> {
    Router::new()
        .route(
            "/api/v2/memories/{memory_id}/playback",
            get(memory_playback_manifest),
        )
        .route(
            "/api/v2/memories/{memory_id}/recordings/{recording_id}/segments/{segment_id}",
            get(memory_playback_segment),
        )
        .route("/api/v2/people/{person_id}/memories", get(person_memories))
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct PlaybackQuery {
    at_ms: Option<i64>,
    cursor: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SegmentQuery {
    projection_revision: i64,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct PersonMemoriesQuery {
    before_id: Option<i64>,
    limit: Option<usize>,
}

#[derive(Debug, Clone, Serialize)]
struct PlaybackTimeline {
    started_at: String,
    ended_at: String,
    duration_ms: i64,
    alignment_quality: &'static str,
}

#[derive(Debug, Clone, Serialize)]
struct PlaybackWindow {
    timeline_start_ms: i64,
    timeline_end_ms: i64,
}

#[derive(Debug, Clone, Serialize)]
struct PlaybackRecording {
    recording_id: String,
    timeline_start_ms: i64,
    timeline_end_ms: i64,
    availability: String,
}

#[derive(Debug, Clone, Serialize)]
struct PlaybackTrack {
    recording_id: String,
    track_id: String,
    kind: String,
    state: String,
}

#[derive(Debug, Clone, Serialize)]
struct PlaybackSegment {
    recording_id: String,
    segment_id: String,
    track_id: String,
    kind: String,
    timeline_start_ms: i64,
    timeline_end_ms: i64,
    duration_ms: i64,
    mime_type: &'static str,
    byte_length: Option<i64>,
    state: String,
}

#[derive(Debug, Clone, Serialize)]
struct PlaybackSourceSpan {
    recording_id: String,
    segment_id: Option<String>,
    segment_start_ms: i64,
    segment_end_ms: i64,
    timeline_start_ms: i64,
    timeline_end_ms: i64,
    source_state: &'static str,
    playable: bool,
}

#[derive(Debug, Clone, Serialize)]
struct PlaybackUtterance {
    utterance_id: i64,
    speaker_observation_id: Option<i64>,
    person_id: Option<i64>,
    display_name: String,
    attribution_state: String,
    timeline_start_ms: i64,
    timeline_end_ms: i64,
    text: String,
    overlap: bool,
    source_spans: Vec<PlaybackSourceSpan>,
}

#[derive(Debug, Clone, Serialize)]
struct PlaybackManifest {
    manifest_version: u8,
    memory_id: i64,
    projection_revision: i64,
    contributing_recording_count: usize,
    timeline: PlaybackTimeline,
    transcript_alignment_quality: &'static str,
    window: PlaybackWindow,
    next_cursor: Option<String>,
    availability: String,
    recordings: Vec<PlaybackRecording>,
    tracks: Vec<PlaybackTrack>,
    segments: Vec<PlaybackSegment>,
    utterances: Vec<PlaybackUtterance>,
}

#[derive(Debug, Clone)]
pub(crate) struct SegmentAuthority {
    pub(crate) recording_id: String,
    pub(crate) segment_id: String,
    pub(crate) track_id: String,
    pub(crate) kind: String,
    pub(crate) capture_session_id: String,
    pub(crate) stream_id: String,
    pub(crate) event_id: String,
    pub(crate) asset_id: Option<String>,
    pub(crate) object_key: Option<String>,
    pub(crate) generation: Option<i64>,
    pub(crate) object_backend: Option<String>,
    pub(crate) stored_mime_type: Option<String>,
    pub(crate) codec: Option<String>,
    pub(crate) byte_length: Option<i64>,
    pub(crate) sha256: Option<String>,
    pub(crate) processing_state: Option<String>,
    pub(crate) deleted_at: Option<String>,
    pub(crate) retention_decision: String,
    pub(crate) storage_backend: String,
    pub(crate) retention_policy_revision: Option<i64>,
    pub(crate) retention_policy_epoch: Option<String>,
    pub(crate) recording_key_epoch: Option<i64>,
    pub(crate) recording_state: String,
    pub(crate) durable_read_authorized: bool,
    pub(crate) timeline_start_ms: i64,
    pub(crate) timeline_end_ms: i64,
}

impl SegmentAuthority {
    fn readable(&self) -> bool {
        let retention_readable = match self.retention_decision.as_str() {
            "processing_window_30d" => {
                self.storage_backend == "processing" && self.recording_state == "processing_only"
            }
            "until_deleted" => {
                self.storage_backend == "recordings"
                    && self.recording_state == "durable"
                    && self.durable_read_authorized
                    && self
                        .retention_policy_revision
                        .is_some_and(|revision| revision > 0)
                    && self.retention_policy_epoch.is_some()
                    && self.recording_key_epoch.is_some_and(|epoch| epoch > 0)
            }
            _ => false,
        };
        self.generation.is_some_and(|generation| generation > 0)
            && self.object_backend.as_deref() == Some("current")
            && self
                .stored_mime_type
                .as_deref()
                .is_some_and(is_supported_audio_mime)
            && self.codec.as_deref() == Some("aac")
            && self
                .byte_length
                .is_some_and(|length| length > 0 && length <= MAX_AUDIO_SEGMENT_BYTES)
            && self.sha256.as_deref().is_some_and(valid_sha256)
            && self.processing_state.as_deref() == Some("ready")
            && self.deleted_at.is_none()
            && self.object_key.is_some()
            && self.asset_id.is_some()
            && retention_readable
    }

    fn state(&self) -> String {
        if self.deleted_at.is_some() || self.recording_state == "delete_pending" {
            "deleted".into()
        } else {
            match self.processing_state.as_deref() {
                Some("pruned") => "pruned".into(),
                Some("queued" | "processing" | "retry_wait") => "pending".into(),
                Some("ready") if self.readable() => "ready".into(),
                _ => "unavailable".into(),
            }
        }
    }

    fn view(&self) -> PlaybackSegment {
        PlaybackSegment {
            recording_id: self.recording_id.clone(),
            segment_id: self.segment_id.clone(),
            track_id: self.track_id.clone(),
            kind: self.kind.clone(),
            timeline_start_ms: self.timeline_start_ms,
            timeline_end_ms: self.timeline_end_ms,
            duration_ms: self.timeline_end_ms.saturating_sub(self.timeline_start_ms),
            mime_type: "audio/mp4",
            byte_length: self.byte_length,
            state: self.state(),
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct UtteranceAuthority {
    pub(crate) utterance_id: i64,
    pub(crate) observation_id: Option<i64>,
    pub(crate) timeline_start_ms: i64,
    pub(crate) timeline_end_ms: i64,
    pub(crate) text: String,
    pub(crate) fallback_label: String,
    pub(crate) overlap: bool,
    pub(crate) person_id: Option<i64>,
    pub(crate) display_name: Option<String>,
    pub(crate) attribution_state: Option<String>,
}

#[derive(Debug, Clone)]
pub(crate) struct SourceAuthority {
    pub(crate) observation_id: i64,
    pub(crate) event_id: String,
    pub(crate) window_start_ms: i64,
    pub(crate) window_end_ms: i64,
    pub(crate) event_start_ms: i64,
    pub(crate) event_end_ms: i64,
}

impl SourceAuthority {
    fn structurally_valid_for(&self, segment: &SegmentAuthority) -> bool {
        let window_duration = self.window_end_ms.checked_sub(self.window_start_ms);
        let event_duration = self.event_end_ms.checked_sub(self.event_start_ms);
        let segment_duration = segment
            .timeline_end_ms
            .checked_sub(segment.timeline_start_ms);
        self.window_start_ms >= 0
            && self.window_end_ms > self.window_start_ms
            && self.event_start_ms >= 0
            && self.event_end_ms > self.event_start_ms
            && window_duration == event_duration
            && segment_duration.is_some_and(|duration| {
                self.event_end_ms <= duration.saturating_add(SOURCE_CLOCK_TOLERANCE_MS)
            })
    }
}

#[derive(Debug, Clone)]
pub(crate) struct PlaybackDataset {
    pub(crate) owner_id: String,
    pub(crate) memory_id: i64,
    pub(crate) started_at: String,
    pub(crate) ended_at: String,
    pub(crate) duration_ms: i64,
    pub(crate) projection_revision: i64,
    pub(crate) segments: Vec<SegmentAuthority>,
    pub(crate) utterances: Vec<UtteranceAuthority>,
    pub(crate) sources: Vec<SourceAuthority>,
}

#[derive(Debug, Serialize)]
pub(crate) struct PersonMemorySummary {
    pub(crate) memory_id: i64,
    pub(crate) title: Option<String>,
    pub(crate) summary: Option<String>,
    pub(crate) started_at: String,
    pub(crate) ended_at: String,
    pub(crate) attributed_utterance_count: i64,
    pub(crate) contributing_recording_count: i64,
    pub(crate) audio_availability: String,
    pub(crate) playback_start_ms: Option<i64>,
    pub(crate) playback_utterance_id: Option<i64>,
}

#[derive(Debug, Serialize)]
pub(crate) struct PersonMemoriesPage {
    pub(crate) memories: Vec<PersonMemorySummary>,
    pub(crate) next_cursor: Option<i64>,
}

#[derive(Clone, Debug)]
pub(crate) struct DurableReadFence {
    pub(crate) policy_revision: i64,
    pub(crate) policy_epoch: String,
}

async fn current_durable_read_fence(
    state: &CpState,
    user_id: &str,
) -> Result<Option<DurableReadFence>> {
    let preference = state
        .repositories
        .recording_retention()
        .preference(user_id)
        .await?;
    if preference.policy == crate::persistence::RecordingRetentionPolicy::UntilDeleted
        && preference.operation_state.is_none()
    {
        let Some(policy_epoch) = preference.policy_epoch else {
            return Err(EnclaveError::Store(
                "durable recording read authority is malformed".into(),
            ));
        };
        return Ok(Some(DurableReadFence {
            policy_revision: preference.revision,
            policy_epoch,
        }));
    }
    Ok(None)
}

async fn memory_playback_manifest(
    State(state): State<Arc<CpState>>,
    Extension(user): Extension<AuthUser>,
    Path(memory_id): Path<i64>,
    Query(query): Query<PlaybackQuery>,
) -> Response {
    // The read path ships dark while epoch 2 is merely known/targeted. This
    // keeps the new browser plaintext boundary coupled to the same signed
    // release gate as durable ingest instead of exposing today's temporary
    // processing objects from an observe-only binary.
    if !playback_capability_available(&state) {
        return not_found();
    }
    if memory_id <= 0
        || query.at_ms.is_some_and(|at| at < 0)
        || (query.at_ms.is_some() && query.cursor.is_some())
    {
        return bad_request("invalid playback window");
    }
    let user_id = user.0;
    if !manifest_limiter()
        .consume_scoped(&state.repositories, "playback-manifest", &user_id)
        .await
    {
        return too_many_requests();
    }
    let durable_read = match current_durable_read_fence(&state, &user_id).await {
        Ok(value) => value,
        Err(error) => return super::routed_read_unavailable("api.memory_playback", &error),
    };
    let result = match state
        .repositories
        .playback()
        .dataset(&user_id, memory_id, durable_read.as_ref())
        .await
    {
        Ok(Some(dataset)) => playback_window_start(&dataset, &query)
            .and_then(|window_start| project_manifest(&dataset, window_start))
            .map(Some),
        Ok(None) => Ok(None),
        Err(error) => Err(error),
    };
    match result {
        Ok(Some(manifest)) => no_store_json(manifest),
        Ok(None) => not_found(),
        Err(EnclaveError::InvalidRequest(_)) => bad_request("invalid playback cursor"),
        Err(error) => super::routed_read_unavailable("api.memory_playback", &error),
    }
}

async fn memory_playback_segment(
    State(state): State<Arc<CpState>>,
    Extension(user): Extension<AuthUser>,
    Path((memory_id, recording_id, segment_id)): Path<(i64, String, String)>,
    Query(query): Query<SegmentQuery>,
) -> Response {
    if !playback_capability_available(&state) {
        return not_found();
    }
    if memory_id <= 0
        || query.projection_revision <= 0
        || !valid_public_id(&recording_id, "rec_")
        || !valid_public_id(&segment_id, "seg_")
    {
        return not_found();
    }

    let user_id = user.0;
    if !segment_limiter()
        .consume_scoped(&state.repositories, "playback-segment", &user_id)
        .await
    {
        return too_many_requests();
    }
    let durable_read = match current_durable_read_fence(&state, &user_id).await {
        Ok(value) => value,
        Err(error) => return super::routed_read_unavailable("api.playback_segment.lookup", &error),
    };
    let lookup_user = user_id.clone();
    let requested_recording = recording_id.clone();
    let requested_segment = segment_id.clone();
    let lookup = match state
        .repositories
        .playback()
        .dataset(&user_id, memory_id, durable_read.as_ref())
        .await
    {
        Ok(Some(dataset)) => {
            if dataset.projection_revision != query.projection_revision {
                Err(EnclaveError::Conflict(
                    "playback projection revision changed".into(),
                ))
            } else {
                let segment = dataset
                    .segments
                    .into_iter()
                    .find(|candidate| {
                        candidate.recording_id == requested_recording
                            && candidate.segment_id == requested_segment
                    })
                    .filter(SegmentAuthority::readable);
                let wrapped_dek = if segment
                    .as_ref()
                    .is_some_and(|segment| segment.retention_decision == "processing_window_30d")
                {
                    match state
                        .repositories
                        .captures()
                        .media_dek_wrapped(&user_id)
                        .await
                    {
                        Ok(value) => value,
                        Err(error) => {
                            return super::routed_read_unavailable(
                                "api.playback_segment.lookup",
                                &error,
                            )
                        }
                    }
                } else {
                    None
                };
                Ok(segment.map(|segment| (segment, wrapped_dek)))
            }
        }
        Ok(None) => Ok(None),
        Err(error) => Err(error),
    };

    let (authority, wrapped_dek) = match lookup {
        Ok(Some(value)) => value,
        Ok(None) => return not_found(),
        Err(EnclaveError::Conflict(_)) => {
            return no_store_error(
                StatusCode::CONFLICT,
                json!({"error": "playback_revision_changed"}),
            )
        }
        Err(error) => return super::routed_read_unavailable("api.playback_segment.lookup", &error),
    };
    let object_key = authority.object_key.as_deref().unwrap_or_default();
    let asset_id = authority.asset_id.as_deref().unwrap_or_default();
    let expected_key = match authority.retention_decision.as_str() {
        "processing_window_30d" => {
            crate::gcs::canonical_capture_media_object_key(&lookup_user, asset_id)
        }
        "until_deleted" => crate::gcs::canonical_recording_media_object_key(&lookup_user, asset_id),
        _ => Err(EnclaveError::Store(
            "playback segment retention authority is invalid".into(),
        )),
    };
    let expected_key = match expected_key {
        Ok(value) => value,
        Err(_) => {
            tracing::error!("playback segment asset identity is malformed");
            return internal_error();
        }
    };
    if object_key != expected_key {
        tracing::error!("playback segment object identity mismatch");
        return internal_error();
    }

    let generation = authority.generation.unwrap_or_default();
    let object = match state
        .repositories
        .media_objects()
        .get_current_generation(object_key, generation)
        .await
    {
        Ok(value) => value,
        Err(EnclaveError::NotFound) => {
            return super::routed_read_unavailable(
                "api.playback_segment.object_missing",
                &EnclaveError::Store("sealed playback segment generation is unavailable".into()),
            )
        }
        Err(error) => return super::routed_read_unavailable("api.playback_segment.object", &error),
    };
    let (provider_key_reference, media_dek, context) = match authority.retention_decision.as_str() {
        "processing_window_30d" => {
            let Some(wrapped_dek) = wrapped_dek else {
                tracing::error!("playback segment has no media DEK authority");
                return internal_error();
            };
            let media_dek = match crate::crypto::load_dek(state.kms.as_ref(), &wrapped_dek).await {
                Ok(value) => value,
                Err(error @ (EnclaveError::Http(_) | EnclaveError::Attestation(_))) => {
                    return super::routed_read_unavailable("api.playback_segment.kms", &error)
                }
                Err(error) => {
                    tracing::error!(error = %error, "playback media DEK load failed");
                    return internal_error();
                }
            };
            (
                wrapped_dek,
                media_dek,
                crate::gcs::media_blob_context(&lookup_user, object_key),
            )
        }
        "until_deleted" => {
            let (Some(policy_epoch), Some(key_epoch), Some(media)) = (
                authority.retention_policy_epoch.as_deref(),
                authority.recording_key_epoch,
                authority.asset_id.as_deref(),
            ) else {
                tracing::error!("playback recording-key authority is incomplete");
                return internal_error();
            };
            let provider_key_reference =
                match crate::gcs::recording_media_key_reference(key_epoch, policy_epoch) {
                    Ok(value) => value,
                    Err(_) => return internal_error(),
                };
            let media_dek = match state
                .repositories
                .recording_retention()
                .key_epoch(&lookup_user, key_epoch, policy_epoch)
                .await
            {
                Ok(Some(value)) => {
                    match crate::crypto::load_dek(state.kms.as_ref(), &value.wrapped_dek_b64).await
                    {
                        Ok(value) => value,
                        Err(error @ (EnclaveError::Http(_) | EnclaveError::Attestation(_))) => {
                            return super::routed_read_unavailable(
                                "api.playback_segment.kms",
                                &error,
                            )
                        }
                        Err(error) => {
                            tracing::error!(error = %error, "playback recording key load failed");
                            return internal_error();
                        }
                    }
                }
                Ok(None) => return internal_error(),
                Err(error) => {
                    tracing::error!(error = %error, "playback recording key lookup failed");
                    return internal_error();
                }
            };
            let context = match crate::gcs::recording_media_blob_context(
                &lookup_user,
                object_key,
                key_epoch,
                policy_epoch,
                &authority.event_id,
                media,
                &authority.capture_session_id,
                &authority.kind,
                authority.codec.as_deref().unwrap_or_default(),
                authority.byte_length.unwrap_or_default(),
                authority.sha256.as_deref().unwrap_or_default(),
            ) {
                Ok(value) => value,
                Err(_) => return internal_error(),
            };
            (provider_key_reference, media_dek, context)
        }
        _ => return internal_error(),
    };
    if object.generation != generation || object.wrapped_dek_b64 != provider_key_reference {
        tracing::error!("playback segment provider identity mismatch");
        return internal_error();
    }
    let opened =
        match crate::crypto::decrypt_bound_blob_v2(&media_dek, &object.ciphertext, &context) {
            Ok(value) => value,
            Err(error) => {
                tracing::error!(error = %error, "playback segment authentication failed");
                return internal_error();
            }
        };
    let expected_length = authority.byte_length.unwrap_or_default();
    let expected_sha = authority.sha256.as_deref().unwrap_or_default();
    let actual_sha = format!("{:x}", Sha256::digest(&opened.plaintext));
    if i64::try_from(opened.plaintext.len()).ok() != Some(expected_length)
        || !actual_sha.eq_ignore_ascii_case(expected_sha)
        || !looks_like_iso_bmff_audio(&opened.plaintext)
    {
        tracing::error!("playback segment plaintext commitment mismatch");
        return internal_error();
    }

    let mut response = (StatusCode::OK, opened.plaintext).into_response();
    let headers = response.headers_mut();
    headers.insert(header::CONTENT_TYPE, HeaderValue::from_static("audio/mp4"));
    headers.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("private, no-store, max-age=0"),
    );
    headers.insert(header::PRAGMA, HeaderValue::from_static("no-cache"));
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    if let Ok(value) = HeaderValue::from_str(&expected_length.to_string()) {
        headers.insert(header::CONTENT_LENGTH, value);
    }
    response
}

fn playback_capability_available(state: &CpState) -> bool {
    state.durable_recording_storage_bound
}

async fn person_memories(
    State(state): State<Arc<CpState>>,
    Extension(user): Extension<AuthUser>,
    Path(person_id): Path<i64>,
    Query(query): Query<PersonMemoriesQuery>,
) -> Response {
    if person_id <= 0 || query.before_id.is_some_and(|cursor| cursor <= 0) {
        return bad_request("person_id and before_id must be positive");
    }
    if !manifest_limiter()
        .consume_scoped(&state.repositories, "playback-person-memories", &user.0)
        .await
    {
        return too_many_requests();
    }
    let limit = query
        .limit
        .unwrap_or(PEOPLE_MEMORIES_DEFAULT_LIMIT)
        .clamp(1, PEOPLE_MEMORIES_MAX_LIMIT);
    let before_id = query.before_id;
    let user_id = user.0;
    let durable_read = match current_durable_read_fence(&state, &user_id).await {
        Ok(value) => value,
        Err(error) => return super::routed_read_unavailable("api.person_memories", &error),
    };
    let result = state
        .repositories
        .playback()
        .person_memories(&user_id, person_id, before_id, limit, durable_read.as_ref())
        .await;
    match result {
        Ok(page) => no_store_json(page),
        Err(EnclaveError::NotFound) => not_found(),
        Err(error) => super::routed_read_unavailable("api.person_memories", &error),
    }
}

pub(crate) fn resolve_utterance_interval(
    observation_start: Option<&str>,
    observation_end: Option<&str>,
    segment_start: &str,
    start_offset_seconds: f64,
    end_offset_seconds: f64,
) -> Option<(i64, i64)> {
    let interval = match (observation_start, observation_end) {
        (Some(start), Some(end)) => (
            super::isotime::parse_epoch_millis(start)?,
            super::isotime::parse_epoch_millis(end)?,
        ),
        (None, None) => {
            if !start_offset_seconds.is_finite()
                || !end_offset_seconds.is_finite()
                || start_offset_seconds < 0.0
                || end_offset_seconds <= start_offset_seconds
                || end_offset_seconds > 24.0 * 60.0 * 60.0
            {
                return None;
            }
            let segment_start = super::isotime::parse_epoch_millis(segment_start)?;
            let start_offset_ms = (start_offset_seconds * 1_000.0).round() as i64;
            let end_offset_ms = (end_offset_seconds * 1_000.0).round() as i64;
            (
                segment_start.checked_add(start_offset_ms)?,
                segment_start.checked_add(end_offset_ms)?,
            )
        }
        _ => return None,
    };
    (interval.1 > interval.0).then_some(interval)
}

fn project_manifest(dataset: &PlaybackDataset, window_start_ms: i64) -> Result<PlaybackManifest> {
    let window_end_ms = window_start_ms
        .saturating_add(PLAYBACK_WINDOW_MS)
        .min(dataset.duration_ms);
    let mut selected_segments: Vec<&SegmentAuthority> = dataset
        .segments
        .iter()
        .filter(|segment| {
            segment.timeline_end_ms > window_start_ms && segment.timeline_start_ms < window_end_ms
        })
        .take(MAX_SEGMENTS_PER_WINDOW)
        .collect();
    selected_segments.sort_by_key(|segment| {
        (
            segment.timeline_start_ms,
            segment.kind.clone(),
            segment.segment_id.clone(),
        )
    });

    let selected_segment_ids: HashSet<&str> = selected_segments
        .iter()
        .map(|segment| segment.segment_id.as_str())
        .collect();
    let segment_by_event: HashMap<&str, &SegmentAuthority> = dataset
        .segments
        .iter()
        .map(|segment| (segment.event_id.as_str(), segment))
        .collect();
    let sources_by_observation = dataset.sources.iter().fold(
        HashMap::<i64, Vec<&SourceAuthority>>::new(),
        |mut grouped, source| {
            grouped
                .entry(source.observation_id)
                .or_default()
                .push(source);
            grouped
        },
    );

    let mut source_span_count = 0usize;
    let mut utterances = Vec::new();
    for utterance in &dataset.utterances {
        if utterances.len() >= MAX_UTTERANCES_PER_WINDOW {
            break;
        }
        let utterance_start = utterance.timeline_start_ms;
        let utterance_end = utterance.timeline_end_ms;
        if utterance_end <= window_start_ms || utterance_start >= window_end_ms {
            continue;
        }
        let mut spans = Vec::new();
        if let Some(observation_id) = utterance.observation_id {
            for source in sources_by_observation
                .get(&observation_id)
                .into_iter()
                .flatten()
            {
                if source_span_count >= MAX_SOURCE_SPANS_PER_WINDOW {
                    break;
                }
                let segment = segment_by_event.get(source.event_id.as_str()).copied();
                let Some(segment) = segment else {
                    continue;
                };
                source_span_count += 1;
                let source_valid = source.structurally_valid_for(segment);
                let segment_selected = selected_segment_ids.contains(segment.segment_id.as_str());
                let playable = source_valid && segment_selected && segment.readable();
                spans.push(PlaybackSourceSpan {
                    recording_id: segment.recording_id.clone(),
                    segment_id: (source_valid && segment_selected)
                        .then(|| segment.segment_id.clone()),
                    segment_start_ms: source.event_start_ms,
                    segment_end_ms: source.event_end_ms,
                    timeline_start_ms: segment
                        .timeline_start_ms
                        .saturating_add(source.event_start_ms),
                    timeline_end_ms: segment
                        .timeline_start_ms
                        .saturating_add(source.event_end_ms),
                    source_state: if !source_valid {
                        "invalid_mapping"
                    } else if playable {
                        "ready"
                    } else {
                        "unavailable"
                    },
                    playable,
                });
            }
        }
        utterances.push(PlaybackUtterance {
            utterance_id: utterance.utterance_id,
            speaker_observation_id: utterance.observation_id,
            person_id: utterance.person_id,
            display_name: utterance
                .display_name
                .clone()
                .unwrap_or_else(|| utterance.fallback_label.clone()),
            attribution_state: utterance
                .attribution_state
                .clone()
                .unwrap_or_else(|| "unavailable".into()),
            timeline_start_ms: utterance_start,
            timeline_end_ms: utterance_end,
            text: utterance.text.clone(),
            overlap: utterance.overlap,
            source_spans: spans,
        });
    }

    let mut recordings_by_id = BTreeMap::<String, PlaybackRecording>::new();
    let mut tracks_by_id = BTreeMap::<String, PlaybackTrack>::new();
    for segment in &selected_segments {
        recordings_by_id
            .entry(segment.recording_id.clone())
            .and_modify(|recording| {
                recording.timeline_start_ms =
                    recording.timeline_start_ms.min(segment.timeline_start_ms);
                recording.timeline_end_ms = recording.timeline_end_ms.max(segment.timeline_end_ms);
                recording.availability =
                    combine_availability(&recording.availability, &segment.state());
            })
            .or_insert_with(|| PlaybackRecording {
                recording_id: segment.recording_id.clone(),
                timeline_start_ms: segment.timeline_start_ms,
                timeline_end_ms: segment.timeline_end_ms,
                availability: segment.state(),
            });
        tracks_by_id
            .entry(segment.track_id.clone())
            .and_modify(|track| track.state = combine_availability(&track.state, &segment.state()))
            .or_insert_with(|| PlaybackTrack {
                recording_id: segment.recording_id.clone(),
                track_id: segment.track_id.clone(),
                kind: segment.kind.clone(),
                state: segment.state(),
            });
    }

    let segments: Vec<PlaybackSegment> = selected_segments
        .into_iter()
        .map(SegmentAuthority::view)
        .collect();
    let availability =
        aggregate_availability(segments.iter().map(|segment| segment.state.as_str()));
    let contributing_recording_count = dataset
        .segments
        .iter()
        .map(|segment| segment.recording_id.as_str())
        .collect::<HashSet<_>>()
        .len();
    let next_cursor = (window_end_ms < dataset.duration_ms).then(|| {
        encode_cursor(
            &dataset.owner_id,
            dataset.memory_id,
            dataset.projection_revision,
            window_end_ms,
        )
    });

    Ok(PlaybackManifest {
        manifest_version: PLAYBACK_MANIFEST_VERSION,
        memory_id: dataset.memory_id,
        projection_revision: dataset.projection_revision,
        contributing_recording_count,
        timeline: PlaybackTimeline {
            started_at: dataset.started_at.clone(),
            ended_at: dataset.ended_at.clone(),
            duration_ms: dataset.duration_ms,
            alignment_quality: "wall_clock_best_effort",
        },
        transcript_alignment_quality: "model_derived_unvalidated",
        window: PlaybackWindow {
            timeline_start_ms: window_start_ms,
            timeline_end_ms: window_end_ms,
        },
        next_cursor,
        availability,
        recordings: recordings_by_id.into_values().collect(),
        tracks: tracks_by_id.into_values().collect(),
        segments,
        utterances,
    })
}

fn playback_window_start(dataset: &PlaybackDataset, query: &PlaybackQuery) -> Result<i64> {
    if let Some(cursor) = query.cursor.as_deref() {
        let offset = decode_cursor(
            cursor,
            &dataset.owner_id,
            dataset.memory_id,
            dataset.projection_revision,
        )?;
        if offset < 0 || offset >= dataset.duration_ms {
            return Err(EnclaveError::InvalidRequest(
                "playback cursor offset is invalid".into(),
            ));
        }
        return Ok(offset);
    }
    let at = query
        .at_ms
        .unwrap_or(0)
        .min(dataset.duration_ms.saturating_sub(1));
    Ok((at / PLAYBACK_WINDOW_MS) * PLAYBACK_WINDOW_MS)
}

pub(crate) fn projection_revision(
    memory_id: i64,
    started_at: &str,
    ended_at: &str,
    segments: &[SegmentAuthority],
    utterances: &[UtteranceAuthority],
    sources: &[SourceAuthority],
) -> i64 {
    let mut digest = Sha256::new();
    digest.update(b"kioku.playback-projection.v1\0");
    digest.update(memory_id.to_be_bytes());
    digest.update(started_at.as_bytes());
    digest.update([0]);
    digest.update(ended_at.as_bytes());
    for segment in segments {
        for value in [
            segment.capture_session_id.as_str(),
            segment.stream_id.as_str(),
            segment.event_id.as_str(),
            segment.asset_id.as_deref().unwrap_or(""),
            segment.object_key.as_deref().unwrap_or(""),
            segment.processing_state.as_deref().unwrap_or(""),
            segment.deleted_at.as_deref().unwrap_or(""),
        ] {
            digest.update(value.as_bytes());
            digest.update([0]);
        }
        digest.update(segment.generation.unwrap_or_default().to_be_bytes());
    }
    for utterance in utterances {
        digest.update(utterance.utterance_id.to_be_bytes());
        digest.update(utterance.observation_id.unwrap_or_default().to_be_bytes());
        digest.update(utterance.timeline_start_ms.to_be_bytes());
        digest.update(utterance.timeline_end_ms.to_be_bytes());
        digest.update(utterance.text.as_bytes());
        digest.update([0]);
    }
    for source in sources {
        digest.update(source.observation_id.to_be_bytes());
        digest.update(source.event_id.as_bytes());
        digest.update([0]);
        digest.update(source.window_start_ms.to_be_bytes());
        digest.update(source.window_end_ms.to_be_bytes());
        digest.update(source.event_start_ms.to_be_bytes());
        digest.update(source.event_end_ms.to_be_bytes());
    }
    let bytes: [u8; 8] = digest.finalize()[..8]
        .try_into()
        .expect("fixed digest prefix");
    (i64::from_be_bytes(bytes) & i64::MAX).max(1)
}

pub(crate) fn opaque_id(prefix: &str, components: &[&str]) -> String {
    let mut digest = Sha256::new();
    digest.update(b"kioku.playback-public-id.v1\0");
    digest.update(prefix.as_bytes());
    for component in components {
        digest.update([0]);
        digest.update(component.as_bytes());
    }
    format!("{prefix}{:x}", digest.finalize())
}

fn valid_public_id(value: &str, prefix: &str) -> bool {
    value.len() == prefix.len() + 64
        && value.starts_with(prefix)
        && value[prefix.len()..]
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

fn encode_cursor(owner_id: &str, memory_id: i64, revision: i64, offset: i64) -> String {
    encode_cursor_at(
        playback_cursor_secret(),
        owner_id,
        memory_id,
        revision,
        offset,
        epoch_seconds(),
    )
}

fn encode_cursor_at(
    key: &[u8; 32],
    owner_id: &str,
    memory_id: i64,
    revision: i64,
    offset: i64,
    now: i64,
) -> String {
    let expires = now.saturating_add(PLAYBACK_CURSOR_TTL_SECONDS);
    let payload = format!("{offset:x}_{expires:x}");
    let signature = cursor_signature(key, owner_id, memory_id, revision, &payload);
    format!("pb1_{payload}_{signature}")
}

fn decode_cursor(value: &str, owner_id: &str, memory_id: i64, revision: i64) -> Result<i64> {
    decode_cursor_at(
        playback_cursor_secret(),
        value,
        owner_id,
        memory_id,
        revision,
        epoch_seconds(),
    )
}

fn decode_cursor_at(
    key: &[u8; 32],
    value: &str,
    owner_id: &str,
    memory_id: i64,
    revision: i64,
    now: i64,
) -> Result<i64> {
    if value.len() > 128 {
        return Err(EnclaveError::InvalidRequest(
            "playback cursor is malformed".into(),
        ));
    }
    let parts: Vec<&str> = value.split('_').collect();
    if parts.len() != 4 || parts[0] != "pb1" || parts[1..].iter().any(|part| part.is_empty()) {
        return Err(EnclaveError::InvalidRequest(
            "playback cursor is malformed".into(),
        ));
    }
    let parse = |part: &str| -> Result<i64> {
        i64::from_str_radix(part, 16)
            .map_err(|_| EnclaveError::InvalidRequest("playback cursor is malformed".into()))
    };
    let offset = parse(parts[1])?;
    let expires = parse(parts[2])?;
    let payload = format!("{}_{}", parts[1], parts[2]);
    let supplied = decode_hex_32(parts[3])
        .ok_or_else(|| EnclaveError::InvalidRequest("playback cursor is malformed".into()))?;
    let mut verifier = HmacSha256::new_from_slice(key).expect("HMAC accepts a fixed key");
    verifier.update(b"kioku.playback-cursor.v1\0");
    verifier.update(owner_id.as_bytes());
    verifier.update(&[0]);
    verifier.update(&memory_id.to_be_bytes());
    verifier.update(&revision.to_be_bytes());
    verifier.update(payload.as_bytes());
    if verifier.verify_slice(&supplied).is_err()
        || expires < now
        || expires > now.saturating_add(PLAYBACK_CURSOR_TTL_SECONDS)
    {
        return Err(EnclaveError::InvalidRequest(
            "playback cursor is stale or belongs to another scope".into(),
        ));
    }
    Ok(offset)
}

fn cursor_signature(
    key: &[u8; 32],
    owner_id: &str,
    memory_id: i64,
    revision: i64,
    payload: &str,
) -> String {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts a fixed key");
    mac.update(b"kioku.playback-cursor.v1\0");
    mac.update(owner_id.as_bytes());
    mac.update(&[0]);
    mac.update(&memory_id.to_be_bytes());
    mac.update(&revision.to_be_bytes());
    mac.update(payload.as_bytes());
    format!("{:x}", mac.finalize().into_bytes())
}

fn decode_hex_32(value: &str) -> Option<[u8; 32]> {
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return None;
    }
    let mut decoded = [0_u8; 32];
    for (index, slot) in decoded.iter_mut().enumerate() {
        *slot = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16).ok()?;
    }
    Some(decoded)
}

fn playback_cursor_secret() -> &'static [u8; 32] {
    static SECRET: OnceLock<[u8; 32]> = OnceLock::new();
    SECRET.get_or_init(|| {
        let mut key = [0_u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut key);
        key
    })
}

fn epoch_seconds() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|duration| i64::try_from(duration.as_secs()).ok())
        .unwrap_or_default()
}

fn is_supported_audio_mime(value: &str) -> bool {
    matches!(value, "audio/m4a" | "audio/mp4")
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn looks_like_iso_bmff_audio(bytes: &[u8]) -> bool {
    bytes.len() >= 12
        && &bytes[4..8] == b"ftyp"
        && matches!(
            &bytes[8..12],
            b"M4A " | b"M4B " | b"isom" | b"mp41" | b"mp42"
        )
}

fn aggregate_availability<'a>(states: impl Iterator<Item = &'a str>) -> String {
    let states: Vec<&str> = states.collect();
    if states.is_empty() {
        return "unavailable".into();
    }
    let ready = states.iter().filter(|state| **state == "ready").count();
    if ready == states.len() {
        "ready".into()
    } else if ready > 0 {
        "partial".into()
    } else if states.contains(&"pending") {
        "pending".into()
    } else if states.iter().all(|state| *state == "deleted") {
        "deleted".into()
    } else if states.iter().all(|state| *state == "pruned") {
        "pruned".into()
    } else {
        "unavailable".into()
    }
}

fn combine_availability(left: &str, right: &str) -> String {
    aggregate_availability([left, right].into_iter())
}

pub(crate) fn availability_from_counts(
    total: i64,
    ready: i64,
    pending: i64,
    deleted: i64,
    pruned: i64,
) -> String {
    if total <= 0 {
        "unavailable"
    } else if ready == total {
        "ready"
    } else if ready > 0 {
        "partial"
    } else if pending > 0 {
        "pending"
    } else if deleted == total {
        "deleted"
    } else if pruned == total {
        "pruned"
    } else {
        "unavailable"
    }
    .into()
}

fn no_store_json<T: Serialize>(value: T) -> Response {
    let mut response = Json(value).into_response();
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("private, no-store, max-age=0"),
    );
    response
        .headers_mut()
        .insert(header::PRAGMA, HeaderValue::from_static("no-cache"));
    response
}

fn bad_request(message: &'static str) -> Response {
    no_store_error(StatusCode::BAD_REQUEST, json!({"error": message}))
}

fn not_found() -> Response {
    no_store_error(StatusCode::NOT_FOUND, json!({"error": "not_found"}))
}

fn too_many_requests() -> Response {
    let mut response = no_store_error(
        StatusCode::TOO_MANY_REQUESTS,
        json!({"error": "playback_rate_limited"}),
    );
    response
        .headers_mut()
        .insert(header::RETRY_AFTER, HeaderValue::from_static("1"));
    response
}

fn internal_error() -> Response {
    no_store_error(
        StatusCode::INTERNAL_SERVER_ERROR,
        json!({"error": "playback_unavailable"}),
    )
}

fn no_store_error(status: StatusCode, value: serde_json::Value) -> Response {
    let mut response = (status, Json(value)).into_response();
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("private, no-store, max-age=0"),
    );
    response
        .headers_mut()
        .insert(header::PRAGMA, HeaderValue::from_static("no-cache"));
    response
}

#[cfg(test)]
mod tests {
    use super::*;

    fn authority(state: &str, deleted: bool) -> SegmentAuthority {
        SegmentAuthority {
            recording_id: "rec_a".into(),
            segment_id: "seg_a".into(),
            track_id: "track_a".into(),
            kind: "mic".into(),
            capture_session_id: "session".into(),
            stream_id: "stream".into(),
            event_id: "event".into(),
            asset_id: Some("asset".into()),
            object_key: Some("raw/user/asset.enc".into()),
            generation: Some(7),
            object_backend: Some("current".into()),
            stored_mime_type: Some("audio/m4a".into()),
            codec: Some("aac".into()),
            byte_length: Some(512_000),
            sha256: Some("a".repeat(64)),
            processing_state: Some(state.into()),
            deleted_at: deleted.then(|| "2026-08-26T15:00:00Z".into()),
            retention_decision: "processing_window_30d".into(),
            storage_backend: "processing".into(),
            retention_policy_revision: None,
            retention_policy_epoch: None,
            recording_key_epoch: None,
            recording_state: "processing_only".into(),
            durable_read_authorized: false,
            timeline_start_ms: 0,
            timeline_end_ms: 60_000,
        }
    }

    #[test]
    fn only_exact_ready_current_audio_is_readable() {
        assert!(authority("ready", false).readable());
        assert_eq!(authority("pruned", false).state(), "pruned");
        assert_eq!(authority("ready", true).state(), "deleted");
        let mut wrong_backend = authority("ready", false);
        wrong_backend.object_backend = Some("recordings".into());
        assert!(!wrong_backend.readable());

        let mut durable = authority("ready", false);
        durable.object_key = Some("recordings/user/asset.enc".into());
        durable.retention_decision = "until_deleted".into();
        durable.storage_backend = "recordings".into();
        durable.retention_policy_revision = Some(7);
        durable.retention_policy_epoch = Some(format!("rpe_{}", "a".repeat(64)));
        durable.recording_key_epoch = Some(1);
        durable.recording_state = "durable".into();
        durable.durable_read_authorized = true;
        assert!(durable.readable());
        durable.durable_read_authorized = false;
        assert!(!durable.readable());
    }

    #[test]
    fn cursor_is_memory_revision_and_offset_bound() {
        let key = [7_u8; 32];
        let now = 1_777_777_777;
        let cursor = encode_cursor_at(&key, "owner-a", 123, 456, 900_000, now);
        assert_eq!(
            decode_cursor_at(&key, &cursor, "owner-a", 123, 456, now).unwrap(),
            900_000
        );
        assert!(decode_cursor_at(&key, &cursor, "owner-b", 123, 456, now).is_err());
        assert!(decode_cursor_at(&key, &cursor, "owner-a", 124, 456, now).is_err());
        assert!(decode_cursor_at(&key, &cursor, "owner-a", 123, 457, now).is_err());
        assert!(decode_cursor_at(
            &key,
            &cursor,
            "owner-a",
            123,
            456,
            now + PLAYBACK_CURSOR_TTL_SECONDS + 1
        )
        .is_err());
        assert!(decode_cursor_at(&key, "pb1_bad", "owner-a", 123, 456, now).is_err());
    }

    #[test]
    fn opaque_ids_do_not_expose_source_identifiers() {
        let id = opaque_id("seg_", &["owner", "event-secret"]);
        assert!(valid_public_id(&id, "seg_"));
        assert!(!id.contains("owner"));
        assert!(!id.contains("event-secret"));
        assert_ne!(id, opaque_id("seg_", &["other", "event-secret"]));
    }

    #[test]
    fn availability_never_calls_missing_audio_ready() {
        assert_eq!(
            aggregate_availability(["ready", "ready"].into_iter()),
            "ready"
        );
        assert_eq!(
            aggregate_availability(["ready", "pruned"].into_iter()),
            "partial"
        );
        assert_eq!(aggregate_availability(["pending"].into_iter()), "pending");
        assert_eq!(aggregate_availability(["pruned"].into_iter()), "pruned");
        assert_eq!(aggregate_availability(std::iter::empty()), "unavailable");
        assert_eq!(availability_from_counts(2, 0, 2, 0, 0), "pending");
        assert_eq!(availability_from_counts(2, 0, 0, 2, 0), "deleted");
        assert_eq!(availability_from_counts(2, 0, 0, 0, 2), "pruned");
    }

    #[test]
    fn source_offsets_become_canonical_milliseconds_without_sql_datetime() {
        assert_eq!(
            resolve_utterance_interval(None, None, "2026-08-26T14:00:00.000Z", 1.25, 2.75),
            Some((1_787_752_801_250, 1_787_752_802_750))
        );
        assert!(resolve_utterance_interval(
            Some("2026-08-26T14:00:01.000Z"),
            None,
            "2026-08-26T14:00:00.000Z",
            1.0,
            2.0
        )
        .is_none());
    }

    #[test]
    fn source_spans_must_be_ordered_equal_length_and_inside_the_event() {
        let segment = authority("ready", false);
        let valid = SourceAuthority {
            observation_id: 1,
            event_id: "event".into(),
            window_start_ms: 10_000,
            window_end_ms: 15_000,
            event_start_ms: 5_000,
            event_end_ms: 10_000,
        };
        assert!(valid.structurally_valid_for(&segment));
        let mut unequal = valid.clone();
        unequal.event_end_ms += 1;
        assert!(!unequal.structurally_valid_for(&segment));
        let mut outside = valid;
        outside.event_end_ms = 70_000;
        outside.window_end_ms = 75_000;
        assert!(!outside.structurally_valid_for(&segment));
    }

    #[test]
    fn m4a_container_gate_is_bounded_and_brand_allowlisted() {
        let mut bytes = vec![0, 0, 0, 24];
        bytes.extend_from_slice(b"ftypM4A ");
        assert!(looks_like_iso_bmff_audio(&bytes));
        assert!(!looks_like_iso_bmff_audio(b"not media"));
        let mut video = vec![0, 0, 0, 24];
        video.extend_from_slice(b"ftypavc1");
        assert!(!looks_like_iso_bmff_audio(&video));
    }
}
