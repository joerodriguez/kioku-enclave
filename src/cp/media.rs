//! V2 raw-media capture API and cloud processing ledger.

pub(crate) mod wal;

use std::collections::HashSet;
use std::sync::Arc;
use std::time::Instant;

use axum::{
    extract::{DefaultBodyLimit, Multipart, Path, Query, State},
    http::{header::RETRY_AFTER, HeaderMap, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Extension, Json, Router,
};
use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::error::{wal_domain, CaptureReferenceFailureReason, EnclaveError, Result};

use super::isotime::parse_epoch_millis;
use super::{auth::AuthUser, limits, CpState};

const MAX_AUDIO_BYTES: i64 = 20 * 1024 * 1024;
const MAX_SCREENSHOT_BYTES: i64 = 5 * 1024 * 1024;
const MAX_ID_LEN: usize = 128;
// Re-exported pub(crate) so the ADR-0022 audio transcript plan can never
// drift from the caps `parse_audio_result` enforces (the text cap counts
// CHARS, not bytes).
pub(crate) const MAX_TEXT_LEN: usize = 20_000;
pub(crate) const MAX_TURNS: usize = 10_000;
const MAX_MANIFEST_BYTES: usize = 128 * 1024;
const MAX_MULTIPART_BYTES: usize = MAX_AUDIO_BYTES as usize + MAX_MANIFEST_BYTES + 64 * 1024;
const MAX_REFERENCE_BATCH_BYTES: usize = 1024 * 1024;
// Highest screen reference dedupe_version this enclave accepts; advertised in
// batch receipts so clients upgrade only after proof of support.
const MAX_SCREEN_DEDUPE_VERSION: u32 = 2;
const MAX_REFERENCE_BATCH_EVENTS: usize = 64;
const REFERENCE_BATCH_ID_DOMAIN: &[u8] = b"kioku.screen-reference-batch.v1\0";
const REFERENCE_BATCH_MANIFEST_DOMAIN: &[u8] = b"kioku.screen-reference-manifests.v1\0";
const MEDIA_DEK_METADATA_KEY: &str = "wrapped_media_dek";
const REQUEST_LOCAL_LABEL_MIGRATION_KEY: &str = "request-local-speaker-labels-v1";
const SPEAKER_IDENTITY_BACKFILL_KEY: &str = "speaker-identity-backfill-v2";
#[allow(dead_code)]
pub(crate) const UNIDENTIFIED_SPEAKER_LABEL: &str = super::identity::UNIDENTIFIED_SPEAKER_LABEL;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StreamKind {
    Mic,
    SystemAudio,
    MacScreen,
    IosMic,
    IosImportedScreenshot,
    IosSharedPage,
}

impl StreamKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::Mic => "mic",
            Self::SystemAudio => "system_audio",
            Self::MacScreen => "mac_screen",
            Self::IosMic => "ios_mic",
            Self::IosImportedScreenshot => "ios_imported_screenshot",
            Self::IosSharedPage => "ios_shared_page",
        }
    }

    pub fn is_audio(self) -> bool {
        matches!(self, Self::Mic | Self::SystemAudio | Self::IosMic)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MediaDescriptor {
    pub asset_id: String,
    pub mime_type: String,
    pub codec: String,
    pub byte_length: i64,
    pub sha256: String,
    pub sample_rate: Option<i64>,
    pub channels: Option<i64>,
    pub frame_count: Option<i64>,
    pub width: Option<i64>,
    pub height: Option<i64>,
    pub scale: Option<f64>,
    pub orientation: Option<String>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MediaDisposition {
    #[default]
    Canonical,
    Reference,
}

impl MediaDisposition {
    fn is_canonical(&self) -> bool {
        matches!(self, Self::Canonical)
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Canonical => "canonical",
            Self::Reference => "reference",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScreenReferenceDescriptor {
    pub canonical_event_id: String,
    pub canonical_asset_id: String,
    pub canonical_media_sha256: String,
    pub perceptual_hash: String,
    pub hamming_distance: u32,
    pub pixel_change_ratio: f64,
    pub context_fingerprint: String,
    pub dedupe_version: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CaptureContext {
    pub capture_status: String,
    pub active_app: Option<String>,
    pub primary_bundle_id: Option<String>,
    pub primary_window_id: Option<i64>,
    pub window_title: Option<String>,
    pub display_id: Option<i64>,
    pub active_url: Option<String>,
    pub active_url_title: Option<String>,
    pub browser_permission_status: Option<String>,
    pub browser_state_key: Option<String>,
    pub browser_snapshot: Option<BrowserSnapshot>,
    pub visible_windows: Option<serde_json::Value>,
    pub visible_windows_truncated: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BrowserTab {
    pub window_index: i64,
    pub tab_index: i64,
    pub title: Option<String>,
    pub url: Option<String>,
    pub is_active: bool,
    pub is_loading: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BrowserSnapshot {
    pub state_key: String,
    pub browser_bundle_id: String,
    pub browser_name: String,
    pub permission_status: String,
    pub active_window_index: Option<i64>,
    pub active_tab_index: Option<i64>,
    pub reported_tab_count: i64,
    pub truncated: bool,
    pub content_hash: String,
    pub tabs: Vec<BrowserTab>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CaptureEventManifest {
    pub schema_version: i64,
    pub event_id: String,
    pub device_id: String,
    pub install_id: String,
    pub capture_session_id: String,
    pub stream_id: String,
    pub stream_kind: StreamKind,
    pub sequence: i64,
    pub source_wall_at: String,
    pub source_monotonic_ns: u64,
    pub started_at: String,
    pub ended_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_finished: Option<bool>,
    pub timezone_id: String,
    pub utc_offset_minutes: i32,
    pub clock_uncertainty_ms: u32,
    #[serde(default, skip_serializing_if = "MediaDisposition::is_canonical")]
    pub media_disposition: MediaDisposition,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub media: Option<MediaDescriptor>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reference: Option<ScreenReferenceDescriptor>,
    pub context: Option<CaptureContext>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audio_role: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audio_route: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub route_epoch: Option<u64>,
}

impl CaptureEventManifest {
    pub fn duration_ms(&self) -> Result<i64> {
        let started = parse_epoch_millis(&self.started_at)
            .ok_or_else(|| EnclaveError::InvalidRequest("started_at must be ISO-8601".into()))?;
        let ended = parse_epoch_millis(&self.ended_at)
            .ok_or_else(|| EnclaveError::InvalidRequest("ended_at must be ISO-8601".into()))?;
        let duration = ended - started;
        if duration <= 0 {
            return Err(EnclaveError::InvalidRequest(
                "ended_at must be after started_at".into(),
            ));
        }
        Ok(duration)
    }

    pub fn validate(&self) -> Result<()> {
        if self.schema_version != 2 && self.schema_version != 3 {
            return Err(EnclaveError::InvalidRequest(
                "schema_version must be 2 or 3".into(),
            ));
        }
        if let Some(role) = self.audio_role.as_deref() {
            if !matches!(
                role,
                "local_transmit" | "remote_received" | "ambient" | "mixed"
            ) {
                return Err(EnclaveError::InvalidRequest(
                    "audio_role must be one of 'local_transmit', 'remote_received', 'ambient', 'mixed'".into(),
                ));
            }
        }
        for (name, value) in [
            ("event_id", self.event_id.as_str()),
            ("device_id", self.device_id.as_str()),
            ("install_id", self.install_id.as_str()),
            ("capture_session_id", self.capture_session_id.as_str()),
            ("stream_id", self.stream_id.as_str()),
        ] {
            validate_id(name, value)?;
        }
        if self.sequence < 0 {
            return Err(EnclaveError::InvalidRequest(
                "sequence must be non-negative".into(),
            ));
        }
        // Parseable, not canonical. `parse_epoch_millis` deliberately accepts
        // a `±HH:MM` offset and ignores fractional digits past the third, and
        // this check is deliberately NOT tightened to reject either.
        //
        // It is tempting to normalize here as defence in depth, because a
        // non-canonical device stamp compared as a raw string is what wedged
        // the media claim lane. But the wedge was a BINDING defect, not an
        // input-shape one: `source_wall_at` belongs in
        // `capture_events.source_wall_at` and `browser_observations_v2.
        // observed_at`, and nowhere else, which is what
        // `wal::is_canonical_commit_stamp` now enforces at plan construction.
        // Rejecting offset-bearing stamps here would instead be a client
        // contract break with no upside: shipped Mac and iOS builds may
        // already send them (`parse_epoch_millis` supports the form on
        // purpose), a 400 on ingest is not something the durable outbox can
        // rebase away, and the tightening would land in a routing change where
        // nobody would look for it. If a future change does normalize device
        // stamps, it belongs in its own migration with the client, and it must
        // never be done by loosening `parse_epoch_millis`.
        if parse_epoch_millis(&self.source_wall_at).is_none() {
            return Err(EnclaveError::InvalidRequest(
                "source_wall_at must be ISO-8601".into(),
            ));
        }
        let duration_ms = self.duration_ms()?;
        if duration_ms > 8 * 60 * 60 * 1000 {
            return Err(EnclaveError::InvalidRequest(
                "capture event duration exceeds eight hours".into(),
            ));
        }
        if self.session_finished == Some(true) && !self.stream_kind.is_audio() {
            return Err(EnclaveError::InvalidRequest(
                "session_finished is permitted only on a final audio event".into(),
            ));
        }
        if self.timezone_id.is_empty() || self.timezone_id.len() > 128 {
            return Err(EnclaveError::InvalidRequest(
                "timezone_id is invalid".into(),
            ));
        }
        if !(-14 * 60..=14 * 60).contains(&self.utc_offset_minutes) {
            return Err(EnclaveError::InvalidRequest(
                "utc_offset_minutes is invalid".into(),
            ));
        }
        match self.media_disposition {
            MediaDisposition::Canonical => {
                let media = self.media.as_ref().ok_or_else(|| {
                    EnclaveError::InvalidRequest("canonical media is required".into())
                })?;
                validate_id("asset_id", &media.asset_id)?;
                validate_media(self.stream_kind, media)?;
                if self.reference.is_some() {
                    return Err(EnclaveError::InvalidRequest(
                        "canonical events cannot contain a reference".into(),
                    ));
                }
            }
            MediaDisposition::Reference => {
                if self.media.is_some() {
                    return Err(EnclaveError::InvalidRequest(
                        "reference events cannot contain media".into(),
                    ));
                }
                if self.stream_kind != StreamKind::MacScreen {
                    return Err(EnclaveError::InvalidRequest(
                        "only mac_screen events may reference canonical media".into(),
                    ));
                }
                validate_screen_reference(self.reference.as_ref().ok_or_else(|| {
                    EnclaveError::InvalidRequest("reference metadata is required".into())
                })?)?;
                if self
                    .context
                    .as_ref()
                    .is_none_or(|context| context.capture_status != "stable")
                {
                    return Err(EnclaveError::InvalidRequest(
                        "reference events require stable capture context".into(),
                    ));
                }
            }
        }
        if let Some(context) = &self.context {
            validate_context(context)?;
        }
        Ok(())
    }
}

fn validate_screen_reference(reference: &ScreenReferenceDescriptor) -> Result<()> {
    validate_id(
        "reference.canonical_event_id",
        &reference.canonical_event_id,
    )?;
    validate_id(
        "reference.canonical_asset_id",
        &reference.canonical_asset_id,
    )?;
    if !validate_sha256(&reference.canonical_media_sha256) {
        return Err(EnclaveError::InvalidRequest(
            "reference.canonical_media_sha256 must be 64 hexadecimal characters".into(),
        ));
    }
    let valid_perceptual_hash = reference.perceptual_hash.len() == 16
        && reference
            .perceptual_hash
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit());
    if !valid_perceptual_hash {
        return Err(EnclaveError::InvalidRequest(
            "reference.perceptual_hash must be 16 hexadecimal characters".into(),
        ));
    }
    // Version 1 kept references so conservative (exact fingerprint including
    // per-window geometry, Hamming ≤ 3, ratio ≤ 0.01) that idle-screen jitter
    // produced canonical uploads. Version 2 drops the volatile window
    // inventory from the fingerprint and widens the pixel bounds enough to
    // absorb clocks, badges, and cursor blinks while a scroll or content
    // change still forces a canonical upload.
    let bounds = match reference.dedupe_version {
        1 => {
            reference.hamming_distance <= 3 && (0.0..=0.01).contains(&reference.pixel_change_ratio)
        }
        2 => {
            reference.hamming_distance <= 8 && (0.0..=0.03).contains(&reference.pixel_change_ratio)
        }
        _ => false,
    };
    if !reference.pixel_change_ratio.is_finite()
        || !bounds
        || !validate_sha256(&reference.context_fingerprint)
    {
        return Err(EnclaveError::InvalidRequest(format!(
            "reference deduplication evidence is outside version {} bounds",
            reference.dedupe_version
        )));
    }
    Ok(())
}

fn validate_id(name: &str, value: &str) -> Result<()> {
    let valid = !value.is_empty()
        && value.len() <= MAX_ID_LEN
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'));
    if valid {
        Ok(())
    } else {
        Err(EnclaveError::InvalidRequest(format!(
            "{name} has an invalid format"
        )))
    }
}

fn validate_state_key(name: &str, value: &str) -> Result<()> {
    let valid = !value.is_empty()
        && value.len() <= 512
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'));
    if valid {
        Ok(())
    } else {
        Err(EnclaveError::InvalidRequest(format!(
            "{name} has an invalid format"
        )))
    }
}

fn validate_sha256(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn validate_media(kind: StreamKind, media: &MediaDescriptor) -> Result<()> {
    if !validate_sha256(&media.sha256) {
        return Err(EnclaveError::InvalidRequest(
            "media.sha256 must be 64 hexadecimal characters".into(),
        ));
    }
    let max_bytes = if kind.is_audio() {
        MAX_AUDIO_BYTES
    } else {
        MAX_SCREENSHOT_BYTES
    };
    if media.byte_length <= 0 || media.byte_length > max_bytes {
        return Err(EnclaveError::InvalidRequest(
            "media.byte_length is outside the allowed range".into(),
        ));
    }
    if media.mime_type.is_empty() || media.mime_type.len() > 128 {
        return Err(EnclaveError::InvalidRequest(
            "media.mime_type is invalid".into(),
        ));
    }
    if media.codec.is_empty() || media.codec.len() > 64 {
        return Err(EnclaveError::InvalidRequest(
            "media.codec is invalid".into(),
        ));
    }
    if kind.is_audio() {
        let sample_rate = media
            .sample_rate
            .ok_or_else(|| EnclaveError::InvalidRequest("audio sample_rate is required".into()))?;
        let channels = media
            .channels
            .ok_or_else(|| EnclaveError::InvalidRequest("audio channels is required".into()))?;
        let frame_count = media
            .frame_count
            .ok_or_else(|| EnclaveError::InvalidRequest("audio frame_count is required".into()))?;
        if !(8_000..=192_000).contains(&sample_rate)
            || !(1..=8).contains(&channels)
            || frame_count <= 0
        {
            return Err(EnclaveError::InvalidRequest(
                "audio format fields are invalid".into(),
            ));
        }
    } else {
        let width = media
            .width
            .ok_or_else(|| EnclaveError::InvalidRequest("image width is required".into()))?;
        let height = media
            .height
            .ok_or_else(|| EnclaveError::InvalidRequest("image height is required".into()))?;
        if !(1..=16_384).contains(&width) || !(1..=16_384).contains(&height) {
            return Err(EnclaveError::InvalidRequest(
                "image dimensions are invalid".into(),
            ));
        }
    }
    Ok(())
}

fn validate_context(context: &CaptureContext) -> Result<()> {
    if !matches!(
        context.capture_status.as_str(),
        "stable" | "unstable" | "unavailable"
    ) {
        return Err(EnclaveError::InvalidRequest(
            "context.capture_status is invalid".into(),
        ));
    }
    for (name, value, max) in [
        ("active_app", context.active_app.as_deref(), 512usize),
        (
            "primary_bundle_id",
            context.primary_bundle_id.as_deref(),
            512,
        ),
        ("window_title", context.window_title.as_deref(), 2_000),
        ("active_url", context.active_url.as_deref(), 8_192),
        (
            "active_url_title",
            context.active_url_title.as_deref(),
            2_000,
        ),
    ] {
        if value.is_some_and(|text| text.len() > max || text.bytes().any(|b| b == 0)) {
            return Err(EnclaveError::InvalidRequest(format!(
                "context.{name} is invalid"
            )));
        }
    }
    if let Some(snapshot) = &context.browser_snapshot {
        validate_state_key("browser_snapshot.state_key", &snapshot.state_key)?;
        if context.browser_state_key.as_deref() != Some(snapshot.state_key.as_str()) {
            return Err(EnclaveError::InvalidRequest(
                "browser_state_key must match browser_snapshot.state_key".into(),
            ));
        }
        if snapshot.browser_bundle_id.is_empty()
            || snapshot.browser_bundle_id.len() > 512
            || snapshot.browser_name.is_empty()
            || snapshot.browser_name.len() > 512
            || snapshot.permission_status.len() > 64
            || snapshot.reported_tab_count < 0
            || snapshot.tabs.len() > 500
            || !validate_sha256(&snapshot.content_hash)
        {
            return Err(EnclaveError::InvalidRequest(
                "browser snapshot metadata is invalid".into(),
            ));
        }
        for tab in &snapshot.tabs {
            if tab.window_index < 0
                || tab.tab_index < 0
                || tab.title.as_ref().is_some_and(|value| value.len() > 2_000)
                || tab.url.as_ref().is_some_and(|value| value.len() > 8_192)
            {
                return Err(EnclaveError::InvalidRequest(
                    "browser snapshot tab is invalid".into(),
                ));
            }
        }
    } else if context.browser_state_key.is_some() {
        validate_state_key(
            "browser_state_key",
            context.browser_state_key.as_deref().unwrap_or_default(),
        )?;
    }
    Ok(())
}

fn sha256_hex(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn manifest_digest(manifest: &CaptureEventManifest) -> Result<String> {
    Ok(sha256_hex(&serde_json::to_vec(manifest)?))
}

fn reference_batch_id(events: &[CaptureEventManifest]) -> Result<String> {
    let count = u32::try_from(events.len())
        .map_err(|_| EnclaveError::InvalidRequest("reference batch is too large".into()))?;
    let mut hasher = Sha256::new();
    hasher.update(REFERENCE_BATCH_ID_DOMAIN);
    hasher.update(count.to_be_bytes());
    for event in events {
        let event_id = event.event_id.as_bytes();
        let event_id_len = u32::try_from(event_id.len())
            .map_err(|_| EnclaveError::InvalidRequest("event_id is too large".into()))?;
        let sequence = u64::try_from(event.sequence)
            .map_err(|_| EnclaveError::InvalidRequest("sequence must be non-negative".into()))?;
        hasher.update(event_id_len.to_be_bytes());
        hasher.update(event_id);
        hasher.update(sequence.to_be_bytes());
    }
    Ok(format!("{:x}", hasher.finalize()))
}

fn reference_batch_manifest_digest(digests: &[String]) -> Result<String> {
    let count = u32::try_from(digests.len())
        .map_err(|_| EnclaveError::InvalidRequest("reference batch is too large".into()))?;
    let mut hasher = Sha256::new();
    hasher.update(REFERENCE_BATCH_MANIFEST_DOMAIN);
    hasher.update(count.to_be_bytes());
    for digest in digests {
        if !validate_sha256(digest) {
            return Err(EnclaveError::InvalidRequest(
                "reference batch manifest digest is invalid".into(),
            ));
        }
        hasher.update(digest.as_bytes());
    }
    Ok(format!("{:x}", hasher.finalize()))
}

fn validate_media_bytes(
    manifest: &CaptureEventManifest,
    bytes: &[u8],
    multipart_content_type: Option<&str>,
) -> Result<()> {
    manifest.validate()?;
    if manifest.media_disposition != MediaDisposition::Canonical {
        return Err(EnclaveError::InvalidRequest(
            "reference events cannot contain a media part".into(),
        ));
    }
    let media = manifest
        .media
        .as_ref()
        .ok_or_else(|| EnclaveError::InvalidRequest("canonical media is required".into()))?;
    if bytes.len() as i64 != media.byte_length {
        return Err(EnclaveError::InvalidRequest(
            "media byte length does not match manifest".into(),
        ));
    }
    if !media.sha256.eq_ignore_ascii_case(&sha256_hex(bytes)) {
        return Err(EnclaveError::InvalidRequest(
            "media sha256 does not match manifest".into(),
        ));
    }
    if multipart_content_type.is_some_and(|value| value != media.mime_type) {
        return Err(EnclaveError::InvalidRequest(
            "multipart content type does not match manifest".into(),
        ));
    }

    let supported = match media.mime_type.as_str() {
        "audio/m4a" | "audio/mp4" if manifest.stream_kind.is_audio() => {
            bytes.len() >= 12 && bytes.get(4..8) == Some(b"ftyp")
        }
        "audio/wav" | "audio/x-wav" if manifest.stream_kind.is_audio() => {
            bytes.len() >= 12
                && bytes.get(..4) == Some(b"RIFF")
                && bytes.get(8..12) == Some(b"WAVE")
        }
        "image/jpeg" if !manifest.stream_kind.is_audio() => {
            bytes.starts_with(&[0xff, 0xd8, 0xff]) && bytes.ends_with(&[0xff, 0xd9])
        }
        "image/png" if !manifest.stream_kind.is_audio() => bytes.starts_with(b"\x89PNG\r\n\x1a\n"),
        _ => false,
    };
    if !supported {
        return Err(EnclaveError::InvalidRequest(
            "media container is unsupported or malformed".into(),
        ));
    }
    Ok(())
}

#[derive(Debug, Serialize)]
struct CaptureAccepted {
    event_id: String,
    asset_id: String,
    media_disposition: MediaDisposition,
    processing_state: &'static str,
    committed_through_sequence: i64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ScreenReferenceBatchRequest {
    schema_version: i64,
    batch_id: String,
    events: Vec<CaptureEventManifest>,
}

#[derive(Debug, Serialize)]
struct ScreenReferenceBatchAccepted {
    batch_id: String,
    stream_id: String,
    first_sequence: i64,
    last_sequence: i64,
    new_count: usize,
    duplicate_count: usize,
    committed_through_sequence: i64,
    // Additive capability advertisement: clients keep sending dedupe_version 1
    // until a batch receipt proves the enclave accepts a newer version, so a
    // new client never wedges its outbox against an older enclave.
    max_screen_dedupe_version: u32,
}

struct ValidatedReferenceBatch {
    manifest_digests: Vec<String>,
    aggregate_manifest_digest: String,
    event_ids: Vec<String>,
    stream_id: String,
    first_sequence: i64,
    last_sequence: i64,
}

fn validate_reference_batch(
    request: &ScreenReferenceBatchRequest,
) -> Result<ValidatedReferenceBatch> {
    if request.schema_version != 1 {
        return Err(EnclaveError::InvalidRequest(
            "reference batch schema_version must be 1".into(),
        ));
    }
    if request.events.is_empty() || request.events.len() > MAX_REFERENCE_BATCH_EVENTS {
        return Err(EnclaveError::InvalidRequest(
            "reference batch must contain between 1 and 64 events".into(),
        ));
    }
    let first = &request.events[0];
    let mut expected_sequence = first.sequence;
    let mut event_ids = HashSet::with_capacity(request.events.len());
    let mut manifest_digests = Vec::with_capacity(request.events.len());
    for event in &request.events {
        event.validate()?;
        if event.stream_kind != StreamKind::MacScreen
            || event.media_disposition != MediaDisposition::Reference
        {
            return Err(EnclaveError::InvalidRequest(
                "reference batches accept only metadata-only mac_screen references".into(),
            ));
        }
        if event.device_id != first.device_id
            || event.install_id != first.install_id
            || event.capture_session_id != first.capture_session_id
            || event.stream_id != first.stream_id
        {
            return Err(EnclaveError::InvalidRequest(
                "reference batch scope must be uniform".into(),
            ));
        }
        if event.sequence != expected_sequence {
            return Err(EnclaveError::InvalidRequest(
                "reference batch sequences must be contiguous".into(),
            ));
        }
        expected_sequence = expected_sequence.checked_add(1).ok_or_else(|| {
            EnclaveError::InvalidRequest("reference batch sequence overflow".into())
        })?;
        if !event_ids.insert(event.event_id.clone()) {
            return Err(EnclaveError::InvalidRequest(
                "reference batch event IDs must be unique".into(),
            ));
        }
        let normalized_manifest = serde_json::to_vec(event)?;
        if normalized_manifest.len() > MAX_MANIFEST_BYTES {
            return Err(EnclaveError::InvalidRequest(
                "reference batch event manifest is too large".into(),
            ));
        }
        manifest_digests.push(sha256_hex(&normalized_manifest));
    }
    let expected_batch_id = reference_batch_id(&request.events)?;
    if request.batch_id != expected_batch_id {
        return Err(EnclaveError::InvalidRequest(
            "reference batch_id does not match its ordered events".into(),
        ));
    }
    let last_sequence = request
        .events
        .last()
        .map(|event| event.sequence)
        .expect("validated nonempty reference batch");
    Ok(ValidatedReferenceBatch {
        aggregate_manifest_digest: reference_batch_manifest_digest(&manifest_digests)?,
        manifest_digests,
        event_ids: request
            .events
            .iter()
            .map(|event| event.event_id.clone())
            .collect(),
        stream_id: first.stream_id.clone(),
        first_sequence: first.sequence,
        last_sequence,
    })
}

#[derive(Debug, Serialize)]
struct StreamAck {
    stream_id: String,
    committed_through_sequence: i64,
}

#[derive(Debug, Serialize)]
struct CaptureStatus {
    event_id: String,
    processing_state: String,
    error_code: Option<String>,
    attempt_count: i64,
}

#[derive(Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum CaptureSessionStage {
    Received,
    Processing,
    Organizing,
    PreparingRecap,
    Ready,
    NeedsAttention,
    /// Terminal honest zero-result (ADR-0034): all linked media processed and
    /// a segmentation pass covering past the session's end linked nothing.
    NoMemory,
}

/// Evidence echo (ADR-0034): facts derived mechanically from accepted
/// evidence, never model output. Absent fields mean unknown — clients render
/// nothing rather than a placeholder.
#[derive(Debug, Serialize)]
struct CaptureSessionEvidence {
    #[serde(skip_serializing_if = "Option::is_none")]
    audio_minutes: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    voice_count: Option<i64>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    top_contexts: Vec<String>,
}

#[derive(Debug, Serialize)]
struct CaptureSessionProcessing {
    queued: i64,
    processing: i64,
    retry_wait: i64,
    ready: i64,
    failed: i64,
}

#[derive(Debug, Serialize)]
struct CaptureSessionMemory {
    id: i64,
    title: Option<String>,
    started_at: String,
    ended_at: String,
    finalization_status: String,
    finalized_at: Option<String>,
}

#[derive(Debug, Serialize)]
struct CaptureSessionStatus {
    capture_session_id: String,
    device_id: String,
    started_at: String,
    last_event_at: String,
    ended_at: Option<String>,
    event_count: i64,
    stage: CaptureSessionStage,
    processing: CaptureSessionProcessing,
    evidence: CaptureSessionEvidence,
    memories: Vec<CaptureSessionMemory>,
}

#[derive(Debug, Serialize)]
struct CaptureSessionList {
    sessions: Vec<CaptureSessionStatus>,
}

#[derive(Debug, Deserialize)]
struct CaptureSessionListQuery {
    window_hours: Option<i64>,
    max_sessions: Option<i64>,
}

#[derive(Debug, Serialize)]
struct PersonSummary {
    id: i64,
    display_name: String,
    voice_profile_count: i64,
    fact_count: i64,
    updated_at: String,
}

#[derive(Debug, Serialize)]
struct PersonProfile {
    person: PersonSummary,
    voice_labels: Vec<String>,
    voice_coverage: String,
    aliases: Vec<PersonNameView>,
    facts: Vec<PersonFactView>,
    evidence: Vec<PersonEvidenceView>,
    recent_statements: Vec<PersonStatementView>,
}

#[derive(Debug, Serialize)]
struct PersonFactView {
    id: i64,
    predicate: String,
    value: String,
    status: String,
    evidence: Value,
    source_event_id: Option<String>,
    speaker_observation_id: Option<i64>,
    observed_at: Option<String>,
    literal_evidence: Option<String>,
    confidence: f64,
    supersedes_id: Option<i64>,
    created_at: String,
}

#[derive(Debug, Serialize)]
struct PersonNameView {
    id: i64,
    name: String,
    status: String,
    evidence_kind: String,
    confidence: f64,
    observed_at: String,
    source_event_id: Option<String>,
}

#[derive(Debug, Serialize)]
struct PersonEvidenceView {
    id: i64,
    kind: String,
    claimed_name: Option<String>,
    score: Option<f64>,
    status: String,
    observed_at: Option<String>,
    source_event_id: Option<String>,
    speaker_observation_id: Option<i64>,
    evidence: Value,
}

#[derive(Debug, Serialize)]
struct PersonStatementView {
    speaker_observation_id: i64,
    started_at: String,
    ended_at: String,
    text: String,
    source_event_id: String,
    episode_id: Option<i64>,
    episode_title: Option<String>,
}

#[derive(Debug, Serialize)]
struct PersonEvidencePage {
    evidence: Vec<PersonEvidenceView>,
    next_cursor: Option<i64>,
}

#[derive(Debug, Serialize)]
struct PersonStatementPage {
    statements: Vec<PersonStatementView>,
    next_cursor: Option<i64>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct PeopleListQuery {
    after_id: Option<i64>,
    limit: Option<usize>,
    q: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct DescendingPageQuery {
    before_id: Option<i64>,
    limit: Option<usize>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PreflightOutcome {
    New,
    Duplicate { committed_through_sequence: i64 },
}

fn response_asset_id(manifest: &CaptureEventManifest) -> Result<String> {
    match manifest.media_disposition {
        MediaDisposition::Canonical => manifest
            .media
            .as_ref()
            .map(|media| media.asset_id.clone())
            .ok_or_else(|| EnclaveError::InvalidRequest("canonical media is required".into())),
        MediaDisposition::Reference => manifest
            .reference
            .as_ref()
            .map(|reference| reference.canonical_asset_id.clone())
            .ok_or_else(|| EnclaveError::InvalidRequest("reference metadata is required".into())),
    }
}

pub fn router() -> Router<Arc<CpState>> {
    Router::new()
        .route("/api/v2/capture/events", post(upload_capture_event))
        .route(
            "/api/v2/capture/screen-reference-batches",
            post(upload_screen_reference_batch)
                .layer(DefaultBodyLimit::max(MAX_REFERENCE_BATCH_BYTES)),
        )
        .route("/api/v2/capture/events/{event_id}", get(capture_status))
        .route("/api/v2/capture/sessions", get(list_capture_sessions))
        .route(
            "/api/v2/capture/sessions/{capture_session_id}",
            get(capture_session_status).post(finish_capture_session),
        )
        .route("/api/v2/capture/streams/{stream_id}/ack", get(stream_ack))
        .route("/api/v2/people", get(list_people))
        .route("/api/v2/people/{person_id}", get(person_profile))
        .route("/api/v2/people/{person_id}/evidence", get(person_evidence))
        .route(
            "/api/v2/people/{person_id}/statements",
            get(person_statements),
        )
        .layer(DefaultBodyLimit::max(MAX_MULTIPART_BYTES))
}

async fn upload_screen_reference_batch(
    State(state): State<Arc<CpState>>,
    Extension(user): Extension<AuthUser>,
    headers: HeaderMap,
    Json(request): Json<ScreenReferenceBatchRequest>,
) -> Response {
    let started_at = Instant::now();
    let user_id = user.0;
    let manifest = request.events.first();
    if headers
        .get("kioku-delivery-mode")
        .and_then(|value| value.to_str().ok())
        != Some("encrypted-outbox-v1")
    {
        return capture_failure_response_for_route(
            "screen_reference_batch",
            started_at,
            manifest,
            CaptureIngestFailureReason::RequestInvalid,
            bad_request("reference batches require encrypted outbox delivery mode"),
        );
    }
    match limits::account_active(&state.control, &user_id).await {
        Ok(true) => {}
        Ok(false) => {
            return capture_failure_response_for_route(
                "screen_reference_batch",
                started_at,
                manifest,
                CaptureIngestFailureReason::AccountSuspended,
                (
                    StatusCode::FORBIDDEN,
                    Json(json!({"error": "account_suspended"})),
                )
                    .into_response(),
            )
        }
        Err(error) => {
            tracing::error!(error = %error, "capture reference batch account lookup failed");
            return capture_failure_response_for_route(
                "screen_reference_batch",
                started_at,
                manifest,
                CaptureIngestFailureReason::AccountStatusUnavailable,
                (StatusCode::SERVICE_UNAVAILABLE, "service unavailable").into_response(),
            );
        }
    }
    if !state.reference_batch_limiter.consume(&user_id).await {
        return capture_failure_response_for_route(
            "screen_reference_batch",
            started_at,
            manifest,
            CaptureIngestFailureReason::RateLimited,
            rate_limited_response(),
        );
    }
    let validated = match validate_reference_batch(&request) {
        Ok(value) => value,
        Err(error) => {
            return capture_error_response_for_route(
                "screen_reference_batch",
                started_at,
                manifest,
                error,
            )
        }
    };
    let _batch_permit = match Arc::clone(&state.reference_batch_concurrency).try_acquire_owned() {
        Ok(permit) => permit,
        Err(_) => {
            return capture_failure_response_for_route(
                "screen_reference_batch",
                started_at,
                manifest,
                CaptureIngestFailureReason::RateLimited,
                rate_limited_response(),
            )
        }
    };
    let _lifecycle_guard = match state.store.lock_user_lifecycle(&user_id).await {
        Ok(guard) => guard,
        Err(error) => {
            return capture_failure_response_for_route(
                "screen_reference_batch",
                started_at,
                manifest,
                CaptureIngestFailureReason::LifecycleUnavailable,
                error.into_response(),
            )
        }
    };
    let _content_write = match state.store.acquire_content_write(&user_id).await {
        Ok(lease) => lease,
        Err(error) => {
            return capture_failure_response_for_route(
                "screen_reference_batch",
                started_at,
                manifest,
                CaptureIngestFailureReason::LifecycleUnavailable,
                error.into_response(),
            )
        }
    };
    // ADR-0022 per-domain routing: a WAL-authoritative user's preflight and
    // batch write route through the settled lane — the sealed plan covers the
    // complete manifest vector and every reference write, and the settle-
    // submit replaces the legacy write+save pair with acknowledgement only
    // after witness settlement. Billing reserve/complete, limits, leases, and
    // telemetry are identical on both branches.
    let wal_authoritative = state.store.is_wal_authoritative(&user_id);
    let preflight = if wal_authoritative {
        let events = request.events.clone();
        let digests = validated.manifest_digests.clone();
        state
            .store
            .wal_authoritative_read(&user_id, move |conn| {
                events
                    .iter()
                    .zip(&digests)
                    .map(|(event, digest)| preflight_source_event(conn, event, digest, None))
                    .collect::<Result<Vec<_>>>()
            })
            .await
    } else {
        state
            .store
            .with_user_read(&user_id, |conn| {
                request
                    .events
                    .iter()
                    .zip(&validated.manifest_digests)
                    .map(|(event, digest)| preflight_source_event(conn, event, digest, None))
                    .collect::<Result<Vec<_>>>()
            })
            .await
    };
    let preflight = match preflight {
        Ok(value) => value,
        Err(error) => {
            return capture_error_response_for_route(
                "screen_reference_batch",
                started_at,
                manifest,
                error,
            )
        }
    };
    let new_event_ids = preflight
        .iter()
        .zip(&validated.event_ids)
        .filter(|(outcome, _)| matches!(outcome, PreflightOutcome::New))
        .map(|(_, event_id)| event_id.clone())
        .collect::<Vec<_>>();
    if let Err(response) = super::billing::reserve_recording_delivery_batch(
        &state,
        &user_id,
        &request.batch_id,
        &validated.aggregate_manifest_digest,
        &validated.stream_id,
        validated.first_sequence,
        validated.last_sequence,
        &validated.event_ids,
        &new_event_ids,
    )
    .await
    {
        let reason = recording_entitlement_failure_reason(response.status());
        return capture_failure_response_for_route(
            "screen_reference_batch",
            started_at,
            manifest,
            reason,
            response,
        );
    }

    let recorded = if wal_authoritative {
        let plan = match wal::MediaReferenceBatchPlan::new(
            user_id.clone(),
            request.batch_id.clone(),
            request.events.clone(),
            enclave_commit_stamp(),
        ) {
            Ok(plan) => plan,
            Err(_) => {
                return capture_error_response_for_route(
                    "screen_reference_batch",
                    started_at,
                    manifest,
                    crate::error::EnclaveError::Store(
                        "reference batch plan construction failed".into(),
                    ),
                )
            }
        };
        // Taken BEFORE `prepare` consumes the plan: the submit narrows every
        // owner refusal to a content-free conflict, so the rebase-required
        // reason has to travel out of band or the route answers 409 and the
        // client's durable outbox re-posts an event only a rebase can fix.
        let refusal = plan.refusal_sink();
        let prepared =
            match crate::archive_v3_wal_idempotency::PreparedLogicalMutation::prepare(plan) {
                Ok(prepared) => prepared,
                Err(_) => {
                    return capture_error_response_for_route(
                        "screen_reference_batch",
                        started_at,
                        manifest,
                        crate::error::EnclaveError::Store(
                            "reference batch plan construction failed".into(),
                        ),
                    )
                }
            };
        match state
            .store
            .wal_authoritative_submit(&user_id, prepared)
            .await
        {
            Ok(outcome) => RecordedReferenceBatch {
                new_count: usize::from(outcome.new_count()),
                duplicate_count: usize::from(outcome.duplicate_count()),
                committed_through_sequence: outcome.committed_through_sequence(),
            },
            Err(error) => {
                return capture_error_response_for_route(
                    "screen_reference_batch",
                    started_at,
                    manifest,
                    refusal.observed().unwrap_or(error),
                )
            }
        }
    } else {
        let recorded = state
            .store
            .with_user(&user_id, |conn| {
                record_reference_batch(conn, &user_id, &request.events, &validated.manifest_digests)
            })
            .await;
        let recorded = match recorded {
            Ok(value) => value,
            Err(error) => {
                return capture_error_response_for_route(
                    "screen_reference_batch",
                    started_at,
                    manifest,
                    error,
                )
            }
        };
        if let Err(error) = state.store.save_user(&user_id).await {
            tracing::error!(error = %error, "capture reference batch persistence failed");
            return capture_failure_response_for_route(
                "screen_reference_batch",
                started_at,
                manifest,
                CaptureIngestFailureReason::PersistenceUnavailable,
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "capture persistence failed",
                )
                    .into_response(),
            );
        }
        recorded
    };
    super::billing::complete_recording_delivery_batch(
        &state,
        &user_id,
        &request.batch_id,
        &validated.aggregate_manifest_digest,
        &validated.event_ids,
    )
    .await;
    let status = if recorded.new_count == 0 {
        StatusCode::OK
    } else {
        StatusCode::CREATED
    };
    (
        status,
        Json(ScreenReferenceBatchAccepted {
            batch_id: request.batch_id,
            stream_id: validated.stream_id,
            first_sequence: validated.first_sequence,
            last_sequence: validated.last_sequence,
            new_count: recorded.new_count,
            duplicate_count: recorded.duplicate_count,
            committed_through_sequence: recorded.committed_through_sequence,
            max_screen_dedupe_version: MAX_SCREEN_DEDUPE_VERSION,
        }),
    )
        .into_response()
}

async fn upload_capture_event(
    State(state): State<Arc<CpState>>,
    Extension(user): Extension<AuthUser>,
    headers: HeaderMap,
    mut multipart: Multipart,
) -> Response {
    let started_at = Instant::now();
    let user_id = user.0;
    let encrypted_outbox_delivery = headers
        .get("kioku-delivery-mode")
        .and_then(|value| value.to_str().ok())
        == Some("encrypted-outbox-v1");
    match limits::account_active(&state.control, &user_id).await {
        Ok(true) => {}
        Ok(false) => {
            return capture_failure_response(
                started_at,
                None,
                CaptureIngestFailureReason::AccountSuspended,
                (
                    StatusCode::FORBIDDEN,
                    Json(json!({"error": "account_suspended"})),
                )
                    .into_response(),
            )
        }
        Err(error) => {
            tracing::error!(error = %error, "capture account status lookup failed");
            return capture_failure_response(
                started_at,
                None,
                CaptureIngestFailureReason::AccountStatusUnavailable,
                (StatusCode::SERVICE_UNAVAILABLE, "service unavailable").into_response(),
            );
        }
    }
    // ADR-0022 per-domain routing: capture ingest is MIGRATED. Its D4 gate is
    // gone because both dispositions this one route serves now have a sealed
    // family:
    //   * canonical  -- `wal::CanonicalCaptureEventPlan` (subtype
    //                   `canonical-capture-event-v1`), taking the object key
    //                   and positive provider generation the upload boundary
    //                   below produces. Its residual was never the plan: it
    //                   treats an already-present event as a hard precondition
    //                   failure while this route answers 200, so the preflight
    //                   below had to route to the settled lane before the
    //                   submit could be reached at all.
    //   * reference  -- `wal::MediaReferenceEventPlan` (subtype
    //                   `adr-0022-single-reference-capture-event-v1`), a new
    //                   family with its own operation-source domain and its
    //                   own ledger. See that module for why a bespoke plan
    //                   reusing the batch id derivation would have collided on
    //                   one `archive_v3_wal_publications` slot and one attempt
    //                   ladder with a fingerprint it could never match.
    //
    // BOTH had to land together. A mac_screen stream interleaves canonical
    // screenshots and their reference pointers by sequence, and
    // `advance_contiguous_ack` walks only while the next sequence exists, so
    // routing the canonical arm alone would have stalled every such stream
    // permanently at its first refused reference event.
    if !state.sync_limiter.consume(&user_id).await {
        return capture_failure_response(
            started_at,
            None,
            CaptureIngestFailureReason::RateLimited,
            rate_limited_response(),
        );
    }

    let mut manifest_bytes: Option<Vec<u8>> = None;
    let mut media_bytes: Option<Vec<u8>> = None;
    let mut media_content_type: Option<String> = None;
    loop {
        let field = match multipart.next_field().await {
            Ok(Some(field)) => field,
            Ok(None) => break,
            Err(_) => {
                return capture_failure_response(
                    started_at,
                    None,
                    CaptureIngestFailureReason::MultipartInvalid,
                    bad_request("invalid multipart body"),
                )
            }
        };
        let name = field.name().unwrap_or_default().to_string();
        match name.as_str() {
            "manifest" if manifest_bytes.is_none() => match field.bytes().await {
                Ok(bytes) if bytes.len() <= MAX_MANIFEST_BYTES => {
                    manifest_bytes = Some(bytes.to_vec())
                }
                Ok(_) => {
                    return capture_failure_response(
                        started_at,
                        None,
                        CaptureIngestFailureReason::ManifestTooLarge,
                        bad_request("manifest is too large"),
                    )
                }
                Err(_) => {
                    return capture_failure_response(
                        started_at,
                        None,
                        CaptureIngestFailureReason::MultipartInvalid,
                        bad_request("invalid manifest field"),
                    )
                }
            },
            "media" if media_bytes.is_none() => {
                media_content_type = field.content_type().map(ToOwned::to_owned);
                match field.bytes().await {
                    Ok(bytes) if bytes.len() <= MAX_AUDIO_BYTES as usize => {
                        media_bytes = Some(bytes.to_vec())
                    }
                    Ok(_) => {
                        return capture_failure_response(
                            started_at,
                            None,
                            CaptureIngestFailureReason::MediaTooLarge,
                            (StatusCode::PAYLOAD_TOO_LARGE, "media is too large").into_response(),
                        )
                    }
                    Err(_) => {
                        return capture_failure_response(
                            started_at,
                            None,
                            CaptureIngestFailureReason::MultipartInvalid,
                            bad_request("invalid media field"),
                        )
                    }
                }
            }
            "manifest" | "media" => {
                return capture_failure_response(
                    started_at,
                    None,
                    CaptureIngestFailureReason::MultipartInvalid,
                    bad_request("duplicate multipart field"),
                )
            }
            _ => {
                return capture_failure_response(
                    started_at,
                    None,
                    CaptureIngestFailureReason::MultipartInvalid,
                    bad_request("unknown multipart field"),
                )
            }
        }
    }
    let Some(manifest_bytes) = manifest_bytes else {
        return capture_failure_response(
            started_at,
            None,
            CaptureIngestFailureReason::ManifestMissing,
            bad_request("manifest field is required"),
        );
    };
    let manifest: CaptureEventManifest = match serde_json::from_slice(&manifest_bytes) {
        Ok(value) => value,
        Err(_) => {
            return capture_failure_response(
                started_at,
                None,
                CaptureIngestFailureReason::ManifestInvalid,
                bad_request("manifest is not valid capture schema v2 JSON"),
            )
        }
    };
    if let Err(error) = manifest.validate() {
        return capture_error_response(started_at, Some(&manifest), error);
    }
    match manifest.media_disposition {
        MediaDisposition::Canonical => {
            let Some(bytes) = media_bytes.as_deref() else {
                return capture_failure_response(
                    started_at,
                    Some(&manifest),
                    CaptureIngestFailureReason::MediaMissing,
                    bad_request("canonical events require a media field"),
                );
            };
            if let Err(error) =
                validate_media_bytes(&manifest, bytes, media_content_type.as_deref())
            {
                return capture_failure_response(
                    started_at,
                    Some(&manifest),
                    CaptureIngestFailureReason::MediaInvalid,
                    error.into_response(),
                );
            }
        }
        MediaDisposition::Reference if media_bytes.is_some() => {
            return capture_failure_response(
                started_at,
                Some(&manifest),
                CaptureIngestFailureReason::MediaInvalid,
                bad_request("reference events cannot contain a media field"),
            )
        }
        MediaDisposition::Reference => {}
    }
    let digest = match manifest_digest(&manifest) {
        Ok(value) => value,
        Err(error) => return capture_error_response(started_at, Some(&manifest), error),
    };
    let asset_id = match response_asset_id(&manifest) {
        Ok(value) => value,
        Err(error) => return capture_error_response(started_at, Some(&manifest), error),
    };
    let object_key = manifest
        .media
        .as_ref()
        .map(|media| format!("raw/{user_id}/{}.enc", media.asset_id));
    let _lifecycle_guard = match state.store.lock_user_lifecycle(&user_id).await {
        Ok(guard) => guard,
        Err(error) => {
            return capture_failure_response(
                started_at,
                Some(&manifest),
                CaptureIngestFailureReason::LifecycleUnavailable,
                error.into_response(),
            )
        }
    };
    // Keep admission alive through the GCS object and durable SQLite record.
    // DELETE /api/account closes this barrier before it inventories media, so
    // an already-authorized capture cannot recreate an object afterward.
    let _content_write = match state.store.acquire_content_write(&user_id).await {
        Ok(lease) => lease,
        Err(error) => {
            return capture_failure_response(
                started_at,
                Some(&manifest),
                CaptureIngestFailureReason::LifecycleUnavailable,
                error.into_response(),
            )
        }
    };
    // ADR-0022 per-domain routing. This preflight is the canonical arm's whole
    // residual and it is load-bearing on BOTH branches:
    //
    //   * A WAL-authoritative user reads the SETTLED lane. Without that, a
    //     selected user's preflight would run through `with_user`, which
    //     refuses outright for a WAL-authoritative archive, and every capture
    //     would fail before it reached a plan.
    //   * `CanonicalCaptureEventPlan` treats an already-present event as a
    //     hard `Precondition` failure (`ensure_domain_targets_absent`), and
    //     the legacy route answers 200 for it. Catching the duplicate HERE,
    //     before the submit, is what keeps a re-posted event answering 200
    //     instead of 409. The reference arm's plan handles a duplicate as a
    //     first-class outcome, so this read is a fast path for it, not a
    //     correctness precondition.
    //
    // Same shape as `upload_screen_reference_batch` above.
    let wal_authoritative = state.store.is_wal_authoritative(&user_id);
    let preflight = if wal_authoritative {
        let preflight_manifest = manifest.clone();
        let preflight_digest = digest.clone();
        let preflight_object_key = object_key.clone();
        state
            .store
            .wal_authoritative_read(&user_id, move |conn| {
                preflight_source_event(
                    conn,
                    &preflight_manifest,
                    &preflight_digest,
                    preflight_object_key.as_deref(),
                )
            })
            .await
    } else {
        state
            .store
            .with_user(&user_id, |conn| {
                preflight_source_event(conn, &manifest, &digest, object_key.as_deref())
            })
            .await
    };
    match preflight {
        Ok(PreflightOutcome::Duplicate {
            committed_through_sequence,
        }) => {
            // A prior attempt may have committed only to the in-memory archive
            // before its durable save failed. Flush even duplicate preflight
            // state before acknowledging or clearing delayed-delivery authority.
            // The WAL lane has no such half-state: it acknowledges only after
            // witness settlement and never persists through `save_user`.
            if !wal_authoritative {
                if let Err(error) = state.store.save_user(&user_id).await {
                    tracing::error!(error = %error, "duplicate capture persistence failed");
                    return capture_failure_response(
                        started_at,
                        Some(&manifest),
                        CaptureIngestFailureReason::PersistenceUnavailable,
                        (
                            StatusCode::INTERNAL_SERVER_ERROR,
                            "capture persistence failed",
                        )
                            .into_response(),
                    );
                }
            }
            if encrypted_outbox_delivery {
                super::billing::complete_recording_delivery(&state, &user_id, &manifest.event_id)
                    .await;
            }
            return (
                StatusCode::OK,
                Json(CaptureAccepted {
                    event_id: manifest.event_id,
                    asset_id,
                    media_disposition: manifest.media_disposition,
                    processing_state: if manifest.media_disposition.is_canonical() {
                        "queued"
                    } else {
                        "ready"
                    },
                    committed_through_sequence,
                }),
            )
                .into_response();
        }
        Ok(PreflightOutcome::New) => {}
        Err(error) => return capture_error_response(started_at, Some(&manifest), error),
    }

    // Wall-clock allowance is consumed by short idempotent recording leases,
    // not by VAD-triggered media duration, which can overlap across streams.
    if capture_requires_recording_lease(manifest.stream_kind) {
        let entitlement = if encrypted_outbox_delivery {
            super::billing::reserve_recording_delivery(
                &state,
                &user_id,
                &manifest.event_id,
                media_bytes.as_ref().map_or(0, |bytes| bytes.len() as i64),
            )
            .await
        } else {
            super::billing::check_recording_entitlement(&state, &user_id).await
        };
        if let Err(response) = entitlement {
            let reason = recording_entitlement_failure_reason(response.status());
            return capture_failure_response(started_at, Some(&manifest), reason, response);
        }
    }

    let mut media_generation = None;
    if manifest.media_disposition == MediaDisposition::Canonical {
        let object_key = object_key
            .as_deref()
            .expect("validated canonical object key");
        let media_bytes = media_bytes.as_deref().expect("validated canonical media");
        let (media_dek, wrapped_dek) = match load_or_create_media_dek(&state, &user_id).await {
            Ok(value) => value,
            Err(error) => {
                tracing::error!(error = %error, "capture media key setup failed");
                return capture_failure_response(
                    started_at,
                    Some(&manifest),
                    CaptureIngestFailureReason::MediaStorageUnavailable,
                    (StatusCode::INTERNAL_SERVER_ERROR, "media upload failed").into_response(),
                );
            }
        };
        let media_context = crate::store::media_blob_context(&user_id, object_key);
        let encrypted =
            match crate::crypto::encrypt_bound_blob(&media_dek, media_bytes, &media_context) {
                Ok(value) => value,
                Err(error) => {
                    tracing::error!(error = %error, "capture media encryption failed");
                    return capture_failure_response(
                        started_at,
                        Some(&manifest),
                        CaptureIngestFailureReason::MediaStorageUnavailable,
                        (StatusCode::INTERNAL_SERVER_ERROR, "media upload failed").into_response(),
                    );
                }
            };
        // The child keeps the provider PUT alive if the HTTP future is
        // cancelled. Deletion waits for that child lease and therefore scans
        // only after the provider has definitively accepted or rejected it.
        let put_lease = _content_write.child();
        let put_store = Arc::clone(&state.store);
        let put_user_id = user_id.clone();
        let put_object_key = object_key.to_string();
        let put_wrapped_dek = wrapped_dek.clone();
        let put = tokio::spawn(async move {
            let _put_lease = put_lease;
            put_store
                .put_user_media(&put_user_id, &put_object_key, &encrypted, &put_wrapped_dek)
                .await
        });
        match put.await {
            Ok(Ok(generation)) => media_generation = Some(generation),
            Ok(Err(put_error)) => {
                if let Err(error) =
                    verify_existing_media(&state, &user_id, object_key, &media_context, media_bytes)
                        .await
                {
                    tracing::error!(error = %put_error, verify_error = %error, "capture media storage failed");
                    return capture_failure_response(
                        started_at,
                        Some(&manifest),
                        CaptureIngestFailureReason::MediaStorageUnavailable,
                        (StatusCode::INTERNAL_SERVER_ERROR, "media upload failed").into_response(),
                    );
                }
                media_generation = match state.store.get_media(object_key).await {
                    Ok(existing) => Some(existing.generation),
                    Err(error) => {
                        tracing::error!(error = %error, "capture media generation lookup failed");
                        return capture_failure_response(
                            started_at,
                            Some(&manifest),
                            CaptureIngestFailureReason::MediaStorageUnavailable,
                            (StatusCode::INTERNAL_SERVER_ERROR, "media upload failed")
                                .into_response(),
                        );
                    }
                };
            }
            Err(error) => {
                tracing::error!(error = %error, "capture media storage task failed");
                return capture_failure_response(
                    started_at,
                    Some(&manifest),
                    CaptureIngestFailureReason::MediaStorageUnavailable,
                    (StatusCode::INTERNAL_SERVER_ERROR, "media upload failed").into_response(),
                );
            }
        }
    }

    // The settle-submit replaces the legacy write+save pair: acknowledgement
    // comes only after immutable publication and witness settlement, so there
    // is no `save_user` on this branch and nothing to flush. Billing, limits,
    // leases, the media upload above and the telemetry below are identical on
    // both branches.
    let (committed, duplicate) = if wal_authoritative {
        match manifest.media_disposition {
            MediaDisposition::Canonical => {
                let object_key = object_key
                    .as_deref()
                    .expect("validated canonical object key");
                // The plan requires the immutable upload handoff: an exact
                // account-bound object key and a POSITIVE provider generation.
                // A missing or non-positive generation means the upload above
                // did not actually fix the object, so refuse rather than mint
                // a receipt for media nothing can be replayed against.
                let Some(generation) = media_generation.filter(|value| *value > 0) else {
                    tracing::error!("canonical capture reached the WAL lane without a generation");
                    return capture_failure_response(
                        started_at,
                        Some(&manifest),
                        CaptureIngestFailureReason::MediaStorageUnavailable,
                        (StatusCode::INTERNAL_SERVER_ERROR, "media upload failed").into_response(),
                    );
                };
                let plan = match wal::CanonicalCaptureEventPlan::new(
                    user_id.clone(),
                    manifest.clone(),
                    object_key.to_string(),
                    generation,
                    enclave_commit_stamp(),
                ) {
                    Ok(plan) => plan,
                    Err(_) => {
                        return capture_error_response(
                            started_at,
                            Some(&manifest),
                            EnclaveError::Store(
                                "canonical capture plan construction failed".into(),
                            ),
                        )
                    }
                };
                let prepared =
                    match crate::archive_v3_wal_idempotency::PreparedLogicalMutation::prepare(plan)
                    {
                        Ok(prepared) => prepared,
                        Err(_) => {
                            return capture_error_response(
                                started_at,
                                Some(&manifest),
                                EnclaveError::Store(
                                    "canonical capture plan construction failed".into(),
                                ),
                            )
                        }
                    };
                match state
                    .store
                    .wal_authoritative_submit(&user_id, prepared)
                    .await
                {
                    Ok(outcome) => (outcome.committed_through_sequence(), false),
                    Err(error) => {
                        return capture_error_response(started_at, Some(&manifest), error)
                    }
                }
            }
            MediaDisposition::Reference => {
                let plan = match wal::MediaReferenceEventPlan::new(
                    user_id.clone(),
                    manifest.clone(),
                    enclave_commit_stamp(),
                ) {
                    Ok(plan) => plan,
                    Err(_) => {
                        return capture_error_response(
                            started_at,
                            Some(&manifest),
                            EnclaveError::Store(
                                "reference capture plan construction failed".into(),
                            ),
                        )
                    }
                };
                // Taken BEFORE `prepare` consumes the plan: the submit narrows
                // every owner refusal to a content-free conflict, and a
                // rebase-required refusal that arrives content-free is a wedge
                // -- the client re-posts an event only a rebase can fix.
                let refusal = plan.refusal_sink();
                let prepared =
                    match crate::archive_v3_wal_idempotency::PreparedLogicalMutation::prepare(plan)
                    {
                        Ok(prepared) => prepared,
                        Err(_) => {
                            return capture_error_response(
                                started_at,
                                Some(&manifest),
                                EnclaveError::Store(
                                    "reference capture plan construction failed".into(),
                                ),
                            )
                        }
                    };
                match state
                    .store
                    .wal_authoritative_submit(&user_id, prepared)
                    .await
                {
                    Ok(outcome) => (outcome.committed_through_sequence(), outcome.duplicate()),
                    Err(error) => {
                        return capture_error_response(
                            started_at,
                            Some(&manifest),
                            refusal.observed().unwrap_or(error),
                        )
                    }
                }
            }
        }
    } else {
        let outcome = state
            .store
            .with_user(&user_id, |conn| {
                match manifest.media_disposition {
                    MediaDisposition::Canonical => record_source_event_with_generation(
                        conn,
                        &user_id,
                        &manifest,
                        &digest,
                        object_key
                            .as_deref()
                            .expect("validated canonical object key"),
                        media_generation,
                    )?,
                    MediaDisposition::Reference => {
                        record_reference_event(conn, &user_id, &manifest, &digest)?
                    }
                };
                committed_through_sequence(conn, &manifest.stream_id)
            })
            .await;
        let committed = match outcome {
            Ok(value) => value,
            Err(error) => return capture_error_response(started_at, Some(&manifest), error),
        };
        if let Err(error) = state.store.save_user(&user_id).await {
            tracing::error!(error = %error, "capture database persistence failed");
            return capture_failure_response(
                started_at,
                Some(&manifest),
                CaptureIngestFailureReason::PersistenceUnavailable,
                (StatusCode::INTERNAL_SERVER_ERROR, "media upload failed").into_response(),
            );
        }
        (committed, false)
    };
    if encrypted_outbox_delivery {
        super::billing::complete_recording_delivery(&state, &user_id, &manifest.event_id).await;
    }
    // A reference event that raced another writer between the preflight and
    // the submit settles as a duplicate rather than refusing, and answers the
    // same 200 the preflight branch above would have.
    let status = if duplicate {
        StatusCode::OK
    } else {
        StatusCode::CREATED
    };
    (
        status,
        Json(CaptureAccepted {
            event_id: manifest.event_id,
            asset_id,
            media_disposition: manifest.media_disposition,
            processing_state: if manifest.media_disposition.is_canonical() {
                "queued"
            } else {
                "ready"
            },
            committed_through_sequence: committed,
        }),
    )
        .into_response()
}

fn capture_requires_recording_lease(_stream_kind: StreamKind) -> bool {
    true
}

async fn stream_ack(
    State(state): State<Arc<CpState>>,
    Extension(user): Extension<AuthUser>,
    Path(stream_id): Path<String>,
) -> Response {
    if let Err(error) = validate_id("stream_id", &stream_id) {
        return error.into_response();
    }
    // ADR-0022 D4: the gate here is GONE because its answerability blocker is.
    // It was retained not because this handler writes -- it is a pure SELECT
    // over `capture_streams` -- but because every canonical stream it could
    // name was created by the then-deferred `upload_capture_event`, so a
    // routed answer for a selected user could only be `NotFound` -> 404 "no
    // such stream" when the truth was "ingest for your account is deferred".
    // Ingest is migrated, so the absence this read reports is now a truthful
    // one, and the read routes: a selected user reads the settled lane, an
    // unselected user keeps the legacy path, and neither is served the other's
    // snapshot. (`with_user_read` rather than the bare `with_user` this
    // replaced, so the legacy fallthrough also runs under SQLite's
    // `query_only` guard.)
    match state
        .store
        .wal_authoritative_read(&user.0, {
            let stream_id = stream_id.clone();
            move |conn| committed_through_sequence(conn, &stream_id)
        })
        .await
    {
        Ok(committed) => Json(StreamAck {
            stream_id,
            committed_through_sequence: committed,
        })
        .into_response(),
        // `committed_through_sequence` folds "no such stream" into
        // `Err(NotFound)` rather than `Ok(None)`, so this arm carries two
        // different things and they must not share a status. The absence is a
        // truthful 404 now that ingest writes every stream this can name --
        // that is the whole reason the gate above could be lifted. Everything
        // else is the routed read itself failing (an unregistered, quarantined
        // or mid-relaunch serving authority arrives as `EnclaveError::Store`),
        // which is retryable and answers the lane's 503 under
        // `super::routed_read_unavailable`'s rule. It is deliberately NOT the
        // 500 the generic arm would render: that makes a retryable read
        // failure indistinguishable from a genuinely non-retryable one.
        Err(EnclaveError::NotFound) => EnclaveError::NotFound.into_response(),
        Err(error) => super::routed_read_unavailable("api.media.stream_ack", &error),
    }
}

async fn capture_status(
    State(state): State<Arc<CpState>>,
    Extension(user): Extension<AuthUser>,
    Path(event_id): Path<String>,
) -> Response {
    if let Err(error) = validate_id("event_id", &event_id) {
        return error.into_response();
    }
    // ADR-0022 D4: the gate here is GONE because its answerability blocker is.
    // This read's only production writer is `upload_capture_event`, which was
    // deferred; a routed `Ok(None)` -> 404 "no such event" for a selected user
    // was then indistinguishable from the truthful "you never uploaded that
    // event". Ingest is migrated, so the 404 is now truthful and the routing
    // below is answerable.
    //
    // The legacy fallthrough is `with_user_read`, so an unselected user's read
    // runs under SQLite's `query_only` guard; a WAL-authoritative user reads
    // the settled-only lane and a user with no registered serving authority
    // refuses as unavailable — never the stale legacy snapshot.
    match state
        .store
        .wal_authoritative_read(&user.0, move |conn| load_capture_status(conn, &event_id))
        .await
    {
        Ok(Some(status)) => Json(status).into_response(),
        Ok(None) => EnclaveError::NotFound.into_response(),
        // A failed routed read is NOT an absence and NOT a fault: the archive
        // is present and merely unreadable. 503 under
        // `super::routed_read_unavailable`'s rule, never the 500 the generic
        // arm renders for `EnclaveError::Store` -- the D4 gate used to fire
        // first, so this arm was unreachable for exactly the population it now
        // serves.
        Err(error) => super::routed_read_unavailable("api.media.capture_status", &error),
    }
}

/// The summarizer cursor, for the no_memory derivation (ADR-0034). Best
/// effort: an unreadable cursor degrades to "unknown", which can only delay
/// the terminal zero-result — never invent it.
async fn summarized_until_ms(state: &CpState, user_id: &str) -> Option<i64> {
    match state.control.summarized_until(user_id).await {
        Ok(cursor) => cursor
            .as_deref()
            .and_then(super::isotime::parse_epoch_millis),
        Err(_) => None,
    }
}

async fn capture_session_status(
    State(state): State<Arc<CpState>>,
    Extension(user): Extension<AuthUser>,
    Path(capture_session_id): Path<String>,
) -> Response {
    if let Err(error) = validate_id("capture_session_id", &capture_session_id) {
        return error.into_response();
    }
    // ADR-0022 D4: gate GONE with ingest. The session rows this reads could
    // once only have been created by the deferred ingest, so a routed answer
    // could only be an absence; ingest is migrated, so an absence here is
    // truthful. Routed exactly as `finish_capture_session` routes this same
    // read.
    let cursor_ms = summarized_until_ms(&state, &user.0).await;
    match state
        .store
        .wal_authoritative_read(&user.0, move |conn| {
            load_capture_session_status(conn, &capture_session_id, cursor_ms)
        })
        .await
    {
        Ok(Some(status)) => Json(status).into_response(),
        Ok(None) => EnclaveError::NotFound.into_response(),
        // See `capture_status`: an unreadable archive is retryable, so it
        // answers 503 rather than the generic 500.
        Err(error) => super::routed_read_unavailable("api.media.capture_session_status", &error),
    }
}

/// Bounded account-scoped session discovery (ADR-0034 §3): the web dashboard
/// holds no capture-session ID, so it lists recent sessions instead. Reads
/// the same per-user facts as the single-session endpoint; nothing global.
async fn list_capture_sessions(
    State(state): State<Arc<CpState>>,
    Extension(user): Extension<AuthUser>,
    Query(query): Query<CaptureSessionListQuery>,
) -> Response {
    // ADR-0022 D4: gate GONE with ingest, which writes every row this could
    // list. It was the endpoint the answerability rule mattered most for,
    // because it answers a COLLECTION: an ungated routed read for a selected
    // user produced `200 {"sessions": []}`, a deferral wearing the face of a
    // truthful empty archive. With ingest migrated the empty list is the
    // truth, and this routes like its single-session sibling.
    let window_hours = query.window_hours.unwrap_or(8).clamp(1, 24);
    let max_sessions = query.max_sessions.unwrap_or(5).clamp(1, 10);
    let cursor_ms = summarized_until_ms(&state, &user.0).await;
    // Per-domain routing, live for every unselected user today: same per-user
    // facts as the single-session endpoint, so it routes the same way.
    match state
        .store
        .wal_authoritative_read(&user.0, move |conn| {
            let ids = load_recent_capture_session_ids(conn, window_hours, max_sessions)?;
            let mut sessions = Vec::with_capacity(ids.len());
            for id in ids {
                if let Some(status) = load_capture_session_status(conn, &id, cursor_ms)? {
                    sessions.push(status);
                }
            }
            Ok(CaptureSessionList { sessions })
        })
        .await
    {
        Ok(list) => Json(list).into_response(),
        // A COLLECTION endpoint, so this arm matters most: 503 with the named
        // reason under `super::routed_read_unavailable`'s rule. Never the
        // generic 500, and never a 200 carrying an empty `sessions` array --
        // a refusal must not wear the face of a truthful empty archive.
        Err(error) => super::routed_read_unavailable("api.media.capture_sessions", &error),
    }
}

/// Sessions that started within the window, plus still-open sessions with
/// recent events (so an in-flight recording is discoverable even when it
/// started before the window). Stale open sessions age out with their last
/// event rather than pinning the list forever.
fn load_recent_capture_session_ids(
    conn: &Connection,
    window_hours: i64,
    max_sessions: i64,
) -> Result<Vec<String>> {
    let window_modifier = format!("-{window_hours} hours");
    let mut statement = conn.prepare(
        "SELECT id FROM capture_sessions \
         WHERE started_at >= strftime('%Y-%m-%dT%H:%M:%fZ','now',?1) \
            OR (ended_at IS NULL \
                AND last_event_at >= strftime('%Y-%m-%dT%H:%M:%fZ','now',?1)) \
         ORDER BY started_at DESC LIMIT ?2",
    )?;
    let ids = statement
        .query_map(params![window_modifier, max_sessions], |row| {
            row.get::<_, String>(0)
        })?
        .collect::<std::result::Result<Vec<_>, _>>()?;
    Ok(ids)
}

async fn finish_capture_session(
    State(state): State<Arc<CpState>>,
    Extension(user): Extension<AuthUser>,
    Path(capture_session_id): Path<String>,
) -> Response {
    if let Err(error) = validate_id("capture_session_id", &capture_session_id) {
        return error.into_response();
    }
    // ADR-0022 per-domain routing: a WAL-authoritative user's finish flows
    // through the sealed capture-session-finish plan — probe, settle-submit,
    // then read the settled status — and is acknowledged only after witness
    // settlement. The probe mirrors the legacy updated==0 branch (an unknown
    // session is already in the goal state), and a submit-time conflict
    // surfaces as an error so the client's durably queued finish marker
    // retries instead of being silently dropped.
    if state.store.is_wal_authoritative(&user.0) {
        let probe_session_id = capture_session_id.clone();
        match state
            .store
            .wal_authoritative_read(&user.0, move |conn| {
                Ok(conn
                    .query_row(
                        "SELECT 1 FROM capture_sessions WHERE id=?1",
                        [&probe_session_id],
                        |_| Ok(()),
                    )
                    .optional()?
                    .is_some())
            })
            .await
        {
            Ok(true) => {}
            Ok(false) => return StatusCode::NO_CONTENT.into_response(),
            Err(error) => return error.into_response(),
        }
        let plan = match wal::CaptureSessionFinishPlan::new(capture_session_id.clone()) {
            Ok(plan) => plan,
            Err(_) => {
                return crate::error::EnclaveError::Store(
                    "capture-session finish plan construction failed".into(),
                )
                .into_response()
            }
        };
        let prepared =
            match crate::archive_v3_wal_idempotency::PreparedLogicalMutation::prepare(plan) {
                Ok(prepared) => prepared,
                Err(_) => {
                    return crate::error::EnclaveError::Store(
                        "capture-session finish plan construction failed".into(),
                    )
                    .into_response()
                }
            };
        if let Err(error) = state
            .store
            .wal_authoritative_submit(&user.0, prepared)
            .await
        {
            return error.into_response();
        }
        let status_session_id = capture_session_id.clone();
        return match state
            .store
            .wal_authoritative_read(&user.0, move |conn| {
                load_capture_session_status(conn, &status_session_id, None)
            })
            .await
        {
            Ok(Some(status)) => {
                super::summarizer::kick_session_settled(&user.0);
                Json(status).into_response()
            }
            Ok(None) => StatusCode::NO_CONTENT.into_response(),
            Err(error) => error.into_response(),
        };
    }
    match state
        .store
        .with_user(&user.0, |conn| {
            let updated = conn.execute(
                "UPDATE capture_sessions SET ended_at=COALESCE(ended_at, \
                 strftime('%Y-%m-%dT%H:%M:%fZ','now')) WHERE id=?1",
                [&capture_session_id],
            )?;
            if updated == 0 {
                return Ok(None);
            }
            load_capture_session_status(conn, &capture_session_id, None)
        })
        .await
    {
        Ok(Some(status)) => match state.store.save_user(&user.0).await {
            Ok(()) => {
                // ADR-0034: the finished session may already be fully
                // processed — let the summarizer form the memory now instead
                // of waiting for the next 10-minute sweep. Only a hint; the
                // settled gate re-checks before any LLM call.
                super::summarizer::kick_session_settled(&user.0);
                Json(status).into_response()
            }
            Err(error) => error.into_response(),
        },
        // Finishing is idempotent: an unknown session is already in the goal
        // state ("not active"), and clients queue finish markers durably, so a
        // 404 here wedges their outbox forever after server-side session loss.
        Ok(None) => StatusCode::NO_CONTENT.into_response(),
        Err(error) => error.into_response(),
    }
}

fn load_capture_status(conn: &Connection, event_id: &str) -> Result<Option<CaptureStatus>> {
    conn.query_row(
        "SELECT e.event_id,COALESCE(m.processing_state,'ready'),j.error_code,\
                COALESCE(j.attempt_count,0) \
         FROM capture_events e LEFT JOIN media_objects m USING(event_id) \
         LEFT JOIN media_processing_jobs j USING(event_id) WHERE e.event_id=?1",
        [event_id],
        |row| {
            Ok(CaptureStatus {
                event_id: row.get(0)?,
                processing_state: row.get(1)?,
                error_code: row.get(2)?,
                attempt_count: row.get(3)?,
            })
        },
    )
    .optional()
    .map_err(Into::into)
}

fn load_capture_session_status(
    conn: &Connection,
    capture_session_id: &str,
    summarized_until_ms: Option<i64>,
) -> Result<Option<CaptureSessionStatus>> {
    let session = conn
        .query_row(
            "SELECT id,device_id,started_at,last_event_at,ended_at FROM capture_sessions WHERE id=?1",
            [capture_session_id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, Option<String>>(4)?,
                ))
            },
        )
        .optional()?;
    let Some((capture_session_id, device_id, started_at, last_event_at, ended_at)) = session else {
        return Ok(None);
    };

    let (event_count, queued, processing, retry_wait, ready, failed) = conn.query_row(
        "SELECT COUNT(*), \
          SUM(CASE WHEN COALESCE(m.processing_state,'ready')='queued' THEN 1 ELSE 0 END), \
          SUM(CASE WHEN COALESCE(m.processing_state,'ready')='processing' THEN 1 ELSE 0 END), \
          SUM(CASE WHEN COALESCE(m.processing_state,'ready')='retry_wait' THEN 1 ELSE 0 END), \
          SUM(CASE WHEN COALESCE(m.processing_state,'ready') IN ('ready','pruned') THEN 1 ELSE 0 END), \
          SUM(CASE WHEN COALESCE(m.processing_state,'ready')='failed' THEN 1 ELSE 0 END) \
         FROM capture_events e LEFT JOIN media_objects m USING(event_id) \
         WHERE e.capture_session_id=?1",
        [&capture_session_id],
        |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, Option<i64>>(1)?.unwrap_or(0),
                row.get::<_, Option<i64>>(2)?.unwrap_or(0),
                row.get::<_, Option<i64>>(3)?.unwrap_or(0),
                row.get::<_, Option<i64>>(4)?.unwrap_or(0),
                row.get::<_, Option<i64>>(5)?.unwrap_or(0),
            ))
        },
    )?;

    // substance='none' episodes are excluded: the finalizer never finalizes
    // them (they are hidden from browse/search under ADR-0009), so surfacing
    // one here would wedge the stage at preparing_recap forever. A recording
    // whose only product is a substance-none episode resolves to no_memory —
    // the honest outcome (ADR-0034).
    let mut statement = conn.prepare(
        "SELECT DISTINCT e.id,e.title,e.started_at,e.ended_at,e.finalization_status,e.finalized_at \
         FROM episodes e JOIN episode_members m ON m.episode_id=e.id \
         LEFT JOIN utterances u ON m.record_type='utterance' AND m.record_id=u.id \
         LEFT JOIN speaker_observations so \
           ON u.source_key=('cloud-v2:'||so.event_id||':'||so.turn_id) \
         LEFT JOIN screenshots s ON m.record_type='screenshot' AND m.record_id=s.id \
         LEFT JOIN capture_events ce ON ce.capture_session_id=?1 AND ( \
           ce.event_id=so.event_id OR s.source_key=('cloud-v2:'||ce.event_id)) \
         WHERE ce.event_id IS NOT NULL AND e.substance!='none' \
         ORDER BY e.started_at DESC,e.id DESC",
    )?;
    let memories = statement
        .query_map([&capture_session_id], |row| {
            Ok(CaptureSessionMemory {
                id: row.get(0)?,
                title: row.get(1)?,
                started_at: row.get(2)?,
                ended_at: row.get(3)?,
                finalization_status: row.get(4)?,
                finalized_at: row.get(5)?,
            })
        })?
        .collect::<std::result::Result<Vec<_>, _>>()?;

    // Evidence echo (ADR-0034): mechanical aggregates over accepted evidence.
    // Mic and system audio cover the same wall-clock span, so take the
    // largest single-kind sum rather than double-counting overlapped tracks.
    let audio_minutes: Option<i64> = conn.query_row(
        "SELECT CAST(MAX(kind_seconds)/60.0 + 0.5 AS INTEGER) FROM ( \
           SELECT SUM((julianday(ended_at)-julianday(started_at))*86400.0) AS kind_seconds \
           FROM capture_events WHERE capture_session_id=?1 \
           AND stream_kind IN ('mic','system_audio','ios_mic') GROUP BY stream_kind)",
        [&capture_session_id],
        |row| row.get(0),
    )?;
    let voice_count: i64 = conn.query_row(
        "SELECT COUNT(DISTINCT u.speaker_label) FROM capture_events ce \
         JOIN speaker_observations so ON so.event_id=ce.event_id \
         JOIN utterances u ON u.source_key=('cloud-v2:'||so.event_id||':'||so.turn_id) \
         WHERE ce.capture_session_id=?1 AND u.speaker_label!=''",
        [&capture_session_id],
        |row| row.get(0),
    )?;
    // Application names only — never window-title text (ADR-0034 §8).
    let mut contexts_statement = conn.prepare(
        "SELECT s.active_app FROM capture_events ce \
         JOIN screenshots s ON s.source_key=('cloud-v2:'||ce.event_id) \
         WHERE ce.capture_session_id=?1 AND s.active_app IS NOT NULL AND s.active_app!='' \
         GROUP BY s.active_app ORDER BY COUNT(*) DESC, s.active_app LIMIT 3",
    )?;
    let top_contexts = contexts_statement
        .query_map([&capture_session_id], |row| row.get::<_, String>(0))?
        .collect::<std::result::Result<Vec<_>, _>>()?;

    let has_ready_memory = memories
        .iter()
        .any(|memory| memory.finalization_status == "complete" && memory.finalized_at.is_some());
    // no_memory is declared only from facts: the session is over, every
    // accepted media item reached a terminal success state, and the
    // summarizer's cursor moved past the session's end without linking a
    // memory. A held cursor (ratchet) keeps the stage at organizing — unknown
    // stays visibly unknown rather than becoming a premature zero result.
    let summarized_past_end = match (&ended_at, summarized_until_ms) {
        (Some(ended), Some(cursor)) => {
            super::isotime::parse_epoch_millis(ended).is_some_and(|end_ms| cursor > end_ms)
        }
        _ => false,
    };
    // In-flight work outranks residual failures (a resurrected failed job is
    // retry_wait again), and a formed memory outranks both: one
    // unprocessable item — or its background retry — must not mask or demote
    // a recap the user can already read. needs_attention is reserved for
    // sessions where failures remain AND no memory materialized — the only
    // case the label can honestly claim the outcome still hinges on the
    // failed work.
    let stage = if queued + processing > 0 {
        CaptureSessionStage::Processing
    } else if has_ready_memory {
        CaptureSessionStage::Ready
    } else if retry_wait > 0 {
        CaptureSessionStage::Processing
    } else if !memories.is_empty() {
        CaptureSessionStage::PreparingRecap
    } else if failed > 0 {
        CaptureSessionStage::NeedsAttention
    } else if ended_at.is_some() {
        if summarized_past_end {
            CaptureSessionStage::NoMemory
        } else {
            CaptureSessionStage::Organizing
        }
    } else {
        CaptureSessionStage::Received
    };

    Ok(Some(CaptureSessionStatus {
        capture_session_id,
        device_id,
        started_at,
        last_event_at,
        ended_at,
        event_count,
        stage,
        processing: CaptureSessionProcessing {
            queued,
            processing,
            retry_wait,
            ready,
            failed,
        },
        evidence: CaptureSessionEvidence {
            audio_minutes,
            voice_count: (voice_count > 0).then_some(voice_count),
            top_contexts,
        },
        memories,
    }))
}

async fn list_people(
    State(state): State<Arc<CpState>>,
    Extension(user): Extension<AuthUser>,
    Query(query): Query<PeopleListQuery>,
) -> Response {
    // ADR-0022 D4, the ANSWERABILITY RULE in `error::wal_domain`. FIRST
    // statement in the handler: a refusal spends nothing, not even the
    // `to_lowercase` allocation below.
    //
    // The other collection endpoint, and the same hazard. `people` and
    // `person_facts` rows come only from `media_worker::create_person` /
    // `persist_person_fact`, reached only from the audio and screen RESULT
    // lanes — and although those lanes are migrated, their sealed families
    // commit NO identity by construction, so for a selected user
    // `process_work_unit` returns early and the two legacy persisters that
    // write these tables are unreachable. A routed read can therefore only
    // answer `200 {"people": []}` — an authoritative-looking "you know
    // nobody". It lifts when a sealed family actually commits these rows, NOT
    // when the voice lanes migrate; see `wal_domain::MEDIA_PEOPLE`.
    if let Some(error) = state.wal_domain_refusal(&user.0, wal_domain::MEDIA_PEOPLE) {
        return error.into_response();
    }
    let after_id = query.after_id.unwrap_or(0).max(0);
    let limit = query.limit.unwrap_or(50).clamp(1, 100);
    let search = query
        .q
        .as_deref()
        .map(str::trim)
        .filter(|query| !query.is_empty())
        .map(|query| format!("%{}%", query.to_lowercase()));
    // Per-domain routing, live for every unselected user today; the gate above
    // is the one line that lifts when the people writers migrate.
    match state
        .store
        .wal_authoritative_read(&user.0, move |conn| {
            let mut statement = conn.prepare(
                "SELECT p.id,p.display_name,COUNT(DISTINCT v.id),COUNT(DISTINCT f.id),p.updated_at \
                 FROM people p LEFT JOIN voice_profiles v ON v.person_id=p.id \
                   AND NOT EXISTS (SELECT 1 FROM voice_profile_revisions r \
                     WHERE r.profile_id=v.id AND r.active=1 \
                       AND r.status IN ('quarantined','superseded','split')) \
                 LEFT JOIN person_facts f ON f.person_id=p.id AND f.status='active' \
                 WHERE p.status='identified' AND p.display_name IS NOT NULL AND p.id>?1 \
                 AND (?2 IS NULL OR lower(p.display_name) LIKE ?2 OR EXISTS (\
                   SELECT 1 FROM person_name_claims n WHERE n.person_id=p.id \
                   AND n.status IN ('accepted','probationary') AND lower(n.name) LIKE ?2)) \
                 GROUP BY p.id ORDER BY p.id LIMIT ?3",
            )?;
            let mut people = statement
                .query_map(params![after_id, search, limit as i64 + 1], |row| {
                    Ok(PersonSummary {
                        id: row.get(0)?,
                        display_name: row.get(1)?,
                        voice_profile_count: row.get(2)?,
                        fact_count: row.get(3)?,
                        updated_at: row.get(4)?,
                    })
                })?
                .collect::<std::result::Result<Vec<_>, _>>()?;
            let next_cursor = (people.len() > limit).then(|| people[limit - 1].id);
            people.truncate(limit);
            Ok((people, next_cursor))
        })
        .await
    {
        Ok((people, next_cursor)) => {
            Json(json!({"people": people, "next_cursor": next_cursor})).into_response()
        }
        Err(error) => error.into_response(),
    }
}

async fn person_profile(
    State(state): State<Arc<CpState>>,
    Extension(user): Extension<AuthUser>,
    Path(person_id): Path<i64>,
) -> Response {
    if person_id <= 0 {
        return bad_request("person_id must be positive");
    }
    // ADR-0022 D4, the ANSWERABILITY RULE in `error::wal_domain`; see
    // `list_people` for the writer chain. Nothing is spent above.
    if let Some(error) = state.wal_domain_refusal(&user.0, wal_domain::MEDIA_PEOPLE) {
        return error.into_response();
    }
    match state
        .store
        .wal_authoritative_read(&user.0, move |conn| load_person_profile(conn, person_id))
        .await
    {
        Ok(profile) => Json(profile).into_response(),
        Err(error) => error.into_response(),
    }
}

async fn person_evidence(
    State(state): State<Arc<CpState>>,
    Extension(user): Extension<AuthUser>,
    Path(person_id): Path<i64>,
    Query(query): Query<DescendingPageQuery>,
) -> Response {
    if person_id <= 0 || query.before_id.is_some_and(|cursor| cursor <= 0) {
        return bad_request("person_id and before_id must be positive");
    }
    // ADR-0022 D4, the ANSWERABILITY RULE in `error::wal_domain`; see
    // `list_people` for the writer chain. Nothing is spent above.
    if let Some(error) = state.wal_domain_refusal(&user.0, wal_domain::MEDIA_PEOPLE) {
        return error.into_response();
    }
    let limit = query.limit.unwrap_or(50).clamp(1, 100);
    let before_id = query.before_id;
    match state
        .store
        .wal_authoritative_read(&user.0, move |conn| {
            ensure_identified_person(conn, person_id)?;
            let (evidence, next_cursor) = load_person_evidence(conn, person_id, before_id, limit)?;
            Ok(PersonEvidencePage {
                evidence,
                next_cursor,
            })
        })
        .await
    {
        Ok(page) => Json(page).into_response(),
        Err(error) => error.into_response(),
    }
}

async fn person_statements(
    State(state): State<Arc<CpState>>,
    Extension(user): Extension<AuthUser>,
    Path(person_id): Path<i64>,
    Query(query): Query<DescendingPageQuery>,
) -> Response {
    if person_id <= 0 || query.before_id.is_some_and(|cursor| cursor <= 0) {
        return bad_request("person_id and before_id must be positive");
    }
    // ADR-0022 D4, the ANSWERABILITY RULE in `error::wal_domain`; see
    // `list_people` for the writer chain. Nothing is spent above.
    if let Some(error) = state.wal_domain_refusal(&user.0, wal_domain::MEDIA_PEOPLE) {
        return error.into_response();
    }
    let limit = query.limit.unwrap_or(50).clamp(1, 100);
    let before_id = query.before_id;
    match state
        .store
        .wal_authoritative_read(&user.0, move |conn| {
            ensure_identified_person(conn, person_id)?;
            let (statements, next_cursor) =
                load_person_statements(conn, person_id, before_id, limit)?;
            Ok(PersonStatementPage {
                statements,
                next_cursor,
            })
        })
        .await
    {
        Ok(page) => Json(page).into_response(),
        Err(error) => error.into_response(),
    }
}

fn ensure_identified_person(conn: &Connection, person_id: i64) -> Result<()> {
    let exists: bool = conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM people WHERE id=?1 AND status='identified')",
        [person_id],
        |row| row.get(0),
    )?;
    if exists {
        Ok(())
    } else {
        Err(EnclaveError::NotFound)
    }
}

fn load_person_profile(conn: &Connection, person_id: i64) -> Result<PersonProfile> {
    let person = conn
        .query_row(
            "SELECT p.id,p.display_name,COUNT(DISTINCT v.id),COUNT(DISTINCT f.id),p.updated_at \
             FROM people p LEFT JOIN voice_profiles v ON v.person_id=p.id \
               AND NOT EXISTS (SELECT 1 FROM voice_profile_revisions r \
                 WHERE r.profile_id=v.id AND r.active=1 \
                   AND r.status IN ('quarantined','superseded','split')) \
             LEFT JOIN person_facts f ON f.person_id=p.id AND f.status='active' \
             WHERE p.id=?1 AND p.status='identified' GROUP BY p.id",
            [person_id],
            |row| {
                Ok(PersonSummary {
                    id: row.get(0)?,
                    display_name: row.get(1)?,
                    voice_profile_count: row.get(2)?,
                    fact_count: row.get(3)?,
                    updated_at: row.get(4)?,
                })
            },
        )
        .optional()?
        .ok_or(EnclaveError::NotFound)?;
    let mut voice_statement = conn.prepare(
        "SELECT label FROM voice_profiles v WHERE person_id=?1 AND status<>'quarantined' \
         AND NOT EXISTS (SELECT 1 FROM voice_profile_revisions r \
           WHERE r.profile_id=v.id AND r.active=1 \
             AND r.status IN ('quarantined','superseded','split')) ORDER BY id",
    )?;
    let voice_labels = voice_statement
        .query_map([person_id], |row| row.get(0))?
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let (stable_profiles, accepted_samples): (i64, i64) = conn.query_row(
        "SELECT \
           (SELECT COUNT(*) FROM voice_profiles v WHERE person_id=?1 AND status='stable' \
             AND NOT EXISTS (SELECT 1 FROM voice_profile_revisions r \
               WHERE r.profile_id=v.id AND r.active=1 \
                 AND r.status IN ('quarantined','superseded','split'))),\
           (SELECT COUNT(*) FROM voice_samples s \
            JOIN voice_sample_profile_assignments a ON a.sample_id=s.id AND a.active=1 \
            JOIN voice_profiles v ON v.id=a.profile_id \
            WHERE v.person_id=?1 AND s.accepted=1 AND s.eligibility='enroll' AND s.outlier=0 \
              AND NOT EXISTS (SELECT 1 FROM voice_profile_revisions r \
                WHERE r.profile_id=v.id AND r.active=1 \
                  AND r.status IN ('quarantined','superseded','split')))",
        [person_id],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    let voice_coverage = if stable_profiles > 0 {
        format!(
            "Recognized from {accepted_samples} high-quality samples across {stable_profiles} stable acoustic profiles"
        )
    } else if accepted_samples > 0 {
        format!("Learning from {accepted_samples} high-quality voice samples")
    } else {
        "No stable voice recognition profile yet".into()
    };
    let mut aliases_statement = conn.prepare(
        "SELECT id,name,status,evidence_kind,confidence,observed_at,source_event_id \
         FROM person_name_claims WHERE person_id=?1 AND status<>'rejected' \
         ORDER BY observed_at DESC,id DESC LIMIT 100",
    )?;
    let aliases = aliases_statement
        .query_map([person_id], |row| {
            Ok(PersonNameView {
                id: row.get(0)?,
                name: row.get(1)?,
                status: row.get(2)?,
                evidence_kind: row.get(3)?,
                confidence: row.get(4)?,
                observed_at: row.get(5)?,
                source_event_id: row.get(6)?,
            })
        })?
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let mut facts_statement = conn.prepare(
        "SELECT id,predicate,value,status,evidence_json,source_event_id,speaker_observation_id,\
                observed_at,literal_evidence,confidence,supersedes_id,created_at \
         FROM person_facts WHERE person_id=?1 \
         ORDER BY COALESCE(observed_at,created_at) DESC,id DESC LIMIT 200",
    )?;
    let facts = facts_statement
        .query_map([person_id], |row| {
            let evidence_json: String = row.get(4)?;
            Ok(PersonFactView {
                id: row.get(0)?,
                predicate: row.get(1)?,
                value: row.get(2)?,
                status: row.get(3)?,
                evidence: serde_json::from_str(&evidence_json).unwrap_or(Value::Null),
                source_event_id: row.get(5)?,
                speaker_observation_id: row.get(6)?,
                observed_at: row.get(7)?,
                literal_evidence: row.get(8)?,
                confidence: row.get(9)?,
                supersedes_id: row.get(10)?,
                created_at: row.get(11)?,
            })
        })?
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let (evidence, _) = load_person_evidence(conn, person_id, None, 100)?;
    let (recent_statements, _) = load_person_statements(conn, person_id, None, 100)?;
    Ok(PersonProfile {
        person,
        voice_labels,
        voice_coverage,
        aliases,
        facts,
        evidence,
        recent_statements,
    })
}

fn load_person_evidence(
    conn: &Connection,
    person_id: i64,
    before_id: Option<i64>,
    limit: usize,
) -> Result<(Vec<PersonEvidenceView>, Option<i64>)> {
    let mut statement = conn.prepare(
        "SELECT id,kind,claimed_name,score,status,observed_at,source_event_id,\
                speaker_observation_id,evidence_json FROM identity_evidence \
         WHERE person_id=?1 AND (?2 IS NULL OR id<?2) ORDER BY id DESC LIMIT ?3",
    )?;
    let mut evidence = statement
        .query_map(params![person_id, before_id, limit as i64 + 1], |row| {
            let raw: String = row.get(8)?;
            Ok(PersonEvidenceView {
                id: row.get(0)?,
                kind: row.get(1)?,
                claimed_name: row.get(2)?,
                score: row.get(3)?,
                status: row.get(4)?,
                observed_at: row.get(5)?,
                source_event_id: row.get(6)?,
                speaker_observation_id: row.get(7)?,
                evidence: serde_json::from_str(&raw).unwrap_or(Value::Null),
            })
        })?
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let next_cursor = (evidence.len() > limit).then(|| evidence[limit - 1].id);
    evidence.truncate(limit);
    Ok((evidence, next_cursor))
}

fn load_person_statements(
    conn: &Connection,
    person_id: i64,
    before_id: Option<i64>,
    limit: usize,
) -> Result<(Vec<PersonStatementView>, Option<i64>)> {
    let mut statement = conn.prepare(
        "SELECT s.id,s.started_at,s.ended_at,s.transcript_text,s.event_id,e.id,e.title \
         FROM speaker_observations s \
         LEFT JOIN utterances u ON u.source_key=('cloud-v2:'||s.event_id||':'||s.turn_id) \
         LEFT JOIN episode_members m ON m.record_type='utterance' AND m.record_id=u.id \
         LEFT JOIN episodes e ON e.id=m.episode_id \
         WHERE s.person_id=?1 AND (?2 IS NULL OR s.id<?2) \
         GROUP BY s.id ORDER BY s.id DESC LIMIT ?3",
    )?;
    let mut statements = statement
        .query_map(params![person_id, before_id, limit as i64 + 1], |row| {
            Ok(PersonStatementView {
                speaker_observation_id: row.get(0)?,
                started_at: row.get(1)?,
                ended_at: row.get(2)?,
                text: row.get(3)?,
                source_event_id: row.get(4)?,
                episode_id: row.get(5)?,
                episode_title: row.get(6)?,
            })
        })?
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let next_cursor =
        (statements.len() > limit).then(|| statements[limit - 1].speaker_observation_id);
    statements.truncate(limit);
    Ok((statements, next_cursor))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CaptureIngestFailureReason {
    AccountSuspended,
    AccountStatusUnavailable,
    RateLimited,
    MultipartInvalid,
    ManifestMissing,
    ManifestTooLarge,
    ManifestInvalid,
    MediaMissing,
    MediaTooLarge,
    MediaInvalid,
    RequestInvalid,
    IdempotencyConflict,
    LifecycleUnavailable,
    RecordingLeaseInactive,
    RecordingLeaseConflict,
    RecordingLeaseUnavailable,
    MediaStorageUnavailable,
    PersistenceUnavailable,
    CanonicalUnavailable,
    ContextFingerprintMismatch,
    ReferenceTargetMismatch,
    CanonicalContextUnavailable,
    ReferenceContextTransition,
    /// ADR-0022 D4: this route's domain has not migrated to the WAL lane and
    /// the account's archive is WAL-authoritative. A deferral, not a fault.
    WalDomainUnmigrated,
    Internal,
}

impl CaptureIngestFailureReason {
    const fn as_str(self) -> &'static str {
        match self {
            Self::AccountSuspended => "account_suspended",
            Self::AccountStatusUnavailable => "account_status_unavailable",
            Self::RateLimited => "rate_limited",
            Self::MultipartInvalid => "multipart_invalid",
            Self::ManifestMissing => "manifest_missing",
            Self::ManifestTooLarge => "manifest_too_large",
            Self::ManifestInvalid => "manifest_invalid",
            Self::MediaMissing => "media_missing",
            Self::MediaTooLarge => "media_too_large",
            Self::MediaInvalid => "media_invalid",
            Self::RequestInvalid => "request_invalid",
            Self::WalDomainUnmigrated => crate::error::WAL_DOMAIN_UNMIGRATED_REASON,
            Self::IdempotencyConflict => "idempotency_conflict",
            Self::LifecycleUnavailable => "lifecycle_unavailable",
            Self::RecordingLeaseInactive => "recording_lease_inactive",
            Self::RecordingLeaseConflict => "recording_lease_conflict",
            Self::RecordingLeaseUnavailable => "recording_lease_unavailable",
            Self::MediaStorageUnavailable => "media_storage_unavailable",
            Self::PersistenceUnavailable => "persistence_unavailable",
            Self::CanonicalUnavailable => "canonical_unavailable",
            Self::ContextFingerprintMismatch => "context_fingerprint_mismatch",
            Self::ReferenceTargetMismatch => "target_mismatch",
            Self::CanonicalContextUnavailable => "canonical_context_unavailable",
            Self::ReferenceContextTransition => "context_transition",
            Self::Internal => "internal",
        }
    }
}

fn capture_failure_response(
    started_at: Instant,
    manifest: Option<&CaptureEventManifest>,
    reason: CaptureIngestFailureReason,
    response: Response,
) -> Response {
    capture_failure_response_for_route("capture_event", started_at, manifest, reason, response)
}

fn capture_failure_response_for_route(
    route: &'static str,
    started_at: Instant,
    manifest: Option<&CaptureEventManifest>,
    reason: CaptureIngestFailureReason,
    response: Response,
) -> Response {
    let status = response.status().as_u16();
    let status_class = match status {
        400..=499 => "4xx",
        500..=599 => "5xx",
        _ => "other",
    };
    let stream_kind = manifest
        .map(|value| value.stream_kind.as_str())
        .unwrap_or("unknown");
    let media_disposition = manifest
        .map(|value| value.media_disposition.as_str())
        .unwrap_or("unknown");
    let reason = reason.as_str();
    let duration_ms = started_at.elapsed().as_millis().min(u64::MAX as u128) as u64;
    if status_class == "5xx" {
        tracing::error!(
            target: "kioku::capture_ingest",
            metric_schema = "capture_ingest_failure_v1",
            route,
            status,
            status_class,
            stream_kind,
            media_disposition,
            reason,
            duration_ms,
            "capture ingest failed"
        );
    } else {
        tracing::warn!(
            target: "kioku::capture_ingest",
            metric_schema = "capture_ingest_failure_v1",
            route,
            status,
            status_class,
            stream_kind,
            media_disposition,
            reason,
            duration_ms,
            "capture ingest failed"
        );
    }
    response
}

fn capture_error_response(
    started_at: Instant,
    manifest: Option<&CaptureEventManifest>,
    error: EnclaveError,
) -> Response {
    capture_error_response_for_route("capture_event", started_at, manifest, error)
}

fn capture_error_response_for_route(
    route: &'static str,
    started_at: Instant,
    manifest: Option<&CaptureEventManifest>,
    error: EnclaveError,
) -> Response {
    let reason = match &error {
        EnclaveError::CaptureReference(reason)
        | EnclaveError::CaptureReferenceBatch { reason, .. } => match reason {
            CaptureReferenceFailureReason::CanonicalUnavailable => {
                CaptureIngestFailureReason::CanonicalUnavailable
            }
            CaptureReferenceFailureReason::ContextFingerprintMismatch => {
                CaptureIngestFailureReason::ContextFingerprintMismatch
            }
            CaptureReferenceFailureReason::TargetMismatch => {
                CaptureIngestFailureReason::ReferenceTargetMismatch
            }
            CaptureReferenceFailureReason::CanonicalContextUnavailable => {
                CaptureIngestFailureReason::CanonicalContextUnavailable
            }
            CaptureReferenceFailureReason::ContextTransition => {
                CaptureIngestFailureReason::ReferenceContextTransition
            }
        },
        EnclaveError::InvalidRequest(_) => CaptureIngestFailureReason::RequestInvalid,
        EnclaveError::Conflict(_) => CaptureIngestFailureReason::IdempotencyConflict,
        EnclaveError::WalDomainUnmigrated(_) => CaptureIngestFailureReason::WalDomainUnmigrated,
        _ => CaptureIngestFailureReason::Internal,
    };
    let response = error.into_response();
    capture_failure_response_for_route(route, started_at, manifest, reason, response)
}

fn recording_entitlement_failure_reason(status: StatusCode) -> CaptureIngestFailureReason {
    match status {
        StatusCode::PAYMENT_REQUIRED => CaptureIngestFailureReason::RecordingLeaseInactive,
        StatusCode::CONFLICT => CaptureIngestFailureReason::RecordingLeaseConflict,
        _ => CaptureIngestFailureReason::RecordingLeaseUnavailable,
    }
}

fn bad_request(message: &'static str) -> Response {
    (StatusCode::BAD_REQUEST, message).into_response()
}

fn rate_limited_response() -> Response {
    let mut response = (
        StatusCode::TOO_MANY_REQUESTS,
        Json(json!({"error": "rate_limited", "retry_after": 5})),
    )
        .into_response();
    response
        .headers_mut()
        .insert(RETRY_AFTER, HeaderValue::from_static("5"));
    response
}

fn preflight_source_event(
    conn: &Connection,
    manifest: &CaptureEventManifest,
    manifest_digest: &str,
    object_key: Option<&str>,
) -> Result<PreflightOutcome> {
    let existing: Option<(String, Option<String>, String, String)> = conn
        .query_row(
            "SELECT e.manifest_digest,m.object_key,e.stream_id,e.media_disposition \
             FROM capture_events e LEFT JOIN media_objects m ON m.event_id=e.event_id \
             WHERE e.event_id=?1",
            [&manifest.event_id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .optional()?;
    let Some((existing_digest, existing_object, existing_stream, existing_disposition)) = existing
    else {
        return Ok(PreflightOutcome::New);
    };
    let disposition = match manifest.media_disposition {
        MediaDisposition::Canonical => "canonical",
        MediaDisposition::Reference => "reference",
    };
    if existing_digest != manifest_digest
        || existing_object.as_deref() != object_key
        || existing_disposition != disposition
    {
        return Err(EnclaveError::Conflict(
            "idempotency conflict for event_id".into(),
        ));
    }
    Ok(PreflightOutcome::Duplicate {
        committed_through_sequence: committed_through_sequence(conn, &existing_stream)?,
    })
}

fn committed_through_sequence(conn: &Connection, stream_id: &str) -> Result<i64> {
    conn.query_row(
        "SELECT committed_through_sequence FROM capture_streams WHERE id=?1",
        [stream_id],
        |row| row.get(0),
    )
    .optional()?
    .ok_or(EnclaveError::NotFound)
}

fn install_media_dek_candidate(conn: &Connection, candidate: &str) -> Result<String> {
    conn.execute(
        "INSERT INTO app_metadata (key,value) VALUES (?1,?2) ON CONFLICT(key) DO NOTHING",
        params![MEDIA_DEK_METADATA_KEY, candidate],
    )?;
    Ok(conn.query_row(
        "SELECT value FROM app_metadata WHERE key=?1",
        [MEDIA_DEK_METADATA_KEY],
        |row| row.get(0),
    )?)
}

pub(in crate::cp) async fn load_or_create_media_dek(
    state: &CpState,
    user_id: &str,
) -> Result<(crate::crypto::Dek, String)> {
    // Routed unconditionally: an unselected user falls through to the legacy
    // read path, a selected user reads the settled lane.
    let existing = read_media_dek_wrapped(state, user_id).await?;
    if let Some(wrapped) = existing {
        let dek = crate::crypto::load_dek(state.store.kms.as_ref(), &wrapped).await?;
        return Ok((dek, wrapped));
    }
    let (candidate_dek, candidate_wrapped) =
        crate::crypto::generate_and_wrap_dek(state.store.kms.as_ref()).await?;
    if state.store.is_wal_authoritative(user_id) {
        let plan = wal::MediaDekInstallPlan::new(
            user_id.to_owned(),
            candidate_wrapped.clone(),
            &candidate_dek,
        )
        .map_err(|_| EnclaveError::Store("media DEK install plan construction failed".into()))?;
        let prepared = crate::archive_v3_wal_idempotency::PreparedLogicalMutation::prepare(plan)
            .map_err(|_| {
                EnclaveError::Store("media DEK install plan construction failed".into())
            })?;
        return match state
            .store
            .wal_authoritative_submit(user_id, prepared)
            .await
        {
            // Settled: our candidate is durably the account DEK (an exact
            // replay of a lost ack lands here too, with identical bytes).
            Ok(_receipt) => Ok((candidate_dek, candidate_wrapped)),
            // A different DEK won between our read and our submit. The plan
            // fails closed on the mismatch; converge by loading the winner
            // exactly as the legacy loser branch does.
            Err(EnclaveError::Conflict(_)) => {
                let winner = read_media_dek_wrapped(state, user_id)
                    .await?
                    .ok_or_else(|| {
                        EnclaveError::Store("media DEK install lost a race to no winner".into())
                    })?;
                let dek = crate::crypto::load_dek(state.store.kms.as_ref(), &winner).await?;
                Ok((dek, winner))
            }
            Err(error) => Err(error),
        };
    }
    let winner = state
        .store
        .with_user(user_id, |conn| {
            install_media_dek_candidate(conn, &candidate_wrapped)
        })
        .await?;
    if winner == candidate_wrapped {
        Ok((candidate_dek, winner))
    } else {
        let dek = crate::crypto::load_dek(state.store.kms.as_ref(), &winner).await?;
        Ok((dek, winner))
    }
}

/// The one production read of the account media-DEK row, routed through the
/// dual-path read so both populations resolve it the same way.
async fn read_media_dek_wrapped(state: &CpState, user_id: &str) -> Result<Option<String>> {
    state
        .store
        .wal_authoritative_read(user_id, |conn| {
            Ok(conn
                .query_row(
                    "SELECT value FROM app_metadata WHERE key=?1",
                    [MEDIA_DEK_METADATA_KEY],
                    |row| row.get(0),
                )
                .optional()?)
        })
        .await
}

async fn verify_existing_media(
    state: &CpState,
    _user_id: &str,
    object_key: &str,
    context: &[u8],
    expected: &[u8],
) -> Result<()> {
    let existing = state.store.get_media(object_key).await?;
    let dek = crate::crypto::load_dek(state.store.kms.as_ref(), &existing.wrapped_dek_b64).await?;
    let plaintext =
        crate::crypto::decrypt_bound_blob(&dek, &existing.ciphertext, context)?.plaintext;
    if plaintext != expected {
        return Err(EnclaveError::Conflict(
            "asset_id was already used for different media".into(),
        ));
    }
    Ok(())
}

pub fn init_schema(conn: &Connection) -> Result<()> {
    conn.execute_batch(
        r#"
        PRAGMA foreign_keys = ON;
        CREATE TABLE IF NOT EXISTS capture_sessions (
            id TEXT PRIMARY KEY,
            device_id TEXT NOT NULL,
            install_id TEXT NOT NULL,
            started_at TEXT NOT NULL,
            last_event_at TEXT NOT NULL,
            ended_at TEXT,
            schema_version INTEGER NOT NULL,
            created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
        );
        CREATE TABLE IF NOT EXISTS capture_streams (
            id TEXT PRIMARY KEY,
            capture_session_id TEXT NOT NULL REFERENCES capture_sessions(id) ON DELETE CASCADE,
            device_id TEXT NOT NULL,
            stream_kind TEXT NOT NULL,
            committed_through_sequence INTEGER NOT NULL DEFAULT -1,
            sealed_sequence INTEGER,
            created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
        );
        CREATE TABLE IF NOT EXISTS capture_events (
            event_id TEXT PRIMARY KEY,
            device_id TEXT NOT NULL,
            install_id TEXT NOT NULL,
            capture_session_id TEXT NOT NULL REFERENCES capture_sessions(id) ON DELETE CASCADE,
            stream_id TEXT NOT NULL REFERENCES capture_streams(id) ON DELETE CASCADE,
            stream_kind TEXT NOT NULL,
            sequence INTEGER NOT NULL,
            source_wall_at TEXT NOT NULL,
            source_monotonic_ns TEXT NOT NULL,
            started_at TEXT NOT NULL,
            ended_at TEXT NOT NULL,
            timezone_id TEXT NOT NULL,
            utc_offset_minutes INTEGER NOT NULL,
            clock_uncertainty_ms INTEGER NOT NULL,
            asset_id TEXT NOT NULL UNIQUE,
            manifest_digest TEXT NOT NULL,
            context_json TEXT,
            media_disposition TEXT NOT NULL DEFAULT 'canonical'
                CHECK (media_disposition IN ('canonical','reference')),
            canonical_event_id TEXT REFERENCES capture_events(event_id) ON DELETE CASCADE,
            canonical_asset_id TEXT,
            canonical_media_sha256 TEXT,
            perceptual_hash TEXT,
            hamming_distance INTEGER,
            pixel_change_ratio REAL,
            context_fingerprint TEXT,
            dedupe_version INTEGER,
            audio_role TEXT,
            audio_route TEXT,
            route_epoch INTEGER,
            received_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
            UNIQUE(device_id, stream_id, sequence)
        );
        CREATE INDEX IF NOT EXISTS idx_capture_events_time
            ON capture_events(started_at, event_id);
        CREATE INDEX IF NOT EXISTS idx_capture_events_session
            ON capture_events(capture_session_id);
        CREATE TABLE IF NOT EXISTS media_objects (
            asset_id TEXT PRIMARY KEY,
            event_id TEXT NOT NULL UNIQUE REFERENCES capture_events(event_id) ON DELETE CASCADE,
            object_key TEXT NOT NULL UNIQUE,
            object_generation INTEGER,
            object_backend TEXT CHECK (object_backend IN ('current')),
            mime_type TEXT NOT NULL,
            codec TEXT NOT NULL,
            byte_length INTEGER NOT NULL,
            sha256 TEXT NOT NULL,
            sample_rate INTEGER,
            channels INTEGER,
            frame_count INTEGER,
            width INTEGER,
            height INTEGER,
            scale REAL,
            orientation TEXT,
            processing_state TEXT NOT NULL DEFAULT 'queued'
                CHECK (processing_state IN ('queued','processing','ready','retry_wait','failed','pruned')),
            retain_until TEXT,
            deleted_at TEXT,
            created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
        );
        CREATE TABLE IF NOT EXISTS browser_states_v2 (
            state_key TEXT PRIMARY KEY,
            browser_bundle_id TEXT NOT NULL,
            browser_name TEXT NOT NULL,
            permission_status TEXT NOT NULL,
            content_hash TEXT NOT NULL,
            tabs_json TEXT NOT NULL DEFAULT '[]',
            created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
        );
        CREATE TABLE IF NOT EXISTS browser_observations_v2 (
            observation_id TEXT PRIMARY KEY,
            event_id TEXT NOT NULL UNIQUE REFERENCES capture_events(event_id) ON DELETE CASCADE,
            observed_at TEXT NOT NULL,
            state_key TEXT REFERENCES browser_states_v2(state_key) ON DELETE SET NULL,
            context_status TEXT NOT NULL,
            active_url TEXT,
            active_title TEXT,
            created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
        );
        CREATE TABLE IF NOT EXISTS media_processing_jobs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_id TEXT NOT NULL REFERENCES capture_events(event_id) ON DELETE CASCADE,
            job_kind TEXT NOT NULL,
            input_revision TEXT NOT NULL,
            processor_version INTEGER NOT NULL,
            state TEXT NOT NULL DEFAULT 'pending'
                CHECK (state IN ('pending','processing','retry_wait','succeeded','failed_terminal','canceled')),
            attempt_count INTEGER NOT NULL DEFAULT 0,
            lease_until TEXT,
            error_code TEXT,
            model_id TEXT,
            prompt_version INTEGER,
            schema_version INTEGER,
            usage_json TEXT,
            updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
            UNIQUE(job_kind, input_revision, processor_version)
        );
        CREATE INDEX IF NOT EXISTS idx_media_jobs_state
            ON media_processing_jobs(state, updated_at, id);
        CREATE TABLE IF NOT EXISTS media_work_units (
            id TEXT PRIMARY KEY,
            work_class TEXT NOT NULL CHECK (work_class IN ('audio','screen')),
            processor_version INTEGER NOT NULL,
            state TEXT NOT NULL CHECK (state IN ('planned','processing','retry_wait','succeeded','failed_terminal')),
            started_at TEXT NOT NULL,
            ended_at TEXT NOT NULL,
            reserved_output_tokens INTEGER NOT NULL,
            reservation_retained INTEGER NOT NULL DEFAULT 0,
            attempt_count INTEGER NOT NULL DEFAULT 0,
            error_code TEXT,
            usage_json TEXT,
            created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
            updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
        );
        CREATE TABLE IF NOT EXISTS media_work_members (
            work_unit_id TEXT NOT NULL REFERENCES media_work_units(id) ON DELETE CASCADE,
            event_id TEXT NOT NULL REFERENCES capture_events(event_id) ON DELETE CASCADE,
            job_id INTEGER NOT NULL REFERENCES media_processing_jobs(id) ON DELETE CASCADE,
            ordinal INTEGER NOT NULL,
            window_start_ms INTEGER NOT NULL,
            window_end_ms INTEGER NOT NULL,
            PRIMARY KEY (work_unit_id,event_id),
            UNIQUE (work_unit_id,ordinal)
        );
        CREATE TABLE IF NOT EXISTS speaker_observations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            person_id INTEGER REFERENCES people(id) ON DELETE SET NULL,
            event_id TEXT NOT NULL REFERENCES capture_events(event_id) ON DELETE CASCADE,
            turn_id TEXT NOT NULL,
            speaker_local_id TEXT NOT NULL,
            started_at TEXT NOT NULL,
            ended_at TEXT NOT NULL,
            transcript_text TEXT NOT NULL,
            language TEXT,
            overlap INTEGER NOT NULL DEFAULT 0,
            voice_eligibility TEXT,
            voice_diagnostics_json TEXT,
            UNIQUE(event_id, turn_id)
        );
        CREATE TABLE IF NOT EXISTS speaker_observation_sources (
            speaker_observation_id INTEGER NOT NULL REFERENCES speaker_observations(id) ON DELETE CASCADE,
            event_id TEXT NOT NULL REFERENCES capture_events(event_id) ON DELETE CASCADE,
            window_start_ms INTEGER NOT NULL,
            window_end_ms INTEGER NOT NULL,
            event_start_ms INTEGER NOT NULL,
            event_end_ms INTEGER NOT NULL,
            PRIMARY KEY (speaker_observation_id,event_id,window_start_ms)
        );
        CREATE TABLE IF NOT EXISTS people (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            display_name TEXT,
            normalized_name TEXT,
            status TEXT NOT NULL DEFAULT 'unknown' CHECK (status IN ('unknown','identified','quarantined')),
            created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
            updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
        );
        CREATE TABLE IF NOT EXISTS person_name_claims (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            person_id INTEGER REFERENCES people(id) ON DELETE CASCADE,
            name TEXT NOT NULL,
            normalized_name TEXT NOT NULL,
            normalized_email TEXT,
            source_event_id TEXT REFERENCES capture_events(event_id) ON DELETE CASCADE,
            speaker_observation_id INTEGER REFERENCES speaker_observations(id) ON DELETE CASCADE,
            observed_at TEXT NOT NULL,
            evidence_kind TEXT NOT NULL,
            evidence_json TEXT NOT NULL,
            confidence REAL NOT NULL,
            status TEXT NOT NULL CHECK (status IN ('proposed','probationary','accepted','conflicted','superseded','rejected')),
            supersedes_id INTEGER REFERENCES person_name_claims(id) ON DELETE SET NULL,
            created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
        );
        CREATE INDEX IF NOT EXISTS idx_person_name_claims_name
            ON person_name_claims(normalized_name, observed_at);
        CREATE INDEX IF NOT EXISTS idx_person_name_claims_person
            ON person_name_claims(person_id, status, observed_at);
        CREATE TABLE IF NOT EXISTS profile_identity_bindings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            voice_profile_id INTEGER NOT NULL REFERENCES voice_profiles(id) ON DELETE CASCADE,
            person_id INTEGER NOT NULL REFERENCES people(id) ON DELETE CASCADE,
            evidence_count INTEGER NOT NULL DEFAULT 1,
            confidence REAL NOT NULL,
            state TEXT NOT NULL CHECK (state IN ('probationary','accepted','conflicted','superseded','rejected')),
            derivation_version INTEGER NOT NULL,
            evidence_json TEXT NOT NULL,
            supersedes_id INTEGER REFERENCES profile_identity_bindings(id) ON DELETE SET NULL,
            created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
            updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
        );
        CREATE TABLE IF NOT EXISTS voice_profiles (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            person_id INTEGER REFERENCES people(id) ON DELETE SET NULL,
            label TEXT NOT NULL UNIQUE,
            embedding_space TEXT NOT NULL,
            channel_domain TEXT NOT NULL,
            centroid BLOB NOT NULL,
            sample_count INTEGER NOT NULL DEFAULT 0,
            scorer_version INTEGER NOT NULL DEFAULT 2,
            representative_kind TEXT NOT NULL DEFAULT 'medoid_trimmed_centroid',
            medoid_sample_id INTEGER,
            status TEXT NOT NULL DEFAULT 'tentative' CHECK (status IN ('tentative','stable','quarantined')),
            created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
            updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
        );
        CREATE TABLE IF NOT EXISTS voice_samples (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            speaker_observation_id INTEGER NOT NULL REFERENCES speaker_observations(id) ON DELETE CASCADE,
            voice_profile_id INTEGER REFERENCES voice_profiles(id) ON DELETE SET NULL,
            embedding_space TEXT NOT NULL,
            channel_domain TEXT NOT NULL,
            embedding BLOB NOT NULL,
            quality_score REAL NOT NULL,
            diagnostics_json TEXT NOT NULL DEFAULT '{}',
            quality_version INTEGER NOT NULL DEFAULT 1,
            scorer_version INTEGER NOT NULL DEFAULT 2,
            eligibility TEXT NOT NULL DEFAULT 'enroll',
            duration_ms INTEGER NOT NULL DEFAULT 0,
            speech_ratio REAL NOT NULL DEFAULT 0,
            snr_proxy_db REAL NOT NULL DEFAULT 0,
            clipping_ratio REAL NOT NULL DEFAULT 0,
            silence_ratio REAL NOT NULL DEFAULT 0,
            embedding_norm REAL NOT NULL DEFAULT 1,
            outlier INTEGER NOT NULL DEFAULT 0,
            similarity REAL,
            decision_margin REAL,
            accepted INTEGER NOT NULL DEFAULT 0,
            embedding_job_id INTEGER REFERENCES voice_embedding_jobs(id) ON DELETE SET NULL,
            created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
        );
        CREATE TABLE IF NOT EXISTS voice_profile_proposals (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            proposal_key TEXT NOT NULL UNIQUE,
            kind TEXT NOT NULL CHECK (kind IN ('merge','split')),
            state TEXT NOT NULL DEFAULT 'proposed' CHECK (state IN ('proposed','approved','applied','revert_requested','rejected','reverted')),
            scorer_version INTEGER NOT NULL,
            derivation_version INTEGER NOT NULL,
            reason_code TEXT NOT NULL,
            created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
            updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
        );
        CREATE TABLE IF NOT EXISTS voice_profile_revisions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            profile_id INTEGER NOT NULL REFERENCES voice_profiles(id) ON DELETE CASCADE,
            status TEXT NOT NULL CHECK (status IN ('tentative','stable','quarantined','superseded','split')),
            derivation_version INTEGER NOT NULL,
            scorer_version INTEGER NOT NULL,
            representative_kind TEXT NOT NULL,
            centroid BLOB NOT NULL,
            sample_count INTEGER NOT NULL,
            medoid_sample_id INTEGER REFERENCES voice_samples(id) ON DELETE SET NULL,
            person_id INTEGER REFERENCES people(id) ON DELETE SET NULL,
            proposal_id INTEGER REFERENCES voice_profile_proposals(id) ON DELETE SET NULL,
            predecessor_revision_id INTEGER REFERENCES voice_profile_revisions(id) ON DELETE SET NULL,
            reason_code TEXT NOT NULL,
            active INTEGER NOT NULL DEFAULT 1 CHECK (active IN (0,1)),
            created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
        );
        CREATE UNIQUE INDEX IF NOT EXISTS idx_voice_profile_revisions_active
            ON voice_profile_revisions(profile_id) WHERE active=1;
        CREATE TABLE IF NOT EXISTS voice_sample_profile_assignments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sample_id INTEGER NOT NULL REFERENCES voice_samples(id) ON DELETE CASCADE,
            profile_id INTEGER NOT NULL REFERENCES voice_profiles(id) ON DELETE CASCADE,
            proposal_id INTEGER REFERENCES voice_profile_proposals(id) ON DELETE SET NULL,
            predecessor_assignment_id INTEGER REFERENCES voice_sample_profile_assignments(id) ON DELETE SET NULL,
            active INTEGER NOT NULL DEFAULT 1 CHECK (active IN (0,1)),
            created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
        );
        CREATE UNIQUE INDEX IF NOT EXISTS idx_voice_sample_assignment_active
            ON voice_sample_profile_assignments(sample_id) WHERE active=1;
        CREATE INDEX IF NOT EXISTS idx_voice_sample_assignment_profile
            ON voice_sample_profile_assignments(profile_id,active,sample_id);
        CREATE TABLE IF NOT EXISTS voice_profile_proposal_profiles (
            proposal_id INTEGER NOT NULL REFERENCES voice_profile_proposals(id) ON DELETE CASCADE,
            profile_id INTEGER NOT NULL REFERENCES voice_profiles(id) ON DELETE CASCADE,
            role TEXT NOT NULL CHECK (role IN ('source','result')),
            partition_ordinal INTEGER NOT NULL DEFAULT 0,
            PRIMARY KEY (proposal_id,profile_id,role)
        );
        CREATE TABLE IF NOT EXISTS voice_profile_proposal_samples (
            proposal_id INTEGER NOT NULL REFERENCES voice_profile_proposals(id) ON DELETE CASCADE,
            sample_id INTEGER NOT NULL REFERENCES voice_samples(id) ON DELETE CASCADE,
            source_profile_id INTEGER NOT NULL REFERENCES voice_profiles(id) ON DELETE CASCADE,
            partition_ordinal INTEGER NOT NULL,
            PRIMARY KEY (proposal_id,sample_id)
        );
        CREATE TABLE IF NOT EXISTS identity_evidence (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            person_id INTEGER REFERENCES people(id) ON DELETE CASCADE,
            voice_profile_id INTEGER REFERENCES voice_profiles(id) ON DELETE CASCADE,
            source_event_id TEXT REFERENCES capture_events(event_id) ON DELETE CASCADE,
            observed_at TEXT,
            speaker_observation_id INTEGER REFERENCES speaker_observations(id) ON DELETE CASCADE,
            kind TEXT NOT NULL,
            claimed_name TEXT,
            evidence_json TEXT NOT NULL,
            score REAL,
            status TEXT NOT NULL CHECK (status IN ('proposed','accepted','rejected','quarantined')),
            created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
        );
        CREATE TABLE IF NOT EXISTS person_facts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            person_id INTEGER NOT NULL REFERENCES people(id) ON DELETE CASCADE,
            predicate TEXT NOT NULL,
            value TEXT NOT NULL,
            evidence_json TEXT NOT NULL,
            derivation_version INTEGER NOT NULL,
            status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active','superseded','conflicted')),
            supersedes_id INTEGER REFERENCES person_facts(id) ON DELETE SET NULL,
            source_event_id TEXT REFERENCES capture_events(event_id) ON DELETE CASCADE,
            speaker_observation_id INTEGER REFERENCES speaker_observations(id) ON DELETE CASCADE,
            observed_at TEXT,
            literal_evidence TEXT,
            confidence REAL NOT NULL DEFAULT 0,
            conflicts_with_id INTEGER REFERENCES person_facts(id) ON DELETE SET NULL,
            created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
        );
        CREATE TABLE IF NOT EXISTS speaker_clusters (
            id                INTEGER PRIMARY KEY AUTOINCREMENT,
            work_unit_id      TEXT NOT NULL REFERENCES media_work_units(id) ON DELETE CASCADE,
            speaker_local_id  TEXT NOT NULL,
            voice_profile_id  INTEGER REFERENCES voice_profiles(id) ON DELETE SET NULL,
            person_id         INTEGER REFERENCES people(id) ON DELETE SET NULL,
            attribution_state TEXT NOT NULL CHECK (attribution_state IN ('owner_transmit','person_bound','anonymous_profile','request_local','unsegmented')),
            created_at        TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
            updated_at        TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
            UNIQUE(work_unit_id, speaker_local_id)
        );
        CREATE INDEX IF NOT EXISTS idx_speaker_clusters_lookup ON speaker_clusters(work_unit_id, speaker_local_id);
        CREATE TABLE IF NOT EXISTS audio_segments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            started_at TEXT NOT NULL,
            ended_at TEXT NOT NULL,
            duration_seconds REAL NOT NULL,
            source_type TEXT NOT NULL,
            audio_format TEXT,
            transcription_status TEXT
        );
        CREATE TABLE IF NOT EXISTS utterances (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            audio_segment_id INTEGER NOT NULL,
            start_offset_seconds REAL,
            end_offset_seconds REAL,
            text TEXT,
            language TEXT,
            confidence REAL,
            speaker_label TEXT,
            source_key TEXT,
            speaker_observation_id INTEGER REFERENCES speaker_observations(id) ON DELETE SET NULL
        );
        CREATE TABLE IF NOT EXISTS episodes (
            id                          INTEGER PRIMARY KEY AUTOINCREMENT,
            started_at                  TEXT NOT NULL,
            ended_at                    TEXT NOT NULL,
            type                        TEXT,
            title                       TEXT,
            summary                     TEXT,
            participants                TEXT,
            languages                   TEXT,
            action_items                TEXT,
            model                       TEXT,
            topics                      TEXT,
            people                      TEXT,
            minute_summaries            TEXT,
            minutes_text                TEXT,
            substance                   TEXT NOT NULL DEFAULT 'normal' CHECK (substance IN ('none','low','normal')),
            visual_evidence             TEXT NOT NULL DEFAULT 'none' CHECK (visual_evidence IN ('none','useful')),
            created_at                  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
            updated_at                  TEXT,
            finalized_at                TEXT,
            finalization_version        INTEGER,
            finalization_status         TEXT NOT NULL DEFAULT 'pending',
            finalization_error          TEXT,
            finalization_attempt_count  INTEGER NOT NULL DEFAULT 0,
            finalization_next_attempt_at TEXT,
            identity_revision           INTEGER NOT NULL DEFAULT 0,
            finalized_identity_revision INTEGER NOT NULL DEFAULT 0,
            identity_refresh_status     TEXT DEFAULT NULL CHECK (identity_refresh_status IN ('queued', 'processing', 'ready', 'failed')),
            speaker_processing_status   TEXT NOT NULL DEFAULT 'ready' CHECK (speaker_processing_status IN ('ready', 'pending', 'degraded'))
        );
        CREATE TABLE IF NOT EXISTS episode_members (
            episode_id  INTEGER NOT NULL REFERENCES episodes(id) ON DELETE CASCADE,
            record_id   INTEGER NOT NULL,
            record_type TEXT NOT NULL CHECK (record_type IN ('utterance','screenshot')),
            PRIMARY KEY (episode_id, record_type, record_id)
        );
        CREATE TABLE IF NOT EXISTS episode_speaker_slots (
            id                 INTEGER PRIMARY KEY AUTOINCREMENT,
            episode_id         INTEGER NOT NULL REFERENCES episodes(id) ON DELETE CASCADE,
            voice_profile_id   INTEGER REFERENCES voice_profiles(id) ON DELETE RESTRICT,
            speaker_cluster_id INTEGER REFERENCES speaker_clusters(id) ON DELETE RESTRICT,
            slot_ordinal       INTEGER NOT NULL CHECK (slot_ordinal >= 0),
            status             TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active','superseded')),
            created_at         TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
            updated_at         TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
            CHECK (
                (status = 'active' AND ((voice_profile_id IS NULL) != (speaker_cluster_id IS NULL)))
                OR status = 'superseded'
            )
        );
        CREATE TABLE IF NOT EXISTS voice_profile_representatives (
            id               INTEGER PRIMARY KEY AUTOINCREMENT,
            profile_id       INTEGER NOT NULL REFERENCES voice_profiles(id) ON DELETE CASCADE,
            channel_domain   TEXT NOT NULL,
            centroid         BLOB NOT NULL,
            sample_count     INTEGER NOT NULL DEFAULT 0,
            medoid_sample_id INTEGER REFERENCES voice_samples(id) ON DELETE SET NULL,
            scorer_version   INTEGER NOT NULL DEFAULT 2,
            created_at       TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
            updated_at       TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
            UNIQUE(profile_id, channel_domain)
        );
        CREATE INDEX IF NOT EXISTS idx_voice_profile_rep_domain ON voice_profile_representatives(channel_domain);
        CREATE TABLE IF NOT EXISTS voice_embedding_jobs (
            id                     INTEGER PRIMARY KEY AUTOINCREMENT,
            speaker_observation_id INTEGER NOT NULL REFERENCES speaker_observations(id) ON DELETE CASCADE,
            embedding_space        TEXT NOT NULL,
            processor_version      INTEGER NOT NULL DEFAULT 1,
            quality_version        INTEGER NOT NULL DEFAULT 1,
            scorer_version         INTEGER NOT NULL DEFAULT 2,
            state                  TEXT NOT NULL CHECK (state IN ('pending','processing','retry_wait','failed','ready','raw_media_expired')),
            lease_owner            TEXT,
            lease_token            TEXT,
            lease_until            TEXT,
            attempt_count          INTEGER NOT NULL DEFAULT 0,
            next_attempt_at        TEXT,
            error_code             TEXT,
            created_at             TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
            updated_at             TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
            UNIQUE(speaker_observation_id, embedding_space, processor_version, quality_version, scorer_version)
        );
        CREATE INDEX IF NOT EXISTS idx_voice_embedding_jobs_lease ON voice_embedding_jobs(state, next_attempt_at, lease_until);
        CREATE TABLE IF NOT EXISTS episode_participants (
            id                  INTEGER PRIMARY KEY AUTOINCREMENT,
            episode_id          INTEGER NOT NULL REFERENCES episodes(id) ON DELETE CASCADE,
            participant_key     TEXT NOT NULL,
            person_id           INTEGER REFERENCES people(id) ON DELETE SET NULL,
            source_claimed_name TEXT,
            speaker_slot_id     INTEGER REFERENCES episode_speaker_slots(id) ON DELETE SET NULL,
            attribution_kind    TEXT NOT NULL CHECK (attribution_kind IN ('owner','verified_voice','direct_identity_evidence','context_inferred')),
            state               TEXT NOT NULL DEFAULT 'active' CHECK (state IN ('active','superseded','quarantined')),
            derivation_version  INTEGER NOT NULL DEFAULT 1,
            confidence          REAL NOT NULL DEFAULT 1.0,
            evidence_json       TEXT NOT NULL DEFAULT '{}',
            created_at          TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
            updated_at          TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
            UNIQUE(episode_id, participant_key)
        );
        CREATE INDEX IF NOT EXISTS idx_episode_participants_ep ON episode_participants(episode_id, state);
        CREATE TABLE IF NOT EXISTS visual_speaker_observations (
            id                INTEGER PRIMARY KEY AUTOINCREMENT,
            event_id          TEXT NOT NULL REFERENCES capture_events(event_id) ON DELETE CASCADE,
            screenshot_id     INTEGER NOT NULL REFERENCES screenshots(id) ON DELETE CASCADE,
            observed_at       TEXT NOT NULL,
            platform          TEXT NOT NULL,
            displayed_name    TEXT NOT NULL,
            normalized_name   TEXT NOT NULL,
            highlight_state   TEXT NOT NULL CHECK (highlight_state IN ('active_speaker_box','audio_waveform','roster_indicator','none')),
            bounding_box_json TEXT,
            model_version     INTEGER NOT NULL DEFAULT 1,
            confidence        REAL NOT NULL,
            created_at        TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
        );
        CREATE INDEX IF NOT EXISTS idx_visual_speaker_obs ON visual_speaker_observations(observed_at, normalized_name);
        "#,
    )?;
    add_column_if_missing(
        conn,
        "capture_sessions",
        "ended_at",
        "ALTER TABLE capture_sessions ADD COLUMN ended_at TEXT",
    )?;
    add_column_if_missing(
        conn,
        "media_objects",
        "object_generation",
        "ALTER TABLE media_objects ADD COLUMN object_generation INTEGER",
    )?;
    add_column_if_missing(
        conn,
        "media_objects",
        "object_backend",
        "ALTER TABLE media_objects ADD COLUMN object_backend TEXT CHECK (object_backend IN ('current'))",
    )?;
    let has_normalized_name: i64 = conn.query_row(
        "SELECT COUNT(*) FROM pragma_table_info('people') WHERE name='normalized_name'",
        [],
        |row| row.get(0),
    )?;
    if has_normalized_name == 0 {
        conn.execute_batch("ALTER TABLE people ADD COLUMN normalized_name TEXT;")?;
    }
    add_column_if_missing(
        conn,
        "speaker_observations",
        "person_id",
        "ALTER TABLE speaker_observations ADD COLUMN person_id INTEGER REFERENCES people(id) ON DELETE SET NULL",
    )?;
    for (table, column, alteration) in [
        (
            "speaker_observations",
            "voice_eligibility",
            "ALTER TABLE speaker_observations ADD COLUMN voice_eligibility TEXT",
        ),
        (
            "speaker_observations",
            "voice_diagnostics_json",
            "ALTER TABLE speaker_observations ADD COLUMN voice_diagnostics_json TEXT",
        ),
        (
            "voice_profiles",
            "scorer_version",
            "ALTER TABLE voice_profiles ADD COLUMN scorer_version INTEGER NOT NULL DEFAULT 1",
        ),
        (
            "voice_profiles",
            "representative_kind",
            "ALTER TABLE voice_profiles ADD COLUMN representative_kind TEXT NOT NULL DEFAULT 'running_mean'",
        ),
        (
            "voice_profiles",
            "medoid_sample_id",
            "ALTER TABLE voice_profiles ADD COLUMN medoid_sample_id INTEGER",
        ),
        (
            "voice_samples",
            "diagnostics_json",
            "ALTER TABLE voice_samples ADD COLUMN diagnostics_json TEXT NOT NULL DEFAULT '{}'",
        ),
        (
            "voice_samples",
            "quality_version",
            "ALTER TABLE voice_samples ADD COLUMN quality_version INTEGER NOT NULL DEFAULT 1",
        ),
        (
            "voice_samples",
            "scorer_version",
            "ALTER TABLE voice_samples ADD COLUMN scorer_version INTEGER NOT NULL DEFAULT 1",
        ),
        (
            "voice_samples",
            "eligibility",
            "ALTER TABLE voice_samples ADD COLUMN eligibility TEXT NOT NULL DEFAULT 'enroll'",
        ),
        (
            "voice_samples",
            "duration_ms",
            "ALTER TABLE voice_samples ADD COLUMN duration_ms INTEGER NOT NULL DEFAULT 0",
        ),
        (
            "voice_samples",
            "speech_ratio",
            "ALTER TABLE voice_samples ADD COLUMN speech_ratio REAL NOT NULL DEFAULT 0",
        ),
        (
            "voice_samples",
            "snr_proxy_db",
            "ALTER TABLE voice_samples ADD COLUMN snr_proxy_db REAL NOT NULL DEFAULT 0",
        ),
        (
            "voice_samples",
            "clipping_ratio",
            "ALTER TABLE voice_samples ADD COLUMN clipping_ratio REAL NOT NULL DEFAULT 0",
        ),
        (
            "voice_samples",
            "silence_ratio",
            "ALTER TABLE voice_samples ADD COLUMN silence_ratio REAL NOT NULL DEFAULT 0",
        ),
        (
            "voice_samples",
            "embedding_norm",
            "ALTER TABLE voice_samples ADD COLUMN embedding_norm REAL NOT NULL DEFAULT 1",
        ),
        (
            "voice_samples",
            "outlier",
            "ALTER TABLE voice_samples ADD COLUMN outlier INTEGER NOT NULL DEFAULT 0",
        ),
    ] {
        add_column_if_missing(conn, table, column, alteration)?;
    }
    add_column_if_missing(
        conn,
        "identity_evidence",
        "source_event_id",
        "ALTER TABLE identity_evidence ADD COLUMN source_event_id TEXT REFERENCES capture_events(event_id) ON DELETE CASCADE",
    )?;
    add_column_if_missing(
        conn,
        "identity_evidence",
        "observed_at",
        "ALTER TABLE identity_evidence ADD COLUMN observed_at TEXT",
    )?;
    add_column_if_missing(
        conn,
        "identity_evidence",
        "speaker_observation_id",
        "ALTER TABLE identity_evidence ADD COLUMN speaker_observation_id INTEGER REFERENCES speaker_observations(id) ON DELETE CASCADE",
    )?;
    for (column, alteration) in [
        (
            "media_disposition",
            "ALTER TABLE capture_events ADD COLUMN media_disposition TEXT NOT NULL DEFAULT 'canonical' CHECK (media_disposition IN ('canonical','reference'))",
        ),
        (
            "canonical_event_id",
            "ALTER TABLE capture_events ADD COLUMN canonical_event_id TEXT REFERENCES capture_events(event_id) ON DELETE CASCADE",
        ),
        (
            "canonical_asset_id",
            "ALTER TABLE capture_events ADD COLUMN canonical_asset_id TEXT",
        ),
        (
            "canonical_media_sha256",
            "ALTER TABLE capture_events ADD COLUMN canonical_media_sha256 TEXT",
        ),
        (
            "perceptual_hash",
            "ALTER TABLE capture_events ADD COLUMN perceptual_hash TEXT",
        ),
        (
            "hamming_distance",
            "ALTER TABLE capture_events ADD COLUMN hamming_distance INTEGER",
        ),
        (
            "pixel_change_ratio",
            "ALTER TABLE capture_events ADD COLUMN pixel_change_ratio REAL",
        ),
        (
            "context_fingerprint",
            "ALTER TABLE capture_events ADD COLUMN context_fingerprint TEXT",
        ),
        (
            "dedupe_version",
            "ALTER TABLE capture_events ADD COLUMN dedupe_version INTEGER",
        ),
        (
            "audio_role",
            "ALTER TABLE capture_events ADD COLUMN audio_role TEXT",
        ),
        (
            "audio_route",
            "ALTER TABLE capture_events ADD COLUMN audio_route TEXT",
        ),
        (
            "route_epoch",
            "ALTER TABLE capture_events ADD COLUMN route_epoch INTEGER",
        ),
    ] {
        add_column_if_missing(conn, "capture_events", column, alteration)?;
    }
    conn.execute_batch(
        "DROP INDEX IF EXISTS idx_people_normalized_name;\
         INSERT INTO person_name_claims \
           (person_id,name,normalized_name,observed_at,evidence_kind,evidence_json,confidence,status) \
         SELECT p.id,p.display_name,p.normalized_name,p.created_at,'legacy_migration','{}',1.0,'accepted' \
         FROM people p WHERE p.normalized_name IS NOT NULL AND p.display_name IS NOT NULL \
           AND NOT EXISTS (SELECT 1 FROM person_name_claims c WHERE c.person_id=p.id);\
         UPDATE people SET normalized_name=NULL WHERE normalized_name IS NOT NULL;\
         CREATE INDEX IF NOT EXISTS idx_capture_events_canonical_reference \
         ON capture_events(canonical_event_id) WHERE canonical_event_id IS NOT NULL;",
    )?;
    for (column, alteration) in [
        (
            "source_event_id",
            "ALTER TABLE person_facts ADD COLUMN source_event_id TEXT REFERENCES capture_events(event_id) ON DELETE CASCADE",
        ),
        (
            "speaker_observation_id",
            "ALTER TABLE person_facts ADD COLUMN speaker_observation_id INTEGER REFERENCES speaker_observations(id) ON DELETE CASCADE",
        ),
        (
            "observed_at",
            "ALTER TABLE person_facts ADD COLUMN observed_at TEXT",
        ),
        (
            "literal_evidence",
            "ALTER TABLE person_facts ADD COLUMN literal_evidence TEXT",
        ),
        (
            "confidence",
            "ALTER TABLE person_facts ADD COLUMN confidence REAL NOT NULL DEFAULT 0",
        ),
        (
            "conflicts_with_id",
            "ALTER TABLE person_facts ADD COLUMN conflicts_with_id INTEGER REFERENCES person_facts(id) ON DELETE SET NULL",
        ),
    ] {
        add_column_if_missing(conn, "person_facts", column, alteration)?;
    }
    for (table, column, alteration) in [
        (
            "people",
            "kind",
            "ALTER TABLE people ADD COLUMN kind TEXT NOT NULL DEFAULT 'person' CHECK (kind IN ('owner','person'))",
        ),
        (
            "profile_identity_bindings",
            "active",
            "ALTER TABLE profile_identity_bindings ADD COLUMN active INTEGER NOT NULL DEFAULT 0 CHECK (active IN (0, 1))",
        ),
        (
            "profile_identity_bindings",
            "operation_id",
            "ALTER TABLE profile_identity_bindings ADD COLUMN operation_id TEXT",
        ),
        (
            "profile_identity_bindings",
            "conflicts_with_id",
            "ALTER TABLE profile_identity_bindings ADD COLUMN conflicts_with_id INTEGER REFERENCES profile_identity_bindings(id) ON DELETE SET NULL",
        ),
        (
            "speaker_observations",
            "cluster_id",
            "ALTER TABLE speaker_observations ADD COLUMN cluster_id INTEGER REFERENCES speaker_clusters(id) ON DELETE SET NULL",
        ),
        (
            "speaker_observations",
            "direct_evidence_id",
            "ALTER TABLE speaker_observations ADD COLUMN direct_evidence_id INTEGER REFERENCES identity_evidence(id) ON DELETE SET NULL",
        ),
        (
            "utterances",
            "speaker_observation_id",
            "ALTER TABLE utterances ADD COLUMN speaker_observation_id INTEGER REFERENCES speaker_observations(id) ON DELETE SET NULL",
        ),
        // Must exist before migrate_speaker_identity_backfill_v2 below: the
        // backfill recalculates this column on databases created before the
        // zero-touch speaker-identity release, and store.rs run_migrations
        // adds it only AFTER init_schema returns (v0.8.26 production 500s).
        (
            "episodes",
            "speaker_processing_status",
            "ALTER TABLE episodes ADD COLUMN speaker_processing_status TEXT NOT NULL DEFAULT 'ready' CHECK (speaker_processing_status IN ('ready', 'pending', 'degraded'))",
        ),
        (
            "identity_evidence",
            "speaker_cluster_id",
            "ALTER TABLE identity_evidence ADD COLUMN speaker_cluster_id INTEGER REFERENCES speaker_clusters(id) ON DELETE SET NULL",
        ),
        (
            "voice_samples",
            "embedding_job_id",
            "ALTER TABLE voice_samples ADD COLUMN embedding_job_id INTEGER REFERENCES voice_embedding_jobs(id) ON DELETE RESTRICT",
        ),
    ] {
        add_column_if_missing(conn, table, column, alteration)?;
    }
    reconcile_profile_identity_bindings_migration(conn)?;
    super::voice_lineage::backfill_profile_lineage(conn)?;
    migrate_request_local_speaker_labels(conn)?;
    migrate_speaker_identity_backfill_v2(conn)?;
    Ok(())
}

/// One-time v2 backfill for the zero-touch speaker-identity release.
///
/// Existing archives predate `utterances.speaker_observation_id`,
/// `visual_speaker_observations`, and durable voice embedding jobs. This
/// migration links historical utterances to their observations, re-resolves
/// their labels through the shared attribution resolver, projects historical
/// active-speaker screen claims into `visual_speaker_observations`, and
/// enqueues embedding jobs only for observations whose retained raw media is
/// still fully present (pruned/expired history is left untouched rather than
/// mass-failing into `degraded`).
fn migrate_speaker_identity_backfill_v2(conn: &Connection) -> Result<()> {
    let has_metadata: i64 = conn.query_row(
        "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='app_metadata'",
        [],
        |row| row.get(0),
    )?;
    if has_metadata == 0 {
        return Ok(());
    }
    let complete: bool = conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM app_metadata WHERE key=?1)",
        [SPEAKER_IDENTITY_BACKFILL_KEY],
        |row| row.get(0),
    )?;
    if complete {
        return Ok(());
    }
    let tx = conn.unchecked_transaction()?;

    // Historical active-speaker screen evidence becomes queryable visual
    // observations so vocative corroboration can see pre-release frames.
    tx.execute(
        "INSERT INTO visual_speaker_observations \
         (event_id, screenshot_id, observed_at, platform, displayed_name, normalized_name, \
          highlight_state, bounding_box_json, model_version, confidence) \
         SELECT c.source_event_id, s.id, c.observed_at, 'screen_capture', c.name, \
                c.normalized_name, 'active_speaker_box', NULL, 1, c.confidence \
         FROM person_name_claims c \
         JOIN capture_events e ON e.event_id = c.source_event_id \
         JOIN screenshots s ON (s.source_key = 'cloud-v2:' || e.event_id \
                                OR s.source_key = e.device_id || ':' || e.stream_id || ':' || e.sequence) \
         WHERE c.evidence_kind = 'screen_active_speaker' \
           AND c.source_event_id IS NOT NULL \
           AND NOT EXISTS ( \
               SELECT 1 FROM visual_speaker_observations v \
               WHERE v.event_id = c.source_event_id \
                 AND v.normalized_name = c.normalized_name \
                 AND v.observed_at = c.observed_at)",
        [],
    )?;

    // Link utterances to observations and re-resolve every label through the
    // shared attribution authority.
    reconcile_request_local_speaker_labels(&tx, None)?;

    // Durable embedding jobs for sample-less observations whose media is still
    // fully retained. Overlapped observations are skipped (policy abstains).
    let candidate_obs: Vec<i64> = {
        let mut stmt = tx.prepare(
            "SELECT o.id FROM speaker_observations o \
             WHERE COALESCE(o.overlap, 0) = 0 \
               AND NOT EXISTS (SELECT 1 FROM voice_samples vs WHERE vs.speaker_observation_id = o.id) \
               AND NOT EXISTS (SELECT 1 FROM voice_embedding_jobs j WHERE j.speaker_observation_id = o.id) \
               AND EXISTS (SELECT 1 FROM speaker_observation_sources src WHERE src.speaker_observation_id = o.id) \
               AND NOT EXISTS ( \
                   SELECT 1 FROM speaker_observation_sources src \
                   LEFT JOIN media_objects mo ON mo.event_id = src.event_id \
                   WHERE src.speaker_observation_id = o.id \
                     AND (mo.object_key IS NULL OR COALESCE(mo.processing_state, '') = 'pruned'))",
        )?;
        let rows = stmt
            .query_map([], |r| r.get(0))?
            .collect::<std::result::Result<Vec<i64>, rusqlite::Error>>()?;
        rows
    };
    for obs_id in candidate_obs {
        super::voice_memory::enqueue_embedding_job(&tx, obs_id)?;
    }

    super::voice_memory::recalculate_all_episode_speaker_processing_status(&tx)?;

    tx.execute(
        "INSERT INTO app_metadata(key,value) VALUES (?1,'complete')",
        [SPEAKER_IDENTITY_BACKFILL_KEY],
    )?;
    tx.commit()?;
    Ok(())
}

fn reconcile_profile_identity_bindings_migration(conn: &Connection) -> Result<()> {
    let has_owner: bool = conn
        .query_row(
            "SELECT 1 FROM people WHERE kind = 'owner' LIMIT 1",
            [],
            |_| Ok(true),
        )
        .optional()?
        .unwrap_or(false);
    if !has_owner {
        conn.execute_batch(
            "CREATE UNIQUE INDEX IF NOT EXISTS idx_one_owner_person ON people(kind) WHERE kind = 'owner';
             INSERT OR IGNORE INTO people (kind, display_name) VALUES ('owner', 'Me');",
        )?;
    }

    let profile_ids: Vec<i64> = {
        let mut stmt = conn.prepare(
            "SELECT DISTINCT voice_profile_id FROM profile_identity_bindings WHERE state = 'accepted'",
        )?;
        let rows = stmt
            .query_map([], |r| r.get(0))?
            .collect::<std::result::Result<Vec<i64>, rusqlite::Error>>()?;
        rows
    };

    for pid in profile_ids {
        let person_count: i64 = conn.query_row(
            "SELECT COUNT(DISTINCT person_id) FROM profile_identity_bindings \
             WHERE voice_profile_id = ?1 AND state = 'accepted'",
            [pid],
            |r| r.get(0),
        )?;

        if person_count == 1 {
            let leaf_id: Option<(i64, i64)> = conn
                .query_row(
                    "SELECT b1.id, b1.person_id FROM profile_identity_bindings b1 \
                     WHERE b1.voice_profile_id = ?1 AND b1.state = 'accepted' \
                       AND NOT EXISTS ( \
                           SELECT 1 FROM profile_identity_bindings b2 \
                           WHERE b2.voice_profile_id = b1.voice_profile_id \
                             AND b2.supersedes_id = b1.id \
                             AND b2.state = 'accepted' \
                       ) \
                     ORDER BY b1.id DESC LIMIT 1",
                    [pid],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .optional()?;

            if let Some((b_id, p_id)) = leaf_id {
                conn.execute(
                    "UPDATE profile_identity_bindings SET active = 0 WHERE voice_profile_id = ?1",
                    [pid],
                )?;
                conn.execute(
                    "UPDATE profile_identity_bindings SET active = 1 WHERE id = ?1",
                    [b_id],
                )?;
                conn.execute(
                    "UPDATE voice_profiles SET person_id = ?1 WHERE id = ?2",
                    params![p_id, pid],
                )?;
            }
        } else {
            conn.execute(
                "UPDATE profile_identity_bindings SET active = 0 WHERE voice_profile_id = ?1",
                [pid],
            )?;
            conn.execute(
                "UPDATE voice_profiles SET person_id = NULL WHERE id = ?1",
                [pid],
            )?;
        }
    }

    conn.execute_batch(
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_one_active_profile_binding
         ON profile_identity_bindings(voice_profile_id)
         WHERE active = 1;
         CREATE UNIQUE INDEX IF NOT EXISTS idx_profile_binding_operation
         ON profile_identity_bindings(voice_profile_id, operation_id)
         WHERE operation_id IS NOT NULL;
         CREATE UNIQUE INDEX IF NOT EXISTS idx_slot_ordinal
         ON episode_speaker_slots(episode_id, slot_ordinal);
         CREATE UNIQUE INDEX IF NOT EXISTS idx_active_slot_profile
         ON episode_speaker_slots(episode_id, voice_profile_id)
         WHERE status = 'active' AND voice_profile_id IS NOT NULL;
         CREATE UNIQUE INDEX IF NOT EXISTS idx_active_slot_cluster
         ON episode_speaker_slots(episode_id, speaker_cluster_id)
         WHERE status = 'active' AND speaker_cluster_id IS NOT NULL;
         CREATE UNIQUE INDEX IF NOT EXISTS idx_voice_samples_job
         ON voice_samples(embedding_job_id)
         WHERE embedding_job_id IS NOT NULL;
         CREATE INDEX IF NOT EXISTS idx_speaker_obs_cluster ON speaker_observations(cluster_id);
         CREATE INDEX IF NOT EXISTS idx_speaker_obs_direct_evidence ON speaker_observations(direct_evidence_id);
         CREATE INDEX IF NOT EXISTS idx_identity_evidence_cluster ON identity_evidence(speaker_cluster_id);",
    )?;

    let has_utterances: i64 = conn.query_row(
        "SELECT count(*) FROM sqlite_master WHERE type='table' AND name='utterances'",
        [],
        |r| r.get(0),
    )?;
    if has_utterances > 0 {
        conn.execute_batch(
            "CREATE INDEX IF NOT EXISTS idx_utterances_speaker_obs ON utterances(speaker_observation_id);",
        )?;
    }

    Ok(())
}

/// Gemini speaker ids are stable only within one media request. They are useful
/// for joining turns inside that request, but they are not a durable identity
/// and must never leak into the archive as if `speaker_0` were a person.
///
/// First replace exact request-local fallbacks with an explicitly unresolved
/// label. Then, within one work unit only, let a unique independently resolved
/// voice/name for the same local id label its sibling turns. Conflicting
/// resolutions abstain. This preserves the independent voice/evidence graph as
/// the only cross-request identity authority.
pub(crate) fn reconcile_request_local_speaker_labels(
    conn: &Connection,
    work_unit_id: Option<&str>,
) -> Result<usize> {
    let required_tables: i64 = conn.query_row(
        "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name IN \
         ('utterances','speaker_observations','media_work_members')",
        [],
        |row| row.get(0),
    )?;
    if required_tables != 3 {
        return Ok(0);
    }

    // 1. Backfill utterances.speaker_observation_id if missing
    let has_missing: bool = conn
        .query_row(
            "SELECT 1 FROM utterances WHERE speaker_observation_id IS NULL AND source_key IS NOT NULL LIMIT 1",
            [],
            |_| Ok(true),
        )
        .optional()?
        .unwrap_or(false);
    if has_missing {
        conn.execute(
            "UPDATE utterances AS u \
             SET speaker_observation_id = ( \
                 SELECT s.id FROM speaker_observations s \
                 WHERE u.source_key = 'cloud-v2:' || s.event_id || ':' || s.turn_id \
                 LIMIT 1 \
             ) \
             WHERE u.speaker_observation_id IS NULL AND u.source_key IS NOT NULL",
            [],
        )?;
    }

    // 2. Query observations in scope
    let observation_ids: Vec<i64> = match work_unit_id {
        Some(w_id) => {
            let mut stmt = conn.prepare(
                "SELECT DISTINCT s.id FROM speaker_observations s \
                 JOIN media_work_members m ON m.event_id = s.event_id \
                 WHERE m.work_unit_id = ?1",
            )?;
            let rows = stmt
                .query_map([w_id], |r| r.get(0))?
                .collect::<std::result::Result<Vec<i64>, rusqlite::Error>>()?;
            rows
        }
        None => {
            let mut stmt = conn.prepare("SELECT DISTINCT id FROM speaker_observations")?;
            let rows = stmt
                .query_map([], |r| r.get(0))?
                .collect::<std::result::Result<Vec<i64>, rusqlite::Error>>()?;
            rows
        }
    };

    let mut updated = 0;
    for obs_id in observation_ids {
        let attribution = crate::cp::identity::resolve_speaker_attribution(conn, obs_id, None)?;
        let count = conn.execute(
            "UPDATE utterances SET speaker_label = ?1 \
             WHERE speaker_observation_id = ?2 AND speaker_label <> ?1",
            params![attribution.display_label, obs_id],
        )?;
        updated += count;
    }

    Ok(updated)
}

fn migrate_request_local_speaker_labels(conn: &Connection) -> Result<()> {
    let has_metadata: i64 = conn.query_row(
        "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='app_metadata'",
        [],
        |row| row.get(0),
    )?;
    if has_metadata == 0 {
        return Ok(());
    }
    let complete: bool = conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM app_metadata WHERE key=?1)",
        [REQUEST_LOCAL_LABEL_MIGRATION_KEY],
        |row| row.get(0),
    )?;
    if complete {
        return Ok(());
    }
    let tx = conn.unchecked_transaction()?;
    reconcile_request_local_speaker_labels(&tx, None)?;
    tx.execute(
        "INSERT INTO app_metadata(key,value) VALUES (?1,'complete')",
        [REQUEST_LOCAL_LABEL_MIGRATION_KEY],
    )?;
    tx.commit()?;
    Ok(())
}

fn add_column_if_missing(
    conn: &Connection,
    table: &str,
    column: &str,
    alteration: &str,
) -> Result<()> {
    let table_exists: i64 = conn.query_row(
        "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?1",
        [table],
        |row| row.get(0),
    )?;
    if table_exists == 0 {
        return Ok(());
    }
    let query = format!("SELECT COUNT(*) FROM pragma_table_info('{table}') WHERE name=?1");
    let present: i64 = conn.query_row(&query, [column], |row| row.get(0))?;
    if present == 0 {
        conn.execute_batch(alteration)?;
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecordOutcome {
    Created,
    Duplicate,
}

#[cfg(test)]
pub fn record_source_event(
    conn: &Connection,
    account_id: &str,
    manifest: &CaptureEventManifest,
    manifest_digest: &str,
    object_key: &str,
) -> Result<RecordOutcome> {
    record_source_event_with_generation(
        conn,
        account_id,
        manifest,
        manifest_digest,
        object_key,
        None,
    )
}

/// Records the generation returned by GCS for canonical media when available.
/// Old rows may not have it; deletion still reconciles the exact user prefix.
pub fn record_source_event_with_generation(
    conn: &Connection,
    account_id: &str,
    manifest: &CaptureEventManifest,
    manifest_digest: &str,
    object_key: &str,
    object_generation: Option<i64>,
) -> Result<RecordOutcome> {
    let tx = conn.unchecked_transaction()?;
    let outcome = record_source_event_in_transaction(
        &tx,
        account_id,
        manifest,
        manifest_digest,
        object_key,
        object_generation,
        None,
    )?;
    tx.commit()?;
    Ok(outcome)
}

fn record_source_event_in_transaction(
    conn: &Connection,
    account_id: &str,
    manifest: &CaptureEventManifest,
    manifest_digest: &str,
    object_key: &str,
    object_generation: Option<i64>,
    commit_stamp: CommitStamp<'_>,
) -> Result<RecordOutcome> {
    manifest.validate()?;
    if manifest.media_disposition != MediaDisposition::Canonical {
        return Err(EnclaveError::InvalidRequest(
            "record_source_event requires canonical media".into(),
        ));
    }
    let media = manifest
        .media
        .as_ref()
        .ok_or_else(|| EnclaveError::InvalidRequest("canonical media is required".into()))?;
    validate_id("account_id", account_id)?;
    if !validate_sha256(manifest_digest) {
        return Err(EnclaveError::InvalidRequest(
            "manifest digest is invalid".into(),
        ));
    }
    if object_key.is_empty() || object_key.len() > 512 || object_key.contains("..") {
        return Err(EnclaveError::InvalidRequest("object_key is invalid".into()));
    }

    let existing: Option<(String, String)> = conn
        .query_row(
            "SELECT e.manifest_digest, m.object_key FROM capture_events e \
             JOIN media_objects m ON m.event_id=e.event_id WHERE e.event_id=?1",
            [&manifest.event_id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?;
    if let Some((existing_digest, existing_object)) = existing {
        if existing_digest == manifest_digest && existing_object == object_key {
            return Ok(RecordOutcome::Duplicate);
        }
        return Err(EnclaveError::Conflict(
            "idempotency conflict for event_id".into(),
        ));
    }

    conn.execute(
        "INSERT INTO capture_sessions \
         (id, device_id, install_id, started_at, last_event_at, schema_version, ended_at, \
          created_at) \
         VALUES (?1,?2,?3,?4,?5,2,CASE WHEN ?6 THEN ?5 ELSE NULL END,\
                 COALESCE(?7,strftime('%Y-%m-%dT%H:%M:%fZ','now'))) \
         ON CONFLICT(id) DO UPDATE SET \
           last_event_at=MAX(last_event_at, excluded.last_event_at), \
           ended_at=CASE WHEN ?6 THEN COALESCE(capture_sessions.ended_at, excluded.ended_at) \
                         ELSE capture_sessions.ended_at END",
        params![
            manifest.capture_session_id,
            manifest.device_id,
            manifest.install_id,
            manifest.started_at,
            manifest.ended_at,
            manifest.session_finished.unwrap_or(false),
            commit_stamp
        ],
    )?;
    conn.execute(
        "INSERT INTO capture_streams \
         (id, capture_session_id, device_id, stream_kind, created_at) \
         VALUES (?1,?2,?3,?4,COALESCE(?5,strftime('%Y-%m-%dT%H:%M:%fZ','now'))) \
         ON CONFLICT(id) DO NOTHING",
        params![
            manifest.stream_id,
            manifest.capture_session_id,
            manifest.device_id,
            manifest.stream_kind.as_str(),
            commit_stamp
        ],
    )?;
    let context_json = manifest
        .context
        .as_ref()
        .map(serde_json::to_string)
        .transpose()?;
    let event_insert = conn.execute(
        "INSERT INTO capture_events \
         (event_id,device_id,install_id,capture_session_id,stream_id,stream_kind,sequence, \
          source_wall_at,source_monotonic_ns,started_at,ended_at,timezone_id,utc_offset_minutes, \
          clock_uncertainty_ms,asset_id,manifest_digest,context_json,audio_role,audio_route,route_epoch,\
          received_at) \
         VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18,?19,?20,\
                 COALESCE(?21,strftime('%Y-%m-%dT%H:%M:%fZ','now')))",
        params![
            manifest.event_id,
            manifest.device_id,
            manifest.install_id,
            manifest.capture_session_id,
            manifest.stream_id,
            manifest.stream_kind.as_str(),
            manifest.sequence,
            manifest.source_wall_at,
            manifest.source_monotonic_ns.to_string(),
            manifest.started_at,
            manifest.ended_at,
            manifest.timezone_id,
            manifest.utc_offset_minutes,
            manifest.clock_uncertainty_ms,
            media.asset_id,
            manifest_digest,
            context_json,
            manifest.audio_role,
            manifest.audio_route,
            manifest.route_epoch.map(|v| v as i64),
            commit_stamp,
        ],
    );
    if let Err(error) = event_insert {
        if error.to_string().contains("UNIQUE constraint failed") {
            return Err(EnclaveError::Conflict(
                "idempotency conflict for stream sequence".into(),
            ));
        }
        return Err(error.into());
    }
    conn.execute(
        "INSERT INTO media_objects \
         (asset_id,event_id,object_key,object_generation,object_backend,mime_type,codec,byte_length,sha256,sample_rate,channels, \
          frame_count,width,height,scale,orientation,retain_until,created_at) \
         VALUES (?1,?2,?3,?4,CASE WHEN ?4 IS NULL THEN NULL ELSE 'current' END,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,\
                 COALESCE(?17,strftime('%Y-%m-%dT%H:%M:%fZ','now')))",
        params![
            media.asset_id,
            manifest.event_id,
            object_key,
            object_generation,
            media.mime_type,
            media.codec,
            media.byte_length,
            media.sha256.to_ascii_lowercase(),
            media.sample_rate,
            media.channels,
            media.frame_count,
            media.width,
            media.height,
            media.scale,
            media.orientation,
            super::isotime::add_seconds(&manifest.ended_at, 30.0 * 86_400.0),
            commit_stamp
        ],
    )?;
    record_browser_observation(conn, manifest, commit_stamp)?;
    let job_kind = if manifest.stream_kind.is_audio() {
        "gemini_audio"
    } else {
        "gemini_screen"
    };
    // `updated_at` is a retry-backoff deadline only for `state='retry_wait'`;
    // a freshly inserted `pending` job is selected without consulting it and
    // the lease scans order by `e.started_at,e.sequence,j.id`, never by it. So
    // binding the commit stamp here changes no scheduling decision — it only
    // keeps the stamp out of the live clock.
    conn.execute(
        "INSERT INTO media_processing_jobs \
         (event_id,job_kind,input_revision,processor_version,state,updated_at) \
         VALUES (?1,?2,?3,1,'pending',COALESCE(?4,strftime('%Y-%m-%dT%H:%M:%fZ','now')))",
        params![manifest.event_id, job_kind, manifest_digest, commit_stamp],
    )?;
    advance_contiguous_ack(conn, &manifest.stream_id)?;
    Ok(RecordOutcome::Created)
}

fn semantic_context_value(context: &CaptureContext, dedupe_version: u32) -> Value {
    let mut value = json!({
        "active_app": context.active_app,
        "active_url": context.active_url,
        "active_url_title": context.active_url_title,
        "browser_permission_status": context.browser_permission_status,
        "capture_status": context.capture_status,
        "display_id": context.display_id,
        "primary_bundle_id": context.primary_bundle_id,
        "primary_window_id": context.primary_window_id,
        "window_title": context.window_title,
    });
    // Version 1 bound the fingerprint to the full visible-window inventory,
    // whose fractional intersection ratios and z-order churn on every
    // background repaint — so semantically identical screens rarely matched.
    // Version 2 fingerprints only the literal foreground context above.
    if dedupe_version <= 1 {
        let map = value
            .as_object_mut()
            .expect("semantic context is an object");
        map.insert("visible_windows".into(), json!(context.visible_windows));
        map.insert(
            "visible_windows_truncated".into(),
            json!(context.visible_windows_truncated),
        );
    }
    value
}

fn semantic_context_fingerprint(context: &CaptureContext, dedupe_version: u32) -> Result<String> {
    Ok(sha256_hex(&serde_json::to_vec(&semantic_context_value(
        context,
        dedupe_version,
    ))?))
}

struct CanonicalReferenceTarget {
    device_id: String,
    install_id: String,
    capture_session_id: String,
    stream_id: String,
    sequence: i64,
    media_disposition: String,
    context_json: Option<String>,
    asset_id: String,
    media_sha256: String,
}

/// ADR-0022: the commit stamp bound in place of this row set's live-clock
/// column DEFAULTs.
///
/// `capture_sessions.created_at`, `capture_streams.created_at`,
/// `capture_events.received_at`, `browser_states_v2.created_at`,
/// `browser_observations_v2.created_at`, `media_objects.created_at` and
/// `media_processing_jobs.updated_at` are every one of them declared
/// `DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))` in `init_schema` — and NOT
/// in `SCHEMA_SQL`, which never declares these tables — and no legacy INSERT
/// binds any of them.
///
/// `None` is the LEGACY path: the parameter is NULL, the `COALESCE` collapses
/// to the identical `strftime` expression the column DEFAULT would have run,
/// and the row is byte-for-byte what it was before this parameter existed.
///
/// `Some(stamp)` is the WAL-authoritative path, where a live clock inside a
/// sealed plan's `apply()` would make the committed pages a function of wall
/// time rather than of the plan — breaking byte-exact replay.
///
/// **The stamp must be an ENCLAVE stamp**, minted by [`enclave_commit_stamp`]
/// on the route and carried in the plan — never a device-supplied field such
/// as `manifest.source_wall_at`. All seven columns above are enclave-side
/// facts (receipt time, row-creation time, scheduling state), the device's own
/// wall clock already has `capture_events.source_wall_at` and
/// `browser_observations_v2.observed_at`, and
/// `media_processing_jobs.updated_at` is compared as a RAW STRING against an
/// enclave `committed_at` by `media_worker::wal::claim` — one device stamp
/// that sorts above `now_iso()` wedges that account's media lane permanently.
/// `wal::is_canonical_commit_stamp` refuses any non-canonical stamp at plan
/// construction; see `wal::capture_event::CanonicalCaptureEventPlan::commit_stamp`
/// for the whole argument.
type CommitStamp<'a> = Option<&'a str>;

/// The enclave's own receipt clock for the ingest plan families, read ONCE per
/// request on the route and then carried in the plan.
///
/// Hoisted out of every `apply()` deliberately (ADR-0022 R7): a sealed plan's
/// committed pages must be a function of the plan, not of wall time. The
/// rendering is `isotime::format_epoch_millis`, which is byte-identical to
/// `media_worker::now_iso` and to `model_usage::settled_now_iso` — that
/// matters, because `media_worker::wal::claim` compares this stamp against
/// `now_iso()` as a raw string.
fn enclave_commit_stamp() -> String {
    super::isotime::format_epoch_millis(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as i64,
    )
}

fn record_reference_event(
    conn: &Connection,
    account_id: &str,
    manifest: &CaptureEventManifest,
    manifest_digest: &str,
) -> Result<RecordOutcome> {
    let tx = conn.unchecked_transaction()?;
    let outcome =
        record_reference_event_in_transaction(&tx, account_id, manifest, manifest_digest, None)?;
    tx.commit()?;
    Ok(outcome)
}

struct RecordedReferenceBatch {
    new_count: usize,
    duplicate_count: usize,
    committed_through_sequence: i64,
}

fn record_reference_batch(
    conn: &Connection,
    account_id: &str,
    events: &[CaptureEventManifest],
    manifest_digests: &[String],
) -> Result<RecordedReferenceBatch> {
    if events.is_empty() || events.len() != manifest_digests.len() {
        return Err(EnclaveError::InvalidRequest(
            "reference batch digest count is invalid".into(),
        ));
    }
    let tx = conn.unchecked_transaction()?;
    let mut new_count = 0usize;
    let mut duplicate_count = 0usize;
    for (index, (event, digest)) in events.iter().zip(manifest_digests).enumerate() {
        let outcome =
            match record_reference_event_in_transaction(&tx, account_id, event, digest, None) {
                Ok(outcome) => outcome,
                Err(EnclaveError::CaptureReference(reason)) => {
                    return Err(EnclaveError::CaptureReferenceBatch {
                        reason,
                        index,
                        sequence: event.sequence,
                    })
                }
                Err(error) => return Err(error),
            };
        match outcome {
            RecordOutcome::Created => new_count += 1,
            RecordOutcome::Duplicate => duplicate_count += 1,
        }
    }
    let committed_through_sequence = committed_through_sequence(&tx, &events[0].stream_id)?;
    tx.commit()?;
    Ok(RecordedReferenceBatch {
        new_count,
        duplicate_count,
        committed_through_sequence,
    })
}

fn record_reference_event_in_transaction(
    conn: &Connection,
    account_id: &str,
    manifest: &CaptureEventManifest,
    manifest_digest: &str,
    commit_stamp: CommitStamp<'_>,
) -> Result<RecordOutcome> {
    manifest.validate()?;
    if manifest.media_disposition != MediaDisposition::Reference {
        return Err(EnclaveError::InvalidRequest(
            "record_reference_event requires reference metadata".into(),
        ));
    }
    validate_id("account_id", account_id)?;
    if !validate_sha256(manifest_digest) {
        return Err(EnclaveError::InvalidRequest(
            "manifest digest is invalid".into(),
        ));
    }
    match preflight_source_event(conn, manifest, manifest_digest, None)? {
        PreflightOutcome::Duplicate { .. } => return Ok(RecordOutcome::Duplicate),
        PreflightOutcome::New => {}
    }

    let reference = manifest
        .reference
        .as_ref()
        .ok_or_else(|| EnclaveError::InvalidRequest("reference metadata is required".into()))?;
    let current_context = manifest.context.as_ref().ok_or_else(|| {
        EnclaveError::InvalidRequest("reference events require capture context".into())
    })?;
    if !reference
        .context_fingerprint
        .eq_ignore_ascii_case(&semantic_context_fingerprint(
            current_context,
            reference.dedupe_version,
        )?)
    {
        return Err(EnclaveError::CaptureReference(
            CaptureReferenceFailureReason::ContextFingerprintMismatch,
        ));
    }

    let canonical: Option<CanonicalReferenceTarget> = conn
        .query_row(
            "SELECT e.device_id,e.install_id,e.capture_session_id,e.stream_id,e.sequence,\
                    e.media_disposition,e.context_json,m.asset_id,m.sha256 \
             FROM capture_events e JOIN media_objects m ON m.event_id=e.event_id \
             WHERE e.event_id=?1",
            [&reference.canonical_event_id],
            |row| {
                Ok(CanonicalReferenceTarget {
                    device_id: row.get(0)?,
                    install_id: row.get(1)?,
                    capture_session_id: row.get(2)?,
                    stream_id: row.get(3)?,
                    sequence: row.get(4)?,
                    media_disposition: row.get(5)?,
                    context_json: row.get(6)?,
                    asset_id: row.get(7)?,
                    media_sha256: row.get(8)?,
                })
            },
        )
        .optional()?;
    let Some(canonical) = canonical else {
        return Err(EnclaveError::CaptureReference(
            CaptureReferenceFailureReason::CanonicalUnavailable,
        ));
    };
    if canonical.media_disposition != "canonical"
        || canonical.device_id != manifest.device_id
        || canonical.install_id != manifest.install_id
        || canonical.capture_session_id != manifest.capture_session_id
        || canonical.stream_id != manifest.stream_id
        || canonical.sequence >= manifest.sequence
        || canonical.asset_id != reference.canonical_asset_id
        || !canonical
            .media_sha256
            .eq_ignore_ascii_case(&reference.canonical_media_sha256)
    {
        return Err(EnclaveError::CaptureReference(
            CaptureReferenceFailureReason::TargetMismatch,
        ));
    }
    let canonical_context: CaptureContext = canonical
        .context_json
        .as_deref()
        .ok_or(EnclaveError::CaptureReference(
            CaptureReferenceFailureReason::CanonicalContextUnavailable,
        ))
        .and_then(|raw| {
            serde_json::from_str(raw).map_err(|_| {
                EnclaveError::CaptureReference(
                    CaptureReferenceFailureReason::CanonicalContextUnavailable,
                )
            })
        })?;
    // The transition check compares at the reference's dedupe version: a v2
    // reference matches its canonical when the literal foreground context is
    // unchanged, even if background window geometry drifted since the
    // canonical was recorded.
    if semantic_context_value(&canonical_context, reference.dedupe_version)
        != semantic_context_value(current_context, reference.dedupe_version)
    {
        return Err(EnclaveError::CaptureReference(
            CaptureReferenceFailureReason::ContextTransition,
        ));
    }

    // The session upsert's max/coalesce merge semantics are unchanged; only
    // `created_at` is added, and it is written by the INSERT half alone, never
    // by the DO UPDATE half, so a second event never rewrites the stamp the
    // session was created with.
    conn.execute(
        "INSERT INTO capture_sessions \
         (id,device_id,install_id,started_at,last_event_at,schema_version,ended_at,created_at) \
         VALUES (?1,?2,?3,?4,?5,2,CASE WHEN ?6 THEN ?5 ELSE NULL END,\
                 COALESCE(?7,strftime('%Y-%m-%dT%H:%M:%fZ','now'))) \
         ON CONFLICT(id) DO UPDATE SET \
           last_event_at=MAX(last_event_at,excluded.last_event_at), \
           ended_at=CASE WHEN ?6 THEN COALESCE(capture_sessions.ended_at,excluded.ended_at) \
                         ELSE capture_sessions.ended_at END",
        params![
            manifest.capture_session_id,
            manifest.device_id,
            manifest.install_id,
            manifest.started_at,
            manifest.ended_at,
            manifest.session_finished.unwrap_or(false),
            commit_stamp
        ],
    )?;
    conn.execute(
        "INSERT INTO capture_streams \
         (id,capture_session_id,device_id,stream_kind,created_at) \
         VALUES (?1,?2,?3,?4,COALESCE(?5,strftime('%Y-%m-%dT%H:%M:%fZ','now'))) \
         ON CONFLICT(id) DO NOTHING",
        params![
            manifest.stream_id,
            manifest.capture_session_id,
            manifest.device_id,
            manifest.stream_kind.as_str(),
            commit_stamp
        ],
    )?;
    let context_json = serde_json::to_string(current_context)?;
    let internal_asset_id = format!("reference-{}", manifest.event_id);
    let event_insert = conn.execute(
        "INSERT INTO capture_events \
         (event_id,device_id,install_id,capture_session_id,stream_id,stream_kind,sequence,\
          source_wall_at,source_monotonic_ns,started_at,ended_at,timezone_id,utc_offset_minutes,\
          clock_uncertainty_ms,asset_id,manifest_digest,context_json,media_disposition,\
          canonical_event_id,canonical_asset_id,canonical_media_sha256,perceptual_hash,\
          hamming_distance,pixel_change_ratio,context_fingerprint,dedupe_version,\
          audio_role,audio_route,route_epoch,received_at) \
         VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,\
                 'reference',?18,?19,?20,?21,?22,?23,?24,?25,?26,?27,?28,\
                 COALESCE(?29,strftime('%Y-%m-%dT%H:%M:%fZ','now')))",
        params![
            manifest.event_id,
            manifest.device_id,
            manifest.install_id,
            manifest.capture_session_id,
            manifest.stream_id,
            manifest.stream_kind.as_str(),
            manifest.sequence,
            manifest.source_wall_at,
            manifest.source_monotonic_ns.to_string(),
            manifest.started_at,
            manifest.ended_at,
            manifest.timezone_id,
            manifest.utc_offset_minutes,
            manifest.clock_uncertainty_ms,
            internal_asset_id,
            manifest_digest,
            context_json,
            reference.canonical_event_id,
            reference.canonical_asset_id,
            reference.canonical_media_sha256.to_ascii_lowercase(),
            reference.perceptual_hash.to_ascii_lowercase(),
            reference.hamming_distance,
            reference.pixel_change_ratio,
            reference.context_fingerprint.to_ascii_lowercase(),
            reference.dedupe_version,
            manifest.audio_role,
            manifest.audio_route,
            manifest.route_epoch.map(|v| v as i64),
            commit_stamp,
        ],
    );
    if let Err(error) = event_insert {
        if error.to_string().contains("UNIQUE constraint failed") {
            return Err(EnclaveError::Conflict(
                "idempotency conflict for stream sequence".into(),
            ));
        }
        return Err(error.into());
    }
    record_browser_observation(conn, manifest, commit_stamp)?;
    advance_contiguous_ack(conn, &manifest.stream_id)?;
    Ok(RecordOutcome::Created)
}

fn record_browser_observation(
    conn: &Connection,
    manifest: &CaptureEventManifest,
    commit_stamp: CommitStamp<'_>,
) -> Result<()> {
    let Some(context) = &manifest.context else {
        return Ok(());
    };
    if let Some(snapshot) = &context.browser_snapshot {
        let tabs_json = serde_json::to_string(&snapshot.tabs)?;
        conn.execute(
            "INSERT INTO browser_states_v2 \
             (state_key,browser_bundle_id,browser_name,permission_status,content_hash,tabs_json,\
              created_at) \
             VALUES (?1,?2,?3,?4,?5,?6,COALESCE(?7,strftime('%Y-%m-%dT%H:%M:%fZ','now'))) \
             ON CONFLICT(state_key) DO NOTHING",
            params![
                snapshot.state_key,
                snapshot.browser_bundle_id,
                snapshot.browser_name,
                snapshot.permission_status,
                snapshot.content_hash.to_ascii_lowercase(),
                tabs_json,
                commit_stamp
            ],
        )?;
        let existing_hash: String = conn.query_row(
            "SELECT content_hash FROM browser_states_v2 WHERE state_key=?1",
            [&snapshot.state_key],
            |row| row.get(0),
        )?;
        if !existing_hash.eq_ignore_ascii_case(&snapshot.content_hash) {
            return Err(EnclaveError::Conflict(
                "browser state key was reused with different content".into(),
            ));
        }
    }
    let state_key = match context.browser_state_key.as_deref() {
        Some(key) => conn
            .query_row(
                "SELECT state_key FROM browser_states_v2 WHERE state_key=?1",
                [key],
                |row| row.get::<_, String>(0),
            )
            .optional()?,
        None => None,
    };
    conn.execute(
        "INSERT INTO browser_observations_v2 \
         (observation_id,event_id,observed_at,state_key,context_status,active_url,active_title,\
          created_at) \
         VALUES (?1,?1,?2,?3,?4,?5,?6,COALESCE(?7,strftime('%Y-%m-%dT%H:%M:%fZ','now')))",
        params![
            manifest.event_id,
            manifest.source_wall_at,
            state_key,
            context.capture_status,
            context.active_url,
            context.active_url_title,
            commit_stamp
        ],
    )?;
    Ok(())
}

fn advance_contiguous_ack(conn: &Connection, stream_id: &str) -> Result<()> {
    let current: i64 = conn.query_row(
        "SELECT committed_through_sequence FROM capture_streams WHERE id=?1",
        [stream_id],
        |row| row.get(0),
    )?;
    let mut next = current + 1;
    loop {
        let exists: i64 = conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM capture_events WHERE stream_id=?1 AND sequence=?2)",
            params![stream_id, next],
            |row| row.get(0),
        )?;
        if exists == 0 {
            break;
        }
        next += 1;
    }
    let advanced = next - 1;
    if advanced > current {
        conn.execute(
            "UPDATE capture_streams SET committed_through_sequence=?1 WHERE id=?2",
            params![advanced, stream_id],
        )?;
    }
    Ok(())
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AudioTurn {
    pub turn_id: String,
    pub start_ms: i64,
    pub end_ms: i64,
    pub speaker_local_id: String,
    pub text: String,
    pub language: Option<String>,
    #[serde(default)]
    pub speaker_name: Option<String>,
    #[serde(default)]
    pub speaker_name_confidence: Option<f64>,
    #[serde(default)]
    pub speaker_name_evidence: Option<String>,
    #[serde(default)]
    pub speaker_name_kind: Option<String>,
    #[serde(default)]
    pub speaker_name_subject_turn_id: Option<String>,
    #[serde(default)]
    pub speaker_name_target_turn_id: Option<String>,
    #[serde(default)]
    pub person_facts: Vec<PersonFact>,
    #[serde(default)]
    pub overlap: bool,
    #[serde(default)]
    pub quality_flags: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PersonFact {
    pub predicate: String,
    pub value: String,
    pub evidence: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AudioResult {
    turns: Vec<AudioTurn>,
}

pub fn parse_audio_result(raw: &str, duration_ms: i64) -> Result<Vec<AudioTurn>> {
    let result: AudioResult = serde_json::from_str(raw)?;
    if result.turns.len() > MAX_TURNS {
        return Err(EnclaveError::InvalidRequest(
            "audio result has too many turns".into(),
        ));
    }
    let mut ids = HashSet::new();
    let mut previous_start = -1;
    let mut previous_end = 0;
    let mut previous_overlap = false;
    for turn in &result.turns {
        validate_id("turn_id", &turn.turn_id)?;
        validate_id("speaker_local_id", &turn.speaker_local_id)?;
        if !ids.insert(turn.turn_id.as_str()) {
            return Err(EnclaveError::InvalidRequest(
                "audio result has duplicate turn_id".into(),
            ));
        }
        if turn.start_ms < 0
            || turn.end_ms <= turn.start_ms
            || turn.end_ms > duration_ms
            || turn.start_ms < previous_start
        {
            return Err(EnclaveError::InvalidRequest(
                "audio turn timestamps are invalid".into(),
            ));
        }
        if turn.start_ms < previous_end && !turn.overlap && !previous_overlap {
            return Err(EnclaveError::InvalidRequest(
                "audio turns overlap without an overlap marker".into(),
            ));
        }
        if turn.text.is_empty()
            || turn.text.chars().count() > MAX_TEXT_LEN
            || turn.text.bytes().any(|byte| byte == 0)
        {
            return Err(EnclaveError::InvalidRequest(
                "audio turn text is invalid".into(),
            ));
        }
        if turn
            .language
            .as_ref()
            .is_some_and(|language| language.len() > 32 || language.bytes().any(|byte| byte == 0))
        {
            return Err(EnclaveError::InvalidRequest(
                "audio turn language is invalid".into(),
            ));
        }
        if turn.person_facts.len() > 20
            || turn.person_facts.iter().any(|fact| {
                !matches!(
                    fact.predicate.as_str(),
                    "role"
                        | "organization"
                        | "relationship"
                        | "preference"
                        | "responsibility"
                        | "contact"
                        | "location"
                        | "other"
                ) || fact.value.trim().is_empty()
                    || fact.value.len() > 2_000
                    || fact.evidence.trim().is_empty()
                    || fact.evidence.len() > 2_000
            })
        {
            return Err(EnclaveError::InvalidRequest(
                "audio turn person facts are invalid".into(),
            ));
        }
        if turn
            .speaker_name
            .as_ref()
            .is_some_and(|name| name.is_empty() || name.len() > 256 || name.bytes().any(|b| b == 0))
            || turn
                .speaker_name_confidence
                .is_some_and(|confidence| !(0.0..=1.0).contains(&confidence))
            || turn.speaker_name_evidence.as_ref().is_some_and(|evidence| {
                evidence.is_empty() || evidence.len() > 2_000 || evidence.bytes().any(|b| b == 0)
            })
        {
            return Err(EnclaveError::InvalidRequest(
                "audio turn speaker-name evidence is invalid".into(),
            ));
        }
        if turn.quality_flags.len() > 16
            || turn
                .quality_flags
                .iter()
                .any(|flag| flag.len() > 64 || flag.bytes().any(|byte| byte == 0))
        {
            return Err(EnclaveError::InvalidRequest(
                "audio turn quality flags are invalid".into(),
            ));
        }
        previous_start = turn.start_ms;
        previous_end = turn.end_ms;
        previous_overlap = turn.overlap;
    }
    Ok(result.turns)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::Connection;
    use serde_json::json;

    fn valid_manifest() -> CaptureEventManifest {
        serde_json::from_value(json!({
            "schema_version": 2,
            "event_id": "019fbab2-8413-7053-9117-eb249b72b15b",
            "device_id": "device-1",
            "install_id": "install-1",
            "capture_session_id": "session-1",
            "stream_id": "system-1",
            "stream_kind": "system_audio",
            "sequence": 7,
            "source_wall_at": "2026-07-31T18:00:00.000Z",
            "source_monotonic_ns": 9000000000_u64,
            "started_at": "2026-07-31T18:00:00.000Z",
            "ended_at": "2026-07-31T18:00:05.000Z",
            "timezone_id": "America/New_York",
            "utc_offset_minutes": -240,
            "clock_uncertainty_ms": 24,
            "media": {
                "asset_id": "019fbab2-8413-7053-9117-eb249b72b15c",
                "mime_type": "audio/m4a",
                "codec": "aac",
                "byte_length": 12,
                "sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "sample_rate": 48000,
                "channels": 2,
                "frame_count": 240000
            },
            "context": {
                "capture_status": "stable",
                "active_app": "Google Chrome",
                "primary_bundle_id": "com.google.Chrome",
                "window_title": "Weekly planning",
                "display_id": 42,
                "active_url": "https://meet.google.com/abc-defg-hij?authuser=0",
                "active_url_title": "Weekly planning",
                "browser_permission_status": "granted"
            }
        }))
        .expect("valid fixture")
    }

    fn valid_screen_manifest(
        sequence: i64,
        event_id: &str,
        asset_id: &str,
    ) -> CaptureEventManifest {
        let mut manifest: CaptureEventManifest = serde_json::from_value(json!({
            "schema_version": 2,
            "event_id": event_id,
            "device_id": "device-1",
            "install_id": "install-1",
            "capture_session_id": "session-1",
            "stream_id": "screen-1",
            "stream_kind": "mac_screen",
            "sequence": sequence,
            "source_wall_at": "2026-07-31T18:00:00.000Z",
            "source_monotonic_ns": 9000000000_u64 + sequence as u64,
            "started_at": "2026-07-31T18:00:00.000Z",
            "ended_at": "2026-07-31T18:00:02.000Z",
            "timezone_id": "America/New_York",
            "utc_offset_minutes": -240,
            "clock_uncertainty_ms": 24,
            "media": {
                "asset_id": asset_id,
                "mime_type": "image/jpeg",
                "codec": "jpeg",
                "byte_length": 12,
                "sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "width": 1280,
                "height": 720
            },
            "context": {
                "capture_status": "stable",
                "active_app": "Google Chrome",
                "primary_bundle_id": "com.google.Chrome",
                "primary_window_id": 9,
                "window_title": "Weekly planning",
                "display_id": 42,
                "active_url": "https://meet.google.com/abc-defg-hij?authuser=0",
                "active_url_title": "Weekly planning",
                "browser_permission_status": "granted",
                "visible_windows": [{"bundle_id":"com.google.Chrome","window_id":9}],
                "visible_windows_truncated": false
            }
        }))
        .expect("valid screen fixture");
        manifest.source_monotonic_ns += sequence as u64;
        manifest
    }

    fn reference_to(
        canonical: &CaptureEventManifest,
        sequence: i64,
        event_id: &str,
    ) -> CaptureEventManifest {
        let mut reference = canonical.clone();
        let media = canonical.media.as_ref().expect("canonical media");
        let context = canonical.context.as_ref().expect("canonical context");
        reference.event_id = event_id.into();
        reference.sequence = sequence;
        reference.source_monotonic_ns += sequence as u64 + 1;
        reference.media_disposition = MediaDisposition::Reference;
        reference.media = None;
        reference.reference = Some(ScreenReferenceDescriptor {
            canonical_event_id: canonical.event_id.clone(),
            canonical_asset_id: media.asset_id.clone(),
            canonical_media_sha256: media.sha256.clone(),
            perceptual_hash: "0123456789abcdef".into(),
            hamming_distance: 2,
            pixel_change_ratio: 0.004,
            context_fingerprint: semantic_context_fingerprint(context, 1).unwrap(),
            dedupe_version: 1,
        });
        reference
    }

    #[test]
    fn screen_context_fingerprint_matches_macos_fractional_geometry_vector() {
        let context: CaptureContext = serde_json::from_value(json!({
            "capture_status": "stable",
            "active_app": "Safari",
            "primary_bundle_id": "com.apple.Safari",
            "primary_window_id": 123,
            "window_title": "Meeting — José",
            "display_id": 1,
            "active_url": "https://example.com/a/b?x=1",
            "active_url_title": "Meeting",
            "browser_permission_status": "granted",
            "visible_windows": [{
                "window_id": 123,
                "owner_pid": 456,
                "bundle_id": "com.apple.Safari",
                "app_name": "Safari",
                "window_title": "Meeting — José",
                "intersection_ratio": 1.0 / 3.0,
                "z_index": 0
            }],
            "visible_windows_truncated": false
        }))
        .unwrap();

        assert_eq!(
            semantic_context_fingerprint(&context, 1).unwrap(),
            "fba21879bdcd32f61bed713119be4eda7a9736e3fff52ea1576f284fba83dabc"
        );
        // Version 2 fingerprints the same context without the volatile
        // visible-window inventory. This vector is pinned cross-language with
        // the macOS client (ScreenTransportTests).
        assert_eq!(
            semantic_context_fingerprint(&context, 2).unwrap(),
            "00e628e17b45c3462a25e7396c88503efbda2a9dc4f3f5234ac45d34728480ea"
        );
    }

    #[test]
    fn screen_reference_bounds_are_versioned() {
        let canonical = valid_screen_manifest(0, "screen-event-0", "screen-asset-0");
        let make = |dedupe_version: u32, hamming_distance: u32, pixel_change_ratio: f64| {
            let mut manifest = reference_to(&canonical, 1, "screen-event-1");
            let context = canonical.context.as_ref().unwrap();
            let descriptor = manifest.reference.as_mut().unwrap();
            descriptor.dedupe_version = dedupe_version;
            descriptor.hamming_distance = hamming_distance;
            descriptor.pixel_change_ratio = pixel_change_ratio;
            descriptor.context_fingerprint =
                semantic_context_fingerprint(context, dedupe_version).unwrap();
            manifest
        };
        // Version 1 keeps its historical bounds.
        assert!(make(1, 3, 0.01).validate().is_ok());
        assert!(make(1, 4, 0.004).validate().is_err());
        assert!(make(1, 2, 0.011).validate().is_err());
        // Version 2 absorbs idle jitter but still rejects real change.
        assert!(make(2, 8, 0.03).validate().is_ok());
        assert!(make(2, 9, 0.004).validate().is_err());
        assert!(make(2, 2, 0.031).validate().is_err());
        // Unknown future versions stay rejected.
        assert!(make(3, 1, 0.001).validate().is_err());
    }

    #[test]
    fn v2_reference_survives_background_window_drift_that_v1_rejects() {
        let conn = Connection::open_in_memory().unwrap();
        init_schema(&conn).unwrap();
        let canonical = valid_screen_manifest(0, "screen-event-0", "screen-asset-0");
        record_source_event(
            &conn,
            "account-1",
            &canonical,
            &manifest_digest(&canonical).unwrap(),
            "object-1",
        )
        .unwrap();

        // Pixel-identical screen, but a background window appeared between
        // captures, so the visible-window inventory drifted.
        let drift = json!([
            {"bundle_id":"com.google.Chrome","window_id":9},
            {"bundle_id":"com.apple.dock","window_id":11}
        ]);

        let mut v1 = reference_to(&canonical, 1, "screen-event-1");
        v1.context.as_mut().unwrap().visible_windows = Some(drift.clone());
        v1.reference.as_mut().unwrap().context_fingerprint =
            semantic_context_fingerprint(v1.context.as_ref().unwrap(), 1).unwrap();
        assert!(matches!(
            record_reference_event(&conn, "account-1", &v1, &"b".repeat(64)),
            Err(EnclaveError::CaptureReference(
                CaptureReferenceFailureReason::ContextTransition
            ))
        ));

        let mut v2 = reference_to(&canonical, 1, "screen-event-2");
        v2.context.as_mut().unwrap().visible_windows = Some(drift);
        let descriptor = v2.reference.as_mut().unwrap();
        descriptor.dedupe_version = 2;
        descriptor.context_fingerprint =
            semantic_context_fingerprint(v2.context.as_ref().unwrap(), 2).unwrap();
        assert!(matches!(
            record_reference_event(&conn, "account-1", &v2, &"c".repeat(64)),
            Ok(RecordOutcome::Created)
        ));
    }

    #[test]
    fn media_dek_route_is_exactly_dual_path() {
        // ADR-0022 F1: the DEK bootstrap reads through the routed dual-path
        // surface for BOTH populations, submits the sealed install plan for a
        // selected user, and keeps the exact legacy compare-and-install for
        // everyone else. A Conflict from the submit converges by re-reading
        // the winner, never by rebuilding the plan (R5).
        let source = include_str!("media.rs");
        let start = source
            .find(concat!("async fn load_or_create_", "media_dek"))
            .unwrap();
        let end = source
            .find(concat!("async fn verify_existing_", "media"))
            .unwrap();
        let route = &source[start..end];
        assert_eq!(
            route.matches(concat!("is_wal_", "authoritative(")).count(),
            1
        );
        assert_eq!(
            route
                .matches(concat!("wal_authoritative_", "submit("))
                .count(),
            1
        );
        // Exactly one legacy write install; every read goes through the
        // routed helper (which itself is the only wal_authoritative_read).
        assert_eq!(route.matches(concat!(".with_", "user(")).count(), 1);
        assert_eq!(
            route
                .matches(concat!("read_media_dek_", "wrapped(state, user_id)"))
                .count(),
            2
        );
        assert_eq!(
            route
                .matches(concat!("wal_authoritative_", "read("))
                .count(),
            1
        );
        // The plan is constructed exactly once, above any retry/converge
        // path, from the candidate the caller minted (R5).
        assert_eq!(
            route
                .matches(concat!("MediaDekInstallPlan::", "new("))
                .count(),
            1
        );
    }

    /// ADR-0022: the ingest route is dual-path, and structurally so.
    ///
    /// The preflight read is the canonical arm's whole residual, and it has to
    /// route: a selected user's `with_user` preflight would refuse before any
    /// plan was reached. Both dispositions must submit, because a mac_screen
    /// stream interleaves canonical screenshots and reference pointers by
    /// sequence and `advance_contiguous_ack` walks only while the next
    /// sequence exists — one migrated arm would stall the stream at the first
    /// refused event of the other.
    ///
    /// Falsifiability, checked by sabotage: deleting either
    /// `wal_authoritative_submit` call drops that count to 1; routing the
    /// preflight back to `with_user` drops the `wal_authoritative_read` count
    /// to 0 and raises the `with_user` count to 2.
    #[test]
    fn capture_event_route_is_exactly_dual_path_on_both_dispositions() {
        let source = include_str!("media.rs");
        let start = source
            .find(concat!("async fn upload_capture_", "event"))
            .unwrap();
        let end = source
            .find(concat!("fn capture_requires_recording_", "lease"))
            .unwrap();
        let route = &source[start..end];
        assert_eq!(
            route.matches(concat!("is_wal_", "authoritative(")).count(),
            1
        );
        // One routed preflight read for the selected branch.
        assert_eq!(
            route
                .matches(concat!("wal_authoritative_", "read("))
                .count(),
            1
        );
        // BOTH dispositions submit: canonical and reference.
        assert_eq!(
            route
                .matches(concat!("wal_authoritative_", "submit("))
                .count(),
            2
        );
        assert_eq!(
            route
                .matches(concat!("CanonicalCaptureEventPlan::", "new("))
                .count(),
            1
        );
        assert_eq!(
            route
                .matches(concat!("MediaReferenceEventPlan::", "new("))
                .count(),
            1
        );
        // The legacy branch keeps its exact preflight + write + save trio and
        // nothing more.
        assert_eq!(route.matches(concat!(".with_", "user(")).count(), 2);
        assert_eq!(route.matches(concat!(".save_", "user(")).count(), 2);
        // The D4 gate is gone: ingest is migrated, so nothing here may refuse
        // a selected user on the grounds that the domain is deferred.
        assert!(!route.contains(concat!("wal_domain_", "refusal")));
        // Both submits carry the rebase reason out of band or the client's
        // durable outbox retries an unrebasable event forever.
        assert_eq!(route.matches("refusal.observed()").count(), 1);
    }

    /// The LEGACY path stays byte-intact: `commit_stamp: None` leaves every
    /// clock DEFAULT to the database exactly as it was before the parameter
    /// existed. The WAL branch is entered only under selection, so an
    /// unselected user's rows must still carry the live clock.
    ///
    /// Falsifiability, checked by sabotage: passing `Some(...)` from the
    /// legacy wrappers stamps these columns with the manifest's
    /// `source_wall_at` and every assertion below fails.
    #[test]
    fn the_legacy_writers_still_leave_every_clock_default_to_the_database() {
        let conn = Connection::open_in_memory().unwrap();
        init_schema(&conn).unwrap();
        let canonical = valid_screen_manifest(0, "screen-event-0", "screen-asset-0");
        record_source_event(&conn, "account-1", &canonical, &"a".repeat(64), "object-0").unwrap();
        let reference = reference_to(&canonical, 1, "screen-event-1");
        record_reference_event(&conn, "account-1", &reference, &"b".repeat(64)).unwrap();

        let stamps: Vec<String> = conn
            .query_row(
                "SELECT
                    (SELECT created_at FROM capture_sessions WHERE id='session-1'),
                    (SELECT created_at FROM capture_streams WHERE id='screen-1'),
                    (SELECT received_at FROM capture_events WHERE event_id='screen-event-0'),
                    (SELECT created_at FROM media_objects WHERE asset_id='screen-asset-0'),
                    (SELECT updated_at FROM media_processing_jobs
                     WHERE event_id='screen-event-0'),
                    (SELECT received_at FROM capture_events WHERE event_id='screen-event-1'),
                    (SELECT created_at FROM browser_observations_v2
                     WHERE event_id='screen-event-1')",
                [],
                |row| {
                    Ok(vec![
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, String>(4)?,
                        row.get::<_, String>(5)?,
                        row.get::<_, String>(6)?,
                    ])
                },
            )
            .unwrap();
        // 2026-07-31 is the fixture's wall clock; SQLite's `now` is the suite's
        // real one, so a bound stamp and a live DEFAULT are never equal.
        for stamp in &stamps {
            assert_ne!(
                stamp, "2026-07-31T18:00:00.000Z",
                "the legacy path must not bind the manifest stamp"
            );
            assert!(
                parse_epoch_millis(stamp).is_some(),
                "the DEFAULT must still produce an ISO-8601 stamp: {stamp}"
            );
        }
    }

    #[test]
    fn reference_batch_route_is_exactly_dual_path() {
        // ADR-0022: the WAL-authoritative branch settles through the routed
        // surfaces only, and the legacy branch keeps its exact write+save
        // pair; the plan's apply shares record_reference_event_in_transaction
        // with the legacy path, so the branches cannot drift semantically.
        let source = include_str!("media.rs");
        let start = source
            .find(concat!("async fn upload_screen_", "reference_batch"))
            .unwrap();
        let end = source
            .find(concat!("async fn upload_capture_", "event"))
            .unwrap();
        let route = &source[start..end];
        assert_eq!(
            route.matches(concat!("is_wal_", "authoritative(")).count(),
            1
        );
        assert_eq!(
            route
                .matches(concat!("wal_authoritative_", "read("))
                .count(),
            1
        );
        assert_eq!(
            route
                .matches(concat!("wal_authoritative_", "submit("))
                .count(),
            1
        );
        assert_eq!(route.matches(concat!(".with_", "user(")).count(), 1);
        assert_eq!(route.matches(concat!(".save_", "user(")).count(), 1);
        let submit_at = route
            .find(concat!("wal_authoritative_", "submit("))
            .unwrap();
        let legacy_write_at = route.find(concat!(".with_", "user(")).unwrap();
        assert!(
            submit_at < legacy_write_at,
            "the settled branch must precede the legacy write"
        );
    }

    #[test]
    fn batch_receipt_advertises_max_dedupe_version() {
        let receipt = ScreenReferenceBatchAccepted {
            batch_id: "b".repeat(64),
            stream_id: "stream-1".into(),
            first_sequence: 1,
            last_sequence: 2,
            new_count: 1,
            duplicate_count: 1,
            committed_through_sequence: 2,
            max_screen_dedupe_version: MAX_SCREEN_DEDUPE_VERSION,
        };
        let value = serde_json::to_value(&receipt).unwrap();
        assert_eq!(value["max_screen_dedupe_version"], json!(2));
    }

    #[test]
    fn missing_screen_reference_has_a_stable_rebase_reason() {
        let conn = Connection::open_in_memory().unwrap();
        init_schema(&conn).unwrap();
        let canonical = valid_screen_manifest(0, "screen-event-0", "screen-asset-0");
        let reference = reference_to(&canonical, 1, "screen-event-1");

        assert!(matches!(
            record_reference_event(&conn, "account-1", &reference, &"b".repeat(64)),
            Err(EnclaveError::CaptureReference(
                crate::error::CaptureReferenceFailureReason::CanonicalUnavailable
            ))
        ));
    }

    #[tokio::test]
    async fn screen_reference_rebase_response_is_content_free_and_machine_readable() {
        let response = EnclaveError::CaptureReference(
            CaptureReferenceFailureReason::ContextFingerprintMismatch,
        )
        .into_response();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body = axum::body::to_bytes(response.into_body(), 1_024)
            .await
            .unwrap();
        assert_eq!(
            serde_json::from_slice::<Value>(&body).unwrap(),
            json!({
                "error": "screen_reference_rebase_required",
                "reason": "context_fingerprint_mismatch"
            })
        );
    }

    #[tokio::test]
    async fn batched_screen_reference_rebase_identifies_only_index_sequence_and_reason() {
        let response = EnclaveError::CaptureReferenceBatch {
            reason: CaptureReferenceFailureReason::CanonicalUnavailable,
            index: 7,
            sequence: 42,
        }
        .into_response();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body = axum::body::to_bytes(response.into_body(), 1_024)
            .await
            .unwrap();
        assert_eq!(
            serde_json::from_slice::<Value>(&body).unwrap(),
            json!({
                "error": "screen_reference_rebase_required",
                "reason": "canonical_unavailable",
                "index": 7,
                "sequence": 42
            })
        );
    }

    #[test]
    fn capture_failure_telemetry_uses_only_fixed_reason_classes() {
        assert_eq!(
            CaptureIngestFailureReason::ContextFingerprintMismatch.as_str(),
            "context_fingerprint_mismatch"
        );
        assert_eq!(
            recording_entitlement_failure_reason(StatusCode::PAYMENT_REQUIRED),
            CaptureIngestFailureReason::RecordingLeaseInactive
        );
        assert_eq!(
            recording_entitlement_failure_reason(StatusCode::SERVICE_UNAVAILABLE),
            CaptureIngestFailureReason::RecordingLeaseUnavailable
        );
    }

    #[test]
    fn manifest_accepts_authoritative_clocks_and_exact_browser_url() {
        let manifest = valid_manifest();
        manifest.validate().expect("manifest should validate");
        assert_eq!(manifest.sequence, 7);
        assert_eq!(manifest.source_monotonic_ns, 9_000_000_000);
        assert_eq!(manifest.duration_ms().unwrap(), 5_000);
        assert_eq!(
            manifest.context.unwrap().active_url.as_deref(),
            Some("https://meet.google.com/abc-defg-hij?authuser=0")
        );
    }

    #[test]
    fn manifest_rejects_invalid_hash_time_and_sequence() {
        let mut manifest = valid_manifest();
        manifest.media.as_mut().unwrap().sha256 = "not-a-hash".into();
        assert!(manifest.validate().is_err());

        let mut manifest = valid_manifest();
        manifest.ended_at = "2026-07-31T17:59:59.000Z".into();
        assert!(manifest.validate().is_err());

        let mut manifest = valid_manifest();
        manifest.sequence = -1;
        assert!(manifest.validate().is_err());
    }

    #[test]
    fn media_schema_is_replay_safe_and_separates_browser_state_from_observation() {
        let conn = Connection::open_in_memory().unwrap();
        init_schema(&conn).unwrap();
        init_schema(&conn).unwrap();

        for table in [
            "capture_sessions",
            "capture_streams",
            "capture_events",
            "media_objects",
            "browser_states_v2",
            "browser_observations_v2",
            "media_processing_jobs",
            "media_work_units",
            "media_work_members",
            "speaker_observations",
            "speaker_observation_sources",
            "voice_profiles",
            "voice_samples",
            "voice_profile_proposals",
            "voice_profile_revisions",
            "voice_sample_profile_assignments",
            "voice_profile_proposal_profiles",
            "voice_profile_proposal_samples",
            "identity_evidence",
            "people",
            "person_name_claims",
            "profile_identity_bindings",
            "person_facts",
        ] {
            let count: i64 = conn
                .query_row(
                    "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?1",
                    [table],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(count, 1, "missing {table}");
        }
    }

    #[test]
    fn legacy_unique_names_migrate_to_non_keyed_claims_without_merging_people() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE people (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                display_name TEXT,
                normalized_name TEXT UNIQUE,
                status TEXT NOT NULL DEFAULT 'unknown',
                created_at TEXT NOT NULL DEFAULT '2026-01-01T00:00:00.000Z',
                updated_at TEXT NOT NULL DEFAULT '2026-01-01T00:00:00.000Z'
             );
             INSERT INTO people(display_name,normalized_name,status)
             VALUES ('John Smith','john smith','identified');",
        )
        .unwrap();

        init_schema(&conn).unwrap();
        assert_eq!(
            conn.query_row("SELECT normalized_name FROM people WHERE id=1", [], |row| {
                row.get::<_, Option<String>>(0)
            },)
                .unwrap(),
            None
        );
        let migrated: (String, String, String) = conn
            .query_row(
                "SELECT name,normalized_name,status FROM person_name_claims WHERE person_id=1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();
        assert_eq!(
            migrated,
            ("John Smith".into(), "john smith".into(), "accepted".into())
        );

        conn.execute(
            "INSERT INTO people(display_name,normalized_name,status) VALUES (?1,NULL,'identified')",
            ["John Smith"],
        )
        .unwrap();
        assert_eq!(
            conn.query_row(
                "SELECT COUNT(*) FROM people WHERE display_name='John Smith'",
                [],
                |row| row.get::<_, i64>(0),
            )
            .unwrap(),
            2
        );
    }

    #[test]
    fn person_evidence_pagination_is_stable_and_never_exposes_voice_vectors() {
        let conn = Connection::open_in_memory().unwrap();
        init_schema(&conn).unwrap();
        conn.execute(
            "INSERT INTO people(display_name,status) VALUES ('John Garcia','identified')",
            [],
        )
        .unwrap();
        for ordinal in 1..=3 {
            conn.execute(
                "INSERT INTO identity_evidence(person_id,kind,claimed_name,evidence_json,score,status) \
                 VALUES (1,'audio_self_identification','John Garcia',?1,0.99,'accepted')",
                [format!(r#"{{"ordinal":{ordinal}}}"#)],
            )
            .unwrap();
        }

        let (first, cursor) = load_person_evidence(&conn, 1, None, 2).unwrap();
        assert_eq!(first.iter().map(|item| item.id).collect::<Vec<_>>(), [3, 2]);
        assert_eq!(cursor, Some(2));
        let encoded = serde_json::to_string(&first).unwrap();
        assert!(!encoded.contains("embedding"));
        assert!(!encoded.contains("centroid"));

        let (second, cursor) = load_person_evidence(&conn, 1, cursor, 2).unwrap();
        assert_eq!(second.iter().map(|item| item.id).collect::<Vec<_>>(), [1]);
        assert_eq!(cursor, None);
    }

    #[test]
    fn identical_event_is_duplicate_but_changed_manifest_conflicts() {
        let conn = Connection::open_in_memory().unwrap();
        init_schema(&conn).unwrap();
        let manifest = valid_manifest();
        let digest_1 = "a".repeat(64);
        let digest_2 = "b".repeat(64);
        let first = record_source_event_with_generation(
            &conn,
            "account-1",
            &manifest,
            &digest_1,
            "object-1",
            Some(42),
        )
        .unwrap();
        assert_eq!(first, RecordOutcome::Created);
        assert_eq!(
            conn.query_row(
                "SELECT object_generation FROM media_objects WHERE object_key='object-1'",
                [],
                |row| row.get::<_, i64>(0),
            )
            .unwrap(),
            42
        );
        assert_eq!(
            conn.query_row(
                "SELECT object_backend FROM media_objects WHERE object_key='object-1'",
                [],
                |row| row.get::<_, String>(0),
            )
            .unwrap(),
            "current"
        );

        let duplicate =
            record_source_event(&conn, "account-1", &manifest, &digest_1, "object-1").unwrap();
        assert_eq!(duplicate, RecordOutcome::Duplicate);

        let conflict =
            record_source_event(&conn, "account-1", &manifest, &digest_2, "object-2").unwrap_err();
        assert!(conflict.to_string().contains("idempotency"));
    }

    #[test]
    fn screen_reference_retains_observation_without_media_or_model_job() {
        let conn = Connection::open_in_memory().unwrap();
        init_schema(&conn).unwrap();
        let canonical = valid_screen_manifest(0, "screen-event-0", "screen-asset-0");
        record_source_event(&conn, "account-1", &canonical, &"a".repeat(64), "object-0").unwrap();
        let reference = reference_to(&canonical, 1, "screen-event-1");
        assert_eq!(
            record_reference_event(&conn, "account-1", &reference, &"b".repeat(64)).unwrap(),
            RecordOutcome::Created
        );

        let (disposition, canonical_id, hamming, ratio): (String, String, i64, f64) = conn
            .query_row(
                "SELECT media_disposition,canonical_event_id,hamming_distance,pixel_change_ratio \
                 FROM capture_events WHERE event_id='screen-event-1'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .unwrap();
        assert_eq!(disposition, "reference");
        assert_eq!(canonical_id, "screen-event-0");
        assert_eq!(hamming, 2);
        assert_eq!(ratio, 0.004);
        assert_eq!(
            conn.query_row(
                "SELECT COUNT(*) FROM media_objects WHERE event_id='screen-event-1'",
                [],
                |row| row.get::<_, i64>(0),
            )
            .unwrap(),
            0
        );
        assert_eq!(
            conn.query_row(
                "SELECT COUNT(*) FROM media_processing_jobs WHERE event_id='screen-event-1'",
                [],
                |row| row.get::<_, i64>(0),
            )
            .unwrap(),
            0
        );
        assert_eq!(committed_through_sequence(&conn, "screen-1").unwrap(), 1);
        let status = load_capture_status(&conn, "screen-event-1")
            .unwrap()
            .expect("reference status");
        assert_eq!(status.processing_state, "ready");
        assert_eq!(status.attempt_count, 0);
    }

    #[test]
    fn screen_reference_is_idempotent_but_changed_evidence_conflicts() {
        let conn = Connection::open_in_memory().unwrap();
        init_schema(&conn).unwrap();
        let canonical = valid_screen_manifest(0, "screen-event-0", "screen-asset-0");
        record_source_event(&conn, "account-1", &canonical, &"a".repeat(64), "object-0").unwrap();
        let reference = reference_to(&canonical, 1, "screen-event-1");
        record_reference_event(&conn, "account-1", &reference, &"b".repeat(64)).unwrap();
        assert_eq!(
            record_reference_event(&conn, "account-1", &reference, &"b".repeat(64)).unwrap(),
            RecordOutcome::Duplicate
        );
        assert!(
            record_reference_event(&conn, "account-1", &reference, &"c".repeat(64))
                .unwrap_err()
                .to_string()
                .contains("idempotency")
        );
    }

    #[test]
    fn reference_batch_validation_is_bounded_contiguous_and_serializer_independent() {
        let canonical = valid_screen_manifest(0, "screen-event-0", "screen-asset-0");
        let cross_language_vector = vec![
            reference_to(&canonical, 43, "reference-event-1"),
            reference_to(&canonical, 44, "reference-event-2"),
        ];
        assert_eq!(
            reference_batch_id(&cross_language_vector).unwrap(),
            "e8e70a04d46c07aa978325fc8bec5bc7e8a7d67a1f89d595facc835cbe234709"
        );
        let references = vec![
            reference_to(&canonical, 1, "screen-event-1"),
            reference_to(&canonical, 2, "screen-event-2"),
        ];
        let batch_id = reference_batch_id(&references).unwrap();
        let request = ScreenReferenceBatchRequest {
            schema_version: 1,
            batch_id: batch_id.clone(),
            events: references.clone(),
        };
        let validated = validate_reference_batch(&request).unwrap();
        assert_eq!(validated.first_sequence, 1);
        assert_eq!(validated.last_sequence, 2);
        assert_eq!(validated.event_ids, ["screen-event-1", "screen-event-2"]);
        assert_eq!(batch_id.len(), 64);

        let mut changed_context = references.clone();
        changed_context[1].context.as_mut().unwrap().window_title = Some("Changed".into());
        changed_context[1]
            .reference
            .as_mut()
            .unwrap()
            .context_fingerprint =
            semantic_context_fingerprint(changed_context[1].context.as_ref().unwrap(), 1).unwrap();
        assert_eq!(reference_batch_id(&changed_context).unwrap(), batch_id);
        let changed_digests = changed_context
            .iter()
            .map(manifest_digest)
            .collect::<Result<Vec<_>>>()
            .unwrap();
        assert_ne!(
            reference_batch_manifest_digest(&validated.manifest_digests).unwrap(),
            reference_batch_manifest_digest(&changed_digests).unwrap()
        );

        let mut gap = request;
        gap.events[1].sequence = 3;
        gap.batch_id = reference_batch_id(&gap.events).unwrap();
        assert!(validate_reference_batch(&gap).is_err());

        let mut oversized = vec![reference_to(&canonical, 1, "oversized-reference")];
        oversized[0].context.as_mut().unwrap().visible_windows =
            Some(json!("x".repeat(MAX_MANIFEST_BYTES)));
        oversized[0].reference.as_mut().unwrap().context_fingerprint =
            semantic_context_fingerprint(oversized[0].context.as_ref().unwrap(), 1).unwrap();
        let oversized = ScreenReferenceBatchRequest {
            schema_version: 1,
            batch_id: reference_batch_id(&oversized).unwrap(),
            events: oversized,
        };
        assert!(validate_reference_batch(&oversized).is_err());
    }

    #[test]
    fn reference_batch_atomically_records_alternating_displays_and_mixed_duplicates() {
        let conn = Connection::open_in_memory().unwrap();
        init_schema(&conn).unwrap();
        let display_one = valid_screen_manifest(0, "screen-event-0", "screen-asset-0");
        let mut display_two = valid_screen_manifest(1, "screen-event-1", "screen-asset-1");
        display_two.context.as_mut().unwrap().display_id = Some(84);
        record_source_event(
            &conn,
            "account-1",
            &display_one,
            &manifest_digest(&display_one).unwrap(),
            "object-0",
        )
        .unwrap();
        record_source_event(
            &conn,
            "account-1",
            &display_two,
            &manifest_digest(&display_two).unwrap(),
            "object-1",
        )
        .unwrap();
        let first = reference_to(&display_one, 2, "screen-event-2");
        let second = reference_to(&display_two, 3, "screen-event-3");
        record_reference_event(
            &conn,
            "account-1",
            &first,
            &manifest_digest(&first).unwrap(),
        )
        .unwrap();
        let events = vec![first, second];
        let digests = events
            .iter()
            .map(manifest_digest)
            .collect::<Result<Vec<_>>>()
            .unwrap();
        let outcome = record_reference_batch(&conn, "account-1", &events, &digests).unwrap();
        assert_eq!(outcome.new_count, 1);
        assert_eq!(outcome.duplicate_count, 1);
        assert_eq!(outcome.committed_through_sequence, 3);
        assert_eq!(
            conn.query_row(
                "SELECT count(*) FROM capture_events WHERE media_disposition='reference'",
                [],
                |row| row.get::<_, i64>(0),
            )
            .unwrap(),
            2
        );
    }

    #[test]
    fn invalid_middle_reference_rolls_back_the_complete_batch() {
        let conn = Connection::open_in_memory().unwrap();
        init_schema(&conn).unwrap();
        let canonical = valid_screen_manifest(0, "screen-event-0", "screen-asset-0");
        record_source_event(
            &conn,
            "account-1",
            &canonical,
            &manifest_digest(&canonical).unwrap(),
            "object-0",
        )
        .unwrap();
        let first = reference_to(&canonical, 1, "screen-event-1");
        let mut invalid = reference_to(&canonical, 2, "screen-event-2");
        invalid.reference.as_mut().unwrap().canonical_event_id = "missing-event".into();
        let third = reference_to(&canonical, 3, "screen-event-3");
        let events = vec![first, invalid, third];
        let digests = events
            .iter()
            .map(manifest_digest)
            .collect::<Result<Vec<_>>>()
            .unwrap();
        assert!(matches!(
            record_reference_batch(&conn, "account-1", &events, &digests),
            Err(EnclaveError::CaptureReferenceBatch {
                reason: CaptureReferenceFailureReason::CanonicalUnavailable,
                index: 1,
                sequence: 2,
            })
        ));
        assert_eq!(
            conn.query_row(
                "SELECT count(*) FROM capture_events WHERE media_disposition='reference'",
                [],
                |row| row.get::<_, i64>(0),
            )
            .unwrap(),
            0
        );
        assert_eq!(committed_through_sequence(&conn, "screen-1").unwrap(), 0);
    }

    #[test]
    fn screen_reference_rejects_missing_forward_cross_stream_chain_digest_and_context() {
        let cases = [
            "missing", "forward", "device", "stream", "chain", "digest", "context",
        ];
        for case in cases {
            let conn = Connection::open_in_memory().unwrap();
            init_schema(&conn).unwrap();
            let canonical = valid_screen_manifest(0, "screen-event-0", "screen-asset-0");
            record_source_event(&conn, "account-1", &canonical, &"a".repeat(64), "object-0")
                .unwrap();
            let mut reference = reference_to(&canonical, 1, "screen-event-1");
            match case {
                "missing" => {
                    reference.reference.as_mut().unwrap().canonical_event_id =
                        "missing-event".into()
                }
                "forward" => reference.sequence = 0,
                "device" => reference.device_id = "device-2".into(),
                "stream" => reference.stream_id = "screen-2".into(),
                "digest" => {
                    reference.reference.as_mut().unwrap().canonical_media_sha256 = "b".repeat(64)
                }
                "context" => {
                    reference.context.as_mut().unwrap().active_url =
                        Some("https://meet.google.com/different".into());
                    reference.reference.as_mut().unwrap().context_fingerprint =
                        semantic_context_fingerprint(reference.context.as_ref().unwrap(), 1)
                            .unwrap();
                }
                "chain" => {
                    let first_reference = reference.clone();
                    record_reference_event(&conn, "account-1", &first_reference, &"b".repeat(64))
                        .unwrap();
                    reference = reference_to(&canonical, 2, "screen-event-2");
                    let descriptor = reference.reference.as_mut().unwrap();
                    descriptor.canonical_event_id = first_reference.event_id;
                    descriptor.canonical_asset_id =
                        format!("reference-{}", descriptor.canonical_event_id);
                }
                _ => unreachable!(),
            }
            assert!(
                record_reference_event(&conn, "account-1", &reference, &"d".repeat(64)).is_err(),
                "{case} must be rejected"
            );
        }
    }

    #[test]
    fn capture_status_distinguishes_an_unknown_event_from_a_store_failure() {
        let conn = Connection::open_in_memory().unwrap();
        init_schema(&conn).unwrap();
        assert!(
            load_capture_status(&conn, "019fbab2-8413-7053-9117-eb249b72b15b")
                .unwrap()
                .is_none()
        );

        let manifest = valid_manifest();
        record_source_event(&conn, "account-1", &manifest, &"a".repeat(64), "object-1").unwrap();
        let status = load_capture_status(&conn, &manifest.event_id)
            .unwrap()
            .expect("recorded event has status");
        assert_eq!(status.event_id, manifest.event_id);
        assert_eq!(status.processing_state, "queued");
        assert_eq!(status.attempt_count, 0);
        assert!(status.error_code.is_none());
    }

    /// Stand-ins for the user-store tables the session status joins against
    /// (the real ones live in `store.rs`; production has both in one DB).
    fn session_status_content_tables(conn: &Connection) {
        conn.execute_batch(
            // `init_schema` now creates episodes/utterances/episode_members
            // itself; only the screenshots stand-in remains external.
            "CREATE TABLE IF NOT EXISTS screenshots (id INTEGER PRIMARY KEY, source_key TEXT, \
                active_app TEXT);",
        )
        .unwrap();
    }

    #[test]
    fn capture_session_status_tracks_processing_recap_and_ready_without_guessing() {
        let conn = Connection::open_in_memory().unwrap();
        init_schema(&conn).unwrap();
        session_status_content_tables(&conn);

        let manifest = valid_manifest();
        record_source_event(&conn, "account-1", &manifest, &"a".repeat(64), "object-1").unwrap();
        let session = load_capture_session_status(&conn, &manifest.capture_session_id, None)
            .unwrap()
            .expect("session exists after its first accepted event");
        assert_eq!(session.stage, CaptureSessionStage::Processing);
        assert_eq!(session.event_count, 1);
        assert!(session.memories.is_empty());

        conn.execute(
            "UPDATE media_objects SET processing_state='ready' WHERE event_id=?1",
            [&manifest.event_id],
        )
        .unwrap();
        conn.execute(
            "UPDATE capture_sessions SET ended_at='2026-08-01T18:01:00.000Z' WHERE id=?1",
            [&manifest.capture_session_id],
        )
        .unwrap();
        assert_eq!(
            load_capture_session_status(&conn, &manifest.capture_session_id, None)
                .unwrap()
                .unwrap()
                .stage,
            CaptureSessionStage::Organizing
        );

        conn.execute(
            "INSERT INTO screenshots(id,source_key) VALUES (1,?1)",
            [format!("cloud-v2:{}", manifest.event_id)],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO episodes(id,title,started_at,ended_at,finalization_status) \
             VALUES (7,'First memory',?1,?2,'pending_horizon')",
            [&manifest.started_at, &manifest.ended_at],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO episode_members(episode_id,record_type,record_id) \
             VALUES (7,'screenshot',1)",
            [],
        )
        .unwrap();
        assert_eq!(
            load_capture_session_status(&conn, &manifest.capture_session_id, None)
                .unwrap()
                .unwrap()
                .stage,
            CaptureSessionStage::PreparingRecap
        );

        conn.execute(
            "UPDATE episodes SET finalization_status='complete', \
             finalized_at='2026-08-01T22:01:00.000Z' WHERE id=7",
            [],
        )
        .unwrap();
        let ready = load_capture_session_status(&conn, &manifest.capture_session_id, None)
            .unwrap()
            .unwrap();
        assert_eq!(ready.stage, CaptureSessionStage::Ready);
        assert_eq!(ready.memories.len(), 1);
        assert_eq!(ready.memories[0].id, 7);

        // A residual terminal failure must not mask the formed memory: the
        // user can already read the recap, so the session stays ready.
        conn.execute(
            "UPDATE media_objects SET processing_state='failed' WHERE event_id=?1",
            [&manifest.event_id],
        )
        .unwrap();
        assert_eq!(
            load_capture_session_status(&conn, &manifest.capture_session_id, None)
                .unwrap()
                .unwrap()
                .stage,
            CaptureSessionStage::Ready
        );

        // Nor does that failure's hourly background retry demote it: only
        // genuinely new work (queued/processing) outranks a ready memory.
        conn.execute(
            "UPDATE media_objects SET processing_state='retry_wait' WHERE event_id=?1",
            [&manifest.event_id],
        )
        .unwrap();
        assert_eq!(
            load_capture_session_status(&conn, &manifest.capture_session_id, None)
                .unwrap()
                .unwrap()
                .stage,
            CaptureSessionStage::Ready
        );
    }

    /// needs_attention is reserved for the one case the label is honest: a
    /// terminal failure remains AND no memory materialized. In-flight work
    /// (for example a resurrected job back in retry_wait) outranks it.
    #[test]
    fn capture_session_needs_attention_only_when_failed_without_memory_or_work() {
        let conn = Connection::open_in_memory().unwrap();
        init_schema(&conn).unwrap();
        session_status_content_tables(&conn);

        let manifest = valid_manifest();
        record_source_event(&conn, "account-1", &manifest, &"a".repeat(64), "object-1").unwrap();
        conn.execute(
            "UPDATE media_objects SET processing_state='failed' WHERE event_id=?1",
            [&manifest.event_id],
        )
        .unwrap();
        assert_eq!(
            load_capture_session_status(&conn, &manifest.capture_session_id, None)
                .unwrap()
                .unwrap()
                .stage,
            CaptureSessionStage::NeedsAttention
        );

        // A resurrected job (retry_wait) means the outcome is still being
        // worked on, so the stage returns to processing rather than alarming.
        conn.execute(
            "UPDATE media_objects SET processing_state='retry_wait' WHERE event_id=?1",
            [&manifest.event_id],
        )
        .unwrap();
        assert_eq!(
            load_capture_session_status(&conn, &manifest.capture_session_id, None)
                .unwrap()
                .unwrap()
                .stage,
            CaptureSessionStage::Processing
        );
    }

    /// ADR-0034: the terminal zero-result requires the summarizer cursor past
    /// the session's end; a held cursor keeps `organizing`, and a
    /// substance-none episode (never finalized, hidden from browse) does not
    /// count as a memory.
    #[test]
    fn capture_session_no_memory_requires_summarized_past_end_and_ignores_substance_none() {
        let conn = Connection::open_in_memory().unwrap();
        init_schema(&conn).unwrap();
        session_status_content_tables(&conn);

        let manifest = valid_manifest();
        record_source_event(&conn, "account-1", &manifest, &"a".repeat(64), "object-1").unwrap();
        conn.execute(
            "UPDATE media_objects SET processing_state='ready' WHERE event_id=?1",
            [&manifest.event_id],
        )
        .unwrap();
        conn.execute(
            "UPDATE capture_sessions SET ended_at='2026-07-31T18:05:00.000Z' WHERE id=?1",
            [&manifest.capture_session_id],
        )
        .unwrap();

        let ended_ms = parse_epoch_millis("2026-07-31T18:05:00.000Z").unwrap();
        // Cursor before the session end: still organizing, never a guess.
        assert_eq!(
            load_capture_session_status(&conn, &manifest.capture_session_id, Some(ended_ms - 1))
                .unwrap()
                .unwrap()
                .stage,
            CaptureSessionStage::Organizing
        );
        // Cursor past the end with nothing linked: honest terminal no_memory.
        assert_eq!(
            load_capture_session_status(&conn, &manifest.capture_session_id, Some(ended_ms + 1))
                .unwrap()
                .unwrap()
                .stage,
            CaptureSessionStage::NoMemory
        );

        // A linked substance-none episode is not a memory: the finalizer
        // skips it, so counting it would wedge the stage at preparing_recap.
        conn.execute(
            "INSERT INTO screenshots(id,source_key) VALUES (1,?1)",
            [format!("cloud-v2:{}", manifest.event_id)],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO episodes(id,title,started_at,ended_at,finalization_status,substance) \
             VALUES (7,'Fragment',?1,?2,'pending_horizon','none')",
            [&manifest.started_at, &manifest.ended_at],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO episode_members(episode_id,record_type,record_id) \
             VALUES (7,'screenshot',1)",
            [],
        )
        .unwrap();
        let status =
            load_capture_session_status(&conn, &manifest.capture_session_id, Some(ended_ms + 1))
                .unwrap()
                .unwrap();
        assert_eq!(status.stage, CaptureSessionStage::NoMemory);
        assert!(status.memories.is_empty());

        // Reclassified upward (e.g. extension added substance): it counts.
        conn.execute("UPDATE episodes SET substance='normal' WHERE id=7", [])
            .unwrap();
        assert_eq!(
            load_capture_session_status(&conn, &manifest.capture_session_id, Some(ended_ms + 1))
                .unwrap()
                .unwrap()
                .stage,
            CaptureSessionStage::PreparingRecap
        );
    }

    /// ADR-0034 evidence echo: mechanical aggregates only, absent when
    /// unknown, app names rather than window titles.
    #[test]
    fn capture_session_evidence_echo_reports_audio_voices_and_contexts() {
        let conn = Connection::open_in_memory().unwrap();
        init_schema(&conn).unwrap();
        session_status_content_tables(&conn);

        let manifest = valid_manifest();
        record_source_event(&conn, "account-1", &manifest, &"a".repeat(64), "object-1").unwrap();

        let before = load_capture_session_status(&conn, &manifest.capture_session_id, None)
            .unwrap()
            .unwrap();
        // A 5-second accepted event rounds to zero whole minutes; no voices
        // or screen evidence exists yet, so those fields stay absent.
        assert_eq!(before.evidence.audio_minutes, Some(0));
        assert_eq!(before.evidence.voice_count, None);
        assert!(before.evidence.top_contexts.is_empty());

        conn.execute(
            "INSERT INTO audio_segments(id,started_at,ended_at,duration_seconds,source_type) \
             VALUES (1,?1,?2,5.0,'mic')",
            params![manifest.started_at, manifest.ended_at],
        )
        .unwrap();
        for (turn, label) in [("t1", "Me"), ("t2", "Speaker 1"), ("t3", "Me")] {
            conn.execute(
                "INSERT INTO speaker_observations(event_id,turn_id,speaker_local_id,\
                 started_at,ended_at,transcript_text) VALUES (?1,?2,'S0',?3,?4,'hello')",
                params![
                    manifest.event_id,
                    turn,
                    manifest.started_at,
                    manifest.ended_at
                ],
            )
            .unwrap();
            conn.execute(
                "INSERT INTO utterances(audio_segment_id,source_key,speaker_label) VALUES (1,?1,?2)",
                params![format!("cloud-v2:{}:{}", manifest.event_id, turn), label],
            )
            .unwrap();
        }
        for app in ["Zoom", "Zoom", "Xcode"] {
            conn.execute(
                "INSERT INTO screenshots(source_key,active_app) VALUES (?1,?2)",
                params![format!("cloud-v2:{}", manifest.event_id), app],
            )
            .unwrap();
        }

        let after = load_capture_session_status(&conn, &manifest.capture_session_id, None)
            .unwrap()
            .unwrap();
        assert_eq!(
            after.evidence.voice_count,
            Some(2),
            "distinct labels, not turns"
        );
        assert_eq!(after.evidence.top_contexts, vec!["Zoom", "Xcode"]);
    }

    /// ADR-0034 §3: discovery lists sessions started in the window plus
    /// still-open recently-active sessions; stale open sessions age out.
    #[test]
    fn recent_capture_session_listing_is_bounded_and_recency_aware() {
        let conn = Connection::open_in_memory().unwrap();
        init_schema(&conn).unwrap();

        let insert = |id: &str, started_offset: &str, last_offset: &str, ended: bool| {
            conn.execute(
                "INSERT INTO capture_sessions(id,device_id,install_id,started_at,\
                 last_event_at,ended_at,schema_version) VALUES (?1,'d','i',\
                 strftime('%Y-%m-%dT%H:%M:%fZ','now',?2),\
                 strftime('%Y-%m-%dT%H:%M:%fZ','now',?3),\
                 CASE WHEN ?4 THEN strftime('%Y-%m-%dT%H:%M:%fZ','now',?3) END,2)",
                params![id, started_offset, last_offset, ended],
            )
            .unwrap();
        };
        insert("fresh-ended", "-1 hours", "-1 hours", true);
        insert("fresh-open", "-2 hours", "-2 hours", false);
        insert("old-open-active", "-30 hours", "-1 hours", false);
        insert("old-open-stale", "-30 hours", "-29 hours", false);
        insert("old-ended", "-30 hours", "-29 hours", true);

        let ids = load_recent_capture_session_ids(&conn, 8, 5).unwrap();
        assert_eq!(ids, vec!["fresh-ended", "fresh-open", "old-open-active"]);

        // The clamp bounds the response, newest first.
        let ids = load_recent_capture_session_ids(&conn, 8, 1).unwrap();
        assert_eq!(ids, vec!["fresh-ended"]);
    }

    #[test]
    fn accepted_final_capture_event_durably_closes_the_exact_session() {
        let conn = Connection::open_in_memory().unwrap();
        init_schema(&conn).unwrap();
        let mut manifest = valid_manifest();
        manifest.session_finished = Some(true);
        let digest = manifest_digest(&manifest).unwrap();

        assert_eq!(
            record_source_event(&conn, "account-1", &manifest, &digest, "object-1").unwrap(),
            RecordOutcome::Created
        );
        assert_eq!(
            record_source_event(&conn, "account-1", &manifest, &digest, "object-1").unwrap(),
            RecordOutcome::Duplicate
        );
        let ended_at: Option<String> = conn
            .query_row(
                "SELECT ended_at FROM capture_sessions WHERE id=?1",
                [&manifest.capture_session_id],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(ended_at.as_deref(), Some(manifest.ended_at.as_str()));
    }

    #[test]
    fn stream_ack_returns_not_found_only_for_an_unknown_stream() {
        let conn = Connection::open_in_memory().unwrap();
        init_schema(&conn).unwrap();
        assert!(matches!(
            committed_through_sequence(&conn, "system-1"),
            Err(EnclaveError::NotFound)
        ));

        let manifest = valid_manifest();
        record_source_event(&conn, "account-1", &manifest, &"a".repeat(64), "object-1").unwrap();
        assert_eq!(
            committed_through_sequence(&conn, &manifest.stream_id).unwrap(),
            -1
        );
    }

    #[test]
    fn browser_snapshot_and_exact_active_url_are_retained_with_the_event_time() {
        let conn = Connection::open_in_memory().unwrap();
        init_schema(&conn).unwrap();
        let mut manifest = valid_manifest();
        let context = manifest.context.as_mut().unwrap();
        context.browser_state_key = Some("device-1:browser-v1:abc123".into());
        context.browser_snapshot = Some(BrowserSnapshot {
            state_key: "device-1:browser-v1:abc123".into(),
            browser_bundle_id: "com.google.Chrome".into(),
            browser_name: "Google Chrome".into(),
            permission_status: "granted".into(),
            active_window_index: Some(0),
            active_tab_index: Some(1),
            reported_tab_count: 2,
            truncated: false,
            content_hash: "c".repeat(64),
            tabs: vec![BrowserTab {
                window_index: 0,
                tab_index: 1,
                title: Some("Weekly planning".into()),
                url: Some("https://meet.google.com/abc-defg-hij?authuser=0".into()),
                is_active: true,
                is_loading: Some(false),
            }],
        });
        manifest.validate().unwrap();
        record_source_event(&conn, "account-1", &manifest, &"d".repeat(64), "object-1").unwrap();

        let (observed_at, active_url, tabs_json): (String, String, String) = conn
            .query_row(
                "SELECT o.observed_at,o.active_url,s.tabs_json \
                 FROM browser_observations_v2 o JOIN browser_states_v2 s USING(state_key)",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();
        assert_eq!(observed_at, manifest.source_wall_at);
        assert_eq!(
            active_url,
            "https://meet.google.com/abc-defg-hij?authuser=0"
        );
        assert!(tabs_json.contains("authuser=0"));
    }

    #[test]
    fn audio_response_requires_bounded_monotonic_turns() {
        let parsed = parse_audio_result(
            r#"{"turns":[
                {"turn_id":"t1","start_ms":0,"end_ms":1100,"speaker_local_id":"speaker_1","text":"Hello","language":"en","overlap":false},
                {"turn_id":"t2","start_ms":1100,"end_ms":2500,"speaker_local_id":"speaker_2","text":"Hi","language":"en","overlap":false}
            ]}"#,
            5_000,
        )
        .unwrap();
        assert_eq!(parsed.len(), 2);

        assert!(parse_audio_result(
            r#"{"turns":[{"turn_id":"t1","start_ms":10,"end_ms":6000,"speaker_local_id":"speaker_1","text":"bad","language":"en","overlap":false}]}"#,
            5_000,
        )
        .is_err());
        assert!(parse_audio_result(
            r#"{"turns":[{"turn_id":"t1","start_ms":100,"end_ms":100,"speaker_local_id":"speaker_1","text":"bad","language":"en","overlap":false}]}"#,
            5_000,
        )
        .is_err());
    }

    #[test]
    fn uploaded_media_must_match_the_manifest_bytes_and_container() {
        let mut manifest = valid_manifest();
        let m4a = b"\0\0\0\x18ftypM4A \0\0\0\0";
        manifest.media.as_mut().unwrap().byte_length = m4a.len() as i64;
        manifest.media.as_mut().unwrap().sha256 = sha256_hex(m4a);
        validate_media_bytes(&manifest, m4a, Some("audio/m4a")).unwrap();

        let mut corrupted = m4a.to_vec();
        corrupted[9] ^= 1;
        assert!(validate_media_bytes(&manifest, &corrupted, Some("audio/m4a")).is_err());
        assert!(validate_media_bytes(&manifest, m4a, Some("image/jpeg")).is_err());

        let invalid_container = vec![0u8; m4a.len()];
        manifest.media.as_mut().unwrap().sha256 = sha256_hex(&invalid_container);
        assert!(validate_media_bytes(&manifest, &invalid_container, Some("audio/m4a")).is_err());
    }

    #[test]
    fn canonical_manifest_digest_is_stable_after_json_key_reordering() {
        let manifest = valid_manifest();
        let value = serde_json::to_value(&manifest).unwrap();
        let reparsed: CaptureEventManifest = serde_json::from_value(value).unwrap();
        assert_eq!(
            manifest_digest(&manifest).unwrap(),
            manifest_digest(&reparsed).unwrap()
        );
        assert_eq!(manifest_digest(&manifest).unwrap().len(), 64);
    }

    #[test]
    fn export_ordering_is_valid_for_every_cloud_capture_table() {
        let conn = Connection::open_in_memory().unwrap();
        init_schema(&conn).unwrap();
        for (table, order) in [
            ("capture_sessions", "created_at"),
            ("capture_streams", "created_at"),
            ("capture_events", "started_at, event_id"),
            ("media_objects", "created_at, event_id"),
            ("browser_states_v2", "created_at, state_key"),
            ("browser_observations_v2", "observed_at, event_id"),
            ("media_processing_jobs", "updated_at, event_id"),
            ("media_work_units", "updated_at, id"),
            ("media_work_members", "work_unit_id, ordinal"),
            ("speaker_observations", "started_at, event_id, id"),
            (
                "speaker_observation_sources",
                "speaker_observation_id, window_start_ms",
            ),
            ("people", "display_name, id"),
            ("voice_profiles", "person_id, id"),
            ("voice_samples", "speaker_observation_id, id"),
            ("voice_profile_proposals", "created_at, id"),
            ("voice_profile_revisions", "profile_id, id"),
            ("voice_sample_profile_assignments", "sample_id, id"),
            (
                "voice_profile_proposal_profiles",
                "proposal_id, role, partition_ordinal, profile_id",
            ),
            (
                "voice_profile_proposal_samples",
                "proposal_id, partition_ordinal, sample_id",
            ),
            ("identity_evidence", "created_at, id"),
            ("person_name_claims", "observed_at, id"),
            ("profile_identity_bindings", "updated_at, id"),
            ("person_facts", "person_id, created_at, id"),
            ("speaker_clusters", "work_unit_id, speaker_local_id"),
            ("episode_speaker_slots", "episode_id, slot_ordinal"),
            (
                "voice_profile_representatives",
                "profile_id, channel_domain",
            ),
            (
                "voice_embedding_jobs",
                "state, next_attempt_at, lease_until",
            ),
            ("episode_participants", "episode_id, participant_key"),
            ("visual_speaker_observations", "observed_at, id"),
        ] {
            assert!(super::super::sync::dump_optional_table(&conn, table, order).is_ok());
        }
    }

    #[test]
    fn rate_limit_response_exposes_retry_after_to_native_uploaders() {
        let response = rate_limited_response();
        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(response.headers().get(RETRY_AFTER).unwrap(), "5");
    }

    #[test]
    fn every_new_capture_kind_requires_a_recording_lease() {
        for stream in [
            StreamKind::Mic,
            StreamKind::SystemAudio,
            StreamKind::MacScreen,
            StreamKind::IosMic,
            StreamKind::IosImportedScreenshot,
            StreamKind::IosSharedPage,
        ] {
            assert!(capture_requires_recording_lease(stream));
        }
    }

    fn finish_test_state() -> Arc<CpState> {
        use crate::store::tests::{FakeGcs, FakeKms};
        let kms = Arc::new(FakeKms);
        let gcs = Arc::new(FakeGcs::new());
        Arc::new(CpState {
            store: Arc::new(crate::store::Store::new(kms.clone(), gcs.clone())),
            control: Arc::new(crate::cp::control_store::ControlStore::new(kms, gcs)),
            billing: Arc::new(crate::cp::billing::FakeBillingGateway),
            recording_lease_gate: Arc::new(crate::cp::billing::RecordingLeaseGates::default()),
            config: Arc::new(crate::cp::CpConfig {
                base_url: "http://localhost:8080".into(),
                jwt_secrets: vec!["test".into()],
                google_desktop_client_id: "desktop".into(),
                google_ios_client_id: "ios".into(),
                google_web_client_id: "web".into(),
                google_web_client_secret: "secret".into(),
                admin_user_ids: Vec::new(),
                signup_limit_per_day: crate::cp::control_store::TEST_SIGNUP_LIMIT,
                scheduler_sa_email: None,
                vertex_project: "project".into(),
                vertex_location: "global".into(),
                vertex_model: "model".into(),
                quota_utterances_per_day: 1,
                quota_screenshots_per_day: 1,
                quota_mcp_calls_per_day: 1,
                quota_vertex_output_tokens_per_day: 1,
                web_origin: "http://localhost:3000".into(),
                reviewer_auth: None,
                apple_sign_in: None,
                billing_enforcement_mode: crate::cp::BillingEnforcementMode::Enforce,
            }),
            user_verifier: Arc::new(crate::cp::auth::UserIdTokenVerifier::new(vec![])),
            reviewer_verifier: None,
            apple_provider: None,
            sync_limiter: crate::cp::limits::RateLimiter::new(10.0, 1.0),
            reference_batch_limiter: crate::cp::limits::RateLimiter::new(10.0, 1.0),
            reference_batch_concurrency: Arc::new(tokio::sync::Semaphore::new(4)),
            mcp_limiter: crate::cp::limits::RateLimiter::new(10.0, 1.0),
            oauth_limiter: crate::cp::limits::RateLimiter::new(10.0, 1.0),
            test_email_limiter: crate::cp::limits::RateLimiter::new(3.0, 0.05),
            email_transport: None,
            push_transport: None,
            embedding: None,
            voice: None,
        })
    }

    #[tokio::test]
    async fn finishing_an_unknown_capture_session_is_an_idempotent_no_op() {
        let state = finish_test_state();
        let response = finish_capture_session(
            State(state),
            axum::Extension(crate::cp::auth::AuthUser(
                "11111111-1111-4111-8111-111111111111".into(),
            )),
            axum::extract::Path("session-lost-before-finish".into()),
        )
        .await;
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
    }

    #[tokio::test]
    async fn finishing_a_known_capture_session_still_reports_its_status() {
        let state = finish_test_state();
        let user = crate::cp::auth::AuthUser("11111111-1111-4111-8111-111111111111".into());
        state
            .store
            .with_user(&user.0, |conn| {
                conn.execute(
                    "INSERT INTO capture_sessions(id,device_id,install_id,started_at,\
                     last_event_at,schema_version) \
                     VALUES('session-1','device-1','install-1',\
                     '2026-08-14T18:00:00.000Z','2026-08-14T18:00:05.000Z',2)",
                    [],
                )?;
                Ok(())
            })
            .await
            .unwrap();
        let response = finish_capture_session(
            State(state),
            axum::Extension(user),
            axum::extract::Path("session-1".into()),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), 65_536)
            .await
            .unwrap();
        let status: Value = serde_json::from_slice(&body).unwrap();
        assert!(status["ended_at"].is_string());
    }

    /// ADR-0022 per-domain routing for the stream-acknowledgement read, now
    /// that its answerability blocker (deferred ingest) is gone.
    ///
    /// The half worth pinning is the one the gate used to make unobservable: a
    /// WAL-AUTHORITATIVE user must never be answered out of the legacy
    /// snapshot. The row below is seeded through `with_user` BEFORE the user is
    /// selected, so it provably exists in that user's own legacy archive; after
    /// selection the same read must refuse rather than serve it, because a
    /// selected user with no registered serving authority has no settled lane
    /// to answer from.
    ///
    /// The refusal's STATUS is pinned exactly, not merely as "some server
    /// error". `wal_authoritative_read` reports an unregistered, quarantined
    /// or mid-relaunch authority as `EnclaveError::Store`, whose generic arm
    /// renders `500 {"error":"internal error"}`; the read lane's rule
    /// (`cp::routed_read_unavailable`) names 500 as one of the three statuses
    /// it is deliberately NOT, because a 500 makes a retryable read failure
    /// indistinguishable from a genuinely non-retryable one. A status-class
    /// assertion would admit that 500.
    ///
    /// Falsifiability, checked by sabotage: reverting the handler to
    /// `with_user` (or to `with_user_read`) turns the refusal into a `200`
    /// carrying `committed_through_sequence: 7`, and both assertions below
    /// fail; handing the `Err` arm to `EnclaveError::into_response` instead of
    /// `routed_read_unavailable` turns the 503 into a 500 and the status and
    /// reason assertions fail.
    #[tokio::test]
    async fn a_selected_stream_ack_is_never_served_the_legacy_snapshot() {
        use crate::cp::wal_gate_test_support::select_wal_authoritative;
        use axum::extract::{Path, State};
        use axum::Extension;

        let state = finish_test_state();
        let user_id = "media-stream-ack-selected";
        state
            .store
            .with_user(user_id, |conn| {
                conn.execute(
                    "INSERT INTO capture_sessions(id,device_id,install_id,started_at,\
                     last_event_at,schema_version) \
                     VALUES('session-1','device-1','install-1',\
                     '2026-08-14T18:00:00.000Z','2026-08-14T18:00:05.000Z',2)",
                    [],
                )?;
                conn.execute(
                    "INSERT INTO capture_streams(id,capture_session_id,device_id,stream_kind,\
                     committed_through_sequence) \
                     VALUES('stream-1','session-1','device-1','mic',7)",
                    [],
                )?;
                Ok(())
            })
            .await
            .unwrap();

        // Unselected: the row is readable, so the refusal below is a routing
        // decision and not an empty or broken store.
        let served = stream_ack(
            State(Arc::clone(&state)),
            Extension(crate::cp::auth::AuthUser(user_id.to_string())),
            Path("stream-1".to_string()),
        )
        .await;
        assert_eq!(served.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(served.into_body(), 4 * 1024)
            .await
            .unwrap();
        let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(body["committed_through_sequence"], 7);

        // The ABSENCE, at the handler. `committed_through_sequence` folds "no
        // such stream" into `Err(NotFound)` rather than `Ok(None)`, so the
        // handler's `Err` arm carries two different things: this truthful 404
        // -- which is exactly what lifting the D4 gate made truthful -- and the
        // unreachable-archive 503 below. Funnelling the whole arm into 503
        // would tell a caller their stream might come back later when it never
        // existed. Only `committed_through_sequence` itself was tested before,
        // so this arm had no coverage at the route at all.
        let absent = stream_ack(
            State(Arc::clone(&state)),
            Extension(crate::cp::auth::AuthUser(user_id.to_string())),
            Path("stream-absent".to_string()),
        )
        .await;
        assert_eq!(absent.status(), StatusCode::NOT_FOUND);
        assert_ne!(absent.status(), StatusCode::SERVICE_UNAVAILABLE);

        select_wal_authoritative(&state.store, user_id);
        let refused = stream_ack(
            State(Arc::clone(&state)),
            Extension(crate::cp::auth::AuthUser(user_id.to_string())),
            Path("stream-1".to_string()),
        )
        .await;
        assert_eq!(refused.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_ne!(refused.status(), StatusCode::OK);
        // A routed-read failure is retryable. 500 would make it
        // indistinguishable from the genuinely non-retryable failures that
        // keep 500 on purpose; see `cp::routed_read_unavailable`.
        assert_ne!(refused.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let bytes = axum::body::to_bytes(refused.into_body(), 4 * 1024)
            .await
            .unwrap();
        let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(body["error"], crate::cp::ROUTED_READ_UNAVAILABLE_REASON);
        assert!(
            body.get("committed_through_sequence").is_none(),
            "the stale acknowledgement leaked: {body}"
        );
    }

    /// Both sides of the now-ROUTED capture-status read, in one test because
    /// each is only meaningful against the other:
    ///
    /// * an UNSELECTED user reads a real row out of the legacy store, so the
    ///   store is provably loadable and populated;
    /// * a WAL-AUTHORITATIVE user reading the SAME archive is refused rather
    ///   than served that row. This is the property the retained gate used to
    ///   hide: with no registered serving authority there is no settled lane,
    ///   and the one thing that must never happen is the stale legacy snapshot
    ///   being handed back as if it were authoritative.
    ///
    /// The gate that used to sit above this is gone: its whole justification
    /// was that ingest was deferred, so a routed `Ok(None)` -> 404 could not be
    /// told apart from "you never uploaded that event". Ingest is migrated, so
    /// the 404 is truthful again.
    ///
    /// The refusal is pinned at the lane's named 503 rather than at a status
    /// class: the unreachable-archive failure must be told apart both from the
    /// truthful 404 above it and from the 500 the generic `EnclaveError::Store`
    /// arm would render. See `cp::routed_read_unavailable`.
    ///
    /// Falsifiability, checked by sabotage: swapping the handler back to
    /// `with_user_read` turns the selected user's refusal into
    /// `200 {"event_id":"evt-1"}` and both selected-side assertions fail;
    /// dropping the `capture_events` insert turns the unselected user's 200
    /// into a 404; handing the `Err` arm to `EnclaveError::into_response`
    /// turns the 503 into a 500 and the status and reason assertions fail.
    #[tokio::test]
    async fn a_selected_capture_status_is_never_served_the_legacy_row() {
        use crate::cp::wal_gate_test_support::select_wal_authoritative;
        use axum::extract::{Path, State};
        use axum::Extension;

        let state = finish_test_state();
        let user_id = "media-status-user";
        state
            .store
            .with_user(user_id, |conn| {
                conn.execute(
                    "INSERT INTO capture_sessions(id,device_id,install_id,started_at,\
                     last_event_at,schema_version) \
                     VALUES('session-1','device-1','install-1',\
                     '2026-08-14T18:00:00.000Z','2026-08-14T18:00:05.000Z',2)",
                    [],
                )?;
                conn.execute(
                    "INSERT INTO capture_streams(id,capture_session_id,device_id,stream_kind) \
                     VALUES('stream-1','session-1','device-1','mic')",
                    [],
                )?;
                conn.execute(
                    "INSERT INTO capture_events(event_id,device_id,install_id,\
                     capture_session_id,stream_id,stream_kind,sequence,source_wall_at,\
                     source_monotonic_ns,started_at,ended_at,timezone_id,utc_offset_minutes,\
                     clock_uncertainty_ms,asset_id,manifest_digest,media_disposition) \
                     VALUES('evt-1','device-1','install-1','session-1','stream-1','mic',0,\
                     '2026-08-14T18:00:00.000Z','1','2026-08-14T18:00:00.000Z',\
                     '2026-08-14T18:00:05.000Z','UTC',0,0,'asset-1','digest-1','canonical')",
                    [],
                )?;
                Ok(())
            })
            .await
            .unwrap();

        let served = capture_status(
            State(Arc::clone(&state)),
            Extension(crate::cp::auth::AuthUser(user_id.to_string())),
            Path("evt-1".to_string()),
        )
        .await;
        assert_eq!(served.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(served.into_body(), 4 * 1024)
            .await
            .unwrap();
        let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(body["event_id"], "evt-1");

        select_wal_authoritative(&state.store, user_id);
        let refused = capture_status(
            State(Arc::clone(&state)),
            Extension(crate::cp::auth::AuthUser(user_id.to_string())),
            Path("evt-1".to_string()),
        )
        .await;
        assert_eq!(refused.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_ne!(refused.status(), StatusCode::OK);
        assert_ne!(refused.status(), StatusCode::NOT_FOUND);
        assert_ne!(refused.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let bytes = axum::body::to_bytes(refused.into_body(), 4 * 1024)
            .await
            .unwrap();
        let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(body["error"], crate::cp::ROUTED_READ_UNAVAILABLE_REASON);
        assert!(
            body.get("event_id").is_none(),
            "the stale row leaked: {body}"
        );
    }

    /// The same two-sided proof for the people domain, which carries four
    /// routes behind one gate. `list_people` answers a COLLECTION, so its
    /// ungated failure mode is the worst shape the answerability rule names:
    /// not a 404 but `200 {"people": []}` once a serving authority exists — a
    /// refusal wearing the face of a truthful empty roster. The assertions
    /// pin that the refusal is the named 503 and that the served roster is
    /// non-empty, so neither side can be satisfied by an empty success.
    ///
    /// Falsifiability, checked by sabotage: deleting the gate turns the
    /// selected user's 503 into a 500; naming a different domain breaks the
    /// `domain` assertion; dropping the `people` insert turns the unselected
    /// user's roster length from 1 to 0.
    #[tokio::test]
    async fn a_deferred_people_list_answers_a_named_503_while_legacy_still_reads_its_roster() {
        use crate::cp::wal_gate_test_support::select_wal_authoritative;
        use axum::extract::{Query, State};
        use axum::Extension;

        let state = finish_test_state();
        let legacy_user = "media-people-legacy";
        state
            .store
            .with_user(legacy_user, |conn| {
                conn.execute(
                    // No explicit id: `init_schema` already seeds the owner
                    // row ('owner','Me'), which stays out of this listing
                    // because its status is 'unknown', not 'identified'.
                    "INSERT INTO people(display_name,status,updated_at) \
                     VALUES('Ada','identified','2026-08-14T18:00:00.000Z')",
                    [],
                )?;
                Ok(())
            })
            .await
            .unwrap();

        let selected_user = "media-people-selected";
        select_wal_authoritative(&state.store, selected_user);
        let refused = list_people(
            State(Arc::clone(&state)),
            Extension(crate::cp::auth::AuthUser(selected_user.to_string())),
            Query(PeopleListQuery::default()),
        )
        .await;
        assert_eq!(refused.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_ne!(refused.status(), StatusCode::OK);
        assert_ne!(refused.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let bytes = axum::body::to_bytes(refused.into_body(), 4 * 1024)
            .await
            .unwrap();
        let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(body["error"], crate::error::WAL_DOMAIN_UNMIGRATED_REASON);
        assert_eq!(body["domain"], wal_domain::MEDIA_PEOPLE);
        assert!(
            body.get("people").is_none(),
            "a refusal must never carry a collection: {body}"
        );

        let served = list_people(
            State(Arc::clone(&state)),
            Extension(crate::cp::auth::AuthUser(legacy_user.to_string())),
            Query(PeopleListQuery::default()),
        )
        .await;
        assert_eq!(served.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(served.into_body(), 16 * 1024)
            .await
            .unwrap();
        let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(body["people"].as_array().unwrap().len(), 1);
        assert_eq!(body["people"][0]["display_name"], "Ada");
    }

    /// The session listing, now routed. It answers a COLLECTION, which is the
    /// shape the answerability rule warned about hardest: an unanswerable
    /// routed read here returns `200 {"sessions": []}`, a refusal wearing the
    /// face of a truthful empty archive. That is exactly why this one must
    /// refuse rather than fall through to the legacy snapshot for a selected
    /// user, and why the assertion checks for the ABSENCE of a `sessions` key
    /// rather than only a status code — an empty success would pass a
    /// status-only check.
    ///
    /// The gate above it is gone with ingest: `upload_capture_event` writes
    /// every row this can list, so an empty list is now the truth rather than
    /// a deferral in disguise.
    ///
    /// The status is pinned at the lane's named 503, not at a status class:
    /// the generic `EnclaveError::Store` arm renders a 500, which
    /// `cp::routed_read_unavailable` names as one of the three statuses this
    /// lane deliberately does not use.
    ///
    /// Falsifiability, checked by sabotage: swapping the handler back to
    /// `with_user_read` turns the selected user's refusal into a `200` whose
    /// `sessions` array has one element and both selected-side assertions
    /// fail; backdating `started_at` outside the 8-hour window empties the
    /// unselected user's list; handing the `Err` arm to
    /// `EnclaveError::into_response` turns the 503 into a 500 and the status
    /// and reason assertions fail.
    #[tokio::test]
    async fn a_selected_session_list_refuses_instead_of_listing_the_legacy_snapshot() {
        use crate::cp::wal_gate_test_support::select_wal_authoritative;
        use axum::extract::{Query, State};
        use axum::Extension;

        let state = finish_test_state();
        let user_id = "media-session-list-user";
        state
            .store
            .with_user(user_id, |conn| {
                // Inside the default 8-hour window, sourced from SQLite's own
                // clock so the row cannot age out of the window as the suite
                // ages.
                conn.execute(
                    "INSERT INTO capture_sessions(id,device_id,install_id,started_at,\
                     last_event_at,schema_version) \
                     VALUES('session-1','device-1','install-1',\
                     strftime('%Y-%m-%dT%H:%M:%fZ','now'),\
                     strftime('%Y-%m-%dT%H:%M:%fZ','now'),2)",
                    [],
                )?;
                Ok(())
            })
            .await
            .unwrap();

        let query = || {
            Query(CaptureSessionListQuery {
                window_hours: None,
                max_sessions: None,
            })
        };
        let served = list_capture_sessions(
            State(Arc::clone(&state)),
            Extension(crate::cp::auth::AuthUser(user_id.to_string())),
            query(),
        )
        .await;
        assert_eq!(served.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(served.into_body(), 16 * 1024)
            .await
            .unwrap();
        let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        let sessions = body["sessions"].as_array().unwrap();
        assert_eq!(sessions.len(), 1);
        assert_eq!(sessions[0]["capture_session_id"], "session-1");

        select_wal_authoritative(&state.store, user_id);
        let refused = list_capture_sessions(
            State(Arc::clone(&state)),
            Extension(crate::cp::auth::AuthUser(user_id.to_string())),
            query(),
        )
        .await;
        assert_eq!(refused.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_ne!(refused.status(), StatusCode::OK);
        assert_ne!(refused.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let bytes = axum::body::to_bytes(refused.into_body(), 16 * 1024)
            .await
            .unwrap();
        let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(body["error"], crate::cp::ROUTED_READ_UNAVAILABLE_REASON);
        assert!(
            body.get("sessions").is_none(),
            "a refusal must never carry a collection: {body}"
        );
    }
    /// The fourth read whose D4 gate lifted with ingest, and the only one that
    /// had no routing test at all. Same two-sided proof as its siblings: an
    /// UNSELECTED user reads the row out of the legacy store, and a
    /// WAL-AUTHORITATIVE user reading the SAME archive is refused rather than
    /// served it.
    ///
    /// The refusal is the lane's named 503, never the 500 the generic
    /// `EnclaveError::Store` arm renders and never the truthful 404 that
    /// `Ok(None)` above it answers -- those three outcomes mean three
    /// different things to a client and this endpoint must not conflate them.
    /// See `cp::routed_read_unavailable`.
    ///
    /// Falsifiability, checked by sabotage: swapping the handler back to
    /// `with_user_read` turns the selected user's refusal into a `200` naming
    /// `session-1`; handing the `Err` arm to `EnclaveError::into_response`
    /// turns the 503 into a 500.
    #[tokio::test]
    async fn a_selected_capture_session_status_refuses_at_the_named_503() {
        use crate::cp::wal_gate_test_support::select_wal_authoritative;
        use axum::extract::{Path, State};
        use axum::Extension;

        let state = finish_test_state();
        let user_id = "media-session-status-user";
        state
            .store
            .with_user(user_id, |conn| {
                conn.execute(
                    "INSERT INTO capture_sessions(id,device_id,install_id,started_at,\
                     last_event_at,schema_version) \
                     VALUES('session-1','device-1','install-1',\
                     '2026-08-14T18:00:00.000Z','2026-08-14T18:00:05.000Z',2)",
                    [],
                )?;
                Ok(())
            })
            .await
            .unwrap();

        let served = capture_session_status(
            State(Arc::clone(&state)),
            Extension(crate::cp::auth::AuthUser(user_id.to_string())),
            Path("session-1".to_string()),
        )
        .await;
        assert_eq!(served.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(served.into_body(), 16 * 1024)
            .await
            .unwrap();
        let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(body["capture_session_id"], "session-1");

        // A session that was never written stays a truthful 404 for the same
        // unselected user, so the 503 below is provably not just "absent".
        let absent = capture_session_status(
            State(Arc::clone(&state)),
            Extension(crate::cp::auth::AuthUser(user_id.to_string())),
            Path("session-absent".to_string()),
        )
        .await;
        assert_eq!(absent.status(), StatusCode::NOT_FOUND);

        select_wal_authoritative(&state.store, user_id);
        let refused = capture_session_status(
            State(Arc::clone(&state)),
            Extension(crate::cp::auth::AuthUser(user_id.to_string())),
            Path("session-1".to_string()),
        )
        .await;
        assert_eq!(refused.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_ne!(refused.status(), StatusCode::OK);
        assert_ne!(refused.status(), StatusCode::NOT_FOUND);
        assert_ne!(refused.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let bytes = axum::body::to_bytes(refused.into_body(), 16 * 1024)
            .await
            .unwrap();
        let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(body["error"], crate::cp::ROUTED_READ_UNAVAILABLE_REASON);
        assert!(
            body.get("capture_session_id").is_none(),
            "the stale session leaked: {body}"
        );
    }
}
