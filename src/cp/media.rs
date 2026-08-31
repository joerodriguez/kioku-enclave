//! V2 raw-media capture API and cloud processing ledger.

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
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::error::{CaptureReferenceFailureReason, EnclaveError, Result};
use crate::persistence::{
    CaptureCommit, CapturePreflight, CaptureSessionStatus, PeopleListRequest, ReferenceBatchCommit,
};

use super::isotime::parse_epoch_millis;
use super::{auth::AuthUser, limits, CpState};

const MAX_AUDIO_BYTES: i64 = 20 * 1024 * 1024;
pub(crate) const MAX_SCREENSHOT_BYTES: i64 = 5 * 1024 * 1024;
const MAX_ID_LEN: usize = 128;
/// The ingest length bound on the device-supplied `started_at`/`ended_at`.
///
/// It is the same 64-byte bound enforced when PostgreSQL-claimed media work is
/// settled. Ingest must not admit a stamp that a paid provider result can never
/// commit.
pub(crate) const MAX_DEVICE_TIMESTAMP_BYTES: usize = 64;
// Shared with audio-result validation so persisted transcript bounds cannot
// drift from provider-response parsing (the text cap counts chars, not bytes).
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BrowserTab {
    pub window_index: i64,
    pub tab_index: i64,
    pub title: Option<String>,
    pub url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url_scheme: Option<String>,
    pub is_active: bool,
    pub is_loading: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ambient_tab_collection_enabled: Option<bool>,
    pub content_hash: String,
    pub tabs: Vec<BrowserTab>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct BrowserStateV2Envelope {
    pub(crate) schema_version: i64,
    pub(crate) active_window_index: Option<i64>,
    pub(crate) active_tab_index: Option<i64>,
    pub(crate) reported_tab_count: i64,
    pub(crate) truncated: bool,
    pub(crate) ambient_tab_collection_enabled: bool,
    pub(crate) tabs: Vec<BrowserTab>,
}

pub(crate) struct BrowserV2PersistedEvidence<'a> {
    pub(crate) event_id: &'a str,
    pub(crate) device_id: &'a str,
    pub(crate) source_wall_at: &'a str,
    pub(crate) observation_id: &'a str,
    pub(crate) observed_at: &'a str,
    pub(crate) state_key: Option<&'a str>,
    pub(crate) context_status: &'a str,
    pub(crate) active_url: Option<&'a str>,
    pub(crate) active_title: Option<&'a str>,
    pub(crate) browser_bundle_id: &'a str,
    pub(crate) browser_name: &'a str,
    pub(crate) permission_status: &'a str,
    pub(crate) content_hash: &'a str,
    pub(crate) tabs_json: &'a str,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecordingRetentionCaptureAuthority {
    pub policy_revision: i64,
    pub policy_epoch: String,
    pub lease_id: String,
    pub authority_token: String,
}

/// Server-final retention decision carried into the durable capture commit.
/// A client echo can identify a signed policy interval, but it cannot select
/// this value; ingest rechecks PostgreSQL retention state, and the repository
/// commit enforces the account and policy fences used by downgrade/deletion.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "retention_decision", rename_all = "snake_case")]
pub(crate) enum RecordingMediaAuthorityDecision {
    ProcessingWindow30d {
        capture_policy_revision: i64,
        decision_at: String,
    },
    UntilDeleted {
        capture_policy_revision: i64,
        retention_policy_revision: i64,
        retention_policy_epoch: String,
        recording_key_epoch: i64,
        decision_at: String,
    },
}

impl RecordingMediaAuthorityDecision {
    fn processing(capture_policy_revision: i64, decision_at: String) -> Self {
        Self::ProcessingWindow30d {
            capture_policy_revision: capture_policy_revision.max(0),
            decision_at,
        }
    }

    pub(crate) const fn is_durable(&self) -> bool {
        matches!(self, Self::UntilDeleted { .. })
    }
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recording_retention: Option<RecordingRetentionCaptureAuthority>,
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
        if let Some(authority) = self.recording_retention.as_ref() {
            if !self.stream_kind.is_audio()
                || self.media_disposition != MediaDisposition::Canonical
                || authority.policy_revision <= 0
                || !authority.policy_epoch.starts_with("rpe_")
                || authority.policy_epoch.len() != 68
                || !authority.policy_epoch[4..]
                    .bytes()
                    .all(|byte| byte.is_ascii_hexdigit())
                || !authority.lease_id.starts_with("lease_")
                || authority.lease_id.len() != 70
                || authority.authority_token.is_empty()
                || authority.authority_token.len() > 2_048
                || !authority.authority_token.is_ascii()
            {
                return Err(EnclaveError::InvalidRequest(
                    "recording_retention authority is malformed".into(),
                ));
            }
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
        // PostgreSQL stores this value only in its source-wall-clock columns;
        // server commit/claim timestamps come from database time. Rejecting
        // offset-bearing stamps would break shipped clients without improving
        // that binding. Any future canonicalization therefore belongs in a
        // separately reviewed client/API change.
        if parse_epoch_millis(&self.source_wall_at).is_none() {
            return Err(EnclaveError::InvalidRequest(
                "source_wall_at must be ISO-8601".into(),
            ));
        }
        // A LENGTH bound, which is a different question from the FORMAT bound
        // the paragraph above declines to add, and the two must not be
        // conflated.
        //
        // `capture_events.started_at`/`ended_at` are device-supplied and reach
        // the PostgreSQL media-settlement predicate, which enforces the same
        // 64-byte maximum. Bounding them before a claim prevents a paid Vertex
        // result from becoming impossible to settle.
        // `parse_epoch_millis` makes this reachable with a stamp that denotes
        // the correct instant: it ignores fractional digits past the third, so
        // `...T14:00:00.<45 zeroes>Z` parses to exactly the same millisecond as
        // the canonical form.
        //
        // This cannot strand a client, and that is the whole reason it is a
        // length bound and not a format one:
        //
        //   * Every timestamp shape `parse_epoch_millis` was widened to accept
        //     on purpose still fits. Canonical `YYYY-MM-DDTHH:MM:SS.mmmZ` is 24
        //     bytes; the `±HH:MM` offset form is 29; nanosecond precision with
        //     an offset is 35. The bound is 64 — nearly double the longest
        //     stamp any real client can emit — so no shipped Mac or iOS build
        //     loses an event it can currently deliver, and the durable outbox
        //     has nothing to rebase.
        //   * It is the contract this manifest ALREADY applies to every other
        //     string field. `validate_id` 400s over-long ids and `timezone_id`
        //     is capped at 128; `started_at`/`ended_at` were the outliers.
        //
        // `source_wall_at` is deliberately not length-bounded here. It reaches
        // no length-bounded settlement predicate and can never become a server
        // commit/claim timestamp.
        for (name, value) in [
            ("started_at", self.started_at.as_str()),
            ("ended_at", self.ended_at.as_str()),
        ] {
            if value.len() > MAX_DEVICE_TIMESTAMP_BYTES {
                return Err(EnclaveError::InvalidRequest(format!(
                    "{name} exceeds {MAX_DEVICE_TIMESTAMP_BYTES} bytes"
                )));
            }
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
            validate_context(context, &self.device_id)?;
            let carries_browser_v2 = context
                .browser_state_key
                .as_deref()
                .is_some_and(|key| key.contains(":browser-v2:"))
                || context
                    .browser_snapshot
                    .as_ref()
                    .is_some_and(|snapshot| snapshot.state_key.contains(":browser-v2:"));
            if carries_browser_v2
                && (self.stream_kind != StreamKind::MacScreen || context.capture_status != "stable")
            {
                return Err(EnclaveError::InvalidRequest(
                    "browser-v2 evidence requires a stable mac_screen event".into(),
                ));
            }
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

fn validate_context(context: &CaptureContext, device_id: &str) -> Result<()> {
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
        if snapshot.state_key.contains(":browser-v2:") {
            validate_browser_v2_snapshot(context, snapshot, device_id)?;
            return Ok(());
        }
        for tab in &snapshot.tabs {
            if tab.window_index < 0
                || tab.tab_index < 0
                || tab.title.as_ref().is_some_and(|value| value.len() > 2_000)
                || tab.url.as_ref().is_some_and(|value| value.len() > 8_192)
                || tab
                    .url_scheme
                    .as_ref()
                    .is_some_and(|value| value.len() > 64 || value.contains('\0'))
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

pub(crate) fn validate_browser_v2_snapshot(
    context: &CaptureContext,
    snapshot: &BrowserSnapshot,
    device_id: &str,
) -> Result<()> {
    let ambient = snapshot.ambient_tab_collection_enabled.ok_or_else(|| {
        EnclaveError::InvalidRequest("browser-v2 requires ambient_tab_collection_enabled".into())
    })?;
    let expected_name = match snapshot.browser_bundle_id.as_str() {
        "com.apple.Safari" => "Safari",
        "com.google.Chrome" => "Google Chrome",
        "com.brave.Browser" => "Brave Browser",
        "com.microsoft.edgemac" => "Microsoft Edge",
        "company.thebrowser.Browser" => "Arc",
        _ => {
            return Err(EnclaveError::InvalidRequest(
                "browser-v2 bundle is unsupported".into(),
            ))
        }
    };
    if snapshot.browser_name != expected_name
        || context.capture_status != "stable"
        || context.primary_bundle_id.as_deref() != Some(snapshot.browser_bundle_id.as_str())
        || context.browser_permission_status.as_deref() != Some(snapshot.permission_status.as_str())
        || context.browser_state_key.as_deref() != Some(snapshot.state_key.as_str())
        || !matches!(
            snapshot.permission_status.as_str(),
            "granted"
                | "not_determined"
                | "denied"
                | "unsupported"
                | "browser_not_running"
                | "timed_out"
                | "script_error"
        )
        || snapshot
            .content_hash
            .bytes()
            .any(|byte| !byte.is_ascii_lowercase() && !byte.is_ascii_digit())
    {
        return Err(EnclaveError::InvalidRequest(
            "browser-v2 metadata is invalid".into(),
        ));
    }
    let expected_key = format!("{device_id}:browser-v2:{}", snapshot.content_hash);
    if snapshot.state_key != expected_key {
        return Err(EnclaveError::InvalidRequest(
            "browser-v2 state key does not bind device and content".into(),
        ));
    }

    if snapshot.permission_status != "granted" {
        if snapshot.active_window_index.is_some()
            || snapshot.active_tab_index.is_some()
            || snapshot.reported_tab_count != 0
            || snapshot.truncated
            || !snapshot.tabs.is_empty()
            || context.active_url.is_some()
            || context.active_url_title.is_some()
        {
            return Err(EnclaveError::InvalidRequest(
                "non-granted browser-v2 state must not invent tabs".into(),
            ));
        }
    } else {
        if snapshot.tabs.is_empty()
            || snapshot.reported_tab_count < i64::try_from(snapshot.tabs.len()).unwrap_or(i64::MAX)
            || snapshot.truncated
                != (snapshot.reported_tab_count
                    > i64::try_from(snapshot.tabs.len()).unwrap_or(i64::MAX))
            || (!ambient
                && (snapshot.tabs.len() != 1
                    || snapshot.reported_tab_count != 1
                    || snapshot.truncated))
        {
            return Err(EnclaveError::InvalidRequest(
                "browser-v2 tab count is inconsistent".into(),
            ));
        }
        let mut coordinates = std::collections::HashSet::new();
        let mut active: Option<&BrowserTab> = None;
        for tab in &snapshot.tabs {
            if tab.window_index <= 0
                || tab.tab_index <= 0
                || !coordinates.insert((tab.window_index, tab.tab_index))
                || tab
                    .title
                    .as_ref()
                    .is_some_and(|value| value.len() > 1_000 || value.contains('\0'))
                || tab
                    .url
                    .as_ref()
                    .is_some_and(|value| value.len() > 4_096 || value.contains('\0'))
                || tab.url_scheme.as_ref().is_some_and(|value| {
                    let mut bytes = value.bytes();
                    value.len() > 64
                        || value.contains('\0')
                        || !bytes.next().is_some_and(|byte| byte.is_ascii_alphabetic())
                        || !bytes.all(|byte| {
                            byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'-' | b'.')
                        })
                })
            {
                return Err(EnclaveError::InvalidRequest(
                    "browser-v2 tab is invalid".into(),
                ));
            }
            if tab.is_active && active.replace(tab).is_some() {
                return Err(EnclaveError::InvalidRequest(
                    "browser-v2 must have exactly one active tab".into(),
                ));
            }
        }
        let active = active.ok_or_else(|| {
            EnclaveError::InvalidRequest("browser-v2 must have exactly one active tab".into())
        })?;
        if snapshot.active_window_index != Some(active.window_index)
            || snapshot.active_tab_index != Some(active.tab_index)
            || context.active_url != active.url
            || context.active_url_title != active.title
        {
            return Err(EnclaveError::InvalidRequest(
                "browser-v2 active evidence is inconsistent".into(),
            ));
        }
    }

    if browser_v2_content_hash(snapshot)? != snapshot.content_hash {
        return Err(EnclaveError::InvalidRequest(
            "browser-v2 content commitment does not match".into(),
        ));
    }
    Ok(())
}

pub(crate) fn validate_browser_v2_persisted_evidence(
    context: &CaptureContext,
    evidence: BrowserV2PersistedEvidence<'_>,
) -> Result<BrowserSnapshot> {
    let envelope: BrowserStateV2Envelope = serde_json::from_str(evidence.tabs_json)
        .map_err(|_| EnclaveError::Store("browser-v2 state is corrupt".into()))?;
    if envelope.schema_version != 2 {
        return Err(EnclaveError::Store(
            "browser-v2 state version is unsupported".into(),
        ));
    }
    let state_key = evidence
        .state_key
        .ok_or_else(|| EnclaveError::Store("browser-v2 observation is missing state".into()))?;
    let snapshot = context
        .browser_snapshot
        .clone()
        .unwrap_or_else(|| BrowserSnapshot {
            state_key: state_key.to_owned(),
            browser_bundle_id: evidence.browser_bundle_id.to_owned(),
            browser_name: evidence.browser_name.to_owned(),
            permission_status: evidence.permission_status.to_owned(),
            active_window_index: envelope.active_window_index,
            active_tab_index: envelope.active_tab_index,
            reported_tab_count: envelope.reported_tab_count,
            truncated: envelope.truncated,
            ambient_tab_collection_enabled: Some(envelope.ambient_tab_collection_enabled),
            content_hash: evidence.content_hash.to_owned(),
            tabs: envelope.tabs.clone(),
        });
    validate_browser_v2_snapshot(context, &snapshot, evidence.device_id)
        .map_err(|_| EnclaveError::Store("browser-v2 snapshot is corrupt".into()))?;
    let expected_envelope = BrowserStateV2Envelope {
        schema_version: 2,
        active_window_index: snapshot.active_window_index,
        active_tab_index: snapshot.active_tab_index,
        reported_tab_count: snapshot.reported_tab_count,
        truncated: snapshot.truncated,
        ambient_tab_collection_enabled: snapshot
            .ambient_tab_collection_enabled
            .ok_or_else(|| EnclaveError::Store("browser-v2 consent is missing".into()))?,
        tabs: snapshot.tabs.clone(),
    };
    if evidence.observation_id != evidence.event_id
        || evidence.observed_at != evidence.source_wall_at
        || state_key != snapshot.state_key
        || evidence.context_status != context.capture_status
        || evidence.active_url != context.active_url.as_deref()
        || evidence.active_title != context.active_url_title.as_deref()
        || evidence.browser_bundle_id != snapshot.browser_bundle_id
        || evidence.browser_name != snapshot.browser_name
        || evidence.permission_status != snapshot.permission_status
        || evidence.content_hash != snapshot.content_hash
        || envelope != expected_envelope
    {
        return Err(EnclaveError::Store(
            "browser-v2 evidence is inconsistent".into(),
        ));
    }
    Ok(snapshot)
}

fn browser_v2_content_hash(snapshot: &BrowserSnapshot) -> Result<String> {
    fn append_u32(bytes: &mut Vec<u8>, value: usize) -> Result<()> {
        let value = u32::try_from(value)
            .map_err(|_| EnclaveError::InvalidRequest("browser-v2 field is too large".into()))?;
        bytes.extend_from_slice(&value.to_be_bytes());
        Ok(())
    }
    fn append_i64(bytes: &mut Vec<u8>, value: i64) {
        bytes.extend_from_slice(&value.to_be_bytes());
    }
    fn append_text(bytes: &mut Vec<u8>, value: &str) -> Result<()> {
        append_u32(bytes, value.len())?;
        bytes.extend_from_slice(value.as_bytes());
        Ok(())
    }
    fn append_optional_text(bytes: &mut Vec<u8>, value: Option<&str>) -> Result<()> {
        bytes.push(u8::from(value.is_some()));
        if let Some(value) = value {
            append_text(bytes, value)?;
        }
        Ok(())
    }
    fn append_optional_i64(bytes: &mut Vec<u8>, value: Option<i64>) {
        bytes.push(u8::from(value.is_some()));
        if let Some(value) = value {
            append_i64(bytes, value);
        }
    }
    fn append_optional_bool(bytes: &mut Vec<u8>, value: Option<bool>) {
        bytes.push(u8::from(value.is_some()));
        if let Some(value) = value {
            bytes.push(u8::from(value));
        }
    }

    let mut bytes = b"kioku-browser-state-v2\0".to_vec();
    append_text(&mut bytes, &snapshot.browser_bundle_id)?;
    append_text(&mut bytes, &snapshot.permission_status)?;
    append_optional_i64(&mut bytes, snapshot.active_window_index);
    append_optional_i64(&mut bytes, snapshot.active_tab_index);
    append_i64(&mut bytes, snapshot.reported_tab_count);
    bytes.push(u8::from(snapshot.truncated));
    bytes.push(u8::from(
        snapshot.ambient_tab_collection_enabled.unwrap_or(false),
    ));
    append_u32(&mut bytes, snapshot.tabs.len())?;
    for tab in &snapshot.tabs {
        append_i64(&mut bytes, tab.window_index);
        append_i64(&mut bytes, tab.tab_index);
        append_optional_text(&mut bytes, tab.title.as_deref())?;
        append_optional_text(&mut bytes, tab.url.as_deref())?;
        append_optional_text(&mut bytes, tab.url_scheme.as_deref())?;
        bytes.push(u8::from(tab.is_active));
        append_optional_bool(&mut bytes, tab.is_loading);
    }
    Ok(sha256_hex(&bytes))
}

fn sha256_hex(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

pub(crate) fn manifest_digest(manifest: &CaptureEventManifest) -> Result<String> {
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
struct CaptureSessionList {
    sessions: Vec<CaptureSessionStatus>,
}

#[derive(Debug, Deserialize)]
struct CaptureSessionListQuery {
    window_hours: Option<i64>,
    max_sessions: Option<i64>,
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
    match limits::account_active(&state.repositories, &user_id).await {
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
    if !state
        .reference_batch_limiter
        .consume_scoped(&state.repositories, "capture-reference-batch", &user_id)
        .await
    {
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
    let concurrency_holder = format!("{}:{:032x}", request.batch_id, rand::random::<u128>());
    let _batch_permit = match limits::try_acquire_concurrency(
        &state.repositories,
        "capture-reference-batch",
        &concurrency_holder,
        32,
        std::time::Duration::from_secs(600),
    )
    .await
    {
        Ok(Some(permit)) => permit,
        Ok(None) => {
            return capture_failure_response_for_route(
                "screen_reference_batch",
                started_at,
                manifest,
                CaptureIngestFailureReason::RateLimited,
                rate_limited_response(),
            )
        }
        Err(error) => {
            tracing::error!(error = %error, "capture reference batch concurrency admission failed");
            return capture_failure_response_for_route(
                "screen_reference_batch",
                started_at,
                manifest,
                CaptureIngestFailureReason::LifecycleUnavailable,
                (StatusCode::SERVICE_UNAVAILABLE, "service unavailable").into_response(),
            );
        }
    };
    let mut preflight = Vec::with_capacity(request.events.len());
    for (event, digest) in request.events.iter().zip(&validated.manifest_digests) {
        match state
            .repositories
            .captures()
            .preflight_event(&user_id, event, digest, None)
            .await
        {
            Ok(outcome) => preflight.push(outcome),
            Err(error) => {
                return capture_error_response_for_route(
                    "screen_reference_batch",
                    started_at,
                    manifest,
                    error,
                )
            }
        }
    }
    let new_event_ids = preflight
        .iter()
        .zip(&validated.event_ids)
        .filter(|(outcome, _)| matches!(outcome, CapturePreflight::New))
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

    let recorded = match state
        .repositories
        .captures()
        .commit_reference_batch(ReferenceBatchCommit {
            account_id: user_id.clone(),
            events: request.events.clone(),
            manifest_digests: validated.manifest_digests.clone(),
            committed_at: enclave_commit_stamp(),
        })
        .await
    {
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
    match limits::account_active(&state.repositories, &user_id).await {
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
    // Canonical and reference dispositions share the PostgreSQL capture
    // preflight/commit contract. Canonical writes persist the exact generation
    // returned by GCS; reference writes persist no media bytes. Keeping both in
    // one ordered stream is required because screen streams interleave full
    // screenshots and reference pointers and advance acknowledgements only
    // across contiguous committed sequences.
    if !state
        .capture_event_limiter
        .consume_scoped(&state.repositories, "capture-event", &user_id)
        .await
    {
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
    let object_key_candidates = match manifest.media.as_ref() {
        Some(media) => {
            let processing =
                match crate::gcs::canonical_capture_media_object_key(&user_id, &media.asset_id) {
                    Ok(key) => key,
                    Err(error) => {
                        return capture_error_response(started_at, Some(&manifest), error)
                    }
                };
            let durable =
                match crate::gcs::canonical_recording_media_object_key(&user_id, &media.asset_id) {
                    Ok(key) => key,
                    Err(error) => {
                        return capture_error_response(started_at, Some(&manifest), error)
                    }
                };
            Some(vec![processing, durable])
        }
        None => None,
    };
    let preflight = state
        .repositories
        .captures()
        .preflight_event(
            &user_id,
            &manifest,
            &digest,
            object_key_candidates.as_deref(),
        )
        .await;
    match preflight {
        Ok(CapturePreflight::Duplicate {
            committed_through_sequence,
        }) => {
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
        Ok(CapturePreflight::New) => {}
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

    let commit_stamp = enclave_commit_stamp();
    let mut media_generation = None;
    let mut object_key = None;
    let mut upload_token = None;
    let mut media_authority = None;
    if manifest.media_disposition == MediaDisposition::Canonical {
        let media = manifest.media.as_ref().expect("validated canonical media");
        let media_bytes = media_bytes.as_deref().expect("validated canonical media");
        let write =
            match prepare_canonical_media_write(&state, &user_id, &manifest, &commit_stamp).await {
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
        let encrypted = match crate::crypto::encrypt_bound_blob(
            &write.encryption_key,
            media_bytes,
            &write.encryption_context,
        ) {
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
        upload_token = match state
            .repositories
            .captures()
            .reserve_media_upload(
                &user_id,
                &manifest.event_id,
                &media.asset_id,
                &write.object_key,
                &digest,
            )
            .await
        {
            Ok(value) => value,
            Err(error) => {
                return capture_failure_response(
                    started_at,
                    Some(&manifest),
                    CaptureIngestFailureReason::LifecycleUnavailable,
                    error.into_response(),
                )
            }
        };
        // The child keeps the provider PUT alive if the HTTP future is
        // cancelled. Deletion waits for that child lease and therefore scans
        // only after the provider has definitively accepted or rejected it.
        let put_store = state.repositories.media_objects_arc();
        let put_user_id = user_id.clone();
        let put_object_key = write.object_key.clone();
        let put_key_reference = write.provider_key_reference.clone();
        let put = tokio::spawn(async move {
            put_store
                .put_current(
                    &put_user_id,
                    &put_object_key,
                    &encrypted,
                    &put_key_reference,
                )
                .await
        });
        match put.await {
            Ok(Ok(generation)) => media_generation = Some(generation),
            Ok(Err(put_error)) => {
                media_generation = match verify_existing_media(
                    state.repositories.media_objects(),
                    &write.object_key,
                    &write.encryption_context,
                    media_bytes,
                    &write.encryption_key,
                    &write.provider_key_reference,
                )
                .await
                {
                    Ok(generation) => Some(generation),
                    Err(error) => {
                        tracing::error!(error = %put_error, verify_error = %error, "capture media storage failed");
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
        object_key = Some(write.object_key);
        media_authority = Some(write.authority);
    }

    let result = match state
        .repositories
        .captures()
        .commit_event(CaptureCommit {
            account_id: user_id.clone(),
            manifest: manifest.clone(),
            manifest_digest: digest.clone(),
            object_key,
            object_generation: media_generation,
            upload_token,
            media_authority,
            committed_at: commit_stamp,
        })
        .await
    {
        Ok(value) => value,
        Err(error) => return capture_error_response(started_at, Some(&manifest), error),
    };
    let committed = result.committed_through_sequence;
    let duplicate = result.duplicate;
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
    // The same PostgreSQL capture repository creates and reads stream rows, so
    // NotFound is a truthful account-scoped absence rather than a backend
    // routing decision.
    match state
        .repositories
        .captures()
        .stream_ack(&user.0, &stream_id)
        .await
    {
        Ok(committed) => Json(StreamAck {
            stream_id,
            committed_through_sequence: committed,
        })
        .into_response(),
        // Keep an absent stream distinct from PostgreSQL unavailability: the
        // former is 404, while the latter remains a retryable routed-read 503.
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
    // Capture ingest and status share the tenant-qualified PostgreSQL
    // repository, making `None` a truthful event absence.
    match state
        .repositories
        .captures()
        .event_status(&user.0, &event_id)
        .await
    {
        Ok(Some(status)) => Json(status).into_response(),
        Ok(None) => EnclaveError::NotFound.into_response(),
        // Database unavailability is retryable and must not masquerade as a
        // missing event.
        Err(error) => super::routed_read_unavailable("api.media.capture_status", &error),
    }
}

/// The summarizer cursor, for the no_memory derivation (ADR-0034). Best
/// effort: an unreadable cursor degrades to "unknown", which can only delay
/// the terminal zero-result — never invent it.
async fn summarized_until_ms(state: &CpState, user_id: &str) -> Option<i64> {
    match state.repositories.work().summarized_until(user_id).await {
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
    // Session rows are created and read in the same tenant-qualified
    // PostgreSQL capture repository, so absence is authoritative.
    let cursor_ms = summarized_until_ms(&state, &user.0).await;
    match state
        .repositories
        .captures()
        .session_status(&user.0, &capture_session_id, cursor_ms)
        .await
    {
        Ok(Some(status)) => Json(status).into_response(),
        Ok(None) => EnclaveError::NotFound.into_response(),
        // See `capture_status`: database unavailability is retryable.
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
    // Ingest writes every row this tenant-qualified PostgreSQL query can list,
    // so an empty collection is authoritative.
    let window_hours = query.window_hours.unwrap_or(8).clamp(1, 24);
    let max_sessions = query.max_sessions.unwrap_or(5).clamp(1, 10);
    let cursor_ms = summarized_until_ms(&state, &user.0).await;
    match state
        .repositories
        .captures()
        .recent_sessions(&user.0, window_hours, max_sessions, cursor_ms)
        .await
    {
        Ok(sessions) => Json(CaptureSessionList { sessions }).into_response(),
        // Unavailability remains a 503, never a false empty collection.
        Err(error) => super::routed_read_unavailable("api.media.capture_sessions", &error),
    }
}

/// Sessions that started within the window, plus still-open sessions with
/// recent events (so an in-flight recording is discoverable even when it
/// started before the window). Stale open sessions age out with their last
/// event rather than pinning the list forever.
async fn finish_capture_session(
    State(state): State<Arc<CpState>>,
    Extension(user): Extension<AuthUser>,
    Path(capture_session_id): Path<String>,
) -> Response {
    if let Err(error) = validate_id("capture_session_id", &capture_session_id) {
        return error.into_response();
    }
    match state
        .repositories
        .captures()
        .finish_session(&user.0, &capture_session_id)
        .await
    {
        Ok(Some(status)) => {
            super::summarizer::kick_session_settled(&user.0);
            Json(status).into_response()
        }
        // Finishing is idempotent: an unknown session is already in the goal
        // state ("not active"), and clients queue finish markers durably, so a
        // 404 here wedges their outbox forever after server-side session loss.
        Ok(None) => StatusCode::NO_CONTENT.into_response(),
        Err(error) => error.into_response(),
    }
}

async fn list_people(
    State(state): State<Arc<CpState>>,
    Extension(user): Extension<AuthUser>,
    Query(query): Query<PeopleListQuery>,
) -> Response {
    // PostgreSQL audio settlement commits the person, accepted name claim,
    // facts, and profile binding atomically before this query can expose them.
    // Absence is therefore a truthful empty roster.
    let after_id = query.after_id.unwrap_or(0).max(0);
    let limit = query.limit.unwrap_or(50).clamp(1, 100);
    let search = query
        .q
        .as_deref()
        .map(str::trim)
        .filter(|query| !query.is_empty())
        .map(str::to_owned);
    match state
        .repositories
        .memory_queries()
        .list_people(
            &user.0,
            &PeopleListRequest {
                after_id,
                limit,
                query: search,
            },
        )
        .await
    {
        Ok(page) => Json(page).into_response(),
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
    match state
        .repositories
        .memory_queries()
        .person_profile(&user.0, person_id)
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
    let limit = query.limit.unwrap_or(50).clamp(1, 100);
    let before_id = query.before_id;
    match state
        .repositories
        .memory_queries()
        .person_evidence(&user.0, person_id, before_id, limit)
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
    let limit = query.limit.unwrap_or(50).clamp(1, 100);
    let before_id = query.before_id;
    match state
        .repositories
        .memory_queries()
        .person_statements(&user.0, person_id, before_id, limit)
        .await
    {
        Ok(page) => Json(page).into_response(),
        Err(error) => error.into_response(),
    }
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
    CanonicalUnavailable,
    ContextFingerprintMismatch,
    ReferenceTargetMismatch,
    CanonicalContextUnavailable,
    ReferenceContextTransition,
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
            Self::IdempotencyConflict => "idempotency_conflict",
            Self::LifecycleUnavailable => "lifecycle_unavailable",
            Self::RecordingLeaseInactive => "recording_lease_inactive",
            Self::RecordingLeaseConflict => "recording_lease_conflict",
            Self::RecordingLeaseUnavailable => "recording_lease_unavailable",
            Self::MediaStorageUnavailable => "media_storage_unavailable",
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

pub(in crate::cp) async fn load_or_create_media_dek(
    state: &CpState,
    user_id: &str,
) -> Result<(crate::crypto::Dek, String)> {
    let existing = state
        .repositories
        .captures()
        .media_dek_wrapped(user_id)
        .await?;
    if let Some(wrapped) = existing {
        let dek = crate::crypto::load_dek(state.kms.as_ref(), &wrapped).await?;
        return Ok((dek, wrapped));
    }
    let (candidate_dek, candidate_wrapped) =
        crate::crypto::generate_and_wrap_dek(state.kms.as_ref()).await?;
    let winner = state
        .repositories
        .captures()
        .install_media_dek(user_id, &candidate_wrapped)
        .await?;
    if winner == candidate_wrapped {
        Ok((candidate_dek, winner))
    } else {
        let dek = crate::crypto::load_dek(state.kms.as_ref(), &winner).await?;
        Ok((dek, winner))
    }
}

struct CanonicalMediaWrite {
    object_key: String,
    encryption_key: crate::crypto::Dek,
    provider_key_reference: String,
    encryption_context: Vec<u8>,
    authority: RecordingMediaAuthorityDecision,
}

async fn recording_media_authority_decision(
    state: &CpState,
    user_id: &str,
    manifest: &CaptureEventManifest,
    decision_at: &str,
) -> Result<RecordingMediaAuthorityDecision> {
    if !manifest.stream_kind.is_audio() {
        return Ok(RecordingMediaAuthorityDecision::processing(
            0,
            decision_at.to_owned(),
        ));
    }
    let Some(echo) = manifest.recording_retention.as_ref() else {
        // An older/offline client with no server-verifiable interval remains
        // eligible only for the established processing window. Promotion is a
        // separate explicit operation and never inferred here.
        return Ok(RecordingMediaAuthorityDecision::processing(
            0,
            decision_at.to_owned(),
        ));
    };
    let claims = super::tokens::verify_recording_retention_lease(
        state.config.jwt_secrets.as_ref(),
        &echo.authority_token,
    )
    .map_err(|_| {
        EnclaveError::InvalidRequest("recording retention authority was rejected".into())
    })?;
    if claims.user_id != user_id
        || claims.lease_id != echo.lease_id
        || claims.policy_revision != echo.policy_revision
        || claims.policy_epoch != echo.policy_epoch
    {
        return Err(EnclaveError::InvalidRequest(
            "recording retention authority did not match the capture".into(),
        ));
    }
    let started_ms = super::isotime::parse_epoch_millis(&manifest.started_at)
        .ok_or_else(|| EnclaveError::InvalidRequest("started_at must be ISO-8601".into()))?;
    let ended_ms = super::isotime::parse_epoch_millis(&manifest.ended_at)
        .ok_or_else(|| EnclaveError::InvalidRequest("ended_at must be ISO-8601".into()))?;
    let interval_covered = started_ms >= claims.valid_from_epoch_millis
        && started_ms < claims.capture_started_before_epoch_millis
        && ended_ms <= claims.valid_until_epoch_millis;
    if !interval_covered {
        return Ok(RecordingMediaAuthorityDecision::processing(
            claims.policy_revision,
            decision_at.to_owned(),
        ));
    }

    let preference = state
        .repositories
        .recording_retention()
        .preference(user_id)
        .await?;
    if preference.policy != crate::persistence::RecordingRetentionPolicy::UntilDeleted
        || preference.revision != claims.policy_revision
        || preference.policy_epoch.as_deref() != Some(claims.policy_epoch.as_str())
        || preference.operation_state.is_some()
    {
        // The PostgreSQL policy revision/state fence makes a stale client echo
        // evidence only, never authority to recreate an object after downgrade.
        return Ok(RecordingMediaAuthorityDecision::processing(
            claims.policy_revision,
            decision_at.to_owned(),
        ));
    }
    if !state.durable_recording_storage_bound {
        return Err(EnclaveError::Store(
            "durable recording storage is temporarily unavailable".into(),
        ));
    }
    let key_epoch = preference.revision;
    if state
        .repositories
        .recording_retention()
        .key_epoch(user_id, key_epoch, &claims.policy_epoch)
        .await?
        .is_none()
    {
        return Err(EnclaveError::Store(
            "durable recording key authority is unavailable".into(),
        ));
    }
    Ok(RecordingMediaAuthorityDecision::UntilDeleted {
        capture_policy_revision: claims.policy_revision,
        retention_policy_revision: preference.revision,
        retention_policy_epoch: claims.policy_epoch,
        recording_key_epoch: key_epoch,
        decision_at: decision_at.to_owned(),
    })
}

async fn prepare_canonical_media_write(
    state: &CpState,
    user_id: &str,
    manifest: &CaptureEventManifest,
    decision_at: &str,
) -> Result<CanonicalMediaWrite> {
    let media = manifest
        .media
        .as_ref()
        .ok_or_else(|| EnclaveError::InvalidRequest("canonical media is required".into()))?;
    let authority =
        recording_media_authority_decision(state, user_id, manifest, decision_at).await?;
    match &authority {
        RecordingMediaAuthorityDecision::UntilDeleted {
            retention_policy_epoch,
            recording_key_epoch,
            ..
        } => {
            let object_key =
                crate::gcs::canonical_recording_media_object_key(user_id, &media.asset_id)?;
            let key_epoch = state
                .repositories
                .recording_retention()
                .key_epoch(user_id, *recording_key_epoch, retention_policy_epoch)
                .await?
                .ok_or_else(|| {
                    EnclaveError::Store("durable recording key authority is unavailable".into())
                })?;
            let encryption_key =
                crate::crypto::load_dek(state.kms.as_ref(), &key_epoch.wrapped_dek_b64).await?;
            let provider_key_reference = crate::gcs::recording_media_key_reference(
                *recording_key_epoch,
                retention_policy_epoch,
            )?;
            let encryption_context = crate::gcs::recording_media_blob_context(
                user_id,
                &object_key,
                *recording_key_epoch,
                retention_policy_epoch,
                &manifest.event_id,
                &media.asset_id,
                &manifest.capture_session_id,
                manifest.stream_kind.as_str(),
                &media.codec,
                media.byte_length,
                &media.sha256,
            )?;
            Ok(CanonicalMediaWrite {
                object_key,
                encryption_key,
                provider_key_reference,
                encryption_context,
                authority,
            })
        }
        RecordingMediaAuthorityDecision::ProcessingWindow30d { .. } => {
            let object_key =
                crate::gcs::canonical_capture_media_object_key(user_id, &media.asset_id)?;
            let (encryption_key, provider_key_reference) =
                load_or_create_media_dek(state, user_id).await?;
            let encryption_context = crate::gcs::media_blob_context(user_id, &object_key);
            Ok(CanonicalMediaWrite {
                object_key,
                encryption_key,
                provider_key_reference,
                encryption_context,
                authority,
            })
        }
    }
}

async fn verify_existing_media(
    media_objects: &dyn crate::persistence::MediaObjectStore,
    object_key: &str,
    context: &[u8],
    expected: &[u8],
    installed_dek: &crate::crypto::Dek,
    installed_wrapped_dek: &str,
) -> Result<i64> {
    // Lost-response adoption is allowed only from the current provider's one
    // live response. It must be encrypted under the account's already chosen
    // DEK and strict v2 AAD; the generation returned here is the same response
    // whose bytes were authenticated, so no verify-N/record-N+1 race exists.
    let existing = media_objects.get_current(object_key).await?;
    if existing.generation <= 0 || existing.wrapped_dek_b64 != installed_wrapped_dek {
        return Err(EnclaveError::Conflict(
            "existing canonical media does not match the installed account key".into(),
        ));
    }
    let plaintext =
        crate::crypto::decrypt_bound_blob_v2(installed_dek, &existing.ciphertext, context)?
            .plaintext;
    if plaintext != expected {
        return Err(EnclaveError::Conflict(
            "asset_id was already used for different media".into(),
        ));
    }
    Ok(existing.generation)
}

pub(crate) fn semantic_context_value(context: &CaptureContext, dedupe_version: u32) -> Value {
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

pub(crate) fn semantic_context_fingerprint(
    context: &CaptureContext,
    dedupe_version: u32,
) -> Result<String> {
    Ok(sha256_hex(&serde_json::to_vec(&semantic_context_value(
        context,
        dedupe_version,
    ))?))
}

fn enclave_commit_stamp() -> String {
    super::isotime::format_epoch_millis(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as i64,
    )
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
mod lost_response_adoption_tests {
    use async_trait::async_trait;

    use super::verify_existing_media;
    use crate::{
        crypto::{encrypt_bound_blob, Dek},
        error::{EnclaveError, Result},
        gcs::GcsGetResponse,
        persistence::MediaObjectStore,
    };

    struct FakeMediaObjectStore {
        object_name: String,
        ciphertext: Vec<u8>,
        wrapped_dek_b64: String,
        generation: i64,
    }

    impl FakeMediaObjectStore {
        fn new(
            object_name: &str,
            ciphertext: Vec<u8>,
            wrapped_dek_b64: &str,
            generation: i64,
        ) -> Self {
            Self {
                object_name: object_name.to_owned(),
                ciphertext,
                wrapped_dek_b64: wrapped_dek_b64.to_owned(),
                generation,
            }
        }
    }

    #[async_trait]
    impl MediaObjectStore for FakeMediaObjectStore {
        async fn put_current(
            &self,
            _account_id: &str,
            _object_name: &str,
            _ciphertext: &[u8],
            _wrapped_dek_b64: &str,
        ) -> Result<i64> {
            Err(EnclaveError::Store("unexpected media put".into()))
        }

        async fn get_current(&self, object_name: &str) -> Result<GcsGetResponse> {
            if object_name != self.object_name {
                return Err(EnclaveError::NotFound);
            }
            Ok(GcsGetResponse {
                ciphertext: self.ciphertext.clone(),
                wrapped_dek_b64: self.wrapped_dek_b64.clone(),
                generation: self.generation,
            })
        }

        async fn get_current_generation(
            &self,
            _object_name: &str,
            _generation: i64,
        ) -> Result<GcsGetResponse> {
            Err(EnclaveError::Store(
                "unexpected media generation get".into(),
            ))
        }

        async fn delete_current(&self, _object_name: &str) -> Result<()> {
            Err(EnclaveError::Store("unexpected media delete".into()))
        }

        async fn purge_recordings(&self, _account_id: &str) -> Result<()> {
            Err(EnclaveError::Store("unexpected recording purge".into()))
        }

        async fn purge_account(&self, _account_id: &str) -> Result<()> {
            Err(EnclaveError::Store("unexpected account purge".into()))
        }
    }

    #[tokio::test]
    async fn adopts_only_exact_current_v2_ciphertext_under_the_installed_key() {
        const V2_MAGIC: &[u8] = b"KIOKU-BLOB\x02";
        let object_name = "raw/account-1/asset-1.enc";
        let context = crate::gcs::media_blob_context("account-1", object_name);
        let plaintext = b"exact captured media";
        let installed_dek = Dek([0x11; 32]);
        let installed_key_reference = "wrapped-installed-dek";
        let ciphertext =
            encrypt_bound_blob(&installed_dek, plaintext, &context).expect("encrypt current media");
        let current =
            FakeMediaObjectStore::new(object_name, ciphertext.clone(), installed_key_reference, 23);

        assert_eq!(
            verify_existing_media(
                &current,
                object_name,
                &context,
                plaintext,
                &installed_dek,
                installed_key_reference,
            )
            .await
            .expect("adopt exact lost response"),
            23
        );

        for generation in [0, -1] {
            let invalid_generation = FakeMediaObjectStore::new(
                object_name,
                ciphertext.clone(),
                installed_key_reference,
                generation,
            );
            assert!(matches!(
                verify_existing_media(
                    &invalid_generation,
                    object_name,
                    &context,
                    plaintext,
                    &installed_dek,
                    installed_key_reference,
                )
                .await,
                Err(EnclaveError::Conflict(_))
            ));
        }

        let wrong_key_reference =
            FakeMediaObjectStore::new(object_name, ciphertext.clone(), "wrapped-other-dek", 23);
        assert!(matches!(
            verify_existing_media(
                &wrong_key_reference,
                object_name,
                &context,
                plaintext,
                &installed_dek,
                installed_key_reference,
            )
            .await,
            Err(EnclaveError::Conflict(_))
        ));

        let unversioned = FakeMediaObjectStore::new(
            object_name,
            ciphertext[V2_MAGIC.len()..].to_vec(),
            installed_key_reference,
            23,
        );
        assert!(matches!(
            verify_existing_media(
                &unversioned,
                object_name,
                &context,
                plaintext,
                &installed_dek,
                installed_key_reference,
            )
            .await,
            Err(EnclaveError::Crypto(_))
        ));

        let wrong_context =
            crate::gcs::media_blob_context("account-1", "raw/account-1/different-asset.enc");
        assert!(matches!(
            verify_existing_media(
                &current,
                object_name,
                &wrong_context,
                plaintext,
                &installed_dek,
                installed_key_reference,
            )
            .await,
            Err(EnclaveError::Crypto(_))
        ));

        let wrong_dek = Dek([0x22; 32]);
        assert!(matches!(
            verify_existing_media(
                &current,
                object_name,
                &context,
                plaintext,
                &wrong_dek,
                installed_key_reference,
            )
            .await,
            Err(EnclaveError::Crypto(_))
        ));

        assert!(matches!(
            verify_existing_media(
                &current,
                object_name,
                &context,
                b"different plaintext",
                &installed_dek,
                installed_key_reference,
            )
            .await,
            Err(EnclaveError::Conflict(_))
        ));
    }
}
