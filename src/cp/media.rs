//! V2 raw-media capture API and cloud processing ledger.

use std::collections::HashSet;
use std::sync::Arc;

use axum::{
    extract::{DefaultBodyLimit, Multipart, Path, State},
    http::{header::RETRY_AFTER, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Extension, Json, Router,
};
use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::error::{EnclaveError, Result};

use super::isotime::parse_epoch_millis;
use super::{auth::AuthUser, limits, CpState};

const MAX_AUDIO_BYTES: i64 = 20 * 1024 * 1024;
const MAX_SCREENSHOT_BYTES: i64 = 5 * 1024 * 1024;
const MAX_ID_LEN: usize = 128;
const MAX_TEXT_LEN: usize = 20_000;
const MAX_TURNS: usize = 10_000;
const MAX_MANIFEST_BYTES: usize = 128 * 1024;
const MAX_MULTIPART_BYTES: usize = MAX_AUDIO_BYTES as usize + MAX_MANIFEST_BYTES + 64 * 1024;
const MEDIA_DEK_METADATA_KEY: &str = "wrapped_media_dek";

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
        if self.schema_version != 2 {
            return Err(EnclaveError::InvalidRequest(
                "schema_version must be 2".into(),
            ));
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
    if reference.hamming_distance > 3
        || !reference.pixel_change_ratio.is_finite()
        || !(0.0..=0.01).contains(&reference.pixel_change_ratio)
        || !validate_sha256(&reference.context_fingerprint)
        || reference.dedupe_version != 1
    {
        return Err(EnclaveError::InvalidRequest(
            "reference deduplication evidence is outside version 1 bounds".into(),
        ));
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
    facts: Vec<PersonFactView>,
}

#[derive(Debug, Serialize)]
struct PersonFactView {
    predicate: String,
    value: String,
    evidence: Value,
    created_at: String,
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
        .route("/api/v2/capture/events/{event_id}", get(capture_status))
        .route("/api/v2/capture/streams/{stream_id}/ack", get(stream_ack))
        .route("/api/v2/people", get(list_people))
        .route("/api/v2/people/{person_id}", get(person_profile))
        .layer(DefaultBodyLimit::max(MAX_MULTIPART_BYTES))
}

async fn upload_capture_event(
    State(state): State<Arc<CpState>>,
    Extension(user): Extension<AuthUser>,
    mut multipart: Multipart,
) -> Response {
    let user_id = user.0;
    match limits::account_active(&state.control, &user_id).await {
        Ok(true) => {}
        Ok(false) => {
            return (
                StatusCode::FORBIDDEN,
                Json(json!({"error": "account_suspended"})),
            )
                .into_response()
        }
        Err(error) => {
            tracing::error!(error = %error, "capture account status lookup failed");
            return (StatusCode::SERVICE_UNAVAILABLE, "service unavailable").into_response();
        }
    }
    if !state.sync_limiter.consume(&user_id).await {
        return rate_limited_response();
    }

    let mut manifest_bytes: Option<Vec<u8>> = None;
    let mut media_bytes: Option<Vec<u8>> = None;
    let mut media_content_type: Option<String> = None;
    loop {
        let field = match multipart.next_field().await {
            Ok(Some(field)) => field,
            Ok(None) => break,
            Err(_) => return bad_request("invalid multipart body"),
        };
        let name = field.name().unwrap_or_default().to_string();
        match name.as_str() {
            "manifest" if manifest_bytes.is_none() => match field.bytes().await {
                Ok(bytes) if bytes.len() <= MAX_MANIFEST_BYTES => {
                    manifest_bytes = Some(bytes.to_vec())
                }
                Ok(_) => return bad_request("manifest is too large"),
                Err(_) => return bad_request("invalid manifest field"),
            },
            "media" if media_bytes.is_none() => {
                media_content_type = field.content_type().map(ToOwned::to_owned);
                match field.bytes().await {
                    Ok(bytes) if bytes.len() <= MAX_AUDIO_BYTES as usize => {
                        media_bytes = Some(bytes.to_vec())
                    }
                    Ok(_) => {
                        return (StatusCode::PAYLOAD_TOO_LARGE, "media is too large")
                            .into_response()
                    }
                    Err(_) => return bad_request("invalid media field"),
                }
            }
            "manifest" | "media" => return bad_request("duplicate multipart field"),
            _ => return bad_request("unknown multipart field"),
        }
    }
    let Some(manifest_bytes) = manifest_bytes else {
        return bad_request("manifest field is required");
    };
    let manifest: CaptureEventManifest = match serde_json::from_slice(&manifest_bytes) {
        Ok(value) => value,
        Err(_) => return bad_request("manifest is not valid capture schema v2 JSON"),
    };
    if let Err(error) = manifest.validate() {
        return error.into_response();
    }
    match manifest.media_disposition {
        MediaDisposition::Canonical => {
            let Some(bytes) = media_bytes.as_deref() else {
                return bad_request("canonical events require a media field");
            };
            if let Err(error) =
                validate_media_bytes(&manifest, bytes, media_content_type.as_deref())
            {
                return error.into_response();
            }
        }
        MediaDisposition::Reference if media_bytes.is_some() => {
            return bad_request("reference events cannot contain a media field")
        }
        MediaDisposition::Reference => {}
    }
    let digest = match manifest_digest(&manifest) {
        Ok(value) => value,
        Err(error) => return error.into_response(),
    };
    let asset_id = match response_asset_id(&manifest) {
        Ok(value) => value,
        Err(error) => return error.into_response(),
    };
    let object_key = manifest
        .media
        .as_ref()
        .map(|media| format!("raw/{user_id}/{}.enc", media.asset_id));
    let preflight = state
        .store
        .with_user(&user_id, |conn| {
            preflight_source_event(conn, &manifest, &digest, object_key.as_deref())
        })
        .await;
    match preflight {
        Ok(PreflightOutcome::Duplicate {
            committed_through_sequence,
        }) => {
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
                .into_response()
        }
        Ok(PreflightOutcome::New) => {}
        Err(error) => return error.into_response(),
    }

    if manifest.media_disposition == MediaDisposition::Canonical {
        let object_key = object_key
            .as_deref()
            .expect("validated canonical object key");
        let media_bytes = media_bytes.as_deref().expect("validated canonical media");
        let (media_dek, wrapped_dek) = match load_or_create_media_dek(&state, &user_id).await {
            Ok(value) => value,
            Err(error) => {
                tracing::error!(error = %error, "capture media key setup failed");
                return (StatusCode::INTERNAL_SERVER_ERROR, "media upload failed").into_response();
            }
        };
        let media_context = crate::store::media_blob_context(&user_id, object_key);
        let encrypted =
            match crate::crypto::encrypt_bound_blob(&media_dek, media_bytes, &media_context) {
                Ok(value) => value,
                Err(error) => {
                    tracing::error!(error = %error, "capture media encryption failed");
                    return (StatusCode::INTERNAL_SERVER_ERROR, "media upload failed")
                        .into_response();
                }
            };
        if let Err(put_error) = state
            .store
            .put_media(object_key, &encrypted, &wrapped_dek)
            .await
        {
            if let Err(error) =
                verify_existing_media(&state, &user_id, object_key, &media_context, media_bytes)
                    .await
            {
                tracing::error!(error = %put_error, verify_error = %error, "capture media storage failed");
                return (StatusCode::INTERNAL_SERVER_ERROR, "media upload failed").into_response();
            }
        }
    }

    let outcome = state
        .store
        .with_user(&user_id, |conn| {
            match manifest.media_disposition {
                MediaDisposition::Canonical => record_source_event(
                    conn,
                    &user_id,
                    &manifest,
                    &digest,
                    object_key
                        .as_deref()
                        .expect("validated canonical object key"),
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
        Err(error) => return error.into_response(),
    };
    if let Err(error) = state.store.save_user(&user_id).await {
        tracing::error!(error = %error, "capture database persistence failed");
        return (StatusCode::INTERNAL_SERVER_ERROR, "media upload failed").into_response();
    }
    (
        StatusCode::CREATED,
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

async fn stream_ack(
    State(state): State<Arc<CpState>>,
    Extension(user): Extension<AuthUser>,
    Path(stream_id): Path<String>,
) -> Response {
    if let Err(error) = validate_id("stream_id", &stream_id) {
        return error.into_response();
    }
    match state
        .store
        .with_user(&user.0, |conn| committed_through_sequence(conn, &stream_id))
        .await
    {
        Ok(committed) => Json(StreamAck {
            stream_id,
            committed_through_sequence: committed,
        })
        .into_response(),
        Err(error) => error.into_response(),
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
    match state
        .store
        .with_user(&user.0, |conn| load_capture_status(conn, &event_id))
        .await
    {
        Ok(Some(status)) => Json(status).into_response(),
        Ok(None) => EnclaveError::NotFound.into_response(),
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

async fn list_people(
    State(state): State<Arc<CpState>>,
    Extension(user): Extension<AuthUser>,
) -> Response {
    match state
        .store
        .with_user(&user.0, |conn| {
            let mut statement = conn.prepare(
                "SELECT p.id,p.display_name,COUNT(DISTINCT v.id),COUNT(DISTINCT f.id),p.updated_at \
                 FROM people p LEFT JOIN voice_profiles v ON v.person_id=p.id \
                 LEFT JOIN person_facts f ON f.person_id=p.id AND f.status='active' \
                 WHERE p.status='identified' AND p.display_name IS NOT NULL \
                 GROUP BY p.id ORDER BY lower(p.display_name),p.id LIMIT 500",
            )?;
            let people = statement
                .query_map([], |row| {
                    Ok(PersonSummary {
                        id: row.get(0)?,
                        display_name: row.get(1)?,
                        voice_profile_count: row.get(2)?,
                        fact_count: row.get(3)?,
                        updated_at: row.get(4)?,
                    })
                })?
                .collect::<std::result::Result<Vec<_>, _>>()?;
            Ok(people)
        })
        .await
    {
        Ok(people) => Json(json!({"people": people})).into_response(),
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
        .store
        .with_user(&user.0, |conn| load_person_profile(conn, person_id))
        .await
    {
        Ok(profile) => Json(profile).into_response(),
        Err(error) => error.into_response(),
    }
}

fn load_person_profile(conn: &Connection, person_id: i64) -> Result<PersonProfile> {
    let person = conn
        .query_row(
            "SELECT p.id,p.display_name,COUNT(DISTINCT v.id),COUNT(DISTINCT f.id),p.updated_at \
             FROM people p LEFT JOIN voice_profiles v ON v.person_id=p.id \
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
        "SELECT label FROM voice_profiles WHERE person_id=?1 AND status<>'quarantined' ORDER BY id",
    )?;
    let voice_labels = voice_statement
        .query_map([person_id], |row| row.get(0))?
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let mut facts_statement = conn.prepare(
        "SELECT predicate,value,evidence_json,created_at FROM person_facts \
         WHERE person_id=?1 AND status='active' ORDER BY created_at,id",
    )?;
    let facts = facts_statement
        .query_map([person_id], |row| {
            let evidence_json: String = row.get(2)?;
            Ok(PersonFactView {
                predicate: row.get(0)?,
                value: row.get(1)?,
                evidence: serde_json::from_str(&evidence_json).unwrap_or(Value::Null),
                created_at: row.get(3)?,
            })
        })?
        .collect::<std::result::Result<Vec<_>, _>>()?;
    Ok(PersonProfile {
        person,
        voice_labels,
        facts,
    })
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

async fn load_or_create_media_dek(
    state: &CpState,
    user_id: &str,
) -> Result<(crate::crypto::Dek, String)> {
    let existing: Option<String> = state
        .store
        .with_user(user_id, |conn| {
            Ok(conn
                .query_row(
                    "SELECT value FROM app_metadata WHERE key=?1",
                    [MEDIA_DEK_METADATA_KEY],
                    |row| row.get(0),
                )
                .optional()?)
        })
        .await?;
    if let Some(wrapped) = existing {
        let dek = crate::crypto::load_dek(state.store.kms.as_ref(), &wrapped).await?;
        return Ok((dek, wrapped));
    }
    let (candidate_dek, candidate_wrapped) =
        crate::crypto::generate_and_wrap_dek(state.store.kms.as_ref()).await?;
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
            received_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
            UNIQUE(device_id, stream_id, sequence)
        );
        CREATE INDEX IF NOT EXISTS idx_capture_events_time
            ON capture_events(started_at, event_id);
        CREATE TABLE IF NOT EXISTS media_objects (
            asset_id TEXT PRIMARY KEY,
            event_id TEXT NOT NULL UNIQUE REFERENCES capture_events(event_id) ON DELETE CASCADE,
            object_key TEXT NOT NULL UNIQUE,
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
            UNIQUE(event_id, turn_id)
        );
        CREATE TABLE IF NOT EXISTS people (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            display_name TEXT,
            normalized_name TEXT UNIQUE,
            status TEXT NOT NULL DEFAULT 'unknown' CHECK (status IN ('unknown','identified','quarantined')),
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
            similarity REAL,
            decision_margin REAL,
            accepted INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
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
            created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
        );
        "#,
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
    ] {
        add_column_if_missing(conn, "capture_events", column, alteration)?;
    }
    conn.execute_batch(
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_people_normalized_name \
         ON people(normalized_name) WHERE normalized_name IS NOT NULL;\
         CREATE INDEX IF NOT EXISTS idx_capture_events_canonical_reference \
         ON capture_events(canonical_event_id) WHERE canonical_event_id IS NOT NULL;",
    )?;
    Ok(())
}

fn add_column_if_missing(
    conn: &Connection,
    table: &str,
    column: &str,
    alteration: &str,
) -> Result<()> {
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

pub fn record_source_event(
    conn: &Connection,
    account_id: &str,
    manifest: &CaptureEventManifest,
    manifest_digest: &str,
    object_key: &str,
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

    let tx = conn.unchecked_transaction()?;
    tx.execute(
        "INSERT INTO capture_sessions \
         (id, device_id, install_id, started_at, last_event_at, schema_version) \
         VALUES (?1,?2,?3,?4,?5,2) \
         ON CONFLICT(id) DO UPDATE SET last_event_at=MAX(last_event_at, excluded.last_event_at)",
        params![
            manifest.capture_session_id,
            manifest.device_id,
            manifest.install_id,
            manifest.started_at,
            manifest.ended_at
        ],
    )?;
    tx.execute(
        "INSERT INTO capture_streams \
         (id, capture_session_id, device_id, stream_kind) VALUES (?1,?2,?3,?4) \
         ON CONFLICT(id) DO NOTHING",
        params![
            manifest.stream_id,
            manifest.capture_session_id,
            manifest.device_id,
            manifest.stream_kind.as_str()
        ],
    )?;
    let context_json = manifest
        .context
        .as_ref()
        .map(serde_json::to_string)
        .transpose()?;
    let event_insert = tx.execute(
        "INSERT INTO capture_events \
         (event_id,device_id,install_id,capture_session_id,stream_id,stream_kind,sequence, \
          source_wall_at,source_monotonic_ns,started_at,ended_at,timezone_id,utc_offset_minutes, \
          clock_uncertainty_ms,asset_id,manifest_digest,context_json) \
         VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17)",
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
            context_json
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
    tx.execute(
        "INSERT INTO media_objects \
         (asset_id,event_id,object_key,mime_type,codec,byte_length,sha256,sample_rate,channels, \
          frame_count,width,height,scale,orientation,retain_until) \
         VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15)",
        params![
            media.asset_id,
            manifest.event_id,
            object_key,
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
            super::isotime::add_seconds(&manifest.ended_at, 30.0 * 86_400.0)
        ],
    )?;
    record_browser_observation(&tx, manifest)?;
    let job_kind = if manifest.stream_kind.is_audio() {
        "gemini_audio"
    } else {
        "gemini_screen"
    };
    tx.execute(
        "INSERT INTO media_processing_jobs \
         (event_id,job_kind,input_revision,processor_version,state) \
         VALUES (?1,?2,?3,1,'pending')",
        params![manifest.event_id, job_kind, manifest_digest],
    )?;
    advance_contiguous_ack(&tx, &manifest.stream_id)?;
    tx.commit()?;
    Ok(RecordOutcome::Created)
}

fn semantic_context_value(context: &CaptureContext) -> Value {
    json!({
        "active_app": context.active_app,
        "active_url": context.active_url,
        "active_url_title": context.active_url_title,
        "browser_permission_status": context.browser_permission_status,
        "capture_status": context.capture_status,
        "display_id": context.display_id,
        "primary_bundle_id": context.primary_bundle_id,
        "primary_window_id": context.primary_window_id,
        "visible_windows": context.visible_windows,
        "visible_windows_truncated": context.visible_windows_truncated,
        "window_title": context.window_title,
    })
}

fn semantic_context_fingerprint(context: &CaptureContext) -> Result<String> {
    Ok(sha256_hex(&serde_json::to_vec(&semantic_context_value(
        context,
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

fn record_reference_event(
    conn: &Connection,
    account_id: &str,
    manifest: &CaptureEventManifest,
    manifest_digest: &str,
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
        .eq_ignore_ascii_case(&semantic_context_fingerprint(current_context)?)
    {
        return Err(EnclaveError::InvalidRequest(
            "reference context fingerprint does not match the manifest".into(),
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
        return Err(EnclaveError::InvalidRequest(
            "referenced canonical screen is unavailable".into(),
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
        return Err(EnclaveError::InvalidRequest(
            "referenced screen must be an earlier canonical event in the same capture stream"
                .into(),
        ));
    }
    let canonical_context: CaptureContext = canonical
        .context_json
        .as_deref()
        .ok_or_else(|| {
            EnclaveError::InvalidRequest("canonical screen has no capture context".into())
        })
        .and_then(|raw| {
            serde_json::from_str(raw).map_err(|_| {
                EnclaveError::InvalidRequest("canonical screen context is invalid".into())
            })
        })?;
    if semantic_context_value(&canonical_context) != semantic_context_value(current_context) {
        return Err(EnclaveError::InvalidRequest(
            "reference events cannot hide a visible context transition".into(),
        ));
    }

    let tx = conn.unchecked_transaction()?;
    tx.execute(
        "INSERT INTO capture_sessions \
         (id,device_id,install_id,started_at,last_event_at,schema_version) \
         VALUES (?1,?2,?3,?4,?5,2) \
         ON CONFLICT(id) DO UPDATE SET last_event_at=MAX(last_event_at,excluded.last_event_at)",
        params![
            manifest.capture_session_id,
            manifest.device_id,
            manifest.install_id,
            manifest.started_at,
            manifest.ended_at
        ],
    )?;
    tx.execute(
        "INSERT INTO capture_streams \
         (id,capture_session_id,device_id,stream_kind) VALUES (?1,?2,?3,?4) \
         ON CONFLICT(id) DO NOTHING",
        params![
            manifest.stream_id,
            manifest.capture_session_id,
            manifest.device_id,
            manifest.stream_kind.as_str()
        ],
    )?;
    let context_json = serde_json::to_string(current_context)?;
    let internal_asset_id = format!("reference-{}", manifest.event_id);
    let event_insert = tx.execute(
        "INSERT INTO capture_events \
         (event_id,device_id,install_id,capture_session_id,stream_id,stream_kind,sequence,\
          source_wall_at,source_monotonic_ns,started_at,ended_at,timezone_id,utc_offset_minutes,\
          clock_uncertainty_ms,asset_id,manifest_digest,context_json,media_disposition,\
          canonical_event_id,canonical_asset_id,canonical_media_sha256,perceptual_hash,\
          hamming_distance,pixel_change_ratio,context_fingerprint,dedupe_version) \
         VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,\
                 'reference',?18,?19,?20,?21,?22,?23,?24,?25)",
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
    record_browser_observation(&tx, manifest)?;
    advance_contiguous_ack(&tx, &manifest.stream_id)?;
    tx.commit()?;
    Ok(RecordOutcome::Created)
}

fn record_browser_observation(conn: &Connection, manifest: &CaptureEventManifest) -> Result<()> {
    let Some(context) = &manifest.context else {
        return Ok(());
    };
    if let Some(snapshot) = &context.browser_snapshot {
        let tabs_json = serde_json::to_string(&snapshot.tabs)?;
        conn.execute(
            "INSERT INTO browser_states_v2 \
             (state_key,browser_bundle_id,browser_name,permission_status,content_hash,tabs_json) \
             VALUES (?1,?2,?3,?4,?5,?6) ON CONFLICT(state_key) DO NOTHING",
            params![
                snapshot.state_key,
                snapshot.browser_bundle_id,
                snapshot.browser_name,
                snapshot.permission_status,
                snapshot.content_hash.to_ascii_lowercase(),
                tabs_json
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
         (observation_id,event_id,observed_at,state_key,context_status,active_url,active_title) \
         VALUES (?1,?1,?2,?3,?4,?5,?6)",
        params![
            manifest.event_id,
            manifest.source_wall_at,
            state_key,
            context.capture_status,
            context.active_url,
            context.active_url_title
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
            context_fingerprint: semantic_context_fingerprint(context).unwrap(),
            dedupe_version: 1,
        });
        reference
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
            "speaker_observations",
            "voice_profiles",
            "voice_samples",
            "identity_evidence",
            "people",
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
    fn identical_event_is_duplicate_but_changed_manifest_conflicts() {
        let conn = Connection::open_in_memory().unwrap();
        init_schema(&conn).unwrap();
        let manifest = valid_manifest();
        let digest_1 = "a".repeat(64);
        let digest_2 = "b".repeat(64);
        let first =
            record_source_event(&conn, "account-1", &manifest, &digest_1, "object-1").unwrap();
        assert_eq!(first, RecordOutcome::Created);

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
                        semantic_context_fingerprint(reference.context.as_ref().unwrap()).unwrap();
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
            ("speaker_observations", "started_at, event_id, id"),
            ("people", "display_name, id"),
            ("voice_profiles", "person_id, id"),
            ("voice_samples", "speaker_observation_id, id"),
            ("identity_evidence", "created_at, id"),
            ("person_facts", "person_id, created_at, id"),
        ] {
            assert!(crate::dump_optional_table(&conn, table, order)
                .unwrap()
                .is_empty());
        }
    }

    #[test]
    fn rate_limit_response_exposes_retry_after_to_native_uploaders() {
        let response = rate_limited_response();
        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(response.headers().get(RETRY_AFTER).unwrap(), "5");
    }
}
