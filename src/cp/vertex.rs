//! Vertex AI client for episode summarization and unified episode analysis. Gemini
//! `generateContent` uses a
//! constrained `responseSchema`. Credentials come from the VM metadata server
//! (cloud-platform scope), same pattern as the GCS/KMS clients.
//!
//! Only the Gemini path is implemented; `VERTEX_MODEL` defaults to the current
//! Gemini 3.5 Flash deployment. These calls send bounded assembled text,
//! decrypted audio windows, and screen storyboards to Vertex outside the TEE.

use base64::{engine::general_purpose::STANDARD as B64, Engine};
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::Digest;
use std::time::Instant;
use tokio::sync::OwnedMutexGuard;

use crate::error::{EnclaveError, Result};

use super::{model_usage, CpState};

const METADATA_TOKEN_URL: &str =
    "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token";
const GENERATION_TIMEOUT_SECONDS: u64 = 120;
pub(crate) const MAX_TEXT_OUTPUT_TOKENS: u32 = 8_192;
pub(crate) const MAX_MEDIA_OUTPUT_TOKENS: u32 = 4_096;
pub(crate) const MAX_SCREEN_OUTPUT_TOKENS: u32 = 1_024;

/// Serialize the complete user-specific Vertex lifecycle with account
/// deletion. The active-account check deliberately happens after acquiring
/// the fence, so a request queued behind deletion cannot recreate its index or
/// send plaintext after the account has become inactive.
async fn lock_active_user_lifecycle(
    store: &crate::store::Store,
    control: &super::control_store::ControlStore,
    user_id: &str,
) -> Result<OwnedMutexGuard<()>> {
    let guard = store.lock_user_lifecycle(user_id).await?;
    if !super::limits::account_active(control, user_id).await? {
        return Err(EnclaveError::Auth("account inactive".into()));
    }
    Ok(guard)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VertexOperation {
    EpisodeSummary,
    EpisodeSummaryRepair,
    SubstanceBackfill,
    VisualEvidenceBackfill,
    FinalEpisodeAnalysis,
    AudioWindow,
    ScreenStoryboard,
}

impl VertexOperation {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::EpisodeSummary
            | Self::EpisodeSummaryRepair
            | Self::SubstanceBackfill
            | Self::VisualEvidenceBackfill => "episode_summarization",
            Self::FinalEpisodeAnalysis => "episode_finalization",
            Self::AudioWindow => "audio_understanding",
            Self::ScreenStoryboard => "screen_understanding",
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub(crate) struct VertexUsage {
    pub prompt_details_present: bool,
    pub cache_details_present: bool,
    pub prompt_tokens: Option<u64>,
    pub input_text_tokens: Option<u64>,
    pub input_audio_tokens: Option<u64>,
    pub input_image_tokens: Option<u64>,
    pub cached_input_tokens: Option<u64>,
    pub cached_input_text_tokens: Option<u64>,
    pub cached_input_audio_tokens: Option<u64>,
    pub cached_input_image_tokens: Option<u64>,
    pub output_tokens: Option<u64>,
    pub tool_use_prompt_tokens: Option<u64>,
    pub thought_tokens: Option<u64>,
    pub total_tokens: Option<u64>,
}

fn detail_token_count(
    usage: &serde_json::Map<String, Value>,
    details_key: &str,
    modality: &str,
) -> Option<u64> {
    usage
        .get(details_key)
        .and_then(Value::as_array)
        .and_then(|details| {
            details.iter().find_map(|detail| {
                (detail.get("modality").and_then(Value::as_str) == Some(modality))
                    .then(|| detail.get("tokenCount").and_then(Value::as_u64))
                    .flatten()
            })
        })
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct VertexMetadata {
    pub usage: Option<VertexUsage>,
    pub model_version: Option<String>,
    pub traffic_type: Option<String>,
}

pub struct TextGeneration {
    pub text: String,
    #[allow(dead_code)] // retained for callers that need provider metadata
    pub metadata: VertexMetadata,
    /// The durable ADR-0022 F2 invocation identity ("vtx_…") this response
    /// settled under; the finalization commit plan anchors on it.
    #[allow(dead_code)]
    pub event_id: String,
}

pub struct MediaGeneration {
    pub text: String,
    pub metadata: VertexMetadata,
    pub latency_ms: u64,
}

fn bounded_output_tokens(requested: u32) -> u32 {
    requested.clamp(1, MAX_TEXT_OUTPUT_TOKENS)
}

fn bounded_media_output_tokens(requested: u32) -> u32 {
    requested.clamp(1, MAX_MEDIA_OUTPUT_TOKENS)
}

fn response_metadata(data: &Value) -> VertexMetadata {
    let usage = data
        .get("usageMetadata")
        .and_then(Value::as_object)
        .map(|usage| VertexUsage {
            prompt_details_present: usage
                .get("promptTokensDetails")
                .is_some_and(Value::is_array),
            cache_details_present: usage.get("cacheTokensDetails").is_some_and(Value::is_array),
            prompt_tokens: usage.get("promptTokenCount").and_then(Value::as_u64),
            input_text_tokens: detail_token_count(usage, "promptTokensDetails", "TEXT"),
            input_audio_tokens: detail_token_count(usage, "promptTokensDetails", "AUDIO"),
            input_image_tokens: detail_token_count(usage, "promptTokensDetails", "IMAGE"),
            cached_input_tokens: usage.get("cachedContentTokenCount").and_then(Value::as_u64),
            cached_input_text_tokens: detail_token_count(usage, "cacheTokensDetails", "TEXT"),
            cached_input_audio_tokens: detail_token_count(usage, "cacheTokensDetails", "AUDIO"),
            cached_input_image_tokens: detail_token_count(usage, "cacheTokensDetails", "IMAGE"),
            output_tokens: usage.get("candidatesTokenCount").and_then(Value::as_u64),
            tool_use_prompt_tokens: usage.get("toolUsePromptTokenCount").and_then(Value::as_u64),
            thought_tokens: usage.get("thoughtsTokenCount").and_then(Value::as_u64),
            total_tokens: usage.get("totalTokenCount").and_then(Value::as_u64),
        });
    VertexMetadata {
        traffic_type: data
            .get("usageMetadata")
            .and_then(|value| value.get("trafficType"))
            .and_then(Value::as_str)
            .map(str::to_string),
        usage,
        model_version: data
            .get("modelVersion")
            .and_then(Value::as_str)
            .map(str::to_string),
    }
}

fn log_usage(
    metadata: &VertexMetadata,
    operation: VertexOperation,
    model: &str,
    output_limit: u32,
) {
    let usage = metadata.usage.as_ref();
    tracing::info!(
        operation = operation.as_str(),
        model,
        output_limit,
        usage_present = usage.is_some(),
        prompt_tokens = usage.and_then(|value| value.prompt_tokens),
        input_text_tokens = usage.and_then(|value| value.input_text_tokens),
        input_audio_tokens = usage.and_then(|value| value.input_audio_tokens),
        input_image_tokens = usage.and_then(|value| value.input_image_tokens),
        cached_input_tokens = usage.and_then(|value| value.cached_input_tokens),
        cached_input_text_tokens = usage.and_then(|value| value.cached_input_text_tokens),
        cached_input_audio_tokens = usage.and_then(|value| value.cached_input_audio_tokens),
        cached_input_image_tokens = usage.and_then(|value| value.cached_input_image_tokens),
        output_tokens = usage.and_then(|value| value.output_tokens),
        tool_use_prompt_tokens = usage.and_then(|value| value.tool_use_prompt_tokens),
        thought_tokens = usage.and_then(|value| value.thought_tokens),
        total_tokens = usage.and_then(|value| value.total_tokens),
        "Vertex inference usage"
    );
}

#[derive(Deserialize)]
struct TokenResp {
    access_token: String,
}

async fn access_token(http: &reqwest::Client) -> Result<String> {
    let tok: TokenResp = http
        .get(METADATA_TOKEN_URL)
        .header("Metadata-Flavor", "Google")
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    Ok(tok.access_token)
}

/// The constrained-decoding schema the model must emit (matches summarizer.js).
fn response_schema() -> Value {
    json!({
        "type": "OBJECT",
        "properties": {
            "episodes": {
                "type": "ARRAY",
                "items": {
                    "type": "OBJECT",
                    "properties": {
                        "episode_ref": {"type": "STRING"},
                        "started_at": {"type": "STRING"},
                        "ended_at": {"type": "STRING"},
                        "type": {"type": "STRING", "enum": ["meeting","lesson","call","coding","browsing","break","other"]},
                        "title": {"type": "STRING"},
                        "summary": {"type": "STRING"},
                        "participants": {"type": "ARRAY", "items": {"type": "STRING"}},
                        "languages": {"type": "ARRAY", "items": {"type": "STRING"}},
                        "action_items": {"type": "ARRAY", "items": {"type": "STRING"}},
                        "substance": {"type": "STRING", "enum": ["none","low","normal"]},
                        "visual_evidence": {"type": "STRING", "enum": ["none","useful"]},
                        // ADR-0004: minute-timeline gists, generated eagerly in
                        // this same pass. Constrained decoding emits nothing
                        // that isn't in the schema — without this field the
                        // model could never return minutes.
                        "minutes": {
                            "type": "ARRAY",
                            "items": {
                                "type": "OBJECT",
                                "properties": {
                                    "start": {"type": "STRING"},
                                    "gist": {"type": "STRING"}
                                },
                                "required": ["start","gist"]
                            }
                        }
                    },
                    "required": ["started_at","ended_at","title","summary","action_items","substance","visual_evidence","minutes"]
                }
            }
        },
        "required": ["episodes"]
    })
}

/// Call Gemini and return the raw response text (expected to be JSON per the
/// schema). `Err` with a `quota` marker string on HTTP 429.
pub async fn generate(
    state: &CpState,
    user_id: &str,
    operation: VertexOperation,
    system: &str,
    user_message: &str,
) -> Result<TextGeneration> {
    generate_custom(
        state,
        user_id,
        operation,
        system,
        user_message,
        response_schema(),
        MAX_TEXT_OUTPUT_TOKENS,
    )
    .await
}

/// Call Gemini with a caller-supplied constrained-decoding schema. The episode
/// summarizer uses [`generate`]; ADR-0009's one-time historical classifier uses
/// this entry point with a compact `{id, substance}` schema.
pub async fn generate_custom(
    state: &CpState,
    user_id: &str,
    operation: VertexOperation,
    system: &str,
    user_message: &str,
    schema: Value,
    max_output_tokens: u32,
) -> Result<TextGeneration> {
    // Hold through the durable terminal usage write on every response/error
    // path. Account deletion waits here before it destroys the usage ledger.
    let _lifecycle_guard =
        lock_active_user_lifecycle(&state.store, &state.control, user_id).await?;
    let config = &state.config;
    let model = &config.vertex_model;
    if config.vertex_project.is_empty() {
        return Err(EnclaveError::Config("VERTEX_PROJECT not set".into()));
    }
    let max_output_tokens = bounded_output_tokens(max_output_tokens);
    // The output ceiling makes two minutes sufficient. A shorter client
    // timeout also limits how long a lost response can block the serialized
    // workers; retries are bounded separately by their durable queues.
    let http = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(GENERATION_TIMEOUT_SECONDS))
        .build()?;
    let token = access_token(&http).await?;

    let url = format!(
        "https://aiplatform.googleapis.com/v1/projects/{}/locations/{}/publishers/google/models/{}:generateContent",
        config.vertex_project, config.vertex_location, model
    );
    let body = json!({
        "contents": [{ "role": "user", "parts": [{ "text": user_message }] }],
        "systemInstruction": { "parts": [{ "text": system }] },
        "generationConfig": {
            // Cost safety boundary: callers may request less, never more.
            "maxOutputTokens": max_output_tokens,
            "responseMimeType": "application/json",
            "responseSchema": schema,
            "thinkingConfig": { "thinkingBudget": 0 }
        }
    });

    // ADR-0022 F2: the caller anchor is a pure function of the assembled
    // request, so a crash-retry of the same logical call derives the same
    // invocation identity while a genuinely different request cannot adopt
    // an old intent.
    let caller_anchor: [u8; 32] = sha2::Sha256::digest(body.to_string().as_bytes()).into();
    let invocation =
        model_usage::begin_invocation(state, user_id, operation, model, &caller_anchor).await?;
    let response = http.post(&url).bearer_auth(&token).json(&body).send().await;

    let resp = match response {
        Ok(response) => response,
        Err(error) => {
            model_usage::record_ambiguous(state, user_id, &invocation, None).await;
            return Err(error.into());
        }
    };

    if resp.status().as_u16() == 429 {
        model_usage::record_not_billed(state, user_id, &invocation, 429).await;
        return Err(EnclaveError::Config("quota".into()));
    }
    let error_status = resp.status().as_u16();
    let resp = match resp.error_for_status() {
        Ok(response) => response,
        Err(error) => {
            model_usage::record_not_billed(state, user_id, &invocation, error_status).await;
            return Err(error.into());
        }
    };
    let data: Value = match resp.json().await {
        Ok(data) => data,
        Err(error) => {
            model_usage::record_ambiguous(state, user_id, &invocation, Some(200)).await;
            return Err(error.into());
        }
    };
    let metadata = response_metadata(&data);
    log_usage(&metadata, operation, model, max_output_tokens);
    model_usage::record_response(state, user_id, &invocation, &metadata).await;
    let text: String = data
        .get("candidates")
        .and_then(|c| c.get(0))
        .and_then(|c| c.get("content"))
        .and_then(|c| c.get("parts"))
        .and_then(|p| p.as_array())
        .map(|parts| {
            parts
                .iter()
                .filter_map(|p| p.get("text").and_then(|t| t.as_str()))
                .collect::<String>()
        })
        .unwrap_or_default();
    if text.is_empty() {
        // Surface the finishReason (SAFETY / MAX_TOKENS / RECITATION / …) —
        // it's the difference between a transient blip and a window that will
        // deterministically fail forever. Metadata only, never content.
        let finish = data
            .get("candidates")
            .and_then(|c| c.get(0))
            .and_then(|c| c.get("finishReason"))
            .and_then(|f| f.as_str())
            .unwrap_or("<no candidates>");
        return Err(EnclaveError::Config(format!(
            "unexpected Vertex response shape (finishReason: {finish})"
        )));
    }
    Ok(TextGeneration {
        text,
        metadata,
        event_id: invocation,
    })
}

fn media_request_body(
    prompt: &str,
    mime_type: &str,
    media: &[u8],
    schema: Value,
    audio_timestamp: bool,
) -> Value {
    json!({
        "contents": [{
            "role": "user",
            "parts": [
                {"inlineData": {"mimeType": mime_type, "data": B64.encode(media)}},
                {"text": prompt}
            ]
        }],
        "generationConfig": {
            "maxOutputTokens": MAX_MEDIA_OUTPUT_TOKENS,
            "responseMimeType": "application/json",
            "responseSchema": schema,
            "audioTimestamp": audio_timestamp,
            "thinkingConfig": {"thinkingBudget": 0}
        }
    })
}

pub struct MediaInput<'a> {
    pub id: &'a str,
    pub mime_type: &'a str,
    pub media: &'a [u8],
}

impl<'a> MediaInput<'a> {
    pub fn new(id: &'a str, mime_type: &'a str, media: &'a [u8]) -> Self {
        Self {
            id,
            mime_type,
            media,
        }
    }
}

fn media_parts_request_body(
    prompt: &str,
    inputs: &[MediaInput<'_>],
    schema: Value,
    audio_timestamp: bool,
    max_output_tokens: u32,
) -> Value {
    let mut parts = Vec::with_capacity(inputs.len().saturating_mul(2).saturating_add(1));
    for input in inputs {
        parts.push(json!({"text": format!("frame_id: {}", input.id)}));
        parts.push(json!({
            "inlineData": {
                "mimeType": input.mime_type,
                "data": B64.encode(input.media),
            }
        }));
    }
    parts.push(json!({"text": prompt}));
    json!({
        "contents": [{"role":"user", "parts": parts}],
        "generationConfig": {
            "maxOutputTokens": bounded_media_output_tokens(max_output_tokens),
            "responseMimeType": "application/json",
            "responseSchema": schema,
            "audioTimestamp": audio_timestamp,
            "thinkingConfig": {"thinkingBudget": 0}
        }
    })
}

async fn send_media_request(
    state: &CpState,
    user_id: &str,
    body: Value,
    operation: VertexOperation,
    max_output_tokens: u32,
    pinned_invocation: Option<String>,
) -> Result<MediaGeneration> {
    // Both audio and storyboard calls share the same deletion fence as the
    // text path; no user-specific Vertex egress bypasses this function.
    let _lifecycle_guard =
        lock_active_user_lifecycle(&state.store, &state.control, user_id).await?;
    let config = &state.config;
    if config.vertex_project.is_empty() {
        return Err(EnclaveError::Config("VERTEX_PROJECT not set".into()));
    }
    // ADR-0022 slice 10e: a pinned invocation identity was already durably
    // fixed by a sealed pre-provider attempt boundary (the screen-storyboard
    // attempt plan records the exact `started` billing intent before any
    // egress), so this path must not mint a second intent for the same paid
    // call. The terminal usage settlements only route through the WAL lane
    // for a selected user, so a pinned identity for an unselected user
    // refuses here — before any provider traffic — instead of egressing
    // without a durable billing intent.
    if pinned_invocation.is_some() && !state.store.is_wal_authoritative(user_id) {
        return Err(EnclaveError::Store(
            "pinned media invocation requires a WAL-authoritative user".into(),
        ));
    }
    let http = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(GENERATION_TIMEOUT_SECONDS))
        .build()?;
    let token = access_token(&http).await?;
    let url = format!(
        "https://aiplatform.googleapis.com/v1/projects/{}/locations/{}/publishers/google/models/{}:generateContent",
        config.vertex_project, config.vertex_location, config.vertex_model
    );
    let caller_anchor: [u8; 32] = sha2::Sha256::digest(body.to_string().as_bytes()).into();
    let invocation = match pinned_invocation {
        Some(event_id) => event_id,
        None => {
            model_usage::begin_invocation(
                state,
                user_id,
                operation,
                &config.vertex_model,
                &caller_anchor,
            )
            .await?
        }
    };
    let started = Instant::now();
    let response = http.post(&url).bearer_auth(token).json(&body).send().await;
    let response = match response {
        Ok(response) => response,
        Err(error) => {
            model_usage::record_ambiguous(state, user_id, &invocation, None).await;
            return Err(error.into());
        }
    };
    if response.status().as_u16() == 429 {
        model_usage::record_not_billed(state, user_id, &invocation, 429).await;
        return Err(EnclaveError::Config("quota".into()));
    }
    let error_status = response.status().as_u16();
    let response = match response.error_for_status() {
        Ok(response) => response,
        Err(error) => {
            model_usage::record_not_billed(state, user_id, &invocation, error_status).await;
            return Err(error.into());
        }
    };
    let data: Value = match response.json().await {
        Ok(data) => data,
        Err(error) => {
            model_usage::record_ambiguous(state, user_id, &invocation, Some(200)).await;
            return Err(error.into());
        }
    };
    let metadata = response_metadata(&data);
    log_usage(
        &metadata,
        operation,
        &config.vertex_model,
        bounded_media_output_tokens(max_output_tokens),
    );
    model_usage::record_response(state, user_id, &invocation, &metadata).await;
    let text = data
        .get("candidates")
        .and_then(|candidates| candidates.get(0))
        .and_then(|candidate| candidate.get("content"))
        .and_then(|content| content.get("parts"))
        .and_then(Value::as_array)
        .map(|parts| {
            parts
                .iter()
                .filter_map(|part| part.get("text").and_then(Value::as_str))
                .collect::<String>()
        })
        .unwrap_or_default();
    if text.is_empty() {
        let finish = data
            .get("candidates")
            .and_then(|candidates| candidates.get(0))
            .and_then(|candidate| candidate.get("finishReason"))
            .and_then(Value::as_str)
            .unwrap_or("<no candidates>");
        return Err(EnclaveError::Config(format!(
            "unexpected Vertex media response shape (finishReason: {finish})"
        )));
    }
    Ok(MediaGeneration {
        text,
        metadata,
        latency_ms: started.elapsed().as_millis().min(u128::from(u64::MAX)) as u64,
    })
}

/// Send one bounded audio or screenshot asset to Gemini using inline data.
/// `audioTimestamp` is enabled for audio-only inputs as required by Vertex's
/// audio understanding API. The caller supplies a constrained JSON schema and
/// validates the returned timestamps again before persistence.
/// `pinned_invocation` carries an invocation identity a sealed ADR-0022
/// pre-provider attempt boundary already durably fixed (its `started`
/// billing intent is the durable intent); it is only accepted for a
/// WAL-authoritative user and suppresses the F2 identity mint.
#[allow(clippy::too_many_arguments)]
pub async fn generate_media_custom(
    state: &CpState,
    user_id: &str,
    operation: VertexOperation,
    prompt: &str,
    mime_type: &str,
    media: &[u8],
    schema: Value,
    audio_timestamp: bool,
    pinned_invocation: Option<String>,
) -> Result<MediaGeneration> {
    send_media_request(
        state,
        user_id,
        media_request_body(prompt, mime_type, media, schema, audio_timestamp),
        operation,
        MAX_MEDIA_OUTPUT_TOKENS,
        pinned_invocation,
    )
    .await
}

/// Send a bounded storyboard with opaque frame identifiers. Callers must
/// validate exact response coverage before projecting any result.
/// `pinned_invocation` carries an invocation identity a sealed ADR-0022
/// pre-provider attempt boundary already durably fixed (its `started`
/// billing intent is the durable intent); it is only accepted for a
/// WAL-authoritative user and suppresses the F2 identity mint.
#[allow(clippy::too_many_arguments)]
pub async fn generate_media_parts_custom(
    state: &CpState,
    user_id: &str,
    operation: VertexOperation,
    prompt: &str,
    inputs: &[MediaInput<'_>],
    schema: Value,
    max_output_tokens: u32,
    pinned_invocation: Option<String>,
) -> Result<MediaGeneration> {
    if inputs.is_empty() || inputs.len() > super::media_planner::MAX_SCREEN_FRAMES {
        return Err(EnclaveError::InvalidRequest(
            "storyboard frame count is outside allowed bounds".into(),
        ));
    }
    if inputs.iter().any(|input| input.id.is_empty()) {
        return Err(EnclaveError::InvalidRequest(
            "storyboard frame id is empty".into(),
        ));
    }
    send_media_request(
        state,
        user_id,
        media_parts_request_body(prompt, inputs, schema, false, max_output_tokens),
        operation,
        max_output_tokens,
        pinned_invocation,
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn deletion_waits_for_paused_vertex_call_and_queued_call_never_egresses() {
        use crate::store::tests::{FakeGcs, FakeKms};
        use std::sync::{
            atomic::{AtomicBool, AtomicUsize, Ordering},
            Arc,
        };
        use tokio::sync::Notify;

        let kms = Arc::new(FakeKms);
        let gcs = Arc::new(FakeGcs::new());
        let store = Arc::new(crate::store::Store::new(kms.clone(), gcs.clone()));
        let control = Arc::new(super::super::control_store::ControlStore::new(kms, gcs));
        let user = control
            .upsert_user(
                "vertex-delete-fence",
                "vertex@example.com",
                crate::cp::control_store::TEST_SIGNUP_LIMIT,
            )
            .await
            .unwrap();

        let started = Arc::new(Notify::new());
        let release = Arc::new(Notify::new());
        let terminal_usage_persisted = Arc::new(AtomicBool::new(false));
        let egresses = Arc::new(AtomicUsize::new(0));
        let call_store = Arc::clone(&store);
        let call_control = Arc::clone(&control);
        let call_user = user.id.clone();
        let call_started = Arc::clone(&started);
        let call_release = Arc::clone(&release);
        let call_terminal = Arc::clone(&terminal_usage_persisted);
        let call_egresses = Arc::clone(&egresses);
        let in_flight = tokio::spawn(async move {
            let _guard = lock_active_user_lifecycle(&call_store, &call_control, &call_user).await?;
            call_egresses.fetch_add(1, Ordering::SeqCst);
            call_started.notify_one();
            call_release.notified().await;
            // Models record_response/record_ambiguous completing before the
            // central sender releases the lifecycle guard.
            call_terminal.store(true, Ordering::SeqCst);
            Ok::<_, EnclaveError>(())
        });
        started.notified().await;

        control.begin_user_deletion(&user.id).await.unwrap();
        let deleting_store = Arc::clone(&store);
        let deleting_user = user.id.clone();
        let deletion =
            tokio::spawn(async move { deleting_store.delete_user(&deleting_user).await });
        for _ in 0..10 {
            tokio::task::yield_now().await;
        }
        assert!(!deletion.is_finished());

        let queued_store = Arc::clone(&store);
        let queued_control = Arc::clone(&control);
        let queued_user = user.id.clone();
        let queued_egresses = Arc::clone(&egresses);
        let queued = tokio::spawn(async move {
            let result =
                lock_active_user_lifecycle(&queued_store, &queued_control, &queued_user).await;
            if result.is_ok() {
                queued_egresses.fetch_add(1, Ordering::SeqCst);
            }
            result.map(drop)
        });

        release.notify_one();
        in_flight.await.unwrap().unwrap();
        deletion.await.unwrap().unwrap();
        assert!(matches!(queued.await.unwrap(), Err(EnclaveError::Auth(_))));
        assert!(terminal_usage_persisted.load(Ordering::SeqCst));
        assert_eq!(egresses.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn pinned_media_invocation_refuses_an_unselected_user_before_any_egress() {
        use crate::store::tests::{FakeGcs, FakeKms};
        use std::sync::Arc;

        let kms = Arc::new(FakeKms);
        let gcs = Arc::new(FakeGcs::new());
        let store = Arc::new(crate::store::Store::new(kms.clone(), gcs.clone()));
        let control = Arc::new(super::super::control_store::ControlStore::new(kms, gcs));
        let user = control
            .upsert_user(
                "vertex-pinned-guard",
                "pinned@example.com",
                crate::cp::control_store::TEST_SIGNUP_LIMIT,
            )
            .await
            .unwrap();
        let state = CpState {
            store,
            control,
            billing: Arc::new(super::super::billing::FakeBillingGateway),
            recording_lease_gate: Arc::new(super::super::billing::RecordingLeaseGates::default()),
            config: Arc::new(super::super::CpConfig {
                base_url: "http://localhost:8080".into(),
                jwt_secrets: vec!["test".into()],
                google_desktop_client_id: "desktop".into(),
                google_ios_client_id: "ios".into(),
                google_web_client_id: "web".into(),
                google_web_client_secret: "secret".into(),
                admin_user_ids: vec![],
                signup_limit_per_day: crate::cp::control_store::TEST_SIGNUP_LIMIT,
                scheduler_sa_email: None,
                vertex_project: "project".into(),
                vertex_location: "global".into(),
                vertex_model: "gemini-3.5-flash".into(),
                quota_utterances_per_day: 1,
                quota_screenshots_per_day: 1,
                quota_mcp_calls_per_day: 1,
                quota_vertex_output_tokens_per_day: 1,
                web_origin: "http://localhost:3000".into(),
                reviewer_auth: None,
                apple_sign_in: None,
                billing_enforcement_mode: super::super::BillingEnforcementMode::Enforce,
            }),
            user_verifier: Arc::new(super::super::auth::UserIdTokenVerifier::new(vec![])),
            reviewer_verifier: None,
            apple_provider: None,
            sync_limiter: super::super::limits::RateLimiter::new(1.0, 1.0),
            reference_batch_limiter: super::super::limits::RateLimiter::new(1.0, 1.0),
            reference_batch_concurrency: Arc::new(tokio::sync::Semaphore::new(4)),
            mcp_limiter: super::super::limits::RateLimiter::new(1.0, 1.0),
            oauth_limiter: super::super::limits::RateLimiter::new(1.0, 1.0),
            test_email_limiter: super::super::limits::RateLimiter::new(1.0, 1.0),
            email_transport: None,
            push_transport: None,
            embedding: None,
            voice: None,
        };

        // A pinned identity claims a sealed attempt boundary already recorded
        // the durable `started` billing intent. That is only true on the WAL
        // lane, so an unselected user must refuse fail-closed BEFORE any
        // provider traffic (this test has no network: reaching the token
        // fetch would fail with a different error, not this exact refusal).
        let frames = vec![MediaInput::new("frame-a", "image/jpeg", b"a")];
        let error = match generate_media_parts_custom(
            &state,
            &user.id,
            VertexOperation::ScreenStoryboard,
            "inspect",
            &frames,
            json!({"type": "OBJECT"}),
            MAX_SCREEN_OUTPUT_TOKENS,
            Some(format!("vtx_{}", "a".repeat(64))),
        )
        .await
        {
            Ok(_) => panic!("pinned invocation for an unselected user unexpectedly succeeded"),
            Err(error) => error,
        };
        assert!(
            matches!(
                error,
                EnclaveError::Store(ref message)
                    if message == "pinned media invocation requires a WAL-authoritative user"
            ),
            "expected the pinned-invocation refusal, got: {error:?}"
        );

        // ADR-0022 slice 11: the audio entrypoint shares the same fail-closed
        // pinned-invocation gate (and therefore the same F2-mint suppression)
        // before any provider traffic.
        let error = match generate_media_custom(
            &state,
            &user.id,
            VertexOperation::AudioWindow,
            "transcribe",
            "audio/wav",
            b"a",
            json!({"type": "OBJECT"}),
            true,
            Some(format!("vtx_{}", "a".repeat(64))),
        )
        .await
        {
            Ok(_) => {
                panic!("pinned audio invocation for an unselected user unexpectedly succeeded")
            }
            Err(error) => error,
        };
        assert!(
            matches!(
                error,
                EnclaveError::Store(ref message)
                    if message == "pinned media invocation requires a WAL-authoritative user"
            ),
            "expected the pinned-invocation refusal, got: {error:?}"
        );
    }

    #[test]
    fn episode_schema_requires_recall_fields_and_visual_evidence() {
        let schema = response_schema();
        let episode = &schema["properties"]["episodes"]["items"];
        let properties = episode["properties"]
            .as_object()
            .expect("episode properties");

        assert!(properties.contains_key("summary"));
        assert!(properties.contains_key("action_items"));
        assert_eq!(
            properties["visual_evidence"]["enum"],
            json!(["none", "useful"])
        );

        let required = episode["required"].as_array().expect("required fields");
        for field in ["summary", "action_items", "visual_evidence"] {
            assert!(
                required.iter().any(|value| value.as_str() == Some(field)),
                "{field} must be required by constrained decoding"
            );
        }
    }

    #[test]
    fn audio_request_inlines_bytes_and_enables_timestamp_understanding() {
        let body = media_request_body(
            "transcribe",
            "audio/m4a",
            b"test-audio",
            json!({"type":"OBJECT"}),
            true,
        );
        assert_eq!(
            body["contents"][0]["parts"][0]["inlineData"]["mimeType"],
            "audio/m4a"
        );
        assert_eq!(body["generationConfig"]["audioTimestamp"], true);
        assert_eq!(
            body["generationConfig"]["maxOutputTokens"],
            MAX_MEDIA_OUTPUT_TOKENS
        );
        assert!(body["contents"][0]["parts"][0]["inlineData"]["data"]
            .as_str()
            .is_some_and(|value| !value.is_empty()));
    }

    #[test]
    fn caller_cannot_request_an_unbounded_text_response() {
        assert_eq!(bounded_output_tokens(65_535), MAX_TEXT_OUTPUT_TOKENS);
        assert_eq!(
            bounded_output_tokens(MAX_TEXT_OUTPUT_TOKENS),
            MAX_TEXT_OUTPUT_TOKENS
        );
        assert_eq!(bounded_output_tokens(1_024), 1_024);
        assert_eq!(MAX_TEXT_OUTPUT_TOKENS, 8_192);
        assert_eq!(MAX_MEDIA_OUTPUT_TOKENS, 4_096);
    }

    #[test]
    fn storyboard_request_has_opaque_frame_ids_and_a_1024_token_ceiling() {
        let frames = vec![
            MediaInput::new("frame-a", "image/jpeg", b"a"),
            MediaInput::new("frame-b", "image/jpeg", b"b"),
        ];
        let body = media_parts_request_body(
            "inspect each frame",
            &frames,
            json!({"type":"OBJECT"}),
            false,
            MAX_SCREEN_OUTPUT_TOKENS,
        );
        assert_eq!(body["generationConfig"]["maxOutputTokens"], 1_024);
        assert_eq!(body["generationConfig"]["audioTimestamp"], false);
        let parts = body["contents"][0]["parts"].as_array().unwrap();
        assert_eq!(parts[0]["text"], "frame_id: frame-a");
        assert_eq!(parts[2]["text"], "frame_id: frame-b");
        assert_eq!(parts.last().unwrap()["text"], "inspect each frame");
    }

    #[test]
    fn media_output_ceiling_is_never_exceeded() {
        assert_eq!(bounded_media_output_tokens(65_535), 4_096);
        assert_eq!(bounded_media_output_tokens(0), 1);
        assert_eq!(bounded_media_output_tokens(1_024), 1_024);
    }

    #[test]
    fn usage_metadata_is_nullable_and_preserves_model_and_modality() {
        let metadata = response_metadata(&json!({
            "modelVersion": "gemini-test-001",
            "usageMetadata": {
                "promptTokenCount": 123,
                "promptTokensDetails": [
                    {"modality":"TEXT","tokenCount":23},
                    {"modality":"AUDIO","tokenCount":100}
                ],
                "cachedContentTokenCount": 45,
                "candidatesTokenCount": 67,
                "toolUsePromptTokenCount": 2,
                "thoughtsTokenCount": 8,
                "totalTokenCount": 200,
                "trafficType": "ON_DEMAND"
            }
        }));
        let usage = metadata.usage.unwrap();
        assert_eq!(usage.prompt_tokens, Some(123));
        assert_eq!(usage.input_text_tokens, Some(23));
        assert_eq!(usage.input_audio_tokens, Some(100));
        assert_eq!(usage.input_image_tokens, None);
        assert_eq!(usage.cached_input_tokens, Some(45));
        assert_eq!(usage.output_tokens, Some(67));
        assert_eq!(usage.tool_use_prompt_tokens, Some(2));
        assert_eq!(usage.thought_tokens, Some(8));
        assert_eq!(usage.total_tokens, Some(200));
        assert_eq!(metadata.model_version.as_deref(), Some("gemini-test-001"));
        assert_eq!(metadata.traffic_type.as_deref(), Some("ON_DEMAND"));
    }

    #[test]
    fn missing_usage_metadata_is_not_zero() {
        let metadata = response_metadata(&json!({"candidates": []}));
        assert_eq!(metadata.usage, None);
    }
}
