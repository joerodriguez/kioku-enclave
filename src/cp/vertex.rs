//! Vertex AI client for episode summarization and unified episode analysis. Gemini
//! `generateContent` uses a
//! constrained `responseSchema`. Credentials come from the VM metadata server
//! (cloud-platform scope), same pattern as the GCS/KMS clients.
//!
//! NOTE: only the Gemini path is ported. Anthropic-on-Vertex (`rawPredict`) is a
//! future toggle — `VERTEX_MODEL` defaults to `gemini-2.5-flash` regardless.
//!
//! These calls send assembled capture text and metadata to Vertex, OUTSIDE the
//! TEE boundary. Raw audio and screenshot pixels are never part of a request.

use base64::{engine::general_purpose::STANDARD as B64, Engine};
use serde::Deserialize;
use serde_json::{json, Value};
use std::time::Instant;

use crate::error::{EnclaveError, Result};

use super::CpConfig;

const METADATA_TOKEN_URL: &str =
    "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token";
const GENERATION_TIMEOUT_SECONDS: u64 = 120;
pub(crate) const MAX_TEXT_OUTPUT_TOKENS: u32 = 8_192;
pub(crate) const MAX_MEDIA_OUTPUT_TOKENS: u32 = 4_096;
pub(crate) const MAX_SCREEN_OUTPUT_TOKENS: u32 = 1_024;

#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct VertexUsage {
    pub prompt_tokens: u64,
    pub cached_input_tokens: u64,
    pub output_tokens: u64,
    pub thought_tokens: u64,
    pub total_tokens: u64,
}

pub struct MediaGeneration {
    pub text: String,
    pub usage: VertexUsage,
    pub latency_ms: u64,
}

fn bounded_output_tokens(requested: u32) -> u32 {
    requested.clamp(1, MAX_TEXT_OUTPUT_TOKENS)
}

fn bounded_media_output_tokens(requested: u32) -> u32 {
    requested.clamp(1, MAX_MEDIA_OUTPUT_TOKENS)
}

fn usage_metadata(data: &Value) -> VertexUsage {
    let usage = data.get("usageMetadata").unwrap_or(&Value::Null);
    VertexUsage {
        prompt_tokens: usage
            .get("promptTokenCount")
            .and_then(Value::as_u64)
            .unwrap_or(0),
        cached_input_tokens: usage
            .get("cachedContentTokenCount")
            .and_then(Value::as_u64)
            .unwrap_or(0),
        output_tokens: usage
            .get("candidatesTokenCount")
            .and_then(Value::as_u64)
            .unwrap_or(0),
        thought_tokens: usage
            .get("thoughtsTokenCount")
            .and_then(Value::as_u64)
            .unwrap_or(0),
        total_tokens: usage
            .get("totalTokenCount")
            .and_then(Value::as_u64)
            .unwrap_or(0),
    }
}

fn log_usage(data: &Value, operation: &str, model: &str, output_limit: u32) {
    let usage = usage_metadata(data);
    tracing::info!(
        operation,
        model,
        output_limit,
        prompt_tokens = usage.prompt_tokens,
        cached_input_tokens = usage.cached_input_tokens,
        output_tokens = usage.output_tokens,
        thought_tokens = usage.thought_tokens,
        total_tokens = usage.total_tokens,
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
pub async fn generate(config: &CpConfig, system: &str, user_message: &str) -> Result<String> {
    generate_custom(
        config,
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
    config: &CpConfig,
    system: &str,
    user_message: &str,
    schema: Value,
    max_output_tokens: u32,
) -> Result<String> {
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
        "https://aiplatform.googleapis.com/v1/projects/{}/locations/global/publishers/google/models/{}:generateContent",
        config.vertex_project, model
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

    let resp = http
        .post(&url)
        .bearer_auth(&token)
        .json(&body)
        .send()
        .await?;

    if resp.status().as_u16() == 429 {
        return Err(EnclaveError::Config("quota".into()));
    }
    let resp = resp.error_for_status()?;
    let data: Value = resp.json().await?;
    log_usage(&data, "text", model, max_output_tokens);
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
    Ok(text)
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
    config: &CpConfig,
    body: Value,
    operation: &str,
    max_output_tokens: u32,
) -> Result<MediaGeneration> {
    if config.vertex_project.is_empty() {
        return Err(EnclaveError::Config("VERTEX_PROJECT not set".into()));
    }
    let http = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(GENERATION_TIMEOUT_SECONDS))
        .build()?;
    let token = access_token(&http).await?;
    let url = format!(
        "https://aiplatform.googleapis.com/v1/projects/{}/locations/global/publishers/google/models/{}:generateContent",
        config.vertex_project, config.vertex_model
    );
    let started = Instant::now();
    let response = http
        .post(&url)
        .bearer_auth(token)
        .json(&body)
        .send()
        .await?;
    if response.status().as_u16() == 429 {
        return Err(EnclaveError::Config("quota".into()));
    }
    let data: Value = response.error_for_status()?.json().await?;
    let usage = usage_metadata(&data);
    log_usage(
        &data,
        operation,
        &config.vertex_model,
        bounded_media_output_tokens(max_output_tokens),
    );
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
        usage,
        latency_ms: started.elapsed().as_millis().min(u128::from(u64::MAX)) as u64,
    })
}

/// Send one bounded audio or screenshot asset to Gemini using inline data.
/// `audioTimestamp` is enabled for audio-only inputs as required by Vertex's
/// audio understanding API. The caller supplies a constrained JSON schema and
/// validates the returned timestamps again before persistence.
pub async fn generate_media_custom(
    config: &CpConfig,
    prompt: &str,
    mime_type: &str,
    media: &[u8],
    schema: Value,
    audio_timestamp: bool,
) -> Result<MediaGeneration> {
    send_media_request(
        config,
        media_request_body(prompt, mime_type, media, schema, audio_timestamp),
        if audio_timestamp {
            "audio"
        } else {
            "screenshot"
        },
        MAX_MEDIA_OUTPUT_TOKENS,
    )
    .await
}

/// Send a bounded storyboard with opaque frame identifiers. Callers must
/// validate exact response coverage before projecting any result.
pub async fn generate_media_parts_custom(
    config: &CpConfig,
    prompt: &str,
    inputs: &[MediaInput<'_>],
    schema: Value,
    max_output_tokens: u32,
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
        config,
        media_parts_request_body(prompt, inputs, schema, false, max_output_tokens),
        "screen_storyboard",
        max_output_tokens,
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn usage_metadata_is_reduced_to_non_content_telemetry() {
        let usage = usage_metadata(&json!({
            "usageMetadata": {
                "promptTokenCount": 123,
                "cachedContentTokenCount": 45,
                "candidatesTokenCount": 67,
                "thoughtsTokenCount": 8,
                "totalTokenCount": 198
            }
        }));
        assert_eq!(usage.prompt_tokens, 123);
        assert_eq!(usage.cached_input_tokens, 45);
        assert_eq!(usage.output_tokens, 67);
        assert_eq!(usage.thought_tokens, 8);
        assert_eq!(usage.total_tokens, 198);
    }
}
