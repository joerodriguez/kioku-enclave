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

use crate::error::{EnclaveError, Result};

use super::CpConfig;

const METADATA_TOKEN_URL: &str =
    "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token";

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
    generate_custom(config, system, user_message, response_schema(), 65_535).await
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
    // Explicit timeout: reqwest has NONE by default, and a hung generateContent
    // call would wedge the summarizer (and, since runs are serialized, every
    // future run) forever. 3 min is generous for a 6-h window.
    let http = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(180))
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
            // Model max (Gemini 2.5 Flash): a JSON response truncated by the
            // output cap is unparseable and deterministically stalls that
            // summarizer window, so leave no headroom to waste.
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
            "maxOutputTokens": 16_384,
            "responseMimeType": "application/json",
            "responseSchema": schema,
            "audioTimestamp": audio_timestamp,
            "thinkingConfig": {"thinkingBudget": 0}
        }
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
) -> Result<String> {
    if config.vertex_project.is_empty() {
        return Err(EnclaveError::Config("VERTEX_PROJECT not set".into()));
    }
    let http = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(180))
        .build()?;
    let token = access_token(&http).await?;
    let url = format!(
        "https://aiplatform.googleapis.com/v1/projects/{}/locations/global/publishers/google/models/{}:generateContent",
        config.vertex_project, config.vertex_model
    );
    let response = http
        .post(&url)
        .bearer_auth(token)
        .json(&media_request_body(
            prompt,
            mime_type,
            media,
            schema,
            audio_timestamp,
        ))
        .send()
        .await?;
    if response.status().as_u16() == 429 {
        return Err(EnclaveError::Config("quota".into()));
    }
    let data: Value = response.error_for_status()?.json().await?;
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
    Ok(text)
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
        assert!(body["contents"][0]["parts"][0]["inlineData"]["data"]
            .as_str()
            .is_some_and(|value| !value.is_empty()));
    }
}
