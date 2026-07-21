//! Vertex AI client for the episode summarizer (ports the Gemini path of
//! `callClaude` in `cloud/src/summarizer.js`). Gemini `generateContent` with a
//! constrained `responseSchema`. Credentials come from the VM metadata server
//! (cloud-platform scope), same pattern as the GCS/KMS clients.
//!
//! NOTE: only the Gemini path is ported. Anthropic-on-Vertex (`rawPredict`) is a
//! future toggle — `VERTEX_MODEL` defaults to `gemini-2.5-flash` regardless.
//!
//! This call sends assembled capture text to Vertex, OUTSIDE the TEE boundary —
//! the documented summarizer caveat (ADR-0001 / docs/ROADMAP Phase 7). The claim
//! for episode summaries is "attested enclave + Google Vertex inference under
//! no-data-retention terms", not enclave-only.

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
                    "required": ["started_at","ended_at","title","substance","minutes"]
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
        config.vertex_project, config.vertex_model
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
