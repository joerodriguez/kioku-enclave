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
                        "action_items": {"type": "ARRAY", "items": {"type": "STRING"}}
                    },
                    "required": ["started_at","ended_at","title"]
                }
            }
        },
        "required": ["episodes"]
    })
}

/// Call Gemini and return the raw response text (expected to be JSON per the
/// schema). `Err` with a `quota` marker string on HTTP 429.
pub async fn generate(config: &CpConfig, system: &str, user_message: &str) -> Result<String> {
    if config.vertex_project.is_empty() {
        return Err(EnclaveError::Config("VERTEX_PROJECT not set".into()));
    }
    let http = reqwest::Client::new();
    let token = access_token(&http).await?;

    let url = format!(
        "https://aiplatform.googleapis.com/v1/projects/{}/locations/global/publishers/google/models/{}:generateContent",
        config.vertex_project, config.vertex_model
    );
    let body = json!({
        "contents": [{ "role": "user", "parts": [{ "text": user_message }] }],
        "systemInstruction": { "parts": [{ "text": system }] },
        "generationConfig": {
            "maxOutputTokens": 32768,
            "responseMimeType": "application/json",
            "responseSchema": response_schema(),
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
        return Err(EnclaveError::Config(
            "unexpected Vertex response shape".into(),
        ));
    }
    Ok(text)
}
