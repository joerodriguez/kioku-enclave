//! Deterministic screen fallbacks used before an episode is settled.
//!
//! Authoritative semantic screen descriptions are produced together with the
//! episode brief by the unified finalizer. This module intentionally contains
//! no model client or background model worker.

use serde::{Deserialize, Serialize};

pub(crate) const OBSERVATION_VERSION: i32 = 3;
pub(crate) const OBSERVATION_PROMPT_VERSION: i32 = 3;
pub(crate) const INTERPRETATION_VERSION: i32 = 2;
pub(crate) const INTERPRETATION_PROMPT_VERSION: i32 = 2;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ScreenObservationInput {
    pub screenshot_id: i64,
    pub source_key: String,
    pub captured_at: String,
    pub capture_status: String,
    pub primary_app: Option<String>,
    pub window_title: Option<String>,
    pub salient_ocr_text: Option<String>,
    pub ocr_text: Option<String>,
    pub active_url: Option<String>,
    pub visual_signals_json: Option<String>,
    pub display_id: Option<i64>,
    pub primary_bundle_id: Option<String>,
    pub visible_windows_json: Option<String>,
    pub browser_context_json: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ScreenObservation {
    pub screenshot_id: i64,
    pub input_revision: String,
    pub observation_version: i32,
    pub status: String,
    pub generation_method: String,
    pub literal_description: String,
    pub screen_state: String,
    pub content_type: String,
    pub visible_text_summary: Option<String>,
    pub notable_items_json: String,
    pub model_name: Option<String>,
    pub prompt_version: i32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ModelScreenObservationOutput {
    pub id: String,
    pub literal_description: String,
    pub screen_state: String,
    pub content_type: String,
    pub visible_text_summary: Option<String>,
    pub notable_items: Vec<String>,
}

pub fn compute_observation_input_revision(input: &ScreenObservationInput) -> String {
    use sha2::{Digest, Sha256};
    let canonical = serde_json::to_string(input).unwrap_or_default();
    let mut hasher = Sha256::new();
    hasher.update(b"screen-observation-v3\0");
    hasher.update(canonical.as_bytes());
    format!("{:x}", hasher.finalize())
}

pub fn build_deterministic_fallback(
    input: &ScreenObservationInput,
    revision: &str,
) -> ScreenObservation {
    let app = input.primary_app.as_deref().unwrap_or("Application");
    let title = input.window_title.as_deref().unwrap_or("screen");
    let ocr = input.salient_ocr_text.as_deref().unwrap_or("").trim();
    let heading = if title.eq_ignore_ascii_case(app) {
        app.to_string()
    } else {
        format!("{app} · {title}")
    };
    let description = if ocr.is_empty() {
        heading
    } else {
        format!(
            "{heading} — visible text: {}",
            ocr.chars().take(100).collect::<String>()
        )
    };
    let state_evidence = format!(
        "{} {} {}",
        title,
        ocr,
        input.visual_signals_json.as_deref().unwrap_or("")
    )
    .to_lowercase();
    let screen_state = if state_evidence.contains("loading") || state_evidence.contains("spinner") {
        "loading"
    } else if ocr.is_empty() {
        "unknown"
    } else {
        "content"
    };

    ScreenObservation {
        screenshot_id: input.screenshot_id,
        input_revision: revision.to_string(),
        observation_version: OBSERVATION_VERSION,
        status: "fallback".into(),
        generation_method: "deterministic_fallback".into(),
        literal_description: description.chars().take(280).collect(),
        screen_state: screen_state.into(),
        content_type: if input.active_url.is_some() {
            "web_page".into()
        } else {
            "application_ui".into()
        },
        visible_text_summary: input
            .salient_ocr_text
            .clone()
            .map(|text| text.chars().take(200).collect()),
        notable_items_json: "[]".into(),
        model_name: None,
        prompt_version: OBSERVATION_PROMPT_VERSION,
    }
}

pub fn validate_model_output(out: &ModelScreenObservationOutput) -> bool {
    const STATES: &[&str] = &[
        "content",
        "blank",
        "loading",
        "error",
        "transition",
        "locked_or_private",
        "unknown",
    ];
    const TYPES: &[&str] = &[
        "document",
        "presentation",
        "web_page",
        "code",
        "terminal",
        "chat",
        "meeting",
        "media",
        "system_ui",
        "application_ui",
        "unknown",
    ];
    STATES.contains(&out.screen_state.as_str())
        && TYPES.contains(&out.content_type.as_str())
        && !out.literal_description.trim().is_empty()
        && out.literal_description.chars().count() <= 280
        && out
            .visible_text_summary
            .as_ref()
            .is_none_or(|value| value.chars().count() <= 200)
        && out.notable_items.len() <= 5
        && out
            .notable_items
            .iter()
            .all(|item| item.chars().count() <= 120)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn input() -> ScreenObservationInput {
        ScreenObservationInput {
            screenshot_id: 7,
            source_key: "device:screen:7".into(),
            captured_at: "2026-07-31T20:49:00Z".into(),
            capture_status: "stable".into(),
            primary_app: Some("Safari".into()),
            window_title: Some("Kioku".into()),
            salient_ocr_text: Some("Episode 323".into()),
            ocr_text: Some("Episode 323".into()),
            active_url: Some("https://example.com/episodes/323".into()),
            visual_signals_json: None,
            display_id: Some(1),
            primary_bundle_id: Some("com.apple.Safari".into()),
            visible_windows_json: None,
            browser_context_json: None,
        }
    }

    #[test]
    fn fallback_is_immediate_and_deterministic() {
        let input = input();
        let revision = compute_observation_input_revision(&input);
        assert_eq!(revision, compute_observation_input_revision(&input));
        let fallback = build_deterministic_fallback(&input, &revision);
        assert_eq!(fallback.status, "fallback");
        assert_eq!(fallback.content_type, "web_page");
        assert!(fallback.literal_description.contains("Safari"));
    }
}
