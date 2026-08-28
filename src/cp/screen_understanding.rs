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

pub struct ModelScreenObservationOutput {
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
    fn revision_is_deterministic_and_model_output_is_bounded() {
        let input = input();
        let revision = compute_observation_input_revision(&input);
        assert_eq!(revision, compute_observation_input_revision(&input));
        assert!(validate_model_output(&ModelScreenObservationOutput {
            literal_description: "Safari showing Kioku episode 323".into(),
            screen_state: "content".into(),
            content_type: "web_page".into(),
            visible_text_summary: Some("Episode 323".into()),
            notable_items: vec!["Kioku".into()],
        }));
    }
}
