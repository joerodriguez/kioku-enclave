//! Backend-neutral episode values and merge policy.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MinuteBucket {
    pub start: String,
    pub gist: String,
}

pub(crate) fn merge_minute_summaries(
    existing_json: Option<&str>,
    new: &[MinuteBucket],
) -> Option<(String, String)> {
    let mut by_start: BTreeMap<i64, MinuteBucket> = BTreeMap::new();
    let minute_key = |bucket: &MinuteBucket| {
        crate::cp::isotime::parse_epoch_millis(&bucket.start).map(|millis| millis / 60_000)
    };
    let existing: Vec<MinuteBucket> = existing_json
        .and_then(|value| serde_json::from_str(value).ok())
        .unwrap_or_default();
    for bucket in existing.into_iter().chain(new.iter().cloned()) {
        if bucket.gist.trim().is_empty() {
            continue;
        }
        if let Some(key) = minute_key(&bucket) {
            by_start.insert(key, bucket);
        }
    }
    if by_start.is_empty() {
        return None;
    }
    let merged: Vec<&MinuteBucket> = by_start.values().collect();
    let json = serde_json::to_string(&merged).unwrap_or_else(|_| "[]".into());
    let text = merged
        .iter()
        .map(|bucket| bucket.gist.as_str())
        .collect::<Vec<_>>()
        .join("\n");
    Some((json, text))
}

#[derive(Debug, Clone, Deserialize)]
pub struct EpisodeInput {
    #[serde(default)]
    pub id: Option<i64>,
    pub started_at: String,
    pub ended_at: String,
    #[serde(rename = "type")]
    pub episode_type: Option<String>,
    pub title: String,
    pub summary: Option<String>,
    pub participants: Option<Vec<String>>,
    pub languages: Option<Vec<String>>,
    pub action_items: Option<Vec<String>>,
    #[serde(default)]
    pub substance: Option<String>,
    #[serde(default)]
    pub visual_evidence: Option<String>,
    #[serde(default)]
    pub minute_summaries: Option<Vec<MinuteBucket>>,
    pub model: Option<String>,
    #[serde(default)]
    pub member_utterance_ids: Vec<i64>,
    #[serde(default)]
    pub member_screenshot_ids: Vec<i64>,
}

fn validate_substance(value: &str) -> Option<&'static str> {
    match value.trim().to_ascii_lowercase().as_str() {
        "none" => Some("none"),
        "low" => Some("low"),
        "normal" => Some("normal"),
        _ => None,
    }
}

pub(crate) fn normalized_substance(value: Option<&str>) -> &'static str {
    value.and_then(validate_substance).unwrap_or("normal")
}

pub(crate) fn merge_substance(existing: Option<&str>, incoming: Option<&str>) -> &'static str {
    let rank = |value: &str| match value {
        "none" => 0,
        "low" => 1,
        _ => 2,
    };
    let existing = normalized_substance(existing);
    let incoming = normalized_substance(incoming);
    if rank(incoming) > rank(existing) {
        incoming
    } else {
        existing
    }
}

fn validate_visual_evidence(value: &str) -> Option<&'static str> {
    match value {
        "none" => Some("none"),
        "useful" => Some("useful"),
        _ => None,
    }
}

pub(crate) fn normalized_visual_evidence(value: Option<&str>) -> &'static str {
    value.and_then(validate_visual_evidence).unwrap_or("none")
}

pub(crate) fn merge_visual_evidence(
    existing: Option<&str>,
    incoming: Option<&str>,
) -> &'static str {
    let rank = |value: &str| if value == "none" { 0 } else { 1 };
    let existing = normalized_visual_evidence(existing);
    let incoming = normalized_visual_evidence(incoming);
    if rank(incoming) > rank(existing) {
        incoming
    } else {
        existing
    }
}

fn source_key_delivery_complete_default() -> bool {
    true
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct EpisodePurge {
    pub deleted_utterances: usize,
    pub deleted_screenshots: usize,
    pub deleted_segments: usize,
    pub utterance_source_keys: Vec<String>,
    pub screenshot_source_keys: Vec<String>,
    #[serde(default)]
    pub source_key_cursor: Option<String>,
    #[serde(default = "source_key_delivery_complete_default")]
    pub source_key_delivery_complete: bool,
}

impl Default for EpisodePurge {
    fn default() -> Self {
        Self {
            deleted_utterances: 0,
            deleted_screenshots: 0,
            deleted_segments: 0,
            utterance_source_keys: Vec::new(),
            screenshot_source_keys: Vec::new(),
            source_key_cursor: None,
            source_key_delivery_complete: true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::EpisodePurge;

    #[test]
    fn legacy_terminal_purge_defaults_to_completed_source_key_delivery() {
        let purge: EpisodePurge = serde_json::from_str(
            r#"{"deleted_utterances":1,"deleted_screenshots":2,"deleted_segments":1,
                "utterance_source_keys":["u"],"screenshot_source_keys":["s"]}"#,
        )
        .expect("legacy purge JSON");
        assert!(purge.source_key_delivery_complete);
        assert!(purge.source_key_cursor.is_none());
    }
}
