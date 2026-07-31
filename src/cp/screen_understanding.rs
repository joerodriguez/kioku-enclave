//! Screen understanding and episode interpretation (ADR-0014).
//!
//! Provides literal, screen-only observations for 100% of canonical nonduplicate screens,
//! contextual episode interpretations, and deterministic fallbacks when model calls fail.

use serde::{Deserialize, Serialize};

use crate::error::Result;

use super::CpState;

#[allow(dead_code)]
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
}

#[allow(dead_code)]
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

#[allow(dead_code)]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ModelScreenObservationOutput {
    pub id: String,
    pub literal_description: String,
    pub screen_state: String,
    pub content_type: String,
    pub visible_text_summary: Option<String>,
    pub notable_items: Vec<String>,
}

/// Compute canonical input revision hash for screen observation idempotency (ADR-0014 §12.1).
#[allow(dead_code)]
pub fn compute_observation_input_revision(input: &ScreenObservationInput) -> String {
    use sha2::{Digest, Sha256};
    let json_val = serde_json::json!({
        "source_key": input.source_key,
        "captured_at": input.captured_at,
        "capture_status": input.capture_status,
        "primary_app": input.primary_app,
        "window_title": input.window_title,
        "salient_ocr_text": input.salient_ocr_text,
        "ocr_text": input.ocr_text,
        "active_url": input.active_url,
        "visual_signals_json": input.visual_signals_json,
    });
    let canonical = serde_json::to_string(&json_val).unwrap_or_default();
    let mut hasher = Sha256::new();
    hasher.update(b"screen-observation-v1\0");
    hasher.update(canonical.as_bytes());
    format!("{:x}", hasher.finalize())
}

/// Build a deterministic fallback observation for a screen when model response is unavailable or invalid.
#[allow(dead_code)]
pub fn build_deterministic_fallback(
    input: &ScreenObservationInput,
    revision: &str,
) -> ScreenObservation {
    let app = input.primary_app.as_deref().unwrap_or("Application");
    let title = input.window_title.as_deref().unwrap_or("screen");
    let ocr = input.salient_ocr_text.as_deref().unwrap_or("").trim();

    let literal_description = if !ocr.is_empty() {
        let snippet = if ocr.chars().count() > 100 {
            let s: String = ocr.chars().take(100).collect();
            format!("{}...", s)
        } else {
            ocr.to_string()
        };
        format!("{} · {} — visible text: {}", app, title, snippet)
    } else {
        format!("{} · {}", app, title)
    };

    let bounded_description = if literal_description.chars().count() > 280 {
        literal_description.chars().take(280).collect()
    } else {
        literal_description
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
    let content_type = if input.active_url.is_some() {
        "web_page"
    } else {
        "application_ui"
    };

    ScreenObservation {
        screenshot_id: input.screenshot_id,
        input_revision: revision.to_string(),
        observation_version: 1,
        status: "fallback".to_string(),
        generation_method: "deterministic_fallback".to_string(),
        literal_description: bounded_description,
        screen_state: screen_state.to_string(),
        content_type: content_type.to_string(),
        visible_text_summary: input
            .salient_ocr_text
            .clone()
            .map(|s| s.chars().take(200).collect()),
        notable_items_json: "[]".to_string(),
        model_name: None,
        prompt_version: 1,
    }
}

/// Validate output from model for bounds and allowed enums.
#[allow(dead_code)]
pub fn validate_model_output(out: &ModelScreenObservationOutput) -> bool {
    let valid_states = [
        "content",
        "blank",
        "loading",
        "error",
        "transition",
        "locked_or_private",
        "unknown",
    ];
    let valid_types = [
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

    if !valid_states.contains(&out.screen_state.as_str()) {
        return false;
    }
    if !valid_types.contains(&out.content_type.as_str()) {
        return false;
    }
    if out.literal_description.trim().is_empty() || out.literal_description.chars().count() > 280 {
        return false;
    }
    if let Some(summary) = &out.visible_text_summary {
        if summary.chars().count() > 200 {
            return false;
        }
    }
    if out.notable_items.len() > 5 {
        return false;
    }
    for item in &out.notable_items {
        if item.chars().count() > 120 {
            return false;
        }
    }
    true
}

/// Materialize episode-specific relevance for every canonical member. This is
/// independent from image upload: metadata-only screens can be key screens,
/// while non-key screens remain available to callers.
pub async fn ensure_episode_interpretations(state: &CpState, user_id: &str) -> Result<()> {
    state
        .store
        .with_user(user_id, |conn| {
            let episode_ids: Vec<i64> = {
                let mut statement = conn.prepare("SELECT id FROM episodes")?;
                let values = statement
                    .query_map([], |row| row.get(0))?
                    .filter_map(std::result::Result::ok)
                    .collect();
                values
            };
            for episode_id in episode_ids {
                type ScreenRow = (
                    i64,
                    String,
                    String,
                    String,
                    Option<String>,
                    Option<String>,
                    Option<String>,
                );
                let screens: Vec<ScreenRow> = {
                    let mut statement = conn.prepare(
                        "SELECT s.id, s.captured_at, o.literal_description, o.screen_state,
                                s.active_app, s.window_title, s.url
                         FROM episode_members m
                         JOIN screenshots s ON s.id=m.record_id
                         JOIN screen_observations o ON o.screenshot_id=s.id
                         WHERE m.episode_id=?1 AND m.record_type='screenshot'
                           AND s.is_duplicate=0
                         ORDER BY s.captured_at, s.id",
                    )?;
                    let values = statement
                        .query_map([episode_id], |row| {
                            Ok((
                                row.get(0)?,
                                row.get(1)?,
                                row.get(2)?,
                                row.get(3)?,
                                row.get(4)?,
                                row.get(5)?,
                                row.get(6)?,
                            ))
                        })?
                        .filter_map(std::result::Result::ok)
                        .collect();
                    values
                };
                let mut ranked: Vec<(usize, i64)> = screens
                    .iter()
                    .enumerate()
                    .map(|(index, screen)| {
                        let mut relevance = match screen.3.as_str() {
                            "content" => 2,
                            "unknown" => 1,
                            _ => 0,
                        };
                        if screen.2.chars().count() >= 120 {
                            relevance = (relevance + 1).min(3);
                        }
                        if screen.6.is_some() {
                            relevance = (relevance + 1).min(3);
                        }
                        (index, relevance)
                    })
                    .collect();
                ranked.sort_by(|left, right| {
                    right
                        .1
                        .cmp(&left.1)
                        .then_with(|| screens[left.0].1.cmp(&screens[right.0].1))
                });
                for (rank_index, (index, relevance)) in ranked.into_iter().enumerate() {
                    let screen = &screens[index];
                    let is_key = relevance >= 2;
                    let group = format!(
                        "{}|{}",
                        screen.4.as_deref().unwrap_or(""),
                        screen.5.as_deref().unwrap_or("")
                    );
                    conn.execute(
                        "INSERT INTO episode_screen_interpretations
                         (episode_id, screenshot_id, activity_summary, relevance_level,
                          relevance_reason, key_rank, is_key_screen, semantic_group, updated_at)
                         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8,
                                 strftime('%Y-%m-%dT%H:%M:%fZ','now'))
                         ON CONFLICT(episode_id, screenshot_id) DO UPDATE SET
                           activity_summary=excluded.activity_summary,
                           relevance_level=excluded.relevance_level,
                           relevance_reason=excluded.relevance_reason,
                           key_rank=excluded.key_rank,
                           is_key_screen=excluded.is_key_screen,
                           semantic_group=excluded.semantic_group,
                           updated_at=excluded.updated_at",
                        rusqlite::params![
                            episode_id,
                            screen.0,
                            Option::<String>::None,
                            relevance,
                            if is_key {
                                "Substantive visible content"
                            } else {
                                "Low-information or transitional screen"
                            },
                            is_key.then_some((rank_index + 1) as i64),
                            is_key as i64,
                            group,
                        ],
                    )?;
                }
            }
            Ok(())
        })
        .await?;
    state.store.save_user(user_id).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compute_observation_input_revision_is_deterministic() {
        let input = ScreenObservationInput {
            screenshot_id: 42,
            source_key: "dev-1:sc:100".to_string(),
            captured_at: "2026-07-31T12:00:00.000Z".to_string(),
            capture_status: "stable".to_string(),
            primary_app: Some("Safari".to_string()),
            window_title: Some("Kioku ADR".to_string()),
            salient_ocr_text: Some("Semantic Screen Memory".to_string()),
            ocr_text: Some("Full OCR content".to_string()),
            active_url: Some("https://kioku.dev".to_string()),
            visual_signals_json: Some("{\"edge_density\":0.2}".to_string()),
        };

        let rev1 = compute_observation_input_revision(&input);
        let rev2 = compute_observation_input_revision(&input);
        assert_eq!(rev1, rev2);
        assert_eq!(rev1.len(), 64);
    }

    #[test]
    fn test_deterministic_fallback_bounds_description() {
        let input = ScreenObservationInput {
            screenshot_id: 1,
            source_key: "sk1".to_string(),
            captured_at: "2026-07-31T12:00:00Z".to_string(),
            capture_status: "stable".to_string(),
            primary_app: Some("Safari".to_string()),
            window_title: Some("Title".to_string()),
            salient_ocr_text: Some("A".repeat(500)),
            ocr_text: None,
            active_url: Some("https://example.com".to_string()),
            visual_signals_json: None,
        };

        let fallback = build_deterministic_fallback(&input, "rev1");
        assert_eq!(fallback.status, "fallback");
        assert_eq!(fallback.generation_method, "deterministic_fallback");
        assert!(fallback.literal_description.chars().count() <= 280);
    }

    #[test]
    fn empty_ocr_is_unknown_without_loading_evidence() {
        let input = ScreenObservationInput {
            screenshot_id: 1,
            source_key: "sk1".into(),
            captured_at: "2026-07-31T12:00:00Z".into(),
            capture_status: "stable".into(),
            primary_app: Some("Claude".into()),
            window_title: Some("Claude".into()),
            salient_ocr_text: None,
            ocr_text: None,
            active_url: None,
            visual_signals_json: None,
        };
        let fallback = build_deterministic_fallback(&input, "revision");
        assert_eq!(fallback.screen_state, "unknown");
    }
}
