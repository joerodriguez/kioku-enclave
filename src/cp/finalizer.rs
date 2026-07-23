use crate::cp::{isotime, vertex, CpState};
use crate::error::{EnclaveError, Result};
use regex::Regex;
use rusqlite::OptionalExtension;
use serde::Deserialize;
use serde_json::{json, Value};
use std::collections::{BTreeSet, HashMap, HashSet};
use std::sync::{Arc, Mutex as StdMutex, OnceLock};
use tracing::{info, warn};

// Version 3 regenerates canonical briefs with salient screen OCR and explicit
// deictic entity retention. Regeneration never re-enqueues Gmail.
pub(crate) const FINALIZATION_VERSION: i32 = crate::store::EPISODE_FINALIZATION_VERSION;
const MIRRORED_UTTERANCE_WINDOW_MS: i64 = 3_000;
const MAX_FINALIZER_MODEL_INPUT_BYTES: usize = 256 * 1024;
const MAX_FINALIZER_CANDIDATE_BYTES: usize = 32 * 1024;
const MAX_FINALIZER_UTTERANCE_CHARS: usize = 4_000;
const MAX_FINALIZER_OCR_CHARS: usize = 4_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FinalizationMode {
    Initial,
    Regeneration,
    AlreadyCurrent,
}

fn finalization_mode(
    finalized_at: Option<&str>,
    finalization_version: Option<i32>,
) -> FinalizationMode {
    if finalized_at.is_none() {
        FinalizationMode::Initial
    } else if finalization_version.unwrap_or(1) < FINALIZATION_VERSION {
        FinalizationMode::Regeneration
    } else {
        FinalizationMode::AlreadyCurrent
    }
}

impl FinalizationMode {
    fn should_enqueue_email(self, email_enabled: bool) -> bool {
        email_enabled && matches!(self, Self::Initial)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct UrlCandidate {
    pub url: String,
    pub record_type: String,
    pub record_id: i64,
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
struct EpisodeRow {
    id: i64,
    started_at: String,
    ended_at: String,
    episode_type: Option<String>,
    title: String,
    summary: Option<String>,
    participants: Option<String>,
    languages: Option<String>,
    action_items: Option<String>,
    model: Option<String>,
}

#[derive(Debug, Clone)]
struct UtteranceEvidenceRow {
    id: i64,
    at: String,
    at_ms: i64,
    speaker: String,
    source_type: String,
    text: String,
}

#[derive(Debug, Clone)]
struct ScreenshotEvidenceRow {
    id: i64,
    captured_at: String,
    captured_at_ms: i64,
    active_app: Option<String>,
    window_title: Option<String>,
    url: Option<String>,
    ocr_text: Option<String>,
    salient_ocr_text: Option<String>,
    is_duplicate: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct GroundingRequirement {
    at_ms: i64,
    entities: Vec<String>,
}

#[derive(Debug)]
struct UtteranceEvidenceGroup {
    at: String,
    at_ms: i64,
    ids: Vec<i64>,
    speakers: BTreeSet<String>,
    source_types: BTreeSet<String>,
    texts: Vec<String>,
}

#[derive(Debug)]
struct RenderedEvidenceEntry {
    at_ms: i64,
    record_order: u8,
    record_id: i64,
    line: String,
}

#[derive(Debug, Clone, Deserialize)]
struct EvidenceRef {
    record_type: String,
    record_id: i64,
}

#[derive(Debug, Clone, Deserialize)]
struct GeminiDecision {
    text: String,
    evidence: Vec<EvidenceRef>,
}

#[derive(Debug, Clone, Deserialize)]
struct GeminiActionItem {
    text: String,
    owner: String,
    due_at: Option<String>,
    evidence: Vec<EvidenceRef>,
}

#[derive(Debug, Clone, Deserialize)]
struct GeminiImportantLink {
    url: String,
    label: String,
    why_it_matters: String,
    evidence: Vec<EvidenceRef>,
}

#[derive(Debug, Clone, Deserialize)]
struct GeminiBriefResponse {
    overview: String,
    decisions: Vec<GeminiDecision>,
    action_items: Vec<GeminiActionItem>,
    important_links: Vec<GeminiImportantLink>,
    open_questions: Vec<String>,
}

/// Clean and normalize URLs.
pub fn clean_url(url: &str) -> String {
    let mut cleaned = url.to_string();
    while let Some(c) = cleaned.chars().last() {
        if ".,;:?!)]'".contains(c) {
            cleaned.pop();
        } else {
            break;
        }
    }

    let mut norm = cleaned;
    let lower = norm.to_lowercase();
    if !lower.starts_with("http://") && !lower.starts_with("https://") {
        norm = format!("https://{}", norm);
    }
    norm
}

/// Deterministically extract candidate URLs from episode evidence.
pub fn extract_candidates(
    utterances: &[(i64, String)],
    screenshots: &[(i64, Option<String>, Option<String>)],
) -> Vec<UrlCandidate> {
    // Regex for URLs starting with http://, https://, or www.
    let url_regex =
        Regex::new(r"(?i)\b(?:https?://|www\.)[a-zA-Z0-9-._~:/?#\[\]@!$&'()*+,;=%]+").unwrap();
    // Regex for bare domains with common TLDs
    let bare_domain_regex = Regex::new(r"(?i)\b[a-zA-Z0-9-]+(?:\.[a-zA-Z0-9-]+)*\.(?:com|org|net|edu|gov|io|co|us|fr|info|biz|me|ly|gl|ai|app|dev|sh)\b(?:/[a-zA-Z0-9-._~:/?#\[\]@!$&'()*+,;=%]*)?").unwrap();

    let mut candidates = Vec::new();
    let mut seen = HashSet::new();

    // From screenshots:
    for &(id, ref url_opt, ref ocr_opt) in screenshots {
        if let Some(ref raw_url) = url_opt {
            if !raw_url.trim().is_empty() {
                let lower = raw_url.to_lowercase();
                if lower.starts_with("http://") || lower.starts_with("https://") {
                    let cleaned = clean_url(raw_url);
                    if seen.insert(cleaned.clone()) {
                        candidates.push(UrlCandidate {
                            url: cleaned,
                            record_type: "screenshot".to_string(),
                            record_id: id,
                        });
                    }
                }
            }
        }

        if let Some(ref ocr) = ocr_opt {
            for m in url_regex.find_iter(ocr) {
                let cleaned = clean_url(m.as_str());
                if seen.insert(cleaned.clone()) {
                    candidates.push(UrlCandidate {
                        url: cleaned,
                        record_type: "screenshot".to_string(),
                        record_id: id,
                    });
                }
            }
            for m in bare_domain_regex.find_iter(ocr) {
                let cleaned = clean_url(m.as_str());
                if seen.insert(cleaned.clone()) {
                    candidates.push(UrlCandidate {
                        url: cleaned,
                        record_type: "screenshot".to_string(),
                        record_id: id,
                    });
                }
            }
        }
    }

    // From utterances:
    for &(id, ref text) in utterances {
        for m in url_regex.find_iter(text) {
            let cleaned = clean_url(m.as_str());
            if seen.insert(cleaned.clone()) {
                candidates.push(UrlCandidate {
                    url: cleaned,
                    record_type: "utterance".to_string(),
                    record_id: id,
                });
            }
        }
        for m in bare_domain_regex.find_iter(text) {
            let cleaned = clean_url(m.as_str());
            if seen.insert(cleaned.clone()) {
                candidates.push(UrlCandidate {
                    url: cleaned,
                    record_type: "utterance".to_string(),
                    record_id: id,
                });
            }
        }
    }

    candidates
}

fn normalized_mirror_text(text: &str) -> String {
    let mut normalized = String::new();
    let mut pending_space = false;
    for ch in text.chars().flat_map(char::to_lowercase) {
        if ch.is_alphanumeric() {
            if pending_space && !normalized.is_empty() {
                normalized.push(' ');
            }
            normalized.push(ch);
            pending_space = false;
        } else {
            pending_space = true;
        }
    }
    normalized
}

fn likely_mirrored_text(left: &str, right: &str) -> bool {
    let left = normalized_mirror_text(left);
    let right = normalized_mirror_text(right);
    if left.is_empty() || right.is_empty() {
        return false;
    }

    let left_tokens = left.split_whitespace().collect::<HashSet<_>>();
    let right_tokens = right.split_whitespace().collect::<HashSet<_>>();
    let shorter_tokens = left_tokens.len().min(right_tokens.len());
    let shorter_chars = left.chars().count().min(right.chars().count());

    // Short acknowledgements and stock phrases are often genuinely spoken by
    // both sides. Never merge them solely because mic/system captured the same
    // words near each other.
    if shorter_tokens < 5 || shorter_chars < 24 {
        return false;
    }
    if left == right {
        return true;
    }

    let overlap = left_tokens.intersection(&right_tokens).count();
    let union = left_tokens.union(&right_tokens).count();
    let containment = overlap as f64 / shorter_tokens as f64;
    let jaccard = overlap as f64 / union.max(1) as f64;
    let length_ratio = left_tokens.len().max(right_tokens.len()) as f64 / shorter_tokens as f64;

    overlap >= 5 && containment >= 0.75 && jaccard >= 0.50 && length_ratio <= 2.5
}

fn compact_capture_field(value: &str, max_chars: usize) -> String {
    let one_line = value.split_whitespace().collect::<Vec<_>>().join(" ");
    let mut chars = one_line.chars();
    let mut compact = chars.by_ref().take(max_chars).collect::<String>();
    if chars.next().is_some() {
        compact.push('…');
    }
    compact
}

fn dedupe_mirrored_utterances(utterances: &[UtteranceEvidenceRow]) -> Vec<UtteranceEvidenceGroup> {
    let mut ordered = utterances.to_vec();
    ordered.sort_by_key(|row| (row.at_ms, row.id));

    let mut groups: Vec<UtteranceEvidenceGroup> = Vec::new();
    for row in ordered {
        let mirror_group = groups
            .iter()
            .enumerate()
            .rev()
            .take_while(|(_, group)| {
                row.at_ms.abs_diff(group.at_ms) <= MIRRORED_UTTERANCE_WINDOW_MS as u64
            })
            .find_map(|(index, group)| {
                (!group.source_types.contains(&row.source_type)
                    && group
                        .texts
                        .iter()
                        .any(|text| likely_mirrored_text(text, &row.text)))
                .then_some(index)
            });

        if let Some(index) = mirror_group {
            let group = &mut groups[index];
            group.ids.push(row.id);
            group.speakers.insert(row.speaker);
            group.source_types.insert(row.source_type);
            if !group.texts.contains(&row.text) {
                group.texts.push(row.text);
            }
        } else {
            let mut speakers = BTreeSet::new();
            speakers.insert(row.speaker);
            let mut source_types = BTreeSet::new();
            source_types.insert(row.source_type);
            groups.push(UtteranceEvidenceGroup {
                at: row.at,
                at_ms: row.at_ms,
                ids: vec![row.id],
                speakers,
                source_types,
                texts: vec![row.text],
            });
        }
    }

    groups
}

fn bounded_chronological_log(mut entries: Vec<RenderedEvidenceEntry>, max_bytes: usize) -> String {
    const HEADER: &str = "CAPTURE LOG EVIDENCE (chronological):\n";
    entries.sort_by_key(|entry| (entry.at_ms, entry.record_order, entry.record_id));

    let full_len = HEADER.len()
        + entries
            .iter()
            .map(|entry| entry.line.len() + 1)
            .sum::<usize>();
    if full_len <= max_bytes {
        let mut rendered = String::with_capacity(full_len);
        rendered.push_str(HEADER);
        for entry in entries {
            rendered.push_str(&entry.line);
            rendered.push('\n');
        }
        return rendered;
    }

    // Keep whole evidence rows from both ends of the episode. This preserves
    // opening context and end-of-session assignments/outcomes without ever
    // cutting an evidence ID or URL in half.
    const MARKER_RESERVE: usize = 128;
    let content_budget = max_bytes
        .saturating_sub(HEADER.len())
        .saturating_sub(MARKER_RESERVE);
    let front_budget = content_budget / 2;
    let back_budget = content_budget - front_budget;

    let mut front_count = 0;
    let mut front_bytes = 0;
    while front_count < entries.len() {
        let next = entries[front_count].line.len() + 1;
        if front_bytes + next > front_budget {
            break;
        }
        front_bytes += next;
        front_count += 1;
    }

    let mut back_count = 0;
    let mut back_bytes = 0;
    while back_count < entries.len().saturating_sub(front_count) {
        let index = entries.len() - back_count - 1;
        let next = entries[index].line.len() + 1;
        if back_bytes + next > back_budget {
            break;
        }
        back_bytes += next;
        back_count += 1;
    }

    let omitted = entries.len().saturating_sub(front_count + back_count);
    let mut rendered = String::with_capacity(max_bytes);
    rendered.push_str(HEADER);
    for entry in entries.iter().take(front_count) {
        rendered.push_str(&entry.line);
        rendered.push('\n');
    }
    rendered.push_str(&format!(
        "[capture-log-boundary] {omitted} middle evidence rows omitted to enforce the input bound\n"
    ));
    for entry in entries.iter().skip(entries.len() - back_count) {
        rendered.push_str(&entry.line);
        rendered.push('\n');
    }
    rendered
}

fn bounded_text_edges(text: &str, max_bytes: usize) -> String {
    const MARKER: &str = "\n[bounded-text] middle omitted\n";
    if text.len() <= max_bytes {
        return text.to_string();
    }
    if max_bytes <= MARKER.len() {
        let mut end = max_bytes.min(text.len());
        while end > 0 && !text.is_char_boundary(end) {
            end -= 1;
        }
        return text[..end].to_string();
    }

    let content = max_bytes - MARKER.len();
    let front_budget = content / 2;
    let back_budget = content - front_budget;
    let mut front_end = front_budget.min(text.len());
    while front_end > 0 && !text.is_char_boundary(front_end) {
        front_end -= 1;
    }
    let mut back_start = text.len().saturating_sub(back_budget);
    while back_start < text.len() && !text.is_char_boundary(back_start) {
        back_start += 1;
    }
    format!("{}{}{}", &text[..front_end], MARKER, &text[back_start..])
}

fn render_capture_log(
    utterances: &[UtteranceEvidenceRow],
    screenshots: &[ScreenshotEvidenceRow],
    max_bytes: usize,
) -> String {
    let mut entries = Vec::new();

    for group in dedupe_mirrored_utterances(utterances) {
        let ids = group
            .ids
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(", ");
        let speakers = group.speakers.into_iter().collect::<Vec<_>>().join(", ");
        let source_types = group
            .source_types
            .into_iter()
            .collect::<Vec<_>>()
            .join(", ");
        let texts = group
            .texts
            .iter()
            .map(|text| compact_capture_field(text, MAX_FINALIZER_UTTERANCE_CHARS))
            .collect::<Vec<_>>();
        entries.push(RenderedEvidenceEntry {
            at_ms: group.at_ms,
            record_order: 0,
            record_id: group.ids[0],
            line: format!(
                "[utterance-evidence] IDs: [{ids}] | At: {} | Speakers: {} | Audio sources: {} | Text variants: {}",
                group.at,
                compact_capture_field(&speakers, 500),
                compact_capture_field(&source_types, 100),
                serde_json::to_string(&texts).unwrap_or_else(|_| "[]".into()),
            ),
        });
    }

    for screenshot in screenshots.iter().filter(|row| !row.is_duplicate) {
        let app = compact_capture_field(screenshot.active_app.as_deref().unwrap_or("<none>"), 500);
        let window = compact_capture_field(
            screenshot.window_title.as_deref().unwrap_or("<none>"),
            1_000,
        );
        // Candidate URLs are already bounded by the sync contract. Preserve
        // the complete literal path; truncation can make a resource unusable.
        let url = screenshot
            .url
            .as_deref()
            .map(|url| compact_capture_field(url, usize::MAX))
            .unwrap_or_else(|| "<none>".into());
        let salient = crate::ocr::select_salient_ocr(
            screenshot.ocr_text.as_deref(),
            screenshot.salient_ocr_text.as_deref(),
        );
        let ocr = compact_capture_field(
            salient.as_deref().unwrap_or("<none>"),
            MAX_FINALIZER_OCR_CHARS,
        );
        let screen_facts = salient
            .as_deref()
            .map(crate::ocr::extract_screen_facts)
            .unwrap_or_default();
        entries.push(RenderedEvidenceEntry {
            at_ms: screenshot.captured_at_ms,
            record_order: 1,
            record_id: screenshot.id,
            line: format!(
                "[screenshot-evidence] ID: {} | At: {} | App: {} | Window: {} | URL: {} | Salient OCR: {} | Screen facts: {}",
                screenshot.id,
                screenshot.captured_at,
                serde_json::to_string(&app).unwrap_or_else(|_| "\"\"".into()),
                serde_json::to_string(&window).unwrap_or_else(|_| "\"\"".into()),
                serde_json::to_string(&url).unwrap_or_else(|_| "\"\"".into()),
                serde_json::to_string(&ocr).unwrap_or_else(|_| "\"\"".into()),
                serde_json::to_string(&screen_facts).unwrap_or_else(|_| "[]".into()),
            ),
        });
    }

    bounded_chronological_log(entries, max_bytes)
}

fn grounding_requirements(
    utterances: &[UtteranceEvidenceRow],
    screenshots: &[ScreenshotEvidenceRow],
) -> Vec<GroundingRequirement> {
    let mut requirements = Vec::new();
    for utterance in utterances {
        let singular_sequence = crate::ocr::contains_singular_deictic(&utterance.text)
            && utterances
                .iter()
                .filter(|candidate| {
                    crate::ocr::contains_singular_deictic(&candidate.text)
                        && (candidate.at_ms - utterance.at_ms).abs() <= 20_000
                })
                .count()
                >= 2;
        if !crate::ocr::contains_plural_deictic(&utterance.text) && !singular_sequence {
            continue;
        }
        if requirements
            .iter()
            .any(|requirement: &GroundingRequirement| {
                (requirement.at_ms - utterance.at_ms).abs() <= 30_000
            })
        {
            continue;
        }
        let mut all_entities = Vec::new();
        let mut all_seen = HashSet::new();
        let mut primary_entities = Vec::new();
        let mut primary_seen = HashSet::new();
        for screenshot in screenshots.iter().filter(|row| {
            !row.is_duplicate && (row.captured_at_ms - utterance.at_ms).abs() <= 45_000
        }) {
            let Some(salient) = crate::ocr::select_salient_ocr(
                screenshot.ocr_text.as_deref(),
                screenshot.salient_ocr_text.as_deref(),
            ) else {
                continue;
            };
            let facts = crate::ocr::extract_screen_facts(&salient);
            if facts.len() == 1 {
                let entity = facts[0].clone();
                if primary_seen.insert(entity.to_lowercase()) {
                    primary_entities.push(entity);
                }
            }
            for entity in facts {
                if all_seen.insert(entity.to_lowercase()) {
                    all_entities.push(entity);
                }
            }
        }
        let entities = if primary_entities.len() == 2 {
            primary_entities
        } else {
            all_entities
        };
        if entities.len() == 2 {
            requirements.push(GroundingRequirement {
                at_ms: utterance.at_ms,
                entities,
            });
        }
    }
    requirements
}

fn render_grounding_requirements(requirements: &[GroundingRequirement]) -> String {
    if requirements.is_empty() {
        return String::new();
    }
    let requirements = requirements
        .iter()
        .map(|requirement| {
            format!(
                "- At {}, the pointing language refers to exactly these literal screen facts: {}. Name both in the overview.",
                isotime::format_epoch_millis(requirement.at_ms),
                requirement
                    .entities
                    .iter()
                    .map(|entity| format!("{entity:?}"))
                    .collect::<Vec<_>>()
                    .join(", ")
            )
        })
        .collect::<Vec<_>>()
        .join("\n");
    format!("\nGROUNDING REQUIREMENTS:\n{requirements}\n")
}

fn missing_grounded_entities(
    brief: &GeminiBriefResponse,
    requirements: &[GroundingRequirement],
) -> Vec<String> {
    let overview = brief.overview.to_lowercase();
    let mut missing = requirements
        .iter()
        .flat_map(|requirement| requirement.entities.iter())
        .filter(|entity| !overview.contains(&entity.to_lowercase()))
        .cloned()
        .collect::<Vec<_>>();
    missing.sort_by_key(|entity| entity.to_lowercase());
    missing.dedup_by(|left, right| left.eq_ignore_ascii_case(right));
    missing
}

fn render_candidate_urls(
    candidates: &[UrlCandidate],
    max_bytes: usize,
) -> (String, HashSet<String>) {
    const HEADER: &str = "\nCANDIDATE URLS ALLOWED:\n";
    const MARKER_RESERVE: usize = 112;
    if max_bytes < HEADER.len() + MARKER_RESERVE {
        return (String::new(), HashSet::new());
    }

    let mut rendered = String::with_capacity(max_bytes);
    rendered.push_str(HEADER);
    let mut rendered_urls = HashSet::new();
    let mut omitted = 0usize;
    for (index, candidate) in candidates.iter().enumerate() {
        let line = format!(
            "Candidate URL {}: {} (from {} id {})\n",
            index + 1,
            candidate.url,
            candidate.record_type,
            candidate.record_id
        );
        if rendered.len() + line.len() + MARKER_RESERVE <= max_bytes {
            rendered.push_str(&line);
            rendered_urls.insert(candidate.url.clone());
        } else {
            omitted += 1;
        }
    }
    if omitted > 0 {
        rendered.push_str(&format!(
            "[candidate-url-boundary] {omitted} candidate URLs omitted to enforce the input bound\n"
        ));
    }
    (rendered, rendered_urls)
}

fn render_finalizer_model_input(
    utterances: &[UtteranceEvidenceRow],
    screenshots: &[ScreenshotEvidenceRow],
    candidates: &[UrlCandidate],
    max_bytes: usize,
) -> (String, HashSet<String>) {
    let candidate_budget = MAX_FINALIZER_CANDIDATE_BYTES.min(max_bytes / 4);
    let capture_budget = max_bytes.saturating_sub(candidate_budget);
    let mut rendered = render_capture_log(utterances, screenshots, capture_budget);
    let remaining = max_bytes.saturating_sub(rendered.len());
    let (candidate_section, rendered_urls) = render_candidate_urls(candidates, remaining);
    rendered.push_str(&candidate_section);
    debug_assert!(rendered.len() <= max_bytes);
    (rendered, rendered_urls)
}

/// The response JSON schema for Gemini final brief.
fn brief_response_schema() -> Value {
    json!({
        "type": "OBJECT",
        "properties": {
            "overview": {"type": "STRING"},
            "decisions": {
                "type": "ARRAY",
                "items": {
                    "type": "OBJECT",
                    "properties": {
                        "text": {"type": "STRING"},
                        "evidence": {
                            "type": "ARRAY",
                            "items": {
                                "type": "OBJECT",
                                "properties": {
                                    "record_type": {"type": "STRING", "enum": ["utterance", "screenshot"]},
                                    "record_id": {"type": "INTEGER"}
                                },
                                "required": ["record_type", "record_id"]
                            }
                        }
                    },
                    "required": ["text", "evidence"]
                }
            },
            "action_items": {
                "type": "ARRAY",
                "items": {
                    "type": "OBJECT",
                    "properties": {
                        "text": {"type": "STRING"},
                        "owner": {"type": "STRING"},
                        "due_at": {"type": "STRING"},
                        "evidence": {
                            "type": "ARRAY",
                            "items": {
                                "type": "OBJECT",
                                "properties": {
                                    "record_type": {"type": "STRING", "enum": ["utterance", "screenshot"]},
                                    "record_id": {"type": "INTEGER"}
                                },
                                "required": ["record_type", "record_id"]
                            }
                        }
                    },
                    "required": ["text", "owner", "evidence"]
                }
            },
            "important_links": {
                "type": "ARRAY",
                "items": {
                    "type": "OBJECT",
                    "properties": {
                        "url": {"type": "STRING"},
                        "label": {"type": "STRING"},
                        "why_it_matters": {"type": "STRING"},
                        "evidence": {
                            "type": "ARRAY",
                            "items": {
                                "type": "OBJECT",
                                "properties": {
                                    "record_type": {"type": "STRING", "enum": ["utterance", "screenshot"]},
                                    "record_id": {"type": "INTEGER"}
                                },
                                "required": ["record_type", "record_id"]
                            }
                        }
                    },
                    "required": ["url", "label", "why_it_matters", "evidence"]
                }
            },
            "open_questions": {
                "type": "ARRAY",
                "items": {"type": "STRING"}
            }
        },
        "required": ["overview", "decisions", "action_items", "important_links", "open_questions"]
    })
}

const FINALIZER_SYSTEM_PROMPT: &str = "You generate a high-signal, evidence-grounded final brief for a completed episode (meeting, lecture, class, etc.).

You are provided with a chronological capture log of utterances and screenshots, along with a list of extracted Candidate URLs that were seen or spoken.

PRINCIPLES:
1. Ground all items in evidence: every decision, action item, and link must reference the correct record_type and record_id from the capture log.
2. Action items: include both specific commitments and explicit requirements or instructions directed at the user. State the exact task, preserve amounts, dates, deadlines, and named resources, identify who owns it (default to 'Me' for requirements directed at the user, or a participant name if known), and use 'due_at' in YYYY-MM-DD format only when explicitly supported (otherwise null).
3. Important links: extract links, provide a descriptive label, explain why it matters, and reference evidence.
4. STRICT LINK RULE: You must ONLY output URLs that are present in the provided list of Candidate URLs. Any URL not in that list is considered a hallucination and is banned.
5. Overview: write 2-3 sentences that preserve the most useful concrete takeaways, requirements, decisions, outcomes, dates, amounts, logistics, and named resources. Do not produce a topic inventory or vague phrases such as 'X was discussed', 'information was provided', or 'the presentation covered'.
6. Never invent, correct, or silently normalize a specific fact. If evidence is ambiguous, omit it or put the uncertainty in open_questions.
7. A mirrored mic/system utterance may appear once with multiple exact evidence IDs. Treat it as one statement, use the listed speaker attribution without guessing, and cite one or more of those IDs as appropriate.
8. Screen facts are conservative literal labels visible on screen. When a GROUNDING REQUIREMENT binds pointing language such as 'these two' to exact screen facts, the overview MUST name every bound entity; never compress them to 'the two items/movies'. Without a requirement, do not guess a pronoun's referent.";

async fn set_finalization_status(
    state: &CpState,
    user_id: &str,
    episode_id: i64,
    status: &str,
    error: Option<&str>,
    attempted: bool,
) -> Result<()> {
    let user = user_id.to_string();
    let status = status.to_string();
    let error = error.map(|value| value.chars().take(1_000).collect::<String>());
    let now = isotime::format_epoch_millis(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as i64,
    );
    let changed = state
        .store
        .with_user(&user, move |conn| {
            let changed = conn.execute(
                "UPDATE episodes
                 SET finalization_status = ?1,
                     finalization_error = ?2,
                     finalization_attempted_at =
                         CASE WHEN ?3 = 1 THEN ?4 ELSE finalization_attempted_at END,
                     updated_at = ?4
                 WHERE id = ?5
                   AND (?3 = 1
                        OR finalization_status != ?1
                        OR COALESCE(finalization_error, '') != COALESCE(?2, ''))",
                rusqlite::params![status, error, i64::from(attempted), now, episode_id],
            )?;
            Ok(changed > 0)
        })
        .await?;
    if changed {
        state.store.save_user(&user).await?;
    }
    Ok(())
}

/// Sweep all eligible episodes for a user and finalize them.
pub async fn finalize_user_episodes(state: &CpState, user_id: &str) -> Result<()> {
    finalize_user_episodes_scoped(state, user_id, None).await
}

/// Retry/finalize one episode without sweeping unrelated history.
pub async fn finalize_user_episode(state: &CpState, user_id: &str, episode_id: i64) -> Result<()> {
    finalize_user_episodes_scoped(state, user_id, Some(episode_id)).await
}

async fn finalize_user_episodes_scoped(
    state: &CpState,
    user_id: &str,
    target_episode_id: Option<i64>,
) -> Result<()> {
    // Scheduler sweeps and user-triggered scoped retries can overlap. Serialize
    // per user so only one model call can target a given episode history at a
    // time, without making one account wait behind another account's sweep.
    static USER_LOCKS: OnceLock<StdMutex<HashMap<String, Arc<tokio::sync::Mutex<()>>>>> =
        OnceLock::new();
    let user_lock = {
        let mut locks = USER_LOCKS
            .get_or_init(|| StdMutex::new(HashMap::new()))
            .lock()
            .unwrap();
        locks
            .entry(user_id.to_string())
            .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(())))
            .clone()
    };
    let _user_guard = user_lock.lock().await;

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64;

    // Four-hour extension window
    let horizon_ms = now - 4 * 60 * 60 * 1000;
    let horizon_iso = isotime::format_epoch_millis(horizon_ms);

    let user = user_id.to_string();

    // Get the summarizer cursor
    let summarized_until = match state.control.summarized_until(user_id).await? {
        Some(c) => c,
        None => {
            if let Some(episode_id) = target_episode_id {
                let _ = set_finalization_status(
                    state,
                    user_id,
                    episode_id,
                    "pending_cursor",
                    None,
                    false,
                )
                .await;
            }
            return Ok(());
        }
    };
    let summarized_until_ms = isotime::parse_epoch_millis(&summarized_until).unwrap_or(0);

    // Fetch candidates from user content DB
    let candidates: Vec<EpisodeRow> = state.store.with_user(&user, move |conn| {
        let mut stmt = conn.prepare(
            "SELECT id, started_at, ended_at, type, title, summary, participants, languages, action_items, model
             FROM episodes
             WHERE (finalized_at IS NULL OR COALESCE(finalization_version, 1) < ?2)
               AND substance != 'none'
               AND (ended_at < ?1 OR ?3 IS NOT NULL)
               AND (?3 IS NULL OR id = ?3)"
        )?;
        let rows = stmt.query_map(rusqlite::params![&horizon_iso, FINALIZATION_VERSION, target_episode_id], |r| {
            Ok(EpisodeRow {
                id: r.get(0)?,
                started_at: r.get(1)?,
                ended_at: r.get(2)?,
                episode_type: r.get(3)?,
                title: r.get(4)?,
                summary: r.get(5)?,
                participants: r.get(6)?,
                languages: r.get(7)?,
                action_items: r.get(8)?,
                model: r.get(9)?,
            })
        })?
        .filter_map(|x| x.ok())
        .collect();
        Ok(rows)
    }).await?;

    for ep in candidates {
        let ended_ms = isotime::parse_epoch_millis(&ep.ended_at).unwrap_or(0);
        if ended_ms >= horizon_ms {
            let _ = set_finalization_status(state, user_id, ep.id, "pending_horizon", None, false)
                .await;
            continue;
        }
        // 1. Cursor check: summarized_until must be >= ended_at + 4h
        if summarized_until_ms < ended_ms + 4 * 60 * 60 * 1000 {
            let _ =
                set_finalization_status(state, user_id, ep.id, "pending_cursor", None, false).await;
            continue;
        }

        // 2. Watermark check: query all contributing devices
        let user_cloned = user.clone();
        let ep_id = ep.id;
        let ended_at_cloned = ep.ended_at.clone();
        let devices: Vec<(String, String)> = state.store.with_user(&user_cloned, move |conn| {
            let mut stmt = conn.prepare(
                "SELECT DISTINCT
                    substr(u.source_key, 1, instr(u.source_key, ':') - 1) as device_id,
                    'audio' as modality
                 FROM utterances u
                 JOIN episode_members m ON m.record_type = 'utterance' AND m.record_id = u.id
                 WHERE m.episode_id = ?1 AND u.source_key IS NOT NULL AND instr(u.source_key, ':') > 0
                 UNION
                 SELECT DISTINCT
                    substr(s.source_key, 1, instr(s.source_key, ':') - 1) as device_id,
                    'screen' as modality
                 FROM screenshots s
                 JOIN episode_members m ON m.record_type = 'screenshot' AND m.record_id = s.id
                 WHERE m.episode_id = ?1 AND s.source_key IS NOT NULL AND instr(s.source_key, ':') > 0"
            )?;
            let rows = stmt.query_map([ep_id], |r| {
                Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?))
            })?
            .filter_map(|x| x.ok())
            .collect();
            Ok(rows)
        }).await?;

        let mut settled = true;
        if !devices.is_empty() {
            let user_cloned2 = user.clone();
            let ended_at_val = ended_at_cloned.clone();
            let device_list = devices.clone();
            let watermarks_ok = state.store.with_user(&user_cloned2, move |conn| {
                for (dev_id, modality) in device_list {
                    let watermark: Option<String> = conn.query_row(
                        "SELECT watermark_at FROM device_watermarks WHERE device_id = ?1 AND modality = ?2",
                        [&dev_id, &modality],
                        |r| r.get(0)
                    )
                    .optional()?;
                    match watermark {
                        Some(w) if w >= ended_at_val => {}
                        _ => return Ok(false),
                    }
                }
                Ok(true)
            }).await?;
            settled = watermarks_ok;
        }

        if !settled {
            let _ =
                set_finalization_status(state, user_id, ep.id, "pending_watermark", None, false)
                    .await;
            info!(
                episode_id = ep.id,
                "episode finalization deferred: devices not settled yet"
            );
            continue;
        }

        let _ = set_finalization_status(state, user_id, ep.id, "processing", None, true).await;

        // 3. Fetch evidence for final brief model input
        let user_cloned3 = user.clone();
        let ep_id = ep.id;
        let (utterance_rows, screenshot_rows): (
            Vec<UtteranceEvidenceRow>,
            Vec<ScreenshotEvidenceRow>,
        ) = state
            .store
            .with_user(&user_cloned3, move |conn| {
                let mut u_stmt = conn.prepare(
                    "SELECT u.id, a.started_at, u.start_offset_seconds, \
                            u.speaker_label, a.source_type, u.text \
                     FROM utterances u \
                     JOIN audio_segments a ON a.id = u.audio_segment_id \
                     JOIN episode_members m \
                       ON m.record_type = 'utterance' AND m.record_id = u.id \
                     WHERE m.episode_id = ?1 \
                     ORDER BY a.started_at ASC, u.start_offset_seconds ASC, u.id ASC",
                )?;
                let utterances = u_stmt
                    .query_map([ep_id], |row| {
                        let segment_started_at: String = row.get(1)?;
                        let start_offset_seconds: f64 = row.get(2)?;
                        let at = isotime::add_seconds(&segment_started_at, start_offset_seconds);
                        Ok(UtteranceEvidenceRow {
                            id: row.get(0)?,
                            at_ms: isotime::parse_epoch_millis(&at).unwrap_or(0),
                            at,
                            speaker: row.get(3)?,
                            source_type: row.get(4)?,
                            text: row.get(5)?,
                        })
                    })?
                    .filter_map(|x| x.ok())
                    .collect();

                let mut s_stmt = conn.prepare(
                    "SELECT s.id, s.captured_at, s.active_app, s.window_title, \
                            s.url, s.ocr_text, s.salient_ocr_text, s.is_duplicate \
                     FROM screenshots s \
                     JOIN episode_members m \
                       ON m.record_type = 'screenshot' AND m.record_id = s.id \
                     WHERE m.episode_id = ?1 \
                     ORDER BY s.captured_at ASC, s.id ASC",
                )?;
                let screenshots = s_stmt
                    .query_map([ep_id], |row| {
                        let captured_at: String = row.get(1)?;
                        Ok(ScreenshotEvidenceRow {
                            id: row.get(0)?,
                            captured_at_ms: isotime::parse_epoch_millis(&captured_at).unwrap_or(0),
                            captured_at,
                            active_app: row.get(2)?,
                            window_title: row.get(3)?,
                            url: row.get(4)?,
                            ocr_text: row.get(5)?,
                            salient_ocr_text: row.get(6)?,
                            is_duplicate: row.get::<_, i64>(7)? != 0,
                        })
                    })?
                    .filter_map(|x| x.ok())
                    .collect();

                Ok((utterances, screenshots))
            })
            .await?;

        // 4. Extract URL candidates
        let utts = utterance_rows
            .iter()
            .map(|row| (row.id, row.text.clone()))
            .collect::<Vec<_>>();
        let scrs = screenshot_rows
            .iter()
            .filter(|row| !row.is_duplicate)
            .map(|row| (row.id, row.url.clone(), row.ocr_text.clone()))
            .collect::<Vec<_>>();
        let candidates = extract_candidates(&utts, &scrs);

        // 5. Build prompt
        let grounding = grounding_requirements(&utterance_rows, &screenshot_rows);
        let grounding_text = render_grounding_requirements(&grounding)
            .chars()
            .take(MAX_FINALIZER_MODEL_INPUT_BYTES / 4)
            .collect::<String>();
        let grounding_bytes = grounding_text.len();
        let (mut log_text, candidate_urls_set) = render_finalizer_model_input(
            &utterance_rows,
            &screenshot_rows,
            &candidates,
            MAX_FINALIZER_MODEL_INPUT_BYTES - grounding_bytes,
        );
        log_text.push_str(&grounding_text);

        info!(episode_id = ep.id, "generating final brief with Gemini");

        let model_resp = match vertex::generate_custom(
            &state.config,
            FINALIZER_SYSTEM_PROMPT,
            &log_text,
            brief_response_schema(),
            16384,
        )
        .await
        {
            Ok(r) => r,
            Err(e) => {
                warn!(episode_id = ep.id, error = %e, "Gemini call for final brief failed");
                let _ = set_finalization_status(
                    state,
                    user_id,
                    ep.id,
                    "retry_model",
                    Some(&e.to_string()),
                    false,
                )
                .await;
                continue;
            }
        };

        let mut parsed: GeminiBriefResponse = match serde_json::from_str(&model_resp) {
            Ok(p) => p,
            Err(e) => {
                warn!(episode_id = ep.id, error = %e, "Gemini final brief response unparseable");
                let _ = set_finalization_status(
                    state,
                    user_id,
                    ep.id,
                    "retry_model",
                    Some("final brief response was not valid JSON"),
                    false,
                )
                .await;
                continue;
            }
        };

        let missing = missing_grounded_entities(&parsed, &grounding);
        if !missing.is_empty() {
            let correction = format!(
                "\n\nCORRECTION REQUIRED: the overview omitted these literal grounded screen titles: {}. \
                 Return the complete corrected JSON and preserve all evidence boundaries.",
                missing
                    .iter()
                    .map(|entity| format!("{entity:?}"))
                    .collect::<Vec<_>>()
                    .join(", ")
            );
            let prior = bounded_text_edges(&model_resp, 32 * 1024);
            let prior_header = "\n\nPRIOR JSON RESPONSE:\n";
            let evidence_budget = MAX_FINALIZER_MODEL_INPUT_BYTES
                .saturating_sub(prior_header.len() + prior.len() + correction.len());
            let repair_log = bounded_text_edges(&log_text, evidence_budget);
            let repair_input = format!("{repair_log}{prior_header}{prior}{correction}");
            debug_assert!(repair_input.len() <= MAX_FINALIZER_MODEL_INPUT_BYTES);
            match vertex::generate_custom(
                &state.config,
                FINALIZER_SYSTEM_PROMPT,
                &repair_input,
                brief_response_schema(),
                16_384,
            )
            .await
            {
                Ok(repaired_text) => {
                    match serde_json::from_str::<GeminiBriefResponse>(&repaired_text) {
                        Ok(repaired)
                            if missing_grounded_entities(&repaired, &grounding).is_empty() =>
                        {
                            parsed = repaired;
                        }
                        _ => {
                            let _ = set_finalization_status(
                                state,
                                user_id,
                                ep.id,
                                "retry_model",
                                Some("grounded screen titles were omitted after one repair"),
                                false,
                            )
                            .await;
                            continue;
                        }
                    }
                }
                Err(error) => {
                    let _ = set_finalization_status(
                        state,
                        user_id,
                        ep.id,
                        "retry_model",
                        Some(&error.to_string()),
                        false,
                    )
                    .await;
                    continue;
                }
            }
        }

        // 6. Validate & filter evidence references + URLs
        let utterance_ids: HashSet<i64> = utts.iter().map(|u| u.0).collect();
        let screenshot_ids: HashSet<i64> = scrs.iter().map(|s| s.0).collect();
        let screenshot_member_ids: HashSet<i64> =
            screenshot_rows.iter().map(|row| row.id).collect();

        let is_valid_evidence = |er: &EvidenceRef| -> bool {
            match er.record_type.as_str() {
                "utterance" => utterance_ids.contains(&er.record_id),
                "screenshot" => screenshot_ids.contains(&er.record_id),
                _ => false,
            }
        };

        let decisions: Vec<Value> = parsed
            .decisions
            .into_iter()
            .map(|d| {
                let filtered_evidence: Vec<Value> = d
                    .evidence
                    .into_iter()
                    .filter(|e| is_valid_evidence(e))
                    .map(|e| json!({"record_type": e.record_type, "record_id": e.record_id}))
                    .collect();
                json!({
                    "text": d.text,
                    "evidence": filtered_evidence
                })
            })
            .collect();

        let action_items: Vec<Value> = parsed
            .action_items
            .into_iter()
            .map(|a| {
                let filtered_evidence: Vec<Value> = a
                    .evidence
                    .into_iter()
                    .filter(|e| is_valid_evidence(e))
                    .map(|e| json!({"record_type": e.record_type, "record_id": e.record_id}))
                    .collect();
                json!({
                    "text": a.text,
                    "owner": a.owner,
                    "due_at": a.due_at,
                    "evidence": filtered_evidence
                })
            })
            .collect();

        let important_links: Vec<Value> = parsed
            .important_links
            .into_iter()
            .filter(|l| {
                let norm = clean_url(&l.url);
                candidate_urls_set.contains(&norm)
            })
            .map(|l| {
                let filtered_evidence: Vec<Value> = l
                    .evidence
                    .into_iter()
                    .filter(|e| is_valid_evidence(e))
                    .map(|e| json!({"record_type": e.record_type, "record_id": e.record_id}))
                    .collect();
                json!({
                    "url": clean_url(&l.url),
                    "label": l.label,
                    "why_it_matters": l.why_it_matters,
                    "evidence": filtered_evidence
                })
            })
            .collect();

        // 7. Check if user has email configured & enabled
        let gmail_config = state.control.get_gmail_config(user_id).await?;
        let email_enabled = gmail_config.as_ref().map(|c| c.enabled).unwrap_or(false);

        // 8. Optimistic commit transaction
        let user_cloned4 = user.clone();
        let ep_id = ep.id;
        let overview = parsed.overview;
        let open_questions_json = serde_json::to_string(&parsed.open_questions).unwrap_or_default();
        let decisions_json = serde_json::to_string(&decisions).unwrap_or_default();
        let action_items_json = serde_json::to_string(&action_items).unwrap_or_default();
        let important_links_json = serde_json::to_string(&important_links).unwrap_or_default();

        let commit_res = state.store.with_user(&user_cloned4, move |conn| {
            conn.execute("BEGIN IMMEDIATE TRANSACTION", [])?;

            // Re-verify the current finalization version. A lower-version brief may
            // be regenerated, but a concurrent current-version commit wins.
            let (existing_finalized_at, existing_version): (Option<String>, Option<i32>) = conn.query_row(
                "SELECT finalized_at, finalization_version FROM episodes WHERE id = ?1",
                [ep_id],
                |r| Ok((r.get(0)?, r.get(1)?))
            )?;

            let mode = finalization_mode(existing_finalized_at.as_deref(), existing_version);
            if mode == FinalizationMode::AlreadyCurrent {
                conn.execute("ROLLBACK", [])?;
                return Err(EnclaveError::Config("episode already finalized at current version".into()));
            }

            // Fetch current members to make sure membership hasn't changed
            let mut u_stmt = conn.prepare("SELECT record_id FROM episode_members WHERE episode_id = ?1 AND record_type = 'utterance'")?;
            let current_utts: HashSet<i64> = u_stmt.query_map([ep_id], |r| r.get(0))?.filter_map(|x| x.ok()).collect();
            let mut s_stmt = conn.prepare("SELECT record_id FROM episode_members WHERE episode_id = ?1 AND record_type = 'screenshot'")?;
            let current_scrs: HashSet<i64> = s_stmt.query_map([ep_id], |r| r.get(0))?.filter_map(|x| x.ok()).collect();

            if current_utts != utterance_ids || current_scrs != screenshot_member_ids {
                conn.execute("ROLLBACK", [])?;
                return Err(EnclaveError::Config("episode membership changed during finalization".into()));
            }

            // Insert final brief
            conn.execute(
                "INSERT OR REPLACE INTO episode_final_briefs (episode_id, overview, decisions, action_items, important_links, open_questions)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                rusqlite::params![ep_id, overview, decisions_json, action_items_json, important_links_json, open_questions_json]
            )?;

            // Only a first finalization may enqueue mail. Versioned repairs update
            // the canonical web/export brief without surprising the user with a
            // second message for the same historical episode.
            let email_enqueued = mode.should_enqueue_email(email_enabled);
            if email_enqueued {
                conn.execute(
                    "INSERT OR REPLACE INTO episode_deliveries (episode_id, channel, delivery_version, state)
                     VALUES (?1, 'gmail', ?2, 'pending')",
                    rusqlite::params![ep_id, FINALIZATION_VERSION]
                )?;
            }

            // Mark a new episode finalized, or atomically advance a regenerated
            // brief while preserving the original finalization timestamp.
            let now_iso = isotime::format_epoch_millis(
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_millis() as i64
            );
            conn.execute(
                "UPDATE episodes
                 SET finalized_at = COALESCE(finalized_at, ?1),
                     finalization_version = ?2,
                     finalization_status = 'complete',
                     finalization_error = NULL,
                     updated_at = ?1
                 WHERE id = ?3",
                rusqlite::params![now_iso, FINALIZATION_VERSION, ep_id]
            )?;

            conn.execute("COMMIT", [])?;
            Ok(email_enqueued)
        }).await;

        match commit_res {
            Ok(email_enqueued) => {
                info!(
                    episode_id = ep.id,
                    email_enqueued, "episode successfully finalized"
                );
                let _ = state.store.save_user(&user).await;
            }
            Err(e) => {
                warn!(episode_id = ep.id, error = %e, "failed to commit finalized episode transaction");
                if e.to_string()
                    .contains("episode already finalized at current version")
                {
                    let _ = set_finalization_status(state, user_id, ep.id, "complete", None, false)
                        .await;
                } else {
                    let _ = set_finalization_status(
                        state,
                        user_id,
                        ep.id,
                        "retry_model",
                        Some(&e.to_string()),
                        false,
                    )
                    .await;
                }
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_french_resource_domains_from_spoken_and_screen_evidence() {
        let utterances = vec![(1, "Apply at visa.fr before arrival.".to_string())];
        let screenshots = vec![(
            2,
            None,
            Some("Book a doctor through doctorly.fr/appointments".to_string()),
        )];

        let urls: HashSet<String> = extract_candidates(&utterances, &screenshots)
            .into_iter()
            .map(|candidate| candidate.url)
            .collect();

        assert!(urls.contains("https://visa.fr"));
        assert!(urls.contains("https://doctorly.fr/appointments"));
    }

    #[test]
    fn finalizer_v3_requires_concrete_user_directed_and_grounded_takeaways() {
        assert_eq!(FINALIZATION_VERSION, 3);
        assert!(FINALIZER_SYSTEM_PROMPT.contains("explicit requirements or instructions"));
        assert!(FINALIZER_SYSTEM_PROMPT.contains("amounts, dates, deadlines"));
        assert!(FINALIZER_SYSTEM_PROMPT.contains("Do not produce a topic inventory"));
        assert!(FINALIZER_SYSTEM_PROMPT.contains("Never invent"));
        assert!(FINALIZER_SYSTEM_PROMPT.contains("GROUNDING REQUIREMENT"));
        assert!(FINALIZER_SYSTEM_PROMPT.contains("never compress them"));
    }

    #[test]
    fn historical_v1_briefs_regenerate_without_reenqueuing_email() {
        let historical_default = finalization_mode(Some("2026-07-01T12:00:00Z"), None);
        let historical_v1 = finalization_mode(Some("2026-07-01T12:00:00Z"), Some(1));

        assert_eq!(historical_default, FinalizationMode::Regeneration);
        assert_eq!(historical_v1, FinalizationMode::Regeneration);
        assert!(!historical_default.should_enqueue_email(true));
        assert!(!historical_v1.should_enqueue_email(true));
    }

    #[test]
    fn current_briefs_are_terminal_but_initial_finalization_may_enqueue() {
        let current = finalization_mode(Some("2026-07-01T12:00:00Z"), Some(3));
        assert_eq!(current, FinalizationMode::AlreadyCurrent);
        assert!(!current.should_enqueue_email(true));

        let initial = finalization_mode(None, None);
        assert_eq!(initial, FinalizationMode::Initial);
        assert!(initial.should_enqueue_email(true));
        assert!(!initial.should_enqueue_email(false));
    }

    #[test]
    fn episode_312_final_brief_requires_both_grounded_movie_titles() {
        let utterances = vec![UtteranceEvidenceRow {
            id: 1,
            at: "2026-07-22T12:39:59Z".into(),
            at_ms: isotime::parse_epoch_millis("2026-07-22T12:39:59Z").unwrap(),
            speaker: "Speaker 2".into(),
            source_type: "system".into(),
            text: "these are the two movies".into(),
        }];
        let screenshot = |id, at: &str, title: &str| ScreenshotEvidenceRow {
            id,
            captured_at: at.into(),
            captured_at_ms: isotime::parse_epoch_millis(at).unwrap(),
            active_app: Some("TV".into()),
            window_title: Some(title.into()),
            url: None,
            ocr_text: Some(format!(
                "TV File Edit Actions View Controls Account Window Help\n{title}\nMovie • Family"
            )),
            salient_ocr_text: None,
            is_duplicate: false,
        };
        let screenshots = vec![
            ScreenshotEvidenceRow {
                id: 6,
                captured_at: "2026-07-22T12:40:27Z".into(),
                captured_at_ms: isotime::parse_epoch_millis("2026-07-22T12:40:27Z").unwrap(),
                active_app: Some("TV".into()),
                window_title: Some("Search".into()),
                url: None,
                ocr_text: Some(
                    "MARY POPPINS\nMovie • Comedy\nMARY POPPINS RETURNS\nMovie • Musical\n\
                     SAVING MR BANKS\nMovie • Drama"
                        .into(),
                ),
                salient_ocr_text: None,
                is_duplicate: false,
            },
            screenshot(7, "2026-07-22T12:40:29Z", "MARY POPPINS"),
            screenshot(8, "2026-07-22T12:40:35Z", "MARY POPPINS RETURNS"),
        ];
        let requirements = grounding_requirements(&utterances, &screenshots);
        assert_eq!(requirements.len(), 1);
        assert_eq!(
            requirements[0].entities,
            vec!["MARY POPPINS", "MARY POPPINS RETURNS"]
        );

        let generic = GeminiBriefResponse {
            overview: "Download the two specified movies for the car trip.".into(),
            decisions: vec![],
            action_items: vec![],
            important_links: vec![],
            open_questions: vec![],
        };
        assert_eq!(
            missing_grounded_entities(&generic, &requirements),
            vec!["MARY POPPINS", "MARY POPPINS RETURNS"]
        );

        let grounded = GeminiBriefResponse {
            overview:
                "Download Mary Poppins (1964) and Mary Poppins Returns (2018) for the car trip."
                    .into(),
            ..generic
        };
        assert!(missing_grounded_entities(&grounded, &requirements).is_empty());

        let log = render_capture_log(&utterances, &screenshots, 20_000);
        assert!(log.contains("Screen facts: [\"MARY POPPINS\"]"));
        assert!(!log.contains("File Edit Actions"));
    }

    #[test]
    fn capture_log_is_chronological_attributed_and_dedupes_mirrored_audio() {
        let utterances = vec![
            UtteranceEvidenceRow {
                id: 1,
                at: "2026-07-01T10:00:02.000Z".into(),
                at_ms: isotime::parse_epoch_millis("2026-07-01T10:00:02.000Z").unwrap(),
                speaker: "Ana".into(),
                source_type: "system".into(),
                text: "Submit the visa.fr form by Friday.".into(),
            },
            UtteranceEvidenceRow {
                id: 2,
                at: "2026-07-01T10:00:02.200Z".into(),
                at_ms: isotime::parse_epoch_millis("2026-07-01T10:00:02.200Z").unwrap(),
                speaker: "Me".into(),
                source_type: "mic".into(),
                text: "Submit the visa.fr form by Friday!".into(),
            },
            UtteranceEvidenceRow {
                id: 3,
                at: "2026-07-01T10:00:05.000Z".into(),
                at_ms: isotime::parse_epoch_millis("2026-07-01T10:00:05.000Z").unwrap(),
                speaker: "Ana".into(),
                source_type: "system".into(),
                text: "Bring the original passport.".into(),
            },
        ];
        let screenshots = vec![
            ScreenshotEvidenceRow {
                id: 7,
                captured_at: "2026-07-01T10:00:03.000Z".into(),
                captured_at_ms: isotime::parse_epoch_millis("2026-07-01T10:00:03.000Z").unwrap(),
                active_app: Some("Chrome".into()),
                window_title: Some("Visa application".into()),
                url: Some("https://visa.fr/apply?case=123".into()),
                ocr_text: Some("Fee: 99 EUR".into()),
                salient_ocr_text: None,
                is_duplicate: false,
            },
            ScreenshotEvidenceRow {
                id: 8,
                captured_at: "2026-07-01T10:00:04.000Z".into(),
                captured_at_ms: isotime::parse_epoch_millis("2026-07-01T10:00:04.000Z").unwrap(),
                active_app: Some("Chrome".into()),
                window_title: Some("Duplicate".into()),
                url: None,
                ocr_text: Some("must not appear".into()),
                salient_ocr_text: None,
                is_duplicate: true,
            },
        ];

        let log = render_capture_log(&utterances, &screenshots, 20_000);
        assert!(log.contains("IDs: [1, 2]"));
        assert!(log.contains("Speakers: Ana, Me"));
        assert!(log.contains("Audio sources: mic, system"));
        assert_eq!(log.matches("[utterance-evidence]").count(), 2);
        assert!(log.contains("Submit the visa.fr form by Friday."));
        assert!(log.contains("Submit the visa.fr form by Friday!"));
        assert!(log.contains("https://visa.fr/apply?case=123"));
        assert!(log.contains("App: \"Chrome\""));
        assert!(!log.contains("must not appear"));

        let first = log.find("IDs: [1, 2]").unwrap();
        let screen = log.find("[screenshot-evidence] ID: 7").unwrap();
        let last = log.find("IDs: [3]").unwrap();
        assert!(first < screen && screen < last);
    }

    #[test]
    fn capture_log_bound_keeps_episode_edges_in_order() {
        let screenshots = (0..12)
            .map(|id| ScreenshotEvidenceRow {
                id,
                captured_at: format!("2026-07-01T10:00:{id:02}.000Z"),
                captured_at_ms: id * 1_000,
                active_app: Some("Chrome".into()),
                window_title: Some(format!("Window {id}")),
                url: Some(format!("https://example.com/{id}")),
                ocr_text: Some("bounded OCR evidence".repeat(4)),
                salient_ocr_text: None,
                is_duplicate: false,
            })
            .collect::<Vec<_>>();

        let log = render_capture_log(&[], &screenshots, 1_000);
        assert!(log.len() <= 1_000);
        assert!(log.contains("[capture-log-boundary]"));
        assert!(log.contains("ID: 0"));
        assert!(log.contains("ID: 11"));
        assert!(log.find("ID: 0").unwrap() < log.find("ID: 11").unwrap());
    }

    #[test]
    fn repair_text_bound_preserves_utf8_edges() {
        let text = format!("START-{}-END", "é記".repeat(100));
        let bounded = bounded_text_edges(&text, 80);
        assert!(bounded.len() <= 80);
        assert!(bounded.starts_with("START-"));
        assert!(bounded.ends_with("-END"));
        assert!(bounded.contains("[bounded-text]"));
    }

    #[test]
    fn mirrored_audio_dedupe_handles_minor_asr_differences_but_not_short_phrases() {
        let at = |timestamp: &str| isotime::parse_epoch_millis(timestamp).unwrap();
        let utterances = vec![
            UtteranceEvidenceRow {
                id: 10,
                at: "2026-07-01T10:00:10.000Z".into(),
                at_ms: at("2026-07-01T10:00:10.000Z"),
                speaker: "Ana".into(),
                source_type: "system".into(),
                text: "You need to submit the visa application form before Friday.".into(),
            },
            UtteranceEvidenceRow {
                id: 11,
                at: "2026-07-01T10:00:10.700Z".into(),
                at_ms: at("2026-07-01T10:00:10.700Z"),
                speaker: "Me".into(),
                source_type: "mic".into(),
                text: "Please submit the visa application form by Friday.".into(),
            },
            UtteranceEvidenceRow {
                id: 12,
                at: "2026-07-01T10:00:20.000Z".into(),
                at_ms: at("2026-07-01T10:00:20.000Z"),
                speaker: "Ana".into(),
                source_type: "system".into(),
                text: "Sounds good.".into(),
            },
            UtteranceEvidenceRow {
                id: 13,
                at: "2026-07-01T10:00:20.200Z".into(),
                at_ms: at("2026-07-01T10:00:20.200Z"),
                speaker: "Me".into(),
                source_type: "mic".into(),
                text: "Sounds good!".into(),
            },
        ];

        let groups = dedupe_mirrored_utterances(&utterances);
        assert!(groups.iter().any(|group| group.ids == vec![10, 11]));
        assert!(groups.iter().any(|group| group.ids == vec![12]));
        assert!(groups.iter().any(|group| group.ids == vec![13]));
        assert_eq!(groups.len(), 3);
    }

    #[test]
    fn whole_model_input_and_rendered_candidate_allow_list_are_bounded() {
        let candidates = (0..40)
            .map(|id| UrlCandidate {
                url: format!(
                    "https://example.com/resource/{id}/{}",
                    "long-path-segment".repeat(8)
                ),
                record_type: "screenshot".into(),
                record_id: id,
            })
            .collect::<Vec<_>>();

        let (input, rendered_urls) = render_finalizer_model_input(&[], &[], &candidates, 2_000);
        let (again, again_urls) = render_finalizer_model_input(&[], &[], &candidates, 2_000);

        assert!(input.len() <= 2_000);
        assert!(input.contains("[candidate-url-boundary]"));
        assert!(!rendered_urls.is_empty());
        assert!(rendered_urls.len() < candidates.len());
        assert!(rendered_urls.iter().all(|url| input.contains(url)));
        assert!(candidates
            .iter()
            .any(|candidate| !rendered_urls.contains(&candidate.url)));
        assert_eq!(input, again);
        assert_eq!(rendered_urls, again_urls);
    }
}
