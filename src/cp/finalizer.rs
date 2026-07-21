use crate::cp::{isotime, vertex, CpState};
use crate::error::{EnclaveError, Result};
use regex::Regex;
use rusqlite::OptionalExtension;
use serde::Deserialize;
use serde_json::{json, Value};
use std::collections::HashSet;
use tracing::{info, warn};

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
    let bare_domain_regex = Regex::new(r"(?i)\b[a-zA-Z0-9-]+(?:\.[a-zA-Z0-9-]+)*\.(?:com|org|net|edu|gov|io|co|us|info|biz|me|ly|gl|ai|app|dev|sh)\b(?:/[a-zA-Z0-9-._~:/?#\[\]@!$&'()*+,;=%]*)?").unwrap();

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
2. Action items: identify specific commitments, who owns them (default to 'Me' or a participant name if known), and a stated due date ('due_at' in YYYY-MM-DD format if explicitly mentioned, or null).
3. Important links: extract links, provide a descriptive label, explain why it matters, and reference evidence.
4. STRICT LINK RULE: You must ONLY output URLs that are present in the provided list of Candidate URLs. Any URL not in that list is considered a hallucination and is banned.
5. Overview: a short 2-3 sentence summary of what occurred.";

/// Sweep all eligible episodes for a user and finalize them.
pub async fn finalize_user_episodes(state: &CpState, user_id: &str) -> Result<()> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64;

    // Four-hour extension window
    let horizon_ms = now - 4 * 60 * 60 * 1000;
    let horizon_iso = isotime::format_epoch_millis(horizon_ms);

    // Get the summarizer cursor
    let summarized_until = match state.control.summarized_until(user_id).await? {
        Some(c) => c,
        None => return Ok(()), // Summarizer hasn't run or has no cursor
    };
    let summarized_until_ms = isotime::parse_epoch_millis(&summarized_until).unwrap_or(0);

    // Fetch candidates from user content DB
    let user = user_id.to_string();
    let candidates: Vec<EpisodeRow> = state.store.with_user(&user, move |conn| {
        let mut stmt = conn.prepare(
            "SELECT id, started_at, ended_at, type, title, summary, participants, languages, action_items, model
             FROM episodes
             WHERE finalized_at IS NULL
               AND substance != 'none'
               AND ended_at < ?1"
        )?;
        let rows = stmt.query_map([&horizon_iso], |r| {
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
        // 1. Cursor check: summarized_until must be >= ended_at + 4h
        if summarized_until_ms < ended_ms + 4 * 60 * 60 * 1000 {
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
            info!(
                episode_id = ep.id,
                "episode finalization deferred: devices not settled yet"
            );
            continue;
        }

        // 3. Fetch evidence for final brief model input
        let user_cloned3 = user.clone();
        let ep_id = ep.id;
        type UtteranceEvidence = Vec<(i64, String)>;
        type ScreenshotEvidence = Vec<(i64, Option<String>, Option<String>)>;
        let (utts, scrs): (UtteranceEvidence, ScreenshotEvidence) = state
            .store
            .with_user(&user_cloned3, move |conn| {
                let mut u_stmt = conn.prepare(
                    "SELECT u.id, u.text FROM utterances u
                 JOIN episode_members m ON m.record_type = 'utterance' AND m.record_id = u.id
                 WHERE m.episode_id = ?1",
                )?;
                let utterances = u_stmt
                    .query_map([ep_id], |r| Ok((r.get(0)?, r.get(1)?)))?
                    .filter_map(|x| x.ok())
                    .collect();

                let mut s_stmt = conn.prepare(
                    "SELECT s.id, s.url, s.ocr_text FROM screenshots s
                 JOIN episode_members m ON m.record_type = 'screenshot' AND m.record_id = s.id
                 WHERE m.episode_id = ?1",
                )?;
                let screenshots = s_stmt
                    .query_map([ep_id], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?
                    .filter_map(|x| x.ok())
                    .collect();

                Ok((utterances, screenshots))
            })
            .await?;

        // 4. Extract URL candidates
        let candidates = extract_candidates(&utts, &scrs);
        let candidate_urls_set: HashSet<String> =
            candidates.iter().map(|c| c.url.clone()).collect();

        // 5. Build prompt
        let mut log_text = String::new();
        log_text.push_str("CAPTURE LOG EVIDENCE:\n");
        for (id, text) in &utts {
            log_text.push_str(&format!(
                "[utterance-evidence] ID: {} | Text: \"{}\"\n",
                id, text
            ));
        }
        for (id, url_opt, ocr_opt) in &scrs {
            log_text.push_str(&format!(
                "[screenshot-evidence] ID: {} | URL: {} | OCR: \"{}\"\n",
                id,
                url_opt.as_deref().unwrap_or("<none>"),
                ocr_opt.as_deref().unwrap_or("<none>")
            ));
        }

        log_text.push_str("\nCANDIDATE URLS ALLOWED:\n");
        for (idx, cand) in candidates.iter().enumerate() {
            log_text.push_str(&format!(
                "Candidate URL {}: {} (from {} id {})\n",
                idx + 1,
                cand.url,
                cand.record_type,
                cand.record_id
            ));
        }

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
                continue;
            }
        };

        let parsed: GeminiBriefResponse = match serde_json::from_str(&model_resp) {
            Ok(p) => p,
            Err(e) => {
                warn!(episode_id = ep.id, error = %e, "Gemini final brief response unparseable");
                continue;
            }
        };

        // 6. Validate & filter evidence references + URLs
        let utterance_ids: HashSet<i64> = utts.iter().map(|u| u.0).collect();
        let screenshot_ids: HashSet<i64> = scrs.iter().map(|s| s.0).collect();

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

            // Re-verify that finalized_at is still null
            let is_finalized: Option<String> = conn.query_row(
                "SELECT finalized_at FROM episodes WHERE id = ?1",
                [ep_id],
                |r| r.get(0)
            )
            .optional()?
            .flatten();

            if is_finalized.is_some() {
                conn.execute("ROLLBACK", [])?;
                return Err(EnclaveError::Config("episode already finalized concurrently".into()));
            }

            // Fetch current members to make sure membership hasn't changed
            let mut u_stmt = conn.prepare("SELECT record_id FROM episode_members WHERE episode_id = ?1 AND record_type = 'utterance'")?;
            let current_utts: HashSet<i64> = u_stmt.query_map([ep_id], |r| r.get(0))?.filter_map(|x| x.ok()).collect();
            let mut s_stmt = conn.prepare("SELECT record_id FROM episode_members WHERE episode_id = ?1 AND record_type = 'screenshot'")?;
            let current_scrs: HashSet<i64> = s_stmt.query_map([ep_id], |r| r.get(0))?.filter_map(|x| x.ok()).collect();

            if current_utts != utterance_ids || current_scrs != screenshot_ids {
                conn.execute("ROLLBACK", [])?;
                return Err(EnclaveError::Config("episode membership changed during finalization".into()));
            }

            // Insert final brief
            conn.execute(
                "INSERT OR REPLACE INTO episode_final_briefs (episode_id, overview, decisions, action_items, important_links, open_questions)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                rusqlite::params![ep_id, overview, decisions_json, action_items_json, important_links_json, open_questions_json]
            )?;

            // Get or default finalization version
            let version: i32 = conn.query_row(
                "SELECT COALESCE(finalization_version, 1) FROM episodes WHERE id = ?1",
                [ep_id],
                |r| r.get(0)
            )?;

            // If email delivery enabled, insert into outbox
            if email_enabled {
                conn.execute(
                    "INSERT OR REPLACE INTO episode_deliveries (episode_id, channel, delivery_version, state)
                     VALUES (?1, 'gmail', ?2, 'pending')",
                    rusqlite::params![ep_id, version]
                )?;
            }

            // Mark episode finalized
            let now_iso = isotime::format_epoch_millis(
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_millis() as i64
            );
            conn.execute(
                "UPDATE episodes SET finalized_at = ?1, updated_at = ?1 WHERE id = ?2",
                rusqlite::params![now_iso, ep_id]
            )?;

            conn.execute("COMMIT", [])?;
            Ok(())
        }).await;

        match commit_res {
            Ok(_) => {
                info!(
                    episode_id = ep.id,
                    email_enqueued = email_enabled,
                    "episode successfully finalized"
                );
                let _ = state.store.save_user(&user).await;
            }
            Err(e) => {
                warn!(episode_id = ep.id, error = %e, "failed to commit finalized episode transaction");
            }
        }
    }

    Ok(())
}
