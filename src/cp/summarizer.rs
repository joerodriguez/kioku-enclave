//! Incremental LLM episode summarizer with explicit episode membership. It runs
//! inside the enclave; the cursor lives in
//! the control DB (`users.summarized_until`) and content I/O is in-process.
//!
//! Faithful to v2: incremental window since the cursor, open-episode refs the
//! model extends, membership by innermost-containing span, significance floor,
//! window cap. **Simplification versus the legacy service:** the OCR term/name-extraction
//! heuristics (`blockScreenTerms`/`blockNameCandidates`, which needed Unicode
//! regex) are dropped — the model still receives the raw OCR excerpts, just
//! without the pre-computed `[screen-terms]`/`[likely names]` hints. Re-add with
//! a regex pass if name recall regresses.
//!
//! **Live-tail cursor semantics:** legacy behavior advanced `summarized_until`
//! to the window end even when the model
//! returned zero episodes. At the caught-up live tail that is a ratchet bug:
//! every 10-min tick fed the model ~10 min of capture (which the prompt rightly
//! refuses to fragment into an episode), got `[]` back, and *consumed the
//! content forever* — no episode was ever created after the initial backfill
//! (observed in production 06-14 → 07-05: zero new episodes). Two rules fix it:
//! (1) don't call the LLM until the tail window is at least
//! [`MIN_WINDOW_MINUTES`] long; (2) when a *tail-bounded* window yields no
//! upserts, hold the cursor so the window keeps growing and the episode can
//! form — a window that reached the 6-h cap still advances unconditionally, so
//! backfill always marches forward through sparse spans.
//!
//! The Vertex call sends text outside the TEE (documented caveat — see
//! [`super::vertex`]).

use std::collections::HashMap;
use std::sync::{Arc, OnceLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde_json::{json, Value};
use tokio::sync::Mutex;
use tracing::{info, warn};

use crate::episodes::{upsert_episodes, write_episode_embedding, EpisodeInput, MinuteBucket};
use crate::error::{EnclaveError, Result};

use super::isotime::{format_epoch_millis, parse_epoch_millis};
use super::CpState;

const LOOKBACK_DAYS: i64 = 7;
const TAIL_MINUTES: i64 = 5;
const OPEN_WINDOW_MS: i64 = 4 * 60 * 60 * 1000;
const MAX_WINDOW_HOURS: i64 = 6;
/// Don't call the LLM on a live-tail window shorter than this — a fragment
/// this small can't form an episode (the prompt forbids <10-min episodes), so
/// calling earlier only burns Vertex quota and risks consuming the content.
const MIN_WINDOW_MINUTES: i64 = 20;
const UTT_CAP: usize = 4000;
const SCR_CAP: usize = 2000;
const SIG_MIN_SUBSTANTIVE_UTT: i64 = 3;
const SIG_MIN_SCREEN_MS: i64 = 2 * 60 * 1000;
const SIG_MIN_UTT_PER_MIN: f64 = 1.0 / 5.0;
const SCHEDULER_INTERVAL_SECS: u64 = 600; // 10 min internal cron (replaces Cloud Scheduler)
const TRIGGER_COOLDOWN_MS: i64 = 3 * 60 * 1000;
const SUBSTANCE_BACKFILL_KEY: &str = "adr_0009_substance_backfill_v1";
const SUBSTANCE_BACKFILL_BATCH: usize = 50;
const VISUAL_EVIDENCE_BACKFILL_KEY: &str = "adr_0010_visual_evidence_backfill_v1";
const VISUAL_EVIDENCE_BACKFILL_BATCH: usize = 50;

/// Compute the summarization window ending bound for a run starting at
/// `new_from` with the live tail at `tail_cutoff` (both epoch ms).
///
/// Returns `None` when the window is shorter than [`MIN_WINDOW_MINUTES`]
/// (don't call the LLM, don't advance). Otherwise `Some((new_to,
/// tail_bounded))` where `tail_bounded` means the window was cut short by the
/// live tail rather than the [`MAX_WINDOW_HOURS`] cap — only tail-bounded
/// windows may hold the cursor on empty output (the ratchet fix; module docs).
fn window_bounds(new_from: i64, tail_cutoff: i64) -> Option<(i64, bool)> {
    if new_from >= tail_cutoff - MIN_WINDOW_MINUTES * 60 * 1000 {
        return None;
    }
    let cap = MAX_WINDOW_HOURS * 60 * 60 * 1000;
    let new_to = tail_cutoff.min(new_from + cap);
    Some((new_to, new_to == tail_cutoff && new_to - new_from < cap))
}

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

fn ms(ts: &str) -> i64 {
    parse_epoch_millis(ts).unwrap_or(0)
}

#[derive(Clone)]
struct UttRow {
    id: i64,
    started_at: String,
    speaker_label: String,
    language: Option<String>,
    text: String,
}

#[derive(Clone)]
struct ScrRow {
    id: i64,
    captured_at: String,
    active_app: Option<String>,
    window_title: Option<String>,
    ocr_text: Option<String>,
    url: Option<String>,
    is_duplicate: i64,
}

struct OpenEp {
    id: i64,
    started_at: String,
    ended_at: String,
    episode_type: Option<String>,
    title: String,
    summary: Option<String>,
    participants: Vec<String>,
    action_items: Vec<String>,
    recent_minutes: Option<String>,
    utt_count: i64,
    scr_count: i64,
}

fn fmt_time(ts: &str) -> String {
    // HH:MM:SS slice of an ISO-8601 string.
    ts.get(11..19).unwrap_or(ts).to_string()
}

/// Substantive = not empty and not a single-glyph hallucination run.
fn is_substantive(text: &str) -> bool {
    let t = text.trim();
    if t.chars().count() < 2 {
        return false;
    }
    let letters = t.chars().filter(|c| c.is_alphabetic()).count();
    if letters < 2 {
        return false;
    }
    let non_space: Vec<char> = t.chars().filter(|c| !c.is_whitespace()).collect();
    if !non_space.is_empty() {
        let mut counts: HashMap<char, usize> = HashMap::new();
        for c in &non_space {
            *counts.entry(*c).or_default() += 1;
        }
        let top = counts.values().copied().max().unwrap_or(0);
        if top as f64 / non_space.len() as f64 > 0.7 {
            return false;
        }
    }
    true
}

#[derive(Clone)]
struct CollapsedScr {
    _id: i64,
    captured_at: String,
    visible_until: Option<String>,
    active_app: Option<String>,
    window_title: Option<String>,
    ocr_text: Option<String>,
    url: Option<String>,
}

fn collapse_screenshots(screenshots: &[ScrRow]) -> Vec<CollapsedScr> {
    let mut collapsed = Vec::new();
    let mut current: Option<CollapsedScr> = None;

    for s in screenshots {
        if s.is_duplicate == 1 {
            if let Some(ref mut cur) = current {
                cur.visible_until = Some(s.captured_at.clone());
            }
        } else {
            if let Some(cur) = current.take() {
                collapsed.push(cur);
            }
            current = Some(CollapsedScr {
                _id: s.id,
                captured_at: s.captured_at.clone(),
                visible_until: None,
                active_app: s.active_app.clone(),
                window_title: s.window_title.clone(),
                ocr_text: s.ocr_text.clone(),
                url: s.url.clone(),
            });
        }
    }
    if let Some(cur) = current {
        collapsed.push(cur);
    }
    collapsed
}

/// Chronological text block for the prompt (utterances + screenshot lines).
fn render_capture_text(utterances: &[UttRow], screenshots: &[ScrRow]) -> String {
    enum Ev<'a> {
        Utt(&'a UttRow),
        Scr(CollapsedScr),
    }
    let collapsed_scrs = collapse_screenshots(screenshots);
    let mut events: Vec<(i64, Ev)> = Vec::new();
    for u in utterances {
        events.push((ms(&u.started_at), Ev::Utt(u)));
    }
    for s in collapsed_scrs {
        events.push((ms(&s.captured_at), Ev::Scr(s)));
    }
    events.sort_by_key(|(t, _)| *t);

    let mut ocr_budget: i64 = 30_000;
    let mut lines = Vec::new();
    for (_, ev) in events {
        match ev {
            Ev::Utt(r) => {
                let label = match &r.language {
                    Some(l) if !l.is_empty() => format!("{}|{}", r.speaker_label, l),
                    _ => r.speaker_label.clone(),
                };
                lines.push(format!(
                    "{} [{}] {}",
                    fmt_time(&r.started_at),
                    label,
                    r.text
                ));
            }
            Ev::Scr(s) => {
                let app = s.active_app.clone().unwrap_or_default();
                let title = s
                    .window_title
                    .as_ref()
                    .filter(|t| !t.is_empty())
                    .map(|t| format!(" — {t}"))
                    .unwrap_or_default();
                let url = s
                    .url
                    .as_ref()
                    // URLs are already bounded by the sync contract. Keep the
                    // literal value: truncating here can turn a useful resource
                    // into a different-looking, unusable path in the summary.
                    .map(|u| format!(" <{u}>"))
                    .unwrap_or_default();

                let time_str = if let Some(until) = &s.visible_until {
                    format!("{} - {}", fmt_time(&s.captured_at), fmt_time(until))
                } else {
                    fmt_time(&s.captured_at)
                };

                lines.push(format!("{} [screen] {}{}{}", time_str, app, title, url));
                if let Some(ocr) = &s.ocr_text {
                    if ocr_budget > 0 {
                        let collapsed: String =
                            ocr.split_whitespace().collect::<Vec<_>>().join(" ");
                        let excerpt: String = collapsed
                            .chars()
                            .take(250.min(ocr_budget as usize))
                            .collect();
                        if !excerpt.is_empty() {
                            ocr_budget -= excerpt.len() as i64;
                            lines.push(format!("         [screen-text] {excerpt}"));
                        }
                    }
                }
            }
        }
    }
    lines.join("\n")
}

/// Extract the first JSON object (Gemini JSON mode usually returns it bare).
fn extract_json(text: &str) -> Option<Value> {
    if let Ok(v) = serde_json::from_str::<Value>(text) {
        return Some(v);
    }
    let start = text.find('{')?;
    let bytes = text.as_bytes();
    let (mut depth, mut in_str, mut esc) = (0i32, false, false);
    for i in start..bytes.len() {
        let ch = bytes[i] as char;
        if esc {
            esc = false;
            continue;
        }
        match ch {
            '\\' if in_str => esc = true,
            '"' => in_str = !in_str,
            '{' if !in_str => depth += 1,
            '}' if !in_str => {
                depth -= 1;
                if depth == 0 {
                    return serde_json::from_str(&text[start..=i]).ok();
                }
            }
            _ => {}
        }
    }
    None
}

fn substance_backfill_schema() -> Value {
    json!({
        "type": "OBJECT",
        "properties": {
            "classifications": {
                "type": "ARRAY",
                "items": {
                    "type": "OBJECT",
                    "properties": {
                        "id": {"type": "INTEGER"},
                        "substance": {"type": "STRING", "enum": ["none", "low", "normal"]}
                    },
                    "required": ["id", "substance"]
                }
            }
        },
        "required": ["classifications"]
    })
}

fn visual_evidence_backfill_schema() -> Value {
    json!({
        "type": "OBJECT",
        "properties": {
            "classifications": {
                "type": "ARRAY",
                "items": {
                    "type": "OBJECT",
                    "properties": {
                        "id": {"type": "INTEGER"},
                        "visual_evidence": {"type": "STRING", "enum": ["none", "useful"]}
                    },
                    "required": ["id", "visual_evidence"]
                }
            }
        },
        "required": ["classifications"]
    })
}

/// Classify historical episodes once per encrypted user database. This is
/// best-effort at the call site: a Vertex outage must not block current-window
/// summarization. The completion marker is written only after every stored row
/// has a valid classification, so interrupted runs safely resume.
async fn run_substance_backfill(state: &CpState, user_id: &str) -> Result<()> {
    let user = user_id.to_string();
    let pending: Option<Vec<(i64, String)>> = state
        .store
        .with_user(&user, |conn| {
            let complete: Option<String> = conn
                .query_row(
                    "SELECT value FROM app_metadata WHERE key = ?1",
                    [SUBSTANCE_BACKFILL_KEY],
                    |r| r.get(0),
                )
                .ok();
            if complete.as_deref() == Some("complete") {
                return Ok(None);
            }

            let mut stmt = conn
                .prepare("SELECT id, title, summary, minutes_text FROM episodes ORDER BY id ASC")?;
            let rows = stmt
                .query_map([], |r| {
                    let id: i64 = r.get(0)?;
                    let parts = [
                        r.get::<_, Option<String>>(1)?,
                        r.get::<_, Option<String>>(2)?,
                        r.get::<_, Option<String>>(3)?,
                    ];
                    let joined = parts.into_iter().flatten().collect::<Vec<_>>().join("\n");
                    // Keep batches bounded even for unusually long OCR-derived
                    // summaries. Classification needs the gist, not full fidelity.
                    let text = joined.chars().take(6_000).collect::<String>();
                    Ok((id, text))
                })?
                .collect::<std::result::Result<Vec<_>, _>>()?;
            Ok(Some(rows))
        })
        .await?;

    let Some(rows) = pending else {
        return Ok(());
    };

    let mut distribution: HashMap<String, usize> = HashMap::new();
    for batch in rows.chunks(SUBSTANCE_BACKFILL_BATCH) {
        let input: Vec<Value> = batch
            .iter()
            .map(|(id, text)| json!({"id": id, "text": text}))
            .collect();
        let message = format!(
            "Classify every episode in this JSON array. Preserve each id exactly.\n\n{}",
            serde_json::to_string(&input)?
        );
        let response = super::vertex::generate_custom(
            &state.config,
            SUBSTANCE_BACKFILL_PROMPT,
            &message,
            substance_backfill_schema(),
            8_192,
        )
        .await?;
        let parsed = extract_json(&response).ok_or_else(|| {
            EnclaveError::Config("substance backfill response was not valid JSON".into())
        })?;
        let classifications = parsed
            .get("classifications")
            .and_then(Value::as_array)
            .ok_or_else(|| {
                EnclaveError::Config("substance backfill omitted classifications".into())
            })?;

        let expected: std::collections::HashSet<i64> = batch.iter().map(|(id, _)| *id).collect();
        let mut updates: HashMap<i64, String> = HashMap::new();
        for item in classifications {
            let Some(id) = item.get("id").and_then(Value::as_i64) else {
                continue;
            };
            if !expected.contains(&id) {
                continue;
            }
            let Some(substance) = item
                .get("substance")
                .and_then(Value::as_str)
                .and_then(crate::episodes::validate_substance)
            else {
                continue;
            };
            updates.insert(id, substance.to_string());
        }
        if updates.len() != batch.len() {
            return Err(EnclaveError::Config(format!(
                "substance backfill classified {}/{} episodes in a batch",
                updates.len(),
                batch.len()
            )));
        }

        for substance in updates.values() {
            *distribution.entry(substance.clone()).or_default() += 1;
        }
        state
            .store
            .with_user(&user, move |conn| {
                for (id, substance) in updates {
                    // Historical rows carry the migration placeholder `normal`;
                    // this one-time pass intentionally overwrites it. Normal
                    // summarizer extensions use upgrade-only merge instead.
                    conn.execute(
                        "UPDATE episodes SET substance = ?2 WHERE id = ?1",
                        rusqlite::params![id, substance],
                    )?;
                }
                Ok(())
            })
            .await?;
    }

    state
        .store
        .with_user(&user, |conn| {
            conn.execute(
                "INSERT INTO app_metadata (key, value) VALUES (?1, 'complete') \
                 ON CONFLICT(key) DO UPDATE SET value='complete', \
                 updated_at=strftime('%Y-%m-%dT%H:%M:%fZ','now')",
                [SUBSTANCE_BACKFILL_KEY],
            )?;
            Ok(())
        })
        .await?;
    state.store.save_user(&user).await?;
    info!(
        user_id,
        episodes = rows.len(),
        none = distribution.get("none").copied().unwrap_or(0),
        low = distribution.get("low").copied().unwrap_or(0),
        normal = distribution.get("normal").copied().unwrap_or(0),
        "episode substance backfill complete"
    );
    Ok(())
}

/// Repair the historical `visual_evidence='none'` placeholder left by builds
/// whose Gemini response schema did not expose the field. Classification uses
/// only already-synced episode text and member screenshot metadata/OCR; image
/// bytes are never loaded or sent. The per-user marker makes the pass one-shot,
/// while the completion-after-validation rule makes an interrupted run retryable.
async fn run_visual_evidence_backfill(state: &CpState, user_id: &str) -> Result<()> {
    let user = user_id.to_string();
    let pending: Option<Vec<(i64, String)>> = state
        .store
        .with_user(&user, |conn| {
            let complete: Option<String> = conn
                .query_row(
                    "SELECT value FROM app_metadata WHERE key = ?1",
                    [VISUAL_EVIDENCE_BACKFILL_KEY],
                    |r| r.get(0),
                )
                .ok();
            if complete.as_deref() == Some("complete") {
                return Ok(None);
            }

            // Only normal episodes can be selected for cloud screenshot
            // evidence, and rows already marked useful need no repair. Keep
            // the episode query separate from the member query so each
            // prepared statement has a simple, deterministic lifetime.
            let episodes: Vec<(i64, String)> = {
                let mut stmt = conn.prepare(
                    "SELECT e.id, e.title, e.summary, e.minutes_text, e.action_items \
                     FROM episodes e \
                     WHERE e.substance = 'normal' AND e.visual_evidence = 'none' \
                       AND EXISTS (SELECT 1 FROM episode_members m \
                                   WHERE m.episode_id = e.id \
                                     AND m.record_type = 'screenshot') \
                     ORDER BY e.id ASC",
                )?;
                let rows = stmt
                    .query_map([], |r| {
                        let id: i64 = r.get(0)?;
                        let parts = [
                            r.get::<_, Option<String>>(1)?,
                            r.get::<_, Option<String>>(2)?,
                            r.get::<_, Option<String>>(3)?,
                            r.get::<_, Option<String>>(4)?,
                        ];
                        Ok((
                            id,
                            parts.into_iter().flatten().collect::<Vec<_>>().join("\n"),
                        ))
                    })?
                    .collect::<std::result::Result<Vec<_>, _>>()?;
                rows
            };

            let mut screens = conn.prepare(
                "SELECT s.captured_at, s.active_app, s.window_title, s.url, \
                        substr(s.ocr_text, 1, 500) \
                 FROM episode_members m \
                 JOIN screenshots s ON s.id = m.record_id \
                 WHERE m.episode_id = ?1 AND m.record_type = 'screenshot' \
                   AND s.is_duplicate = 0 \
                 ORDER BY s.captured_at ASC LIMIT 120",
            )?;
            let mut rows = Vec::with_capacity(episodes.len());
            for (id, episode_text) in episodes {
                let screen_lines: Vec<String> = screens
                    .query_map([id], |r| {
                        let captured_at: String = r.get(0)?;
                        let app: Option<String> = r.get(1)?;
                        let title: Option<String> = r.get(2)?;
                        let url: Option<String> = r.get(3)?;
                        let ocr: Option<String> = r.get(4)?;
                        Ok(format!(
                            "{captured_at} | app={} | title={} | url={} | text={}",
                            app.as_deref().unwrap_or(""),
                            title.as_deref().unwrap_or(""),
                            url.as_deref().unwrap_or(""),
                            ocr.as_deref().unwrap_or("")
                        ))
                    })?
                    .collect::<std::result::Result<Vec<_>, _>>()?;
                if screen_lines.is_empty() {
                    continue;
                }
                let episode_excerpt = episode_text.chars().take(6_000).collect::<String>();
                let screen_excerpt = screen_lines
                    .join("\n")
                    .chars()
                    .take(10_000)
                    .collect::<String>();
                let evidence = format!(
                    "EPISODE TEXT:\n{episode_excerpt}\n\nSCREEN METADATA (TEXT ONLY; NO PIXELS):\n{screen_excerpt}"
                );
                rows.push((id, evidence));
            }
            Ok(Some(rows))
        })
        .await?;

    let Some(rows) = pending else {
        return Ok(());
    };

    let mut distribution: HashMap<String, usize> = HashMap::new();
    for batch in rows.chunks(VISUAL_EVIDENCE_BACKFILL_BATCH) {
        let input: Vec<Value> = batch
            .iter()
            .map(|(id, evidence)| json!({"id": id, "evidence": evidence}))
            .collect();
        let message = format!(
            "Classify every episode in this JSON array. Preserve each id exactly.\n\n{}",
            serde_json::to_string(&input)?
        );
        let response = super::vertex::generate_custom(
            &state.config,
            VISUAL_EVIDENCE_BACKFILL_PROMPT,
            &message,
            visual_evidence_backfill_schema(),
            8_192,
        )
        .await?;
        let parsed = extract_json(&response).ok_or_else(|| {
            EnclaveError::Config("visual evidence backfill response was not valid JSON".into())
        })?;
        let classifications = parsed
            .get("classifications")
            .and_then(Value::as_array)
            .ok_or_else(|| {
                EnclaveError::Config("visual evidence backfill omitted classifications".into())
            })?;

        let expected: std::collections::HashSet<i64> = batch.iter().map(|(id, _)| *id).collect();
        let mut updates: HashMap<i64, String> = HashMap::new();
        for item in classifications {
            let Some(id) = item.get("id").and_then(Value::as_i64) else {
                continue;
            };
            if !expected.contains(&id) {
                continue;
            }
            let Some(visual_evidence) = item
                .get("visual_evidence")
                .and_then(Value::as_str)
                .and_then(crate::episodes::validate_visual_evidence)
            else {
                continue;
            };
            updates.insert(id, visual_evidence.to_string());
        }
        if updates.len() != batch.len() {
            return Err(EnclaveError::Config(format!(
                "visual evidence backfill classified {}/{} episodes in a batch",
                updates.len(),
                batch.len()
            )));
        }

        for visual_evidence in updates.values() {
            *distribution.entry(visual_evidence.clone()).or_default() += 1;
        }
        state
            .store
            .with_user(&user, move |conn| {
                for (id, visual_evidence) in updates {
                    conn.execute(
                        "UPDATE episodes SET visual_evidence = ?2 WHERE id = ?1",
                        rusqlite::params![id, visual_evidence],
                    )?;
                }
                Ok(())
            })
            .await?;
    }

    state
        .store
        .with_user(&user, |conn| {
            conn.execute(
                "INSERT INTO app_metadata (key, value) VALUES (?1, 'complete') \
                 ON CONFLICT(key) DO UPDATE SET value='complete', \
                 updated_at=strftime('%Y-%m-%dT%H:%M:%fZ','now')",
                [VISUAL_EVIDENCE_BACKFILL_KEY],
            )?;
            Ok(())
        })
        .await?;
    state.store.save_user(&user).await?;
    info!(
        user_id,
        episodes = rows.len(),
        none = distribution.get("none").copied().unwrap_or(0),
        useful = distribution.get("useful").copied().unwrap_or(0),
        "episode visual evidence backfill complete"
    );
    Ok(())
}

/// Membership by innermost-containing span. Returns, per episode index, the
/// member utterance ids and screenshot ids.
fn derive_membership(
    utterances: &[UttRow],
    screenshots: &[ScrRow],
    spans: &[(i64, i64)], // (started_ms, ended_ms) per episode
) -> Vec<(Vec<i64>, Vec<i64>)> {
    let mut out: Vec<(Vec<i64>, Vec<i64>)> =
        spans.iter().map(|_| (Vec::new(), Vec::new())).collect();
    let assign = |t: i64| -> Option<usize> {
        let mut best: Option<usize> = None;
        let mut best_span = i64::MAX;
        for (i, (s, e)) in spans.iter().enumerate() {
            if t < *s || t > *e {
                continue;
            }
            let span = e - s;
            if span < best_span {
                best_span = span;
                best = Some(i);
            }
        }
        best
    };
    for u in utterances {
        if let Some(i) = assign(ms(&u.started_at)) {
            out[i].0.push(u.id);
        }
    }
    for s in screenshots {
        if let Some(i) = assign(ms(&s.captured_at)) {
            out[i].1.push(s.id);
        }
    }
    out
}

/// Summarize one user's recent capture into episodes. Returns a short status.
pub async fn summarize_user(state: &CpState, user_id: &str) -> Result<Value> {
    // Serialize runs: the scheduler's catch-up loop and the list_episodes
    // freshness trigger can fire concurrently for the same user, and two
    // racing runs would summarize the same window and double-create episodes
    // (the cursor is only re-read here, under the lock). Global rather than
    // per-user is fine at current scale — runs are deliberately sequential
    // anyway to avoid Vertex rate-limit storms.
    static SUMMARIZE_LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    let _guard = SUMMARIZE_LOCK.get_or_init(|| Mutex::new(())).lock().await;

    if let Err(e) = run_substance_backfill(state, user_id).await {
        // Backfill is corrective and retryable; current capture must continue
        // to summarize even when its separate short Vertex call fails.
        warn!(user_id, error = %e, "episode substance backfill deferred");
    }
    if let Err(e) = run_visual_evidence_backfill(state, user_id).await {
        // Historical screenshot eligibility is also corrective and retryable;
        // never let it block current-window summarization.
        warn!(user_id, error = %e, "episode visual evidence backfill deferred");
    }

    let summarized_until = state.control.summarized_until(user_id).await?;
    let now = now_ms();
    let tail_cutoff = now - TAIL_MINUTES * 60 * 1000;
    let max_lookback = now - LOOKBACK_DAYS * 24 * 60 * 60 * 1000;

    let new_from = match &summarized_until {
        Some(c) => ms(c).max(max_lookback),
        None => max_lookback,
    };
    let Some(win) = window_bounds(new_from, tail_cutoff) else {
        // Live tail too short to possibly hold an episode — wait for it to
        // grow (see module docs). Cursor is NOT advanced.
        return Ok(serde_json::json!({ "skipped": true }));
    };
    let (new_to, tail_bounded) = win;
    let new_from_iso = format_epoch_millis(new_from);
    let new_to_iso = format_epoch_millis(new_to);

    // Fetch range records (with ids) from the user's index.
    let (utterances, screenshots) = fetch_range(state, user_id, &new_from_iso, &new_to_iso).await?;

    if utterances.is_empty() && screenshots.is_empty() {
        state
            .control
            .set_summarized_until(user_id, &new_to_iso)
            .await?;
        return Ok(serde_json::json!({ "skipped": true, "reason": "no_new_records" }));
    }

    let last_utt = utterances.last().map(|u| ms(&u.started_at));
    let last_scr = screenshots.last().map(|s| ms(&s.captured_at));
    let effective_cutoff = [last_utt, last_scr]
        .into_iter()
        .flatten()
        .max()
        .unwrap_or(new_from);
    if effective_cutoff <= new_from {
        state
            .control
            .set_summarized_until(user_id, &new_to_iso)
            .await?;
        return Ok(serde_json::json!({ "skipped": true, "reason": "no_new_records" }));
    }

    // Open episodes (digests the model can extend by ref).
    let open_cutoff = new_from - OPEN_WINDOW_MS;
    let list_start = format_epoch_millis(new_from - OPEN_WINDOW_MS - 4 * 60 * 60 * 1000);
    let open_episodes =
        fetch_open_episodes(state, user_id, &list_start, &new_to_iso, open_cutoff).await?;

    let capture_text = render_capture_text(&utterances, &screenshots);
    let open_text = render_open_episodes(&open_episodes);

    let range_from = utterances
        .first()
        .map(|u| u.started_at.clone())
        .unwrap_or_else(|| screenshots[0].captured_at.clone());
    let range_to = format_epoch_millis(effective_cutoff);

    let user_message = format!(
        "Range: {range_from} → {range_to}\n\n{}NEW CAPTURE LOG:\n{capture_text}",
        if open_text.is_empty() {
            String::new()
        } else {
            format!(
                "OPEN EPISODES (extend by ref when the new log continues one):\n{open_text}\n\n"
            )
        }
    );

    // Call Vertex. Failed windows return an `error` status carrying
    // `window_to` so the sweep can skip past a window that fails
    // deterministically (see summarize_all) instead of stalling forever.
    let system_prompt = format!("{SYSTEM_PROMPT}\n\n{WORKFLOW_CONTINUITY_RULE}");
    let response = match super::vertex::generate(&state.config, &system_prompt, &user_message).await
    {
        Ok(t) => t,
        Err(e) if e.to_string().contains("quota") => {
            return Ok(serde_json::json!({ "skipped": true, "reason": "quota" }));
        }
        Err(e) => {
            warn!(error = %e, "summarizer LLM call failed");
            return Ok(serde_json::json!({ "error": e.to_string(), "window_to": new_to_iso }));
        }
    };
    let Some(parsed) = extract_json(&response) else {
        // Length only — the response paraphrases user content, never log it.
        warn!(
            response_len = response.len(),
            "summarizer LLM response unparseable"
        );
        return Ok(
            serde_json::json!({ "error": "unparseable LLM response", "window_to": new_to_iso }),
        );
    };
    let episodes_json = parsed
        .get("episodes")
        .and_then(|e| e.as_array())
        .cloned()
        .unwrap_or_default();

    // Resolve refs, merge spans, build spans list for membership.
    struct Ep {
        existing_id: Option<i64>,
        started: i64,
        ended: i64,
        type_: Option<String>,
        title: String,
        summary: Option<String>,
        participants: Option<Vec<String>>,
        languages: Option<Vec<String>>,
        action_items: Option<Vec<String>>,
        substance: Option<String>,
        visual_evidence: Option<String>,
        minutes: Option<Vec<MinuteBucket>>,
    }
    let str_arr = |v: Option<&Value>| -> Option<Vec<String>> {
        v.and_then(|x| x.as_array()).map(|a| {
            a.iter()
                .filter_map(|s| s.as_str().map(String::from))
                .collect()
        })
    };
    let mut eps: Vec<Ep> = Vec::new();
    for e in &episodes_json {
        let (Some(started), Some(ended), Some(title)) = (
            e.get("started_at").and_then(|v| v.as_str()),
            e.get("ended_at").and_then(|v| v.as_str()),
            e.get("title").and_then(|v| v.as_str()),
        ) else {
            continue;
        };
        let (mut s_ms, mut e_ms) = (ms(started), ms(ended));
        let mut existing_id = None;
        if let Some(r) = e.get("episode_ref").and_then(|v| v.as_str()) {
            if let Some(open) = open_episodes.get(parse_ref(r)) {
                existing_id = Some(open.id);
                s_ms = s_ms.min(ms(&open.started_at));
                e_ms = e_ms.max(ms(&open.ended_at));
            }
        }
        // Minute-timeline gists for THIS window (ADR-0004). On extension these
        // cover only the new minutes; the upsert merges them into the stored
        // buckets (§G.1).
        let minutes = e.get("minutes").and_then(|v| v.as_array()).map(|arr| {
            arr.iter()
                .filter_map(|m| {
                    Some(MinuteBucket {
                        start: m.get("start")?.as_str()?.to_string(),
                        gist: m.get("gist")?.as_str()?.to_string(),
                    })
                })
                .collect::<Vec<_>>()
        });
        let substance = e
            .get("substance")
            .and_then(|v| v.as_str())
            .map(String::from);
        let visual_evidence = e
            .get("visual_evidence")
            .and_then(|v| v.as_str())
            .map(String::from);

        eps.push(Ep {
            existing_id,
            started: s_ms,
            ended: e_ms,
            type_: e.get("type").and_then(|v| v.as_str()).map(String::from),
            title: title.to_string(),
            summary: e.get("summary").and_then(|v| v.as_str()).map(String::from),
            participants: str_arr(e.get("participants")),
            languages: str_arr(e.get("languages")),
            action_items: str_arr(e.get("action_items")),
            substance,
            visual_evidence,
            minutes,
        });
    }

    let spans: Vec<(i64, i64)> = eps.iter().map(|e| (e.started, e.ended)).collect();
    let membership = derive_membership(&utterances, &screenshots, &spans);
    let utt_by_id: HashMap<i64, &UttRow> = utterances.iter().map(|u| (u.id, u)).collect();

    // Significance floor (new episodes only) + build upsert payload.
    let mut to_upsert: Vec<EpisodeInput> = Vec::new();
    let mut dropped = 0;
    for (i, ep) in eps.iter().enumerate() {
        let (utt_ids, scr_ids) = &membership[i];
        if ep.existing_id.is_none() {
            let substantive = utt_ids
                .iter()
                .filter(|id| utt_by_id.get(id).is_some_and(|u| is_substantive(&u.text)))
                .count() as i64;
            let scr_times: Vec<i64> = scr_ids
                .iter()
                .filter_map(|id| screenshots.iter().find(|s| s.id == *id))
                .map(|s| ms(&s.captured_at))
                .collect();
            let screen_span = match (scr_times.iter().min(), scr_times.iter().max()) {
                (Some(a), Some(b)) => b - a,
                _ => 0,
            };
            let span_min = (((ep.ended - ep.started) as f64) / 60000.0).max(1.0);
            let dense = substantive >= SIG_MIN_SUBSTANTIVE_UTT
                && (substantive as f64) >= span_min * SIG_MIN_UTT_PER_MIN;
            if !(dense || screen_span >= SIG_MIN_SCREEN_MS) {
                dropped += 1;
                continue;
            }
        }
        to_upsert.push(EpisodeInput {
            id: ep.existing_id,
            started_at: format_epoch_millis(ep.started),
            ended_at: format_epoch_millis(ep.ended),
            episode_type: ep.type_.clone(),
            title: ep.title.clone(),
            summary: ep.summary.clone(),
            participants: ep.participants.clone(),
            languages: ep.languages.clone(),
            action_items: ep.action_items.clone(),
            substance: ep.substance.clone(),
            visual_evidence: ep.visual_evidence.clone(),
            minute_summaries: ep.minutes.clone(),
            model: Some(state.config.vertex_model.clone()),
            member_utterance_ids: utt_ids.clone(),
            member_screenshot_ids: scr_ids.clone(),
        });
    }

    let mut upserted = 0;
    if !to_upsert.is_empty() {
        let user = user_id.to_string();
        let ids = state
            .store
            .with_user(&user, move |conn| upsert_episodes(conn, &to_upsert))
            .await?;
        upserted = ids.len();
        // §G.2: embed the upserted episodes in-enclave BEFORE the save so the
        // vectors persist in the same GCS write.
        embed_episodes(state, &user, &ids).await;
        state.store.save_user(&user).await?;
    }

    // Nothing upserted from a tail-bounded window: HOLD the cursor so the tail
    // keeps growing until an episode can form (the ratchet fix — see module
    // docs). Once the window hits the 6-h cap it stops being tail-bounded and
    // the else-branch advances past genuinely insignificant content.
    if upserted == 0 && tail_bounded {
        info!(
            user_id,
            dropped, "summarized nothing; holding cursor for tail to grow"
        );
        return Ok(serde_json::json!({ "waiting": true, "dropped": dropped }));
    }

    let cutoff_iso = format_epoch_millis(effective_cutoff);
    state
        .control
        .set_summarized_until(user_id, &cutoff_iso)
        .await?;
    info!(user_id, upserted, dropped, "summarized");
    Ok(serde_json::json!({ "episodes": upserted, "dropped": dropped, "to": cutoff_iso }))
}

/// In-enclave episode embeddings (ADR-0004 §G.2). Episodes are born in the
/// enclave — the Mac never sees them — so their vectors are computed HERE
/// with the in-TEE candle encoder, in the same pinned `MODEL_ID` space as the
/// Mac-computed document vectors (mixing spaces silently corrupts KNN). Cost
/// is bounded: one embed per upserted episode per summarizer window.
///
/// Text is read back from the stored rows (title + exec summary + minute
/// gists) so extensions embed the full §G.1-merged timeline, not just the new
/// window. Best-effort: an absent engine or a failed embed leaves the episode
/// FTS-only — it never fails the summarizer run.
async fn embed_episodes(state: &CpState, user_id: &str, ids: &[i64]) {
    let Some(engine) = state.embedding.as_ref().cloned() else {
        return;
    };

    let id_list = ids.to_vec();
    let rows: Vec<(i64, String)> = match state
        .store
        .with_user(user_id, move |conn| {
            let mut out = Vec::new();
            for id in id_list {
                let row: Option<(Option<String>, Option<String>, Option<String>)> = conn
                    .query_row(
                        "SELECT title, summary, minutes_text FROM episodes WHERE id = ?1",
                        [id],
                        |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
                    )
                    .ok();
                if let Some((title, summary, minutes)) = row {
                    let text = [title, summary, minutes]
                        .into_iter()
                        .flatten()
                        .collect::<Vec<_>>()
                        .join("\n");
                    if !text.trim().is_empty() {
                        out.push((id, text));
                    }
                }
            }
            Ok(out)
        })
        .await
    {
        Ok(r) => r,
        Err(e) => {
            warn!(error = %e, "episode embed: read-back failed");
            return;
        }
    };

    // CPU-bound inference (~10–50 ms each) — blocking pool, not the async worker.
    let mut vectors: Vec<(i64, Vec<f32>)> = Vec::new();
    for (id, text) in rows {
        let eng = engine.clone();
        match tokio::task::spawn_blocking(move || eng.embed(&text)).await {
            Ok(Ok(v)) => vectors.push((id, v)),
            Ok(Err(e)) => {
                warn!(
                    episode_id = id,
                    "episode embed failed ({e}) — FTS-only for this episode"
                );
            }
            Err(e) => warn!(episode_id = id, "episode embed task panicked ({e})"),
        }
    }
    if vectors.is_empty() {
        return;
    }
    if let Err(e) = state
        .store
        .with_user(user_id, move |conn| {
            for (id, v) in &vectors {
                write_episode_embedding(conn, *id, v)?;
            }
            Ok(())
        })
        .await
    {
        warn!(error = %e, "episode embed: vector write failed");
    }
}

fn parse_ref(r: &str) -> usize {
    r.trim()
        .trim_start_matches('E')
        .parse()
        .unwrap_or(usize::MAX)
}

fn render_open_episodes(open: &[OpenEp]) -> String {
    open.iter()
        .enumerate()
        .map(|(i, ep)| {
            // The extend-vs-new decision needs the prior episode's objective,
            // not just a short title. Multi-hop workflows can cross calls,
            // apps, and participants while remaining one activity. Keep this
            // bounded because up to 30 open episodes share the prompt.
            let summary = compact_excerpt(ep.summary.as_deref().unwrap_or(""), 600);
            let recent = compact_tail_excerpt(ep.recent_minutes.as_deref().unwrap_or(""), 300);
            let participants = if ep.participants.is_empty() {
                "unknown".to_string()
            } else {
                ep.participants.join(", ")
            };
            let actions = if ep.action_items.is_empty() {
                "none".to_string()
            } else {
                compact_excerpt(&ep.action_items.join("; "), 600)
            };
            format!(
                "[E{i}] type={} \"{}\" ({} → {}, {} utt/{} scr)\n  participants: {}\n  objective/summary: {}\n  current actions/requirements: {}\n  recent timeline: {}",
                ep.episode_type.as_deref().unwrap_or("other"),
                ep.title,
                ep.started_at,
                ep.ended_at,
                ep.utt_count,
                ep.scr_count,
                participants,
                if summary.is_empty() { "unavailable" } else { &summary },
                actions,
                if recent.is_empty() { "unavailable" } else { &recent },
            )
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn compact_excerpt(text: &str, max_chars: usize) -> String {
    text.split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .chars()
        .take(max_chars)
        .collect()
}

fn compact_tail_excerpt(text: &str, max_chars: usize) -> String {
    let compact = text.split_whitespace().collect::<Vec<_>>().join(" ");
    let chars: Vec<char> = compact.chars().collect();
    chars[chars.len().saturating_sub(max_chars)..]
        .iter()
        .collect()
}

async fn fetch_range(
    state: &CpState,
    user_id: &str,
    from: &str,
    to: &str,
) -> Result<(Vec<UttRow>, Vec<ScrRow>)> {
    let (f, t) = (from.to_string(), to.to_string());
    state
        .store
        .with_user(user_id, move |conn| {
            let mut us = conn.prepare(
                "SELECT u.id, s.started_at, u.speaker_label, u.language, u.text \
                 FROM utterances u JOIN audio_segments s ON s.id = u.audio_segment_id \
                 WHERE s.started_at >= ?1 AND s.started_at < ?2 \
                 ORDER BY s.started_at ASC LIMIT ?3",
            )?;
            let utterances: Vec<UttRow> = us
                .query_map(rusqlite::params![f, t, UTT_CAP as i64], |r| {
                    Ok(UttRow {
                        id: r.get(0)?,
                        started_at: r.get(1)?,
                        speaker_label: r.get(2)?,
                        language: r.get(3)?,
                        text: r.get(4)?,
                    })
                })?
                .filter_map(|x| x.ok())
                .collect();
            let mut ss = conn.prepare(
                "SELECT id, captured_at, active_app, window_title, substr(ocr_text,1,4000), url, is_duplicate \
                 FROM screenshots WHERE captured_at >= ?1 AND captured_at < ?2 \
                 ORDER BY captured_at ASC LIMIT ?3",
            )?;
            let screenshots: Vec<ScrRow> = ss
                .query_map(rusqlite::params![f, t, SCR_CAP as i64], |r| {
                    Ok(ScrRow {
                        id: r.get(0)?,
                        captured_at: r.get(1)?,
                        active_app: r.get(2)?,
                        window_title: r.get(3)?,
                        ocr_text: r.get(4)?,
                        url: r.get(5)?,
                        is_duplicate: r.get(6)?,
                    })
                })?
                .filter_map(|x| x.ok())
                .collect();
            Ok((utterances, screenshots))
        })
        .await
}

async fn fetch_open_episodes(
    state: &CpState,
    user_id: &str,
    list_start: &str,
    list_end: &str,
    open_cutoff_ms: i64,
) -> Result<Vec<OpenEp>> {
    let (ls, le) = (list_start.to_string(), list_end.to_string());
    let mut eps = state
        .store
        .with_user(user_id, move |conn| {
            let mut stmt = conn.prepare(
                "SELECT e.id, e.started_at, e.ended_at, e.type, e.title, e.summary, \
                        e.participants, e.action_items, e.minutes_text, \
                        (SELECT count(*) FROM episode_members m WHERE m.episode_id=e.id AND m.record_type='utterance'), \
                        (SELECT count(*) FROM episode_members m WHERE m.episode_id=e.id AND m.record_type='screenshot') \
                 FROM episodes e WHERE e.ended_at >= ?1 AND e.started_at <= ?2 \
                 ORDER BY e.ended_at ASC LIMIT 100",
            )?;
            let rows: Vec<OpenEp> = stmt
                .query_map(rusqlite::params![ls, le], |r| {
                    let participants_json: Option<String> = r.get(6)?;
                    let participants = participants_json
                        .as_deref()
                        .and_then(|raw| serde_json::from_str::<Vec<String>>(raw).ok())
                        .unwrap_or_default();
                    let action_items_json: Option<String> = r.get(7)?;
                    let action_items = action_items_json
                        .as_deref()
                        .and_then(|raw| serde_json::from_str::<Vec<String>>(raw).ok())
                        .unwrap_or_default();
                    Ok(OpenEp {
                        id: r.get(0)?,
                        started_at: r.get(1)?,
                        ended_at: r.get(2)?,
                        episode_type: r.get(3)?,
                        title: r.get::<_, Option<String>>(4)?.unwrap_or_else(|| "untitled".into()),
                        summary: r.get(5)?,
                        participants,
                        action_items,
                        recent_minutes: r.get(8)?,
                        utt_count: r.get(9)?,
                        scr_count: r.get(10)?,
                    })
                })?
                .filter_map(|x| x.ok())
                .collect();
            Ok(rows)
        })
        .await?;
    // Keep only those still "open" (ended within the window), newest 30.
    eps.retain(|e| ms(&e.ended_at) >= open_cutoff_ms);
    let n = eps.len();
    if n > 30 {
        eps.drain(0..n - 30);
    }
    Ok(eps)
}

/// Sweep all users (internal cron). Sequential to avoid Vertex rate-limit storms.
///
/// Per user, keeps running windows while the cursor is making forward progress
/// (bounded) so a cold-start backfill — up to 7 d ÷ 6 h = 28 windows — catches
/// up within one tick instead of one window per 10-min tick (~5 h).
pub async fn summarize_all(state: &CpState) {
    const MAX_WINDOWS_PER_SWEEP: u32 = 32;
    let ids = match state.control.all_user_ids().await {
        Ok(ids) => ids,
        Err(e) => {
            warn!(error = %e, "summarize_all: list users failed");
            return;
        }
    };
    // (window_to, consecutive failures) per user: a window whose LLM response
    // fails deterministically (e.g. unparseable every attempt) would otherwise
    // stall the cursor forever — observed live 2026-07-05 (backfill froze
    // silently after 3 windows). After MAX_WINDOW_FAILURES consecutive
    // failures on the SAME window, skip past it (losing that one window's
    // episodes, loudly) so the sweep keeps moving.
    const MAX_WINDOW_FAILURES: u32 = 3;
    static FAILING: OnceLock<Mutex<HashMap<String, (String, u32)>>> = OnceLock::new();
    let failing = FAILING.get_or_init(|| Mutex::new(HashMap::new()));

    for id in ids {
        for _ in 0..MAX_WINDOWS_PER_SWEEP {
            match summarize_user(state, &id).await {
                // Cursor advanced (episodes emitted or empty span consumed) —
                // there may be more backlog; keep going. NOT on "quota": that
                // skip does not advance and retrying would hammer Vertex.
                Ok(v)
                    if v.get("to").is_some()
                        || v.get("reason").and_then(|r| r.as_str()) == Some("no_new_records") =>
                {
                    failing.lock().await.remove(&id);
                    // Every advanced window PUTs control.db.enc, and GCS
                    // rate-limits writes to one object to ~1/sec. Windows with
                    // records pace themselves via the LLM call, but empty
                    // (no_new_records) windows complete in ms — observed live
                    // as 429 Too Many Requests killing the sweep. Pace them.
                    tokio::time::sleep(Duration::from_millis(1200)).await;
                    continue;
                }
                // A failed window that did not advance: count consecutive
                // failures of the SAME window; skip past it once it's clearly
                // deterministic. Otherwise leave it for the next tick.
                Ok(v) if v.get("error").is_some() => {
                    let Some(window_to) = v.get("window_to").and_then(|w| w.as_str()) else {
                        break;
                    };
                    let mut guard = failing.lock().await;
                    let entry = guard
                        .entry(id.clone())
                        .or_insert((window_to.to_string(), 0));
                    if entry.0 == window_to {
                        entry.1 += 1;
                    } else {
                        *entry = (window_to.to_string(), 1);
                    }
                    if entry.1 < MAX_WINDOW_FAILURES {
                        break;
                    }
                    tracing::error!(
                        user_id = %id,
                        window_to,
                        failures = entry.1,
                        "summarizer window failing deterministically; skipping past it"
                    );
                    guard.remove(&id);
                    drop(guard);
                    if let Err(e) = state.control.set_summarized_until(&id, window_to).await {
                        warn!(user_id = %id, error = %e, "failed to skip stuck window");
                        break;
                    }
                    tokio::time::sleep(Duration::from_millis(1200)).await;
                    continue;
                }
                // Caught up ("skipped"), holding for the tail ("waiting"), or
                // quota — done with this user for now.
                Ok(_) => break,
                Err(e) => {
                    warn!(user_id = %id, error = %e, "summarize_user failed");
                    break;
                }
            }
        }

        if let Err(e) = super::finalizer::finalize_user_episodes(state, &id).await {
            warn!(user_id = %id, error = %e, "finalize_user_episodes failed");
        }
        if let Err(e) = super::email_worker::deliver_user_emails(state, &id).await {
            warn!(user_id = %id, error = %e, "deliver_user_emails failed");
        }
    }
}

/// Spawn the internal summarizer cron (replaces Cloud Scheduler). Sweeps every
/// [`SCHEDULER_INTERVAL_SECS`].
pub fn spawn_scheduler(state: Arc<CpState>) {
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_secs(SCHEDULER_INTERVAL_SECS));
        loop {
            tick.tick().await;
            summarize_all(&state).await;
        }
    });
}

/// Fire-and-forget freshness trigger from `list_episodes` (3-min cooldown).
pub fn maybe_trigger(state: Arc<CpState>, user_id: String) {
    static LAST: OnceLock<Mutex<HashMap<String, i64>>> = OnceLock::new();
    let map = LAST.get_or_init(|| Mutex::new(HashMap::new()));
    tokio::spawn(async move {
        {
            let mut guard = map.lock().await;
            let last = guard.get(&user_id).copied().unwrap_or(0);
            if now_ms() - last < TRIGGER_COOLDOWN_MS {
                return;
            }
            guard.insert(user_id.clone(), now_ms());
        }
        // Only run if stale (>10 min since cursor).
        let stale = match state.control.summarized_until(&user_id).await {
            Ok(Some(c)) => now_ms() - ms(&c) > 10 * 60 * 1000,
            Ok(None) => true,
            Err(_) => false,
        };
        if stale {
            let _ = summarize_user(&state, &user_id).await;
        }
    });
}

const SUBSTANCE_BACKFILL_PROMPT: &str = "Classify the substance of stored personal activity episodes from title, summary, and minute gists. substance=none: fragments with no coherent topic, hallucination-like repetition, or content-free filler. substance=low: real but trivial activity such as a few passing remarks or background TV. substance=normal: everything else. When in doubt, prefer the higher tier. Return one classification for every supplied id and do not invent ids.";

const VISUAL_EVIDENCE_BACKFILL_PROMPT: &str = "Classify whether stored screenshot pixels would materially improve recall or verification for each episode, using only the supplied episode text and member screenshot metadata/OCR. visual_evidence=useful when the screens contain material slides, documents, diagrams, errors, designs, settings state, on-screen instructions, resources, or decision evidence. visual_evidence=none when screens are absent, generic app chrome, duplicated state, or would add no material evidence beyond the text. Do not infer unseen pixels and do not classify an episode as useful merely because screenshots exist. Return one classification for every supplied id and do not invent ids.";

const WORKFLOW_CONTINUITY_RULE: &str = "CRITICAL EXTENSION RULE: Define continuity by the person's concrete real-world objective, subject, or workflow — not by session mechanics. Continuation does NOT require the same call connection, participant, app, or document. A goodbye followed by a new greeting, a transfer, hold time, reconnect, or a call to a different person or organization is not a boundary when the person is still pursuing the same task. For example, calling a provider, then an insurer, then the provider again about one bill is ONE episode using the same OPEN EPISODE ref. Prefer EXTEND when the open episode and new log share the same real-world goal; open a NEW episode only when the goal or subject actually changes.";

const SYSTEM_PROMPT: &str = r#"You segment a chronological personal capture log (speech transcripts + screen activity) into episodes a person would recognize as distinct activities in their day. The episode fields must also be a useful, evidence-grounded memory of what the person needs to know or do — not a topic inventory.

The log format: timestamped utterances as "HH:MM:SS [speaker|lang] text" (speaker "Me" is the device owner; "Speaker N" are diarized other voices); "[screen] App — Title <url>" lines for what was on screen; "[screen-text]" OCR excerpts.

Episode types: meeting | lesson | call | coding | browsing | break | other

You are also given OPEN EPISODES: recent episodes that may still be in progress, each with a ref like "E0". The NEW CAPTURE LOG is only the activity SINCE those were last summarized.

PRINCIPLES (in priority order):
1. EXTEND vs NEW. For each episode you output, set "episode_ref" to the "E<n>" of an OPEN EPISODE when the new log is a continuation of it — give its UPDATED ended_at and a summary covering the whole episode. Otherwise omit episode_ref (or "") to open a NEW episode. A continuous activity is exactly ONE episode. For an extension, preserve still-valid concrete takeaways and current actions/requirements from the open-episode digest while incorporating the new evidence.
2. SPEECH OUTWEIGHS SCREEN for deciding what an episode IS. Sustained back-and-forth between "Me" and other speakers means a live interaction (meeting/lesson/call) even when the visible app is a browser. Classify by dynamics: instruction/drill/correction → lesson; collaborative discussion → meeting; few-person social/logistic conversation → call. Long stretches with only "Me" speaking sporadically + screen activity → coding/browsing per the apps.
3. SIGNIFICANCE — not everything is an episode. Idle, empty, or sparse-noise spans are NOT episodes. Do NOT emit "Break"/"Idle"/"Misc" filler. A break is the silence between episodes — leave it out.
4. ATTENDEES for any episode with conversation: combine names spoken aloud, names visible on screen, and diarized labels. Map labels to names when justified ("Ana (Speaker 2)"); keep bare "Speaker N" otherwise. People search their archive BY NAME. Repeated or mirrored transcript rows are corroboration, not separate statements or takeaways.
5. Titles identify the activity, purpose, and people when known ("Spanish lesson with Ana: past tense"). Do not make a title a comma-separated sample of topics, and never use a generic title.
6. Boundaries follow the activity, not the apps. DO NOT FRAGMENT: an episode shorter than ~10 minutes is usually wrong — merge brief pauses. A short distinct activity nested in a longer one IS its own episode.
7. SUMMARY QUALITY. summary is 1–10 Markdown bullets, one per line and each beginning "- ". Every bullet must state a concrete takeaway, instruction, requirement, decision, result, constraint, or fact that helps the device owner remember or act. Prioritize, in order: (a) steps or requirements directed at the owner, (b) decisions, commitments, owners, deadlines and dates, (c) exact amounts, limits, logistics and named resources, services or URLs, (d) substantive outcomes or explanations. Omit greetings, atmosphere and promotional color before compressing any high-value detail. Never write topic-inventory prose such as "X was discussed", "information was provided/shared", "details about X", or "the conversation covered X"; state the actual detail instead. Do not pad to reach a bullet count.
8. EVIDENCE BOUNDARY. Names, spellings, dates, times, amounts, requirements, resource names and URLs must be supported literally by the capture log or open-episode digest. Preserve an observed URL exactly. Never invent or complete a domain/path, silently correct an uncertain transcription, infer a missing date/amount, or turn a mentioned resource into a URL that was not captured. If evidence is ambiguous, use the literal supported wording or omit the uncertain specific.
9. ACTION ITEMS. action_items contains only explicit commitments, requested follow-ups, or requirements/instructions directed at a person; otherwise []. A requirement addressed to "Me" belongs here even if the owner did not verbally promise it. Phrase each item as the concrete action, owner when known, and exact due date or condition when stated. Do not promote optional general information into an action.
10. started_at/ended_at: ISO 8601 within the provided range (for an extension, the FULL span). languages: BCP-47 codes actually heard.
11. MINUTE TIMELINE. minutes is a timeline of the episode's NEW activity. Bucket the NEW CAPTURE LOG into 1–5-minute buckets. Each gist is one concrete sentence naming who said/did/decided/required what when speaker identity is supported, and retaining a material date, amount, step, outcome, resource or URL when present. Never use generic filler or topic labels such as "conversation continues" or "transportation discussed". Each bucket: {"start":"<ISO of bucket start>","gist":"..."}. Cover ONLY minutes present in the NEW CAPTURE LOG — for an extension, earlier minutes are already stored; never re-emit or invent them.
12. substance: none for fragments with no coherent topic, hallucination-like repetition, or content-free filler; low for real but trivial activity (a few passing remarks, background TV); normal for everything else. When in doubt, prefer the higher tier.
13. visual_evidence: useful if visual state is material (for example a slide, document, diagram, error, design, settings state, or on-screen decision evidence); none if pixels would not materially improve verification.

Return STRICT JSON only: {"episodes":[{"episode_ref":"E0 or omit","started_at":"<ISO>","ended_at":"<ISO>","type":"<type>","title":"...","summary":"- concrete takeaway\n- concrete requirement","participants":["Me","Ana (Speaker 2)"],"languages":["fr"],"action_items":[],"substance":"normal","visual_evidence":"none","minutes":[{"start":"<ISO>","gist":"..."}]}]}"#;

#[cfg(test)]
mod tests {
    use super::*;

    const MIN: i64 = 60 * 1000;
    const HOUR: i64 = 60 * MIN;

    /// The live-tail ratchet fix (module docs): short tails wait, medium tails
    /// are tail-bounded (may hold the cursor), capped windows always advance.
    #[test]
    fn window_bounds_semantics() {
        let tail = 1_000_000 * MIN; // arbitrary "now - 5min" reference

        // Tail shorter than MIN_WINDOW: don't run at all.
        assert_eq!(window_bounds(tail - 10 * MIN, tail), None);
        assert_eq!(window_bounds(tail, tail), None, "caught up exactly");
        assert_eq!(window_bounds(tail + MIN, tail), None, "cursor past tail");

        // Tail-bounded window: ends at the tail, below the 6-h cap.
        let (to, tail_bounded) = window_bounds(tail - 30 * MIN, tail).unwrap();
        assert_eq!(to, tail);
        assert!(tail_bounded, "30-min live window may hold the cursor");

        // Window at the cap: advances unconditionally (backfill marches).
        let (to, tail_bounded) = window_bounds(tail - 26 * HOUR, tail).unwrap();
        assert_eq!(to, tail - 26 * HOUR + MAX_WINDOW_HOURS * HOUR);
        assert!(!tail_bounded, "capped window must not hold the cursor");

        // Window exactly 6 h to the tail: treated as capped (advance) so a
        // pathological always-insignificant span can't hold forever.
        let (to, tail_bounded) = window_bounds(tail - MAX_WINDOW_HOURS * HOUR, tail).unwrap();
        assert_eq!(to, tail);
        assert!(!tail_bounded);
    }

    #[test]
    fn test_collapse_screenshots() {
        let scrs = vec![
            ScrRow {
                id: 1,
                captured_at: "2026-06-01T14:00:00Z".to_string(),
                active_app: Some("Finder".to_string()),
                window_title: Some("Desktop".to_string()),
                ocr_text: Some("foo".to_string()),
                url: None,
                is_duplicate: 0,
            },
            ScrRow {
                id: 2,
                captured_at: "2026-06-01T14:00:02Z".to_string(),
                active_app: Some("Finder".to_string()),
                window_title: Some("Desktop".to_string()),
                ocr_text: Some("foo".to_string()),
                url: None,
                is_duplicate: 1,
            },
            ScrRow {
                id: 3,
                captured_at: "2026-06-01T14:00:04Z".to_string(),
                active_app: Some("Finder".to_string()),
                window_title: Some("Desktop".to_string()),
                ocr_text: Some("foo".to_string()),
                url: None,
                is_duplicate: 1,
            },
            ScrRow {
                id: 4,
                captured_at: "2026-06-01T14:00:06Z".to_string(),
                active_app: Some("Xcode".to_string()),
                window_title: Some("main.swift".to_string()),
                ocr_text: Some("bar".to_string()),
                url: None,
                is_duplicate: 0,
            },
        ];

        let collapsed = collapse_screenshots(&scrs);
        assert_eq!(collapsed.len(), 2);
        assert_eq!(collapsed[0].active_app.as_deref(), Some("Finder"));
        assert_eq!(collapsed[0].captured_at, "2026-06-01T14:00:00Z");
        assert_eq!(
            collapsed[0].visible_until.as_deref(),
            Some("2026-06-01T14:00:04Z")
        );

        assert_eq!(collapsed[1].active_app.as_deref(), Some("Xcode"));
        assert_eq!(collapsed[1].captured_at, "2026-06-01T14:00:06Z");
        assert_eq!(collapsed[1].visible_until, None);
    }

    #[test]
    fn open_episode_digest_preserves_workflow_context() {
        let rendered = render_open_episodes(&[OpenEp {
            id: 307,
            started_at: "2026-07-21T16:39:04Z".into(),
            ended_at: "2026-07-21T16:47:09Z".into(),
            episode_type: Some("call".into()),
            title: "Transportation billing inquiry".into(),
            summary: Some(
                "Discussed an outstanding transportation balance and next steps with insurance."
                    .into(),
            ),
            participants: vec!["Me".into(), "Provider representative".into()],
            action_items: vec!["Me: send the insurer's payment reference".into()],
            recent_minutes: Some("12:46 PM: insurer payment and balance billing".into()),
            utt_count: 24,
            scr_count: 80,
        }]);

        assert!(rendered.contains("[E0] type=call"));
        assert!(rendered.contains("Provider representative"));
        assert!(rendered.contains("outstanding transportation balance"));
        assert!(rendered.contains("send the insurer's payment reference"));
        assert!(rendered.contains("insurer payment and balance billing"));
    }

    #[test]
    fn prompt_keeps_multi_hop_workflows_in_one_episode() {
        assert!(WORKFLOW_CONTINUITY_RULE.contains(
            "calling a provider, then an insurer, then the provider again about one bill is ONE episode"
        ));
        assert!(WORKFLOW_CONTINUITY_RULE
            .contains("A goodbye followed by a new greeting, a transfer, hold time, reconnect"));
    }

    #[test]
    fn prompt_requires_concrete_evidence_bound_recall() {
        assert!(SYSTEM_PROMPT.contains("not a topic inventory"));
        assert!(SYSTEM_PROMPT.contains("steps or requirements directed at the owner"));
        assert!(SYSTEM_PROMPT.contains("exact amounts, limits, logistics"));
        assert!(SYSTEM_PROMPT.contains("Never write topic-inventory prose"));
        assert!(SYSTEM_PROMPT.contains("Preserve an observed URL exactly"));
        assert!(SYSTEM_PROMPT.contains("Never invent or complete a domain/path"));
        assert!(SYSTEM_PROMPT.contains("A requirement addressed to \"Me\" belongs here"));
    }

    #[test]
    fn prompt_requires_attributed_specific_minute_gists() {
        assert!(SYSTEM_PROMPT.contains(
            "naming who said/did/decided/required what when speaker identity is supported"
        ));
        assert!(SYSTEM_PROMPT.contains("retaining a material date, amount, step, outcome"));
        assert!(SYSTEM_PROMPT.contains("never re-emit or invent them"));
    }

    #[test]
    fn capture_prompt_preserves_literal_url_without_truncation() {
        let url = format!(
            "https://example.edu/{}?required=true",
            "orientation/".repeat(14)
        );
        assert!(url.len() > 120);
        let rendered = render_capture_text(
            &[],
            &[ScrRow {
                id: 7,
                captured_at: "2026-07-21T09:03:00Z".into(),
                active_app: Some("Browser".into()),
                window_title: Some("Student setup".into()),
                ocr_text: None,
                url: Some(url.clone()),
                is_duplicate: 0,
            }],
        );

        assert!(rendered.contains(&format!("<{url}>")));
    }

    #[test]
    fn historical_visual_evidence_backfill_contract_is_constrained_and_text_only() {
        let schema = visual_evidence_backfill_schema();
        let item = &schema["properties"]["classifications"]["items"];
        assert_eq!(
            item["properties"]["visual_evidence"]["enum"],
            json!(["none", "useful"])
        );
        assert!(item["required"]
            .as_array()
            .expect("required fields")
            .iter()
            .any(|field| field.as_str() == Some("visual_evidence")));
        assert!(VISUAL_EVIDENCE_BACKFILL_PROMPT.contains("metadata/OCR"));
        assert!(VISUAL_EVIDENCE_BACKFILL_PROMPT.contains("Do not infer unseen pixels"));
        assert!(VISUAL_EVIDENCE_BACKFILL_PROMPT
            .contains("do not classify an episode as useful merely because screenshots exist"));
        assert_ne!(VISUAL_EVIDENCE_BACKFILL_KEY, SUBSTANCE_BACKFILL_KEY);
    }
}
