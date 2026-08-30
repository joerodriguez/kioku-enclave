//! Incremental LLM episode summarizer with explicit episode membership. It runs
//! inside the enclave; PostgreSQL owns the durable cursor, evidence, claims,
//! episode writes, and embeddings while content I/O remains in-process.
//!
//! Faithful to v2: incremental window since the cursor, open-episode refs the
//! model extends, membership by innermost-containing span, significance floor,
//! window cap. Full screenshot OCR remains indexed, while prompts use the
//! bounded salient projection in [`crate::ocr`] plus conservative
//! `[screen-facts]` title labels, which are less likely to promote menu chrome
//! or neighboring search results than broad block-term hints.
//!
//! **Live-tail cursor semantics:** advancing `summarized_until` to the window
//! end when the model returns zero episodes creates a caught-up-tail ratchet:
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

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[cfg(test)]
use serde_json::json;
use serde_json::Value;
use tokio::sync::Mutex;
use tracing::{info, warn};

use crate::error::{EnclaveError, Result};
use crate::persistence::{
    EpisodeEmbeddingWrite, EpisodeInput, MinuteBucket, OpenEpisode as OpenEp,
    SummaryScreenshot as ScrRow, SummaryUtterance as UttRow, SummaryWindowClaim,
    SummaryWindowSettlement,
};

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
/// Session-settled runs (ADR-0034) accept any window at least this long: the
/// session is closed evidence, so the 20-minute live-tail floor above does
/// not apply, but a sub-minute window cannot survive the significance floor
/// and would only burn a call.
const SETTLED_MIN_WINDOW_MS: i64 = 60 * 1000;
const UTT_CAP: usize = 4000;
const SCR_CAP: usize = 2000;
const SIG_MIN_SUBSTANTIVE_UTT: i64 = 3;
const SIG_MIN_SCREEN_MS: i64 = 2 * 60 * 1000;
const SIG_MIN_UTT_PER_MIN: f64 = 1.0 / 5.0;
const SCHEDULER_INTERVAL_SECS: u64 = 600; // 10 min internal cron (replaces Cloud Scheduler)
/// Both an interactive finish trigger and the durable recurring backstop may
/// inherit a cursor at the seven-day lookback floor. Walk enough proven-empty
/// six-hour windows to reach the live tail in one bounded pass. The caller
/// stops at the first result that may have invoked the model, so this bound
/// never stacks multiple summarizer model calls for one user in one wakeup.
const SPARSE_LOOKBACK_MAX_WINDOWS: u32 =
    ((LOOKBACK_DAYS * 24 + MAX_WINDOW_HOURS - 1) / MAX_WINDOW_HOURS) as u32 + 1;

/// Compute the summarization window ending bound for a run starting at
/// `new_from` with the live tail at `tail_cutoff` (both epoch ms).
///
/// Returns `None` when the window is shorter than `min_window_ms`
/// (don't call the LLM, don't advance). Otherwise `Some((new_to,
/// tail_bounded))` where `tail_bounded` means the window was cut short by the
/// live tail rather than the [`MAX_WINDOW_HOURS`] cap — only tail-bounded
/// windows may hold the cursor on empty output (the ratchet fix; module docs).
fn window_bounds(new_from: i64, tail_cutoff: i64, min_window_ms: i64) -> Option<(i64, bool)> {
    if new_from >= tail_cutoff - min_window_ms {
        return None;
    }
    let cap = MAX_WINDOW_HOURS * 60 * 60 * 1000;
    let new_to = tail_cutoff.min(new_from + cap);
    Some((new_to, new_to == tail_cutoff && new_to - new_from < cap))
}

/// How a summarizer run was initiated (ADR-0034).
#[derive(Clone, Copy, PartialEq, Eq)]
enum SummarizeMode {
    /// The recurring sweep: a [`TAIL_MINUTES`] settle buffer and a
    /// [`MIN_WINDOW_MINUTES`] floor keep live-tail fragments away from the
    /// LLM (module docs).
    Scheduled,
    /// A capture session just finished and every accepted media item is
    /// processed, so the tail is complete evidence rather than a growing
    /// fragment. The window may be short and runs to now; empty output still
    /// holds the cursor (tail-bounded semantics), so an early call can never
    /// consume content — at worst it spends one bounded LLM call.
    SessionSettled,
}

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

async fn reserve_vertex_output(state: &CpState, user_id: &str, output_tokens: u32) -> Result<()> {
    let reserved = super::limits::reserve_vertex_output_tokens_for_class(
        &state.repositories,
        user_id,
        super::limits::VertexWorkClass::DerivedText,
        i64::from(output_tokens),
        state.config.quota_vertex_output_tokens_per_day,
    )
    .await?;
    if reserved {
        Ok(())
    } else {
        Err(EnclaveError::Config("vertex_daily_budget".into()))
    }
}

fn ms(ts: &str) -> i64 {
    parse_epoch_millis(ts).unwrap_or(0)
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
    salient_ocr_text: Option<String>,
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
                salient_ocr_text: s.salient_ocr_text.clone(),
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
                let salient = crate::ocr::select_salient_ocr(
                    s.ocr_text.as_deref(),
                    s.salient_ocr_text.as_deref(),
                );
                if let Some(ocr) = salient {
                    if ocr_budget > 0 {
                        let collapsed: String =
                            ocr.split_whitespace().collect::<Vec<_>>().join(" ");
                        let excerpt: String = collapsed
                            .chars()
                            .take(1_200.min(ocr_budget as usize))
                            .collect();
                        if !excerpt.is_empty() {
                            ocr_budget -= excerpt.len() as i64;
                            lines.push(format!("         [screen-text] {excerpt}"));
                        }
                    }
                    let facts = crate::ocr::extract_screen_facts(&ocr);
                    if !facts.is_empty() {
                        lines.push(format!(
                            "         [screen-facts] {}",
                            facts
                                .iter()
                                .map(|fact| format!("{fact:?}"))
                                .collect::<Vec<_>>()
                                .join(", ")
                        ));
                    }
                }
            }
        }
    }
    lines.join("\n")
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct GroundingRequirement {
    at_ms: i64,
    entities: Vec<String>,
}

/// Bind deictic speech only when the evidence is unusually constrained:
/// explicit plural pointing language (or a pair of nearby "this one" turns)
/// plus exactly two conservative title-like facts on screens within 45
/// seconds. More/fewer candidates means no binding.
fn grounding_requirements(
    utterances: &[UttRow],
    screenshots: &[ScrRow],
) -> Vec<GroundingRequirement> {
    let mut requirements = Vec::new();
    for utterance in utterances {
        let at_ms = ms(&utterance.started_at);
        let singular_sequence = crate::ocr::contains_singular_deictic(&utterance.text)
            && utterances
                .iter()
                .filter(|candidate| {
                    crate::ocr::contains_singular_deictic(&candidate.text)
                        && (ms(&candidate.started_at) - at_ms).abs() <= 20_000
                })
                .count()
                >= 2;
        if !crate::ocr::contains_plural_deictic(&utterance.text) && !singular_sequence {
            continue;
        }
        if requirements
            .iter()
            .any(|requirement: &GroundingRequirement| (requirement.at_ms - at_ms).abs() <= 30_000)
        {
            continue;
        }
        let mut all_entities = Vec::new();
        let mut all_seen = HashSet::new();
        let mut primary_entities = Vec::new();
        let mut primary_seen = HashSet::new();
        for screenshot in screenshots {
            if (ms(&screenshot.captured_at) - at_ms).abs() > 45_000 {
                continue;
            }
            let Some(salient) = crate::ocr::select_salient_ocr(
                screenshot.ocr_text.as_deref(),
                screenshot.salient_ocr_text.as_deref(),
            ) else {
                continue;
            };
            let facts = crate::ocr::extract_screen_facts(&salient);
            if facts.len() == 1 {
                let fact = facts[0].clone();
                if primary_seen.insert(fact.to_lowercase()) {
                    primary_entities.push(fact);
                }
            }
            for fact in facts {
                if all_seen.insert(fact.to_lowercase()) {
                    all_entities.push(fact);
                }
            }
        }
        // A detail screen with one title is stronger than a search-results
        // grid containing many neighboring titles. Prefer the exact set of
        // singleton-frame titles, then fall back to an overall exact pair.
        let entities = if primary_entities.len() == 2 {
            primary_entities
        } else {
            all_entities
        };
        if entities.len() == 2 {
            requirements.push(GroundingRequirement { at_ms, entities });
        }
    }
    requirements
}

fn render_grounding_requirements(requirements: &[GroundingRequirement]) -> String {
    if requirements.is_empty() {
        return String::new();
    }
    let lines = requirements
        .iter()
        .map(|requirement| {
            format!(
                "- At {}, deictic speech points to exactly these literal on-screen titles: {}. \
                 The summary bullet for the episode containing this moment MUST name both titles.",
                format_epoch_millis(requirement.at_ms),
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
    format!(
        "GROUNDING REQUIREMENTS (literal screen evidence; do not infer beyond it):\n{lines}\n\n"
    )
}

fn missing_grounded_entities(parsed: &Value, requirements: &[GroundingRequirement]) -> Vec<String> {
    let episodes = parsed
        .get("episodes")
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or_default();
    let mut missing = Vec::new();
    for requirement in requirements {
        let containing = episodes.iter().find(|episode| {
            let start = episode
                .get("started_at")
                .and_then(Value::as_str)
                .map(ms)
                .unwrap_or(i64::MAX);
            let end = episode
                .get("ended_at")
                .and_then(Value::as_str)
                .map(ms)
                .unwrap_or(i64::MIN);
            requirement.at_ms >= start - 10_000 && requirement.at_ms <= end + 10_000
        });
        let summary = containing
            .and_then(|episode| episode.get("summary"))
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_lowercase();
        for entity in &requirement.entities {
            if !summary.contains(&entity.to_lowercase()) {
                missing.push(entity.clone());
            }
        }
    }
    missing.sort_by_key(|entity| entity.to_lowercase());
    missing.dedup_by(|left, right| left.eq_ignore_ascii_case(right));
    missing
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

/// One user's outstanding settle refusal: a window that was derived, paid for
/// with a summary call, and then refused by PostgreSQL at settlement time.
///
/// Holding the cursor is the right answer for evidence integrity — those
/// episodes were never written, and a forward-only cursor that steps over
/// them loses them for good. But holding it alone means the very next sweep
/// re-derives the identical window and re-issues the identical PAID call, ten
/// minutes later, and again ten minutes after that, until the daily Vertex
/// budget refuses. This memo bounds that: it records which held cursor is
/// refusing and how long to wait before spending on it again.
///
const SUMMARY_CLAIM_LEASE_SECONDS: i64 = 15 * 60;

async fn release_summary_claim(
    state: &CpState,
    claim: &SummaryWindowClaim,
    error_code: Option<&str>,
) {
    if let Err(error) = state
        .repositories
        .memory_formation()
        .release_summary_window(claim, &format_epoch_millis(now_ms()), error_code)
        .await
    {
        warn!(error = %error, "failed to release summarizer window claim");
    }
}

/// Summarize one user's recent capture into episodes. Returns a short status.
pub async fn summarize_user(state: &CpState, user_id: &str) -> Result<Value> {
    summarize_user_window(state, user_id, SummarizeMode::Scheduled).await
}

async fn summarize_user_window(
    state: &CpState,
    user_id: &str,
    mode: SummarizeMode,
) -> Result<Value> {
    // The durable PostgreSQL claim below is the cross-replica serialization
    // boundary. This short process-local lock also coalesces the scheduler and
    // session-settled kick before either attempts to claim or spend at Vertex.
    static SUMMARIZE_LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    let _guard = SUMMARIZE_LOCK.get_or_init(|| Mutex::new(())).lock().await;

    let summarized_until = state.repositories.work().summarized_until(user_id).await?;
    let now = now_ms();
    let (tail_cutoff, min_window_ms) = match mode {
        SummarizeMode::Scheduled => (
            now - TAIL_MINUTES * 60 * 1000,
            MIN_WINDOW_MINUTES * 60 * 1000,
        ),
        // Settled evidence: nothing more arrives for this tail, so run to now
        // and accept short windows (a bounded 5-minute recording is a
        // legitimate episode when it survives the significance floor).
        SummarizeMode::SessionSettled => (now, SETTLED_MIN_WINDOW_MS),
    };
    let max_lookback = now - LOOKBACK_DAYS * 24 * 60 * 60 * 1000;

    let new_from = match &summarized_until {
        Some(c) => ms(c).max(max_lookback),
        None => max_lookback,
    };
    let Some(win) = window_bounds(new_from, tail_cutoff, min_window_ms) else {
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
        // An empty span may still be waiting on recoverable media work (in
        // flight, or terminally failed but inside the resurrection ladder's
        // memory-hold rounds). Advancing would strand later-recovered records
        // behind the forward-only cursor, so hold; the hold predicate expires
        // with the ladder, so the cursor can never wedge permanently.
        if span_holds_recoverable_media(state, user_id, &new_from_iso, &new_to_iso).await? {
            return Ok(
                serde_json::json!({ "skipped": true, "reason": "recoverable_media_pending" }),
            );
        }
        state
            .repositories
            .work()
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
        if span_holds_recoverable_media(state, user_id, &new_from_iso, &new_to_iso).await? {
            return Ok(
                serde_json::json!({ "skipped": true, "reason": "recoverable_media_pending" }),
            );
        }
        state
            .repositories
            .work()
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
    let grounding = grounding_requirements(&utterances, &screenshots);
    let grounding_text = render_grounding_requirements(&grounding);

    let range_from = utterances
        .first()
        .map(|u| u.started_at.clone())
        .unwrap_or_else(|| screenshots[0].captured_at.clone());
    let range_to = format_epoch_millis(effective_cutoff);

    let user_message = format!(
        "Range: {range_from} → {range_to}\n\n{}{grounding_text}NEW CAPTURE LOG:\n{capture_text}",
        if open_text.is_empty() {
            String::new()
        } else {
            format!(
                "OPEN EPISODES (extend by ref when the new log continues one):\n{open_text}\n\n"
            )
        }
    );

    // Claim before any provider-backed work. The opaque lease makes one
    // replica authoritative for this exact window and settlement revalidates it.
    let Some(summary_claim) = state
        .repositories
        .memory_formation()
        .claim_summary_window(
            user_id,
            &new_from_iso,
            &new_to_iso,
            &format_epoch_millis(now_ms()),
            SUMMARY_CLAIM_LEASE_SECONDS,
        )
        .await?
    else {
        return Ok(serde_json::json!({
            "skipped": true,
            "reason": "summary_window_claimed"
        }));
    };

    // Call Vertex. Failed windows return an `error` status carrying
    // `window_to` so the sweep can skip past a window that fails
    // deterministically (see summarize_all) instead of stalling forever.
    let system_prompt = format!("{SYSTEM_PROMPT}\n\n{WORKFLOW_CONTINUITY_RULE}");
    if let Err(error) =
        reserve_vertex_output(state, user_id, super::vertex::MAX_TEXT_OUTPUT_TOKENS).await
    {
        release_summary_claim(state, &summary_claim, Some("quota_reservation")).await;
        return Err(error);
    }
    let response = match super::vertex::generate(
        state,
        user_id,
        super::vertex::VertexOperation::EpisodeSummary,
        &system_prompt,
        &user_message,
    )
    .await
    {
        Ok(t) => t.text,
        Err(e) if e.to_string().contains("quota") => {
            release_summary_claim(state, &summary_claim, Some("quota")).await;
            return Ok(serde_json::json!({ "skipped": true, "reason": "quota" }));
        }
        Err(e) => {
            warn!(error = %e, "summarizer LLM call failed");
            release_summary_claim(state, &summary_claim, Some("model_call")).await;
            return Ok(serde_json::json!({ "error": e.to_string(), "window_to": new_to_iso }));
        }
    };
    let Some(mut parsed) = extract_json(&response) else {
        // Length only — the response paraphrases user content, never log it.
        warn!(
            response_len = response.len(),
            "summarizer LLM response unparseable"
        );
        release_summary_claim(state, &summary_claim, Some("unparseable")).await;
        return Ok(
            serde_json::json!({ "error": "unparseable LLM response", "window_to": new_to_iso }),
        );
    };
    let missing = missing_grounded_entities(&parsed, &grounding);
    if !missing.is_empty() {
        // One bounded repair call. It may only repair the supplied JSON using
        // the same evidence; if it remains incomplete, retain the original
        // response rather than synthesizing or guessing names in code.
        let repair_message = format!(
            "{user_message}\n\nPRIOR JSON RESPONSE:\n{response}\n\n\
             CORRECTION REQUIRED: the summary for the episode containing the grounded moment \
             omitted these literal on-screen titles: {}. Return the complete corrected JSON, \
             preserving all other evidence boundaries.",
            missing
                .iter()
                .map(|entity| format!("{entity:?}"))
                .collect::<Vec<_>>()
                .join(", ")
        );
        if let Err(error) =
            reserve_vertex_output(state, user_id, super::vertex::MAX_TEXT_OUTPUT_TOKENS).await
        {
            release_summary_claim(state, &summary_claim, Some("repair_quota")).await;
            return Err(error);
        }
        match super::vertex::generate(
            state,
            user_id,
            super::vertex::VertexOperation::EpisodeSummaryRepair,
            &system_prompt,
            &repair_message,
        )
        .await
        {
            Ok(repaired_text) => {
                if let Some(repaired) = extract_json(&repaired_text.text) {
                    if missing_grounded_entities(&repaired, &grounding).is_empty() {
                        parsed = repaired;
                    } else {
                        warn!("summarizer grounding repair remained incomplete");
                    }
                } else {
                    warn!("summarizer grounding repair was unparseable");
                }
            }
            Err(error) => warn!(%error, "summarizer grounding repair deferred"),
        }
    }
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

    let cutoff_iso = format_epoch_millis(effective_cutoff);
    if to_upsert.is_empty() && tail_bounded {
        release_summary_claim(state, &summary_claim, None).await;
        info!(
            user_id,
            dropped, "summarized nothing; holding cursor for tail to grow"
        );
        return Ok(serde_json::json!({ "waiting": true, "dropped": dropped }));
    }
    let ids = state
        .repositories
        .memory_formation()
        .settle_summary_window(SummaryWindowSettlement {
            claim: summary_claim,
            episodes: to_upsert,
            cursor: Some(cutoff_iso.clone()),
        })
        .await?;
    let upserted = ids.len();
    embed_episodes(state, user_id, &ids).await;
    info!(user_id, upserted, dropped, "summarized");
    Ok(serde_json::json!({
        "episodes": upserted,
        "dropped": dropped,
        "to": cutoff_iso
    }))
}
/// In-enclave episode embeddings (ADR-0004 §G.2). Episodes are born in the
/// enclave — the Mac never sees them — so their vectors are computed HERE
/// with the in-TEE candle encoder, in the same pinned `MODEL_ID` space as the
/// Mac-computed document vectors (mixing spaces silently corrupts KNN). Cost
/// is bounded: one embed per upserted episode per summarizer window.
///
/// Text is read back from the stored rows (title + exec summary + minute
/// gists + the human string values in any settled final brief) so extensions
/// embed the full memory projection, not just the new window. Best-effort: an
/// absent engine or a failed embed leaves the episode FTS-only — it never
/// fails the summarizer run.
pub(crate) async fn embed_episodes(state: &CpState, user_id: &str, ids: &[i64]) {
    let Some(engine) = state.embedding.as_ref().cloned() else {
        return;
    };

    let rows = match state
        .repositories
        .memory_formation()
        .episode_embedding_sources(user_id, ids)
        .await
    {
        Ok(rows) => rows,
        Err(error) => {
            warn!(error = %error, "episode embed: read-back failed");
            return;
        }
    };

    let mut writes = Vec::new();
    for row in rows {
        let episode_id = row.id;
        let text = row.text;
        let engine = Arc::clone(&engine);
        match tokio::task::spawn_blocking(move || engine.embed(&text)).await {
            Ok(Ok(embedding)) => writes.push(EpisodeEmbeddingWrite {
                id: episode_id,
                embedding,
            }),
            Ok(Err(error)) => {
                warn!(
                    episode_id,
                    "episode embed failed ({error}) — FTS-only for this episode"
                );
            }
            Err(error) => warn!(episode_id, "episode embed task panicked ({error})"),
        }
    }
    if writes.is_empty() {
        return;
    }
    if let Err(error) = state
        .repositories
        .memory_formation()
        .write_episode_embeddings(user_id, &writes)
        .await
    {
        warn!(error = %error, "episode embed: vector write failed");
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

/// Hold the forward-only cursor while recent failed or pending media can still
/// become searchable evidence.
async fn span_holds_recoverable_media(
    state: &CpState,
    user_id: &str,
    from: &str,
    to: &str,
) -> Result<bool> {
    let resurrection_window_start = format_epoch_millis(
        now_ms() - (super::media_worker::RESURRECTION_WINDOW_SECONDS * 1000.0) as i64,
    );
    state
        .repositories
        .media_processing()
        .span_has_recoverable_media(
            user_id,
            from,
            to,
            &resurrection_window_start,
            super::media_worker::RESURRECTION_MEMORY_HOLD_TOTAL_ATTEMPTS,
        )
        .await
}

/// Load the bounded evidence for one claimed summarization window.
async fn fetch_range(
    state: &CpState,
    user_id: &str,
    from: &str,
    to: &str,
) -> Result<(Vec<UttRow>, Vec<ScrRow>)> {
    state
        .repositories
        .memory_formation()
        .summary_evidence(user_id, from, to, UTT_CAP as i64, SCR_CAP as i64)
        .await
}

/// Load the recent episode digests that the model may extend by reference.
async fn fetch_open_episodes(
    state: &CpState,
    user_id: &str,
    list_start: &str,
    list_end: &str,
    open_cutoff_ms: i64,
) -> Result<Vec<OpenEp>> {
    let mut episodes = state
        .repositories
        .memory_formation()
        .open_episodes(user_id, list_start, list_end, 100)
        .await?;
    episodes.retain(|episode| ms(&episode.ended_at) >= open_cutoff_ms);
    let excess = episodes.len().saturating_sub(30);
    if excess > 0 {
        episodes.drain(0..excess);
    }
    Ok(episodes)
}

/// Sweep all users (internal cron). Sequential to avoid Vertex rate-limit storms.
///
/// The recurring backstop crosses only proven-empty windows and stops after
/// the first non-empty/model outcome. This also repairs a settled session
/// whose process-local finish hint was lost before a deploy or restart: the
/// durable account cursor and capture evidence are rediscovered on the first
/// scheduler tick without stacking model calls.
pub async fn summarize_all(state: &CpState) {
    let ids = match state.repositories.work().active_account_ids().await {
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
        for _ in 0..SPARSE_LOOKBACK_MAX_WINDOWS {
            match summarize_user(state, &id).await {
                // Empty spans perform no model work and are safe to traverse
                // in one bounded wakeup. Any non-empty success (`to`), hold,
                // claim, quota response, or error stops this user's pass.
                Ok(v) if should_cross_proven_empty_window(&v) => {
                    failing.lock().await.remove(&id);
                    continue;
                }
                Ok(v) if v.get("to").is_some() => {
                    failing.lock().await.remove(&id);
                    break;
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
                    if let Err(e) = state
                        .repositories
                        .work()
                        .set_summarized_until(&id, window_to)
                        .await
                    {
                        warn!(user_id = %id, error = %e, "failed to skip stuck window");
                        break;
                    }
                    // The failed call already spent this wakeup's one model
                    // attempt. Leave later evidence for the next scheduler
                    // tick after the durable PostgreSQL cursor advance.
                    break;
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

        finalize_and_deliver_user(state, &id).await;
    }
}

/// The per-user post-summarization tail: finalization plus webhook, email,
/// and push delivery. Every step is idempotent and no-ops when nothing new
/// finalized, so both the sweep and the session-settled kick run it.
async fn finalize_and_deliver_user(state: &CpState, id: &str) {
    if let Err(e) = super::finalizer::finalize_user_episodes(state, id).await {
        warn!(user_id = %id, error = %e, "finalize_user_episodes failed");
    }
    if let Err(e) = super::webhook_worker::deliver_user_webhooks(state, id).await {
        warn!(error = %e, "deliver_user_webhooks failed");
    }
    if let Some(ref transport) = state.email_transport {
        if let Err(e) =
            super::email_worker::deliver_user_emails(state, transport.as_ref(), id).await
        {
            warn!(user_id = %id, error = %e, "deliver_user_emails failed");
        }
    }
    if let Some(ref transport) = state.push_transport {
        if let Err(e) = super::push::deliver_user_pushes(state, transport.as_ref(), id).await {
            warn!(user_id = %id, error = %e, "deliver_user_pushes failed");
        }
    }
}

/// Session-settled kick queue (ADR-0034). Ingest and the media worker hint
/// that a user's finished capture session may be fully processed; the
/// scheduler task drains the queue between sweeps. A missing receiver (tests,
/// or startup before [`spawn_scheduler`]) makes the kick a silent no-op — the
/// 10-minute sweep remains the correctness backstop.
static SESSION_SETTLED_KICKS: OnceLock<tokio::sync::mpsc::UnboundedSender<String>> =
    OnceLock::new();

/// Hint that `user_id`'s live tail may have just settled (a session finished
/// or its last media work completed). Cheap, non-blocking, and safe to call
/// speculatively: the scheduler re-checks the settled gate before any LLM
/// call.
pub fn kick_session_settled(user_id: &str) {
    if let Some(sender) = SESSION_SETTLED_KICKS.get() {
        let _ = sender.send(user_id.to_string());
    }
}

/// Return true only when the account has no recent open capture session and no
/// accepted media still eligible for processing.
async fn session_tail_is_settled(state: &CpState, user_id: &str) -> bool {
    let cutoff = format_epoch_millis(now_ms() - 30 * 60 * 1000);
    match state
        .repositories
        .memory_formation()
        .session_tail_is_settled(user_id, &cutoff)
        .await
    {
        Ok(settled) => settled,
        Err(error) => {
            warn!(user_id, error = %error, "session-settled gate check failed");
            false
        }
    }
}

fn should_cross_proven_empty_window(value: &Value) -> bool {
    value.get("reason").and_then(Value::as_str) == Some("no_new_records")
}

async fn summarize_session_settled(state: &CpState, user_id: &str) {
    if !session_tail_is_settled(state, user_id).await {
        return;
    }

    // A new/stale cursor begins as far as seven days behind. Each ordinary
    // run is deliberately capped at six hours, so a single finish kick used
    // to advance one empty window and then wait for the 10-minute cron. In the
    // worst case today's recording needed roughly 28 ticks (~4h40m) before it
    // was even offered to the model. Empty-window advancement is already the
    // safe path: it first checks the recoverable-media hold and refuses to
    // move past unsettled evidence. Keep following only that explicit result;
    // any model call, hold, claim, quota response, or error stops this trigger.
    for _ in 0..SPARSE_LOOKBACK_MAX_WINDOWS {
        match summarize_user_window(state, user_id, SummarizeMode::SessionSettled).await {
            Ok(value) if should_cross_proven_empty_window(&value) => {}
            Ok(_) => break,
            Err(e) => {
                warn!(user_id, error = %e, "session-settled summarize failed");
                return;
            }
        }
    }
    finalize_and_deliver_user(state, user_id).await;
}

/// Collapse only the kicks already waiting in the channel. Unlike a
/// time-based debounce, this cannot discard the meaningful media-complete
/// kick merely because an earlier session-finish hint found pending work.
/// A kick arriving while formation is running remains queued for a fresh
/// settled-gate check afterwards.
fn coalesced_kick_batch(
    first_user_id: String,
    receiver: &mut tokio::sync::mpsc::UnboundedReceiver<String>,
) -> Vec<String> {
    let mut seen = HashSet::new();
    let mut users = Vec::new();
    if seen.insert(first_user_id.clone()) {
        users.push(first_user_id);
    }
    while let Ok(user_id) = receiver.try_recv() {
        if seen.insert(user_id.clone()) {
            users.push(user_id);
        }
    }
    users
}

/// Spawn the internal summarizer cron (replaces Cloud Scheduler). Sweeps every
/// [`SCHEDULER_INTERVAL_SECS`] and drains session-settled kicks between
/// sweeps.
pub fn spawn_scheduler(state: Arc<CpState>) {
    let (sender, mut receiver) = tokio::sync::mpsc::unbounded_channel::<String>();
    let _ = SESSION_SETTLED_KICKS.set(sender);
    tokio::spawn(async move {
        // Tokio's first interval tick is immediately ready. That first
        // durable sweep is the restart recovery for completed sessions whose
        // earlier process-local kick no longer exists.
        let mut tick = tokio::time::interval(Duration::from_secs(SCHEDULER_INTERVAL_SECS));
        loop {
            tokio::select! {
                _ = tick.tick() => summarize_all(&state).await,
                Some(first_user_id) = receiver.recv() => {
                    for user_id in coalesced_kick_batch(first_user_id, &mut receiver) {
                        summarize_session_settled(&state, &user_id).await;
                    }
                }
            }
        }
    });
}

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
8a. DEICTIC SCREEN GROUNDING. `[screen-facts]` are conservative literal labels visible on screen. When a GROUNDING REQUIREMENT binds pointing language such as "these two" or "this one" to exact screen facts, name every bound entity in the episode's summary bullet; never replace them with "the two items/movies" or another generic reference. If no requirement is supplied, do not guess what a pronoun refers to.
9. ACTION ITEMS. action_items contains only explicit commitments, requested follow-ups, or requirements/instructions directed at a person; otherwise []. A requirement addressed to "Me" belongs here even if the owner did not verbally promise it. Phrase each item as the concrete action, owner when known, and exact due date or condition when stated. Do not promote optional general information into an action.
10. started_at/ended_at: ISO 8601 within the provided range (for an extension, the FULL span). languages: BCP-47 codes actually heard.
11. MINUTE TIMELINE. minutes is a timeline of the episode's NEW activity. Bucket the NEW CAPTURE LOG into 1–5-minute buckets. Each gist is one concrete sentence naming who said/did/decided/required what when speaker identity is supported, and retaining a material date, amount, step, outcome, resource or URL when present. Never use generic filler or topic labels such as "conversation continues" or "transportation discussed". Each bucket: {"start":"<ISO of bucket start>","gist":"..."}. Cover ONLY minutes present in the NEW CAPTURE LOG — for an extension, earlier minutes are already stored; never re-emit or invent them.
12. substance: none for fragments with no coherent topic, hallucination-like repetition, or content-free filler; low for real but trivial activity (a few passing remarks, background TV); normal for everything else. When in doubt, prefer the higher tier.
13. visual_evidence: useful if visual state is material (for example a slide, document, diagram, error, design, settings state, or on-screen decision evidence); none if pixels would not materially improve verification.

Return STRICT JSON only: {"episodes":[{"episode_ref":"E0 or omit","started_at":"<ISO>","ended_at":"<ISO>","type":"<type>","title":"...","summary":"- concrete takeaway\n- concrete requirement","participants":["Me","Ana (Speaker 2)"],"languages":["fr"],"action_items":[],"substance":"normal","visual_evidence":"none","minutes":[{"start":"<ISO>","gist":"..."}]}]}"#;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn automatic_summarization_crosses_sparse_history_without_stacking_model_work() {
        assert!(
            i64::from(SPARSE_LOOKBACK_MAX_WINDOWS) * MAX_WINDOW_HOURS > LOOKBACK_DAYS * 24,
            "the first durable scheduler tick can rediscover today's evidence"
        );
        assert!(should_cross_proven_empty_window(&json!({
            "skipped": true,
            "reason": "no_new_records"
        })));
        assert!(!should_cross_proven_empty_window(&json!({
            "episodes": 1,
            "to": "2026-08-28T12:00:00.000Z"
        })));
    }

    #[test]
    fn session_settled_trigger_can_cross_the_complete_sparse_lookback() {
        assert!(
            i64::from(SPARSE_LOOKBACK_MAX_WINDOWS) * MAX_WINDOW_HOURS > LOOKBACK_DAYS * 24,
            "one finish trigger must reach today's evidence from the oldest allowed cursor"
        );
    }

    #[test]
    fn session_settled_repeats_only_after_a_proven_empty_advance() {
        assert!(should_cross_proven_empty_window(&json!({
            "skipped": true,
            "reason": "no_new_records"
        })));
        for terminal_for_this_trigger in [
            json!({ "waiting": true }),
            json!({ "skipped": true, "reason": "recoverable_media_pending" }),
            json!({ "skipped": true, "reason": "summary_window_claimed" }),
            json!({ "skipped": true, "reason": "quota" }),
            json!({ "episodes": 1, "to": "2026-08-28T12:00:00.000Z" }),
            json!({ "error": "model_call" }),
        ] {
            assert!(!should_cross_proven_empty_window(
                &terminal_for_this_trigger
            ));
        }
    }

    #[test]
    fn kick_coalescing_drops_queued_duplicates_but_not_a_later_kick() {
        let (sender, mut receiver) = tokio::sync::mpsc::unbounded_channel();
        for user_id in ["alice", "alice", "bob", "alice"] {
            sender.send(user_id.to_string()).unwrap();
        }

        let first = receiver.try_recv().unwrap();
        assert_eq!(
            coalesced_kick_batch(first, &mut receiver),
            vec!["alice".to_string(), "bob".to_string()]
        );

        // This models media completion arriving after an earlier finish hint
        // was handled. It must form a new batch regardless of wall-clock gap.
        sender.send("alice".to_string()).unwrap();
        let later = receiver.try_recv().unwrap();
        assert_eq!(
            coalesced_kick_batch(later, &mut receiver),
            vec!["alice".to_string()]
        );
    }

    const MIN: i64 = 60 * 1000;
    const HOUR: i64 = 60 * MIN;

    const SCHEDULED_MIN_WINDOW: i64 = MIN_WINDOW_MINUTES * MIN;

    /// The live-tail ratchet fix (module docs): short tails wait, medium tails
    /// are tail-bounded (may hold the cursor), capped windows always advance.
    #[test]
    fn window_bounds_semantics() {
        let tail = 1_000_000 * MIN; // arbitrary "now - 5min" reference

        // Tail shorter than MIN_WINDOW: don't run at all.
        assert_eq!(
            window_bounds(tail - 10 * MIN, tail, SCHEDULED_MIN_WINDOW),
            None
        );
        assert_eq!(
            window_bounds(tail, tail, SCHEDULED_MIN_WINDOW),
            None,
            "caught up exactly"
        );
        assert_eq!(
            window_bounds(tail + MIN, tail, SCHEDULED_MIN_WINDOW),
            None,
            "cursor past tail"
        );

        // Tail-bounded window: ends at the tail, below the 6-h cap.
        let (to, tail_bounded) =
            window_bounds(tail - 30 * MIN, tail, SCHEDULED_MIN_WINDOW).unwrap();
        assert_eq!(to, tail);
        assert!(tail_bounded, "30-min live window may hold the cursor");

        // Window at the cap: advances unconditionally (backfill marches).
        let (to, tail_bounded) =
            window_bounds(tail - 26 * HOUR, tail, SCHEDULED_MIN_WINDOW).unwrap();
        assert_eq!(to, tail - 26 * HOUR + MAX_WINDOW_HOURS * HOUR);
        assert!(!tail_bounded, "capped window must not hold the cursor");

        // Window exactly 6 h to the tail: treated as capped (advance) so a
        // pathological always-insignificant span can't hold forever.
        let (to, tail_bounded) =
            window_bounds(tail - MAX_WINDOW_HOURS * HOUR, tail, SCHEDULED_MIN_WINDOW).unwrap();
        assert_eq!(to, tail);
        assert!(!tail_bounded);
    }

    /// ADR-0034 session-settled runs: a short window is allowed (the session
    /// is closed evidence), but it stays tail-bounded so empty output still
    /// holds the cursor — an early call can never consume content.
    #[test]
    fn session_settled_window_accepts_short_tail_and_stays_tail_bounded() {
        let tail = 1_000_000 * MIN;

        let (to, tail_bounded) = window_bounds(tail - 5 * MIN, tail, SETTLED_MIN_WINDOW_MS)
            .expect("a settled 5-minute recording is summarizable immediately");
        assert_eq!(to, tail);
        assert!(
            tail_bounded,
            "short settled window must hold cursor on empty output"
        );

        // Still refuses degenerate/caught-up windows.
        assert_eq!(window_bounds(tail, tail, SETTLED_MIN_WINDOW_MS), None);
        assert_eq!(window_bounds(tail + MIN, tail, SETTLED_MIN_WINDOW_MS), None);
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
                salient_ocr_text: None,
                url: None,
                is_duplicate: 0,
            },
            ScrRow {
                id: 2,
                captured_at: "2026-06-01T14:00:02Z".to_string(),
                active_app: Some("Finder".to_string()),
                window_title: Some("Desktop".to_string()),
                ocr_text: Some("foo".to_string()),
                salient_ocr_text: None,
                url: None,
                is_duplicate: 1,
            },
            ScrRow {
                id: 3,
                captured_at: "2026-06-01T14:00:04Z".to_string(),
                active_app: Some("Finder".to_string()),
                window_title: Some("Desktop".to_string()),
                ocr_text: Some("foo".to_string()),
                salient_ocr_text: None,
                url: None,
                is_duplicate: 1,
            },
            ScrRow {
                id: 4,
                captured_at: "2026-06-01T14:00:06Z".to_string(),
                active_app: Some("Xcode".to_string()),
                window_title: Some("main.swift".to_string()),
                ocr_text: Some("bar".to_string()),
                salient_ocr_text: None,
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
                salient_ocr_text: None,
                url: Some(url.clone()),
                is_duplicate: 0,
            }],
        );

        assert!(rendered.contains(&format!("<{url}>")));
    }

    fn episode_312_fixture() -> (Vec<UttRow>, Vec<ScrRow>) {
        let utterances = vec![UttRow {
            id: 1,
            started_at: "2026-07-22T12:39:59Z".into(),
            speaker_label: "Speaker 2".into(),
            language: Some("en".into()),
            text: "these are the two movies".into(),
        }];
        let screenshots = vec![
            ScrRow {
                id: 9,
                captured_at: "2026-07-22T12:40:27Z".into(),
                active_app: Some("TV".into()),
                window_title: Some("Search".into()),
                ocr_text: Some(
                    "Top Results\nMARY POPPINS\nMovie • Comedy - 1964\n\
                     MARY POPPINS RETURNS\nMovie • Musical - 2018\n\
                     SAVING MR BANKS\nMovie • Drama - 2013"
                        .into(),
                ),
                salient_ocr_text: None,
                url: None,
                is_duplicate: 0,
            },
            ScrRow {
                id: 10,
                captured_at: "2026-07-22T12:40:29Z".into(),
                active_app: Some("TV".into()),
                window_title: Some("Mary Poppins".into()),
                ocr_text: Some(
                    "TV File Edit Actions View Controls Account Window Help\n\
                     MARY POPPINS\nMovie • Comedy - Kids & Family\n1964 • 2 hr 19 min"
                        .into(),
                ),
                salient_ocr_text: None,
                url: None,
                is_duplicate: 0,
            },
            ScrRow {
                id: 11,
                captured_at: "2026-07-22T12:40:35Z".into(),
                active_app: Some("TV".into()),
                window_title: Some("Mary Poppins Returns".into()),
                ocr_text: Some(
                    "TV File Edit Actions View Controls Account Window Help\n\
                     MARY POPPINS RETURNS\nMovie • Musical - Adventure\n2018 • 2 hr 10 min"
                        .into(),
                ),
                salient_ocr_text: None,
                url: None,
                is_duplicate: 0,
            },
        ];
        (utterances, screenshots)
    }

    #[test]
    fn episode_312_deictic_grounding_requires_both_titles_in_takeaway() {
        let (utterances, screenshots) = episode_312_fixture();
        let requirements = grounding_requirements(&utterances, &screenshots);
        assert_eq!(requirements.len(), 1);
        assert_eq!(
            requirements[0].entities,
            vec!["MARY POPPINS", "MARY POPPINS RETURNS"]
        );

        let generic = json!({
            "episodes": [{
                "started_at": "2026-07-22T12:39:59Z",
                "ended_at": "2026-07-22T12:40:39Z",
                "summary": "- Ensure the two specified movies are downloaded."
            }]
        });
        assert_eq!(
            missing_grounded_entities(&generic, &requirements),
            vec!["MARY POPPINS", "MARY POPPINS RETURNS"]
        );

        let grounded = json!({
            "episodes": [{
                "started_at": "2026-07-22T12:39:59Z",
                "ended_at": "2026-07-22T12:40:39Z",
                "summary": "- Download Mary Poppins (1964) and Mary Poppins Returns (2018) for the car trip."
            }]
        });
        assert!(missing_grounded_entities(&grounded, &requirements).is_empty());
    }

    #[test]
    fn ambiguous_screen_facts_do_not_create_a_grounding_requirement() {
        let (utterances, mut screenshots) = episode_312_fixture();
        screenshots.push(ScrRow {
            id: 12,
            captured_at: "2026-07-22T12:40:20Z".into(),
            active_app: Some("TV".into()),
            window_title: Some("Search".into()),
            ocr_text: Some("SAVING MR BANKS\nMovie • Drama - 2013".into()),
            salient_ocr_text: None,
            url: None,
            is_duplicate: 0,
        });
        assert!(grounding_requirements(&utterances, &screenshots).is_empty());
    }

    #[test]
    fn two_nearby_this_one_utterances_form_one_grounding_requirement() {
        let (_, screenshots) = episode_312_fixture();
        let utterances = vec![
            UttRow {
                id: 1,
                started_at: "2026-07-22T12:39:59Z".into(),
                speaker_label: "Speaker 2".into(),
                language: Some("en".into()),
                text: "This one here".into(),
            },
            UttRow {
                id: 2,
                started_at: "2026-07-22T12:40:04Z".into(),
                speaker_label: "Speaker 2".into(),
                language: Some("en".into()),
                text: "And also this one right here".into(),
            },
        ];
        let requirements = grounding_requirements(&utterances, &screenshots);
        assert_eq!(requirements.len(), 1);
        assert_eq!(
            requirements[0].entities,
            vec!["MARY POPPINS", "MARY POPPINS RETURNS"]
        );
    }

    #[test]
    fn capture_prompt_uses_salient_ocr_but_keeps_screen_facts() {
        let (utterances, screenshots) = episode_312_fixture();
        let rendered = render_capture_text(&utterances, &screenshots);
        assert!(rendered.contains("[screen-facts] \"MARY POPPINS\""));
        assert!(rendered.contains("\"MARY POPPINS RETURNS\""));
        assert!(!rendered.contains("File Edit Actions"));
    }
}
