//! Durable raw-media processing worker.
//!
//! The device upload endpoint only validates, encrypts, and records source
//! events. This worker leases those events from each user's encrypted SQLite
//! ledger, opens the media inside the enclave, sends the bounded asset to
//! Vertex Gemini, validates constrained JSON, and transactionally projects the
//! result into the searchable archive. No media or generated content is logged.

pub(crate) mod wal;

use std::collections::HashSet;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use rusqlite::{params, Connection, OptionalExtension};
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tokio::task::JoinSet;
use tracing::{info, warn};

use crate::error::{EnclaveError, Result};
use crate::store::Store;

use super::media::{parse_audio_result, AudioTurn};
use super::media_planner::{self, PlanningEvent, SourceInterval, WorkClass};
use super::{isotime, vertex, CpState};

const WORKER_INTERVAL_SECONDS: u64 = 30;
const MAX_JOBS_PER_USER_PER_SWEEP: usize = 2;
const MAX_CONCURRENT_USER_SWEEPS: usize = 4;
const MAX_ATTEMPTS: i64 = 3;
const PROCESSOR_VERSION: i64 = 1;
const PROMPT_VERSION: i64 = 2;
// Bounded second-chance ladder for terminally failed jobs: after the fast
// 3-attempt ladder exhausts, one attempt per hour may be resurrected until the
// hard attempt cap, and only while the source event is recent. Failures whose
// cause is deterministic (media integrity) are never resurrected. This keeps a
// transient Vertex outage from freezing a session in `needs_attention`
// forever, while capping worst-case extra inference per poisoned item.
const RESURRECTION_DELAY_SECONDS: f64 = 3_600.0;
const RESURRECTION_TOTAL_ATTEMPT_CAP: i64 = 9;
pub(crate) const RESURRECTION_WINDOW_SECONDS: f64 = 7.0 * 24.0 * 3_600.0;
// A mass outage can terminally fail a large backlog at once; cap how many
// jobs one sweep resurrects so recovered work cannot starve live capture
// processing (2 work units per user per 30s sweep).
const RESURRECTION_MAX_PER_SWEEP: i64 = 16;
/// The summarizer holds its forward-only cursor over spans whose failures are
/// still inside the first resurrection rounds (fast ladder + 2), so recovered
/// records can still form a memory instead of being stranded behind the
/// cursor. Later rounds only enrich search.
pub(crate) const RESURRECTION_MEMORY_HOLD_TOTAL_ATTEMPTS: i64 = MAX_ATTEMPTS + 2;

#[derive(Debug, Clone)]
struct MediaJob {
    id: i64,
    event_id: String,
    job_kind: String,
    object_key: String,
    mime_type: String,
    codec: String,
    byte_length: i64,
    sample_rate: Option<i64>,
    channels: Option<i64>,
    width: Option<i64>,
    height: Option<i64>,
    sha256: String,
    started_at: String,
    ended_at: String,
    stream_kind: String,
    capture_session_id: String,
    stream_id: String,
    sequence: i64,
    context_json: Option<String>,
    usage_json: Option<String>,
    audio_role: Option<String>,
    audio_route: Option<String>,
    route_epoch: Option<i64>,
}

impl MediaJob {
    fn class(&self) -> WorkClass {
        if self.job_kind == "gemini_audio" {
            WorkClass::Audio
        } else {
            WorkClass::Screen
        }
    }

    fn planning_event(&self) -> Result<PlanningEvent> {
        let started_ms = isotime::parse_epoch_millis(&self.started_at)
            .ok_or_else(|| EnclaveError::InvalidRequest("job start timestamp is invalid".into()))?;
        let ended_ms = isotime::parse_epoch_millis(&self.ended_at)
            .ok_or_else(|| EnclaveError::InvalidRequest("job end timestamp is invalid".into()))?;
        Ok(PlanningEvent {
            job_id: self.id,
            event_id: self.event_id.clone(),
            class: self.class(),
            capture_session_id: self.capture_session_id.clone(),
            stream_id: self.stream_id.clone(),
            sequence: self.sequence,
            started_ms,
            ended_ms,
            byte_length: self.byte_length,
            pixel_count: self
                .width
                .unwrap_or(0)
                .saturating_mul(self.height.unwrap_or(0)),
            route_key: format!(
                "{}:{}:{}:{}:{}:{}:{}:{}",
                self.stream_kind,
                self.mime_type,
                self.codec,
                self.sample_rate.unwrap_or(0),
                self.channels.unwrap_or(0),
                self.audio_role.as_deref().unwrap_or(""),
                self.audio_route.as_deref().unwrap_or(""),
                self.route_epoch.unwrap_or(0)
            ),
        })
    }

    fn acoustic_domain(&self) -> String {
        let role = self.audio_role.as_deref().unwrap_or("");
        let route = self.audio_route.as_deref().unwrap_or("");
        if !role.is_empty() || !route.is_empty() {
            format!("{}:{}:{}", self.stream_kind, role, route)
        } else {
            self.stream_kind.clone()
        }
    }
}

#[derive(Debug, Clone)]
struct MediaWorkUnit {
    id: String,
    class: WorkClass,
    jobs: Vec<MediaJob>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ScreenResult {
    literal_description: String,
    screen_state: String,
    content_type: String,
    visible_text: String,
    salient_text: String,
    #[serde(default)]
    people: Vec<PersonEvidence>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoryboardResult {
    frames: Vec<StoryboardFrameResult>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoryboardFrameResult {
    frame_id: String,
    literal_description: String,
    screen_state: String,
    content_type: String,
    visible_text: String,
    salient_text: String,
    #[serde(default)]
    people: Vec<PersonEvidence>,
}

impl StoryboardFrameResult {
    fn into_screen_result(self) -> ScreenResult {
        ScreenResult {
            literal_description: self.literal_description,
            screen_state: self.screen_state,
            content_type: self.content_type,
            visible_text: self.visible_text,
            salient_text: self.salient_text,
            people: self.people,
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PersonEvidence {
    name: String,
    evidence: String,
    confidence: f64,
    is_active_speaker: bool,
}

fn now_iso() -> String {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64;
    isotime::format_epoch_millis(millis)
}

fn audio_schema() -> Value {
    json!({
        "type": "OBJECT",
        "properties": {
            "turns": {
                "type": "ARRAY",
                "items": {
                    "type": "OBJECT",
                    "properties": {
                        "turn_id": {"type":"STRING"},
                        "start_ms": {"type":"INTEGER"},
                        "end_ms": {"type":"INTEGER"},
                        "speaker_local_id": {"type":"STRING"},
                        "text": {"type":"STRING"},
                        "language": {"type":"STRING", "nullable":true},
                        "overlap": {"type":"BOOLEAN"},
                        "quality_flags": {"type":"ARRAY", "items":{"type":"STRING"}},
                        "speaker_name": {"type":"STRING", "nullable":true},
                        "speaker_name_confidence": {"type":"NUMBER", "nullable":true},
                        "speaker_name_evidence": {"type":"STRING", "nullable":true},
                        "speaker_name_kind": {"type":"STRING", "enum":["self_identification","vocative_address","third_party_mention"], "nullable":true},
                        "speaker_name_subject_turn_id": {"type":"STRING", "nullable":true},
                        "speaker_name_target_turn_id": {"type":"STRING", "nullable":true},
                        "person_facts": {
                            "type":"ARRAY",
                            "items": {
                                "type":"OBJECT",
                                "properties": {
                                    "predicate":{"type":"STRING","enum":["role","organization","relationship","preference","responsibility","contact","location","other"]},
                                    "value":{"type":"STRING"},
                                    "evidence":{"type":"STRING"}
                                },
                                "required":["predicate","value","evidence"]
                            }
                        }
                    },
                    "required": ["turn_id","start_ms","end_ms","speaker_local_id","text","overlap","quality_flags"]
                }
            }
        },
        "required": ["turns"]
    })
}

fn screen_schema() -> Value {
    json!({
        "type":"OBJECT",
        "properties": {
            "literal_description":{"type":"STRING"},
            "screen_state":{"type":"STRING","enum":[
                "content","blank","loading","error","transition",
                "locked_or_private","unknown"]},
            "content_type":{"type":"STRING","enum":[
                "document","presentation","web_page","code","terminal","chat",
                "meeting","media","system_ui","application_ui","unknown"]},
            "visible_text":{"type":"STRING"},
            "salient_text":{"type":"STRING"},
            "people": {
                "type":"ARRAY",
                "items": {
                    "type":"OBJECT",
                    "properties": {
                        "name":{"type":"STRING"},
                        "evidence":{"type":"STRING"},
                        "confidence":{"type":"NUMBER"},
                        "is_active_speaker":{"type":"BOOLEAN"}
                    },
                    "required":["name","evidence","confidence","is_active_speaker"]
                }
            }
        },
        "required":["literal_description","screen_state","content_type","visible_text","salient_text","people"]
    })
}

fn storyboard_schema() -> Value {
    let screen = screen_schema();
    let mut properties = screen["properties"].clone();
    properties["frame_id"] = json!({"type":"STRING"});
    let mut required = screen["required"].clone();
    required
        .as_array_mut()
        .expect("static screen schema required array")
        .insert(0, json!("frame_id"));
    json!({
        "type":"OBJECT",
        "properties": {
            "frames": {
                "type":"ARRAY",
                "items": {
                    "type":"OBJECT",
                    "properties": properties,
                    "required": required
                }
            }
        },
        "required":["frames"]
    })
}

fn validate_storyboard_result(
    raw: &str,
    expected_frame_ids: &[String],
) -> Result<Vec<(String, ScreenResult)>> {
    let result: StoryboardResult = serde_json::from_str(raw)?;
    if result.frames.len() != expected_frame_ids.len() {
        return Err(EnclaveError::InvalidRequest(
            "storyboard response does not cover every frame".into(),
        ));
    }
    let expected = expected_frame_ids.iter().collect::<HashSet<_>>();
    let mut seen = HashSet::new();
    let mut by_id = std::collections::HashMap::new();
    for frame in result.frames {
        if !expected.contains(&frame.frame_id) || !seen.insert(frame.frame_id.clone()) {
            return Err(EnclaveError::InvalidRequest(
                "storyboard response has an unknown or duplicate frame id".into(),
            ));
        }
        by_id.insert(frame.frame_id.clone(), frame.into_screen_result());
    }
    expected_frame_ids
        .iter()
        .map(|id| {
            by_id
                .remove(id)
                .map(|result| (id.clone(), result))
                .ok_or_else(|| {
                    EnclaveError::InvalidRequest("storyboard response is missing a frame id".into())
                })
        })
        .collect()
}

#[cfg(test)]
fn lease_next_job(conn: &Connection, now: &str) -> Result<Option<MediaJob>> {
    let tx = conn.unchecked_transaction()?;
    let selected: Option<MediaJob> = tx
        .query_row(
            "SELECT j.id,j.event_id,j.job_kind,m.object_key,m.mime_type,m.codec,m.byte_length,\
                    m.sample_rate,m.channels,m.width,m.height,m.sha256,\
                    e.started_at,e.ended_at,e.stream_kind,e.capture_session_id,e.stream_id,e.sequence,e.context_json,j.usage_json,e.audio_role,e.audio_route,e.route_epoch \
             FROM media_processing_jobs j \
             JOIN capture_events e ON e.event_id=j.event_id \
             JOIN media_objects m ON m.event_id=j.event_id \
             WHERE j.processor_version=?1 AND ( \
                 j.state='pending' OR \
                 (j.state='retry_wait' AND j.updated_at<=?2) OR \
                 (j.state='processing' AND j.lease_until<=?2)) \
             ORDER BY j.id LIMIT 1",
            params![PROCESSOR_VERSION, now],
            |row| {
                Ok(MediaJob {
                    id: row.get(0)?,
                    event_id: row.get(1)?,
                    job_kind: row.get(2)?,
                    object_key: row.get(3)?,
                    mime_type: row.get(4)?,
                    codec: row.get(5)?,
                    byte_length: row.get(6)?,
                    sample_rate: row.get(7)?,
                    channels: row.get(8)?,
                    width: row.get(9)?,
                    height: row.get(10)?,
                    sha256: row.get(11)?,
                    started_at: row.get(12)?,
                    ended_at: row.get(13)?,
                    stream_kind: row.get(14)?,
                    capture_session_id: row.get(15)?,
                    stream_id: row.get(16)?,
                    sequence: row.get(17)?,
                    context_json: row.get(18)?,
                    usage_json: row.get(19)?,
                    audio_role: row.get(20)?,
                    audio_route: row.get(21)?,
                    route_epoch: row.get(22)?,
                })
            },
        )
        .optional()?;
    if let Some(job) = &selected {
        let lease_until = isotime::add_seconds(now, 300.0);
        tx.execute(
            "UPDATE media_processing_jobs SET state='processing',attempt_count=attempt_count+1, \
             lease_until=?1,error_code=NULL,updated_at=?2 WHERE id=?3",
            params![lease_until, now, job.id],
        )?;
        tx.execute(
            "UPDATE media_objects SET processing_state='processing' WHERE event_id=?1",
            [&job.event_id],
        )?;
    }
    tx.commit()?;
    Ok(selected)
}

fn pending_work_classes(conn: &Connection, now: &str) -> Result<(bool, bool)> {
    let mut statement = conn.prepare(
        "SELECT j.job_kind FROM media_processing_jobs j \
         WHERE j.processor_version=?1 AND (j.state='pending' OR \
           (j.state='retry_wait' AND j.updated_at<=?2) OR \
           (j.state='processing' AND j.lease_until<=?2)) \
         GROUP BY j.job_kind",
    )?;
    let kinds = statement
        .query_map(params![PROCESSOR_VERSION, now], |row| {
            row.get::<_, String>(0)
        })?
        .collect::<std::result::Result<Vec<_>, _>>()?;
    Ok((
        kinds.iter().any(|kind| kind == "gemini_audio"),
        kinds.iter().any(|kind| kind == "gemini_screen"),
    ))
}

fn lease_work_unit(
    conn: &Connection,
    now: &str,
    class: WorkClass,
) -> Result<Option<MediaWorkUnit>> {
    let tx = conn.unchecked_transaction()?;
    let job_kind = match class {
        WorkClass::Audio => "gemini_audio",
        WorkClass::Screen => "gemini_screen",
    };
    let jobs = {
        let mut statement = tx.prepare(
            "SELECT j.id,j.event_id,j.job_kind,m.object_key,m.mime_type,m.codec,m.byte_length,\
                    m.sample_rate,m.channels,m.width,m.height,m.sha256,\
                    e.started_at,e.ended_at,e.stream_kind,e.capture_session_id,e.stream_id,e.sequence,e.context_json,j.usage_json,e.audio_role,e.audio_route,e.route_epoch \
             FROM media_processing_jobs j \
             JOIN capture_events e ON e.event_id=j.event_id \
             JOIN media_objects m ON m.event_id=j.event_id \
             WHERE j.processor_version=?1 AND j.job_kind=?2 AND ( \
                 j.state='pending' OR \
                 (j.state='retry_wait' AND j.updated_at<=?3) OR \
                 (j.state='processing' AND j.lease_until<=?3)) \
             ORDER BY e.started_at,e.sequence,j.id LIMIT 128",
        )?;
        let rows = statement
            .query_map(params![PROCESSOR_VERSION, job_kind, now], |row| {
                Ok(MediaJob {
                    id: row.get(0)?,
                    event_id: row.get(1)?,
                    job_kind: row.get(2)?,
                    object_key: row.get(3)?,
                    mime_type: row.get(4)?,
                    codec: row.get(5)?,
                    byte_length: row.get(6)?,
                    sample_rate: row.get(7)?,
                    channels: row.get(8)?,
                    width: row.get(9)?,
                    height: row.get(10)?,
                    sha256: row.get(11)?,
                    started_at: row.get(12)?,
                    ended_at: row.get(13)?,
                    stream_kind: row.get(14)?,
                    capture_session_id: row.get(15)?,
                    stream_id: row.get(16)?,
                    sequence: row.get(17)?,
                    context_json: row.get(18)?,
                    usage_json: row.get(19)?,
                    audio_role: row.get(20)?,
                    audio_route: row.get(21)?,
                    route_epoch: row.get(22)?,
                })
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        rows
    };
    if jobs.is_empty() {
        tx.commit()?;
        return Ok(None);
    }
    let candidates = jobs
        .iter()
        .map(MediaJob::planning_event)
        .collect::<Result<Vec<_>>>()?;
    let plan = media_planner::plan_first(&candidates);
    let member_ids = plan.member_job_ids.iter().copied().collect::<HashSet<_>>();
    let selected = jobs
        .into_iter()
        .filter(|job| member_ids.contains(&job.id))
        .collect::<Vec<_>>();
    let mut digest = Sha256::new();
    digest.update(format!("media-work-v1:{class:?}:"));
    for job in &selected {
        digest.update(job.event_id.as_bytes());
        digest.update([0]);
        digest.update(job.sha256.as_bytes());
        digest.update([0]);
    }
    let id = format!("{:x}", digest.finalize());
    let reservation_retained = selected.iter().all(|job| {
        job.usage_json
            .as_deref()
            .and_then(|raw| serde_json::from_str::<Value>(raw).ok())
            .is_some_and(|usage| {
                usage.get("work_unit_id").and_then(Value::as_str) == Some(id.as_str())
                    && usage.get("reservation_state").and_then(Value::as_str) == Some("reserved")
            })
    });
    let lease_until = isotime::add_seconds(now, 300.0);
    let usage_json = json!({
        "work_unit_id": id,
        "work_class": match class { WorkClass::Audio => "audio", WorkClass::Screen => "screen" },
        "member_count": selected.len(),
        "reservation_state": if reservation_retained { "reserved" } else { "planned" },
        "processor_version": PROCESSOR_VERSION,
    })
    .to_string();
    tx.execute(
        "INSERT INTO media_work_units \
         (id,work_class,processor_version,state,started_at,ended_at,reserved_output_tokens,\
          reservation_retained,attempt_count,usage_json) \
         VALUES (?1,?2,?3,'processing',?4,?5,?6,?7,1,?8) \
         ON CONFLICT(id) DO UPDATE SET state='processing',error_code=NULL,\
          reservation_retained=?7,attempt_count=attempt_count+1,usage_json=?8,updated_at=?9",
        params![
            id,
            match class {
                WorkClass::Audio => "audio",
                WorkClass::Screen => "screen",
            },
            PROCESSOR_VERSION,
            isotime::format_epoch_millis(plan.started_ms),
            isotime::format_epoch_millis(plan.ended_ms),
            match class {
                WorkClass::Audio => i64::from(vertex::MAX_MEDIA_OUTPUT_TOKENS),
                WorkClass::Screen => i64::from(vertex::MAX_SCREEN_OUTPUT_TOKENS),
            },
            reservation_retained as i64,
            usage_json,
            now,
        ],
    )?;
    for (ordinal, job) in selected.iter().enumerate() {
        let started_ms = isotime::parse_epoch_millis(&job.started_at)
            .ok_or_else(|| EnclaveError::InvalidRequest("job timestamp is invalid".into()))?;
        let ended_ms = isotime::parse_epoch_millis(&job.ended_at)
            .ok_or_else(|| EnclaveError::InvalidRequest("job timestamp is invalid".into()))?;
        tx.execute(
            "INSERT OR IGNORE INTO media_work_members \
             (work_unit_id,event_id,job_id,ordinal,window_start_ms,window_end_ms) \
             VALUES (?1,?2,?3,?4,?5,?6)",
            params![
                id,
                job.event_id,
                job.id,
                ordinal as i64,
                started_ms - plan.started_ms,
                ended_ms - plan.started_ms,
            ],
        )?;
        tx.execute(
            "UPDATE media_processing_jobs SET state='processing',attempt_count=attempt_count+1, \
             lease_until=?1,error_code=NULL,usage_json=?2,updated_at=?3 WHERE id=?4",
            params![lease_until, usage_json, now, job.id],
        )?;
        tx.execute(
            "UPDATE media_objects SET processing_state='processing' WHERE event_id=?1",
            [&job.event_id],
        )?;
    }
    tx.commit()?;
    Ok(Some(MediaWorkUnit {
        id,
        class,
        jobs: selected,
    }))
}

fn normalized_name(name: &str) -> String {
    name.split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .to_lowercase()
}

fn is_full_name(name: &str) -> bool {
    name.split_whitespace()
        .filter(|part| part.chars().any(char::is_alphabetic))
        .count()
        >= 2
}

fn validate_person_evidence(evidence: &PersonEvidence) -> Result<()> {
    if evidence.name.trim().is_empty()
        || evidence.name.len() > 256
        || evidence.evidence.trim().is_empty()
        || evidence.evidence.len() > 2_000
        || !(0.0..=1.0).contains(&evidence.confidence)
    {
        return Err(EnclaveError::InvalidRequest(
            "screen person evidence is invalid".into(),
        ));
    }
    Ok(())
}

fn create_person(conn: &Connection, name: &str) -> Result<i64> {
    let normalized = normalized_name(name);
    if normalized.is_empty() {
        return Err(EnclaveError::InvalidRequest("person name is empty".into()));
    }
    conn.execute(
        "INSERT INTO people (display_name,normalized_name,status) VALUES (?1,NULL,'identified')",
        [name.trim()],
    )?;
    Ok(conn.last_insert_rowid())
}

struct NameClaim<'a> {
    person_id: Option<i64>,
    name: &'a str,
    source_event_id: &'a str,
    speaker_observation_id: Option<i64>,
    observed_at: &'a str,
    evidence_kind: &'a str,
    evidence_json: String,
    confidence: f64,
    status: &'a str,
}

fn record_name_claim(conn: &Connection, claim: NameClaim<'_>) -> Result<i64> {
    conn.execute(
        "INSERT INTO person_name_claims \
         (person_id,name,normalized_name,source_event_id,speaker_observation_id,observed_at,\
          evidence_kind,evidence_json,confidence,status) \
         VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)",
        params![
            claim.person_id,
            claim.name.trim(),
            normalized_name(claim.name),
            claim.source_event_id,
            claim.speaker_observation_id,
            claim.observed_at,
            claim.evidence_kind,
            claim.evidence_json,
            claim.confidence,
            claim.status,
        ],
    )?;
    Ok(conn.last_insert_rowid())
}

struct FactEvidence<'a> {
    person_id: i64,
    fact: &'a super::media::PersonFact,
    source_event_id: &'a str,
    speaker_observation_id: i64,
    observed_at: &'a str,
    evidence_json: String,
}

fn persist_person_fact(conn: &Connection, evidence: FactEvidence<'_>) -> Result<()> {
    let exact: i64 = conn.query_row(
        "SELECT COUNT(*) FROM person_facts WHERE person_id=?1 AND predicate=?2 \
         AND lower(value)=lower(?3) AND status='active'",
        params![
            evidence.person_id,
            evidence.fact.predicate,
            evidence.fact.value
        ],
        |row| row.get(0),
    )?;
    if exact > 0 {
        return Ok(());
    }
    let temporal_singleton = matches!(
        evidence.fact.predicate.as_str(),
        "role" | "organization" | "location"
    );
    let supersedes_id: Option<i64> = if temporal_singleton {
        conn.query_row(
            "SELECT id FROM person_facts WHERE person_id=?1 AND predicate=?2 AND status='active' \
             ORDER BY COALESCE(observed_at,created_at) DESC,id DESC LIMIT 1",
            params![evidence.person_id, evidence.fact.predicate],
            |row| row.get(0),
        )
        .optional()?
    } else {
        None
    };
    if let Some(previous_id) = supersedes_id {
        conn.execute(
            "UPDATE person_facts SET status='superseded' WHERE id=?1 AND status='active'",
            [previous_id],
        )?;
    }
    conn.execute(
        "INSERT INTO person_facts \
         (person_id,predicate,value,evidence_json,derivation_version,status,supersedes_id,\
          source_event_id,speaker_observation_id,observed_at,literal_evidence,confidence) \
         VALUES (?1,?2,?3,?4,2,'active',?5,?6,?7,?8,?9,1.0)",
        params![
            evidence.person_id,
            evidence.fact.predicate,
            evidence.fact.value,
            evidence.evidence_json,
            supersedes_id,
            evidence.source_event_id,
            evidence.speaker_observation_id,
            evidence.observed_at,
            evidence.fact.evidence,
        ],
    )?;
    Ok(())
}

fn corroborated_active_screen_person(
    conn: &Connection,
    started_at: &str,
    ended_at: &str,
) -> Result<Option<i64>> {
    let window_start = isotime::add_seconds(started_at, -2.0);
    let window_end = isotime::add_seconds(ended_at, 2.0);

    let mut stmt = conn.prepare(
        "SELECT normalized_name, MAX(displayed_name), MIN(observed_at), MAX(observed_at), COUNT(DISTINCT event_id) \
         FROM visual_speaker_observations \
         WHERE highlight_state IN ('active_speaker_box', 'audio_waveform') \
           AND confidence >= 0.90 \
           AND observed_at >= ?1 AND observed_at <= ?2 \
         GROUP BY normalized_name \
         HAVING COUNT(DISTINCT event_id) >= 2 \
         LIMIT 2",
    )?;

    let candidates = stmt
        .query_map(params![window_start, window_end], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, String>(3)?,
                r.get::<_, i64>(4)?,
            ))
        })?
        .collect::<std::result::Result<Vec<_>, _>>()?;

    if candidates.len() != 1 {
        return Ok(None);
    }

    let (norm_name, disp_name, min_at, max_at, _count) = &candidates[0];
    let t_min = isotime::parse_epoch_millis(min_at).unwrap_or(0);
    let t_max = isotime::parse_epoch_millis(max_at).unwrap_or(0);

    // Enforce >= 3.0 seconds temporal separation between frames
    if (t_max - t_min).abs() < 3000 {
        return Ok(None);
    }

    let existing_person: Option<i64> = conn
        .query_row(
            "SELECT person_id FROM person_name_claims \
             WHERE normalized_name = ?1 AND status = 'accepted' AND person_id IS NOT NULL \
             ORDER BY id DESC LIMIT 1",
            [norm_name],
            |r| r.get(0),
        )
        .optional()?;

    let person_id = match existing_person {
        Some(pid) => pid,
        None => create_person(conn, disp_name)?,
    };

    conn.execute(
        "UPDATE person_name_claims SET person_id = ?1, status = 'accepted' \
         WHERE normalized_name = ?2 AND evidence_kind = 'screen_active_speaker' \
           AND observed_at >= ?3 AND observed_at <= ?4",
        params![person_id, norm_name, window_start, window_end],
    )?;

    conn.execute(
        "UPDATE identity_evidence SET person_id = ?1, status = 'accepted' \
         WHERE kind = 'screen_active_speaker' AND lower(trim(claimed_name)) = ?2 \
           AND observed_at >= ?3 AND observed_at <= ?4",
        params![person_id, norm_name, window_start, window_end],
    )?;

    Ok(Some(person_id))
}

/// Returns true when repeated active-speaker visual evidence exists for this
/// exact normalized name around the given interval: at least two distinct
/// frames at high confidence separated by the documented 3-second minimum.
fn visual_corroboration_for_name(
    conn: &Connection,
    normalized: &str,
    started_at: &str,
    ended_at: &str,
) -> Result<bool> {
    let window_start = isotime::add_seconds(started_at, -2.0);
    let window_end = isotime::add_seconds(ended_at, 2.0);
    let row: Option<(Option<String>, Option<String>, i64)> = conn
        .query_row(
            "SELECT MIN(observed_at), MAX(observed_at), COUNT(DISTINCT event_id) \
             FROM visual_speaker_observations \
             WHERE highlight_state IN ('active_speaker_box', 'audio_waveform') \
               AND confidence >= 0.90 \
               AND normalized_name = ?1 \
               AND observed_at >= ?2 AND observed_at <= ?3",
            params![normalized, window_start, window_end],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .optional()?;
    let Some((Some(min_at), Some(max_at), count)) = row else {
        return Ok(false);
    };
    if count < 2 {
        return Ok(false);
    }
    let t_min = isotime::parse_epoch_millis(&min_at).unwrap_or(0);
    let t_max = isotime::parse_epoch_millis(&max_at).unwrap_or(0);
    Ok((t_max - t_min).abs() >= 3000)
}

fn bind_person_to_speaker_observation(
    conn: &Connection,
    speaker_observation_id: i64,
    person_id: i64,
) -> Result<bool> {
    let profile: Option<(i64, Option<i64>)> = conn
        .query_row(
            "SELECT v.id,v.person_id FROM voice_samples s \
             JOIN voice_sample_profile_assignments a ON a.sample_id=s.id AND a.active=1 \
             JOIN voice_profiles v ON v.id=a.profile_id WHERE s.speaker_observation_id=?1 \
             AND s.accepted=1 ORDER BY s.id DESC LIMIT 1",
            [speaker_observation_id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?;
    if let Some((profile_id, existing_person)) = profile {
        if existing_person.is_some_and(|existing| existing != person_id) {
            return Ok(false);
        }
        let op_id = format!("person_bind_obs:{speaker_observation_id}");
        let evidence_json = json!({
            "kind": "speaker_observation_binding",
            "speaker_observation_id": speaker_observation_id
        })
        .to_string();
        crate::cp::identity::bind_profile_to_person(
            conn,
            profile_id,
            person_id,
            &op_id,
            &evidence_json,
            0.99,
        )?;
    }
    conn.execute(
        "UPDATE speaker_observations SET person_id=?1 WHERE id=?2 \
         AND (person_id IS NULL OR person_id=?1)",
        params![person_id, speaker_observation_id],
    )?;
    let (event_id, turn_id): (String, String) = conn.query_row(
        "SELECT event_id,turn_id FROM speaker_observations WHERE id=?1",
        [speaker_observation_id],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    conn.execute(
        "UPDATE utterances SET speaker_label=(SELECT display_name FROM people WHERE id=?1) \
         WHERE source_key=?2",
        params![person_id, format!("cloud-v2:{event_id}:{turn_id}")],
    )?;
    Ok(true)
}

fn promote_screen_name_if_corroborated(
    conn: &Connection,
    observed_at: &str,
    name: &str,
) -> Result<Option<(i64, i64, Option<i64>)>> {
    let window_start = isotime::add_seconds(observed_at, -2.0);
    let window_end = isotime::add_seconds(observed_at, 2.0);

    let mut statement = conn.prepare(
        "SELECT s.id FROM speaker_observations s JOIN capture_events e ON e.event_id=s.event_id \
         WHERE e.stream_kind='system_audio' AND s.overlap=0 \
         AND s.started_at<=?1 AND s.ended_at>=?2 ORDER BY s.id LIMIT 2",
    )?;
    let observations = statement
        .query_map(params![window_end, window_start], |row| {
            row.get::<_, i64>(0)
        })?
        .collect::<std::result::Result<Vec<_>, _>>()?;
    if observations.len() != 1 {
        return Ok(None);
    }
    let observation_id = observations[0];
    let (started_at, ended_at, existing_person): (String, String, Option<i64>) = conn.query_row(
        "SELECT started_at,ended_at,person_id FROM speaker_observations WHERE id=?1",
        [observation_id],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
    )?;
    let normalized = normalized_name(name);
    let obs_window_start = isotime::add_seconds(&started_at, -2.0);
    let obs_window_end = isotime::add_seconds(&ended_at, 2.0);

    let mut frame_stmt = conn.prepare(
        "SELECT MIN(observed_at), MAX(observed_at), COUNT(DISTINCT event_id) \
         FROM visual_speaker_observations \
         WHERE highlight_state IN ('active_speaker_box', 'audio_waveform') \
           AND confidence >= 0.90 \
           AND normalized_name = ?1 \
           AND observed_at >= ?2 AND observed_at <= ?3",
    )?;
    let frame_row = frame_stmt
        .query_row(params![normalized, obs_window_start, obs_window_end], |r| {
            Ok((
                r.get::<_, Option<String>>(0)?,
                r.get::<_, Option<String>>(1)?,
                r.get::<_, i64>(2)?,
            ))
        })
        .optional()?;

    let Some((Some(min_at), Some(max_at), count)) = frame_row else {
        return Ok(None);
    };

    if count < 2 {
        return Ok(None);
    }

    let t_min = isotime::parse_epoch_millis(&min_at).unwrap_or(0);
    let t_max = isotime::parse_epoch_millis(&max_at).unwrap_or(0);

    // Enforce >= 3.0 seconds temporal separation between frames
    if (t_max - t_min).abs() < 3000 {
        return Ok(None);
    }

    let person_id = match existing_person {
        Some(person_id) => person_id,
        None => create_person(conn, name)?,
    };
    conn.execute(
        "UPDATE person_name_claims SET person_id=?1,status='accepted' \
         WHERE normalized_name=?2 AND evidence_kind='screen_active_speaker' \
         AND observed_at>=?3 AND observed_at<=?4 AND status IN ('proposed','probationary')",
        params![person_id, normalized, obs_window_start, obs_window_end],
    )?;
    conn.execute(
        "UPDATE identity_evidence SET person_id=?1,status='accepted',speaker_observation_id=?2 \
         WHERE kind='screen_active_speaker' AND lower(trim(claimed_name))=?3 \
         AND observed_at>=?4 AND observed_at<=?5 AND status='proposed'",
        params![
            person_id,
            observation_id,
            normalized,
            obs_window_start,
            obs_window_end
        ],
    )?;
    let _ = bind_person_to_speaker_observation(conn, observation_id, person_id)?;
    let voice_profile_id: Option<i64> = conn
        .query_row(
            "SELECT a.profile_id FROM voice_samples s \
             JOIN voice_sample_profile_assignments a ON a.sample_id=s.id AND a.active=1 \
             WHERE s.speaker_observation_id=?1 AND s.accepted=1 ORDER BY s.id DESC LIMIT 1",
            [observation_id],
            |row| row.get(0),
        )
        .optional()?;
    if let Some(profile_id) = voice_profile_id {
        let op_id = format!("corroborated_screen:{observation_id}");
        let evidence_json = json!({
            "kind": "repeated_active_speaker_frames",
            "speaker_observation_id": observation_id
        })
        .to_string();
        crate::cp::identity::bind_profile_to_person(
            conn,
            profile_id,
            person_id,
            &op_id,
            &evidence_json,
            0.99,
        )?;
    }

    conn.execute(
        "UPDATE speaker_observations SET direct_evidence_id = ( \
             SELECT id FROM identity_evidence WHERE speaker_observation_id = ?1 AND status = 'accepted' ORDER BY id DESC LIMIT 1 \
         ) WHERE id = ?1",
        [observation_id],
    )?;
    conn.execute(
        "UPDATE speaker_clusters SET person_id = ?1, attribution_state = 'person_bound', \
         updated_at = strftime('%Y-%m-%dT%H:%M:%fZ','now') \
         WHERE id = (SELECT cluster_id FROM speaker_observations WHERE id = ?2)",
        params![person_id, observation_id],
    )?;

    if let Some(profile_id) = voice_profile_id {
        crate::cp::identity::queue_episode_identity_refresh_for_profile(conn, profile_id)?;
    }

    Ok(Some((person_id, observation_id, voice_profile_id)))
}

fn persist_audio_window_result(
    conn: &Connection,
    work_unit_id: &str,
    jobs: &[MediaJob],
    sources: &[SourceInterval],
    turns: &[AudioTurn],
    voiceprints: &[super::voice_memory::EmbeddedTurn],
) -> Result<()> {
    let job = jobs
        .first()
        .ok_or_else(|| EnclaveError::InvalidRequest("audio window has no jobs".into()))?;
    let tx = conn.unchecked_transaction()?;
    let window_started_at = jobs
        .iter()
        .min_by_key(|job| &job.started_at)
        .map(|job| job.started_at.clone())
        .ok_or_else(|| EnclaveError::InvalidRequest("audio window has no start".into()))?;
    let window_ended_at = jobs
        .iter()
        .max_by_key(|job| &job.ended_at)
        .map(|job| job.ended_at.clone())
        .ok_or_else(|| EnclaveError::InvalidRequest("audio window has no end".into()))?;
    let duration_ms = isotime::parse_epoch_millis(&window_ended_at)
        .zip(isotime::parse_epoch_millis(&window_started_at))
        .map(|(end, start)| end - start)
        .ok_or_else(|| EnclaveError::InvalidRequest("window timestamps are invalid".into()))?;

    tx.execute(
        "INSERT INTO media_work_units \
         (id, work_class, processor_version, state, started_at, ended_at, reserved_output_tokens) \
         VALUES (?1, 'audio', 1, 'processing', ?2, ?3, 1024) \
         ON CONFLICT(id) DO NOTHING",
        params![work_unit_id, window_started_at, window_ended_at],
    )?;
    for (idx, job) in jobs.iter().enumerate() {
        tx.execute(
            "INSERT INTO media_work_members \
             (work_unit_id, event_id, job_id, ordinal, window_start_ms, window_end_ms) \
             VALUES (?1, ?2, ?3, ?4, 0, ?5) \
             ON CONFLICT(work_unit_id, event_id) DO NOTHING",
            params![work_unit_id, job.event_id, job.id, idx as i64, duration_ms],
        )?;
    }

    tx.execute(
        "INSERT INTO audio_segments \
         (started_at,ended_at,duration_seconds,source_type,audio_format,transcription_status) \
         VALUES (?1,?2,?3,?4,?5,'done')",
        params![
            window_started_at,
            window_ended_at,
            duration_ms as f64 / 1000.0,
            if job.stream_kind == "system_audio" {
                "system"
            } else {
                "mic"
            },
            "audio/wav"
        ],
    )?;
    let segment_id = tx.last_insert_rowid();
    let distinct_speakers = turns
        .iter()
        .map(|t| &t.speaker_local_id)
        .collect::<std::collections::HashSet<_>>()
        .len();

    struct TurnMeta {
        turn_id: String,
        started_at: String,
        ended_at: String,
        speaker_observation_id: i64,
        cluster_id: i64,
        embedding_job_id: i64,
        anchor_event_id: String,
        projected: Vec<super::media_planner::ProjectedInterval>,
    }

    let mut turn_metas = Vec::new();
    let mut turn_obs_map: std::collections::HashMap<String, (i64, i64, String, String, String)> =
        std::collections::HashMap::new();

    for turn in turns {
        let projected = media_planner::project_interval(sources, turn.start_ms, turn.end_ms);
        let anchor = projected.first().ok_or_else(|| {
            EnclaveError::InvalidRequest("audio turn falls outside every source event".into())
        })?;
        let anchor_job = jobs
            .iter()
            .find(|candidate| candidate.event_id == anchor.event_id)
            .ok_or_else(|| {
                EnclaveError::InvalidRequest("audio source mapping is invalid".into())
            })?;
        let turn_started_at =
            isotime::add_seconds(&window_started_at, turn.start_ms as f64 / 1000.0);
        let turn_ended_at = isotime::add_seconds(&window_started_at, turn.end_ms as f64 / 1000.0);

        let initial_attribution_state = if job.audio_role.as_deref() == Some("local_transmit")
            || job.stream_kind == "local_transmit"
        {
            if distinct_speakers <= 1 {
                "owner_transmit"
            } else {
                "request_local"
            }
        } else {
            "request_local"
        };

        let cluster_id: i64 =
            {
                tx.execute(
                "INSERT INTO speaker_clusters (work_unit_id, speaker_local_id, attribution_state) \
                 VALUES (?1, ?2, ?3) \
                 ON CONFLICT(work_unit_id, speaker_local_id) DO NOTHING",
                params![work_unit_id, turn.speaker_local_id, initial_attribution_state],
            )?;
                tx.query_row(
                "SELECT id FROM speaker_clusters WHERE work_unit_id = ?1 AND speaker_local_id = ?2",
                params![work_unit_id, turn.speaker_local_id],
                |r| r.get(0),
            )?
            };

        tx.execute(
            "INSERT INTO speaker_observations \
             (event_id,turn_id,speaker_local_id,started_at,ended_at,transcript_text,language,overlap,cluster_id) \
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9)",
            params![
                anchor_job.event_id,
                turn.turn_id,
                turn.speaker_local_id,
                turn_started_at,
                turn_ended_at,
                turn.text,
                turn.language,
                turn.overlap as i64,
                cluster_id
            ],
        )?;
        let speaker_observation_id = tx.last_insert_rowid();
        for source in &projected {
            tx.execute(
                "INSERT INTO speaker_observation_sources \
                 (speaker_observation_id,event_id,window_start_ms,window_end_ms,event_start_ms,event_end_ms) \
                 VALUES (?1,?2,?3,?4,?5,?6)",
                params![
                    speaker_observation_id,
                    source.event_id,
                    source.window_start_ms,
                    source.window_end_ms,
                    source.event_start_ms,
                    source.event_end_ms,
                ],
            )?;
        }
        let embedding_job_id =
            super::voice_memory::enqueue_embedding_job(&tx, speaker_observation_id)?;

        turn_obs_map.insert(
            turn.turn_id.clone(),
            (
                speaker_observation_id,
                cluster_id,
                turn_started_at.clone(),
                turn_ended_at.clone(),
                turn.speaker_local_id.clone(),
            ),
        );

        turn_metas.push(TurnMeta {
            turn_id: turn.turn_id.clone(),
            started_at: turn_started_at,
            ended_at: turn_ended_at,
            speaker_observation_id,
            cluster_id,
            embedding_job_id,
            anchor_event_id: anchor_job.event_id.clone(),
            projected,
        });
    }

    let mut cluster_person_map: std::collections::HashMap<String, i64> =
        std::collections::HashMap::new();
    let mut turn_person_map: std::collections::HashMap<String, i64> =
        std::collections::HashMap::new();

    // Pass 1a: Resolve self-identifications
    for turn in turns {
        if turn.speaker_name_kind.as_deref() == Some("self_identification")
            && turn.speaker_name_subject_turn_id.as_deref() == Some(turn.turn_id.as_str())
        {
            if let (Some(name), Some(confidence)) =
                (turn.speaker_name.as_deref(), turn.speaker_name_confidence)
            {
                if confidence >= 0.90 {
                    let voice_candidate = voiceprints
                        .iter()
                        .find(|candidate| candidate.turn_id == turn.turn_id);
                    let matched = voice_candidate
                        .and_then(|candidate| candidate.embedding.as_deref())
                        .map(|embedding| {
                            super::voice_memory::match_existing_person(
                                &tx,
                                embedding,
                                &job.acoustic_domain(),
                            )
                        })
                        .transpose()?
                        .flatten()
                        .filter(|person_id| {
                            tx.query_row(
                                "SELECT COUNT(*)=0 OR SUM(normalized_name=?1)>0 FROM person_name_claims \
                                 WHERE person_id=?2 AND status='accepted'",
                                params![normalized_name(name), person_id],
                                |row| row.get::<_, bool>(0),
                            )
                            .unwrap_or(false)
                        });
                    let pid = match matched {
                        Some(p) => p,
                        None => create_person(&tx, name)?,
                    };
                    cluster_person_map.insert(turn.speaker_local_id.clone(), pid);
                    turn_person_map.insert(turn.turn_id.clone(), pid);

                    let anchor_event_id = turn_metas
                        .iter()
                        .find(|m| m.turn_id == turn.turn_id)
                        .map(|m| m.anchor_event_id.as_str())
                        .unwrap_or("");
                    let meta = turn_metas.iter().find(|m| m.turn_id == turn.turn_id);
                    if let Some(m) = meta {
                        let evidence = turn.speaker_name_evidence.as_deref().unwrap_or("");
                        let evidence_json = json!({"work_unit_id":work_unit_id,"event_id":anchor_event_id,"turn_id":turn.turn_id,"evidence":evidence}).to_string();
                        tx.execute(
                            "INSERT INTO identity_evidence \
                             (person_id,source_event_id,observed_at,speaker_observation_id,kind, \
                              claimed_name,evidence_json,score,status) \
                             VALUES (?1,?2,?3,?4,'audio_self_identification',?5,?6,?7,'accepted')",
                            params![
                                pid,
                                anchor_event_id,
                                m.started_at,
                                m.speaker_observation_id,
                                name,
                                evidence_json,
                                confidence
                            ],
                        )?;
                        let ev_id = tx.last_insert_rowid();
                        tx.execute(
                            "UPDATE speaker_observations SET direct_evidence_id = ?1 WHERE id = ?2",
                            params![ev_id, m.speaker_observation_id],
                        )?;
                        record_name_claim(
                            &tx,
                            NameClaim {
                                person_id: Some(pid),
                                name,
                                source_event_id: anchor_event_id,
                                speaker_observation_id: Some(m.speaker_observation_id),
                                observed_at: &m.started_at,
                                evidence_kind: "audio_self_identification",
                                evidence_json,
                                confidence,
                                status: "accepted",
                            },
                        )?;
                    }
                }
            }
        }
    }

    // Pass 1b: Resolve vocative addresses with safe corroboration.
    //
    // A vocative alone is never sufficient for a permanent biometric binding.
    // Permanent acceptance requires independent corroboration:
    //   (a) repeated active-speaker visual evidence for the SAME name around the
    //       addressed turn (>= 2 distinct frames >= 3 s apart, confidence >= 0.90), or
    //   (b) the addressed voice biometrically matching an existing person whose
    //       accepted name claims already include the spoken name.
    // Ordinary conversational exchange (two speakers taking turns) is NOT
    // corroboration. Self-referential, ambiguous, distant (> 8 s), overlapping,
    // and third-party cases abstain and are recorded only as proposed evidence.
    for turn in turns {
        if turn.speaker_name_kind.as_deref() != Some("vocative_address") {
            continue;
        }
        let (Some(name), Some(confidence), Some(evidence)) = (
            turn.speaker_name.as_deref(),
            turn.speaker_name_confidence,
            turn.speaker_name_evidence.as_deref(),
        ) else {
            continue;
        };

        // Explicit target ids must exist in the same work unit; the fallback
        // operates only when exactly two distinct speaker clusters are present
        // and picks the temporally nearest turn by the other speaker.
        let target_turn = if let Some(target_id) = turn.speaker_name_target_turn_id.as_deref() {
            turns.iter().find(|t| t.turn_id == target_id)
        } else if distinct_speakers == 2 {
            turns
                .iter()
                .filter(|t| t.speaker_local_id != turn.speaker_local_id)
                .min_by_key(|t| (t.start_ms - turn.start_ms).abs())
        } else {
            None
        };

        let target_is_valid = !turn.overlap
            && target_turn.is_some_and(|t| {
                t.speaker_local_id != turn.speaker_local_id
                    && (t.start_ms - turn.start_ms).abs() <= 8000
                    && !t.overlap
            });

        let target_info = if target_is_valid {
            let target_id = target_turn.map(|t| t.turn_id.as_str()).unwrap_or("");
            turn_obs_map.get(target_id).cloned()
        } else {
            None
        };

        let anchor_event_id = turn_metas
            .iter()
            .find(|m| m.turn_id == turn.turn_id)
            .map(|m| m.anchor_event_id.as_str())
            .unwrap_or("");

        let evidence_json = json!({
            "work_unit_id": work_unit_id,
            "event_id": anchor_event_id,
            "turn_id": turn.turn_id,
            "target_turn_id": target_turn.map(|t| t.turn_id.as_str()),
            "evidence": evidence
        })
        .to_string();

        let Some((
            target_obs_id,
            target_cluster_id,
            target_started_at,
            target_ended_at,
            target_speaker_local_id,
        )) = target_info
        else {
            // Invalid, self-referential, distant, overlapping, or ambiguous
            // target: abstain. Record only a proposed evidence row.
            let first_started_at = turn_metas
                .first()
                .map(|m| m.started_at.as_str())
                .unwrap_or("");
            let first_obs_id = turn_metas
                .first()
                .map(|m| m.speaker_observation_id)
                .unwrap_or(0);
            tx.execute(
                "INSERT INTO identity_evidence \
                 (person_id,source_event_id,observed_at,speaker_observation_id,kind, \
                  claimed_name,evidence_json,score,status) \
                 VALUES (NULL,?1,?2,?3,'spoken_vocative_address',?4,?5,?6,'proposed')",
                params![
                    anchor_event_id,
                    first_started_at,
                    first_obs_id,
                    name,
                    evidence_json,
                    confidence
                ],
            )?;
            continue;
        };

        let normalized = normalized_name(name);

        // (a) Name-matched repeated active-speaker visual corroboration.
        let visual_corroborated = confidence >= 0.85
            && visual_corroboration_for_name(
                &tx,
                &normalized,
                &target_started_at,
                &target_ended_at,
            )?;

        // (b) The addressed voice matches an existing person already carrying
        // this exact accepted name (validated self-identification history).
        let target_turn_id_str = target_turn.map(|t| t.turn_id.as_str()).unwrap_or("");
        let voice_matched_person: Option<i64> = if confidence >= 0.85 {
            voiceprints
                .iter()
                .find(|vp| vp.turn_id == target_turn_id_str)
                .and_then(|candidate| candidate.embedding.as_deref())
                .map(|embedding| {
                    super::voice_memory::match_existing_person(
                        &tx,
                        embedding,
                        &job.acoustic_domain(),
                    )
                })
                .transpose()?
                .flatten()
                .filter(|person_id| {
                    tx.query_row(
                        "SELECT COUNT(*) > 0 FROM person_name_claims \
                         WHERE person_id = ?1 AND status = 'accepted' AND normalized_name = ?2",
                        params![person_id, normalized],
                        |row| row.get::<_, bool>(0),
                    )
                    .unwrap_or(false)
                })
        } else {
            None
        };

        let vocative_person_id = if let Some(matched) = voice_matched_person {
            Some(matched)
        } else if visual_corroborated {
            // Reuse the person already accepted under this exact name if one
            // exists; repeated Frankie evidence must never fork duplicates.
            let existing: Option<i64> = tx
                .query_row(
                    "SELECT person_id FROM person_name_claims \
                     WHERE normalized_name = ?1 AND status = 'accepted' AND person_id IS NOT NULL \
                     ORDER BY id DESC LIMIT 1",
                    [&normalized],
                    |r| r.get(0),
                )
                .optional()?;
            Some(match existing {
                Some(pid) => pid,
                None => create_person(&tx, name)?,
            })
        } else {
            None
        };

        // Binding must remain conflict-safe: if the addressed observation's
        // profile is already accepted for a different person, abstain here and
        // leave the accepted edge untouched.
        let bound = match vocative_person_id {
            Some(pid) => bind_person_to_speaker_observation(&tx, target_obs_id, pid)?,
            None => false,
        };

        let accepted = vocative_person_id.is_some() && bound;
        let status = if accepted { "accepted" } else { "proposed" };
        let recorded_person = if accepted { vocative_person_id } else { None };

        tx.execute(
            "INSERT INTO identity_evidence \
             (person_id,source_event_id,observed_at,speaker_observation_id,kind, \
              claimed_name,evidence_json,score,status) \
             VALUES (?1,?2,?3,?4,'spoken_vocative_address',?5,?6,?7,?8)",
            params![
                recorded_person,
                anchor_event_id,
                target_started_at,
                target_obs_id,
                name,
                evidence_json,
                confidence,
                status
            ],
        )?;
        let ev_id = tx.last_insert_rowid();

        if accepted {
            let vocative_pid = vocative_person_id.expect("accepted implies person");
            cluster_person_map.insert(target_speaker_local_id, vocative_pid);
            if let Some(t) = target_turn {
                turn_person_map.insert(t.turn_id.clone(), vocative_pid);
            }

            tx.execute(
                "UPDATE speaker_observations SET direct_evidence_id = ?1 WHERE id = ?2",
                params![ev_id, target_obs_id],
            )?;
            record_name_claim(
                &tx,
                NameClaim {
                    person_id: Some(vocative_pid),
                    name,
                    source_event_id: anchor_event_id,
                    speaker_observation_id: Some(target_obs_id),
                    observed_at: &target_started_at,
                    evidence_kind: "spoken_vocative_address",
                    evidence_json: json!({"work_unit_id":work_unit_id,"turn_id":turn.turn_id,"evidence":evidence}).to_string(),
                    confidence,
                    status: "accepted",
                },
            )?;
            tx.execute(
                "UPDATE speaker_clusters SET person_id = COALESCE(?1, person_id), attribution_state = 'person_bound', \
                 updated_at = strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE id = ?2",
                params![vocative_pid, target_cluster_id],
            )?;
        }
    }

    for (i, turn) in turns.iter().enumerate() {
        let meta = &turn_metas[i];
        let speaker_observation_id = meta.speaker_observation_id;
        let cluster_id = meta.cluster_id;
        let turn_started_at = &meta.started_at;
        let turn_ended_at = &meta.ended_at;
        let projected = &meta.projected;
        let embedding_job_id = meta.embedding_job_id;
        let anchor_event_id = &meta.anchor_event_id;

        let turn_person_id = turn_person_map.get(&turn.turn_id).copied();
        let cluster_person_id = cluster_person_map.get(&turn.speaker_local_id).copied();
        let screen_person_id = if turn_person_id.is_none()
            && cluster_person_id.is_none()
            && job.stream_kind == "system_audio"
            && !turn.overlap
        {
            corroborated_active_screen_person(&tx, turn_started_at, turn_ended_at)?
        } else {
            None
        };
        let evidence_person_id = turn_person_id.or(cluster_person_id).or(screen_person_id);

        let voice_candidate = voiceprints
            .iter()
            .find(|candidate| candidate.turn_id == turn.turn_id);

        let _voice_label = voice_candidate
            .map(|candidate| {
                let res = super::voice_memory::match_and_store_candidate(
                    &tx,
                    speaker_observation_id,
                    candidate,
                    &job.acoustic_domain(),
                    evidence_person_id,
                    Some(embedding_job_id),
                );
                // The job may be marked ready only after a sample was actually
                // persisted. A candidate whose embedding extraction failed
                // (embedding = None) stores no sample and must stay 'pending'
                // so the durable background worker reconstructs it.
                if res.is_ok() {
                    let _ = tx.execute(
                        "UPDATE voice_embedding_jobs \
                         SET state = 'ready', updated_at = strftime('%Y-%m-%dT%H:%M:%fZ','now') \
                         WHERE id = ?1 AND EXISTS ( \
                             SELECT 1 FROM voice_samples WHERE speaker_observation_id = ?2 \
                         )",
                        params![embedding_job_id, speaker_observation_id],
                    );
                }
                res
            })
            .transpose()?
            .flatten();
        let voice_binding: Option<(i64, Option<i64>)> = tx
            .query_row(
                "SELECT v.id,v.person_id FROM voice_samples s \
                 JOIN voice_sample_profile_assignments a ON a.sample_id=s.id AND a.active=1 \
                 JOIN voice_profiles v ON v.id=a.profile_id \
                 WHERE s.speaker_observation_id=?1 AND s.accepted=1 \
                 ORDER BY s.id DESC LIMIT 1",
                [speaker_observation_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;

        let voice_person_id = voice_binding.and_then(|(_, pid)| pid);
        let person_id = evidence_person_id.or(voice_person_id);

        let cluster_profile: Option<(Option<i64>, String)> = tx
            .query_row(
                "SELECT voice_profile_id, attribution_state FROM speaker_clusters WHERE id = ?1",
                [cluster_id],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;

        if let Some((voice_profile_id, voice_person)) = voice_binding {
            let existing_vp = cluster_profile.as_ref().and_then(|(vp, _)| *vp);
            let existing_state = cluster_profile.as_ref().map(|(_, s)| s.as_str());

            // Never overwrite a cluster that was already demoted to 'unsegmented' due to
            // conflicting profiles — doing so would erase the conflict signal.
            if existing_state == Some("unsegmented") {
                // Leave the cluster as-is; subsequent turns do not re-promote it.
            } else if let Some(existing_vp_id) = existing_vp {
                if existing_vp_id != voice_profile_id {
                    tx.execute(
                        "UPDATE speaker_clusters SET voice_profile_id = NULL, attribution_state = 'unsegmented', \
                         updated_at = strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE id = ?1",
                        [cluster_id],
                    )?;
                }
            } else {
                let state = if voice_person.is_some() || evidence_person_id.is_some() {
                    "person_bound"
                } else {
                    "anonymous_profile"
                };
                tx.execute(
                    "UPDATE speaker_clusters SET voice_profile_id = ?1, person_id = COALESCE(?2, person_id), \
                     attribution_state = ?3, updated_at = strftime('%Y-%m-%dT%H:%M:%fZ','now') \
                     WHERE id = ?4",
                    params![
                        voice_profile_id,
                        evidence_person_id.or(voice_person),
                        state,
                        cluster_id
                    ],
                )?;
            }
        }

        if let (Some(effective_person_id), Some((voice_profile_id, _))) =
            (evidence_person_id, voice_binding)
        {
            let op_id = format!("person_binding:{speaker_observation_id}");
            let evidence_json = json!({
                "kind": "direct_audio_or_screen_identification",
                "speaker_observation_id": speaker_observation_id
            })
            .to_string();
            crate::cp::identity::bind_profile_to_person(
                &tx,
                voice_profile_id,
                effective_person_id,
                &op_id,
                &evidence_json,
                0.99,
            )?;
        }

        let attribution =
            crate::cp::identity::resolve_speaker_attribution(&tx, speaker_observation_id, None)?;
        let speaker_label = attribution.display_label;
        let source_key = format!("cloud-v2:{}:{}", anchor_event_id, turn.turn_id);
        tx.execute(
            "INSERT INTO utterances \
             (audio_segment_id,start_offset_seconds,end_offset_seconds,text,language,confidence, \
              speaker_label,source_key,speaker_observation_id) VALUES (?1,?2,?3,?4,?5,NULL,?6,?7,?8)",
            params![
                segment_id,
                turn.start_ms as f64 / 1000.0,
                turn.end_ms as f64 / 1000.0,
                turn.text,
                turn.language,
                speaker_label,
                source_key,
                speaker_observation_id
            ],
        )?;
        if let Some(person_id) = person_id {
            let _ = bind_person_to_speaker_observation(&tx, speaker_observation_id, person_id)?;
        }
        if let Some(person_id) = person_id {
            for fact in &turn.person_facts {
                let evidence_json = json!({"work_unit_id":work_unit_id,"event_id":anchor_event_id,"source_event_ids":projected.iter().map(|source| &source.event_id).collect::<Vec<_>>(),"turn_id":turn.turn_id,"evidence":fact.evidence}).to_string();
                persist_person_fact(
                    &tx,
                    FactEvidence {
                        person_id,
                        fact,
                        source_event_id: anchor_event_id,
                        speaker_observation_id,
                        observed_at: turn_started_at,
                        evidence_json,
                    },
                )?;
            }
        }
    }
    super::media::reconcile_request_local_speaker_labels(&tx, Some(work_unit_id))?;
    // Job states changed in this transaction (new pending jobs, some settled).
    // Episodes are usually created later by segmentation — which derives its own
    // status — but replayed windows may already have episode members, so
    // recalculate the shared projection for every affected episode here too.
    super::voice_memory::recalculate_all_episode_speaker_processing_status(&tx)?;
    for job in jobs {
        mark_succeeded(&tx, job)?;
    }
    tx.execute(
        "UPDATE media_work_units SET state='succeeded',error_code=NULL,updated_at=?1 WHERE id=?2",
        params![now_iso(), work_unit_id],
    )?;
    tx.commit()?;
    Ok(())
}

#[cfg(test)]
fn persist_audio_result(
    conn: &Connection,
    job: &MediaJob,
    turns: &[AudioTurn],
    voiceprints: &[super::voice_memory::EmbeddedTurn],
) -> Result<()> {
    let duration_ms = isotime::parse_epoch_millis(&job.ended_at)
        .zip(isotime::parse_epoch_millis(&job.started_at))
        .map(|(end, start)| end - start)
        .ok_or_else(|| EnclaveError::InvalidRequest("job timestamps are invalid".into()))?;
    persist_audio_window_result(
        conn,
        &format!("single-{}", job.event_id),
        std::slice::from_ref(job),
        &[SourceInterval::new(&job.event_id, 0, duration_ms)],
        turns,
        voiceprints,
    )
}

fn persist_screen_result_body(
    conn: &Connection,
    job: &MediaJob,
    result: &ScreenResult,
) -> Result<()> {
    if result.literal_description.is_empty()
        || result.literal_description.len() > 20_000
        || result.visible_text.len() > 100_000
        || result.salient_text.len() > 20_000
        || result.people.len() > 100
    {
        return Err(EnclaveError::InvalidRequest(
            "screen result is outside allowed bounds".into(),
        ));
    }
    for evidence in &result.people {
        validate_person_evidence(evidence)?;
    }
    let context: Value = job
        .context_json
        .as_deref()
        .map(serde_json::from_str)
        .transpose()?
        .unwrap_or_else(|| json!({}));
    conn.execute(
        "INSERT INTO screenshots \
         (captured_at,active_app,window_title,ocr_text,salient_ocr_text,url,image_hash,source_key, \
          display_id,capture_context_version,capture_status,primary_bundle_id,primary_window_id, \
          visible_windows_json,visible_windows_truncated) \
         VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,2,?10,?11,?12,?13,?14)",
        params![
            job.started_at,
            context.get("active_app").and_then(Value::as_str),
            context.get("window_title").and_then(Value::as_str),
            result.visible_text,
            result.salient_text,
            context.get("active_url").and_then(Value::as_str),
            job.sha256,
            format!("cloud-v2:{}", job.event_id),
            context.get("display_id").and_then(Value::as_i64),
            context.get("capture_status").and_then(Value::as_str),
            context.get("primary_bundle_id").and_then(Value::as_str),
            context.get("primary_window_id").and_then(Value::as_i64),
            context.get("visible_windows").map(Value::to_string),
            context
                .get("visible_windows_truncated")
                .and_then(Value::as_bool)
                .unwrap_or(false) as i64
        ],
    )?;
    let screenshot_id = conn.last_insert_rowid();
    conn.execute(
        "INSERT INTO screen_observations \
         (screenshot_id,input_revision,observation_version,status,generation_method, \
          literal_description,screen_state,content_type,visible_text_summary,notable_items_json, \
          model_name,prompt_version) \
         VALUES (?1,?2,2,'ready','gemini_pixels',?3,?4,?5,?6,'[]',?7,?8)",
        params![
            screenshot_id,
            job.sha256,
            result.literal_description,
            result.screen_state,
            result.content_type,
            result.salient_text,
            "gemini-3.5-flash",
            PROMPT_VERSION
        ],
    )?;
    for evidence in &result.people {
        let strong_complete_name = evidence.confidence >= 0.90 && is_full_name(&evidence.name);
        let evidence_kind = if evidence.is_active_speaker {
            "screen_active_speaker"
        } else {
            "screen_visible_name"
        };
        let highlight_state = if evidence.is_active_speaker {
            "active_speaker_box"
        } else {
            "none"
        };
        let evidence_json = json!({"event_id":job.event_id,"screenshot_id":screenshot_id,"evidence":evidence.evidence}).to_string();
        conn.execute(
            "INSERT INTO visual_speaker_observations \
             (event_id, screenshot_id, observed_at, platform, displayed_name, normalized_name, \
              highlight_state, bounding_box_json, model_version, confidence) \
             VALUES (?1, ?2, ?3, 'screen_capture', ?4, ?5, ?6, ?7, 1, ?8)",
            params![
                job.event_id,
                screenshot_id,
                job.started_at,
                evidence.name,
                normalized_name(&evidence.name),
                highlight_state,
                evidence_json,
                evidence.confidence,
            ],
        )?;
        conn.execute(
            "INSERT INTO identity_evidence \
             (person_id,source_event_id,observed_at,kind,claimed_name,evidence_json,score,status) \
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8)",
            params![
                Option::<i64>::None,
                job.event_id,
                job.started_at,
                evidence_kind,
                evidence.name,
                evidence_json,
                evidence.confidence,
                "proposed"
            ],
        )?;
        let evidence_id = conn.last_insert_rowid();
        if strong_complete_name {
            record_name_claim(
                conn,
                NameClaim {
                    person_id: None,
                    name: &evidence.name,
                    source_event_id: &job.event_id,
                    speaker_observation_id: None,
                    observed_at: &job.started_at,
                    evidence_kind,
                    evidence_json: json!({"event_id":job.event_id,"screenshot_id":screenshot_id,"evidence":evidence.evidence}).to_string(),
                    confidence: evidence.confidence,
                    status: if evidence.is_active_speaker {
                        "probationary"
                    } else {
                        "proposed"
                    },
                },
            )?;
        }
        if strong_complete_name && evidence.is_active_speaker {
            if let Some((person_id, observation_id, voice_profile_id)) =
                promote_screen_name_if_corroborated(conn, &job.started_at, &evidence.name)?
            {
                conn.execute(
                    "UPDATE identity_evidence SET person_id=?1,speaker_observation_id=?2,\
                     voice_profile_id=?3,status='accepted' WHERE id=?4",
                    params![person_id, observation_id, voice_profile_id, evidence_id],
                )?;
            }
        }
    }
    Ok(())
}

#[cfg(test)]
fn persist_screen_result(conn: &Connection, job: &MediaJob, result: &ScreenResult) -> Result<()> {
    let tx = conn.unchecked_transaction()?;
    persist_screen_result_body(&tx, job, result)?;
    mark_succeeded(&tx, job)?;
    tx.commit()?;
    Ok(())
}

fn persist_storyboard_results(
    conn: &Connection,
    work_unit_id: &str,
    jobs: &[MediaJob],
    results: Vec<(String, ScreenResult)>,
) -> Result<()> {
    let tx = conn.unchecked_transaction()?;
    let mut results = results
        .into_iter()
        .collect::<std::collections::HashMap<_, _>>();
    for job in jobs {
        let result = results.remove(&job.event_id).ok_or_else(|| {
            EnclaveError::InvalidRequest("storyboard persistence is missing a frame".into())
        })?;
        persist_screen_result_body(&tx, job, &result)?;
        mark_succeeded(&tx, job)?;
    }
    if !results.is_empty() {
        return Err(EnclaveError::InvalidRequest(
            "storyboard persistence has an unknown frame".into(),
        ));
    }
    tx.execute(
        "UPDATE media_work_units SET state='succeeded',error_code=NULL,updated_at=?1 WHERE id=?2",
        params![now_iso(), work_unit_id],
    )?;
    tx.commit()?;
    Ok(())
}

fn mark_succeeded(conn: &Connection, job: &MediaJob) -> Result<()> {
    conn.execute(
        "UPDATE media_processing_jobs SET state='succeeded',lease_until=NULL,error_code=NULL, \
         model_id=?1,prompt_version=?2,schema_version=2,updated_at=?3 WHERE id=?4",
        params!["gemini-3.5-flash", PROMPT_VERSION, now_iso(), job.id],
    )?;
    conn.execute(
        "UPDATE media_objects SET processing_state='ready' WHERE event_id=?1",
        [&job.event_id],
    )?;
    Ok(())
}

fn mark_failed(conn: &Connection, job_id: i64, error_code: &str, now: &str) -> Result<()> {
    let attempts: i64 = conn.query_row(
        "SELECT attempt_count FROM media_processing_jobs WHERE id=?1",
        [job_id],
        |row| row.get(0),
    )?;
    let terminal = attempts >= MAX_ATTEMPTS;
    let retry_at = isotime::add_seconds(now, (30_i64 * (1_i64 << attempts.min(6))) as f64);
    conn.execute(
        "UPDATE media_processing_jobs SET state=?1,lease_until=NULL,error_code=?2,updated_at=?3 \
         WHERE id=?4",
        params![
            if terminal {
                "failed_terminal"
            } else {
                "retry_wait"
            },
            error_code,
            if terminal { now } else { &retry_at },
            job_id
        ],
    )?;
    conn.execute(
        "UPDATE media_objects SET processing_state=?1 WHERE event_id=( \
         SELECT event_id FROM media_processing_jobs WHERE id=?2)",
        params![if terminal { "failed" } else { "retry_wait" }, job_id],
    )?;
    Ok(())
}

/// True when [from, to) still contains capture media whose processing can
/// recover into memory-relevant records: work in flight, or terminal
/// failures within the resurrection ladder's memory-hold rounds and recency
/// window. The summarizer consults this before advancing its forward-only
/// cursor over an empty span (see `RESURRECTION_MEMORY_HOLD_TOTAL_ATTEMPTS`).
pub(crate) fn span_has_recoverable_media(
    conn: &Connection,
    from: &str,
    to: &str,
    resurrection_window_start: &str,
) -> Result<bool> {
    let count: i64 = conn.query_row(
        "SELECT COUNT(*) FROM capture_events e \
         JOIN media_objects m ON m.event_id=e.event_id \
         LEFT JOIN media_processing_jobs j ON j.event_id=e.event_id \
         WHERE e.started_at < ?1 AND e.ended_at > ?2 \
           AND (m.processing_state IN ('queued','processing','retry_wait') \
                OR (m.processing_state='failed' \
                    AND j.error_code IS NOT 'media_integrity' \
                    AND j.attempt_count < ?3 \
                    AND e.started_at >= ?4))",
        params![
            to,
            from,
            RESURRECTION_MEMORY_HOLD_TOTAL_ATTEMPTS,
            resurrection_window_start
        ],
        |row| row.get(0),
    )?;
    Ok(count > 0)
}

fn defer_for_budget(conn: &Connection, job_id: i64, now: &str) -> Result<()> {
    // A job whose event has left the resurrection window can never recover
    // into a memory, and endless budget deferral would pin its session at
    // `processing` while holding the settled-summarize gate for unrelated
    // new sessions. Terminalize honestly instead of parking it forever.
    let window_start = isotime::add_seconds(now, -RESURRECTION_WINDOW_SECONDS);
    let stale: bool = conn.query_row(
        "SELECT e.started_at < ?2 FROM media_processing_jobs j \
         JOIN capture_events e ON e.event_id=j.event_id WHERE j.id=?1",
        params![job_id, window_start],
        |row| row.get(0),
    )?;
    if stale {
        conn.execute(
            "UPDATE media_processing_jobs SET state='failed_terminal',lease_until=NULL, \
             error_code='vertex_daily_budget',updated_at=?1 WHERE id=?2",
            params![now, job_id],
        )?;
        conn.execute(
            "UPDATE media_objects SET processing_state='failed' WHERE event_id=( \
             SELECT event_id FROM media_processing_jobs WHERE id=?1)",
            [job_id],
        )?;
        return Ok(());
    }
    let retry_at = isotime::add_seconds(now, 6.0 * 60.0 * 60.0);
    conn.execute(
        "UPDATE media_processing_jobs
         SET state='retry_wait',
             attempt_count=MAX(attempt_count-1, 0),
             lease_until=NULL,
             error_code='vertex_daily_budget',
             updated_at=?1
         WHERE id=?2",
        params![retry_at, job_id],
    )?;
    conn.execute(
        "UPDATE media_objects SET processing_state='retry_wait' WHERE event_id=(
         SELECT event_id FROM media_processing_jobs WHERE id=?1)",
        [job_id],
    )?;
    Ok(())
}

async fn reserve_media_output(state: &CpState, user_id: &str, work: &MediaWorkUnit) -> Result<()> {
    // Reserve for every outbound attempt, including retries. A prior attempt
    // may have completed billable work even when Kioku timed out or rejected
    // its response, so reusing that attempt's reservation would let retry
    // spend exceed the configured hard ceiling.
    let (class, requested) = match work.class {
        WorkClass::Audio => (
            super::limits::VertexWorkClass::Audio,
            i64::from(vertex::MAX_MEDIA_OUTPUT_TOKENS),
        ),
        WorkClass::Screen => (
            super::limits::VertexWorkClass::Screen,
            i64::from(vertex::MAX_SCREEN_OUTPUT_TOKENS),
        ),
    };
    let reserved = super::limits::reserve_vertex_output_tokens_for_class(
        &state.control,
        user_id,
        class,
        requested,
        state.config.quota_vertex_output_tokens_per_day,
    )
    .await?;
    if reserved.allowed {
        let work_id = work.id.clone();
        let mut ids = work.jobs.iter().map(|job| job.id).collect::<Vec<_>>();
        let class_name = match work.class {
            WorkClass::Audio => "audio",
            WorkClass::Screen => "screen",
        };
        if state.store.is_wal_authoritative(user_id) {
            // Routed read of the durable attempt anchor and the observed
            // predecessors, then the sealed plan is constructed ONCE (R5) and
            // settled through the WAL lane. The predecessor pins the observed
            // reservation_retained -- 1 on a retry -- never a literal 0.
            ids.sort_unstable();
            let probe_work_id = work_id.clone();
            let probe_ids = ids.clone();
            let (attempt_count, retained, unit_usage, job_usage) = state
                .store
                .wal_authoritative_read(user_id, move |conn| {
                    let (attempt_count, retained, unit_usage): (i64, i64, Option<String>) = conn
                        .query_row(
                            "SELECT attempt_count,reservation_retained,usage_json
                             FROM media_work_units WHERE id=?1",
                            [&probe_work_id],
                            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                        )?;
                    let mut job_usage = Vec::with_capacity(probe_ids.len());
                    for id in &probe_ids {
                        job_usage.push(conn.query_row(
                            "SELECT usage_json FROM media_processing_jobs WHERE id=?1",
                            [id],
                            |row| row.get::<_, Option<String>>(0),
                        )?);
                    }
                    Ok((attempt_count, retained, unit_usage, job_usage))
                })
                .await?;
            let plan = wal::MediaWorkReservationPlan::new(
                user_id.to_owned(),
                work_id,
                class_name.to_owned(),
                attempt_count,
                ids,
                requested,
                now_iso(),
                retained,
                unit_usage,
                job_usage,
            )
            .map_err(|_| {
                EnclaveError::Store("media work reservation plan construction failed".into())
            })?;
            let prepared = crate::archive_v3_wal_idempotency::PreparedLogicalMutation::prepare(
                plan,
            )
            .map_err(|_| {
                EnclaveError::Store("media work reservation plan construction failed".into())
            })?;
            state
                .store
                .wal_authoritative_submit(user_id, prepared)
                .await?;
            return Ok(());
        }
        state
            .store
            .with_user(user_id, move |conn| {
                let tx = conn.unchecked_transaction()?;
                let usage = json!({
                    "work_unit_id": work_id,
                    "work_class": class_name,
                    "member_count": ids.len(),
                    "reservation_state": "reserved",
                    "reserved_output_tokens": requested,
                    "processor_version": PROCESSOR_VERSION,
                })
                .to_string();
                for id in ids {
                    tx.execute(
                        "UPDATE media_processing_jobs SET usage_json=?1 WHERE id=?2",
                        params![usage, id],
                    )?;
                }
                tx.execute(
                    "UPDATE media_work_units SET reservation_retained=1,usage_json=?1,updated_at=?2 \
                     WHERE id=?3",
                    params![usage, now_iso(), work_id],
                )?;
                tx.commit()?;
                Ok(())
            })
            .await?;
        state.store.save_user(user_id).await?;
        Ok(())
    } else {
        Err(EnclaveError::Config("vertex_daily_budget".into()))
    }
}

async fn load_raw_media_bytes(state: &CpState, user_id: &str, object_key: &str) -> Result<Vec<u8>> {
    let stored = state.store.get_media(object_key).await?;
    let dek = crate::crypto::load_dek(state.store.kms.as_ref(), &stored.wrapped_dek_b64).await?;
    let context = crate::store::media_blob_context(user_id, object_key);
    let media = crate::crypto::decrypt_bound_blob(&dek, &stored.ciphertext, &context)?.plaintext;
    Ok(media)
}

async fn load_job_media(state: &CpState, user_id: &str, job: &MediaJob) -> Result<Vec<u8>> {
    let media = load_raw_media_bytes(state, user_id, &job.object_key).await?;
    let actual_hash = format!("{:x}", Sha256::digest(&media));
    if !actual_hash.eq_ignore_ascii_case(&job.sha256) {
        return Err(EnclaveError::Crypto("raw media hash mismatch".into()));
    }
    Ok(media)
}

async fn candidate_name_vocabulary(state: &CpState, user_id: &str) -> Result<Vec<String>> {
    state
        .store
        .with_user(user_id, |conn| {
            let mut statement = conn.prepare(
                "SELECT name FROM person_name_claims WHERE status IN ('accepted','probationary') \
                 GROUP BY normalized_name ORDER BY MAX(observed_at) DESC LIMIT 50",
            )?;
            let names = statement
                .query_map([], |row| row.get::<_, String>(0))?
                .collect::<std::result::Result<Vec<_>, _>>()?;
            Ok(names)
        })
        .await
}

async fn persist_actual_media_usage(
    state: &CpState,
    user_id: &str,
    work: &MediaWorkUnit,
    generation: &vertex::MediaGeneration,
) -> Result<()> {
    let work_id = work.id.clone();
    let ids = work.jobs.iter().map(|job| job.id).collect::<Vec<_>>();
    let class_name = match work.class {
        WorkClass::Audio => "audio",
        WorkClass::Screen => "screen",
    };
    let reserved = match work.class {
        WorkClass::Audio => vertex::MAX_MEDIA_OUTPUT_TOKENS,
        WorkClass::Screen => vertex::MAX_SCREEN_OUTPUT_TOKENS,
    };
    let usage = json!({
        "work_unit_id": work_id,
        "work_class": class_name,
        "member_count": ids.len(),
        "reservation_state": "reserved",
        "reserved_output_tokens": reserved,
        "actual_prompt_tokens": generation.metadata.usage.as_ref().and_then(|usage| usage.prompt_tokens),
        "actual_input_text_tokens": generation.metadata.usage.as_ref().and_then(|usage| usage.input_text_tokens),
        "actual_input_audio_tokens": generation.metadata.usage.as_ref().and_then(|usage| usage.input_audio_tokens),
        "actual_input_image_tokens": generation.metadata.usage.as_ref().and_then(|usage| usage.input_image_tokens),
        "actual_cached_input_tokens": generation.metadata.usage.as_ref().and_then(|usage| usage.cached_input_tokens),
        "actual_output_tokens": generation.metadata.usage.as_ref().and_then(|usage| usage.output_tokens),
        "actual_thought_tokens": generation.metadata.usage.as_ref().and_then(|usage| usage.thought_tokens),
        "actual_total_tokens": generation.metadata.usage.as_ref().and_then(|usage| usage.total_tokens),
        "returned_model": generation.metadata.model_version.as_deref(),
        "traffic_type": generation.metadata.traffic_type.as_deref(),
        "latency_ms": generation.latency_ms,
        "processor_version": PROCESSOR_VERSION,
        "outcome": "model_returned",
    })
    .to_string();
    state
        .store
        .with_user(user_id, move |conn| {
            let tx = conn.unchecked_transaction()?;
            for id in ids {
                tx.execute(
                    "UPDATE media_processing_jobs SET usage_json=?1 WHERE id=?2",
                    params![usage, id],
                )?;
            }
            tx.execute(
                "UPDATE media_work_units SET usage_json=?1,updated_at=?2 WHERE id=?3",
                params![usage, now_iso(), work_id],
            )?;
            tx.commit()?;
            Ok(())
        })
        .await?;
    state.store.save_user(user_id).await
}

fn assemble_audio_window(
    jobs: &[MediaJob],
    media: &[Vec<u8>],
) -> Result<(Vec<u8>, Vec<SourceInterval>, i64)> {
    if jobs.is_empty() || jobs.len() != media.len() {
        return Err(EnclaveError::InvalidRequest(
            "audio window members are invalid".into(),
        ));
    }
    let window_started_ms = isotime::parse_epoch_millis(&jobs[0].started_at)
        .ok_or_else(|| EnclaveError::InvalidRequest("audio window timestamp is invalid".into()))?;
    let window_ended_ms = jobs
        .iter()
        .filter_map(|job| isotime::parse_epoch_millis(&job.ended_at))
        .max()
        .ok_or_else(|| EnclaveError::InvalidRequest("audio window timestamp is invalid".into()))?;
    let duration_ms = window_ended_ms.saturating_sub(window_started_ms);
    if !(1..=media_planner::MAX_AUDIO_WINDOW_MS).contains(&duration_ms) {
        return Err(EnclaveError::InvalidRequest(
            "audio window duration is outside allowed bounds".into(),
        ));
    }
    let sample_count =
        ((duration_ms as u64 * super::voice_memory::TARGET_SAMPLE_RATE as u64) / 1_000) as usize;
    let mut samples = vec![0_f32; sample_count];
    let mut weights = vec![0_u8; sample_count];
    let mut sources = Vec::with_capacity(jobs.len());
    for (job, bytes) in jobs.iter().zip(media) {
        let started_ms = isotime::parse_epoch_millis(&job.started_at).ok_or_else(|| {
            EnclaveError::InvalidRequest("audio event timestamp is invalid".into())
        })?;
        let ended_ms = isotime::parse_epoch_millis(&job.ended_at).ok_or_else(|| {
            EnclaveError::InvalidRequest("audio event timestamp is invalid".into())
        })?;
        let source_start_ms = started_ms - window_started_ms;
        let source_end_ms = ended_ms - window_started_ms;
        sources.push(SourceInterval::new(
            &job.event_id,
            source_start_ms,
            source_end_ms,
        ));
        let decoded = super::voice_memory::decode_mono_16khz(bytes, &job.mime_type)?;
        let destination_start = ((source_start_ms.max(0) as u64
            * super::voice_memory::TARGET_SAMPLE_RATE as u64)
            / 1_000) as usize;
        let authoritative_len = (((source_end_ms - source_start_ms).max(0) as u64
            * super::voice_memory::TARGET_SAMPLE_RATE as u64)
            / 1_000) as usize;
        for (index, sample) in decoded.iter().take(authoritative_len).enumerate() {
            let destination = destination_start.saturating_add(index);
            if destination >= samples.len() {
                break;
            }
            let weight = weights[destination];
            samples[destination] = if weight == 0 {
                *sample
            } else {
                (samples[destination] * f32::from(weight) + *sample) / (f32::from(weight) + 1.0)
            };
            weights[destination] = weight.saturating_add(1);
        }
    }
    Ok((
        super::voice_memory::encode_mono_16khz_wav(&samples)?,
        sources,
        duration_ms,
    ))
}

/// ADR-0022 slice 10e: settle the sealed screen-storyboard attempt boundary
/// for a WAL-authoritative user. The routed read authenticates the complete
/// reserved leased work topology at one caller-fixed attempt time and
/// returns the exact predecessor and post-usage-stable attempt commitments;
/// the sealed plan is then constructed ONCE (R5) and settled through the WAL
/// lane AFTER the settled reservation and BEFORE any Vertex egress. The
/// typed receipt carries the derived event id — the pinned invocation
/// identity the usage settlements target — and the binding commitment the
/// bound result plan later consumes. Same-attempt crash retries replay the
/// exact receipt; a renewed lease/counter topology derives a new identity.
async fn settle_screen_storyboard_attempt(
    state: &CpState,
    user_id: &str,
    work: &MediaWorkUnit,
) -> Result<wal::attempt::ScreenStoryboardAttemptReceipt> {
    let attempted_at = now_iso();
    let probe_work_id = work.id.clone();
    let probe_attempted_at = attempted_at.clone();
    let commitments = state
        .store
        .wal_authoritative_read(user_id, move |conn| {
            wal::result::current_screen_work_attempt_commitments(
                conn,
                &probe_work_id,
                &probe_attempted_at,
            )
            .map_err(|_| {
                EnclaveError::Store("screen storyboard attempt predecessor read failed".into())
            })
        })
        .await?;
    let plan = wal::ScreenStoryboardAttemptPlan::new(
        user_id.to_owned(),
        work.id.clone(),
        commitments.predecessor(),
        commitments.attempt(),
        state.config.vertex_model.clone(),
        state.config.vertex_location.clone(),
        attempted_at,
    )
    .map_err(|_| {
        EnclaveError::Store("screen storyboard attempt plan construction failed".into())
    })?;
    let prepared = crate::archive_v3_wal_idempotency::PreparedLogicalMutation::prepare(plan)
        .map_err(|_| {
            EnclaveError::Store("screen storyboard attempt plan construction failed".into())
        })?;
    state
        .store
        .wal_authoritative_submit(user_id, prepared)
        .await
}

/// ADR-0022 slice 10e: settle the sealed bound screen-storyboard result for
/// a WAL-authoritative user — it replaces `persist_storyboard_results` on
/// this lane. Every fact the plan carries is read through the routed read
/// (the terminal Vertex attempt commitment on the attempt's own event id,
/// the exact work predecessor, and the base for the caller-fixed screenshot
/// row ids) or computed pre-submit (the validated frame results in exact
/// member order, one canonical commit time); the sealed plan is constructed
/// ONCE (R5). The reviewed v2 subtype carries no person evidence, so
/// screen-visible name projections are deliberately absent on this lane.
/// The sealed result vocabulary is a hard whitelist; an off-list label from
/// the model would discard a PAID call and loop fresh paid attempts to the
/// cap. The schema now pins the enum at the provider request; this is the
/// fail-safe for residual drift. Legacy persistence keeps the verbatim label.
fn canonical_screen_state(value: &str) -> &str {
    match value {
        "content" | "blank" | "loading" | "error" | "transition" | "locked_or_private"
        | "unknown" => value,
        _ => "unknown",
    }
}

fn canonical_content_type(value: &str) -> &str {
    match value {
        "document" | "presentation" | "web_page" | "code" | "terminal" | "chat" | "meeting"
        | "media" | "system_ui" | "application_ui" | "unknown" => value,
        _ => "unknown",
    }
}

async fn settle_screen_storyboard_result(
    state: &CpState,
    user_id: &str,
    work: &MediaWorkUnit,
    receipt: &wal::attempt::ScreenStoryboardAttemptReceipt,
    results: Vec<(String, ScreenResult)>,
) -> Result<()> {
    let requested_model = state.config.vertex_model.clone();
    let probe_event_id = receipt.event_id().to_owned();
    let probe_model = requested_model.clone();
    let probe_work_id = work.id.clone();
    let (vertex_attempt_commitment, predecessor_commitment, first_screenshot_id) = state
        .store
        .wal_authoritative_read(user_id, move |conn| {
            let vertex_attempt_commitment = wal::result::current_screen_vertex_attempt_commitment(
                conn,
                &probe_event_id,
                &probe_model,
            )
            .map_err(|_| {
                EnclaveError::Store("screen storyboard terminal attempt read failed".into())
            })?;
            let predecessor_commitment =
                wal::result::current_screen_work_predecessor_commitment(conn, &probe_work_id)
                    .map_err(|_| {
                        EnclaveError::Store("screen storyboard predecessor read failed".into())
                    })?;
            let max_screenshot_id: i64 =
                conn.query_row("SELECT COALESCE(MAX(id),0) FROM screenshots", [], |row| {
                    row.get(0)
                })?;
            Ok((
                vertex_attempt_commitment,
                predecessor_commitment,
                max_screenshot_id.max(0).saturating_add(1),
            ))
        })
        .await?;
    let mut frames = Vec::with_capacity(results.len());
    for (index, (event_id, result)) in results.into_iter().enumerate() {
        let screenshot_id = i64::try_from(index)
            .ok()
            .and_then(|offset| first_screenshot_id.checked_add(offset))
            .ok_or_else(|| {
                EnclaveError::Store("screen storyboard result plan construction failed".into())
            })?;
        frames.push(
            wal::result::ScreenStoryboardFrameResult::new(
                event_id,
                screenshot_id,
                result.literal_description,
                canonical_screen_state(&result.screen_state).to_owned(),
                canonical_content_type(&result.content_type).to_owned(),
                result.visible_text,
                result.salient_text,
            )
            .map_err(|_| {
                EnclaveError::Store("screen storyboard result plan construction failed".into())
            })?,
        );
    }
    let plan = wal::ScreenStoryboardResultPlan::new(
        user_id.to_owned(),
        receipt.event_id().to_owned(),
        vertex_attempt_commitment,
        receipt.binding_commitment(),
        work.id.clone(),
        predecessor_commitment,
        requested_model,
        now_iso(),
        frames,
    )
    .map_err(|_| EnclaveError::Store("screen storyboard result plan construction failed".into()))?;
    let prepared = crate::archive_v3_wal_idempotency::PreparedLogicalMutation::prepare(plan)
        .map_err(|_| {
            EnclaveError::Store("screen storyboard result plan construction failed".into())
        })?;
    state
        .store
        .wal_authoritative_submit(user_id, prepared)
        .await
}

async fn process_work_unit(state: &CpState, user_id: &str, work: &MediaWorkUnit) -> Result<()> {
    let mut media = Vec::with_capacity(work.jobs.len());
    for job in &work.jobs {
        media.push(load_job_media(state, user_id, job).await?);
    }

    if work.class == WorkClass::Audio {
        let (window, sources, duration_ms) = assemble_audio_window(&work.jobs, &media)?;
        reserve_media_output(state, user_id, work).await?;
        let candidate_names = candidate_name_vocabulary(state, user_id).await?;
        let prompt = format!(
            "Transcribe this audio exactly. The source kind is {}. Return chronological speaker turns with millisecond offsets from the beginning. Keep stable speaker_local_id values within this entire asset. Prefer an existing local id whenever the voice remains acoustically consistent. Do not invent a new speaker solely because of a one-word interjection, a short phrase, a pause, changed volume or prosody, device movement, or background noise; create a new local id only when sustained acoustic evidence supports a different human voice. Mark overlap. Only populate speaker_name, speaker_name_confidence, and speaker_name_evidence when the audio itself explicitly supports the person's full or partial name; never guess from voice alone. When speaker_name is populated, you MUST set speaker_name_kind ('self_identification' when the speaker identifies themselves, 'vocative_address' when addressing someone, 'third_party_mention' when mentioning someone), speaker_name_subject_turn_id (the turn_id of the speaker who is identified or named), and speaker_name_target_turn_id (for vocative_address, the turn_id of the speaker being addressed). For every turn, include only durable person_facts explicitly supported by that turn, with literal evidence; never infer sensitive traits or unstated facts. The following bounded names are spelling vocabulary only, not proof that anyone is present, speaking, or has any identity: {}",
            work.jobs[0].stream_kind,
            serde_json::to_string(&candidate_names)?
        );
        let generation = vertex::generate_media_custom(
            state,
            user_id,
            vertex::VertexOperation::AudioWindow,
            &prompt,
            "audio/wav",
            &window,
            audio_schema(),
            true,
        )
        .await?;
        persist_actual_media_usage(state, user_id, work, &generation).await?;
        let turns = parse_audio_result(&generation.text, duration_ms)?;
        let voiceprints = match &state.voice {
            Some(engine) => match engine.embed_turns(&window, "audio/wav", &turns) {
                Ok(voiceprints) => voiceprints,
                Err(error) => {
                    warn!(work_unit_id = work.id, error = %error, "voice fingerprint extraction skipped");
                    Vec::new()
                }
            },
            None => Vec::new(),
        };
        state
            .store
            .with_user(user_id, |conn| {
                persist_audio_window_result(
                    conn,
                    &work.id,
                    &work.jobs,
                    &sources,
                    &turns,
                    &voiceprints,
                )
            })
            .await?;
    } else {
        reserve_media_output(state, user_id, work).await?;
        // ADR-0022 slice 10e: for a WAL-authoritative user the sealed attempt
        // boundary durably fixes the Vertex attempt identity and the exact
        // `started` billing intent AFTER the settled reservation and BEFORE
        // the storyboard request leaves; its receipt pins the invocation
        // identity the usage settlements and the bound result plan consume.
        let storyboard_attempt = if state.store.is_wal_authoritative(user_id) {
            Some(settle_screen_storyboard_attempt(state, user_id, work).await?)
        } else {
            None
        };
        let prompt = "Inspect every labeled screenshot literally and return exactly one result for every supplied frame_id. Never invent, omit, merge, or duplicate a frame ID. Transcribe useful visible text, produce a compact salient-text projection and literal description, and classify screen_state/content_type per frame. List a person only when a visible name label supports it, preferring the complete first and last name. Set is_active_speaker true only for the specific frame where the meeting UI visibly marks that exact label as currently speaking; otherwise false. Evidence must quote or describe the visible label/highlight; never infer identity from a face.";
        let inputs = work
            .jobs
            .iter()
            .zip(&media)
            .map(|(job, bytes)| vertex::MediaInput::new(&job.event_id, &job.mime_type, bytes))
            .collect::<Vec<_>>();
        let generation = vertex::generate_media_parts_custom(
            state,
            user_id,
            vertex::VertexOperation::ScreenStoryboard,
            prompt,
            &inputs,
            storyboard_schema(),
            vertex::MAX_SCREEN_OUTPUT_TOKENS,
            storyboard_attempt
                .as_ref()
                .map(|receipt| receipt.event_id().to_owned()),
        )
        .await?;
        if let Some(receipt) = storyboard_attempt.as_ref() {
            // The bound result settle refuses without this attempt's terminal
            // usage row, but record_response inside the generate path is
            // best-effort: a transiently deferred settle would strand a PAID
            // result (the reconcile sweep can only degrade the row to
            // 'ambiguous', which the result guard also refuses). Re-drive it
            // here as a required, idempotent settle — a replay when the
            // best-effort write landed, the authoritative retry when not.
            super::model_usage::settle_response_required(
                state,
                user_id,
                receipt.event_id(),
                &generation.metadata,
            )
            .await?;
        }
        persist_actual_media_usage(state, user_id, work, &generation).await?;
        let expected = work
            .jobs
            .iter()
            .map(|job| job.event_id.clone())
            .collect::<Vec<_>>();
        let results = validate_storyboard_result(&generation.text, &expected)?;
        if let Some(receipt) = storyboard_attempt {
            // The sealed bound result consumes the attempt's binding
            // commitment and replaces the legacy storyboard persistence for
            // WAL-authoritative users; `save_user` is a provider-silent no-op
            // on this lane, so returning here matches the legacy tail.
            return settle_screen_storyboard_result(state, user_id, work, &receipt, results).await;
        }
        state
            .store
            .with_user(user_id, |conn| {
                persist_storyboard_results(conn, &work.id, &work.jobs, results)
            })
            .await?;
    }
    state.store.save_user(user_id).await?;
    Ok(())
}

/// Moves eligible terminally failed jobs back to `retry_wait` so the normal
/// claim path grants exactly one more attempt per resurrection (`mark_failed`
/// re-terminalizes at `attempts >= MAX_ATTEMPTS` after every later failure).
fn resurrect_failed_jobs(conn: &Connection, now: &str) -> Result<usize> {
    let stale_before = isotime::add_seconds(now, -RESURRECTION_DELAY_SECONDS);
    let window_start = isotime::add_seconds(now, -RESURRECTION_WINDOW_SECONDS);
    let tx = conn.unchecked_transaction()?;
    let eligible: Vec<(i64, String)> = {
        let mut statement = tx.prepare(
            "SELECT j.id, j.event_id FROM media_processing_jobs j \
             JOIN capture_events e ON e.event_id = j.event_id \
             WHERE j.processor_version = ?1 AND j.state = 'failed_terminal' \
               AND j.error_code IS NOT 'media_integrity' \
               AND j.attempt_count < ?2 \
               AND j.updated_at <= ?3 \
               AND e.started_at >= ?4 \
             ORDER BY j.id LIMIT ?5",
        )?;
        let rows = statement.query_map(
            params![
                PROCESSOR_VERSION,
                RESURRECTION_TOTAL_ATTEMPT_CAP,
                stale_before,
                window_start,
                RESURRECTION_MAX_PER_SWEEP
            ],
            |row| Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?)),
        )?;
        rows.collect::<std::result::Result<Vec<_>, _>>()?
    };
    for (job_id, event_id) in &eligible {
        tx.execute(
            "UPDATE media_processing_jobs SET state='retry_wait',lease_until=NULL, \
             updated_at=?1 WHERE id=?2",
            params![now, job_id],
        )?;
        tx.execute(
            "UPDATE media_objects SET processing_state='retry_wait' \
             WHERE event_id=?1 AND processing_state='failed'",
            [event_id],
        )?;
    }
    tx.commit()?;
    Ok(eligible.len())
}

async fn resurrect_user_failed_jobs(state: &CpState, user_id: &str) {
    let now = now_iso();
    if state.store.is_wal_authoritative(user_id) {
        // The sealed F7 lane: enumerate the bounded eligible set through the
        // routed read, then settle the resolved set as one plan (R6). The
        // identity is the set's predecessor tuples; the sweep bounds and the
        // commit stamp enter only the fingerprinted request. `apply()` re-runs
        // the same query (shared fn, identical by construction) and refuses a
        // stale enumeration.
        let stale_before = isotime::add_seconds(&now, -RESURRECTION_DELAY_SECONDS);
        let window_start = isotime::add_seconds(&now, -RESURRECTION_WINDOW_SECONDS);
        let probe_stale = stale_before.clone();
        let probe_window = window_start.clone();
        let eligible = state
            .store
            .wal_authoritative_read(user_id, move |conn| {
                Ok(wal::resurrection::enumerate_resurrectable(
                    conn,
                    PROCESSOR_VERSION,
                    RESURRECTION_TOTAL_ATTEMPT_CAP,
                    &probe_stale,
                    &probe_window,
                    RESURRECTION_MAX_PER_SWEEP,
                )?)
            })
            .await;
        let eligible = match eligible {
            Ok(eligible) => eligible,
            Err(error) => {
                warn!(user_id, error = %error, "failed-job resurrection scan failed");
                return;
            }
        };
        if eligible.is_empty() {
            return;
        }
        let count = eligible.len();
        let prepared = eligible
            .into_iter()
            .map(|(job_id, event_id, attempt_count, updated_at)| {
                wal::resurrection::ResurrectableJob::new(
                    job_id,
                    event_id,
                    attempt_count,
                    updated_at,
                )
            })
            .collect::<std::result::Result<Vec<_>, _>>()
            .and_then(|jobs| {
                wal::MediaJobResurrectionPlan::new(
                    user_id.to_owned(),
                    jobs,
                    PROCESSOR_VERSION,
                    RESURRECTION_TOTAL_ATTEMPT_CAP,
                    RESURRECTION_MAX_PER_SWEEP,
                    stale_before,
                    window_start,
                    now,
                )
            })
            .and_then(crate::archive_v3_wal_idempotency::PreparedLogicalMutation::prepare);
        let prepared = match prepared {
            Ok(prepared) => prepared,
            Err(error) => {
                warn!(
                    user_id,
                    error = ?error,
                    "failed-job resurrection plan construction failed"
                );
                return;
            }
        };
        match state
            .store
            .wal_authoritative_submit(user_id, prepared)
            .await
        {
            Ok(_) => info!(user_id, count, "resurrected terminally failed media jobs"),
            Err(error) => warn!(user_id, error = %error, "failed-job resurrection failed"),
        }
        return;
    }
    let resurrected = state
        .store
        .with_user(user_id, |conn| resurrect_failed_jobs(conn, &now))
        .await;
    match resurrected {
        Ok(0) => {}
        Ok(count) => {
            info!(user_id, count, "resurrected terminally failed media jobs");
            let _ = state.store.save_user(user_id).await;
        }
        Err(error) => warn!(user_id, error = %error, "failed-job resurrection failed"),
    }
}

async fn process_user(state: &CpState, user_id: &str) {
    let now = now_iso();
    let pending = state
        .store
        .with_user(user_id, |conn| pending_work_classes(conn, &now))
        .await;
    let (audio_pending, screen_pending) = match pending {
        Ok(pending) => pending,
        Err(error) => {
            warn!(user_id, error = %error, "media class scan failed");
            return;
        }
    };
    let mut completed_work = false;
    for class in
        media_planner::schedule_classes(audio_pending, screen_pending, MAX_JOBS_PER_USER_PER_SWEEP)
    {
        let leased_at = now_iso();
        let lease = state
            .store
            .with_user(user_id, |conn| lease_work_unit(conn, &leased_at, class))
            .await;
        let Some(work) = (match lease {
            Ok(work) => work,
            Err(error) => {
                warn!(user_id, error = %error, "media job lease failed");
                return;
            }
        }) else {
            return;
        };
        if let Err(error) = process_work_unit(state, user_id, &work).await {
            let error_code = match error {
                EnclaveError::Config(ref message) if message == "quota" => "vertex_quota",
                EnclaveError::Config(ref message) if message == "vertex_daily_budget" => {
                    "vertex_daily_budget"
                }
                EnclaveError::Json(_) | EnclaveError::InvalidRequest(_) => "invalid_model_output",
                EnclaveError::Crypto(_) => "media_integrity",
                _ => "processing_error",
            };
            warn!(
                user_id,
                work_unit_id = work.id,
                error_code,
                "media work unit failed"
            );
            let failed_at = now_iso();
            let update = state.store.with_user(user_id, |conn| {
                let tx = conn.unchecked_transaction()?;
                for job in &work.jobs {
                    if error_code == "vertex_daily_budget" {
                        defer_for_budget(&tx, job.id, &failed_at)?;
                    } else {
                        mark_failed(&tx, job.id, error_code, &failed_at)?;
                    }
                }
                let state = if error_code == "vertex_daily_budget" {
                    "retry_wait"
                } else {
                    let terminal: i64 = tx.query_row(
                        "SELECT COUNT(*) FROM media_processing_jobs \
                         WHERE id IN (SELECT job_id FROM media_work_members WHERE work_unit_id=?1) \
                         AND state='failed_terminal'",
                        [&work.id],
                        |row| row.get(0),
                    )?;
                    if terminal > 0 {
                        "failed_terminal"
                    } else {
                        "retry_wait"
                    }
                };
                tx.execute(
                    "UPDATE media_work_units SET state=?1,error_code=?2,updated_at=?3 WHERE id=?4",
                    params![state, error_code, failed_at, work.id],
                )?;
                tx.commit()?;
                Ok(())
            });
            if let Err(mark_error) = update.await {
                warn!(user_id, work_unit_id = work.id, error = %mark_error, "media work failure persistence failed");
                return;
            }
            let _ = state.store.save_user(user_id).await;
            if matches!(error_code, "vertex_quota" | "vertex_daily_budget") {
                return;
            }
        }
        completed_work = true;
    }
    if completed_work {
        // ADR-0034: this pass may have drained the user's last pending media
        // for a finished capture session. Only a hint; the summarizer's
        // settled gate re-checks open sessions and remaining media work.
        super::summarizer::kick_session_settled(user_id);
    }
    match state
        .store
        .with_user(user_id, |conn| {
            super::voice_memory::reconcile_profiles(conn, 10)
        })
        .await
    {
        Ok(updated) if updated > 0 => {
            let _ = state.store.save_user(user_id).await;
        }
        Ok(_) => {}
        Err(error) => {
            warn!(user_id, error = %error, "bounded voice-profile reconciliation failed");
        }
    }
    match state
        .store
        .with_user(user_id, |conn| {
            super::voice_lineage::process_lineage_actions(conn, 10)
        })
        .await
    {
        Ok(processed) if processed > 0 => {
            let _ = state.store.save_user(user_id).await;
        }
        Ok(_) => {}
        Err(error) => {
            warn!(user_id, error = %error, "bounded voice-profile lineage action failed");
        }
    }
}

async fn prune_user_media(state: &CpState, user_id: &str) {
    prune_user_media_store(state.store.as_ref(), user_id).await;
}

async fn prune_user_media_store(store: &Store, user_id: &str) {
    let now = now_iso();
    if store.is_wal_authoritative(user_id) {
        // ADR-0022: the local pruned receipt settles as the sealed
        // RetentionSettlementPlan after the provider delete, pinning the
        // exact observed row tuple. Scan through the routed read lane;
        // provider deletion is Control/GCS-side and unchanged.
        let probe_now = now.clone();
        let due = store
            .wal_authoritative_read(user_id, move |conn| {
                let mut statement = conn.prepare(
                    "SELECT event_id,object_key,object_generation,object_backend,sha256,\
                     retain_until,processing_state FROM media_objects \
                     WHERE deleted_at IS NULL AND retain_until<=?1 \
                     AND processing_state IN ('ready','failed') ORDER BY retain_until LIMIT 100",
                )?;
                let rows = statement
                    .query_map([&probe_now], |row| {
                        Ok((
                            row.get::<_, String>(0)?,
                            row.get::<_, String>(1)?,
                            row.get::<_, Option<i64>>(2)?,
                            row.get::<_, Option<String>>(3)?,
                            row.get::<_, String>(4)?,
                            row.get::<_, String>(5)?,
                            row.get::<_, String>(6)?,
                        ))
                    })?
                    .collect::<std::result::Result<Vec<_>, _>>()?;
                Ok(rows)
            })
            .await;
        let due = match due {
            Ok(due) => due,
            Err(error) => {
                warn!(user_id, error = %error, "raw media retention scan failed");
                return;
            }
        };
        for (
            event_id,
            object_key,
            object_generation,
            object_backend,
            sha256,
            retain_until,
            state,
        ) in due
        {
            let delete_result = store
                .delete_retained_media(
                    user_id,
                    &object_key,
                    object_generation,
                    object_backend.as_deref(),
                    &sha256,
                )
                .await;
            if let Err(error) = delete_result {
                warn!(error = %error, "raw media retention delete failed");
                continue;
            }
            let deleted_at = now_iso();
            let prepared = wal::RetentionSettlementPlan::new(
                user_id.to_owned(),
                event_id,
                object_key,
                object_generation,
                object_backend,
                sha256,
                retain_until,
                state,
                deleted_at,
            )
            .and_then(crate::archive_v3_wal_idempotency::PreparedLogicalMutation::prepare);
            let prepared = match prepared {
                Ok(prepared) => prepared,
                Err(error) => {
                    warn!(?error, "raw media retention plan construction failed");
                    continue;
                }
            };
            if let Err(error) = store.wal_authoritative_submit(user_id, prepared).await {
                warn!(error = %error, "raw media retention ledger update failed");
            }
        }
        return;
    }
    let due = store
        .with_user(user_id, |conn| {
            let mut statement = conn.prepare(
                "SELECT event_id,object_key,object_generation,object_backend,sha256 FROM media_objects \
                 WHERE deleted_at IS NULL AND retain_until<=?1 \
                 AND processing_state IN ('ready','failed') ORDER BY retain_until LIMIT 100",
            )?;
            let rows = statement
                .query_map([&now], |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, Option<i64>>(2)?,
                        row.get::<_, Option<String>>(3)?,
                        row.get::<_, String>(4)?,
                    ))
                })?
                .collect::<std::result::Result<Vec<_>, _>>()?;
            Ok(rows)
        })
        .await;
    let due = match due {
        Ok(due) => due,
        Err(error) => {
            warn!(user_id, error = %error, "raw media retention scan failed");
            return;
        }
    };
    let mut changed = false;
    for (event_id, object_key, object_generation, object_backend, sha256) in due {
        let delete_result = store
            .delete_retained_media(
                user_id,
                &object_key,
                object_generation,
                object_backend.as_deref(),
                &sha256,
            )
            .await;
        if let Err(error) = delete_result {
            warn!(error = %error, "raw media retention delete failed");
            continue;
        }
        let deleted_at = now_iso();
        if let Err(error) = store
            .with_user(user_id, |conn| {
                conn.execute(
                    "UPDATE media_objects SET processing_state='pruned',deleted_at=?1 \
                     WHERE event_id=?2 AND object_key=?3",
                    params![deleted_at, event_id, object_key],
                )?;
                Ok(())
            })
            .await
        {
            warn!(error = %error, "raw media retention ledger update failed");
            continue;
        }
        changed = true;
    }
    if changed {
        let _ = store.save_user(user_id).await;
    }
}

async fn process_user_voice_embedding_jobs(state: &CpState, user_id: &str) {
    let now = now_iso();
    let worker_id = "media_worker";
    let lease_token = format!(
        "{worker_id}-{}",
        isotime::parse_epoch_millis(&now).unwrap_or(0)
    );

    let leased_jobs = match state
        .store
        .with_user(user_id, {
            let now = now.clone();
            let lease_token = lease_token.clone();
            move |conn| {
                super::voice_memory::lease_embedding_jobs(
                    conn,
                    worker_id,
                    &lease_token,
                    &now,
                    300,
                    32,
                )
            }
        })
        .await
    {
        Ok(jobs) => jobs,
        Err(e) => {
            warn!(error = %e, user_id = user_id, "failed to lease voice embedding jobs");
            return;
        }
    };

    if leased_jobs.is_empty() {
        return;
    }

    let voice_engine = state.voice.clone();

    for job in leased_jobs {
        // Renew the batch lease before each potentially slow decode/inference
        // pass so a long batch cannot silently expire mid-job.
        {
            let lease_token = lease_token.clone();
            let renewed = state
                .store
                .with_user(user_id, move |conn| {
                    super::voice_memory::renew_embedding_job_lease(conn, job.id, &lease_token, 300)
                })
                .await
                .unwrap_or(false);
            if !renewed {
                // Lease lost (expired and re-leased elsewhere). Skip: the new
                // holder owns the job; our fenced completion would no-op anyway.
                continue;
            }
        }

        #[derive(Debug)]
        enum JobPlan {
            /// Sample already persisted (synchronous path succeeded earlier).
            AlreadyEnrolled,
            /// Observation row is gone; nothing to reconstruct.
            ObservationMissing,
            /// One or more source media objects are pruned/expired: terminal.
            MediaPruned,
            /// No recorded sources: terminal (cannot ever reconstruct).
            NoSources,
            Reconstruct {
                overlap: bool,
                sources: Vec<(String, i64, i64, String, String)>,
                acoustic_domain: String,
                person_id: Option<i64>,
            },
        }

        let plan: Option<JobPlan> = state
            .store
            .with_user(user_id, move |conn| {
                let already_enrolled: bool = conn
                    .query_row(
                        "SELECT COUNT(*) > 0 FROM voice_samples WHERE speaker_observation_id = ?1",
                        [job.speaker_observation_id],
                        |r| r.get(0),
                    )
                    .unwrap_or(false);

                if already_enrolled {
                    let _ = conn.execute(
                        "UPDATE voice_samples SET embedding_job_id = ?1 WHERE speaker_observation_id = ?2 AND embedding_job_id IS NULL",
                        params![job.id, job.speaker_observation_id],
                    );
                    return Ok(JobPlan::AlreadyEnrolled);
                }

                let obs = conn
                    .query_row(
                        "SELECT o.overlap, o.person_id FROM speaker_observations o WHERE o.id = ?1",
                        [job.speaker_observation_id],
                        |r| Ok((r.get::<_, i64>(0)? != 0, r.get::<_, Option<i64>>(1)?)),
                    )
                    .optional()?;

                let Some((overlap, person_id)) = obs else {
                    return Ok(JobPlan::ObservationMissing);
                };

                let mut stmt = conn.prepare(
                    "SELECT s.event_id, s.event_start_ms, s.event_end_ms, \
                            m.object_key, m.mime_type, \
                            COALESCE(m.processing_state, ''), \
                            COALESCE(e.audio_role, ''), COALESCE(e.audio_route, ''), e.stream_kind \
                     FROM speaker_observation_sources s \
                     JOIN capture_events e ON e.event_id = s.event_id \
                     JOIN media_objects m ON m.event_id = s.event_id \
                     WHERE s.speaker_observation_id = ?1 \
                     ORDER BY s.window_start_ms ASC",
                )?;
                let mut acoustic_domain = String::new();
                let mut any_pruned = false;
                let sources: Vec<(String, i64, i64, String, String)> = stmt
                    .query_map([job.speaker_observation_id], |r| {
                        let event_id: String = r.get(0)?;
                        let event_start_ms: i64 = r.get(1)?;
                        let event_end_ms: i64 = r.get(2)?;
                        let object_key: String = r.get(3)?;
                        let mime_type: String = r.get(4)?;
                        let processing_state: String = r.get(5)?;
                        let role: String = r.get(6)?;
                        let route: String = r.get(7)?;
                        let stream_kind: String = r.get(8)?;
                        Ok((
                            event_id,
                            event_start_ms,
                            event_end_ms,
                            object_key,
                            mime_type,
                            processing_state,
                            role,
                            route,
                            stream_kind,
                        ))
                    })?
                    .filter_map(|x| x.ok())
                    .map(
                        |(
                            event_id,
                            event_start_ms,
                            event_end_ms,
                            object_key,
                            mime_type,
                            processing_state,
                            role,
                            route,
                            stream_kind,
                        )| {
                            if processing_state == "pruned" {
                                any_pruned = true;
                            }
                            if acoustic_domain.is_empty() {
                                if !role.is_empty() || !route.is_empty() {
                                    acoustic_domain = format!("{stream_kind}:{role}:{route}");
                                } else {
                                    acoustic_domain = stream_kind;
                                }
                            }
                            (event_id, event_start_ms, event_end_ms, object_key, mime_type)
                        },
                    )
                    .collect();

                if any_pruned {
                    return Ok(JobPlan::MediaPruned);
                }
                if sources.is_empty() {
                    return Ok(JobPlan::NoSources);
                }
                Ok(JobPlan::Reconstruct {
                    overlap,
                    sources,
                    acoustic_domain,
                    person_id,
                })
            })
            .await
            .ok();

        let complete = |success: bool, code: Option<&'static str>, terminal: bool| {
            let lease_token = lease_token.clone();
            async move {
                let _ = state
                    .store
                    .with_user(user_id, move |conn| {
                        if terminal {
                            super::voice_memory::fail_embedding_job_terminal(
                                conn,
                                job.id,
                                &lease_token,
                                code.unwrap_or("ERR_TERMINAL"),
                            )
                        } else {
                            super::voice_memory::complete_embedding_job(
                                conn,
                                job.id,
                                &lease_token,
                                success,
                                code,
                                None,
                            )
                        }
                    })
                    .await;
            }
        };

        let Some(plan) = plan else {
            // Transient store/database error while planning: bounded retry.
            complete(false, Some("ERR_PLAN_UNAVAILABLE"), false).await;
            continue;
        };

        let (overlap, sources, acoustic_domain, person_id) = match plan {
            JobPlan::AlreadyEnrolled => {
                complete(true, None, false).await;
                continue;
            }
            JobPlan::ObservationMissing => {
                complete(false, Some("ERR_OBSERVATION_NOT_FOUND"), true).await;
                continue;
            }
            JobPlan::MediaPruned => {
                complete(false, Some("ERR_MEDIA_PRUNED"), true).await;
                continue;
            }
            JobPlan::NoSources => {
                complete(false, Some("ERR_NO_SOURCES_RECORDED"), true).await;
                continue;
            }
            JobPlan::Reconstruct {
                overlap,
                sources,
                acoustic_domain,
                person_id,
            } => (overlap, sources, acoustic_domain, person_id),
        };

        let Some(engine) = &voice_engine else {
            complete(false, Some("ERR_NO_VOICE_ENGINE"), false).await;
            continue;
        };

        // Reconstruct the exact observation span across every recorded source
        // event, in window order, slicing each decoded event by its recorded
        // within-event offsets so no audio is duplicated or shifted.
        let mut full_samples: Vec<f32> = Vec::new();
        let mut terminal_error: Option<&'static str> = None;
        let mut transient_error: Option<&'static str> = None;

        for (_event_id, start_ms, end_ms, object_key, mime_type) in &sources {
            let media_bytes = match load_raw_media_bytes(state, user_id, object_key).await {
                Ok(bytes) => bytes,
                Err(EnclaveError::NotFound) => {
                    terminal_error = Some("ERR_MEDIA_EXPIRED");
                    break;
                }
                Err(_) => {
                    transient_error = Some("ERR_MEDIA_LOAD");
                    break;
                }
            };
            let decoded = match super::voice_memory::decode_mono_16khz(&media_bytes, mime_type) {
                Ok(pcm) => pcm,
                Err(_) => {
                    // Same bytes decode the same way every time: terminal.
                    terminal_error = Some("ERR_MEDIA_UNDECODABLE");
                    break;
                }
            };
            let samples =
                super::voice_memory::slice_observation_source(&decoded, *start_ms, *end_ms);
            full_samples.extend_from_slice(samples);
        }

        if let Some(code) = terminal_error {
            complete(false, Some(code), true).await;
            continue;
        }
        if let Some(code) = transient_error {
            complete(false, Some(code), false).await;
            continue;
        }
        if full_samples.is_empty() {
            complete(false, Some("ERR_EMPTY_SPAN"), true).await;
            continue;
        }

        let diagnostics = super::voice_quality::diagnose(&full_samples, overlap, &[]);
        if diagnostics.decision == super::voice_quality::SampleDecision::NoEmbedding {
            // A quality-policy abstention is settled, not degraded: retrying the
            // same audio can never produce a sample. Record the diagnostics on
            // the observation and mark the job ready with an annotation.
            let diag_json = serde_json::to_string(&diagnostics).unwrap_or_default();
            let decision = diagnostics.decision.as_str();
            let _ = state
                .store
                .with_user(user_id, move |conn| {
                    conn.execute(
                        "UPDATE speaker_observations SET voice_eligibility = ?1, voice_diagnostics_json = ?2 WHERE id = ?3",
                        params![decision, diag_json, job.speaker_observation_id],
                    )?;
                    Ok(())
                })
                .await;
            complete(true, Some("QUALITY_REJECTED"), false).await;
            continue;
        }

        let embedding = match engine.embed_samples(&full_samples) {
            Ok(emb) => emb,
            Err(_) => {
                complete(false, Some("ERR_INFERENCE"), false).await;
                continue;
            }
        };

        let candidate = super::voice_memory::EmbeddedTurn {
            turn_id: format!("retry-{}", job.id),
            embedding: Some(embedding),
            diagnostics,
        };

        let lease_token_store = lease_token.clone();
        let _ = state
            .store
            .with_user(user_id, move |conn| {
                let _ = super::voice_memory::match_and_store_candidate(
                    conn,
                    job.speaker_observation_id,
                    &candidate,
                    &acoustic_domain,
                    person_id,
                    Some(job.id),
                )?;
                super::voice_memory::complete_embedding_job(
                    conn,
                    job.id,
                    &lease_token_store,
                    true,
                    None,
                    None,
                )
            })
            .await;
    }

    let _ = state
        .store
        .with_user(user_id, |conn| {
            super::voice_memory::recalculate_all_episode_speaker_processing_status(conn)
        })
        .await;
}

async fn sweep(state: &Arc<CpState>) {
    let users = match state.control.all_user_ids().await {
        Ok(users) => users,
        Err(error) => {
            warn!(error = %error, "media worker user listing failed");
            return;
        }
    };
    let mut tasks = JoinSet::new();
    for user_id in users {
        if tasks.len() >= MAX_CONCURRENT_USER_SWEEPS {
            if let Some(Err(error)) = tasks.join_next().await {
                warn!(error = %error, "media user worker task failed");
            }
        }
        let state = Arc::clone(state);
        tasks.spawn(async move {
            resurrect_user_failed_jobs(&state, &user_id).await;
            process_user(&state, &user_id).await;
            process_user_voice_embedding_jobs(&state, &user_id).await;
            prune_user_media(&state, &user_id).await;
        });
    }
    while let Some(result) = tasks.join_next().await {
        if let Err(error) = result {
            warn!(error = %error, "media user worker task failed");
        }
    }
}

pub fn spawn_scheduler(state: Arc<CpState>) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(WORKER_INTERVAL_SECONDS));
        loop {
            interval.tick().await;
            sweep(&state).await;
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cp::media::{
        init_schema, record_source_event, record_source_event_with_generation,
        CaptureEventManifest, StreamKind,
    };
    use crate::store::tests::{FakeGcs, FakeKms};
    use crate::store::GcsClient;

    fn job_fixture_db() -> Connection {
        crate::store::init_vec_extension();
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE app_metadata(key TEXT PRIMARY KEY,value TEXT NOT NULL); \
             CREATE TABLE episodes(id INTEGER PRIMARY KEY AUTOINCREMENT,started_at TEXT NOT NULL,ended_at TEXT NOT NULL,type TEXT,title TEXT,summary TEXT,participants TEXT,languages TEXT,action_items TEXT,model TEXT,topics TEXT,people TEXT,minute_summaries TEXT,minutes_text TEXT,substance TEXT NOT NULL DEFAULT 'normal',visual_evidence TEXT NOT NULL DEFAULT 'none',created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),updated_at TEXT,finalized_at TEXT,finalization_version INTEGER,finalization_status TEXT NOT NULL DEFAULT 'pending_horizon',finalization_error TEXT,finalization_attempted_at TEXT,finalization_attempt_count INTEGER NOT NULL DEFAULT 0,finalization_next_attempt_at TEXT,identity_revision INTEGER NOT NULL DEFAULT 0,finalized_identity_revision INTEGER NOT NULL DEFAULT 0,identity_refresh_status TEXT DEFAULT NULL,speaker_processing_status TEXT NOT NULL DEFAULT 'ready'); \
             CREATE TABLE episode_members(episode_id INTEGER NOT NULL,record_type TEXT NOT NULL,record_id INTEGER NOT NULL); \
             CREATE TABLE audio_segments(id INTEGER PRIMARY KEY,started_at TEXT NOT NULL,ended_at TEXT NOT NULL, \
             duration_seconds REAL NOT NULL,source_type TEXT NOT NULL,audio_format TEXT,transcription_status TEXT); \
             CREATE TABLE utterances(id INTEGER PRIMARY KEY,audio_segment_id INTEGER NOT NULL,start_offset_seconds REAL, \
             end_offset_seconds REAL,text TEXT,language TEXT,confidence REAL,speaker_label TEXT,source_key TEXT,speaker_observation_id INTEGER); \
             CREATE TABLE screenshots(id INTEGER PRIMARY KEY,captured_at TEXT,active_app TEXT,window_title TEXT,ocr_text TEXT, \
             salient_ocr_text TEXT,url TEXT,image_hash TEXT,source_key TEXT,display_id INTEGER,capture_context_version INTEGER, \
             capture_status TEXT,primary_bundle_id TEXT,primary_window_id INTEGER,visible_windows_json TEXT, \
             visible_windows_truncated INTEGER); \
             CREATE TABLE screen_observations(screenshot_id INTEGER PRIMARY KEY,input_revision TEXT,observation_version INTEGER, \
             status TEXT,generation_method TEXT,literal_description TEXT,screen_state TEXT,content_type TEXT, \
             visible_text_summary TEXT,notable_items_json TEXT,model_name TEXT,prompt_version INTEGER);",
        )
        .unwrap();
        init_schema(&conn).unwrap();
        conn
    }

    #[test]
    fn media_inference_has_bounded_sweep_and_retry_exposure() {
        assert_eq!(MAX_JOBS_PER_USER_PER_SWEEP, 2);
        assert_eq!(MAX_ATTEMPTS, 3);
        // Resurrection bounds: at most one extra attempt per hour, a hard
        // total-attempt cap, and only for recent events — worst case six
        // extra inference attempts per item, spread over six hours — with a
        // per-sweep cap so a mass outage cannot starve live capture.
        assert_eq!(RESURRECTION_DELAY_SECONDS, 3_600.0);
        assert_eq!(RESURRECTION_TOTAL_ATTEMPT_CAP, 9);
        assert_eq!(RESURRECTION_WINDOW_SECONDS, 604_800.0);
        assert_eq!(RESURRECTION_MAX_PER_SWEEP, 16);
        assert_eq!(RESURRECTION_MEMORY_HOLD_TOTAL_ATTEMPTS, MAX_ATTEMPTS + 2);
    }

    #[test]
    fn recoverable_span_predicate_holds_only_for_recoverable_failures() {
        let conn = job_fixture_db();
        let manifest = numbered_audio_manifest(0);
        record_source_event(
            &conn,
            "account-1",
            &manifest,
            &format!("{:064x}", 1),
            "raw/hold-0",
        )
        .unwrap();
        let from = "2026-07-31T17:00:00.000Z";
        let to = "2026-07-31T19:00:00.000Z";
        let window_start = "2026-07-30T00:00:00.000Z";

        // Queued work in the span holds the cursor.
        assert!(span_has_recoverable_media(&conn, from, to, window_start).unwrap());

        // A terminal failure inside the memory-hold rounds still holds.
        conn.execute(
            "UPDATE media_objects SET processing_state='failed' WHERE event_id=?1",
            [&manifest.event_id],
        )
        .unwrap();
        conn.execute(
            "UPDATE media_processing_jobs SET state='failed_terminal', \
             error_code='processing_error',attempt_count=3",
            [],
        )
        .unwrap();
        assert!(span_has_recoverable_media(&conn, from, to, window_start).unwrap());

        // Beyond the memory-hold attempts the cursor may advance.
        conn.execute(
            "UPDATE media_processing_jobs SET attempt_count=?1",
            [RESURRECTION_MEMORY_HOLD_TOTAL_ATTEMPTS],
        )
        .unwrap();
        assert!(!span_has_recoverable_media(&conn, from, to, window_start).unwrap());

        // Deterministic integrity failures never hold.
        conn.execute(
            "UPDATE media_processing_jobs SET attempt_count=3,error_code='media_integrity'",
            [],
        )
        .unwrap();
        assert!(!span_has_recoverable_media(&conn, from, to, window_start).unwrap());

        // Events older than the resurrection window never hold.
        conn.execute(
            "UPDATE media_processing_jobs SET error_code='processing_error'",
            [],
        )
        .unwrap();
        assert!(!span_has_recoverable_media(&conn, from, to, "2026-08-05T00:00:00.000Z").unwrap());

        // A span that does not overlap the event never holds.
        assert!(!span_has_recoverable_media(
            &conn,
            "2026-07-31T19:00:00.000Z",
            "2026-07-31T20:00:00.000Z",
            window_start
        )
        .unwrap());

        // Fully processed media never holds.
        conn.execute("UPDATE media_objects SET processing_state='ready'", [])
            .unwrap();
        conn.execute("UPDATE media_processing_jobs SET state='succeeded'", [])
            .unwrap();
        assert!(!span_has_recoverable_media(&conn, from, to, window_start).unwrap());
    }

    #[test]
    fn budget_deferral_terminalizes_events_past_the_resurrection_window() {
        let conn = job_fixture_db();
        let manifest = numbered_audio_manifest(0);
        record_source_event(
            &conn,
            "account-1",
            &manifest,
            &format!("{:064x}", 1),
            "raw/defer-0",
        )
        .unwrap();
        let job = lease_next_job(&conn, "2026-07-31T18:00:06.000Z")
            .unwrap()
            .expect("claimable job");

        // Within the window: deferral parks the job and refunds the attempt.
        defer_for_budget(&conn, job.id, "2026-08-01T00:00:00.000Z").unwrap();
        let (state, attempts, processing_state) = job_state(&conn, &manifest.event_id);
        assert_eq!(state, "retry_wait");
        assert_eq!(attempts, 0);
        assert_eq!(processing_state, "retry_wait");

        // Past the window: deferral gives up honestly instead of cycling a
        // week-old job through claim → defer forever.
        let job = lease_next_job(&conn, "2026-08-02T00:00:01.000Z")
            .unwrap()
            .expect("reclaimable job");
        defer_for_budget(&conn, job.id, "2026-08-10T00:00:00.000Z").unwrap();
        let (state, _, processing_state) = job_state(&conn, &manifest.event_id);
        assert_eq!(state, "failed_terminal");
        assert_eq!(processing_state, "failed");
    }

    fn job_state(conn: &Connection, event_id: &str) -> (String, i64, String) {
        conn.query_row(
            "SELECT j.state, j.attempt_count, m.processing_state \
             FROM media_processing_jobs j JOIN media_objects m ON m.event_id=j.event_id \
             WHERE j.event_id=?1",
            [event_id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap()
    }

    #[test]
    fn resurrection_grants_one_hourly_attempt_until_the_hard_cap() {
        let conn = job_fixture_db();
        let manifest = numbered_audio_manifest(0);
        record_source_event(
            &conn,
            "account-1",
            &manifest,
            &format!("{:064x}", 1),
            "raw/resurrect-0",
        )
        .unwrap();

        // Exhaust the fast ladder: three lease+fail rounds reach terminal.
        for round in 0..3 {
            let at = isotime::add_seconds("2026-07-31T19:00:00.000Z", round as f64 * 3_600.0);
            let job = lease_next_job(&conn, &at).unwrap().expect("claimable job");
            mark_failed(&conn, job.id, "processing_error", &at).unwrap();
        }
        let (state, attempts, processing_state) = job_state(&conn, &manifest.event_id);
        assert_eq!(state, "failed_terminal");
        assert_eq!(attempts, 3);
        assert_eq!(processing_state, "failed");

        // Less than the resurrection delay after the terminal failure:
        // nothing moves.
        assert_eq!(
            resurrect_failed_jobs(&conn, "2026-07-31T21:30:00.000Z").unwrap(),
            0
        );

        // Each delay-spaced resurrection grants exactly one more attempt and
        // the next failure re-terminalizes, until the hard cap refuses.
        let mut at = "2026-07-31T23:00:00.000Z".to_string();
        let mut resurrections = 0;
        loop {
            let moved = resurrect_failed_jobs(&conn, &at).unwrap();
            if moved == 0 {
                break;
            }
            resurrections += moved;
            let (state, _, processing_state) = job_state(&conn, &manifest.event_id);
            assert_eq!(state, "retry_wait");
            assert_eq!(processing_state, "retry_wait");
            let job = lease_next_job(&conn, &at)
                .unwrap()
                .expect("resurrected job");
            mark_failed(&conn, job.id, "processing_error", &at).unwrap();
            assert_eq!(job_state(&conn, &manifest.event_id).0, "failed_terminal");
            at = isotime::add_seconds(&at, 2.0 * 3_600.0);
        }
        assert_eq!(
            resurrections as i64,
            RESURRECTION_TOTAL_ATTEMPT_CAP - MAX_ATTEMPTS
        );
        assert_eq!(
            job_state(&conn, &manifest.event_id).1,
            RESURRECTION_TOTAL_ATTEMPT_CAP
        );
    }

    #[test]
    fn resurrection_skips_integrity_failures_and_stale_events() {
        let conn = job_fixture_db();
        let manifest = numbered_audio_manifest(0);
        record_source_event(
            &conn,
            "account-1",
            &manifest,
            &format!("{:064x}", 1),
            "raw/resurrect-1",
        )
        .unwrap();
        for round in 0..3 {
            let at = isotime::add_seconds("2026-07-31T19:00:00.000Z", round as f64 * 3_600.0);
            let job = lease_next_job(&conn, &at).unwrap().expect("claimable job");
            mark_failed(&conn, job.id, "media_integrity", &at).unwrap();
        }
        assert_eq!(job_state(&conn, &manifest.event_id).0, "failed_terminal");

        // A deterministic integrity failure never earns more inference.
        assert_eq!(
            resurrect_failed_jobs(&conn, "2026-08-01T12:00:00.000Z").unwrap(),
            0
        );

        // Even a resurrectable error code stops once the event leaves the
        // recency window.
        conn.execute(
            "UPDATE media_processing_jobs SET error_code='processing_error'",
            [],
        )
        .unwrap();
        assert_eq!(
            resurrect_failed_jobs(&conn, "2026-08-01T12:00:00.000Z").unwrap(),
            1
        );
        let job = lease_next_job(&conn, "2026-08-01T12:00:00.000Z")
            .unwrap()
            .expect("resurrected job");
        mark_failed(
            &conn,
            job.id,
            "processing_error",
            "2026-08-01T12:00:00.000Z",
        )
        .unwrap();
        assert_eq!(
            resurrect_failed_jobs(&conn, "2026-08-10T12:00:00.000Z").unwrap(),
            0,
            "events older than the window stay terminal"
        );
    }

    fn manifest() -> CaptureEventManifest {
        serde_json::from_value(json!({
            "schema_version":2,"event_id":"event-1","device_id":"device-1","install_id":"install-1",
            "capture_session_id":"session-1","stream_id":"stream-1","stream_kind":"mic","sequence":0,
            "source_wall_at":"2026-07-31T18:00:00.000Z","source_monotonic_ns":1,
            "started_at":"2026-07-31T18:00:00.000Z","ended_at":"2026-07-31T18:00:05.000Z",
            "timezone_id":"UTC","utc_offset_minutes":0,"clock_uncertainty_ms":1,
            "media":{"asset_id":"asset-1","mime_type":"audio/m4a","codec":"aac","byte_length":12,
            "sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "sample_rate":48000,"channels":1,"frame_count":240000},"context":null
        }))
        .unwrap()
    }

    fn system_manifest() -> CaptureEventManifest {
        let mut value = manifest();
        value.stream_kind = StreamKind::SystemAudio;
        value.stream_id = "system-stream-1".into();
        value
    }

    fn numbered_audio_manifest(index: i64) -> CaptureEventManifest {
        let mut value = manifest();
        value.event_id = format!("event-{index}");
        value.stream_id = "audio-window-stream".into();
        value.sequence = index;
        value.source_monotonic_ns = (index + 1) as u64;
        value.started_at = isotime::add_seconds("2026-07-31T18:00:00.000Z", index as f64 * 5.0);
        value.ended_at = isotime::add_seconds(&value.started_at, 5.0);
        value.source_wall_at = value.started_at.clone();
        let media = value.media.as_mut().unwrap();
        media.asset_id = format!("asset-{index}");
        media.sha256 = format!("{:064x}", index + 100);
        value
    }

    fn screen_manifest() -> CaptureEventManifest {
        serde_json::from_value(json!({
            "schema_version":2,"event_id":"screen-event-1","device_id":"device-1","install_id":"install-1",
            "capture_session_id":"session-1","stream_id":"screen-stream-1","stream_kind":"mac_screen","sequence":0,
            "source_wall_at":"2026-07-31T18:00:01.000Z","source_monotonic_ns":2,
            "started_at":"2026-07-31T18:00:01.000Z","ended_at":"2026-07-31T18:00:01.001Z",
            "timezone_id":"UTC","utc_offset_minutes":0,"clock_uncertainty_ms":1,
            "media":{"asset_id":"screen-asset-1","mime_type":"image/jpeg","codec":"jpeg","byte_length":4,
            "sha256":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
            "width":1,"height":1,"scale":1,"orientation":"up"},
            "context":{"capture_status":"stable","active_app":"Google Chrome","primary_bundle_id":"com.google.Chrome",
            "primary_window_id":7,"window_title":"Meeting","display_id":1,"active_url":"https://meet.google.com/abc",
            "active_url_title":"Meeting","browser_permission_status":"granted","browser_state_key":null,
            "browser_snapshot":null,"visible_windows":[],"visible_windows_truncated":false}
        }))
        .unwrap()
    }

    fn numbered_screen_manifest(index: i64) -> CaptureEventManifest {
        let mut value = screen_manifest();
        value.event_id = format!("screen-event-{index}");
        value.sequence = index;
        value.source_monotonic_ns += index as u64;
        value.started_at = isotime::add_seconds(&value.started_at, index as f64 * 3.5);
        value.ended_at = isotime::add_seconds(&value.started_at, 0.001);
        value.source_wall_at = value.started_at.clone();
        let media = value.media.as_mut().unwrap();
        media.asset_id = format!("screen-asset-{index}");
        media.sha256 = format!("{:064x}", index + 200);
        value
    }

    fn unnamed_turn() -> AudioTurn {
        AudioTurn {
            turn_id: "turn-1".into(),
            start_ms: 0,
            end_ms: 5_000,
            speaker_local_id: "speaker-1".into(),
            text: "The launch is ready".into(),
            language: Some("en".into()),
            speaker_name: None,
            speaker_name_confidence: None,
            speaker_name_evidence: None,
            speaker_name_kind: None,
            speaker_name_subject_turn_id: None,
            speaker_name_target_turn_id: None,
            person_facts: vec![],
            overlap: false,
            quality_flags: vec![],
        }
    }

    fn enrolled_voiceprint() -> super::super::voice_memory::EmbeddedTurn {
        enrolled_voiceprint_for("turn-1", vec![0.0625; 256])
    }

    fn enrolled_voiceprint_for(
        turn_id: &str,
        embedding: Vec<f32>,
    ) -> super::super::voice_memory::EmbeddedTurn {
        super::super::voice_memory::EmbeddedTurn {
            turn_id: turn_id.into(),
            embedding: Some(embedding),
            diagnostics: super::super::voice_quality::diagnose(
                &vec![0.2; super::super::voice_quality::SAMPLE_RATE as usize * 4],
                false,
                &[],
            ),
        }
    }

    fn persist_single_audio_work(
        conn: &Connection,
        turns: &[AudioTurn],
        voiceprints: &[super::super::voice_memory::EmbeddedTurn],
    ) {
        record_source_event(
            conn,
            "account-1",
            &manifest(),
            &"b".repeat(64),
            "raw/object",
        )
        .unwrap();
        let work = lease_work_unit(conn, "2026-07-31T18:01:00.000Z", WorkClass::Audio)
            .unwrap()
            .unwrap();
        persist_audio_window_result(
            conn,
            &work.id,
            &work.jobs,
            &[SourceInterval::new("event-1", 0, 5_000)],
            turns,
            voiceprints,
        )
        .unwrap();
    }

    fn persisted_speaker_labels(conn: &Connection) -> Vec<String> {
        conn.prepare("SELECT speaker_label FROM utterances ORDER BY id")
            .unwrap()
            .query_map([], |row| row.get(0))
            .unwrap()
            .collect::<std::result::Result<Vec<_>, _>>()
            .unwrap()
    }

    fn active_speaker_screen() -> ScreenResult {
        ScreenResult {
            literal_description: "John Garcia is visibly marked as speaking".into(),
            screen_state: "meeting".into(),
            content_type: "video_call".into(),
            visible_text: "John Garcia".into(),
            salient_text: "John Garcia".into(),
            people: vec![PersonEvidence {
                name: "John Garcia".into(),
                evidence: "The John Garcia tile has the active-speaker ring".into(),
                confidence: 0.99,
                is_active_speaker: true,
            }],
        }
    }

    fn roster_only_screen() -> ScreenResult {
        let mut result = active_speaker_screen();
        result.people[0].is_active_speaker = false;
        result.people[0].evidence = "John Garcia is visible only in the attendee roster".into();
        result
    }

    fn storyboard_json(ids: &[&str]) -> String {
        json!({
            "frames": ids.iter().map(|id| json!({
                "frame_id":id,
                "literal_description":"A meeting frame",
                "screen_state":"meeting",
                "content_type":"video_call",
                "visible_text":"John Garcia",
                "salient_text":"John Garcia",
                "people":[]
            })).collect::<Vec<_>>()
        })
        .to_string()
    }

    fn assert_john_bound(conn: &Connection) {
        let profile_name: String = conn
            .query_row(
                "SELECT p.display_name FROM voice_profiles v JOIN people p ON p.id=v.person_id",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(profile_name, "John Garcia");
        let label: String = conn
            .query_row("SELECT speaker_label FROM utterances", [], |row| row.get(0))
            .unwrap();
        assert_eq!(label, "John Garcia");
    }

    #[test]
    fn lease_is_exclusive_and_expired_leases_are_recoverable() {
        let conn = job_fixture_db();
        record_source_event(
            &conn,
            "account-1",
            &manifest(),
            &"b".repeat(64),
            "raw/object",
        )
        .unwrap();
        let first = lease_next_job(&conn, "2026-07-31T18:00:06.000Z")
            .unwrap()
            .unwrap();
        assert_eq!(first.event_id, "event-1");
        assert!(lease_next_job(&conn, "2026-07-31T18:00:07.000Z")
            .unwrap()
            .is_none());
        assert!(lease_next_job(&conn, "2026-07-31T18:06:00.000Z")
            .unwrap()
            .is_some());
    }

    #[test]
    fn work_unit_lease_batches_adjacent_audio_with_durable_offset_members() {
        let conn = job_fixture_db();
        for index in 0..3 {
            let manifest = numbered_audio_manifest(index);
            record_source_event(
                &conn,
                "account-1",
                &manifest,
                &format!("{:064x}", index + 1),
                &format!("raw/audio-{index}"),
            )
            .unwrap();
        }
        let work = lease_work_unit(&conn, "2026-07-31T18:01:00.000Z", WorkClass::Audio)
            .unwrap()
            .unwrap();
        assert_eq!(work.jobs.len(), 3);
        assert_eq!(
            work.jobs.iter().map(|job| job.sequence).collect::<Vec<_>>(),
            vec![0, 1, 2]
        );
        let offsets = conn
            .prepare(
                "SELECT window_start_ms,window_end_ms FROM media_work_members \
                 WHERE work_unit_id=?1 ORDER BY ordinal",
            )
            .unwrap()
            .query_map([&work.id], |row| {
                Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?))
            })
            .unwrap()
            .collect::<std::result::Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(offsets, vec![(0, 5_000), (5_000, 10_000), (10_000, 15_000)]);
        assert!(
            lease_work_unit(&conn, "2026-07-31T18:01:01.000Z", WorkClass::Audio)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn storyboard_requires_exact_frame_coverage_and_restores_input_order() {
        let expected = vec!["frame-a".to_string(), "frame-b".to_string()];
        let ordered =
            validate_storyboard_result(&storyboard_json(&["frame-b", "frame-a"]), &expected)
                .unwrap();
        assert_eq!(
            ordered.into_iter().map(|(id, _)| id).collect::<Vec<_>>(),
            expected
        );
        assert!(validate_storyboard_result(&storyboard_json(&["frame-a"]), &expected).is_err());
        assert!(
            validate_storyboard_result(&storyboard_json(&["frame-a", "frame-a"]), &expected)
                .is_err()
        );
        assert!(
            validate_storyboard_result(&storyboard_json(&["frame-a", "unknown"]), &expected)
                .is_err()
        );
    }

    #[test]
    fn cross_event_audio_turn_persists_exact_source_projection() {
        let conn = job_fixture_db();
        for index in 0..2 {
            let manifest = numbered_audio_manifest(index);
            record_source_event(
                &conn,
                "account-1",
                &manifest,
                &format!("{:064x}", index + 1),
                &format!("raw/audio-{index}"),
            )
            .unwrap();
        }
        let work = lease_work_unit(&conn, "2026-07-31T18:01:00.000Z", WorkClass::Audio)
            .unwrap()
            .unwrap();
        let sources = vec![
            SourceInterval::new("event-0", 0, 5_000),
            SourceInterval::new("event-1", 5_000, 10_000),
        ];
        let mut turn = unnamed_turn();
        turn.start_ms = 4_500;
        turn.end_ms = 5_500;
        persist_audio_window_result(&conn, &work.id, &work.jobs, &sources, &[turn], &[]).unwrap();
        let mappings = conn
            .prepare(
                "SELECT event_id,window_start_ms,window_end_ms,event_start_ms,event_end_ms \
                 FROM speaker_observation_sources ORDER BY event_id",
            )
            .unwrap()
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, i64>(4)?,
                ))
            })
            .unwrap()
            .collect::<std::result::Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(
            mappings,
            vec![
                ("event-0".into(), 4_500, 5_000, 4_500, 5_000),
                ("event-1".into(), 5_000, 5_500, 0, 500),
            ]
        );
    }

    #[test]
    fn unmatched_request_local_speaker_id_is_not_persisted_as_identity() {
        let conn = job_fixture_db();
        // Single speaker on legacy "mic" is request_local (not owner_transmit).
        // Before episode slot allocation, it resolves to UNIDENTIFIED_SPEAKER_LABEL.
        persist_single_audio_work(&conn, &[unnamed_turn()], &[]);
        assert_eq!(
            persisted_speaker_labels(&conn),
            vec![super::super::media::UNIDENTIFIED_SPEAKER_LABEL]
        );
        let external_person_count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM people WHERE kind = 'person'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(
            external_person_count, 0,
            "unresolved speakers must not create a person record"
        );
    }

    #[test]
    fn synthetic_pipeline_learns_frankie_and_refreshes_prior_episode() {
        let conn = job_fixture_db();

        // 1. Create historical Episode 335 (finalized, with anonymous speaker)
        conn.execute(
            "INSERT INTO episodes (id, started_at, ended_at, type, title, summary, participants, finalized_at, finalization_version, finalization_status, identity_revision, finalized_identity_revision, identity_refresh_status) \
             VALUES (335, '2026-07-31T18:00:00.000Z', '2026-07-31T18:05:00.000Z', 'conversation', 'Launch Sync', 'Sync on launch', '[]', '2026-07-31T18:05:00.000Z', 5, 'complete', 1, 1, 'ready')",
            [],
        ).unwrap();

        // 2. Ingest first work unit for Episode 335 with unnamed remote voice
        let embedding_vector = vec![0.1f32; 256];
        let mut turn1 = unnamed_turn();
        turn1.turn_id = "turn-ep335-1".into();
        turn1.text = "Deployment looks good on our end".into();
        persist_single_audio_work(
            &conn,
            &[turn1],
            &[enrolled_voiceprint_for(
                "turn-ep335-1",
                embedding_vector.clone(),
            )],
        );

        // Bind utterance 1 to Episode 335
        conn.execute(
            "INSERT INTO episode_members (episode_id, record_id, record_type) VALUES (335, 1, 'utterance')",
            [],
        ).unwrap();

        // Initial reconciliation: speaker is anonymous slot A
        crate::cp::identity::reconcile_episode_speaker_slots(&conn, 335).unwrap();
        let turn1_label: String = conn
            .query_row(
                "SELECT speaker_label FROM utterances WHERE id = 1",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(turn1_label, "Unknown speaker A");

        // 3. Ingest subsequent work unit: the same voice explicitly self-identifies as "Frankie"
        let mut manifest2 = manifest();
        manifest2.event_id = "event-ep336-1".into();
        manifest2.stream_id = "stream-2".into();
        manifest2.started_at = "2026-07-31T18:10:00.000Z".into();
        manifest2.ended_at = "2026-07-31T18:15:00.000Z".into();
        manifest2.media.as_mut().unwrap().asset_id = "asset-2".into();
        manifest2.media.as_mut().unwrap().sha256 = "c".repeat(64);

        record_source_event(
            &conn,
            "account-1",
            &manifest2,
            &"c".repeat(64),
            "raw/object2",
        )
        .unwrap();
        let work2 = lease_work_unit(&conn, "2026-07-31T18:16:00.000Z", WorkClass::Audio)
            .unwrap()
            .unwrap();

        let mut turn2 = unnamed_turn();
        turn2.turn_id = "turn-ep336-1".into();
        turn2.text = "Hi, I'm Frankie from the infra team".into();
        turn2.speaker_name = Some("Frankie".into());
        turn2.speaker_name_confidence = Some(0.95);
        turn2.speaker_name_evidence = Some("I'm Frankie".into());
        turn2.speaker_name_kind = Some("self_identification".into());
        turn2.speaker_name_subject_turn_id = Some("turn-ep336-1".into());
        turn2.speaker_name_target_turn_id = None;

        persist_audio_window_result(
            &conn,
            &work2.id,
            &work2.jobs,
            &[SourceInterval::new("event-ep336-1", 0, 5_000)],
            &[turn2],
            &[enrolled_voiceprint_for("turn-ep336-1", embedding_vector)],
        )
        .unwrap();

        // 4. Verify automatic pipeline outcome:
        // - Person "Frankie" was automatically created
        let person_name: String = conn
            .query_row(
                "SELECT display_name FROM people WHERE display_name = 'Frankie'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(person_name, "Frankie");

        // - Profile identity binding is active and accepted
        let bound_person_id: Option<i64> = conn
            .query_row(
                "SELECT b.person_id FROM profile_identity_bindings b \
                 JOIN people p ON p.id = b.person_id \
                 WHERE p.display_name = 'Frankie' AND b.active = 1 AND b.state = 'accepted'",
                [],
                |r| r.get(0),
            )
            .optional()
            .unwrap();
        assert!(bound_person_id.is_some());

        // - Episode 335 was automatically queued for IdentityRefresh
        let (identity_rev, fin_identity_rev, refresh_status): (i64, i64, String) = conn
            .query_row(
                "SELECT identity_revision, finalized_identity_revision, identity_refresh_status FROM episodes WHERE id = 335",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .unwrap();
        assert_eq!(refresh_status, "queued");
        assert!(fin_identity_rev < identity_rev);

        // 5. Simulate Finalizer processing Episode 335 in IdentityRefresh mode:
        crate::cp::identity::reconcile_episode_speaker_slots(&conn, 335).unwrap();
        let turn1_updated_label: String = conn
            .query_row(
                "SELECT speaker_label FROM utterances WHERE id = 1",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(turn1_updated_label, "Frankie");

        let updated_participants: String = conn
            .query_row(
                "SELECT participants FROM episodes WHERE id = 335",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(updated_participants, "[\"Frankie\"]");
    }

    #[test]
    fn unique_voice_resolution_labels_same_local_id_siblings_within_work_unit() {
        let conn = job_fixture_db();
        let mut unresolved = unnamed_turn();
        unresolved.end_ms = 500;
        unresolved.text = "What?".into();
        let mut resolved = unnamed_turn();
        resolved.turn_id = "turn-2".into();
        resolved.start_ms = 500;
        resolved.text = "The rest of the launch plan is ready".into();
        persist_single_audio_work(
            &conn,
            &[unresolved, resolved],
            &[enrolled_voiceprint_for("turn-2", vec![0.0625; 256])],
        );
        assert_eq!(persisted_speaker_labels(&conn), vec!["Voice 1", "Voice 1"]);
    }

    #[test]
    fn schema_migration_repairs_historical_request_local_labels() {
        let conn = job_fixture_db();
        let mut unresolved = unnamed_turn();
        unresolved.end_ms = 500;
        unresolved.text = "What?".into();
        let mut resolved = unnamed_turn();
        resolved.turn_id = "turn-2".into();
        resolved.start_ms = 500;
        persist_single_audio_work(
            &conn,
            &[unresolved, resolved],
            &[enrolled_voiceprint_for("turn-2", vec![0.0625; 256])],
        );
        conn.execute(
            "UPDATE utterances SET speaker_label='speaker-1' WHERE id=(SELECT MIN(id) FROM utterances)",
            [],
        )
        .unwrap();
        conn.execute(
            "DELETE FROM app_metadata WHERE key='request-local-speaker-labels-v1'",
            [],
        )
        .unwrap();

        init_schema(&conn).unwrap();

        assert_eq!(persisted_speaker_labels(&conn), vec!["Voice 1", "Voice 1"]);
        let completed: bool = conn
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM app_metadata WHERE key='request-local-speaker-labels-v1')",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert!(completed);
    }

    #[test]
    fn voice_resolution_does_not_cross_request_local_speaker_ids() {
        let conn = job_fixture_db();
        let mut unresolved = unnamed_turn();
        unresolved.end_ms = 500;
        unresolved.text = "What?".into();
        let mut resolved = unnamed_turn();
        resolved.turn_id = "turn-2".into();
        resolved.start_ms = 500;
        resolved.speaker_local_id = "speaker-2".into();
        resolved.text = "A different voice continues the launch plan".into();
        persist_single_audio_work(
            &conn,
            &[unresolved, resolved],
            &[enrolled_voiceprint_for("turn-2", vec![0.0625; 256])],
        );
        assert_eq!(
            persisted_speaker_labels(&conn),
            vec![super::super::media::UNIDENTIFIED_SPEAKER_LABEL, "Voice 1"]
        );
    }

    #[test]
    fn conflicting_voice_resolutions_do_not_claim_an_unresolved_sibling() {
        let conn = job_fixture_db();
        let mut unresolved = unnamed_turn();
        unresolved.end_ms = 500;
        unresolved.text = "What?".into();
        let mut first_voice = unnamed_turn();
        first_voice.turn_id = "turn-2".into();
        first_voice.start_ms = 500;
        first_voice.end_ms = 2_500;
        let mut second_voice = unnamed_turn();
        second_voice.turn_id = "turn-3".into();
        second_voice.start_ms = 2_500;
        second_voice.text = "Another voice has a different embedding".into();
        let mut orthogonal = vec![0.0; 256];
        orthogonal[0] = 1.0;
        persist_single_audio_work(
            &conn,
            &[unresolved, first_voice, second_voice],
            &[
                enrolled_voiceprint_for("turn-2", vec![0.0625; 256]),
                enrolled_voiceprint_for("turn-3", orthogonal),
            ],
        );
        assert_eq!(
            persisted_speaker_labels(&conn),
            vec![
                super::super::media::UNIDENTIFIED_SPEAKER_LABEL,
                "Voice 1",
                "Voice 2"
            ]
        );
    }

    #[test]
    fn named_audio_turn_builds_searchable_transcript_and_person_evidence_atomically() {
        let conn = job_fixture_db();
        record_source_event(
            &conn,
            "account-1",
            &manifest(),
            &"b".repeat(64),
            "raw/object",
        )
        .unwrap();
        let job = lease_next_job(&conn, "2026-07-31T18:00:06.000Z")
            .unwrap()
            .unwrap();
        let turns = vec![AudioTurn {
            turn_id: "turn-1".into(),
            start_ms: 0,
            end_ms: 1000,
            speaker_local_id: "speaker-1".into(),
            text: "I'm John Garcia".into(),
            language: Some("en".into()),
            speaker_name: Some("John Garcia".into()),
            speaker_name_confidence: Some(0.98),
            speaker_name_evidence: Some("I'm John Garcia".into()),
            speaker_name_kind: Some("self_identification".into()),
            speaker_name_subject_turn_id: Some("turn-1".into()),
            speaker_name_target_turn_id: None,
            person_facts: vec![crate::cp::media::PersonFact {
                predicate: "organization".into(),
                value: "Northwind".into(),
                evidence: "I work at Northwind".into(),
            }],
            overlap: false,
            quality_flags: vec![],
        }];
        persist_audio_result(&conn, &job, &turns, &[]).unwrap();
        let label: String = conn
            .query_row("SELECT speaker_label FROM utterances", [], |row| row.get(0))
            .unwrap();
        assert_eq!(label, "John Garcia");
        let person_count: i64 = conn
            .query_row(
                "SELECT COUNT(DISTINCT person_id) FROM person_name_claims \
                 WHERE normalized_name='john garcia' AND status='accepted'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(person_count, 1);
        let fact_count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM person_facts WHERE predicate='organization' AND value='Northwind'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(fact_count, 1);
        let state: String = conn
            .query_row("SELECT state FROM media_processing_jobs", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(state, "succeeded");
    }

    #[test]
    fn two_different_voices_with_the_same_complete_name_remain_distinct_people() {
        let conn = job_fixture_db();
        for index in 0..2 {
            let manifest = numbered_audio_manifest(index);
            record_source_event(
                &conn,
                "account-1",
                &manifest,
                &format!("{:064x}", index + 1),
                &format!("raw/same-name-{index}"),
            )
            .unwrap();
            let job = lease_next_job(&conn, "2026-07-31T18:01:00.000Z")
                .unwrap()
                .unwrap();
            let turn_id = format!("turn-{index}");
            let turn = AudioTurn {
                turn_id: turn_id.clone(),
                start_ms: 0,
                end_ms: 4_000,
                speaker_local_id: format!("speaker-{index}"),
                text: "I'm John Smith".into(),
                language: Some("en".into()),
                speaker_name: Some("John Smith".into()),
                speaker_name_confidence: Some(0.99),
                speaker_name_evidence: Some("I'm John Smith".into()),
                speaker_name_kind: Some("self_identification".into()),
                speaker_name_subject_turn_id: Some(turn_id.clone()),
                speaker_name_target_turn_id: None,
                person_facts: vec![],
                overlap: false,
                quality_flags: vec![],
            };
            let mut embedding = vec![0.0; 256];
            embedding[index as usize] = 1.0;
            persist_audio_result(
                &conn,
                &job,
                &[turn],
                &[enrolled_voiceprint_for(&turn_id, embedding)],
            )
            .unwrap();
        }
        let people: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM people WHERE display_name='John Smith'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(people, 2);
        let accepted: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM profile_identity_bindings WHERE active = 1 AND state = 'accepted'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(accepted, 2);
        let linked_profiles: i64 = conn
            .query_row(
                "SELECT COUNT(DISTINCT person_id) FROM voice_profiles WHERE person_id IS NOT NULL",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(linked_profiles, 2);
    }

    #[test]
    fn roster_names_alone_never_create_or_bind_a_person() {
        let conn = job_fixture_db();
        for index in 0..2 {
            record_source_event(
                &conn,
                "account-1",
                &numbered_screen_manifest(index),
                &format!("{:064x}", index + 10),
                &format!("raw/roster-{index}"),
            )
            .unwrap();
            let job = lease_next_job(&conn, "2026-07-31T18:00:04.000Z")
                .unwrap()
                .unwrap();
            persist_screen_result(&conn, &job, &roster_only_screen()).unwrap();
        }
        let people: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM people WHERE kind <> 'owner'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(people, 0);
        let proposed: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM person_name_claims WHERE status='proposed'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(proposed, 2);
    }

    #[test]
    fn later_voice_attributed_facts_are_provenanced_and_temporally_supersede() {
        let conn = job_fixture_db();
        for index in 0..2 {
            let manifest = numbered_audio_manifest(index);
            record_source_event(
                &conn,
                "account-1",
                &manifest,
                &format!("{:064x}", index + 1),
                &format!("raw/fact-{index}"),
            )
            .unwrap();
            let job = lease_next_job(&conn, "2026-07-31T18:01:00.000Z")
                .unwrap()
                .unwrap();
            let mut turn = unnamed_turn();
            turn.turn_id = format!("fact-turn-{index}");
            turn.start_ms = 0;
            turn.end_ms = 4_000;
            turn.person_facts = vec![crate::cp::media::PersonFact {
                predicate: "role".into(),
                value: if index == 0 { "Engineer" } else { "CTO" }.into(),
                evidence: if index == 0 {
                    "I am an engineer"
                } else {
                    "I am now the CTO"
                }
                .into(),
            }];
            if index == 0 {
                turn.text = "I'm John Garcia, and I am an engineer".into();
                turn.speaker_name = Some("John Garcia".into());
                turn.speaker_name_confidence = Some(0.99);
                turn.speaker_name_evidence = Some("I'm John Garcia".into());
                turn.speaker_name_kind = Some("self_identification".into());
                turn.speaker_name_subject_turn_id = Some(turn.turn_id.clone());
                turn.speaker_name_target_turn_id = None;
            } else {
                turn.text = "I am now the CTO".into();
            }
            let voiceprint = enrolled_voiceprint_for(&turn.turn_id, vec![0.0625; 256]);
            persist_audio_result(&conn, &job, &[turn], &[voiceprint]).unwrap();
        }
        let facts = conn
            .prepare(
                "SELECT value,status,source_event_id,speaker_observation_id,literal_evidence,\
                        supersedes_id FROM person_facts ORDER BY id",
            )
            .unwrap()
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, Option<String>>(2)?,
                    row.get::<_, Option<i64>>(3)?,
                    row.get::<_, Option<String>>(4)?,
                    row.get::<_, Option<i64>>(5)?,
                ))
            })
            .unwrap()
            .collect::<std::result::Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(facts.len(), 2);
        assert_eq!(facts[0].0, "Engineer");
        assert_eq!(facts[0].1, "superseded");
        assert_eq!(facts[1].0, "CTO");
        assert_eq!(facts[1].1, "active");
        assert!(facts[1].2.is_some());
        assert!(facts[1].3.is_some());
        assert_eq!(facts[1].4.as_deref(), Some("I am now the CTO"));
        assert_eq!(facts[1].5, Some(1));
    }

    #[test]
    fn active_speaker_screen_processed_first_names_the_later_voice_profile() {
        let conn = job_fixture_db();
        for index in 0..2 {
            record_source_event(
                &conn,
                "account-1",
                &numbered_screen_manifest(index),
                &format!("{:064x}", index + 10),
                &format!("raw/screen-{index}"),
            )
            .unwrap();
            let screen_job = lease_next_job(&conn, "2026-07-31T18:00:04.000Z")
                .unwrap()
                .unwrap();
            persist_screen_result(&conn, &screen_job, &active_speaker_screen()).unwrap();
        }

        record_source_event(
            &conn,
            "account-1",
            &system_manifest(),
            &"e".repeat(64),
            "raw/audio",
        )
        .unwrap();
        let audio_job = lease_next_job(&conn, "2026-07-31T18:00:03.000Z")
            .unwrap()
            .unwrap();
        persist_audio_result(
            &conn,
            &audio_job,
            &[unnamed_turn()],
            &[enrolled_voiceprint()],
        )
        .unwrap();
        assert_john_bound(&conn);
    }

    #[test]
    fn active_speaker_screen_processed_later_relabels_the_existing_voice_profile() {
        let conn = job_fixture_db();
        record_source_event(
            &conn,
            "account-1",
            &system_manifest(),
            &"e".repeat(64),
            "raw/audio",
        )
        .unwrap();
        let audio_job = lease_next_job(&conn, "2026-07-31T18:00:01.000Z")
            .unwrap()
            .unwrap();
        persist_audio_result(
            &conn,
            &audio_job,
            &[unnamed_turn()],
            &[enrolled_voiceprint()],
        )
        .unwrap();

        for index in 0..2 {
            record_source_event(
                &conn,
                "account-1",
                &numbered_screen_manifest(index),
                &format!("{:064x}", index + 10),
                &format!("raw/screen-{index}"),
            )
            .unwrap();
            let screen_job = lease_next_job(&conn, "2026-07-31T18:00:04.000Z")
                .unwrap()
                .unwrap();
            persist_screen_result(&conn, &screen_job, &active_speaker_screen()).unwrap();
        }
        assert_john_bound(&conn);
    }

    #[tokio::test]
    async fn retention_exact_generation_waits_for_both_media_providers_before_pruning_row() {
        let indexes = Arc::new(FakeGcs::new());
        let current = Arc::new(FakeGcs::new());
        let legacy = Arc::new(FakeGcs::new());
        let store = Store::new_with_media_and_legacy(
            Arc::new(FakeKms),
            indexes,
            current.clone(),
            legacy.clone(),
        );
        let user_id = "retention-split-owner";
        let object_key = format!("raw/{user_id}/asset.enc");
        let plaintext = b"retained logical media";
        let sha256 = format!("{:x}", Sha256::digest(plaintext));
        let (dek, wrapped_dek) = crate::crypto::generate_and_wrap_dek(store.kms.as_ref())
            .await
            .unwrap();
        let ciphertext = crate::crypto::encrypt_bound_blob(
            &dek,
            plaintext,
            &crate::store::media_blob_context(user_id, &object_key),
        )
        .unwrap();
        let seed_generation = current
            .put_object(&object_key, b"older-unrelated-generation", "wrapped", 0)
            .await
            .unwrap();
        let retained_generation = current
            .put_object(&object_key, &ciphertext, &wrapped_dek, seed_generation)
            .await
            .unwrap();
        let legacy_generation = legacy
            .put_object(&object_key, &ciphertext, &wrapped_dek, 0)
            .await
            .unwrap();
        assert_ne!(legacy_generation, retained_generation);
        let mut capture = manifest();
        capture.media.as_mut().unwrap().sha256 = sha256;
        store
            .with_user(user_id, |conn| {
                record_source_event_with_generation(
                    conn,
                    user_id,
                    &capture,
                    &"d".repeat(64),
                    &object_key,
                    Some(retained_generation),
                )?;
                conn.execute(
                    "UPDATE media_objects SET processing_state='ready',retain_until='2000-01-01T00:00:00.000Z' \
                     WHERE event_id=?1",
                    [&capture.event_id],
                )?;
                Ok(())
            })
            .await
            .unwrap();
        legacy.fail_next_generation_delete(&object_key, legacy_generation);

        prune_user_media_store(&store, user_id).await;
        let after_failure: (String, Option<String>) = store
            .with_user_read(user_id, |conn| {
                Ok(conn.query_row(
                    "SELECT processing_state,deleted_at FROM media_objects WHERE event_id=?1",
                    [&capture.event_id],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )?)
            })
            .await
            .unwrap();
        assert_eq!(after_failure, ("ready".into(), None));
        assert_eq!(current.version_count(&object_key), 2);
        assert_eq!(legacy.version_count(&object_key), 1);

        prune_user_media_store(&store, user_id).await;
        let after_retry: (String, Option<String>) = store
            .with_user_read(user_id, |conn| {
                Ok(conn.query_row(
                    "SELECT processing_state,deleted_at FROM media_objects WHERE event_id=?1",
                    [&capture.event_id],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )?)
            })
            .await
            .unwrap();
        assert_eq!(after_retry.0, "pruned");
        assert!(after_retry.1.is_some());
        assert_eq!(current.version_count(&object_key), 1);
        assert_eq!(legacy.version_count(&object_key), 0);
    }

    /// Seeds repeated active-speaker visual frames for `name` inside the given
    /// window so a vocative can be independently corroborated: two distinct
    /// screen events at high confidence, more than three seconds apart.
    fn seed_visual_corroboration(conn: &Connection, name: &str, at_a: &str, at_b: &str) {
        for (i, at) in [(0, at_a), (1, at_b)] {
            conn.execute(
                "INSERT OR IGNORE INTO capture_events (event_id, device_id, install_id, capture_session_id, stream_id, stream_kind, sequence, source_wall_at, source_monotonic_ns, started_at, ended_at, timezone_id, utc_offset_minutes, clock_uncertainty_ms, asset_id, manifest_digest) \
                 VALUES (?1, 'device-1', 'install-1', 'session-1', 'audio-window-stream', 'mac_screen', ?2, ?3, ?2, ?3, ?3, 'UTC', 0, 0, ?4, ?5)",
                params![
                    format!("vse-{name}-{i}"),
                    900 + i,
                    at,
                    format!("vse-asset-{name}-{i}"),
                    format!("vse-digest-{name}-{i}")
                ],
            )
            .unwrap();
            conn.execute(
                "INSERT OR IGNORE INTO screenshots (id, captured_at, source_key) VALUES (?1, ?2, ?3)",
                params![
                    9900 + i,
                    at,
                    format!("cloud-v2:vse-{name}-{i}")
                ],
            )
            .unwrap();
            conn.execute(
                "INSERT INTO visual_speaker_observations \
                 (event_id, screenshot_id, observed_at, platform, displayed_name, normalized_name, \
                  highlight_state, bounding_box_json, model_version, confidence) \
                 VALUES (?1, ?2, ?3, 'screen_capture', ?4, ?5, 'active_speaker_box', NULL, 1, 0.95)",
                params![
                    format!("vse-{name}-{i}"),
                    9900 + i,
                    at,
                    name,
                    normalized_name(name)
                ],
            )
            .unwrap();
        }
    }

    #[test]
    fn vocative_address_with_corroboration_binds_target_person_and_propagates_to_cluster() {
        let conn = job_fixture_db();
        let manifest = numbered_audio_manifest(0);
        record_source_event(
            &conn,
            "account-1",
            &manifest,
            &"a".repeat(64),
            "raw/vocative-audio",
        )
        .unwrap();
        let job = lease_next_job(&conn, "2026-07-31T18:01:00.000Z")
            .unwrap()
            .unwrap();

        // Independent corroboration: Alice repeatedly marked as the active
        // speaker on screen around the addressed turn (window starts at the
        // manifest start; turn-2 spans +2.5s..+5s).
        seed_visual_corroboration(
            &conn,
            "Alice",
            &isotime::add_seconds(&job.started_at, 3.0),
            &isotime::add_seconds(&job.started_at, 6.5),
        );

        // 2 distinct speakers in a multi-turn conversation within 8s
        let turns = vec![
            AudioTurn {
                turn_id: "turn-1".into(),
                start_ms: 0,
                end_ms: 2000,
                speaker_local_id: "speaker-1".into(),
                text: "Hey Alice, can you review this?".into(),
                language: Some("en".into()),
                speaker_name: Some("Alice".into()),
                speaker_name_confidence: Some(0.95),
                speaker_name_evidence: Some("Hey Alice".into()),
                speaker_name_kind: Some("vocative_address".into()),
                speaker_name_subject_turn_id: None,
                speaker_name_target_turn_id: Some("turn-2".into()),
                person_facts: vec![],
                overlap: false,
                quality_flags: vec![],
            },
            AudioTurn {
                turn_id: "turn-2".into(),
                start_ms: 2500,
                end_ms: 5000,
                speaker_local_id: "speaker-2".into(),
                text: "Sure, I'll take a look now.".into(),
                language: Some("en".into()),
                speaker_name: None,
                speaker_name_confidence: None,
                speaker_name_evidence: None,
                speaker_name_kind: None,
                speaker_name_subject_turn_id: None,
                speaker_name_target_turn_id: None,
                person_facts: vec![],
                overlap: false,
                quality_flags: vec![],
            },
        ];

        let vp1 = enrolled_voiceprint_for("turn-1", vec![0.1; 256]);
        let vp2 = enrolled_voiceprint_for("turn-2", vec![0.9; 256]);

        persist_audio_result(&conn, &job, &turns, &[vp1, vp2]).unwrap();

        // Verify that Alice was created and accepted
        let alice_person_id: i64 = conn
            .query_row(
                "SELECT id FROM people WHERE display_name = 'Alice'",
                [],
                |r| r.get(0),
            )
            .unwrap();

        // Verify speaker-2's cluster is person_bound to Alice
        let (attribution_state, person_id): (String, Option<i64>) = conn
            .query_row(
                "SELECT attribution_state, person_id FROM speaker_clusters WHERE speaker_local_id = 'speaker-2'",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!(attribution_state, "person_bound");
        assert_eq!(person_id, Some(alice_person_id));

        // Verify utterance for turn-2 resolved to Alice
        let turn2_label: String = conn
            .query_row(
                "SELECT speaker_label FROM utterances WHERE source_key LIKE '%turn-2'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(turn2_label, "Alice");
    }

    #[test]
    fn uncorroborated_or_distant_vocative_remains_probationary() {
        let conn = job_fixture_db();
        let manifest = numbered_audio_manifest(0);
        record_source_event(
            &conn,
            "account-1",
            &manifest,
            &"a".repeat(64),
            "raw/uncorroborated-vocative",
        )
        .unwrap();
        let job = lease_next_job(&conn, "2026-07-31T18:01:00.000Z")
            .unwrap()
            .unwrap();

        // Turn where vocative addresses same speaker or no valid corroboration with low confidence
        let turns = vec![AudioTurn {
            turn_id: "turn-1".into(),
            start_ms: 0,
            end_ms: 2000,
            speaker_local_id: "speaker-1".into(),
            text: "Hello Bob".into(),
            language: Some("en".into()),
            speaker_name: Some("Bob".into()),
            speaker_name_confidence: Some(0.80), // below 0.85
            speaker_name_evidence: Some("Hello Bob".into()),
            speaker_name_kind: Some("vocative_address".into()),
            speaker_name_subject_turn_id: None,
            speaker_name_target_turn_id: None,
            person_facts: vec![],
            overlap: false,
            quality_flags: vec![],
        }];

        let vp1 = enrolled_voiceprint_for("turn-1", vec![0.1; 256]);
        persist_audio_result(&conn, &job, &turns, &[vp1]).unwrap();

        // No Bob person should be accepted
        let bob_count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM people WHERE display_name = 'Bob'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(bob_count, 0);

        // Identity evidence should be 'proposed'
        let evidence_status: String = conn
            .query_row(
                "SELECT status FROM identity_evidence WHERE claimed_name = 'Bob'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(evidence_status, "proposed");
    }

    fn vocative_turn_pair(target_overlap: bool) -> Vec<AudioTurn> {
        vec![
            AudioTurn {
                turn_id: "turn-1".into(),
                start_ms: 0,
                end_ms: 2000,
                speaker_local_id: "speaker-1".into(),
                text: "Hey Alice, can you review this?".into(),
                language: Some("en".into()),
                speaker_name: Some("Alice".into()),
                speaker_name_confidence: Some(0.95),
                speaker_name_evidence: Some("Hey Alice".into()),
                speaker_name_kind: Some("vocative_address".into()),
                speaker_name_subject_turn_id: None,
                speaker_name_target_turn_id: Some("turn-2".into()),
                person_facts: vec![],
                overlap: false,
                quality_flags: vec![],
            },
            AudioTurn {
                turn_id: "turn-2".into(),
                start_ms: 2500,
                end_ms: 5000,
                speaker_local_id: "speaker-2".into(),
                text: "Sure, I'll take a look now.".into(),
                language: Some("en".into()),
                speaker_name: None,
                speaker_name_confidence: None,
                speaker_name_evidence: None,
                speaker_name_kind: None,
                speaker_name_subject_turn_id: None,
                speaker_name_target_turn_id: None,
                person_facts: vec![],
                overlap: target_overlap,
                quality_flags: vec![],
            },
        ]
    }

    #[test]
    fn uncorroborated_two_party_vocative_stays_probationary() {
        // An ordinary two-speaker exchange is NOT independent corroboration:
        // with no visual evidence and no known-voice match, the vocative must
        // remain a proposed claim and create no person or binding.
        let conn = job_fixture_db();
        let manifest = numbered_audio_manifest(0);
        record_source_event(
            &conn,
            "account-1",
            &manifest,
            &"a".repeat(64),
            "raw/two-party-vocative",
        )
        .unwrap();
        let job = lease_next_job(&conn, "2026-07-31T18:01:00.000Z")
            .unwrap()
            .unwrap();
        let turns = vocative_turn_pair(false);
        let vp1 = enrolled_voiceprint_for("turn-1", vec![0.1; 256]);
        let vp2 = enrolled_voiceprint_for("turn-2", vec![0.9; 256]);
        persist_audio_result(&conn, &job, &turns, &[vp1, vp2]).unwrap();

        let alice_people: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM people WHERE display_name = 'Alice'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(
            alice_people, 0,
            "two-party exchange must not create a person"
        );
        let evidence_status: String = conn
            .query_row(
                "SELECT status FROM identity_evidence WHERE claimed_name = 'Alice'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(evidence_status, "proposed");
        let bindings: i64 = conn
            .query_row("SELECT COUNT(*) FROM profile_identity_bindings", [], |r| {
                r.get(0)
            })
            .unwrap();
        assert_eq!(bindings, 0);
    }

    #[test]
    fn overlapping_vocative_target_abstains_even_with_visual_corroboration() {
        let conn = job_fixture_db();
        let manifest = numbered_audio_manifest(0);
        record_source_event(
            &conn,
            "account-1",
            &manifest,
            &"a".repeat(64),
            "raw/overlap-vocative",
        )
        .unwrap();
        let job = lease_next_job(&conn, "2026-07-31T18:01:00.000Z")
            .unwrap()
            .unwrap();
        seed_visual_corroboration(
            &conn,
            "Alice",
            &isotime::add_seconds(&job.started_at, 3.0),
            &isotime::add_seconds(&job.started_at, 6.5),
        );
        let turns = vocative_turn_pair(true);
        let vp1 = enrolled_voiceprint_for("turn-1", vec![0.1; 256]);
        let vp2 = enrolled_voiceprint_for("turn-2", vec![0.9; 256]);
        persist_audio_result(&conn, &job, &turns, &[vp1, vp2]).unwrap();

        let alice_people: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM people WHERE display_name = 'Alice'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(alice_people, 0, "overlapping target turn must abstain");
    }

    #[test]
    fn third_party_mention_never_creates_identity() {
        let conn = job_fixture_db();
        let manifest = numbered_audio_manifest(0);
        record_source_event(
            &conn,
            "account-1",
            &manifest,
            &"a".repeat(64),
            "raw/third-party",
        )
        .unwrap();
        let job = lease_next_job(&conn, "2026-07-31T18:01:00.000Z")
            .unwrap()
            .unwrap();
        let mut turns = vocative_turn_pair(false);
        turns[0].speaker_name_kind = Some("third_party_mention".into());
        turns[0].text = "Alice told me yesterday".into();
        let vp1 = enrolled_voiceprint_for("turn-1", vec![0.1; 256]);
        let vp2 = enrolled_voiceprint_for("turn-2", vec![0.9; 256]);
        persist_audio_result(&conn, &job, &turns, &[vp1, vp2]).unwrap();

        let people: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM people WHERE kind <> 'owner'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(people, 0, "a third-party mention must never bind identity");
    }

    #[test]
    fn media_reservation_route_is_exactly_dual_path() {
        // ADR-0022 F6: the selected branch reads the durable attempt anchor
        // and observed predecessors through the routed read, constructs the
        // sealed plan once (R5), submits, and returns; the legacy branch
        // keeps its exact write+save pair. The predecessor CAS pins the
        // OBSERVED reservation_retained, never a literal 0 -- the flag is
        // one-way, so a hard-coded 0 would wedge every media retry.
        let source = include_str!("media_worker.rs");
        let start = source
            .find(concat!("async fn reserve_media_", "output"))
            .unwrap();
        let end = source
            .find(concat!("async fn candidate_name_", "vocabulary"))
            .unwrap();
        let route = &source[start..end];
        assert_eq!(
            route.matches(concat!("is_wal_", "authoritative(")).count(),
            1
        );
        assert_eq!(
            route
                .matches(concat!("wal_authoritative_", "read("))
                .count(),
            1
        );
        assert_eq!(
            route
                .matches(concat!("wal_authoritative_", "submit("))
                .count(),
            1
        );
        assert_eq!(route.matches(concat!(".with_", "user(")).count(), 1);
        assert_eq!(
            route
                .matches(concat!("MediaWorkReservationPlan::", "new("))
                .count(),
            1
        );
        // The identity anchor comes from the durable row, not a counter the
        // route invents.
        assert!(route.contains("attempt_count"));
    }

    #[test]
    fn the_sealed_vocabulary_is_pinned_at_the_schema_and_normalized_at_the_seam() {
        // The provider request constrains both classification fields to the
        // sealed vocabulary...
        let schema = screen_schema();
        assert_eq!(
            schema["properties"]["screen_state"]["enum"]
                .as_array()
                .unwrap()
                .len(),
            7
        );
        assert_eq!(
            schema["properties"]["content_type"]["enum"]
                .as_array()
                .unwrap()
                .len(),
            11
        );
        // ...and residual drift normalizes to "unknown" instead of
        // discarding a paid call against the sealed whitelist.
        assert_eq!(canonical_screen_state("content"), "content");
        assert_eq!(canonical_screen_state("email"), "unknown");
        assert_eq!(canonical_content_type("web_page"), "web_page");
        assert_eq!(canonical_content_type("browser"), "unknown");
    }

    #[test]
    fn screen_storyboard_route_is_exactly_dual_path() {
        // ADR-0022 slice 10e: for a WAL-authoritative user the sealed attempt
        // boundary settles after the settled reservation and before the
        // Vertex storyboard egress, its receipt pins the invocation identity
        // the egress carries, and the sealed bound result replaces the legacy
        // storyboard persistence; each plan is constructed exactly once (R5)
        // and the legacy with_user branches survive for unselected users.
        let source = include_str!("media_worker.rs");
        let start = source
            .find(concat!("async fn settle_screen_storyboard_", "attempt"))
            .unwrap();
        let end = source
            .find(concat!("fn resurrect_failed_", "jobs"))
            .unwrap();
        let route = &source[start..end];
        assert_eq!(
            route.matches(concat!("is_wal_", "authoritative(")).count(),
            1
        );
        assert_eq!(
            route
                .matches(concat!("wal_authoritative_", "read("))
                .count(),
            2
        );
        assert_eq!(
            route
                .matches(concat!("wal_authoritative_", "submit("))
                .count(),
            2
        );
        assert_eq!(
            route
                .matches(concat!("ScreenStoryboardAttemptPlan::", "new("))
                .count(),
            1
        );
        assert_eq!(
            route
                .matches(concat!("ScreenStoryboardResultPlan::", "new("))
                .count(),
            1
        );
        // Both legacy persistence branches (audio result, storyboard result)
        // survive byte-for-byte for unselected users.
        assert_eq!(route.matches(concat!(".with_", "user(")).count(), 2);
        assert_eq!(
            route
                .matches(concat!("persist_storyboard_", "results(conn"))
                .count(),
            1
        );
        // Order on the WAL lane: settled reservation, then the attempt
        // boundary, then the pinned egress, then the bound result — and the
        // surviving legacy persistence stays after all of them in the arm.
        let reservation = route
            .rfind(concat!("reserve_media_", "output(state"))
            .unwrap();
        let attempt = route
            .find(concat!("Some(settle_screen_storyboard_", "attempt("))
            .unwrap();
        let egress = route
            .find(concat!("generate_media_parts_", "custom("))
            .unwrap();
        let bound_result = route
            .find(concat!("settle_screen_storyboard_", "result(state"))
            .unwrap();
        let legacy = route
            .find(concat!("persist_storyboard_", "results(conn"))
            .unwrap();
        assert!(reservation < attempt);
        assert!(attempt < egress);
        assert!(egress < bound_result);
        assert!(bound_result < legacy);
        // The egress carries the attempt receipt's derived identity, never a
        // second freshly minted intent for the same paid call.
        assert!(route.contains(concat!("receipt.event_", "id().to_owned()")));
    }

    #[test]
    fn repeated_vocative_evidence_reuses_single_person_and_binding() {
        let conn = job_fixture_db();

        // First corroborated encounter creates Alice.
        let manifest0 = numbered_audio_manifest(0);
        record_source_event(&conn, "account-1", &manifest0, &"a".repeat(64), "raw/rep-0").unwrap();
        let job0 = lease_next_job(&conn, "2026-07-31T18:01:00.000Z")
            .unwrap()
            .unwrap();
        seed_visual_corroboration(
            &conn,
            "Alice",
            &isotime::add_seconds(&job0.started_at, 3.0),
            &isotime::add_seconds(&job0.started_at, 6.5),
        );
        let turns = vocative_turn_pair(false);
        persist_audio_result(
            &conn,
            &job0,
            &turns,
            &[
                enrolled_voiceprint_for("turn-1", vec![0.1; 256]),
                enrolled_voiceprint_for("turn-2", vec![0.9; 256]),
            ],
        )
        .unwrap();

        // Second encounter: same voice addressed as Alice again. Both the
        // biometric match and the accepted-name reuse paths must converge on
        // the SAME person instead of forking a duplicate Alice.
        let manifest1 = numbered_audio_manifest(1);
        record_source_event(&conn, "account-1", &manifest1, &"c".repeat(64), "raw/rep-1").unwrap();
        let job1 = lease_next_job(&conn, "2026-07-31T18:20:00.000Z")
            .unwrap()
            .unwrap();
        conn.execute(
            "UPDATE visual_speaker_observations SET observed_at = ?1 WHERE id = (SELECT MIN(id) FROM visual_speaker_observations)",
            [isotime::add_seconds(&job1.started_at, 3.0)],
        )
        .unwrap();
        conn.execute(
            "UPDATE visual_speaker_observations SET observed_at = ?1 WHERE id = (SELECT MAX(id) FROM visual_speaker_observations)",
            [isotime::add_seconds(&job1.started_at, 6.5)],
        )
        .unwrap();
        persist_audio_result(
            &conn,
            &job1,
            &turns,
            &[
                enrolled_voiceprint_for("turn-1", vec![0.1; 256]),
                enrolled_voiceprint_for("turn-2", vec![0.9; 256]),
            ],
        )
        .unwrap();

        let alice_people: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM people WHERE display_name = 'Alice'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(
            alice_people, 1,
            "repeated evidence must not fork duplicate people"
        );

        let active_bindings: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM profile_identity_bindings WHERE active = 1 AND state = 'accepted'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert!(
            active_bindings <= 2,
            "one active binding per involved profile at most"
        );
        let competing: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM (SELECT voice_profile_id FROM profile_identity_bindings \
                 WHERE active = 1 GROUP BY voice_profile_id HAVING COUNT(*) > 1)",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(competing, 0, "no competing active bindings for one profile");
    }
}
