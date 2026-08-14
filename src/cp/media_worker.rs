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
use tracing::warn;

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
                "{}:{}:{}:{}:{}",
                self.stream_kind,
                self.mime_type,
                self.codec,
                self.sample_rate.unwrap_or(0),
                self.channels.unwrap_or(0)
            ),
        })
    }

    fn acoustic_domain(&self) -> String {
        format!(
            "{}:{}:{}:{}:{}",
            self.stream_kind,
            self.mime_type,
            self.codec,
            self.sample_rate.unwrap_or(0),
            self.channels.unwrap_or(0)
        )
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
                        "speaker_name_evidence": {"type":"STRING", "nullable":true}
                        ,"person_facts": {
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
            "screen_state":{"type":"STRING"},
            "content_type":{"type":"STRING"},
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
                    e.started_at,e.ended_at,e.stream_kind,e.capture_session_id,e.stream_id,e.sequence,e.context_json,j.usage_json \
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
                    e.started_at,e.ended_at,e.stream_kind,e.capture_session_id,e.stream_id,e.sequence,e.context_json,j.usage_json \
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
    let mut statement = conn.prepare(
        "SELECT DISTINCT person_id FROM identity_evidence \
         WHERE kind='screen_active_speaker' AND status='accepted' \
         AND person_id IS NOT NULL AND observed_at>=?1 AND observed_at<=?2 LIMIT 2",
    )?;
    let people = statement
        .query_map(params![started_at, ended_at], |row| row.get::<_, i64>(0))?
        .collect::<std::result::Result<Vec<_>, _>>()?;
    if people.len() == 1 {
        return Ok(Some(people[0]));
    }
    let claims: Vec<(String, String)> = {
        let mut statement = conn.prepare(
            "SELECT normalized_name,MAX(name) FROM person_name_claims \
             WHERE evidence_kind='screen_active_speaker' AND status IN ('proposed','probationary') \
             AND observed_at>=?1 AND observed_at<=?2 GROUP BY normalized_name \
             HAVING COUNT(DISTINCT source_event_id)>=2 LIMIT 2",
        )?;
        let rows = statement
            .query_map(params![started_at, ended_at], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        rows
    };
    if claims.len() != 1 {
        return Ok(None);
    }
    let person_id = create_person(conn, &claims[0].1)?;
    conn.execute(
        "UPDATE person_name_claims SET person_id=?1,status='accepted' \
         WHERE normalized_name=?2 AND evidence_kind='screen_active_speaker' \
         AND observed_at>=?3 AND observed_at<=?4 AND status IN ('proposed','probationary')",
        params![person_id, claims[0].0, started_at, ended_at],
    )?;
    conn.execute(
        "UPDATE identity_evidence SET person_id=?1,status='accepted' \
         WHERE kind='screen_active_speaker' AND claimed_name IS NOT NULL \
         AND lower(trim(claimed_name))=?2 AND observed_at>=?3 AND observed_at<=?4 \
         AND status='proposed'",
        params![person_id, claims[0].0, started_at, ended_at],
    )?;
    Ok(Some(person_id))
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
        conn.execute(
            "UPDATE voice_profiles SET person_id=?1,updated_at=strftime('%Y-%m-%dT%H:%M:%fZ','now') \
             WHERE id=?2 AND (person_id IS NULL OR person_id=?1)",
            params![person_id, profile_id],
        )?;
        super::voice_lineage::refresh_profile_revision(
            conn,
            profile_id,
            "identity_binding_updated",
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
    let mut statement = conn.prepare(
        "SELECT s.id FROM speaker_observations s JOIN capture_events e ON e.event_id=s.event_id \
         WHERE e.stream_kind='system_audio' AND s.overlap=0 \
         AND s.started_at<=?1 AND s.ended_at>=?1 ORDER BY s.id LIMIT 2",
    )?;
    let observations = statement
        .query_map([observed_at], |row| row.get::<_, i64>(0))?
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
    let evidence_count: i64 = conn.query_row(
        "SELECT COUNT(DISTINCT source_event_id) FROM person_name_claims \
         WHERE normalized_name=?1 AND evidence_kind='screen_active_speaker' \
         AND confidence>=0.90 AND observed_at>=?2 AND observed_at<=?3 \
         AND status IN ('proposed','probationary','accepted')",
        params![normalized, started_at, ended_at],
        |row| row.get(0),
    )?;
    if evidence_count < 2 {
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
        params![person_id, normalized, started_at, ended_at],
    )?;
    conn.execute(
        "UPDATE identity_evidence SET person_id=?1,status='accepted',speaker_observation_id=?2 \
         WHERE kind='screen_active_speaker' AND lower(trim(claimed_name))=?3 \
         AND observed_at>=?4 AND observed_at<=?5 AND status='proposed'",
        params![person_id, observation_id, normalized, started_at, ended_at],
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
        conn.execute(
            "INSERT INTO profile_identity_bindings \
             (voice_profile_id,person_id,evidence_count,confidence,state,derivation_version,evidence_json) \
             SELECT ?1,?2,?3,0.99,'accepted',1,?4 \
             WHERE NOT EXISTS (SELECT 1 FROM profile_identity_bindings \
               WHERE voice_profile_id=?1 AND person_id=?2 AND state='accepted')",
            params![
                profile_id,
                person_id,
                evidence_count,
                json!({"kind":"repeated_active_speaker_frames","speaker_observation_id":observation_id}).to_string()
            ],
        )?;
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
        tx.execute(
            "INSERT INTO speaker_observations \
             (event_id,turn_id,speaker_local_id,started_at,ended_at,transcript_text,language,overlap) \
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8)",
            params![
                anchor_job.event_id,
                turn.turn_id,
                turn.speaker_local_id,
                turn_started_at,
                turn_ended_at,
                turn.text,
                turn.language,
                turn.overlap as i64
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
        let confident_name = match (
            turn.speaker_name.as_deref(),
            turn.speaker_name_confidence,
            turn.speaker_name_evidence.as_deref(),
        ) {
            (Some(name), Some(confidence), Some(_)) if confidence >= 0.90 && is_full_name(name) => {
                Some(name)
            }
            _ => None,
        };
        let voice_candidate = voiceprints
            .iter()
            .find(|candidate| candidate.turn_id == turn.turn_id);
        let explicit_person_id = if let Some(name) = confident_name {
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
            Some(match matched {
                Some(person_id) => person_id,
                None => create_person(&tx, name)?,
            })
        } else {
            None
        };
        let screen_person_id =
            if explicit_person_id.is_none() && job.stream_kind == "system_audio" && !turn.overlap {
                corroborated_active_screen_person(&tx, &turn_started_at, &turn_ended_at)?
            } else {
                None
            };
        let evidence_person_id = explicit_person_id.or(screen_person_id);
        let voice_label = voice_candidate
            .map(|candidate| {
                super::voice_memory::match_and_store_candidate(
                    &tx,
                    speaker_observation_id,
                    candidate,
                    &job.acoustic_domain(),
                    evidence_person_id,
                )
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
        let voice_person_id = voice_binding.and_then(|(_, person_id)| person_id);
        let person_id = evidence_person_id.or(voice_person_id);
        if let (Some(explicit_person_id), Some((voice_profile_id, _))) =
            (explicit_person_id, voice_binding)
        {
            tx.execute(
                "INSERT INTO profile_identity_bindings \
                 (voice_profile_id,person_id,evidence_count,confidence,state,derivation_version,evidence_json) \
                 SELECT ?1,?2,1,0.99,'accepted',1,?3 \
                 WHERE NOT EXISTS (SELECT 1 FROM profile_identity_bindings \
                   WHERE voice_profile_id=?1 AND person_id=?2 AND state='accepted')",
                params![
                    voice_profile_id,
                    explicit_person_id,
                    json!({"kind":"direct_audio_self_identification","speaker_observation_id":speaker_observation_id}).to_string()
                ],
            )?;
        }
        let speaker_label = confident_name
            .map(ToOwned::to_owned)
            .or(voice_label)
            .unwrap_or_else(|| super::media::UNIDENTIFIED_SPEAKER_LABEL.to_string());
        let source_key = format!("cloud-v2:{}:{}", anchor_job.event_id, turn.turn_id);
        tx.execute(
            "INSERT INTO utterances \
             (audio_segment_id,start_offset_seconds,end_offset_seconds,text,language,confidence, \
              speaker_label,source_key) VALUES (?1,?2,?3,?4,?5,NULL,?6,?7)",
            params![
                segment_id,
                turn.start_ms as f64 / 1000.0,
                turn.end_ms as f64 / 1000.0,
                turn.text,
                turn.language,
                speaker_label,
                source_key
            ],
        )?;
        if let Some(person_id) = person_id {
            let _ = bind_person_to_speaker_observation(&tx, speaker_observation_id, person_id)?;
        }
        if let (Some(name), Some(confidence), Some(evidence)) = (
            turn.speaker_name.as_deref(),
            turn.speaker_name_confidence,
            turn.speaker_name_evidence.as_deref(),
        ) {
            let evidence_json = json!({"work_unit_id":work_unit_id,"event_id":anchor_job.event_id,"source_event_ids":projected.iter().map(|source| &source.event_id).collect::<Vec<_>>(),"turn_id":turn.turn_id,"evidence":evidence}).to_string();
            tx.execute(
                "INSERT INTO identity_evidence \
                 (person_id,source_event_id,observed_at,speaker_observation_id,kind, \
                  claimed_name,evidence_json,score,status) \
                 VALUES (?1,?2,?3,?4,'audio_self_identification',?5,?6,?7,?8)",
                params![
                    explicit_person_id,
                    anchor_job.event_id,
                    turn_started_at,
                    speaker_observation_id,
                    name,
                    evidence_json,
                    confidence,
                    if explicit_person_id.is_some() {
                        "accepted"
                    } else {
                        "proposed"
                    }
                ],
            )?;
            if let Some(person_id) = explicit_person_id {
                record_name_claim(
                    &tx,
                    NameClaim {
                        person_id: Some(person_id),
                        name,
                        source_event_id: &anchor_job.event_id,
                        speaker_observation_id: Some(speaker_observation_id),
                        observed_at: &turn_started_at,
                        evidence_kind: "audio_self_identification",
                        evidence_json: json!({"work_unit_id":work_unit_id,"turn_id":turn.turn_id,"evidence":evidence}).to_string(),
                        confidence,
                        status: "accepted",
                    },
                )?;
            }
        }
        if let Some(person_id) = person_id {
            for fact in &turn.person_facts {
                let evidence_json = json!({"work_unit_id":work_unit_id,"event_id":anchor_job.event_id,"source_event_ids":projected.iter().map(|source| &source.event_id).collect::<Vec<_>>(),"turn_id":turn.turn_id,"evidence":fact.evidence}).to_string();
                persist_person_fact(
                    &tx,
                    FactEvidence {
                        person_id,
                        fact,
                        source_event_id: &anchor_job.event_id,
                        speaker_observation_id,
                        observed_at: &turn_started_at,
                        evidence_json,
                    },
                )?;
            }
        }
    }
    super::media::reconcile_request_local_speaker_labels(&tx, Some(work_unit_id))?;
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
        let evidence_json = json!({"event_id":job.event_id,"screenshot_id":screenshot_id,"evidence":evidence.evidence}).to_string();
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

fn defer_for_budget(conn: &Connection, job_id: i64, now: &str) -> Result<()> {
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
        let ids = work.jobs.iter().map(|job| job.id).collect::<Vec<_>>();
        let class_name = match work.class {
            WorkClass::Audio => "audio",
            WorkClass::Screen => "screen",
        };
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

async fn load_job_media(state: &CpState, user_id: &str, job: &MediaJob) -> Result<Vec<u8>> {
    let stored = state.store.get_media(&job.object_key).await?;
    let dek = crate::crypto::load_dek(state.store.kms.as_ref(), &stored.wrapped_dek_b64).await?;
    let context = crate::store::media_blob_context(user_id, &job.object_key);
    let media = crate::crypto::decrypt_bound_blob(&dek, &stored.ciphertext, &context)?.plaintext;
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
            "Transcribe this audio exactly. The source kind is {}. Return chronological speaker turns with millisecond offsets from the beginning. Keep stable speaker_local_id values within this entire asset. Prefer an existing local id whenever the voice remains acoustically consistent. Do not invent a new speaker solely because of a one-word interjection, a short phrase, a pause, changed volume or prosody, device movement, or background noise; create a new local id only when sustained acoustic evidence supports a different human voice. Mark overlap. Only populate speaker_name, speaker_name_confidence, and speaker_name_evidence when the audio itself explicitly supports the person's full or partial name; never guess from voice alone. For every turn, include only durable person_facts explicitly supported by that turn, with literal evidence; never infer sensitive traits or unstated facts. The following bounded names are spelling vocabulary only, not proof that anyone is present, speaking, or has any identity: {}",
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
        )
        .await?;
        persist_actual_media_usage(state, user_id, work, &generation).await?;
        let expected = work
            .jobs
            .iter()
            .map(|job| job.event_id.clone())
            .collect::<Vec<_>>();
        let results = validate_storyboard_result(&generation.text, &expected)?;
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
            process_user(&state, &user_id).await;
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
             CREATE TABLE audio_segments(id INTEGER PRIMARY KEY,started_at TEXT NOT NULL,ended_at TEXT NOT NULL, \
             duration_seconds REAL NOT NULL,source_type TEXT NOT NULL,audio_format TEXT,transcription_status TEXT); \
             CREATE TABLE utterances(id INTEGER PRIMARY KEY,audio_segment_id INTEGER NOT NULL,start_offset_seconds REAL, \
             end_offset_seconds REAL,text TEXT,language TEXT,confidence REAL,speaker_label TEXT,source_key TEXT); \
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
        value.started_at = isotime::add_seconds(&value.started_at, index as f64);
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
        persist_single_audio_work(&conn, &[unnamed_turn()], &[]);
        assert_eq!(
            persisted_speaker_labels(&conn),
            vec![super::super::media::UNIDENTIFIED_SPEAKER_LABEL]
        );
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
                "SELECT COUNT(DISTINCT person_id) FROM person_name_claims \
                 WHERE normalized_name='john smith' AND status='accepted'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(people, 2);
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
            .query_row("SELECT COUNT(*) FROM people", [], |row| row.get(0))
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
}
