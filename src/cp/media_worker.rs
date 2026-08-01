//! Durable raw-media processing worker.
//!
//! The device upload endpoint only validates, encrypts, and records source
//! events. This worker leases those events from each user's encrypted SQLite
//! ledger, opens the media inside the enclave, sends the bounded asset to
//! Vertex Gemini, validates constrained JSON, and transactionally projects the
//! result into the searchable archive. No media or generated content is logged.

use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use rusqlite::{params, Connection, OptionalExtension};
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tokio::task::JoinSet;
use tracing::warn;

use crate::error::{EnclaveError, Result};

use super::media::{parse_audio_result, AudioTurn};
use super::{isotime, vertex, CpState};

const WORKER_INTERVAL_SECONDS: u64 = 5;
const MAX_JOBS_PER_USER_PER_SWEEP: usize = 24;
const MAX_CONCURRENT_USER_SWEEPS: usize = 8;
const MAX_ATTEMPTS: i64 = 5;
const PROCESSOR_VERSION: i64 = 1;
const PROMPT_VERSION: i64 = 1;

#[derive(Debug, Clone)]
struct MediaJob {
    id: i64,
    event_id: String,
    job_kind: String,
    object_key: String,
    mime_type: String,
    sha256: String,
    started_at: String,
    ended_at: String,
    stream_kind: String,
    context_json: Option<String>,
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

fn lease_next_job(conn: &Connection, now: &str) -> Result<Option<MediaJob>> {
    let tx = conn.unchecked_transaction()?;
    let selected: Option<MediaJob> = tx
        .query_row(
            "SELECT j.id,j.event_id,j.job_kind,m.object_key,m.mime_type,m.sha256, \
                    e.started_at,e.ended_at,e.stream_kind,e.context_json \
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
                    sha256: row.get(5)?,
                    started_at: row.get(6)?,
                    ended_at: row.get(7)?,
                    stream_kind: row.get(8)?,
                    context_json: row.get(9)?,
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

fn upsert_person(conn: &Connection, name: &str) -> Result<i64> {
    let normalized = normalized_name(name);
    if normalized.is_empty() {
        return Err(EnclaveError::InvalidRequest("person name is empty".into()));
    }
    conn.execute(
        "INSERT INTO people (display_name,normalized_name,status) VALUES (?1,?2,'identified') \
         ON CONFLICT(normalized_name) DO UPDATE SET \
         display_name=CASE WHEN length(excluded.display_name)>length(display_name) \
                           THEN excluded.display_name ELSE display_name END, \
         updated_at=strftime('%Y-%m-%dT%H:%M:%fZ','now')",
        params![name.trim(), normalized],
    )?;
    Ok(conn.query_row(
        "SELECT id FROM people WHERE normalized_name=?1",
        [normalized],
        |row| row.get(0),
    )?)
}

fn unique_active_screen_person(
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
    Ok(if people.len() == 1 {
        Some(people[0])
    } else {
        None
    })
}

fn bind_person_to_speaker_observation(
    conn: &Connection,
    speaker_observation_id: i64,
    person_id: i64,
) -> Result<bool> {
    let profile: Option<(i64, Option<i64>)> = conn
        .query_row(
            "SELECT v.id,v.person_id FROM voice_samples s JOIN voice_profiles v \
             ON v.id=s.voice_profile_id WHERE s.speaker_observation_id=?1 \
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

fn bind_screen_person_to_existing_speaker(
    conn: &Connection,
    observed_at: &str,
    person_id: i64,
) -> Result<Option<i64>> {
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
    Ok(
        bind_person_to_speaker_observation(conn, observations[0], person_id)?
            .then_some(observations[0]),
    )
}

fn persist_audio_result(
    conn: &Connection,
    job: &MediaJob,
    turns: &[AudioTurn],
    voiceprints: &[(String, Vec<f32>, f64)],
) -> Result<()> {
    let tx = conn.unchecked_transaction()?;
    let duration_ms = isotime::parse_epoch_millis(&job.ended_at)
        .zip(isotime::parse_epoch_millis(&job.started_at))
        .map(|(end, start)| end - start)
        .ok_or_else(|| EnclaveError::InvalidRequest("job timestamps are invalid".into()))?;
    tx.execute(
        "INSERT INTO audio_segments \
         (started_at,ended_at,duration_seconds,source_type,audio_format,transcription_status) \
         VALUES (?1,?2,?3,?4,?5,'done')",
        params![
            job.started_at,
            job.ended_at,
            duration_ms as f64 / 1000.0,
            if job.stream_kind == "system_audio" {
                "system"
            } else {
                "mic"
            },
            job.mime_type
        ],
    )?;
    let segment_id = tx.last_insert_rowid();
    for turn in turns {
        let turn_started_at = isotime::add_seconds(&job.started_at, turn.start_ms as f64 / 1000.0);
        let turn_ended_at = isotime::add_seconds(&job.started_at, turn.end_ms as f64 / 1000.0);
        tx.execute(
            "INSERT INTO speaker_observations \
             (event_id,turn_id,speaker_local_id,started_at,ended_at,transcript_text,language,overlap) \
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8)",
            params![
                job.event_id,
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
        let explicit_person_id = confident_name
            .map(|name| upsert_person(&tx, name))
            .transpose()?;
        let screen_person_id =
            if explicit_person_id.is_none() && job.stream_kind == "system_audio" && !turn.overlap {
                unique_active_screen_person(&tx, &turn_started_at, &turn_ended_at)?
            } else {
                None
            };
        let person_id = explicit_person_id.or(screen_person_id);
        let voice_label = voiceprints
            .iter()
            .find(|(turn_id, _, _)| turn_id == &turn.turn_id)
            .map(|(_, embedding, energy)| {
                super::voice_memory::match_and_store(
                    &tx,
                    speaker_observation_id,
                    embedding,
                    &job.stream_kind,
                    person_id,
                    energy.clamp(0.0, 1.0),
                )
            })
            .transpose()?;
        let speaker_label = confident_name
            .map(ToOwned::to_owned)
            .or(voice_label)
            .unwrap_or_else(|| turn.speaker_local_id.clone());
        let source_key = format!("cloud-v2:{}:{}", job.event_id, turn.turn_id);
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
            tx.execute(
                "INSERT INTO identity_evidence \
                 (person_id,source_event_id,observed_at,speaker_observation_id,kind, \
                  claimed_name,evidence_json,score,status) \
                 VALUES (?1,?2,?3,?4,'audio_self_identification',?5,?6,?7,?8)",
                params![
                    explicit_person_id,
                    job.event_id,
                    turn_started_at,
                    speaker_observation_id,
                    name,
                    json!({"event_id":job.event_id,"turn_id":turn.turn_id,"evidence":evidence})
                        .to_string(),
                    confidence,
                    if explicit_person_id.is_some() {
                        "accepted"
                    } else {
                        "proposed"
                    }
                ],
            )?;
            if let Some(person_id) = explicit_person_id {
                for fact in &turn.person_facts {
                    tx.execute(
                        "INSERT INTO person_facts \
                         (person_id,predicate,value,evidence_json,derivation_version,status) \
                         SELECT ?1,?2,?3,?4,1,'active' \
                         WHERE NOT EXISTS (SELECT 1 FROM person_facts \
                         WHERE person_id=?1 AND predicate=?2 AND lower(value)=lower(?3) AND status='active')",
                        params![
                            person_id,
                            fact.predicate,
                            fact.value,
                            json!({"event_id":job.event_id,"turn_id":turn.turn_id,"evidence":fact.evidence}).to_string()
                        ],
                    )?;
                }
            }
        }
    }
    mark_succeeded(&tx, job)?;
    tx.commit()?;
    Ok(())
}

fn persist_screen_result(conn: &Connection, job: &MediaJob, result: &ScreenResult) -> Result<()> {
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
    let tx = conn.unchecked_transaction()?;
    tx.execute(
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
    let screenshot_id = tx.last_insert_rowid();
    tx.execute(
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
        let person_id = if evidence.confidence >= 0.90 && is_full_name(&evidence.name) {
            Some(upsert_person(&tx, &evidence.name)?)
        } else {
            None
        };
        tx.execute(
            "INSERT INTO identity_evidence \
             (person_id,source_event_id,observed_at,kind,claimed_name,evidence_json,score,status) \
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8)",
            params![
                person_id,
                job.event_id,
                job.started_at,
                if evidence.is_active_speaker {
                    "screen_active_speaker"
                } else {
                    "screen_visible_name"
                },
                evidence.name,
                json!({"event_id":job.event_id,"screenshot_id":screenshot_id,"evidence":evidence.evidence}).to_string(),
                evidence.confidence,
                if person_id.is_some() { "accepted" } else { "proposed" }
            ],
        )?;
        let evidence_id = tx.last_insert_rowid();
        if evidence.is_active_speaker {
            if let Some(person_id) = person_id {
                if let Some(observation_id) =
                    bind_screen_person_to_existing_speaker(&tx, &job.started_at, person_id)?
                {
                    let voice_profile_id: Option<i64> = tx
                        .query_row(
                            "SELECT voice_profile_id FROM voice_samples \
                             WHERE speaker_observation_id=?1 AND accepted=1 \
                             ORDER BY id DESC LIMIT 1",
                            [observation_id],
                            |row| row.get(0),
                        )
                        .optional()?;
                    tx.execute(
                        "UPDATE identity_evidence SET speaker_observation_id=?1,voice_profile_id=?2 \
                         WHERE id=?3",
                        params![observation_id, voice_profile_id, evidence_id],
                    )?;
                }
            }
        }
    }
    mark_succeeded(&tx, job)?;
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

async fn process_job(state: &CpState, user_id: &str, job: &MediaJob) -> Result<()> {
    let stored = state.store.get_media(&job.object_key).await?;
    let dek = crate::crypto::load_dek(state.store.kms.as_ref(), &stored.wrapped_dek_b64).await?;
    let context = crate::store::media_blob_context(user_id, &job.object_key);
    let media = crate::crypto::decrypt_bound_blob(&dek, &stored.ciphertext, &context)?.plaintext;
    let actual_hash = format!("{:x}", Sha256::digest(&media));
    if !actual_hash.eq_ignore_ascii_case(&job.sha256) {
        return Err(EnclaveError::Crypto("raw media hash mismatch".into()));
    }

    if job.job_kind == "gemini_audio" {
        let duration_ms = isotime::parse_epoch_millis(&job.ended_at)
            .zip(isotime::parse_epoch_millis(&job.started_at))
            .map(|(end, start)| end - start)
            .ok_or_else(|| EnclaveError::InvalidRequest("job timestamps are invalid".into()))?;
        let prompt = "Transcribe this audio exactly. Return chronological speaker turns with millisecond offsets from the beginning. Keep stable speaker_local_id values within this asset. Mark overlap. Only populate speaker_name, speaker_name_confidence, and speaker_name_evidence when the audio itself explicitly supports the person's full or partial name; never guess from voice alone. For a named speaker, include only durable person_facts explicitly supported by that turn, with literal evidence; never infer sensitive traits or unstated facts.";
        let raw = vertex::generate_media_custom(
            &state.config,
            prompt,
            &job.mime_type,
            &media,
            audio_schema(),
            true,
        )
        .await?;
        let turns = parse_audio_result(&raw, duration_ms)?;
        let voiceprints = match &state.voice {
            Some(engine) => match engine.embed_turns(&media, &job.mime_type, &turns) {
                Ok(voiceprints) => voiceprints,
                Err(error) => {
                    warn!(job_id = job.id, error = %error, "voice fingerprint extraction skipped");
                    Vec::new()
                }
            },
            None => Vec::new(),
        };
        state
            .store
            .with_user(user_id, |conn| {
                persist_audio_result(conn, job, &turns, &voiceprints)
            })
            .await?;
    } else {
        let prompt = "Inspect the screenshot pixels literally. Transcribe all useful visible text, produce a compact salient-text projection and literal description, and classify screen_state/content_type. List a person only when a visible name label supports it, preferring the complete first and last name. Set is_active_speaker true only when the meeting UI visibly marks that exact label as currently speaking; otherwise false. Evidence must quote or describe the visible label/highlight; never infer identity from a face.";
        let raw = vertex::generate_media_custom(
            &state.config,
            prompt,
            &job.mime_type,
            &media,
            screen_schema(),
            false,
        )
        .await?;
        let result: ScreenResult = serde_json::from_str(&raw)?;
        state
            .store
            .with_user(user_id, |conn| persist_screen_result(conn, job, &result))
            .await?;
    }
    state.store.save_user(user_id).await?;
    Ok(())
}

async fn process_user(state: &CpState, user_id: &str) {
    for _ in 0..MAX_JOBS_PER_USER_PER_SWEEP {
        let now = now_iso();
        let lease = state
            .store
            .with_user(user_id, |conn| lease_next_job(conn, &now))
            .await;
        let Some(job) = (match lease {
            Ok(job) => job,
            Err(error) => {
                warn!(user_id, error = %error, "media job lease failed");
                return;
            }
        }) else {
            return;
        };
        if let Err(error) = process_job(state, user_id, &job).await {
            let error_code = match error {
                EnclaveError::Config(ref message) if message == "quota" => "vertex_quota",
                EnclaveError::Json(_) | EnclaveError::InvalidRequest(_) => "invalid_model_output",
                EnclaveError::Crypto(_) => "media_integrity",
                _ => "processing_error",
            };
            warn!(user_id, job_id = job.id, error_code, "media job failed");
            let failed_at = now_iso();
            if let Err(mark_error) = state
                .store
                .with_user(user_id, |conn| {
                    mark_failed(conn, job.id, error_code, &failed_at)
                })
                .await
            {
                warn!(user_id, job_id = job.id, error = %mark_error, "media job failure persistence failed");
                return;
            }
            let _ = state.store.save_user(user_id).await;
            if error_code == "vertex_quota" {
                return;
            }
        }
    }
}

async fn prune_user_media(state: &CpState, user_id: &str) {
    let now = now_iso();
    let due = state
        .store
        .with_user(user_id, |conn| {
            let mut statement = conn.prepare(
                "SELECT event_id,object_key FROM media_objects \
                 WHERE deleted_at IS NULL AND retain_until<=?1 \
                 AND processing_state IN ('ready','failed') ORDER BY retain_until LIMIT 100",
            )?;
            let rows = statement
                .query_map([&now], |row| {
                    Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
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
    for (event_id, object_key) in due {
        if let Err(error) = state.store.delete_media(&object_key).await {
            warn!(user_id, error = %error, "raw media retention delete failed");
            continue;
        }
        let deleted_at = now_iso();
        if let Err(error) = state
            .store
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
            warn!(user_id, error = %error, "raw media retention ledger update failed");
            continue;
        }
        changed = true;
    }
    if changed {
        let _ = state.store.save_user(user_id).await;
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
    use crate::cp::media::{init_schema, record_source_event, CaptureEventManifest, StreamKind};

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
                "SELECT COUNT(*) FROM people WHERE normalized_name='john garcia'",
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
    fn active_speaker_screen_processed_first_names_the_later_voice_profile() {
        let conn = job_fixture_db();
        record_source_event(
            &conn,
            "account-1",
            &screen_manifest(),
            &"d".repeat(64),
            "raw/screen",
        )
        .unwrap();
        let screen_job = lease_next_job(&conn, "2026-07-31T18:00:02.000Z")
            .unwrap()
            .unwrap();
        persist_screen_result(&conn, &screen_job, &active_speaker_screen()).unwrap();

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
            &[("turn-1".into(), vec![0.0625; 256], 0.8)],
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
            &[("turn-1".into(), vec![0.0625; 256], 0.8)],
        )
        .unwrap();

        record_source_event(
            &conn,
            "account-1",
            &screen_manifest(),
            &"d".repeat(64),
            "raw/screen",
        )
        .unwrap();
        let screen_job = lease_next_job(&conn, "2026-07-31T18:00:02.000Z")
            .unwrap()
            .unwrap();
        persist_screen_result(&conn, &screen_job, &active_speaker_screen()).unwrap();
        assert_john_bound(&conn);
    }
}
