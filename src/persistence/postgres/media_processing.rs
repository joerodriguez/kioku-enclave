use std::collections::{HashMap, HashSet};

use async_trait::async_trait;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use sqlx::Row;

use crate::{
    cp::{isotime, media_planner},
    error::{EnclaveError, Result},
    persistence::{
        is_supported_self_identification, names_form_refinement, prefer_claimed_display_name,
        AudioMediaSettlement, MediaPersonEvidence, MediaProcessingClaim, MediaProcessingClass,
        MediaProcessingJob, MediaProcessingRepository, MediaUsageSettlement, ScreenMediaSettlement,
    },
};

use super::{allocate_content_id, PostgresPersistence};

const PROCESSOR_VERSION: i64 = 1;
const PROMPT_VERSION: i64 = 3;

fn parse_time(value: &str, field: &str) -> Result<i64> {
    isotime::parse_epoch_millis(value)
        .ok_or_else(|| EnclaveError::InvalidRequest(format!("{field} is invalid")))
}

fn class_to_planner(value: MediaProcessingClass) -> media_planner::WorkClass {
    match value {
        MediaProcessingClass::Audio => media_planner::WorkClass::Audio,
        MediaProcessingClass::Screen => media_planner::WorkClass::Screen,
    }
}

fn work_unit_id(class: MediaProcessingClass, jobs: &[MediaProcessingJob]) -> String {
    let mut digest = Sha256::new();
    let class = match class {
        MediaProcessingClass::Audio => "Audio",
        MediaProcessingClass::Screen => "Screen",
    };
    digest.update(format!("media-work-v1:{class}:"));
    for job in jobs {
        digest.update(job.event_id.as_bytes());
        digest.update([0]);
        digest.update(job.sha256.as_bytes());
        digest.update([0]);
    }
    format!("{:x}", digest.finalize())
}

fn normalize_name(value: &str) -> String {
    value
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .to_lowercase()
}

fn valid_person_evidence(value: &MediaPersonEvidence) -> bool {
    !value.name.trim().is_empty()
        && value.name.len() <= 200
        && !value.evidence.trim().is_empty()
        && value.evidence.len() <= 2_000
        && value.confidence.is_finite()
        && (0.0..=1.0).contains(&value.confidence)
}

fn usage_for_reservation(claim: &MediaProcessingClaim, reserved_output_tokens: i64) -> Value {
    json!({
        "work_unit_id": claim.work_unit_id,
        "work_class": claim.class.as_str(),
        "member_count": claim.jobs.len(),
        "reservation_state": "reserved",
        "reserved_output_tokens": reserved_output_tokens,
        "processor_version": PROCESSOR_VERSION,
    })
}

fn job_from_row(row: &sqlx::postgres::PgRow) -> Result<MediaProcessingJob> {
    let context = row
        .try_get::<Option<String>, _>("context_json")?
        .map(|raw| serde_json::from_str(&raw))
        .transpose()?;
    Ok(MediaProcessingJob {
        id: row.try_get("id")?,
        event_id: row.try_get("event_id")?,
        job_kind: row.try_get("job_kind")?,
        object_key: row.try_get("object_key")?,
        object_generation: row.try_get("object_generation")?,
        mime_type: row.try_get("mime_type")?,
        codec: row.try_get("codec")?,
        byte_length: row.try_get("byte_length")?,
        sample_rate: row.try_get("sample_rate")?,
        channels: row.try_get("channels")?,
        width: row.try_get("width")?,
        height: row.try_get("height")?,
        sha256: row.try_get("sha256")?,
        started_at: isotime::format_epoch_millis(row.try_get("started_at_ms")?),
        ended_at: isotime::format_epoch_millis(row.try_get("ended_at_ms")?),
        stream_kind: row.try_get("stream_kind")?,
        capture_session_id: row.try_get("capture_session_id")?,
        stream_id: row.try_get("stream_id")?,
        sequence: row.try_get("sequence")?,
        context,
        audio_role: row.try_get("audio_role")?,
        audio_route: row.try_get("audio_route")?,
        route_epoch: row.try_get("route_epoch")?,
    })
}

async fn work_state_for_update(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    claim: &MediaProcessingClaim,
) -> Result<String> {
    let row = sqlx::query(
        "SELECT state,claim_token FROM media_work_units \
         WHERE account_id=$1 AND id=$2 FOR UPDATE",
    )
    .bind(&claim.account_id)
    .bind(&claim.work_unit_id)
    .fetch_optional(&mut **transaction)
    .await?
    .ok_or_else(|| EnclaveError::Conflict("media work claim is absent".into()))?;
    let token: Option<String> = row.try_get("claim_token")?;
    if token.as_deref() != Some(claim.claim_token.as_str()) {
        return Err(EnclaveError::Conflict(
            "media work claim was superseded".into(),
        ));
    }
    Ok(row.try_get("state")?)
}

async fn mark_claim_succeeded(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    claim: &MediaProcessingClaim,
) -> Result<()> {
    let ids = claim.jobs.iter().map(|job| job.id).collect::<Vec<_>>();
    let events = claim
        .jobs
        .iter()
        .map(|job| job.event_id.as_str())
        .collect::<Vec<_>>();
    let changed = sqlx::query(
        "UPDATE media_processing_jobs SET state='succeeded',lease_until=NULL,error_code=NULL, \
                model_id='gemini-3.5-flash',prompt_version=$4,schema_version=2,updated_at=now() \
         WHERE account_id=$1 AND id=ANY($2) AND lease_token=$3",
    )
    .bind(&claim.account_id)
    .bind(&ids)
    .bind(&claim.claim_token)
    .bind(PROMPT_VERSION)
    .execute(&mut **transaction)
    .await?
    .rows_affected();
    if changed != ids.len() as u64 {
        return Err(EnclaveError::Conflict(
            "media job claim was superseded".into(),
        ));
    }
    sqlx::query(
        "UPDATE media_objects SET processing_state='ready' \
         WHERE account_id=$1 AND event_id=ANY($2)",
    )
    .bind(&claim.account_id)
    .bind(&events)
    .execute(&mut **transaction)
    .await?;
    sqlx::query(
        "UPDATE media_work_units SET state='succeeded',error_code=NULL,updated_at=now() \
         WHERE account_id=$1 AND id=$2 AND claim_token=$3",
    )
    .bind(&claim.account_id)
    .bind(&claim.work_unit_id)
    .bind(&claim.claim_token)
    .execute(&mut **transaction)
    .await?;
    Ok(())
}

#[async_trait]
impl MediaProcessingRepository for PostgresPersistence {
    async fn pending_classes(&self, account_id: &str, now: &str) -> Result<(bool, bool)> {
        let now_ms = parse_time(now, "media scan time")?;
        let kinds = sqlx::query_scalar::<_, String>(
            "SELECT DISTINCT job_kind FROM media_processing_jobs \
             WHERE account_id=$1 AND processor_version=$2 AND ( \
                 state='pending' OR \
                 (state='retry_wait' AND updated_at<=to_timestamp($3::double precision/1000.0)) OR \
                 (state='processing' AND lease_until<=to_timestamp($3::double precision/1000.0)))",
        )
        .bind(account_id)
        .bind(PROCESSOR_VERSION)
        .bind(now_ms)
        .fetch_all(&self.pool)
        .await?;
        Ok((
            kinds.iter().any(|kind| kind == "gemini_audio"),
            kinds.iter().any(|kind| kind == "gemini_screen"),
        ))
    }

    async fn claim(
        &self,
        account_id: &str,
        class: MediaProcessingClass,
        claimed_at: &str,
        lease_seconds: i64,
        scan_limit: i64,
    ) -> Result<Option<MediaProcessingClaim>> {
        if lease_seconds <= 0 || !(1..=1_024).contains(&scan_limit) {
            return Err(EnclaveError::Config(
                "media claim bounds are invalid".into(),
            ));
        }
        let claimed_at_ms = parse_time(claimed_at, "media claim time")?;
        let lease_until = isotime::add_seconds(claimed_at, lease_seconds as f64);
        let lease_until_ms = parse_time(&lease_until, "media lease deadline")?;
        let mut transaction = self.pool.begin().await?;
        let status =
            sqlx::query_scalar::<_, String>("SELECT status FROM accounts WHERE id=$1 FOR UPDATE")
                .bind(account_id)
                .fetch_optional(&mut *transaction)
                .await?;
        if status.as_deref() != Some("active") {
            transaction.rollback().await?;
            return Ok(None);
        }
        let rows = sqlx::query(
            "SELECT j.id,j.event_id,j.job_kind,m.object_key,m.object_generation,m.mime_type,m.codec, \
                    m.byte_length,m.sample_rate,m.channels,m.width,m.height,m.sha256, \
                    floor(extract(epoch FROM e.started_at)*1000)::bigint AS started_at_ms, \
                    floor(extract(epoch FROM e.ended_at)*1000)::bigint AS ended_at_ms, \
                    e.stream_kind,e.capture_session_id,e.stream_id,e.sequence, \
                    e.context_json::text AS context_json,e.audio_role,e.audio_route,e.route_epoch \
             FROM media_processing_jobs j \
             JOIN capture_events e ON e.account_id=j.account_id AND e.event_id=j.event_id \
             JOIN media_objects m ON m.account_id=j.account_id AND m.event_id=j.event_id \
             WHERE j.account_id=$1 AND j.processor_version=$2 AND j.job_kind=$3 AND ( \
                 j.state='pending' OR \
                 (j.state='retry_wait' AND j.updated_at<=to_timestamp($4::double precision/1000.0)) OR \
                 (j.state='processing' AND j.lease_until<=to_timestamp($4::double precision/1000.0))) \
             ORDER BY e.started_at,e.sequence,j.id LIMIT $5 FOR UPDATE OF j SKIP LOCKED",
        )
        .bind(account_id)
        .bind(PROCESSOR_VERSION)
        .bind(class.job_kind())
        .bind(claimed_at_ms)
        .bind(scan_limit)
        .fetch_all(&mut *transaction)
        .await?;
        if rows.is_empty() {
            transaction.commit().await?;
            return Ok(None);
        }
        let jobs = rows.iter().map(job_from_row).collect::<Result<Vec<_>>>()?;
        let candidates = jobs
            .iter()
            .map(|job| {
                Ok(media_planner::PlanningEvent {
                    job_id: job.id,
                    event_id: job.event_id.clone(),
                    class: class_to_planner(class),
                    capture_session_id: job.capture_session_id.clone(),
                    stream_id: job.stream_id.clone(),
                    sequence: job.sequence,
                    started_ms: parse_time(&job.started_at, "media job start")?,
                    ended_ms: parse_time(&job.ended_at, "media job end")?,
                    byte_length: job.byte_length,
                    pixel_count: job
                        .width
                        .unwrap_or(0)
                        .saturating_mul(job.height.unwrap_or(0)),
                    route_key: format!(
                        "{}:{}:{}:{}:{}:{}:{}:{}",
                        job.stream_kind,
                        job.mime_type,
                        job.codec,
                        job.sample_rate.unwrap_or(0),
                        job.channels.unwrap_or(0),
                        job.audio_role.as_deref().unwrap_or(""),
                        job.audio_route.as_deref().unwrap_or(""),
                        job.route_epoch.unwrap_or(0),
                    ),
                })
            })
            .collect::<Result<Vec<_>>>()?;
        let plan = media_planner::plan_first(&candidates);
        if plan.member_job_ids.is_empty() {
            sqlx::query(
                "UPDATE media_processing_jobs SET state='failed_terminal',error_code='unplannable_media', \
                        lease_owner=NULL,lease_token=NULL,lease_until=NULL,updated_at=now() \
                 WHERE account_id=$1 AND id=$2",
            )
            .bind(account_id)
            .bind(plan.head_job_id)
            .execute(&mut *transaction)
            .await?;
            sqlx::query(
                "UPDATE media_objects SET processing_state='failed' WHERE account_id=$1 AND event_id=( \
                    SELECT event_id FROM media_processing_jobs WHERE account_id=$1 AND id=$2)",
            )
            .bind(account_id)
            .bind(plan.head_job_id)
            .execute(&mut *transaction)
            .await?;
            transaction.commit().await?;
            return Ok(None);
        }
        let member_ids = plan.member_job_ids.iter().copied().collect::<HashSet<_>>();
        let selected = jobs
            .into_iter()
            .filter(|job| member_ids.contains(&job.id))
            .collect::<Vec<_>>();
        let work_unit_id = work_unit_id(class, &selected);
        let claim_token = crate::cp::tokens::random_token_hex();
        let reserved_output_tokens = match class {
            MediaProcessingClass::Audio => 4_096_i64,
            MediaProcessingClass::Screen => 1_024_i64,
        };
        let usage = json!({
            "work_unit_id": work_unit_id,
            "work_class": class.as_str(),
            "member_count": selected.len(),
            "reservation_state": "planned",
            "processor_version": PROCESSOR_VERSION,
        });
        sqlx::query(
            "INSERT INTO media_work_units \
             (account_id,id,work_class,processor_version,state,started_at,ended_at, \
              reserved_output_tokens,attempt_count,claim_token,claim_until,usage_json,updated_at) \
             VALUES($1,$2,$3,$4,'processing',to_timestamp($5::double precision/1000.0), \
                    to_timestamp($6::double precision/1000.0),$7,1,$8, \
                    to_timestamp($9::double precision/1000.0),$10::jsonb, \
                    to_timestamp($11::double precision/1000.0)) \
             ON CONFLICT(account_id,id) DO UPDATE SET \
                 state='processing',error_code=NULL,attempt_count=media_work_units.attempt_count+1, \
                 claim_token=excluded.claim_token,claim_until=excluded.claim_until, \
                 usage_json=excluded.usage_json,updated_at=excluded.updated_at",
        )
        .bind(account_id)
        .bind(&work_unit_id)
        .bind(class.as_str())
        .bind(PROCESSOR_VERSION)
        .bind(plan.started_ms)
        .bind(plan.ended_ms)
        .bind(reserved_output_tokens)
        .bind(&claim_token)
        .bind(lease_until_ms)
        .bind(serde_json::to_string(&usage)?)
        .bind(claimed_at_ms)
        .execute(&mut *transaction)
        .await?;
        for (ordinal, job) in selected.iter().enumerate() {
            let started_ms = parse_time(&job.started_at, "media member start")?;
            let ended_ms = parse_time(&job.ended_at, "media member end")?;
            sqlx::query(
                "INSERT INTO media_work_members \
                 (account_id,work_unit_id,event_id,job_id,ordinal,window_start_ms,window_end_ms) \
                 VALUES($1,$2,$3,$4,$5,$6,$7) ON CONFLICT DO NOTHING",
            )
            .bind(account_id)
            .bind(&work_unit_id)
            .bind(&job.event_id)
            .bind(job.id)
            .bind(ordinal as i64)
            .bind(started_ms - plan.started_ms)
            .bind(ended_ms - plan.started_ms)
            .execute(&mut *transaction)
            .await?;
        }
        let ids = selected.iter().map(|job| job.id).collect::<Vec<_>>();
        let events = selected
            .iter()
            .map(|job| job.event_id.as_str())
            .collect::<Vec<_>>();
        let changed = sqlx::query(
            "UPDATE media_processing_jobs SET state='processing',attempt_count=attempt_count+1, \
                    lease_owner=$3,lease_token=$3,lease_until=to_timestamp($4::double precision/1000.0), \
                    error_code=NULL,usage_json=$5::jsonb,updated_at=to_timestamp($6::double precision/1000.0) \
             WHERE account_id=$1 AND id=ANY($2)",
        )
        .bind(account_id)
        .bind(&ids)
        .bind(&claim_token)
        .bind(lease_until_ms)
        .bind(serde_json::to_string(&usage)?)
        .bind(claimed_at_ms)
        .execute(&mut *transaction)
        .await?
        .rows_affected();
        if changed != selected.len() as u64 {
            return Err(EnclaveError::Conflict(
                "media work claim changed an unexpected number of jobs".into(),
            ));
        }
        sqlx::query(
            "UPDATE media_objects SET processing_state='processing' \
             WHERE account_id=$1 AND event_id=ANY($2)",
        )
        .bind(account_id)
        .bind(&events)
        .execute(&mut *transaction)
        .await?;
        transaction.commit().await?;
        Ok(Some(MediaProcessingClaim {
            account_id: account_id.to_owned(),
            work_unit_id,
            class,
            claim_token,
            claim_until: lease_until,
            jobs: selected,
        }))
    }

    async fn candidate_name_vocabulary(&self, account_id: &str) -> Result<Vec<String>> {
        Ok(sqlx::query_scalar(
            "SELECT name FROM person_name_claims \
             WHERE account_id=$1 AND status IN ('accepted','probationary') \
             GROUP BY normalized_name,name ORDER BY max(observed_at) DESC LIMIT 50",
        )
        .bind(account_id)
        .fetch_all(&self.pool)
        .await?)
    }

    async fn record_reservation(
        &self,
        claim: &MediaProcessingClaim,
        reserved_output_tokens: i64,
        reserved_at: &str,
    ) -> Result<()> {
        if reserved_output_tokens < 0 {
            return Err(EnclaveError::InvalidRequest(
                "reserved output tokens are invalid".into(),
            ));
        }
        let reserved_at_ms = parse_time(reserved_at, "reservation time")?;
        let usage = serde_json::to_string(&usage_for_reservation(claim, reserved_output_tokens))?;
        let mut transaction = self.pool.begin().await?;
        if work_state_for_update(&mut transaction, claim).await? == "succeeded" {
            transaction.commit().await?;
            return Ok(());
        }
        let ids = claim.jobs.iter().map(|job| job.id).collect::<Vec<_>>();
        sqlx::query(
            "UPDATE media_processing_jobs SET usage_json=$4::jsonb,updated_at=to_timestamp($5::double precision/1000.0) \
             WHERE account_id=$1 AND id=ANY($2) AND lease_token=$3",
        )
        .bind(&claim.account_id)
        .bind(&ids)
        .bind(&claim.claim_token)
        .bind(&usage)
        .bind(reserved_at_ms)
        .execute(&mut *transaction)
        .await?;
        let changed = sqlx::query(
            "UPDATE media_work_units SET reservation_retained=true,reserved_output_tokens=$4, \
                    usage_json=$5::jsonb,updated_at=to_timestamp($6::double precision/1000.0) \
             WHERE account_id=$1 AND id=$2 AND claim_token=$3",
        )
        .bind(&claim.account_id)
        .bind(&claim.work_unit_id)
        .bind(&claim.claim_token)
        .bind(reserved_output_tokens)
        .bind(&usage)
        .bind(reserved_at_ms)
        .execute(&mut *transaction)
        .await?
        .rows_affected();
        if changed != 1 {
            return Err(EnclaveError::Conflict(
                "media work reservation was superseded".into(),
            ));
        }
        transaction.commit().await?;
        Ok(())
    }

    async fn settle_usage(&self, command: MediaUsageSettlement) -> Result<()> {
        let mut transaction = self.pool.begin().await?;
        if work_state_for_update(&mut transaction, &command.claim).await? == "succeeded" {
            transaction.commit().await?;
            return Ok(());
        }
        let usage = serde_json::to_string(&command.usage)?;
        let ids = command
            .claim
            .jobs
            .iter()
            .map(|job| job.id)
            .collect::<Vec<_>>();
        sqlx::query(
            "UPDATE media_processing_jobs SET usage_json=$4::jsonb,updated_at=now() \
             WHERE account_id=$1 AND id=ANY($2) AND lease_token=$3",
        )
        .bind(&command.claim.account_id)
        .bind(&ids)
        .bind(&command.claim.claim_token)
        .bind(&usage)
        .execute(&mut *transaction)
        .await?;
        sqlx::query(
            "UPDATE media_work_units SET usage_json=$4::jsonb,updated_at=now() \
             WHERE account_id=$1 AND id=$2 AND claim_token=$3",
        )
        .bind(&command.claim.account_id)
        .bind(&command.claim.work_unit_id)
        .bind(&command.claim.claim_token)
        .bind(&usage)
        .execute(&mut *transaction)
        .await?;
        transaction.commit().await?;
        Ok(())
    }

    async fn settle_audio(&self, command: AudioMediaSettlement) -> Result<()> {
        if command.claim.class != MediaProcessingClass::Audio || command.claim.jobs.is_empty() {
            return Err(EnclaveError::InvalidRequest(
                "audio settlement claim is invalid".into(),
            ));
        }
        let window_start = command
            .claim
            .jobs
            .iter()
            .map(|job| parse_time(&job.started_at, "audio start"))
            .collect::<Result<Vec<_>>>()?
            .into_iter()
            .min()
            .ok_or_else(|| EnclaveError::InvalidRequest("audio window is empty".into()))?;
        let window_end = command
            .claim
            .jobs
            .iter()
            .map(|job| parse_time(&job.ended_at, "audio end"))
            .collect::<Result<Vec<_>>>()?
            .into_iter()
            .max()
            .ok_or_else(|| EnclaveError::InvalidRequest("audio window is empty".into()))?;
        let duration_ms = window_end.saturating_sub(window_start);
        let sources = command
            .claim
            .jobs
            .iter()
            .map(|job| {
                Ok(media_planner::SourceInterval::new(
                    &job.event_id,
                    parse_time(&job.started_at, "audio source start")? - window_start,
                    parse_time(&job.ended_at, "audio source end")? - window_start,
                ))
            })
            .collect::<Result<Vec<_>>>()?;
        for turn in &command.turns {
            if media_planner::project_interval(&sources, turn.start_ms, turn.end_ms).is_empty() {
                return Err(EnclaveError::InvalidRequest(
                    "audio turn falls outside source media".into(),
                ));
            }
        }
        let mut transaction = self.pool.begin().await?;
        if work_state_for_update(&mut transaction, &command.claim).await? == "succeeded" {
            transaction.commit().await?;
            return Ok(());
        }
        let account_id = &command.claim.account_id;
        let segment_id = allocate_content_id(&mut transaction, account_id, "audio_segment").await?;
        sqlx::query(
            "INSERT INTO audio_segments \
             (account_id,id,started_at,ended_at,duration_seconds,source_type,audio_format,transcription_status) \
             VALUES($1,$2,to_timestamp($3::double precision/1000.0), \
                    to_timestamp($4::double precision/1000.0),$5,$6,'audio/wav','done')",
        )
        .bind(account_id)
        .bind(segment_id)
        .bind(window_start)
        .bind(window_end)
        .bind(duration_ms as f64 / 1_000.0)
        .bind(if command.claim.jobs[0].stream_kind == "system_audio" {
            "system"
        } else {
            "mic"
        })
        .execute(&mut *transaction)
        .await?;
        let distinct_speakers = command
            .turns
            .iter()
            .map(|turn| turn.speaker_local_id.as_str())
            .collect::<HashSet<_>>()
            .len();
        let mut cluster_ids = HashMap::<String, i64>::new();
        let mut resolved_people = HashMap::<String, (i64, String)>::new();
        for turn in &command.turns {
            let projected = media_planner::project_interval(&sources, turn.start_ms, turn.end_ms);
            let anchor = projected.first().expect("validated projection");
            let cluster_id = if let Some(id) = cluster_ids.get(&turn.speaker_local_id) {
                *id
            } else {
                let id =
                    allocate_content_id(&mut transaction, account_id, "speaker_cluster").await?;
                let initial = if command.claim.jobs[0].audio_role.as_deref()
                    == Some("local_transmit")
                    && distinct_speakers <= 1
                {
                    "owner_transmit"
                } else {
                    "request_local"
                };
                sqlx::query(
                    "INSERT INTO speaker_clusters \
                     (account_id,id,work_unit_id,speaker_local_id,attribution_state) \
                     VALUES($1,$2,$3,$4,$5)",
                )
                .bind(account_id)
                .bind(id)
                .bind(&command.claim.work_unit_id)
                .bind(&turn.speaker_local_id)
                .bind(initial)
                .execute(&mut *transaction)
                .await?;
                cluster_ids.insert(turn.speaker_local_id.clone(), id);
                id
            };
            let speaker_observation_id =
                allocate_content_id(&mut transaction, account_id, "speaker_observation").await?;
            let turn_start = window_start.saturating_add(turn.start_ms);
            let turn_end = window_start.saturating_add(turn.end_ms);
            sqlx::query(
                "INSERT INTO speaker_observations \
                 (account_id,id,event_id,turn_id,speaker_local_id,started_at,ended_at, \
                  transcript_text,language,overlap,cluster_id) \
                 VALUES($1,$2,$3,$4,$5,to_timestamp($6::double precision/1000.0), \
                        to_timestamp($7::double precision/1000.0),$8,$9,$10,$11)",
            )
            .bind(account_id)
            .bind(speaker_observation_id)
            .bind(&anchor.event_id)
            .bind(&turn.turn_id)
            .bind(&turn.speaker_local_id)
            .bind(turn_start)
            .bind(turn_end)
            .bind(&turn.text)
            .bind(turn.language.as_deref())
            .bind(turn.overlap)
            .bind(cluster_id)
            .execute(&mut *transaction)
            .await?;
            for source in &projected {
                sqlx::query(
                    "INSERT INTO speaker_observation_sources \
                     (account_id,speaker_observation_id,event_id,window_start_ms,window_end_ms, \
                      event_start_ms,event_end_ms) VALUES($1,$2,$3,$4,$5,$6,$7)",
                )
                .bind(account_id)
                .bind(speaker_observation_id)
                .bind(&source.event_id)
                .bind(source.window_start_ms)
                .bind(source.window_end_ms)
                .bind(source.event_start_ms)
                .bind(source.event_end_ms)
                .execute(&mut *transaction)
                .await?;
            }
            let embedding_job_id =
                allocate_content_id(&mut transaction, account_id, "voice_embedding_job").await?;
            sqlx::query(
                "INSERT INTO voice_embedding_jobs \
                 (account_id,id,speaker_observation_id,embedding_space,state) \
                 VALUES($1,$2,$3,'wespeaker-resnet34-lm-v1','pending')",
            )
            .bind(account_id)
            .bind(embedding_job_id)
            .bind(speaker_observation_id)
            .execute(&mut *transaction)
            .await?;

            let inherited_person = resolved_people.get(&turn.speaker_local_id).cloned();
            let accepted_name = is_supported_self_identification(turn, &command.turns)
                .then(|| {
                    turn.speaker_name
                        .as_deref()
                        .zip(turn.speaker_name_confidence)
                })
                .flatten()
                .filter(|(name, _)| {
                    inherited_person
                        .as_ref()
                        .is_none_or(|(_, display)| names_form_refinement(display, name))
                });
            let mut person_id = inherited_person.as_ref().map(|(id, _)| *id);
            let mut speaker_label = inherited_person
                .as_ref()
                .map(|(_, display)| display.clone())
                .unwrap_or_else(|| "Unidentified voice".to_owned());
            if let Some((name, confidence)) = accepted_name {
                let normalized = normalize_name(name);
                let (id, display_name) = match inherited_person {
                    Some((id, current_display)) => {
                        let display_name = if prefer_claimed_display_name(&current_display, name) {
                            let refined = name.trim().to_owned();
                            sqlx::query(
                                "UPDATE people SET display_name=$3,normalized_name=$4,updated_at=now() \
                                 WHERE account_id=$1 AND id=$2 AND status='identified'",
                            )
                            .bind(account_id)
                            .bind(id)
                            .bind(&refined)
                            .bind(&normalized)
                            .execute(&mut *transaction)
                            .await?;
                            sqlx::query(
                                "UPDATE utterances u SET speaker_label=$3 \
                                 FROM speaker_observations s \
                                 WHERE u.account_id=$1 AND s.account_id=u.account_id \
                                   AND s.id=u.speaker_observation_id AND s.cluster_id=$2",
                            )
                            .bind(account_id)
                            .bind(cluster_id)
                            .bind(&refined)
                            .execute(&mut *transaction)
                            .await?;
                            refined
                        } else {
                            current_display
                        };
                        (id, display_name)
                    }
                    None => {
                        let existing = sqlx::query_as::<_, (i64, String)>(
                            "SELECT c.person_id,COALESCE(p.display_name,c.name) \
                             FROM person_name_claims c JOIN people p \
                               ON p.account_id=c.account_id AND p.id=c.person_id \
                             WHERE c.account_id=$1 AND c.normalized_name=$2 \
                               AND c.status='accepted' AND c.person_id IS NOT NULL \
                               AND p.status='identified' \
                             ORDER BY c.id DESC LIMIT 1",
                        )
                        .bind(account_id)
                        .bind(&normalized)
                        .fetch_optional(&mut *transaction)
                        .await?
                        .filter(|(candidate_id, _)| {
                            resolved_people
                                .values()
                                .all(|(assigned_id, _)| assigned_id != candidate_id)
                        });
                        if let Some(existing) = existing {
                            existing
                        } else {
                            let id =
                                allocate_content_id(&mut transaction, account_id, "person").await?;
                            let display_name = name.trim().to_owned();
                            sqlx::query(
                                "INSERT INTO people(account_id,id,display_name,normalized_name,status) \
                                 VALUES($1,$2,$3,$4,'identified')",
                            )
                            .bind(account_id)
                            .bind(id)
                            .bind(&display_name)
                            .bind(&normalized)
                            .execute(&mut *transaction)
                            .await?;
                            (id, display_name)
                        }
                    }
                };
                resolved_people.insert(turn.speaker_local_id.clone(), (id, display_name.clone()));
                let evidence_id =
                    allocate_content_id(&mut transaction, account_id, "identity_evidence").await?;
                let evidence = json!({
                    "work_unit_id": command.claim.work_unit_id,
                    "event_id": anchor.event_id,
                    "turn_id": turn.turn_id,
                    "evidence": turn.speaker_name_evidence,
                });
                sqlx::query(
                    "INSERT INTO identity_evidence \
                     (account_id,id,person_id,source_event_id,observed_at,speaker_observation_id, \
                      kind,claimed_name,evidence,score,status) \
                     VALUES($1,$2,$3,$4,to_timestamp($5::double precision/1000.0),$6, \
                            'audio_self_identification',$7,$8::jsonb,$9,'accepted')",
                )
                .bind(account_id)
                .bind(evidence_id)
                .bind(id)
                .bind(&anchor.event_id)
                .bind(turn_start)
                .bind(speaker_observation_id)
                .bind(name)
                .bind(serde_json::to_string(&evidence)?)
                .bind(confidence)
                .execute(&mut *transaction)
                .await?;
                let claim_id =
                    allocate_content_id(&mut transaction, account_id, "person_name_claim").await?;
                sqlx::query(
                    "INSERT INTO person_name_claims \
                     (account_id,id,person_id,name,normalized_name,source_event_id,speaker_observation_id, \
                      observed_at,evidence_kind,evidence,confidence,status) \
                     VALUES($1,$2,$3,$4,$5,$6,$7,to_timestamp($8::double precision/1000.0), \
                            'audio_self_identification',$9::jsonb,$10,'accepted')",
                )
                .bind(account_id)
                .bind(claim_id)
                .bind(id)
                .bind(name)
                .bind(&normalized)
                .bind(&anchor.event_id)
                .bind(speaker_observation_id)
                .bind(turn_start)
                .bind(serde_json::to_string(&evidence)?)
                .bind(confidence)
                .execute(&mut *transaction)
                .await?;
                sqlx::query(
                    "UPDATE speaker_observations SET person_id=$3,direct_evidence_id=$4 \
                     WHERE account_id=$1 AND id=$2",
                )
                .bind(account_id)
                .bind(speaker_observation_id)
                .bind(id)
                .bind(evidence_id)
                .execute(&mut *transaction)
                .await?;
                sqlx::query(
                    "UPDATE speaker_clusters SET person_id=$3,attribution_state='person_bound',updated_at=now() \
                     WHERE account_id=$1 AND id=$2",
                )
                .bind(account_id)
                .bind(cluster_id)
                .bind(id)
                .execute(&mut *transaction)
                .await?;
                person_id = Some(id);
                speaker_label = display_name;
            } else if let Some(id) = person_id {
                // A work-unit speaker already resolved by stronger direct
                // evidence remains that opaque person on sibling turns, but a
                // rejected/conflicting name supplies no new direct edge.
                sqlx::query(
                    "UPDATE speaker_observations SET person_id=$3 \
                     WHERE account_id=$1 AND id=$2 AND person_id IS NULL",
                )
                .bind(account_id)
                .bind(speaker_observation_id)
                .bind(id)
                .execute(&mut *transaction)
                .await?;
            }
            let utterance_id =
                allocate_content_id(&mut transaction, account_id, "utterance").await?;
            sqlx::query(
                "INSERT INTO utterances \
                 (account_id,id,audio_segment_id,start_offset_seconds,end_offset_seconds,text, \
                  language,confidence,speaker_label,source_key,speaker_observation_id) \
                 VALUES($1,$2,$3,$4,$5,$6,$7,NULL,$8,$9,$10)",
            )
            .bind(account_id)
            .bind(utterance_id)
            .bind(segment_id)
            .bind(turn.start_ms as f64 / 1_000.0)
            .bind(turn.end_ms as f64 / 1_000.0)
            .bind(&turn.text)
            .bind(turn.language.as_deref())
            .bind(&speaker_label)
            .bind(format!("cloud-v2:{}:{}", anchor.event_id, turn.turn_id))
            .bind(speaker_observation_id)
            .execute(&mut *transaction)
            .await?;
            if let Some(person_id) = person_id {
                for fact in &turn.person_facts {
                    let fact_id =
                        allocate_content_id(&mut transaction, account_id, "person_fact").await?;
                    let evidence = json!({
                        "work_unit_id": command.claim.work_unit_id,
                        "event_id": anchor.event_id,
                        "turn_id": turn.turn_id,
                        "evidence": fact.evidence,
                    });
                    sqlx::query(
                        "INSERT INTO person_facts \
                         (account_id,id,person_id,predicate,value,evidence,derivation_version,status, \
                          source_event_id,speaker_observation_id,observed_at,literal_evidence,confidence) \
                         VALUES($1,$2,$3,$4,$5,$6::jsonb,1,'active',$7,$8, \
                                to_timestamp($9::double precision/1000.0),$10,1.0)",
                    )
                    .bind(account_id)
                    .bind(fact_id)
                    .bind(person_id)
                    .bind(&fact.predicate)
                    .bind(&fact.value)
                    .bind(serde_json::to_string(&evidence)?)
                    .bind(&anchor.event_id)
                    .bind(speaker_observation_id)
                    .bind(turn_start)
                    .bind(&fact.evidence)
                    .execute(&mut *transaction)
                    .await?;
                }
            }
        }
        mark_claim_succeeded(&mut transaction, &command.claim).await?;
        transaction.commit().await?;
        Ok(())
    }

    async fn settle_screens(&self, command: ScreenMediaSettlement) -> Result<()> {
        if command.claim.class != MediaProcessingClass::Screen
            || command.results.len() != command.claim.jobs.len()
        {
            return Err(EnclaveError::InvalidRequest(
                "screen settlement does not match its claim".into(),
            ));
        }
        let mut results = command
            .results
            .into_iter()
            .map(|result| (result.event_id.clone(), result))
            .collect::<HashMap<_, _>>();
        if results.len() != command.claim.jobs.len()
            || command
                .claim
                .jobs
                .iter()
                .any(|job| !results.contains_key(&job.event_id))
        {
            return Err(EnclaveError::InvalidRequest(
                "screen settlement frame identities are invalid".into(),
            ));
        }
        let mut transaction = self.pool.begin().await?;
        if work_state_for_update(&mut transaction, &command.claim).await? == "succeeded" {
            transaction.commit().await?;
            return Ok(());
        }
        let account_id = &command.claim.account_id;
        for job in &command.claim.jobs {
            let result = results
                .remove(&job.event_id)
                .expect("validated frame result");
            if result.literal_description.trim().is_empty()
                || result.literal_description.len() > 20_000
                || result.visible_text.len() > 100_000
                || result.salient_text.len() > 20_000
                || result.people.len() > 100
                || result
                    .people
                    .iter()
                    .any(|person| !valid_person_evidence(person))
            {
                return Err(EnclaveError::InvalidRequest(
                    "screen result is outside allowed bounds".into(),
                ));
            }
            let context = job.context.as_ref().cloned().unwrap_or_else(|| json!({}));
            let screenshot_id =
                allocate_content_id(&mut transaction, account_id, "screenshot").await?;
            let captured_at = parse_time(&job.started_at, "screenshot time")?;
            sqlx::query(
                "INSERT INTO screenshots \
                 (account_id,id,captured_at,active_app,window_title,ocr_text,salient_ocr_text,url, \
                  image_hash,source_key,display_id,capture_context_version,capture_status, \
                  primary_bundle_id,primary_window_id,visible_windows,visible_windows_truncated) \
                 VALUES($1,$2,to_timestamp($3::double precision/1000.0),$4,$5,$6,$7,$8,$9,$10, \
                        $11,2,$12,$13,$14,$15::jsonb,$16)",
            )
            .bind(account_id)
            .bind(screenshot_id)
            .bind(captured_at)
            .bind(context.get("active_app").and_then(Value::as_str))
            .bind(context.get("window_title").and_then(Value::as_str))
            .bind(&result.visible_text)
            .bind(&result.salient_text)
            .bind(context.get("active_url").and_then(Value::as_str))
            .bind(&job.sha256)
            .bind(format!("cloud-v2:{}", job.event_id))
            .bind(context.get("display_id").and_then(Value::as_i64))
            .bind(context.get("capture_status").and_then(Value::as_str))
            .bind(context.get("primary_bundle_id").and_then(Value::as_str))
            .bind(context.get("primary_window_id").and_then(Value::as_i64))
            .bind(
                context
                    .get("visible_windows")
                    .map(serde_json::to_string)
                    .transpose()?,
            )
            .bind(
                context
                    .get("visible_windows_truncated")
                    .and_then(Value::as_bool)
                    .unwrap_or(false),
            )
            .execute(&mut *transaction)
            .await?;
            sqlx::query(
                "INSERT INTO screen_observations \
                 (account_id,screenshot_id,input_revision,observation_version,status,generation_method, \
                  literal_description,screen_state,content_type,visible_text_summary,notable_items, \
                  model_name,prompt_version) \
                 VALUES($1,$2,$3,2,'ready','gemini_pixels',$4,$5,$6,$7,'[]'::jsonb, \
                        'gemini-3.5-flash',$8)",
            )
            .bind(account_id)
            .bind(screenshot_id)
            .bind(&job.sha256)
            .bind(&result.literal_description)
            .bind(&result.screen_state)
            .bind(&result.content_type)
            .bind(&result.salient_text)
            .bind(PROMPT_VERSION)
            .execute(&mut *transaction)
            .await?;
            for person in result.people {
                let evidence = json!({
                    "event_id": job.event_id,
                    "screenshot_id": screenshot_id,
                    "evidence": person.evidence,
                });
                let observation_id =
                    allocate_content_id(&mut transaction, account_id, "visual_speaker_observation")
                        .await?;
                sqlx::query(
                    "INSERT INTO visual_speaker_observations \
                     (account_id,id,event_id,screenshot_id,observed_at,platform,displayed_name, \
                      normalized_name,highlight_state,bounding_box,model_version,confidence) \
                     VALUES($1,$2,$3,$4,to_timestamp($5::double precision/1000.0),'screen_capture', \
                            $6,$7,$8,$9::jsonb,1,$10)",
                )
                .bind(account_id)
                .bind(observation_id)
                .bind(&job.event_id)
                .bind(screenshot_id)
                .bind(captured_at)
                .bind(&person.name)
                .bind(normalize_name(&person.name))
                .bind(if person.is_active_speaker {
                    "active_speaker_box"
                } else {
                    "none"
                })
                .bind(serde_json::to_string(&evidence)?)
                .bind(person.confidence)
                .execute(&mut *transaction)
                .await?;
                let evidence_id =
                    allocate_content_id(&mut transaction, account_id, "identity_evidence").await?;
                sqlx::query(
                    "INSERT INTO identity_evidence \
                     (account_id,id,source_event_id,observed_at,kind,claimed_name,evidence,score,status) \
                     VALUES($1,$2,$3,to_timestamp($4::double precision/1000.0),$5,$6,$7::jsonb,$8,'proposed')",
                )
                .bind(account_id)
                .bind(evidence_id)
                .bind(&job.event_id)
                .bind(captured_at)
                .bind(if person.is_active_speaker {
                    "screen_active_speaker"
                } else {
                    "screen_visible_name"
                })
                .bind(&person.name)
                .bind(serde_json::to_string(&evidence)?)
                .bind(person.confidence)
                .execute(&mut *transaction)
                .await?;
                if person.name.split_whitespace().count() >= 2 && person.confidence >= 0.90 {
                    let claim_id =
                        allocate_content_id(&mut transaction, account_id, "person_name_claim")
                            .await?;
                    sqlx::query(
                        "INSERT INTO person_name_claims \
                         (account_id,id,name,normalized_name,source_event_id,observed_at,evidence_kind, \
                          evidence,confidence,status) \
                         VALUES($1,$2,$3,$4,$5,to_timestamp($6::double precision/1000.0),$7, \
                                $8::jsonb,$9,$10)",
                    )
                    .bind(account_id)
                    .bind(claim_id)
                    .bind(&person.name)
                    .bind(normalize_name(&person.name))
                    .bind(&job.event_id)
                    .bind(captured_at)
                    .bind(if person.is_active_speaker {
                        "screen_active_speaker"
                    } else {
                        "screen_visible_name"
                    })
                    .bind(serde_json::to_string(&evidence)?)
                    .bind(person.confidence)
                    .bind(if person.is_active_speaker {
                        "probationary"
                    } else {
                        "proposed"
                    })
                    .execute(&mut *transaction)
                    .await?;
                }
            }
        }
        mark_claim_succeeded(&mut transaction, &command.claim).await?;
        transaction.commit().await?;
        Ok(())
    }

    async fn settle_failure(
        &self,
        claim: &MediaProcessingClaim,
        error_code: &str,
        failed_at: &str,
        max_attempts: i64,
        budget_retry_seconds: i64,
        resurrection_window_seconds: i64,
    ) -> Result<()> {
        if error_code.is_empty()
            || error_code.len() > 128
            || max_attempts <= 0
            || budget_retry_seconds <= 0
            || resurrection_window_seconds <= 0
        {
            return Err(EnclaveError::InvalidRequest(
                "media failure settlement is invalid".into(),
            ));
        }
        let failed_at_ms = parse_time(failed_at, "media failure time")?;
        let window_start_ms = failed_at_ms.saturating_sub(resurrection_window_seconds * 1_000);
        let mut transaction = self.pool.begin().await?;
        if work_state_for_update(&mut transaction, claim).await? == "succeeded" {
            transaction.commit().await?;
            return Ok(());
        }
        let mut terminal = false;
        for job in &claim.jobs {
            let row = sqlx::query(
                "SELECT j.attempt_count, \
                        floor(extract(epoch FROM e.started_at)*1000)::bigint AS started_at_ms \
                 FROM media_processing_jobs j JOIN capture_events e \
                   ON e.account_id=j.account_id AND e.event_id=j.event_id \
                 WHERE j.account_id=$1 AND j.id=$2 AND j.lease_token=$3 FOR UPDATE",
            )
            .bind(&claim.account_id)
            .bind(job.id)
            .bind(&claim.claim_token)
            .fetch_optional(&mut *transaction)
            .await?
            .ok_or_else(|| EnclaveError::Conflict("media job claim was superseded".into()))?;
            let attempts: i64 = row.try_get("attempt_count")?;
            let started_at_ms: i64 = row.try_get("started_at_ms")?;
            let (state, media_state, next_at_ms, next_attempt_count) =
                if error_code == "vertex_daily_budget" && started_at_ms >= window_start_ms {
                    (
                        "retry_wait",
                        "retry_wait",
                        failed_at_ms.saturating_add(budget_retry_seconds * 1_000),
                        attempts.saturating_sub(1),
                    )
                } else if error_code == "vertex_daily_budget" || attempts >= max_attempts {
                    terminal = true;
                    ("failed_terminal", "failed", failed_at_ms, attempts)
                } else {
                    let exponent = u32::try_from(attempts.min(6)).unwrap_or(6);
                    let delay = 30_i64.saturating_mul(1_i64 << exponent);
                    (
                        "retry_wait",
                        "retry_wait",
                        failed_at_ms.saturating_add(delay * 1_000),
                        attempts,
                    )
                };
            sqlx::query(
                "UPDATE media_processing_jobs SET state=$4,attempt_count=$5,lease_owner=NULL, \
                        lease_token=NULL,lease_until=NULL,error_code=$6, \
                        updated_at=to_timestamp($7::double precision/1000.0) \
                 WHERE account_id=$1 AND id=$2 AND lease_token=$3",
            )
            .bind(&claim.account_id)
            .bind(job.id)
            .bind(&claim.claim_token)
            .bind(state)
            .bind(next_attempt_count)
            .bind(error_code)
            .bind(next_at_ms)
            .execute(&mut *transaction)
            .await?;
            sqlx::query(
                "UPDATE media_objects SET processing_state=$3 \
                 WHERE account_id=$1 AND event_id=$2",
            )
            .bind(&claim.account_id)
            .bind(&job.event_id)
            .bind(media_state)
            .execute(&mut *transaction)
            .await?;
        }
        sqlx::query(
            "UPDATE media_work_units SET state=$4,claim_token=NULL,claim_until=NULL, \
                    error_code=$5,updated_at=to_timestamp($6::double precision/1000.0) \
             WHERE account_id=$1 AND id=$2 AND claim_token=$3",
        )
        .bind(&claim.account_id)
        .bind(&claim.work_unit_id)
        .bind(&claim.claim_token)
        .bind(if terminal {
            "failed_terminal"
        } else {
            "retry_wait"
        })
        .bind(error_code)
        .bind(failed_at_ms)
        .execute(&mut *transaction)
        .await?;
        transaction.commit().await?;
        Ok(())
    }

    async fn resurrect_recent_failures(
        &self,
        account_id: &str,
        now: &str,
        delay_seconds: i64,
        total_attempt_cap: i64,
        window_seconds: i64,
        limit: i64,
    ) -> Result<u64> {
        if delay_seconds <= 0 || total_attempt_cap <= 0 || window_seconds <= 0 || limit <= 0 {
            return Err(EnclaveError::Config(
                "media resurrection bounds are invalid".into(),
            ));
        }
        let now_ms = parse_time(now, "media resurrection time")?;
        let stale_before = now_ms.saturating_sub(delay_seconds * 1_000);
        let window_start = now_ms.saturating_sub(window_seconds * 1_000);
        let mut transaction = self.pool.begin().await?;
        let rows = sqlx::query(
            "SELECT j.id,j.event_id FROM media_processing_jobs j \
             JOIN capture_events e ON e.account_id=j.account_id AND e.event_id=j.event_id \
             WHERE j.account_id=$1 AND j.processor_version=$2 AND j.state='failed_terminal' \
               AND j.error_code NOT IN ('media_integrity','transcript_target_conflict','unplannable_media') \
               AND j.attempt_count<$3 \
               AND j.updated_at<=to_timestamp($4::double precision/1000.0) \
               AND e.started_at>=to_timestamp($5::double precision/1000.0) \
             ORDER BY j.id LIMIT $6 FOR UPDATE OF j SKIP LOCKED",
        )
        .bind(account_id)
        .bind(PROCESSOR_VERSION)
        .bind(total_attempt_cap)
        .bind(stale_before)
        .bind(window_start)
        .bind(limit)
        .fetch_all(&mut *transaction)
        .await?;
        let ids = rows
            .iter()
            .map(|row| row.get::<i64, _>("id"))
            .collect::<Vec<_>>();
        let events = rows
            .iter()
            .map(|row| row.get::<String, _>("event_id"))
            .collect::<Vec<_>>();
        if !ids.is_empty() {
            sqlx::query(
                "UPDATE media_processing_jobs SET state='retry_wait',error_code=NULL, \
                        lease_owner=NULL,lease_token=NULL,lease_until=NULL,updated_at=now() \
                 WHERE account_id=$1 AND id=ANY($2)",
            )
            .bind(account_id)
            .bind(&ids)
            .execute(&mut *transaction)
            .await?;
            sqlx::query(
                "UPDATE media_objects SET processing_state='retry_wait' \
                 WHERE account_id=$1 AND event_id=ANY($2)",
            )
            .bind(account_id)
            .bind(&events)
            .execute(&mut *transaction)
            .await?;
        }
        transaction.commit().await?;
        Ok(ids.len() as u64)
    }

    async fn span_has_recoverable_media(
        &self,
        account_id: &str,
        from: &str,
        to: &str,
        resurrection_window_start: &str,
        memory_hold_attempts: i64,
    ) -> Result<bool> {
        let from_ms = parse_time(from, "media span start")?;
        let to_ms = parse_time(to, "media span end")?;
        let window_ms = parse_time(resurrection_window_start, "media recovery window")?;
        Ok(sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM capture_events e \
             JOIN media_objects m ON m.account_id=e.account_id AND m.event_id=e.event_id \
             LEFT JOIN media_processing_jobs j ON j.account_id=e.account_id AND j.event_id=e.event_id \
             WHERE e.account_id=$1 \
               AND e.started_at<to_timestamp($2::double precision/1000.0) \
               AND e.ended_at>to_timestamp($3::double precision/1000.0) \
               AND (m.processing_state IN ('queued','processing','retry_wait') OR ( \
                    m.processing_state='failed' \
                    AND j.error_code NOT IN ('media_integrity','transcript_target_conflict','unplannable_media') \
                    AND j.attempt_count<$4 \
                    AND e.started_at>=to_timestamp($5::double precision/1000.0))))",
        )
        .bind(account_id)
        .bind(to_ms)
        .bind(from_ms)
        .bind(memory_hold_attempts)
        .bind(window_ms)
        .fetch_one(&self.pool)
        .await?)
    }
}
