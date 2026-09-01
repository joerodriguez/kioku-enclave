use std::collections::{HashMap, HashSet};

use async_trait::async_trait;
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use sqlx::Row;

use crate::{
    cp::{
        isotime, media_planner,
        media_worker::{NON_RESURRECTABLE_MEDIA_ERROR_CODES, PROCESSOR_VERSION},
        vertex::VertexOperation,
    },
    error::{EnclaveError, Result},
    persistence::{
        is_owner_source_audio, is_supported_self_identification, media_provider_attempt_identity,
        names_form_refinement, prefer_claimed_display_name, vertex_attempt_event_id,
        AudioMediaSettlement, MediaFailureDisposition, MediaFailurePolicy, MediaPersonEvidence,
        MediaProcessingClaim, MediaProcessingClass, MediaProcessingJob, MediaProcessingRepository,
        MediaProviderAttempt, MediaProviderStagedResponse, MediaUsageSettlement,
        ScreenMediaSettlement, MAX_MEDIA_PROVIDER_ATTEMPTS, MAX_MEDIA_PROVIDER_JOURNAL_BYTES,
        MAX_MEDIA_PROVIDER_RESPONSE_BYTES,
    },
};

#[cfg(test)]
use crate::persistence::MediaScreenProjection;

use super::{
    activation::lock_activation_contract_key_share_if_installed,
    advisory_transaction_lock, allocate_content_id,
    capture::mark_capture_formation_dirty,
    model_usage::{invocation_fingerprint, refresh_coverage},
    PostgresPersistence,
};

const PROMPT_VERSION: i64 = 3;
// Vertex generation has a hard 120-second request timeout. Refresh the exact
// durable work and job leases immediately before provider egress so deletion
// can conservatively treat either live lease as an in-flight disclosure
// fence, with ample time left for response accounting and settlement.
const PROVIDER_EGRESS_LEASE_SECONDS: f64 = 15.0 * 60.0;
const PROVIDER_JOURNAL_VERSION: i64 = 1;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProviderAttemptJournalEntry {
    number: i64,
    identity_sha256: String,
    request_sha256: String,
    event_id: String,
    requested_model: String,
    location: String,
    state: String,
    admitted_at: Option<String>,
    completed_at: Option<String>,
    http_status: Option<u16>,
    response_sha256: Option<String>,
    response_b64: Option<String>,
    latency_ms: Option<u64>,
}

#[derive(Clone, Debug, Default)]
struct ProviderAttemptJournal {
    attempts: Vec<ProviderAttemptJournalEntry>,
}

fn digest_hex(value: &[u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(64);
    for byte in value {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    encoded
}

fn parse_digest_hex(value: &str, field: &str) -> Result<[u8; 32]> {
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(EnclaveError::Store(format!(
            "media provider journal {field} is invalid"
        )));
    }
    let mut digest = [0_u8; 32];
    for (index, slot) in digest.iter_mut().enumerate() {
        *slot = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16).map_err(|_| {
            EnclaveError::Store(format!("media provider journal {field} is invalid"))
        })?;
    }
    Ok(digest)
}

fn usage_object_mut(usage: &mut Value) -> Result<&mut serde_json::Map<String, Value>> {
    if usage.is_null() {
        *usage = json!({});
    }
    usage
        .as_object_mut()
        .ok_or_else(|| EnclaveError::Store("media work usage journal is not a JSON object".into()))
}

fn provider_journal(usage: &Value) -> Result<ProviderAttemptJournal> {
    let Some(object) = usage.as_object() else {
        return if usage.is_null() {
            Ok(ProviderAttemptJournal::default())
        } else {
            Err(EnclaveError::Store(
                "media work usage journal is not a JSON object".into(),
            ))
        };
    };
    let Some(raw_attempts) = object.get("provider_attempts") else {
        return Ok(ProviderAttemptJournal::default());
    };
    if object
        .get("provider_attempt_journal_version")
        .and_then(Value::as_i64)
        != Some(PROVIDER_JOURNAL_VERSION)
    {
        return Err(EnclaveError::Store(
            "media provider journal version is invalid".into(),
        ));
    }
    let attempts: Vec<ProviderAttemptJournalEntry> = serde_json::from_value(raw_attempts.clone())?;
    if attempts.len() > MAX_MEDIA_PROVIDER_ATTEMPTS as usize {
        return Err(EnclaveError::Store(
            "media provider journal exceeds its attempt bound".into(),
        ));
    }
    for (index, attempt) in attempts.iter().enumerate() {
        if attempt.number != index as i64 + 1 {
            return Err(EnclaveError::Store(
                "media provider journal numbering is not contiguous".into(),
            ));
        }
        if !matches!(
            attempt.state.as_str(),
            "admitted"
                | "response_staged"
                | "usage_settled"
                | "confirmed_not_billed"
                | "ambiguous"
                | "confirmed_invalid"
                | "settled"
        ) {
            return Err(EnclaveError::Store(
                "media provider journal state is invalid".into(),
            ));
        }
    }
    Ok(ProviderAttemptJournal { attempts })
}

fn persist_provider_journal(usage: &mut Value, journal: &ProviderAttemptJournal) -> Result<String> {
    if journal.attempts.len() > MAX_MEDIA_PROVIDER_ATTEMPTS as usize {
        return Err(EnclaveError::Conflict(
            "media provider attempt bound is exhausted".into(),
        ));
    }
    let object = usage_object_mut(usage)?;
    object.insert(
        "provider_attempt_journal_version".into(),
        Value::from(PROVIDER_JOURNAL_VERSION),
    );
    object.insert(
        "provider_attempts".into(),
        serde_json::to_value(&journal.attempts)?,
    );
    let encoded = serde_json::to_string(usage)?;
    if encoded.len() > MAX_MEDIA_PROVIDER_JOURNAL_BYTES {
        return Err(EnclaveError::Conflict(
            "media provider journal exceeds its byte bound".into(),
        ));
    }
    Ok(encoded)
}

fn validate_provider_attempt(
    account_id: &str,
    work_unit_id: &str,
    attempt: &ProviderAttemptJournalEntry,
) -> Result<MediaProviderAttempt> {
    let request_sha256 = parse_digest_hex(&attempt.request_sha256, "request digest")?;
    let identity_sha256 = parse_digest_hex(&attempt.identity_sha256, "attempt identity")?;
    let expected_identity =
        media_provider_attempt_identity(account_id, work_unit_id, attempt.number, &request_sha256);
    if identity_sha256 != expected_identity
        || attempt.event_id != vertex_attempt_event_id(&identity_sha256)
    {
        return Err(EnclaveError::Store(
            "media provider journal identity commitment is invalid".into(),
        ));
    }
    Ok(MediaProviderAttempt {
        number: attempt.number,
        identity_sha256,
        request_sha256,
        event_id: attempt.event_id.clone(),
        requested_model: attempt.requested_model.clone(),
        location: attempt.location.clone(),
    })
}

fn staged_response_from_entry(
    account_id: &str,
    work_unit_id: &str,
    entry: &ProviderAttemptJournalEntry,
) -> Result<MediaProviderStagedResponse> {
    if !matches!(entry.state.as_str(), "response_staged" | "usage_settled") {
        return Err(EnclaveError::Store(
            "media provider response is not staged".into(),
        ));
    }
    let bytes = B64
        .decode(
            entry
                .response_b64
                .as_deref()
                .ok_or_else(|| EnclaveError::Store("staged media response is absent".into()))?,
        )
        .map_err(|_| EnclaveError::Store("staged media response encoding is invalid".into()))?;
    if bytes.len() > MAX_MEDIA_PROVIDER_RESPONSE_BYTES {
        return Err(EnclaveError::Store(
            "staged media response exceeds its byte bound".into(),
        ));
    }
    let response_sha256 = parse_digest_hex(
        entry
            .response_sha256
            .as_deref()
            .ok_or_else(|| EnclaveError::Store("staged media response digest is absent".into()))?,
        "response digest",
    )?;
    if <[u8; 32]>::from(Sha256::digest(&bytes)) != response_sha256 {
        return Err(EnclaveError::Store(
            "staged media response digest does not match its bytes".into(),
        ));
    }
    Ok(MediaProviderStagedResponse {
        attempt: validate_provider_attempt(account_id, work_unit_id, entry)?,
        http_status: entry
            .http_status
            .ok_or_else(|| EnclaveError::Store("staged media response status is absent".into()))?,
        response_sha256,
        response_bytes: bytes,
        latency_ms: entry
            .latency_ms
            .ok_or_else(|| EnclaveError::Store("staged media response latency is absent".into()))?,
    })
}

fn claim_provider_state(
    usage: &Value,
    account_id: &str,
    work_unit_id: &str,
) -> Result<(i64, Option<MediaProviderStagedResponse>, bool)> {
    let journal = provider_journal(usage)?;
    let Some(last) = journal.attempts.last() else {
        return Ok((1, None, false));
    };
    validate_provider_attempt(account_id, work_unit_id, last)?;
    match last.state.as_str() {
        "confirmed_not_billed" => Ok((last.number + 1, None, false)),
        "response_staged" | "usage_settled" => Ok((
            last.number,
            Some(staged_response_from_entry(account_id, work_unit_id, last)?),
            false,
        )),
        // Once an admission can have crossed egress, lease loss cannot mint a
        // replacement attempt. The reclaim path terminalizes it providerlessly.
        "admitted" | "ambiguous" | "confirmed_invalid" => Ok((last.number, None, true)),
        "settled" => Err(EnclaveError::Store(
            "settled media provider attempt belongs to unfinished work".into(),
        )),
        _ => unreachable!("journal state was validated"),
    }
}

async fn database_now_iso(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
) -> Result<String> {
    let millis = sqlx::query_scalar::<_, i64>(
        "SELECT floor(extract(epoch FROM clock_timestamp())*1000)::bigint",
    )
    .fetch_one(&mut **transaction)
    .await?;
    Ok(isotime::format_epoch_millis(millis))
}

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

fn vertex_operation_for_class(class: MediaProcessingClass) -> VertexOperation {
    match class {
        MediaProcessingClass::Audio => VertexOperation::AudioWindow,
        MediaProcessingClass::Screen => VertexOperation::ScreenStoryboard,
    }
}

struct PersistedMediaWorkPlan {
    work_unit_id: String,
    started_ms: i64,
    ended_ms: i64,
    member_job_ids: Vec<i64>,
}

/// A job can be bound to only one durable work unit. Reclaim that exact
/// membership before applying current planner policy so an image upgrade (or
/// a late adjacent event) cannot expand an already-frozen provider identity.
async fn persisted_media_work_for_head(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    account_id: &str,
    head_job_id: i64,
    class: MediaProcessingClass,
) -> Result<Option<PersistedMediaWorkPlan>> {
    let rows = sqlx::query(
        "SELECT work.id,work.work_class,work.processor_version,work.state, \
                floor(extract(epoch FROM work.started_at)*1000)::bigint AS started_at_ms, \
                floor(extract(epoch FROM work.ended_at)*1000)::bigint AS ended_at_ms, \
                member.job_id,member.ordinal \
           FROM media_work_members head \
           JOIN media_work_units work \
             ON work.account_id=head.account_id AND work.id=head.work_unit_id \
           JOIN media_work_members member \
             ON member.account_id=work.account_id AND member.work_unit_id=work.id \
          WHERE head.account_id=$1 AND head.job_id=$2 \
          ORDER BY member.ordinal",
    )
    .bind(account_id)
    .bind(head_job_id)
    .fetch_all(&mut **transaction)
    .await?;
    let Some(first) = rows.first() else {
        return Ok(None);
    };
    let work_unit_id: String = first.try_get("id")?;
    let started_ms: i64 = first.try_get("started_at_ms")?;
    let ended_ms: i64 = first.try_get("ended_at_ms")?;
    if first.try_get::<String, _>("work_class")? != class.as_str()
        || first.try_get::<i64, _>("processor_version")? != PROCESSOR_VERSION
        || !matches!(
            first.try_get::<String, _>("state")?.as_str(),
            "planned" | "processing" | "retry_wait"
        )
        || started_ms >= ended_ms
        || rows.iter().enumerate().any(|(ordinal, row)| {
            row.try_get::<String, _>("id").ok().as_deref() != Some(work_unit_id.as_str())
                || row.try_get::<i64, _>("ordinal").ok() != Some(ordinal as i64)
        })
    {
        return Err(EnclaveError::Store(
            "persisted media work membership is invalid".into(),
        ));
    }
    let member_job_ids = rows
        .iter()
        .map(|row| row.try_get::<i64, _>("job_id"))
        .collect::<std::result::Result<Vec<_>, _>>()?;
    if member_job_ids.first() != Some(&head_job_id) {
        return Err(EnclaveError::Store(
            "persisted media work does not retain its head".into(),
        ));
    }
    Ok(Some(PersistedMediaWorkPlan {
        work_unit_id,
        started_ms,
        ended_ms,
        member_job_ids,
    }))
}

async fn eligible_media_jobs_for_exact_work(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    account_id: &str,
    member_job_ids: &[i64],
    class: MediaProcessingClass,
) -> Result<Vec<MediaProcessingJob>> {
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
          WHERE j.account_id=$1 AND j.id=ANY($2::bigint[]) \
            AND j.processor_version=$3 AND j.job_kind=$4 AND (j.state='pending' OR \
                (j.state='retry_wait' AND j.updated_at<=clock_timestamp()) OR \
                (j.state='processing' AND j.lease_until<=clock_timestamp())) \
            AND NOT EXISTS(SELECT 1 FROM episode_deletions deletion \
                 WHERE deletion.account_id=e.account_id AND deletion.state='pending' \
                   AND (deletion.orphan_event_ids ? e.event_id OR deletion.orphan_event_ids ? \
                        coalesce(e.canonical_event_id,e.event_id))) \
          ORDER BY array_position($2::bigint[],j.id)",
    )
    .bind(account_id)
    .bind(member_job_ids)
    .bind(PROCESSOR_VERSION)
    .bind(class.job_kind())
    .fetch_all(&mut **transaction)
    .await?;
    rows.iter().map(job_from_row).collect()
}

async fn require_exact_vertex_usage_attempt(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    account_id: &str,
    class: MediaProcessingClass,
    attempt: &MediaProviderAttempt,
) -> Result<(String, Option<i32>)> {
    let operation = vertex_operation_for_class(class);
    let expected_fingerprint = invocation_fingerprint(
        account_id,
        operation,
        &attempt.requested_model,
        &attempt.location,
        &attempt.request_sha256,
    );
    let row = sqlx::query(
        "SELECT request_fingerprint,operation,requested_model,location,outcome,http_status \
           FROM vertex_usage_events WHERE account_id=$1 AND event_id=$2 FOR KEY SHARE",
    )
    .bind(account_id)
    .bind(&attempt.event_id)
    .fetch_optional(&mut **transaction)
    .await?
    .ok_or_else(|| EnclaveError::Conflict("media provider usage intent is absent".into()))?;
    let stored_fingerprint: Vec<u8> = row.try_get("request_fingerprint")?;
    if stored_fingerprint.as_slice() != expected_fingerprint.as_slice()
        || row.try_get::<String, _>("operation")? != operation.as_str()
        || row.try_get::<String, _>("requested_model")? != attempt.requested_model.as_str()
        || row.try_get::<String, _>("location")? != attempt.location.as_str()
    {
        return Err(EnclaveError::Conflict(
            "media provider usage intent does not match its exact request".into(),
        ));
    }
    Ok((row.try_get("outcome")?, row.try_get("http_status")?))
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

struct LockedClaim {
    state: String,
    usage: Value,
}

async fn lock_claim_for_update(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    claim: &MediaProcessingClaim,
    require_live: bool,
) -> Result<LockedClaim> {
    let row = sqlx::query(
        "SELECT state,claim_token,claim_until>clock_timestamp() AS claim_live, \
                coalesce(usage_json,'{}'::jsonb)::text AS usage_json \
           FROM media_work_units \
         WHERE account_id=$1 AND id=$2 FOR UPDATE",
    )
    .bind(&claim.account_id)
    .bind(&claim.work_unit_id)
    .fetch_optional(&mut **transaction)
    .await?
    .ok_or_else(|| EnclaveError::Conflict("media work claim is absent".into()))?;
    let state: String = row.try_get("state")?;
    if state == "succeeded" {
        return Ok(LockedClaim {
            state,
            usage: serde_json::from_str(row.try_get("usage_json")?)?,
        });
    }
    let token: Option<String> = row.try_get("claim_token")?;
    let claim_live: Option<bool> = row.try_get("claim_live")?;
    if state != "processing"
        || token.as_deref() != Some(claim.claim_token.as_str())
        || (require_live && claim_live != Some(true))
    {
        return Err(EnclaveError::Conflict(
            "media work claim is no longer live".into(),
        ));
    }
    let members = sqlx::query(
        "SELECT member.ordinal,job.id,job.event_id,job.state,job.lease_token, \
                job.lease_until>clock_timestamp() AS lease_live \
           FROM media_work_members member \
           JOIN media_processing_jobs job \
             ON job.account_id=member.account_id AND job.id=member.job_id \
          WHERE member.account_id=$1 AND member.work_unit_id=$2 \
          ORDER BY member.ordinal FOR UPDATE OF job",
    )
    .bind(&claim.account_id)
    .bind(&claim.work_unit_id)
    .fetch_all(&mut **transaction)
    .await?;
    if members.len() != claim.jobs.len() {
        return Err(EnclaveError::Conflict(
            "media work membership changed".into(),
        ));
    }
    for (ordinal, (member, expected)) in members.iter().zip(&claim.jobs).enumerate() {
        let persisted_ordinal: i64 = member.try_get("ordinal")?;
        let persisted_job_id: i64 = member.try_get("id")?;
        let persisted_event_id: String = member.try_get("event_id")?;
        let persisted_state: String = member.try_get("state")?;
        let persisted_token: Option<String> = member.try_get("lease_token")?;
        let lease_live: Option<bool> = member.try_get("lease_live")?;
        if persisted_ordinal != ordinal as i64
            || persisted_job_id != expected.id
            || persisted_event_id != expected.event_id
            || persisted_state != "processing"
            || persisted_token.as_deref() != Some(claim.claim_token.as_str())
            || (require_live && lease_live != Some(true))
        {
            return Err(EnclaveError::Conflict(
                "media job claim is no longer live".into(),
            ));
        }
    }
    Ok(LockedClaim {
        state,
        usage: serde_json::from_str(row.try_get("usage_json")?)?,
    })
}

/// Episode deletion persists its exact canonical/reference event family before
/// any provider bytes or projections are erased. Claim and settlement both
/// hold the activation fence followed by the account reconciliation lock, so
/// a pending receipt wins the race and no late provider result can recreate
/// structured evidence while deletion is in progress.
async fn ensure_claim_sources_not_pending_deletion(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    claim: &MediaProcessingClaim,
) -> Result<()> {
    let event_ids = claim
        .jobs
        .iter()
        .map(|job| job.event_id.as_str())
        .collect::<Vec<_>>();
    let blocked = sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS(SELECT 1 FROM capture_events event \
          JOIN episode_deletions deletion ON deletion.account_id=event.account_id \
               AND deletion.state='pending' \
         WHERE event.account_id=$1 AND event.event_id=ANY($2) \
           AND (deletion.orphan_event_ids ? event.event_id \
                OR deletion.orphan_event_ids ? \
                   coalesce(event.canonical_event_id,event.event_id)))",
    )
    .bind(&claim.account_id)
    .bind(&event_ids)
    .fetch_one(&mut **transaction)
    .await?;
    if blocked {
        return Err(EnclaveError::Conflict(
            "media source is pending episode deletion".into(),
        ));
    }
    Ok(())
}

async fn mark_claim_succeeded(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    claim: &MediaProcessingClaim,
    provider_attempt: &MediaProviderAttempt,
    work_usage: &mut Value,
) -> Result<()> {
    let mut journal = provider_journal(work_usage)?;
    let entry = journal.attempts.last_mut().ok_or_else(|| {
        EnclaveError::Conflict("media provider attempt is absent at projection settlement".into())
    })?;
    if validate_provider_attempt(&claim.account_id, &claim.work_unit_id, entry)?
        != *provider_attempt
        || entry.state != "usage_settled"
    {
        return Err(EnclaveError::Conflict(
            "media projection settlement does not match terminal provider usage".into(),
        ));
    }
    entry.state = "settled".into();
    entry.completed_at = Some(database_now_iso(transaction).await?);
    entry.response_b64 = None;
    let usage = persist_provider_journal(work_usage, &journal)?;
    let ids = claim.jobs.iter().map(|job| job.id).collect::<Vec<_>>();
    let events = claim
        .jobs
        .iter()
        .map(|job| job.event_id.as_str())
        .collect::<Vec<_>>();
    let changed = sqlx::query(
        "UPDATE media_processing_jobs SET state='succeeded',lease_owner=NULL,lease_token=NULL, \
                lease_until=NULL,error_code=NULL, \
                model_id='gemini-3.5-flash',prompt_version=$4,schema_version=2, \
                updated_at=clock_timestamp() \
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
    let changed_objects = sqlx::query(
        "UPDATE media_objects SET processing_state='ready' \
         WHERE account_id=$1 AND event_id=ANY($2)",
    )
    .bind(&claim.account_id)
    .bind(&events)
    .execute(&mut **transaction)
    .await?
    .rows_affected();
    if changed_objects != events.len() as u64 {
        return Err(EnclaveError::Conflict(
            "media object projection settlement changed unexpected rows".into(),
        ));
    }
    let changed_work = sqlx::query(
        "UPDATE media_work_units SET state='succeeded',error_code=NULL,claim_token=NULL, \
                claim_until=NULL,usage_json=$4::jsonb,updated_at=clock_timestamp() \
         WHERE account_id=$1 AND id=$2 AND claim_token=$3",
    )
    .bind(&claim.account_id)
    .bind(&claim.work_unit_id)
    .bind(&claim.claim_token)
    .bind(&usage)
    .execute(&mut **transaction)
    .await?
    .rows_affected();
    if changed_work != 1 {
        return Err(EnclaveError::Conflict(
            "media work projection settlement lost its claim".into(),
        ));
    }
    Ok(())
}

#[async_trait]
impl MediaProcessingRepository for PostgresPersistence {
    async fn pending_classes(&self, account_id: &str, now: &str) -> Result<(bool, bool)> {
        let _now_ms = parse_time(now, "media scan time")?;
        let kinds = sqlx::query_scalar::<_, String>(
            "SELECT DISTINCT job_kind FROM media_processing_jobs \
             WHERE account_id=$1 AND processor_version=$2 AND ( \
                 state='pending' OR \
                 (state='retry_wait' AND updated_at<=clock_timestamp()) OR \
                 (state='processing' AND lease_until<=clock_timestamp()))",
        )
        .bind(account_id)
        .bind(PROCESSOR_VERSION)
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
        let _claimed_at_ms = parse_time(claimed_at, "media claim time")?;
        let mut transaction = self.pool.begin().await?;
        lock_activation_contract_key_share_if_installed(&mut transaction).await?;
        advisory_transaction_lock(&mut transaction, "memory-reconciliation", account_id).await?;
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
                 (j.state='retry_wait' AND j.updated_at<=clock_timestamp()) OR \
                 (j.state='processing' AND j.lease_until<=clock_timestamp())) \
               AND NOT EXISTS(SELECT 1 FROM episode_deletions deletion \
                    WHERE deletion.account_id=e.account_id AND deletion.state='pending' \
                      AND (deletion.orphan_event_ids ? e.event_id \
                           OR deletion.orphan_event_ids ? \
                              coalesce(e.canonical_event_id,e.event_id))) \
             ORDER BY e.started_at,e.sequence,j.id LIMIT $4",
        )
        .bind(account_id)
        .bind(PROCESSOR_VERSION)
        .bind(class.job_kind())
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
        let head_job_id = media_planner::plan_first(&candidates).head_job_id;
        let persisted =
            persisted_media_work_for_head(&mut transaction, account_id, head_job_id, class).await?;
        let (selected, work_unit_id, plan_started_ms, plan_ended_ms) = if let Some(persisted) =
            persisted
        {
            let selected = eligible_media_jobs_for_exact_work(
                &mut transaction,
                account_id,
                &persisted.member_job_ids,
                class,
            )
            .await?;
            if selected.len() != persisted.member_job_ids.len()
                || selected
                    .iter()
                    .zip(&persisted.member_job_ids)
                    .any(|(job, expected_id)| job.id != *expected_id)
                || work_unit_id(class, &selected) != persisted.work_unit_id
            {
                return Err(EnclaveError::Conflict(
                    "persisted media work is not exactly reclaimable".into(),
                ));
            }
            (
                selected,
                persisted.work_unit_id,
                persisted.started_ms,
                persisted.ended_ms,
            )
        } else {
            let plan = media_planner::plan_first(&candidates);
            if plan.member_job_ids.is_empty() {
                sqlx::query(
                "UPDATE media_processing_jobs SET state='failed_terminal',error_code='unplannable_media', \
                        lease_owner=NULL,lease_token=NULL,lease_until=NULL, \
                        updated_at=clock_timestamp() \
                 WHERE account_id=$1 AND id=$2 AND (state='pending' OR state='retry_wait' OR \
                       (state='processing' AND lease_until<=clock_timestamp()))",
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
            (selected, work_unit_id, plan.started_ms, plan.ended_ms)
        };
        let claim_token = crate::cp::tokens::random_token_hex();
        let reserved_output_tokens = match class {
            MediaProcessingClass::Audio => 4_096_i64,
            MediaProcessingClass::Screen => 1_024_i64,
        };
        let planned_usage = json!({
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
             VALUES($1,$2,$3,$4,'planned',to_timestamp($5::double precision/1000.0), \
                    to_timestamp($6::double precision/1000.0),$7,0,NULL,NULL,$8::jsonb, \
                    clock_timestamp()) ON CONFLICT(account_id,id) DO NOTHING",
        )
        .bind(account_id)
        .bind(&work_unit_id)
        .bind(class.as_str())
        .bind(PROCESSOR_VERSION)
        .bind(plan_started_ms)
        .bind(plan_ended_ms)
        .bind(reserved_output_tokens)
        .bind(serde_json::to_string(&planned_usage)?)
        .execute(&mut *transaction)
        .await?;

        // The aggregate is always the first inner row lock. Candidate reads
        // above are intentionally unlocked; the account advisory lock keeps
        // claim planning stable until the exact jobs are locked below.
        let work = sqlx::query(
            "SELECT state,claim_token,claim_until>clock_timestamp() AS claim_live, \
                    coalesce(usage_json,'{}'::jsonb)::text AS usage_json \
               FROM media_work_units WHERE account_id=$1 AND id=$2 FOR UPDATE",
        )
        .bind(account_id)
        .bind(&work_unit_id)
        .fetch_one(&mut *transaction)
        .await?;
        let work_state: String = work.try_get("state")?;
        let work_token: Option<String> = work.try_get("claim_token")?;
        let work_live: Option<bool> = work.try_get("claim_live")?;
        if work_state == "succeeded"
            || (work_state == "processing" && work_live == Some(true) && work_token.is_some())
        {
            transaction.commit().await?;
            return Ok(None);
        }
        let mut work_usage: Value = serde_json::from_str(work.try_get("usage_json")?)?;
        let (provider_attempt_number, staged_response, lost_admission) =
            claim_provider_state(&work_usage, account_id, &work_unit_id)?;
        if provider_attempt_number > MAX_MEDIA_PROVIDER_ATTEMPTS {
            return Err(EnclaveError::Conflict(
                "media provider attempt bound is exhausted".into(),
            ));
        }
        {
            let object = usage_object_mut(&mut work_usage)?;
            for (key, value) in planned_usage
                .as_object()
                .expect("planned media usage is an object")
            {
                object.insert(key.clone(), value.clone());
            }
        }
        let work_usage_json = {
            let journal = provider_journal(&work_usage)?;
            persist_provider_journal(&mut work_usage, &journal)?
        };
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
            .bind(started_ms - plan_started_ms)
            .bind(ended_ms - plan_started_ms)
            .execute(&mut *transaction)
            .await?;
        }
        let ids = selected.iter().map(|job| job.id).collect::<Vec<_>>();
        let events = selected
            .iter()
            .map(|job| job.event_id.as_str())
            .collect::<Vec<_>>();
        let locked_rows = sqlx::query(
            "SELECT j.id,j.event_id,j.job_kind,m.object_key,m.object_generation,m.mime_type,m.codec, \
                    m.byte_length,m.sample_rate,m.channels,m.width,m.height,m.sha256, \
                    floor(extract(epoch FROM e.started_at)*1000)::bigint AS started_at_ms, \
                    floor(extract(epoch FROM e.ended_at)*1000)::bigint AS ended_at_ms, \
                    e.stream_kind,e.capture_session_id,e.stream_id,e.sequence, \
                    e.context_json::text AS context_json,e.audio_role,e.audio_route,e.route_epoch \
               FROM media_processing_jobs j \
               JOIN capture_events e ON e.account_id=j.account_id AND e.event_id=j.event_id \
               JOIN media_objects m ON m.account_id=j.account_id AND m.event_id=j.event_id \
              WHERE j.account_id=$1 AND j.id=ANY($2::bigint[]) AND (j.state='pending' OR \
                    (j.state='retry_wait' AND j.updated_at<=clock_timestamp()) OR \
                    (j.state='processing' AND j.lease_until<=clock_timestamp())) \
                AND NOT EXISTS(SELECT 1 FROM episode_deletions deletion \
                     WHERE deletion.account_id=e.account_id AND deletion.state='pending' \
                       AND (deletion.orphan_event_ids ? e.event_id OR deletion.orphan_event_ids ? \
                            coalesce(e.canonical_event_id,e.event_id))) \
              ORDER BY array_position($2::bigint[],j.id) FOR UPDATE OF j",
        )
        .bind(account_id)
        .bind(&ids)
        .fetch_all(&mut *transaction)
        .await?;
        let locked_jobs = locked_rows
            .iter()
            .map(job_from_row)
            .collect::<Result<Vec<_>>>()?;
        if locked_jobs.len() != selected.len()
            || locked_jobs.iter().zip(&selected).any(|(locked, expected)| {
                locked.id != expected.id
                    || locked.event_id != expected.event_id
                    || locked.sha256 != expected.sha256
            })
        {
            return Err(EnclaveError::Conflict(
                "media work candidates changed before exact claim locking".into(),
            ));
        }

        let member_rows = sqlx::query(
            "SELECT ordinal,event_id,job_id FROM media_work_members \
              WHERE account_id=$1 AND work_unit_id=$2 ORDER BY ordinal",
        )
        .bind(account_id)
        .bind(&work_unit_id)
        .fetch_all(&mut *transaction)
        .await?;
        if member_rows.len() != selected.len()
            || member_rows
                .iter()
                .zip(&selected)
                .enumerate()
                .any(|(ordinal, (row, expected))| {
                    row.get::<i64, _>("ordinal") != ordinal as i64
                        || row.get::<i64, _>("job_id") != expected.id
                        || row.get::<String, _>("event_id") != expected.event_id
                })
        {
            return Err(EnclaveError::Conflict(
                "media work membership is not exact".into(),
            ));
        }

        if lost_admission {
            let completed_at = database_now_iso(&mut transaction).await?;
            let mut journal = provider_journal(&work_usage)?;
            let last = journal.attempts.last_mut().ok_or_else(|| {
                EnclaveError::Store("lost media admission has no journal entry".into())
            })?;
            let lost_attempt = validate_provider_attempt(account_id, &work_unit_id, last)?;
            let (usage_outcome, _) = require_exact_vertex_usage_attempt(
                &mut transaction,
                account_id,
                class,
                &lost_attempt,
            )
            .await?;
            if usage_outcome == "started" {
                let changed_usage = sqlx::query(
                    "UPDATE vertex_usage_events SET outcome='ambiguous',updated_at=clock_timestamp() \
                      WHERE account_id=$1 AND event_id=$2 AND outcome='started'",
                )
                .bind(account_id)
                .bind(&lost_attempt.event_id)
                .execute(&mut *transaction)
                .await?
                .rows_affected();
                if changed_usage != 1 {
                    return Err(EnclaveError::Conflict(
                        "lost media admission usage terminalization was superseded".into(),
                    ));
                }
                refresh_coverage(&mut transaction, account_id).await?;
            } else if !matches!(
                usage_outcome.as_str(),
                "ambiguous" | "metered" | "usage_missing"
            ) {
                return Err(EnclaveError::Conflict(
                    "lost media admission has a non-ambiguous usage outcome".into(),
                ));
            }
            last.state = "ambiguous".into();
            last.completed_at = Some(completed_at);
            last.response_b64 = None;
            let usage_json = persist_provider_journal(&mut work_usage, &journal)?;
            let changed_jobs = sqlx::query(
                "UPDATE media_processing_jobs SET state='failed_terminal', \
                        error_code='vertex_ambiguous',lease_owner=NULL,lease_token=NULL, \
                        lease_until=NULL,updated_at=clock_timestamp() \
                  WHERE account_id=$1 AND id=ANY($2::bigint[]) AND (state='pending' OR \
                        state='retry_wait' OR state='processing')",
            )
            .bind(account_id)
            .bind(&ids)
            .execute(&mut *transaction)
            .await?
            .rows_affected();
            if changed_jobs != ids.len() as u64 {
                return Err(EnclaveError::Conflict(
                    "lost media admission terminalization changed unexpected jobs".into(),
                ));
            }
            sqlx::query(
                "UPDATE media_objects SET processing_state='failed' \
                  WHERE account_id=$1 AND event_id=ANY($2::text[])",
            )
            .bind(account_id)
            .bind(&events)
            .execute(&mut *transaction)
            .await?;
            let changed_work = sqlx::query(
                "UPDATE media_work_units SET state='failed_terminal',claim_token=NULL, \
                        claim_until=NULL,error_code='vertex_ambiguous',usage_json=$3::jsonb, \
                        updated_at=clock_timestamp() WHERE account_id=$1 AND id=$2",
            )
            .bind(account_id)
            .bind(&work_unit_id)
            .bind(&usage_json)
            .execute(&mut *transaction)
            .await?
            .rows_affected();
            if changed_work != 1 {
                return Err(EnclaveError::Conflict(
                    "lost media admission work terminalization failed".into(),
                ));
            }
            transaction.commit().await?;
            return Ok(None);
        }

        let job_usage = serde_json::to_string(&planned_usage)?;
        let changed_jobs = sqlx::query(
            "UPDATE media_processing_jobs SET state='processing',attempt_count=attempt_count+1, \
                    lease_owner=$3,lease_token=$3, \
                    lease_until=clock_timestamp()+make_interval(secs=>$4), \
                    error_code=NULL,usage_json=$5::jsonb,updated_at=clock_timestamp() \
              WHERE account_id=$1 AND id=ANY($2::bigint[]) AND (state='pending' OR \
                    state='retry_wait' OR (state='processing' AND lease_until<=clock_timestamp()))",
        )
        .bind(account_id)
        .bind(&ids)
        .bind(&claim_token)
        .bind(lease_seconds as f64)
        .bind(&job_usage)
        .execute(&mut *transaction)
        .await?
        .rows_affected();
        if changed_jobs != selected.len() as u64 {
            return Err(EnclaveError::Conflict(
                "media work claim changed an unexpected number of jobs".into(),
            ));
        }
        let claim_until_ms = sqlx::query_scalar::<_, i64>(
            "UPDATE media_work_units SET state='processing',error_code=NULL, \
                    attempt_count=attempt_count+1,claim_token=$3, \
                    claim_until=clock_timestamp()+make_interval(secs=>$4), \
                    usage_json=$5::jsonb,updated_at=clock_timestamp() \
              WHERE account_id=$1 AND id=$2 AND state!='succeeded' \
              RETURNING floor(extract(epoch FROM claim_until)*1000)::bigint",
        )
        .bind(account_id)
        .bind(&work_unit_id)
        .bind(&claim_token)
        .bind(lease_seconds as f64)
        .bind(&work_usage_json)
        .fetch_optional(&mut *transaction)
        .await?
        .ok_or_else(|| EnclaveError::Conflict("media work claim was superseded".into()))?;
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
            claim_until: isotime::format_epoch_millis(claim_until_ms),
            jobs: selected,
            provider_attempt_number,
            staged_response,
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

    async fn authorize_provider_attempt(
        &self,
        claim: &MediaProcessingClaim,
        reserved_output_tokens: i64,
        attempt: &MediaProviderAttempt,
    ) -> Result<()> {
        if reserved_output_tokens < 0
            || attempt.number != claim.provider_attempt_number
            || attempt.number <= 0
            || attempt.number > MAX_MEDIA_PROVIDER_ATTEMPTS
            || attempt.identity_sha256
                != media_provider_attempt_identity(
                    &claim.account_id,
                    &claim.work_unit_id,
                    attempt.number,
                    &attempt.request_sha256,
                )
            || attempt.event_id != vertex_attempt_event_id(&attempt.identity_sha256)
        {
            return Err(EnclaveError::InvalidRequest(
                "media provider attempt authorization is invalid".into(),
            ));
        }
        let mut transaction = self.pool.begin().await?;
        lock_activation_contract_key_share_if_installed(&mut transaction).await?;
        advisory_transaction_lock(&mut transaction, "memory-reconciliation", &claim.account_id)
            .await?;
        let mut locked = lock_claim_for_update(&mut transaction, claim, true).await?;
        if locked.state == "succeeded" {
            return Err(EnclaveError::Conflict(
                "succeeded media work cannot authorize provider egress".into(),
            ));
        }
        ensure_claim_sources_not_pending_deletion(&mut transaction, claim).await?;

        let (usage_outcome, _) = require_exact_vertex_usage_attempt(
            &mut transaction,
            &claim.account_id,
            claim.class,
            attempt,
        )
        .await?;
        if usage_outcome != "started" {
            return Err(EnclaveError::Conflict(
                "media provider usage intent is not send-authorized".into(),
            ));
        }

        let mut journal = provider_journal(&locked.usage)?;
        if journal.attempts.len() as i64 != attempt.number - 1
            || (attempt.number > 1
                && journal.attempts.last().map(|entry| entry.state.as_str())
                    != Some("confirmed_not_billed"))
        {
            return Err(EnclaveError::Conflict(
                "media provider attempt was already admitted or is out of order".into(),
            ));
        }
        journal.attempts.push(ProviderAttemptJournalEntry {
            number: attempt.number,
            identity_sha256: digest_hex(&attempt.identity_sha256),
            request_sha256: digest_hex(&attempt.request_sha256),
            event_id: attempt.event_id.clone(),
            requested_model: attempt.requested_model.clone(),
            location: attempt.location.clone(),
            state: "admitted".into(),
            admitted_at: Some(database_now_iso(&mut transaction).await?),
            completed_at: None,
            http_status: None,
            response_sha256: None,
            response_b64: None,
            latency_ms: None,
        });
        let reservation = usage_for_reservation(claim, reserved_output_tokens);
        {
            let object = usage_object_mut(&mut locked.usage)?;
            for (key, value) in reservation
                .as_object()
                .expect("reservation usage is an object")
            {
                object.insert(key.clone(), value.clone());
            }
        }
        let work_usage = persist_provider_journal(&mut locked.usage, &journal)?;
        // Never copy the raw-response journal to per-job rows.
        let job_usage = serde_json::to_string(&reservation)?;

        let ids = claim.jobs.iter().map(|job| job.id).collect::<Vec<_>>();
        let changed_jobs = sqlx::query(
            "UPDATE media_processing_jobs SET usage_json=$4::jsonb, \
                    lease_until=greatest(lease_until, \
                        clock_timestamp()+make_interval(secs=>$5)), \
                    updated_at=clock_timestamp() \
              WHERE account_id=$1 AND id=ANY($2) AND state='processing' \
                AND lease_token=$3 AND lease_until>clock_timestamp()",
        )
        .bind(&claim.account_id)
        .bind(&ids)
        .bind(&claim.claim_token)
        .bind(&job_usage)
        .bind(PROVIDER_EGRESS_LEASE_SECONDS)
        .execute(&mut *transaction)
        .await?
        .rows_affected();
        if changed_jobs != ids.len() as u64 {
            return Err(EnclaveError::Conflict(
                "media job reservation was superseded".into(),
            ));
        }
        let changed = sqlx::query(
            "UPDATE media_work_units SET reservation_retained=true,reserved_output_tokens=$4, \
                    usage_json=$5::jsonb,claim_until=greatest(claim_until, \
                        clock_timestamp()+make_interval(secs=>$6)), \
                    updated_at=clock_timestamp() \
              WHERE account_id=$1 AND id=$2 AND state='processing' \
                AND claim_token=$3 AND claim_until>clock_timestamp()",
        )
        .bind(&claim.account_id)
        .bind(&claim.work_unit_id)
        .bind(&claim.claim_token)
        .bind(reserved_output_tokens)
        .bind(&work_usage)
        .bind(PROVIDER_EGRESS_LEASE_SECONDS)
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

    async fn stage_provider_response(
        &self,
        claim: &MediaProcessingClaim,
        response: &MediaProviderStagedResponse,
    ) -> Result<()> {
        if response.response_bytes.len() > MAX_MEDIA_PROVIDER_RESPONSE_BYTES
            || <[u8; 32]>::from(Sha256::digest(&response.response_bytes))
                != response.response_sha256
            || response.attempt.number != claim.provider_attempt_number
        {
            return Err(EnclaveError::InvalidRequest(
                "media provider response stage is invalid".into(),
            ));
        }
        let mut transaction = self.pool.begin().await?;
        lock_activation_contract_key_share_if_installed(&mut transaction).await?;
        advisory_transaction_lock(&mut transaction, "memory-reconciliation", &claim.account_id)
            .await?;
        let mut locked = lock_claim_for_update(&mut transaction, claim, true).await?;
        if locked.state == "succeeded" {
            transaction.commit().await?;
            return Ok(());
        }
        ensure_claim_sources_not_pending_deletion(&mut transaction, claim).await?;
        let mut journal = provider_journal(&locked.usage)?;
        let entry = journal.attempts.last_mut().ok_or_else(|| {
            EnclaveError::Conflict("media provider attempt was not admitted".into())
        })?;
        let persisted = validate_provider_attempt(&claim.account_id, &claim.work_unit_id, entry)?;
        if persisted != response.attempt {
            return Err(EnclaveError::Conflict(
                "media provider response does not match its admitted attempt".into(),
            ));
        }
        if entry.state == "response_staged" || entry.state == "usage_settled" {
            let existing =
                staged_response_from_entry(&claim.account_id, &claim.work_unit_id, entry)?;
            if existing != *response {
                return Err(EnclaveError::Conflict(
                    "media provider response was already staged differently".into(),
                ));
            }
            transaction.commit().await?;
            return Ok(());
        }
        if entry.state != "admitted" {
            return Err(EnclaveError::Conflict(
                "media provider attempt is not stageable".into(),
            ));
        }
        let (usage_outcome, _) = require_exact_vertex_usage_attempt(
            &mut transaction,
            &claim.account_id,
            claim.class,
            &response.attempt,
        )
        .await?;
        if usage_outcome != "started" {
            return Err(EnclaveError::Conflict(
                "media provider response usage intent is not stageable".into(),
            ));
        }
        entry.state = "response_staged".into();
        entry.http_status = Some(response.http_status);
        entry.response_sha256 = Some(digest_hex(&response.response_sha256));
        entry.response_b64 = Some(B64.encode(&response.response_bytes));
        entry.latency_ms = Some(response.latency_ms);
        let usage = persist_provider_journal(&mut locked.usage, &journal)?;
        let changed = sqlx::query(
            "UPDATE media_work_units SET usage_json=$4::jsonb,updated_at=clock_timestamp() \
              WHERE account_id=$1 AND id=$2 AND claim_token=$3 AND state='processing' \
                AND claim_until>clock_timestamp()",
        )
        .bind(&claim.account_id)
        .bind(&claim.work_unit_id)
        .bind(&claim.claim_token)
        .bind(&usage)
        .execute(&mut *transaction)
        .await?
        .rows_affected();
        if changed != 1 {
            return Err(EnclaveError::Conflict(
                "media provider response stage lost its claim".into(),
            ));
        }
        transaction.commit().await?;
        Ok(())
    }

    async fn settle_usage(&self, command: MediaUsageSettlement) -> Result<()> {
        let mut transaction = self.pool.begin().await?;
        lock_activation_contract_key_share_if_installed(&mut transaction).await?;
        advisory_transaction_lock(
            &mut transaction,
            "memory-reconciliation",
            &command.claim.account_id,
        )
        .await?;
        let mut locked = lock_claim_for_update(&mut transaction, &command.claim, true).await?;
        if locked.state == "succeeded" {
            transaction.commit().await?;
            return Ok(());
        }
        let mut journal = provider_journal(&locked.usage)?;
        let entry = journal.attempts.last_mut().ok_or_else(|| {
            EnclaveError::Conflict("media provider response is not staged".into())
        })?;
        if validate_provider_attempt(
            &command.claim.account_id,
            &command.claim.work_unit_id,
            entry,
        )? != command.provider_attempt
            || !matches!(entry.state.as_str(), "response_staged" | "usage_settled")
        {
            return Err(EnclaveError::Conflict(
                "media usage settlement does not match its staged response".into(),
            ));
        }
        // This also re-hashes the exact staged bytes before any projection can
        // consume them.
        staged_response_from_entry(
            &command.claim.account_id,
            &command.claim.work_unit_id,
            entry,
        )?;
        let (usage_outcome, http_status) = require_exact_vertex_usage_attempt(
            &mut transaction,
            &command.claim.account_id,
            command.claim.class,
            &command.provider_attempt,
        )
        .await?;
        if !matches!(usage_outcome.as_str(), "metered" | "usage_missing")
            || http_status != Some(200)
        {
            return Err(EnclaveError::Conflict(
                "media provider usage is not durably terminal".into(),
            ));
        }
        entry.state = "usage_settled".into();
        let content_free_usage = serde_json::to_string(&command.usage)?;
        {
            let object = usage_object_mut(&mut locked.usage)?;
            let supplied = command.usage.as_object().ok_or_else(|| {
                EnclaveError::InvalidRequest("media usage settlement is not an object".into())
            })?;
            if supplied.contains_key("provider_attempts")
                || supplied.contains_key("provider_attempt_journal_version")
            {
                return Err(EnclaveError::InvalidRequest(
                    "media usage settlement cannot replace its provider journal".into(),
                ));
            }
            for (key, value) in supplied {
                object.insert(key.clone(), value.clone());
            }
        }
        let work_usage = persist_provider_journal(&mut locked.usage, &journal)?;
        let ids = command
            .claim
            .jobs
            .iter()
            .map(|job| job.id)
            .collect::<Vec<_>>();
        let changed_jobs = sqlx::query(
            "UPDATE media_processing_jobs SET usage_json=$4::jsonb,updated_at=clock_timestamp() \
             WHERE account_id=$1 AND id=ANY($2::bigint[]) AND state='processing' \
               AND lease_token=$3 AND lease_until>clock_timestamp()",
        )
        .bind(&command.claim.account_id)
        .bind(&ids)
        .bind(&command.claim.claim_token)
        .bind(&content_free_usage)
        .execute(&mut *transaction)
        .await?
        .rows_affected();
        if changed_jobs != ids.len() as u64 {
            return Err(EnclaveError::Conflict(
                "media usage settlement changed unexpected jobs".into(),
            ));
        }
        let changed_work = sqlx::query(
            "UPDATE media_work_units SET usage_json=$4::jsonb,updated_at=clock_timestamp() \
             WHERE account_id=$1 AND id=$2 AND state='processing' AND claim_token=$3 \
               AND claim_until>clock_timestamp()",
        )
        .bind(&command.claim.account_id)
        .bind(&command.claim.work_unit_id)
        .bind(&command.claim.claim_token)
        .bind(&work_usage)
        .execute(&mut *transaction)
        .await?
        .rows_affected();
        if changed_work != 1 {
            return Err(EnclaveError::Conflict(
                "media usage settlement lost its work claim".into(),
            ));
        }
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
        lock_activation_contract_key_share_if_installed(&mut transaction).await?;
        advisory_transaction_lock(
            &mut transaction,
            "memory-reconciliation",
            &command.claim.account_id,
        )
        .await?;
        let mut locked = lock_claim_for_update(&mut transaction, &command.claim, true).await?;
        if locked.state == "succeeded" {
            transaction.commit().await?;
            return Ok(());
        }
        ensure_claim_sources_not_pending_deletion(&mut transaction, &command.claim).await?;
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
        let owner_source_audio = is_owner_source_audio(
            command.claim.jobs[0].audio_role.as_deref(),
            distinct_speakers,
        );
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
                let initial = if owner_source_audio {
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
            let accepted_name = (!owner_source_audio
                && is_supported_self_identification(turn, &command.turns))
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
            let mut speaker_label = if owner_source_audio {
                "Me".to_owned()
            } else {
                inherited_person
                    .as_ref()
                    .map(|(_, display)| display.clone())
                    .unwrap_or_else(|| "Unidentified voice".to_owned())
            };
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
        mark_capture_formation_dirty(
            &mut transaction,
            account_id,
            &command
                .claim
                .jobs
                .iter()
                .map(|job| job.capture_session_id.clone())
                .collect::<Vec<_>>(),
        )
        .await?;
        mark_claim_succeeded(
            &mut transaction,
            &command.claim,
            &command.provider_attempt,
            &mut locked.usage,
        )
        .await?;
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
        lock_activation_contract_key_share_if_installed(&mut transaction).await?;
        advisory_transaction_lock(
            &mut transaction,
            "memory-reconciliation",
            &command.claim.account_id,
        )
        .await?;
        let mut locked = lock_claim_for_update(&mut transaction, &command.claim, true).await?;
        if locked.state == "succeeded" {
            transaction.commit().await?;
            return Ok(());
        }
        ensure_claim_sources_not_pending_deletion(&mut transaction, &command.claim).await?;
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
        mark_capture_formation_dirty(
            &mut transaction,
            account_id,
            &command
                .claim
                .jobs
                .iter()
                .map(|job| job.capture_session_id.clone())
                .collect::<Vec<_>>(),
        )
        .await?;
        mark_claim_succeeded(
            &mut transaction,
            &command.claim,
            &command.provider_attempt,
            &mut locked.usage,
        )
        .await?;
        transaction.commit().await?;
        Ok(())
    }

    async fn settle_failure(
        &self,
        claim: &MediaProcessingClaim,
        provider_attempt: Option<&MediaProviderAttempt>,
        disposition: MediaFailureDisposition,
        error_code: &str,
        failed_at: &str,
        policy: MediaFailurePolicy,
    ) -> Result<()> {
        let MediaFailurePolicy {
            max_attempts,
            budget_retry_seconds,
            resurrection_window_seconds,
        } = policy;
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
        let _failed_at_ms = parse_time(failed_at, "media failure time")?;
        if (provider_attempt.is_none()
            && disposition != MediaFailureDisposition::RetryableBeforeEgress)
            || (provider_attempt.is_some()
                && disposition == MediaFailureDisposition::RetryableBeforeEgress)
        {
            return Err(EnclaveError::InvalidRequest(
                "media failure provider disposition is inconsistent".into(),
            ));
        }
        let mut transaction = self.pool.begin().await?;
        lock_activation_contract_key_share_if_installed(&mut transaction).await?;
        advisory_transaction_lock(&mut transaction, "memory-reconciliation", &claim.account_id)
            .await?;
        let mut locked = lock_claim_for_update(&mut transaction, claim, true).await?;
        if locked.state == "succeeded" {
            transaction.commit().await?;
            return Ok(());
        }
        let ids = claim.jobs.iter().map(|job| job.id).collect::<Vec<_>>();
        let events = claim
            .jobs
            .iter()
            .map(|job| job.event_id.as_str())
            .collect::<Vec<_>>();
        let attempt_counts = sqlx::query_scalar::<_, i64>(
            "SELECT attempt_count FROM media_processing_jobs \
              WHERE account_id=$1 AND id=ANY($2::bigint[]) ORDER BY id",
        )
        .bind(&claim.account_id)
        .bind(&ids)
        .fetch_all(&mut *transaction)
        .await?;
        if attempt_counts.len() != ids.len() {
            return Err(EnclaveError::Conflict(
                "media failure settlement membership changed".into(),
            ));
        }

        let mut journal = provider_journal(&locked.usage)?;
        if let Some(attempt) = provider_attempt {
            if attempt.number != claim.provider_attempt_number
                || attempt.identity_sha256
                    != media_provider_attempt_identity(
                        &claim.account_id,
                        &claim.work_unit_id,
                        attempt.number,
                        &attempt.request_sha256,
                    )
                || attempt.event_id != vertex_attempt_event_id(&attempt.identity_sha256)
            {
                return Err(EnclaveError::InvalidRequest(
                    "media failure attempt identity is invalid".into(),
                ));
            }
            let (usage_outcome, usage_http_status) = require_exact_vertex_usage_attempt(
                &mut transaction,
                &claim.account_id,
                claim.class,
                attempt,
            )
            .await?;
            let expected_usage = match disposition {
                MediaFailureDisposition::RetryableNotBilled => usage_outcome == "not_billed",
                MediaFailureDisposition::AmbiguousTerminal => matches!(
                    usage_outcome.as_str(),
                    "ambiguous" | "metered" | "usage_missing"
                ),
                MediaFailureDisposition::ConfirmedInvalid => {
                    matches!(
                        usage_outcome.as_str(),
                        "metered" | "usage_missing" | "ambiguous"
                    )
                }
                MediaFailureDisposition::RetryableBeforeEgress => false,
            };
            if !expected_usage {
                return Err(EnclaveError::Conflict(
                    "media failure does not match terminal provider usage".into(),
                ));
            }
            let completed_at = database_now_iso(&mut transaction).await?;
            let may_append_pre_authorize = matches!(
                disposition,
                MediaFailureDisposition::RetryableNotBilled
                    | MediaFailureDisposition::AmbiguousTerminal
            );
            let entry = if journal.attempts.len() as i64 == attempt.number - 1
                && may_append_pre_authorize
            {
                journal.attempts.push(ProviderAttemptJournalEntry {
                    number: attempt.number,
                    identity_sha256: digest_hex(&attempt.identity_sha256),
                    request_sha256: digest_hex(&attempt.request_sha256),
                    event_id: attempt.event_id.clone(),
                    requested_model: attempt.requested_model.clone(),
                    location: attempt.location.clone(),
                    state: match disposition {
                        MediaFailureDisposition::RetryableNotBilled => "confirmed_not_billed",
                        MediaFailureDisposition::AmbiguousTerminal => "ambiguous",
                        _ => unreachable!("pre-authorize append was bounded above"),
                    }
                    .into(),
                    admitted_at: None,
                    completed_at: Some(completed_at.clone()),
                    http_status: usage_http_status
                        .map(u16::try_from)
                        .transpose()
                        .map_err(|_| EnclaveError::Store("invalid Vertex status".into()))?,
                    response_sha256: None,
                    response_b64: None,
                    latency_ms: None,
                });
                journal.attempts.last_mut().expect("just pushed")
            } else {
                journal.attempts.last_mut().ok_or_else(|| {
                    EnclaveError::Conflict("media provider attempt journal is absent".into())
                })?
            };
            if validate_provider_attempt(&claim.account_id, &claim.work_unit_id, entry)? != *attempt
            {
                return Err(EnclaveError::Conflict(
                    "media failure does not match its journal attempt".into(),
                ));
            }
            entry.state = match disposition {
                MediaFailureDisposition::RetryableNotBilled => "confirmed_not_billed",
                MediaFailureDisposition::AmbiguousTerminal => "ambiguous",
                MediaFailureDisposition::ConfirmedInvalid => "confirmed_invalid",
                MediaFailureDisposition::RetryableBeforeEgress => unreachable!(),
            }
            .into();
            entry.completed_at.get_or_insert(completed_at);
            entry.response_b64 = None;
        }

        let force_terminal = matches!(
            disposition,
            MediaFailureDisposition::AmbiguousTerminal | MediaFailureDisposition::ConfirmedInvalid
        );
        let budget_window_live = if error_code == "vertex_daily_budget" {
            sqlx::query_scalar::<_, bool>(
                "SELECT bool_and(event.started_at >= \
                        clock_timestamp()-make_interval(secs=>$3)) \
                   FROM media_processing_jobs job JOIN capture_events event \
                     ON event.account_id=job.account_id AND event.event_id=job.event_id \
                  WHERE job.account_id=$1 AND job.id=ANY($2::bigint[])",
            )
            .bind(&claim.account_id)
            .bind(&ids)
            .bind(resurrection_window_seconds as f64)
            .fetch_one(&mut *transaction)
            .await?
        } else {
            true
        };
        let terminal = force_terminal
            || (error_code == "vertex_daily_budget" && !budget_window_live)
            || (error_code != "vertex_daily_budget"
                && disposition != MediaFailureDisposition::RetryableNotBilled
                && attempt_counts
                    .iter()
                    .any(|attempts| *attempts >= max_attempts));
        let delay_seconds = if terminal {
            0
        } else if error_code == "vertex_daily_budget" {
            budget_retry_seconds
        } else {
            let attempts = attempt_counts.iter().copied().max().unwrap_or(1);
            let exponent = u32::try_from(attempts.min(6)).unwrap_or(6);
            30_i64.saturating_mul(1_i64 << exponent)
        };
        let work_usage = persist_provider_journal(&mut locked.usage, &journal)?;
        let state = if terminal {
            "failed_terminal"
        } else {
            "retry_wait"
        };
        let media_state = if terminal { "failed" } else { "retry_wait" };
        let decrement_attempt = error_code == "vertex_daily_budget"
            || disposition == MediaFailureDisposition::RetryableNotBilled;
        let changed_jobs = sqlx::query(
            "UPDATE media_processing_jobs SET state=$4, \
                    attempt_count=CASE WHEN $5 THEN greatest(attempt_count-1,0) \
                                       ELSE attempt_count END, \
                    lease_owner=NULL,lease_token=NULL,lease_until=NULL,error_code=$6, \
                    updated_at=CASE WHEN $4='failed_terminal' THEN clock_timestamp() \
                      ELSE clock_timestamp()+make_interval(secs=>$7) END \
              WHERE account_id=$1 AND id=ANY($2::bigint[]) AND lease_token=$3",
        )
        .bind(&claim.account_id)
        .bind(&ids)
        .bind(&claim.claim_token)
        .bind(state)
        .bind(decrement_attempt)
        .bind(error_code)
        .bind(delay_seconds as f64)
        .execute(&mut *transaction)
        .await?
        .rows_affected();
        if changed_jobs != ids.len() as u64 {
            return Err(EnclaveError::Conflict(
                "media failure settlement changed unexpected jobs".into(),
            ));
        }
        let changed_objects = sqlx::query(
            "UPDATE media_objects SET processing_state=$3 \
              WHERE account_id=$1 AND event_id=ANY($2::text[])",
        )
        .bind(&claim.account_id)
        .bind(&events)
        .bind(media_state)
        .execute(&mut *transaction)
        .await?
        .rows_affected();
        if changed_objects != events.len() as u64 {
            return Err(EnclaveError::Conflict(
                "media failure settlement changed unexpected objects".into(),
            ));
        }
        let changed_work = sqlx::query(
            "UPDATE media_work_units SET state=$4,claim_token=NULL,claim_until=NULL, \
                    error_code=$5,usage_json=$6::jsonb, \
                    updated_at=CASE WHEN $4='failed_terminal' THEN clock_timestamp() \
                      ELSE clock_timestamp()+make_interval(secs=>$7) END \
              WHERE account_id=$1 AND id=$2 AND claim_token=$3",
        )
        .bind(&claim.account_id)
        .bind(&claim.work_unit_id)
        .bind(&claim.claim_token)
        .bind(state)
        .bind(error_code)
        .bind(&work_usage)
        .bind(delay_seconds as f64)
        .execute(&mut *transaction)
        .await?
        .rows_affected();
        if changed_work != 1 {
            return Err(EnclaveError::Conflict(
                "media failure settlement lost its work claim".into(),
            ));
        }
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
        let _now_ms = parse_time(now, "media resurrection time")?;
        let mut transaction = self.pool.begin().await?;
        lock_activation_contract_key_share_if_installed(&mut transaction).await?;
        advisory_transaction_lock(&mut transaction, "memory-reconciliation", account_id).await?;
        let rows = sqlx::query(
            "SELECT j.id,j.event_id FROM media_processing_jobs j \
             JOIN capture_events e ON e.account_id=j.account_id AND e.event_id=j.event_id \
             WHERE j.account_id=$1 AND j.processor_version=$2 AND j.state='failed_terminal' \
               AND NOT (coalesce(j.error_code,'')=ANY($3::text[])) \
               AND j.attempt_count<$4 \
               AND j.updated_at<=clock_timestamp()-make_interval(secs=>$5) \
               AND e.started_at>=clock_timestamp()-make_interval(secs=>$6) \
             ORDER BY j.id LIMIT $7 FOR UPDATE OF j SKIP LOCKED",
        )
        .bind(account_id)
        .bind(PROCESSOR_VERSION)
        .bind(NON_RESURRECTABLE_MEDIA_ERROR_CODES.as_slice())
        .bind(total_attempt_cap)
        .bind(delay_seconds as f64)
        .bind(window_seconds as f64)
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
                        lease_owner=NULL,lease_token=NULL,lease_until=NULL, \
                        updated_at=clock_timestamp() \
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
                    AND j.processor_version=$4 \
                    AND NOT (coalesce(j.error_code,'')=ANY($5::text[])) \
                    AND j.attempt_count<$6 \
                    AND e.started_at>=to_timestamp($7::double precision/1000.0))))",
        )
        .bind(account_id)
        .bind(to_ms)
        .bind(from_ms)
        .bind(PROCESSOR_VERSION)
        .bind(NON_RESURRECTABLE_MEDIA_ERROR_CODES.as_slice())
        .bind(memory_hold_attempts)
        .bind(window_ms)
        .fetch_one(&self.pool)
        .await?)
    }
}

#[cfg(test)]
async fn test_insert_screen_work_fixture(
    persistence: &PostgresPersistence,
    account_id: &str,
    suffix: &str,
) -> Result<String> {
    let session_id = format!("media-session-{suffix}");
    let stream_id = format!("media-stream-{suffix}");
    let event_id = format!("media-event-{suffix}");
    let asset_id = format!("media-asset-{suffix}");
    sqlx::query(
        "INSERT INTO accounts(id,email,primary_provider,primary_subject) \
         VALUES($1,$2,'google',$3)",
    )
    .bind(account_id)
    .bind(format!("{suffix}@example.com"))
    .bind(format!("subject-{suffix}"))
    .execute(persistence.pool())
    .await?;
    sqlx::query(
        "INSERT INTO capture_sessions( \
             account_id,id,device_id,install_id,started_at,last_event_at,ended_at,schema_version) \
         VALUES($1,$2,$3,$4,clock_timestamp()-interval '2 minutes', \
                clock_timestamp()-interval '1 minute',clock_timestamp(),2)",
    )
    .bind(account_id)
    .bind(&session_id)
    .bind(format!("device-{suffix}"))
    .bind(format!("install-{suffix}"))
    .execute(persistence.pool())
    .await?;
    sqlx::query(
        "INSERT INTO capture_streams( \
             account_id,id,capture_session_id,device_id,stream_kind,committed_through_sequence) \
         VALUES($1,$2,$3,$4,'mac_screen',0)",
    )
    .bind(account_id)
    .bind(&stream_id)
    .bind(&session_id)
    .bind(format!("device-{suffix}"))
    .execute(persistence.pool())
    .await?;
    sqlx::query(
        "INSERT INTO capture_events( \
             account_id,event_id,device_id,install_id,capture_session_id,stream_id,stream_kind, \
             sequence,source_wall_at,source_monotonic_ns,started_at,ended_at,timezone_id, \
             utc_offset_minutes,clock_uncertainty_ms,asset_id,manifest_digest,context_json, \
             media_disposition,dedupe_version,received_at) \
         VALUES($1,$2,$3,$4,$5,$6,'mac_screen',0,clock_timestamp()-interval '2 minutes','1', \
                clock_timestamp()-interval '2 minutes',clock_timestamp()-interval '119 seconds', \
                'UTC',0,0,$7,repeat('a',64),'{}','canonical',1,clock_timestamp())",
    )
    .bind(account_id)
    .bind(&event_id)
    .bind(format!("device-{suffix}"))
    .bind(format!("install-{suffix}"))
    .bind(&session_id)
    .bind(&stream_id)
    .bind(&asset_id)
    .execute(persistence.pool())
    .await?;
    sqlx::query(
        "INSERT INTO media_objects( \
             account_id,asset_id,event_id,object_key,object_generation,object_backend,mime_type, \
             codec,byte_length,sha256,width,height,processing_state) \
         VALUES($1,$2,$3,$4,1,'current','image/png','png',1024,repeat('e',64),100,100,'queued')",
    )
    .bind(account_id)
    .bind(&asset_id)
    .bind(&event_id)
    .bind(format!("media/{suffix}"))
    .execute(persistence.pool())
    .await?;
    sqlx::query(
        "INSERT INTO media_processing_jobs( \
             account_id,event_id,job_kind,input_revision,processor_version,state) \
         VALUES($1,$2,'gemini_screen',$3,1,'pending')",
    )
    .bind(account_id)
    .bind(&event_id)
    .bind(format!("input-{suffix}"))
    .execute(persistence.pool())
    .await?;
    Ok(event_id)
}

#[cfg(test)]
async fn test_insert_audio_job_fixture(
    persistence: &PostgresPersistence,
    account_id: &str,
    event_id: &str,
    stream_id: &str,
    stream_kind: &str,
    sequence: i64,
    start_offset_seconds: i64,
) -> Result<()> {
    let asset_id = format!("asset-{event_id}");
    let (audio_role, audio_route) = match stream_kind {
        "mic" => ("ambient", "builtin_mic"),
        "system_audio" => ("remote_received", "system_output"),
        _ => {
            return Err(EnclaveError::Config(
                "audio fixture stream kind is invalid".into(),
            ))
        }
    };
    sqlx::query(
        "INSERT INTO capture_events( \
             account_id,event_id,device_id,install_id,capture_session_id,stream_id,stream_kind, \
             sequence,source_wall_at,source_monotonic_ns,started_at,ended_at,timezone_id, \
             utc_offset_minutes,clock_uncertainty_ms,asset_id,manifest_digest,context_json, \
             audio_role,audio_route,route_epoch,media_disposition,dedupe_version,received_at) \
         VALUES($1,$2,'planner-device','planner-install','planner-session',$3,$4,$5, \
                clock_timestamp()-make_interval(secs=>$6),$5::text, \
                clock_timestamp()-make_interval(secs=>$6), \
                clock_timestamp()-make_interval(secs=>$6-60), \
                'UTC',0,0,$7,repeat('a',64),'{}',$8,$9,0,'canonical',1,clock_timestamp())",
    )
    .bind(account_id)
    .bind(event_id)
    .bind(stream_id)
    .bind(stream_kind)
    .bind(sequence)
    .bind(start_offset_seconds)
    .bind(&asset_id)
    .bind(audio_role)
    .bind(audio_route)
    .execute(persistence.pool())
    .await?;
    sqlx::query(
        "INSERT INTO media_objects( \
             account_id,asset_id,event_id,object_key,object_generation,object_backend,mime_type, \
             codec,byte_length,sha256,sample_rate,channels,processing_state) \
         VALUES($1,$2,$3,'media/'||$3,1,'current','audio/mp4','aac',480000, \
                repeat('b',64),48000,1,'queued')",
    )
    .bind(account_id)
    .bind(&asset_id)
    .bind(event_id)
    .execute(persistence.pool())
    .await?;
    sqlx::query(
        "INSERT INTO media_processing_jobs( \
             account_id,event_id,job_kind,input_revision,processor_version,state) \
         VALUES($1,$2,'gemini_audio','planner-input-'||$2,1,'pending')",
    )
    .bind(account_id)
    .bind(event_id)
    .execute(persistence.pool())
    .await?;
    Ok(())
}

#[cfg(test)]
async fn test_persisted_media_work_upgrade_contract(
    persistence: &PostgresPersistence,
) -> Result<()> {
    const ACCOUNT: &str = "media-planner-upgrade-contract";
    sqlx::query(
        "INSERT INTO accounts(id,email,primary_provider,primary_subject) \
         VALUES($1,'planner-upgrade@example.com','google','planner-upgrade-subject')",
    )
    .bind(ACCOUNT)
    .execute(persistence.pool())
    .await?;
    sqlx::query(
        "INSERT INTO capture_sessions( \
             account_id,id,device_id,install_id,started_at,last_event_at,ended_at,schema_version) \
         VALUES($1,'planner-session','planner-device','planner-install', \
                clock_timestamp()-interval '11 minutes', \
                clock_timestamp()-interval '7 minutes',clock_timestamp(),2)",
    )
    .bind(ACCOUNT)
    .execute(persistence.pool())
    .await?;
    sqlx::query(
        "INSERT INTO capture_streams( \
             account_id,id,capture_session_id,device_id,stream_kind,committed_through_sequence) \
         VALUES($1,'planner-mic','planner-session','planner-device','mic',2), \
               ($1,'planner-system','planner-session','planner-device','system_audio',2)",
    )
    .bind(ACCOUNT)
    .execute(persistence.pool())
    .await?;

    // Freeze the exact one-member identity an older image could have created
    // before any interleaved later work was visible.
    test_insert_audio_job_fixture(
        persistence,
        ACCOUNT,
        "planner-mic-0",
        "planner-mic",
        "mic",
        0,
        600,
    )
    .await?;
    let frozen = persistence
        .claim(
            ACCOUNT,
            MediaProcessingClass::Audio,
            "2099-01-01T00:00:00.000Z",
            300,
            128,
        )
        .await?
        .ok_or_else(|| EnclaveError::Store("one-member media fixture was not claimable".into()))?;
    if frozen.jobs.len() != 1 || frozen.jobs[0].event_id != "planner-mic-0" {
        return Err(EnclaveError::Store(
            "one-member media fixture did not freeze its exact head".into(),
        ));
    }
    persistence
        .settle_failure(
            &frozen,
            None,
            MediaFailureDisposition::RetryableBeforeEgress,
            "vertex_daily_budget",
            "2099-01-01T00:00:00.000Z",
            MediaFailurePolicy {
                max_attempts: 3,
                budget_retry_seconds: 6 * 60 * 60,
                resurrection_window_seconds: 7 * 24 * 60 * 60,
            },
        )
        .await?;
    let retry_remains_delayed = sqlx::query_scalar::<_, bool>(
        "SELECT bool_and(job.updated_at>clock_timestamp()+interval '5 hours') \
           FROM media_processing_jobs job \
           JOIN media_work_members member \
             ON member.account_id=job.account_id AND member.job_id=job.id \
          WHERE job.account_id=$1 AND member.work_unit_id=$2",
    )
    .bind(ACCOUNT)
    .bind(&frozen.work_unit_id)
    .fetch_one(persistence.pool())
    .await?;
    if !retry_remains_delayed {
        return Err(EnclaveError::Store(
            "daily-budget retry did not retain its six-hour timestamp".into(),
        ));
    }

    for (event_id, stream_id, stream_kind, sequence, offset) in [
        ("planner-system-0", "planner-system", "system_audio", 0, 600),
        ("planner-mic-1", "planner-mic", "mic", 1, 540),
        ("planner-system-1", "planner-system", "system_audio", 1, 540),
        ("planner-mic-2", "planner-mic", "mic", 2, 480),
        ("planner-system-2", "planner-system", "system_audio", 2, 480),
    ] {
        test_insert_audio_job_fixture(
            persistence,
            ACCOUNT,
            event_id,
            stream_id,
            stream_kind,
            sequence,
            offset,
        )
        .await?;
    }
    // Raising the baked limit does not rewrite the existing six-hour retry;
    // the fixture makes it due explicitly before exercising reclaim.
    sqlx::query(
        "UPDATE media_processing_jobs SET updated_at=clock_timestamp()-interval '1 second' \
          WHERE account_id=$1 AND id=ANY(SELECT job_id FROM media_work_members \
            WHERE account_id=$1 AND work_unit_id=$2)",
    )
    .bind(ACCOUNT)
    .bind(&frozen.work_unit_id)
    .execute(persistence.pool())
    .await?;
    sqlx::query(
        "UPDATE media_work_units SET updated_at=clock_timestamp()-interval '1 second' \
          WHERE account_id=$1 AND id=$2",
    )
    .bind(ACCOUNT)
    .bind(&frozen.work_unit_id)
    .execute(persistence.pool())
    .await?;

    let reclaimed = persistence
        .claim(
            ACCOUNT,
            MediaProcessingClass::Audio,
            "2000-01-01T00:00:00.000Z",
            300,
            128,
        )
        .await?
        .ok_or_else(|| EnclaveError::Store("persisted media work was not reclaimable".into()))?;
    if reclaimed.work_unit_id != frozen.work_unit_id
        || reclaimed.jobs.len() != 1
        || reclaimed.jobs[0].event_id != "planner-mic-0"
    {
        return Err(EnclaveError::Store(
            "upgrade reclaim expanded an already-persisted media work unit".into(),
        ));
    }

    sqlx::query(
        "UPDATE media_processing_jobs SET state='succeeded',lease_owner=NULL,lease_token=NULL, \
                lease_until=NULL,updated_at=clock_timestamp() \
          WHERE account_id=$1 AND lease_token=$2",
    )
    .bind(ACCOUNT)
    .bind(&reclaimed.claim_token)
    .execute(persistence.pool())
    .await?;
    sqlx::query(
        "UPDATE media_work_units SET state='succeeded',claim_token=NULL,claim_until=NULL, \
                updated_at=clock_timestamp() \
          WHERE account_id=$1 AND id=$2 AND claim_token=$3",
    )
    .bind(ACCOUNT)
    .bind(&reclaimed.work_unit_id)
    .bind(&reclaimed.claim_token)
    .execute(persistence.pool())
    .await?;
    sqlx::query(
        "UPDATE media_objects SET processing_state='ready' \
          WHERE account_id=$1 AND event_id='planner-mic-0'",
    )
    .bind(ACCOUNT)
    .execute(persistence.pool())
    .await?;

    let regrouped = persistence
        .claim(
            ACCOUNT,
            MediaProcessingClass::Audio,
            "2000-01-01T00:00:00.000Z",
            300,
            128,
        )
        .await?
        .ok_or_else(|| EnclaveError::Store("unbound interleaved work was not claimable".into()))?;
    if regrouped.jobs.len() != 3
        || regrouped
            .jobs
            .iter()
            .any(|job| job.stream_id != "planner-system")
    {
        return Err(EnclaveError::Store(
            "new media work did not group one stream across interleaved rows".into(),
        ));
    }
    sqlx::query("DELETE FROM accounts WHERE id=$1")
        .bind(ACCOUNT)
        .execute(persistence.pool())
        .await?;
    Ok(())
}

#[cfg(test)]
async fn test_expire_media_claim(
    persistence: &PostgresPersistence,
    claim: &MediaProcessingClaim,
) -> Result<()> {
    sqlx::query(
        "UPDATE media_processing_jobs SET lease_until=clock_timestamp()-interval '1 second' \
          WHERE account_id=$1 AND lease_token=$2",
    )
    .bind(&claim.account_id)
    .bind(&claim.claim_token)
    .execute(persistence.pool())
    .await?;
    sqlx::query(
        "UPDATE media_work_units SET claim_until=clock_timestamp()-interval '1 second' \
          WHERE account_id=$1 AND claim_token=$2",
    )
    .bind(&claim.account_id)
    .bind(&claim.claim_token)
    .execute(persistence.pool())
    .await?;
    Ok(())
}

#[cfg(test)]
pub(super) async fn test_begin_media_provider_attempt(
    persistence: &PostgresPersistence,
    claim: &MediaProcessingClaim,
) -> Result<MediaProviderAttempt> {
    use crate::{
        cp::vertex::VertexOperation,
        persistence::{ModelUsageRepository as _, VertexInvocationAdmission},
    };

    let request_sha256: [u8; 32] = Sha256::digest(
        format!(
            "test-media-request:{}:{}:{}",
            claim.account_id, claim.work_unit_id, claim.provider_attempt_number
        )
        .as_bytes(),
    )
    .into();
    let identity_sha256 = media_provider_attempt_identity(
        &claim.account_id,
        &claim.work_unit_id,
        claim.provider_attempt_number,
        &request_sha256,
    );
    let operation = match claim.class {
        MediaProcessingClass::Audio => VertexOperation::AudioWindow,
        MediaProcessingClass::Screen => VertexOperation::ScreenStoryboard,
    };
    let invocation = persistence
        .begin_invocation_attempt(
            &claim.account_id,
            operation,
            "gemini-3.5-flash",
            "us-central1",
            &request_sha256,
            &identity_sha256,
        )
        .await?;
    if invocation.admission != VertexInvocationAdmission::Send {
        return Err(EnclaveError::Store(
            "test media provider attempt was not newly send-admitted".into(),
        ));
    }
    Ok(MediaProviderAttempt {
        number: claim.provider_attempt_number,
        identity_sha256,
        request_sha256,
        event_id: invocation.event_id,
        requested_model: "gemini-3.5-flash".into(),
        location: "us-central1".into(),
    })
}

#[cfg(test)]
pub(super) async fn test_stage_media_provider_success(
    persistence: &PostgresPersistence,
    claim: &MediaProcessingClaim,
    reserved_output_tokens: i64,
) -> Result<MediaProviderAttempt> {
    use crate::{
        cp::vertex::VertexMetadata,
        persistence::{MediaProcessingRepository as _, ModelUsageRepository as _},
    };

    let attempt = test_begin_media_provider_attempt(persistence, claim).await?;
    persistence
        .authorize_provider_attempt(claim, reserved_output_tokens, &attempt)
        .await?;
    let response_bytes = br#"{"candidates":[{"content":{"parts":[{"text":"{}"}]}}]}"#.to_vec();
    persistence
        .stage_provider_response(
            claim,
            &MediaProviderStagedResponse {
                attempt: attempt.clone(),
                http_status: 200,
                response_sha256: Sha256::digest(&response_bytes).into(),
                response_bytes,
                latency_ms: 1,
            },
        )
        .await?;
    persistence
        .settle_response(
            &claim.account_id,
            &attempt.event_id,
            &VertexMetadata::default(),
        )
        .await?;
    Ok(attempt)
}

#[cfg(test)]
pub(super) async fn test_real_pg_media_provider_deletion_contract(
    persistence: &PostgresPersistence,
) -> Result<()> {
    test_persisted_media_work_upgrade_contract(persistence).await?;
    use crate::{
        cp::vertex::{VertexMetadata, VertexOperation},
        persistence::{
            EpisodeDeletionRepository as _, EpisodeDeletionStart, MediaProcessingRepository as _,
            ModelUsageRepository as _, VertexInvocationAdmission,
        },
    };

    const ACCOUNT: &str = "activation-media-egress-contract";
    const EPISODE_ID: i64 = 70;
    const CANONICAL_EVENT: &str = "media-egress-canonical";
    const REFERENCE_EVENT: &str = "media-egress-reference";

    sqlx::raw_sql(
        "INSERT INTO accounts(id,email,primary_provider,primary_subject) \
         VALUES('activation-media-egress-contract','media-egress@example.com', \
                'google','activation-media-egress'); \
         INSERT INTO capture_sessions( \
             account_id,id,device_id,install_id,started_at,last_event_at,ended_at,schema_version) \
         VALUES('activation-media-egress-contract','media-egress-session', \
                'media-egress-device','media-egress-install', \
                clock_timestamp()-interval '2 minutes', \
                clock_timestamp()-interval '1 minute',clock_timestamp(),2); \
         INSERT INTO capture_streams( \
             account_id,id,capture_session_id,device_id,stream_kind,committed_through_sequence) \
         VALUES('activation-media-egress-contract','media-egress-stream', \
                'media-egress-session','media-egress-device','mac_screen',1); \
         INSERT INTO capture_events( \
             account_id,event_id,device_id,install_id,capture_session_id,stream_id,stream_kind, \
             sequence,source_wall_at,source_monotonic_ns,started_at,ended_at,timezone_id, \
             utc_offset_minutes,clock_uncertainty_ms,asset_id,manifest_digest,context_json, \
             media_disposition,canonical_event_id,canonical_asset_id,canonical_media_sha256, \
             perceptual_hash,hamming_distance,pixel_change_ratio,context_fingerprint, \
             dedupe_version,received_at) \
         VALUES \
             ('activation-media-egress-contract','media-egress-canonical', \
              'media-egress-device','media-egress-install','media-egress-session', \
              'media-egress-stream','mac_screen',0,clock_timestamp()-interval '2 minutes','1', \
              clock_timestamp()-interval '2 minutes',clock_timestamp()-interval '2 minutes' \
                  + interval '1 second','UTC',0,0,'media-egress-asset',repeat('a',64),'{}', \
              'canonical',NULL,NULL,NULL,NULL,NULL,NULL,NULL,1,clock_timestamp()), \
             ('activation-media-egress-contract','media-egress-reference', \
              'media-egress-device','media-egress-install','media-egress-session', \
              'media-egress-stream','mac_screen',1,clock_timestamp()-interval '1 minute','2', \
              clock_timestamp()-interval '1 minute',clock_timestamp()-interval '1 minute' \
                  + interval '1 second','UTC',0,0,'media-egress-reference-asset',repeat('b',64), \
              '{}','reference','media-egress-canonical','media-egress-asset',repeat('c',64), \
              '0123456789abcdef',1,0.001,repeat('d',64),1,clock_timestamp()); \
         INSERT INTO media_objects( \
             account_id,asset_id,event_id,object_key,object_generation,object_backend,mime_type, \
             codec,byte_length,sha256,width,height,processing_state) \
         VALUES('activation-media-egress-contract','media-egress-asset', \
                'media-egress-canonical','media/egress/canonical',1,'current','image/png','png', \
                1024,repeat('e',64),100,100,'queued'); \
         INSERT INTO media_processing_jobs( \
             account_id,event_id,job_kind,input_revision,processor_version,state) \
         VALUES('activation-media-egress-contract','media-egress-canonical','gemini_screen', \
                'media-egress-input-v1',1,'pending'); \
         INSERT INTO episodes(account_id,id,started_at,ended_at,type,title,summary) \
         VALUES('activation-media-egress-contract',70,clock_timestamp()-interval '2 minutes', \
                clock_timestamp()-interval '1 minute','work','Media egress deletion','fixture'); \
         INSERT INTO screenshots(account_id,id,captured_at,source_key) \
         VALUES('activation-media-egress-contract',71,clock_timestamp()-interval '1 minute', \
                'cloud-v2:media-egress-reference'); \
         INSERT INTO episode_members(account_id,episode_id,record_type,record_id) \
         VALUES('activation-media-egress-contract',70,'screenshot',71);",
    )
    .execute(persistence.pool())
    .await?;

    let database_now = || async {
        let millis = sqlx::query_scalar::<_, i64>(
            "SELECT floor(extract(epoch FROM clock_timestamp())*1000)::bigint",
        )
        .fetch_one(persistence.pool())
        .await?;
        Ok::<String, EnclaveError>(isotime::format_epoch_millis(millis))
    };
    let first = persistence
        .claim(
            ACCOUNT,
            MediaProcessingClass::Screen,
            &database_now().await?,
            300,
            8,
        )
        .await?
        .ok_or_else(|| EnclaveError::Store("media egress fixture was not claimable".into()))?;
    if first.jobs.len() != 1 || first.jobs[0].event_id != CANONICAL_EVENT {
        return Err(EnclaveError::Store(
            "media egress fixture claimed an unexpected canonical family member".into(),
        ));
    }

    // Deterministically supersede an expired worker before it reaches its
    // final authorization boundary.
    sqlx::query(
        "UPDATE media_processing_jobs SET lease_until=clock_timestamp()-interval '1 second' \
          WHERE account_id=$1 AND lease_token=$2",
    )
    .bind(ACCOUNT)
    .bind(&first.claim_token)
    .execute(persistence.pool())
    .await?;
    sqlx::query(
        "UPDATE media_work_units SET claim_until=clock_timestamp()-interval '1 second' \
          WHERE account_id=$1 AND claim_token=$2",
    )
    .bind(ACCOUNT)
    .bind(&first.claim_token)
    .execute(persistence.pool())
    .await?;
    let takeover = persistence
        .claim(
            ACCOUNT,
            MediaProcessingClass::Screen,
            &database_now().await?,
            300,
            8,
        )
        .await?
        .ok_or_else(|| EnclaveError::Store("expired media work was not reclaimable".into()))?;
    if takeover.claim_token == first.claim_token {
        return Err(EnclaveError::Store(
            "media work takeover reused its superseded token".into(),
        ));
    }
    let attempt = test_begin_media_provider_attempt(persistence, &takeover).await?;
    match persistence
        .authorize_provider_attempt(&first, 1_024, &attempt)
        .await
    {
        Err(EnclaveError::Conflict(_)) => {}
        Err(error) => return Err(error),
        Ok(()) => {
            return Err(EnclaveError::Store(
                "superseded media worker retained provider authority".into(),
            ))
        }
    }

    // Put the authoritative token close enough to expiry that it could not
    // cover one provider request, then prove the final authorizer renews both
    // the aggregate and every exact member from DB statement time.
    sqlx::query(
        "UPDATE media_processing_jobs SET lease_until=clock_timestamp()+interval '5 seconds' \
          WHERE account_id=$1 AND lease_token=$2",
    )
    .bind(ACCOUNT)
    .bind(&takeover.claim_token)
    .execute(persistence.pool())
    .await?;
    sqlx::query(
        "UPDATE media_work_units SET claim_until=clock_timestamp()+interval '5 seconds' \
          WHERE account_id=$1 AND claim_token=$2",
    )
    .bind(ACCOUNT)
    .bind(&takeover.claim_token)
    .execute(persistence.pool())
    .await?;
    persistence
        .authorize_provider_attempt(&takeover, 1_024, &attempt)
        .await?;
    let minimum_remaining_seconds = sqlx::query_scalar::<_, f64>(
        "SELECT min(remaining_seconds)::double precision FROM ( \
             SELECT extract(epoch FROM (work.claim_until-clock_timestamp())) \
                        AS remaining_seconds \
               FROM media_work_units work \
              WHERE work.account_id=$1 AND work.id=$2 \
             UNION ALL \
             SELECT extract(epoch FROM (job.lease_until-clock_timestamp())) \
               FROM media_work_members member \
               JOIN media_processing_jobs job \
                 ON job.account_id=member.account_id AND job.id=member.job_id \
              WHERE member.account_id=$1 AND member.work_unit_id=$2 \
         ) live_leases",
    )
    .bind(ACCOUNT)
    .bind(&takeover.work_unit_id)
    .fetch_one(persistence.pool())
    .await?;
    if minimum_remaining_seconds < PROVIDER_EGRESS_LEASE_SECONDS - 10.0 {
        return Err(EnclaveError::Store(
            "media provider authorization did not renew every exact lease".into(),
        ));
    }

    // Claim-first: the renewed lease is a durable provider-disclosure fence,
    // including when the episode is rooted at the reference member.
    match persistence
        .begin_episode_deletion(ACCOUNT, EPISODE_ID)
        .await
    {
        Err(EnclaveError::Conflict(message))
            if message == "episode media processing provider work is in flight" => {}
        Err(error) => return Err(error),
        Ok(_) => {
            return Err(EnclaveError::Store(
                "episode deletion ignored live canonical-family media work".into(),
            ))
        }
    }

    sqlx::query(
        "UPDATE media_processing_jobs SET lease_until=clock_timestamp()-interval '1 second' \
          WHERE account_id=$1 AND lease_token=$2",
    )
    .bind(ACCOUNT)
    .bind(&takeover.claim_token)
    .execute(persistence.pool())
    .await?;
    sqlx::query(
        "UPDATE media_work_units SET claim_until=clock_timestamp()-interval '1 second' \
          WHERE account_id=$1 AND claim_token=$2",
    )
    .bind(ACCOUNT)
    .bind(&takeover.claim_token)
    .execute(persistence.pool())
    .await?;
    let pending = persistence
        .begin_episode_deletion(ACCOUNT, EPISODE_ID)
        .await?;
    if !matches!(pending, EpisodeDeletionStart::Pending(_)) {
        return Err(EnclaveError::Store(
            "delete-first media egress fixture was not durably frozen".into(),
        ));
    }
    let exact_family = sqlx::query_scalar::<_, bool>(
        "SELECT orphan_event_ids ? $3 AND orphan_event_ids ? $4 \
           FROM episode_deletions WHERE account_id=$1 AND episode_id=$2",
    )
    .bind(ACCOUNT)
    .bind(EPISODE_ID)
    .bind(CANONICAL_EVENT)
    .bind(REFERENCE_EVENT)
    .fetch_one(persistence.pool())
    .await?;
    if !exact_family {
        return Err(EnclaveError::Store(
            "episode deletion did not freeze the exact canonical/reference family".into(),
        ));
    }

    // Delete-first: even a stale process whose leases are made live again
    // cannot pass the final pending-family authorization, so the worker makes
    // zero provider calls (the app invokes this boundary immediately before
    // HTTP egress).
    sqlx::query(
        "UPDATE media_processing_jobs SET lease_until=clock_timestamp()+interval '15 minutes' \
          WHERE account_id=$1 AND lease_token=$2",
    )
    .bind(ACCOUNT)
    .bind(&takeover.claim_token)
    .execute(persistence.pool())
    .await?;
    sqlx::query(
        "UPDATE media_work_units SET claim_until=clock_timestamp()+interval '15 minutes' \
          WHERE account_id=$1 AND claim_token=$2",
    )
    .bind(ACCOUNT)
    .bind(&takeover.claim_token)
    .execute(persistence.pool())
    .await?;
    match persistence
        .authorize_provider_attempt(&takeover, 1_024, &attempt)
        .await
    {
        Err(EnclaveError::Conflict(message))
            if message == "media source is pending episode deletion" => {}
        Err(error) => return Err(error),
        Ok(()) => {
            return Err(EnclaveError::Store(
                "pending deletion retained media provider authority".into(),
            ))
        }
    }

    sqlx::query("DELETE FROM accounts WHERE id=$1")
        .bind(ACCOUNT)
        .execute(persistence.pool())
        .await?;

    // Crash after durable invocation begin but before the final authorizer:
    // there is no attempt journal yet. The next owner receives the same exact
    // attempt number, makes the started usage intent terminally ambiguous,
    // and appends the content-free terminal journal without provider egress.
    const PREAUTH_ACCOUNT: &str = "activation-media-preauth-crash";
    test_insert_screen_work_fixture(persistence, PREAUTH_ACCOUNT, "preauth-crash").await?;
    let preauth_claim = persistence
        .claim(
            PREAUTH_ACCOUNT,
            MediaProcessingClass::Screen,
            "2099-01-01T00:00:00.000Z",
            300,
            8,
        )
        .await?
        .ok_or_else(|| EnclaveError::Store("preauthorize fixture was not claimable".into()))?;
    let db_claim_seconds = sqlx::query_scalar::<_, f64>(
        "SELECT extract(epoch FROM (claim_until-clock_timestamp()))::double precision \
           FROM media_work_units WHERE account_id=$1 AND id=$2",
    )
    .bind(PREAUTH_ACCOUNT)
    .bind(&preauth_claim.work_unit_id)
    .fetch_one(persistence.pool())
    .await?;
    if !(285.0..=300.0).contains(&db_claim_seconds) {
        return Err(EnclaveError::Store(
            "media claim deadline used caller time instead of database time".into(),
        ));
    }
    let preauth_attempt = test_begin_media_provider_attempt(persistence, &preauth_claim).await?;
    test_expire_media_claim(persistence, &preauth_claim).await?;
    let preauth_takeover = persistence
        .claim(
            PREAUTH_ACCOUNT,
            MediaProcessingClass::Screen,
            "2000-01-01T00:00:00.000Z",
            300,
            8,
        )
        .await?
        .ok_or_else(|| EnclaveError::Store("preauthorize fixture was not reclaimable".into()))?;
    if preauth_takeover.provider_attempt_number != 1 {
        return Err(EnclaveError::Store(
            "preauthorize crash advanced an unjournaled provider attempt".into(),
        ));
    }
    let replay = persistence
        .begin_invocation_attempt(
            PREAUTH_ACCOUNT,
            VertexOperation::ScreenStoryboard,
            &preauth_attempt.requested_model,
            &preauth_attempt.location,
            &preauth_attempt.request_sha256,
            &preauth_attempt.identity_sha256,
        )
        .await?;
    if replay.admission != VertexInvocationAdmission::AmbiguousTerminal
        || replay.event_id != preauth_attempt.event_id
    {
        return Err(EnclaveError::Store(
            "preauthorize crash did not preserve terminal attempt identity".into(),
        ));
    }
    persistence
        .settle_failure(
            &preauth_takeover,
            Some(&preauth_attempt),
            MediaFailureDisposition::AmbiguousTerminal,
            "vertex_ambiguous",
            &database_now().await?,
            MediaFailurePolicy {
                max_attempts: 3,
                budget_retry_seconds: 60,
                resurrection_window_seconds: 604_800,
            },
        )
        .await?;
    let preauth_terminal = sqlx::query_scalar::<_, bool>(
        "SELECT work.state='failed_terminal' \
                AND work.usage_json#>>'{provider_attempts,0,state}'='ambiguous' \
                AND work.usage_json#>>'{provider_attempts,0,admitted_at}' IS NULL \
                AND usage.outcome='ambiguous' \
           FROM media_work_units work JOIN vertex_usage_events usage \
             ON usage.account_id=work.account_id AND usage.event_id=$3 \
          WHERE work.account_id=$1 AND work.id=$2",
    )
    .bind(PREAUTH_ACCOUNT)
    .bind(&preauth_takeover.work_unit_id)
    .bind(&preauth_attempt.event_id)
    .fetch_one(persistence.pool())
    .await?;
    if !preauth_terminal {
        return Err(EnclaveError::Store(
            "preauthorize crash did not terminalize usage and journal consistently".into(),
        ));
    }
    sqlx::query("DELETE FROM accounts WHERE id=$1")
        .bind(PREAUTH_ACCOUNT)
        .execute(persistence.pool())
        .await?;

    // A superseded final authorizer is provably pre-egress. Its no-journal
    // usage intent becomes not-billed; the current owner appends that outcome
    // and the next durable claim advances to exactly attempt two.
    const REFUSAL_ACCOUNT: &str = "activation-media-authorize-refusal";
    test_insert_screen_work_fixture(persistence, REFUSAL_ACCOUNT, "authorize-refusal").await?;
    let refusal_first = persistence
        .claim(
            REFUSAL_ACCOUNT,
            MediaProcessingClass::Screen,
            "2099-01-01T00:00:00.000Z",
            300,
            8,
        )
        .await?
        .ok_or_else(|| {
            EnclaveError::Store("authorization refusal fixture was not claimable".into())
        })?;
    let refusal_attempt = test_begin_media_provider_attempt(persistence, &refusal_first).await?;
    test_expire_media_claim(persistence, &refusal_first).await?;
    let refusal_takeover = persistence
        .claim(
            REFUSAL_ACCOUNT,
            MediaProcessingClass::Screen,
            "2000-01-01T00:00:00.000Z",
            300,
            8,
        )
        .await?
        .ok_or_else(|| {
            EnclaveError::Store("authorization refusal fixture was not reclaimable".into())
        })?;
    if !matches!(
        persistence
            .authorize_provider_attempt(&refusal_first, 1_024, &refusal_attempt)
            .await,
        Err(EnclaveError::Conflict(_))
    ) {
        return Err(EnclaveError::Store(
            "superseded final authorization was not refused".into(),
        ));
    }
    persistence
        .settle_pre_egress_not_billed(REFUSAL_ACCOUNT, &refusal_attempt.event_id)
        .await?;
    let refusal_replay = persistence
        .begin_invocation_attempt(
            REFUSAL_ACCOUNT,
            VertexOperation::ScreenStoryboard,
            &refusal_attempt.requested_model,
            &refusal_attempt.location,
            &refusal_attempt.request_sha256,
            &refusal_attempt.identity_sha256,
        )
        .await?;
    if refusal_replay.admission != VertexInvocationAdmission::ConfirmedNotBilled {
        return Err(EnclaveError::Store(
            "pre-egress refusal did not replay as confirmed not billed".into(),
        ));
    }
    persistence
        .settle_failure(
            &refusal_takeover,
            Some(&refusal_attempt),
            MediaFailureDisposition::RetryableNotBilled,
            "vertex_not_billed",
            &database_now().await?,
            MediaFailurePolicy {
                max_attempts: 3,
                budget_retry_seconds: 60,
                resurrection_window_seconds: 604_800,
            },
        )
        .await?;
    sqlx::query(
        "UPDATE media_processing_jobs SET updated_at=clock_timestamp()-interval '1 second' \
          WHERE account_id=$1",
    )
    .bind(REFUSAL_ACCOUNT)
    .execute(persistence.pool())
    .await?;
    sqlx::query(
        "UPDATE media_work_units SET updated_at=clock_timestamp()-interval '1 second' \
          WHERE account_id=$1",
    )
    .bind(REFUSAL_ACCOUNT)
    .execute(persistence.pool())
    .await?;
    let refusal_next = persistence
        .claim(
            REFUSAL_ACCOUNT,
            MediaProcessingClass::Screen,
            "2099-01-01T00:00:00.000Z",
            300,
            8,
        )
        .await?
        .ok_or_else(|| EnclaveError::Store("confirmed not-billed work did not retry".into()))?;
    if refusal_next.provider_attempt_number != 2 {
        return Err(EnclaveError::Store(
            "confirmed not-billed retry did not advance exactly one attempt".into(),
        ));
    }
    sqlx::query("DELETE FROM accounts WHERE id=$1")
        .bind(REFUSAL_ACCOUNT)
        .execute(persistence.pool())
        .await?;

    // Response staging survives a lost owner and replays exact bytes without
    // another admission. Terminal projection atomically removes raw bytes but
    // retains the content-free response commitment.
    const STAGE_ACCOUNT: &str = "activation-media-stage-replay";
    let stage_event =
        test_insert_screen_work_fixture(persistence, STAGE_ACCOUNT, "stage-replay").await?;
    let stage_claim = persistence
        .claim(
            STAGE_ACCOUNT,
            MediaProcessingClass::Screen,
            "2099-01-01T00:00:00.000Z",
            300,
            8,
        )
        .await?
        .ok_or_else(|| EnclaveError::Store("stage replay fixture was not claimable".into()))?;
    let stage_attempt = test_stage_media_provider_success(persistence, &stage_claim, 1_024).await?;
    persistence
        .settle_usage(MediaUsageSettlement {
            claim: stage_claim.clone(),
            provider_attempt: stage_attempt.clone(),
            usage: json!({"outcome":"model_returned","actual_output_tokens":0}),
        })
        .await?;
    test_expire_media_claim(persistence, &stage_claim).await?;
    let stage_takeover = persistence
        .claim(
            STAGE_ACCOUNT,
            MediaProcessingClass::Screen,
            "2000-01-01T00:00:00.000Z",
            300,
            8,
        )
        .await?
        .ok_or_else(|| EnclaveError::Store("staged response was not reclaimable".into()))?;
    let replayed_response = stage_takeover
        .staged_response
        .as_ref()
        .ok_or_else(|| EnclaveError::Store("staged response bytes were not replayed".into()))?;
    if replayed_response.attempt != stage_attempt {
        return Err(EnclaveError::Store(
            "staged response replay changed provider attempt identity".into(),
        ));
    }
    persistence
        .settle_screens(ScreenMediaSettlement {
            claim: stage_takeover.clone(),
            provider_attempt: stage_attempt.clone(),
            results: vec![MediaScreenProjection {
                event_id: stage_event,
                literal_description: "fixture".into(),
                screen_state: "content".into(),
                content_type: "document".into(),
                visible_text: String::new(),
                salient_text: String::new(),
                people: Vec::new(),
            }],
        })
        .await?;
    let stage_terminal = sqlx::query_scalar::<_, bool>(
        "SELECT state='succeeded' \
                AND usage_json#>>'{provider_attempts,0,state}'='settled' \
                AND usage_json#>'{provider_attempts,0,response_b64}'='null'::jsonb \
                AND usage_json#>>'{provider_attempts,0,response_sha256}' IS NOT NULL \
           FROM media_work_units WHERE account_id=$1 AND id=$2",
    )
    .bind(STAGE_ACCOUNT)
    .bind(&stage_takeover.work_unit_id)
    .fetch_one(persistence.pool())
    .await?;
    if !stage_terminal {
        return Err(EnclaveError::Store(
            "terminal media projection retained raw provider bytes".into(),
        ));
    }
    sqlx::query("DELETE FROM accounts WHERE id=$1")
        .bind(STAGE_ACCOUNT)
        .execute(persistence.pool())
        .await?;

    // Once admitted, a response lost before staging is unknowable. Lease
    // takeover makes both the usage ledger and journal terminally ambiguous;
    // no new provider attempt is emitted.
    const RESPONSE_GAP_ACCOUNT: &str = "activation-media-response-gap";
    test_insert_screen_work_fixture(persistence, RESPONSE_GAP_ACCOUNT, "response-gap").await?;
    let response_gap_claim = persistence
        .claim(
            RESPONSE_GAP_ACCOUNT,
            MediaProcessingClass::Screen,
            "2099-01-01T00:00:00.000Z",
            300,
            8,
        )
        .await?
        .ok_or_else(|| EnclaveError::Store("response gap fixture was not claimable".into()))?;
    let response_gap_attempt =
        test_begin_media_provider_attempt(persistence, &response_gap_claim).await?;
    persistence
        .authorize_provider_attempt(&response_gap_claim, 1_024, &response_gap_attempt)
        .await?;
    test_expire_media_claim(persistence, &response_gap_claim).await?;
    if persistence
        .claim(
            RESPONSE_GAP_ACCOUNT,
            MediaProcessingClass::Screen,
            "2000-01-01T00:00:00.000Z",
            300,
            8,
        )
        .await?
        .is_some()
    {
        return Err(EnclaveError::Store(
            "admitted response gap was automatically resent".into(),
        ));
    }
    let response_gap_terminal = sqlx::query_scalar::<_, bool>(
        "SELECT work.state='failed_terminal' \
                AND work.usage_json#>>'{provider_attempts,0,state}'='ambiguous' \
                AND usage.outcome='ambiguous' \
           FROM media_work_units work JOIN vertex_usage_events usage \
             ON usage.account_id=work.account_id AND usage.event_id=$3 \
          WHERE work.account_id=$1 AND work.id=$2",
    )
    .bind(RESPONSE_GAP_ACCOUNT)
    .bind(&response_gap_claim.work_unit_id)
    .bind(&response_gap_attempt.event_id)
    .fetch_one(persistence.pool())
    .await?;
    if !response_gap_terminal {
        return Err(EnclaveError::Store(
            "admitted response gap was not terminalized consistently".into(),
        ));
    }
    sqlx::query("DELETE FROM accounts WHERE id=$1")
        .bind(RESPONSE_GAP_ACCOUNT)
        .execute(persistence.pool())
        .await?;

    // The derived event id is not sufficient authority. Corrupting any exact
    // request dimension must refuse the final provider admission.
    const PROVENANCE_ACCOUNT: &str = "activation-media-provenance";
    test_insert_screen_work_fixture(persistence, PROVENANCE_ACCOUNT, "provenance").await?;
    let provenance_claim = persistence
        .claim(
            PROVENANCE_ACCOUNT,
            MediaProcessingClass::Screen,
            "2099-01-01T00:00:00.000Z",
            300,
            8,
        )
        .await?
        .ok_or_else(|| EnclaveError::Store("provenance fixture was not claimable".into()))?;
    let provenance_attempt =
        test_begin_media_provider_attempt(persistence, &provenance_claim).await?;
    let exact_fingerprint = invocation_fingerprint(
        PROVENANCE_ACCOUNT,
        VertexOperation::ScreenStoryboard,
        &provenance_attempt.requested_model,
        &provenance_attempt.location,
        &provenance_attempt.request_sha256,
    );

    sqlx::query(
        "UPDATE vertex_usage_events SET request_fingerprint=decode(repeat('00',32),'hex') \
          WHERE account_id=$1 AND event_id=$2",
    )
    .bind(PROVENANCE_ACCOUNT)
    .bind(&provenance_attempt.event_id)
    .execute(persistence.pool())
    .await?;
    if !matches!(
        persistence
            .authorize_provider_attempt(&provenance_claim, 1_024, &provenance_attempt)
            .await,
        Err(EnclaveError::Conflict(_))
    ) {
        return Err(EnclaveError::Store(
            "wrong media invocation fingerprint retained provider authority".into(),
        ));
    }
    sqlx::query(
        "UPDATE vertex_usage_events SET request_fingerprint=$3 \
          WHERE account_id=$1 AND event_id=$2",
    )
    .bind(PROVENANCE_ACCOUNT)
    .bind(&provenance_attempt.event_id)
    .bind(exact_fingerprint.as_slice())
    .execute(persistence.pool())
    .await?;

    for (column, wrong, expected) in [
        (
            "requested_model",
            "wrong-model",
            provenance_attempt.requested_model.as_str(),
        ),
        (
            "location",
            "wrong-location",
            provenance_attempt.location.as_str(),
        ),
        ("operation", "audio_understanding", "screen_understanding"),
    ] {
        let corrupt = match column {
            "requested_model" => {
                sqlx::query(
                    "UPDATE vertex_usage_events SET requested_model=$3 \
                      WHERE account_id=$1 AND event_id=$2",
                )
                .bind(PROVENANCE_ACCOUNT)
                .bind(&provenance_attempt.event_id)
                .bind(wrong)
                .execute(persistence.pool())
                .await?
            }
            "location" => {
                sqlx::query(
                    "UPDATE vertex_usage_events SET location=$3 \
                      WHERE account_id=$1 AND event_id=$2",
                )
                .bind(PROVENANCE_ACCOUNT)
                .bind(&provenance_attempt.event_id)
                .bind(wrong)
                .execute(persistence.pool())
                .await?
            }
            "operation" => {
                sqlx::query(
                    "UPDATE vertex_usage_events SET operation=$3 \
                      WHERE account_id=$1 AND event_id=$2",
                )
                .bind(PROVENANCE_ACCOUNT)
                .bind(&provenance_attempt.event_id)
                .bind(wrong)
                .execute(persistence.pool())
                .await?
            }
            _ => unreachable!(),
        };
        if corrupt.rows_affected() != 1
            || !matches!(
                persistence
                    .authorize_provider_attempt(&provenance_claim, 1_024, &provenance_attempt)
                    .await,
                Err(EnclaveError::Conflict(_))
            )
        {
            return Err(EnclaveError::Store(format!(
                "wrong media invocation {column} retained provider authority"
            )));
        }
        match column {
            "requested_model" => {
                sqlx::query(
                    "UPDATE vertex_usage_events SET requested_model=$3 \
                      WHERE account_id=$1 AND event_id=$2",
                )
                .bind(PROVENANCE_ACCOUNT)
                .bind(&provenance_attempt.event_id)
                .bind(expected)
                .execute(persistence.pool())
                .await?;
            }
            "location" => {
                sqlx::query(
                    "UPDATE vertex_usage_events SET location=$3 \
                      WHERE account_id=$1 AND event_id=$2",
                )
                .bind(PROVENANCE_ACCOUNT)
                .bind(&provenance_attempt.event_id)
                .bind(expected)
                .execute(persistence.pool())
                .await?;
            }
            "operation" => {
                sqlx::query(
                    "UPDATE vertex_usage_events SET operation=$3 \
                      WHERE account_id=$1 AND event_id=$2",
                )
                .bind(PROVENANCE_ACCOUNT)
                .bind(&provenance_attempt.event_id)
                .bind(expected)
                .execute(persistence.pool())
                .await?;
            }
            _ => unreachable!(),
        }
    }
    persistence
        .authorize_provider_attempt(&provenance_claim, 1_024, &provenance_attempt)
        .await?;
    let provenance_bytes = br#"{"candidates":[]}"#.to_vec();
    let provenance_response = MediaProviderStagedResponse {
        attempt: provenance_attempt.clone(),
        http_status: 200,
        response_sha256: Sha256::digest(&provenance_bytes).into(),
        response_bytes: provenance_bytes,
        latency_ms: 1,
    };
    sqlx::query(
        "UPDATE vertex_usage_events SET location='wrong-location' \
          WHERE account_id=$1 AND event_id=$2",
    )
    .bind(PROVENANCE_ACCOUNT)
    .bind(&provenance_attempt.event_id)
    .execute(persistence.pool())
    .await?;
    if !matches!(
        persistence
            .stage_provider_response(&provenance_claim, &provenance_response)
            .await,
        Err(EnclaveError::Conflict(_))
    ) {
        return Err(EnclaveError::Store(
            "wrong media invocation location was accepted at response stage".into(),
        ));
    }
    sqlx::query("UPDATE vertex_usage_events SET location=$3 WHERE account_id=$1 AND event_id=$2")
        .bind(PROVENANCE_ACCOUNT)
        .bind(&provenance_attempt.event_id)
        .bind(&provenance_attempt.location)
        .execute(persistence.pool())
        .await?;
    persistence
        .stage_provider_response(&provenance_claim, &provenance_response)
        .await?;
    persistence
        .settle_response(
            PROVENANCE_ACCOUNT,
            &provenance_attempt.event_id,
            &VertexMetadata::default(),
        )
        .await?;
    sqlx::query(
        "UPDATE vertex_usage_events SET requested_model='wrong-model' \
          WHERE account_id=$1 AND event_id=$2",
    )
    .bind(PROVENANCE_ACCOUNT)
    .bind(&provenance_attempt.event_id)
    .execute(persistence.pool())
    .await?;
    let provenance_usage = MediaUsageSettlement {
        claim: provenance_claim.clone(),
        provider_attempt: provenance_attempt.clone(),
        usage: json!({"outcome":"model_returned"}),
    };
    if !matches!(
        persistence.settle_usage(provenance_usage.clone()).await,
        Err(EnclaveError::Conflict(_))
    ) {
        return Err(EnclaveError::Store(
            "wrong media invocation model was accepted at usage settlement".into(),
        ));
    }
    sqlx::query(
        "UPDATE vertex_usage_events SET requested_model=$3 \
          WHERE account_id=$1 AND event_id=$2",
    )
    .bind(PROVENANCE_ACCOUNT)
    .bind(&provenance_attempt.event_id)
    .bind(&provenance_attempt.requested_model)
    .execute(persistence.pool())
    .await?;
    persistence.settle_usage(provenance_usage).await?;
    sqlx::query("DELETE FROM accounts WHERE id=$1")
        .bind(PROVENANCE_ACCOUNT)
        .execute(persistence.pool())
        .await?;

    // Deleting one member of an expired staged aggregate must erase the raw
    // response, release the old aggregate membership, and make the surviving
    // job claimable in a new exact work unit without replaying the old stage.
    const CLEANUP_ACCOUNT: &str = "activation-media-delete-cleanup";
    sqlx::raw_sql(
        "INSERT INTO accounts(id,email,primary_provider,primary_subject) \
         VALUES('activation-media-delete-cleanup','media-delete-cleanup@example.com', \
                'google','media-delete-cleanup'); \
         INSERT INTO capture_sessions( \
             account_id,id,device_id,install_id,started_at,last_event_at,ended_at,schema_version) \
         VALUES('activation-media-delete-cleanup','media-delete-cleanup-session', \
                'media-delete-cleanup-device','media-delete-cleanup-install', \
                clock_timestamp()-interval '2 minutes',clock_timestamp()-interval '1 minute', \
                clock_timestamp(),2); \
         INSERT INTO capture_streams( \
             account_id,id,capture_session_id,device_id,stream_kind,committed_through_sequence) \
         VALUES('activation-media-delete-cleanup','media-delete-cleanup-stream', \
                'media-delete-cleanup-session','media-delete-cleanup-device','mac_screen',1); \
         INSERT INTO capture_events( \
             account_id,event_id,device_id,install_id,capture_session_id,stream_id,stream_kind, \
             sequence,source_wall_at,source_monotonic_ns,started_at,ended_at,timezone_id, \
             utc_offset_minutes,clock_uncertainty_ms,asset_id,manifest_digest,context_json, \
             media_disposition,dedupe_version,received_at) VALUES \
           ('activation-media-delete-cleanup','media-delete-cleanup-drop', \
            'media-delete-cleanup-device','media-delete-cleanup-install', \
            'media-delete-cleanup-session','media-delete-cleanup-stream','mac_screen',0, \
            clock_timestamp()-interval '2 minutes','1',clock_timestamp()-interval '2 minutes', \
            clock_timestamp()-interval '119 seconds','UTC',0,0,'media-delete-cleanup-asset-drop', \
            repeat('a',64),'{}','canonical',1,clock_timestamp()), \
           ('activation-media-delete-cleanup','media-delete-cleanup-keep', \
            'media-delete-cleanup-device','media-delete-cleanup-install', \
            'media-delete-cleanup-session','media-delete-cleanup-stream','mac_screen',1, \
            clock_timestamp()-interval '119 seconds','2',clock_timestamp()-interval '119 seconds', \
            clock_timestamp()-interval '118 seconds','UTC',0,0,'media-delete-cleanup-asset-keep', \
            repeat('b',64),'{}','canonical',1,clock_timestamp()); \
         INSERT INTO media_objects( \
             account_id,asset_id,event_id,object_key,object_generation,object_backend,mime_type, \
             codec,byte_length,sha256,width,height,processing_state) VALUES \
           ('activation-media-delete-cleanup','media-delete-cleanup-asset-drop', \
            'media-delete-cleanup-drop','media/delete-cleanup/drop',1,'current','image/png','png', \
            1024,repeat('c',64),100,100,'queued'), \
           ('activation-media-delete-cleanup','media-delete-cleanup-asset-keep', \
            'media-delete-cleanup-keep','media/delete-cleanup/keep',1,'current','image/png','png', \
            1024,repeat('d',64),100,100,'queued'); \
         INSERT INTO media_processing_jobs( \
             account_id,event_id,job_kind,input_revision,processor_version,state) VALUES \
           ('activation-media-delete-cleanup','media-delete-cleanup-drop','gemini_screen', \
            'media-delete-cleanup-drop-v1',1,'pending'), \
           ('activation-media-delete-cleanup','media-delete-cleanup-keep','gemini_screen', \
            'media-delete-cleanup-keep-v1',1,'pending'); \
         INSERT INTO episodes(account_id,id,started_at,ended_at,type,title,summary) \
         VALUES('activation-media-delete-cleanup',800,clock_timestamp()-interval '2 minutes', \
                clock_timestamp()-interval '1 minute','work','cleanup','cleanup'); \
         INSERT INTO screenshots(account_id,id,captured_at,source_key) \
         VALUES('activation-media-delete-cleanup',801,clock_timestamp(), \
                'cloud-v2:media-delete-cleanup-drop'); \
         INSERT INTO episode_members(account_id,episode_id,record_type,record_id) \
         VALUES('activation-media-delete-cleanup',800,'screenshot',801);",
    )
    .execute(persistence.pool())
    .await?;
    let cleanup_claim = persistence
        .claim(
            CLEANUP_ACCOUNT,
            MediaProcessingClass::Screen,
            "2099-01-01T00:00:00.000Z",
            300,
            8,
        )
        .await?
        .ok_or_else(|| EnclaveError::Store("media cleanup fixture was not claimable".into()))?;
    if cleanup_claim.jobs.len() != 2 {
        return Err(EnclaveError::Store(
            "media cleanup fixture did not form one multi-member aggregate".into(),
        ));
    }
    let cleanup_attempt = test_begin_media_provider_attempt(persistence, &cleanup_claim).await?;
    persistence
        .authorize_provider_attempt(&cleanup_claim, 1_024, &cleanup_attempt)
        .await?;
    let cleanup_bytes = br#"{"candidates":[]}"#.to_vec();
    persistence
        .stage_provider_response(
            &cleanup_claim,
            &MediaProviderStagedResponse {
                attempt: cleanup_attempt,
                http_status: 200,
                response_sha256: Sha256::digest(&cleanup_bytes).into(),
                response_bytes: cleanup_bytes,
                latency_ms: 1,
            },
        )
        .await?;
    test_expire_media_claim(persistence, &cleanup_claim).await?;
    let cleanup_plan = match persistence
        .begin_episode_deletion(CLEANUP_ACCOUNT, 800)
        .await?
    {
        EpisodeDeletionStart::Pending(plan) => plan,
        _ => {
            return Err(EnclaveError::Store(
                "media cleanup deletion was not prepared".into(),
            ))
        }
    };
    persistence
        .complete_episode_deletion(CLEANUP_ACCOUNT, &cleanup_plan)
        .await?;
    let cleanup_exact = sqlx::query_scalar::<_, bool>(
        "SELECT NOT EXISTS(SELECT 1 FROM media_work_units work \
             CROSS JOIN LATERAL jsonb_array_elements( \
               CASE WHEN jsonb_typeof(work.usage_json->'provider_attempts')='array' \
                    THEN work.usage_json->'provider_attempts' ELSE '[]'::jsonb END) attempt \
             WHERE work.account_id=$1 AND attempt->>'response_b64' IS NOT NULL) \
          AND EXISTS(SELECT 1 FROM media_processing_jobs job \
             WHERE job.account_id=$1 AND job.event_id='media-delete-cleanup-keep' \
               AND job.state='pending' AND job.lease_token IS NULL AND job.usage_json IS NULL) \
          AND NOT EXISTS(SELECT 1 FROM media_work_members member \
             WHERE member.account_id=$1)",
    )
    .bind(CLEANUP_ACCOUNT)
    .fetch_one(persistence.pool())
    .await?;
    if !cleanup_exact {
        return Err(EnclaveError::Store(
            "episode deletion stranded a staged response or surviving media job".into(),
        ));
    }
    let cleanup_reclaim = persistence
        .claim(
            CLEANUP_ACCOUNT,
            MediaProcessingClass::Screen,
            "2000-01-01T00:00:00.000Z",
            300,
            8,
        )
        .await?
        .ok_or_else(|| EnclaveError::Store("surviving media job was not replannable".into()))?;
    if cleanup_reclaim.jobs.len() != 1
        || cleanup_reclaim.jobs[0].event_id != "media-delete-cleanup-keep"
        || cleanup_reclaim.staged_response.is_some()
    {
        return Err(EnclaveError::Store(
            "surviving media job inherited an inexact provider stage".into(),
        ));
    }
    sqlx::query("DELETE FROM accounts WHERE id=$1")
        .bind(CLEANUP_ACCOUNT)
        .execute(persistence.pool())
        .await?;

    // Two candidate roots with one externally owned survivor prove that
    // family retention is correlated per canonical root instead of allowing
    // one survivor to retain every unrelated family.
    const TWO_ROOT_ACCOUNT: &str = "activation-media-two-root";
    sqlx::raw_sql(
        "INSERT INTO accounts(id,email,primary_provider,primary_subject) \
         VALUES('activation-media-two-root','media-two-root@example.com','google','media-two-root'); \
         INSERT INTO capture_sessions( \
             account_id,id,device_id,install_id,started_at,last_event_at,ended_at,schema_version) \
         VALUES('activation-media-two-root','media-two-root-session','media-two-root-device', \
                'media-two-root-install',clock_timestamp()-interval '3 minutes', \
                clock_timestamp()-interval '1 minute',clock_timestamp(),2); \
         INSERT INTO capture_streams( \
             account_id,id,capture_session_id,device_id,stream_kind,committed_through_sequence) \
         VALUES('activation-media-two-root','media-two-root-stream','media-two-root-session', \
                'media-two-root-device','mac_screen',2); \
         INSERT INTO capture_events( \
             account_id,event_id,device_id,install_id,capture_session_id,stream_id,stream_kind, \
             sequence,source_wall_at,source_monotonic_ns,started_at,ended_at,timezone_id, \
             utc_offset_minutes,clock_uncertainty_ms,asset_id,manifest_digest,context_json, \
             media_disposition,canonical_event_id,canonical_asset_id,canonical_media_sha256, \
             perceptual_hash,hamming_distance,pixel_change_ratio,context_fingerprint, \
             dedupe_version,received_at) \
         VALUES \
           ('activation-media-two-root','media-two-root-a','media-two-root-device', \
            'media-two-root-install','media-two-root-session','media-two-root-stream','mac_screen', \
            0,clock_timestamp()-interval '3 minutes','1',clock_timestamp()-interval '3 minutes', \
            clock_timestamp()-interval '179 seconds','UTC',0,0,'media-two-root-asset-a', \
            repeat('a',64),'{}','canonical',NULL,NULL,NULL,NULL,NULL,NULL,NULL,1,clock_timestamp()), \
           ('activation-media-two-root','media-two-root-ref-a','media-two-root-device', \
            'media-two-root-install','media-two-root-session','media-two-root-stream','mac_screen', \
            1,clock_timestamp()-interval '2 minutes','2',clock_timestamp()-interval '2 minutes', \
            clock_timestamp()-interval '119 seconds','UTC',0,0,'media-two-root-ref-asset-a', \
            repeat('b',64),'{}','reference','media-two-root-a','media-two-root-asset-a', \
            repeat('c',64),'0123456789abcdef',1,0.001,repeat('d',64),1,clock_timestamp()), \
           ('activation-media-two-root','media-two-root-b','media-two-root-device', \
            'media-two-root-install','media-two-root-session','media-two-root-stream','mac_screen', \
            2,clock_timestamp()-interval '1 minute','3',clock_timestamp()-interval '1 minute', \
            clock_timestamp()-interval '59 seconds','UTC',0,0,'media-two-root-asset-b', \
            repeat('e',64),'{}','canonical',NULL,NULL,NULL,NULL,NULL,NULL,NULL,1,clock_timestamp()); \
         INSERT INTO episodes(account_id,id,started_at,ended_at,type,title,summary) VALUES \
           ('activation-media-two-root',900,clock_timestamp()-interval '3 minutes', \
            clock_timestamp()-interval '1 minute','work','target','target'), \
           ('activation-media-two-root',910,clock_timestamp()-interval '3 minutes', \
            clock_timestamp()-interval '1 minute','work','survivor','survivor'); \
         INSERT INTO screenshots(account_id,id,captured_at,source_key) VALUES \
           ('activation-media-two-root',901,clock_timestamp(),'cloud-v2:media-two-root-ref-a'), \
           ('activation-media-two-root',902,clock_timestamp(),'cloud-v2:media-two-root-b'), \
           ('activation-media-two-root',911,clock_timestamp(),'cloud-v2:media-two-root-a'); \
         INSERT INTO episode_members(account_id,episode_id,record_type,record_id) VALUES \
           ('activation-media-two-root',900,'screenshot',901), \
           ('activation-media-two-root',900,'screenshot',902), \
           ('activation-media-two-root',910,'screenshot',911);",
    )
    .execute(persistence.pool())
    .await?;
    if !matches!(
        persistence
            .begin_episode_deletion(TWO_ROOT_ACCOUNT, 900)
            .await?,
        EpisodeDeletionStart::Pending(_)
    ) {
        return Err(EnclaveError::Store(
            "two-root deletion did not create its exact pending receipt".into(),
        ));
    }
    let two_root_exact = sqlx::query_scalar::<_, bool>(
        "SELECT orphan_event_ids ? 'media-two-root-b' \
                AND NOT (orphan_event_ids ? 'media-two-root-a') \
                AND NOT (orphan_event_ids ? 'media-two-root-ref-a') \
           FROM episode_deletions WHERE account_id=$1 AND episode_id=900",
    )
    .bind(TWO_ROOT_ACCOUNT)
    .fetch_one(persistence.pool())
    .await?;
    if !two_root_exact {
        return Err(EnclaveError::Store(
            "canonical survivor retention leaked across unrelated roots".into(),
        ));
    }
    sqlx::query("DELETE FROM accounts WHERE id=$1")
        .bind(TWO_ROOT_ACCOUNT)
        .execute(persistence.pool())
        .await?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn attempt_entry(state: &str) -> ProviderAttemptJournalEntry {
        let request_sha256: [u8; 32] = Sha256::digest(b"bounded-media-request").into();
        let identity_sha256 =
            media_provider_attempt_identity("account", "work", 1, &request_sha256);
        ProviderAttemptJournalEntry {
            number: 1,
            identity_sha256: digest_hex(&identity_sha256),
            request_sha256: digest_hex(&request_sha256),
            event_id: vertex_attempt_event_id(&identity_sha256),
            requested_model: "gemini-3.5-flash".into(),
            location: "us-central1".into(),
            state: state.into(),
            admitted_at: Some("2026-08-31T12:00:00.000Z".into()),
            completed_at: None,
            http_status: None,
            response_sha256: None,
            response_b64: None,
            latency_ms: None,
        }
    }

    #[test]
    fn provider_journal_reclaim_never_resends_an_ambiguous_attempt() {
        let mut usage = json!({});
        let mut journal = ProviderAttemptJournal {
            attempts: vec![attempt_entry("admitted")],
        };
        persist_provider_journal(&mut usage, &journal).unwrap();
        assert_eq!(
            claim_provider_state(&usage, "account", "work").unwrap(),
            (1, None, true)
        );

        journal.attempts[0].state = "confirmed_not_billed".into();
        journal.attempts[0].completed_at = Some("2026-08-31T12:00:01.000Z".into());
        persist_provider_journal(&mut usage, &journal).unwrap();
        assert_eq!(
            claim_provider_state(&usage, "account", "work").unwrap(),
            (2, None, false)
        );
    }

    #[test]
    fn staged_response_replay_binds_exact_bytes_and_attempt() {
        let mut usage = json!({});
        let mut entry = attempt_entry("response_staged");
        let bytes = br#"{"candidates":[]}"#.to_vec();
        let digest: [u8; 32] = Sha256::digest(&bytes).into();
        entry.http_status = Some(200);
        entry.response_sha256 = Some(digest_hex(&digest));
        entry.response_b64 = Some(B64.encode(&bytes));
        entry.latency_ms = Some(7);
        let journal = ProviderAttemptJournal {
            attempts: vec![entry],
        };
        persist_provider_journal(&mut usage, &journal).unwrap();
        let (number, staged, lost) = claim_provider_state(&usage, "account", "work").unwrap();
        assert_eq!(number, 1);
        assert!(!lost);
        let staged = staged.unwrap();
        assert_eq!(staged.response_bytes, bytes);
        assert_eq!(staged.response_sha256, digest);

        let object = usage.as_object_mut().unwrap();
        object.get_mut("provider_attempts").unwrap()[0]["response_b64"] =
            Value::from(B64.encode(b"different"));
        assert!(claim_provider_state(&usage, "account", "work").is_err());
    }

    #[test]
    fn exact_vertex_usage_authority_binds_every_request_dimension() {
        let source = include_str!("media_processing.rs");
        let authority = source
            .split("async fn require_exact_vertex_usage_attempt(")
            .nth(1)
            .unwrap()
            .split("async fn database_now_iso(")
            .next()
            .unwrap();
        for commitment in [
            "request_fingerprint",
            "operation",
            "requested_model",
            "location",
            "attempt.request_sha256",
            "invocation_fingerprint(",
        ] {
            assert!(authority.contains(commitment), "missing {commitment}");
        }
        for boundary in [
            "async fn authorize_provider_attempt(",
            "async fn stage_provider_response(",
            "async fn settle_usage(",
            "async fn settle_failure(",
        ] {
            let body = source.split(boundary).nth(1).unwrap();
            assert!(body.contains("require_exact_vertex_usage_attempt"));
        }
    }

    #[test]
    fn terminality_and_resurrection_use_statement_time_after_lock_waits() {
        let source = include_str!("media_processing.rs");
        let failure = source
            .split("async fn settle_failure(")
            .nth(1)
            .unwrap()
            .split("async fn resurrect_recent_failures(")
            .next()
            .unwrap();
        assert!(failure.contains("THEN clock_timestamp()"));
        assert!(!failure.contains("THEN CURRENT_TIMESTAMP"));

        let resurrection = source
            .split("async fn resurrect_recent_failures(")
            .nth(1)
            .unwrap()
            .split("async fn span_has_recoverable_media(")
            .next()
            .unwrap();
        assert!(resurrection.contains("j.updated_at<=clock_timestamp()"));
        assert!(resurrection.contains("e.started_at>=clock_timestamp()"));
        assert!(!resurrection.contains("CURRENT_TIMESTAMP"));
    }

    #[test]
    fn pending_episode_deletion_fences_media_claim_and_projection_settlement() {
        let source = include_str!("media_processing.rs");
        let fence = source
            .split("async fn ensure_claim_sources_not_pending_deletion(")
            .nth(1)
            .unwrap()
            .split("async fn mark_claim_succeeded(")
            .next()
            .unwrap();
        assert!(fence.contains("deletion.state='pending'"));
        assert!(fence.contains("deletion.orphan_event_ids ? event.event_id"));
        assert!(fence.contains("coalesce(event.canonical_event_id,event.event_id)"));

        let claim = source
            .split("async fn claim(")
            .nth(1)
            .unwrap()
            .split("async fn candidate_name_vocabulary(")
            .next()
            .unwrap();
        assert!(claim.contains("NOT EXISTS(SELECT 1 FROM episode_deletions"));

        for (settlement, boundary) in [
            ("async fn settle_audio(", "async fn settle_screens("),
            ("async fn settle_screens(", "async fn settle_failure("),
        ] {
            let body = source
                .split(settlement)
                .nth(1)
                .unwrap()
                .split(boundary)
                .next()
                .unwrap();
            let fence_position = body
                .find("ensure_claim_sources_not_pending_deletion")
                .unwrap();
            let projection_position = body
                .find(if settlement.contains("audio") {
                    "INSERT INTO audio_segments"
                } else {
                    "INSERT INTO screenshots"
                })
                .unwrap();
            assert!(fence_position < projection_position);
        }
    }

    #[test]
    fn provider_egress_revalidates_and_renews_the_exact_db_live_claim() {
        let source = include_str!("media_processing.rs");
        let authorization = source
            .split("async fn authorize_provider_attempt(")
            .nth(1)
            .unwrap()
            .split("async fn stage_provider_response(")
            .next()
            .unwrap();
        let claim_lock = source
            .split("async fn lock_claim_for_update(")
            .nth(1)
            .unwrap()
            .split("async fn ensure_claim_sources_not_pending_deletion(")
            .next()
            .unwrap();

        let activation = authorization
            .find("lock_activation_contract_key_share_if_installed")
            .unwrap();
        let account = authorization.find("advisory_transaction_lock").unwrap();
        let work_lock = authorization.find("lock_claim_for_update").unwrap();
        let pending_delete = authorization
            .find("ensure_claim_sources_not_pending_deletion")
            .unwrap();
        let exact_usage = authorization
            .find("require_exact_vertex_usage_attempt")
            .unwrap();
        let job_renewal = authorization.find("UPDATE media_processing_jobs").unwrap();
        let work_renewal = authorization.find("UPDATE media_work_units").unwrap();
        assert!(activation < account);
        assert!(account < work_lock);
        assert!(work_lock < pending_delete);
        assert!(pending_delete < exact_usage);
        assert!(exact_usage < job_renewal);
        assert!(job_renewal < work_renewal);

        let aggregate_lock = claim_lock.find("FROM media_work_units").unwrap();
        let member_lock = claim_lock.find("FROM media_work_members").unwrap();
        assert!(aggregate_lock < member_lock);
        assert!(claim_lock.contains("ORDER BY member.ordinal FOR UPDATE OF job"));
        assert!(claim_lock.contains("claim_until>clock_timestamp() AS claim_live"));
        assert!(claim_lock.contains("job.lease_until>clock_timestamp() AS lease_live"));
        assert!(authorization.contains("lease_token=$3 AND lease_until>clock_timestamp()"));
        assert!(authorization.contains("claim_token=$3 AND claim_until>clock_timestamp()"));
        assert_eq!(authorization.matches("make_interval(secs=>$").count(), 2);
        assert!(!authorization.contains("to_timestamp($6"));
        assert_eq!(PROVIDER_EGRESS_LEASE_SECONDS, 15.0 * 60.0);
    }
}
