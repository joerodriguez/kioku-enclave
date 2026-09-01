use async_trait::async_trait;
use serde_json::json;
use sha2::{Digest, Sha256};
use sqlx::Row;

use crate::{
    cp::{
        isotime,
        media_worker::{
            NON_RESURRECTABLE_MEDIA_ERROR_CODES, PROCESSOR_VERSION, RESURRECTION_TOTAL_ATTEMPT_CAP,
            RESURRECTION_WINDOW_SECONDS_INTEGRAL,
        },
        tokens,
    },
    error::{EnclaveError, Result},
    persistence::{
        capture_formation_response_schema_v1, merge_minute_summaries, merge_substance,
        merge_visual_evidence, normalized_substance, normalized_visual_evidence,
        parse_capture_formation_provider_response, CaptureFormationClaim,
        CaptureFormationProviderRequest, CaptureFormationProviderResponse,
        CaptureFormationRetryDisposition, CaptureFormationSettlement, EpisodeEmbeddingSource,
        EpisodeEmbeddingWrite, MemoryFormationRepository, OpenEpisode, SummaryScreenshot,
        SummaryUtterance, SummaryWindowClaim, SummaryWindowSettlement,
        CAPTURE_FORMATION_PROVIDER_MAX_OUTPUT_TOKENS, CAPTURE_FORMATION_PROVIDER_REQUEST_MAX_BYTES,
        CAPTURE_FORMATION_SCREENSHOT_PAGE_SIZE, CAPTURE_FORMATION_UTTERANCE_PAGE_SIZE,
    },
};

use super::{
    activation::lock_activation_contract_key_share_if_installed, advisory_transaction_lock,
    allocate_content_id, duration_seconds, PostgresPersistence,
};

const OPEN_EPISODES_SQL: &str =
    "SELECT e.id,floor(extract(epoch FROM e.started_at)*1000)::bigint AS started_at_ms,\
            floor(extract(epoch FROM e.ended_at)*1000)::bigint AS ended_at_ms,\
            e.type,e.title,e.summary,e.participants::text AS participants,\
            e.action_items::text AS action_items,e.minutes_text,\
            count(*) FILTER (WHERE m.record_type='utterance')::bigint AS utterance_count,\
            count(*) FILTER (WHERE m.record_type='screenshot')::bigint AS screenshot_count \
       FROM episodes e JOIN memory_handles h \
         ON h.account_id=e.account_id AND h.episode_id=e.id AND h.state='active' \
       LEFT JOIN episode_members m \
         ON m.account_id=e.account_id AND m.episode_id=e.id \
      WHERE e.account_id=$1 AND e.structure_state='draft' AND e.finalized_at IS NULL \
        AND e.finalization_claim_token IS NULL \
        AND e.finalization_status NOT IN ('processing','deleting') \
        AND e.ended_at>=to_timestamp($2::double precision/1000.0) \
        AND e.started_at<=to_timestamp($3::double precision/1000.0) \
      GROUP BY e.account_id,e.id ORDER BY e.ended_at,e.id LIMIT $4";

const EXTENDABLE_EPISODE_SQL: &str =
    "SELECT e.id,e.minute_summaries::text AS minutes,e.substance,e.visual_evidence \
       FROM episodes e JOIN memory_handles h \
         ON h.account_id=e.account_id AND h.episode_id=e.id AND h.state='active' \
      WHERE e.account_id=$1 AND e.id=$2 AND e.structure_state='draft' \
        AND e.finalized_at IS NULL AND e.finalization_claim_token IS NULL \
        AND e.finalization_status NOT IN ('processing','deleting') \
      FOR UPDATE OF e,h";

const CAPTURE_FORMATION_RETRY_SECONDS: f64 = 10.0 * 60.0;
/// A short server-time debounce avoids spending on the finish event before
/// its immediately trailing media settlement while still repairing late
/// evidence far ahead of the four-hour structural reconciliation horizon.
const CAPTURE_FORMATION_QUIET_SECONDS: i64 = 30;
/// Structural topology is immutable only after the same four-hour quiet
/// horizon used by reconciliation cohort closure.
const CAPTURE_SEAL_QUIET_SECONDS: i64 = 4 * 60 * 60;
const CAPTURE_SEAL_BATCH_SIZE: i64 = 32;
/// Every provider-egress authorization renews its durable deletion fence.
/// This exceeds the bounded initial plus repair HTTP timeouts and leaves a
/// settlement margin even when the original claim was close to expiry.
const PROVIDER_EGRESS_CLAIM_FENCE_SECONDS: f64 = 15.0 * 60.0;
const MAX_STAGED_FORMATION_RESPONSE_BYTES: usize = 2 * 1024 * 1024;

fn timestamp(value: &str, field: &str) -> Result<i64> {
    isotime::parse_epoch_millis(value)
        .ok_or_else(|| EnclaveError::InvalidRequest(format!("{field} is invalid")))
}

#[derive(Clone, Debug)]
struct CaptureFormationPage {
    page_index: i64,
    source_fingerprint: Vec<u8>,
    page_source_commitment: Vec<u8>,
    covered_utterance_ids: Vec<i64>,
    covered_screenshot_ids: Vec<i64>,
    provider_utterance_ids: Vec<i64>,
    provider_screenshot_ids: Vec<i64>,
    has_more: bool,
    provider_attempt: i64,
    provider_request: Option<CaptureFormationProviderRequest>,
    provider_request_sha256: Option<Vec<u8>>,
    staged_provider_response: Option<String>,
    staged_response_sha256: Option<Vec<u8>>,
    staged_vertex_event_id: Option<String>,
}

fn capture_formation_provider_request_bytes(
    request: &CaptureFormationProviderRequest,
) -> Result<Vec<u8>> {
    if request.contract_version != 1
        || request.vertex_project.is_empty()
        || request.vertex_project.len() > 256
        || request.vertex_location.is_empty()
        || request.vertex_location.len() > 128
        || request.model.is_empty()
        || request.model.len() > 256
        || request.api_version != "v1"
        || request.publisher != "google"
        || request.method != "generateContent"
        || request.response_mime_type != "application/json"
        || request.max_output_tokens != CAPTURE_FORMATION_PROVIDER_MAX_OUTPUT_TOKENS
        || request.thinking_budget != 0
        || request.response_schema != capture_formation_response_schema_v1()
        || [
            &request.vertex_project,
            &request.vertex_location,
            &request.model,
        ]
        .into_iter()
        .any(|value| {
            !value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
        })
    {
        return Err(EnclaveError::InvalidRequest(
            "capture formation provider request contract is invalid".into(),
        ));
    }
    let bytes = serde_json::to_vec(request)?;
    if bytes.len() > CAPTURE_FORMATION_PROVIDER_REQUEST_MAX_BYTES {
        return Err(EnclaveError::InvalidRequest(
            "capture formation provider request exceeds its exact byte bound".into(),
        ));
    }
    Ok(bytes)
}

fn capture_formation_provider_caller_anchor(
    request: &CaptureFormationProviderRequest,
) -> Result<[u8; 32]> {
    capture_formation_provider_request_bytes(request)?;
    crate::cp::vertex::custom_text_request_caller_anchor(
        &crate::cp::vertex::CustomTextGenerationRequest {
            operation: crate::cp::vertex::VertexOperation::EpisodeSummary,
            system: &request.system_prompt,
            user_message: &request.user_message,
            schema: request.response_schema.clone(),
            max_output_tokens: request.max_output_tokens,
            model: &request.model,
        },
    )
}

fn capture_formation_page_commitment(
    source_fingerprint: &[u8],
    page_index: i64,
    covered_utterance_ids: &[i64],
    covered_screenshot_ids: &[i64],
    provider_utterance_ids: &[i64],
    provider_screenshot_ids: &[i64],
    has_more: bool,
) -> Result<Vec<u8>> {
    let mut digest = Sha256::new();
    digest.update(b"kioku.capture-formation.page.v1\0");
    digest.update(serde_json::to_vec(&json!({
        "source_fingerprint": source_fingerprint,
        "page_index": page_index,
        "covered_utterance_ids": covered_utterance_ids,
        "covered_screenshot_ids": covered_screenshot_ids,
        "provider_utterance_ids": provider_utterance_ids,
        "provider_screenshot_ids": provider_screenshot_ids,
        "has_more": has_more,
    }))?);
    Ok(digest.finalize().to_vec())
}

fn capture_formation_provider_attempt_identity(
    account_id: &str,
    capture_session_id: &str,
    source_revision: i64,
    page_index: i64,
    page_source_commitment: &[u8],
    provider_attempt: i64,
) -> Vec<u8> {
    let mut digest = Sha256::new();
    digest.update(b"kioku.capture-formation.provider-attempt.v1\0");
    digest.update(account_id.as_bytes());
    digest.update([0]);
    digest.update(capture_session_id.as_bytes());
    digest.update(source_revision.to_be_bytes());
    digest.update(page_index.to_be_bytes());
    digest.update(page_source_commitment);
    digest.update(provider_attempt.to_be_bytes());
    digest.finalize().to_vec()
}

fn vertex_attempt_event_id(attempt_identity: &[u8]) -> Result<String> {
    if attempt_identity.len() != 32 {
        return Err(EnclaveError::InvalidRequest(
            "capture formation provider attempt is invalid".into(),
        ));
    }
    let digest = Sha256::digest(
        [
            b"kioku.vertex-invocation-attempt.v1\0".as_slice(),
            attempt_identity,
        ]
        .concat(),
    );
    let mut event_id = String::from("vtx_");
    for byte in digest {
        use std::fmt::Write as _;
        write!(&mut event_id, "{byte:02x}")
            .map_err(|_| EnclaveError::Store("Vertex attempt id formatting failed".into()))?;
    }
    Ok(event_id)
}

async fn ensure_terminal_formation_usage_event(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    account_id: &str,
    event_id: &str,
    provider_request: &CaptureFormationProviderRequest,
) -> Result<()> {
    let caller_anchor = capture_formation_provider_caller_anchor(provider_request)?;
    let expected_fingerprint = crate::persistence::vertex_invocation_fingerprint(
        account_id,
        crate::cp::vertex::VertexOperation::EpisodeSummary,
        &provider_request.model,
        &provider_request.vertex_location,
        &caller_anchor,
    );
    let terminal = sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS(SELECT 1 FROM vertex_usage_events \
          WHERE account_id=$1 AND event_id=$2 AND request_fingerprint=$3 \
            AND operation='episode_summarization' AND requested_model=$4 AND location=$5 \
            AND outcome IN ('metered','usage_missing') AND http_status=200)",
    )
    .bind(account_id)
    .bind(event_id)
    .bind(expected_fingerprint.as_slice())
    .bind(&provider_request.model)
    .bind(&provider_request.vertex_location)
    .fetch_one(&mut **transaction)
    .await?;
    if !terminal {
        return Err(EnclaveError::Conflict(
            "capture formation staged response has no terminal usage event".into(),
        ));
    }
    Ok(())
}

fn capture_formation_page_from_row(row: &sqlx::postgres::PgRow) -> Result<CaptureFormationPage> {
    let provider_request_raw = row.try_get::<Option<String>, _>("provider_request_json")?;
    let provider_request = provider_request_raw
        .as_deref()
        .map(serde_json::from_str::<CaptureFormationProviderRequest>)
        .transpose()?;
    let staged_response = row.try_get::<Option<String>, _>("staged_provider_response")?;
    let page = CaptureFormationPage {
        page_index: row.try_get("page_index")?,
        source_fingerprint: row.try_get("source_fingerprint")?,
        page_source_commitment: row.try_get("page_source_commitment")?,
        covered_utterance_ids: row.try_get("covered_utterance_ids")?,
        covered_screenshot_ids: row.try_get("covered_screenshot_ids")?,
        provider_utterance_ids: row.try_get("provider_utterance_ids")?,
        provider_screenshot_ids: row.try_get("provider_screenshot_ids")?,
        has_more: row.try_get("has_more")?,
        provider_attempt: row.try_get("provider_attempt")?,
        provider_request,
        provider_request_sha256: row.try_get("provider_request_sha256")?,
        staged_provider_response: staged_response,
        staged_response_sha256: row.try_get("staged_response_sha256")?,
        staged_vertex_event_id: row.try_get("staged_vertex_event_id")?,
    };
    let commitment = capture_formation_page_commitment(
        &page.source_fingerprint,
        page.page_index,
        &page.covered_utterance_ids,
        &page.covered_screenshot_ids,
        &page.provider_utterance_ids,
        &page.provider_screenshot_ids,
        page.has_more,
    )?;
    if commitment != page.page_source_commitment {
        return Err(EnclaveError::Store(
            "capture formation page commitment mismatch".into(),
        ));
    }
    match (
        page.provider_request.as_ref(),
        page.provider_request_sha256.as_deref(),
    ) {
        (None, None) => {}
        (Some(request), Some(commitment))
            if Sha256::digest(capture_formation_provider_request_bytes(request)?).as_slice()
                == commitment => {}
        _ => {
            return Err(EnclaveError::Store(
                "capture formation provider request commitment mismatch".into(),
            ))
        }
    }
    if page.staged_provider_response.is_some() && page.provider_request.is_none() {
        return Err(EnclaveError::Store(
            "capture formation staged response has no bound provider request".into(),
        ));
    }
    match (
        page.staged_provider_response.as_deref(),
        page.staged_response_sha256.as_deref(),
        page.staged_vertex_event_id.as_deref(),
    ) {
        (None, None, None) => {}
        (Some(response), Some(commitment), Some(_))
            if Sha256::digest(response.as_bytes()).as_slice() == commitment => {}
        _ => {
            return Err(EnclaveError::Store(
                "capture formation staged response commitment mismatch".into(),
            ))
        }
    }
    Ok(page)
}

async fn create_capture_formation_page(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    account_id: &str,
    capture_session_id: &str,
    source_revision: i64,
    source_fingerprint: &[u8],
    page_index: i64,
) -> Result<CaptureFormationPage> {
    let utterance_rows = sqlx::query(
        "WITH evidence_events AS ( \
             SELECT DISTINCT coalesce(canonical_event_id,event_id) AS event_id \
               FROM capture_events WHERE account_id=$1 AND capture_session_id=$2), \
         evidence AS ( \
             SELECT DISTINCT utterance.id, \
                    floor(extract(epoch FROM coalesce(observation.started_at, \
                         segment.started_at+utterance.start_offset_seconds*interval '1 second'))*1000)::bigint \
                         AS source_ms, \
                    EXISTS(SELECT 1 FROM active_episode_members owner \
                      WHERE owner.account_id=utterance.account_id AND owner.record_type='utterance' \
                        AND owner.record_id=utterance.id) AS active_owned \
               FROM evidence_events event \
               JOIN speaker_observations observation ON observation.account_id=$1 \
                    AND (observation.event_id=event.event_id OR EXISTS( \
                        SELECT 1 FROM speaker_observation_sources source \
                         WHERE source.account_id=observation.account_id \
                           AND source.speaker_observation_id=observation.id \
                           AND source.event_id=event.event_id)) \
               JOIN utterances utterance ON utterance.account_id=observation.account_id \
                    AND utterance.speaker_observation_id=observation.id \
               JOIN audio_segments segment ON segment.account_id=utterance.account_id \
                    AND segment.id=utterance.audio_segment_id) \
         SELECT id,source_ms,active_owned FROM evidence \
          WHERE NOT EXISTS(SELECT 1 FROM capture_formation_pages page \
                 WHERE page.account_id=$1 AND page.capture_session_id=$2 \
                   AND page.source_revision=$3 AND id=ANY(page.covered_utterance_ids)) \
          ORDER BY source_ms,id LIMIT $4",
    )
    .bind(account_id)
    .bind(capture_session_id)
    .bind(source_revision)
    .bind(CAPTURE_FORMATION_UTTERANCE_PAGE_SIZE + 1)
    .fetch_all(&mut **transaction)
    .await?;
    let screenshot_rows = sqlx::query(
        "WITH evidence_events AS ( \
             SELECT DISTINCT coalesce(canonical_event_id,event_id) AS event_id \
               FROM capture_events WHERE account_id=$1 AND capture_session_id=$2), \
         evidence AS ( \
             SELECT DISTINCT screenshot.id, \
                    floor(extract(epoch FROM screenshot.captured_at)*1000)::bigint AS source_ms, \
                    EXISTS(SELECT 1 FROM active_episode_members owner \
                      WHERE owner.account_id=screenshot.account_id AND owner.record_type='screenshot' \
                        AND owner.record_id=screenshot.id) AS active_owned \
               FROM evidence_events event JOIN screenshots screenshot \
                 ON screenshot.account_id=$1 \
                AND screenshot.source_key=concat('cloud-v2:',event.event_id)) \
         SELECT id,source_ms,active_owned FROM evidence \
          WHERE NOT EXISTS(SELECT 1 FROM capture_formation_pages page \
                 WHERE page.account_id=$1 AND page.capture_session_id=$2 \
                   AND page.source_revision=$3 AND id=ANY(page.covered_screenshot_ids)) \
          ORDER BY source_ms,id LIMIT $4",
    )
    .bind(account_id)
    .bind(capture_session_id)
    .bind(source_revision)
    .bind(CAPTURE_FORMATION_SCREENSHOT_PAGE_SIZE + 1)
    .fetch_all(&mut **transaction)
    .await?;
    let has_more = i64::try_from(utterance_rows.len()).unwrap_or(i64::MAX)
        > CAPTURE_FORMATION_UTTERANCE_PAGE_SIZE
        || i64::try_from(screenshot_rows.len()).unwrap_or(i64::MAX)
            > CAPTURE_FORMATION_SCREENSHOT_PAGE_SIZE;
    let utterance_rows = utterance_rows
        .into_iter()
        .take(usize::try_from(CAPTURE_FORMATION_UTTERANCE_PAGE_SIZE).unwrap_or(usize::MAX))
        .collect::<Vec<_>>();
    let screenshot_rows = screenshot_rows
        .into_iter()
        .take(usize::try_from(CAPTURE_FORMATION_SCREENSHOT_PAGE_SIZE).unwrap_or(usize::MAX))
        .collect::<Vec<_>>();
    let covered_utterance_ids = utterance_rows
        .iter()
        .map(|row| row.try_get("id"))
        .collect::<std::result::Result<Vec<i64>, _>>()?;
    let covered_screenshot_ids = screenshot_rows
        .iter()
        .map(|row| row.try_get("id"))
        .collect::<std::result::Result<Vec<i64>, _>>()?;
    let provider_utterance_ids = utterance_rows
        .iter()
        .filter_map(|row| match row.try_get::<bool, _>("active_owned") {
            Ok(false) => Some(row.try_get::<i64, _>("id")),
            Ok(true) => None,
            Err(error) => Some(Err(error)),
        })
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let provider_screenshot_ids = screenshot_rows
        .iter()
        .filter_map(|row| match row.try_get::<bool, _>("active_owned") {
            Ok(false) => Some(row.try_get::<i64, _>("id")),
            Ok(true) => None,
            Err(error) => Some(Err(error)),
        })
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let page_source_commitment = capture_formation_page_commitment(
        source_fingerprint,
        page_index,
        &covered_utterance_ids,
        &covered_screenshot_ids,
        &provider_utterance_ids,
        &provider_screenshot_ids,
        has_more,
    )?;
    Ok(CaptureFormationPage {
        page_index,
        source_fingerprint: source_fingerprint.to_vec(),
        page_source_commitment,
        covered_utterance_ids,
        covered_screenshot_ids,
        provider_utterance_ids,
        provider_screenshot_ids,
        has_more,
        provider_attempt: 1,
        provider_request: None,
        provider_request_sha256: None,
        staged_provider_response: None,
        staged_response_sha256: None,
        staged_vertex_event_id: None,
    })
}

fn vector_literal(values: &[f32]) -> Result<String> {
    if values.len() != 384 || values.iter().any(|value| !value.is_finite()) {
        return Err(EnclaveError::Store(
            "episode embedding must contain 384 finite values".into(),
        ));
    }
    let mut output = String::with_capacity(values.len() * 12 + 2);
    output.push('[');
    for (index, value) in values.iter().enumerate() {
        if index > 0 {
            output.push(',');
        }
        output.push_str(&value.to_string());
    }
    output.push(']');
    Ok(output)
}

fn string_array(raw: Option<String>) -> Vec<String> {
    raw.and_then(|value| serde_json::from_str(&value).ok())
        .unwrap_or_default()
}

async fn capture_formation_contract_installed(connection: &mut sqlx::PgConnection) -> Result<bool> {
    Ok(
        sqlx::query_scalar("SELECT to_regclass('capture_formation_receipts') IS NOT NULL")
            .fetch_one(connection)
            .await?,
    )
}

pub(super) async fn invalidate_reconciliation_neighborhood_scan(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    account_id: &str,
) -> Result<()> {
    sqlx::query(
        "DELETE FROM persistence_feature_reconciliation_neighborhood_scans \
          WHERE account_id=$1",
    )
    .bind(account_id)
    .execute(&mut **transaction)
    .await?;
    Ok(())
}

async fn capture_session_is_formation_ready(
    connection: &mut sqlx::PgConnection,
    account_id: &str,
    capture_session_id: &str,
) -> Result<bool> {
    Ok(sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM capture_sessions session \
                  JOIN capture_formation_receipts receipt \
                    ON receipt.account_id=session.account_id \
                   AND receipt.capture_session_id=session.id \
                  JOIN accounts account ON account.id=session.account_id \
                 WHERE session.account_id=$1 AND session.id=$2 \
                   AND session.ended_at IS NOT NULL \
                   AND receipt.finish_requested_at IS NOT NULL \
                   AND receipt.finish_requested_at<=clock_timestamp()-make_interval(secs=>$7) \
                   AND account.summarized_until>=greatest(session.last_event_at, \
                       coalesce(session.ended_at,session.last_event_at), \
                       coalesce((SELECT max(event.ended_at) FROM capture_events event \
                                 WHERE event.account_id=session.account_id \
                                   AND event.capture_session_id=session.id), \
                                session.last_event_at))) \
          AND EXISTS(SELECT 1 FROM capture_streams stream \
                        WHERE stream.account_id=$1 AND stream.capture_session_id=$2) \
          AND NOT EXISTS(SELECT 1 FROM capture_streams stream \
                        WHERE stream.account_id=$1 AND stream.capture_session_id=$2 \
                          AND (stream.committed_through_sequence IS DISTINCT FROM \
                                  capture_formation_stream_accepted_max( \
                                      stream.account_id,stream.id) \
                               OR capture_formation_stream_contiguous_through( \
                                      stream.account_id,stream.id) IS DISTINCT FROM \
                                  stream.committed_through_sequence \
                               OR (stream.sealed_sequence IS NOT NULL \
                                   AND stream.sealed_sequence<>stream.committed_through_sequence))) \
          AND NOT EXISTS(SELECT 1 FROM capture_events event \
                        WHERE event.account_id=$1 AND event.capture_session_id=$2 \
                          AND event.received_at>clock_timestamp()-make_interval(secs=>$7)) \
          AND NOT EXISTS(SELECT 1 FROM capture_events event \
                        WHERE event.account_id=$1 AND event.capture_session_id=$2 \
                          AND event.media_disposition='canonical' \
                          AND NOT EXISTS(SELECT 1 FROM media_processing_jobs job \
                                WHERE job.account_id=event.account_id \
                                  AND job.event_id=event.event_id)) \
          AND NOT EXISTS(SELECT 1 FROM capture_events event \
                    JOIN media_processing_jobs job \
                      ON job.account_id=event.account_id AND job.event_id=event.event_id \
                   WHERE event.account_id=$1 AND event.capture_session_id=$2 \
                     AND (job.updated_at>clock_timestamp()-make_interval(secs=>$7) \
                          OR (job.state NOT IN ('succeeded','canceled') \
                              AND (job.state<>'failed_terminal' OR ( \
                                   job.processor_version=$3 \
                                   AND NOT (coalesce(job.error_code,'')=ANY($4::text[])) \
                                   AND job.attempt_count<$5 \
                                   AND event.started_at>=clock_timestamp()-make_interval(secs=>$6)))))) \
          AND NOT EXISTS(SELECT 1 FROM capture_events event \
                    JOIN media_objects object \
                      ON object.account_id=event.account_id AND object.event_id=event.event_id \
                   WHERE event.account_id=$1 AND event.capture_session_id=$2 \
                     AND object.deleted_at IS NULL \
                     AND object.processing_state IN ('queued','processing','retry_wait'))",
    )
    .bind(account_id)
    .bind(capture_session_id)
    .bind(PROCESSOR_VERSION)
    .bind(NON_RESURRECTABLE_MEDIA_ERROR_CODES.as_slice())
    .bind(RESURRECTION_TOTAL_ATTEMPT_CAP)
    .bind(RESURRECTION_WINDOW_SECONDS_INTEGRAL as f64)
    .bind(CAPTURE_FORMATION_QUIET_SECONDS as f64)
    .fetch_one(connection)
    .await?)
}

/// Once the signed draining transition has established that no predecessor
/// binary remains, historical `ended_at` is durable old-client finish intent.
/// Import it only as a provisional request: late sources remain admissible,
/// and the ordinary four-hour sealer below is still the sole authority that
/// can make stream boundaries immutable. Re-running this bounded sweep is the
/// recovery path for rows missed by a crash or startup ordering.
async fn import_legacy_provisional_finishes(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    account_id: &str,
) -> Result<u64> {
    let predecessor_drained = sqlx::query_scalar::<_, bool>(
        "SELECT coalesce((SELECT phase IN ('draining','active','paused') \
            FROM persistence_feature_activation_events \
           WHERE feature='episode_topology_reconciliation' \
           ORDER BY generation DESC LIMIT 1),false)",
    )
    .fetch_one(&mut **transaction)
    .await?;
    if !predecessor_drained {
        return Ok(0);
    }
    let capture_session_ids = sqlx::query_scalar::<_, String>(
        "SELECT receipt.capture_session_id \
           FROM capture_formation_receipts receipt \
           JOIN capture_sessions session ON session.account_id=receipt.account_id \
                AND session.id=receipt.capture_session_id \
          WHERE receipt.account_id=$1 AND session.ended_at IS NOT NULL \
            AND receipt.finish_requested_at IS NULL AND receipt.seal_finalized_at IS NULL \
          ORDER BY session.ended_at,receipt.capture_session_id \
          LIMIT $2 FOR UPDATE OF receipt,session SKIP LOCKED",
    )
    .bind(account_id)
    .bind(CAPTURE_SEAL_BATCH_SIZE)
    .fetch_all(&mut **transaction)
    .await?;
    if capture_session_ids.is_empty() {
        return Ok(0);
    }
    Ok(sqlx::query(
        "UPDATE capture_formation_receipts receipt \
            SET finish_requested_at=session.ended_at, \
                finish_request_provenance='legacy_ended_v1',updated_at=clock_timestamp() \
           FROM capture_sessions session \
          WHERE receipt.account_id=$1 AND receipt.capture_session_id=ANY($2::text[]) \
            AND session.account_id=receipt.account_id AND session.id=receipt.capture_session_id \
            AND session.ended_at IS NOT NULL \
            AND receipt.finish_requested_at IS NULL AND receipt.seal_finalized_at IS NULL",
    )
    .bind(account_id)
    .bind(&capture_session_ids)
    .execute(&mut **transaction)
    .await?
    .rows_affected())
}

/// Finalize provisional stream boundaries in a bounded batch. Candidate
/// readiness is filtered before LIMIT, preventing old ambiguous sessions from
/// starving a newer provably quiet session. All capture/media writers share
/// the caller's account reconciliation lock, so the per-stream maxima remain
/// stable through the atomic seal and audit update.
async fn finalize_quiet_capture_seals(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    account_id: &str,
) -> Result<u64> {
    // A schema-26 predecessor does not understand the v27 seal/reopen audit
    // and can still accept a late event without dirtying the receipt. Never
    // create the first immutable boundary during the mixed-fleet `installed`
    // phase. The signed draining transition proves predecessors are gone;
    // its bounded refresh then repairs any dark-period source changes before
    // this recurring sealer becomes authoritative.
    let predecessor_drained = sqlx::query_scalar::<_, bool>(
        "SELECT coalesce((SELECT phase IN ('draining','active','paused') \
            FROM persistence_feature_activation_events \
           WHERE feature='episode_topology_reconciliation' \
           ORDER BY generation DESC LIMIT 1),false)",
    )
    .fetch_one(&mut **transaction)
    .await?;
    if !predecessor_drained {
        return Ok(0);
    }
    let candidates = sqlx::query_scalar::<_, String>(
        "SELECT receipt.capture_session_id \
           FROM capture_formation_receipts receipt \
           JOIN capture_sessions session ON session.account_id=receipt.account_id \
                AND session.id=receipt.capture_session_id \
          WHERE receipt.account_id=$1 AND receipt.finish_requested_at IS NOT NULL \
            AND receipt.seal_finalized_at IS NULL AND session.ended_at IS NOT NULL \
            AND receipt.finish_requested_at<=clock_timestamp()-make_interval(secs=>$6) \
            AND EXISTS(SELECT 1 FROM capture_streams stream \
                        WHERE stream.account_id=receipt.account_id \
                          AND stream.capture_session_id=receipt.capture_session_id) \
            AND NOT EXISTS(SELECT 1 FROM capture_streams stream \
                        WHERE stream.account_id=receipt.account_id \
                          AND stream.capture_session_id=receipt.capture_session_id \
                          AND (stream.committed_through_sequence IS DISTINCT FROM \
                                   capture_formation_stream_accepted_max( \
                                       stream.account_id,stream.id) \
                               OR capture_formation_stream_contiguous_through( \
                                       stream.account_id,stream.id) IS DISTINCT FROM \
                                  stream.committed_through_sequence \
                               OR (stream.sealed_sequence IS NOT NULL \
                                   AND stream.sealed_sequence IS DISTINCT FROM \
                                       stream.committed_through_sequence))) \
            AND NOT EXISTS(SELECT 1 FROM capture_events event \
                        WHERE event.account_id=receipt.account_id \
                          AND event.capture_session_id=receipt.capture_session_id \
                          AND event.received_at>clock_timestamp()-make_interval(secs=>$6)) \
            AND NOT EXISTS(SELECT 1 FROM capture_events event \
                        WHERE event.account_id=receipt.account_id \
                          AND event.capture_session_id=receipt.capture_session_id \
                          AND event.media_disposition='canonical' \
                          AND NOT EXISTS(SELECT 1 FROM media_processing_jobs job \
                                WHERE job.account_id=event.account_id \
                                  AND job.event_id=event.event_id)) \
            AND NOT EXISTS(SELECT 1 FROM capture_events event \
                        JOIN media_processing_jobs job ON job.account_id=event.account_id \
                             AND job.event_id=event.event_id \
                       WHERE event.account_id=receipt.account_id \
                         AND event.capture_session_id=receipt.capture_session_id \
                         AND (job.updated_at>clock_timestamp()-make_interval(secs=>$6) \
                              OR (job.state NOT IN ('succeeded','canceled') \
                                  AND (job.state<>'failed_terminal' OR ( \
                                       job.processor_version=$2 \
                                       AND NOT (coalesce(job.error_code,'')=ANY($3::text[])) \
                                       AND job.attempt_count<$4 \
                                       AND event.started_at>=clock_timestamp()-make_interval(secs=>$5)))))) \
            AND NOT EXISTS(SELECT 1 FROM capture_events event \
                        JOIN media_objects object ON object.account_id=event.account_id \
                             AND object.event_id=event.event_id \
                       WHERE event.account_id=receipt.account_id \
                         AND event.capture_session_id=receipt.capture_session_id \
                         AND object.deleted_at IS NULL \
                         AND object.processing_state IN ('queued','processing','retry_wait')) \
          ORDER BY receipt.finish_requested_at,receipt.capture_session_id \
          LIMIT $7 FOR UPDATE OF receipt,session SKIP LOCKED",
    )
    .bind(account_id)
    .bind(PROCESSOR_VERSION)
    .bind(NON_RESURRECTABLE_MEDIA_ERROR_CODES.as_slice())
    .bind(RESURRECTION_TOTAL_ATTEMPT_CAP)
    .bind(RESURRECTION_WINDOW_SECONDS_INTEGRAL as f64)
    .bind(CAPTURE_SEAL_QUIET_SECONDS as f64)
    .bind(CAPTURE_SEAL_BATCH_SIZE)
    .fetch_all(&mut **transaction)
    .await?;
    let mut finalized = 0_u64;
    for capture_session_id in candidates {
        let receipt = sqlx::query(
            "SELECT source_revision,seal_generation,finish_request_provenance \
               FROM capture_formation_receipts \
              WHERE account_id=$1 AND capture_session_id=$2 \
                AND finish_requested_at IS NOT NULL AND seal_finalized_at IS NULL \
              FOR UPDATE",
        )
        .bind(account_id)
        .bind(&capture_session_id)
        .fetch_optional(&mut **transaction)
        .await?
        .ok_or_else(|| EnclaveError::Conflict("capture seal candidate lost its receipt".into()))?;
        let source_revision: i64 = receipt.try_get("source_revision")?;
        let prior_generation: i64 = receipt.try_get("seal_generation")?;
        let next_generation = prior_generation
            .checked_add(1)
            .ok_or_else(|| EnclaveError::Store("capture seal generation overflowed".into()))?;
        let finish_request_provenance: String = receipt.try_get("finish_request_provenance")?;
        let finalization_provenance = if matches!(
            finish_request_provenance.as_str(),
            "legacy_client_refinish_v1" | "legacy_ended_v1"
        ) {
            "legacy_quiet_contiguous_v1"
        } else {
            "quiet_contiguous_v1"
        };
        let streams = sqlx::query(
            "SELECT stream.id,stream.committed_through_sequence,stream.sealed_sequence, \
                    capture_formation_stream_accepted_max(stream.account_id,stream.id) \
                        AS maximum_sequence, \
                    capture_formation_stream_contiguous_through(stream.account_id,stream.id) \
                        AS contiguous_through \
               FROM capture_streams stream \
              WHERE stream.account_id=$1 AND stream.capture_session_id=$2 \
              ORDER BY stream.id FOR UPDATE",
        )
        .bind(account_id)
        .bind(&capture_session_id)
        .fetch_all(&mut **transaction)
        .await?;
        if streams.is_empty() {
            return Err(EnclaveError::Conflict(
                "capture stream changed during quiet seal finalization".into(),
            ));
        }
        for stream in &streams {
            let stream_id: String = stream.try_get("id")?;
            let maximum: Option<i64> = stream.try_get("maximum_sequence")?;
            let contiguous: i64 = stream.try_get("contiguous_through")?;
            let committed: i64 = stream.try_get("committed_through_sequence")?;
            let Some(maximum) =
                maximum.filter(|maximum| *maximum == committed && *maximum == contiguous)
            else {
                return Err(EnclaveError::Conflict(
                    "capture stream changed during quiet seal finalization".into(),
                ));
            };
            let existing_seal: Option<i64> = stream.try_get("sealed_sequence")?;
            if existing_seal.is_some_and(|seal| seal != maximum) {
                return Err(EnclaveError::Conflict(
                    "capture stream contains a stale legacy seal boundary".into(),
                ));
            }
            let changed = sqlx::query(
                "UPDATE capture_streams SET sealed_sequence=$3 \
                  WHERE account_id=$1 AND id=$2 \
                    AND (sealed_sequence IS NULL OR sealed_sequence=$3) \
                    AND committed_through_sequence=$3 \
                    AND capture_formation_stream_accepted_max(account_id,id)=$3 \
                    AND capture_formation_stream_contiguous_through(account_id,id)=$3",
            )
            .bind(account_id)
            .bind(&stream_id)
            .bind(maximum)
            .execute(&mut **transaction)
            .await?
            .rows_affected();
            if changed != 1 {
                return Err(EnclaveError::Conflict(
                    "capture stream seal lost its authority".into(),
                ));
            }
        }
        let stream_maxima_sha256 = sqlx::query_scalar::<_, Vec<u8>>(
            "SELECT capture_formation_stream_maxima_sha256($1,$2)",
        )
        .bind(account_id)
        .bind(&capture_session_id)
        .fetch_one(&mut **transaction)
        .await?;
        if stream_maxima_sha256.len() != 32 {
            return Err(EnclaveError::Store(
                "capture stream maxima commitment is malformed".into(),
            ));
        }
        let inserted = sqlx::query(
            "INSERT INTO capture_formation_seal_events( \
                 account_id,capture_session_id,seal_generation,source_revision,event_kind, \
                 trigger_event_id,stream_maxima_sha256,provenance) \
             VALUES($1,$2,$3,$4,'seal',NULL,$5,$6)",
        )
        .bind(account_id)
        .bind(&capture_session_id)
        .bind(next_generation)
        .bind(source_revision)
        .bind(stream_maxima_sha256)
        .bind(finalization_provenance)
        .execute(&mut **transaction)
        .await?
        .rows_affected();
        if inserted != 1 {
            return Err(EnclaveError::Conflict(
                "capture seal lost its append-only audit claim".into(),
            ));
        }
        let changed = sqlx::query(
            "UPDATE capture_formation_receipts SET seal_finalized_at=clock_timestamp(), \
                    seal_generation=$3,seal_finalization_provenance=$4, \
                    updated_at=clock_timestamp() \
              WHERE account_id=$1 AND capture_session_id=$2 \
                AND finish_requested_at IS NOT NULL AND seal_finalized_at IS NULL \
                AND seal_generation=$5 AND source_revision=$6",
        )
        .bind(account_id)
        .bind(&capture_session_id)
        .bind(next_generation)
        .bind(finalization_provenance)
        .bind(prior_generation)
        .bind(source_revision)
        .execute(&mut **transaction)
        .await?
        .rows_affected();
        if changed != 1 {
            return Err(EnclaveError::Conflict(
                "capture seal audit receipt lost its authority".into(),
            ));
        }
        invalidate_reconciliation_neighborhood_scan(transaction, account_id).await?;
        finalized += 1;
    }
    Ok(finalized)
}

const CAPTURE_FORMATION_FINGERPRINT_EVENT_PAGE_SIZE: i64 = 128;
const CAPTURE_FORMATION_FINGERPRINT_PROJECTION_PAGE_SIZE: i64 = 512;

#[derive(Clone, Debug)]
struct CaptureFormationFingerprintEvent {
    row_kind: i16,
    event_id: String,
    stream_id: String,
    sequence: i64,
    manifest_digest: String,
    deletion_episode_id: Option<i64>,
    deletion_provenance: Option<String>,
    media_disposition: Option<String>,
    canonical_event_id: Option<String>,
    evidence_event_id: Option<String>,
}

/// Canonical source-fingerprint framing. Every variable-width value is
/// length-prefixed; optional values add an explicit 0/1 marker, so NULL and
/// the empty string can never collide. Integers are fixed-width big-endian.
fn capture_formation_fingerprint_frame(digest: &mut Sha256, value: &[u8]) {
    digest.update(u64::try_from(value.len()).unwrap_or(u64::MAX).to_be_bytes());
    digest.update(value);
}

fn capture_formation_fingerprint_optional_text(digest: &mut Sha256, value: Option<&str>) {
    match value {
        None => digest.update([0]),
        Some(value) => {
            digest.update([1]);
            capture_formation_fingerprint_frame(digest, value.as_bytes());
        }
    }
}

fn capture_formation_fingerprint_optional_i64(digest: &mut Sha256, value: Option<i64>) {
    match value {
        None => digest.update([0]),
        Some(value) => {
            digest.update([1]);
            digest.update(value.to_be_bytes());
        }
    }
}

fn capture_formation_fingerprint_event_start(
    digest: &mut Sha256,
    event: &CaptureFormationFingerprintEvent,
) -> Result<()> {
    let row_kind = u8::try_from(event.row_kind).map_err(|_| {
        EnclaveError::Store("capture formation fingerprint row kind is invalid".into())
    })?;
    if row_kind > 1 {
        return Err(EnclaveError::Store(
            "capture formation fingerprint row kind is invalid".into(),
        ));
    }
    digest.update([0x01, row_kind]);
    capture_formation_fingerprint_frame(digest, event.event_id.as_bytes());
    capture_formation_fingerprint_frame(digest, event.stream_id.as_bytes());
    digest.update(event.sequence.to_be_bytes());
    capture_formation_fingerprint_frame(digest, event.manifest_digest.as_bytes());
    capture_formation_fingerprint_optional_i64(digest, event.deletion_episode_id);
    capture_formation_fingerprint_optional_text(digest, event.deletion_provenance.as_deref());
    capture_formation_fingerprint_optional_text(digest, event.media_disposition.as_deref());
    capture_formation_fingerprint_optional_text(digest, event.canonical_event_id.as_deref());
    capture_formation_fingerprint_optional_text(digest, event.evidence_event_id.as_deref());
    Ok(())
}

fn capture_formation_fingerprint_event_end(digest: &mut Sha256, projection_count: u64) {
    digest.update([0x02]);
    digest.update(projection_count.to_be_bytes());
}

fn capture_formation_fingerprint_projection(
    digest: &mut Sha256,
    row: &sqlx::postgres::PgRow,
) -> Result<()> {
    let record_type: String = row.try_get("record_type")?;
    digest.update([0x10]);
    capture_formation_fingerprint_frame(digest, record_type.as_bytes());
    digest.update(row.try_get::<i64, _>("record_id")?.to_be_bytes());
    digest.update([u8::from(row.try_get::<bool, _>("active_owned")?)]);
    match record_type.as_str() {
        "screenshot" => {
            digest.update(row.try_get::<i64, _>("captured_at_ms")?.to_be_bytes());
            capture_formation_fingerprint_optional_text(
                digest,
                row.try_get::<Option<String>, _>("active_app")?.as_deref(),
            );
            capture_formation_fingerprint_optional_text(
                digest,
                row.try_get::<Option<String>, _>("window_title")?.as_deref(),
            );
            capture_formation_fingerprint_optional_text(
                digest,
                row.try_get::<Option<String>, _>("ocr_text")?.as_deref(),
            );
            capture_formation_fingerprint_optional_text(
                digest,
                row.try_get::<Option<String>, _>("salient_ocr_text")?
                    .as_deref(),
            );
            capture_formation_fingerprint_optional_text(
                digest,
                row.try_get::<Option<String>, _>("url")?.as_deref(),
            );
            digest.update([u8::from(row.try_get::<bool, _>("is_duplicate")?)]);
            capture_formation_fingerprint_frame(
                digest,
                row.try_get::<String, _>("source_key")?.as_bytes(),
            );
        }
        "utterance" => {
            digest.update(row.try_get::<i64, _>("started_at_ms")?.to_be_bytes());
            digest.update(row.try_get::<i64, _>("ended_at_ms")?.to_be_bytes());
            capture_formation_fingerprint_frame(
                digest,
                row.try_get::<String, _>("speaker_label")?.as_bytes(),
            );
            capture_formation_fingerprint_optional_text(
                digest,
                row.try_get::<Option<String>, _>("language")?.as_deref(),
            );
            capture_formation_fingerprint_frame(
                digest,
                row.try_get::<String, _>("utterance_text")?.as_bytes(),
            );
        }
        _ => {
            return Err(EnclaveError::Store(
                "capture formation fingerprint projection type is invalid".into(),
            ))
        }
    }
    Ok(())
}

async fn capture_formation_fingerprint_event_batch(
    connection: &mut sqlx::PgConnection,
    account_id: &str,
    events: &[CaptureFormationFingerprintEvent],
    digest: &mut Sha256,
) -> Result<()> {
    let mut event_ordinals = Vec::new();
    let mut evidence_event_ids = Vec::new();
    for (ordinal, event) in events.iter().enumerate() {
        if let Some(evidence_event_id) = event.evidence_event_id.as_ref() {
            event_ordinals.push(i64::try_from(ordinal).map_err(|_| {
                EnclaveError::Store("capture formation event page index overflowed".into())
            })?);
            evidence_event_ids.push(evidence_event_id.clone());
        }
    }

    let mut next_event = 0usize;
    let mut open_event = None;
    let mut projection_count = 0_u64;
    let mut cursor_ordinal = None;
    let mut cursor_record_type: Option<String> = None;
    let mut cursor_record_id = i64::MIN;
    if !event_ordinals.is_empty() {
        loop {
            let rows = sqlx::query(
                "WITH input(event_ordinal,evidence_event_id) AS ( \
                     SELECT * FROM unnest($2::bigint[],$3::text[]) \
                 ), projected AS ( \
                     SELECT input.event_ordinal,'screenshot'::text AS record_type, \
                            screenshot.id AS record_id, \
                            EXISTS(SELECT 1 FROM active_episode_members owner \
                              WHERE owner.account_id=screenshot.account_id \
                                AND owner.record_type='screenshot' \
                                AND owner.record_id=screenshot.id) AS active_owned, \
                            NULL::bigint AS started_at_ms,NULL::bigint AS ended_at_ms, \
                            NULL::text AS speaker_label,NULL::text AS language, \
                            NULL::text AS utterance_text, \
                            floor(extract(epoch FROM screenshot.captured_at)*1000)::bigint \
                                AS captured_at_ms, \
                            screenshot.active_app,screenshot.window_title,screenshot.ocr_text, \
                            screenshot.salient_ocr_text,screenshot.url,screenshot.is_duplicate, \
                            screenshot.source_key \
                       FROM input JOIN screenshots screenshot \
                         ON screenshot.account_id=$1 \
                        AND screenshot.source_key=concat('cloud-v2:',input.evidence_event_id) \
                      UNION ALL \
                     SELECT input.event_ordinal,'utterance'::text,utterance.id, \
                            EXISTS(SELECT 1 FROM active_episode_members owner \
                              WHERE owner.account_id=utterance.account_id \
                                AND owner.record_type='utterance' \
                                AND owner.record_id=utterance.id), \
                            floor(extract(epoch FROM observation.started_at)*1000)::bigint, \
                            floor(extract(epoch FROM observation.ended_at)*1000)::bigint, \
                            utterance.speaker_label,utterance.language,utterance.text, \
                            NULL::bigint,NULL::text,NULL::text,NULL::text,NULL::text,NULL::text, \
                            NULL::boolean,NULL::text \
                       FROM input JOIN speaker_observations observation \
                         ON observation.account_id=$1 \
                        AND (observation.event_id=input.evidence_event_id OR EXISTS( \
                            SELECT 1 FROM speaker_observation_sources source \
                             WHERE source.account_id=observation.account_id \
                               AND source.speaker_observation_id=observation.id \
                               AND source.event_id=input.evidence_event_id)) \
                       JOIN utterances utterance ON utterance.account_id=observation.account_id \
                            AND utterance.speaker_observation_id=observation.id \
                 ) SELECT event_ordinal,record_type,record_id,active_owned, \
                          started_at_ms,ended_at_ms,speaker_label,language,utterance_text, \
                          captured_at_ms,active_app,window_title,ocr_text,salient_ocr_text,url, \
                          is_duplicate,source_key \
                    FROM projected \
                    WHERE $4::bigint IS NULL OR \
                          (event_ordinal,record_type,record_id)> \
                          ($4::bigint,$5::text,$6::bigint) \
                    ORDER BY event_ordinal,record_type,record_id LIMIT $7",
            )
            .bind(account_id)
            .bind(&event_ordinals)
            .bind(&evidence_event_ids)
            .bind(cursor_ordinal)
            .bind(cursor_record_type.as_deref())
            .bind(cursor_record_id)
            .bind(CAPTURE_FORMATION_FINGERPRINT_PROJECTION_PAGE_SIZE)
            .fetch_all(&mut *connection)
            .await?;
            let row_count = rows.len();
            for row in &rows {
                let ordinal_i64: i64 = row.try_get("event_ordinal")?;
                let ordinal = usize::try_from(ordinal_i64).map_err(|_| {
                    EnclaveError::Store(
                        "capture formation projection event index is invalid".into(),
                    )
                })?;
                if ordinal >= events.len() || open_event.is_some_and(|open| ordinal < open) {
                    return Err(EnclaveError::Store(
                        "capture formation projection order is invalid".into(),
                    ));
                }
                if open_event != Some(ordinal) {
                    if let Some(open) = open_event.take() {
                        capture_formation_fingerprint_event_end(digest, projection_count);
                        next_event = open + 1;
                    }
                    if ordinal < next_event {
                        return Err(EnclaveError::Store(
                            "capture formation projection order regressed".into(),
                        ));
                    }
                    while next_event < ordinal {
                        capture_formation_fingerprint_event_start(digest, &events[next_event])?;
                        capture_formation_fingerprint_event_end(digest, 0);
                        next_event += 1;
                    }
                    capture_formation_fingerprint_event_start(digest, &events[ordinal])?;
                    open_event = Some(ordinal);
                    projection_count = 0;
                }
                capture_formation_fingerprint_projection(digest, row)?;
                projection_count = projection_count.checked_add(1).ok_or_else(|| {
                    EnclaveError::Store("capture formation projection count overflowed".into())
                })?;
                cursor_ordinal = Some(ordinal_i64);
                cursor_record_type = Some(row.try_get("record_type")?);
                cursor_record_id = row.try_get("record_id")?;
            }
            if row_count
                < usize::try_from(CAPTURE_FORMATION_FINGERPRINT_PROJECTION_PAGE_SIZE)
                    .unwrap_or(usize::MAX)
            {
                break;
            }
        }
    }
    if let Some(open) = open_event {
        capture_formation_fingerprint_event_end(digest, projection_count);
        next_event = open + 1;
    }
    while next_event < events.len() {
        capture_formation_fingerprint_event_start(digest, &events[next_event])?;
        capture_formation_fingerprint_event_end(digest, 0);
        next_event += 1;
    }
    Ok(())
}

pub(super) async fn capture_formation_source_fingerprint(
    connection: &mut sqlx::PgConnection,
    account_id: &str,
    capture_session_id: &str,
    source_revision: i64,
) -> Result<Vec<u8>> {
    let mut digest = Sha256::new();
    digest.update(b"kioku.capture-formation.source.v3\0");
    capture_formation_fingerprint_frame(&mut digest, account_id.as_bytes());
    capture_formation_fingerprint_frame(&mut digest, capture_session_id.as_bytes());
    digest.update(source_revision.to_be_bytes());

    let mut cursor_stream_id: Option<String> = None;
    let mut cursor_sequence = i64::MIN;
    let mut cursor_event_id: Option<String> = None;
    let mut cursor_row_kind = -1_i16;
    let mut event_count = 0_u64;
    loop {
        let rows = sqlx::query(
            "WITH exact_event AS ( \
                 SELECT 0::smallint AS row_kind,event.event_id,event.stream_id,event.sequence, \
                        event.manifest_digest,NULL::bigint AS deletion_episode_id, \
                        NULL::text AS deletion_provenance,event.media_disposition, \
                        event.canonical_event_id,coalesce(event.canonical_event_id,event.event_id) \
                            AS evidence_event_id \
                   FROM capture_events event \
                  WHERE event.account_id=$1 AND event.capture_session_id=$2 \
                  UNION ALL \
                 SELECT 1::smallint,deleted.event_id,deleted.stream_id,deleted.sequence, \
                        deleted.original_manifest_digest,deleted.deletion_episode_id, \
                        deleted.provenance,NULL::text,NULL::text,NULL::text \
                   FROM capture_formation_deleted_sequences deleted \
                  WHERE deleted.account_id=$1 AND deleted.capture_session_id=$2 \
             ) SELECT row_kind,event_id,stream_id,sequence,manifest_digest, \
                      deletion_episode_id,deletion_provenance,media_disposition, \
                      canonical_event_id,evidence_event_id \
                FROM exact_event \
                WHERE $3::text IS NULL OR \
                      (stream_id,sequence,event_id,row_kind)> \
                      ($3::text,$4::bigint,$5::text,$6::smallint) \
                ORDER BY stream_id,sequence,event_id,row_kind LIMIT $7",
        )
        .bind(account_id)
        .bind(capture_session_id)
        .bind(cursor_stream_id.as_deref())
        .bind(cursor_sequence)
        .bind(cursor_event_id.as_deref())
        .bind(cursor_row_kind)
        .bind(CAPTURE_FORMATION_FINGERPRINT_EVENT_PAGE_SIZE)
        .fetch_all(&mut *connection)
        .await?;
        let row_count = rows.len();
        let events = rows
            .into_iter()
            .map(|row| {
                Ok(CaptureFormationFingerprintEvent {
                    row_kind: row.try_get("row_kind")?,
                    event_id: row.try_get("event_id")?,
                    stream_id: row.try_get("stream_id")?,
                    sequence: row.try_get("sequence")?,
                    manifest_digest: row.try_get("manifest_digest")?,
                    deletion_episode_id: row.try_get("deletion_episode_id")?,
                    deletion_provenance: row.try_get("deletion_provenance")?,
                    media_disposition: row.try_get("media_disposition")?,
                    canonical_event_id: row.try_get("canonical_event_id")?,
                    evidence_event_id: row.try_get("evidence_event_id")?,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        if let Some(last) = events.last() {
            cursor_stream_id = Some(last.stream_id.clone());
            cursor_sequence = last.sequence;
            cursor_event_id = Some(last.event_id.clone());
            cursor_row_kind = last.row_kind;
        }
        event_count = event_count
            .checked_add(u64::try_from(events.len()).unwrap_or(u64::MAX))
            .ok_or_else(|| {
                EnclaveError::Store("capture formation fingerprint event count overflowed".into())
            })?;
        capture_formation_fingerprint_event_batch(connection, account_id, &events, &mut digest)
            .await?;
        if row_count
            < usize::try_from(CAPTURE_FORMATION_FINGERPRINT_EVENT_PAGE_SIZE).unwrap_or(usize::MAX)
        {
            break;
        }
    }
    digest.update([0xff]);
    digest.update(event_count.to_be_bytes());
    Ok(digest.finalize().to_vec())
}

/// Refresh one session selected by a durable bounded source mutation/backfill.
/// The caller holds the activation contract row first (FOR UPDATE for a
/// transition or KEY SHARE for an ordinary writer), then the account
/// reconciliation lock when topology may change. Missing rows are inserted,
/// while a completed revision is recomputed using the exact claim fingerprint
/// and reopened only when its source projection became stale. A deletion can
/// also invalidate a finalized, tombstone-bound seal while formation is still
/// pending; the append-only seal commitment detects and repairs that case
/// without spuriously rotating unchanged pending receipts during backfill.
pub(super) async fn refresh_capture_formation_receipt(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    account_id: &str,
    capture_session_id: &str,
) -> Result<bool> {
    let inserted = sqlx::query(
        "INSERT INTO capture_formation_receipts( \
             account_id,capture_session_id,source_revision,completed_revision,state) \
         SELECT session.account_id,session.id,1,0,'pending' FROM capture_sessions session \
          WHERE session.account_id=$1 AND session.id=$2 \
         ON CONFLICT(account_id,capture_session_id) DO NOTHING",
    )
    .bind(account_id)
    .bind(capture_session_id)
    .execute(&mut **transaction)
    .await?
    .rows_affected()
        == 1;
    if inserted {
        invalidate_reconciliation_neighborhood_scan(transaction, account_id).await?;
        return Ok(true);
    }
    let receipt = sqlx::query(
        "SELECT state,source_revision,completed_source_fingerprint, \
                seal_finalized_at IS NOT NULL AS seal_finalized,seal_generation \
           FROM capture_formation_receipts \
          WHERE account_id=$1 AND capture_session_id=$2 FOR UPDATE",
    )
    .bind(account_id)
    .bind(capture_session_id)
    .fetch_optional(&mut **transaction)
    .await?
    .ok_or(EnclaveError::NotFound)?;
    let state: String = receipt.try_get("state")?;
    let source_revision: i64 = receipt.try_get("source_revision")?;
    let completed_fingerprint: Option<Vec<u8>> = receipt.try_get("completed_source_fingerprint")?;
    let completed_source_changed = if state == "complete" {
        let completed_fingerprint = completed_fingerprint.as_ref().ok_or_else(|| {
            EnclaveError::Store("complete capture formation fingerprint is missing".into())
        })?;
        capture_formation_source_fingerprint(
            transaction,
            account_id,
            capture_session_id,
            source_revision,
        )
        .await?
            != *completed_fingerprint
    } else {
        false
    };
    let seal_finalized: bool = receipt.try_get("seal_finalized")?;
    let seal_generation: i64 = receipt.try_get("seal_generation")?;
    let mut topology_rebind = false;
    let mut sealed_contract_changed = false;
    if seal_finalized {
        let seal_state = sqlx::query(
            "SELECT EXISTS(SELECT 1 FROM capture_streams stream \
                      WHERE stream.account_id=$1 AND stream.capture_session_id=$2) \
                    AND NOT EXISTS(SELECT 1 FROM capture_streams stream \
                      WHERE stream.account_id=$1 AND stream.capture_session_id=$2 \
                        AND (stream.committed_through_sequence IS DISTINCT FROM \
                               capture_formation_stream_accepted_max( \
                                   stream.account_id,stream.id) \
                             OR capture_formation_stream_contiguous_through( \
                                   stream.account_id,stream.id) IS DISTINCT FROM \
                                stream.committed_through_sequence \
                             OR stream.sealed_sequence IS DISTINCT FROM \
                                stream.committed_through_sequence)) AS streams_exact, \
                    EXISTS(SELECT 1 FROM capture_formation_seal_events seal \
                      WHERE seal.account_id=$1 AND seal.capture_session_id=$2 \
                        AND seal.seal_generation=$3 AND seal.source_revision=$4 \
                        AND seal.event_kind='seal' \
                        AND NOT EXISTS(SELECT 1 FROM capture_formation_seal_events reopen \
                              WHERE reopen.account_id=seal.account_id \
                                AND reopen.capture_session_id=seal.capture_session_id \
                                AND reopen.seal_generation=seal.seal_generation \
                                AND reopen.event_kind='reopen')) AS prior_seal_present, \
                    EXISTS(SELECT 1 FROM capture_formation_seal_events seal \
                      WHERE seal.account_id=$1 AND seal.capture_session_id=$2 \
                        AND seal.seal_generation=$3 AND seal.source_revision=$4 \
                        AND seal.event_kind='seal' \
                        AND seal.stream_maxima_sha256= \
                            capture_formation_stream_maxima_sha256($1,$2) \
                        AND NOT EXISTS(SELECT 1 FROM capture_formation_seal_events reopen \
                              WHERE reopen.account_id=seal.account_id \
                                AND reopen.capture_session_id=seal.capture_session_id \
                                AND reopen.seal_generation=seal.seal_generation \
                                AND reopen.event_kind='reopen')) AS current_seal_present, \
                    EXISTS(SELECT 1 FROM capture_formation_seal_events seal \
                      JOIN capture_formation_deleted_sequences deleted \
                        ON deleted.account_id=seal.account_id \
                       AND deleted.capture_session_id=seal.capture_session_id \
                       AND deleted.deleted_at>seal.recorded_at \
                     WHERE seal.account_id=$1 AND seal.capture_session_id=$2 \
                       AND seal.seal_generation=$3 AND seal.source_revision=$4 \
                       AND seal.event_kind='seal' \
                       AND NOT EXISTS(SELECT 1 FROM capture_formation_seal_events reopen \
                             WHERE reopen.account_id=seal.account_id \
                               AND reopen.capture_session_id=seal.capture_session_id \
                               AND reopen.seal_generation=seal.seal_generation \
                               AND reopen.event_kind='reopen')) AS deletion_rebind_pending",
        )
        .bind(account_id)
        .bind(capture_session_id)
        .bind(seal_generation)
        .bind(source_revision)
        .fetch_one(&mut **transaction)
        .await?;
        let streams_exact: bool = seal_state.try_get("streams_exact")?;
        let prior_seal_present: bool = seal_state.try_get("prior_seal_present")?;
        let current_seal_present: bool = seal_state.try_get("current_seal_present")?;
        let deletion_rebind_pending: bool = seal_state.try_get("deletion_rebind_pending")?;
        if !prior_seal_present
            || (streams_exact && !current_seal_present && !deletion_rebind_pending)
        {
            return Err(EnclaveError::Conflict(
                "capture formation refresh found an unauditable finalized seal".into(),
            ));
        }
        sealed_contract_changed = !current_seal_present;
        topology_rebind = streams_exact;
    }
    if !completed_source_changed && !sealed_contract_changed {
        return Ok(false);
    }
    let next_source_revision = source_revision
        .checked_add(1)
        .ok_or_else(|| EnclaveError::Store("capture formation revision overflowed".into()))?;
    let reopened = sqlx::query(
        "UPDATE capture_formation_receipts SET source_revision=$5,state='pending', \
                claimed_revision=NULL,claimed_source_fingerprint=NULL,claim_token=NULL, \
                claim_until=NULL,next_attempt_at=NULL,completed_outcome=NULL, \
                completed_claim_token=NULL,completed_source_fingerprint=NULL,completed_at=NULL, \
                seal_finalized_at=CASE WHEN $6 THEN NULL ELSE seal_finalized_at END, \
                seal_finalization_provenance= \
                    CASE WHEN $6 THEN NULL ELSE seal_finalization_provenance END, \
                last_error_code=NULL,updated_at=clock_timestamp() \
          WHERE account_id=$1 AND capture_session_id=$2 AND state=$7 \
            AND source_revision=$3 \
            AND completed_source_fingerprint IS NOT DISTINCT FROM $4",
    )
    .bind(account_id)
    .bind(capture_session_id)
    .bind(source_revision)
    .bind(&completed_fingerprint)
    .bind(next_source_revision)
    .bind(seal_finalized)
    .bind(&state)
    .execute(&mut **transaction)
    .await?
    .rows_affected();
    if reopened != 1 {
        return Err(EnclaveError::Conflict(
            "capture formation refresh lost its activation fence".into(),
        ));
    }
    sqlx::query(
        "UPDATE capture_formation_pages SET state='invalidated',claim_token=NULL,claim_until=NULL, \
                provider_request=NULL,provider_request_sha256=NULL, \
                staged_response=NULL,staged_response_sha256=NULL,staged_vertex_event_id=NULL, \
                last_error_code='source_revision_invalidated',updated_at=clock_timestamp() \
          WHERE account_id=$1 AND capture_session_id=$2 AND source_revision=$3 \
            AND state<>'complete'",
    )
    .bind(account_id)
    .bind(capture_session_id)
    .bind(source_revision)
    .execute(&mut **transaction)
    .await?;
    if seal_finalized && !topology_rebind {
        // The mutable stream boundary is no longer exact. Preserve the old
        // append-only seal event, but remove current readiness and let the
        // ordinary four-hour quiet sealer establish the next exact boundary.
        sqlx::query(
            "UPDATE capture_streams SET sealed_sequence=NULL \
              WHERE account_id=$1 AND capture_session_id=$2 \
                AND sealed_sequence IS NOT NULL",
        )
        .bind(account_id)
        .bind(capture_session_id)
        .execute(&mut **transaction)
        .await?;
    }
    if topology_rebind {
        let next_seal_generation = seal_generation
            .checked_add(1)
            .ok_or_else(|| EnclaveError::Store("capture seal generation overflowed".into()))?;
        let inserted = sqlx::query(
            "INSERT INTO capture_formation_seal_events( \
                 account_id,capture_session_id,seal_generation,source_revision,event_kind, \
                 trigger_event_id,stream_maxima_sha256,provenance) \
             VALUES($1,$2,$3,$4,'seal',NULL, \
                    capture_formation_stream_maxima_sha256($1,$2),'topology_rebind_v1')",
        )
        .bind(account_id)
        .bind(capture_session_id)
        .bind(next_seal_generation)
        .bind(next_source_revision)
        .execute(&mut **transaction)
        .await?
        .rows_affected();
        if inserted != 1 {
            return Err(EnclaveError::Conflict(
                "capture topology refresh lost its append-only seal claim".into(),
            ));
        }
        let rebound = sqlx::query(
            "UPDATE capture_formation_receipts \
                SET seal_generation=$3,seal_finalized_at=clock_timestamp(), \
                    seal_finalization_provenance='topology_rebind_v1', \
                    updated_at=clock_timestamp() \
              WHERE account_id=$1 AND capture_session_id=$2 \
                AND source_revision=$4 AND seal_generation=$5 \
                AND seal_finalized_at IS NULL",
        )
        .bind(account_id)
        .bind(capture_session_id)
        .bind(next_seal_generation)
        .bind(next_source_revision)
        .bind(seal_generation)
        .execute(&mut **transaction)
        .await?
        .rows_affected();
        if rebound != 1 {
            return Err(EnclaveError::Conflict(
                "capture topology refresh lost its seal receipt".into(),
            ));
        }
    }
    invalidate_reconciliation_neighborhood_scan(transaction, account_id).await?;
    Ok(true)
}

/// Bind provider egress and episode membership to live projections outside
/// every pending episode-deletion family. The source resolution mirrors the
/// deletion planner: direct cloud-v2 source keys plus primary/additional
/// speaker observation event IDs are expanded to the canonical capture
/// family before the pending receipt check. Callers hold the activation fence
/// followed by the account reconciliation lock.
async fn ensure_formation_sources_available(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    account_id: &str,
    utterance_ids: &[i64],
    screenshot_ids: &[i64],
) -> Result<()> {
    let state = sqlx::query(
        "WITH requested_utterances(id) AS ( \
             SELECT DISTINCT unnest($2::bigint[])), \
         requested_screenshots(id) AS ( \
             SELECT DISTINCT unnest($3::bigint[])), \
         projection_events(event_id) AS ( \
             SELECT DISTINCT split_part(substr(utterance.source_key,10),':',1) \
               FROM utterances utterance \
              WHERE utterance.account_id=$1 \
                AND utterance.id IN (SELECT id FROM requested_utterances) \
                AND utterance.source_key LIKE 'cloud-v2:%' \
             UNION \
             SELECT DISTINCT substr(screenshot.source_key,10) \
               FROM screenshots screenshot \
              WHERE screenshot.account_id=$1 \
                AND screenshot.id IN (SELECT id FROM requested_screenshots) \
                AND screenshot.source_key LIKE 'cloud-v2:%' \
             UNION \
             SELECT DISTINCT observation.event_id \
               FROM utterances utterance \
               JOIN speaker_observations observation \
                 ON observation.account_id=utterance.account_id \
                AND observation.id=utterance.speaker_observation_id \
              WHERE utterance.account_id=$1 \
                AND utterance.id IN (SELECT id FROM requested_utterances) \
                AND observation.event_id IS NOT NULL \
             UNION \
             SELECT DISTINCT source.event_id \
               FROM utterances utterance \
               JOIN speaker_observation_sources source \
                 ON source.account_id=utterance.account_id \
                AND source.speaker_observation_id=utterance.speaker_observation_id \
              WHERE utterance.account_id=$1 \
                AND utterance.id IN (SELECT id FROM requested_utterances)), \
         capture_family(event_id,canonical_event_id) AS ( \
             SELECT DISTINCT event.event_id, \
                    coalesce(event.canonical_event_id,event.event_id) \
               FROM capture_events event \
              WHERE event.account_id=$1 AND ( \
                    event.event_id IN (SELECT event_id FROM projection_events) \
                    OR event.canonical_event_id IN (SELECT event_id FROM projection_events))) \
         SELECT NOT EXISTS(SELECT 1 FROM requested_utterances requested \
                    LEFT JOIN utterances utterance ON utterance.account_id=$1 \
                         AND utterance.id=requested.id \
                   WHERE utterance.id IS NULL) \
                AND NOT EXISTS(SELECT 1 FROM requested_screenshots requested \
                    LEFT JOIN screenshots screenshot ON screenshot.account_id=$1 \
                         AND screenshot.id=requested.id \
                   WHERE screenshot.id IS NULL) AS sources_exist, \
                NOT EXISTS(SELECT 1 FROM episode_deletions deletion \
                    JOIN capture_family family ON deletion.account_id=$1 \
                     AND (deletion.orphan_event_ids ? family.event_id \
                          OR deletion.orphan_event_ids ? family.canonical_event_id) \
                   WHERE deletion.account_id=$1 AND deletion.state='pending') \
                    AS deletion_clear",
    )
    .bind(account_id)
    .bind(utterance_ids)
    .bind(screenshot_ids)
    .fetch_one(&mut **transaction)
    .await?;
    if !state.try_get::<bool, _>("sources_exist")? {
        return Err(EnclaveError::Conflict(
            "memory formation source disappeared before provider or settlement".into(),
        ));
    }
    if !state.try_get::<bool, _>("deletion_clear")? {
        return Err(EnclaveError::Conflict(
            "memory formation source is pending episode deletion".into(),
        ));
    }
    Ok(())
}

async fn ensure_open_episodes_available(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    account_id: &str,
    episode_ids: &[i64],
) -> Result<()> {
    let available = sqlx::query_scalar::<_, bool>(
        "WITH requested(id) AS (SELECT DISTINCT unnest($2::bigint[])) \
         SELECT NOT EXISTS(SELECT 1 FROM requested \
             LEFT JOIN episodes episode ON episode.account_id=$1 AND episode.id=requested.id \
             LEFT JOIN memory_handles handle ON handle.account_id=episode.account_id \
                  AND handle.episode_id=episode.id AND handle.state='active' \
            WHERE episode.id IS NULL OR handle.episode_id IS NULL \
               OR episode.structure_state<>'draft' OR episode.finalized_at IS NOT NULL \
               OR episode.finalization_claim_token IS NOT NULL \
               OR episode.finalization_status IN ('processing','deleting') \
               OR EXISTS(SELECT 1 FROM episode_deletions deletion \
                    WHERE deletion.account_id=$1 AND deletion.episode_id=requested.id \
                      AND deletion.state='pending'))",
    )
    .bind(account_id)
    .bind(episode_ids)
    .fetch_one(&mut **transaction)
    .await?;
    if !available {
        return Err(EnclaveError::Conflict(
            "summarizer open-episode context changed before provider egress".into(),
        ));
    }
    Ok(())
}

async fn ensure_episode_sources_unowned(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    account_id: &str,
    episodes: &[crate::persistence::EpisodeInput],
) -> Result<()> {
    let utterance_ids = episodes
        .iter()
        .flat_map(|episode| episode.member_utterance_ids.iter().copied())
        .collect::<Vec<_>>();
    let screenshot_ids = episodes
        .iter()
        .flat_map(|episode| episode.member_screenshot_ids.iter().copied())
        .collect::<Vec<_>>();
    ensure_formation_sources_available(transaction, account_id, &utterance_ids, &screenshot_ids)
        .await?;
    let mut assigned = std::collections::BTreeSet::<(&str, i64)>::new();
    for episode in episodes {
        if episode.member_utterance_ids.is_empty() && episode.member_screenshot_ids.is_empty() {
            return Err(EnclaveError::InvalidRequest(
                "formed episode must own at least one evidence source".into(),
            ));
        }
        for (record_type, record_id) in episode
            .member_utterance_ids
            .iter()
            .map(|id| ("utterance", *id))
            .chain(
                episode
                    .member_screenshot_ids
                    .iter()
                    .map(|id| ("screenshot", *id)),
            )
        {
            if !assigned.insert((record_type, record_id)) {
                return Err(EnclaveError::InvalidRequest(
                    "formation assigns one source to multiple episodes".into(),
                ));
            }
            let owner = sqlx::query_scalar::<_, i64>(
                "SELECT episode_id FROM active_episode_members \
                  WHERE account_id=$1 AND record_type=$2 AND record_id=$3",
            )
            .bind(account_id)
            .bind(record_type)
            .bind(record_id)
            .fetch_optional(&mut **transaction)
            .await?;
            if owner.is_some_and(|owner| Some(owner) != episode.id) {
                return Err(EnclaveError::Conflict(
                    "formation evidence acquired a different active owner".into(),
                ));
            }
        }
    }
    Ok(())
}

async fn ensure_capture_episode_sources(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    account_id: &str,
    capture_session_id: &str,
    episodes: &[crate::persistence::EpisodeInput],
) -> Result<()> {
    let utterance_ids = episodes
        .iter()
        .flat_map(|episode| episode.member_utterance_ids.iter().copied())
        .collect::<Vec<_>>();
    let screenshot_ids = episodes
        .iter()
        .flat_map(|episode| episode.member_screenshot_ids.iter().copied())
        .collect::<Vec<_>>();
    let exact = sqlx::query_scalar::<_, bool>(
        "WITH evidence_events AS ( \
             SELECT DISTINCT coalesce(canonical_event_id,event_id) AS event_id \
               FROM capture_events WHERE account_id=$1 AND capture_session_id=$2), \
         evidence_utterances AS ( \
             SELECT DISTINCT utterance.id FROM evidence_events evidence \
               JOIN speaker_observations observation ON observation.account_id=$1 \
                    AND (observation.event_id=evidence.event_id OR EXISTS( \
                        SELECT 1 FROM speaker_observation_sources source \
                         WHERE source.account_id=observation.account_id \
                           AND source.speaker_observation_id=observation.id \
                           AND source.event_id=evidence.event_id)) \
               JOIN utterances utterance ON utterance.account_id=observation.account_id \
                    AND utterance.speaker_observation_id=observation.id), \
         evidence_screenshots AS ( \
             SELECT DISTINCT screenshot.id FROM evidence_events evidence \
               JOIN screenshots screenshot ON screenshot.account_id=$1 \
                    AND screenshot.source_key=concat('cloud-v2:',evidence.event_id)) \
         SELECT NOT EXISTS(SELECT requested.id FROM unnest($3::bigint[]) requested(id) \
                            WHERE NOT EXISTS(SELECT 1 FROM evidence_utterances evidence \
                                              WHERE evidence.id=requested.id)) \
            AND NOT EXISTS(SELECT requested.id FROM unnest($4::bigint[]) requested(id) \
                            WHERE NOT EXISTS(SELECT 1 FROM evidence_screenshots evidence \
                                              WHERE evidence.id=requested.id))",
    )
    .bind(account_id)
    .bind(capture_session_id)
    .bind(&utterance_ids)
    .bind(&screenshot_ids)
    .fetch_one(&mut **transaction)
    .await?;
    if !exact {
        return Err(EnclaveError::Conflict(
            "capture formation settlement assigns evidence outside its exact session".into(),
        ));
    }
    Ok(())
}

async fn capture_session_owner_ids(
    connection: &mut sqlx::PgConnection,
    account_id: &str,
    capture_session_id: &str,
) -> Result<Vec<i64>> {
    Ok(sqlx::query_scalar(
        "WITH evidence_events AS ( \
             SELECT DISTINCT coalesce(canonical_event_id,event_id) AS event_id \
               FROM capture_events WHERE account_id=$1 AND capture_session_id=$2), \
         evidence AS ( \
             SELECT 'utterance'::text AS record_type,utterance.id AS record_id \
               FROM evidence_events event \
               JOIN speaker_observations observation ON observation.account_id=$1 \
                    AND (observation.event_id=event.event_id OR EXISTS( \
                        SELECT 1 FROM speaker_observation_sources source \
                         WHERE source.account_id=observation.account_id \
                           AND source.speaker_observation_id=observation.id \
                           AND source.event_id=event.event_id)) \
               JOIN utterances utterance ON utterance.account_id=observation.account_id \
                    AND utterance.speaker_observation_id=observation.id \
             UNION \
             SELECT 'screenshot',screenshot.id FROM evidence_events event \
               JOIN screenshots screenshot ON screenshot.account_id=$1 \
                    AND screenshot.source_key=concat('cloud-v2:',event.event_id)) \
         SELECT DISTINCT owner.episode_id FROM evidence \
           JOIN active_episode_members owner ON owner.account_id=$1 \
                AND owner.record_type=evidence.record_type AND owner.record_id=evidence.record_id \
          ORDER BY owner.episode_id",
    )
    .bind(account_id)
    .bind(capture_session_id)
    .fetch_all(connection)
    .await?)
}

async fn capture_formation_revision_coverage_complete(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    account_id: &str,
    capture_session_id: &str,
    source_revision: i64,
) -> Result<bool> {
    Ok(sqlx::query_scalar(
        "WITH evidence_events AS ( \
             SELECT DISTINCT coalesce(canonical_event_id,event_id) AS event_id \
               FROM capture_events WHERE account_id=$1 AND capture_session_id=$2), \
         evidence(record_type,record_id) AS ( \
             SELECT DISTINCT 'utterance'::text,utterance.id \
               FROM evidence_events event \
               JOIN speaker_observations observation ON observation.account_id=$1 \
                    AND (observation.event_id=event.event_id OR EXISTS( \
                        SELECT 1 FROM speaker_observation_sources source \
                         WHERE source.account_id=observation.account_id \
                           AND source.speaker_observation_id=observation.id \
                           AND source.event_id=event.event_id)) \
               JOIN utterances utterance ON utterance.account_id=observation.account_id \
                    AND utterance.speaker_observation_id=observation.id \
             UNION \
             SELECT DISTINCT 'screenshot',screenshot.id FROM evidence_events event \
               JOIN screenshots screenshot ON screenshot.account_id=$1 \
                    AND screenshot.source_key=concat('cloud-v2:',event.event_id)), \
         covered(record_type,record_id) AS ( \
             SELECT 'utterance',unnest(page.covered_utterance_ids) \
               FROM capture_formation_pages page WHERE page.account_id=$1 \
                AND page.capture_session_id=$2 AND page.source_revision=$3 AND page.state='complete' \
             UNION ALL \
             SELECT 'screenshot',unnest(page.covered_screenshot_ids) \
               FROM capture_formation_pages page WHERE page.account_id=$1 \
                AND page.capture_session_id=$2 AND page.source_revision=$3 AND page.state='complete'), \
         page_state AS ( \
             SELECT count(*)::bigint AS page_count,min(page_index) AS first_page, \
                    max(page_index) AS last_page, \
                    bool_and(CASE WHEN page_index=(SELECT max(page_index) FROM capture_formation_pages \
                          WHERE account_id=$1 AND capture_session_id=$2 AND source_revision=$3 \
                            AND state='complete') THEN NOT has_more ELSE has_more END) AS boundaries_exact \
               FROM capture_formation_pages WHERE account_id=$1 AND capture_session_id=$2 \
                AND source_revision=$3 AND state='complete') \
         SELECT NOT EXISTS((SELECT * FROM evidence EXCEPT SELECT * FROM covered) \
                           UNION ALL (SELECT * FROM covered EXCEPT SELECT * FROM evidence)) \
            AND page_count>0 AND first_page=0 AND last_page+1=page_count AND boundaries_exact \
           FROM page_state",
    )
    .bind(account_id)
    .bind(capture_session_id)
    .bind(source_revision)
    .fetch_one(&mut **transaction)
    .await?)
}

#[async_trait]
impl MemoryFormationRepository for PostgresPersistence {
    async fn ensure_reviewer_fixture(&self, account_id: &str) -> Result<bool> {
        let mut transaction = self.pool.begin().await?;
        lock_activation_contract_key_share_if_installed(&mut transaction).await?;
        advisory_transaction_lock(&mut transaction, "account-lifecycle", account_id).await?;
        let active = sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS(SELECT 1 FROM accounts WHERE id=$1 AND status='active')",
        )
        .bind(account_id)
        .fetch_one(&mut *transaction)
        .await?;
        if !active {
            return Err(EnclaveError::Auth("account inactive".into()));
        }
        let inserted = sqlx::query_scalar::<_, String>(
            "INSERT INTO reviewer_fixtures(account_id,fixture_version) VALUES($1,1) \
             ON CONFLICT(account_id) DO NOTHING RETURNING account_id",
        )
        .bind(account_id)
        .fetch_optional(&mut *transaction)
        .await?
        .is_some();
        if !inserted {
            transaction.commit().await?;
            return Ok(false);
        }

        sqlx::query(
            "INSERT INTO audio_segments \
                (account_id,id,started_at,ended_at,duration_seconds,source_type,transcription_status) VALUES \
             ($1,910001,'2026-07-22T09:00:00Z','2026-07-22T09:35:00Z',2100,'mic','done'), \
             ($1,910002,'2026-07-22T10:15:00Z','2026-07-22T10:50:00Z',2100,'system','done'), \
             ($1,910003,'2026-07-22T14:00:00Z','2026-07-22T15:00:00Z',3600,'mic','done')",
        )
        .bind(account_id)
        .execute(&mut *transaction)
        .await?;
        sqlx::query(
            "INSERT INTO utterances \
                (account_id,id,audio_segment_id,start_offset_seconds,end_offset_seconds,text,language,confidence,speaker_label,source_key) VALUES \
             ($1,920001,910001,90,104,'We agreed to move the Kioku launch from August 12 to August 19 so QA can finish the release checks.','en',0.99,'Maya','review:launch:decision'), \
             ($1,920002,910001,118,134,'Alex owns the launch checklist and will confirm the migration rehearsal by Friday.','en',0.99,'Maya','review:launch:action'), \
             ($1,920003,910002,240,263,'The stale dashboard came from a cache invalidation bug: the episode detail key was not cleared after an update.','en',0.99,'Me','review:cache:diagnosis'), \
             ($1,920004,910002,284,302,'The fix is to invalidate both the episode list and episode detail cache keys after a successful write.','en',0.99,'Me','review:cache:fix'), \
             ($1,920005,910003,300,326,'Use depuis for an action that began in the past and continues now; depuis is followed by the starting point or duration.','en',0.99,'Camille','review:french:depuis'), \
             ($1,920006,910003,690,714,'Use pendant for a completed duration. Practice contrasting depuis deux ans with pendant deux ans.','en',0.99,'Camille','review:french:pendant')",
        )
        .bind(account_id)
        .execute(&mut *transaction)
        .await?;
        sqlx::query(
            "INSERT INTO screenshots \
                (account_id,id,captured_at,active_app,window_title,ocr_text,salient_ocr_text,url,image_hash,is_duplicate,source_key) VALUES \
             ($1,930001,'2026-07-22T11:20:00Z','Google Chrome','Vendor renewal checklist', \
              'Renewal checklist: review the synthetic agreement at https://example.com/renewal before August 1.', \
              'Renewal checklist at example.com/renewal','https://example.com/renewal', \
              'review-synthetic-renewal',false,'review:screen:renewal')",
        )
        .bind(account_id)
        .execute(&mut *transaction)
        .await?;
        sqlx::query(
            "INSERT INTO episodes \
                (account_id,id,started_at,ended_at,type,title,summary,participants,languages,action_items,model,minute_summaries,minutes_text,substance,visual_evidence,finalized_at,finalization_version,finalization_status) VALUES \
             ($1,940001,'2026-07-22T09:00:00Z','2026-07-22T09:35:00Z','meeting','Launch planning and QA decision', \
              'The team moved the Kioku launch from August 12 to August 19 so QA could complete release checks. Alex owns the launch checklist.', \
              '[\"Maya\",\"Alex\",\"Me\"]','[\"en\"]','[\"Alex: confirm the migration rehearsal by Friday\",\"Complete the launch checklist before August 19\"]','synthetic-review','[]','Reviewed QA readiness. Moved launch to August 19. Assigned the checklist to Alex.','normal','none','2026-07-22T16:00:00Z',3,'complete'), \
             ($1,940002,'2026-07-22T10:15:00Z','2026-07-22T10:50:00Z','coding','Dashboard cache invalidation fix', \
              'Diagnosed stale episode details as an invalidation bug and updated the write path to clear list and detail cache keys.', \
              '[\"Me\"]','[\"en\"]','[\"Add a regression test for episode detail invalidation\"]','synthetic-review','[]','Reproduced stale dashboard state. Found the missing detail-key invalidation. Implemented the cache fix.','normal','none','2026-07-22T16:00:00Z',3,'complete'), \
             ($1,940003,'2026-07-22T11:18:00Z','2026-07-22T11:24:00Z','browsing','Vendor renewal page', \
              'Reviewed a synthetic vendor renewal checklist and its example.com renewal link.', \
              '[\"Me\"]','[\"en\"]','[\"Review the renewal checklist before August 1\"]','synthetic-review','[]','Opened the vendor renewal checklist at example.com/renewal.','normal','useful','2026-07-22T16:00:00Z',3,'complete'), \
             ($1,940004,'2026-07-22T14:00:00Z','2026-07-22T15:00:00Z','lesson','French lesson: depuis and pendant', \
              'Practiced the difference between depuis for continuing situations and pendant for completed durations.', \
              '[\"Camille\",\"Me\"]','[\"fr\",\"en\"]','[\"Practice five sentence pairs contrasting depuis and pendant\"]','synthetic-review','[]','Reviewed depuis for continuing actions. Contrasted depuis with pendant. Assigned practice.','normal','none','2026-07-22T16:00:00Z',3,'complete')",
        )
        .bind(account_id)
        .execute(&mut *transaction)
        .await?;
        sqlx::query(
            "INSERT INTO episode_members(account_id,episode_id,record_type,record_id) VALUES \
             ($1,940001,'utterance',920001),($1,940001,'utterance',920002), \
             ($1,940002,'utterance',920003),($1,940002,'utterance',920004), \
             ($1,940003,'screenshot',930001),($1,940004,'utterance',920005), \
             ($1,940004,'utterance',920006)",
        )
        .bind(account_id)
        .execute(&mut *transaction)
        .await?;
        sqlx::query(
            "INSERT INTO episode_final_briefs \
                (account_id,episode_id,overview,decisions,action_items,important_links,open_questions) VALUES \
             ($1,940001,'The team delayed the Kioku launch by one week to finish QA.','[\"Move the launch from August 12 to August 19\"]','[{\"owner\":\"Alex\",\"task\":\"Confirm the migration rehearsal by Friday\"}]','[]','[]'), \
             ($1,940002,'The stale dashboard was traced to incomplete cache invalidation.','[\"Invalidate both episode list and detail keys after writes\"]','[{\"owner\":\"Me\",\"task\":\"Add a regression test for episode detail invalidation\"}]','[]','[]'), \
             ($1,940003,'Reviewed the synthetic vendor renewal checklist.','[]','[{\"owner\":\"Me\",\"task\":\"Review the renewal checklist before August 1\"}]','[{\"url\":\"https://example.com/renewal\",\"label\":\"Synthetic renewal checklist\"}]','[]'), \
             ($1,940004,'Practiced choosing depuis for continuing situations and pendant for completed durations.','[]','[{\"owner\":\"Me\",\"task\":\"Write five sentence pairs contrasting depuis and pendant\"}]','[]','[]')",
        )
        .bind(account_id)
        .execute(&mut *transaction)
        .await?;
        sqlx::query(
            "INSERT INTO content_id_counters(account_id,entity_kind,next_id) VALUES \
             ($1,'audio_segment',910004),($1,'utterance',920007), \
             ($1,'screenshot',930002),($1,'episodes',940005) \
             ON CONFLICT(account_id,entity_kind) DO UPDATE SET \
             next_id=greatest(content_id_counters.next_id,excluded.next_id)",
        )
        .bind(account_id)
        .execute(&mut *transaction)
        .await?;
        transaction.commit().await?;
        Ok(true)
    }

    async fn claim_summary_window(
        &self,
        account_id: &str,
        from: &str,
        to: &str,
        claimed_at: &str,
        lease_seconds: i64,
    ) -> Result<Option<SummaryWindowClaim>> {
        let from_ms = timestamp(from, "summary window start")?;
        let to_ms = timestamp(to, "summary window end")?;
        let _claimed_ms = timestamp(claimed_at, "summary claim time")?;
        if to_ms <= from_ms || !(1..=3_600).contains(&lease_seconds) {
            return Err(EnclaveError::InvalidRequest(
                "summary window or lease is invalid".into(),
            ));
        }
        let claim_token = tokens::new_uuid();
        let row = sqlx::query(
            "INSERT INTO summary_window_claims(\
                 account_id,window_from,window_to,state,claim_token,claim_until,attempt_count,updated_at) \
             VALUES($1,to_timestamp($2::double precision/1000.0),\
                       to_timestamp($3::double precision/1000.0),'processing',$4,\
                       clock_timestamp()+make_interval(secs=>$5),1,clock_timestamp()) \
             ON CONFLICT(account_id) DO UPDATE SET \
                 window_from=excluded.window_from,window_to=excluded.window_to,state='processing',\
                 claim_token=excluded.claim_token,claim_until=excluded.claim_until,\
                 attempt_count=summary_window_claims.attempt_count+1,error_code=NULL,\
                 completed_claim_token=NULL,completed_at=NULL,updated_at=excluded.updated_at \
             WHERE summary_window_claims.state='retry_wait' \
                OR summary_window_claims.claim_until<=clock_timestamp() \
                OR (summary_window_claims.state='succeeded' AND \
                    (summary_window_claims.window_from<>excluded.window_from OR \
                     summary_window_claims.window_to<>excluded.window_to)) \
             RETURNING claim_token",
        )
        .bind(account_id)
        .bind(from_ms)
        .bind(to_ms)
        .bind(&claim_token)
        .bind(duration_seconds(std::time::Duration::from_secs(
            u64::try_from(lease_seconds).map_err(|_| {
                EnclaveError::InvalidRequest("summary lease is invalid".into())
            })?,
        ))?)
        .fetch_optional(self.pool())
        .await?;
        Ok(row.map(|_| SummaryWindowClaim {
            account_id: account_id.to_owned(),
            from: from.to_owned(),
            to: to.to_owned(),
            claim_token,
        }))
    }

    async fn release_summary_window(
        &self,
        claim: &SummaryWindowClaim,
        released_at: &str,
        error_code: Option<&str>,
    ) -> Result<()> {
        let released_ms = timestamp(released_at, "summary release time")?;
        let result = sqlx::query(
            "UPDATE summary_window_claims SET state='retry_wait',claim_token=NULL,\
                    claim_until=NULL,error_code=$3,updated_at=\
                    to_timestamp($4::double precision/1000.0) \
              WHERE account_id=$1 AND claim_token=$2 AND state='processing'",
        )
        .bind(&claim.account_id)
        .bind(&claim.claim_token)
        .bind(error_code)
        .bind(released_ms)
        .execute(self.pool())
        .await?;
        if result.rows_affected() != 1 {
            return Err(EnclaveError::Conflict(
                "summary window claim is no longer authoritative".into(),
            ));
        }
        Ok(())
    }

    async fn authorize_summary_window_egress(
        &self,
        claim: &SummaryWindowClaim,
        utterance_ids: &[i64],
        screenshot_ids: &[i64],
        open_episode_ids: &[i64],
    ) -> Result<()> {
        let from_ms = timestamp(&claim.from, "summary window start")?;
        let to_ms = timestamp(&claim.to, "summary window end")?;
        let mut transaction = self.pool().begin().await?;
        lock_activation_contract_key_share_if_installed(&mut transaction).await?;
        advisory_transaction_lock(&mut transaction, "memory-reconciliation", &claim.account_id)
            .await?;
        let authoritative = sqlx::query_scalar::<_, bool>(
            "UPDATE summary_window_claims SET \
                    claim_until=greatest(claim_until,\
                        clock_timestamp()+make_interval(secs=>$5)),\
                    updated_at=clock_timestamp() \
              WHERE account_id=$1 AND claim_token=$2 AND state='processing' \
                AND claim_until>clock_timestamp() \
                AND window_from=to_timestamp($3::double precision/1000.0) \
                AND window_to=to_timestamp($4::double precision/1000.0) \
              RETURNING true",
        )
        .bind(&claim.account_id)
        .bind(&claim.claim_token)
        .bind(from_ms)
        .bind(to_ms)
        .bind(PROVIDER_EGRESS_CLAIM_FENCE_SECONDS)
        .fetch_optional(&mut *transaction)
        .await?
        .unwrap_or(false);
        if !authoritative {
            return Err(EnclaveError::Conflict(
                "summary provider-egress claim is no longer authoritative".into(),
            ));
        }
        ensure_formation_sources_available(
            &mut transaction,
            &claim.account_id,
            utterance_ids,
            screenshot_ids,
        )
        .await?;
        ensure_open_episodes_available(&mut transaction, &claim.account_id, open_episode_ids)
            .await?;
        transaction.commit().await?;
        Ok(())
    }

    async fn summary_evidence(
        &self,
        account_id: &str,
        from: &str,
        to: &str,
        utterance_limit: i64,
        screenshot_limit: i64,
    ) -> Result<(Vec<SummaryUtterance>, Vec<SummaryScreenshot>)> {
        let from_ms = timestamp(from, "summary evidence start")?;
        let to_ms = timestamp(to, "summary evidence end")?;
        if to_ms <= from_ms || utterance_limit <= 0 || screenshot_limit <= 0 {
            return Err(EnclaveError::InvalidRequest(
                "summary evidence bounds are invalid".into(),
            ));
        }
        let mut connection = self.pool.acquire().await?;
        let formation_receipts_installed =
            capture_formation_contract_installed(&mut connection).await?;
        let utterance_sql = if formation_receipts_installed {
            "SELECT u.id,floor(extract(epoch FROM coalesce(\
                        o.started_at,s.started_at + (u.start_offset_seconds * interval '1 second')\
                    ))*1000)::bigint AS started_at_ms,\
                    u.speaker_label,u.language,u.text \
               FROM utterances u JOIN audio_segments s \
                 ON s.account_id=u.account_id AND s.id=u.audio_segment_id \
               LEFT JOIN speaker_observations o \
                 ON o.account_id=u.account_id AND o.id=u.speaker_observation_id \
              WHERE u.account_id=$1 \
                AND coalesce(o.started_at,s.started_at + (u.start_offset_seconds * interval '1 second')) \
                    >=to_timestamp($2::double precision/1000.0) \
                AND coalesce(o.started_at,s.started_at + (u.start_offset_seconds * interval '1 second')) \
                    <to_timestamp($3::double precision/1000.0) \
                AND NOT EXISTS(SELECT 1 FROM active_episode_members owner \
                      WHERE owner.account_id=u.account_id AND owner.record_type='utterance' \
                        AND owner.record_id=u.id) \
                AND NOT EXISTS(SELECT 1 FROM capture_formation_receipts receipt \
                      JOIN capture_events event ON event.account_id=receipt.account_id \
                           AND event.capture_session_id=receipt.capture_session_id \
                     WHERE receipt.account_id=u.account_id AND receipt.state='complete' \
                       AND receipt.completed_revision=receipt.source_revision \
                       AND o.id IS NOT NULL AND ( \
                           o.event_id=coalesce(event.canonical_event_id,event.event_id) \
                           OR EXISTS(SELECT 1 FROM speaker_observation_sources source \
                                WHERE source.account_id=o.account_id \
                                  AND source.speaker_observation_id=o.id \
                                  AND source.event_id=coalesce(event.canonical_event_id,event.event_id)))) \
              ORDER BY coalesce(o.started_at,s.started_at + (u.start_offset_seconds * interval '1 second')),u.id \
              LIMIT $4"
        } else {
            "SELECT u.id,floor(extract(epoch FROM coalesce(\
                        o.started_at,s.started_at + (u.start_offset_seconds * interval '1 second')\
                    ))*1000)::bigint AS started_at_ms,\
                    u.speaker_label,u.language,u.text \
               FROM utterances u JOIN audio_segments s \
                 ON s.account_id=u.account_id AND s.id=u.audio_segment_id \
               LEFT JOIN speaker_observations o \
                 ON o.account_id=u.account_id AND o.id=u.speaker_observation_id \
              WHERE u.account_id=$1 \
                AND coalesce(o.started_at,s.started_at + (u.start_offset_seconds * interval '1 second')) \
                    >=to_timestamp($2::double precision/1000.0) \
                AND coalesce(o.started_at,s.started_at + (u.start_offset_seconds * interval '1 second')) \
                    <to_timestamp($3::double precision/1000.0) \
                AND NOT EXISTS(SELECT 1 FROM active_episode_members owner \
                      WHERE owner.account_id=u.account_id AND owner.record_type='utterance' \
                        AND owner.record_id=u.id) \
              ORDER BY coalesce(o.started_at,s.started_at + (u.start_offset_seconds * interval '1 second')),u.id \
              LIMIT $4"
        };
        let utterances = sqlx::query(utterance_sql)
            .bind(account_id)
            .bind(from_ms)
            .bind(to_ms)
            .bind(utterance_limit)
            .fetch_all(&mut *connection)
            .await?
            .into_iter()
            .map(|row| {
                Ok(SummaryUtterance {
                    id: row.try_get("id")?,
                    started_at: isotime::format_epoch_millis(row.try_get("started_at_ms")?),
                    speaker_label: row.try_get("speaker_label")?,
                    language: row.try_get("language")?,
                    text: row.try_get("text")?,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        let screenshot_sql = if formation_receipts_installed {
            "SELECT screenshot.id, \
                    floor(extract(epoch FROM screenshot.captured_at)*1000)::bigint AS captured_at_ms,\
                    screenshot.active_app,screenshot.window_title,left(screenshot.ocr_text,4000) AS ocr_text,\
                    left(screenshot.salient_ocr_text,4000) AS salient_ocr_text,screenshot.url, \
                    screenshot.is_duplicate \
               FROM screenshots screenshot WHERE screenshot.account_id=$1 \
                AND screenshot.captured_at>=to_timestamp($2::double precision/1000.0) \
                AND screenshot.captured_at<to_timestamp($3::double precision/1000.0) \
                AND NOT EXISTS(SELECT 1 FROM active_episode_members owner \
                      WHERE owner.account_id=screenshot.account_id AND owner.record_type='screenshot' \
                        AND owner.record_id=screenshot.id) \
                AND NOT EXISTS(SELECT 1 FROM capture_formation_receipts receipt \
                      JOIN capture_events event ON event.account_id=receipt.account_id \
                           AND event.capture_session_id=receipt.capture_session_id \
                     WHERE receipt.account_id=screenshot.account_id AND receipt.state='complete' \
                       AND receipt.completed_revision=receipt.source_revision \
                       AND screenshot.source_key=concat('cloud-v2:', \
                           coalesce(event.canonical_event_id,event.event_id))) \
              ORDER BY screenshot.captured_at,screenshot.id LIMIT $4"
        } else {
            "SELECT screenshot.id, \
                    floor(extract(epoch FROM screenshot.captured_at)*1000)::bigint AS captured_at_ms,\
                    screenshot.active_app,screenshot.window_title,left(screenshot.ocr_text,4000) AS ocr_text,\
                    left(screenshot.salient_ocr_text,4000) AS salient_ocr_text,screenshot.url, \
                    screenshot.is_duplicate \
               FROM screenshots screenshot WHERE screenshot.account_id=$1 \
                AND screenshot.captured_at>=to_timestamp($2::double precision/1000.0) \
                AND screenshot.captured_at<to_timestamp($3::double precision/1000.0) \
                AND NOT EXISTS(SELECT 1 FROM active_episode_members owner \
                      WHERE owner.account_id=screenshot.account_id AND owner.record_type='screenshot' \
                        AND owner.record_id=screenshot.id) \
              ORDER BY screenshot.captured_at,screenshot.id LIMIT $4"
        };
        let screenshots = sqlx::query(screenshot_sql)
            .bind(account_id)
            .bind(from_ms)
            .bind(to_ms)
            .bind(screenshot_limit)
            .fetch_all(&mut *connection)
            .await?
            .into_iter()
            .map(|row| {
                Ok(SummaryScreenshot {
                    id: row.try_get("id")?,
                    captured_at: isotime::format_epoch_millis(row.try_get("captured_at_ms")?),
                    active_app: row.try_get("active_app")?,
                    window_title: row.try_get("window_title")?,
                    ocr_text: row.try_get("ocr_text")?,
                    salient_ocr_text: row.try_get("salient_ocr_text")?,
                    url: row.try_get("url")?,
                    is_duplicate: i64::from(row.try_get::<bool, _>("is_duplicate")?),
                })
            })
            .collect::<Result<Vec<_>>>()?;
        Ok((utterances, screenshots))
    }

    async fn claim_capture_formation(
        &self,
        account_id: &str,
        lease_seconds: i64,
    ) -> Result<Option<CaptureFormationClaim>> {
        if !(1..=3_600).contains(&lease_seconds) {
            return Err(EnclaveError::InvalidRequest(
                "capture formation lease is invalid".into(),
            ));
        }
        let mut transaction = self.pool().begin().await?;
        lock_activation_contract_key_share_if_installed(&mut transaction).await?;
        if !capture_formation_contract_installed(&mut transaction).await? {
            transaction.commit().await?;
            return Ok(None);
        }
        advisory_transaction_lock(&mut transaction, "memory-reconciliation", account_id).await?;
        import_legacy_provisional_finishes(&mut transaction, account_id).await?;
        finalize_quiet_capture_seals(&mut transaction, account_id).await?;
        let selected = sqlx::query(
            "SELECT receipt.capture_session_id,receipt.source_revision, \
                    floor(extract(epoch FROM least(session.started_at, \
                         coalesce((SELECT min(event.started_at) FROM capture_events event \
                                   WHERE event.account_id=receipt.account_id \
                                     AND event.capture_session_id=receipt.capture_session_id), \
                                  session.started_at)))*1000)::bigint AS from_ms, \
                    floor(extract(epoch FROM greatest(session.last_event_at, \
                         coalesce(session.ended_at,session.last_event_at), \
                         coalesce((SELECT max(event.ended_at) FROM capture_events event \
                                   WHERE event.account_id=receipt.account_id \
                                     AND event.capture_session_id=receipt.capture_session_id), \
                                  session.last_event_at)))*1000)::bigint AS to_ms \
               FROM capture_formation_receipts receipt \
               JOIN capture_sessions session ON session.account_id=receipt.account_id \
                    AND session.id=receipt.capture_session_id \
               JOIN accounts account ON account.id=receipt.account_id AND account.status='active' \
              WHERE receipt.account_id=$1 AND receipt.source_revision>receipt.completed_revision \
                AND receipt.finish_requested_at IS NOT NULL AND session.ended_at IS NOT NULL \
                AND account.summarized_until>=greatest(session.last_event_at, \
                    coalesce(session.ended_at,session.last_event_at), \
                    coalesce((SELECT max(event.ended_at) FROM capture_events event \
                              WHERE event.account_id=receipt.account_id \
                                AND event.capture_session_id=receipt.capture_session_id), \
                             session.last_event_at)) \
                AND (receipt.state='pending' \
                     OR (receipt.state='retry_wait' AND receipt.next_attempt_at<=clock_timestamp()) \
                     OR (receipt.state='processing' AND receipt.claim_until<=clock_timestamp())) \
                AND receipt.finish_requested_at<=clock_timestamp()-make_interval(secs=>$6) \
                AND EXISTS(SELECT 1 FROM capture_streams stream \
                      WHERE stream.account_id=receipt.account_id \
                        AND stream.capture_session_id=receipt.capture_session_id) \
                AND NOT EXISTS(SELECT 1 FROM capture_streams stream \
                      WHERE stream.account_id=receipt.account_id \
                        AND stream.capture_session_id=receipt.capture_session_id \
                        AND (stream.committed_through_sequence IS DISTINCT FROM \
                                capture_formation_stream_accepted_max( \
                                    stream.account_id,stream.id) \
                             OR capture_formation_stream_contiguous_through( \
                                    stream.account_id,stream.id) IS DISTINCT FROM \
                                stream.committed_through_sequence \
                             OR (stream.sealed_sequence IS NOT NULL \
                                 AND stream.sealed_sequence<>stream.committed_through_sequence))) \
                AND NOT EXISTS(SELECT 1 FROM capture_events event \
                      WHERE event.account_id=receipt.account_id \
                        AND event.capture_session_id=receipt.capture_session_id \
                        AND event.received_at>clock_timestamp()-make_interval(secs=>$6)) \
                AND NOT EXISTS(SELECT 1 FROM capture_events event \
                      WHERE event.account_id=receipt.account_id \
                        AND event.capture_session_id=receipt.capture_session_id \
                        AND event.media_disposition='canonical' \
                        AND NOT EXISTS(SELECT 1 FROM media_processing_jobs job \
                              WHERE job.account_id=event.account_id \
                                AND job.event_id=event.event_id)) \
                AND NOT EXISTS(SELECT 1 FROM capture_events event \
                      JOIN media_processing_jobs job ON job.account_id=event.account_id \
                           AND job.event_id=event.event_id \
                     WHERE event.account_id=receipt.account_id \
                       AND event.capture_session_id=receipt.capture_session_id \
                       AND (job.updated_at>clock_timestamp()-make_interval(secs=>$6) \
                            OR (job.state NOT IN ('succeeded','canceled') \
                                AND (job.state<>'failed_terminal' OR ( \
                                     job.processor_version=$2 \
                                     AND NOT (coalesce(job.error_code,'')=ANY($3::text[])) \
                                     AND job.attempt_count<$4 \
                                     AND event.started_at>=clock_timestamp()-make_interval(secs=>$5)))))) \
                AND NOT EXISTS(SELECT 1 FROM capture_events event \
                      JOIN media_objects object ON object.account_id=event.account_id \
                           AND object.event_id=event.event_id \
                     WHERE event.account_id=receipt.account_id \
                       AND event.capture_session_id=receipt.capture_session_id \
                       AND object.deleted_at IS NULL \
                       AND object.processing_state IN ('queued','processing','retry_wait')) \
              ORDER BY receipt.updated_at,receipt.capture_session_id LIMIT 1 \
              FOR UPDATE OF receipt SKIP LOCKED",
        )
        .bind(account_id)
        .bind(PROCESSOR_VERSION)
        .bind(NON_RESURRECTABLE_MEDIA_ERROR_CODES.as_slice())
        .bind(RESURRECTION_TOTAL_ATTEMPT_CAP)
        .bind(RESURRECTION_WINDOW_SECONDS_INTEGRAL as f64)
        .bind(CAPTURE_FORMATION_QUIET_SECONDS as f64)
        .fetch_optional(&mut *transaction)
        .await?;
        let Some(selected) = selected else {
            transaction.commit().await?;
            return Ok(None);
        };
        let capture_session_id: String = selected.try_get("capture_session_id")?;
        let source_revision: i64 = selected.try_get("source_revision")?;
        let from_ms: i64 = selected.try_get("from_ms")?;
        let to_ms: i64 = selected.try_get("to_ms")?;
        if !capture_session_is_formation_ready(&mut transaction, account_id, &capture_session_id)
            .await?
        {
            return Err(EnclaveError::Conflict(
                "capture formation readiness changed while claiming".into(),
            ));
        }
        let source_fingerprint = capture_formation_source_fingerprint(
            &mut transaction,
            account_id,
            &capture_session_id,
            source_revision,
        )
        .await?;
        let existing_page = sqlx::query(
            "SELECT page_index,source_fingerprint,page_source_commitment, \
                    covered_utterance_ids,covered_screenshot_ids,provider_utterance_ids, \
                    provider_screenshot_ids,has_more,provider_attempt, \
                    provider_request #>> '{}' AS provider_request_json,provider_request_sha256, \
                    staged_response #>> '{}' AS staged_provider_response,staged_response_sha256, \
                    staged_vertex_event_id \
               FROM capture_formation_pages \
              WHERE account_id=$1 AND capture_session_id=$2 AND source_revision=$3 \
                AND state NOT IN ('complete','invalidated') \
              ORDER BY page_index LIMIT 1 FOR UPDATE",
        )
        .bind(account_id)
        .bind(&capture_session_id)
        .bind(source_revision)
        .fetch_optional(&mut *transaction)
        .await?;
        let reclaimed_page = existing_page.is_some();
        let page = if let Some(row) = existing_page {
            let page = capture_formation_page_from_row(&row)?;
            if page.source_fingerprint != source_fingerprint {
                return Err(EnclaveError::Conflict(
                    "capture formation page source changed before reclaim".into(),
                ));
            }
            page
        } else {
            let page_index: i64 = sqlx::query_scalar(
                "SELECT coalesce(max(page_index)+1,0) FROM capture_formation_pages \
                  WHERE account_id=$1 AND capture_session_id=$2 AND source_revision=$3 \
                    AND state='complete'",
            )
            .bind(account_id)
            .bind(&capture_session_id)
            .bind(source_revision)
            .fetch_one(&mut *transaction)
            .await?;
            create_capture_formation_page(
                &mut transaction,
                account_id,
                &capture_session_id,
                source_revision,
                &source_fingerprint,
                page_index,
            )
            .await?
        };
        let claim_token = tokens::new_uuid();
        let page_changed = if reclaimed_page {
            sqlx::query(
                "UPDATE capture_formation_pages SET state='processing',claim_token=$5, \
                        claim_until=clock_timestamp()+make_interval(secs=>$6), \
                        last_error_code=NULL,updated_at=clock_timestamp() \
                  WHERE account_id=$1 AND capture_session_id=$2 AND source_revision=$3 \
                    AND page_index=$4 AND state NOT IN ('complete','invalidated')",
            )
            .bind(account_id)
            .bind(&capture_session_id)
            .bind(source_revision)
            .bind(page.page_index)
            .bind(&claim_token)
            .bind(lease_seconds as f64)
            .execute(&mut *transaction)
            .await?
            .rows_affected()
        } else {
            sqlx::query(
                "INSERT INTO capture_formation_pages( \
                     account_id,capture_session_id,source_revision,page_index,source_fingerprint, \
                     page_source_commitment,covered_utterance_ids,covered_screenshot_ids, \
                     provider_utterance_ids,provider_screenshot_ids,has_more,state,claim_token, \
                     claim_until,provider_attempt) \
                 VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,'processing',$12, \
                        clock_timestamp()+make_interval(secs=>$13),$14)",
            )
            .bind(account_id)
            .bind(&capture_session_id)
            .bind(source_revision)
            .bind(page.page_index)
            .bind(&page.source_fingerprint)
            .bind(&page.page_source_commitment)
            .bind(&page.covered_utterance_ids)
            .bind(&page.covered_screenshot_ids)
            .bind(&page.provider_utterance_ids)
            .bind(&page.provider_screenshot_ids)
            .bind(page.has_more)
            .bind(&claim_token)
            .bind(lease_seconds as f64)
            .bind(page.provider_attempt)
            .execute(&mut *transaction)
            .await?
            .rows_affected()
        };
        if page_changed != 1 {
            transaction.rollback().await?;
            return Ok(None);
        }
        let changed = sqlx::query(
            "UPDATE capture_formation_receipts SET state='processing', \
                    claimed_revision=source_revision,claimed_source_fingerprint=$4, \
                    claim_token=$3,claim_until=clock_timestamp()+make_interval(secs=>$5), \
                    next_attempt_at=NULL,attempt_count=attempt_count+1,last_error_code=NULL, \
                    updated_at=clock_timestamp() \
              WHERE account_id=$1 AND capture_session_id=$2 AND source_revision=$6 \
                AND source_revision>completed_revision AND (state='pending' \
                     OR (state='retry_wait' AND next_attempt_at<=clock_timestamp()) \
                     OR (state='processing' AND claim_until<=clock_timestamp()))",
        )
        .bind(account_id)
        .bind(&capture_session_id)
        .bind(&claim_token)
        .bind(&source_fingerprint)
        .bind(lease_seconds as f64)
        .bind(source_revision)
        .execute(&mut *transaction)
        .await?
        .rows_affected();
        if changed != 1 {
            transaction.rollback().await?;
            return Ok(None);
        }
        invalidate_reconciliation_neighborhood_scan(&mut transaction, account_id).await?;
        transaction.commit().await?;
        let provider_attempt_identity = capture_formation_provider_attempt_identity(
            account_id,
            &capture_session_id,
            source_revision,
            page.page_index,
            &page.page_source_commitment,
            page.provider_attempt,
        );
        Ok(Some(CaptureFormationClaim {
            account_id: account_id.to_owned(),
            capture_session_id,
            source_revision,
            source_fingerprint,
            from: isotime::format_epoch_millis(from_ms),
            to: isotime::format_epoch_millis(to_ms),
            page_index: page.page_index,
            page_source_commitment: page.page_source_commitment,
            provider_attempt_identity,
            provider_request: page.provider_request,
            staged_provider_response: page.staged_provider_response,
            staged_vertex_event_id: page.staged_vertex_event_id,
            page_has_more: page.has_more,
            covered_utterance_count: i64::try_from(page.covered_utterance_ids.len())
                .unwrap_or(i64::MAX),
            covered_screenshot_count: i64::try_from(page.covered_screenshot_ids.len())
                .unwrap_or(i64::MAX),
            claim_token,
        }))
    }

    async fn release_capture_formation(
        &self,
        claim: &CaptureFormationClaim,
        error_code: Option<&str>,
        disposition: CaptureFormationRetryDisposition,
    ) -> Result<()> {
        if error_code.is_some_and(|value| value.is_empty() || value.len() > 128) {
            return Err(EnclaveError::InvalidRequest(
                "capture formation error code is invalid".into(),
            ));
        }
        let mut transaction = self.pool().begin().await?;
        lock_activation_contract_key_share_if_installed(&mut transaction).await?;
        advisory_transaction_lock(&mut transaction, "memory-reconciliation", &claim.account_id)
            .await?;
        let page_changed = sqlx::query(
            "UPDATE capture_formation_pages SET state='retry_wait',claim_token=NULL, \
                    claim_until=NULL,provider_attempt=provider_attempt+CASE WHEN $7 THEN 1 ELSE 0 END, \
                    provider_request=CASE WHEN $7 THEN NULL ELSE provider_request END, \
                    provider_request_sha256=CASE WHEN $7 THEN NULL ELSE provider_request_sha256 END, \
                    last_error_code=$6,updated_at=clock_timestamp() \
              WHERE account_id=$1 AND capture_session_id=$2 AND source_revision=$3 \
                AND page_index=$4 AND page_source_commitment=$5 \
                AND state='processing' AND claim_token=$8 \
                AND (NOT $7 OR staged_response IS NULL)",
        )
        .bind(&claim.account_id)
        .bind(&claim.capture_session_id)
        .bind(claim.source_revision)
        .bind(claim.page_index)
        .bind(&claim.page_source_commitment)
        .bind(error_code)
        .bind(matches!(
            disposition,
            CaptureFormationRetryDisposition::AdvanceConfirmedNotBilled
        ))
        .bind(&claim.claim_token)
        .execute(&mut *transaction)
        .await?
        .rows_affected();
        if page_changed != 1 {
            return Err(EnclaveError::Conflict(
                "capture formation page claim is no longer authoritative".into(),
            ));
        }
        let changed = sqlx::query(
            "UPDATE capture_formation_receipts SET state='retry_wait',claimed_revision=NULL, \
                    claimed_source_fingerprint=NULL,claim_token=NULL,claim_until=NULL, \
                    next_attempt_at=clock_timestamp()+make_interval(secs=>$5), \
                    last_error_code=$4,updated_at=clock_timestamp() \
              WHERE account_id=$1 AND capture_session_id=$2 AND source_revision=$3 \
                AND state='processing' AND claim_token=$6",
        )
        .bind(&claim.account_id)
        .bind(&claim.capture_session_id)
        .bind(claim.source_revision)
        .bind(error_code)
        .bind(CAPTURE_FORMATION_RETRY_SECONDS)
        .bind(&claim.claim_token)
        .execute(&mut *transaction)
        .await?
        .rows_affected();
        if changed != 1 {
            return Err(EnclaveError::Conflict(
                "capture formation claim is no longer authoritative".into(),
            ));
        }
        invalidate_reconciliation_neighborhood_scan(&mut transaction, &claim.account_id).await?;
        transaction.commit().await?;
        Ok(())
    }

    async fn capture_formation_evidence(
        &self,
        claim: &CaptureFormationClaim,
        utterance_limit: i64,
        screenshot_limit: i64,
    ) -> Result<(Vec<SummaryUtterance>, Vec<SummaryScreenshot>)> {
        if utterance_limit != CAPTURE_FORMATION_UTTERANCE_PAGE_SIZE
            || screenshot_limit != CAPTURE_FORMATION_SCREENSHOT_PAGE_SIZE
            || claim.source_fingerprint.len() != 32
            || claim.page_source_commitment.len() != 32
        {
            return Err(EnclaveError::InvalidRequest(
                "capture formation evidence bounds are invalid".into(),
            ));
        }
        let mut transaction = self.pool().begin().await?;
        lock_activation_contract_key_share_if_installed(&mut transaction).await?;
        advisory_transaction_lock(&mut transaction, "memory-reconciliation", &claim.account_id)
            .await?;
        let authoritative = sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS(SELECT 1 FROM capture_formation_receipts \
              WHERE account_id=$1 AND capture_session_id=$2 AND source_revision=$3 \
                AND claimed_revision=$3 AND claimed_source_fingerprint=$4 AND state='processing' \
                AND claim_token=$5 AND claim_until>clock_timestamp())",
        )
        .bind(&claim.account_id)
        .bind(&claim.capture_session_id)
        .bind(claim.source_revision)
        .bind(&claim.source_fingerprint)
        .bind(&claim.claim_token)
        .fetch_one(&mut *transaction)
        .await?;
        let current_fingerprint = capture_formation_source_fingerprint(
            &mut transaction,
            &claim.account_id,
            &claim.capture_session_id,
            claim.source_revision,
        )
        .await?;
        if !authoritative
            || current_fingerprint != claim.source_fingerprint
            || !capture_session_is_formation_ready(
                &mut transaction,
                &claim.account_id,
                &claim.capture_session_id,
            )
            .await?
        {
            return Err(EnclaveError::Conflict(
                "capture formation source changed".into(),
            ));
        }
        let page = sqlx::query(
            "SELECT page_index,source_fingerprint,page_source_commitment, \
                    covered_utterance_ids,covered_screenshot_ids,provider_utterance_ids, \
                    provider_screenshot_ids,has_more,provider_attempt, \
                    provider_request #>> '{}' AS provider_request_json,provider_request_sha256, \
                    staged_response #>> '{}' AS staged_provider_response,staged_response_sha256, \
                    staged_vertex_event_id \
               FROM capture_formation_pages \
              WHERE account_id=$1 AND capture_session_id=$2 AND source_revision=$3 \
                AND page_index=$4 AND state='processing' AND claim_token=$5 \
                AND claim_until>clock_timestamp() FOR UPDATE",
        )
        .bind(&claim.account_id)
        .bind(&claim.capture_session_id)
        .bind(claim.source_revision)
        .bind(claim.page_index)
        .bind(&claim.claim_token)
        .fetch_optional(&mut *transaction)
        .await?
        .ok_or_else(|| EnclaveError::Conflict("capture formation page claim changed".into()))?;
        let page = capture_formation_page_from_row(&page)?;
        if page.page_source_commitment != claim.page_source_commitment {
            return Err(EnclaveError::Conflict(
                "capture formation page commitment changed".into(),
            ));
        }
        let utterance_rows = sqlx::query(
            "WITH evidence_events AS ( \
                 SELECT DISTINCT coalesce(canonical_event_id,event_id) AS event_id \
                   FROM capture_events WHERE account_id=$1 AND capture_session_id=$2) \
             SELECT DISTINCT utterance.id, \
                    floor(extract(epoch FROM coalesce(observation.started_at, \
                         segment.started_at+utterance.start_offset_seconds*interval '1 second'))*1000)::bigint \
                         AS started_at_ms,utterance.speaker_label,utterance.language,utterance.text \
               FROM evidence_events evidence \
               JOIN speaker_observations observation ON observation.account_id=$1 \
                    AND (observation.event_id=evidence.event_id OR EXISTS( \
                        SELECT 1 FROM speaker_observation_sources source \
                         WHERE source.account_id=observation.account_id \
                           AND source.speaker_observation_id=observation.id \
                           AND source.event_id=evidence.event_id)) \
               JOIN utterances utterance ON utterance.account_id=observation.account_id \
                    AND utterance.speaker_observation_id=observation.id \
               JOIN audio_segments segment ON segment.account_id=utterance.account_id \
                    AND segment.id=utterance.audio_segment_id \
              WHERE utterance.id=ANY($3) \
              ORDER BY started_at_ms,utterance.id",
        )
        .bind(&claim.account_id)
        .bind(&claim.capture_session_id)
        .bind(&page.provider_utterance_ids)
        .fetch_all(&mut *transaction)
        .await?;
        let screenshot_rows = sqlx::query(
            "WITH evidence_events AS ( \
                 SELECT DISTINCT coalesce(canonical_event_id,event_id) AS event_id \
                   FROM capture_events WHERE account_id=$1 AND capture_session_id=$2) \
             SELECT DISTINCT screenshot.id, \
                    floor(extract(epoch FROM screenshot.captured_at)*1000)::bigint AS captured_at_ms, \
                    screenshot.active_app,screenshot.window_title,left(screenshot.ocr_text,4000) AS ocr_text, \
                    left(screenshot.salient_ocr_text,4000) AS salient_ocr_text,screenshot.url, \
                    screenshot.is_duplicate \
               FROM evidence_events evidence JOIN screenshots screenshot ON screenshot.account_id=$1 \
                    AND screenshot.source_key=concat('cloud-v2:',evidence.event_id) \
              WHERE screenshot.id=ANY($3) \
              ORDER BY captured_at_ms,screenshot.id",
        )
        .bind(&claim.account_id)
        .bind(&claim.capture_session_id)
        .bind(&page.provider_screenshot_ids)
        .fetch_all(&mut *transaction)
        .await?;
        if i64::try_from(utterance_rows.len()).unwrap_or(i64::MAX)
            != i64::try_from(page.provider_utterance_ids.len()).unwrap_or(i64::MAX)
            || i64::try_from(screenshot_rows.len()).unwrap_or(i64::MAX)
                != i64::try_from(page.provider_screenshot_ids.len()).unwrap_or(i64::MAX)
        {
            return Err(EnclaveError::Conflict(
                "capture formation page evidence changed".into(),
            ));
        }
        let utterances = utterance_rows
            .into_iter()
            .map(|row| {
                Ok(SummaryUtterance {
                    id: row.try_get("id")?,
                    started_at: isotime::format_epoch_millis(row.try_get("started_at_ms")?),
                    speaker_label: row.try_get("speaker_label")?,
                    language: row.try_get("language")?,
                    text: row.try_get("text")?,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        let screenshots = screenshot_rows
            .into_iter()
            .map(|row| {
                Ok(SummaryScreenshot {
                    id: row.try_get("id")?,
                    captured_at: isotime::format_epoch_millis(row.try_get("captured_at_ms")?),
                    active_app: row.try_get("active_app")?,
                    window_title: row.try_get("window_title")?,
                    ocr_text: row.try_get("ocr_text")?,
                    salient_ocr_text: row.try_get("salient_ocr_text")?,
                    url: row.try_get("url")?,
                    is_duplicate: i64::from(row.try_get::<bool, _>("is_duplicate")?),
                })
            })
            .collect::<Result<Vec<_>>>()?;
        transaction.commit().await?;
        Ok((utterances, screenshots))
    }

    async fn authorize_capture_formation_egress(
        &self,
        claim: &CaptureFormationClaim,
        utterance_ids: &[i64],
        screenshot_ids: &[i64],
        current_request: &CaptureFormationProviderRequest,
    ) -> Result<CaptureFormationProviderRequest> {
        if claim.source_fingerprint.len() != 32
            || claim.page_source_commitment.len() != 32
            || claim.provider_attempt_identity.len() != 32
        {
            return Err(EnclaveError::InvalidRequest(
                "capture formation fingerprint is invalid".into(),
            ));
        }
        let request_to_bind = claim.provider_request.as_ref().unwrap_or(current_request);
        let current_request_bytes = capture_formation_provider_request_bytes(request_to_bind)?;
        let current_request_json =
            String::from_utf8(current_request_bytes.clone()).map_err(|_| {
                EnclaveError::Store("capture formation provider request is not UTF-8".into())
            })?;
        let current_request_sha256 = Sha256::digest(&current_request_bytes).to_vec();
        let mut transaction = self.pool().begin().await?;
        lock_activation_contract_key_share_if_installed(&mut transaction).await?;
        advisory_transaction_lock(&mut transaction, "memory-reconciliation", &claim.account_id)
            .await?;
        let authoritative = sqlx::query_scalar::<_, bool>(
            "UPDATE capture_formation_receipts SET \
                    claim_until=greatest(claim_until,\
                        clock_timestamp()+make_interval(secs=>$6)),\
                    updated_at=clock_timestamp() \
              WHERE account_id=$1 AND capture_session_id=$2 AND source_revision=$3 \
                AND claimed_revision=$3 AND claimed_source_fingerprint=$4 AND state='processing' \
                AND claim_token=$5 AND claim_until>clock_timestamp() \
              RETURNING true",
        )
        .bind(&claim.account_id)
        .bind(&claim.capture_session_id)
        .bind(claim.source_revision)
        .bind(&claim.source_fingerprint)
        .bind(&claim.claim_token)
        .bind(PROVIDER_EGRESS_CLAIM_FENCE_SECONDS)
        .fetch_optional(&mut *transaction)
        .await?
        .unwrap_or(false);
        let current_fingerprint = capture_formation_source_fingerprint(
            &mut transaction,
            &claim.account_id,
            &claim.capture_session_id,
            claim.source_revision,
        )
        .await?;
        if !authoritative
            || current_fingerprint != claim.source_fingerprint
            || !capture_session_is_formation_ready(
                &mut transaction,
                &claim.account_id,
                &claim.capture_session_id,
            )
            .await?
        {
            return Err(EnclaveError::Conflict(
                "capture provider-egress source changed".into(),
            ));
        }
        let page = sqlx::query(
            "UPDATE capture_formation_pages SET \
                    claim_until=greatest(claim_until, \
                        clock_timestamp()+make_interval(secs=>$7)), \
                    provider_request=coalesce(provider_request,to_jsonb($8::text)), \
                    provider_request_sha256=coalesce(provider_request_sha256,$9), \
                    updated_at=clock_timestamp() \
              WHERE account_id=$1 AND capture_session_id=$2 AND source_revision=$3 \
                AND page_index=$4 AND page_source_commitment=$5 AND state='processing' \
                AND claim_token=$6 AND claim_until>clock_timestamp() \
                AND staged_response IS NULL \
              RETURNING provider_utterance_ids,provider_screenshot_ids,provider_attempt, \
                        provider_request #>> '{}' AS provider_request_json, \
                        provider_request_sha256",
        )
        .bind(&claim.account_id)
        .bind(&claim.capture_session_id)
        .bind(claim.source_revision)
        .bind(claim.page_index)
        .bind(&claim.page_source_commitment)
        .bind(&claim.claim_token)
        .bind(PROVIDER_EGRESS_CLAIM_FENCE_SECONDS)
        .bind(&current_request_json)
        .bind(&current_request_sha256)
        .fetch_optional(&mut *transaction)
        .await?
        .ok_or_else(|| {
            EnclaveError::Conflict("capture provider-egress page claim changed".into())
        })?;
        let provider_utterance_ids: Vec<i64> = page.try_get("provider_utterance_ids")?;
        let provider_screenshot_ids: Vec<i64> = page.try_get("provider_screenshot_ids")?;
        let provider_attempt: i64 = page.try_get("provider_attempt")?;
        let expected_attempt = capture_formation_provider_attempt_identity(
            &claim.account_id,
            &claim.capture_session_id,
            claim.source_revision,
            claim.page_index,
            &claim.page_source_commitment,
            provider_attempt,
        );
        if provider_utterance_ids != utterance_ids
            || provider_screenshot_ids != screenshot_ids
            || expected_attempt != claim.provider_attempt_identity
        {
            return Err(EnclaveError::Conflict(
                "capture provider-egress page evidence or attempt changed".into(),
            ));
        }
        let stored_request_json: String = page.try_get("provider_request_json")?;
        let stored_request_sha256: Vec<u8> = page.try_get("provider_request_sha256")?;
        if Sha256::digest(stored_request_json.as_bytes()).as_slice()
            != stored_request_sha256.as_slice()
        {
            return Err(EnclaveError::Store(
                "capture provider-egress request commitment changed".into(),
            ));
        }
        let stored_request: CaptureFormationProviderRequest =
            serde_json::from_str(&stored_request_json)?;
        capture_formation_provider_request_bytes(&stored_request)?;
        if claim
            .provider_request
            .as_ref()
            .is_some_and(|request| request != &stored_request)
        {
            return Err(EnclaveError::Conflict(
                "capture provider-egress request changed after claim".into(),
            ));
        }
        ensure_formation_sources_available(
            &mut transaction,
            &claim.account_id,
            utterance_ids,
            screenshot_ids,
        )
        .await?;
        transaction.commit().await?;
        Ok(stored_request)
    }

    async fn stage_capture_formation_response(
        &self,
        claim: &CaptureFormationClaim,
        response: &str,
        vertex_event_id: &str,
    ) -> Result<()> {
        if response.len() > MAX_STAGED_FORMATION_RESPONSE_BYTES
            || vertex_event_id.is_empty()
            || vertex_event_id.len() > 256
        {
            return Err(EnclaveError::InvalidRequest(
                "capture formation staged response is invalid".into(),
            ));
        }
        if vertex_attempt_event_id(&claim.provider_attempt_identity)? != vertex_event_id {
            return Err(EnclaveError::Conflict(
                "capture formation staged response event identity mismatch".into(),
            ));
        }
        let response_sha256 = Sha256::digest(response.as_bytes()).to_vec();
        let mut transaction = self.pool().begin().await?;
        lock_activation_contract_key_share_if_installed(&mut transaction).await?;
        advisory_transaction_lock(&mut transaction, "memory-reconciliation", &claim.account_id)
            .await?;
        let staged = sqlx::query(
            "UPDATE capture_formation_pages SET staged_response=to_jsonb($7::text), \
                    staged_response_sha256=$8,staged_vertex_event_id=$9, \
                    updated_at=clock_timestamp() \
              WHERE account_id=$1 AND capture_session_id=$2 AND source_revision=$3 \
                AND page_index=$4 AND page_source_commitment=$5 AND state='processing' \
                AND claim_token=$6 AND claim_until>clock_timestamp() \
                AND provider_request IS NOT NULL AND provider_request_sha256 IS NOT NULL \
                AND (staged_response IS NULL OR (staged_response=to_jsonb($7::text) \
                     AND staged_response_sha256=$8 AND staged_vertex_event_id=$9)) \
              RETURNING provider_request #>> '{}' AS provider_request_json, \
                        provider_request_sha256",
        )
        .bind(&claim.account_id)
        .bind(&claim.capture_session_id)
        .bind(claim.source_revision)
        .bind(claim.page_index)
        .bind(&claim.page_source_commitment)
        .bind(&claim.claim_token)
        .bind(response)
        .bind(&response_sha256)
        .bind(vertex_event_id)
        .fetch_optional(&mut *transaction)
        .await?
        .ok_or_else(|| {
            EnclaveError::Conflict("capture formation staged response lost its page claim".into())
        })?;
        let provider_request_json: String = staged.try_get("provider_request_json")?;
        let provider_request_sha256: Vec<u8> = staged.try_get("provider_request_sha256")?;
        if Sha256::digest(provider_request_json.as_bytes()).as_slice()
            != provider_request_sha256.as_slice()
        {
            return Err(EnclaveError::Store(
                "capture formation staged request commitment mismatch".into(),
            ));
        }
        let provider_request: CaptureFormationProviderRequest =
            serde_json::from_str(&provider_request_json)?;
        capture_formation_provider_request_bytes(&provider_request)?;
        ensure_terminal_formation_usage_event(
            &mut transaction,
            &claim.account_id,
            vertex_event_id,
            &provider_request,
        )
        .await?;
        transaction.commit().await?;
        Ok(())
    }

    async fn settle_capture_formation(
        &self,
        settlement: CaptureFormationSettlement,
    ) -> Result<Vec<i64>> {
        if settlement.claim.source_fingerprint.len() != 32
            || settlement
                .episodes
                .iter()
                .any(|episode| episode.id.is_some())
        {
            return Err(EnclaveError::InvalidRequest(
                "capture formation fingerprint or new-draft settlement is invalid".into(),
            ));
        }
        let mut transaction = self.pool().begin().await?;
        lock_activation_contract_key_share_if_installed(&mut transaction).await?;
        advisory_transaction_lock(
            &mut transaction,
            "memory-reconciliation",
            &settlement.claim.account_id,
        )
        .await?;
        let replayed_page = sqlx::query_scalar::<_, Vec<i64>>(
            "SELECT successor_episode_ids FROM capture_formation_pages \
              WHERE account_id=$1 AND capture_session_id=$2 AND source_revision=$3 \
                AND page_index=$4 AND page_source_commitment=$5 AND state='complete' \
                AND completed_claim_token=$6",
        )
        .bind(&settlement.claim.account_id)
        .bind(&settlement.claim.capture_session_id)
        .bind(settlement.claim.source_revision)
        .bind(settlement.claim.page_index)
        .bind(&settlement.claim.page_source_commitment)
        .bind(&settlement.claim.claim_token)
        .fetch_optional(&mut *transaction)
        .await?;
        if let Some(ids) = replayed_page {
            transaction.commit().await?;
            return Ok(ids);
        }
        let receipt = sqlx::query(
            "SELECT state,source_revision,completed_revision,completed_claim_token, \
                    claimed_source_fingerprint \
               FROM capture_formation_receipts WHERE account_id=$1 AND capture_session_id=$2 \
               FOR UPDATE",
        )
        .bind(&settlement.claim.account_id)
        .bind(&settlement.claim.capture_session_id)
        .fetch_optional(&mut *transaction)
        .await?
        .ok_or_else(|| EnclaveError::Conflict("capture formation receipt is absent".into()))?;
        let state: String = receipt.try_get("state")?;
        let source_revision: i64 = receipt.try_get("source_revision")?;
        let completed_revision: i64 = receipt.try_get("completed_revision")?;
        let completed_claim_token: Option<String> = receipt.try_get("completed_claim_token")?;
        if state == "complete"
            && completed_revision == settlement.claim.source_revision
            && completed_claim_token.as_deref() == Some(settlement.claim.claim_token.as_str())
        {
            let ids = capture_session_owner_ids(
                &mut transaction,
                &settlement.claim.account_id,
                &settlement.claim.capture_session_id,
            )
            .await?;
            transaction.commit().await?;
            return Ok(ids);
        }
        let claimed_fingerprint: Option<Vec<u8>> = receipt.try_get("claimed_source_fingerprint")?;
        let authoritative = state == "processing"
            && source_revision == settlement.claim.source_revision
            && claimed_fingerprint.as_deref()
                == Some(settlement.claim.source_fingerprint.as_slice())
            && sqlx::query_scalar::<_, bool>(
                "SELECT EXISTS(SELECT 1 FROM capture_formation_receipts \
                  WHERE account_id=$1 AND capture_session_id=$2 AND claim_token=$3 \
                    AND claimed_revision=$4 AND claim_until>clock_timestamp())",
            )
            .bind(&settlement.claim.account_id)
            .bind(&settlement.claim.capture_session_id)
            .bind(&settlement.claim.claim_token)
            .bind(settlement.claim.source_revision)
            .fetch_one(&mut *transaction)
            .await?;
        let page = sqlx::query(
            "SELECT page_index,source_fingerprint,page_source_commitment, \
                    covered_utterance_ids,covered_screenshot_ids,provider_utterance_ids, \
                    provider_screenshot_ids,has_more,provider_attempt, \
                    provider_request #>> '{}' AS provider_request_json,provider_request_sha256, \
                    staged_response #>> '{}' AS staged_provider_response,staged_response_sha256, \
                    staged_vertex_event_id \
               FROM capture_formation_pages \
              WHERE account_id=$1 AND capture_session_id=$2 AND source_revision=$3 \
                AND page_index=$4 AND page_source_commitment=$5 AND state='processing' \
                AND claim_token=$6 AND claim_until>clock_timestamp() FOR UPDATE",
        )
        .bind(&settlement.claim.account_id)
        .bind(&settlement.claim.capture_session_id)
        .bind(settlement.claim.source_revision)
        .bind(settlement.claim.page_index)
        .bind(&settlement.claim.page_source_commitment)
        .bind(&settlement.claim.claim_token)
        .fetch_optional(&mut *transaction)
        .await?
        .ok_or_else(|| {
            EnclaveError::Conflict("capture formation page is not authoritative".into())
        })?;
        let page = capture_formation_page_from_row(&page)?;
        let provider_visible =
            !page.provider_utterance_ids.is_empty() || !page.provider_screenshot_ids.is_empty();
        if let Some(event_id) = page.staged_vertex_event_id.as_deref() {
            let attempt_identity = capture_formation_provider_attempt_identity(
                &settlement.claim.account_id,
                &settlement.claim.capture_session_id,
                settlement.claim.source_revision,
                settlement.claim.page_index,
                &settlement.claim.page_source_commitment,
                page.provider_attempt,
            );
            if vertex_attempt_event_id(&attempt_identity)? != event_id {
                return Err(EnclaveError::Conflict(
                    "capture formation staged event no longer matches its page attempt".into(),
                ));
            }
            ensure_terminal_formation_usage_event(
                &mut transaction,
                &settlement.claim.account_id,
                event_id,
                page.provider_request.as_ref().ok_or_else(|| {
                    EnclaveError::Store(
                        "capture formation staged response lost its provider request".into(),
                    )
                })?,
            )
            .await?;
        } else {
            let exact_conservative_keep = !settlement.episodes.is_empty()
                && settlement.episodes.iter().all(|episode| {
                    episode.model.as_deref() == Some("conservative-capture-page-keep-v1")
                });
            if (provider_visible && !exact_conservative_keep)
                || (!provider_visible && !settlement.episodes.is_empty())
            {
                return Err(EnclaveError::Conflict(
                    "capture formation page without a staged response must be provider-empty or an exact conservative keep"
                        .into(),
                ));
            }
        }
        if provider_visible && settlement.episodes.is_empty() {
            let staged_declares_no_memory = page
                .staged_provider_response
                .as_deref()
                .and_then(parse_capture_formation_provider_response)
                .is_some_and(|response| {
                    matches!(response, CaptureFormationProviderResponse::ExplicitNoMemory)
                });
            if !staged_declares_no_memory {
                return Err(EnclaveError::Conflict(
                    "provider-visible capture formation can settle no-memory only from an explicit empty staged response"
                        .into(),
                ));
            }
        }
        let current_fingerprint = capture_formation_source_fingerprint(
            &mut transaction,
            &settlement.claim.account_id,
            &settlement.claim.capture_session_id,
            settlement.claim.source_revision,
        )
        .await?;
        if !authoritative
            || current_fingerprint != settlement.claim.source_fingerprint
            || !capture_session_is_formation_ready(
                &mut transaction,
                &settlement.claim.account_id,
                &settlement.claim.capture_session_id,
            )
            .await?
        {
            return Err(EnclaveError::Conflict(
                "capture formation claim is no longer authoritative".into(),
            ));
        }
        let provider_utterances = page
            .provider_utterance_ids
            .iter()
            .copied()
            .collect::<std::collections::BTreeSet<_>>();
        let provider_screenshots = page
            .provider_screenshot_ids
            .iter()
            .copied()
            .collect::<std::collections::BTreeSet<_>>();
        if settlement
            .episodes
            .iter()
            .flat_map(|episode| episode.member_utterance_ids.iter())
            .any(|id| !provider_utterances.contains(id))
            || settlement
                .episodes
                .iter()
                .flat_map(|episode| episode.member_screenshot_ids.iter())
                .any(|id| !provider_screenshots.contains(id))
        {
            return Err(EnclaveError::Conflict(
                "capture formation page settlement references evidence outside its commitment"
                    .into(),
            ));
        }
        if !settlement.episodes.is_empty() {
            let utterance_members = settlement
                .episodes
                .iter()
                .flat_map(|episode| episode.member_utterance_ids.iter().copied())
                .collect::<Vec<_>>();
            let screenshot_members = settlement
                .episodes
                .iter()
                .flat_map(|episode| episode.member_screenshot_ids.iter().copied())
                .collect::<Vec<_>>();
            if utterance_members.len() != provider_utterances.len()
                || screenshot_members.len() != provider_screenshots.len()
                || utterance_members
                    .iter()
                    .copied()
                    .collect::<std::collections::BTreeSet<_>>()
                    != provider_utterances
                || screenshot_members
                    .iter()
                    .copied()
                    .collect::<std::collections::BTreeSet<_>>()
                    != provider_screenshots
            {
                return Err(EnclaveError::Conflict(
                    "capture formation memories must exactly partition the provider page".into(),
                ));
            }
        }
        ensure_episode_sources_unowned(
            &mut transaction,
            &settlement.claim.account_id,
            &settlement.episodes,
        )
        .await?;
        ensure_capture_episode_sources(
            &mut transaction,
            &settlement.claim.account_id,
            &settlement.claim.capture_session_id,
            &settlement.episodes,
        )
        .await?;

        let mut ids = Vec::with_capacity(settlement.episodes.len());
        for episode in &settlement.episodes {
            let existing = if let Some(id) = episode.id {
                sqlx::query(EXTENDABLE_EPISODE_SQL)
                    .bind(&settlement.claim.account_id)
                    .bind(id)
                    .fetch_optional(&mut *transaction)
                    .await?
            } else {
                None
            };
            let existing_id = existing.as_ref().map(|row| row.get::<i64, _>("id"));
            let existing_minutes = existing
                .as_ref()
                .and_then(|row| row.try_get::<Option<String>, _>("minutes").ok().flatten());
            let existing_substance = existing
                .as_ref()
                .and_then(|row| row.try_get::<String, _>("substance").ok());
            let existing_visual = existing
                .as_ref()
                .and_then(|row| row.try_get::<String, _>("visual_evidence").ok());
            let merged_minutes = merge_minute_summaries(
                existing_minutes.as_deref(),
                episode.minute_summaries.as_deref().unwrap_or(&[]),
            );
            let (minutes_json, minutes_text) =
                merged_minutes.unwrap_or_else(|| ("[]".into(), String::new()));
            let substance = if existing_id.is_some() {
                merge_substance(existing_substance.as_deref(), episode.substance.as_deref())
            } else {
                normalized_substance(episode.substance.as_deref())
            };
            let visual_evidence = if existing_id.is_some() {
                merge_visual_evidence(
                    existing_visual.as_deref(),
                    episode.visual_evidence.as_deref(),
                )
            } else {
                normalized_visual_evidence(episode.visual_evidence.as_deref())
            };
            let id = existing_id.unwrap_or(
                allocate_content_id(&mut transaction, &settlement.claim.account_id, "episodes")
                    .await?,
            );
            let started_ms = timestamp(&episode.started_at, "episode start")?;
            let ended_ms = timestamp(&episode.ended_at, "episode end")?;
            if ended_ms < started_ms {
                return Err(EnclaveError::InvalidRequest(
                    "episode end precedes its start".into(),
                ));
            }
            sqlx::query(
                "INSERT INTO episodes( \
                    account_id,id,started_at,ended_at,type,title,summary,participants,languages, \
                    action_items,model,minute_summaries,minutes_text,substance,visual_evidence,updated_at) \
                 VALUES($1,$2,to_timestamp($3::double precision/1000.0), \
                        to_timestamp($4::double precision/1000.0),$5,$6,$7,$8::jsonb,$9::jsonb, \
                        $10::jsonb,$11,$12::jsonb,$13,$14,$15,now()) \
                 ON CONFLICT(account_id,id) DO UPDATE SET started_at=excluded.started_at, \
                    ended_at=excluded.ended_at,type=excluded.type,title=excluded.title, \
                    summary=excluded.summary,participants=excluded.participants, \
                    languages=excluded.languages,action_items=excluded.action_items, \
                    model=excluded.model,minute_summaries=excluded.minute_summaries, \
                    minutes_text=excluded.minutes_text,substance=excluded.substance, \
                    visual_evidence=excluded.visual_evidence,updated_at=now()",
            )
            .bind(&settlement.claim.account_id)
            .bind(id)
            .bind(started_ms)
            .bind(ended_ms)
            .bind(&episode.episode_type)
            .bind(&episode.title)
            .bind(&episode.summary)
            .bind(serde_json::to_string(
                episode.participants.as_deref().unwrap_or_default(),
            )?)
            .bind(serde_json::to_string(
                episode.languages.as_deref().unwrap_or_default(),
            )?)
            .bind(serde_json::to_string(
                episode.action_items.as_deref().unwrap_or_default(),
            )?)
            .bind(&episode.model)
            .bind(minutes_json)
            .bind(minutes_text)
            .bind(substance)
            .bind(visual_evidence)
            .execute(&mut *transaction)
            .await?;
            for member_id in &episode.member_utterance_ids {
                sqlx::query(
                    "INSERT INTO episode_members(account_id,episode_id,record_type,record_id) \
                     SELECT $1,$2,'utterance',$3 WHERE EXISTS( \
                       SELECT 1 FROM utterances WHERE account_id=$1 AND id=$3) \
                     ON CONFLICT DO NOTHING",
                )
                .bind(&settlement.claim.account_id)
                .bind(id)
                .bind(member_id)
                .execute(&mut *transaction)
                .await?;
            }
            for member_id in &episode.member_screenshot_ids {
                sqlx::query(
                    "INSERT INTO episode_members(account_id,episode_id,record_type,record_id) \
                     SELECT $1,$2,'screenshot',$3 WHERE EXISTS( \
                       SELECT 1 FROM screenshots WHERE account_id=$1 AND id=$3) \
                     ON CONFLICT DO NOTHING",
                )
                .bind(&settlement.claim.account_id)
                .bind(id)
                .bind(member_id)
                .execute(&mut *transaction)
                .await?;
            }
            ids.push(id);
        }
        let page_outcome = if !ids.is_empty() {
            "memories"
        } else if page.provider_utterance_ids.is_empty()
            && page.provider_screenshot_ids.is_empty()
            && (!page.covered_utterance_ids.is_empty() || !page.covered_screenshot_ids.is_empty())
        {
            "accounted"
        } else {
            "no_memory"
        };
        let page_changed = sqlx::query(
        "UPDATE capture_formation_pages SET state='complete',claim_token=NULL,claim_until=NULL, \
                provider_request=NULL,provider_request_sha256=NULL, \
                staged_response=NULL,staged_response_sha256=NULL,staged_vertex_event_id=NULL, \
                    completed_outcome=$7,successor_episode_ids=$8,completed_claim_token=$6, \
                    completed_at=clock_timestamp(),last_error_code=NULL,updated_at=clock_timestamp() \
              WHERE account_id=$1 AND capture_session_id=$2 AND source_revision=$3 \
                AND page_index=$4 AND page_source_commitment=$5 AND state='processing' \
                AND claim_token=$6 AND claim_until>clock_timestamp()",
        )
        .bind(&settlement.claim.account_id)
        .bind(&settlement.claim.capture_session_id)
        .bind(settlement.claim.source_revision)
        .bind(settlement.claim.page_index)
        .bind(&settlement.claim.page_source_commitment)
        .bind(&settlement.claim.claim_token)
        .bind(page_outcome)
        .bind(&ids)
        .execute(&mut *transaction)
        .await?
        .rows_affected();
        if page_changed != 1 {
            return Err(EnclaveError::Conflict(
                "capture formation page expired before settlement".into(),
            ));
        }
        invalidate_reconciliation_neighborhood_scan(&mut transaction, &settlement.claim.account_id)
            .await?;
        if page.has_more {
            let changed = sqlx::query(
                "UPDATE capture_formation_receipts SET state='pending', \
                        claimed_revision=NULL,claimed_source_fingerprint=NULL,claim_token=NULL, \
                        claim_until=NULL,next_attempt_at=NULL,last_error_code=NULL, \
                        updated_at=clock_timestamp() \
                  WHERE account_id=$1 AND capture_session_id=$2 AND source_revision=$3 \
                    AND state='processing' AND claim_token=$4 AND claimed_revision=$3 \
                    AND claim_until>clock_timestamp()",
            )
            .bind(&settlement.claim.account_id)
            .bind(&settlement.claim.capture_session_id)
            .bind(settlement.claim.source_revision)
            .bind(&settlement.claim.claim_token)
            .execute(&mut *transaction)
            .await?
            .rows_affected();
            if changed != 1 {
                return Err(EnclaveError::Conflict(
                    "capture formation claim expired before page continuation".into(),
                ));
            }
            transaction.commit().await?;
            return Ok(ids);
        }
        if !capture_formation_revision_coverage_complete(
            &mut transaction,
            &settlement.claim.account_id,
            &settlement.claim.capture_session_id,
            settlement.claim.source_revision,
        )
        .await?
        {
            return Err(EnclaveError::Conflict(
                "capture formation receipt cannot complete before exact page coverage".into(),
            ));
        }
        let outcome: String = sqlx::query_scalar(
            "SELECT CASE WHEN bool_or(completed_outcome='memories') THEN 'memories' \
                         WHEN bool_or(completed_outcome='accounted') THEN 'accounted' \
                         ELSE 'no_memory' END \
               FROM capture_formation_pages WHERE account_id=$1 AND capture_session_id=$2 \
                AND source_revision=$3 AND state='complete'",
        )
        .bind(&settlement.claim.account_id)
        .bind(&settlement.claim.capture_session_id)
        .bind(settlement.claim.source_revision)
        .fetch_one(&mut *transaction)
        .await?;
        // Episode membership is itself part of the topology-neutral source
        // classification (`active_owned` boolean). A successful formation can
        // legitimately flip it from false to true, so completion binds the
        // post-write fingerprint while the claim retains the pre-write CAS.
        let completed_source_fingerprint = capture_formation_source_fingerprint(
            &mut transaction,
            &settlement.claim.account_id,
            &settlement.claim.capture_session_id,
            settlement.claim.source_revision,
        )
        .await?;
        let changed = sqlx::query(
            "UPDATE capture_formation_receipts SET state='complete', \
                    completed_revision=source_revision,completed_source_fingerprint=$4, \
                    completed_outcome=$5,completed_claim_token=claim_token,completed_at=clock_timestamp(), \
                    claimed_revision=NULL,claimed_source_fingerprint=NULL,claim_token=NULL,claim_until=NULL, \
                    next_attempt_at=NULL,last_error_code=NULL,updated_at=clock_timestamp() \
              WHERE account_id=$1 AND capture_session_id=$2 AND source_revision=$3 \
                AND state='processing' AND claim_token=$6 AND claimed_revision=$3 \
                AND claim_until>clock_timestamp()",
        )
        .bind(&settlement.claim.account_id)
        .bind(&settlement.claim.capture_session_id)
        .bind(settlement.claim.source_revision)
        .bind(&completed_source_fingerprint)
        .bind(outcome)
        .bind(&settlement.claim.claim_token)
        .execute(&mut *transaction)
        .await?
        .rows_affected();
        if changed != 1 {
            return Err(EnclaveError::Conflict(
                "capture formation claim expired before settlement".into(),
            ));
        }
        transaction.commit().await?;
        Ok(ids)
    }

    async fn open_episodes(
        &self,
        account_id: &str,
        from: &str,
        to: &str,
        limit: i64,
    ) -> Result<Vec<OpenEpisode>> {
        let from_ms = timestamp(from, "open episode start")?;
        let to_ms = timestamp(to, "open episode end")?;
        let rows = sqlx::query(OPEN_EPISODES_SQL)
            .bind(account_id)
            .bind(from_ms)
            .bind(to_ms)
            .bind(limit)
            .fetch_all(self.pool())
            .await?;
        rows.into_iter()
            .map(|row| {
                Ok(OpenEpisode {
                    id: row.try_get("id")?,
                    started_at: isotime::format_epoch_millis(row.try_get("started_at_ms")?),
                    ended_at: isotime::format_epoch_millis(row.try_get("ended_at_ms")?),
                    episode_type: row.try_get("type")?,
                    title: row
                        .try_get::<Option<String>, _>("title")?
                        .unwrap_or_else(|| "untitled".into()),
                    summary: row.try_get("summary")?,
                    participants: string_array(row.try_get("participants")?),
                    action_items: string_array(row.try_get("action_items")?),
                    recent_minutes: row.try_get("minutes_text")?,
                    utt_count: row.try_get("utterance_count")?,
                    scr_count: row.try_get("screenshot_count")?,
                })
            })
            .collect()
    }

    async fn settle_summary_window(&self, settlement: SummaryWindowSettlement) -> Result<Vec<i64>> {
        let mut transaction = self.pool().begin().await?;
        lock_activation_contract_key_share_if_installed(&mut transaction).await?;
        // The model may have selected an open draft before reconciliation
        // published. Share the account-local topology lock so the state check
        // below observes either the complete old topology or the complete new
        // one. A stale episode reference then allocates a fresh draft instead
        // of reopening a reconciled (or already finalized) memory.
        advisory_transaction_lock(
            &mut transaction,
            "memory-reconciliation",
            &settlement.claim.account_id,
        )
        .await?;
        let claimed = sqlx::query_scalar::<_, bool>(
            "SELECT true FROM summary_window_claims WHERE account_id=$1 \
              AND claim_token=$2 AND state='processing' \
              AND claim_until>clock_timestamp() FOR UPDATE",
        )
        .bind(&settlement.claim.account_id)
        .bind(&settlement.claim.claim_token)
        .fetch_optional(&mut *transaction)
        .await?
        .unwrap_or(false);
        if !claimed {
            let from_ms = timestamp(&settlement.claim.from, "summary window start")?;
            let to_ms = timestamp(&settlement.claim.to, "summary window end")?;
            let replay_succeeded = sqlx::query_scalar::<_, bool>(
                "SELECT EXISTS(SELECT 1 FROM summary_window_claims c \
                  WHERE c.account_id=$1 AND c.state='succeeded' \
                    AND c.completed_claim_token=$2 \
                    AND c.window_from=to_timestamp($3::double precision/1000.0) \
                    AND c.window_to=to_timestamp($4::double precision/1000.0))",
            )
            .bind(&settlement.claim.account_id)
            .bind(&settlement.claim.claim_token)
            .bind(from_ms)
            .bind(to_ms)
            .fetch_one(&mut *transaction)
            .await?;
            if replay_succeeded {
                let replay = sqlx::query_scalar::<_, i64>(
                    "SELECT episode_id FROM summary_window_results \
                      WHERE account_id=$1 \
                        AND window_from=to_timestamp($2::double precision/1000.0) \
                        AND window_to=to_timestamp($3::double precision/1000.0) \
                      ORDER BY ordinal",
                )
                .bind(&settlement.claim.account_id)
                .bind(from_ms)
                .bind(to_ms)
                .fetch_all(&mut *transaction)
                .await?;
                transaction.rollback().await?;
                return Ok(replay);
            }
            return Err(EnclaveError::Conflict(
                "summary window claim is no longer authoritative".into(),
            ));
        }

        ensure_episode_sources_unowned(
            &mut transaction,
            &settlement.claim.account_id,
            &settlement.episodes,
        )
        .await?;
        let mut ids = Vec::with_capacity(settlement.episodes.len());
        for episode in &settlement.episodes {
            let existing = if let Some(id) = episode.id {
                sqlx::query(EXTENDABLE_EPISODE_SQL)
                    .bind(&settlement.claim.account_id)
                    .bind(id)
                    .fetch_optional(&mut *transaction)
                    .await?
            } else {
                None
            };
            let existing_id = existing.as_ref().map(|row| row.get::<i64, _>("id"));
            let existing_minutes = existing
                .as_ref()
                .and_then(|row| row.try_get::<Option<String>, _>("minutes").ok().flatten());
            let existing_substance = existing
                .as_ref()
                .and_then(|row| row.try_get::<String, _>("substance").ok());
            let existing_visual = existing
                .as_ref()
                .and_then(|row| row.try_get::<String, _>("visual_evidence").ok());
            let merged_minutes = merge_minute_summaries(
                existing_minutes.as_deref(),
                episode.minute_summaries.as_deref().unwrap_or(&[]),
            );
            let (minutes_json, minutes_text) =
                merged_minutes.unwrap_or_else(|| ("[]".into(), String::new()));
            let substance = if existing_id.is_some() {
                merge_substance(existing_substance.as_deref(), episode.substance.as_deref())
            } else {
                normalized_substance(episode.substance.as_deref())
            };
            let visual_evidence = if existing_id.is_some() {
                merge_visual_evidence(
                    existing_visual.as_deref(),
                    episode.visual_evidence.as_deref(),
                )
            } else {
                normalized_visual_evidence(episode.visual_evidence.as_deref())
            };
            let id = existing_id.unwrap_or(
                allocate_content_id(&mut transaction, &settlement.claim.account_id, "episodes")
                    .await?,
            );
            let started_ms = timestamp(&episode.started_at, "episode start")?;
            let ended_ms = timestamp(&episode.ended_at, "episode end")?;
            if ended_ms < started_ms {
                return Err(EnclaveError::InvalidRequest(
                    "episode end precedes its start".into(),
                ));
            }
            let participants =
                serde_json::to_string(episode.participants.as_deref().unwrap_or_default())?;
            let languages =
                serde_json::to_string(episode.languages.as_deref().unwrap_or_default())?;
            let action_items =
                serde_json::to_string(episode.action_items.as_deref().unwrap_or_default())?;
            sqlx::query(
                "INSERT INTO episodes(\
                    account_id,id,started_at,ended_at,type,title,summary,participants,languages,\
                    action_items,model,minute_summaries,minutes_text,substance,visual_evidence,updated_at) \
                 VALUES($1,$2,to_timestamp($3::double precision/1000.0),\
                        to_timestamp($4::double precision/1000.0),$5,$6,$7,$8::jsonb,$9::jsonb,\
                        $10::jsonb,$11,$12::jsonb,$13,$14,$15,now()) \
                 ON CONFLICT(account_id,id) DO UPDATE SET started_at=excluded.started_at,\
                    ended_at=excluded.ended_at,type=excluded.type,title=excluded.title,\
                    summary=excluded.summary,participants=excluded.participants,\
                    languages=excluded.languages,action_items=excluded.action_items,\
                    model=excluded.model,minute_summaries=excluded.minute_summaries,\
                    minutes_text=excluded.minutes_text,substance=excluded.substance,\
                    visual_evidence=excluded.visual_evidence,updated_at=now()",
            )
            .bind(&settlement.claim.account_id)
            .bind(id)
            .bind(started_ms)
            .bind(ended_ms)
            .bind(&episode.episode_type)
            .bind(&episode.title)
            .bind(&episode.summary)
            .bind(participants)
            .bind(languages)
            .bind(action_items)
            .bind(&episode.model)
            .bind(minutes_json)
            .bind(minutes_text)
            .bind(substance)
            .bind(visual_evidence)
            .execute(&mut *transaction)
            .await?;
            for member_id in &episode.member_utterance_ids {
                sqlx::query(
                    "INSERT INTO episode_members(account_id,episode_id,record_type,record_id) \
                     SELECT $1,$2,'utterance',$3 WHERE EXISTS(\
                       SELECT 1 FROM utterances WHERE account_id=$1 AND id=$3) \
                     ON CONFLICT DO NOTHING",
                )
                .bind(&settlement.claim.account_id)
                .bind(id)
                .bind(member_id)
                .execute(&mut *transaction)
                .await?;
            }
            for member_id in &episode.member_screenshot_ids {
                sqlx::query(
                    "INSERT INTO episode_members(account_id,episode_id,record_type,record_id) \
                     SELECT $1,$2,'screenshot',$3 WHERE EXISTS(\
                       SELECT 1 FROM screenshots WHERE account_id=$1 AND id=$3) \
                     ON CONFLICT DO NOTHING",
                )
                .bind(&settlement.claim.account_id)
                .bind(id)
                .bind(member_id)
                .execute(&mut *transaction)
                .await?;
            }
            ids.push(id);
        }
        let window_from_ms = timestamp(&settlement.claim.from, "summary window start")?;
        let window_to_ms = timestamp(&settlement.claim.to, "summary window end")?;
        for (ordinal, episode_id) in ids.iter().enumerate() {
            sqlx::query(
                "INSERT INTO summary_window_results(\
                    account_id,window_from,window_to,ordinal,episode_id) \
                 VALUES($1,to_timestamp($2::double precision/1000.0),\
                        to_timestamp($3::double precision/1000.0),$4,$5)",
            )
            .bind(&settlement.claim.account_id)
            .bind(window_from_ms)
            .bind(window_to_ms)
            .bind(
                i64::try_from(ordinal)
                    .map_err(|_| EnclaveError::Store("summary result ordinal overflow".into()))?,
            )
            .bind(episode_id)
            .execute(&mut *transaction)
            .await?;
        }
        if let Some(cursor) = settlement.cursor.as_deref() {
            let cursor_ms = timestamp(cursor, "summary cursor")?;
            sqlx::query(
                "UPDATE accounts SET summarized_until=GREATEST(\
                    coalesce(summarized_until,'epoch'::timestamptz),\
                    to_timestamp($2::double precision/1000.0)),updated_at=now() WHERE id=$1",
            )
            .bind(&settlement.claim.account_id)
            .bind(cursor_ms)
            .execute(&mut *transaction)
            .await?;
        }
        sqlx::query(
            "UPDATE summary_window_claims SET state='succeeded',\
                    completed_claim_token=claim_token,claim_token=NULL,claim_until=NULL,\
                    error_code=NULL,completed_at=now(),updated_at=now() \
              WHERE account_id=$1 AND claim_token=$2",
        )
        .bind(&settlement.claim.account_id)
        .bind(&settlement.claim.claim_token)
        .execute(&mut *transaction)
        .await?;
        transaction.commit().await?;
        Ok(ids)
    }

    async fn episode_embedding_sources(
        &self,
        account_id: &str,
        ids: &[i64],
    ) -> Result<Vec<EpisodeEmbeddingSource>> {
        let rows = sqlx::query(
            "SELECT e.id,concat_ws(E'\\n',e.title,e.summary,e.minutes_text,fb.overview, \
                    (SELECT string_agg(value #>> '{}',E'\\n' ORDER BY ordinal) \
                       FROM jsonb_path_query( \
                         fb.decisions||fb.action_items||fb.important_links||fb.open_questions, \
                         'strict $.** ? (@.type() == \"string\")' \
                       ) WITH ORDINALITY AS strings(value,ordinal))) AS text \
               FROM episodes e LEFT JOIN episode_final_briefs fb \
                 ON fb.account_id=e.account_id AND fb.episode_id=e.id \
              WHERE e.account_id=$1 AND e.id=ANY($2) ORDER BY e.id",
        )
        .bind(account_id)
        .bind(ids)
        .fetch_all(self.pool())
        .await?;
        rows.into_iter()
            .filter_map(|row| {
                let text = row.try_get::<String, _>("text").ok()?;
                if text.trim().is_empty() {
                    return None;
                }
                Some(Ok(EpisodeEmbeddingSource {
                    id: row.get("id"),
                    text,
                }))
            })
            .collect()
    }

    async fn write_episode_embeddings(
        &self,
        account_id: &str,
        writes: &[EpisodeEmbeddingWrite],
    ) -> Result<()> {
        let mut transaction = self.pool().begin().await?;
        for write in writes {
            sqlx::query("UPDATE episodes SET embedding=$3::vector,updated_at=now() WHERE account_id=$1 AND id=$2")
                .bind(account_id)
                .bind(write.id)
                .bind(vector_literal(&write.embedding)?)
                .execute(&mut *transaction)
                .await?;
        }
        transaction.commit().await?;
        Ok(())
    }

    async fn session_tail_is_settled(&self, account_id: &str, recent_after: &str) -> Result<bool> {
        let recent_after_ms = timestamp(recent_after, "recent session cutoff")?;
        Ok(sqlx::query_scalar::<_, bool>(
            "SELECT NOT EXISTS(SELECT 1 FROM capture_sessions WHERE account_id=$1 \
                    AND ended_at IS NULL AND last_event_at>=to_timestamp($2::double precision/1000.0)) \
                AND NOT EXISTS(SELECT 1 FROM media_objects WHERE account_id=$1 \
                    AND processing_state IN ('queued','processing','retry_wait') AND deleted_at IS NULL)",
        )
        .bind(account_id)
        .bind(recent_after_ms)
        .fetch_one(self.pool())
        .await?)
    }
}

#[cfg(test)]
pub(super) async fn test_real_pg_oversized_formation_and_neighborhood(
    persistence: &PostgresPersistence,
) -> Result<()> {
    use crate::{
        cp::vertex::VertexOperation,
        persistence::{
            MemoryReconciliationRepository as _, ModelUsageRepository as _,
            OversizedKeepPromotionPolicy, OversizedKeepPromotionResult, VertexInvocationAdmission,
        },
    };

    const ACCOUNT: &str = "activation-oversized-formation";
    const SESSION: &str = "oversized-formation-session";
    sqlx::query(
        "INSERT INTO accounts(id,email,primary_provider,primary_subject,summarized_until,created_at) \
         VALUES($1,'oversized-formation@example.com','google','oversized-formation-subject', \
                '2026-08-02T00:00:00Z','2026-08-01T00:00:00Z')",
    )
    .bind(ACCOUNT)
    .execute(persistence.pool())
    .await?;
    sqlx::query(
        "INSERT INTO content_id_counters(account_id,entity_kind,next_id) VALUES($1,'episodes',1)",
    )
    .bind(ACCOUNT)
    .execute(persistence.pool())
    .await?;
    sqlx::query(
        "INSERT INTO capture_sessions( \
             account_id,id,device_id,install_id,started_at,last_event_at,ended_at,schema_version,created_at) \
         VALUES($1,$2,'oversized-device','oversized-install','2026-08-01T10:00:00Z', \
                '2026-08-01T10:01:00Z','2026-08-01T10:01:00Z',2,'2026-08-01T10:00:00Z')",
    )
    .bind(ACCOUNT)
    .bind(SESSION)
    .execute(persistence.pool())
    .await?;
    sqlx::query(
        "INSERT INTO capture_streams( \
             account_id,id,capture_session_id,device_id,stream_kind, \
             committed_through_sequence,sealed_sequence,created_at) \
         VALUES($1,'oversized-stream',$2,'oversized-device','mac_screen',2000,2000, \
                '2026-08-01T10:00:00Z')",
    )
    .bind(ACCOUNT)
    .bind(SESSION)
    .execute(persistence.pool())
    .await?;
    sqlx::query(
        "INSERT INTO capture_events( \
             account_id,event_id,device_id,install_id,capture_session_id,stream_id,stream_kind, \
             sequence,source_wall_at,source_monotonic_ns,started_at,ended_at,timezone_id, \
             utc_offset_minutes,clock_uncertainty_ms,asset_id,manifest_digest,media_disposition,received_at) \
         SELECT $1,format('oversized-event-%s',n),'oversized-device','oversized-install',$2, \
                'oversized-stream','mac_screen',n, \
                '2026-08-01T10:00:00Z'::timestamptz+n*interval '1 millisecond',n::text, \
                '2026-08-01T10:00:00Z'::timestamptz+n*interval '1 millisecond', \
                '2026-08-01T10:00:00Z'::timestamptz+(n+1)*interval '1 millisecond', \
                'UTC',0,0,format('oversized-asset-%s',n),repeat('a',64),'canonical', \
                '2026-08-01T10:00:00Z' \
           FROM generate_series(0,2000) n",
    )
    .bind(ACCOUNT)
    .bind(SESSION)
    .execute(persistence.pool())
    .await?;
    sqlx::query(
        "INSERT INTO media_processing_jobs( \
             account_id,event_id,job_kind,input_revision,processor_version,state,updated_at) \
         SELECT $1,format('oversized-event-%s',n),'gemini_screen', \
                format('oversized-input-%s',n),1,'succeeded','2026-08-01T10:00:00Z' \
           FROM generate_series(0,2000) n",
    )
    .bind(ACCOUNT)
    .execute(persistence.pool())
    .await?;
    sqlx::query(
        "INSERT INTO screenshots(account_id,id,captured_at,active_app,window_title,ocr_text,source_key) \
         SELECT $1,10000+n,'2026-08-01T10:00:00Z'::timestamptz+n*interval '1 millisecond', \
                'Test','Oversized page',format('screenshot %s',n), \
                format('cloud-v2:oversized-event-%s',n) \
           FROM generate_series(0,2000) n",
    )
    .bind(ACCOUNT)
    .execute(persistence.pool())
    .await?;
    sqlx::query(
        "INSERT INTO audio_segments( \
             account_id,id,started_at,ended_at,duration_seconds,source_type,transcription_status) \
         VALUES($1,1,'2026-08-01T10:00:00Z','2026-08-01T10:10:00Z',600,'system','ready')",
    )
    .bind(ACCOUNT)
    .execute(persistence.pool())
    .await?;
    sqlx::query(
        "INSERT INTO speaker_observations( \
             account_id,id,event_id,turn_id,speaker_local_id,started_at,ended_at,transcript_text) \
         VALUES($1,1,'oversized-event-0','turn-0','speaker-0', \
                '2026-08-01T10:00:00Z','2026-08-01T10:00:10Z','oversized transcript')",
    )
    .bind(ACCOUNT)
    .execute(persistence.pool())
    .await?;
    sqlx::query(
        "INSERT INTO utterances( \
             account_id,id,audio_segment_id,start_offset_seconds,end_offset_seconds,text, \
             speaker_label,source_key,speaker_observation_id) \
         SELECT $1,n,1,n::double precision/1000.0,(n+1)::double precision/1000.0, \
                format('utterance %s',n),'Me', \
                format('cloud-v2:oversized-event-0:utterance:%s',n),1 \
           FROM generate_series(1,4001) n",
    )
    .bind(ACCOUNT)
    .execute(persistence.pool())
    .await?;
    let first_source_fingerprint = {
        let mut connection = persistence.pool().acquire().await?;
        capture_formation_source_fingerprint(&mut connection, ACCOUNT, SESSION, 1).await?
    };
    let restarted_source_fingerprint = {
        let mut connection = persistence.pool().acquire().await?;
        capture_formation_source_fingerprint(&mut connection, ACCOUNT, SESSION, 1).await?
    };
    assert_eq!(
        first_source_fingerprint, restarted_source_fingerprint,
        "the bounded 2,001-event/4,001-utterance/2,001-screenshot fingerprint must be restart-stable"
    );
    sqlx::query(
        "INSERT INTO capture_formation_receipts( \
             account_id,capture_session_id,source_revision,finish_requested_at,finish_request_provenance) \
         VALUES($1,$2,1,'2026-08-01T10:02:00Z','finish_endpoint_v1')",
    )
    .bind(ACCOUNT)
    .bind(SESSION)
    .execute(persistence.pool())
    .await?;
    let seal_preflight = sqlx::query(
        "SELECT receipt.source_revision,receipt.seal_generation, \
                receipt.finish_requested_at IS NOT NULL AS finish_requested, \
                receipt.seal_finalized_at IS NULL AS not_finalized, \
                stream.committed_through_sequence,stream.sealed_sequence, \
                capture_formation_stream_accepted_max(stream.account_id,stream.id) AS accepted_max, \
                capture_formation_stream_contiguous_through(stream.account_id,stream.id) \
                    AS contiguous_through \
           FROM capture_formation_receipts receipt \
           JOIN capture_streams stream ON stream.account_id=receipt.account_id \
                AND stream.capture_session_id=receipt.capture_session_id \
          WHERE receipt.account_id=$1 AND receipt.capture_session_id=$2",
    )
    .bind(ACCOUNT)
    .bind(SESSION)
    .fetch_one(persistence.pool())
    .await?;
    let seal_preflight_exact = seal_preflight.try_get::<i64, _>("source_revision")? == 1
        && seal_preflight.try_get::<i64, _>("seal_generation")? == 0
        && seal_preflight.try_get::<bool, _>("finish_requested")?
        && seal_preflight.try_get::<bool, _>("not_finalized")?
        && seal_preflight.try_get::<i64, _>("committed_through_sequence")? == 2_000
        && seal_preflight.try_get::<Option<i64>, _>("sealed_sequence")? == Some(2_000)
        && seal_preflight.try_get::<Option<i64>, _>("accepted_max")? == Some(2_000)
        && seal_preflight.try_get::<i64, _>("contiguous_through")? == 2_000;
    if !seal_preflight_exact {
        return Err(EnclaveError::Store(format!(
            "oversized formation seal preflight is not exact: {seal_preflight:?}"
        )));
    }
    sqlx::query(
        "INSERT INTO capture_formation_seal_events( \
             account_id,capture_session_id,seal_generation,source_revision,event_kind, \
             stream_maxima_sha256,provenance) \
         VALUES($1,$2,1,1,'seal',capture_formation_stream_maxima_sha256($1,$2), \
                'quiet_contiguous_v1')",
    )
    .bind(ACCOUNT)
    .bind(SESSION)
    .execute(persistence.pool())
    .await?;
    sqlx::query(
        "UPDATE capture_formation_receipts SET seal_generation=1, \
                seal_finalized_at='2026-08-01T10:03:00Z', \
                seal_finalization_provenance='quiet_contiguous_v1' \
          WHERE account_id=$1 AND capture_session_id=$2",
    )
    .bind(ACCOUNT)
    .bind(SESSION)
    .execute(persistence.pool())
    .await?;

    let request = |tag: &str| CaptureFormationProviderRequest {
        contract_version: 1,
        vertex_project: "kioku-test".into(),
        vertex_location: "us-central1".into(),
        api_version: "v1".into(),
        publisher: "google".into(),
        model: format!("gemini-page-{tag}"),
        method: "generateContent".into(),
        system_prompt: format!("system contract {tag}"),
        user_message: format!("exact page contract {tag}"),
        response_schema: capture_formation_response_schema_v1(),
        max_output_tokens: CAPTURE_FORMATION_PROVIDER_MAX_OUTPUT_TOKENS,
        response_mime_type: "application/json".into(),
        thinking_budget: 0,
    };
    let mark_due = || async {
        sqlx::query(
            "UPDATE capture_formation_receipts SET next_attempt_at=clock_timestamp()-interval '1 second' \
              WHERE account_id=$1 AND capture_session_id=$2 AND state='retry_wait'",
        )
        .bind(ACCOUNT)
        .bind(SESSION)
        .execute(persistence.pool())
        .await
        .map(|_| ())
        .map_err(EnclaveError::from)
    };

    let first = persistence
        .claim_capture_formation(ACCOUNT, 900)
        .await?
        .ok_or_else(|| EnclaveError::Store("oversized formation page 0 was not claimed".into()))?;
    assert_eq!(first.page_index, 0);
    assert!(first.page_has_more);
    let (page0_utterances, page0_screenshots) = persistence
        .capture_formation_evidence(&first, 4_000, 2_000)
        .await?;
    assert_eq!(page0_utterances.len(), 4_000);
    assert_eq!(page0_screenshots.len(), 2_000);
    let page0_utterance_ids = page0_utterances
        .iter()
        .map(|row| row.id)
        .collect::<Vec<_>>();
    let page0_screenshot_ids = page0_screenshots
        .iter()
        .map(|row| row.id)
        .collect::<Vec<_>>();
    let request_v1 = request("v1");
    assert_eq!(
        persistence
            .authorize_capture_formation_egress(
                &first,
                &page0_utterance_ids,
                &page0_screenshot_ids,
                &request_v1,
            )
            .await?,
        request_v1
    );
    let request_v1_hash =
        Sha256::digest(capture_formation_provider_request_bytes(&request_v1)?).to_vec();
    sqlx::query(
        "UPDATE capture_formation_pages SET provider_request_sha256=$3 \
          WHERE account_id=$1 AND capture_session_id=$2 AND source_revision=1 AND page_index=0",
    )
    .bind(ACCOUNT)
    .bind(SESSION)
    .bind(vec![0_u8; 32])
    .execute(persistence.pool())
    .await?;
    assert!(persistence
        .capture_formation_evidence(&first, 4_000, 2_000)
        .await
        .is_err());
    sqlx::query(
        "UPDATE capture_formation_pages SET provider_request_sha256=$3 \
          WHERE account_id=$1 AND capture_session_id=$2 AND source_revision=1 AND page_index=0",
    )
    .bind(ACCOUNT)
    .bind(SESSION)
    .bind(&request_v1_hash)
    .execute(persistence.pool())
    .await?;
    let mut invalidation = persistence.pool().begin().await?;
    super::capture::mark_capture_formation_dirty(&mut invalidation, ACCOUNT, &[SESSION.to_owned()])
        .await?;
    // This synthetic mutation occurs after the fixture's structural seal.
    // Model the writer's matching seal invalidation before appending the next
    // exact generation; the append-only trigger must never be weakened merely
    // to make a revised formation page claimable.
    sqlx::query(
        "UPDATE capture_formation_receipts SET seal_finalized_at=NULL, \
                seal_finalization_provenance=NULL \
          WHERE account_id=$1 AND capture_session_id=$2 AND source_revision=2 \
            AND seal_generation=1",
    )
    .bind(ACCOUNT)
    .bind(SESSION)
    .execute(&mut *invalidation)
    .await?;
    invalidation.commit().await?;
    let invalidated = sqlx::query(
        "SELECT state,provider_request IS NULL AS request_cleared, \
                staged_response IS NULL AS response_cleared \
           FROM capture_formation_pages \
          WHERE account_id=$1 AND capture_session_id=$2 AND source_revision=1 AND page_index=0",
    )
    .bind(ACCOUNT)
    .bind(SESSION)
    .fetch_one(persistence.pool())
    .await?;
    assert_eq!(invalidated.try_get::<String, _>("state")?, "invalidated");
    assert!(invalidated.try_get::<bool, _>("request_cleared")?);
    assert!(invalidated.try_get::<bool, _>("response_cleared")?);
    sqlx::query(
        "INSERT INTO capture_formation_seal_events( \
             account_id,capture_session_id,seal_generation,source_revision,event_kind, \
             stream_maxima_sha256,provenance) \
         VALUES($1,$2,2,2,'seal',capture_formation_stream_maxima_sha256($1,$2), \
                'quiet_contiguous_v1')",
    )
    .bind(ACCOUNT)
    .bind(SESSION)
    .execute(persistence.pool())
    .await?;
    sqlx::query(
        "UPDATE capture_formation_receipts SET seal_generation=2, \
                seal_finalized_at='2026-08-01T10:03:30Z', \
                seal_finalization_provenance='quiet_contiguous_v1' \
          WHERE account_id=$1 AND capture_session_id=$2",
    )
    .bind(ACCOUNT)
    .bind(SESSION)
    .execute(persistence.pool())
    .await?;
    let first = persistence
        .claim_capture_formation(ACCOUNT, 900)
        .await?
        .ok_or_else(|| EnclaveError::Store("revised oversized page was not claimed".into()))?;
    assert_eq!(first.source_revision, 2);
    let (page0_utterances, page0_screenshots) = persistence
        .capture_formation_evidence(&first, 4_000, 2_000)
        .await?;
    let page0_utterance_ids = page0_utterances
        .iter()
        .map(|row| row.id)
        .collect::<Vec<_>>();
    let page0_screenshot_ids = page0_screenshots
        .iter()
        .map(|row| row.id)
        .collect::<Vec<_>>();
    assert_eq!(
        persistence
            .authorize_capture_formation_egress(
                &first,
                &page0_utterance_ids,
                &page0_screenshot_ids,
                &request_v1,
            )
            .await?,
        request_v1
    );
    persistence
        .release_capture_formation(
            &first,
            Some("test_pre_egress"),
            CaptureFormationRetryDisposition::PreserveProviderAttempt,
        )
        .await?;
    mark_due().await?;
    let replay = persistence
        .claim_capture_formation(ACCOUNT, 900)
        .await?
        .ok_or_else(|| EnclaveError::Store("oversized page replay was not claimed".into()))?;
    assert_eq!(
        replay.provider_attempt_identity,
        first.provider_attempt_identity
    );
    assert_eq!(replay.provider_request.as_ref(), Some(&request_v1));
    let request_v2 = request("v2");
    assert_eq!(
        persistence
            .authorize_capture_formation_egress(
                &replay,
                &page0_utterance_ids,
                &page0_screenshot_ids,
                &request_v2,
            )
            .await?,
        request_v1,
        "cross-deploy reclaim must use the already-bound request"
    );
    persistence
        .release_capture_formation(
            &replay,
            Some("test_confirmed_not_billed"),
            CaptureFormationRetryDisposition::AdvanceConfirmedNotBilled,
        )
        .await?;
    mark_due().await?;
    let second_attempt = persistence
        .claim_capture_formation(ACCOUNT, 900)
        .await?
        .ok_or_else(|| EnclaveError::Store("confirmed retry was not claimed".into()))?;
    assert_ne!(
        second_attempt.provider_attempt_identity,
        first.provider_attempt_identity
    );
    assert!(second_attempt.provider_request.is_none());
    assert_eq!(
        persistence
            .authorize_capture_formation_egress(
                &second_attempt,
                &page0_utterance_ids,
                &page0_screenshot_ids,
                &request_v2,
            )
            .await?,
        request_v2
    );
    let page0_event_id = vertex_attempt_event_id(&second_attempt.provider_attempt_identity)?;
    assert!(persistence
        .stage_capture_formation_response(&second_attempt, "{\"episodes\":[]}", "vtx_wrong")
        .await
        .is_err());
    assert!(persistence
        .stage_capture_formation_response(&second_attempt, "{\"episodes\":[]}", &page0_event_id,)
        .await
        .is_err());
    let page0_attempt_identity: [u8; 32] = second_attempt
        .provider_attempt_identity
        .as_slice()
        .try_into()
        .map_err(|_| EnclaveError::Store("test formation attempt identity is invalid".into()))?;
    let page0_caller_anchor = capture_formation_provider_caller_anchor(&request_v2)?;
    let page0_invocation = persistence
        .begin_invocation_attempt(
            ACCOUNT,
            VertexOperation::EpisodeSummary,
            &request_v2.model,
            &request_v2.vertex_location,
            &page0_caller_anchor,
            &page0_attempt_identity,
        )
        .await?;
    assert_eq!(page0_invocation.admission, VertexInvocationAdmission::Send);
    assert_eq!(page0_invocation.event_id, page0_event_id);
    sqlx::query(
        "UPDATE vertex_usage_events SET outcome='usage_missing',http_status=200, \
                updated_at=clock_timestamp() WHERE account_id=$1 AND event_id=$2",
    )
    .bind(ACCOUNT)
    .bind(&page0_event_id)
    .execute(persistence.pool())
    .await?;
    let exact_usage_fingerprint: Vec<u8> = sqlx::query_scalar(
        "SELECT request_fingerprint FROM vertex_usage_events \
          WHERE account_id=$1 AND event_id=$2",
    )
    .bind(ACCOUNT)
    .bind(&page0_event_id)
    .fetch_one(persistence.pool())
    .await?;
    let staged_response = "{\"episodes\":[],\"literal\":\"記憶🙂\"}";
    assert!(persistence
        .stage_capture_formation_response(
            &second_attempt,
            &"x".repeat(MAX_STAGED_FORMATION_RESPONSE_BYTES + 1),
            &page0_event_id,
        )
        .await
        .is_err());
    sqlx::query(
        "UPDATE vertex_usage_events SET request_fingerprint=$3 \
          WHERE account_id=$1 AND event_id=$2",
    )
    .bind(ACCOUNT)
    .bind(&page0_event_id)
    .bind(vec![9_u8; 32])
    .execute(persistence.pool())
    .await?;
    assert!(persistence
        .stage_capture_formation_response(&second_attempt, staged_response, &page0_event_id)
        .await
        .is_err());
    sqlx::query(
        "UPDATE vertex_usage_events SET request_fingerprint=$3 \
          WHERE account_id=$1 AND event_id=$2",
    )
    .bind(ACCOUNT)
    .bind(&page0_event_id)
    .bind(&exact_usage_fingerprint)
    .execute(persistence.pool())
    .await?;
    for (wrong_model, wrong_location, wrong_operation, wrong_outcome) in [
        (Some("wrong-model"), None, None, None),
        (None, Some("wrong-location"), None, None),
        (None, None, Some("episode_finalization"), None),
        (None, None, None, Some("ambiguous")),
    ] {
        sqlx::query(
            "UPDATE vertex_usage_events SET \
                    requested_model=coalesce($3,requested_model), \
                    location=coalesce($4,location),operation=coalesce($5,operation), \
                    outcome=coalesce($6,outcome) \
              WHERE account_id=$1 AND event_id=$2",
        )
        .bind(ACCOUNT)
        .bind(&page0_event_id)
        .bind(wrong_model)
        .bind(wrong_location)
        .bind(wrong_operation)
        .bind(wrong_outcome)
        .execute(persistence.pool())
        .await?;
        assert!(persistence
            .stage_capture_formation_response(&second_attempt, staged_response, &page0_event_id)
            .await
            .is_err());
        sqlx::query(
            "UPDATE vertex_usage_events SET requested_model=$3,location=$4, \
                    operation='episode_summarization',outcome='usage_missing' \
              WHERE account_id=$1 AND event_id=$2",
        )
        .bind(ACCOUNT)
        .bind(&page0_event_id)
        .bind(&request_v2.model)
        .bind(&request_v2.vertex_location)
        .execute(persistence.pool())
        .await?;
    }
    sqlx::query(
        "UPDATE vertex_usage_events SET http_status=500 \
          WHERE account_id=$1 AND event_id=$2",
    )
    .bind(ACCOUNT)
    .bind(&page0_event_id)
    .execute(persistence.pool())
    .await?;
    assert!(persistence
        .stage_capture_formation_response(&second_attempt, staged_response, &page0_event_id)
        .await
        .is_err());
    sqlx::query(
        "UPDATE vertex_usage_events SET http_status=200 \
          WHERE account_id=$1 AND event_id=$2",
    )
    .bind(ACCOUNT)
    .bind(&page0_event_id)
    .execute(persistence.pool())
    .await?;
    persistence
        .stage_capture_formation_response(&second_attempt, staged_response, &page0_event_id)
        .await?;
    assert!(sqlx::query(
        "UPDATE capture_formation_pages \
            SET provider_request=NULL,provider_request_sha256=NULL \
          WHERE account_id=$1 AND capture_session_id=$2 AND source_revision=2 AND page_index=0",
    )
    .bind(ACCOUNT)
    .bind(SESSION)
    .execute(persistence.pool())
    .await
    .is_err());
    assert!(persistence
        .release_capture_formation(
            &second_attempt,
            Some("test_invalid_advance_after_stage"),
            CaptureFormationRetryDisposition::AdvanceConfirmedNotBilled,
        )
        .await
        .is_err());
    assert_eq!(
        sqlx::query_scalar::<_, String>(
            "SELECT staged_response #>> '{}' FROM capture_formation_pages \
              WHERE account_id=$1 AND capture_session_id=$2 AND source_revision=2 AND page_index=0",
        )
        .bind(ACCOUNT)
        .bind(SESSION)
        .fetch_one(persistence.pool())
        .await?,
        staged_response
    );
    sqlx::query(
        "UPDATE capture_formation_pages SET staged_response_sha256=$3 \
          WHERE account_id=$1 AND capture_session_id=$2 AND source_revision=2 AND page_index=0",
    )
    .bind(ACCOUNT)
    .bind(SESSION)
    .bind(vec![0_u8; 32])
    .execute(persistence.pool())
    .await?;
    assert!(persistence
        .capture_formation_evidence(&second_attempt, 4_000, 2_000)
        .await
        .is_err());
    sqlx::query(
        "UPDATE capture_formation_pages SET staged_response_sha256=$3 \
          WHERE account_id=$1 AND capture_session_id=$2 AND source_revision=2 AND page_index=0",
    )
    .bind(ACCOUNT)
    .bind(SESSION)
    .bind(Sha256::digest(staged_response.as_bytes()).to_vec())
    .execute(persistence.pool())
    .await?;
    let page0_settlement = CaptureFormationSettlement {
        claim: second_attempt.clone(),
        episodes: Vec::new(),
    };
    sqlx::query(
        "UPDATE capture_formation_pages SET staged_vertex_event_id=$3 \
          WHERE account_id=$1 AND capture_session_id=$2 AND source_revision=2 AND page_index=0",
    )
    .bind(ACCOUNT)
    .bind(SESSION)
    .bind(format!("vtx_{}", "0".repeat(64)))
    .execute(persistence.pool())
    .await?;
    assert!(persistence
        .settle_capture_formation(page0_settlement.clone())
        .await
        .is_err());
    sqlx::query(
        "UPDATE capture_formation_pages SET staged_vertex_event_id=$3 \
          WHERE account_id=$1 AND capture_session_id=$2 AND source_revision=2 AND page_index=0",
    )
    .bind(ACCOUNT)
    .bind(SESSION)
    .bind(&page0_event_id)
    .execute(persistence.pool())
    .await?;
    sqlx::query(
        "UPDATE vertex_usage_events SET request_fingerprint=$3 \
          WHERE account_id=$1 AND event_id=$2",
    )
    .bind(ACCOUNT)
    .bind(&page0_event_id)
    .bind(vec![7_u8; 32])
    .execute(persistence.pool())
    .await?;
    assert!(persistence
        .settle_capture_formation(page0_settlement.clone())
        .await
        .is_err());
    sqlx::query(
        "UPDATE vertex_usage_events SET request_fingerprint=$3 \
          WHERE account_id=$1 AND event_id=$2",
    )
    .bind(ACCOUNT)
    .bind(&page0_event_id)
    .bind(&exact_usage_fingerprint)
    .execute(persistence.pool())
    .await?;
    for rejected_response in ["not-json", r#"{"episodes":[{}]}"#] {
        sqlx::query(
            "UPDATE capture_formation_pages \
                SET staged_response=to_jsonb($3::text),staged_response_sha256=$4 \
              WHERE account_id=$1 AND capture_session_id=$2 \
                AND source_revision=2 AND page_index=0",
        )
        .bind(ACCOUNT)
        .bind(SESSION)
        .bind(rejected_response)
        .bind(Sha256::digest(rejected_response.as_bytes()).to_vec())
        .execute(persistence.pool())
        .await?;
        assert!(persistence
            .settle_capture_formation(page0_settlement.clone())
            .await
            .is_err());
        assert_eq!(
            sqlx::query_scalar::<_, String>(
                "SELECT state FROM capture_formation_pages \
                  WHERE account_id=$1 AND capture_session_id=$2 \
                    AND source_revision=2 AND page_index=0",
            )
            .bind(ACCOUNT)
            .bind(SESSION)
            .fetch_one(persistence.pool())
            .await?,
            "processing"
        );
    }
    sqlx::query(
        "UPDATE capture_formation_pages \
            SET staged_response=to_jsonb($3::text),staged_response_sha256=$4 \
          WHERE account_id=$1 AND capture_session_id=$2 \
            AND source_revision=2 AND page_index=0",
    )
    .bind(ACCOUNT)
    .bind(SESSION)
    .bind(staged_response)
    .bind(Sha256::digest(staged_response.as_bytes()).to_vec())
    .execute(persistence.pool())
    .await?;
    assert!(persistence
        .settle_capture_formation(page0_settlement.clone())
        .await?
        .is_empty());
    assert!(persistence
        .settle_capture_formation(page0_settlement)
        .await?
        .is_empty());

    let last_page = persistence
        .claim_capture_formation(ACCOUNT, 900)
        .await?
        .ok_or_else(|| EnclaveError::Store("oversized formation page 1 was not claimed".into()))?;
    assert_eq!(last_page.page_index, 1);
    assert!(!last_page.page_has_more);
    let (last_utterances, last_screenshots) = persistence
        .capture_formation_evidence(&last_page, 4_000, 2_000)
        .await?;
    assert_eq!(last_utterances.len(), 1);
    assert_eq!(last_screenshots.len(), 1);
    let last_utterance_ids = last_utterances.iter().map(|row| row.id).collect::<Vec<_>>();
    let last_screenshot_ids = last_screenshots
        .iter()
        .map(|row| row.id)
        .collect::<Vec<_>>();
    let request_v3 = request("v3");
    assert_eq!(
        persistence
            .authorize_capture_formation_egress(
                &last_page,
                &last_utterance_ids,
                &last_screenshot_ids,
                &request_v3,
            )
            .await?,
        request_v3
    );
    let attempt_identity: [u8; 32] = last_page
        .provider_attempt_identity
        .as_slice()
        .try_into()
        .map_err(|_| EnclaveError::Store("test formation attempt identity is invalid".into()))?;
    let caller_anchor = capture_formation_provider_caller_anchor(&request_v3)?;
    let started = persistence
        .begin_invocation_attempt(
            ACCOUNT,
            VertexOperation::EpisodeSummary,
            &request_v3.model,
            &request_v3.vertex_location,
            &caller_anchor,
            &attempt_identity,
        )
        .await?;
    assert_eq!(started.admission, VertexInvocationAdmission::Send);
    sqlx::query(
        "UPDATE vertex_usage_events SET outcome='usage_missing',http_status=200, \
                updated_at=clock_timestamp() WHERE account_id=$1 AND event_id=$2",
    )
    .bind(ACCOUNT)
    .bind(&started.event_id)
    .execute(persistence.pool())
    .await?;
    persistence
        .release_capture_formation(
            &last_page,
            Some("test_crash_before_stage"),
            CaptureFormationRetryDisposition::PreserveProviderAttempt,
        )
        .await?;
    mark_due().await?;
    let lost_response = persistence
        .claim_capture_formation(ACCOUNT, 900)
        .await?
        .ok_or_else(|| EnclaveError::Store("ambiguous formation page was not reclaimed".into()))?;
    assert_eq!(
        lost_response.provider_attempt_identity,
        last_page.provider_attempt_identity
    );
    assert!(lost_response.staged_provider_response.is_none());
    let request_v4 = request("v4");
    let exact_replay_request = persistence
        .authorize_capture_formation_egress(
            &lost_response,
            &last_utterance_ids,
            &last_screenshot_ids,
            &request_v4,
        )
        .await?;
    assert_eq!(exact_replay_request, request_v3);
    let replay_admission = persistence
        .begin_invocation_attempt(
            ACCOUNT,
            VertexOperation::EpisodeSummary,
            &exact_replay_request.model,
            &exact_replay_request.vertex_location,
            &caller_anchor,
            &attempt_identity,
        )
        .await?;
    assert_eq!(
        replay_admission.admission,
        VertexInvocationAdmission::AmbiguousTerminal,
        "a terminal provider intent without staged bytes must never re-egress"
    );
    assert!(persistence
        .settle_capture_formation(CaptureFormationSettlement {
            claim: lost_response.clone(),
            episodes: Vec::new(),
        })
        .await
        .is_err());
    assert_eq!(
        sqlx::query_as::<_, (String, String)>(
            "SELECT page.state,receipt.state FROM capture_formation_pages page \
              JOIN capture_formation_receipts receipt ON receipt.account_id=page.account_id \
                   AND receipt.capture_session_id=page.capture_session_id \
             WHERE page.account_id=$1 AND page.capture_session_id=$2 \
               AND page.source_revision=2 AND page.page_index=1",
        )
        .bind(ACCOUNT)
        .bind(SESSION)
        .fetch_one(persistence.pool())
        .await?,
        ("processing".into(), "processing".into()),
        "provider-visible evidence cannot become false no-memory without a staged response"
    );
    let episode = |utterances: Vec<i64>, screenshots: Vec<i64>| crate::persistence::EpisodeInput {
        id: None,
        started_at: "2026-08-01T10:00:00.000Z".into(),
        ended_at: "2026-08-01T10:00:01.000Z".into(),
        episode_type: Some("other".into()),
        title: "Conservative exact page".into(),
        summary: Some("Every exact source remains owned.".into()),
        participants: Some(Vec::new()),
        languages: Some(Vec::new()),
        action_items: Some(Vec::new()),
        substance: Some("normal".into()),
        visual_evidence: Some("useful".into()),
        minute_summaries: Some(Vec::new()),
        model: Some("conservative-capture-page-keep-v1".into()),
        member_utterance_ids: utterances,
        member_screenshot_ids: screenshots,
    };
    assert!(persistence
        .settle_capture_formation(CaptureFormationSettlement {
            claim: lost_response.clone(),
            episodes: vec![episode(last_utterance_ids.clone(), Vec::new())],
        })
        .await
        .is_err());
    let final_settlement = CaptureFormationSettlement {
        claim: lost_response,
        episodes: vec![episode(
            last_utterance_ids.clone(),
            last_screenshot_ids.clone(),
        )],
    };
    let episode_ids = persistence
        .settle_capture_formation(final_settlement.clone())
        .await?;
    assert_eq!(episode_ids.len(), 1);
    assert_eq!(
        persistence
            .settle_capture_formation(final_settlement)
            .await?,
        episode_ids
    );

    let page_totals = sqlx::query(
        "SELECT count(*)::bigint AS page_count, \
                sum(cardinality(covered_utterance_ids))::bigint AS utterance_count, \
                sum(cardinality(covered_screenshot_ids))::bigint AS screenshot_count, \
                array_agg(completed_outcome ORDER BY page_index) AS outcomes, \
                bool_and(provider_request IS NULL AND provider_request_sha256 IS NULL \
                         AND staged_response IS NULL AND staged_response_sha256 IS NULL \
                         AND staged_vertex_event_id IS NULL) AS plaintext_cleared \
           FROM capture_formation_pages WHERE account_id=$1 AND capture_session_id=$2 \
             AND source_revision=2 AND state='complete'",
    )
    .bind(ACCOUNT)
    .bind(SESSION)
    .fetch_one(persistence.pool())
    .await?;
    assert_eq!(page_totals.try_get::<i64, _>("page_count")?, 2);
    assert_eq!(page_totals.try_get::<i64, _>("utterance_count")?, 4_001);
    assert_eq!(page_totals.try_get::<i64, _>("screenshot_count")?, 2_001);
    assert_eq!(
        page_totals.try_get::<Vec<String>, _>("outcomes")?,
        vec!["no_memory", "memories"]
    );
    assert!(page_totals.try_get::<bool, _>("plaintext_cleared")?);

    sqlx::query(
        "INSERT INTO capture_sessions( \
             account_id,id,device_id,install_id,started_at,last_event_at,ended_at,schema_version,created_at) \
         SELECT $1,format('oversized-neighbor-%s',n),'neighbor-device','neighbor-install', \
                '2026-08-01T10:00:00Z','2026-08-01T10:01:00Z','2026-08-01T10:01:00Z',2, \
                '2026-08-01T10:00:00Z' FROM generate_series(1,256) n",
    )
    .bind(ACCOUNT)
    .execute(persistence.pool())
    .await?;
    sqlx::query(
        "INSERT INTO capture_streams( \
             account_id,id,capture_session_id,device_id,stream_kind, \
             committed_through_sequence,sealed_sequence,created_at) \
         SELECT $1,format('oversized-neighbor-stream-%s',n),format('oversized-neighbor-%s',n), \
                'neighbor-device','mac_screen',-1,-1,'2026-08-01T10:00:00Z' \
           FROM generate_series(1,256) n",
    )
    .bind(ACCOUNT)
    .execute(persistence.pool())
    .await?;
    sqlx::query(
        "INSERT INTO capture_formation_receipts( \
             account_id,capture_session_id,source_revision,state,finish_requested_at, \
             finish_request_provenance) \
         SELECT $1,format('oversized-neighbor-%s',n),1,'pending','2026-08-01T10:02:00Z', \
                'finish_endpoint_v1' \
           FROM generate_series(1,256) n",
    )
    .bind(ACCOUNT)
    .execute(persistence.pool())
    .await?;
    sqlx::query(
        "INSERT INTO capture_formation_seal_events( \
             account_id,capture_session_id,seal_generation,source_revision,event_kind, \
             stream_maxima_sha256,provenance) \
         SELECT $1,format('oversized-neighbor-%s',n),1,1,'seal', \
                capture_formation_stream_maxima_sha256($1,format('oversized-neighbor-%s',n)), \
                'quiet_contiguous_v1' FROM generate_series(1,256) n",
    )
    .bind(ACCOUNT)
    .execute(persistence.pool())
    .await?;
    sqlx::query(
        "UPDATE capture_formation_receipts SET seal_generation=1, \
                seal_finalized_at='2026-08-01T10:03:00Z', \
                seal_finalization_provenance='quiet_contiguous_v1' \
          WHERE account_id=$1 AND capture_session_id LIKE 'oversized-neighbor-%'",
    )
    .bind(ACCOUNT)
    .execute(persistence.pool())
    .await?;
    assert_eq!(
        sqlx::query_as::<_, (i64, i64, i64)>(
            "SELECT capture_formation_stream_accepted_max($1,'oversized-neighbor-stream-1'), \
                    capture_formation_stream_contiguous_through( \
                        $1,'oversized-neighbor-stream-1'), \
                    count(*)::bigint FROM capture_formation_seal_events \
              WHERE account_id=$1 AND capture_session_id='oversized-neighbor-1'",
        )
        .bind(ACCOUNT)
        .fetch_one(persistence.pool())
        .await?,
        (-1, -1, 1),
        "an exact empty stream must seal at the canonical -1 prefix"
    );
    // Drive a later novel sequence through the same state transitions as the
    // capture writer: the old empty seal becomes append-only reopen history,
    // the receipt revision advances, and the stream is no longer sealed.
    let mut late_event = persistence.pool().begin().await?;
    lock_activation_contract_key_share_if_installed(&mut late_event).await?;
    advisory_transaction_lock(&mut late_event, "memory-reconciliation", ACCOUNT).await?;
    sqlx::query(
        "INSERT INTO capture_events( \
             account_id,event_id,device_id,install_id,capture_session_id,stream_id,stream_kind, \
             sequence,source_wall_at,source_monotonic_ns,started_at,ended_at,timezone_id, \
             utc_offset_minutes,clock_uncertainty_ms,asset_id,manifest_digest,media_disposition, \
             received_at) \
         VALUES($1,'oversized-neighbor-event-1','neighbor-device','neighbor-install', \
                'oversized-neighbor-1','oversized-neighbor-stream-1','mac_screen',0, \
                '2026-08-01T10:00:00Z','0','2026-08-01T10:00:00Z', \
                '2026-08-01T10:00:00.001Z','UTC',0,0,'oversized-neighbor-asset-1', \
                repeat('b',64),'canonical','2026-08-01T10:00:00Z')",
    )
    .bind(ACCOUNT)
    .execute(&mut *late_event)
    .await?;
    sqlx::query(
        "UPDATE capture_streams SET committed_through_sequence=0 \
          WHERE account_id=$1 AND id='oversized-neighbor-stream-1'",
    )
    .bind(ACCOUNT)
    .execute(&mut *late_event)
    .await?;
    super::capture::mark_capture_formation_dirty(
        &mut late_event,
        ACCOUNT,
        &["oversized-neighbor-1".to_owned()],
    )
    .await?;
    sqlx::query(
        "INSERT INTO capture_formation_seal_events( \
             account_id,capture_session_id,seal_generation,source_revision,event_kind, \
             stream_maxima_sha256,provenance,trigger_event_id) \
         VALUES($1,'oversized-neighbor-1',1,2,'reopen', \
                capture_formation_stream_maxima_sha256($1,'oversized-neighbor-1'), \
                'late_source_reopen_v1','oversized-neighbor-event-1')",
    )
    .bind(ACCOUNT)
    .execute(&mut *late_event)
    .await?;
    sqlx::query(
        "UPDATE capture_streams SET sealed_sequence=NULL \
          WHERE account_id=$1 AND id='oversized-neighbor-stream-1'",
    )
    .bind(ACCOUNT)
    .execute(&mut *late_event)
    .await?;
    sqlx::query(
        "UPDATE capture_formation_receipts SET seal_finalized_at=NULL, \
                seal_finalization_provenance=NULL \
          WHERE account_id=$1 AND capture_session_id='oversized-neighbor-1'",
    )
    .bind(ACCOUNT)
    .execute(&mut *late_event)
    .await?;
    late_event.commit().await?;
    assert_eq!(
        sqlx::query_as::<_, (i64, i64, Option<i64>, bool)>(
            "SELECT capture_formation_stream_accepted_max( \
                        $1,'oversized-neighbor-stream-1'), \
                    capture_formation_stream_contiguous_through( \
                        $1,'oversized-neighbor-stream-1'),stream.sealed_sequence, \
                    receipt.source_revision=2 AND receipt.seal_finalized_at IS NULL \
               FROM capture_streams stream \
               JOIN capture_formation_receipts receipt ON receipt.account_id=stream.account_id \
                    AND receipt.capture_session_id=stream.capture_session_id \
              WHERE stream.account_id=$1 AND stream.id='oversized-neighbor-stream-1'",
        )
        .bind(ACCOUNT)
        .fetch_one(persistence.pool())
        .await?,
        (0, 0, None, true),
        "a novel sequence after the empty seal must reopen the exact source"
    );
    sqlx::query(
        "UPDATE capture_streams SET sealed_sequence=0 \
          WHERE account_id=$1 AND id='oversized-neighbor-stream-1'",
    )
    .bind(ACCOUNT)
    .execute(persistence.pool())
    .await?;
    sqlx::query(
        "INSERT INTO capture_formation_seal_events( \
             account_id,capture_session_id,seal_generation,source_revision,event_kind, \
             stream_maxima_sha256,provenance) \
         VALUES($1,'oversized-neighbor-1',2,2,'seal', \
                capture_formation_stream_maxima_sha256($1,'oversized-neighbor-1'), \
                'quiet_contiguous_v1')",
    )
    .bind(ACCOUNT)
    .execute(persistence.pool())
    .await?;
    sqlx::query(
        "UPDATE capture_formation_receipts SET seal_generation=2, \
                seal_finalized_at='2026-08-01T10:03:30Z', \
                seal_finalization_provenance='quiet_contiguous_v1' \
          WHERE account_id=$1 AND capture_session_id='oversized-neighbor-1'",
    )
    .bind(ACCOUNT)
    .execute(persistence.pool())
    .await?;
    let mut transaction = persistence.pool().begin().await?;
    for ordinal in 1..=256 {
        let session_id = format!("oversized-neighbor-{ordinal}");
        let source_revision = if ordinal == 1 { 2 } else { 1 };
        let fingerprint = capture_formation_source_fingerprint(
            &mut transaction,
            ACCOUNT,
            &session_id,
            source_revision,
        )
        .await?;
        sqlx::query(
            "UPDATE capture_formation_receipts SET state='complete', \
                    completed_revision=source_revision,completed_outcome='no_memory', \
                    completed_claim_token=$3, \
                    completed_source_fingerprint=$4,completed_at='2026-08-01T10:04:00Z' \
              WHERE account_id=$1 AND capture_session_id=$2",
        )
        .bind(ACCOUNT)
        .bind(&session_id)
        .bind(format!("neighbor-{ordinal}"))
        .bind(fingerprint)
        .execute(&mut *transaction)
        .await?;
    }
    transaction.commit().await?;
    let provider_events_before: i64 =
        sqlx::query_scalar("SELECT count(*)::bigint FROM vertex_usage_events WHERE account_id=$1")
            .bind(ACCOUNT)
            .fetch_one(persistence.pool())
            .await?;
    let policy = OversizedKeepPromotionPolicy {
        draft_limit: 32,
        atom_limit: 4_000,
        reconciliation_version: 1,
        prompt_version: 1,
        partition_schema_version: 1,
        validator_version: 1,
    };
    let mut promoted = None;
    for _ in 0..8 {
        match persistence
            .promote_oversized_source_settled_prefix(ACCOUNT, 4 * 60 * 60, None, policy)
            .await?
        {
            OversizedKeepPromotionResult::Promoted {
                episode_ids: promoted_ids,
                reconciliation_id,
                archive_revision,
            } => {
                promoted = Some((promoted_ids, reconciliation_id, archive_revision));
                break;
            }
            OversizedKeepPromotionResult::Held { .. } => {}
            OversizedKeepPromotionResult::NotOversized => {
                return Err(EnclaveError::Store(
                    "257-session mixed-page cohort was not recognized as oversized".into(),
                ));
            }
        }
    }
    let (promoted_ids, _, archive_revision) = promoted.ok_or_else(|| {
        EnclaveError::Store("257-session mixed-page cohort did not make bounded progress".into())
    })?;
    assert_eq!(promoted_ids, episode_ids);
    assert_eq!(archive_revision, 1);
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT count(*)::bigint FROM vertex_usage_events WHERE account_id=$1",
        )
        .bind(ACCOUNT)
        .fetch_one(persistence.pool())
        .await?,
        provider_events_before,
        "oversized KEEP must not perform provider egress"
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT count(*)::bigint FROM persistence_feature_reconciliation_neighborhood_scans \
              WHERE account_id=$1",
        )
        .bind(ACCOUNT)
        .fetch_one(persistence.pool())
        .await?,
        0,
        "successful KEEP must consume its ready scan atomically"
    );
    assert!(
        sqlx::query_scalar::<_, bool>(
            "SELECT bool_and(structure_state='reconciled') FROM episodes \
          WHERE account_id=$1 AND id=ANY($2)",
        )
        .bind(ACCOUNT)
        .bind(&episode_ids)
        .fetch_one(persistence.pool())
        .await?
    );
    sqlx::query("DELETE FROM accounts WHERE id=$1")
        .bind(ACCOUNT)
        .execute(persistence.pool())
        .await?;
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT count(*)::bigint FROM capture_formation_pages WHERE account_id=$1",
        )
        .bind(ACCOUNT)
        .fetch_one(persistence.pool())
        .await?,
        0,
        "account erasure must cascade every ephemeral formation request and response"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        capture_formation_fingerprint_event_end, capture_formation_fingerprint_event_start,
        capture_formation_provider_attempt_identity, capture_formation_provider_request_bytes,
        vertex_attempt_event_id, CaptureFormationFingerprintEvent, EXTENDABLE_EPISODE_SQL,
        OPEN_EPISODES_SQL, PROVIDER_EGRESS_CLAIM_FENCE_SECONDS,
    };
    use crate::persistence::{
        capture_formation_response_schema_v1, CaptureFormationProviderRequest,
        CAPTURE_FORMATION_PROVIDER_MAX_OUTPUT_TOKENS, CAPTURE_FORMATION_PROVIDER_REQUEST_MAX_BYTES,
    };
    use sha2::{Digest, Sha256};

    fn requires_active_unfinalized_draft(query: &str) {
        assert!(query.contains("JOIN memory_handles h"));
        assert!(query.contains("h.state='active'"));
        assert!(query.contains("structure_state='draft'"));
        assert!(query.contains("finalized_at IS NULL"));
        assert!(query.contains("finalization_claim_token IS NULL"));
        assert!(query.contains("finalization_status NOT IN ('processing','deleting')"));
    }

    #[test]
    fn open_episode_projection_exposes_only_extendable_drafts() {
        requires_active_unfinalized_draft(OPEN_EPISODES_SQL);
    }

    #[test]
    fn stale_episode_reference_cannot_reopen_reconciled_memory() {
        requires_active_unfinalized_draft(EXTENDABLE_EPISODE_SQL);
        assert!(EXTENDABLE_EPISODE_SQL.contains("FOR UPDATE OF e,h"));
    }

    fn provider_request(user_message: String) -> CaptureFormationProviderRequest {
        CaptureFormationProviderRequest {
            contract_version: 1,
            vertex_project: "kioku-prod".into(),
            vertex_location: "us-central1".into(),
            api_version: "v1".into(),
            publisher: "google".into(),
            model: "gemini-flash".into(),
            method: "generateContent".into(),
            system_prompt: "Exact system prompt".into(),
            user_message,
            response_schema: capture_formation_response_schema_v1(),
            max_output_tokens: CAPTURE_FORMATION_PROVIDER_MAX_OUTPUT_TOKENS,
            response_mime_type: "application/json".into(),
            thinking_budget: 0,
        }
    }

    #[test]
    fn provider_attempt_is_stable_but_confirmed_retry_gets_a_new_identity() {
        let page = [7_u8; 32];
        let first = capture_formation_provider_attempt_identity("a", "s", 2, 3, &page, 1);
        assert_eq!(
            first,
            capture_formation_provider_attempt_identity("a", "s", 2, 3, &page, 1)
        );
        assert_ne!(
            first,
            capture_formation_provider_attempt_identity("a", "s", 2, 3, &page, 2)
        );
        assert_eq!(vertex_attempt_event_id(&first).unwrap().len(), 68);
    }

    #[test]
    fn provider_request_roundtrips_exact_utf8_and_rejects_contract_drift_or_oversize() {
        let request = provider_request("literal 記憶 🙂 bytes".into());
        let bytes = capture_formation_provider_request_bytes(&request).unwrap();
        let restored: CaptureFormationProviderRequest = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(restored, request);

        let mut wrong_schema = request.clone();
        wrong_schema.response_schema = serde_json::json!({"type":"OBJECT"});
        assert!(capture_formation_provider_request_bytes(&wrong_schema).is_err());

        let oversized = provider_request("x".repeat(CAPTURE_FORMATION_PROVIDER_REQUEST_MAX_BYTES));
        assert!(capture_formation_provider_request_bytes(&oversized).is_err());

        let mut json = serde_json::to_value(request).unwrap();
        json.as_object_mut()
            .unwrap()
            .insert("unknown_generation_control".into(), serde_json::json!(true));
        assert!(serde_json::from_value::<CaptureFormationProviderRequest>(json).is_err());
    }

    #[test]
    fn provider_plaintext_and_stage_are_ephemeral_and_hash_checked() {
        let source = include_str!("memory_formation.rs");
        assert!(source.contains("Sha256::digest(stored_request_json.as_bytes())"));
        assert!(source.contains("Sha256::digest(response.as_bytes()).as_slice() == commitment"));
        assert!(source.contains("ensure_terminal_formation_usage_event"));
        assert!(source.contains("vertex_attempt_event_id(&claim.provider_attempt_identity)?"));
        assert!(source.contains("staged response has no bound provider request"));
        assert!(source.contains("AND (NOT $7 OR staged_response IS NULL)"));
        assert!(source.contains("provider_request=NULL,provider_request_sha256=NULL"));
        assert!(source.contains(
            "staged_response=NULL,staged_response_sha256=NULL,staged_vertex_event_id=NULL"
        ));
    }

    #[test]
    fn exact_lane_is_cursor_behind_and_ready_filtered_before_limit() {
        let source = include_str!("memory_formation.rs");
        let claim = source
            .split("async fn claim_capture_formation(")
            .nth(1)
            .unwrap()
            .split("async fn release_capture_formation(")
            .next()
            .unwrap();
        assert!(claim.contains("account.summarized_until>=greatest"));
        assert!(claim.contains("stream.committed_through_sequence IS DISTINCT FROM"));
        assert!(claim.contains("job.updated_at>clock_timestamp()"));
        assert!(claim.contains("LIMIT 1"));
        assert!(!claim.contains("LIMIT 64"));
        let selected = claim
            .split("let selected = sqlx::query(")
            .nth(1)
            .unwrap()
            .split(".bind(account_id)")
            .next()
            .unwrap();
        assert!(
            !selected.contains("seal_finalized_at"),
            "late provisional evidence must reform well before the structural seal horizon"
        );
    }

    #[test]
    fn quiet_seal_is_server_timed_contiguous_and_terminal() {
        let source = include_str!("memory_formation.rs");
        let activation_migration =
            include_str!("../../../migrations/0027_memory_reconciliation_activation.sql");
        assert!(activation_migration.contains("coalesce(max(accepted.sequence),-1)"));
        let sealer = source
            .split("async fn finalize_quiet_capture_seals(")
            .nth(1)
            .unwrap()
            .split("pub(super) async fn capture_formation_source_fingerprint(")
            .next()
            .unwrap();
        assert!(sealer.contains("CAPTURE_SEAL_QUIET_SECONDS"));
        assert!(sealer.contains("phase IN ('draining','active','paused')"));
        assert!(sealer.contains("event.received_at>clock_timestamp()"));
        assert!(sealer.contains("job.updated_at>clock_timestamp()"));
        assert!(sealer.contains("stream.committed_through_sequence IS DISTINCT FROM"));
        assert!(sealer.contains("capture_formation_stream_accepted_max"));
        assert!(sealer.contains("capture_formation_stream_contiguous_through"));
        assert!(sealer.contains("job.state NOT IN ('succeeded','canceled')"));
        assert!(sealer.contains("sealed_sequence=$3"));
        assert!(sealer.contains("seal_finalization_provenance"));
        assert!(sealer.contains("capture_formation_stream_maxima_sha256"));
        assert!(sealer.contains("INSERT INTO capture_formation_seal_events"));
        assert!(sealer.contains("seal_generation=$3"));
        assert!(sealer.contains("checked_add(1)"));
    }

    #[test]
    fn formation_fingerprint_binds_content_but_not_owner_identity() {
        let source = include_str!("memory_formation.rs");
        let fingerprint = source
            .split("const CAPTURE_FORMATION_FINGERPRINT_EVENT_PAGE_SIZE")
            .nth(1)
            .unwrap()
            .split("pub(super) async fn refresh_capture_formation_receipt(")
            .next()
            .unwrap();
        assert!(fingerprint.starts_with(": i64 = 128;"));
        assert!(
            fingerprint.contains("CAPTURE_FORMATION_FINGERPRINT_PROJECTION_PAGE_SIZE: i64 = 512")
        );
        assert!(fingerprint.contains("AS active_owned"));
        assert!(!fingerprint.contains("'active_owner'"));
        for field in ["utterance.text", "screenshot.ocr_text", "source_key"] {
            assert!(fingerprint.contains(field));
        }
        assert!(fingerprint.contains("capture_formation_deleted_sequences"));
        assert!(fingerprint.contains("deleted.original_manifest_digest"));
        assert!(fingerprint.contains("1::smallint"));
        assert!(fingerprint.contains("NULL::text,NULL::text,NULL::text"));
        assert!(fingerprint.contains("(stream_id,sequence,event_id,row_kind)>"));
        assert!(fingerprint.contains("ORDER BY stream_id,sequence,event_id,row_kind LIMIT $7"));
        assert!(fingerprint.contains("ORDER BY event_ordinal,record_type,record_id LIMIT $7"));
        assert!(fingerprint.contains("kioku.capture-formation.source.v3"));
        assert!(!fingerprint.contains("jsonb_agg"));
        assert!(!fingerprint.contains("serde_json::to_vec"));
    }

    fn framed_test_event_hash(row_kind: i16, canonical_event_id: Option<&str>) -> Vec<u8> {
        let mut digest = Sha256::new();
        digest.update(b"kioku.capture-formation.source.v3\0");
        let event = CaptureFormationFingerprintEvent {
            row_kind,
            event_id: "event".into(),
            stream_id: "stream".into(),
            sequence: 7,
            manifest_digest: "manifest".into(),
            deletion_episode_id: None,
            deletion_provenance: None,
            media_disposition: None,
            canonical_event_id: canonical_event_id.map(str::to_owned),
            evidence_event_id: None,
        };
        capture_formation_fingerprint_event_start(&mut digest, &event).unwrap();
        capture_formation_fingerprint_event_end(&mut digest, 0);
        digest.finalize().to_vec()
    }

    #[test]
    fn formation_fingerprint_framing_distinguishes_null_empty_and_row_kind() {
        let null_text = framed_test_event_hash(0, None);
        let empty_text = framed_test_event_hash(0, Some(""));
        let deleted_row = framed_test_event_hash(1, None);
        assert_ne!(
            null_text, empty_text,
            "NULL and empty text must not collide"
        );
        assert_ne!(
            null_text, deleted_row,
            "live and deleted rows must not collide"
        );
    }

    #[test]
    fn topology_refresh_rebinds_exact_seals_and_reopens_inexact_boundaries() {
        let source = include_str!("memory_formation.rs");
        let refresh = source
            .split("pub(super) async fn refresh_capture_formation_receipt(")
            .nth(1)
            .unwrap()
            .split("async fn ensure_episode_sources_unowned(")
            .next()
            .unwrap();
        assert!(refresh.contains("source_revision=$5,state='pending'"));
        assert!(refresh.contains("seal_finalized_at=CASE WHEN $6 THEN NULL"));
        assert!(refresh.contains("capture_formation_stream_maxima_sha256($1,$2)"));
        assert!(refresh.contains("capture_formation_stream_accepted_max"));
        assert!(refresh.contains("capture_formation_stream_contiguous_through"));
        assert!(refresh.contains("deletion_rebind_pending"));
        assert!(refresh.contains("capture_formation_deleted_sequences"));
        assert!(refresh.contains("sealed_contract_changed = !current_seal_present"));
        assert!(refresh.contains("!completed_source_changed && !sealed_contract_changed"));
        assert!(refresh.contains("completed_source_fingerprint IS NOT DISTINCT FROM $4"));
        assert!(!refresh.contains("state != \"complete\""));
        assert!(refresh.contains("'topology_rebind_v1'"));
        assert!(refresh.contains("seal_generation=$3,seal_finalized_at=clock_timestamp()"));
        assert!(refresh.contains("UPDATE capture_streams SET sealed_sequence=NULL"));
        assert!(refresh.contains("checked_add(1)"));
        assert!(
            !refresh.contains("CAPTURE_SEAL_QUIET_SECONDS"),
            "a projection-only rebind must not invent a new capture/media quiet wait"
        );
    }

    #[test]
    fn forward_lane_excludes_active_and_exactly_completed_sources() {
        let source = include_str!("memory_formation.rs");
        let evidence = source
            .split("async fn summary_evidence(")
            .nth(1)
            .unwrap()
            .split("async fn claim_capture_formation(")
            .next()
            .unwrap();
        assert!(evidence.contains("active_episode_members owner"));
        assert!(evidence.contains("receipt.state='complete'"));
        assert!(evidence.contains("receipt.completed_revision=receipt.source_revision"));
        assert!(evidence.contains("coalesce(event.canonical_event_id,event.event_id)"));
    }

    #[test]
    fn exact_settlement_is_new_draft_and_session_evidence_only() {
        let source = include_str!("memory_formation.rs");
        let settlement = source
            .split("async fn settle_capture_formation(")
            .nth(1)
            .unwrap()
            .split("async fn open_episodes(")
            .next()
            .unwrap();
        assert!(settlement.contains("episode.id.is_some()"));
        assert!(settlement.contains("ensure_capture_episode_sources"));

        let evidence_guard = source
            .split("async fn ensure_capture_episode_sources(")
            .nth(1)
            .unwrap()
            .split("async fn capture_session_owner_ids(")
            .next()
            .unwrap();
        assert!(evidence_guard.contains("coalesce(canonical_event_id,event_id)"));
        assert!(evidence_guard.contains("speaker_observation_sources"));
        assert!(evidence_guard.contains("cloud-v2:"));
    }

    #[test]
    fn provider_and_settlement_source_guard_fences_episode_deletion() {
        let source = include_str!("memory_formation.rs");
        let forward_claim = source
            .split("async fn claim_summary_window(")
            .nth(1)
            .unwrap()
            .split("async fn release_summary_window(")
            .next()
            .unwrap();
        assert!(forward_claim.contains("clock_timestamp()+make_interval"));
        assert!(forward_claim.contains("claim_until<=clock_timestamp()"));
        assert!(!forward_claim.contains("claim_until <= to_timestamp"));
        let forward_settlement = source
            .split("async fn settle_summary_window(")
            .nth(1)
            .unwrap()
            .split("async fn episode_embedding_sources(")
            .next()
            .unwrap();
        assert!(forward_settlement.contains("claim_until>clock_timestamp() FOR UPDATE"));

        let guard = source
            .split("async fn ensure_formation_sources_available(")
            .nth(1)
            .unwrap()
            .split("async fn ensure_open_episodes_available(")
            .next()
            .unwrap();
        assert!(guard.contains("requested_utterances"));
        assert!(guard.contains("requested_screenshots"));
        assert!(guard.contains("utterance.id IS NULL"));
        assert!(guard.contains("screenshot.id IS NULL"));
        assert!(guard.contains("split_part(substr(utterance.source_key,10),':',1)"));
        assert!(guard.contains("speaker_observation_sources"));
        assert!(guard.contains("coalesce(event.canonical_event_id,event.event_id)"));
        assert!(guard.contains("deletion.state='pending'"));
        assert!(guard.contains("deletion.orphan_event_ids ? family.event_id"));
        assert!(guard.contains("deletion.orphan_event_ids ? family.canonical_event_id"));

        let ownership = source
            .split("async fn ensure_episode_sources_unowned(")
            .nth(1)
            .unwrap()
            .split("async fn ensure_capture_episode_sources(")
            .next()
            .unwrap();
        assert!(ownership.contains("ensure_formation_sources_available"));

        for authorization in [
            "async fn authorize_summary_window_egress(",
            "async fn authorize_capture_formation_egress(",
        ] {
            let body = source.split(authorization).nth(1).unwrap();
            assert!(body.contains("lock_activation_contract_key_share_if_installed"));
            assert!(body.contains("advisory_transaction_lock"));
            assert!(body.contains("claim_until=greatest(claim_until"));
            assert!(body.contains("PROVIDER_EGRESS_CLAIM_FENCE_SECONDS"));
            assert!(body.contains("ensure_formation_sources_available"));
        }
        assert_eq!(PROVIDER_EGRESS_CLAIM_FENCE_SECONDS, 15.0 * 60.0);
    }
}
