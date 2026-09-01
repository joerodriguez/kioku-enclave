use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

use async_trait::async_trait;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use sqlx::{PgConnection, Postgres, Row, Transaction};

use crate::{
    cp::{
        isotime,
        media_worker::{
            NON_RESURRECTABLE_MEDIA_ERROR_CODES, PROCESSOR_VERSION, RESURRECTION_TOTAL_ATTEMPT_CAP,
            RESURRECTION_WINDOW_SECONDS_INTEGRAL,
        },
        tokens,
        vertex::VertexOperation,
    },
    error::{EnclaveError, Result},
    persistence::{
        oversized_keep_policy_commitment, reconciliation_outputs_commitment,
        reconciliation_provider_attempt_identity, vertex_attempt_event_id,
        ActiveReconciliationAuthority, MemoryHandleResolution, MemoryHandleState,
        MemoryReconciliationRepository, OversizedKeepPromotionPolicy, OversizedKeepPromotionResult,
        ReconciledMemoryWrite, ReconciliationClaim, ReconciliationDraft, ReconciliationEgressGuard,
        ReconciliationEvidenceAtom, ReconciliationPublish, ReconciliationPublishResult,
        ReconciliationSnapshot, ReconciliationStageWrite, StagedReconciliation,
        MAX_OVERSIZED_KEEP_SOURCES, OVERSIZED_KEEP_MODEL, OVERSIZED_KEEP_SOURCE_PAGE_SIZE,
    },
};

use super::{
    activation::active_reconciliation_authority,
    advisory_transaction_lock, allocate_content_id, duration_seconds,
    memory_formation::{capture_formation_source_fingerprint, refresh_capture_formation_receipt},
    PostgresPersistence,
};

const QUIET_HORIZON_SECONDS: i64 = 4 * 60 * 60;
const MAX_DRAFTS: i64 = 32;
const MAX_ATOMS: i64 = 4_000;
const MAX_SOURCE_SESSIONS: usize = 256;
const MAX_CANDIDATE_HEADERS: usize = 257;
const NEIGHBORHOOD_PAGE_SIZE: i64 = 256;
const NEIGHBORHOOD_MAX_PAGES_PER_INVOCATION: usize = 4;

fn empty_neighborhood_commitment() -> Vec<u8> {
    Sha256::digest(b"kioku.memory-reconciliation.neighborhood.empty.v1\0").to_vec()
}

struct PostgresReconciliationEgressGuard {
    transaction: Option<Transaction<'static, Postgres>>,
    claim: ReconciliationClaim,
}

#[async_trait]
impl ReconciliationEgressGuard for PostgresReconciliationEgressGuard {
    async fn stage_and_release(
        mut self: Box<Self>,
        staged: ReconciliationStageWrite,
    ) -> Result<StagedReconciliation> {
        let mut transaction = self.transaction.take().ok_or_else(|| {
            EnclaveError::Store("memory reconciliation egress guard was already released".into())
        })?;
        let stored = match stage_reconciliation_locked(&mut transaction, &self.claim, staged).await
        {
            Ok(stored) => stored,
            Err(error) => {
                let _ = transaction.rollback().await;
                return Err(error);
            }
        };
        transaction.commit().await?;
        Ok(stored)
    }

    async fn abort(mut self: Box<Self>) -> Result<()> {
        if let Some(transaction) = self.transaction.take() {
            transaction.rollback().await?;
        }
        Ok(())
    }
}

fn timestamp(value: &str, field: &str) -> Result<i64> {
    isotime::parse_epoch_millis(value)
        .ok_or_else(|| EnclaveError::InvalidRequest(format!("{field} is invalid")))
}

fn valid_digest(value: &[u8]) -> bool {
    value.len() == 32 && value.iter().any(|byte| *byte != 0)
}

fn claim_matches_authority(
    claim: &ReconciliationClaim,
    authority: &ActiveReconciliationAuthority,
) -> bool {
    claim.activation_generation == authority.generation
        && claim.producer_contract_sha256 == authority.producer_contract_sha256
        && claim.reconciliation_model == authority.reconciliation_model
        && claim.vertex_location == authority.vertex_location
}

fn source_id(record_type: &str, record_id: i64) -> String {
    format!("{record_type}:{record_id}")
}

fn json_string_array(value: Option<String>) -> Vec<String> {
    value
        .and_then(|raw| serde_json::from_str(&raw).ok())
        .unwrap_or_default()
}

fn json_value(value: Option<String>, fallback: Value) -> Value {
    value
        .and_then(|raw| serde_json::from_str(&raw).ok())
        .unwrap_or(fallback)
}

fn digest_json(domain: &[u8], value: &Value) -> Result<Vec<u8>> {
    let mut digest = Sha256::new();
    digest.update(domain);
    digest.update(serde_json::to_vec(value)?);
    Ok(digest.finalize().to_vec())
}

fn partition_commitment(value: &Value) -> Result<Vec<u8>> {
    Ok(Sha256::digest(serde_json::to_vec(value)?).to_vec())
}

async fn archive_revision(connection: &mut PgConnection, account_id: &str) -> Result<i64> {
    Ok(sqlx::query_scalar(
        "INSERT INTO memory_archive_state(account_id,revision) VALUES($1,0) \
         ON CONFLICT(account_id) DO UPDATE SET account_id=excluded.account_id \
         RETURNING revision",
    )
    .bind(account_id)
    .fetch_one(connection)
    .await?)
}

async fn candidate_headers(
    connection: &mut PgConnection,
    account_id: &str,
    resume_after_component_ended_ms: Option<i64>,
) -> Result<Vec<(i64, i64, i64)>> {
    let rows = sqlx::query(
        "SELECT episode.id,floor(extract(epoch FROM episode.started_at)*1000)::bigint AS started_ms, \
                floor(extract(epoch FROM episode.ended_at)*1000)::bigint AS ended_ms \
           FROM episodes episode \
           JOIN memory_handles handle ON handle.account_id=episode.account_id \
                AND handle.episode_id=episode.id AND handle.state='active' \
          WHERE episode.account_id=$1 AND episode.structure_state='draft' \
            AND episode.finalized_at IS NULL \
            AND ($2::bigint IS NULL OR episode.started_at> \
                 to_timestamp($2::double precision/1000.0)+make_interval(secs=>$3)) \
          ORDER BY episode.started_at,episode.id LIMIT 257",
    )
    .bind(account_id)
    .bind(resume_after_component_ended_ms)
    .bind(QUIET_HORIZON_SECONDS as f64)
    .fetch_all(&mut *connection)
    .await?;
    rows.into_iter()
        .map(|row| {
            Ok((
                row.try_get("id")?,
                row.try_get("started_ms")?,
                row.try_get("ended_ms")?,
            ))
        })
        .collect::<Result<Vec<_>>>()
}

fn oldest_connected_prefix_with_boundary(
    headers: &[(i64, i64, i64)],
    draft_limit: i64,
) -> (Vec<i64>, bool, Option<i64>, bool) {
    let mut prefix = Vec::new();
    let mut component_end = i64::MIN;
    let mut oversized = false;
    let limit = usize::try_from(draft_limit.max(0)).unwrap_or(usize::MAX);
    for (id, started_ms, ended_ms) in headers {
        if (!prefix.is_empty() || oversized)
            && *started_ms > component_end.saturating_add(QUIET_HORIZON_SECONDS * 1_000)
        {
            return (prefix, oversized, Some(component_end), true);
        }
        component_end = component_end.max(*ended_ms);
        if prefix.len() < limit {
            prefix.push(*id);
        } else {
            oversized = true;
        }
    }
    (
        prefix,
        oversized,
        (component_end != i64::MIN).then_some(component_end),
        headers.len() < MAX_CANDIDATE_HEADERS,
    )
}

fn oldest_connected_prefix(headers: &[(i64, i64, i64)], draft_limit: i64) -> (Vec<i64>, bool) {
    let (prefix, oversized, _, _) = oldest_connected_prefix_with_boundary(headers, draft_limit);
    (prefix, oversized)
}

fn oldest_connected_drafts(headers: &[(i64, i64, i64)], draft_limit: i64) -> Result<Vec<i64>> {
    let (component, oversized) = oldest_connected_prefix(headers, draft_limit);
    if oversized {
        return Err(EnclaveError::Store(
            "memory reconciliation cohort exceeds its configured bound".into(),
        ));
    }
    Ok(component)
}

async fn read_atoms(
    connection: &mut PgConnection,
    account_id: &str,
    predecessor_ids: &[i64],
    envelope_started_ms: i64,
    envelope_ended_ms: i64,
    atom_limit: i64,
) -> Result<Vec<ReconciliationEvidenceAtom>> {
    let rows = sqlx::query(
        "WITH evidence AS ( \
             SELECT 'utterance'::text AS record_type,utterance.id AS record_id, \
                    segment.started_at + utterance.start_offset_seconds*interval '1 second' AS started_at, \
                    segment.started_at + utterance.end_offset_seconds*interval '1 second' AS ended_at, \
                    concat('[',utterance.speaker_label,'] ',utterance.text) AS context \
               FROM utterances utterance \
               JOIN audio_segments segment ON segment.account_id=utterance.account_id \
                    AND segment.id=utterance.audio_segment_id \
              WHERE utterance.account_id=$1 AND ( \
                    EXISTS(SELECT 1 FROM active_episode_members member \
                            WHERE member.account_id=$1 AND member.episode_id=ANY($2) \
                              AND member.record_type='utterance' AND member.record_id=utterance.id) \
                    OR (NOT EXISTS(SELECT 1 FROM active_episode_members owner \
                            WHERE owner.account_id=$1 AND owner.record_type='utterance' \
                              AND owner.record_id=utterance.id) \
                        AND segment.started_at + utterance.start_offset_seconds*interval '1 second' \
                        BETWEEN to_timestamp($3::double precision/1000.0) \
                            AND to_timestamp($4::double precision/1000.0))) \
             UNION ALL \
             SELECT 'screenshot',screenshot.id,screenshot.captured_at, \
                    coalesce(screenshot.visible_until,screenshot.captured_at), \
                    concat_ws(' | ',screenshot.active_app,screenshot.window_title,screenshot.url, \
                              screenshot.salient_ocr_text,screenshot.ocr_text) \
               FROM screenshots screenshot \
              WHERE screenshot.account_id=$1 AND ( \
                    EXISTS(SELECT 1 FROM active_episode_members member \
                            WHERE member.account_id=$1 AND member.episode_id=ANY($2) \
                              AND member.record_type='screenshot' AND member.record_id=screenshot.id) \
                    OR (NOT EXISTS(SELECT 1 FROM active_episode_members owner \
                            WHERE owner.account_id=$1 AND owner.record_type='screenshot' \
                              AND owner.record_id=screenshot.id) \
                        AND screenshot.captured_at BETWEEN to_timestamp($3::double precision/1000.0) \
                            AND to_timestamp($4::double precision/1000.0))) \
         ) \
         SELECT record_type,record_id, \
                floor(extract(epoch FROM started_at)*1000)::bigint AS started_at_ms, \
                floor(extract(epoch FROM greatest(ended_at,started_at))*1000)::bigint AS ended_at_ms, \
                left(context,8000) AS context \
           FROM evidence ORDER BY started_at,record_type,record_id LIMIT $5",
    )
    .bind(account_id)
    .bind(predecessor_ids)
    .bind(envelope_started_ms)
    .bind(envelope_ended_ms)
    .bind(atom_limit + 1)
    .fetch_all(&mut *connection)
    .await?;
    if i64::try_from(rows.len()).unwrap_or(i64::MAX) > atom_limit {
        return Err(EnclaveError::Store(
            "memory reconciliation evidence exceeds its configured bound".into(),
        ));
    }
    rows.into_iter()
        .map(|row| {
            let record_type: String = row.try_get("record_type")?;
            let record_id: i64 = row.try_get("record_id")?;
            Ok(ReconciliationEvidenceAtom {
                source_id: source_id(&record_type, record_id),
                record_type,
                record_id,
                started_at: isotime::format_epoch_millis(row.try_get("started_at_ms")?),
                ended_at: isotime::format_epoch_millis(row.try_get("ended_at_ms")?),
                context: row.try_get("context")?,
            })
        })
        .collect()
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct OutsideDraftClosure {
    episode_ids: Vec<i64>,
    started_ms: Option<i64>,
    ended_ms: Option<i64>,
}

async fn outside_draft_closure(
    connection: &mut PgConnection,
    account_id: &str,
    predecessor_ids: &[i64],
    envelope_started_ms: i64,
    envelope_ended_ms: i64,
) -> Result<OutsideDraftClosure> {
    let row = sqlx::query(
        "WITH outside_draft AS ( \
             SELECT owner.episode_id, \
                    segment.started_at + utterance.start_offset_seconds*interval '1 second' AS started_at, \
                    segment.started_at + utterance.end_offset_seconds*interval '1 second' AS ended_at \
               FROM utterances utterance \
               JOIN audio_segments segment ON segment.account_id=utterance.account_id \
                    AND segment.id=utterance.audio_segment_id \
               JOIN active_episode_members owner ON owner.account_id=utterance.account_id \
                    AND owner.record_type='utterance' AND owner.record_id=utterance.id \
               JOIN episodes episode ON episode.account_id=owner.account_id \
                    AND episode.id=owner.episode_id \
              WHERE utterance.account_id=$1 AND NOT (owner.episode_id=ANY($2)) \
                AND episode.structure_state='draft' AND episode.finalized_at IS NULL \
                AND segment.started_at + utterance.start_offset_seconds*interval '1 second' \
                    BETWEEN to_timestamp($3::double precision/1000.0) \
                        AND to_timestamp($4::double precision/1000.0) \
             UNION ALL \
             SELECT owner.episode_id,screenshot.captured_at, \
                    coalesce(screenshot.visible_until,screenshot.captured_at) \
               FROM screenshots screenshot \
               JOIN active_episode_members owner ON owner.account_id=screenshot.account_id \
                    AND owner.record_type='screenshot' AND owner.record_id=screenshot.id \
               JOIN episodes episode ON episode.account_id=owner.account_id \
                    AND episode.id=owner.episode_id \
              WHERE screenshot.account_id=$1 AND NOT (owner.episode_id=ANY($2)) \
                AND episode.structure_state='draft' AND episode.finalized_at IS NULL \
                AND screenshot.captured_at BETWEEN to_timestamp($3::double precision/1000.0) \
                    AND to_timestamp($4::double precision/1000.0) \
         ) SELECT coalesce(array_agg(DISTINCT episode_id ORDER BY episode_id),'{}'::bigint[]) \
                    AS episode_ids, \
                  floor(extract(epoch FROM min(started_at))*1000)::bigint AS started_ms, \
                  floor(extract(epoch FROM max(greatest(ended_at,started_at)))*1000)::bigint AS ended_ms \
             FROM outside_draft",
    )
    .bind(account_id)
    .bind(predecessor_ids)
    .bind(envelope_started_ms)
    .bind(envelope_ended_ms)
    .fetch_one(connection)
    .await?;
    Ok(OutsideDraftClosure {
        episode_ids: row.try_get("episode_ids")?,
        started_ms: row.try_get("started_ms")?,
        ended_ms: row.try_get("ended_ms")?,
    })
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct SourceSession {
    id: String,
    started_ms: i64,
    ended_ms: i64,
    sealed: bool,
    streams_settled: bool,
    jobs_terminal: bool,
    media_terminal: bool,
    server_quiet: bool,
    formation_state: Option<String>,
    formation_source_revision: Option<i64>,
    formation_completed_revision: Option<i64>,
    formation_completed_outcome: Option<String>,
    formation_completed_source_fingerprint: Option<Vec<u8>>,
    formation_finish_requested_ms: Option<i64>,
    formation_seal_finalized_ms: Option<i64>,
    formation_seal_generation: Option<i64>,
    formation_seal_source_revision: Option<i64>,
    formation_seal_stream_maxima_sha256: Option<Vec<u8>>,
    formation_seal_finalization_provenance: Option<String>,
    formation_current: bool,
}

fn connected_source_sessions(
    sessions: &[SourceSession],
    initial_started_ms: i64,
    initial_ended_ms: i64,
) -> Vec<SourceSession> {
    let mut started_ms = initial_started_ms;
    let mut ended_ms = initial_ended_ms;
    let mut selected = BTreeMap::<String, SourceSession>::new();
    loop {
        let before = (selected.len(), started_ms, ended_ms);
        for session in sessions {
            if session.started_ms <= ended_ms.saturating_add(QUIET_HORIZON_SECONDS * 1_000)
                && session.ended_ms >= started_ms.saturating_sub(QUIET_HORIZON_SECONDS * 1_000)
            {
                started_ms = started_ms.min(session.started_ms);
                ended_ms = ended_ms.max(session.ended_ms);
                selected.insert(session.id.clone(), session.clone());
            }
        }
        if before == (selected.len(), started_ms, ended_ms) {
            break;
        }
    }
    selected.into_values().collect()
}

fn source_sessions_are_settled(sessions: &[SourceSession]) -> bool {
    sessions.iter().all(|session| {
        session.sealed
            && session.streams_settled
            && session.jobs_terminal
            && session.media_terminal
            && session.server_quiet
            && session.formation_current
    })
}

fn source_session_guard(session: &SourceSession) -> Value {
    json!({
        "session_id": session.id,
        "started_ms": session.started_ms,
        "ended_ms": session.ended_ms,
        "sealed": session.sealed,
        "streams_settled": session.streams_settled,
        "jobs_terminal": session.jobs_terminal,
        "media_terminal": session.media_terminal,
        "server_quiet": session.server_quiet,
        "formation_state": session.formation_state,
        "formation_source_revision": session.formation_source_revision,
        "formation_completed_revision": session.formation_completed_revision,
        "formation_completed_outcome": session.formation_completed_outcome,
        "formation_completed_source_fingerprint": session.formation_completed_source_fingerprint,
        "formation_finish_requested_ms": session.formation_finish_requested_ms,
        "formation_seal_finalized_ms": session.formation_seal_finalized_ms,
        "formation_seal_generation": session.formation_seal_generation,
        "formation_seal_source_revision": session.formation_seal_source_revision,
        "formation_seal_stream_maxima_sha256": session.formation_seal_stream_maxima_sha256,
        "formation_seal_finalization_provenance": session.formation_seal_finalization_provenance,
        "formation_current": session.formation_current,
    })
}

fn source_session_guard_commitment(session: &SourceSession) -> Result<Vec<u8>> {
    digest_json(
        b"kioku.memory-reconciliation.neighborhood-session.v1\0",
        &source_session_guard(session),
    )
}

fn advance_neighborhood_commitment(prior: &[u8], sessions: &[SourceSession]) -> Result<Vec<u8>> {
    let guards = sessions
        .iter()
        .map(source_session_guard)
        .collect::<Vec<_>>();
    digest_json(
        b"kioku.memory-reconciliation.neighborhood-page.v1\0",
        &json!({"prior": prior, "sessions": guards}),
    )
}

async fn verify_source_session_formation(
    connection: &mut PgConnection,
    account_id: &str,
    sessions: &mut [SourceSession],
) -> Result<()> {
    for session in sessions {
        let Some(source_revision) = session.formation_source_revision else {
            session.formation_current = false;
            continue;
        };
        let complete = session.formation_state.as_deref() == Some("complete")
            && session.formation_completed_revision == Some(source_revision)
            && session.formation_completed_outcome.is_some()
            && session.formation_finish_requested_ms.is_some()
            && session.formation_seal_finalized_ms.is_some()
            && session
                .formation_seal_generation
                .is_some_and(|generation| generation >= 1)
            && session.formation_seal_source_revision == Some(source_revision)
            && session
                .formation_seal_stream_maxima_sha256
                .as_deref()
                .is_some_and(valid_digest);
        let Some(completed_fingerprint) = session
            .formation_completed_source_fingerprint
            .as_deref()
            .filter(|value| valid_digest(value))
        else {
            session.formation_current = false;
            continue;
        };
        if !complete {
            session.formation_current = false;
            continue;
        }
        let current = capture_formation_source_fingerprint(
            connection,
            account_id,
            &session.id,
            source_revision,
        )
        .await?;
        session.formation_current = current == completed_fingerprint;
    }
    Ok(())
}

async fn database_quiet_horizon(connection: &mut PgConnection, boundary_ms: i64) -> Result<bool> {
    Ok(sqlx::query_scalar(
        "SELECT to_timestamp($1::double precision/1000.0) \
                    <=clock_timestamp()-make_interval(secs=>$2)",
    )
    .bind(boundary_ms)
    .bind(QUIET_HORIZON_SECONDS as f64)
    .fetch_one(connection)
    .await?)
}

fn ensure_source_session_bound(count: usize) -> Result<()> {
    if count > MAX_SOURCE_SESSIONS {
        Err(EnclaveError::Store(
            "memory reconciliation source-session neighborhood exceeds its bound".into(),
        ))
    } else {
        Ok(())
    }
}

fn ensure_no_external_owners(predecessors: &[i64], owners: &[i64]) -> Result<()> {
    let predecessors = predecessors.iter().copied().collect::<BTreeSet<_>>();
    let external = owners
        .iter()
        .copied()
        .filter(|owner| !predecessors.contains(owner))
        .collect::<BTreeSet<_>>();
    if external.is_empty() {
        Ok(())
    } else {
        Err(EnclaveError::Conflict(format!(
            "memory reconciliation source closure has active owners outside the bounded cohort: {external:?}"
        )))
    }
}

async fn source_session_candidate_page(
    connection: &mut PgConnection,
    account_id: &str,
    closure_started_ms: i64,
    closure_ended_ms: i64,
    after_session_id: Option<&str>,
) -> Result<(Vec<String>, bool)> {
    let neighborhood_started_ms = closure_started_ms.saturating_sub(QUIET_HORIZON_SECONDS * 1_000);
    let neighborhood_ended_ms = closure_ended_ms.saturating_add(QUIET_HORIZON_SECONDS * 1_000);
    let mut ids = sqlx::query_scalar::<_, String>(
        "WITH candidate(id) AS ( \
             SELECT id FROM capture_sessions WHERE account_id=$1 \
               AND started_at<=to_timestamp($3::double precision/1000.0) \
               AND greatest(last_event_at,coalesce(ended_at,last_event_at)) \
                    >=to_timestamp($2::double precision/1000.0) \
             UNION \
             SELECT capture_session_id FROM capture_events WHERE account_id=$1 \
               AND started_at<=to_timestamp($3::double precision/1000.0) \
               AND ended_at>=to_timestamp($2::double precision/1000.0)) \
         SELECT id FROM candidate WHERE ($4::text IS NULL OR id>$4) \
          ORDER BY id LIMIT $5",
    )
    .bind(account_id)
    .bind(neighborhood_started_ms)
    .bind(neighborhood_ended_ms)
    .bind(after_session_id)
    .bind(NEIGHBORHOOD_PAGE_SIZE + 1)
    .fetch_all(&mut *connection)
    .await?;
    let has_more = i64::try_from(ids.len()).unwrap_or(i64::MAX) > NEIGHBORHOOD_PAGE_SIZE;
    ids.truncate(usize::try_from(NEIGHBORHOOD_PAGE_SIZE).unwrap_or(usize::MAX));
    Ok((ids, has_more))
}

async fn load_source_sessions_by_ids(
    connection: &mut PgConnection,
    account_id: &str,
    candidate_ids: &[String],
) -> Result<Vec<SourceSession>> {
    if candidate_ids.is_empty() {
        return Ok(Vec::new());
    }
    if candidate_ids.len() > usize::try_from(NEIGHBORHOOD_PAGE_SIZE).unwrap_or(usize::MAX) {
        return Err(EnclaveError::InvalidRequest(
            "memory reconciliation session page exceeds its bound".into(),
        ));
    }
    let rows = sqlx::query(
        "SELECT session.id, \
                floor(extract(epoch FROM least(session.started_at,coalesce(min(event.started_at),session.started_at)))*1000)::bigint AS started_ms, \
                floor(extract(epoch FROM greatest(session.last_event_at,coalesce(session.ended_at,session.last_event_at), \
                     coalesce(max(event.ended_at),session.last_event_at)))*1000)::bigint AS ended_ms, \
                receipt.seal_finalized_at IS NOT NULL AND receipt.seal_generation>=1 \
                    AND seal.event_kind='seal' AND seal.source_revision=receipt.source_revision \
                    AND NOT EXISTS(SELECT 1 FROM capture_formation_seal_events reopen \
                         WHERE reopen.account_id=receipt.account_id \
                           AND reopen.capture_session_id=receipt.capture_session_id \
                           AND reopen.seal_generation=receipt.seal_generation \
                           AND reopen.event_kind='reopen') AS sealed, \
                EXISTS(SELECT 1 FROM capture_streams stream \
                    WHERE stream.account_id=$1 AND stream.capture_session_id=session.id) \
                  AND NOT EXISTS(SELECT 1 FROM capture_streams stream \
                    WHERE stream.account_id=$1 AND stream.capture_session_id=session.id \
                      AND (stream.sealed_sequence IS NULL \
                           OR stream.committed_through_sequence<>stream.sealed_sequence)) \
                    AS streams_settled, \
                NOT EXISTS(SELECT 1 FROM capture_events event \
                    JOIN media_processing_jobs job ON job.account_id=event.account_id AND job.event_id=event.event_id \
                    WHERE event.account_id=$1 AND event.capture_session_id=session.id \
                      AND job.state NOT IN ('succeeded','canceled') \
                      AND (job.state<>'failed_terminal' OR ( \
                           job.processor_version=$3 \
                           AND NOT (coalesce(job.error_code,'')=ANY($4::text[])) \
                           AND job.attempt_count<$5 \
                           AND event.started_at>=clock_timestamp()-make_interval(secs=>$6)))) \
                    AS jobs_terminal, \
                NOT EXISTS(SELECT 1 FROM capture_events event \
                    JOIN media_objects object ON object.account_id=event.account_id AND object.event_id=event.event_id \
                    WHERE event.account_id=$1 AND event.capture_session_id=session.id \
                      AND object.deleted_at IS NULL \
                      AND object.processing_state IN ('queued','processing','retry_wait')) AS media_terminal, \
                greatest( \
                    session.created_at,coalesce(session.ended_at,session.created_at), \
                    coalesce((SELECT max(received.received_at) FROM capture_events received \
                               WHERE received.account_id=$1 \
                                 AND received.capture_session_id=session.id),session.created_at), \
                    coalesce((SELECT max(job.updated_at) FROM capture_events source \
                               JOIN media_processing_jobs job \
                                 ON job.account_id=source.account_id AND job.event_id=source.event_id \
                              WHERE source.account_id=$1 \
                                AND source.capture_session_id=session.id),session.created_at)) \
                    <=clock_timestamp()-make_interval(secs=>$7) AS server_quiet, \
                receipt.state AS formation_state, \
                receipt.source_revision AS formation_source_revision, \
                receipt.completed_revision AS formation_completed_revision, \
                receipt.completed_outcome AS formation_completed_outcome, \
                receipt.completed_source_fingerprint AS formation_completed_source_fingerprint, \
                floor(extract(epoch FROM receipt.finish_requested_at)*1000)::bigint \
                    AS formation_finish_requested_ms, \
                floor(extract(epoch FROM receipt.seal_finalized_at)*1000)::bigint \
                    AS formation_seal_finalized_ms, \
                receipt.seal_generation AS formation_seal_generation, \
                seal.source_revision AS formation_seal_source_revision, \
                seal.stream_maxima_sha256 AS formation_seal_stream_maxima_sha256, \
                receipt.seal_finalization_provenance \
               FROM capture_sessions session LEFT JOIN capture_events event \
                 ON event.account_id=session.account_id AND event.capture_session_id=session.id \
               LEFT JOIN capture_formation_receipts receipt \
                 ON receipt.account_id=session.account_id \
                AND receipt.capture_session_id=session.id \
               LEFT JOIN capture_formation_seal_events seal \
                 ON seal.account_id=receipt.account_id \
                AND seal.capture_session_id=receipt.capture_session_id \
                AND seal.seal_generation=receipt.seal_generation \
                AND seal.event_kind='seal' \
              WHERE session.account_id=$1 AND session.id=ANY($2) \
              GROUP BY session.account_id,session.id,session.started_at,session.last_event_at,session.ended_at, \
                       receipt.account_id,receipt.capture_session_id,receipt.state, \
                       receipt.source_revision,receipt.completed_revision, \
                       receipt.completed_outcome,receipt.completed_source_fingerprint, \
                       receipt.finish_requested_at,receipt.seal_finalized_at, \
                       receipt.seal_generation,receipt.seal_finalization_provenance, \
                       seal.event_kind,seal.source_revision,seal.stream_maxima_sha256 \
              ORDER BY session.id",
    )
    .bind(account_id)
    .bind(candidate_ids)
    .bind(PROCESSOR_VERSION)
    .bind(NON_RESURRECTABLE_MEDIA_ERROR_CODES.as_slice())
    .bind(RESURRECTION_TOTAL_ATTEMPT_CAP)
    .bind(RESURRECTION_WINDOW_SECONDS_INTEGRAL as f64)
    .bind(QUIET_HORIZON_SECONDS as f64)
    .fetch_all(&mut *connection)
    .await?;
    if rows.len() != candidate_ids.len() {
        return Err(EnclaveError::Conflict(
            "memory reconciliation session page changed while loading".into(),
        ));
    }
    rows.into_iter()
        .map(|row| {
            Ok(SourceSession {
                id: row.try_get("id")?,
                started_ms: row.try_get("started_ms")?,
                ended_ms: row.try_get("ended_ms")?,
                sealed: row.try_get("sealed")?,
                streams_settled: row.try_get("streams_settled")?,
                jobs_terminal: row.try_get("jobs_terminal")?,
                media_terminal: row.try_get("media_terminal")?,
                server_quiet: row.try_get("server_quiet")?,
                formation_state: row.try_get("formation_state")?,
                formation_source_revision: row.try_get("formation_source_revision")?,
                formation_completed_revision: row.try_get("formation_completed_revision")?,
                formation_completed_outcome: row.try_get("formation_completed_outcome")?,
                formation_completed_source_fingerprint: row
                    .try_get("formation_completed_source_fingerprint")?,
                formation_finish_requested_ms: row.try_get("formation_finish_requested_ms")?,
                formation_seal_finalized_ms: row.try_get("formation_seal_finalized_ms")?,
                formation_seal_generation: row.try_get("formation_seal_generation")?,
                formation_seal_source_revision: row.try_get("formation_seal_source_revision")?,
                formation_seal_stream_maxima_sha256: row
                    .try_get("formation_seal_stream_maxima_sha256")?,
                formation_seal_finalization_provenance: row
                    .try_get("seal_finalization_provenance")?,
                formation_current: false,
            })
        })
        .collect()
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ReadyNeighborhoodScan {
    closure_started_ms: i64,
    closure_ended_ms: i64,
    session_count: i64,
    session_commitment: Vec<u8>,
    all_settled: bool,
    verification_generation: i64,
}

enum NeighborhoodScanAdvance {
    Pending,
    Ready(ReadyNeighborhoodScan),
}

async fn ready_neighborhood_scan(
    connection: &mut PgConnection,
    account_id: &str,
    component_seed_sha256: &[u8],
) -> Result<Option<ReadyNeighborhoodScan>> {
    let row = sqlx::query(
        "SELECT scan.closure_started_ms,scan.closure_ended_ms,scan.discovery_count, \
                scan.discovery_commitment,scan.verification_generation, \
                coalesce(bool_and(member.settled),true) AS all_settled \
           FROM persistence_feature_reconciliation_neighborhood_scans scan \
           LEFT JOIN persistence_feature_reconciliation_neighborhood_members member \
             ON member.account_id=scan.account_id \
            AND member.component_seed_sha256=scan.component_seed_sha256 \
            AND member.closure_generation=scan.closure_generation \
          WHERE scan.account_id=$1 AND scan.component_seed_sha256=$2 AND scan.phase='ready' \
          GROUP BY scan.account_id,scan.closure_started_ms,scan.closure_ended_ms, \
                   scan.discovery_count,scan.discovery_commitment,scan.verification_generation",
    )
    .bind(account_id)
    .bind(component_seed_sha256)
    .fetch_optional(&mut *connection)
    .await?;
    row.map(|row| {
        Ok(ReadyNeighborhoodScan {
            closure_started_ms: row.try_get("closure_started_ms")?,
            closure_ended_ms: row.try_get("closure_ended_ms")?,
            session_count: row.try_get("discovery_count")?,
            session_commitment: row.try_get("discovery_commitment")?,
            all_settled: row.try_get("all_settled")?,
            verification_generation: row.try_get("verification_generation")?,
        })
    })
    .transpose()
}

async fn reset_neighborhood_scan(
    connection: &mut PgConnection,
    account_id: &str,
    component_seed_sha256: &[u8],
    predecessor_episode_ids: &[i64],
    closure_started_ms: i64,
    closure_ended_ms: i64,
) -> Result<()> {
    sqlx::query(
        "DELETE FROM persistence_feature_reconciliation_neighborhood_scans \
          WHERE account_id=$1",
    )
    .bind(account_id)
    .execute(&mut *connection)
    .await?;
    sqlx::query(
        "INSERT INTO persistence_feature_reconciliation_neighborhood_scans( \
             account_id,component_seed_sha256,predecessor_episode_ids,phase,closure_generation, \
             closure_started_ms,closure_ended_ms,pass_started_ms,pass_ended_ms, \
             rolling_commitment,rolling_count) \
         VALUES($1,$2,$3,'discovery',1,$4,$5,$4,$5,$6,0)",
    )
    .bind(account_id)
    .bind(component_seed_sha256)
    .bind(predecessor_episode_ids)
    .bind(closure_started_ms)
    .bind(closure_ended_ms)
    .bind(empty_neighborhood_commitment())
    .execute(&mut *connection)
    .await?;
    Ok(())
}

async fn restart_neighborhood_discovery(
    connection: &mut PgConnection,
    account_id: &str,
    closure_started_ms: i64,
    closure_ended_ms: i64,
) -> Result<()> {
    sqlx::query(
        "DELETE FROM persistence_feature_reconciliation_neighborhood_members \
          WHERE account_id=$1",
    )
    .bind(account_id)
    .execute(&mut *connection)
    .await?;
    sqlx::query(
        "UPDATE persistence_feature_reconciliation_neighborhood_scans SET \
                phase='discovery',closure_generation=closure_generation+1, \
                closure_started_ms=$2,closure_ended_ms=$3,pass_started_ms=$2,pass_ended_ms=$3, \
                cursor_session_id=NULL,rolling_commitment=$4,rolling_count=0, \
                discovery_commitment=NULL,discovery_count=NULL,updated_at=clock_timestamp() \
          WHERE account_id=$1",
    )
    .bind(account_id)
    .bind(closure_started_ms)
    .bind(closure_ended_ms)
    .bind(empty_neighborhood_commitment())
    .execute(&mut *connection)
    .await?;
    Ok(())
}

async fn advance_neighborhood_scan(
    connection: &mut PgConnection,
    account_id: &str,
    component_seed_sha256: &[u8],
    predecessor_episode_ids: &[i64],
    initial_started_ms: i64,
    initial_ended_ms: i64,
) -> Result<NeighborhoodScanAdvance> {
    let existing = sqlx::query(
        "SELECT component_seed_sha256,predecessor_episode_ids,closure_started_ms,closure_ended_ms FROM \
                persistence_feature_reconciliation_neighborhood_scans \
          WHERE account_id=$1 FOR UPDATE",
    )
    .bind(account_id)
    .fetch_optional(&mut *connection)
    .await?;
    let matches = existing.as_ref().is_some_and(|row| {
        row.try_get::<Vec<u8>, _>("component_seed_sha256")
            .ok()
            .as_deref()
            == Some(component_seed_sha256)
            && row
                .try_get::<Vec<i64>, _>("predecessor_episode_ids")
                .ok()
                .as_deref()
                == Some(predecessor_episode_ids)
    });
    if !matches {
        reset_neighborhood_scan(
            connection,
            account_id,
            component_seed_sha256,
            predecessor_episode_ids,
            initial_started_ms,
            initial_ended_ms,
        )
        .await?;
    } else if let Some(existing) = existing {
        let stored_started_ms: i64 = existing.try_get("closure_started_ms")?;
        let stored_ended_ms: i64 = existing.try_get("closure_ended_ms")?;
        if initial_started_ms < stored_started_ms || initial_ended_ms > stored_ended_ms {
            restart_neighborhood_discovery(
                connection,
                account_id,
                initial_started_ms.min(stored_started_ms),
                initial_ended_ms.max(stored_ended_ms),
            )
            .await?;
        }
    }
    if let Some(ready) =
        ready_neighborhood_scan(connection, account_id, component_seed_sha256).await?
    {
        return Ok(NeighborhoodScanAdvance::Ready(ready));
    }

    for _ in 0..NEIGHBORHOOD_MAX_PAGES_PER_INVOCATION {
        let row = sqlx::query(
            "SELECT phase,closure_generation,closure_started_ms,closure_ended_ms, \
                    pass_started_ms,pass_ended_ms,cursor_session_id,rolling_commitment, \
                    rolling_count,discovery_commitment,discovery_count,verification_generation \
               FROM persistence_feature_reconciliation_neighborhood_scans \
              WHERE account_id=$1 AND component_seed_sha256=$2 FOR UPDATE",
        )
        .bind(account_id)
        .bind(component_seed_sha256)
        .fetch_one(&mut *connection)
        .await?;
        let phase: String = row.try_get("phase")?;
        if phase == "ready" {
            return ready_neighborhood_scan(connection, account_id, component_seed_sha256)
                .await?
                .map(NeighborhoodScanAdvance::Ready)
                .ok_or_else(|| EnclaveError::Store("ready neighborhood scan disappeared".into()));
        }
        let closure_generation: i64 = row.try_get("closure_generation")?;
        let mut closure_started_ms: i64 = row.try_get("closure_started_ms")?;
        let mut closure_ended_ms: i64 = row.try_get("closure_ended_ms")?;
        let pass_started_ms: i64 = row.try_get("pass_started_ms")?;
        let pass_ended_ms: i64 = row.try_get("pass_ended_ms")?;
        let cursor: Option<String> = row.try_get("cursor_session_id")?;
        let rolling_commitment: Vec<u8> = row.try_get("rolling_commitment")?;
        let rolling_count: i64 = row.try_get("rolling_count")?;
        let discovery_commitment: Option<Vec<u8>> = row.try_get("discovery_commitment")?;
        let discovery_count: Option<i64> = row.try_get("discovery_count")?;
        let verification_generation: i64 = row.try_get("verification_generation")?;
        let (ids, has_more) = source_session_candidate_page(
            connection,
            account_id,
            closure_started_ms,
            closure_ended_ms,
            cursor.as_deref(),
        )
        .await?;
        let mut sessions = load_source_sessions_by_ids(connection, account_id, &ids).await?;
        verify_source_session_formation(connection, account_id, &mut sessions).await?;
        for session in &sessions {
            closure_started_ms = closure_started_ms.min(session.started_ms);
            closure_ended_ms = closure_ended_ms.max(session.ended_ms);
        }
        let next_commitment = advance_neighborhood_commitment(&rolling_commitment, &sessions)?;
        let next_count = rolling_count
            .checked_add(i64::try_from(sessions.len()).unwrap_or(i64::MAX))
            .ok_or_else(|| EnclaveError::Store("neighborhood session count overflowed".into()))?;
        if phase == "discovery" {
            for session in &sessions {
                sqlx::query(
                    "INSERT INTO persistence_feature_reconciliation_neighborhood_members( \
                         account_id,component_seed_sha256,closure_generation,session_id, \
                         started_ms,ended_ms,guard_commitment,settled) \
                     VALUES($1,$2,$3,$4,$5,$6,$7,$8)",
                )
                .bind(account_id)
                .bind(component_seed_sha256)
                .bind(closure_generation)
                .bind(&session.id)
                .bind(session.started_ms)
                .bind(session.ended_ms)
                .bind(source_session_guard_commitment(session)?)
                .bind(source_sessions_are_settled(std::slice::from_ref(session)))
                .execute(&mut *connection)
                .await?;
            }
        } else {
            let matching: i64 = if sessions.is_empty() {
                0
            } else {
                let ids = sessions
                    .iter()
                    .map(|session| session.id.clone())
                    .collect::<Vec<_>>();
                let commitments = sessions
                    .iter()
                    .map(source_session_guard_commitment)
                    .collect::<Result<Vec<_>>>()?;
                sqlx::query_scalar(
                    "SELECT count(*)::bigint FROM unnest($2::text[],$3::bytea[]) \
                          AS expected(session_id,guard_commitment) \
                      JOIN persistence_feature_reconciliation_neighborhood_members member \
                        ON member.account_id=$1 AND member.session_id=expected.session_id \
                       AND member.guard_commitment=expected.guard_commitment",
                )
                .bind(account_id)
                .bind(&ids)
                .bind(&commitments)
                .fetch_one(&mut *connection)
                .await?
            };
            if matching != i64::try_from(sessions.len()).unwrap_or(i64::MAX) {
                restart_neighborhood_discovery(
                    connection,
                    account_id,
                    closure_started_ms,
                    closure_ended_ms,
                )
                .await?;
                return Ok(NeighborhoodScanAdvance::Pending);
            }
        }
        let next_cursor = sessions.last().map(|session| session.id.as_str());
        if has_more {
            sqlx::query(
                "UPDATE persistence_feature_reconciliation_neighborhood_scans SET \
                        closure_started_ms=$3,closure_ended_ms=$4,cursor_session_id=$5, \
                        rolling_commitment=$6,rolling_count=$7,updated_at=clock_timestamp() \
                  WHERE account_id=$1 AND component_seed_sha256=$2",
            )
            .bind(account_id)
            .bind(component_seed_sha256)
            .bind(closure_started_ms)
            .bind(closure_ended_ms)
            .bind(next_cursor)
            .bind(&next_commitment)
            .bind(next_count)
            .execute(&mut *connection)
            .await?;
            continue;
        }
        if phase == "discovery" {
            if closure_started_ms != pass_started_ms || closure_ended_ms != pass_ended_ms {
                restart_neighborhood_discovery(
                    connection,
                    account_id,
                    closure_started_ms,
                    closure_ended_ms,
                )
                .await?;
                continue;
            }
            sqlx::query(
                "UPDATE persistence_feature_reconciliation_neighborhood_scans SET \
                        phase='verification',cursor_session_id=NULL,rolling_commitment=$3, \
                        rolling_count=0,discovery_commitment=$4,discovery_count=$5, \
                        verification_generation=verification_generation+1, \
                        updated_at=clock_timestamp() \
                  WHERE account_id=$1 AND component_seed_sha256=$2",
            )
            .bind(account_id)
            .bind(component_seed_sha256)
            .bind(empty_neighborhood_commitment())
            .bind(&next_commitment)
            .bind(next_count)
            .execute(&mut *connection)
            .await?;
            continue;
        }
        let verification_exact = discovery_commitment.as_deref()
            == Some(next_commitment.as_slice())
            && discovery_count == Some(next_count)
            && closure_started_ms == pass_started_ms
            && closure_ended_ms == pass_ended_ms;
        if !verification_exact {
            restart_neighborhood_discovery(
                connection,
                account_id,
                closure_started_ms,
                closure_ended_ms,
            )
            .await?;
            return Ok(NeighborhoodScanAdvance::Pending);
        }
        sqlx::query(
            "UPDATE persistence_feature_reconciliation_neighborhood_scans SET phase='ready', \
                    cursor_session_id=NULL,rolling_commitment=$3,rolling_count=$4, \
                    updated_at=clock_timestamp() \
              WHERE account_id=$1 AND component_seed_sha256=$2 AND phase='verification' \
                AND verification_generation=$5",
        )
        .bind(account_id)
        .bind(component_seed_sha256)
        .bind(&next_commitment)
        .bind(next_count)
        .bind(verification_generation)
        .execute(&mut *connection)
        .await?;
        return ready_neighborhood_scan(connection, account_id, component_seed_sha256)
            .await?
            .map(NeighborhoodScanAdvance::Ready)
            .ok_or_else(|| {
                EnclaveError::Store("neighborhood verification did not become ready".into())
            });
    }
    Ok(NeighborhoodScanAdvance::Pending)
}

async fn load_source_sessions(
    connection: &mut PgConnection,
    account_id: &str,
    closure_started_ms: i64,
    closure_ended_ms: i64,
) -> Result<Vec<SourceSession>> {
    let neighborhood_started_ms = closure_started_ms.saturating_sub(QUIET_HORIZON_SECONDS * 1_000);
    let neighborhood_ended_ms = closure_ended_ms.saturating_add(QUIET_HORIZON_SECONDS * 1_000);
    let intrinsic_session_ids = sqlx::query_scalar::<_, String>(
        "SELECT id FROM capture_sessions \
          WHERE account_id=$1 \
            AND started_at<=to_timestamp($3::double precision/1000.0) \
            AND greatest(last_event_at,coalesce(ended_at,last_event_at))\
                >=to_timestamp($2::double precision/1000.0) \
          ORDER BY id LIMIT 257",
    )
    .bind(account_id)
    .bind(neighborhood_started_ms)
    .bind(neighborhood_ended_ms)
    .fetch_all(&mut *connection)
    .await?;
    ensure_source_session_bound(intrinsic_session_ids.len())?;
    let event_session_ids = sqlx::query_scalar::<_, String>(
        "SELECT DISTINCT capture_session_id FROM capture_events \
          WHERE account_id=$1 \
            AND started_at<=to_timestamp($3::double precision/1000.0) \
            AND ended_at>=to_timestamp($2::double precision/1000.0) \
          ORDER BY capture_session_id LIMIT 257",
    )
    .bind(account_id)
    .bind(neighborhood_started_ms)
    .bind(neighborhood_ended_ms)
    .fetch_all(&mut *connection)
    .await?;
    ensure_source_session_bound(event_session_ids.len())?;
    let candidate_ids = intrinsic_session_ids
        .into_iter()
        .chain(event_session_ids)
        .collect::<BTreeSet<_>>();
    ensure_source_session_bound(candidate_ids.len())?;
    if candidate_ids.is_empty() {
        return Ok(Vec::new());
    }
    let candidate_ids = candidate_ids.into_iter().collect::<Vec<_>>();
    let rows = sqlx::query(
        "SELECT session.id, \
                floor(extract(epoch FROM least(session.started_at,coalesce(min(event.started_at),session.started_at)))*1000)::bigint AS started_ms, \
                floor(extract(epoch FROM greatest(session.last_event_at,coalesce(session.ended_at,session.last_event_at), \
                     coalesce(max(event.ended_at),session.last_event_at)))*1000)::bigint AS ended_ms, \
                receipt.seal_finalized_at IS NOT NULL AND receipt.seal_generation>=1 \
                    AND seal.event_kind='seal' AND seal.source_revision=receipt.source_revision \
                    AND NOT EXISTS(SELECT 1 FROM capture_formation_seal_events reopen \
                         WHERE reopen.account_id=receipt.account_id \
                           AND reopen.capture_session_id=receipt.capture_session_id \
                           AND reopen.seal_generation=receipt.seal_generation \
                           AND reopen.event_kind='reopen') AS sealed, \
                EXISTS(SELECT 1 FROM capture_streams stream \
                    WHERE stream.account_id=$1 AND stream.capture_session_id=session.id) \
                  AND NOT EXISTS(SELECT 1 FROM capture_streams stream \
                    WHERE stream.account_id=$1 AND stream.capture_session_id=session.id \
                      AND (stream.sealed_sequence IS NULL \
                           OR stream.committed_through_sequence<>stream.sealed_sequence)) \
                    AS streams_settled, \
                NOT EXISTS(SELECT 1 FROM capture_events event \
                    JOIN media_processing_jobs job ON job.account_id=event.account_id AND job.event_id=event.event_id \
                    WHERE event.account_id=$1 AND event.capture_session_id=session.id \
                      AND job.state NOT IN ('succeeded','canceled') \
                      AND (job.state<>'failed_terminal' OR ( \
                           job.processor_version=$3 \
                           AND NOT (coalesce(job.error_code,'')=ANY($4::text[])) \
                           AND job.attempt_count<$5 \
                           AND event.started_at>=clock_timestamp()-make_interval(secs=>$6)))) \
                    AS jobs_terminal, \
                NOT EXISTS(SELECT 1 FROM capture_events event \
                    JOIN media_objects object ON object.account_id=event.account_id AND object.event_id=event.event_id \
                    WHERE event.account_id=$1 AND event.capture_session_id=session.id \
                      AND object.deleted_at IS NULL \
                      AND object.processing_state IN ('queued','processing','retry_wait')) AS media_terminal \
               ,greatest( \
                    session.created_at,coalesce(session.ended_at,session.created_at), \
                    coalesce((SELECT max(received.received_at) FROM capture_events received \
                               WHERE received.account_id=$1 \
                                 AND received.capture_session_id=session.id),session.created_at), \
                    coalesce((SELECT max(job.updated_at) FROM capture_events source \
                               JOIN media_processing_jobs job \
                                 ON job.account_id=source.account_id AND job.event_id=source.event_id \
                              WHERE source.account_id=$1 \
                                AND source.capture_session_id=session.id),session.created_at)) \
                    <=clock_timestamp()-make_interval(secs=>$7) AS server_quiet, \
                receipt.state AS formation_state, \
                receipt.source_revision AS formation_source_revision, \
                receipt.completed_revision AS formation_completed_revision, \
                receipt.completed_outcome AS formation_completed_outcome, \
                receipt.completed_source_fingerprint AS formation_completed_source_fingerprint, \
                floor(extract(epoch FROM receipt.finish_requested_at)*1000)::bigint \
                    AS formation_finish_requested_ms, \
                floor(extract(epoch FROM receipt.seal_finalized_at)*1000)::bigint \
                    AS formation_seal_finalized_ms, \
                receipt.seal_generation AS formation_seal_generation, \
                seal.source_revision AS formation_seal_source_revision, \
                seal.stream_maxima_sha256 AS formation_seal_stream_maxima_sha256, \
                receipt.seal_finalization_provenance \
               FROM capture_sessions session LEFT JOIN capture_events event \
                 ON event.account_id=session.account_id AND event.capture_session_id=session.id \
               LEFT JOIN capture_formation_receipts receipt \
                 ON receipt.account_id=session.account_id \
                AND receipt.capture_session_id=session.id \
               LEFT JOIN capture_formation_seal_events seal \
                 ON seal.account_id=receipt.account_id \
                AND seal.capture_session_id=receipt.capture_session_id \
                AND seal.seal_generation=receipt.seal_generation \
                AND seal.event_kind='seal' \
              WHERE session.account_id=$1 AND session.id=ANY($2) \
              GROUP BY session.account_id,session.id,session.started_at,session.last_event_at,session.ended_at, \
                       receipt.account_id,receipt.capture_session_id,receipt.state, \
                       receipt.source_revision,receipt.completed_revision, \
                       receipt.completed_outcome,receipt.completed_source_fingerprint, \
                       receipt.finish_requested_at,receipt.seal_finalized_at, \
                       receipt.seal_generation,receipt.seal_finalization_provenance, \
                       seal.event_kind,seal.source_revision,seal.stream_maxima_sha256 \
              ORDER BY started_ms,session.id",
    )
    .bind(account_id)
    .bind(&candidate_ids)
    .bind(PROCESSOR_VERSION)
    .bind(NON_RESURRECTABLE_MEDIA_ERROR_CODES.as_slice())
    .bind(RESURRECTION_TOTAL_ATTEMPT_CAP)
    .bind(RESURRECTION_WINDOW_SECONDS_INTEGRAL as f64)
    .bind(QUIET_HORIZON_SECONDS as f64)
    .fetch_all(&mut *connection)
    .await?;
    ensure_source_session_bound(rows.len())?;
    rows.into_iter()
        .map(|row| {
            Ok(SourceSession {
                id: row.try_get("id")?,
                started_ms: row.try_get("started_ms")?,
                ended_ms: row.try_get("ended_ms")?,
                sealed: row.try_get("sealed")?,
                streams_settled: row.try_get("streams_settled")?,
                jobs_terminal: row.try_get("jobs_terminal")?,
                media_terminal: row.try_get("media_terminal")?,
                server_quiet: row.try_get("server_quiet")?,
                formation_state: row.try_get("formation_state")?,
                formation_source_revision: row.try_get("formation_source_revision")?,
                formation_completed_revision: row.try_get("formation_completed_revision")?,
                formation_completed_outcome: row.try_get("formation_completed_outcome")?,
                formation_completed_source_fingerprint: row
                    .try_get("formation_completed_source_fingerprint")?,
                formation_finish_requested_ms: row.try_get("formation_finish_requested_ms")?,
                formation_seal_finalized_ms: row.try_get("formation_seal_finalized_ms")?,
                formation_seal_generation: row.try_get("formation_seal_generation")?,
                formation_seal_source_revision: row.try_get("formation_seal_source_revision")?,
                formation_seal_stream_maxima_sha256: row
                    .try_get("formation_seal_stream_maxima_sha256")?,
                formation_seal_finalization_provenance: row
                    .try_get("seal_finalization_provenance")?,
                formation_current: false,
            })
        })
        .collect()
}

async fn read_snapshot(
    connection: &mut PgConnection,
    account_id: &str,
    predecessor_ids: &[i64],
    atom_limit: i64,
    authority: &ActiveReconciliationAuthority,
) -> Result<Option<(ReconciliationSnapshot, bool)>> {
    if predecessor_ids.is_empty() || predecessor_ids.len() > MAX_DRAFTS as usize {
        return Err(EnclaveError::InvalidRequest(
            "memory reconciliation predecessor set is invalid".into(),
        ));
    }
    let rows = sqlx::query(
        "SELECT episode.id, \
                floor(extract(epoch FROM episode.started_at)*1000)::bigint AS started_at_ms, \
                floor(extract(epoch FROM episode.ended_at)*1000)::bigint AS ended_at_ms, \
                episode.type,episode.title,episode.summary,episode.participants::text, \
                episode.languages::text,episode.action_items::text,episode.model, \
                episode.minute_summaries::text,episode.minutes_text,episode.substance, \
                episode.visual_evidence, \
                floor(extract(epoch FROM episode.updated_at)*1000)::bigint AS updated_at_ms, \
                episode.identity_revision,episode.structure_state,handle.state \
           FROM episodes episode JOIN memory_handles handle \
             ON handle.account_id=episode.account_id AND handle.episode_id=episode.id \
          WHERE episode.account_id=$1 AND episode.id=ANY($2) \
            AND episode.finalized_at IS NULL \
            AND episode.finalization_status NOT IN ('processing','deleting') \
            AND episode.finalization_claim_token IS NULL \
            AND NOT EXISTS(SELECT 1 FROM episode_final_briefs brief \
                 WHERE brief.account_id=episode.account_id AND brief.episode_id=episode.id) \
            AND NOT EXISTS(SELECT 1 FROM webhook_deliveries delivery \
                 WHERE delivery.account_id=episode.account_id AND delivery.episode_id=episode.id) \
            AND NOT EXISTS(SELECT 1 FROM email_deliveries delivery \
                 WHERE delivery.account_id=episode.account_id AND delivery.episode_id=episode.id) \
            AND NOT EXISTS(SELECT 1 FROM push_deliveries delivery \
                 WHERE delivery.account_id=episode.account_id AND delivery.episode_id=episode.id) \
          ORDER BY episode.id FOR UPDATE OF episode",
    )
    .bind(account_id)
    .bind(predecessor_ids)
    .fetch_all(&mut *connection)
    .await?;
    if rows.len() != predecessor_ids.len() {
        return Ok(None);
    }
    let member_rows = sqlx::query(
        "SELECT episode_id,record_type,record_id FROM active_episode_members \
          WHERE account_id=$1 AND episode_id=ANY($2) \
          ORDER BY episode_id,record_type,record_id",
    )
    .bind(account_id)
    .bind(predecessor_ids)
    .fetch_all(&mut *connection)
    .await?;
    let mut members = HashMap::<i64, Vec<String>>::new();
    for row in member_rows {
        let record_type: String = row.try_get("record_type")?;
        members
            .entry(row.try_get("episode_id")?)
            .or_default()
            .push(source_id(&record_type, row.try_get("record_id")?));
    }
    let mut drafts = Vec::with_capacity(rows.len());
    for row in rows {
        let structure: String = row.try_get("structure_state")?;
        let state: String = row.try_get("state")?;
        if structure != "draft" || state != "active" {
            return Ok(None);
        }
        let updated_ms = row.try_get::<Option<i64>, _>("updated_at_ms")?;
        let id: i64 = row.try_get("id")?;
        drafts.push(ReconciliationDraft {
            id,
            started_at: isotime::format_epoch_millis(row.try_get("started_at_ms")?),
            ended_at: isotime::format_epoch_millis(row.try_get("ended_at_ms")?),
            episode_type: row.try_get("type")?,
            title: row
                .try_get::<Option<String>, _>("title")?
                .unwrap_or_default(),
            summary: row.try_get("summary")?,
            participants: json_string_array(row.try_get("participants")?),
            languages: json_string_array(row.try_get("languages")?),
            action_items: json_string_array(row.try_get("action_items")?),
            model: row.try_get("model")?,
            minute_summaries: json_value(row.try_get("minute_summaries")?, json!([])),
            minutes_text: row.try_get("minutes_text")?,
            substance: row.try_get("substance")?,
            visual_evidence: row.try_get("visual_evidence")?,
            updated_at: updated_ms.map(isotime::format_epoch_millis),
            identity_revision: row.try_get("identity_revision")?,
            member_source_ids: members.remove(&id).unwrap_or_default(),
        });
    }
    let mut closure_started_ms = drafts
        .iter()
        .map(|draft| timestamp(&draft.started_at, "reconciliation draft start"))
        .collect::<Result<Vec<_>>>()?
        .into_iter()
        .min()
        .ok_or_else(|| EnclaveError::Store("memory reconciliation cohort is empty".into()))?;
    let mut closure_ended_ms = drafts
        .iter()
        .map(|draft| timestamp(&draft.ended_at, "reconciliation draft end"))
        .collect::<Result<Vec<_>>>()?
        .into_iter()
        .max()
        .ok_or_else(|| EnclaveError::Store("memory reconciliation cohort is empty".into()))?;
    let mut atoms = Vec::new();
    let mut sessions = Vec::new();
    let mut outside_drafts = OutsideDraftClosure::default();
    let mut converged = false;
    for _ in 0..=256 {
        let before = (
            closure_started_ms,
            closure_ended_ms,
            sessions
                .iter()
                .map(|row: &SourceSession| row.id.clone())
                .collect::<Vec<_>>(),
            atoms
                .iter()
                .map(|row: &ReconciliationEvidenceAtom| row.source_id.clone())
                .collect::<Vec<_>>(),
            outside_drafts.episode_ids.clone(),
        );
        let candidates =
            load_source_sessions(connection, account_id, closure_started_ms, closure_ended_ms)
                .await?;
        sessions = connected_source_sessions(&candidates, closure_started_ms, closure_ended_ms);
        for session in &sessions {
            closure_started_ms = closure_started_ms.min(session.started_ms);
            closure_ended_ms = closure_ended_ms.max(session.ended_ms);
        }
        atoms = read_atoms(
            connection,
            account_id,
            predecessor_ids,
            closure_started_ms,
            closure_ended_ms,
            atom_limit,
        )
        .await?;
        for atom in &atoms {
            closure_started_ms = closure_started_ms.min(timestamp(
                &atom.started_at,
                "reconciliation evidence start",
            )?);
            closure_ended_ms =
                closure_ended_ms.max(timestamp(&atom.ended_at, "reconciliation evidence end")?);
        }
        outside_drafts = outside_draft_closure(
            connection,
            account_id,
            predecessor_ids,
            closure_started_ms,
            closure_ended_ms,
        )
        .await?;
        if let Some(started_ms) = outside_drafts.started_ms {
            closure_started_ms = closure_started_ms.min(started_ms);
        }
        if let Some(ended_ms) = outside_drafts.ended_ms {
            closure_ended_ms = closure_ended_ms.max(ended_ms);
        }
        let after = (
            closure_started_ms,
            closure_ended_ms,
            sessions
                .iter()
                .map(|row| row.id.clone())
                .collect::<Vec<_>>(),
            atoms
                .iter()
                .map(|row| row.source_id.clone())
                .collect::<Vec<_>>(),
            outside_drafts.episode_ids.clone(),
        );
        if before == after {
            converged = true;
            break;
        }
    }
    if !converged {
        return Err(EnclaveError::Store(
            "memory reconciliation source closure did not converge within its bound".into(),
        ));
    }
    verify_source_session_formation(connection, account_id, &mut sessions).await?;
    ensure_no_external_owners(predecessor_ids, &outside_drafts.episode_ids)?;
    if atoms.is_empty() {
        return Ok(None);
    }
    let atom_ids = atoms
        .iter()
        .map(|atom| atom.source_id.as_str())
        .collect::<HashSet<_>>();
    if drafts
        .iter()
        .flat_map(|draft| &draft.member_source_ids)
        .any(|id| !atom_ids.contains(id.as_str()))
    {
        return Err(EnclaveError::Conflict(
            "memory reconciliation source closure changed".into(),
        ));
    }
    let active_owners = sqlx::query_scalar::<_, i64>(
        "SELECT DISTINCT member.episode_id FROM active_episode_members member \
          WHERE member.account_id=$1 \
            AND (member.record_type,member.record_id) IN ( \
                SELECT 'utterance',unnest($2::bigint[]) \
                UNION ALL SELECT 'screenshot',unnest($3::bigint[])) \
          ORDER BY member.episode_id",
    )
    .bind(account_id)
    .bind(
        atoms
            .iter()
            .filter(|atom| atom.record_type == "utterance")
            .map(|atom| atom.record_id)
            .collect::<Vec<_>>(),
    )
    .bind(
        atoms
            .iter()
            .filter(|atom| atom.record_type == "screenshot")
            .map(|atom| atom.record_id)
            .collect::<Vec<_>>(),
    )
    .fetch_all(&mut *connection)
    .await?;
    ensure_no_external_owners(predecessor_ids, &active_owners)?;
    let cohort_started_at = isotime::format_epoch_millis(closure_started_ms);
    let cohort_ended_at = isotime::format_epoch_millis(closure_ended_ms);
    sessions.sort_by(|left, right| left.id.cmp(&right.id));
    // This gate intentionally does not consult the summarizer cursor. The
    // closure reads raw utterance/screenshot projections directly, expands
    // every touching capture session to its full event horizon, and requires
    // sealed streams plus terminal media jobs/objects. The cursor can lag
    // without hiding accepted atoms from this snapshot.
    let settled = source_sessions_are_settled(&sessions)
        && database_quiet_horizon(connection, closure_ended_ms).await?;
    let guard = sessions
        .iter()
        .map(|session| {
            json!({
                "session_id": session.id,
                "started_ms": session.started_ms,
                "ended_ms": session.ended_ms,
                "sealed": session.sealed,
                "streams_settled": session.streams_settled,
                "jobs_terminal": session.jobs_terminal,
                "media_terminal": session.media_terminal,
                "server_quiet": session.server_quiet,
                "formation_state": session.formation_state,
                "formation_source_revision": session.formation_source_revision,
                "formation_completed_revision": session.formation_completed_revision,
                "formation_completed_outcome": session.formation_completed_outcome,
                "formation_completed_source_fingerprint": session.formation_completed_source_fingerprint,
                "formation_finish_requested_ms": session.formation_finish_requested_ms,
                "formation_seal_finalized_ms": session.formation_seal_finalized_ms,
                "formation_seal_generation": session.formation_seal_generation,
                "formation_seal_source_revision": session.formation_seal_source_revision,
                "formation_seal_stream_maxima_sha256": session.formation_seal_stream_maxima_sha256,
                "formation_seal_finalization_provenance": session.formation_seal_finalization_provenance,
                "formation_current": session.formation_current,
            })
        })
        .collect::<Vec<_>>();
    let archive_revision = archive_revision(connection, account_id).await?;
    let source_fingerprint = digest_json(
        b"kioku.memory-reconciliation.source.v1\0",
        &json!({
            "account_id": account_id,
            "cohort_started_at": cohort_started_at,
            "cohort_ended_at": cohort_ended_at,
            "drafts": drafts,
            "atoms": atoms,
            "source_guard": guard,
            "outside_draft_owners": outside_drafts.episode_ids,
            "activation_generation": authority.generation,
            "producer_contract_sha256": authority.producer_contract_sha256,
            "reconciliation_model": authority.reconciliation_model,
            "vertex_location": authority.vertex_location,
        }),
    )?;
    let topology_fingerprint = digest_json(
        b"kioku.memory-reconciliation.topology.v1\0",
        &json!({
            "archive_revision": archive_revision,
            "source_fingerprint": source_fingerprint,
            "predecessor_episode_ids": predecessor_ids,
            "active_members": drafts.iter().map(|draft| (&draft.id,&draft.member_source_ids)).collect::<Vec<_>>(),
            "episode_revisions": drafts.iter().map(|draft| (&draft.id,&draft.updated_at,draft.identity_revision)).collect::<Vec<_>>(),
        }),
    )?;
    Ok(Some((
        ReconciliationSnapshot {
            account_id: account_id.to_owned(),
            cohort_started_at,
            cohort_ended_at,
            predecessor_episode_ids: predecessor_ids.to_vec(),
            drafts,
            atoms,
            capture_session_ids: sessions.iter().map(|session| session.id.clone()).collect(),
            source_fingerprint,
            topology_fingerprint,
            archive_revision,
        },
        settled,
    )))
}

#[derive(Clone, Debug, PartialEq)]
struct KeepDraft {
    id: i64,
    started_ms: i64,
    ended_ms: i64,
    exact_row: Value,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct KeepEvidenceClosure {
    count: i64,
    unowned_count: i64,
    selected_owned_count: i64,
    started_ms: Option<i64>,
    ended_ms: Option<i64>,
}

fn digest_framed(digest: &mut Sha256, bytes: &[u8]) {
    digest.update(u64::try_from(bytes.len()).unwrap_or(u64::MAX).to_be_bytes());
    digest.update(bytes);
}

fn lowercase_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

fn held_keep_promotion(
    component_ended_ms: Option<i64>,
    boundary_complete: bool,
) -> OversizedKeepPromotionResult {
    OversizedKeepPromotionResult::Held {
        resume_after_component_ended_at: boundary_complete
            .then(|| component_ended_ms.map(isotime::format_epoch_millis))
            .flatten(),
    }
}

async fn read_keep_drafts(
    connection: &mut PgConnection,
    account_id: &str,
    episode_ids: &[i64],
) -> Result<Option<Vec<KeepDraft>>> {
    let rows = sqlx::query(
        "SELECT episode.id, \
                floor(extract(epoch FROM episode.started_at)*1000)::bigint AS started_ms, \
                floor(extract(epoch FROM episode.ended_at)*1000)::bigint AS ended_ms, \
                to_jsonb(episode)::text AS exact_row \
           FROM episodes episode \
           JOIN memory_handles handle ON handle.account_id=episode.account_id \
                AND handle.episode_id=episode.id AND handle.state='active' \
          WHERE episode.account_id=$1 AND episode.id=ANY($2) \
            AND episode.structure_state='draft' AND episode.finalized_at IS NULL \
            AND episode.finalization_status NOT IN ('processing','deleting') \
            AND episode.finalization_claim_token IS NULL \
            AND NOT EXISTS(SELECT 1 FROM episode_final_briefs brief \
                 WHERE brief.account_id=episode.account_id AND brief.episode_id=episode.id) \
            AND NOT EXISTS(SELECT 1 FROM webhook_deliveries delivery \
                 WHERE delivery.account_id=episode.account_id AND delivery.episode_id=episode.id) \
            AND NOT EXISTS(SELECT 1 FROM email_deliveries delivery \
                 WHERE delivery.account_id=episode.account_id AND delivery.episode_id=episode.id) \
            AND NOT EXISTS(SELECT 1 FROM push_deliveries delivery \
                 WHERE delivery.account_id=episode.account_id AND delivery.episode_id=episode.id) \
          ORDER BY array_position($2::bigint[],episode.id) FOR UPDATE OF episode",
    )
    .bind(account_id)
    .bind(episode_ids)
    .fetch_all(connection)
    .await?;
    if rows.len() != episode_ids.len() {
        return Ok(None);
    }
    rows.into_iter()
        .map(|row| {
            Ok(KeepDraft {
                id: row.try_get("id")?,
                started_ms: row.try_get("started_ms")?,
                ended_ms: row.try_get("ended_ms")?,
                exact_row: serde_json::from_str(&row.try_get::<String, _>("exact_row")?)?,
            })
        })
        .collect::<Result<Vec<_>>>()
        .map(Some)
}

async fn selected_members_are_exact(
    connection: &mut PgConnection,
    account_id: &str,
    episode_ids: &[i64],
) -> Result<bool> {
    sqlx::query_scalar(
        "SELECT NOT EXISTS( \
             SELECT 1 FROM ( \
                 (SELECT episode_id,record_type,record_id FROM episode_members \
                    WHERE account_id=$1 AND episode_id=ANY($2) \
                  EXCEPT \
                  SELECT episode_id,record_type,record_id FROM active_episode_members \
                    WHERE account_id=$1 AND episode_id=ANY($2)) \
                 UNION ALL \
                 (SELECT episode_id,record_type,record_id FROM active_episode_members \
                    WHERE account_id=$1 AND episode_id=ANY($2) \
                  EXCEPT \
                  SELECT episode_id,record_type,record_id FROM episode_members \
                    WHERE account_id=$1 AND episode_id=ANY($2)) \
             ) mismatch)",
    )
    .bind(account_id)
    .bind(episode_ids)
    .fetch_one(connection)
    .await
    .map_err(Into::into)
}

async fn keep_evidence_closure(
    connection: &mut PgConnection,
    account_id: &str,
    episode_ids: &[i64],
    started_ms: i64,
    ended_ms: i64,
) -> Result<KeepEvidenceClosure> {
    let row = sqlx::query(
        "WITH evidence AS ( \
             SELECT segment.started_at + utterance.start_offset_seconds*interval '1 second' AS started_at, \
                    segment.started_at + utterance.end_offset_seconds*interval '1 second' AS ended_at, \
                    owner.episode_id \
               FROM utterances utterance \
               JOIN audio_segments segment ON segment.account_id=utterance.account_id \
                    AND segment.id=utterance.audio_segment_id \
               LEFT JOIN active_episode_members owner ON owner.account_id=utterance.account_id \
                    AND owner.record_type='utterance' AND owner.record_id=utterance.id \
              WHERE utterance.account_id=$1 AND (owner.episode_id=ANY($2) \
                    OR segment.started_at + utterance.start_offset_seconds*interval '1 second' \
                       BETWEEN to_timestamp($3::double precision/1000.0) \
                           AND to_timestamp($4::double precision/1000.0)) \
             UNION ALL \
             SELECT screenshot.captured_at,coalesce(screenshot.visible_until,screenshot.captured_at), \
                    owner.episode_id \
               FROM screenshots screenshot \
               LEFT JOIN active_episode_members owner ON owner.account_id=screenshot.account_id \
                    AND owner.record_type='screenshot' AND owner.record_id=screenshot.id \
              WHERE screenshot.account_id=$1 AND (owner.episode_id=ANY($2) \
                    OR screenshot.captured_at BETWEEN to_timestamp($3::double precision/1000.0) \
                           AND to_timestamp($4::double precision/1000.0)) \
         ) SELECT count(*)::bigint AS evidence_count, \
                  count(*) FILTER (WHERE episode_id IS NULL)::bigint AS unowned_count, \
                  count(*) FILTER (WHERE episode_id=ANY($2))::bigint AS selected_owned_count, \
                  floor(extract(epoch FROM min(started_at))*1000)::bigint AS started_ms, \
                  floor(extract(epoch FROM max(greatest(ended_at,started_at)))*1000)::bigint AS ended_ms \
             FROM evidence",
    )
    .bind(account_id)
    .bind(episode_ids)
    .bind(started_ms)
    .bind(ended_ms)
    .fetch_one(connection)
    .await?;
    Ok(KeepEvidenceClosure {
        count: row.try_get("evidence_count")?,
        unowned_count: row.try_get("unowned_count")?,
        selected_owned_count: row.try_get("selected_owned_count")?,
        started_ms: row.try_get("started_ms")?,
        ended_ms: row.try_get("ended_ms")?,
    })
}

async fn unowned_evidence_is_explicit_no_memory(
    connection: &mut PgConnection,
    account_id: &str,
    episode_ids: &[i64],
    started_ms: i64,
    ended_ms: i64,
    component_seed_sha256: &[u8],
) -> Result<bool> {
    sqlx::query_scalar(
        "WITH evidence(record_type,record_id,episode_id) AS ( \
             SELECT 'utterance'::text,utterance.id,owner.episode_id \
               FROM utterances utterance \
               JOIN audio_segments segment ON segment.account_id=utterance.account_id \
                    AND segment.id=utterance.audio_segment_id \
               LEFT JOIN active_episode_members owner ON owner.account_id=utterance.account_id \
                    AND owner.record_type='utterance' AND owner.record_id=utterance.id \
              WHERE utterance.account_id=$1 AND (owner.episode_id=ANY($2) \
                    OR segment.started_at + utterance.start_offset_seconds*interval '1 second' \
                       BETWEEN to_timestamp($3::double precision/1000.0) \
                           AND to_timestamp($4::double precision/1000.0)) \
             UNION ALL \
             SELECT 'screenshot'::text,screenshot.id,owner.episode_id \
               FROM screenshots screenshot \
               LEFT JOIN active_episode_members owner ON owner.account_id=screenshot.account_id \
                    AND owner.record_type='screenshot' AND owner.record_id=screenshot.id \
              WHERE screenshot.account_id=$1 AND (owner.episode_id=ANY($2) \
                    OR screenshot.captured_at BETWEEN to_timestamp($3::double precision/1000.0) \
                           AND to_timestamp($4::double precision/1000.0)) \
         ) SELECT NOT EXISTS( \
             SELECT 1 FROM evidence source \
              WHERE source.episode_id IS NULL AND NOT EXISTS( \
                  SELECT 1 FROM capture_formation_pages page \
                  JOIN capture_formation_receipts receipt \
                    ON receipt.account_id=page.account_id \
                   AND receipt.capture_session_id=page.capture_session_id \
                   AND receipt.source_revision=page.source_revision \
                  JOIN persistence_feature_reconciliation_neighborhood_members member \
                    ON member.account_id=page.account_id \
                   AND member.session_id=page.capture_session_id \
                   AND member.component_seed_sha256=$5 \
                   AND member.settled \
                 WHERE page.account_id=$1 AND page.state='complete' \
                   AND page.completed_outcome='no_memory' \
                   AND receipt.state='complete' \
                   AND receipt.completed_revision=receipt.source_revision \
                   AND ((source.record_type='utterance' \
                         AND source.record_id=ANY(page.provider_utterance_ids)) \
                     OR (source.record_type='screenshot' \
                         AND source.record_id=ANY(page.provider_screenshot_ids))) \
              ))",
    )
    .bind(account_id)
    .bind(episode_ids)
    .bind(started_ms)
    .bind(ended_ms)
    .bind(component_seed_sha256)
    .fetch_one(connection)
    .await
    .map_err(Into::into)
}

async fn selected_members_commitment(
    connection: &mut PgConnection,
    account_id: &str,
    episode_ids: &[i64],
) -> Result<(i64, Vec<u8>)> {
    let count: i64 = sqlx::query_scalar(
        "SELECT count(*)::bigint FROM active_episode_members \
          WHERE account_id=$1 AND episode_id=ANY($2)",
    )
    .bind(account_id)
    .bind(episode_ids)
    .fetch_one(&mut *connection)
    .await?;
    if count > MAX_OVERSIZED_KEEP_SOURCES {
        return Err(EnclaveError::Store(
            "providerless KEEP source count exceeds its operational bound".into(),
        ));
    }
    let mut digest = Sha256::new();
    digest.update(b"kioku.memory-reconciliation.oversized-keep-members.v1\0");
    let mut after_type = String::new();
    let mut after_id = 0_i64;
    let mut seen = 0_i64;
    loop {
        let rows = sqlx::query(
            "SELECT episode_id,record_type,record_id FROM active_episode_members \
              WHERE account_id=$1 AND episode_id=ANY($2) \
                AND (record_type,record_id)>($3,$4) \
              ORDER BY record_type,record_id LIMIT $5",
        )
        .bind(account_id)
        .bind(episode_ids)
        .bind(&after_type)
        .bind(after_id)
        .bind(OVERSIZED_KEEP_SOURCE_PAGE_SIZE)
        .fetch_all(&mut *connection)
        .await?;
        if rows.is_empty() {
            break;
        }
        for row in &rows {
            let episode_id: i64 = row.try_get("episode_id")?;
            let record_type: String = row.try_get("record_type")?;
            let record_id: i64 = row.try_get("record_id")?;
            digest_framed(&mut digest, &episode_id.to_be_bytes());
            digest_framed(&mut digest, record_type.as_bytes());
            digest_framed(&mut digest, &record_id.to_be_bytes());
            after_type = record_type;
            after_id = record_id;
            seen += 1;
        }
    }
    if seen != count {
        return Err(EnclaveError::Conflict(
            "providerless KEEP membership changed while hashing".into(),
        ));
    }
    Ok((count, digest.finalize().to_vec()))
}

fn staged_from_row(row: &sqlx::postgres::PgRow) -> Result<StagedReconciliation> {
    let normalized_partition: Value =
        serde_json::from_str(&row.try_get::<String, _>("normalized_partition")?)?;
    let result_commitment: Vec<u8> = row.try_get("result_commitment")?;
    if partition_commitment(&normalized_partition)? != result_commitment {
        return Err(EnclaveError::Store(
            "persisted reconciliation partition commitment mismatch".into(),
        ));
    }
    let planned_outputs: Vec<ReconciledMemoryWrite> =
        serde_json::from_str(&row.try_get::<String, _>("planned_outputs")?)?;
    let planned_outputs_commitment: Vec<u8> = row.try_get("planned_outputs_commitment")?;
    if reconciliation_outputs_commitment(&planned_outputs)? != planned_outputs_commitment {
        return Err(EnclaveError::Store(
            "persisted reconciliation output commitment mismatch".into(),
        ));
    }
    Ok(StagedReconciliation {
        account_id: row.try_get("account_id")?,
        source_fingerprint: row.try_get("source_fingerprint")?,
        topology_fingerprint: row.try_get("topology_fingerprint")?,
        predecessor_episode_ids: row.try_get("predecessor_episode_ids")?,
        normalized_partition,
        result_commitment,
        planned_outputs,
        planned_outputs_commitment,
        model: row.try_get("model")?,
        vertex_event_id: row.try_get("vertex_event_id")?,
        provider_attempt_identity: row.try_get("provider_attempt_identity")?,
        provider_invocation_fingerprint: row.try_get("provider_invocation_fingerprint")?,
        reconciliation_version: row.try_get("reconciliation_version")?,
        prompt_version: row.try_get("prompt_version")?,
        partition_schema_version: row.try_get("partition_schema_version")?,
        validator_version: row.try_get("validator_version")?,
        activation_generation: row.try_get("activation_generation")?,
        producer_contract_sha256: row.try_get("producer_contract_sha256")?,
        reconciliation_model: row.try_get("reconciliation_model")?,
        vertex_location: row.try_get("vertex_location")?,
    })
}

struct ReconciliationProviderProvenance<'a> {
    account_id: &'a str,
    reconciliation_model: &'a str,
    vertex_location: &'a str,
    staged_model: &'a str,
    vertex_event_id: Option<&'a str>,
    provider_attempt_identity: Option<&'a [u8]>,
    provider_invocation_fingerprint: Option<&'a [u8]>,
}

async fn validate_reconciliation_provider_provenance(
    connection: &mut PgConnection,
    provenance: ReconciliationProviderProvenance<'_>,
) -> Result<()> {
    let ReconciliationProviderProvenance {
        account_id,
        reconciliation_model,
        vertex_location,
        staged_model,
        vertex_event_id,
        provider_attempt_identity,
        provider_invocation_fingerprint,
    } = provenance;
    if staged_model == "conservative-v1" {
        if vertex_event_id.is_none()
            && provider_attempt_identity.is_none()
            && provider_invocation_fingerprint.is_none()
        {
            return Ok(());
        }
        return Err(EnclaveError::Conflict(
            "providerless reconciliation stage has provider provenance".into(),
        ));
    }
    let ambiguity = staged_model == "conservative-ambiguity-v1";
    if !ambiguity && staged_model != reconciliation_model {
        return Err(EnclaveError::Conflict(
            "reconciliation provider stage model is not authoritative".into(),
        ));
    }
    let event_id = vertex_event_id.ok_or_else(|| {
        EnclaveError::Conflict("reconciliation provider stage has no usage event".into())
    })?;
    let attempt_identity: [u8; 32] = provider_attempt_identity
        .ok_or_else(|| {
            EnclaveError::Conflict("reconciliation provider stage has no attempt identity".into())
        })?
        .try_into()
        .map_err(|_| {
            EnclaveError::Conflict(
                "reconciliation provider stage attempt identity is invalid".into(),
            )
        })?;
    let invocation_fingerprint = provider_invocation_fingerprint.ok_or_else(|| {
        EnclaveError::Conflict("reconciliation provider stage has no invocation fingerprint".into())
    })?;
    if !valid_digest(invocation_fingerprint)
        || vertex_attempt_event_id(&attempt_identity) != event_id
    {
        return Err(EnclaveError::Conflict(
            "reconciliation provider stage identity is inconsistent".into(),
        ));
    }
    let usage = sqlx::query(
        "SELECT request_fingerprint,operation,requested_model,location,outcome,http_status \
           FROM vertex_usage_events WHERE account_id=$1 AND event_id=$2",
    )
    .bind(account_id)
    .bind(event_id)
    .fetch_optional(&mut *connection)
    .await?
    .ok_or_else(|| {
        EnclaveError::Conflict("reconciliation provider usage event is absent".into())
    })?;
    let request_fingerprint: Vec<u8> = usage.try_get("request_fingerprint")?;
    let operation: String = usage.try_get("operation")?;
    let requested_model: String = usage.try_get("requested_model")?;
    let location: String = usage.try_get("location")?;
    let outcome: String = usage.try_get("outcome")?;
    let http_status: Option<i32> = usage.try_get("http_status")?;
    let successful_response =
        matches!(outcome.as_str(), "metered" | "usage_missing") && http_status == Some(200);
    let terminal_is_valid = if ambiguity {
        outcome == "ambiguous" || successful_response
    } else {
        successful_response
    };
    if request_fingerprint.as_slice() != invocation_fingerprint
        || operation != VertexOperation::EpisodeReconciliation.as_str()
        || requested_model != reconciliation_model
        || location != vertex_location
        || !terminal_is_valid
    {
        return Err(EnclaveError::Conflict(
            "reconciliation provider usage provenance is inconsistent".into(),
        ));
    }
    Ok(())
}

async fn read_stage(
    connection: &mut PgConnection,
    account_id: &str,
    fingerprint: &[u8],
) -> Result<Option<StagedReconciliation>> {
    let row = sqlx::query(
        "SELECT stage.account_id,stage.source_fingerprint,stage.topology_fingerprint, \
                stage.predecessor_episode_ids, \
                stage.normalized_partition::text AS normalized_partition,stage.result_commitment, \
                stage.planned_outputs::text AS planned_outputs,stage.planned_outputs_commitment, \
                stage.model,stage.vertex_event_id,stage.reconciliation_version, \
                stage.prompt_version,stage.partition_schema_version,stage.validator_version, \
                contract.activation_generation,contract.producer_contract_sha256, \
                contract.reconciliation_model,contract.vertex_location, \
                contract.provider_attempt_identity,contract.provider_invocation_fingerprint \
           FROM memory_reconciliation_stages stage \
           JOIN persistence_feature_reconciliation_stage_contracts contract \
             ON contract.account_id=stage.account_id \
            AND contract.source_fingerprint=stage.source_fingerprint \
            AND contract.reconciliation_id IS NULL \
          WHERE stage.account_id=$1 AND stage.source_fingerprint=$2",
    )
    .bind(account_id)
    .bind(fingerprint)
    .fetch_optional(&mut *connection)
    .await?;
    let Some(row) = row else {
        return Ok(None);
    };
    let staged = staged_from_row(&row)?;
    validate_reconciliation_provider_provenance(
        connection,
        ReconciliationProviderProvenance {
            account_id: &staged.account_id,
            reconciliation_model: &staged.reconciliation_model,
            vertex_location: &staged.vertex_location,
            staged_model: &staged.model,
            vertex_event_id: staged.vertex_event_id.as_deref(),
            provider_attempt_identity: staged.provider_attempt_identity.as_deref(),
            provider_invocation_fingerprint: staged.provider_invocation_fingerprint.as_deref(),
        },
    )
    .await?;
    Ok(Some(staged))
}

fn validate_output(output: &ReconciledMemoryWrite) -> Result<()> {
    if output.output_ordinal < 0
        || output.predecessor_episode_ids.is_empty()
        || output.member_source_ids.is_empty()
        || output.title.trim().is_empty()
        || !matches!(output.substance.as_str(), "none" | "low" | "normal")
        || !matches!(output.visual_evidence.as_str(), "none" | "useful")
        || timestamp(&output.started_at, "reconciled memory start")?
            >= timestamp(&output.ended_at, "reconciled memory end")?
    {
        return Err(EnclaveError::InvalidRequest(
            "reconciled memory output is invalid".into(),
        ));
    }
    Ok(())
}

/// Persists one exact stage on a transaction whose caller already holds the
/// activation contract KEY SHARE and the account reconciliation advisory lock.
/// Provider-backed callers additionally retain the snapshot row locks acquired
/// by the egress guard; providerless callers establish the same lock order in
/// `stage_reconciliation` before entering here.
async fn stage_reconciliation_locked(
    connection: &mut PgConnection,
    claim: &ReconciliationClaim,
    staged: ReconciliationStageWrite,
) -> Result<StagedReconciliation> {
    if !valid_digest(&staged.result_commitment)
        || !staged.normalized_partition.is_object()
        || staged.planned_outputs.is_empty()
        || staged.planned_outputs.len() > MAX_DRAFTS as usize
        || staged.model.trim().is_empty()
        || [
            staged.reconciliation_version,
            staged.prompt_version,
            staged.partition_schema_version,
            staged.validator_version,
        ]
        .into_iter()
        .any(|version| version <= 0)
    {
        return Err(EnclaveError::InvalidRequest(
            "memory reconciliation stage is invalid".into(),
        ));
    }
    if partition_commitment(&staged.normalized_partition)? != staged.result_commitment {
        return Err(EnclaveError::InvalidRequest(
            "memory reconciliation result commitment does not bind the normalized partition".into(),
        ));
    }
    for output in &staged.planned_outputs {
        validate_output(output)?;
    }
    validate_reconciliation_provider_provenance(
        connection,
        ReconciliationProviderProvenance {
            account_id: &claim.account_id,
            reconciliation_model: &claim.reconciliation_model,
            vertex_location: &claim.vertex_location,
            staged_model: &staged.model,
            vertex_event_id: staged.vertex_event_id.as_deref(),
            provider_attempt_identity: staged.provider_attempt_identity.as_deref(),
            provider_invocation_fingerprint: staged.provider_invocation_fingerprint.as_deref(),
        },
    )
    .await?;
    if let Some(attempt_identity) = staged.provider_attempt_identity.as_deref() {
        let expected_attempt = reconciliation_provider_attempt_identity(
            &claim.source_fingerprint,
            claim.activation_generation,
            &claim.producer_contract_sha256,
            claim.model_attempt_count,
        )?;
        if attempt_identity != expected_attempt {
            return Err(EnclaveError::Conflict(
                "reconciliation provider attempt does not match its claim".into(),
            ));
        }
    }
    let planned_outputs_commitment = reconciliation_outputs_commitment(&staged.planned_outputs)?;
    let authoritative = sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS(SELECT 1 FROM memory_reconciliation_jobs \
          WHERE account_id=$1 AND source_fingerprint=$2 AND topology_fingerprint=$3 \
            AND predecessor_episode_ids=$4 AND state='processing' AND claim_token=$5 \
            AND claim_until>clock_timestamp())",
    )
    .bind(&claim.account_id)
    .bind(&claim.source_fingerprint)
    .bind(&claim.topology_fingerprint)
    .bind(&claim.predecessor_episode_ids)
    .bind(&claim.claim_token)
    .fetch_one(&mut *connection)
    .await?;
    if !authoritative {
        return Err(EnclaveError::Conflict(
            "memory reconciliation claim is no longer authoritative".into(),
        ));
    }
    let partition = serde_json::to_string(&staged.normalized_partition)?;
    let planned_outputs = serde_json::to_string(&staged.planned_outputs)?;
    let existing_contract = sqlx::query(
        "SELECT reconciliation_id \
           FROM persistence_feature_reconciliation_stage_contracts \
          WHERE account_id=$1 AND source_fingerprint=$2 FOR UPDATE",
    )
    .bind(&claim.account_id)
    .bind(&claim.source_fingerprint)
    .fetch_optional(&mut *connection)
    .await?;
    if let Some(existing_contract) = existing_contract {
        let reconciliation_id: Option<String> = existing_contract.try_get("reconciliation_id")?;
        if reconciliation_id.is_some() {
            return Err(EnclaveError::Conflict(
                "a committed reconciliation stage cannot be replaced".into(),
            ));
        }
    }
    let stage_changed = sqlx::query(
        "INSERT INTO memory_reconciliation_stages( \
             account_id,source_fingerprint,topology_fingerprint,predecessor_episode_ids, \
             normalized_partition,result_commitment,planned_outputs,planned_outputs_commitment, \
             model,vertex_event_id,reconciliation_version,prompt_version, \
             partition_schema_version,validator_version) \
         VALUES($1,$2,$3,$4,$5::jsonb,$6,$7::jsonb,$8,$9,$10,$11,$12,$13,$14) \
         ON CONFLICT(account_id,source_fingerprint) DO UPDATE SET \
             topology_fingerprint=excluded.topology_fingerprint, \
             predecessor_episode_ids=excluded.predecessor_episode_ids, \
             normalized_partition=excluded.normalized_partition, \
             result_commitment=excluded.result_commitment, \
             planned_outputs=excluded.planned_outputs, \
             planned_outputs_commitment=excluded.planned_outputs_commitment, \
             model=excluded.model, \
             vertex_event_id=excluded.vertex_event_id, \
             reconciliation_version=excluded.reconciliation_version, \
             prompt_version=excluded.prompt_version, \
             partition_schema_version=excluded.partition_schema_version, \
             validator_version=excluded.validator_version,created_at=clock_timestamp() \
         WHERE ROW(memory_reconciliation_stages.topology_fingerprint, \
                   memory_reconciliation_stages.predecessor_episode_ids, \
                   memory_reconciliation_stages.normalized_partition, \
                   memory_reconciliation_stages.result_commitment, \
                   memory_reconciliation_stages.planned_outputs, \
                   memory_reconciliation_stages.planned_outputs_commitment, \
                   memory_reconciliation_stages.model, \
                   memory_reconciliation_stages.vertex_event_id, \
                   memory_reconciliation_stages.reconciliation_version, \
                   memory_reconciliation_stages.prompt_version, \
                   memory_reconciliation_stages.partition_schema_version, \
                   memory_reconciliation_stages.validator_version) \
               IS DISTINCT FROM \
               ROW(excluded.topology_fingerprint,excluded.predecessor_episode_ids, \
                   excluded.normalized_partition,excluded.result_commitment, \
                   excluded.planned_outputs,excluded.planned_outputs_commitment, \
                   excluded.model,excluded.vertex_event_id, \
                   excluded.reconciliation_version,excluded.prompt_version, \
                   excluded.partition_schema_version,excluded.validator_version)",
    )
    .bind(&claim.account_id)
    .bind(&claim.source_fingerprint)
    .bind(&claim.topology_fingerprint)
    .bind(&claim.predecessor_episode_ids)
    .bind(partition)
    .bind(&staged.result_commitment)
    .bind(planned_outputs)
    .bind(&planned_outputs_commitment)
    .bind(&staged.model)
    .bind(staged.vertex_event_id.as_deref())
    .bind(staged.reconciliation_version)
    .bind(staged.prompt_version)
    .bind(staged.partition_schema_version)
    .bind(staged.validator_version)
    .execute(&mut *connection)
    .await?
    .rows_affected();
    let _contract_changed = sqlx::query(
        "INSERT INTO persistence_feature_reconciliation_stage_contracts( \
             account_id,source_fingerprint,activation_generation,producer_contract_sha256, \
             reconciliation_model,vertex_location,provider_attempt_identity, \
             provider_invocation_fingerprint) \
         VALUES($1,$2,$3,$4,$5,$6,$7,$8) \
         ON CONFLICT(account_id,source_fingerprint) DO UPDATE SET \
             activation_generation=excluded.activation_generation, \
             producer_contract_sha256=excluded.producer_contract_sha256, \
             reconciliation_model=excluded.reconciliation_model, \
             vertex_location=excluded.vertex_location, \
             provider_attempt_identity=excluded.provider_attempt_identity, \
             provider_invocation_fingerprint=excluded.provider_invocation_fingerprint, \
             staged_at=clock_timestamp(), \
             reconciliation_id=NULL,committed_at=NULL \
         WHERE persistence_feature_reconciliation_stage_contracts.reconciliation_id IS NULL \
           AND ROW(persistence_feature_reconciliation_stage_contracts.activation_generation, \
                   persistence_feature_reconciliation_stage_contracts.producer_contract_sha256, \
                   persistence_feature_reconciliation_stage_contracts.reconciliation_model, \
                   persistence_feature_reconciliation_stage_contracts.vertex_location, \
                   persistence_feature_reconciliation_stage_contracts.provider_attempt_identity, \
                   persistence_feature_reconciliation_stage_contracts.provider_invocation_fingerprint) \
               IS DISTINCT FROM ROW(excluded.activation_generation, \
                   excluded.producer_contract_sha256,excluded.reconciliation_model, \
                   excluded.vertex_location,excluded.provider_attempt_identity, \
                   excluded.provider_invocation_fingerprint)",
    )
    .bind(&claim.account_id)
    .bind(&claim.source_fingerprint)
    .bind(claim.activation_generation)
    .bind(&claim.producer_contract_sha256)
    .bind(&claim.reconciliation_model)
    .bind(&claim.vertex_location)
    .bind(staged.provider_attempt_identity.as_deref())
    .bind(staged.provider_invocation_fingerprint.as_deref())
    .execute(&mut *connection)
    .await?
    .rows_affected();
    let stored = read_stage(
        &mut *connection,
        &claim.account_id,
        &claim.source_fingerprint,
    )
    .await?
    .ok_or_else(|| EnclaveError::Store("reconciliation stage was not persisted".into()))?;
    let expected = StagedReconciliation {
        account_id: claim.account_id.clone(),
        source_fingerprint: claim.source_fingerprint.clone(),
        topology_fingerprint: claim.topology_fingerprint.clone(),
        predecessor_episode_ids: claim.predecessor_episode_ids.clone(),
        normalized_partition: staged.normalized_partition,
        result_commitment: staged.result_commitment,
        planned_outputs: staged.planned_outputs,
        planned_outputs_commitment,
        model: staged.model,
        vertex_event_id: staged.vertex_event_id,
        provider_attempt_identity: staged.provider_attempt_identity,
        provider_invocation_fingerprint: staged.provider_invocation_fingerprint,
        reconciliation_version: staged.reconciliation_version,
        prompt_version: staged.prompt_version,
        partition_schema_version: staged.partition_schema_version,
        validator_version: staged.validator_version,
        activation_generation: claim.activation_generation,
        producer_contract_sha256: claim.producer_contract_sha256.clone(),
        reconciliation_model: claim.reconciliation_model.clone(),
        vertex_location: claim.vertex_location.clone(),
    };
    if stored.account_id != expected.account_id
        || stored.source_fingerprint != expected.source_fingerprint
        || stored.topology_fingerprint != expected.topology_fingerprint
        || stored.predecessor_episode_ids != expected.predecessor_episode_ids
        || stored.normalized_partition != expected.normalized_partition
        || stored.result_commitment != expected.result_commitment
        || stored.planned_outputs != expected.planned_outputs
        || stored.planned_outputs_commitment != expected.planned_outputs_commitment
        || stored.model != expected.model
        || stored.vertex_event_id != expected.vertex_event_id
        || stored.provider_attempt_identity != expected.provider_attempt_identity
        || stored.provider_invocation_fingerprint != expected.provider_invocation_fingerprint
        || stored.reconciliation_version != expected.reconciliation_version
        || stored.prompt_version != expected.prompt_version
        || stored.partition_schema_version != expected.partition_schema_version
        || stored.validator_version != expected.validator_version
        || stored.activation_generation != expected.activation_generation
        || stored.producer_contract_sha256 != expected.producer_contract_sha256
        || stored.reconciliation_model != expected.reconciliation_model
        || stored.vertex_location != expected.vertex_location
    {
        return Err(EnclaveError::Conflict(
            "a different reconciliation result is already staged".into(),
        ));
    }
    // A paid model attempt is charged only when a provider-backed stage/event
    // actually changes. An identical replay and a generation-only companion
    // provenance refresh are both idempotent and must not consume the bounded
    // model-attempt budget.
    if stage_changed == 1 && expected.vertex_event_id.is_some() {
        sqlx::query(
            "UPDATE memory_reconciliation_jobs SET model_attempt_count=model_attempt_count+1, \
                    updated_at=clock_timestamp() \
              WHERE account_id=$1 AND source_fingerprint=$2 AND claim_token=$3",
        )
        .bind(&claim.account_id)
        .bind(&claim.source_fingerprint)
        .bind(&claim.claim_token)
        .execute(&mut *connection)
        .await?;
    }
    Ok(stored)
}

fn validate_resolution_graph(
    requested_episode_id: i64,
    states: &BTreeMap<i64, String>,
    edges: &BTreeMap<i64, BTreeSet<i64>>,
    max_leaves: i64,
) -> Result<Vec<i64>> {
    if !states.contains_key(&requested_episode_id) {
        return Err(EnclaveError::NotFound);
    }
    let mut indegree = states
        .keys()
        .map(|episode_id| (*episode_id, 0usize))
        .collect::<BTreeMap<_, _>>();
    for (predecessor, successors) in edges {
        if !states.contains_key(predecessor) {
            return Err(EnclaveError::Store(
                "memory lineage predecessor handle is missing".into(),
            ));
        }
        for successor in successors {
            let Some(value) = indegree.get_mut(successor) else {
                return Err(EnclaveError::Store(
                    "memory lineage successor handle is missing".into(),
                ));
            };
            *value += 1;
        }
    }
    let mut ready = indegree
        .iter()
        .filter_map(|(episode_id, degree)| (*degree == 0).then_some(*episode_id))
        .collect::<Vec<_>>();
    let mut processed = 0usize;
    while let Some(episode_id) = ready.pop() {
        processed += 1;
        if let Some(successors) = edges.get(&episode_id) {
            for successor in successors {
                let degree = indegree
                    .get_mut(successor)
                    .expect("successor existence validated above");
                *degree -= 1;
                if *degree == 0 {
                    ready.push(*successor);
                }
            }
        }
    }
    if processed != states.len() {
        return Err(EnclaveError::Store(
            "memory lineage contains a cycle".into(),
        ));
    }
    let mut active = Vec::new();
    for (episode_id, state) in states {
        let has_successors = edges.get(episode_id).is_some_and(|rows| !rows.is_empty());
        match state.as_str() {
            "active" if !has_successors => active.push(*episode_id),
            "active" => {
                return Err(EnclaveError::Store(
                    "active memory handle has lineage successors".into(),
                ))
            }
            "superseded" if has_successors => {}
            "superseded" => {
                return Err(EnclaveError::Store(
                    "superseded memory handle has no lineage successors".into(),
                ))
            }
            "retired" if !has_successors => {}
            "retired" => {
                return Err(EnclaveError::Store(
                    "retired memory handle has lineage successors".into(),
                ))
            }
            _ => return Err(EnclaveError::Store("invalid memory handle state".into())),
        }
    }
    if i64::try_from(active.len()).unwrap_or(i64::MAX) > max_leaves {
        return Err(EnclaveError::Store(
            "memory handle resolution exceeds its leaf bound".into(),
        ));
    }
    Ok(active)
}

#[async_trait]
impl MemoryReconciliationRepository for PostgresPersistence {
    async fn promote_oversized_source_settled_prefix(
        &self,
        account_id: &str,
        quiet_horizon_seconds: i64,
        resume_after_component_ended_at: Option<&str>,
        policy: OversizedKeepPromotionPolicy,
    ) -> Result<OversizedKeepPromotionResult> {
        let OversizedKeepPromotionPolicy {
            draft_limit,
            atom_limit,
            reconciliation_version,
            prompt_version,
            partition_schema_version,
            validator_version,
        } = policy;
        if quiet_horizon_seconds != QUIET_HORIZON_SECONDS
            || !(1..=MAX_DRAFTS).contains(&draft_limit)
            || !(1..=MAX_ATOMS).contains(&atom_limit)
            || [
                reconciliation_version,
                prompt_version,
                partition_schema_version,
                validator_version,
            ]
            .into_iter()
            .any(|version| version <= 0)
        {
            return Err(EnclaveError::InvalidRequest(
                "providerless KEEP bounds or producer versions are invalid".into(),
            ));
        }
        let resume_after_component_ended_ms = resume_after_component_ended_at
            .map(|value| timestamp(value, "held reconciliation component end"))
            .transpose()?;
        let mut transaction = self.pool().begin().await?;
        sqlx::query("SET TRANSACTION ISOLATION LEVEL SERIALIZABLE")
            .execute(&mut *transaction)
            .await?;
        let Some(authority) = active_reconciliation_authority(&mut transaction, account_id).await?
        else {
            return Ok(held_keep_promotion(None, false));
        };
        advisory_transaction_lock(&mut transaction, "memory-reconciliation", account_id).await?;
        let headers = candidate_headers(
            &mut transaction,
            account_id,
            resume_after_component_ended_ms,
        )
        .await?;
        let (episode_ids, oversized_drafts, _component_ended_ms, boundary_complete) =
            oldest_connected_prefix_with_boundary(&headers, draft_limit);
        if episode_ids.is_empty() {
            return Ok(OversizedKeepPromotionResult::NotOversized);
        }
        let overlapping_paid_work = sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS(SELECT 1 FROM memory_reconciliation_jobs job \
              WHERE job.account_id=$1 AND job.predecessor_episode_ids && $2 \
                AND ((job.state='processing' AND job.claim_until>clock_timestamp()) \
                     OR EXISTS(SELECT 1 FROM memory_reconciliation_stages stage \
                          WHERE stage.account_id=job.account_id \
                            AND stage.source_fingerprint=job.source_fingerprint)))",
        )
        .bind(account_id)
        .bind(&episode_ids)
        .fetch_one(&mut *transaction)
        .await?;
        if overlapping_paid_work {
            return Ok(held_keep_promotion(None, false));
        }
        let Some(drafts) = read_keep_drafts(&mut transaction, account_id, &episode_ids).await?
        else {
            return Ok(held_keep_promotion(None, false));
        };
        if !selected_members_are_exact(&mut transaction, account_id, &episode_ids).await? {
            return Ok(held_keep_promotion(None, false));
        }
        let mut closure_started_ms = drafts
            .iter()
            .map(|draft| draft.started_ms)
            .min()
            .ok_or_else(|| EnclaveError::Store("providerless KEEP cohort is empty".into()))?;
        let mut closure_ended_ms = drafts
            .iter()
            .map(|draft| draft.ended_ms)
            .max()
            .ok_or_else(|| EnclaveError::Store("providerless KEEP cohort is empty".into()))?;
        let member_count: i64 = sqlx::query_scalar(
            "SELECT count(*)::bigint FROM active_episode_members \
              WHERE account_id=$1 AND episode_id=ANY($2)",
        )
        .bind(account_id)
        .bind(&episode_ids)
        .fetch_one(&mut *transaction)
        .await?;
        if member_count > MAX_OVERSIZED_KEEP_SOURCES {
            return Ok(held_keep_promotion(
                Some(closure_ended_ms),
                boundary_complete,
            ));
        }
        let (committed_member_count, member_commitment) =
            selected_members_commitment(&mut transaction, account_id, &episode_ids).await?;
        if committed_member_count != member_count {
            return Ok(held_keep_promotion(
                Some(closure_ended_ms),
                boundary_complete,
            ));
        }
        let prior_archive_revision = archive_revision(&mut transaction, account_id).await?;
        let component_seed_sha256 = digest_json(
            b"kioku.memory-reconciliation.neighborhood-seed.v1\0",
            &json!({
                "account_id": account_id,
                "episode_ids": episode_ids,
                "exact_episode_rows": drafts.iter().map(|draft| &draft.exact_row).collect::<Vec<_>>(),
                "member_count": member_count,
                "member_commitment": member_commitment,
                "archive_revision": prior_archive_revision,
                "activation_generation": authority.generation,
                "producer_contract_sha256": authority.producer_contract_sha256,
                "reconciliation_model": authority.reconciliation_model,
                "vertex_location": authority.vertex_location,
                "policy_commitment": oversized_keep_policy_commitment(),
            }),
        )?;
        let mut evidence = KeepEvidenceClosure::default();
        let mut converged = false;
        for _ in 0..=8 {
            let before = (closure_started_ms, closure_ended_ms, evidence);
            evidence = keep_evidence_closure(
                &mut transaction,
                account_id,
                &episode_ids,
                closure_started_ms,
                closure_ended_ms,
            )
            .await?;
            if let Some(started_ms) = evidence.started_ms {
                closure_started_ms = closure_started_ms.min(started_ms);
            }
            if let Some(ended_ms) = evidence.ended_ms {
                closure_ended_ms = closure_ended_ms.max(ended_ms);
            }
            let after = (closure_started_ms, closure_ended_ms, evidence);
            if before == after {
                converged = true;
                break;
            }
        }
        if !converged {
            return Ok(held_keep_promotion(None, false));
        }
        let scan = match advance_neighborhood_scan(
            &mut transaction,
            account_id,
            &component_seed_sha256,
            &episode_ids,
            closure_started_ms,
            closure_ended_ms,
        )
        .await?
        {
            NeighborhoodScanAdvance::Pending => {
                transaction.commit().await?;
                return Ok(held_keep_promotion(None, false));
            }
            NeighborhoodScanAdvance::Ready(scan) => scan,
        };
        closure_started_ms = closure_started_ms.min(scan.closure_started_ms);
        closure_ended_ms = closure_ended_ms.max(scan.closure_ended_ms);
        let expanded_evidence = keep_evidence_closure(
            &mut transaction,
            account_id,
            &episode_ids,
            closure_started_ms,
            closure_ended_ms,
        )
        .await?;
        let expanded_started_ms = expanded_evidence
            .started_ms
            .map_or(closure_started_ms, |value| closure_started_ms.min(value));
        let expanded_ended_ms = expanded_evidence
            .ended_ms
            .map_or(closure_ended_ms, |value| closure_ended_ms.max(value));
        if expanded_started_ms != scan.closure_started_ms
            || expanded_ended_ms != scan.closure_ended_ms
        {
            restart_neighborhood_discovery(
                &mut transaction,
                account_id,
                expanded_started_ms,
                expanded_ended_ms,
            )
            .await?;
            transaction.commit().await?;
            return Ok(held_keep_promotion(None, false));
        }
        evidence = expanded_evidence;
        let oversized_evidence = evidence.count > atom_limit;
        let oversized_sessions = scan.session_count > MAX_SOURCE_SESSIONS as i64;
        if !oversized_drafts && !oversized_evidence && !oversized_sessions {
            return Ok(OversizedKeepPromotionResult::NotOversized);
        }
        let unowned_evidence_accounted = unowned_evidence_is_explicit_no_memory(
            &mut transaction,
            account_id,
            &episode_ids,
            closure_started_ms,
            closure_ended_ms,
            &component_seed_sha256,
        )
        .await?;
        if !unowned_evidence_accounted
            || (evidence.count > 0 && scan.session_count == 0)
            || !scan.all_settled
            || !database_quiet_horizon(&mut transaction, closure_ended_ms).await?
        {
            return Ok(held_keep_promotion(
                Some(closure_ended_ms),
                boundary_complete,
            ));
        }
        if evidence.selected_owned_count != member_count {
            return Ok(held_keep_promotion(
                Some(closure_ended_ms),
                boundary_complete,
            ));
        }
        let source_guard = json!({
            "component_seed_sha256": component_seed_sha256,
            "session_count": scan.session_count,
            "session_commitment": scan.session_commitment,
            "verification_generation": scan.verification_generation,
            "bounded_page_size": NEIGHBORHOOD_PAGE_SIZE,
            "bounded_pages_per_invocation": NEIGHBORHOOD_MAX_PAGES_PER_INVOCATION,
        });
        let source_fingerprint = digest_json(
            b"kioku.memory-reconciliation.oversized-keep-source.v1\0",
            &json!({
                "account_id": account_id,
                "episode_ids": episode_ids,
                "exact_episode_rows": drafts.iter().map(|draft| &draft.exact_row).collect::<Vec<_>>(),
                "member_count": member_count,
                "member_commitment": member_commitment,
                "evidence_count": evidence.count,
                "explicit_no_memory_count": evidence.unowned_count,
                "closure_started_ms": closure_started_ms,
                "closure_ended_ms": closure_ended_ms,
                "source_guard": source_guard,
                "activation_generation": authority.generation,
                "producer_contract_sha256": authority.producer_contract_sha256,
                "reconciliation_model": authority.reconciliation_model,
                "vertex_location": authority.vertex_location,
                "reconciliation_version": reconciliation_version,
                "prompt_version": prompt_version,
                "partition_schema_version": partition_schema_version,
                "validator_version": validator_version,
                "policy": OVERSIZED_KEEP_MODEL,
                "policy_commitment": oversized_keep_policy_commitment(),
            }),
        )?;
        let topology_fingerprint = digest_json(
            b"kioku.memory-reconciliation.oversized-keep-topology.v1\0",
            &json!({
                "archive_revision": prior_archive_revision,
                "source_fingerprint": source_fingerprint,
                "episode_ids": episode_ids,
                "mutation": "structure_state:draft->reconciled",
            }),
        )?;
        let result_commitment = digest_json(
            b"kioku.memory-reconciliation.oversized-keep-result.v1\0",
            &json!({
                "source_fingerprint": source_fingerprint,
                "topology_fingerprint": topology_fingerprint,
                "episode_ids": episode_ids,
                "preserve_episode_rows_except_structure_state": true,
                "preserve_members": true,
                "provider_egress": false,
                "policy": OVERSIZED_KEEP_MODEL,
                "policy_commitment": oversized_keep_policy_commitment(),
                "reconciliation_version": reconciliation_version,
                "prompt_version": prompt_version,
                "partition_schema_version": partition_schema_version,
                "validator_version": validator_version,
            }),
        )?;
        let reconciliation_id = format!("keep-{}", lowercase_hex(&result_commitment));
        let archive_revision: i64 = sqlx::query_scalar(
            "UPDATE memory_archive_state SET revision=revision+1,updated_at=clock_timestamp() \
              WHERE account_id=$1 RETURNING revision",
        )
        .bind(account_id)
        .fetch_one(&mut *transaction)
        .await?;
        sqlx::query(
            "INSERT INTO memory_reconciliations( \
                 account_id,id,reconciliation_version,model,prompt_version,vertex_event_id, \
                 cohort_started_at,cohort_ended_at,source_fingerprint,topology_fingerprint, \
                 result_commitment,archive_revision) \
             VALUES($1,$2,$3,$4,$5,NULL,to_timestamp($6::double precision/1000.0), \
                    to_timestamp($7::double precision/1000.0),$8,$9,$10,$11)",
        )
        .bind(account_id)
        .bind(&reconciliation_id)
        .bind(reconciliation_version)
        .bind(OVERSIZED_KEEP_MODEL)
        .bind(prompt_version)
        .bind(closure_started_ms)
        .bind(closure_ended_ms)
        .bind(&source_fingerprint)
        .bind(&topology_fingerprint)
        .bind(&result_commitment)
        .bind(archive_revision)
        .execute(&mut *transaction)
        .await?;
        sqlx::query(
            "DELETE FROM persistence_feature_reconciliation_stage_contracts contract \
              WHERE contract.account_id=$1 AND contract.reconciliation_id IS NULL \
                AND EXISTS(SELECT 1 FROM memory_reconciliation_stages stage \
                    WHERE stage.account_id=contract.account_id \
                      AND stage.source_fingerprint=contract.source_fingerprint \
                      AND stage.predecessor_episode_ids && $2)",
        )
        .bind(account_id)
        .bind(&episode_ids)
        .execute(&mut *transaction)
        .await?;
        sqlx::query(
            "DELETE FROM memory_reconciliation_stages \
              WHERE account_id=$1 AND predecessor_episode_ids && $2",
        )
        .bind(account_id)
        .bind(&episode_ids)
        .execute(&mut *transaction)
        .await?;
        sqlx::query(
            "DELETE FROM memory_reconciliation_jobs \
              WHERE account_id=$1 AND predecessor_episode_ids && $2 AND state<>'complete'",
        )
        .bind(account_id)
        .bind(&episode_ids)
        .execute(&mut *transaction)
        .await?;
        sqlx::query(
            "INSERT INTO memory_reconciliation_jobs( \
                 account_id,source_fingerprint,topology_fingerprint,predecessor_episode_ids, \
                 cohort_started_at,cohort_ended_at,state,attempt_count,model_attempt_count, \
                 reconciliation_id,updated_at) \
             VALUES($1,$2,$3,$4,to_timestamp($5::double precision/1000.0), \
                    to_timestamp($6::double precision/1000.0),'complete',0,0,$7,clock_timestamp())",
        )
        .bind(account_id)
        .bind(&source_fingerprint)
        .bind(&topology_fingerprint)
        .bind(&episode_ids)
        .bind(closure_started_ms)
        .bind(closure_ended_ms)
        .bind(&reconciliation_id)
        .execute(&mut *transaction)
        .await?;
        let audited_sources = sqlx::query(
            "INSERT INTO memory_reconciliation_sources( \
                 account_id,reconciliation_id,record_type,record_id,successor_episode_id) \
             SELECT account_id,$3,record_type,record_id,episode_id \
               FROM active_episode_members \
              WHERE account_id=$1 AND episode_id=ANY($2) \
              ORDER BY record_type,record_id",
        )
        .bind(account_id)
        .bind(&episode_ids)
        .bind(&reconciliation_id)
        .execute(&mut *transaction)
        .await?
        .rows_affected();
        if audited_sources != u64::try_from(member_count).unwrap_or(u64::MAX) {
            return Err(EnclaveError::Conflict(
                "providerless KEEP source audit changed before publication".into(),
            ));
        }
        sqlx::query(
            "INSERT INTO persistence_feature_reconciliation_stage_contracts( \
                 account_id,source_fingerprint,activation_generation,producer_contract_sha256, \
                 reconciliation_model,vertex_location,reconciliation_id,committed_at) \
             VALUES($1,$2,$3,$4,$5,$6,$7,clock_timestamp())",
        )
        .bind(account_id)
        .bind(&source_fingerprint)
        .bind(authority.generation)
        .bind(&authority.producer_contract_sha256)
        .bind(&authority.reconciliation_model)
        .bind(&authority.vertex_location)
        .bind(&reconciliation_id)
        .execute(&mut *transaction)
        .await?;
        let changed = sqlx::query(
            "UPDATE episodes SET structure_state='reconciled' \
              WHERE account_id=$1 AND id=ANY($2) AND structure_state='draft' \
                AND finalized_at IS NULL AND finalization_claim_token IS NULL",
        )
        .bind(account_id)
        .bind(&episode_ids)
        .execute(&mut *transaction)
        .await?
        .rows_affected();
        if changed != u64::try_from(episode_ids.len()).unwrap_or(u64::MAX) {
            return Err(EnclaveError::Conflict(
                "providerless KEEP episode set changed before publication".into(),
            ));
        }
        // `ready` is a transaction-local authorization state, never durable
        // across a Held result. Successful KEEP consumes and garbage-collects
        // the bounded proof atomically with publication.
        sqlx::query(
            "DELETE FROM persistence_feature_reconciliation_neighborhood_scans \
              WHERE account_id=$1 AND component_seed_sha256=$2 AND phase='ready'",
        )
        .bind(account_id)
        .bind(&component_seed_sha256)
        .execute(&mut *transaction)
        .await?;
        transaction.commit().await?;
        Ok(OversizedKeepPromotionResult::Promoted {
            episode_ids,
            reconciliation_id,
            archive_revision,
        })
    }

    async fn next_source_settled_cohort(
        &self,
        account_id: &str,
        quiet_horizon_seconds: i64,
        resume_after_component_ended_at: Option<&str>,
        draft_limit: i64,
        atom_limit: i64,
    ) -> Result<Option<ReconciliationSnapshot>> {
        if quiet_horizon_seconds != QUIET_HORIZON_SECONDS
            || !(1..=MAX_DRAFTS).contains(&draft_limit)
            || !(1..=MAX_ATOMS).contains(&atom_limit)
        {
            return Err(EnclaveError::InvalidRequest(
                "memory reconciliation bounds are invalid".into(),
            ));
        }
        let resume_after_component_ended_ms = resume_after_component_ended_at
            .map(|value| timestamp(value, "held reconciliation component end"))
            .transpose()?;
        let mut transaction = self.pool().begin().await?;
        let Some(authority) = active_reconciliation_authority(&mut transaction, account_id).await?
        else {
            return Ok(None);
        };
        let ids = oldest_connected_drafts(
            &candidate_headers(
                &mut transaction,
                account_id,
                resume_after_component_ended_ms,
            )
            .await?,
            draft_limit,
        )?;
        if ids.is_empty() {
            return Ok(None);
        }
        let Some((snapshot, settled)) =
            read_snapshot(&mut transaction, account_id, &ids, atom_limit, &authority).await?
        else {
            return Ok(None);
        };
        if !settled {
            return Ok(None);
        }
        transaction.commit().await?;
        Ok(Some(snapshot))
    }

    async fn revalidate_source_fingerprint(
        &self,
        account_id: &str,
        predecessor_episode_ids: &[i64],
        expected_source_fingerprint: &[u8],
    ) -> Result<bool> {
        if !valid_digest(expected_source_fingerprint) {
            return Err(EnclaveError::InvalidRequest(
                "memory reconciliation source fingerprint is invalid".into(),
            ));
        }
        let mut transaction = self.pool().begin().await?;
        let Some(authority) = active_reconciliation_authority(&mut transaction, account_id).await?
        else {
            return Ok(false);
        };
        let Some((snapshot, settled)) = read_snapshot(
            &mut transaction,
            account_id,
            predecessor_episode_ids,
            MAX_ATOMS,
            &authority,
        )
        .await?
        else {
            return Ok(false);
        };
        Ok(settled && snapshot.source_fingerprint == expected_source_fingerprint)
    }

    async fn acquire_provider_egress_guard(
        &self,
        claim: &ReconciliationClaim,
    ) -> Result<Option<Box<dyn ReconciliationEgressGuard>>> {
        if !valid_digest(&claim.source_fingerprint)
            || !valid_digest(&claim.topology_fingerprint)
            || !valid_digest(&claim.producer_contract_sha256)
            || claim.predecessor_episode_ids.is_empty()
            || claim.claim_token.trim().is_empty()
        {
            return Err(EnclaveError::InvalidRequest(
                "memory reconciliation provider-egress claim is invalid".into(),
            ));
        }
        let mut transaction = self.pool().begin().await?;
        let Some(authority) =
            active_reconciliation_authority(&mut transaction, &claim.account_id).await?
        else {
            return Ok(None);
        };
        if !claim_matches_authority(claim, &authority) {
            return Ok(None);
        }
        // Global order for every reconciliation/source mutation is activation
        // contract KEY SHARE, then the account advisory lock, then row locks.
        // The same transaction later persists the provider stage, avoiding a
        // second waiter behind a source mutation that already owns this lock.
        advisory_transaction_lock(&mut transaction, "memory-reconciliation", &claim.account_id)
            .await?;
        let authoritative = sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS(SELECT 1 FROM memory_reconciliation_jobs \
              WHERE account_id=$1 AND source_fingerprint=$2 AND topology_fingerprint=$3 \
                AND predecessor_episode_ids=$4 AND state='processing' AND claim_token=$5 \
                AND claim_until>clock_timestamp())",
        )
        .bind(&claim.account_id)
        .bind(&claim.source_fingerprint)
        .bind(&claim.topology_fingerprint)
        .bind(&claim.predecessor_episode_ids)
        .bind(&claim.claim_token)
        .fetch_one(&mut *transaction)
        .await?;
        if !authoritative {
            return Ok(None);
        }
        let Some((snapshot, settled)) = read_snapshot(
            &mut transaction,
            &claim.account_id,
            &claim.predecessor_episode_ids,
            MAX_ATOMS,
            &authority,
        )
        .await?
        else {
            return Ok(None);
        };
        if !settled
            || snapshot.source_fingerprint != claim.source_fingerprint
            || snapshot.topology_fingerprint != claim.topology_fingerprint
        {
            return Ok(None);
        }
        Ok(Some(Box::new(PostgresReconciliationEgressGuard {
            transaction: Some(transaction),
            claim: claim.clone(),
        })))
    }

    async fn claim_reconciliation(
        &self,
        snapshot: &ReconciliationSnapshot,
        lease_seconds: i64,
    ) -> Result<Option<ReconciliationClaim>> {
        if !valid_digest(&snapshot.source_fingerprint)
            || !valid_digest(&snapshot.topology_fingerprint)
            || !(1..=3_600).contains(&lease_seconds)
        {
            return Err(EnclaveError::InvalidRequest(
                "memory reconciliation claim is invalid".into(),
            ));
        }
        let claim_token = tokens::new_uuid();
        let mut transaction = self.pool().begin().await?;
        sqlx::query("SET TRANSACTION ISOLATION LEVEL SERIALIZABLE")
            .execute(&mut *transaction)
            .await?;
        let Some(authority) =
            active_reconciliation_authority(&mut transaction, &snapshot.account_id).await?
        else {
            return Ok(None);
        };
        advisory_transaction_lock(
            &mut transaction,
            "memory-reconciliation",
            &snapshot.account_id,
        )
        .await?;
        let Some((current, settled)) = read_snapshot(
            &mut transaction,
            &snapshot.account_id,
            &snapshot.predecessor_episode_ids,
            MAX_ATOMS,
            &authority,
        )
        .await?
        else {
            return Ok(None);
        };
        if !settled
            || current.source_fingerprint != snapshot.source_fingerprint
            || current.topology_fingerprint != snapshot.topology_fingerprint
        {
            return Ok(None);
        }
        let row = sqlx::query(
            "INSERT INTO memory_reconciliation_jobs( \
                 account_id,source_fingerprint,topology_fingerprint,predecessor_episode_ids, \
                 cohort_started_at,cohort_ended_at,state,attempt_count,claim_token,claim_until,updated_at) \
             VALUES($1,$2,$3,$4,to_timestamp($5::double precision/1000.0), \
                    to_timestamp($6::double precision/1000.0),'processing',1,$7, \
                    clock_timestamp()+make_interval(secs=>$8),clock_timestamp()) \
             ON CONFLICT(account_id,source_fingerprint) DO UPDATE SET \
                 topology_fingerprint=excluded.topology_fingerprint, \
                 predecessor_episode_ids=excluded.predecessor_episode_ids,state='processing', \
                 attempt_count=memory_reconciliation_jobs.attempt_count+1,claim_token=excluded.claim_token, \
                 claim_until=excluded.claim_until,next_attempt_at=NULL,last_error_code=NULL, \
                 updated_at=excluded.updated_at \
             WHERE (memory_reconciliation_jobs.state='retry_wait' \
                       AND memory_reconciliation_jobs.next_attempt_at<=clock_timestamp()) \
                OR (memory_reconciliation_jobs.state='processing' \
                       AND memory_reconciliation_jobs.claim_until<=clock_timestamp()) \
                OR memory_reconciliation_jobs.state='pending' \
             RETURNING floor(extract(epoch FROM claim_until)*1000)::bigint AS claim_until_ms, \
                       attempt_count,model_attempt_count",
        )
        .bind(&snapshot.account_id)
        .bind(&snapshot.source_fingerprint)
        .bind(&snapshot.topology_fingerprint)
        .bind(&snapshot.predecessor_episode_ids)
        .bind(timestamp(&snapshot.cohort_started_at, "reconciliation cohort start")?)
        .bind(timestamp(&snapshot.cohort_ended_at, "reconciliation cohort end")?)
        .bind(&claim_token)
        .bind(duration_seconds(std::time::Duration::from_secs(
            u64::try_from(lease_seconds)
                .map_err(|_| EnclaveError::InvalidRequest("invalid reconciliation lease".into()))?,
        ))?)
        .fetch_optional(&mut *transaction)
        .await?;
        let Some(row) = row else { return Ok(None) };
        let lease_ms: i64 = row.try_get("claim_until_ms")?;
        let claim = ReconciliationClaim {
            account_id: snapshot.account_id.clone(),
            source_fingerprint: snapshot.source_fingerprint.clone(),
            topology_fingerprint: snapshot.topology_fingerprint.clone(),
            predecessor_episode_ids: snapshot.predecessor_episode_ids.clone(),
            claim_token,
            lease_until: isotime::format_epoch_millis(lease_ms),
            attempt_count: row.try_get("attempt_count")?,
            model_attempt_count: row.try_get("model_attempt_count")?,
            activation_generation: authority.generation,
            producer_contract_sha256: authority.producer_contract_sha256,
            reconciliation_model: authority.reconciliation_model,
            vertex_location: authority.vertex_location,
        };
        transaction.commit().await?;
        Ok(Some(claim))
    }

    async fn staged_result(
        &self,
        claim: &ReconciliationClaim,
    ) -> Result<Option<StagedReconciliation>> {
        if !valid_digest(&claim.source_fingerprint)
            || !valid_digest(&claim.producer_contract_sha256)
        {
            return Err(EnclaveError::InvalidRequest(
                "memory reconciliation source fingerprint is invalid".into(),
            ));
        }
        let mut transaction = self.pool().begin().await?;
        let Some(authority) =
            active_reconciliation_authority(&mut transaction, &claim.account_id).await?
        else {
            return Ok(None);
        };
        if !claim_matches_authority(claim, &authority) {
            return Ok(None);
        }
        let staged = read_stage(
            &mut transaction,
            &claim.account_id,
            &claim.source_fingerprint,
        )
        .await?;
        let current = staged.filter(|stage| {
            stage.activation_generation == claim.activation_generation
                && stage.producer_contract_sha256 == claim.producer_contract_sha256
                && stage.reconciliation_model == claim.reconciliation_model
                && stage.vertex_location == claim.vertex_location
        });
        transaction.commit().await?;
        Ok(current)
    }

    async fn stage_reconciliation(
        &self,
        claim: &ReconciliationClaim,
        staged: ReconciliationStageWrite,
    ) -> Result<StagedReconciliation> {
        let mut transaction = self.pool().begin().await?;
        let Some(authority) =
            active_reconciliation_authority(&mut transaction, &claim.account_id).await?
        else {
            return Err(EnclaveError::Conflict(
                "memory reconciliation activation is no longer active".into(),
            ));
        };
        advisory_transaction_lock(&mut transaction, "memory-reconciliation", &claim.account_id)
            .await?;
        if !claim_matches_authority(claim, &authority) {
            return Err(EnclaveError::Conflict(
                "memory reconciliation producer authority changed".into(),
            ));
        }
        let stored = stage_reconciliation_locked(&mut transaction, claim, staged).await?;
        transaction.commit().await?;
        Ok(stored)
    }

    async fn release_reconciliation(
        &self,
        claim: &ReconciliationClaim,
        retry_delay_seconds: Option<i64>,
        error_code: &str,
        terminal: bool,
        consume_model_attempt: bool,
    ) -> Result<()> {
        if error_code.is_empty()
            || (!terminal && retry_delay_seconds.is_none())
            || (terminal && retry_delay_seconds.is_some())
            || retry_delay_seconds.is_some_and(|seconds| !(0..=7 * 24 * 60 * 60).contains(&seconds))
        {
            return Err(EnclaveError::InvalidRequest(
                "memory reconciliation release is invalid".into(),
            ));
        }
        let changed = sqlx::query(
            "UPDATE memory_reconciliation_jobs SET state=$4,claim_token=NULL,claim_until=NULL, \
                    next_attempt_at=CASE WHEN $5::bigint IS NULL THEN NULL \
                         ELSE clock_timestamp()+make_interval(secs=>$5) END, \
                    last_error_code=$6,updated_at=clock_timestamp(), \
                    model_attempt_count=model_attempt_count+CASE WHEN $7 THEN 1 ELSE 0 END \
              WHERE account_id=$1 AND source_fingerprint=$2 AND claim_token=$3 AND state='processing'",
        )
        .bind(&claim.account_id)
        .bind(&claim.source_fingerprint)
        .bind(&claim.claim_token)
        .bind(if terminal { "failed_terminal" } else { "retry_wait" })
        .bind(retry_delay_seconds)
        .bind(error_code)
        .bind(consume_model_attempt)
        .execute(self.pool())
        .await?
        .rows_affected();
        if changed != 1 {
            return Err(EnclaveError::Conflict(
                "memory reconciliation claim is no longer authoritative".into(),
            ));
        }
        Ok(())
    }

    async fn publish_reconciliation(
        &self,
        command: ReconciliationPublish,
    ) -> Result<ReconciliationPublishResult> {
        if !valid_digest(&command.result_commitment) {
            return Err(EnclaveError::InvalidRequest(
                "memory reconciliation publication is invalid".into(),
            ));
        }
        let mut transaction = self.pool().begin().await?;
        sqlx::query("SET TRANSACTION ISOLATION LEVEL SERIALIZABLE")
            .execute(&mut *transaction)
            .await?;
        let Some(authority) =
            active_reconciliation_authority(&mut transaction, &command.claim.account_id).await?
        else {
            return Err(EnclaveError::Conflict(
                "memory reconciliation activation is no longer active".into(),
            ));
        };
        advisory_transaction_lock(
            &mut transaction,
            "memory-reconciliation",
            &command.claim.account_id,
        )
        .await?;
        if !claim_matches_authority(&command.claim, &authority) {
            return Err(EnclaveError::Conflict(
                "memory reconciliation producer authority changed".into(),
            ));
        }

        if let Some(row) = sqlx::query(
            "SELECT archive_revision FROM memory_reconciliations WHERE account_id=$1 AND id=$2",
        )
        .bind(&command.claim.account_id)
        .bind(&command.reconciliation_id)
        .fetch_optional(&mut *transaction)
        .await?
        {
            let ids = sqlx::query_scalar::<_, i64>(
                "SELECT DISTINCT successor_episode_id FROM memory_reconciliation_sources \
                  WHERE account_id=$1 AND reconciliation_id=$2 ORDER BY successor_episode_id",
            )
            .bind(&command.claim.account_id)
            .bind(&command.reconciliation_id)
            .fetch_all(&mut *transaction)
            .await?;
            transaction.commit().await?;
            return Ok(ReconciliationPublishResult::Replayed {
                successor_episode_ids: ids,
                archive_revision: row.try_get("archive_revision")?,
            });
        }
        let job_ok = sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS(SELECT 1 FROM memory_reconciliation_jobs \
              WHERE account_id=$1 AND source_fingerprint=$2 AND topology_fingerprint=$3 \
                AND predecessor_episode_ids=$4 AND state='processing' AND claim_token=$5 \
                AND claim_until>clock_timestamp())",
        )
        .bind(&command.claim.account_id)
        .bind(&command.claim.source_fingerprint)
        .bind(&command.claim.topology_fingerprint)
        .bind(&command.claim.predecessor_episode_ids)
        .bind(&command.claim.claim_token)
        .fetch_one(&mut *transaction)
        .await?;
        if !job_ok {
            return Err(EnclaveError::Conflict(
                "memory reconciliation claim is no longer authoritative".into(),
            ));
        }
        let stage = read_stage(
            &mut transaction,
            &command.claim.account_id,
            &command.claim.source_fingerprint,
        )
        .await?
        .ok_or_else(|| {
            EnclaveError::Conflict("memory reconciliation result is not staged".into())
        })?;
        if stage.result_commitment != command.result_commitment
            || stage.predecessor_episode_ids != command.claim.predecessor_episode_ids
            || stage.activation_generation != command.claim.activation_generation
            || stage.producer_contract_sha256 != command.claim.producer_contract_sha256
            || stage.reconciliation_model != command.claim.reconciliation_model
            || stage.vertex_location != command.claim.vertex_location
        {
            return Err(EnclaveError::Conflict(
                "memory reconciliation stage does not match the claim".into(),
            ));
        }
        let outputs = &stage.planned_outputs;
        if outputs.is_empty() || outputs.len() > MAX_DRAFTS as usize {
            return Err(EnclaveError::Store(
                "staged reconciliation publication is invalid".into(),
            ));
        }
        for output in outputs {
            validate_output(output)?;
        }
        let Some((current, settled)) = read_snapshot(
            &mut transaction,
            &command.claim.account_id,
            &command.claim.predecessor_episode_ids,
            MAX_ATOMS,
            &authority,
        )
        .await?
        else {
            return Err(EnclaveError::Conflict(
                "memory reconciliation topology changed".into(),
            ));
        };
        if !settled
            || current.source_fingerprint != command.claim.source_fingerprint
            || current.topology_fingerprint != command.claim.topology_fingerprint
            || current.cohort_started_at != command.cohort_started_at
            || current.cohort_ended_at != command.cohort_ended_at
        {
            return Err(EnclaveError::Conflict(
                "memory reconciliation source or topology changed".into(),
            ));
        }
        let expected_atoms = current
            .atoms
            .iter()
            .map(|atom| atom.source_id.clone())
            .collect::<BTreeSet<_>>();
        let mut assigned_atoms = BTreeSet::new();
        let expected_predecessors = command
            .claim
            .predecessor_episode_ids
            .iter()
            .copied()
            .collect::<BTreeSet<_>>();
        let mut mentioned_predecessors = BTreeSet::new();
        let mut ordinals = BTreeSet::new();
        for output in outputs {
            if !ordinals.insert(output.output_ordinal) {
                return Err(EnclaveError::InvalidRequest(
                    "duplicate reconciliation output ordinal".into(),
                ));
            }
            for predecessor in &output.predecessor_episode_ids {
                if !expected_predecessors.contains(predecessor) {
                    return Err(EnclaveError::InvalidRequest(
                        "unknown reconciliation predecessor".into(),
                    ));
                }
                mentioned_predecessors.insert(*predecessor);
            }
            if let Some(retained) = output.retained_episode_id {
                if output.predecessor_episode_ids.as_slice() != [retained] {
                    return Err(EnclaveError::InvalidRequest(
                        "retained memory must be a one-to-one reconciliation".into(),
                    ));
                }
            }
            for atom in &output.member_source_ids {
                if !expected_atoms.contains(atom) || !assigned_atoms.insert(atom.clone()) {
                    return Err(EnclaveError::InvalidRequest(
                        "reconciliation output has a duplicate or unknown source".into(),
                    ));
                }
            }
        }
        if assigned_atoms != expected_atoms || mentioned_predecessors != expected_predecessors {
            return Err(EnclaveError::InvalidRequest(
                "reconciliation output is not an exhaustive partition".into(),
            ));
        }
        for retained in outputs
            .iter()
            .filter_map(|output| output.retained_episode_id)
        {
            if outputs
                .iter()
                .filter(|output| output.predecessor_episode_ids.contains(&retained))
                .count()
                != 1
            {
                return Err(EnclaveError::InvalidRequest(
                    "retained memory must be globally one-to-one".into(),
                ));
            }
        }

        let archive_revision: i64 = sqlx::query_scalar(
            "UPDATE memory_archive_state SET revision=revision+1,updated_at=clock_timestamp() \
              WHERE account_id=$1 RETURNING revision",
        )
        .bind(&command.claim.account_id)
        .fetch_one(&mut *transaction)
        .await?;
        sqlx::query(
            "INSERT INTO memory_reconciliations( \
                 account_id,id,reconciliation_version,model,prompt_version,vertex_event_id, \
                 cohort_started_at,cohort_ended_at,source_fingerprint,topology_fingerprint, \
                 result_commitment,archive_revision) \
             VALUES($1,$2,$3,$4,$5,$6,to_timestamp($7::double precision/1000.0), \
                    to_timestamp($8::double precision/1000.0),$9,$10,$11,$12)",
        )
        .bind(&command.claim.account_id)
        .bind(&command.reconciliation_id)
        .bind(stage.reconciliation_version)
        .bind(&stage.model)
        .bind(stage.prompt_version)
        .bind(stage.vertex_event_id.as_deref())
        .bind(timestamp(
            &command.cohort_started_at,
            "reconciliation cohort start",
        )?)
        .bind(timestamp(
            &command.cohort_ended_at,
            "reconciliation cohort end",
        )?)
        .bind(&command.claim.source_fingerprint)
        .bind(&command.claim.topology_fingerprint)
        .bind(&command.result_commitment)
        .bind(archive_revision)
        .execute(&mut *transaction)
        .await?;

        let retained_ids = outputs
            .iter()
            .filter_map(|output| output.retained_episode_id)
            .collect::<Vec<_>>();
        let replaced_predecessor_ids = command
            .claim
            .predecessor_episode_ids
            .iter()
            .copied()
            .filter(|episode_id| !retained_ids.contains(episode_id))
            .collect::<Vec<_>>();

        // Remove the previous active projection before inserting the exhaustive replacement.
        sqlx::query("DELETE FROM episode_members WHERE account_id=$1 AND episode_id=ANY($2)")
            .bind(&command.claim.account_id)
            .bind(&command.claim.predecessor_episode_ids)
            .execute(&mut *transaction)
            .await?;
        sqlx::query("DELETE FROM episode_final_briefs WHERE account_id=$1 AND episode_id=ANY($2)")
            .bind(&command.claim.account_id)
            .bind(&command.claim.predecessor_episode_ids)
            .execute(&mut *transaction)
            .await?;
        sqlx::query(
            "DELETE FROM episode_screen_interpretations WHERE account_id=$1 AND episode_id=ANY($2)",
        )
        .bind(&command.claim.account_id)
        .bind(&command.claim.predecessor_episode_ids)
        .execute(&mut *transaction)
        .await?;
        // A strict one-to-one reconciliation retains the episode identity and its
        // exact identity projections. Changed topology receives new episode ids;
        // those successors are reprojected below only from their assigned
        // utterances' durable speaker/identity evidence.
        sqlx::query("DELETE FROM episode_participants WHERE account_id=$1 AND episode_id=ANY($2)")
            .bind(&command.claim.account_id)
            .bind(&replaced_predecessor_ids)
            .execute(&mut *transaction)
            .await?;
        sqlx::query("DELETE FROM episode_speaker_slots WHERE account_id=$1 AND episode_id=ANY($2)")
            .bind(&command.claim.account_id)
            .bind(&replaced_predecessor_ids)
            .execute(&mut *transaction)
            .await?;

        let mut successor_ids = Vec::with_capacity(outputs.len());
        let mut new_successor_ids = Vec::new();
        let mut source_owner = HashMap::<String, i64>::new();
        for output in outputs {
            let id = if let Some(id) = output.retained_episode_id {
                sqlx::query(
                    "UPDATE episodes SET started_at=to_timestamp($3::double precision/1000.0), \
                         ended_at=to_timestamp($4::double precision/1000.0),type=$5,title=$6,summary=$7, \
                         participants=$8::jsonb,languages=$9::jsonb,action_items=$10::jsonb,model=$11, \
                         minute_summaries=$12::jsonb,minutes_text=$13,substance=$14,visual_evidence=$15, \
                         structure_state='reconciled',embedding=NULL,finalized_at=NULL, \
                         finalization_status='pending_horizon',updated_at=clock_timestamp() \
                       WHERE account_id=$1 AND id=$2",
                )
                .bind(&command.claim.account_id).bind(id)
                .bind(timestamp(&output.started_at,"reconciled memory start")?)
                .bind(timestamp(&output.ended_at,"reconciled memory end")?)
                .bind(output.episode_type.as_deref()).bind(&output.title).bind(output.summary.as_deref())
                .bind(serde_json::to_string(&output.participants)?)
                .bind(serde_json::to_string(&output.languages)?)
                .bind(serde_json::to_string(&output.action_items)?)
                .bind(output.model.as_deref())
                .bind(serde_json::to_string(&output.minute_summaries)?)
                .bind(output.minutes_text.as_deref()).bind(&output.substance).bind(&output.visual_evidence)
                .execute(&mut *transaction).await?;
                id
            } else {
                let id =
                    allocate_content_id(&mut transaction, &command.claim.account_id, "episodes")
                        .await?;
                sqlx::query(
                    "INSERT INTO episodes(account_id,id,started_at,ended_at,type,title,summary,participants, \
                         languages,action_items,model,minute_summaries,minutes_text,substance,visual_evidence, \
                         structure_state,finalization_status,updated_at) \
                     VALUES($1,$2,to_timestamp($3::double precision/1000.0), \
                         to_timestamp($4::double precision/1000.0),$5,$6,$7,$8::jsonb,$9::jsonb,$10::jsonb, \
                         $11,$12::jsonb,$13,$14,$15,'reconciled','pending_horizon',clock_timestamp())",
                )
                .bind(&command.claim.account_id).bind(id)
                .bind(timestamp(&output.started_at,"reconciled memory start")?)
                .bind(timestamp(&output.ended_at,"reconciled memory end")?)
                .bind(output.episode_type.as_deref()).bind(&output.title).bind(output.summary.as_deref())
                .bind(serde_json::to_string(&output.participants)?)
                .bind(serde_json::to_string(&output.languages)?)
                .bind(serde_json::to_string(&output.action_items)?)
                .bind(output.model.as_deref()).bind(serde_json::to_string(&output.minute_summaries)?)
                .bind(output.minutes_text.as_deref()).bind(&output.substance).bind(&output.visual_evidence)
                .execute(&mut *transaction).await?;
                new_successor_ids.push(id);
                id
            };
            successor_ids.push(id);
            for atom in &output.member_source_ids {
                source_owner.insert(atom.clone(), id);
            }
        }

        for predecessor in &command.claim.predecessor_episode_ids {
            let successors = outputs
                .iter()
                .zip(&successor_ids)
                .filter(|(output, _)| output.predecessor_episode_ids.contains(predecessor))
                .map(|(_, id)| *id)
                .collect::<Vec<_>>();
            if successors.as_slice() == [*predecessor] {
                continue;
            }
            let relation = if outputs.len() == 1 {
                "merge"
            } else if successors.len() > 1 && command.claim.predecessor_episode_ids.len() == 1 {
                "split"
            } else {
                "repartition"
            };
            sqlx::query(
                "UPDATE memory_handles SET state='superseded',origin_relation=$4, \
                        reconciliation_id=$3,retired_at=clock_timestamp() \
                  WHERE account_id=$1 AND episode_id=$2 AND state='active'",
            )
            .bind(&command.claim.account_id)
            .bind(predecessor)
            .bind(&command.reconciliation_id)
            .bind(relation)
            .execute(&mut *transaction)
            .await?;
            sqlx::query("UPDATE episodes SET structure_state='reconciled',updated_at=clock_timestamp() WHERE account_id=$1 AND id=$2")
                .bind(&command.claim.account_id).bind(predecessor)
                .execute(&mut *transaction).await?;
            for (ordinal, successor) in successors.iter().enumerate() {
                sqlx::query(
                    "INSERT INTO memory_lineage_edges(account_id,reconciliation_id,predecessor_episode_id,successor_episode_id,ordinal) \
                     VALUES($1,$2,$3,$4,$5)",
                ).bind(&command.claim.account_id).bind(&command.reconciliation_id)
                    .bind(predecessor).bind(successor).bind(i64::try_from(ordinal).unwrap_or(i64::MAX))
                    .execute(&mut *transaction).await?;
            }
        }
        for atom in &current.atoms {
            let successor = *source_owner.get(&atom.source_id).ok_or_else(|| {
                EnclaveError::Store("reconciliation source owner disappeared".into())
            })?;
            sqlx::query(
                "INSERT INTO episode_members(account_id,episode_id,record_type,record_id) VALUES($1,$2,$3,$4)",
            ).bind(&command.claim.account_id).bind(successor).bind(&atom.record_type).bind(atom.record_id)
                .execute(&mut *transaction).await?;
            sqlx::query(
                "INSERT INTO memory_reconciliation_sources(account_id,reconciliation_id,record_type,record_id,successor_episode_id) \
                 VALUES($1,$2,$3,$4,$5)",
            ).bind(&command.claim.account_id).bind(&command.reconciliation_id)
                .bind(&atom.record_type).bind(atom.record_id).bind(successor)
                .execute(&mut *transaction).await?;
            if atom.record_type == "screenshot" {
                sqlx::query("UPDATE screenshot_images SET episode_id=$3 WHERE account_id=$1 AND screenshot_id=$2")
                    .bind(&command.claim.account_id).bind(atom.record_id).bind(successor)
                .execute(&mut *transaction).await?;
            }
        }

        let speaker_evidence = if new_successor_ids.is_empty() {
            Vec::new()
        } else {
            sqlx::query(
                "SELECT member.episode_id,observation.cluster_id AS speaker_cluster_id, \
                        cluster.voice_profile_id,cluster.attribution_state, \
                        observation.direct_evidence_id IS NOT NULL AS has_direct_identity, \
                        CASE WHEN observation_person.status='identified' \
                             THEN observation.person_id END AS observation_person_id, \
                        CASE WHEN cluster_person.status='identified' \
                             THEN cluster.person_id END AS cluster_person_id, \
                        CASE WHEN profile_person.status='identified' \
                             THEN profile.person_id END AS profile_person_id \
                   FROM episode_members member \
                   JOIN utterances utterance ON utterance.account_id=member.account_id \
                        AND utterance.id=member.record_id \
                   JOIN speaker_observations observation ON observation.account_id=utterance.account_id \
                        AND observation.id=utterance.speaker_observation_id \
                   LEFT JOIN speaker_clusters cluster ON cluster.account_id=observation.account_id \
                        AND cluster.id=observation.cluster_id \
                   LEFT JOIN voice_profiles profile ON profile.account_id=cluster.account_id \
                        AND profile.id=cluster.voice_profile_id \
                   LEFT JOIN people observation_person ON observation_person.account_id=observation.account_id \
                        AND observation_person.id=observation.person_id \
                   LEFT JOIN people cluster_person ON cluster_person.account_id=cluster.account_id \
                        AND cluster_person.id=cluster.person_id \
                   LEFT JOIN people profile_person ON profile_person.account_id=profile.account_id \
                        AND profile_person.id=profile.person_id \
                  WHERE member.account_id=$1 AND member.episode_id=ANY($2) \
                    AND member.record_type='utterance' \
                  ORDER BY member.episode_id,cluster.voice_profile_id,observation.cluster_id,observation.id",
            )
            .bind(&command.claim.account_id)
            .bind(&new_successor_ids)
            .fetch_all(&mut *transaction)
            .await?
            .into_iter()
            .map(|row| {
                Ok(AssignedSpeakerEvidence {
                    episode_id: row.try_get("episode_id")?,
                    voice_profile_id: row.try_get("voice_profile_id")?,
                    speaker_cluster_id: row.try_get("speaker_cluster_id")?,
                    attribution_state: row.try_get("attribution_state")?,
                    has_direct_identity: row.try_get("has_direct_identity")?,
                    observation_person_id: row.try_get("observation_person_id")?,
                    cluster_person_id: row.try_get("cluster_person_id")?,
                    profile_person_id: row.try_get("profile_person_id")?,
                })
            })
            .collect::<Result<Vec<_>>>()?
        };
        let speaker_projections = rebuilt_speaker_projections(&speaker_evidence)?;
        if !speaker_projections.is_empty() {
            sqlx::query(
                "INSERT INTO content_id_counters(account_id,entity_kind,next_id) \
                 SELECT $1,'episode_speaker_slot',coalesce(max(id),0)+1 \
                   FROM episode_speaker_slots WHERE account_id=$1 \
                 ON CONFLICT(account_id,entity_kind) DO UPDATE SET \
                   next_id=greatest(content_id_counters.next_id,excluded.next_id)",
            )
            .bind(&command.claim.account_id)
            .execute(&mut *transaction)
            .await?;
            sqlx::query(
                "INSERT INTO content_id_counters(account_id,entity_kind,next_id) \
                 SELECT $1,'episode_participant',coalesce(max(id),0)+1 \
                   FROM episode_participants WHERE account_id=$1 \
                 ON CONFLICT(account_id,entity_kind) DO UPDATE SET \
                   next_id=greatest(content_id_counters.next_id,excluded.next_id)",
            )
            .bind(&command.claim.account_id)
            .execute(&mut *transaction)
            .await?;

            let mut slot_ordinals = HashMap::<i64, i64>::new();
            let mut participants =
                BTreeMap::<(i64, String), (Option<i64>, Option<i64>, String, u8)>::new();
            for projection in speaker_projections {
                let slot_id = if projection.voice_profile_id.is_some()
                    || projection.speaker_cluster_id.is_some()
                {
                    let slot_id = allocate_content_id(
                        &mut transaction,
                        &command.claim.account_id,
                        "episode_speaker_slot",
                    )
                    .await?;
                    let ordinal = slot_ordinals.entry(projection.episode_id).or_default();
                    sqlx::query(
                        "INSERT INTO episode_speaker_slots( \
                             account_id,id,episode_id,voice_profile_id,speaker_cluster_id,slot_ordinal) \
                         VALUES($1,$2,$3,$4,$5,$6)",
                    )
                    .bind(&command.claim.account_id)
                    .bind(slot_id)
                    .bind(projection.episode_id)
                    .bind(projection.voice_profile_id)
                    .bind(projection.speaker_cluster_id)
                    .bind(*ordinal)
                    .execute(&mut *transaction)
                    .await?;
                    *ordinal += 1;
                    Some(slot_id)
                } else {
                    None
                };
                let priority = match projection.attribution_kind.as_str() {
                    "owner_source_role" | "direct_identity_evidence" => 3,
                    "verified_voice" => 2,
                    _ => 1,
                };
                let key = (projection.episode_id, projection.participant_key);
                let candidate = (
                    projection.person_id,
                    slot_id,
                    projection.attribution_kind,
                    priority,
                );
                match participants.entry(key) {
                    std::collections::btree_map::Entry::Vacant(entry) => {
                        entry.insert(candidate);
                    }
                    std::collections::btree_map::Entry::Occupied(mut entry)
                        if priority > entry.get().3 =>
                    {
                        entry.insert(candidate);
                    }
                    std::collections::btree_map::Entry::Occupied(_) => {}
                }
            }
            let evidence = serde_json::to_string(&json!({
                "derivation": "assigned_utterance_identity",
                "reconciliation_id": command.reconciliation_id,
            }))?;
            for ((episode_id, participant_key), (person_id, slot_id, attribution_kind, _)) in
                participants
            {
                let participant_id = allocate_content_id(
                    &mut transaction,
                    &command.claim.account_id,
                    "episode_participant",
                )
                .await?;
                sqlx::query(
                    "INSERT INTO episode_participants( \
                         account_id,id,episode_id,participant_key,person_id,speaker_slot_id, \
                         attribution_kind,evidence) \
                     VALUES($1,$2,$3,$4,$5,$6,$7,$8::jsonb)",
                )
                .bind(&command.claim.account_id)
                .bind(participant_id)
                .bind(episode_id)
                .bind(participant_key)
                .bind(person_id)
                .bind(slot_id)
                .bind(attribution_kind)
                .bind(&evidence)
                .execute(&mut *transaction)
                .await?;
            }
        }
        // Formation fingerprints intentionally bind ownership as a boolean.
        // Refresh after topology mutation so any true->false transition bumps
        // the exact source revision before this transaction becomes visible.
        for capture_session_id in &current.capture_session_ids {
            refresh_capture_formation_receipt(
                &mut transaction,
                &command.claim.account_id,
                capture_session_id,
            )
            .await?;
        }
        sqlx::query(
            "DELETE FROM memory_reconciliation_stages \
              WHERE account_id=$1 AND predecessor_episode_ids && $2",
        )
        .bind(&command.claim.account_id)
        .bind(&command.claim.predecessor_episode_ids)
        .execute(&mut *transaction)
        .await?;
        sqlx::query(
            "DELETE FROM memory_reconciliation_jobs \
              WHERE account_id=$1 AND source_fingerprint<>$2 \
                AND predecessor_episode_ids && $3 AND state<>'complete'",
        )
        .bind(&command.claim.account_id)
        .bind(&command.claim.source_fingerprint)
        .bind(&command.claim.predecessor_episode_ids)
        .execute(&mut *transaction)
        .await?;
        let completed = sqlx::query(
            "UPDATE memory_reconciliation_jobs SET state='complete',claim_token=NULL,claim_until=NULL, \
                    reconciliation_id=$3,updated_at=clock_timestamp() \
              WHERE account_id=$1 AND source_fingerprint=$2 AND claim_token=$4 \
                AND state='processing' AND claim_until>clock_timestamp()",
        ).bind(&command.claim.account_id).bind(&command.claim.source_fingerprint)
            .bind(&command.reconciliation_id).bind(&command.claim.claim_token)
            .execute(&mut *transaction).await?.rows_affected();
        if completed != 1 {
            return Err(EnclaveError::Conflict(
                "memory reconciliation claim expired before publication".into(),
            ));
        }
        let provenance_committed = sqlx::query(
            "UPDATE persistence_feature_reconciliation_stage_contracts \
                SET reconciliation_id=$3,committed_at=clock_timestamp() \
              WHERE account_id=$1 AND source_fingerprint=$2 \
                AND activation_generation=$4 AND producer_contract_sha256=$5 \
                AND reconciliation_model=$6 AND vertex_location=$7 \
                AND reconciliation_id IS NULL",
        )
        .bind(&command.claim.account_id)
        .bind(&command.claim.source_fingerprint)
        .bind(&command.reconciliation_id)
        .bind(command.claim.activation_generation)
        .bind(&command.claim.producer_contract_sha256)
        .bind(&command.claim.reconciliation_model)
        .bind(&command.claim.vertex_location)
        .execute(&mut *transaction)
        .await?
        .rows_affected();
        if provenance_committed != 1 {
            return Err(EnclaveError::Conflict(
                "memory reconciliation producer provenance changed".into(),
            ));
        }
        sqlx::query("DELETE FROM episodes WHERE account_id=$1 AND id=ANY($2) AND NOT (id=ANY($3))")
            .bind(&command.claim.account_id)
            .bind(&command.claim.predecessor_episode_ids)
            .bind(&retained_ids)
            .execute(&mut *transaction)
            .await?;
        transaction.commit().await?;
        successor_ids.sort_unstable();
        Ok(ReconciliationPublishResult::Published {
            successor_episode_ids: successor_ids,
            archive_revision,
        })
    }

    async fn resolve_memory_handle(
        &self,
        account_id: &str,
        episode_id: i64,
        max_leaves: i64,
    ) -> Result<MemoryHandleResolution> {
        if episode_id <= 0 || !(1..=32).contains(&max_leaves) {
            return Err(EnclaveError::InvalidRequest(
                "memory handle request is invalid".into(),
            ));
        }
        let mut transaction = self.pool().begin().await?;
        sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
            .execute(&mut *transaction)
            .await?;
        let exists = sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS(SELECT 1 FROM memory_handles WHERE account_id=$1 AND episode_id=$2)",
        )
        .bind(account_id)
        .bind(episode_id)
        .fetch_one(&mut *transaction)
        .await?;
        if !exists {
            return Err(EnclaveError::NotFound);
        }
        let mut nodes = BTreeSet::from([episode_id]);
        let mut frontier = vec![episode_id];
        let mut edges = BTreeMap::<i64, BTreeSet<i64>>::new();
        for depth in 0..=32 {
            let rows = sqlx::query(
                "SELECT predecessor_episode_id,successor_episode_id FROM memory_lineage_edges \
                  WHERE account_id=$1 AND predecessor_episode_id=ANY($2) \
                  ORDER BY predecessor_episode_id,ordinal",
            )
            .bind(account_id)
            .bind(&frontier)
            .fetch_all(&mut *transaction)
            .await?;
            if depth == 32 && !rows.is_empty() {
                return Err(EnclaveError::Store(
                    "memory handle resolution exceeds its depth bound".into(),
                ));
            }
            let mut next = BTreeSet::new();
            for row in rows {
                let predecessor: i64 = row.try_get("predecessor_episode_id")?;
                let successor: i64 = row.try_get("successor_episode_id")?;
                edges.entry(predecessor).or_default().insert(successor);
                if nodes.insert(successor) {
                    next.insert(successor);
                }
            }
            if nodes.len() > 1_024 {
                return Err(EnclaveError::Store(
                    "memory handle resolution exceeds its node bound".into(),
                ));
            }
            if next.is_empty() {
                break;
            }
            frontier = next.into_iter().collect();
        }
        let node_ids = nodes.into_iter().collect::<Vec<_>>();
        let rows = sqlx::query(
            "SELECT episode_id,state,origin_relation FROM memory_handles \
              WHERE account_id=$1 AND episode_id=ANY($2) ORDER BY episode_id",
        )
        .bind(account_id)
        .bind(&node_ids)
        .fetch_all(&mut *transaction)
        .await?;
        if rows.len() != node_ids.len() {
            return Err(EnclaveError::Store(
                "memory lineage references a missing handle".into(),
            ));
        }
        let mut states = BTreeMap::new();
        let mut requested_relation = None;
        for row in rows {
            let id: i64 = row.try_get("episode_id")?;
            states.insert(id, row.try_get("state")?);
            if id == episode_id {
                requested_relation = row.try_get("origin_relation")?;
            }
        }
        let active_episode_ids =
            validate_resolution_graph(episode_id, &states, &edges, max_leaves)?;
        let raw_state = states
            .get(&episode_id)
            .ok_or_else(|| EnclaveError::Store("requested memory handle disappeared".into()))?;
        let state = match raw_state.as_str() {
            "active" => MemoryHandleState::Active,
            "superseded" => MemoryHandleState::Superseded,
            "retired" => MemoryHandleState::Retired,
            _ => return Err(EnclaveError::Store("invalid memory handle state".into())),
        };
        let revision = sqlx::query_scalar::<_, i64>(
            "SELECT coalesce((SELECT revision FROM memory_archive_state WHERE account_id=$1),0)",
        )
        .bind(account_id)
        .fetch_one(&mut *transaction)
        .await?;
        transaction.commit().await?;
        Ok(MemoryHandleResolution {
            requested_episode_id: episode_id,
            state,
            origin_relation: requested_relation,
            active_episode_ids,
            archive_revision: revision,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct AssignedSpeakerEvidence {
    episode_id: i64,
    voice_profile_id: Option<i64>,
    speaker_cluster_id: Option<i64>,
    attribution_state: Option<String>,
    has_direct_identity: bool,
    observation_person_id: Option<i64>,
    cluster_person_id: Option<i64>,
    profile_person_id: Option<i64>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct RebuiltSpeakerProjection {
    episode_id: i64,
    voice_profile_id: Option<i64>,
    speaker_cluster_id: Option<i64>,
    person_id: Option<i64>,
    participant_key: String,
    attribution_kind: String,
}

#[derive(Default)]
struct SpeakerProjectionAccumulator {
    person_ids: BTreeSet<i64>,
    owner_source: bool,
    direct_identity: bool,
}

fn rebuilt_speaker_projections(
    evidence: &[AssignedSpeakerEvidence],
) -> Result<Vec<RebuiltSpeakerProjection>> {
    // Profile identity is the stable slot when present; otherwise the exact
    // request-local cluster is the slot. A legacy observation with neither can
    // still project an explicitly identified Person, but never an inferred name.
    let mut slots = BTreeMap::<(i64, u8, i64), SpeakerProjectionAccumulator>::new();
    for row in evidence {
        let row_people = [
            row.observation_person_id,
            row.cluster_person_id,
            row.profile_person_id,
        ]
        .into_iter()
        .flatten()
        .collect::<BTreeSet<_>>();
        if row_people.len() > 1 {
            return Err(EnclaveError::Store(
                "assigned utterance has conflicting identified speaker evidence".into(),
            ));
        }
        let slot_key = if let Some(profile_id) = row.voice_profile_id {
            (row.episode_id, 0, profile_id)
        } else if let Some(cluster_id) = row.speaker_cluster_id {
            (row.episode_id, 1, cluster_id)
        } else if let Some(person_id) = row_people.first() {
            (row.episode_id, 2, *person_id)
        } else {
            continue;
        };
        let slot = slots.entry(slot_key).or_default();
        slot.person_ids.extend(row_people);
        slot.owner_source |= row.attribution_state.as_deref() == Some("owner_transmit");
        slot.direct_identity |=
            row.has_direct_identity || row.attribution_state.as_deref() == Some("person_bound");
    }

    slots
        .into_iter()
        .map(|((episode_id, kind, source_id), evidence)| {
            if evidence.person_ids.len() > 1 {
                return Err(EnclaveError::Store(
                    "assigned speaker has conflicting identified people".into(),
                ));
            }
            let person_id = (!evidence.owner_source)
                .then(|| evidence.person_ids.first().copied())
                .flatten();
            let (voice_profile_id, speaker_cluster_id) = match kind {
                0 => (Some(source_id), None),
                1 => (None, Some(source_id)),
                2 => (None, None),
                _ => unreachable!("speaker projection kind is locally constructed"),
            };
            let participant_key = if evidence.owner_source {
                "owner".to_owned()
            } else if let Some(person_id) = person_id {
                format!("person:{person_id}")
            } else if let Some(profile_id) = voice_profile_id {
                format!("voice_profile:{profile_id}")
            } else {
                format!("speaker_cluster:{source_id}")
            };
            let attribution_kind = if evidence.owner_source {
                "owner_source_role"
            } else if evidence.direct_identity {
                "direct_identity_evidence"
            } else if voice_profile_id.is_some() && person_id.is_some() {
                "verified_voice"
            } else {
                "context_inferred"
            };
            Ok(RebuiltSpeakerProjection {
                episode_id,
                voice_profile_id,
                speaker_cluster_id,
                person_id,
                participant_key,
                attribution_kind: attribution_kind.to_owned(),
            })
        })
        .collect()
}

#[cfg(test)]
pub(super) fn test_provider_stage_write(
    snapshot: &ReconciliationSnapshot,
    variant: &str,
) -> Result<ReconciliationStageWrite> {
    let partition = json!({
        "contract": "provider-egress-lock-order-v1",
        "predecessor_episode_ids": snapshot.predecessor_episode_ids,
        "variant": variant,
    });
    let result_commitment = partition_commitment(&partition)?;
    let first = snapshot
        .drafts
        .first()
        .ok_or_else(|| EnclaveError::Store("test reconciliation snapshot has no drafts".into()))?;
    let member_source_ids = snapshot
        .atoms
        .iter()
        .map(|atom| atom.source_id.clone())
        .collect::<Vec<_>>();
    if member_source_ids.is_empty() {
        return Err(EnclaveError::Store(
            "test reconciliation snapshot has no evidence".into(),
        ));
    }
    Ok(ReconciliationStageWrite {
        normalized_partition: partition,
        result_commitment,
        planned_outputs: vec![ReconciledMemoryWrite {
            output_ordinal: 0,
            retained_episode_id: None,
            predecessor_episode_ids: snapshot.predecessor_episode_ids.clone(),
            started_at: snapshot.cohort_started_at.clone(),
            ended_at: snapshot.cohort_ended_at.clone(),
            episode_type: first.episode_type.clone(),
            title: format!("Provider egress lock order {variant}"),
            summary: Some(format!("Durable same-transaction stage {variant}")),
            participants: Vec::new(),
            languages: Vec::new(),
            action_items: Vec::new(),
            model: Some("conservative-v1".into()),
            minute_summaries: json!([]),
            minutes_text: None,
            substance: "normal".into(),
            visual_evidence: "useful".into(),
            member_source_ids,
        }],
        model: "conservative-v1".into(),
        vertex_event_id: None,
        provider_attempt_identity: None,
        provider_invocation_fingerprint: None,
        reconciliation_version: 1,
        prompt_version: 1,
        partition_schema_version: 1,
        validator_version: 1,
    })
}

#[cfg(test)]
pub(super) fn test_provider_stage_write_with_provenance(
    snapshot: &ReconciliationSnapshot,
    variant: &str,
    model: &str,
    vertex_event_id: &str,
    provider_attempt_identity: &[u8; 32],
    provider_invocation_fingerprint: &[u8; 32],
) -> Result<ReconciliationStageWrite> {
    let mut stage = test_provider_stage_write(snapshot, variant)?;
    stage.model = model.to_owned();
    for output in &mut stage.planned_outputs {
        output.model = Some(model.to_owned());
    }
    stage.vertex_event_id = Some(vertex_event_id.to_owned());
    stage.provider_attempt_identity = Some(provider_attempt_identity.to_vec());
    stage.provider_invocation_fingerprint = Some(provider_invocation_fingerprint.to_vec());
    Ok(stage)
}

#[cfg(test)]
mod tests {
    use super::{
        connected_source_sessions, digest_json, ensure_no_external_owners,
        ensure_source_session_bound, held_keep_promotion, oldest_connected_drafts,
        oldest_connected_prefix_with_boundary, partition_commitment, rebuilt_speaker_projections,
        source_id, source_sessions_are_settled, valid_digest, validate_resolution_graph,
        AssignedSpeakerEvidence, SourceSession,
    };
    use crate::persistence::{
        reconciliation_outputs_commitment, OversizedKeepPromotionResult, ReconciledMemoryWrite,
    };
    use serde_json::json;
    use std::collections::{BTreeMap, BTreeSet};

    #[test]
    fn source_ids_are_opaque_and_typed() {
        assert_eq!(source_id("utterance", 42), "utterance:42");
        assert_eq!(source_id("screenshot", 7), "screenshot:7");
    }

    #[test]
    fn fingerprints_are_domain_separated_and_fixed_width() {
        let value = json!({"atoms":["utterance:1"]});
        let source = digest_json(b"source\0", &value).unwrap();
        let topology = digest_json(b"topology\0", &value).unwrap();
        assert!(valid_digest(&source));
        assert_ne!(source, topology);
    }

    #[test]
    fn staged_commitment_binds_exact_normalized_partition() {
        let partition = json!({"memories":[{"title":"Bound"}]});
        let commitment = partition_commitment(&partition).unwrap();
        assert_eq!(commitment.len(), 32);
        assert_ne!(
            commitment,
            partition_commitment(&json!({"memories":[]})).unwrap()
        );
    }

    #[test]
    fn staged_output_commitment_binds_every_publication_field() {
        let output = ReconciledMemoryWrite {
            output_ordinal: 0,
            retained_episode_id: Some(7),
            predecessor_episode_ids: vec![7],
            started_at: "2026-08-30T12:00:00.000Z".into(),
            ended_at: "2026-08-30T12:01:00.000Z".into(),
            episode_type: Some("work".into()),
            title: "Bound title".into(),
            summary: Some("Bound summary".into()),
            participants: Vec::new(),
            languages: vec!["en".into()],
            action_items: Vec::new(),
            model: Some("contract-model".into()),
            minute_summaries: json!([]),
            minutes_text: Some(String::new()),
            substance: "normal".into(),
            visual_evidence: "none".into(),
            member_source_ids: vec!["utterance:1".into()],
        };
        let original = reconciliation_outputs_commitment(std::slice::from_ref(&output)).unwrap();
        let mut changed = output;
        changed.title = "Substituted title".into();
        assert_ne!(
            original,
            reconciliation_outputs_commitment(&[changed]).unwrap()
        );
    }

    #[test]
    fn oldest_component_includes_neighbor_that_has_not_crossed_quiet_cutoff() {
        let hour = 60 * 60 * 1_000;
        let headers = vec![
            (10, 9 * hour, 10 * hour),
            (11, 10 * hour + 30 * 60 * 1_000, 10 * hour + 45 * 60 * 1_000),
            (12, 16 * hour, 17 * hour),
        ];
        assert_eq!(oldest_connected_drafts(&headers, 32).unwrap(), vec![10, 11]);
    }

    #[test]
    fn thirty_three_connected_drafts_yield_an_exact_thirty_two_draft_prefix() {
        let minute = 60 * 1_000;
        let mut headers = (0..33)
            .map(|offset| {
                let started = offset * minute;
                (10 + offset, started, started + minute)
            })
            .collect::<Vec<_>>();
        headers.push((99, 20 * 60 * minute, 20 * 60 * minute + minute));
        let (prefix, oversized, component_end, complete) =
            oldest_connected_prefix_with_boundary(&headers, 32);
        assert_eq!(prefix, (10..42).collect::<Vec<_>>());
        assert!(oversized);
        assert_eq!(component_end, Some(33 * minute));
        assert!(complete);
        assert!(matches!(
            held_keep_promotion(component_end, complete),
            OversizedKeepPromotionResult::Held {
                resume_after_component_ended_at: Some(_)
            }
        ));
    }

    #[test]
    fn truncated_component_never_returns_an_unsafe_skip_cursor() {
        let headers = (0..257)
            .map(|offset| (offset + 1, offset * 1_000, offset * 1_000 + 2_000))
            .collect::<Vec<_>>();
        let (_, oversized, component_end, complete) =
            oldest_connected_prefix_with_boundary(&headers, 32);
        assert!(oversized);
        assert!(!complete);
        assert_eq!(
            held_keep_promotion(component_end, complete),
            OversizedKeepPromotionResult::Held {
                resume_after_component_ended_at: None
            }
        );
    }

    #[test]
    fn source_ceiling_hold_exposes_a_complete_boundary_for_disconnected_work() {
        let hour = 60 * 60 * 1_000;
        let headers = vec![(1, 0, hour), (2, 10 * hour, 11 * hour)];
        let (prefix, oversized, component_end, complete) =
            oldest_connected_prefix_with_boundary(&headers, 32);
        assert_eq!(prefix, vec![1]);
        assert!(
            !oversized,
            "the evidence count, not draft count, is oversized"
        );
        assert!(complete);
        assert_eq!(component_end, Some(hour));
        let held = held_keep_promotion(component_end, complete);
        assert!(matches!(
            held,
            OversizedKeepPromotionResult::Held {
                resume_after_component_ended_at: Some(_)
            }
        ));
        assert!(headers[1].1 > component_end.unwrap() + 4 * hour);
    }

    #[test]
    fn touching_unassigned_pending_session_fences_source_settlement() {
        let pending = SourceSession {
            id: "session-pending".into(),
            started_ms: 10_000,
            ended_ms: 20_000,
            sealed: false,
            streams_settled: false,
            jobs_terminal: false,
            media_terminal: false,
            server_quiet: false,
            formation_state: None,
            formation_source_revision: None,
            formation_completed_revision: None,
            formation_completed_outcome: None,
            formation_completed_source_fingerprint: None,
            formation_finish_requested_ms: None,
            formation_seal_finalized_ms: None,
            formation_seal_generation: None,
            formation_seal_source_revision: None,
            formation_seal_stream_maxima_sha256: None,
            formation_seal_finalization_provenance: None,
            formation_current: false,
        };
        let closure = connected_source_sessions(&[pending], 9_000, 11_000);
        assert_eq!(closure.len(), 1);
        assert!(!source_sessions_are_settled(&closure));
    }

    #[test]
    fn source_session_neighborhood_refuses_truncation_before_settlement() {
        assert!(ensure_source_session_bound(256).is_ok());
        assert!(ensure_source_session_bound(257).is_err());
    }

    #[test]
    fn external_active_owner_is_a_diagnosable_bounded_hold() {
        let error = ensure_no_external_owners(&[10, 11], &[10, 11, 99]).unwrap_err();
        assert!(error.to_string().contains("99"));
        assert!(error.to_string().contains("outside the bounded cohort"));
    }

    #[test]
    fn migration_and_queries_keep_stage_replacement_cleanup_and_lease_fences() {
        let migration = include_str!("../../../migrations/0026_memory_reconciliation.sql");
        let activation_migration =
            include_str!("../../../migrations/0027_memory_reconciliation_activation.sql");
        let legacy_guard = include_str!(
            "../../../migrations/0026_memory_reconciliation_episode_members_unique_index.sql"
        );
        let adapter = include_str!("memory_reconciliation.rs");
        assert!(migration.contains("memory_reconciliation_stages_predecessors_idx"));
        assert!(adapter.contains("ON CONFLICT(account_id,source_fingerprint) DO UPDATE SET"));
        assert!(adapter.contains("IS DISTINCT FROM ROW(excluded.activation_generation"));
        assert!(adapter.contains("if stage_changed == 1 && expected.vertex_event_id.is_some()"));
        assert!(activation_migration.contains("provider_attempt_identity bytea"));
        assert!(activation_migration.contains("provider_invocation_fingerprint bytea"));
        assert!(adapter.contains("validate_reconciliation_provider_provenance"));
        assert!(adapter.contains("VertexOperation::EpisodeReconciliation.as_str()"));
        assert!(adapter.contains("outcome == \"ambiguous\" || successful_response"));
        let stale_attempt_charge = ["if stage_changed == 1 || ", "contract_changed == 1"].concat();
        assert!(!adapter.contains(&stale_attempt_charge));
        assert!(adapter.contains("predecessor_episode_ids && $2"));
        assert!(adapter.contains("claim_until>clock_timestamp()"));
        let production = adapter.split("#[cfg(test)]").next().unwrap();
        let stale_transaction_time = ["CURRENT", "TIMESTAMP"].join("_");
        assert!(!production.contains(&stale_transaction_time));
        assert!(adapter.contains("capture_formation_seal_events seal"));
        assert!(adapter.contains("seal.stream_maxima_sha256"));
        assert!(adapter.contains("seal.source_revision=receipt.source_revision"));
        assert!(adapter.contains("NOT EXISTS(SELECT 1 FROM capture_formation_seal_events reopen"));
        assert!(adapter.contains("owner.episode_id=ANY($2)"));
        assert!(adapter.contains("episode.structure_state='draft'"));
        assert!(adapter.contains("job.state='processing' AND job.claim_until>clock_timestamp()"));
        assert!(adapter.contains("clock_timestamp()+make_interval(secs=>$5)"));
        assert!(!production.contains("memory reconciliation claim time"));
        assert!(!production.contains("memory reconciliation quiet cutoff"));
        assert!(!production.contains("memory reconciliation release time"));
        assert!(!production.contains("memory reconciliation retry time"));
        assert!(adapter.contains("providerless KEEP source count exceeds its operational bound"));
        let providerless = adapter
            .split("async fn promote_oversized_source_settled_prefix(")
            .nth(1)
            .unwrap()
            .split("async fn next_source_settled_cohort(")
            .next()
            .unwrap();
        assert!(providerless.contains("UPDATE episodes SET structure_state='reconciled'"));
        assert!(!providerless.contains("UPDATE episodes SET structure_state='reconciled',"));
        assert!(legacy_guard.contains("CREATE UNIQUE INDEX CONCURRENTLY"));
        assert!(legacy_guard.contains("account_id,record_type,record_id"));
        assert!(!migration.contains("SELECT DISTINCT ON (member.account_id"));
    }

    #[test]
    fn changed_topology_rebuilds_only_durable_speaker_identity_projections() {
        let projections = rebuilt_speaker_projections(&[
            AssignedSpeakerEvidence {
                episode_id: 101,
                voice_profile_id: Some(7),
                speaker_cluster_id: Some(70),
                attribution_state: Some("anonymous_profile".into()),
                has_direct_identity: false,
                observation_person_id: Some(9),
                cluster_person_id: Some(9),
                profile_person_id: Some(9),
            },
            AssignedSpeakerEvidence {
                episode_id: 101,
                voice_profile_id: None,
                speaker_cluster_id: Some(71),
                attribution_state: Some("owner_transmit".into()),
                has_direct_identity: false,
                observation_person_id: Some(99),
                cluster_person_id: None,
                profile_person_id: None,
            },
            AssignedSpeakerEvidence {
                episode_id: 102,
                voice_profile_id: None,
                speaker_cluster_id: Some(72),
                attribution_state: Some("request_local".into()),
                has_direct_identity: false,
                observation_person_id: None,
                cluster_person_id: None,
                profile_person_id: None,
            },
        ])
        .unwrap();
        assert_eq!(projections.len(), 3);
        assert!(projections.iter().any(|projection| {
            projection.episode_id == 101
                && projection.voice_profile_id == Some(7)
                && projection.speaker_cluster_id.is_none()
                && projection.person_id == Some(9)
                && projection.participant_key == "person:9"
                && projection.attribution_kind == "verified_voice"
        }));
        assert!(projections.iter().any(|projection| {
            projection.episode_id == 101
                && projection.participant_key == "owner"
                && projection.person_id.is_none()
                && projection.attribution_kind == "owner_source_role"
        }));
        assert!(projections.iter().any(|projection| {
            projection.episode_id == 102
                && projection.participant_key == "speaker_cluster:72"
                && projection.person_id.is_none()
                && projection.attribution_kind == "context_inferred"
        }));
    }

    #[test]
    fn conflicting_identified_speaker_evidence_fails_closed() {
        let error = rebuilt_speaker_projections(&[AssignedSpeakerEvidence {
            episode_id: 101,
            voice_profile_id: Some(7),
            speaker_cluster_id: Some(70),
            attribution_state: Some("person_bound".into()),
            has_direct_identity: true,
            observation_person_id: Some(9),
            cluster_person_id: Some(10),
            profile_person_id: None,
        }])
        .unwrap_err();
        assert!(error.to_string().contains("conflicting identified"));
    }

    #[test]
    fn publication_preserves_retained_identity_and_rebuilds_new_successors() {
        let adapter = include_str!("memory_reconciliation.rs");
        assert!(adapter.contains("replaced_predecessor_ids"));
        assert!(adapter.contains("new_successor_ids"));
        assert!(adapter.contains("JOIN speaker_observations observation"));
        assert!(adapter.contains("THEN observation.person_id END"));
        assert!(adapter.contains("'episode_speaker_slot'"));
        assert!(adapter.contains("'episode_participant'"));
        assert!(adapter.contains("\"derivation\": \"assigned_utterance_identity\""));
    }

    #[test]
    fn resolution_graph_fails_closed_on_cycles_and_missing_handles() {
        let states = BTreeMap::from([(1, "superseded".into()), (2, "superseded".into())]);
        let cycle = BTreeMap::from([(1, BTreeSet::from([2])), (2, BTreeSet::from([1]))]);
        assert!(validate_resolution_graph(1, &states, &cycle, 32)
            .unwrap_err()
            .to_string()
            .contains("cycle"));

        let missing = BTreeMap::from([(1, BTreeSet::from([3]))]);
        assert!(validate_resolution_graph(1, &states, &missing, 32)
            .unwrap_err()
            .to_string()
            .contains("missing"));
    }

    #[test]
    fn superseded_handle_may_resolve_to_only_explicitly_retired_leaves() {
        let states = BTreeMap::from([(1, "superseded".into()), (2, "retired".into())]);
        let edges = BTreeMap::from([(1, BTreeSet::from([2]))]);
        assert!(validate_resolution_graph(1, &states, &edges, 32)
            .unwrap()
            .is_empty());
    }
}
