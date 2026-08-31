use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

use async_trait::async_trait;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use sqlx::{PgConnection, Row};

use crate::{
    cp::{isotime, tokens},
    error::{EnclaveError, Result},
    persistence::{
        reconciliation_outputs_commitment, MemoryHandleResolution, MemoryHandleState,
        MemoryReconciliationRepository, ReconciledMemoryWrite, ReconciliationClaim,
        ReconciliationDraft, ReconciliationEvidenceAtom, ReconciliationPublish,
        ReconciliationPublishResult, ReconciliationSnapshot, ReconciliationStageWrite,
        StagedReconciliation,
    },
};

use super::{
    advisory_transaction_lock, allocate_content_id, duration_seconds, PostgresPersistence,
};

const QUIET_HORIZON_SECONDS: i64 = 4 * 60 * 60;
const MAX_DRAFTS: i64 = 32;
const MAX_ATOMS: i64 = 4_000;
const MAX_SOURCE_SESSIONS: usize = 256;

fn timestamp(value: &str, field: &str) -> Result<i64> {
    isotime::parse_epoch_millis(value)
        .ok_or_else(|| EnclaveError::InvalidRequest(format!("{field} is invalid")))
}

fn valid_digest(value: &[u8]) -> bool {
    value.len() == 32 && value.iter().any(|byte| *byte != 0)
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

async fn candidate_ids(
    connection: &mut PgConnection,
    account_id: &str,
    draft_limit: i64,
) -> Result<Vec<i64>> {
    let rows = sqlx::query(
        "SELECT episode.id,floor(extract(epoch FROM episode.started_at)*1000)::bigint AS started_ms, \
                floor(extract(epoch FROM episode.ended_at)*1000)::bigint AS ended_ms \
           FROM episodes episode \
           JOIN memory_handles handle ON handle.account_id=episode.account_id \
                AND handle.episode_id=episode.id AND handle.state='active' \
          WHERE episode.account_id=$1 AND episode.structure_state='draft' \
            AND episode.finalized_at IS NULL \
          ORDER BY episode.started_at,episode.id LIMIT 257",
    )
    .bind(account_id)
    .fetch_all(&mut *connection)
    .await?;
    let headers = rows
        .into_iter()
        .map(|row| {
            Ok((
                row.try_get("id")?,
                row.try_get("started_ms")?,
                row.try_get("ended_ms")?,
            ))
        })
        .collect::<Result<Vec<_>>>()?;
    oldest_connected_drafts(&headers, draft_limit)
}

fn oldest_connected_drafts(headers: &[(i64, i64, i64)], draft_limit: i64) -> Result<Vec<i64>> {
    let mut component = Vec::new();
    let mut component_end = i64::MIN;
    for (id, started_ms, ended_ms) in headers {
        if !component.is_empty()
            && *started_ms > component_end.saturating_add(QUIET_HORIZON_SECONDS * 1_000)
        {
            break;
        }
        component.push(*id);
        component_end = component_end.max(*ended_ms);
        if i64::try_from(component.len()).unwrap_or(i64::MAX) > draft_limit {
            return Err(EnclaveError::Store(
                "memory reconciliation cohort exceeds its configured bound".into(),
            ));
        }
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
                    OR (segment.started_at + utterance.start_offset_seconds*interval '1 second' \
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
                    OR screenshot.captured_at BETWEEN to_timestamp($3::double precision/1000.0) \
                            AND to_timestamp($4::double precision/1000.0)) \
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

#[derive(Clone, Debug, PartialEq, Eq)]
struct SourceSession {
    id: String,
    started_ms: i64,
    ended_ms: i64,
    sealed: bool,
    streams_sealed: bool,
    jobs_terminal: bool,
    media_terminal: bool,
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
        session.sealed && session.streams_sealed && session.jobs_terminal && session.media_terminal
    })
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
                session.ended_at IS NOT NULL AS sealed, \
                NOT EXISTS(SELECT 1 FROM capture_streams stream \
                    WHERE stream.account_id=$1 AND stream.capture_session_id=session.id \
                      AND stream.sealed_sequence IS NULL) AS streams_sealed, \
                NOT EXISTS(SELECT 1 FROM capture_events event \
                    JOIN media_processing_jobs job ON job.account_id=event.account_id AND job.event_id=event.event_id \
                    WHERE event.account_id=$1 AND event.capture_session_id=session.id \
                      AND job.state NOT IN ('succeeded','failed_terminal','canceled')) AS jobs_terminal, \
                NOT EXISTS(SELECT 1 FROM capture_events event \
                    JOIN media_objects object ON object.account_id=event.account_id AND object.event_id=event.event_id \
                    WHERE event.account_id=$1 AND event.capture_session_id=session.id \
                      AND object.deleted_at IS NULL \
                      AND object.processing_state IN ('queued','processing','retry_wait')) AS media_terminal \
               FROM capture_sessions session LEFT JOIN capture_events event \
                 ON event.account_id=session.account_id AND event.capture_session_id=session.id \
              WHERE session.account_id=$1 AND session.id=ANY($2) \
              GROUP BY session.account_id,session.id,session.started_at,session.last_event_at,session.ended_at \
              ORDER BY started_ms,session.id",
    )
    .bind(account_id)
    .bind(&candidate_ids)
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
                streams_sealed: row.try_get("streams_sealed")?,
                jobs_terminal: row.try_get("jobs_terminal")?,
                media_terminal: row.try_get("media_terminal")?,
            })
        })
        .collect()
}

async fn read_snapshot(
    connection: &mut PgConnection,
    account_id: &str,
    predecessor_ids: &[i64],
    atom_limit: i64,
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
    let settled = source_sessions_are_settled(&sessions);
    let guard = sessions
        .iter()
        .map(|session| {
            json!({
                "session_id": session.id,
                "started_ms": session.started_ms,
                "ended_ms": session.ended_ms,
                "sealed": session.sealed,
                "streams_sealed": session.streams_sealed,
                "jobs_terminal": session.jobs_terminal,
                "media_terminal": session.media_terminal,
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
            source_fingerprint,
            topology_fingerprint,
            archive_revision,
        },
        settled,
    )))
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
        reconciliation_version: row.try_get("reconciliation_version")?,
        prompt_version: row.try_get("prompt_version")?,
        partition_schema_version: row.try_get("partition_schema_version")?,
        validator_version: row.try_get("validator_version")?,
    })
}

async fn read_stage(
    connection: &mut PgConnection,
    account_id: &str,
    fingerprint: &[u8],
) -> Result<Option<StagedReconciliation>> {
    let row = sqlx::query(
        "SELECT account_id,source_fingerprint,topology_fingerprint,predecessor_episode_ids, \
                normalized_partition::text AS normalized_partition,result_commitment, \
                planned_outputs::text AS planned_outputs,planned_outputs_commitment,model, \
                vertex_event_id,reconciliation_version,prompt_version,partition_schema_version, \
                validator_version FROM memory_reconciliation_stages \
          WHERE account_id=$1 AND source_fingerprint=$2",
    )
    .bind(account_id)
    .bind(fingerprint)
    .fetch_optional(connection)
    .await?;
    row.as_ref().map(staged_from_row).transpose()
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
    async fn next_source_settled_cohort(
        &self,
        account_id: &str,
        quiet_before: &str,
        draft_limit: i64,
        atom_limit: i64,
    ) -> Result<Option<ReconciliationSnapshot>> {
        if !(1..=MAX_DRAFTS).contains(&draft_limit) || !(1..=MAX_ATOMS).contains(&atom_limit) {
            return Err(EnclaveError::InvalidRequest(
                "memory reconciliation bounds are invalid".into(),
            ));
        }
        let quiet_before_ms = timestamp(quiet_before, "memory reconciliation quiet cutoff")?;
        let mut connection = self.pool().acquire().await?;
        let ids = candidate_ids(&mut connection, account_id, draft_limit).await?;
        if ids.is_empty() {
            return Ok(None);
        }
        let Some((snapshot, settled)) =
            read_snapshot(&mut connection, account_id, &ids, atom_limit).await?
        else {
            return Ok(None);
        };
        if !settled
            || timestamp(
                &snapshot.cohort_ended_at,
                "memory reconciliation cohort end",
            )? > quiet_before_ms
        {
            return Ok(None);
        }
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
        let mut connection = self.pool().acquire().await?;
        let Some((snapshot, settled)) = read_snapshot(
            &mut connection,
            account_id,
            predecessor_episode_ids,
            MAX_ATOMS,
        )
        .await?
        else {
            return Ok(false);
        };
        Ok(settled && snapshot.source_fingerprint == expected_source_fingerprint)
    }

    async fn claim_reconciliation(
        &self,
        snapshot: &ReconciliationSnapshot,
        claimed_at: &str,
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
        let _claimed_ms = timestamp(claimed_at, "memory reconciliation claim time")?;
        let claim_token = tokens::new_uuid();
        let mut transaction = self.pool().begin().await?;
        sqlx::query("SET TRANSACTION ISOLATION LEVEL SERIALIZABLE")
            .execute(&mut *transaction)
            .await?;
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
                    CURRENT_TIMESTAMP+make_interval(secs=>$8),CURRENT_TIMESTAMP) \
             ON CONFLICT(account_id,source_fingerprint) DO UPDATE SET \
                 topology_fingerprint=excluded.topology_fingerprint, \
                 predecessor_episode_ids=excluded.predecessor_episode_ids,state='processing', \
                 attempt_count=memory_reconciliation_jobs.attempt_count+1,claim_token=excluded.claim_token, \
                 claim_until=excluded.claim_until,next_attempt_at=NULL,last_error_code=NULL, \
                 updated_at=excluded.updated_at \
             WHERE (memory_reconciliation_jobs.state='retry_wait' \
                       AND memory_reconciliation_jobs.next_attempt_at<=CURRENT_TIMESTAMP) \
                OR (memory_reconciliation_jobs.state='processing' \
                       AND memory_reconciliation_jobs.claim_until<=CURRENT_TIMESTAMP) \
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
        };
        transaction.commit().await?;
        Ok(Some(claim))
    }

    async fn staged_result(
        &self,
        account_id: &str,
        source_fingerprint: &[u8],
    ) -> Result<Option<StagedReconciliation>> {
        if !valid_digest(source_fingerprint) {
            return Err(EnclaveError::InvalidRequest(
                "memory reconciliation source fingerprint is invalid".into(),
            ));
        }
        let mut connection = self.pool().acquire().await?;
        read_stage(&mut connection, account_id, source_fingerprint).await
    }

    async fn stage_reconciliation(
        &self,
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
                "memory reconciliation result commitment does not bind the normalized partition"
                    .into(),
            ));
        }
        for output in &staged.planned_outputs {
            validate_output(output)?;
        }
        let planned_outputs_commitment =
            reconciliation_outputs_commitment(&staged.planned_outputs)?;
        let mut transaction = self.pool().begin().await?;
        advisory_transaction_lock(&mut transaction, "memory-reconciliation", &claim.account_id)
            .await?;
        let authoritative = sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS(SELECT 1 FROM memory_reconciliation_jobs \
              WHERE account_id=$1 AND source_fingerprint=$2 AND topology_fingerprint=$3 \
                AND predecessor_episode_ids=$4 AND state='processing' AND claim_token=$5 \
                AND claim_until>CURRENT_TIMESTAMP)",
        )
        .bind(&claim.account_id)
        .bind(&claim.source_fingerprint)
        .bind(&claim.topology_fingerprint)
        .bind(&claim.predecessor_episode_ids)
        .bind(&claim.claim_token)
        .fetch_one(&mut *transaction)
        .await?;
        if !authoritative {
            return Err(EnclaveError::Conflict(
                "memory reconciliation claim is no longer authoritative".into(),
            ));
        }
        let partition = serde_json::to_string(&staged.normalized_partition)?;
        let planned_outputs = serde_json::to_string(&staged.planned_outputs)?;
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
                 validator_version=excluded.validator_version,created_at=now() \
             WHERE memory_reconciliation_stages.model<>excluded.model \
                OR memory_reconciliation_stages.reconciliation_version<>excluded.reconciliation_version \
                OR memory_reconciliation_stages.prompt_version<>excluded.prompt_version \
                OR memory_reconciliation_stages.partition_schema_version<>excluded.partition_schema_version \
                OR memory_reconciliation_stages.validator_version<>excluded.validator_version",
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
        .execute(&mut *transaction)
        .await?
        .rows_affected();
        let stored = read_stage(
            &mut transaction,
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
            reconciliation_version: staged.reconciliation_version,
            prompt_version: staged.prompt_version,
            partition_schema_version: staged.partition_schema_version,
            validator_version: staged.validator_version,
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
            || stored.reconciliation_version != expected.reconciliation_version
            || stored.prompt_version != expected.prompt_version
            || stored.partition_schema_version != expected.partition_schema_version
            || stored.validator_version != expected.validator_version
        {
            return Err(EnclaveError::Conflict(
                "a different reconciliation result is already staged".into(),
            ));
        }
        if stage_changed == 1 {
            sqlx::query(
                "UPDATE memory_reconciliation_jobs SET model_attempt_count=model_attempt_count+1,updated_at=now() \
                  WHERE account_id=$1 AND source_fingerprint=$2 AND claim_token=$3",
            )
            .bind(&claim.account_id)
            .bind(&claim.source_fingerprint)
            .bind(&claim.claim_token)
            .execute(&mut *transaction)
            .await?;
        }
        transaction.commit().await?;
        Ok(stored)
    }

    async fn release_reconciliation(
        &self,
        claim: &ReconciliationClaim,
        released_at: &str,
        retry_at: Option<&str>,
        error_code: &str,
        terminal: bool,
        consume_model_attempt: bool,
    ) -> Result<()> {
        if error_code.is_empty()
            || (!terminal && retry_at.is_none())
            || (terminal && retry_at.is_some())
        {
            return Err(EnclaveError::InvalidRequest(
                "memory reconciliation release is invalid".into(),
            ));
        }
        let released_ms = timestamp(released_at, "memory reconciliation release time")?;
        let retry_ms = retry_at
            .map(|value| timestamp(value, "memory reconciliation retry time"))
            .transpose()?;
        let changed = sqlx::query(
            "UPDATE memory_reconciliation_jobs SET state=$4,claim_token=NULL,claim_until=NULL, \
                    next_attempt_at=CASE WHEN $5::bigint IS NULL THEN NULL \
                         ELSE to_timestamp($5::double precision/1000.0) END, \
                    last_error_code=$6,updated_at=to_timestamp($7::double precision/1000.0), \
                    model_attempt_count=model_attempt_count+CASE WHEN $8 THEN 1 ELSE 0 END \
              WHERE account_id=$1 AND source_fingerprint=$2 AND claim_token=$3 AND state='processing'",
        )
        .bind(&claim.account_id)
        .bind(&claim.source_fingerprint)
        .bind(&claim.claim_token)
        .bind(if terminal { "failed_terminal" } else { "retry_wait" })
        .bind(retry_ms)
        .bind(error_code)
        .bind(released_ms)
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
        advisory_transaction_lock(
            &mut transaction,
            "memory-reconciliation",
            &command.claim.account_id,
        )
        .await?;

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
                AND claim_until>CURRENT_TIMESTAMP)",
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
            "UPDATE memory_archive_state SET revision=revision+1,updated_at=now() \
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
                         finalization_status='pending_horizon',updated_at=now() \
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
                         $11,$12::jsonb,$13,$14,$15,'reconciled','pending_horizon',now())",
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
                        reconciliation_id=$3,retired_at=now() \
                  WHERE account_id=$1 AND episode_id=$2 AND state='active'",
            )
            .bind(&command.claim.account_id)
            .bind(predecessor)
            .bind(&command.reconciliation_id)
            .bind(relation)
            .execute(&mut *transaction)
            .await?;
            sqlx::query("UPDATE episodes SET structure_state='reconciled',updated_at=now() WHERE account_id=$1 AND id=$2")
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
                    reconciliation_id=$3,updated_at=now() \
              WHERE account_id=$1 AND source_fingerprint=$2 AND claim_token=$4 \
                AND state='processing' AND claim_until>CURRENT_TIMESTAMP",
        ).bind(&command.claim.account_id).bind(&command.claim.source_fingerprint)
            .bind(&command.reconciliation_id).bind(&command.claim.claim_token)
            .execute(&mut *transaction).await?.rows_affected();
        if completed != 1 {
            return Err(EnclaveError::Conflict(
                "memory reconciliation claim expired before publication".into(),
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
mod tests {
    use super::{
        connected_source_sessions, digest_json, ensure_no_external_owners,
        ensure_source_session_bound, oldest_connected_drafts, partition_commitment,
        rebuilt_speaker_projections, source_id, source_sessions_are_settled, valid_digest,
        validate_resolution_graph, AssignedSpeakerEvidence, SourceSession,
    };
    use crate::persistence::{reconciliation_outputs_commitment, ReconciledMemoryWrite};
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
    fn touching_unassigned_pending_session_fences_source_settlement() {
        let pending = SourceSession {
            id: "session-pending".into(),
            started_ms: 10_000,
            ended_ms: 20_000,
            sealed: false,
            streams_sealed: false,
            jobs_terminal: false,
            media_terminal: false,
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
        let legacy_guard = include_str!(
            "../../../migrations/0026_memory_reconciliation_episode_members_unique_index.sql"
        );
        let adapter = include_str!("memory_reconciliation.rs");
        assert!(migration.contains("memory_reconciliation_stages_predecessors_idx"));
        assert!(adapter.contains("ON CONFLICT(account_id,source_fingerprint) DO UPDATE SET"));
        assert!(adapter.contains("predecessor_episode_ids && $2"));
        assert!(adapter.contains("claim_until>CURRENT_TIMESTAMP"));
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
