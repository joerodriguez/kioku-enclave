//! Recover a missing client finish marker without inventing source completeness.

use sqlx::Row;

use crate::{
    cp::media_worker::{
        NON_RESURRECTABLE_MEDIA_ERROR_CODES, PROCESSOR_VERSION, RESURRECTION_TOTAL_ATTEMPT_CAP,
        RESURRECTION_WINDOW_SECONDS_INTEGRAL,
    },
    error::Result,
};

use super::{
    activation::lock_activation_contract_key_share_if_installed, advisory_transaction_lock,
    capture::record_provisional_finish, PostgresPersistence,
};

const INACTIVITY_SECONDS: f64 = 30.0 * 60.0;
const RECOVERY_BATCH_SIZE: i64 = 32;

pub(super) async fn recover_inactive_sessions(
    persistence: &PostgresPersistence,
    account_id: &str,
) -> Result<u64> {
    let mut transaction = persistence.pool().begin().await?;
    if !lock_activation_contract_key_share_if_installed(&mut transaction).await? {
        transaction.commit().await?;
        return Ok(0);
    }
    super::interrupted_capture_schema::verify(&mut transaction).await?;
    // Predecessors must be drained before server finishes may change the
    // lifecycle of a session that an older writer still considers open.
    let drained = sqlx::query_scalar::<_, bool>(
        "SELECT coalesce((SELECT phase IN ('draining','active','paused') \
            FROM persistence_feature_activation_events \
           WHERE feature='episode_topology_reconciliation' \
           ORDER BY generation DESC LIMIT 1),false)",
    )
    .fetch_one(&mut *transaction)
    .await?;
    if !drained {
        transaction.commit().await?;
        return Ok(0);
    }
    advisory_transaction_lock(&mut transaction, "account-lifecycle", account_id).await?;
    advisory_transaction_lock(&mut transaction, "memory-reconciliation", account_id).await?;
    // Upload reservation takes this same account row lock. A reservation that
    // wins first holds recovery; one admitted afterwards remains a late upload.
    let active = sqlx::query_scalar::<_, String>(
        "SELECT id FROM accounts WHERE id=$1 AND status='active' FOR UPDATE SKIP LOCKED",
    )
    .bind(account_id)
    .fetch_optional(&mut *transaction)
    .await?;
    if active.is_none() {
        transaction.commit().await?;
        return Ok(0);
    }
    let held = sqlx::query_scalar::<_, bool>(
        // Upload intents do not contain session identity. Conservatively hold
        // the account rather than guess ownership of a not-yet-accepted event.
        "SELECT EXISTS(SELECT 1 FROM capture_upload_intents \
                        WHERE account_id=$1 AND expires_at>clock_timestamp()) \
             OR EXISTS(SELECT 1 FROM episode_deletions WHERE account_id=$1 AND state='pending') \
             OR EXISTS(SELECT 1 FROM orphan_capture_erasure_operations \
                        WHERE account_id=$1 AND capture_upload_fenced)",
    )
    .bind(account_id)
    .fetch_one(&mut *transaction)
    .await?;
    if held {
        transaction.commit().await?;
        return Ok(0);
    }
    // Every eligibility condition precedes LIMIT: incomplete old sessions
    // cannot monopolize the bounded pass. Receipt time is database-assigned at
    // acceptance; backdated offline timestamps and duplicate replays cannot
    // shorten or indefinitely extend this inactivity interval.
    let candidates = sqlx::query(
        "SELECT session.id, \
                floor(extract(epoch FROM greatest(session.last_event_at, \
                    (SELECT max(event.ended_at) FROM capture_events event \
                      WHERE event.account_id=session.account_id \
                        AND event.capture_session_id=session.id)))*1000)::bigint AS ended_ms \
           FROM capture_sessions session \
           JOIN capture_formation_receipts receipt \
             ON receipt.account_id=session.account_id AND receipt.capture_session_id=session.id \
          WHERE session.account_id=$1 AND session.ended_at IS NULL \
            AND receipt.finish_requested_at IS NULL AND receipt.seal_finalized_at IS NULL \
            AND (receipt.claim_until IS NULL OR receipt.claim_until<=clock_timestamp()) \
            AND session.created_at<=clock_timestamp()-make_interval(secs=>$2) \
            AND EXISTS(SELECT 1 FROM capture_events event WHERE event.account_id=session.account_id \
                        AND event.capture_session_id=session.id) \
            AND NOT EXISTS(SELECT 1 FROM capture_events event \
                        WHERE event.account_id=session.account_id AND event.capture_session_id=session.id \
                          AND event.received_at>clock_timestamp()-make_interval(secs=>$2)) \
            AND EXISTS(SELECT 1 FROM capture_streams stream WHERE stream.account_id=session.account_id \
                        AND stream.capture_session_id=session.id) \
            AND NOT EXISTS(SELECT 1 FROM capture_streams stream \
                        WHERE stream.account_id=session.account_id AND stream.capture_session_id=session.id \
                          AND (stream.sealed_sequence IS NOT NULL \
                               OR stream.committed_through_sequence IS DISTINCT FROM \
                                  capture_formation_stream_accepted_max(stream.account_id,stream.id) \
                               OR stream.committed_through_sequence IS DISTINCT FROM \
                                  capture_formation_stream_contiguous_through(stream.account_id,stream.id))) \
            AND NOT EXISTS( \
                SELECT 1 FROM capture_events event \
                LEFT JOIN capture_events root ON root.account_id=event.account_id \
                     AND root.event_id=coalesce(event.canonical_event_id,event.event_id) \
                LEFT JOIN media_processing_jobs job ON job.account_id=root.account_id \
                     AND job.event_id=root.event_id \
                LEFT JOIN media_objects object ON object.account_id=root.account_id \
                     AND object.event_id=root.event_id \
                WHERE event.account_id=session.account_id AND event.capture_session_id=session.id \
                  AND (root.event_id IS NULL OR job.id IS NULL OR object.event_id IS NULL \
                       OR (job.state NOT IN ('succeeded','canceled') \
                           AND (job.state<>'failed_terminal' OR (job.processor_version=$3 \
                                AND NOT (coalesce(job.error_code,'')=ANY($4::text[])) \
                                AND job.attempt_count<$5 \
                                AND root.started_at>=clock_timestamp()-make_interval(secs=>$6)))) \
                       OR (object.deleted_at IS NULL \
                           AND object.processing_state IN ('queued','processing','retry_wait')))) \
          ORDER BY session.created_at,session.id \
          LIMIT $7 FOR UPDATE OF session,receipt SKIP LOCKED",
    )
    .bind(account_id)
    .bind(INACTIVITY_SECONDS)
    .bind(PROCESSOR_VERSION)
    .bind(NON_RESURRECTABLE_MEDIA_ERROR_CODES.as_slice())
    .bind(RESURRECTION_TOTAL_ATTEMPT_CAP)
    .bind(RESURRECTION_WINDOW_SECONDS_INTEGRAL as f64)
    .bind(RECOVERY_BATCH_SIZE)
    .fetch_all(&mut *transaction)
    .await?;
    for candidate in &candidates {
        record_provisional_finish(
            &mut transaction,
            account_id,
            candidate.try_get("id")?,
            Some(candidate.try_get("ended_ms")?),
            "server_inactivity_v1",
        )
        .await?;
    }
    transaction.commit().await?;
    Ok(candidates.len() as u64)
}

#[cfg(test)]
#[path = "capture_recovery_tests.rs"]
mod tests;

#[cfg(test)]
pub(super) use tests::test_real_pg_interrupted_capture_recovery;
