//! Tenant-qualified morning digest scheduling, revision snapshots, and source coverage.
//! No provider call happens here. Claims reuse the ordinary disclosure fences and
//! service-wide email lane; expired disclosed claims become terminal ambiguity.

use sqlx::Row;

use super::{advisory_transaction_lock, PostgresPersistence};
use crate::{
    cp::{delivery::FinalizedEpisode, isotime, tokens},
    error::{EnclaveError, Result},
    persistence::{
        delivery_outbox::DailyEmailSnapshot, EmailDeliveryCandidate, EmailDeliveryClaim,
        EmailProviderOutcome, FrozenEmailDelivery,
    },
};

type Transaction<'a> = sqlx::Transaction<'a, sqlx::Postgres>;
const MAX_BRIEFS: i64 = 32;

pub(super) async fn enqueue_brief(
    tx: &mut Transaction<'_>,
    account_id: &str,
    episode_id: i64,
    include_content: bool,
) -> Result<()> {
    sqlx::query("INSERT INTO morning_email_sources(account_id,record_type,record_id,origin_episode_id,include_content,state) \
        SELECT $1,m.record_type,m.record_id,$2,$3,'pending' FROM episode_members m \
        JOIN episode_email_preferences p ON p.account_id=m.account_id AND p.enabled \
        WHERE m.account_id=$1 AND m.episode_id=$2 ON CONFLICT DO NOTHING")
        .bind(account_id).bind(episode_id).bind(include_content).execute(&mut **tx).await?;
    Ok(())
}

pub(super) async fn cancel_unsent(
    tx: &mut Transaction<'_>,
    account_id: &str,
    revoked: bool,
) -> Result<()> {
    sqlx::query("UPDATE morning_email_sources s SET delivery_id=NULL,state=CASE WHEN $2 THEN 'cancelled' ELSE s.state END,updated_at=clock_timestamp() \
        WHERE s.account_id=$1 AND s.state='pending' AND (s.delivery_id IS NULL OR EXISTS( \
            SELECT 1 FROM morning_email_deliveries d WHERE d.account_id=s.account_id AND d.delivery_id=s.delivery_id \
              AND d.state IN ('assembling','pending','retry_wait')))")
        .bind(account_id).bind(revoked).execute(&mut **tx).await?;
    sqlx::query("UPDATE morning_email_deliveries SET state='cancelled',error_code='email_preferences_changed', \
        snapshot='{}',frozen_request=NULL,updated_at=clock_timestamp() WHERE account_id=$1 AND state IN ('assembling','pending','retry_wait')")
        .bind(account_id).execute(&mut **tx).await?;
    Ok(())
}

pub(super) async fn recover_expired(tx: &mut Transaction<'_>, account_id: &str) -> Result<()> {
    let rows = sqlx::query("UPDATE morning_email_deliveries SET state='ambiguous',completed_claim_token=claim_token, \
        claim_token=NULL,claim_until=NULL,error_code='claim_expired_after_disclosure',updated_at=clock_timestamp() \
        WHERE account_id=$1 AND state='processing' AND claim_until<=clock_timestamp() \
        RETURNING delivery_id,completed_claim_token")
        .bind(account_id).fetch_all(&mut **tx).await?;
    for row in rows {
        let delivery: String = row.try_get("delivery_id")?;
        let token: String = row.try_get("completed_claim_token")?;
        sqlx::query("UPDATE morning_email_sources SET state='ambiguous',updated_at=clock_timestamp() WHERE account_id=$1 AND delivery_id=$2 AND state='pending'")
            .bind(account_id).bind(&delivery).execute(&mut **tx).await?;
        release_fence(tx, account_id, &delivery, &token, None).await?;
    }
    Ok(())
}

async fn lock_account(tx: &mut Transaction<'_>, account_id: &str) -> Result<()> {
    super::activation::finalization_requires_reconciled(tx, account_id).await?;
    advisory_transaction_lock(tx, "account-lifecycle", account_id).await?;
    advisory_transaction_lock(tx, "memory-reconciliation", account_id).await?;
    // Identity refresh locks this row before changing the canonical address.
    // Keep it stable until the disclosure fence commits; the database trigger
    // then refuses address changes while a submitted request remains in flight.
    sqlx::query("SELECT id FROM accounts WHERE id=$1 FOR SHARE")
        .bind(account_id)
        .fetch_optional(&mut **tx)
        .await?;
    advisory_transaction_lock(tx, "email-preference", account_id).await?;
    recover_expired(tx, account_id).await?;
    super::delivery_outbox::recover_expired_email_claims(tx, account_id).await?;
    Ok(())
}

async fn load_episode(
    tx: &mut Transaction<'_>,
    account_id: &str,
    episode_id: i64,
) -> Result<Option<FinalizedEpisode>> {
    if super::activation::finalization_requires_reconciled(tx, account_id).await?
        && !super::memory_reconciliation::brief_sources_are_settled(tx, account_id, episode_id)
            .await?
    {
        return Ok(None);
    }
    let row = sqlx::query("SELECT e.id AS episode_id,e.title,e.type AS episode_type,e.participants::text AS participants, \
        floor(extract(epoch FROM e.started_at)*1000)::bigint AS started_at_ms, \
        floor(extract(epoch FROM e.ended_at)*1000)::bigint AS ended_at_ms, \
        floor(extract(epoch FROM e.finalized_at)*1000)::bigint AS finalized_at_ms, \
        b.overview,b.sections::text AS sections,b.decisions::text AS decisions,b.action_items::text AS action_items, \
        b.important_links::text AS important_links,b.open_questions::text AS open_questions \
        FROM episodes e JOIN episode_final_briefs b ON b.account_id=e.account_id AND b.episode_id=e.id \
        JOIN memory_handles h ON h.account_id=e.account_id AND h.episode_id=e.id AND h.state='active' \
        WHERE e.account_id=$1 AND e.id=$2 AND e.finalization_status='complete' AND e.finalized_at IS NOT NULL \
        FOR SHARE OF e,b,h")
        .bind(account_id).bind(episode_id).fetch_optional(&mut **tx).await?;
    match row
        .as_ref()
        .map(super::delivery_outbox::episode_from_row)
        .transpose()?
    {
        Some(episode) => Ok(Some(
            super::delivery_outbox::present_episode(tx, account_id, episode).await?,
        )),
        None => Ok(None),
    }
}

async fn sources(
    tx: &mut Transaction<'_>,
    account_id: &str,
    episode_id: i64,
) -> Result<Vec<(i64, String, i64)>> {
    let rows = sqlx::query(
        "SELECT episode_id,record_type,record_id FROM active_episode_members \
        WHERE account_id=$1 AND episode_id=$2 ORDER BY record_type,record_id",
    )
    .bind(account_id)
    .bind(episode_id)
    .fetch_all(&mut **tx)
    .await?;
    rows.iter()
        .map(|row| {
            Ok((
                row.try_get("episode_id")?,
                row.try_get("record_type")?,
                row.try_get("record_id")?,
            ))
        })
        .collect()
}

async fn brief_revision(
    tx: &mut Transaction<'_>,
    account_id: &str,
    episode_id: i64,
) -> Result<Option<String>> {
    Ok(sqlx::query_scalar("SELECT jsonb_build_object('analysis_revision',e.finalization_analysis_revision, \
        'finalization_version',e.finalization_version,'identity_revision',e.identity_revision, \
        'finalized_identity_revision',e.finalized_identity_revision,'brief_created_at',b.created_at, \
        'reconciliation_id',h.reconciliation_id)::text FROM episodes e \
        JOIN episode_final_briefs b ON b.account_id=e.account_id AND b.episode_id=e.id \
        JOIN memory_handles h ON h.account_id=e.account_id AND h.episode_id=e.id \
        WHERE e.account_id=$1 AND e.id=$2")
        .bind(account_id).bind(episode_id).fetch_optional(&mut **tx).await?)
}

async fn cancel_snapshot(
    tx: &mut Transaction<'_>,
    account_id: &str,
    delivery_id: &str,
) -> Result<()> {
    sqlx::query(
        "UPDATE morning_email_deliveries SET state='cancelled',error_code='snapshot_changed', \
        snapshot='{}',frozen_request=NULL,updated_at=clock_timestamp() \
        WHERE account_id=$1 AND delivery_id=$2 AND state IN ('assembling','pending','retry_wait')",
    )
    .bind(account_id)
    .bind(delivery_id)
    .execute(&mut **tx)
    .await?;
    sqlx::query(
        "UPDATE morning_email_sources SET delivery_id=NULL,updated_at=clock_timestamp() \
        WHERE account_id=$1 AND delivery_id=$2 AND state='pending'",
    )
    .bind(account_id)
    .bind(delivery_id)
    .execute(&mut **tx)
    .await?;
    Ok(())
}

async fn read_candidate(
    tx: &mut Transaction<'_>,
    account_id: &str,
) -> Result<Option<EmailDeliveryCandidate>> {
    let row = sqlx::query("SELECT d.delivery_id,d.attempt_count,d.recipient_email,d.include_content,d.snapshot::text AS snapshot, \
        d.consent_revision=(p.updated_at::text) AND d.recipient_email=a.email AND p.enabled \
            AND a.status='active' AND (NOT d.include_content OR p.include_content) AS authorized \
        FROM morning_email_deliveries d JOIN accounts a ON a.id=d.account_id \
        JOIN episode_email_preferences p ON p.account_id=d.account_id \
        WHERE d.account_id=$1 AND d.state IN ('pending','retry_wait') AND d.next_attempt_at<=clock_timestamp() \
        ORDER BY d.delivery_date LIMIT 1 FOR UPDATE OF d")
        .bind(account_id).fetch_optional(&mut **tx).await?;
    let Some(row) = row else { return Ok(None) };
    let delivery_id: String = row.try_get("delivery_id")?;
    let mut snapshot: DailyEmailSnapshot =
        serde_json::from_str(&row.try_get::<String, _>("snapshot")?)?;
    if !row.try_get::<bool, _>("authorized")? {
        cancel_snapshot(tx, account_id, &delivery_id).await?;
        return Ok(None);
    }
    let mut changed_ids = Vec::new();
    for episode in &snapshot.episodes {
        let expected_sources: Vec<_> = snapshot
            .sources
            .iter()
            .filter(|source| source.0 == episode.episode_id)
            .cloned()
            .collect();
        if load_episode(tx, account_id, episode.episode_id)
            .await?
            .as_ref()
            != Some(episode)
            || sources(tx, account_id, episode.episode_id).await? != expected_sources
            || brief_revision(tx, account_id, episode.episode_id)
                .await?
                .as_ref()
                != snapshot
                    .revisions
                    .iter()
                    .find(|revision| revision.0 == episode.episode_id)
                    .map(|revision| &revision.1)
        {
            changed_ids.push(episode.episode_id);
        }
    }
    if !changed_ids.is_empty() {
        if row.try_get::<i64, _>("attempt_count")? > 0 {
            cancel_snapshot(tx, account_id, &delivery_id).await?;
            return Ok(None);
        }
        for (_, kind, id) in snapshot
            .sources
            .iter()
            .filter(|source| changed_ids.contains(&source.0))
        {
            sqlx::query("UPDATE morning_email_sources SET delivery_id=NULL,updated_at=clock_timestamp() \
                WHERE account_id=$1 AND record_type=$2 AND record_id=$3 AND delivery_id=$4 AND state='pending'")
                .bind(account_id).bind(kind).bind(id).bind(&delivery_id).execute(&mut **tx).await?;
        }
        snapshot
            .episodes
            .retain(|episode| !changed_ids.contains(&episode.episode_id));
        snapshot
            .sources
            .retain(|source| !changed_ids.contains(&source.0));
        snapshot
            .revisions
            .retain(|revision| !changed_ids.contains(&revision.0));
        if snapshot.episodes.is_empty() {
            cancel_snapshot(tx, account_id, &delivery_id).await?;
            return Ok(None);
        }
        sqlx::query("UPDATE morning_email_deliveries SET snapshot=$3::jsonb,updated_at=clock_timestamp() WHERE account_id=$1 AND delivery_id=$2")
            .bind(account_id).bind(&delivery_id).bind(serde_json::to_string(&snapshot)?).execute(&mut **tx).await?;
    }
    Ok(Some(EmailDeliveryCandidate {
        account_id: account_id.to_owned(),
        episode_id: 0,
        delivery_version: 1,
        delivery_id,
        attempt_count: row.try_get("attempt_count")?,
        include_content: row.try_get("include_content")?,
        recipient_email: row.try_get("recipient_email")?,
        episode: snapshot.episodes[0].clone(),
        daily: Some(snapshot),
    }))
}

async fn continue_assembly(
    tx: &mut Transaction<'_>,
    account_id: &str,
    delivery_id: &str,
) -> Result<Option<EmailDeliveryCandidate>> {
    let row=sqlx::query("SELECT d.snapshot::text AS snapshot,d.include_content, \
        d.consent_revision=p.updated_at::text AND d.recipient_email=a.email AND p.enabled AND a.status='active' \
          AND (NOT d.include_content OR p.include_content) AS authorized \
        FROM morning_email_deliveries d JOIN accounts a ON a.id=d.account_id \
        JOIN episode_email_preferences p ON p.account_id=d.account_id \
        WHERE d.account_id=$1 AND d.delivery_id=$2 AND d.state='assembling' FOR UPDATE OF d")
        .bind(account_id).bind(delivery_id).fetch_one(&mut **tx).await?;
    if !row.try_get::<bool, _>("authorized")? {
        cancel_snapshot(tx, account_id, delivery_id).await?;
        return Ok(None);
    }
    let mut snapshot: DailyEmailSnapshot =
        serde_json::from_str(&row.try_get::<String, _>("snapshot")?)?;
    let mut include_content: bool = row.try_get("include_content")?;
    let ids = sqlx::query_scalar::<_,i64>("SELECT e.id FROM episodes e JOIN memory_handles h ON h.account_id=e.account_id AND h.episode_id=e.id AND h.state='active' \
        WHERE e.account_id=$1 AND e.finalization_status='complete' AND e.finalized_at IS NOT NULL \
        AND (e.ended_at AT TIME ZONE $2)::date<$3::date AND EXISTS( \
            SELECT 1 FROM active_episode_members m JOIN morning_email_sources s ON s.account_id=m.account_id AND s.record_type=m.record_type AND s.record_id=m.record_id \
            WHERE m.account_id=e.account_id AND m.episode_id=e.id AND s.state='pending' AND s.delivery_id IS NULL AND s.last_considered_delivery_id IS DISTINCT FROM $5) \
        AND NOT EXISTS(SELECT 1 FROM active_episode_members m JOIN morning_email_sources s \
            ON s.account_id=m.account_id AND s.record_type=m.record_type AND s.record_id=m.record_id \
            WHERE m.account_id=e.account_id AND m.episode_id=e.id AND (s.state!='pending' OR s.delivery_id IS NOT NULL)) \
        ORDER BY (SELECT min(s.updated_at) FROM active_episode_members m JOIN morning_email_sources s \
            ON s.account_id=m.account_id AND s.record_type=m.record_type AND s.record_id=m.record_id \
            WHERE m.account_id=e.account_id AND m.episode_id=e.id),e.ended_at,e.id LIMIT $4")
        .bind(account_id).bind(&snapshot.timezone).bind(&snapshot.delivery_date).bind(MAX_BRIEFS).bind(delivery_id).fetch_all(&mut **tx).await?;
    let scanned = ids.len();
    for id in ids {
        if snapshot.episodes.len() >= MAX_BRIEFS as usize {
            break;
        }
        sqlx::query("UPDATE morning_email_sources s SET last_considered_delivery_id=$3,updated_at=clock_timestamp() FROM active_episode_members m \
            WHERE m.account_id=$1 AND m.episode_id=$2 AND s.account_id=m.account_id \
              AND s.record_type=m.record_type AND s.record_id=m.record_id AND s.state='pending' AND s.delivery_id IS NULL")
            .bind(account_id).bind(id).bind(delivery_id).execute(&mut **tx).await?;
        if let Some(episode) = load_episode(tx, account_id, id).await? {
            let members = sources(tx, account_id, id).await?;
            if members.is_empty() {
                continue;
            }
            let consent = sqlx::query_scalar::<_,bool>("SELECT coalesce(bool_and(s.include_content),false) FROM active_episode_members m \
                JOIN morning_email_sources s ON s.account_id=m.account_id AND s.record_type=m.record_type AND s.record_id=m.record_id \
                WHERE m.account_id=$1 AND m.episode_id=$2")
                .bind(account_id).bind(id).fetch_one(&mut **tx).await?;
            include_content &= consent;
            let revision = brief_revision(tx, account_id, id)
                .await?
                .ok_or_else(|| EnclaveError::Store("morning brief revision disappeared".into()))?;
            snapshot.revisions.push((id, revision));
            snapshot.episodes.push(episode);
            snapshot.sources.extend(members);
        }
    }
    for (_, kind, id) in &snapshot.sources {
        sqlx::query("UPDATE morning_email_sources SET delivery_id=$4,updated_at=clock_timestamp() WHERE account_id=$1 AND record_type=$2 AND record_id=$3 AND state='pending' AND delivery_id IS NULL")
            .bind(account_id).bind(kind).bind(id).bind(delivery_id).execute(&mut **tx).await?;
    }
    let complete = snapshot.episodes.len() >= MAX_BRIEFS as usize || scanned < MAX_BRIEFS as usize;
    let state = if !complete {
        "assembling"
    } else if snapshot.episodes.is_empty() {
        "empty"
    } else {
        "pending"
    };
    sqlx::query("UPDATE morning_email_deliveries SET snapshot=$3::jsonb,include_content=$4,state=$5,updated_at=clock_timestamp() WHERE account_id=$1 AND delivery_id=$2")
        .bind(account_id).bind(delivery_id).bind(serde_json::to_string(&snapshot)?).bind(include_content).bind(state).execute(&mut **tx).await?;
    if state == "pending" {
        read_candidate(tx, account_id).await
    } else {
        Ok(None)
    }
}

/// Names PostgreSQL knows but that are not user-facing IANA zones. Shared by the
/// explicit preference save and the recording-device follower.
pub(super) fn plausible_timezone_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 100
        && !name.starts_with("posix/")
        && !name.starts_with("right/")
        && !matches!(name, "Factory" | "posixrules")
}

/// The morning email follows the device the account records with (owner
/// decision 2026-09-11, amending ADR-0045's "collect the zone explicitly"): a
/// schedule with no zone is bootstrapped from the newest capture event, and a
/// recording received after the schedule's last change re-follows the device,
/// so an explicit settings save (any save bumps the schedule) wins only until
/// the next recording. Delivery stays at 07:00 local. Following can only bring
/// the due time forward to the next local morning, never push it out, so two
/// devices disagreeing about the zone cannot starve delivery. Events whose
/// device clock is more than a day ahead are ignored, and an offline backlog
/// recorded more than a day before an explicit save cannot override it. Device
/// zone names PostgreSQL does not know are warned about and ignored. Accounts
/// that never enabled email have no schedule row and are untouched.
pub(super) async fn follow_recording_timezone(
    tx: &mut Transaction<'_>,
    account_id: &str,
) -> Result<Option<String>> {
    let Some(row) = sqlx::query(
        "SELECT e.timezone_id AS device_timezone,s.timezone, \
                (e.received_at>s.updated_at AND e.started_at>s.updated_at-interval '1 day') AS newer \
           FROM morning_email_schedules s \
           JOIN LATERAL (SELECT timezone_id,received_at,started_at FROM capture_events \
                          WHERE account_id=s.account_id \
                            AND started_at<=clock_timestamp()+interval '1 day' \
                          ORDER BY started_at DESC,event_id DESC LIMIT 1) e ON true \
          WHERE s.account_id=$1",
    )
    .bind(account_id)
    .fetch_optional(&mut **tx)
    .await?
    else {
        return Ok(None);
    };
    let device: String = row.try_get("device_timezone")?;
    let current: Option<String> = row.try_get("timezone")?;
    let newer: bool = row.try_get("newer")?;
    if current.as_deref() == Some(device.as_str()) || (current.is_some() && !newer) {
        return Ok(None);
    }
    let known = plausible_timezone_name(&device)
        && sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS(SELECT 1 FROM pg_timezone_names WHERE name=$1)",
        )
        .bind(&device)
        .fetch_one(&mut **tx)
        .await?;
    if !known {
        tracing::warn!(
            timezone = %device,
            "recording device reports a timezone PostgreSQL does not know; morning email keeps its schedule"
        );
        return Ok(None);
    }
    // The next 07:00 in the device zone: today if it has not passed, else
    // tomorrow. LEAST ignores a NULL (unscheduled) due time and never delays an
    // already scheduled morning.
    sqlx::query(
        "UPDATE morning_email_schedules SET timezone=$2, \
            next_due_at=LEAST(next_due_at, \
              CASE WHEN (clock_timestamp() AT TIME ZONE $2)::time<time '07:00' \
                   THEN ((clock_timestamp() AT TIME ZONE $2)::date+time '07:00') AT TIME ZONE $2 \
                   ELSE (((clock_timestamp() AT TIME ZONE $2)::date+1)+time '07:00') AT TIME ZONE $2 END), \
            updated_at=clock_timestamp() WHERE account_id=$1",
    )
    .bind(account_id)
    .bind(&device)
    .execute(&mut **tx)
    .await?;
    tracing::info!(
        timezone = %device,
        bootstrapped = current.is_none(),
        "morning email follows the recording device timezone"
    );
    Ok(Some(device))
}

pub(super) async fn next_candidate(
    repository: &PostgresPersistence,
    account_id: &str,
) -> Result<Option<EmailDeliveryCandidate>> {
    let mut tx = repository.pool().begin().await?;
    lock_account(&mut tx, account_id).await?;
    // Following is best effort: a transient failure here must not cost the
    // account its pending delivery for this sweep.
    if let Err(error) = follow_recording_timezone(&mut tx, account_id).await {
        tracing::warn!(error = %error, "could not follow the recording device timezone");
    }
    // A definitive rejection may retry only its frozen request and only inside
    // the provider idempotency window. Never rebuild a possibly submitted body.
    let expired = sqlx::query_scalar::<_,String>("UPDATE morning_email_deliveries SET state='failed',error_code='retry_window_expired',updated_at=clock_timestamp() \
        WHERE account_id=$1 AND state='retry_wait' AND first_send_at<=clock_timestamp()-interval '23 hours' RETURNING delivery_id")
        .bind(account_id).fetch_all(&mut *tx).await?;
    for id in expired {
        sqlx::query("UPDATE morning_email_sources SET state='failed',updated_at=clock_timestamp() WHERE account_id=$1 AND delivery_id=$2 AND state='pending'")
            .bind(account_id).bind(id).execute(&mut *tx).await?;
    }
    if let Some(candidate) = read_candidate(&mut tx, account_id).await? {
        tx.commit().await?;
        return Ok(Some(candidate));
    }
    if let Some(delivery_id)=sqlx::query_scalar::<_,String>("SELECT delivery_id FROM morning_email_deliveries WHERE account_id=$1 AND state='assembling' ORDER BY delivery_date LIMIT 1")
        .bind(account_id).fetch_optional(&mut *tx).await? {
        let candidate=continue_assembly(&mut tx,account_id,&delivery_id).await?;
        tx.commit().await?;return Ok(candidate);
    }
    let schedule = sqlx::query("SELECT s.timezone,(clock_timestamp() AT TIME ZONE s.timezone)::date::text AS delivery_date, \
        p.updated_at::text AS consent_revision,p.include_content,a.email \
        FROM morning_email_schedules s JOIN episode_email_preferences p ON p.account_id=s.account_id \
        JOIN accounts a ON a.id=s.account_id WHERE s.account_id=$1 AND s.timezone IS NOT NULL \
        AND s.next_due_at<=clock_timestamp() AND (clock_timestamp() AT TIME ZONE s.timezone)::time>=time '07:00' \
        AND p.enabled AND a.status='active' FOR UPDATE OF s")
        .bind(account_id).fetch_optional(&mut *tx).await?;
    let Some(schedule) = schedule else {
        tx.commit().await?;
        return Ok(None);
    };
    let timezone: String = schedule.try_get("timezone")?;
    let date: String = schedule.try_get("delivery_date")?;
    let consent_revision: String = schedule.try_get("consent_revision")?;
    let preference_content: bool = schedule.try_get("include_content")?;
    let recipient: String = schedule.try_get("email")?;
    // Travel never reopens an already used local delivery date. Missed days are
    // combined at the next observed morning, not replayed as historical emails.
    sqlx::query("UPDATE morning_email_schedules SET next_due_at=(($2::date+1)+time '07:00') AT TIME ZONE timezone,updated_at=clock_timestamp() WHERE account_id=$1")
        .bind(account_id).bind(&date).execute(&mut *tx).await?;
    let exists: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM morning_email_deliveries WHERE account_id=$1 AND delivery_date=$2::date)")
        .bind(account_id).bind(&date).fetch_one(&mut *tx).await?;
    if exists {
        tx.commit().await?;
        return Ok(None);
    }
    // A later split can separate genuinely unsent evidence from a sent
    // predecessor. Withholding is a current-membership decision, never a send receipt.
    sqlx::query("UPDATE morning_email_sources s SET state='pending',updated_at=clock_timestamp() \
        FROM active_episode_members m WHERE s.account_id=$1 AND m.account_id=s.account_id \
        AND m.record_type=s.record_type AND m.record_id=s.record_id AND s.state='withheld_update' \
        AND NOT EXISTS(SELECT 1 FROM active_episode_members old JOIN morning_email_sources covered \
            ON covered.account_id=old.account_id AND covered.record_type=old.record_type AND covered.record_id=old.record_id \
            WHERE old.account_id=m.account_id AND old.episode_id=m.episode_id AND covered.state IN ('delivered','ambiguous','cancelled','failed'))")
        .bind(account_id).execute(&mut *tx).await?;
    // A sent source in the same current memory means this is an update, not a
    // new complete brief. Persist the unsent coverage without inventing an
    // automatic correction-email stream. Splits with wholly new sources remain eligible.
    sqlx::query("UPDATE morning_email_sources s SET state='withheld_update',updated_at=clock_timestamp() \
        FROM active_episode_members m WHERE s.account_id=$1 AND m.account_id=s.account_id \
        AND m.record_type=s.record_type AND m.record_id=s.record_id AND s.state='pending' AND s.delivery_id IS NULL \
        AND EXISTS(SELECT 1 FROM active_episode_members old JOIN morning_email_sources covered \
            ON covered.account_id=old.account_id AND covered.record_type=old.record_type AND covered.record_id=old.record_id \
            WHERE old.account_id=m.account_id AND old.episode_id=m.episode_id AND covered.state IN ('delivered','ambiguous','withheld_update','cancelled','failed'))")
        .bind(account_id).execute(&mut *tx).await?;
    let snapshot = DailyEmailSnapshot {
        delivery_date: date.clone(),
        timezone,
        consent_revision: consent_revision.clone(),
        episodes: Vec::new(),
        sources: Vec::new(),
        revisions: Vec::new(),
    };
    let delivery_id = format!("digest_{}", tokens::new_uuid());
    sqlx::query("INSERT INTO morning_email_deliveries(account_id,delivery_date,delivery_id,timezone,consent_revision,recipient_email,include_content,state,snapshot) \
        VALUES($1,$2::date,$3,$4,$5,$6,$7,'assembling',$8::jsonb)")
        .bind(account_id).bind(&date).bind(&delivery_id).bind(&snapshot.timezone).bind(&consent_revision).bind(&recipient)
        .bind(preference_content).bind(serde_json::to_string(&snapshot)?).execute(&mut *tx).await?;
    let candidate = continue_assembly(&mut tx, account_id, &delivery_id).await?;
    tx.commit().await?;
    Ok(candidate)
}

pub(super) async fn claim(
    repository: &PostgresPersistence,
    candidate: &EmailDeliveryCandidate,
    request: FrozenEmailDelivery,
    lease_seconds: i64,
) -> Result<Option<EmailDeliveryClaim>> {
    if !(1..=120).contains(&lease_seconds)
        || candidate.daily.is_none()
        || candidate.attempt_count >= 10
        || request.recipient_email != candidate.recipient_email
        || request.include_content != candidate.include_content
    {
        return Err(EnclaveError::Store("invalid morning email claim".into()));
    }
    for (value, maximum) in [
        (&request.recipient_email, 320),
        (&request.subject, 998),
        (&request.text_body, 8 * 1024 * 1024),
        (&request.html_body, 16 * 1024 * 1024),
    ] {
        if value.is_empty() || value.len() > maximum || value.contains('\0') {
            return Err(EnclaveError::Store(
                "morning email payload exceeds safe bounds".into(),
            ));
        }
    }
    let mut tx = repository.pool().begin().await?;
    lock_account(&mut tx, &candidate.account_id).await?;
    let current = read_candidate(&mut tx, &candidate.account_id).await?;
    if current.as_ref() != Some(candidate) {
        tx.commit().await?;
        return Ok(None);
    }
    let available = sqlx::query_scalar::<_,bool>("SELECT owner_token IS NULL AND next_send_at<=clock_timestamp() AND (circuit_until IS NULL OR circuit_until<=clock_timestamp()) \
        FROM provider_send_lanes WHERE provider='email' FOR UPDATE")
        .fetch_one(&mut *tx).await?;
    if !available {
        tx.commit().await?;
        return Ok(None);
    }
    let old_request = sqlx::query_scalar::<_,Option<String>>("SELECT frozen_request::text FROM morning_email_deliveries WHERE account_id=$1 AND delivery_id=$2 FOR UPDATE")
        .bind(&candidate.account_id).bind(&candidate.delivery_id).fetch_one(&mut *tx).await?;
    let request = match old_request {
        Some(value) => {
            let frozen: FrozenEmailDelivery = serde_json::from_str(&value)?;
            if frozen != request {
                cancel_snapshot(&mut tx, &candidate.account_id, &candidate.delivery_id).await?;
                tx.commit().await?;
                return Ok(None);
            }
            frozen
        }
        None => request,
    };
    let token = tokens::new_uuid();
    let lease_ms: i64 = sqlx::query_scalar(
        "SELECT floor(extract(epoch FROM clock_timestamp()+make_interval(secs=>$1))*1000)::bigint",
    )
    .bind(lease_seconds as f64)
    .fetch_one(&mut *tx)
    .await?;
    sqlx::query("UPDATE morning_email_deliveries SET state='processing',attempt_count=attempt_count+1,claim_token=$3,completed_claim_token=NULL, \
        claim_until=to_timestamp($4::double precision/1000.0),frozen_request=$5::jsonb,first_send_at=coalesce(first_send_at,clock_timestamp()),updated_at=clock_timestamp() \
        WHERE account_id=$1 AND delivery_id=$2 AND state IN ('pending','retry_wait')")
        .bind(&candidate.account_id).bind(&candidate.delivery_id).bind(&token).bind(lease_ms).bind(serde_json::to_string(&request)?).execute(&mut *tx).await?;
    sqlx::query("INSERT INTO email_send_fences(account_id,delivery_id,claim_id,lease_expires_at,recipient_email,include_content) VALUES($1,$2,$3,to_timestamp($4::double precision/1000.0),$5,$6)")
        .bind(&candidate.account_id).bind(&candidate.delivery_id).bind(&token).bind(lease_ms).bind(&request.recipient_email).bind(request.include_content).execute(&mut *tx).await?;
    sqlx::query("UPDATE provider_send_lanes SET owner_token=$1,lease_until=to_timestamp($2::double precision/1000.0),updated_at=clock_timestamp() WHERE provider='email'")
        .bind(&token).bind(lease_ms).execute(&mut *tx).await?;
    tx.commit().await?;
    Ok(Some(EmailDeliveryClaim {
        account_id: candidate.account_id.clone(),
        episode_id: 0,
        delivery_version: 1,
        delivery_id: candidate.delivery_id.clone(),
        claim_token: token,
        lease_expires_at: isotime::format_epoch_millis(lease_ms),
        attempt_count: candidate.attempt_count + 1,
        request,
    }))
}

async fn release_fence(
    tx: &mut Transaction<'_>,
    account_id: &str,
    delivery_id: &str,
    token: &str,
    circuit_seconds: Option<i64>,
) -> Result<()> {
    sqlx::query(
        "DELETE FROM email_send_fences WHERE account_id=$1 AND delivery_id=$2 AND claim_id=$3",
    )
    .bind(account_id)
    .bind(delivery_id)
    .bind(token)
    .execute(&mut **tx)
    .await?;
    sqlx::query("UPDATE provider_send_lanes SET owner_token=NULL,lease_until=NULL,next_send_at=clock_timestamp()+interval '250 milliseconds', \
        circuit_until=CASE WHEN $2::double precision IS NULL THEN circuit_until ELSE clock_timestamp()+make_interval(secs=>$2) END,updated_at=clock_timestamp() \
        WHERE provider='email' AND owner_token=$1")
        .bind(token).bind(circuit_seconds.map(|v|v as f64)).execute(&mut **tx).await?;
    Ok(())
}

pub(super) async fn settle(
    repository: &PostgresPersistence,
    claim: &EmailDeliveryClaim,
    outcome: EmailProviderOutcome,
    circuit_seconds: Option<i64>,
) -> Result<()> {
    if !outcome.is_valid() || circuit_seconds.is_some_and(|v| !(1..=21600).contains(&v)) {
        return Err(EnclaveError::Store(
            "invalid morning email settlement".into(),
        ));
    }
    let mut tx = repository.pool().begin().await?;
    advisory_transaction_lock(&mut tx, "email-preference", &claim.account_id).await?;
    let row=sqlx::query("SELECT state,claim_token,completed_claim_token FROM morning_email_deliveries WHERE account_id=$1 AND delivery_id=$2 FOR UPDATE")
        .bind(&claim.account_id).bind(&claim.delivery_id).fetch_optional(&mut *tx).await?.ok_or_else(||EnclaveError::Conflict("morning email disappeared".into()))?;
    if row
        .try_get::<Option<String>, _>("completed_claim_token")?
        .as_deref()
        == Some(&claim.claim_token)
    {
        tx.commit().await?;
        return Ok(());
    }
    if row.try_get::<String, _>("state")? != "processing"
        || row.try_get::<Option<String>, _>("claim_token")?.as_deref() != Some(&claim.claim_token)
    {
        return Err(EnclaveError::Conflict(
            "morning email claim superseded".into(),
        ));
    }
    let fenced:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM email_send_fences WHERE account_id=$1 AND delivery_id=$2 AND claim_id=$3 AND recipient_email=$4 AND include_content=$5)")
        .bind(&claim.account_id).bind(&claim.delivery_id).bind(&claim.claim_token).bind(&claim.request.recipient_email).bind(claim.request.include_content).fetch_one(&mut *tx).await?;
    if !fenced {
        return Err(EnclaveError::Conflict(
            "morning email disclosure fence missing".into(),
        ));
    }
    let (state, status, provider_id, error, retry_at) = match outcome {
        EmailProviderOutcome::Accepted {
            status,
            provider_message_id,
        } => (
            "delivered",
            Some(status),
            Some(provider_message_id),
            None,
            None,
        ),
        EmailProviderOutcome::Retry {
            status,
            code,
            retry_at,
        } => (
            "retry_wait",
            status,
            None,
            Some(code),
            Some(
                isotime::parse_epoch_millis(&retry_at)
                    .ok_or_else(|| EnclaveError::Store("invalid retry timestamp".into()))?,
            ),
        ),
        EmailProviderOutcome::Ambiguous => (
            "ambiguous",
            None,
            None,
            Some("outcome_unknown".to_owned()),
            None,
        ),
        EmailProviderOutcome::Failed { status, code } => ("failed", status, None, Some(code), None),
    };
    sqlx::query("UPDATE morning_email_deliveries SET state=$3,completed_claim_token=claim_token,claim_token=NULL,claim_until=NULL, \
        response_status=$4,provider_message_id=$5,error_code=$6,next_attempt_at=coalesce(to_timestamp($7::double precision/1000.0),next_attempt_at),updated_at=clock_timestamp() \
        WHERE account_id=$1 AND delivery_id=$2")
        .bind(&claim.account_id).bind(&claim.delivery_id).bind(state).bind(status).bind(provider_id).bind(error).bind(retry_at).execute(&mut *tx).await?;
    if state != "retry_wait" {
        sqlx::query("UPDATE morning_email_sources SET state=$3,updated_at=clock_timestamp() WHERE account_id=$1 AND delivery_id=$2 AND state='pending'")
            .bind(&claim.account_id).bind(&claim.delivery_id).bind(state).execute(&mut *tx).await?;
    }
    release_fence(
        &mut tx,
        &claim.account_id,
        &claim.delivery_id,
        &claim.claim_token,
        circuit_seconds,
    )
    .await?;
    tx.commit().await?;
    Ok(())
}

/// Narrow transport fixtures use a preselected historical day; calendar/source
/// scheduling is exercised separately by the real PostgreSQL daily contracts.
#[cfg(test)]
pub(super) async fn seed_candidate_for_contract(
    repository: &PostgresPersistence,
    account_id: &str,
    episode_id: i64,
    date: &str,
) {
    let mut tx = repository.pool().begin().await.unwrap();
    let episode = load_episode(&mut tx, account_id, episode_id)
        .await
        .unwrap()
        .unwrap();
    let members = sources(&mut tx, account_id, episode_id).await.unwrap();
    let (consent,email)=sqlx::query_as::<_,(String,String)>("SELECT p.updated_at::text,a.email FROM episode_email_preferences p JOIN accounts a ON a.id=p.account_id WHERE p.account_id=$1")
        .bind(account_id).fetch_one(&mut *tx).await.unwrap();
    let snapshot = DailyEmailSnapshot {
        delivery_date: date.into(),
        timezone: "UTC".into(),
        consent_revision: consent.clone(),
        episodes: vec![episode],
        sources: members,
        revisions: vec![(
            episode_id,
            brief_revision(&mut tx, account_id, episode_id)
                .await
                .unwrap()
                .unwrap(),
        )],
    };
    sqlx::query("INSERT INTO morning_email_deliveries(account_id,delivery_date,delivery_id,timezone,consent_revision,recipient_email,include_content,state,snapshot) VALUES($1,$2::date,$3,'UTC',$4,$5,true,'pending',$6::jsonb)")
        .bind(account_id).bind(date).bind(format!("digest_{}",tokens::new_uuid())).bind(consent).bind(email).bind(serde_json::to_string(&snapshot).unwrap()).execute(&mut *tx).await.unwrap();
    tx.commit().await.unwrap();
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::persistence::{MemoryQueryRepository, NotificationRepository};

    async fn account(repo: &PostgresPersistence, id: &str) {
        sqlx::query("INSERT INTO accounts(id,email,primary_provider,primary_subject) VALUES($1,$2,'google',$1)")
            .bind(id).bind(format!("{id}@example.com")).execute(repo.pool()).await.unwrap();
    }
    async fn memory(repo: &PostgresPersistence, account: &str, id: i64, complete: bool) {
        sqlx::query("INSERT INTO screenshots(account_id,id,captured_at,ocr_text,source_key) VALUES($1,$2,clock_timestamp()-interval '2 days','synthetic private evidence',$3)")
            .bind(account).bind(id).bind(format!("shot-{id}")).execute(repo.pool()).await.unwrap();
        sqlx::query("INSERT INTO episodes(account_id,id,started_at,ended_at,title,summary,finalized_at,finalization_status) \
            VALUES($1,$2,clock_timestamp()-interval '2 days 1 hour',clock_timestamp()-interval '2 days',$3,'summary',clock_timestamp(),$4)")
            .bind(account).bind(id).bind(format!("Private memory {id}")).bind(if complete{"complete"}else{"queued"}).execute(repo.pool()).await.unwrap();
        sqlx::query("INSERT INTO episode_members(account_id,episode_id,record_type,record_id) VALUES($1,$2,'screenshot',$2)")
            .bind(account).bind(id).execute(repo.pool()).await.unwrap();
        sqlx::query("INSERT INTO episode_final_briefs(account_id,episode_id,overview,decisions,action_items,important_links,open_questions) \
            VALUES($1,$2,'A complete synthetic brief','[]','[]','[]','[]')")
            .bind(account).bind(id).execute(repo.pool()).await.unwrap();
        let mut tx = repo.pool().begin().await.unwrap();
        enqueue_brief(&mut tx, account, id, true).await.unwrap();
        tx.commit().await.unwrap();
    }
    fn request(candidate: &EmailDeliveryCandidate) -> FrozenEmailDelivery {
        let daily = candidate.daily.as_ref().unwrap();
        let (subject, text_body, html_body) = crate::cp::email_renderer::render_morning_email(
            &daily.episodes,
            candidate.include_content,
            &daily.delivery_date,
            &daily.timezone,
            "https://app.example",
        );
        FrozenEmailDelivery {
            recipient_email: candidate.recipient_email.clone(),
            include_content: candidate.include_content,
            subject,
            text_body,
            html_body,
        }
    }
    async fn due(repo: &PostgresPersistence, account: &str) {
        sqlx::query("UPDATE morning_email_schedules SET next_due_at=clock_timestamp()-interval '1 minute' WHERE account_id=$1")
            .bind(account).execute(repo.pool()).await.unwrap();
        sqlx::query("UPDATE provider_send_lanes SET owner_token=NULL,lease_until=NULL,next_send_at=clock_timestamp(),circuit_until=NULL WHERE provider='email'")
            .execute(repo.pool()).await.unwrap();
    }
    async fn tomorrow_fixture(repo: &PostgresPersistence, account: &str) {
        // Advance prior logical dates, leaving source dispositions untouched.
        sqlx::query("UPDATE morning_email_deliveries SET delivery_date=(SELECT min(delivery_date)-1 FROM morning_email_deliveries WHERE account_id=$1) WHERE account_id=$1 AND delivery_date=(SELECT max(delivery_date) FROM morning_email_deliveries WHERE account_id=$1)")
            .bind(account).execute(repo.pool()).await.unwrap();
        due(repo, account).await;
    }

    async fn recording(repo: &PostgresPersistence, account: &str, n: i64, zone: &str) {
        // One capture session/stream/event per recording; `received_at` is
        // the server clock, so a later recording is newer than any earlier
        // schedule change made in this test.
        sqlx::query("INSERT INTO capture_sessions(account_id,id,device_id,install_id,started_at,last_event_at,ended_at,schema_version,created_at) \
            VALUES($1,$2,'device','install',clock_timestamp(),clock_timestamp(),clock_timestamp(),2,clock_timestamp())")
            .bind(account).bind(format!("session-{n}")).execute(repo.pool()).await.unwrap();
        sqlx::query("INSERT INTO capture_streams(account_id,id,capture_session_id,device_id,stream_kind) VALUES($1,$2,$3,'device','mac_screen')")
            .bind(account).bind(format!("stream-{n}")).bind(format!("session-{n}")).execute(repo.pool()).await.unwrap();
        sqlx::query("INSERT INTO capture_events(account_id,event_id,device_id,install_id,capture_session_id,stream_id,stream_kind,sequence, \
            source_wall_at,source_monotonic_ns,started_at,ended_at,timezone_id,utc_offset_minutes,clock_uncertainty_ms,asset_id,manifest_digest,media_disposition,received_at) \
            VALUES($1,$2,'device','install',$3,$4,'mac_screen',1,clock_timestamp(),'0',clock_timestamp(),clock_timestamp(),$5,0,0,$6,repeat('a',64),'canonical',clock_timestamp())")
            .bind(account).bind(format!("event-{n}")).bind(format!("session-{n}")).bind(format!("stream-{n}")).bind(zone).bind(format!("asset-{n}"))
            .execute(repo.pool()).await.unwrap();
    }
    async fn schedule_timezone(
        repo: &PostgresPersistence,
        account: &str,
    ) -> Option<Option<String>> {
        sqlx::query_scalar::<_, Option<String>>(
            "SELECT timezone FROM morning_email_schedules WHERE account_id=$1",
        )
        .bind(account)
        .fetch_optional(repo.pool())
        .await
        .unwrap()
    }

    async fn schedule_state(repo: &PostgresPersistence, account: &str) -> (String, String) {
        sqlx::query_as::<_, (String, String)>(
            "SELECT next_due_at::text,updated_at::text FROM morning_email_schedules WHERE account_id=$1",
        )
        .bind(account)
        .fetch_one(repo.pool())
        .await
        .unwrap()
    }
    async fn next_local_morning(repo: &PostgresPersistence, zone: &str) -> String {
        sqlx::query_scalar::<_, String>(
            "SELECT (CASE WHEN (clock_timestamp() AT TIME ZONE $1)::time<time '07:00' \
                THEN ((clock_timestamp() AT TIME ZONE $1)::date+time '07:00') AT TIME ZONE $1 \
                ELSE (((clock_timestamp() AT TIME ZONE $1)::date+1)+time '07:00') AT TIME ZONE $1 END)::text",
        )
        .bind(zone)
        .fetch_one(repo.pool())
        .await
        .unwrap()
    }
    async fn due_now(repo: &PostgresPersistence, account: &str) {
        sqlx::query("UPDATE morning_email_schedules SET next_due_at=clock_timestamp()-interval '1 minute' WHERE account_id=$1")
            .bind(account).execute(repo.pool()).await.unwrap();
    }

    /// The morning email follows the recording device: a missing zone is
    /// bootstrapped from the newest recording, later recordings re-follow the
    /// device, an explicit save wins until the next recording, unknown device
    /// zones are ignored, following never delays an already scheduled morning,
    /// and accounts without email have no schedule at all.
    #[tokio::test]
    async fn real_postgres_morning_email_follows_recording_device() {
        let Some(fixture) = super::super::tests::test_persistence().await else {
            return;
        };
        let repo = &fixture.persistence;
        account(repo, "tz-owner").await;
        account(repo, "tz-silent").await;
        let pref = repo
            .set_email_preference("tz-owner", true, false)
            .await
            .unwrap();
        assert_eq!(pref.timezone, None);
        assert_eq!(schedule_timezone(repo, "tz-owner").await, Some(None));
        // No recording yet: the sweep leaves the schedule paused.
        assert!(next_candidate(repo, "tz-owner").await.unwrap().is_none());
        assert_eq!(schedule_timezone(repo, "tz-owner").await, Some(None));
        // The first recording bootstraps the zone and schedules the next local morning.
        recording(repo, "tz-owner", 1, "Europe/Berlin").await;
        assert!(next_candidate(repo, "tz-owner").await.unwrap().is_none());
        assert_eq!(
            schedule_timezone(repo, "tz-owner").await,
            Some(Some("Europe/Berlin".into()))
        );
        let (due, _) = schedule_state(repo, "tz-owner").await;
        assert_eq!(due, next_local_morning(repo, "Europe/Berlin").await);
        // A later recording elsewhere moves the schedule with the device, and
        // only ever brings the due time forward.
        recording(repo, "tz-owner", 2, "America/New_York").await;
        assert!(next_candidate(repo, "tz-owner").await.unwrap().is_none());
        assert_eq!(
            schedule_timezone(repo, "tz-owner").await,
            Some(Some("America/New_York".into()))
        );
        let (due_after_move, _) = schedule_state(repo, "tz-owner").await;
        let earlier: bool = sqlx::query_scalar("SELECT $1::timestamptz<=$2::timestamptz")
            .bind(&due_after_move)
            .bind(&due)
            .fetch_one(repo.pool())
            .await
            .unwrap();
        assert!(earlier, "following never delays a scheduled morning");
        // Two devices disagreeing about the zone flip the schedule but cannot
        // push the due time out: after the follow step alone, an already due
        // morning is still due (the sweep then consumes it as usual).
        due_now(repo, "tz-owner").await;
        recording(repo, "tz-owner", 3, "Europe/Berlin").await;
        let mut tx = repo.pool().begin().await.unwrap();
        assert_eq!(
            follow_recording_timezone(&mut tx, "tz-owner")
                .await
                .unwrap()
                .as_deref(),
            Some("Europe/Berlin")
        );
        tx.commit().await.unwrap();
        let still_due: bool = sqlx::query_scalar(
            "SELECT next_due_at<=clock_timestamp() FROM morning_email_schedules WHERE account_id=$1",
        )
        .bind("tz-owner")
        .fetch_one(repo.pool())
        .await
        .unwrap();
        assert!(
            still_due,
            "a zone flip must not starve an already due delivery"
        );
        assert!(
            next_candidate(repo, "tz-owner").await.unwrap().is_none(),
            "no settled briefs yet"
        );
        assert_eq!(
            schedule_timezone(repo, "tz-owner").await,
            Some(Some("Europe/Berlin".into()))
        );
        // An explicit save is newer than every recording and therefore wins,
        // and any save (even one omitting the zone) counts as the last change.
        let pref = repo
            .set_email_preference_with_timezone("tz-owner", true, false, Some("UTC"))
            .await
            .unwrap();
        assert_eq!(pref.timezone.as_deref(), Some("UTC"));
        assert!(next_candidate(repo, "tz-owner").await.unwrap().is_none());
        assert_eq!(
            schedule_timezone(repo, "tz-owner").await,
            Some(Some("UTC".into()))
        );
        repo.set_email_preference("tz-owner", true, true)
            .await
            .unwrap();
        assert!(next_candidate(repo, "tz-owner").await.unwrap().is_none());
        assert_eq!(
            schedule_timezone(repo, "tz-owner").await,
            Some(Some("UTC".into()))
        );
        // ...until the next recording, which re-follows the device.
        recording(repo, "tz-owner", 4, "Asia/Tokyo").await;
        assert!(next_candidate(repo, "tz-owner").await.unwrap().is_none());
        assert_eq!(
            schedule_timezone(repo, "tz-owner").await,
            Some(Some("Asia/Tokyo".into()))
        );
        // Device zone names PostgreSQL does not know, and non-IANA aliases, are ignored.
        recording(repo, "tz-owner", 5, "Mars/Olympus").await;
        assert!(next_candidate(repo, "tz-owner").await.unwrap().is_none());
        assert_eq!(
            schedule_timezone(repo, "tz-owner").await,
            Some(Some("Asia/Tokyo".into()))
        );
        recording(repo, "tz-owner", 6, "posix/Europe/Paris").await;
        assert!(next_candidate(repo, "tz-owner").await.unwrap().is_none());
        assert_eq!(
            schedule_timezone(repo, "tz-owner").await,
            Some(Some("Asia/Tokyo".into()))
        );
        // The same zone again is a no-op: neither the due time nor the change
        // marker moves.
        let before = schedule_state(repo, "tz-owner").await;
        recording(repo, "tz-owner", 7, "Asia/Tokyo").await;
        assert!(next_candidate(repo, "tz-owner").await.unwrap().is_none());
        assert_eq!(before, schedule_state(repo, "tz-owner").await);
        // A device clock far in the future never pins the zone.
        sqlx::query("INSERT INTO capture_sessions(account_id,id,device_id,install_id,started_at,last_event_at,ended_at,schema_version,created_at) \
            VALUES($1,'session-future','device','install',clock_timestamp(),clock_timestamp(),clock_timestamp(),2,clock_timestamp())")
            .bind("tz-owner").execute(repo.pool()).await.unwrap();
        sqlx::query("INSERT INTO capture_streams(account_id,id,capture_session_id,device_id,stream_kind) VALUES($1,'stream-future','session-future','device','mac_screen')")
            .bind("tz-owner").execute(repo.pool()).await.unwrap();
        sqlx::query("INSERT INTO capture_events(account_id,event_id,device_id,install_id,capture_session_id,stream_id,stream_kind,sequence, \
            source_wall_at,source_monotonic_ns,started_at,ended_at,timezone_id,utc_offset_minutes,clock_uncertainty_ms,asset_id,manifest_digest,media_disposition,received_at) \
            VALUES($1,'event-future','device','install','session-future','stream-future','mac_screen',1,clock_timestamp(),'0', \
                   clock_timestamp()+interval '30 days',clock_timestamp()+interval '30 days','Pacific/Auckland',0,0,'asset-future',repeat('a',64),'canonical',clock_timestamp())")
            .bind("tz-owner").execute(repo.pool()).await.unwrap();
        assert!(next_candidate(repo, "tz-owner").await.unwrap().is_none());
        assert_eq!(
            schedule_timezone(repo, "tz-owner").await,
            Some(Some("Asia/Tokyo".into()))
        );
        recording(repo, "tz-owner", 8, "Europe/Berlin").await;
        assert!(next_candidate(repo, "tz-owner").await.unwrap().is_none());
        assert_eq!(
            schedule_timezone(repo, "tz-owner").await,
            Some(Some("Europe/Berlin".into())),
            "a sane recording after a future-clocked one is still followed"
        );
        // Recording without ever enabling email creates no schedule.
        recording(repo, "tz-silent", 9, "Europe/Berlin").await;
        assert!(next_candidate(repo, "tz-silent").await.unwrap().is_none());
        assert_eq!(schedule_timezone(repo, "tz-silent").await, None);
    }

    #[tokio::test]
    async fn real_postgres_morning_digest_contract() {
        let Some(fixture) = super::super::tests::test_persistence().await else {
            return;
        };
        let repo = &fixture.persistence;
        account(repo, "daily-owner").await;
        account(repo, "daily-empty").await;
        account(repo, "daily-private").await;
        account(repo, "daily-paged").await;
        let timezone:String=sqlx::query_scalar("SELECT name FROM pg_timezone_names WHERE name IN ('Pacific/Kiritimati','Pacific/Honolulu','UTC') \
            AND (clock_timestamp() AT TIME ZONE name)::time>=time '07:00' ORDER BY name LIMIT 1")
            .fetch_one(repo.pool()).await.unwrap();
        let pref = repo
            .set_email_preference("daily-owner", true, true)
            .await
            .unwrap();
        assert_eq!(pref.timezone, None);
        assert!(next_candidate(repo, "daily-owner").await.unwrap().is_none());
        assert!(repo
            .set_email_preference_with_timezone("daily-owner", true, true, Some("Mars/Olympus"))
            .await
            .is_err());
        let pref = repo
            .set_email_preference_with_timezone("daily-owner", true, true, Some(&timezone))
            .await
            .unwrap();
        assert_eq!(pref.timezone.as_deref(), Some(timezone.as_str()));
        assert!(
            next_candidate(repo, "daily-owner").await.unwrap().is_none(),
            "timezone starts at next local morning"
        );
        for id in 1..=3 {
            memory(repo, "daily-owner", id, id != 3).await;
        }
        due(repo, "daily-owner").await;
        let candidate = next_candidate(repo, "daily-owner").await.unwrap().unwrap();
        assert_eq!(candidate.daily.as_ref().unwrap().episodes.len(), 2);
        assert_eq!(candidate.daily.as_ref().unwrap().sources.len(), 2);
        assert!(candidate.include_content);
        assert!(candidate
            .daily
            .as_ref()
            .unwrap()
            .episodes
            .iter()
            .all(|e| e.episode_id != 3));
        let (one, two) = tokio::join!(
            claim(repo, &candidate, request(&candidate), 60),
            claim(repo, &candidate, request(&candidate), 60)
        );
        let claims = vec![one.unwrap(), two.unwrap()];
        assert_eq!(claims.iter().filter(|c| c.is_some()).count(), 1);
        let claimed = claims.into_iter().flatten().next().unwrap();
        assert!(
            sqlx::query("UPDATE accounts SET email='changed@example.com' WHERE id='daily-owner'")
                .execute(repo.pool())
                .await
                .is_err(),
            "canonical recipient is fenced during disclosure"
        );
        assert!(repo
            .set_email_preference("daily-owner", false, false)
            .await
            .is_err());
        assert!(sqlx::query("UPDATE episodes SET finalization_status='deleting' WHERE account_id='daily-owner' AND id=1").execute(repo.pool()).await.is_err());
        settle(
            repo,
            &claimed,
            EmailProviderOutcome::Accepted {
                status: 202,
                provider_message_id: "synthetic-provider-receipt".into(),
            },
            None,
        )
        .await
        .unwrap();
        settle(
            repo,
            &claimed,
            EmailProviderOutcome::Accepted {
                status: 202,
                provider_message_id: "synthetic-provider-receipt".into(),
            },
            None,
        )
        .await
        .unwrap();
        assert!(
            next_candidate(repo, "daily-owner").await.unwrap().is_none(),
            "one logical digest per date"
        );
        assert_eq!(sqlx::query_scalar::<_,i64>("SELECT count(*) FROM morning_email_sources WHERE account_id='daily-owner' AND state='delivered'").fetch_one(repo.pool()).await.unwrap(),2);

        // A resumed sent memory gets new source coverage, but never a replayed
        // full brief. A wholly unsent settled memory remains eligible tomorrow.
        sqlx::query("INSERT INTO screenshots(account_id,id,captured_at,ocr_text,source_key) VALUES('daily-owner',4,clock_timestamp()-interval '1 day','continuation','new-source')")
            .execute(repo.pool()).await.unwrap();
        sqlx::query("INSERT INTO episode_members(account_id,episode_id,record_type,record_id) VALUES('daily-owner',1,'screenshot',4)")
            .execute(repo.pool()).await.unwrap();
        let mut tx = repo.pool().begin().await.unwrap();
        enqueue_brief(&mut tx, "daily-owner", 1, true)
            .await
            .unwrap();
        tx.commit().await.unwrap();
        sqlx::query("UPDATE episodes SET finalization_status='complete' WHERE account_id='daily-owner' AND id=3")
            .execute(repo.pool()).await.unwrap();
        tomorrow_fixture(repo, "daily-owner").await;
        let deferred = next_candidate(repo, "daily-owner").await.unwrap().unwrap();
        assert_eq!(
            deferred
                .daily
                .as_ref()
                .unwrap()
                .episodes
                .iter()
                .map(|e| e.episode_id)
                .collect::<Vec<_>>(),
            vec![3]
        );
        assert_eq!(sqlx::query_scalar::<_,String>("SELECT state FROM morning_email_sources WHERE account_id='daily-owner' AND record_id=4").fetch_one(repo.pool()).await.unwrap(),"withheld_update");
        sqlx::query("UPDATE episodes SET title='Changed before freeze' WHERE account_id='daily-owner' AND id=3").execute(repo.pool()).await.unwrap();
        assert!(
            claim(repo, &deferred, request(&deferred), 60)
                .await
                .unwrap()
                .is_none(),
            "stale title/brief cannot freeze"
        );
        assert!(
            next_candidate(repo, "daily-owner").await.unwrap().is_none(),
            "no same-day catchup after changed snapshot"
        );

        // Content-free consent is enforced on the whole provider request.
        repo.set_email_preference_with_timezone("daily-private", true, false, Some(&timezone))
            .await
            .unwrap();
        memory(repo, "daily-private", 1, true).await;
        due(repo, "daily-private").await;
        let private = next_candidate(repo, "daily-private")
            .await
            .unwrap()
            .unwrap();
        let body = request(&private);
        assert!(!body.text_body.contains("Private memory"));
        assert!(!body.html_body.contains("synthetic brief"));
        assert!(body.text_body.contains("https://app.example/app"));
        let private_claim = claim(repo, &private, body, 60).await.unwrap().unwrap();
        sqlx::query("UPDATE morning_email_deliveries SET claim_until=clock_timestamp()-interval '1 second' WHERE account_id='daily-private'").execute(repo.pool()).await.unwrap();
        assert!(next_candidate(repo, "daily-private")
            .await
            .unwrap()
            .is_none());
        assert_eq!(
            sqlx::query_scalar::<_, String>(
                "SELECT state FROM morning_email_deliveries WHERE account_id='daily-private'"
            )
            .fetch_one(repo.pool())
            .await
            .unwrap(),
            "ambiguous"
        );
        assert!(
            settle(
                repo,
                &private_claim,
                EmailProviderOutcome::Accepted {
                    status: 202,
                    provider_message_id: "late-accept".into()
                },
                None
            )
            .await
            .is_ok(),
            "completed claim replay has no new effect"
        );

        repo.set_email_preference_with_timezone("daily-empty", true, true, Some(&timezone))
            .await
            .unwrap();
        memory(repo, "daily-empty", 1, false).await;
        due(repo, "daily-empty").await;
        assert!(next_candidate(repo, "daily-empty").await.unwrap().is_none());
        sqlx::query(
            "UPDATE episodes SET finalization_status='complete' WHERE account_id='daily-empty'",
        )
        .execute(repo.pool())
        .await
        .unwrap();
        assert!(
            next_candidate(repo, "daily-empty").await.unwrap().is_none(),
            "unfinished-only day cannot create catchup email"
        );
        assert_eq!(
            sqlx::query_scalar::<_, String>(
                "SELECT state FROM morning_email_deliveries WHERE account_id='daily-empty'"
            )
            .fetch_one(repo.pool())
            .await
            .unwrap(),
            "empty"
        );

        // A large stale prefix is scanned across durable sweeps. It cannot
        // hide a settled brief later in the same scheduled digest.
        repo.set_email_preference_with_timezone("daily-paged", true, true, Some(&timezone))
            .await
            .unwrap();
        for id in 1..=33 {
            memory(repo, "daily-paged", id, true).await;
        }
        sqlx::query(
            "DELETE FROM episode_final_briefs WHERE account_id='daily-paged' AND episode_id<=32",
        )
        .execute(repo.pool())
        .await
        .unwrap();
        due(repo, "daily-paged").await;
        assert!(next_candidate(repo, "daily-paged").await.unwrap().is_none());
        assert_eq!(
            sqlx::query_scalar::<_, String>(
                "SELECT state FROM morning_email_deliveries WHERE account_id='daily-paged'"
            )
            .fetch_one(repo.pool())
            .await
            .unwrap(),
            "assembling"
        );
        let paged = next_candidate(repo, "daily-paged").await.unwrap().unwrap();
        assert_eq!(
            paged
                .daily
                .as_ref()
                .unwrap()
                .episodes
                .iter()
                .map(|e| e.episode_id)
                .collect::<Vec<_>>(),
            vec![33]
        );
        assert_eq!(
            sqlx::query_scalar::<_, i64>(
                "SELECT count(*) FROM morning_email_deliveries WHERE account_id='daily-paged'"
            )
            .fetch_one(repo.pool())
            .await
            .unwrap(),
            1
        );

        // Once a split separates wholly unsent evidence from sent evidence,
        // the next morning's selection restores eligibility for that source.
        sqlx::query("INSERT INTO episodes(account_id,id,started_at,ended_at,title,summary,finalized_at,finalization_status) \
            SELECT account_id,5,started_at,ended_at,'New independent memory','summary',clock_timestamp(),'complete' FROM episodes WHERE account_id='daily-owner' AND id=1")
            .execute(repo.pool()).await.unwrap();
        sqlx::query("INSERT INTO episode_final_briefs(account_id,episode_id,overview) VALUES('daily-owner',5,'Wholly new source')").execute(repo.pool()).await.unwrap();
        sqlx::query("DELETE FROM episode_members WHERE account_id='daily-owner' AND episode_id=1 AND record_type='screenshot' AND record_id=4").execute(repo.pool()).await.unwrap();
        sqlx::query("INSERT INTO episode_members(account_id,episode_id,record_type,record_id) VALUES('daily-owner',5,'screenshot',4)").execute(repo.pool()).await.unwrap();
        tomorrow_fixture(repo, "daily-owner").await;
        let split = next_candidate(repo, "daily-owner").await.unwrap().unwrap();
        assert!(split
            .daily
            .as_ref()
            .unwrap()
            .episodes
            .iter()
            .any(|e| e.episode_id == 5));
        assert_eq!(sqlx::query_scalar::<_,String>("SELECT state FROM morning_email_sources WHERE account_id='daily-owner' AND record_id=4").fetch_one(repo.pool()).await.unwrap(),"pending");

        // Changing timezone affects future dates; disabled eligibility stays revoked.
        let before: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM morning_email_deliveries WHERE account_id='daily-owner'",
        )
        .fetch_one(repo.pool())
        .await
        .unwrap();
        repo.set_email_preference_with_timezone("daily-owner", false, false, Some("Europe/Paris"))
            .await
            .unwrap();
        assert_eq!(
            repo.get_email_preference("daily-owner")
                .await
                .unwrap()
                .timezone
                .as_deref(),
            Some("Europe/Paris")
        );
        assert_eq!(sqlx::query_scalar::<_,i64>("SELECT count(*) FROM morning_email_sources WHERE account_id='daily-owner' AND state='pending'").fetch_one(repo.pool()).await.unwrap(),0);
        assert_eq!(
            sqlx::query_scalar::<_, i64>(
                "SELECT count(*) FROM morning_email_deliveries WHERE account_id='daily-owner'"
            )
            .fetch_one(repo.pool())
            .await
            .unwrap(),
            before
        );
        let exported = repo.export("daily-owner").await.unwrap();
        assert!(exported["morning_email_sources"]
            .as_array()
            .unwrap()
            .iter()
            .any(|r| r["record_id"] == 4 && r["state"] == "cancelled"));
        assert_eq!(
            exported["morning_email_schedules"][0]["timezone"],
            "Europe/Paris"
        );
        // Cached complete plaintext is erased on memory deletion; durable date remains.
        sqlx::query("UPDATE episodes SET finalization_status='deleting' WHERE account_id='daily-owner' AND id=1").execute(repo.pool()).await.unwrap();
        assert_eq!(sqlx::query_scalar::<_,String>("SELECT snapshot::text FROM morning_email_deliveries WHERE account_id='daily-owner' AND state='delivered'").fetch_one(repo.pool()).await.unwrap(),"{}");
        sqlx::query("DELETE FROM accounts WHERE id='daily-owner'")
            .execute(repo.pool())
            .await
            .unwrap();
        for table in [
            "morning_email_schedules",
            "morning_email_deliveries",
            "morning_email_sources",
        ] {
            assert_eq!(
                sqlx::query_scalar::<_, i64>(sqlx::AssertSqlSafe(format!(
                    "SELECT count(*) FROM {table} WHERE account_id='daily-owner'"
                )))
                .fetch_one(repo.pool())
                .await
                .unwrap(),
                0
            );
        }
        // Local 7am follows both DST offsets and ordinary international offsets.
        for (date, zone, expected) in [
            ("2026-03-08", "America/New_York", "2026-03-08T11:00:00.000Z"),
            ("2026-11-01", "America/New_York", "2026-11-01T12:00:00.000Z"),
            ("2026-07-01", "America/Chicago", "2026-07-01T12:00:00.000Z"),
            (
                "2026-07-01",
                "America/Los_Angeles",
                "2026-07-01T14:00:00.000Z",
            ),
            ("2026-10-25", "Europe/Paris", "2026-10-25T06:00:00.000Z"),
        ] {
            let millis:i64=sqlx::query_scalar("SELECT floor(extract(epoch FROM (($1::date+time '07:00') AT TIME ZONE $2))*1000)::bigint")
                .bind(date).bind(zone).fetch_one(repo.pool()).await.unwrap();
            assert_eq!(isotime::format_epoch_millis(millis), expected);
        }
        repo.pool().close().await;
        sqlx::query(sqlx::AssertSqlSafe(format!(
            "DROP SCHEMA {} CASCADE",
            fixture.schema
        )))
        .execute(fixture.base.pool())
        .await
        .unwrap();
        fixture.base.pool().close().await;
    }
}
