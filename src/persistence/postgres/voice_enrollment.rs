//! Owner enrollment decisions, withdrawal and source-lifetime maintenance.
use super::{owner_enrollment_policy as policy, owner_voice, voice_identity, PostgresPersistence};
use crate::{
    cp::{
        isotime,
        voice_memory::EMBEDDING_SPACE,
        voice_quality::{QUALITY_VERSION, SCORER_VERSION},
    },
    error::{EnclaveError, Result},
    persistence::{
        OwnerVoiceDomainStatus, OwnerVoiceEnrollmentAttempt, OwnerVoiceEnrollmentStatus,
        VoiceEnrollmentReason, VoiceEnrollmentState,
    },
};
use sqlx::{Postgres, Row, Transaction};

const SESSION_BATCH: i64 = 8;
const OBSERVATION_LIMIT: i64 = 4096;

async fn status_in_transaction(
    tx: &mut Transaction<'_, Postgres>,
    account: &str,
) -> Result<OwnerVoiceEnrollmentStatus> {
    let revision: i64 = sqlx::query_scalar(
        "SELECT enrollment_revision FROM accounts WHERE id=$1 AND status='active'",
    )
    .bind(account)
    .fetch_optional(&mut **tx)
    .await?
    .ok_or(EnclaveError::NotFound)?;
    let domains:Vec<String>=sqlx::query_scalar("SELECT channel_domain FROM voice_enrollment_sessions WHERE account_id=$1 AND channel_domain IS NOT NULL UNION SELECT p.channel_domain FROM voice_profiles p JOIN people owner ON owner.account_id=p.account_id AND owner.id=p.person_id AND owner.status='owner' WHERE p.account_id=$1 ORDER BY channel_domain")
        .bind(account).fetch_all(&mut **tx).await?;
    let mut projection = Vec::with_capacity(domains.len());
    for domain in domains {
        let recognized = owner_voice::domain_recognized(tx, account, &domain).await?;
        projection.push(OwnerVoiceDomainStatus {
            channel_domain: domain,
            recognized,
        });
    }
    let latest=sqlx::query("SELECT state,reason,channel_domain,floor(extract(epoch FROM updated_at)*1000)::bigint updated_ms FROM voice_enrollment_sessions WHERE account_id=$1 ORDER BY created_at DESC,capture_session_id DESC LIMIT 1")
        .bind(account).fetch_optional(&mut **tx).await?;
    let latest_attempt = latest
        .map(|row| {
            Ok::<_, EnclaveError>(OwnerVoiceEnrollmentAttempt {
                state: VoiceEnrollmentState::parse(&row.try_get::<String, _>("state")?)?,
                reason: row
                    .try_get::<Option<String>, _>("reason")?
                    .as_deref()
                    .map(VoiceEnrollmentReason::parse)
                    .transpose()?,
                channel_domain: row.try_get("channel_domain")?,
                updated_at: isotime::format_epoch_millis(row.try_get("updated_ms")?),
            })
        })
        .transpose()?;
    Ok(OwnerVoiceEnrollmentStatus {
        enrollment_revision: revision,
        domains: projection,
        latest_attempt,
    })
}

pub(super) async fn status(
    repo: &PostgresPersistence,
    account: &str,
) -> Result<OwnerVoiceEnrollmentStatus> {
    // Expiry must be truthful even when the model or rollout is unavailable.
    maintain(repo, account).await?;
    let mut tx = repo.pool().begin().await?;
    sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
        .execute(&mut *tx)
        .await?;
    let status = status_in_transaction(&mut tx, account).await?;
    tx.commit().await?;
    Ok(status)
}

pub(super) async fn erase_samples(
    tx: &mut Transaction<'_, Postgres>,
    account: &str,
    samples: &[i64],
) -> Result<()> {
    if samples.is_empty() {
        return Ok(());
    }
    super::identity_presentation::initialize_account_semantics(tx, account).await?;
    let profiles:Vec<i64>=sqlx::query_scalar("SELECT profile_id FROM voice_sample_profile_assignments WHERE account_id=$1 AND sample_id=ANY($2::bigint[]) UNION SELECT voice_profile_id FROM voice_samples WHERE account_id=$1 AND id=ANY($2::bigint[]) AND voice_profile_id IS NOT NULL ORDER BY profile_id")
        .bind(account).bind(samples).fetch_all(&mut **tx).await?;
    let clusters:Vec<i64>=sqlx::query_scalar("SELECT DISTINCT o.cluster_id FROM speaker_observations o JOIN voice_samples sample ON sample.account_id=o.account_id AND sample.speaker_observation_id=o.id WHERE sample.account_id=$1 AND sample.id=ANY($2::bigint[]) AND o.cluster_id IS NOT NULL ORDER BY o.cluster_id")
        .bind(account).bind(samples).fetch_all(&mut **tx).await?;
    let events: Vec<String> = sqlx::query_scalar("SELECT o.event_id FROM speaker_observations o JOIN voice_samples s ON s.account_id=o.account_id AND s.speaker_observation_id=o.id WHERE s.account_id=$1 AND s.id=ANY($2::bigint[]) UNION SELECT part.event_id FROM speaker_observation_sources part JOIN voice_samples s ON s.account_id=part.account_id AND s.speaker_observation_id=part.speaker_observation_id WHERE s.account_id=$1 AND s.id=ANY($2::bigint[])")
        .bind(account).bind(samples).fetch_all(&mut **tx).await?;
    let name_profiles =
        super::identity_fusion::profiles_depending_on_events(tx, account, &events).await?;
    let fact_people =
        super::identity_fusion::fact_people_depending_on_events(tx, account, &events).await?;
    let mut targets =
        voice_identity::affected_speaker_projection_targets(tx, account, &clusters, &profiles, &[])
            .await?;
    targets.extend(
        voice_identity::affected_speaker_projection_targets(tx, account, &[], &name_profiles, &[])
            .await?,
    );
    owner_voice::clear_sample_attribution(tx, account, samples).await?;
    sqlx::query("DELETE FROM voice_samples WHERE account_id=$1 AND id=ANY($2::bigint[])")
        .bind(account)
        .bind(samples)
        .execute(&mut **tx)
        .await?;
    // Clear source-cluster fallbacks before the canonical projection refresh.
    owner_voice::refresh_clusters(tx, account, &clusters).await?;
    voice_identity::recompute_erased_profiles(
        tx,
        account,
        &voice_identity::VoiceErasureAffected {
            profiles,
            name_profiles,
            fact_people,
            targets,
        },
    )
    .await?;
    Ok(())
}

/// A late source only withdraws this enrollment's contribution. The account's
/// older valid enrollment in another session is never overwritten by its state.
pub(super) async fn invalidate_owner_enrollment(
    tx: &mut Transaction<'_, Postgres>,
    account: &str,
    session: &str,
    reason: VoiceEnrollmentReason,
) -> Result<()> {
    let row=sqlx::query("SELECT state,reason,channel_domain FROM voice_enrollment_sessions WHERE account_id=$1 AND capture_session_id=$2 FOR UPDATE")
        .bind(account).bind(session).fetch_optional(&mut **tx).await?;
    let Some(row) = row else {
        return Ok(());
    };
    let existing_reason: Option<String> = row.try_get("reason")?;
    let expired = row.try_get::<String, _>("state")? == "expired";
    if existing_reason
        .as_deref()
        .is_some_and(|r| matches!(r, "forgotten" | "enrollment_revoked"))
    {
        return Ok(());
    }
    // Source churn cannot undo withdrawal or a sticky capture violation.
    if reason == VoiceEnrollmentReason::SourceChanged
        && (expired
            || existing_reason.as_deref().is_some_and(|r| {
                !matches!(
                    r,
                    "source_changed"
                        | "no_speech"
                        | "no_eligible_sample"
                        | "no_dominant_voice"
                        | "overlapping_speech"
                        | "processing_failed"
                )
            }))
    {
        return Ok(());
    }
    let samples:Vec<i64>=sqlx::query_scalar("SELECT DISTINCT sample.id FROM voice_samples sample JOIN speaker_observations o ON o.account_id=sample.account_id AND o.id=sample.speaker_observation_id JOIN capture_events event ON event.account_id=o.account_id AND event.event_id=o.event_id WHERE sample.account_id=$1 AND event.capture_session_id=$2 AND EXISTS(SELECT 1 FROM voice_sample_profile_assignments assignment JOIN voice_profiles profile ON profile.account_id=assignment.account_id AND profile.id=assignment.profile_id JOIN people owner ON owner.account_id=profile.account_id AND owner.id=profile.person_id AND owner.status='owner' WHERE assignment.account_id=sample.account_id AND assignment.sample_id=sample.id) ORDER BY sample.id")
        .bind(account).bind(session).fetch_all(&mut **tx).await?;
    erase_samples(tx, account, &samples).await?;
    let (state, reason_value) = match reason {
        VoiceEnrollmentReason::SourceChanged => ("processing", None),
        VoiceEnrollmentReason::RawMediaExpired
        | VoiceEnrollmentReason::SourceDeleted
        | VoiceEnrollmentReason::Forgotten => ("expired", Some(reason.as_str())),
        _ => ("inconclusive", Some(reason.as_str())),
    };
    sqlx::query("UPDATE voice_enrollment_sessions SET state=$3,reason=$4,dominant_share=NULL,accepted_sample_count=0,voice_profile_id=NULL,source_revision=NULL,seal_generation=NULL,updated_at=clock_timestamp() WHERE account_id=$1 AND capture_session_id=$2")
        .bind(account).bind(session).bind(state).bind(reason_value).execute(&mut **tx).await?;
    if let Some(domain) = row.try_get::<Option<String>, _>("channel_domain")? {
        owner_voice::refresh_domains(tx, account, &[domain]).await?;
    }
    // Invalidated source samples may be embedded afresh only for a still-valid
    // session decision. Withdrawn sessions cannot recreate the owner graph.
    if reason == VoiceEnrollmentReason::SourceChanged {
        sqlx::query("UPDATE voice_embedding_jobs j SET state='pending',attempt_count=0,next_attempt_at=NULL,lease_owner=NULL,lease_token=NULL,lease_until=NULL,error_code=NULL,updated_at=clock_timestamp() FROM speaker_observations o JOIN capture_events e ON e.account_id=o.account_id AND e.event_id=o.event_id WHERE j.account_id=$1 AND o.account_id=j.account_id AND o.id=j.speaker_observation_id AND e.capture_session_id=$2 AND NOT EXISTS(SELECT 1 FROM voice_samples s WHERE s.account_id=o.account_id AND s.speaker_observation_id=o.id) AND j.state='ready'")
            .bind(account).bind(session).execute(&mut **tx).await?;
        sqlx::query("UPDATE speaker_observations o SET embedding_status='pending' FROM voice_embedding_jobs j WHERE o.account_id=$1 AND j.account_id=o.account_id AND j.speaker_observation_id=o.id AND j.state='pending' AND EXISTS(SELECT 1 FROM capture_events event WHERE event.account_id=o.account_id AND event.event_id=o.event_id AND event.capture_session_id=$2)")
            .bind(account).bind(session).execute(&mut **tx).await?;
    }
    Ok(())
}

pub(super) async fn expire_sessions_for_events(
    tx: &mut Transaction<'_, Postgres>,
    account: &str,
    events: &[String],
) -> Result<()> {
    let sessions:Vec<String>=sqlx::query_scalar("SELECT DISTINCT enrollment.capture_session_id FROM voice_enrollment_sessions enrollment JOIN capture_events event ON event.account_id=enrollment.account_id AND event.capture_session_id=enrollment.capture_session_id WHERE enrollment.account_id=$1 AND event.event_id=ANY($2::text[]) AND enrollment.state<>'expired' ORDER BY enrollment.capture_session_id")
        .bind(account).bind(events).fetch_all(&mut **tx).await?;
    // Do not erase other samples from this session: the caller removes exact
    // event-derived samples, then recomputes the shared owner profile.
    sqlx::query("UPDATE voice_enrollment_sessions SET state='expired',reason='source_deleted',dominant_share=NULL,accepted_sample_count=0,voice_profile_id=NULL,updated_at=clock_timestamp() WHERE account_id=$1 AND capture_session_id=ANY($2::text[])")
        .bind(account).bind(&sessions).execute(&mut **tx).await?;
    Ok(())
}

pub(super) async fn forget(
    repo: &PostgresPersistence,
    account: &str,
) -> Result<OwnerVoiceEnrollmentStatus> {
    let mut tx = repo.pool().begin().await?;
    if !voice_identity::lock_account(&mut tx, account).await? {
        return Err(EnclaveError::NotFound);
    }
    sqlx::query("UPDATE accounts SET enrollment_revision=enrollment_revision+1 WHERE id=$1")
        .bind(account)
        .execute(&mut *tx)
        .await?;
    let profiles:Vec<i64>=sqlx::query_scalar("SELECT profile.id FROM voice_profiles profile JOIN people owner ON owner.account_id=profile.account_id AND owner.id=profile.person_id AND owner.status='owner' WHERE profile.account_id=$1 ORDER BY profile.id")
        .bind(account).fetch_all(&mut *tx).await?;
    let domains:Vec<String>=sqlx::query_scalar("SELECT channel_domain FROM voice_profiles WHERE account_id=$1 AND id=ANY($2::bigint[]) UNION SELECT channel_domain FROM voice_enrollment_sessions WHERE account_id=$1 AND channel_domain IS NOT NULL ORDER BY channel_domain")
        .bind(account).bind(&profiles).fetch_all(&mut *tx).await?;
    // Unpublished enrollment candidates are also withdrawn; successful
    // sessions' other participants and unmarked recordings keep their evidence.
    let samples:Vec<i64>=sqlx::query_scalar("SELECT sample_id FROM voice_sample_profile_assignments WHERE account_id=$1 AND profile_id=ANY($2::bigint[]) UNION SELECT id AS sample_id FROM voice_samples WHERE account_id=$1 AND voice_profile_id=ANY($2::bigint[]) UNION SELECT sample.id AS sample_id FROM voice_samples sample JOIN speaker_observations o ON o.account_id=sample.account_id AND o.id=sample.speaker_observation_id JOIN capture_events event ON event.account_id=o.account_id AND event.event_id=o.event_id JOIN voice_enrollment_sessions enrollment ON enrollment.account_id=event.account_id AND enrollment.capture_session_id=event.capture_session_id WHERE sample.account_id=$1 AND enrollment.designated AND enrollment.state IN ('recording','processing','inconclusive') ORDER BY sample_id")
        .bind(account).bind(&profiles).fetch_all(&mut *tx).await?;

    let targets =
        voice_identity::affected_speaker_projection_targets(&mut tx, account, &[], &profiles, &[])
            .await?;
    sqlx::query("UPDATE voice_enrollment_sessions SET state='expired',reason='forgotten',dominant_share=NULL,accepted_sample_count=0,voice_profile_id=NULL,source_revision=NULL,seal_generation=NULL,updated_at=clock_timestamp() WHERE account_id=$1")
        .bind(account).execute(&mut *tx).await?;
    // Revoke existing work in the same transaction; stale marked uploads that
    // arrive later are rejected by the revision predicate at claim/settlement.
    sqlx::query("WITH canceled AS (UPDATE voice_embedding_jobs j SET state='failed',error_code='enrollment_revoked',lease_owner=NULL,lease_token=NULL,lease_until=NULL,next_attempt_at=NULL,updated_at=clock_timestamp() FROM speaker_observations o JOIN capture_events e ON e.account_id=o.account_id AND e.event_id=o.event_id JOIN voice_enrollment_sessions enrollment ON enrollment.account_id=e.account_id AND enrollment.capture_session_id=e.capture_session_id AND enrollment.designated WHERE j.account_id=$1 AND o.account_id=j.account_id AND o.id=j.speaker_observation_id AND j.state IN ('pending','processing','retry_wait') RETURNING j.speaker_observation_id) UPDATE speaker_observations o SET embedding_status='failed' FROM canceled WHERE o.account_id=$1 AND o.id=canceled.speaker_observation_id").bind(account).execute(&mut *tx).await?;
    erase_samples(&mut tx, account, &samples).await?;
    sqlx::query("DELETE FROM identity_evidence WHERE account_id=$1 AND (kind IN ('owner_enrollment','owner_voice') OR voice_profile_id=ANY($2::bigint[]))")
        .bind(account).bind(&profiles).execute(&mut *tx).await?;
    sqlx::query("UPDATE speaker_observations SET person_id=NULL,owner_evidence_id=NULL,voice_profile_id=NULL,voice_sample_id=NULL WHERE account_id=$1 AND person_id IN (SELECT id FROM people WHERE account_id=$1 AND status='owner')")
        .bind(account).execute(&mut *tx).await?;
    sqlx::query("DELETE FROM voice_profiles WHERE account_id=$1 AND id=ANY($2::bigint[])")
        .bind(account)
        .bind(&profiles)
        .execute(&mut *tx)
        .await?;
    sqlx::query("UPDATE speaker_clusters SET owner=false WHERE account_id=$1 AND owner")
        .bind(account)
        .execute(&mut *tx)
        .await?;
    super::speaker_identity::refresh_episode_speaker_projections(&mut tx, account, &targets, &[])
        .await?;
    owner_voice::refresh_domains(&mut tx, account, &domains).await?;
    let result = status_in_transaction(&mut tx, account).await?;
    tx.commit().await?;
    Ok(result)
}

pub(super) async fn maintain(repo: &PostgresPersistence, account: &str) -> Result<()> {
    let mut tx = repo.pool().begin().await?;
    if !voice_identity::lock_account(&mut tx, account).await? {
        return Err(EnclaveError::NotFound);
    }
    let deletion:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM episode_deletions WHERE account_id=$1 AND state='pending') OR EXISTS(SELECT 1 FROM orphan_capture_erasure_operations WHERE account_id=$1 AND capture_upload_fenced)")
        .bind(account).fetch_one(&mut *tx).await?;
    if deletion {
        tx.commit().await?;
        return Ok(());
    }
    // Owner maintenance settles enrollment status as well as its biometrics.
    // General voice maintenance also expires non-owner samples. A partially
    // surviving enrollment may still recognize its domain after recomputation.
    let expired_events:Vec<String>=sqlx::query_scalar("SELECT DISTINCT e.event_id FROM voice_enrollment_sessions enrollment JOIN capture_events e ON e.account_id=enrollment.account_id AND e.capture_session_id=enrollment.capture_session_id LEFT JOIN media_objects m ON m.account_id=e.account_id AND m.event_id=e.event_id WHERE enrollment.account_id=$1 AND enrollment.designated AND (enrollment.state<>'expired' OR EXISTS(SELECT 1 FROM voice_samples sample JOIN speaker_observations o ON o.account_id=sample.account_id AND o.id=sample.speaker_observation_id JOIN voice_profiles profile ON profile.account_id=sample.account_id AND profile.id=sample.voice_profile_id JOIN people owner ON owner.account_id=profile.account_id AND owner.id=profile.person_id AND owner.status='owner' WHERE o.account_id=e.account_id AND (o.event_id=e.event_id OR EXISTS(SELECT 1 FROM speaker_observation_sources source WHERE source.account_id=o.account_id AND source.speaker_observation_id=o.id AND source.event_id=e.event_id)))) AND e.media_disposition='canonical' AND (enrollment.timeline_cutoff_at IS NULL OR e.started_at<enrollment.timeline_cutoff_at) AND (m.event_id IS NULL OR m.deleted_at IS NOT NULL OR m.processing_state='pruned' OR (m.retain_until IS NOT NULL AND m.retain_until<=clock_timestamp())) ORDER BY e.event_id LIMIT 1024")
        .bind(account).fetch_all(&mut *tx).await?;
    if !expired_events.is_empty() {
        let samples:Vec<i64>=sqlx::query_scalar("SELECT DISTINCT sample.id FROM voice_samples sample JOIN speaker_observations o ON o.account_id=sample.account_id AND o.id=sample.speaker_observation_id WHERE sample.account_id=$1 AND (o.event_id=ANY($2::text[]) OR EXISTS(SELECT 1 FROM speaker_observation_sources source WHERE source.account_id=o.account_id AND source.speaker_observation_id=o.id AND source.event_id=ANY($2::text[]))) AND EXISTS(SELECT 1 FROM voice_sample_profile_assignments assignment JOIN voice_profiles profile ON profile.account_id=assignment.account_id AND profile.id=assignment.profile_id JOIN people owner ON owner.account_id=profile.account_id AND owner.id=profile.person_id AND owner.status='owner' WHERE assignment.account_id=sample.account_id AND assignment.sample_id=sample.id) ORDER BY sample.id")
            .bind(account).bind(&expired_events).fetch_all(&mut *tx).await?;
        erase_samples(&mut tx, account, &samples).await?;
        expire_sessions_for_events(&mut tx, account, &expired_events).await?;
        sqlx::query("UPDATE voice_enrollment_sessions enrollment SET reason='raw_media_expired' WHERE enrollment.account_id=$1 AND enrollment.reason='source_deleted' AND EXISTS(SELECT 1 FROM capture_events e WHERE e.account_id=enrollment.account_id AND e.capture_session_id=enrollment.capture_session_id AND e.event_id=ANY($2::text[]))")
            .bind(account).bind(&expired_events).execute(&mut *tx).await?;
    }
    let sessions:Vec<String>=sqlx::query_scalar("SELECT capture_session_id FROM voice_enrollment_sessions WHERE account_id=$1 AND designated AND state IN ('recording','processing','enrolled') ORDER BY CASE WHEN state='enrolled' THEN 1 ELSE 0 END,updated_at,capture_session_id LIMIT $2")
        .bind(account).bind(SESSION_BATCH).fetch_all(&mut *tx).await?;
    for session in sessions {
        settle(&mut tx, account, &session).await?;
    }
    tx.commit().await?;
    Ok(())
}

async fn fail(
    tx: &mut Transaction<'_, Postgres>,
    account: &str,
    session: &str,
    reason: VoiceEnrollmentReason,
) -> Result<()> {
    sqlx::query("UPDATE voice_enrollment_sessions SET state='inconclusive',reason=$3,dominant_share=NULL,accepted_sample_count=0,updated_at=clock_timestamp() WHERE account_id=$1 AND capture_session_id=$2")
        .bind(account).bind(session).bind(reason.as_str()).execute(&mut **tx).await?;
    Ok(())
}

async fn settle(tx: &mut Transaction<'_, Postgres>, account: &str, session: &str) -> Result<()> {
    let row=sqlx::query("SELECT enrollment.state,enrollment.reason,enrollment.channel_domain,enrollment.enrollment_revision,account.enrollment_revision current_revision,enrollment.source_revision decided_revision,enrollment.seal_generation decided_seal,receipt.source_revision,receipt.seal_generation,session.ended_at IS NOT NULL AND receipt.finish_requested_at IS NOT NULL finished, floor(extract(epoch FROM (SELECT min(event.started_at) FROM capture_events event WHERE event.account_id=enrollment.account_id AND event.capture_session_id=enrollment.capture_session_id))*1000)::bigint start_ms FROM voice_enrollment_sessions enrollment JOIN accounts account ON account.id=enrollment.account_id JOIN capture_sessions session ON session.account_id=enrollment.account_id AND session.id=enrollment.capture_session_id LEFT JOIN capture_formation_receipts receipt ON receipt.account_id=enrollment.account_id AND receipt.capture_session_id=enrollment.capture_session_id WHERE enrollment.account_id=$1 AND enrollment.capture_session_id=$2 FOR UPDATE OF enrollment")
        .bind(account).bind(session).fetch_one(&mut **tx).await?;
    if row.try_get::<i64, _>("enrollment_revision")? != row.try_get::<i64, _>("current_revision")? {
        return invalidate_owner_enrollment(
            tx,
            account,
            session,
            VoiceEnrollmentReason::EnrollmentRevoked,
        )
        .await;
    }
    let revision: Option<i64> = row.try_get("source_revision")?;
    if row.try_get::<String, _>("state")? == "enrolled" {
        if row.try_get::<Option<i64>, _>("decided_revision")? != revision
            || row.try_get::<Option<i64>, _>("decided_seal")?
                != row.try_get::<Option<i64>, _>("seal_generation")?
        {
            return invalidate_owner_enrollment(
                tx,
                account,
                session,
                VoiceEnrollmentReason::SourceChanged,
            )
            .await;
        }
        return Ok(());
    }
    if row.try_get::<Option<String>, _>("reason")?.is_some()
        || !row.try_get::<Option<bool>, _>("finished")?.unwrap_or(false)
    {
        return Ok(());
    }
    let Some(start) = row.try_get::<Option<i64>, _>("start_ms")? else {
        return fail(tx, account, session, VoiceEnrollmentReason::NoSpeech).await;
    };
    let cutoff = start.saturating_add(policy::MAX_ENROLLMENT_MS);
    // Later ordinary audio remains processable, but cannot hold or fail the
    // first three minutes of enrollment. Gaps before the in-bound horizon do.
    // Unaccepted account-wide upload intents have no session/span authority;
    // later acceptance invalidates this source revision under the same lock.
    let held:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM capture_streams stream WHERE stream.account_id=$1 AND stream.capture_session_id=$2 AND stream.committed_through_sequence<(SELECT coalesce(max(event.sequence),-1) FROM capture_events event WHERE event.account_id=stream.account_id AND event.stream_id=stream.id AND event.started_at<to_timestamp($3::double precision/1000.0))) OR EXISTS(SELECT 1 FROM capture_events e WHERE e.account_id=$1 AND e.capture_session_id=$2 AND e.started_at<to_timestamp($3::double precision/1000.0) AND e.media_disposition='canonical' AND NOT EXISTS(SELECT 1 FROM media_processing_jobs j WHERE j.account_id=e.account_id AND j.event_id=e.event_id AND j.job_kind='gemini_audio' AND j.state IN ('succeeded','failed_terminal','canceled'))) OR EXISTS(SELECT 1 FROM voice_embedding_jobs j JOIN speaker_observations o ON o.account_id=j.account_id AND o.id=j.speaker_observation_id JOIN capture_events e ON e.account_id=o.account_id AND e.event_id=o.event_id WHERE j.account_id=$1 AND e.capture_session_id=$2 AND o.started_at<to_timestamp($3::double precision/1000.0) AND j.state IN ('pending','processing','retry_wait'))")
        .bind(account).bind(session).bind(cutoff).fetch_one(&mut **tx).await?;
    if held {
        sqlx::query("UPDATE voice_enrollment_sessions SET state='processing',updated_at=clock_timestamp() WHERE account_id=$1 AND capture_session_id=$2 AND state IN ('recording','processing')")
            .bind(account).bind(session).execute(&mut **tx).await?;
        return Ok(());
    }
    let failed:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM media_processing_jobs j JOIN capture_events e ON e.account_id=j.account_id AND e.event_id=j.event_id WHERE j.account_id=$1 AND e.capture_session_id=$2 AND e.started_at<to_timestamp($3::double precision/1000.0) AND j.state IN ('failed_terminal','canceled'))")
        .bind(account).bind(session).bind(cutoff).fetch_one(&mut **tx).await?;
    if failed {
        return fail(
            tx,
            account,
            session,
            VoiceEnrollmentReason::ProcessingFailed,
        )
        .await;
    }
    let evidence=sqlx::query("SELECT o.id,floor(extract(epoch FROM o.started_at)*1000)::bigint start_ms,floor(extract(epoch FROM o.ended_at)*1000)::bigint end_ms,o.overlap,coalesce(o.voice_profile_id,CASE WHEN NOT coalesce(c.profile_updates_quarantined,false) THEN c.voice_profile_id END) profile,s.id sample,s.channel_domain,coalesce(s.accepted AND s.eligibility='enroll' AND NOT coalesce(c.profile_updates_quarantined,false),false) eligible FROM speaker_observations o JOIN capture_events e ON e.account_id=o.account_id AND e.event_id=o.event_id LEFT JOIN speaker_clusters c ON c.account_id=o.account_id AND c.id=o.cluster_id LEFT JOIN voice_samples s ON s.account_id=o.account_id AND s.speaker_observation_id=o.id AND s.embedding_space=$3 AND s.quality_version=$4 AND s.scorer_version=$5 WHERE o.account_id=$1 AND e.capture_session_id=$2 AND o.started_at<to_timestamp($6::double precision/1000.0) ORDER BY o.started_at,o.id LIMIT $7")
        .bind(account).bind(session).bind(EMBEDDING_SPACE).bind(QUALITY_VERSION).bind(SCORER_VERSION).bind(cutoff).bind(OBSERVATION_LIMIT+1).fetch_all(&mut **tx).await?;
    if evidence.len() > OBSERVATION_LIMIT as usize {
        return fail(
            tx,
            account,
            session,
            VoiceEnrollmentReason::ProcessingFailed,
        )
        .await;
    }
    let mut domains = std::collections::BTreeSet::new();
    let mut speech = Vec::with_capacity(evidence.len());
    for r in evidence {
        if let Some(domain) = r.try_get::<Option<String>, _>("channel_domain")? {
            domains.insert(domain);
        }
        speech.push(policy::Speech {
            observation: r.try_get("id")?,
            group: r.try_get("profile")?,
            start: r.try_get("start_ms")?,
            end: r.try_get("end_ms")?,
            overlap: r.try_get("overlap")?,
            sample: r.try_get("sample")?,
            enrollment_eligible: r.try_get("eligible")?,
        });
    }
    if speech.is_empty() {
        return fail(tx, account, session, VoiceEnrollmentReason::NoSpeech).await;
    }
    let domain: Option<String> = row.try_get("channel_domain")?;
    if domains.len() > 1
        || domain
            .as_ref()
            .is_some_and(|domain| domains.iter().any(|other| other != domain))
    {
        return fail(tx, account, session, VoiceEnrollmentReason::RouteChanged).await;
    }
    let Some(domain) = domain.or_else(|| domains.into_iter().next()) else {
        return fail(
            tx,
            account,
            session,
            VoiceEnrollmentReason::NoEligibleSample,
        )
        .await;
    };
    let decision = match policy::decide(&speech, start) {
        Ok(decision) => decision,
        Err(reason) => return fail(tx, account, session, reason).await,
    };
    // Maintenance still expires and terminates inconclusive attempts while
    // paused, but successful enrollment is a new binding and obeys Pause.
    if !voice_identity::controls_admit(tx, account).await?.0 {
        sqlx::query("UPDATE voice_enrollment_sessions SET state='processing',updated_at=clock_timestamp() WHERE account_id=$1 AND capture_session_id=$2 AND state IN ('recording','processing')").bind(account).bind(session).execute(&mut **tx).await?;
        return Ok(());
    }
    let owner = match sqlx::query_scalar::<_, i64>(
        "SELECT id FROM people WHERE account_id=$1 AND status='owner'",
    )
    .bind(account)
    .fetch_optional(&mut **tx)
    .await?
    {
        Some(id) => id,
        None => {
            let id = voice_identity::allocate_voice_id(tx, account, "person").await?;
            sqlx::query("INSERT INTO people(account_id,id,status) VALUES($1,$2,'owner')")
                .bind(account)
                .bind(id)
                .execute(&mut **tx)
                .await?;
            id
        }
    };
    let chosen = decision
        .samples
        .iter()
        .map(|(_, sample)| *sample)
        .collect::<Vec<_>>();
    let selected=sqlx::query("SELECT id,embedding FROM voice_samples WHERE account_id=$1 AND id=ANY($2::bigint[]) ORDER BY id")
        .bind(account).bind(&chosen).fetch_all(&mut **tx).await?.into_iter().map(|r|Ok((r.try_get::<i64,_>("id")?,crate::cp::voice_identity::decode_embedding(&r.try_get::<Vec<u8>,_>("embedding")?)?))).collect::<Result<Vec<_>>>()?;
    let representative =
        crate::cp::voice_identity::representative(&selected)?.ok_or_else(|| {
            EnclaveError::Store("accepted enrollment representative is absent".into())
        })?;
    let candidates =
        owner_voice::owner_profiles(tx, account, &domain, EMBEDDING_SPACE, SCORER_VERSION).await?;
    let scores = candidates
        .iter()
        .map(|(id, bytes)| {
            Ok((
                *id,
                crate::cp::voice_quality::cosine(
                    &representative.centroid,
                    &crate::cp::voice_identity::decode_embedding(bytes)?,
                ),
            ))
        })
        .collect::<Result<Vec<_>>>()?;
    let existing = match crate::cp::voice_identity::decide_continuity(
        &scores,
        crate::cp::voice_quality::SampleDecision::MatchOnly,
    )
    .0
    {
        crate::cp::voice_identity::ContinuityDecision::Match(id) => Some(id),
        _ => None,
    };
    let profile = if let Some(id) = existing {
        id
    } else {
        let id = voice_identity::allocate_voice_id(tx, account, "voice_profile").await?;
        sqlx::query("INSERT INTO voice_profiles(account_id,id,person_id,label,embedding_space,channel_domain,centroid,scorer_version) SELECT $1,$2,$3,'owner-voice',$4,$5,embedding,$6 FROM voice_samples WHERE account_id=$1 AND id=$7")
            .bind(account).bind(id).bind(owner).bind(EMBEDDING_SPACE).bind(&domain).bind(SCORER_VERSION).bind(decision.samples[0].1).execute(&mut **tx).await?;
        id
    };
    // Enrollment evidence is exactly the clean, wholly contained selection.
    // Other turns get ordinary owner matching only after this representative
    // exists, never by inheriting temporary anonymous group membership.
    let mut promotion = decision.samples.clone();
    let promoted_samples = promotion
        .iter()
        .map(|(_, sample)| *sample)
        .collect::<Vec<_>>();
    let mut old_profiles:Vec<i64>=sqlx::query_scalar("SELECT DISTINCT voice_profile_id FROM voice_samples WHERE account_id=$1 AND id=ANY($2::bigint[]) AND voice_profile_id IS NOT NULL AND voice_profile_id<>$3 ORDER BY voice_profile_id")
        .bind(account).bind(&promoted_samples).bind(profile).fetch_all(&mut **tx).await?;
    for (observation, sample) in &promotion {
        let enrolled = decision.samples.contains(&(*observation, *sample));
        if !enrolled {
            sqlx::query("UPDATE voice_samples SET eligibility='match_only' WHERE account_id=$1 AND id=$2 AND eligibility='enroll'").bind(account).bind(sample).execute(&mut **tx).await?;
        }
        owner_voice::assign_sample(
            tx,
            account,
            *observation,
            *sample,
            profile,
            Some(if enrolled {
                "owner_enrollment"
            } else {
                "owner_voice"
            }),
        )
        .await?;
    }
    sqlx::query("UPDATE identity_evidence SET evidence=evidence||jsonb_build_object('enrollment_policy_version',$3::bigint) WHERE account_id=$1 AND kind='owner_enrollment' AND speaker_observation_id=ANY($2::bigint[])")
        .bind(account).bind(decision.samples.iter().map(|(observation,_)|*observation).collect::<Vec<_>>()).bind(policy::POLICY_VERSION).execute(&mut **tx).await?;
    // A newly validated re-record can rehabilitate a profile with no surviving
    // old enrollment support; arbitrary ordinary recordings cannot.
    sqlx::query("UPDATE voice_profiles SET status='tentative' WHERE account_id=$1 AND id=$2 AND status='quarantined'").bind(account).bind(profile).execute(&mut **tx).await?;
    voice_identity::recompute_profile(tx, account, profile, "owner_enrollment").await?;
    let owner_candidates =
        owner_voice::owner_profiles(tx, account, &domain, EMBEDDING_SPACE, SCORER_VERSION).await?;
    let others=sqlx::query("SELECT s.id,o.id observation,s.embedding,s.voice_profile_id FROM voice_samples s JOIN speaker_observations o ON o.account_id=s.account_id AND o.id=s.speaker_observation_id JOIN capture_events e ON e.account_id=o.account_id AND e.event_id=o.event_id WHERE s.account_id=$1 AND e.capture_session_id=$2 AND s.accepted AND s.embedding_space=$3 AND s.quality_version=$4 AND s.scorer_version=$5 AND s.channel_domain=$6 AND NOT (s.id=ANY($7::bigint[])) ORDER BY o.started_at,o.id LIMIT $8")
        .bind(account).bind(session).bind(EMBEDDING_SPACE).bind(QUALITY_VERSION).bind(SCORER_VERSION).bind(&domain).bind(&chosen).bind(OBSERVATION_LIMIT).fetch_all(&mut **tx).await?;
    for other in others {
        let sample: i64 = other.try_get("id")?;
        let observation: i64 = other.try_get("observation")?;
        let old: Option<i64> = other.try_get("voice_profile_id")?;
        let vector = crate::cp::voice_identity::decode_embedding(
            &other.try_get::<Vec<u8>, _>("embedding")?,
        )?;
        let scores = owner_candidates
            .iter()
            .map(|(id, bytes)| {
                Ok((
                    *id,
                    crate::cp::voice_quality::cosine(
                        &vector,
                        &crate::cp::voice_identity::decode_embedding(bytes)?,
                    ),
                ))
            })
            .collect::<Result<Vec<_>>>()?;
        let (result, best, _) = crate::cp::voice_identity::decide_continuity(
            &scores,
            crate::cp::voice_quality::SampleDecision::MatchOnly,
        );
        if let crate::cp::voice_identity::ContinuityDecision::Match(owner_profile) = result {
            // A crossing or post-cutoff sample may match the newly known owner,
            // but its bytes must never contribute to enrollment or its centroid.
            sqlx::query(
                "UPDATE voice_samples SET eligibility='match_only' WHERE account_id=$1 AND id=$2",
            )
            .bind(account)
            .bind(sample)
            .execute(&mut **tx)
            .await?;
            owner_voice::assign_sample(
                tx,
                account,
                observation,
                sample,
                owner_profile,
                Some("owner_voice"),
            )
            .await?;
            if let Some(old) = old.filter(|old| *old != owner_profile) {
                old_profiles.push(old);
            }
            promotion.push((observation, sample));
        } else if old == Some(decision.group)
            && best.is_some_and(|score| score >= crate::cp::voice_memory::NEW_PROFILE_THRESHOLD)
        {
            // An ambiguous former alias is not affirmative second-person
            // evidence. Preserve its sample for reevaluation without a binding.
            sqlx::query("UPDATE voice_sample_profile_assignments SET active=false WHERE account_id=$1 AND sample_id=$2 AND active").bind(account).bind(sample).execute(&mut **tx).await?;
            sqlx::query(
                "UPDATE voice_samples SET voice_profile_id=NULL WHERE account_id=$1 AND id=$2",
            )
            .bind(account)
            .bind(sample)
            .execute(&mut **tx)
            .await?;
            sqlx::query("UPDATE speaker_observations SET voice_profile_id=NULL WHERE account_id=$1 AND id=$2").bind(account).bind(observation).execute(&mut **tx).await?;
            old_profiles.push(decision.group);
            promotion.push((observation, sample));
        }
    }
    old_profiles.sort_unstable();
    old_profiles.dedup();
    for old in &old_profiles {
        voice_identity::recompute_profile(tx, account, *old, "owner_enrollment_transfer").await?;
    }
    let clusters:Vec<i64>=sqlx::query_scalar("SELECT DISTINCT cluster_id FROM speaker_observations WHERE account_id=$1 AND id=ANY($2::bigint[]) AND cluster_id IS NOT NULL ORDER BY cluster_id")
        .bind(account).bind(promotion.iter().map(|(observation,_)|*observation).collect::<Vec<_>>()).fetch_all(&mut **tx).await?;
    owner_voice::refresh_clusters(tx, account, &clusters).await?;
    sqlx::query("UPDATE voice_enrollment_sessions SET state='enrolled',reason=NULL,channel_domain=$3,timeline_started_at=to_timestamp($4::double precision/1000.0),timeline_cutoff_at=to_timestamp($5::double precision/1000.0),source_revision=$6,seal_generation=$7,dominant_share=$8,accepted_sample_count=$9,voice_profile_id=$10,updated_at=clock_timestamp() WHERE account_id=$1 AND capture_session_id=$2")
        .bind(account).bind(session).bind(&domain).bind(start).bind(cutoff).bind(revision).bind(row.try_get::<Option<i64>,_>("seal_generation")?).bind(decision.share).bind(decision.samples.len() as i64).bind(profile).execute(&mut **tx).await?;
    let mut changed = old_profiles;
    changed.push(profile);
    voice_identity::refresh_affected_speaker_projections(
        tx,
        account,
        &clusters,
        &changed,
        &[owner],
    )
    .await?;
    owner_voice::refresh_domains(tx, account, &[domain]).await?;
    Ok(())
}
