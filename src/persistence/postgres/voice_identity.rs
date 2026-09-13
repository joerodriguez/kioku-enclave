//! PostgreSQL voice leases, scoped continuity, retained-sample reconsideration and erasure.
use super::{
    activation::lock_activation_contract_key_share_if_installed,
    advisory_transaction_lock, allocate_content_id, current_schema_relation_exists,
    speaker_identity::{refresh_episode_speaker_projections, SpeakerProjectionTarget},
    PostgresPersistence,
};
use crate::{
    cp::{
        voice_identity::{self, ContinuityDecision},
        voice_memory::EMBEDDING_SPACE,
        voice_quality::{self, SampleDecision, QUALITY_VERSION, SCORER_VERSION},
    },
    error::{EnclaveError, Result},
    persistence::{
        VoiceCohort, VoiceEmbeddingBatch, VoiceEmbeddingClaim, VoiceEmbeddingOutcome,
        VoiceEmbeddingSource, VoiceIdentityControls, VoiceIdentityRepository,
    },
};
use async_trait::async_trait;
use sqlx::{Postgres, Row, Transaction};

// o is a speaker observation. Every source must be retained, including the
// canonical inventory row. Missing inventory is expiry, never a provider read.
pub(super) const RETAINED: &str = "EXISTS(SELECT 1 FROM speaker_observation_sources s WHERE s.account_id=o.account_id AND s.speaker_observation_id=o.id) AND NOT EXISTS(SELECT 1 FROM speaker_observation_sources s LEFT JOIN media_objects m ON m.account_id=s.account_id AND m.event_id=s.event_id WHERE s.account_id=o.account_id AND s.speaker_observation_id=o.id AND (m.event_id IS NULL OR m.deleted_at IS NOT NULL OR m.processing_state='pruned' OR m.object_generation IS NULL OR m.object_generation<=0 OR m.object_backend IS DISTINCT FROM 'current' OR (m.retain_until IS NOT NULL AND m.retain_until<=clock_timestamp()))) AND NOT EXISTS(SELECT 1 FROM speaker_observation_sources source JOIN media_objects retained_media ON retained_media.account_id=source.account_id AND retained_media.event_id=source.event_id JOIN recording_media_authority authority ON authority.account_id=retained_media.account_id AND authority.asset_id=retained_media.asset_id AND authority.storage_backend='recordings' WHERE source.account_id=o.account_id AND source.speaker_observation_id=o.id AND NOT EXISTS(SELECT 1 FROM recording_retention_preferences preference WHERE preference.account_id=authority.account_id AND preference.policy='until_deleted' AND preference.revision=authority.retention_policy_revision AND preference.policy_epoch=authority.retention_policy_epoch AND preference.revocation_cutoff IS NULL))";
const FENCED: &str = "EXISTS(SELECT 1 FROM utterances u JOIN episode_members member ON member.account_id=u.account_id AND member.record_type='utterance' AND member.record_id=u.id JOIN episode_deletions d ON d.account_id=member.account_id AND d.episode_id=member.episode_id AND d.state='pending' WHERE u.account_id=o.account_id AND u.speaker_observation_id=o.id) OR EXISTS(SELECT 1 FROM orphan_capture_erasure_operations operation WHERE operation.account_id=o.account_id AND operation.capture_upload_fenced) OR EXISTS(SELECT 1 FROM speaker_observation_sources s JOIN capture_events e ON e.account_id=s.account_id AND e.event_id=s.event_id WHERE s.account_id=o.account_id AND s.speaker_observation_id=o.id AND (EXISTS(SELECT 1 FROM episode_deletions d WHERE d.account_id=e.account_id AND d.state='pending' AND (d.orphan_event_ids ? e.event_id OR d.orphan_event_ids ? coalesce(e.canonical_event_id,e.event_id))) OR EXISTS(SELECT 1 FROM orphan_capture_erasure_sessions erased WHERE erased.account_id=e.account_id AND erased.capture_session_id=e.capture_session_id)))";
// A withdrawn designated source never gets another biometric sample, even if
// another explicit session has since enrolled a fresh profile in this domain.
const ENROLLMENT_REVOKED: &str = "EXISTS(SELECT 1 FROM capture_events event JOIN voice_enrollment_sessions enrollment ON enrollment.account_id=event.account_id AND enrollment.capture_session_id=event.capture_session_id JOIN accounts account ON account.id=enrollment.account_id WHERE event.account_id=o.account_id AND event.event_id=o.event_id AND enrollment.designated AND (enrollment.enrollment_revision<>account.enrollment_revision OR enrollment.state='expired' OR enrollment.reason IN ('forgotten','enrollment_revoked')))";
// Already-published retained samples survive a partially expired enrollment.
// Only explicit withdrawal/revision mismatch invalidates all its contributions.
pub(super) const WITHDRAWN: &str = "EXISTS(SELECT 1 FROM capture_events event JOIN voice_enrollment_sessions enrollment ON enrollment.account_id=event.account_id AND enrollment.capture_session_id=event.capture_session_id JOIN accounts account ON account.id=enrollment.account_id WHERE event.account_id=o.account_id AND event.event_id=o.event_id AND enrollment.designated AND (enrollment.enrollment_revision<>account.enrollment_revision OR enrollment.reason IN ('forgotten','enrollment_revoked')))";
const DUE: &str = "j.state IN ('pending','retry_wait','processing') AND (j.next_attempt_at IS NULL OR j.next_attempt_at<=clock_timestamp()) AND (j.lease_until IS NULL OR j.lease_until<=clock_timestamp())";

// Unlike legacy orphan_event_ids, the paged event/root inventory survives
// utterance/member purge and remains authoritative between deletion ticks.
const PAGED_FENCED: &str = "EXISTS(SELECT 1 FROM capture_events e JOIN persistence_feature_episode_deletion_events planned ON planned.account_id=e.account_id AND (planned.event_id=e.event_id OR planned.event_id=coalesce(e.canonical_event_id,e.event_id) OR planned.root_event_id=coalesce(e.canonical_event_id,e.event_id)) JOIN episode_deletions d ON d.account_id=planned.account_id AND d.episode_id=planned.episode_id AND d.state='pending' WHERE e.account_id=o.account_id AND (e.event_id=o.event_id OR EXISTS(SELECT 1 FROM speaker_observation_sources source WHERE source.account_id=o.account_id AND source.speaker_observation_id=o.id AND source.event_id=e.event_id)))";

pub(super) async fn source_fence(tx: &mut sqlx::PgConnection) -> Result<String> {
    // Probe the current schema after the shared release lock, so a v26 writer
    // cannot cache table absence across a concurrent v27 installation.
    if current_schema_relation_exists(tx, "persistence_feature_episode_deletion_events").await? {
        Ok(format!("({FENCED}) OR ({PAGED_FENCED})"))
    } else if current_schema_relation_exists(tx, "persistence_feature_activation_contracts").await?
    {
        Err(EnclaveError::Config(
            "voice identity paged deletion inventory is missing".into(),
        ))
    } else {
        Ok(FENCED.to_owned())
    }
}

/// Earlier voice lineage may predate the counter writer. Advance the existing
/// counter monotonically past those rows while the account lock serializes
/// allocators, instead of assuming an absent counter means an empty table.
pub(super) async fn allocate_voice_id(
    tx: &mut Transaction<'_, Postgres>,
    account: &str,
    kind: &str,
) -> Result<i64> {
    let table = match kind {
        "person" => "people",
        "person_name_claim" => "person_name_claims",
        "person_fact" => "person_facts",
        "identity_evidence" => "identity_evidence",
        "voice_profile" => "voice_profiles",
        "voice_profile_proposal" => "voice_profile_proposals",
        "voice_sample" => "voice_samples",
        "voice_profile_revision" => "voice_profile_revisions",
        "voice_profile_representative" => "voice_profile_representatives",
        "voice_sample_profile_assignment" => "voice_sample_profile_assignments",
        _ => {
            return Err(EnclaveError::Store(
                "voice content id kind is invalid".into(),
            ))
        }
    };
    let sql=format!("INSERT INTO content_id_counters(account_id,entity_kind,next_id) SELECT $1,$2,coalesce(max(id),0)+1 FROM {table} WHERE account_id=$1 ON CONFLICT(account_id,entity_kind) DO UPDATE SET next_id=greatest(content_id_counters.next_id,excluded.next_id)");
    sqlx::query(sqlx::AssertSqlSafe(sql))
        .bind(account)
        .bind(kind)
        .execute(&mut **tx)
        .await?;
    allocate_content_id(tx, account, kind).await
}

pub(super) async fn lock_account(
    tx: &mut Transaction<'_, Postgres>,
    account: &str,
) -> Result<bool> {
    lock_activation_contract_key_share_if_installed(tx).await?;
    advisory_transaction_lock(tx, "memory-reconciliation", account).await?;
    let active =
        sqlx::query_scalar::<_, String>("SELECT status FROM accounts WHERE id=$1 FOR UPDATE")
            .bind(account)
            .fetch_optional(&mut **tx)
            .await?
            .as_deref()
            == Some("active");
    if active {
        super::identity_presentation::initialize_account_semantics(tx, account).await?;
    }
    Ok(active)
}
/// Refresh every memory reached by the changed identity, including stored
/// reservations/participants whose last source was removed by erasure. This is
/// only reachability: the canonical projector owns labels, acceptance and fences.
/// Callers hold the activation/account memory lock ladder in this transaction.
pub(super) async fn refresh_affected_speaker_projections(
    tx: &mut Transaction<'_, Postgres>,
    account: &str,
    clusters: &[i64],
    profiles: &[i64],
    people: &[i64],
) -> Result<()> {
    let targets =
        affected_speaker_projection_targets(tx, account, clusters, profiles, people).await?;
    refresh_episode_speaker_projections(tx, account, &targets, &[]).await?;
    Ok(())
}

pub(super) async fn affected_speaker_projection_targets(
    tx: &mut Transaction<'_, Postgres>,
    account: &str,
    clusters: &[i64],
    profiles: &[i64],
    people: &[i64],
) -> Result<Vec<SpeakerProjectionTarget>> {
    if clusters.is_empty() && profiles.is_empty() && people.is_empty() {
        return Ok(Vec::new());
    }
    let episodes: Vec<i64> = sqlx::query_scalar(
        "SELECT member.episode_id FROM episode_members member \
           JOIN utterances u ON u.account_id=member.account_id AND u.id=member.record_id \
           JOIN speaker_observations observation ON observation.account_id=u.account_id \
                AND observation.id=u.speaker_observation_id \
           LEFT JOIN speaker_clusters cluster ON cluster.account_id=observation.account_id \
                AND cluster.id=observation.cluster_id \
           LEFT JOIN voice_profiles profile ON profile.account_id=cluster.account_id \
                AND profile.id=coalesce(observation.voice_profile_id,cluster.voice_profile_id) \
          WHERE member.account_id=$1 AND member.record_type='utterance' \
            AND (observation.cluster_id=ANY($2::bigint[]) \
              OR observation.voice_profile_id=ANY($3::bigint[]) OR cluster.voice_profile_id=ANY($3::bigint[]) \
              OR observation.person_id=ANY($4::bigint[]) \
              OR cluster.person_id=ANY($4::bigint[]) OR profile.person_id=ANY($4::bigint[])) \
         UNION SELECT slot.episode_id FROM episode_speaker_slots slot \
          WHERE slot.account_id=$1 AND (slot.speaker_cluster_id=ANY($2::bigint[]) \
              OR slot.voice_profile_id=ANY($3::bigint[])) \
         UNION SELECT participant.episode_id FROM episode_participants participant \
          WHERE participant.account_id=$1 AND participant.person_id=ANY($4::bigint[]) \
         ORDER BY episode_id",
    )
    .bind(account)
    .bind(clusters)
    .bind(profiles)
    .bind(people)
    .fetch_all(&mut **tx)
    .await?;
    Ok(episodes
        .into_iter()
        .map(SpeakerProjectionTarget::current)
        .collect())
}

pub(super) async fn controls_admit(
    tx: &mut Transaction<'_, Postgres>,
    account: &str,
) -> Result<(bool, VoiceCohort)> {
    // Shared lock prevents an operator pause from committing midway through a
    // settlement; the same locked snapshot supplies its postcommit metric cohort.
    let row=sqlx::query("SELECT cohort,NOT paused AND (cohort='all' OR (cohort='explicit' AND $1=ANY(explicit_account_ids))) AS admitted FROM voice_identity_controls WHERE singleton FOR SHARE").bind(account).fetch_one(&mut **tx).await?;
    Ok((
        row.try_get("admitted")?,
        VoiceCohort::parse(&row.try_get::<String, _>("cohort")?)?,
    ))
}

async fn terminalize(
    tx: &mut Transaction<'_, Postgres>,
    account: &str,
    predicate: &str,
    fenced: &str,
    state: &str,
    error: &str,
) -> Result<u64> {
    let sql=format!("WITH selected AS (SELECT j.id FROM voice_embedding_jobs j JOIN speaker_observations o ON o.account_id=j.account_id AND o.id=j.speaker_observation_id WHERE j.account_id=$1 AND {DUE} AND NOT ({fenced}) AND ({predicate}) ORDER BY o.started_at,j.id LIMIT 500 FOR UPDATE OF j), updated AS (UPDATE voice_embedding_jobs j SET state=$2,error_code=$3,lease_owner=NULL,lease_token=NULL,lease_until=NULL,next_attempt_at=NULL,updated_at=clock_timestamp() FROM selected WHERE j.account_id=$1 AND j.id=selected.id RETURNING j.speaker_observation_id) UPDATE speaker_observations o SET embedding_status=$2 FROM updated WHERE o.account_id=$1 AND o.id=updated.speaker_observation_id");
    Ok(sqlx::query(sqlx::AssertSqlSafe(sql))
        .bind(account)
        .bind(state)
        .bind(error)
        .execute(&mut **tx)
        .await?
        .rows_affected())
}
async fn update_job(
    tx: &mut Transaction<'_, Postgres>,
    claim: &VoiceEmbeddingClaim,
    state: &str,
    error: Option<&str>,
    skip: bool,
) -> Result<()> {
    sqlx::query("UPDATE voice_embedding_jobs SET state=$4,error_code=$5,lease_owner=NULL,lease_token=NULL,lease_until=NULL,next_attempt_at=CASE WHEN $4='retry_wait' THEN clock_timestamp()+interval '300 seconds' ELSE NULL END,attempt_count=greatest(0,attempt_count-CASE WHEN $6 THEN 1 ELSE 0 END),updated_at=clock_timestamp() WHERE account_id=$1 AND id=$2 AND lease_token=$3").bind(&claim.account_id).bind(claim.id).bind(&claim.lease_token).bind(state).bind(error).bind(skip).execute(&mut **tx).await?;
    sqlx::query(
        "UPDATE speaker_observations SET embedding_status=$3 WHERE account_id=$1 AND id=$2",
    )
    .bind(&claim.account_id)
    .bind(claim.speaker_observation_id)
    .bind(if state == "retry_wait" {
        "pending"
    } else {
        state
    })
    .execute(&mut **tx)
    .await?;
    Ok(())
}

#[async_trait]
impl VoiceIdentityRepository for PostgresPersistence {
    async fn voice_identity_controls(&self) -> Result<VoiceIdentityControls> {
        PostgresPersistence::voice_identity_controls(self).await
    }
    async fn owner_voice_enrollment_status(
        &self,
        account_id: &str,
    ) -> Result<crate::persistence::OwnerVoiceEnrollmentStatus> {
        super::voice_enrollment::status(self, account_id).await
    }
    async fn forget_owner_voice_enrollment(
        &self,
        account_id: &str,
    ) -> Result<crate::persistence::OwnerVoiceEnrollmentStatus> {
        super::voice_enrollment::forget(self, account_id).await
    }
    async fn maintain_owner_voice_enrollment(&self, account_id: &str) -> Result<()> {
        super::voice_enrollment::maintain(self, account_id).await
    }
    async fn maintain_voice_profiles(&self, account_id: &str) -> Result<()> {
        maintain_profiles(self, account_id).await
    }
    async fn claim_voice_embeddings(
        &self,
        account: &str,
        owner: &str,
    ) -> Result<VoiceEmbeddingBatch> {
        let mut batch = VoiceEmbeddingBatch::default();
        let mut tx = self.pool.begin().await?;
        if !lock_account(&mut tx, account).await? || !controls_admit(&mut tx, account).await?.0 {
            tx.commit().await?;
            return Ok(batch);
        }
        // One outstanding account batch across replicas preserves capture order.
        let busy: bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM voice_embedding_jobs WHERE account_id=$1 AND state='processing' AND lease_until>clock_timestamp())").bind(account).fetch_one(&mut *tx).await?;
        if busy {
            tx.commit().await?;
            return Ok(batch);
        }
        let fenced = source_fence(&mut tx).await?;
        // Fenced work remains retryable and clears any expired lease. It must
        // never consume expiry/exhaustion paths while deletion owns the source.
        let skip_sql=format!("WITH selected AS (SELECT j.id FROM voice_embedding_jobs j JOIN speaker_observations o ON o.account_id=j.account_id AND o.id=j.speaker_observation_id WHERE j.account_id=$1 AND {DUE} AND ({fenced}) ORDER BY o.started_at,j.id LIMIT 500 FOR UPDATE OF j), updated AS (UPDATE voice_embedding_jobs j SET state='retry_wait',error_code='source_fenced',lease_owner=NULL,lease_token=NULL,lease_until=NULL,attempt_count=greatest(0,j.attempt_count-CASE WHEN j.state='processing' THEN 1 ELSE 0 END),next_attempt_at=clock_timestamp()+interval '300 seconds',updated_at=clock_timestamp() FROM selected WHERE j.account_id=$1 AND j.id=selected.id RETURNING j.speaker_observation_id) UPDATE speaker_observations o SET embedding_status='pending' FROM updated WHERE o.account_id=$1 AND o.id=updated.speaker_observation_id");
        sqlx::query(sqlx::AssertSqlSafe(skip_sql))
            .bind(account)
            .execute(&mut *tx)
            .await?;
        terminalize(
            &mut tx,
            account,
            ENROLLMENT_REVOKED,
            &fenced,
            "failed",
            "enrollment_revoked",
        )
        .await?;
        batch.expired_count = terminalize(
            &mut tx,
            account,
            &format!("NOT ({RETAINED})"),
            &fenced,
            "raw_media_expired",
            "raw_media_expired",
        )
        .await?;
        batch.exhausted_count = terminalize(
            &mut tx,
            account,
            "j.attempt_count>=3",
            &fenced,
            "failed",
            "attempts_exhausted",
        )
        .await?;
        let sql=format!("SELECT j.id,j.speaker_observation_id,j.embedding_space,j.quality_version,j.scorer_version,o.overlap FROM voice_embedding_jobs j JOIN speaker_observations o ON o.account_id=j.account_id AND o.id=j.speaker_observation_id WHERE j.account_id=$1 AND {DUE} AND j.attempt_count<3 AND j.embedding_space=$2 AND j.quality_version=$3 AND j.scorer_version=$4 AND j.processor_version=1 AND ({RETAINED}) AND NOT ({fenced}) AND NOT ({ENROLLMENT_REVOKED}) ORDER BY o.started_at,j.id LIMIT 16 FOR UPDATE OF j");
        let rows = sqlx::query(sqlx::AssertSqlSafe(sql))
            .bind(account)
            .bind(EMBEDDING_SPACE)
            .bind(QUALITY_VERSION)
            .bind(SCORER_VERSION)
            .fetch_all(&mut *tx)
            .await?;
        for row in rows {
            let id: i64 = row.try_get("id")?;
            let observation: i64 = row.try_get("speaker_observation_id")?;
            let token = crate::cp::tokens::random_token_hex();
            sqlx::query("UPDATE voice_embedding_jobs SET state='processing',lease_owner=$3,lease_token=$4,lease_until=clock_timestamp()+interval '240 seconds',attempt_count=attempt_count+1,next_attempt_at=NULL,error_code=NULL,updated_at=clock_timestamp() WHERE account_id=$1 AND id=$2").bind(account).bind(id).bind(owner).bind(&token).execute(&mut *tx).await?;
            sqlx::query("UPDATE speaker_observations SET embedding_status='processing' WHERE account_id=$1 AND id=$2").bind(account).bind(observation).execute(&mut *tx).await?;
            let sources=sqlx::query("SELECT s.event_id,s.event_start_ms,s.event_end_ms,s.window_start_ms,e.capture_session_id,e.stream_kind,e.audio_role,e.audio_route,m.mime_type,m.object_key,m.object_generation,m.byte_length,m.sha256 FROM speaker_observation_sources s JOIN capture_events e ON e.account_id=s.account_id AND e.event_id=s.event_id JOIN media_objects m ON m.account_id=s.account_id AND m.event_id=s.event_id WHERE s.account_id=$1 AND s.speaker_observation_id=$2 ORDER BY s.window_start_ms,s.event_id").bind(account).bind(observation).fetch_all(&mut *tx).await?.into_iter().map(|r| Ok(VoiceEmbeddingSource {event_id:r.try_get("event_id")?,capture_session_id:r.try_get("capture_session_id")?,stream_kind:r.try_get("stream_kind")?,audio_role:r.try_get("audio_role")?,audio_route:r.try_get("audio_route")?,mime_type:r.try_get("mime_type")?,object_name:r.try_get("object_key")?,object_generation:r.try_get("object_generation")?,byte_length:r.try_get("byte_length")?,sha256:r.try_get("sha256")?,event_start_ms:r.try_get("event_start_ms")?,event_end_ms:r.try_get("event_end_ms")?,window_start_ms:r.try_get("window_start_ms")?})).collect::<Result<Vec<_>>>()?;
            batch.claims.push(VoiceEmbeddingClaim {
                account_id: account.into(),
                id,
                speaker_observation_id: observation,
                lease_token: token,
                embedding_space: row.try_get("embedding_space")?,
                quality_version: row.try_get("quality_version")?,
                scorer_version: row.try_get("scorer_version")?,
                overlap: row.try_get("overlap")?,
                sources,
            });
        }
        tx.commit().await?;
        Ok(batch)
    }
    async fn settle_voice_embedding(
        &self,
        claim: &VoiceEmbeddingClaim,
        outcome: VoiceEmbeddingOutcome,
    ) -> Result<bool> {
        let mut identity_outcomes = Vec::new();
        let mut tx = self.pool.begin().await?;
        let active = lock_account(&mut tx, &claim.account_id).await?;
        let owned:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM voice_embedding_jobs WHERE account_id=$1 AND id=$2 AND speaker_observation_id=$3 AND lease_token=$4 AND state='processing' AND lease_until>clock_timestamp())").bind(&claim.account_id).bind(claim.id).bind(claim.speaker_observation_id).bind(&claim.lease_token).fetch_one(&mut *tx).await?;
        if !owned {
            tx.commit().await?;
            return Ok(false);
        }
        let (admitted, cohort) = controls_admit(&mut tx, &claim.account_id).await?;
        let fenced = source_fence(&mut tx).await?;
        let row=sqlx::query(sqlx::AssertSqlSafe(format!("SELECT ({RETAINED}) AS retained,({fenced}) AS fenced,({ENROLLMENT_REVOKED}) AS enrollment_revoked FROM speaker_observations o WHERE o.account_id=$1 AND o.id=$2"))).bind(&claim.account_id).bind(claim.speaker_observation_id).fetch_one(&mut *tx).await?;
        if !active || !admitted || row.try_get::<bool, _>("fenced")? {
            update_job(&mut tx, claim, "retry_wait", Some("source_fenced"), true).await?;
        } else if row.try_get::<bool, _>("enrollment_revoked")? {
            update_job(&mut tx, claim, "failed", Some("enrollment_revoked"), false).await?;
        } else if !row.try_get::<bool, _>("retained")?
            || matches!(&outcome, VoiceEmbeddingOutcome::RawMediaExpired)
        {
            update_job(
                &mut tx,
                claim,
                "raw_media_expired",
                Some("raw_media_expired"),
                false,
            )
            .await?;
        } else {
            match outcome {
                VoiceEmbeddingOutcome::Sample {
                    embedding,
                    diagnostics,
                    channel_domain,
                } => {
                    identity_outcomes =
                        persist_sample(&mut tx, claim, &embedding, &diagnostics, &channel_domain)
                            .await?;
                    update_job(&mut tx, claim, "ready", None, false).await?;
                }
                VoiceEmbeddingOutcome::NoEmbedding { diagnostics } => {
                    sqlx::query("UPDATE speaker_observations SET voice_eligibility='no_embedding',voice_diagnostics=$3::jsonb WHERE account_id=$1 AND id=$2").bind(&claim.account_id).bind(claim.speaker_observation_id).bind(serde_json::to_string(&diagnostics)?).execute(&mut *tx).await?;
                    update_job(&mut tx, claim, "ready", Some("no_embedding"), false).await?;
                }
                VoiceEmbeddingOutcome::Retry => {
                    update_job(
                        &mut tx,
                        claim,
                        "retry_wait",
                        Some("inference_failed"),
                        false,
                    )
                    .await?
                }
                VoiceEmbeddingOutcome::RawMediaExpired => {
                    unreachable!("handled above")
                }
            }
        }
        tx.commit().await?;
        for outcome in identity_outcomes {
            observe_identity(cohort, outcome);
        }
        Ok(true)
    }
}

/// Source erasure is independent of inference, Pause and cohort admission.
/// Reconsideration rotates through ready jobs without fetching media or changing
/// their embedding result, lease, attempts, or source observations.
pub(super) async fn maintain_profiles(repo: &PostgresPersistence, account: &str) -> Result<()> {
    let mut tx = repo.pool().begin().await?;
    if !lock_account(&mut tx, account).await? {
        return Err(EnclaveError::NotFound);
    }
    let fence = source_fence(&mut tx).await?;
    let expired: Vec<i64> = sqlx::query_scalar(sqlx::AssertSqlSafe(format!(
        "SELECT s.id FROM voice_samples s JOIN speaker_observations o ON o.account_id=s.account_id AND o.id=s.speaker_observation_id WHERE s.account_id=$1 AND NOT ({fence}) AND (NOT ({RETAINED}) OR ({WITHDRAWN})) ORDER BY s.id LIMIT 500"
    ))).bind(account).fetch_all(&mut *tx).await?;
    super::voice_enrollment::erase_samples(&mut tx, account, &expired).await?;
    let (admitted, cohort) = controls_admit(&mut tx, account).await?;
    let mut outcomes = Vec::new();
    if admitted {
        super::voice_profile_reconciliation::adopt_current_policy(&mut tx, account).await?;
        let rows = sqlx::query(sqlx::AssertSqlSafe(format!(
            "SELECT s.id,s.speaker_observation_id,s.embedding,s.embedding_space,s.scorer_version,s.channel_domain,s.eligibility,j.id job_id FROM voice_samples s JOIN speaker_observations o ON o.account_id=s.account_id AND o.id=s.speaker_observation_id JOIN voice_embedding_jobs j ON j.account_id=s.account_id AND j.id=s.embedding_job_id AND j.speaker_observation_id=s.speaker_observation_id AND j.state='ready' WHERE s.account_id=$1 AND s.accepted AND s.voice_profile_id IS NULL AND s.eligibility IN ('enroll','match_only') AND s.embedding_space=$2 AND s.quality_version=$3 AND s.scorer_version=$4 AND NOT EXISTS(SELECT 1 FROM voice_sample_profile_assignments a WHERE a.account_id=s.account_id AND a.sample_id=s.id AND a.active) AND ({RETAINED}) AND NOT ({fence}) AND NOT ({ENROLLMENT_REVOKED}) ORDER BY j.updated_at,s.id LIMIT 16"
        ))).bind(account).bind(EMBEDDING_SPACE).bind(QUALITY_VERSION).bind(SCORER_VERSION).fetch_all(&mut *tx).await?;
        for row in rows {
            let space: String = row.try_get("embedding_space")?;
            let domain: String = row.try_get("channel_domain")?;
            let embedding =
                voice_identity::decode_embedding(&row.try_get::<Vec<u8>, _>("embedding")?)?;
            let eligibility = if row.try_get::<String, _>("eligibility")? == "enroll" {
                SampleDecision::Enroll
            } else {
                SampleDecision::MatchOnly
            };
            outcomes.extend(
                assign_stored_sample(
                    &mut tx,
                    &VoiceMatchContext {
                        account,
                        observation: row.try_get("speaker_observation_id")?,
                        space: &space,
                        scorer: row.try_get("scorer_version")?,
                    },
                    row.try_get("id")?,
                    &embedding,
                    eligibility,
                    &domain,
                )
                .await?,
            );
            sqlx::query("UPDATE voice_embedding_jobs SET updated_at=clock_timestamp() WHERE account_id=$1 AND id=$2 AND state='ready'")
                .bind(account).bind(row.try_get::<i64,_>("job_id")?).execute(&mut *tx).await?;
        }
    }
    let mut changed_profiles = super::identity_fusion::maintain(&mut tx, account, admitted).await?;
    if admitted {
        outcomes.extend(super::voice_profile_reconciliation::reconcile(&mut tx, account).await?);
    }
    changed_profiles.extend(super::voice_recurrence::refresh(&mut tx, account).await?);
    refresh_affected_speaker_projections(&mut tx, account, &[], &changed_profiles, &[]).await?;
    tx.commit().await?;
    for outcome in outcomes {
        observe_identity(cohort, outcome);
    }
    Ok(())
}

async fn persist_sample(
    tx: &mut Transaction<'_, Postgres>,
    claim: &VoiceEmbeddingClaim,
    embedding: &[f32],
    diagnostics: &voice_quality::VoiceDiagnostics,
    domain: &str,
) -> Result<Vec<&'static str>> {
    let account = &claim.account_id;
    let bytes = voice_identity::encode_embedding(embedding)?;
    if diagnostics.quality_version != claim.quality_version
        || diagnostics.decision == SampleDecision::NoEmbedding
    {
        return Err(EnclaveError::InvalidRequest(
            "voice sample diagnostics do not match claimed versions".into(),
        ));
    }
    let exists:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM voice_samples WHERE account_id=$1 AND speaker_observation_id=$2 AND embedding_space=$3 AND quality_version=$4 AND scorer_version=$5)").bind(account).bind(claim.speaker_observation_id).bind(&claim.embedding_space).bind(claim.quality_version).bind(claim.scorer_version).fetch_one(&mut **tx).await?;
    if exists {
        return Ok(vec!["unassigned"]);
    }
    let eligibility = match diagnostics.decision {
        SampleDecision::Enroll => "enroll",
        SampleDecision::MatchOnly => "match_only",
        SampleDecision::Quarantine => "quarantine",
        SampleDecision::NoEmbedding => unreachable!(),
    };
    let sample_id = allocate_voice_id(tx, account, "voice_sample").await?;
    let diagnostics_json = serde_json::to_string(&diagnostics)?;
    sqlx::query("INSERT INTO voice_samples(account_id,id,speaker_observation_id,embedding_space,channel_domain,embedding,quality_score,diagnostics,quality_version,scorer_version,eligibility,duration_ms,speech_ratio,snr_proxy_db,clipping_ratio,silence_ratio,embedding_norm,accepted,embedding_job_id) VALUES($1,$2,$3,$4,$5,$6,$7,$8::jsonb,$9,$10,$11,$12,$7,$13,$14,$15,1.0,$16,$17)").bind(account).bind(sample_id).bind(claim.speaker_observation_id).bind(&claim.embedding_space).bind(domain).bind(bytes).bind(diagnostics.speech_ratio).bind(&diagnostics_json).bind(claim.quality_version).bind(claim.scorer_version).bind(eligibility).bind(diagnostics.duration_ms).bind(diagnostics.snr_proxy_db).bind(diagnostics.clipping_ratio).bind(diagnostics.silence_ratio).bind(diagnostics.decision!=SampleDecision::Quarantine).bind(claim.id).execute(&mut **tx).await?;
    sqlx::query("UPDATE speaker_observations SET voice_eligibility=$3,voice_diagnostics=$4::jsonb WHERE account_id=$1 AND id=$2").bind(account).bind(claim.speaker_observation_id).bind(eligibility).bind(diagnostics_json).execute(&mut **tx).await?;
    assign_stored_sample(
        tx,
        &VoiceMatchContext {
            account,
            observation: claim.speaker_observation_id,
            space: &claim.embedding_space,
            scorer: claim.scorer_version,
        },
        sample_id,
        embedding,
        diagnostics.decision,
        domain,
    )
    .await
}

struct VoiceMatchContext<'a> {
    account: &'a str,
    observation: i64,
    space: &'a str,
    scorer: i64,
}

async fn assign_stored_sample(
    tx: &mut Transaction<'_, Postgres>,
    context: &VoiceMatchContext<'_>,
    sample_id: i64,
    embedding: &[f32],
    eligibility: SampleDecision,
    domain: &str,
) -> Result<Vec<&'static str>> {
    let account = context.account;
    let cluster=sqlx::query("SELECT c.id,c.attribution_state,c.person_id,e.capture_session_id FROM speaker_observations o JOIN speaker_clusters c ON c.account_id=o.account_id AND c.id=o.cluster_id JOIN capture_events e ON e.account_id=o.account_id AND e.event_id=o.event_id WHERE o.account_id=$1 AND o.id=$2 FOR UPDATE OF c").bind(account).bind(context.observation).fetch_optional(&mut **tx).await?;
    let Some(cluster) = cluster else {
        return Ok(vec!["unassigned"]);
    };
    let cluster_id: i64 = cluster.try_get("id")?;
    let state: String = cluster.try_get("attribution_state")?;
    let session: String = cluster.try_get("capture_session_id")?;
    sqlx::query("UPDATE speaker_clusters SET channel_domain=$3 WHERE account_id=$1 AND id=$2 AND channel_domain IS DISTINCT FROM $3").bind(account).bind(cluster_id).bind(domain).execute(&mut **tx).await?;
    if eligibility == SampleDecision::Quarantine {
        return Ok(vec!["unassigned"]);
    }
    let owner_candidates =
        super::owner_voice::owner_profiles(tx, account, domain, context.space, context.scorer)
            .await?;
    let owner_scores = owner_candidates
        .iter()
        .map(|(id, bytes)| {
            Ok((
                *id,
                voice_quality::cosine(embedding, &voice_identity::decode_embedding(bytes)?),
            ))
        })
        .collect::<Result<Vec<_>>>()?;
    let (owner_decision, owner_best, owner_margin) =
        voice_identity::decide_continuity(&owner_scores, SampleDecision::MatchOnly);
    let enrollment:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM voice_enrollment_sessions enrollment JOIN accounts a ON a.id=enrollment.account_id WHERE enrollment.account_id=$1 AND enrollment.capture_session_id=$2 AND enrollment.designated AND enrollment.enrollment_revision=a.enrollment_revision AND enrollment.state<>'enrolled')").bind(account).bind(&session).fetch_one(&mut **tx).await?;
    // A designated attempt may not add any owner biometric/evidence before its
    // complete dominance decision. Its temporary anonymous continuity remains
    // useful for that decision and never contaminates an older owner profile.
    let owner_match = !enrollment && matches!(owner_decision, ContinuityDecision::Match(_));
    // Route attribution is labeling only. Explicit enrollment still computes
    // ordinary continuity samples, which are promoted only after full closure.
    if state == "owner_transmit" && owner_candidates.is_empty() && !enrollment {
        return Ok(vec!["unassigned"]);
    }
    let (decision, best, margin) = if owner_match {
        (owner_decision, owner_best, owner_margin)
    } else {
        let session_scores =
            nonowner_candidate_scores(tx, context, embedding, domain, Some(&session)).await?;
        let session_decision = voice_identity::decide_continuity(&session_scores, eligibility);
        let account_scores = if !enrollment
            && session_scores.len() <= voice_identity::MAX_CANDIDATE_PROFILES
            && !matches!(session_decision.0, ContinuityDecision::Match(_))
        {
            nonowner_candidate_scores(tx, context, embedding, domain, None).await?
        } else {
            Vec::new()
        };
        voice_identity::decide_scoped_continuity(&session_scores, &account_scores, eligibility)
    };
    sqlx::query(
        "UPDATE voice_samples SET similarity=$3,decision_margin=$4 WHERE account_id=$1 AND id=$2",
    )
    .bind(account)
    .bind(sample_id)
    .bind(best.map(f64::from))
    .bind(margin.map(f64::from))
    .execute(&mut **tx)
    .await?;
    let cluster_person: Option<i64> = if state == "person_bound" && !owner_match {
        cluster.try_get("person_id")?
    } else {
        None
    };
    let (profile, created) = match decision {
        ContinuityDecision::Abstain => return Ok(vec!["unassigned"]),
        ContinuityDecision::Match(id) => (id, false),
        ContinuityDecision::Create => {
            let id = allocate_voice_id(tx, account, "voice_profile").await?;
            sqlx::query("INSERT INTO voice_profiles(account_id,id,person_id,label,embedding_space,channel_domain,centroid,scorer_version) VALUES($1,$2,$3,$4,$5,$6,$7,$8)").bind(account).bind(id).bind(cluster_person).bind(format!("voice-profile-{id}")).bind(context.space).bind(domain).bind(voice_identity::encode_embedding(embedding)?).bind(context.scorer).execute(&mut **tx).await?;
            (id, true)
        }
    };
    let _current_person: Option<i64> = sqlx::query_scalar(
        "SELECT person_id FROM voice_profiles WHERE account_id=$1 AND id=$2 FOR UPDATE",
    )
    .bind(account)
    .bind(profile)
    .fetch_one(&mut **tx)
    .await?;
    // Acoustic continuity remains usable when names conflict. The source-backed
    // reducer owns propagated names independently of matching quarantine.
    let propagated = false;
    super::owner_voice::assign_sample(
        tx,
        account,
        context.observation,
        sample_id,
        profile,
        owner_match.then_some("owner_voice"),
    )
    .await?;
    super::owner_voice::refresh_clusters(tx, account, &[cluster_id]).await?;
    if eligibility == SampleDecision::Enroll {
        recompute_profile(
            tx,
            account,
            profile,
            if created {
                "created"
            } else if propagated {
                "person_propagation"
            } else {
                "enroll_recompute"
            },
        )
        .await?;
    } else if propagated {
        append_revision(tx, account, profile, "person_propagation").await?;
    }
    let mut changed_profiles = vec![profile];
    if !owner_match {
        changed_profiles.extend(
            super::identity_fusion::reconcile_profiles(tx, account, &[profile], true).await?,
        );
    }
    refresh_affected_speaker_projections(tx, account, &[cluster_id], &changed_profiles, &[])
        .await?;
    let mut outcomes = vec![if owner_match {
        "owner_voice"
    } else if created {
        "new_profile"
    } else {
        "matched"
    }];
    if propagated {
        outcomes.push("person_propagated");
    }
    Ok(outcomes)
}

/// A NULL session selects stable account-wide profiles. Both scopes hold any
/// centroid with expired/withdrawn contributions until maintenance recomputes it.
/// In-progress owner-enrollment candidates stay private to their recording.
async fn nonowner_candidate_scores(
    tx: &mut Transaction<'_, Postgres>,
    context: &VoiceMatchContext<'_>,
    embedding: &[f32],
    domain: &str,
    session: Option<&str>,
) -> Result<Vec<(i64, f32)>> {
    let fence = source_fence(tx).await?;
    let sql = format!(
        "SELECT p.id,p.centroid FROM voice_profiles p \
         LEFT JOIN people person ON person.account_id=p.account_id AND person.id=p.person_id \
         WHERE p.account_id=$1 AND p.embedding_space=$2 AND p.scorer_version=$3 \
         AND p.channel_domain=$4 AND p.status<>'quarantined' AND coalesce(person.status,'')<>'owner' \
         AND EXISTS(SELECT 1 FROM voice_profile_revisions revision WHERE revision.account_id=p.account_id \
           AND revision.profile_id=p.id AND revision.active AND revision.status=p.status AND ($5::text IS NOT NULL OR revision.derivation_version=$7)) \
         AND (($5::text IS NULL AND p.status='stable') OR EXISTS( \
           SELECT 1 FROM voice_sample_profile_assignments a \
           JOIN voice_samples s ON s.account_id=a.account_id AND s.id=a.sample_id \
           JOIN speaker_observations o ON o.account_id=s.account_id AND o.id=s.speaker_observation_id \
           JOIN capture_events e ON e.account_id=o.account_id AND e.event_id=o.event_id \
           WHERE a.account_id=p.account_id AND a.profile_id=p.id AND a.active AND e.capture_session_id=$5)) \
         AND NOT EXISTS(SELECT 1 FROM voice_sample_profile_assignments a \
           JOIN voice_samples s ON s.account_id=a.account_id AND s.id=a.sample_id \
           JOIN speaker_observations o ON o.account_id=s.account_id AND o.id=s.speaker_observation_id \
           WHERE a.account_id=p.account_id AND a.profile_id=p.id AND a.active \
             AND (NOT ({RETAINED}) OR ({fence}))) \
         AND ($5::text IS NOT NULL OR NOT EXISTS(SELECT 1 FROM voice_sample_profile_assignments a \
           JOIN voice_samples s ON s.account_id=a.account_id AND s.id=a.sample_id \
           JOIN speaker_observations o ON o.account_id=s.account_id AND o.id=s.speaker_observation_id \
           JOIN capture_events e ON e.account_id=o.account_id AND e.event_id=o.event_id \
           JOIN voice_enrollment_sessions enrollment ON enrollment.account_id=e.account_id \
             AND enrollment.capture_session_id=e.capture_session_id \
           WHERE a.account_id=p.account_id AND a.profile_id=p.id AND a.active \
             AND enrollment.designated AND enrollment.state<>'enrolled')) \
         ORDER BY p.id LIMIT $6"
    );
    let rows = sqlx::query(sqlx::AssertSqlSafe(sql))
        .bind(context.account)
        .bind(context.space)
        .bind(context.scorer)
        .bind(domain)
        .bind(session)
        .bind((voice_identity::MAX_CANDIDATE_PROFILES + 1) as i64)
        .bind(voice_identity::IDENTITY_DERIVATION_VERSION)
        .fetch_all(&mut **tx)
        .await?;
    rows.into_iter()
        .map(|row| {
            Ok((
                row.try_get("id")?,
                voice_quality::cosine(
                    embedding,
                    &voice_identity::decode_embedding(&row.try_get::<Vec<u8>, _>("centroid")?)?,
                ),
            ))
        })
        .collect()
}

fn observe_identity(cohort: VoiceCohort, outcome: &'static str) {
    tracing::info!(target: "kioku::voice", metric_schema="voice_identity_v1", cohort=cohort.as_str(), outcome, count=1_u64, "voice identity outcome");
}

pub(super) async fn append_revision(
    tx: &mut Transaction<'_, Postgres>,
    account: &str,
    profile: i64,
    reason: &str,
) -> Result<()> {
    let unchanged: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM voice_profile_revisions r JOIN voice_profiles p ON p.account_id=r.account_id AND p.id=r.profile_id WHERE p.account_id=$1 AND p.id=$2 AND r.active AND r.derivation_version=$3 AND r.status=p.status AND r.scorer_version=p.scorer_version AND r.representative_kind=p.representative_kind AND r.centroid=p.centroid AND r.sample_count=p.sample_count AND r.medoid_sample_id IS NOT DISTINCT FROM p.medoid_sample_id AND r.person_id IS NOT DISTINCT FROM p.person_id)").bind(account).bind(profile).bind(voice_identity::IDENTITY_DERIVATION_VERSION).fetch_one(&mut **tx).await?;
    if unchanged {
        return Ok(());
    }
    let predecessor: Option<i64> = sqlx::query_scalar(
        "SELECT id FROM voice_profile_revisions WHERE account_id=$1 AND profile_id=$2 AND active",
    )
    .bind(account)
    .bind(profile)
    .fetch_optional(&mut **tx)
    .await?;
    sqlx::query("UPDATE voice_profile_revisions SET active=false WHERE account_id=$1 AND profile_id=$2 AND active").bind(account).bind(profile).execute(&mut **tx).await?;
    let id = allocate_voice_id(tx, account, "voice_profile_revision").await?;
    sqlx::query("INSERT INTO voice_profile_revisions(account_id,id,profile_id,status,derivation_version,scorer_version,representative_kind,centroid,sample_count,medoid_sample_id,person_id,predecessor_revision_id,reason_code) SELECT account_id,$3,id,status,$6,scorer_version,representative_kind,centroid,sample_count,medoid_sample_id,person_id,$4,$5 FROM voice_profiles WHERE account_id=$1 AND id=$2").bind(account).bind(profile).bind(id).bind(predecessor).bind(reason).bind(voice_identity::IDENTITY_DERIVATION_VERSION).execute(&mut **tx).await?;
    Ok(())
}

pub(super) async fn recompute_profile(
    tx: &mut Transaction<'_, Postgres>,
    account: &str,
    profile: i64,
    reason: &str,
) -> Result<()> {
    let rows=sqlx::query("SELECT s.id,s.speaker_observation_id,s.embedding FROM voice_samples s JOIN voice_sample_profile_assignments a ON a.account_id=s.account_id AND a.sample_id=s.id AND a.active JOIN voice_profiles p ON p.account_id=a.account_id AND p.id=a.profile_id JOIN speaker_observations observation ON observation.account_id=s.account_id AND observation.id=s.speaker_observation_id LEFT JOIN speaker_clusters cluster ON cluster.account_id=observation.account_id AND cluster.id=observation.cluster_id WHERE s.account_id=$1 AND a.profile_id=$2 AND s.accepted AND s.eligibility='enroll' AND s.quality_version=$3 AND NOT coalesce(cluster.profile_updates_quarantined,false) AND s.embedding_space=p.embedding_space AND s.scorer_version=p.scorer_version AND s.channel_domain=p.channel_domain ORDER BY s.id").bind(account).bind(profile).bind(QUALITY_VERSION).fetch_all(&mut **tx).await?;
    let samples = rows
        .iter()
        .map(|r| {
            Ok((
                r.try_get::<i64, _>("id")?,
                voice_identity::decode_embedding(&r.try_get::<Vec<u8>, _>("embedding")?)?,
            ))
        })
        .collect::<Result<Vec<_>>>()?;
    let bimodal = crate::cp::voice_reconciliation::has_distinct_modes(&samples)?;
    if bimodal {
        sqlx::query("UPDATE voice_profiles SET status='quarantined' WHERE account_id=$1 AND id=$2")
            .bind(account)
            .bind(profile)
            .execute(&mut **tx)
            .await?;
    }
    if let Some(rep) = voice_identity::representative(&samples)? {
        let bytes = voice_identity::encode_embedding(&rep.centroid)?;
        let observations = rows
            .iter()
            .filter(|row| rep.retained_sample_ids.contains(&row.get::<i64, _>("id")))
            .map(|row| row.get::<i64, _>("speaker_observation_id"))
            .collect::<std::collections::BTreeSet<_>>();
        let stable = observations.len() >= voice_identity::MIN_STABLE_OBSERVATIONS;
        sqlx::query("UPDATE voice_profiles p SET centroid=$3,sample_count=$4,medoid_sample_id=$5,status=CASE WHEN p.status='quarantined' OR EXISTS(SELECT 1 FROM people person WHERE person.account_id=p.account_id AND person.id=p.person_id AND person.status='owner') THEN p.status WHEN $6 THEN 'stable' ELSE 'tentative' END,updated_at=clock_timestamp() WHERE p.account_id=$1 AND p.id=$2").bind(account).bind(profile).bind(&bytes).bind(rep.sample_count).bind(rep.medoid_sample_id).bind(stable).execute(&mut **tx).await?;
        let id = allocate_voice_id(tx, account, "voice_profile_representative").await?;
        sqlx::query("INSERT INTO voice_profile_representatives(account_id,id,profile_id,channel_domain,centroid,sample_count,medoid_sample_id,scorer_version) SELECT account_id,$3,id,channel_domain,centroid,sample_count,medoid_sample_id,scorer_version FROM voice_profiles WHERE account_id=$1 AND id=$2 ON CONFLICT(account_id,profile_id,channel_domain) DO UPDATE SET centroid=excluded.centroid,sample_count=excluded.sample_count,medoid_sample_id=excluded.medoid_sample_id,scorer_version=excluded.scorer_version,updated_at=clock_timestamp()").bind(account).bind(profile).bind(id).execute(&mut **tx).await?;
    } else {
        // No surviving enrollment evidence: clear live representatives, preserve
        // append-only lineage, and permanently exclude the profile from matching.
        sqlx::query("UPDATE voice_profiles SET status='quarantined',centroid=''::bytea,sample_count=0,medoid_sample_id=NULL,updated_at=clock_timestamp() WHERE account_id=$1 AND id=$2").bind(account).bind(profile).execute(&mut **tx).await?;
        sqlx::query(
            "DELETE FROM voice_profile_representatives WHERE account_id=$1 AND profile_id=$2",
        )
        .bind(account)
        .bind(profile)
        .execute(&mut **tx)
        .await?;
    }
    append_revision(
        tx,
        account,
        profile,
        if bimodal { "bimodal_support" } else { reason },
    )
    .await
}

/// Identity reachability is captured before source cascades remove named
/// observations that never needed an anonymous slot reservation.
pub(super) struct VoiceErasureAffected {
    pub(super) profiles: Vec<i64>,
    pub(super) name_profiles: Vec<i64>,
    pub(super) fact_people: Vec<i64>,
    pub(super) targets: Vec<SpeakerProjectionTarget>,
}

/// Member purges precede source-event cascades. Capture their identity closure
/// while visual/utterance edges and contextual memberships still exist.
pub(super) async fn capture_projection_erasure(
    tx: &mut Transaction<'_, Postgres>,
    account: &str,
    utterances: &[i64],
    screenshots: &[i64],
) -> Result<VoiceErasureAffected> {
    let events: Vec<String> = sqlx::query_scalar("SELECT o.event_id FROM utterances u JOIN speaker_observations o ON o.account_id=u.account_id AND o.id=u.speaker_observation_id WHERE u.account_id=$1 AND u.id=ANY($2::bigint[])
        UNION SELECT source.event_id FROM utterances u JOIN speaker_observation_sources source ON source.account_id=u.account_id AND source.speaker_observation_id=u.speaker_observation_id WHERE u.account_id=$1 AND u.id=ANY($2::bigint[])
        UNION SELECT event_id FROM visual_speaker_observations WHERE account_id=$1 AND screenshot_id=ANY($3::bigint[])")
        .bind(account).bind(utterances).bind(screenshots).fetch_all(&mut **tx).await?;
    let mut name_profiles =
        super::identity_fusion::profiles_depending_on_events(tx, account, &events).await?;
    let direct: Vec<i64> = sqlx::query_scalar("SELECT DISTINCT o.voice_profile_id FROM utterances u JOIN speaker_observations o ON o.account_id=u.account_id AND o.id=u.speaker_observation_id WHERE u.account_id=$1 AND u.id=ANY($2::bigint[]) AND o.voice_profile_id IS NOT NULL")
        .bind(account).bind(utterances).fetch_all(&mut **tx).await?;
    name_profiles.extend(direct);
    name_profiles.sort_unstable();
    name_profiles.dedup();
    let fact_people =
        super::identity_fusion::fact_people_depending_on_events(tx, account, &events).await?;
    let targets =
        affected_speaker_projection_targets(tx, account, &[], &name_profiles, &fact_people).await?;
    Ok(VoiceErasureAffected {
        profiles: vec![],
        name_profiles,
        fact_people,
        targets,
    })
}

/// Remove every sample derived from a deleted event, including multi-event
/// observations anchored in a surviving event, before source-row cascades lose
/// that provenance. The caller holds the ordinary deletion lock ladder.
pub(super) async fn erase_event_samples(
    tx: &mut Transaction<'_, Postgres>,
    account: &str,
    events: &[String],
) -> Result<VoiceErasureAffected> {
    let sample_ids:Vec<i64>=sqlx::query_scalar("SELECT s.id FROM voice_samples s JOIN speaker_observations o ON o.account_id=s.account_id AND o.id=s.speaker_observation_id WHERE s.account_id=$1 AND (o.event_id=ANY($2::text[]) OR EXISTS(SELECT 1 FROM speaker_observation_sources source WHERE source.account_id=o.account_id AND source.speaker_observation_id=o.id AND source.event_id=ANY($2::text[]))) ORDER BY s.id").bind(account).bind(events).fetch_all(&mut **tx).await?;
    let profiles:Vec<i64>=sqlx::query_scalar("SELECT profile_id FROM voice_sample_profile_assignments WHERE account_id=$1 AND sample_id=ANY($2::bigint[]) UNION SELECT voice_profile_id AS profile_id FROM voice_samples WHERE account_id=$1 AND id=ANY($2::bigint[]) AND voice_profile_id IS NOT NULL ORDER BY profile_id").bind(account).bind(&sample_ids).fetch_all(&mut **tx).await?;
    let name_profiles =
        super::identity_fusion::profiles_depending_on_events(tx, account, events).await?;
    let fact_people =
        super::identity_fusion::fact_people_depending_on_events(tx, account, events).await?;
    let mut targets = affected_speaker_projection_targets(tx, account, &[], &profiles, &[]).await?;
    targets
        .extend(affected_speaker_projection_targets(tx, account, &[], &name_profiles, &[]).await?);
    let source_memories: Vec<i64> = sqlx::query_scalar("SELECT DISTINCT member.episode_id FROM episode_members member JOIN utterances u ON u.account_id=member.account_id AND u.id=member.record_id JOIN speaker_observations o ON o.account_id=u.account_id AND o.id=u.speaker_observation_id WHERE member.account_id=$1 AND member.record_type='utterance' AND (o.event_id=ANY($2::text[]) OR EXISTS(SELECT 1 FROM speaker_observation_sources source WHERE source.account_id=o.account_id AND source.speaker_observation_id=o.id AND source.event_id=ANY($2::text[]))) ORDER BY member.episode_id").bind(account).bind(events).fetch_all(&mut **tx).await?;
    targets.extend(
        source_memories
            .into_iter()
            .map(SpeakerProjectionTarget::current),
    );
    targets.sort_by_key(|target| target.episode_id);
    targets.dedup_by_key(|target| target.episode_id);
    super::owner_voice::clear_sample_attribution(tx, account, &sample_ids).await?;
    super::voice_enrollment::expire_sessions_for_events(tx, account, events).await?;
    sqlx::query("DELETE FROM voice_samples WHERE account_id=$1 AND id=ANY($2::bigint[])")
        .bind(account)
        .bind(&sample_ids)
        .execute(&mut **tx)
        .await?;
    Ok(VoiceErasureAffected {
        profiles,
        name_profiles,
        fact_people,
        targets,
    })
}
pub(super) async fn recompute_erased_profiles(
    tx: &mut Transaction<'_, Postgres>,
    account: &str,
    affected: &VoiceErasureAffected,
) -> Result<()> {
    let profiles = &affected.profiles;
    // Revision metadata/history survives, but erased biometrics must not.
    // Exact historical membership is unavailable, so redact every previous
    // centroid for each affected profile before appending the recomputed state.
    sqlx::query("UPDATE voice_profile_revisions SET centroid=''::bytea WHERE account_id=$1 AND profile_id=ANY($2::bigint[])").bind(account).bind(profiles).execute(&mut **tx).await?;
    for profile in profiles {
        recompute_profile(tx, account, *profile, "erasure_recompute").await?;
    }
    let domains:Vec<String>=sqlx::query_scalar("SELECT DISTINCT p.channel_domain FROM voice_profiles p JOIN people owner ON owner.account_id=p.account_id AND owner.id=p.person_id AND owner.status='owner' WHERE p.account_id=$1 AND p.id=ANY($2::bigint[])").bind(account).bind(profiles).fetch_all(&mut **tx).await?;
    sqlx::query("UPDATE speaker_clusters c SET owner=false WHERE c.account_id=$1 AND c.owner AND EXISTS(SELECT 1 FROM voice_profiles p WHERE p.account_id=c.account_id AND p.id=c.voice_profile_id AND (p.status='quarantined' OR p.sample_count=0))").bind(account).execute(&mut **tx).await?;
    super::owner_voice::refresh_domains(tx, account, &domains).await?;
    let mut name_profiles = profiles.clone();
    name_profiles.extend(&affected.name_profiles);
    name_profiles.sort_unstable();
    name_profiles.dedup();
    let changed_names =
        super::identity_fusion::reconcile_profiles(tx, account, &name_profiles, false).await?;
    super::identity_fusion::enrich_facts_for_people(tx, account, false, &affected.fact_people)
        .await?;
    let mut targets = affected.targets.clone();
    targets
        .extend(affected_speaker_projection_targets(tx, account, &[], &changed_names, &[]).await?);
    refresh_episode_speaker_projections(tx, account, &targets, &[]).await?;
    Ok(())
}

#[cfg(test)]
pub(super) mod tests {
    use super::*;

    pub(crate) async fn seed_voice_observation(
        repo: &PostgresPersistence,
        account: &str,
        session: &str,
        event: &str,
        observation: i64,
        cluster: i64,
    ) {
        sqlx::query("INSERT INTO accounts(id,email,primary_provider,primary_subject) VALUES($1,'synthetic@example.test','google',$1) ON CONFLICT(id) DO NOTHING").bind(account).execute(repo.pool()).await.unwrap();
        sqlx::query("INSERT INTO capture_sessions(account_id,id,device_id,install_id,started_at,last_event_at,schema_version) VALUES($1,$2,'synthetic-device','synthetic-install',now(),now(),1) ON CONFLICT DO NOTHING").bind(account).bind(session).execute(repo.pool()).await.unwrap();
        sqlx::query("INSERT INTO capture_streams(account_id,id,capture_session_id,device_id,stream_kind) VALUES($1,$2,$2,'synthetic-device','mic') ON CONFLICT DO NOTHING").bind(account).bind(session).execute(repo.pool()).await.unwrap();
        sqlx::query("INSERT INTO capture_events(account_id,event_id,device_id,install_id,capture_session_id,stream_id,stream_kind,sequence,source_wall_at,source_monotonic_ns,started_at,ended_at,timezone_id,utc_offset_minutes,clock_uncertainty_ms,asset_id,manifest_digest,media_disposition,audio_role,audio_route) VALUES($1,$2,'synthetic-device','synthetic-install',$3,$3,'mic',$4,now(),'0',now()+make_interval(secs=>$4::double precision),now()+make_interval(secs=>$4::double precision)+interval '4 seconds','UTC',0,0,$2,repeat('a',64),'canonical','ambient','builtin_mic')").bind(account).bind(event).bind(session).bind(observation).execute(repo.pool()).await.unwrap();
        sqlx::query("INSERT INTO media_objects(account_id,asset_id,event_id,object_key,object_generation,object_backend,mime_type,codec,byte_length,sha256,processing_state,retain_until) VALUES($1,$2,$2,'raw/'||$1||'/'||$2||'.enc',1,'current','audio/wav','pcm',128044,repeat('b',64),'ready',clock_timestamp()+interval '1 day')").bind(account).bind(event).execute(repo.pool()).await.unwrap();
        sqlx::query("INSERT INTO media_work_units(account_id,id,work_class,processor_version,state,started_at,ended_at,reserved_output_tokens) VALUES($1,$2,'audio',1,'succeeded',now(),now()+interval '4 seconds',0) ON CONFLICT DO NOTHING").bind(account).bind(event).execute(repo.pool()).await.unwrap();
        sqlx::query("INSERT INTO speaker_clusters(account_id,id,work_unit_id,speaker_local_id,attribution_state) VALUES($1,$2,$3,'speaker-a','request_local') ON CONFLICT DO NOTHING").bind(account).bind(cluster).bind(event).execute(repo.pool()).await.unwrap();
        sqlx::query("INSERT INTO speaker_observations(account_id,id,event_id,turn_id,speaker_local_id,started_at,ended_at,transcript_text,cluster_id) VALUES($1,$2,$3,'turn-a','speaker-a',now()+make_interval(secs=>$2::double precision),now()+make_interval(secs=>$2::double precision)+interval '4 seconds','Synthetic fixture',$4)").bind(account).bind(observation).bind(event).bind(cluster).execute(repo.pool()).await.unwrap();
        sqlx::query("INSERT INTO speaker_observation_sources(account_id,speaker_observation_id,event_id,window_start_ms,window_end_ms,event_start_ms,event_end_ms) VALUES($1,$2,$3,0,4000,0,4000)").bind(account).bind(observation).bind(event).execute(repo.pool()).await.unwrap();
        sqlx::query("INSERT INTO voice_embedding_jobs(account_id,id,speaker_observation_id,embedding_space,state) VALUES($1,$2,$2,$3,'pending')").bind(account).bind(observation).bind(EMBEDDING_SPACE).execute(repo.pool()).await.unwrap();
    }
    pub(crate) async fn seed_voice_memory(
        repo: &PostgresPersistence,
        account: &str,
        observation: i64,
        episode: i64,
    ) {
        sqlx::query("INSERT INTO audio_segments(account_id,id,started_at,ended_at,duration_seconds,source_type) VALUES($1,$2,now(),now()+interval '4 seconds',4,'mic')").bind(account).bind(observation).execute(repo.pool()).await.unwrap();
        sqlx::query("INSERT INTO utterances(account_id,id,audio_segment_id,start_offset_seconds,end_offset_seconds,text,speaker_label,speaker_observation_id) VALUES($1,$2,$2,0,4,'Synthetic fixture','Original source label',$2)").bind(account).bind(observation).execute(repo.pool()).await.unwrap();
        sqlx::query("INSERT INTO episodes(account_id,id,started_at,ended_at,identity_revision) VALUES($1,$2,now(),now()+interval '4 seconds',7) ON CONFLICT DO NOTHING").bind(account).bind(episode).execute(repo.pool()).await.unwrap();
        sqlx::query("INSERT INTO episode_members(account_id,episode_id,record_type,record_id) VALUES($1,$2,'utterance',$3)").bind(account).bind(episode).bind(observation).execute(repo.pool()).await.unwrap();
        sqlx::query("INSERT INTO memory_archive_state(account_id,revision) VALUES($1,9) ON CONFLICT(account_id) DO UPDATE SET revision=9").bind(account).execute(repo.pool()).await.unwrap();
    }

    async fn projected_people(repo: &PostgresPersistence, account: &str, episode: i64) -> Vec<i64> {
        sqlx::query_scalar("SELECT person_id FROM episode_participants WHERE account_id=$1 AND episode_id=$2 AND state='active' AND person_id IS NOT NULL ORDER BY person_id")
            .bind(account).bind(episode).fetch_all(repo.pool()).await.unwrap()
    }

    async fn assert_projection_source_unchanged(repo: &PostgresPersistence, account: &str) {
        assert_eq!(
            sqlx::query_scalar::<_, i64>(
                "SELECT revision FROM memory_archive_state WHERE account_id=$1"
            )
            .bind(account)
            .fetch_one(repo.pool())
            .await
            .unwrap(),
            9,
            "speaker projection refresh must not advance archive revision"
        );
        // identity_revision is mutable presentation metadata under ADR-0048;
        // source immutability covers archive coordinates and recorded labels.
        assert!(sqlx::query_scalar::<_,bool>("SELECT bool_and(speaker_label='Original source label') FROM utterances WHERE account_id=$1").bind(account).fetch_one(repo.pool()).await.unwrap(), "speaker projection refresh must preserve frozen source labels");
    }

    fn embedding(index: usize) -> Vec<f32> {
        let mut e = vec![0.; 256];
        e[index] = 1.;
        e
    }
    fn outcome(index: usize, decision: SampleDecision) -> VoiceEmbeddingOutcome {
        let mut diagnostics = voice_quality::diagnose(&vec![0.1; 64000], false, &[]);
        diagnostics.decision = decision;
        VoiceEmbeddingOutcome::Sample {
            embedding: embedding(index),
            diagnostics,
            channel_domain: "macos:builtin_mic".into(),
        }
    }
    async fn claim_one(repo: &PostgresPersistence, account: &str) -> VoiceEmbeddingClaim {
        repo.claim_voice_embeddings(account, "synthetic-worker")
            .await
            .unwrap()
            .claims
            .into_iter()
            .next()
            .expect("one claim")
    }
    async fn cleanup(fixture: super::super::tests::ControlPlaneContractFixture) {
        fixture.persistence.pool().close().await;
        sqlx::query(sqlx::AssertSqlSafe(format!(
            "DROP SCHEMA {} CASCADE",
            fixture.schema
        )))
        .execute(fixture.base.pool())
        .await
        .unwrap();
    }
    #[tokio::test]
    async fn ready_unassigned_samples_are_reconsidered_without_inference_and_respect_pause() {
        let Some(fixture) = super::super::tests::test_persistence().await else {
            return;
        };
        let repo = &fixture.persistence;
        const ACCOUNT: &str = "stored-reconsideration";
        repo.set_voice_identity_cohort(VoiceCohort::All, &[])
            .await
            .unwrap();
        seed_voice_observation(repo, ACCOUNT, "earlier", "earlier-event", 1, 1).await;
        seed_voice_memory(repo, ACCOUNT, 1, 1).await;
        repo.settle_voice_embedding(
            &claim_one(repo, ACCOUNT).await,
            outcome(0, SampleDecision::MatchOnly),
        )
        .await
        .unwrap();
        for i in 2..=4 {
            seed_voice_observation(repo, ACCOUNT, "later", &format!("later-{i}"), i, i).await;
            seed_voice_memory(repo, ACCOUNT, i, i).await;
            repo.settle_voice_embedding(
                &claim_one(repo, ACCOUNT).await,
                outcome(0, SampleDecision::Enroll),
            )
            .await
            .unwrap();
        }
        let before: Vec<(i64,String,i64,Option<String>)> = sqlx::query_as("SELECT id,state,attempt_count,lease_token FROM voice_embedding_jobs WHERE account_id=$1 ORDER BY id").bind(ACCOUNT).fetch_all(repo.pool()).await.unwrap();
        repo.set_voice_identity_paused(true).await.unwrap();
        repo.maintain_voice_profiles(ACCOUNT).await.unwrap();
        assert_eq!(sqlx::query_scalar::<_,Option<i64>>("SELECT voice_profile_id FROM voice_samples WHERE account_id=$1 AND speaker_observation_id=1").bind(ACCOUNT).fetch_one(repo.pool()).await.unwrap(), None,
            "Pause must freeze stored-sample identity bindings");
        repo.set_voice_identity_paused(false).await.unwrap();
        repo.maintain_voice_profiles(ACCOUNT).await.unwrap();
        assert!(sqlx::query_scalar::<_,bool>("SELECT bool_and(voice_profile_id IS NOT NULL) AND count(DISTINCT voice_profile_id)=1 FROM voice_samples WHERE account_id=$1").bind(ACCOUNT).fetch_one(repo.pool()).await.unwrap(),
            "a stored ready sample must join the later stable voice without another embedding");
        let after: Vec<(i64,String,i64,Option<String>)> = sqlx::query_as("SELECT id,state,attempt_count,lease_token FROM voice_embedding_jobs WHERE account_id=$1 ORDER BY id").bind(ACCOUNT).fetch_all(repo.pool()).await.unwrap();
        assert_eq!(
            before, after,
            "reconsideration must preserve terminal jobs, attempts and leases"
        );
        let lineage: (i64,i64,i64) = sqlx::query_as("SELECT (SELECT count(*) FROM voice_samples WHERE account_id=$1),(SELECT count(*) FROM voice_sample_profile_assignments WHERE account_id=$1),(SELECT count(*) FROM voice_profile_revisions WHERE account_id=$1)").bind(ACCOUNT).fetch_one(repo.pool()).await.unwrap();
        repo.maintain_voice_profiles(ACCOUNT).await.unwrap();
        assert_eq!(sqlx::query_as::<_,(i64,i64,i64)>("SELECT (SELECT count(*) FROM voice_samples WHERE account_id=$1),(SELECT count(*) FROM voice_sample_profile_assignments WHERE account_id=$1),(SELECT count(*) FROM voice_profile_revisions WHERE account_id=$1)").bind(ACCOUNT).fetch_one(repo.pool()).await.unwrap(),lineage,
            "reconsideration must be idempotent and MatchOnly must not grow the centroid");
        assert_projection_source_unchanged(repo, ACCOUNT).await;
        cleanup(fixture).await;
    }

    #[tokio::test]
    async fn paused_maintenance_erases_expired_nonowner_biometrics_and_preserves_sources() {
        let Some(fixture) = super::super::tests::test_persistence().await else {
            return;
        };
        let repo = &fixture.persistence;
        const ACCOUNT: &str = "nonowner-expiry";
        repo.set_voice_identity_cohort(VoiceCohort::All, &[])
            .await
            .unwrap();
        for i in 1..=3 {
            seed_voice_observation(repo, ACCOUNT, "recording", &format!("event-{i}"), i, i).await;
            seed_voice_memory(repo, ACCOUNT, i, i).await;
            repo.settle_voice_embedding(
                &claim_one(repo, ACCOUNT).await,
                outcome(0, SampleDecision::Enroll),
            )
            .await
            .unwrap();
        }
        let profile: i64 = sqlx::query_scalar("SELECT id FROM voice_profiles WHERE account_id=$1")
            .bind(ACCOUNT)
            .fetch_one(repo.pool())
            .await
            .unwrap();
        repo.set_voice_identity_paused(true).await.unwrap();
        sqlx::query("UPDATE media_objects SET retain_until=clock_timestamp()-interval '1 second' WHERE account_id=$1 AND event_id='event-1'").bind(ACCOUNT).execute(repo.pool()).await.unwrap();
        repo.maintain_voice_profiles(ACCOUNT).await.unwrap();
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT count(*) FROM voice_samples WHERE account_id=$1")
                .bind(ACCOUNT)
                .fetch_one(repo.pool())
                .await
                .unwrap(),
            2,
            "expired nonowner biometric samples must be erased while paused"
        );
        assert_eq!(sqlx::query_scalar::<_,i64>("SELECT count(*) FROM episode_speaker_slots WHERE account_id=$1 AND episode_id=1 AND status='active' AND voice_profile_id=$2").bind(ACCOUNT).bind(profile).fetch_one(repo.pool()).await.unwrap(),0,
            "expiry must remove stale profile slots before any lazy read");
        assert_eq!(sqlx::query_scalar::<_,i64>("SELECT count(*) FROM episode_participants WHERE account_id=$1 AND episode_id=1 AND state='active' AND participant_key=$2").bind(ACCOUNT).bind(format!("voice_profile:{profile}")).fetch_one(repo.pool()).await.unwrap(),0,
            "expiry must remove stale profile participants before any lazy read");
        assert_eq!(
            sqlx::query_as::<_, (String, i64)>(
                "SELECT status,sample_count FROM voice_profiles WHERE account_id=$1 AND id=$2"
            )
            .bind(ACCOUNT)
            .bind(profile)
            .fetch_one(repo.pool())
            .await
            .unwrap(),
            ("tentative".into(), 2),
            "expired support must withdraw stability and recompute the surviving representative"
        );
        assert!(sqlx::query_scalar::<_,bool>("SELECT bool_and(octet_length(centroid)=0) FROM voice_profile_revisions WHERE account_id=$1 AND NOT active").bind(ACCOUNT).fetch_one(repo.pool()).await.unwrap(),
            "expiry must redact historical biometric payloads");
        sqlx::query("UPDATE media_objects SET retain_until=clock_timestamp()-interval '1 second' WHERE account_id=$1").bind(ACCOUNT).execute(repo.pool()).await.unwrap();
        repo.maintain_voice_profiles(ACCOUNT).await.unwrap();
        assert_eq!(sqlx::query_as::<_,(String,i64,i32)>("SELECT status,sample_count,octet_length(centroid) FROM voice_profiles WHERE account_id=$1 AND id=$2").bind(ACCOUNT).bind(profile).fetch_one(repo.pool()).await.unwrap(),("quarantined".into(),0,0),
            "complete expiry must clear and quarantine the empty profile");
        assert_eq!(sqlx::query_as::<_,(i64,i64,i64)>("SELECT (SELECT count(*) FROM capture_events WHERE account_id=$1),(SELECT count(*) FROM utterances WHERE account_id=$1),(SELECT count(*) FROM episode_members WHERE account_id=$1)").bind(ACCOUNT).fetch_one(repo.pool()).await.unwrap(),(3,3,3),
            "biometric expiry must preserve source records and memory topology");
        assert_projection_source_unchanged(repo, ACCOUNT).await;
        cleanup(fixture).await;
    }

    #[tokio::test]
    async fn stable_nonowner_profiles_match_across_recordings_without_match_only_growth() {
        let Some(fixture) = super::super::tests::test_persistence().await else {
            return;
        };
        let repo = &fixture.persistence;
        const ACCOUNT: &str = "recurring-scope";
        repo.set_voice_identity_cohort(VoiceCohort::All, &[])
            .await
            .unwrap();
        for i in 1..=3 {
            seed_voice_observation(
                repo,
                ACCOUNT,
                "first-recording",
                &format!("event-{i}"),
                i,
                i,
            )
            .await;
            seed_voice_memory(repo, ACCOUNT, i, i).await;
            let claim = claim_one(repo, ACCOUNT).await;
            repo.settle_voice_embedding(&claim, outcome(0, SampleDecision::Enroll))
                .await
                .unwrap();
            let states: Vec<(String, i64)> = sqlx::query_as(
                "SELECT status,sample_count FROM voice_profiles WHERE account_id=$1 ORDER BY id",
            )
            .bind(ACCOUNT)
            .fetch_all(repo.pool())
            .await
            .unwrap();
            assert_eq!(
                states,
                vec![(if i == 3 { "stable" } else { "tentative" }.to_owned(), i)],
                "three distinct clean observations must establish one stable profile"
            );
        }
        let profile: i64 = sqlx::query_scalar("SELECT id FROM voice_profiles WHERE account_id=$1")
            .bind(ACCOUNT)
            .fetch_one(repo.pool())
            .await
            .unwrap();
        let revisions_before: i64 =
            sqlx::query_scalar("SELECT count(*) FROM voice_profile_revisions WHERE account_id=$1")
                .bind(ACCOUNT)
                .fetch_one(repo.pool())
                .await
                .unwrap();
        seed_voice_observation(repo, ACCOUNT, "second-recording", "event-4", 4, 4).await;
        seed_voice_memory(repo, ACCOUNT, 4, 4).await;
        let claim = claim_one(repo, ACCOUNT).await;
        repo.settle_voice_embedding(&claim, outcome(0, SampleDecision::MatchOnly))
            .await
            .unwrap();
        assert_eq!(sqlx::query_scalar::<_,Option<i64>>("SELECT voice_profile_id FROM voice_samples WHERE account_id=$1 AND speaker_observation_id=4")
            .bind(ACCOUNT).fetch_one(repo.pool()).await.unwrap(), Some(profile),
            "a new recording must reuse a matching stable account voice before creating another profile");
        assert_eq!(
            sqlx::query_scalar::<_, i64>(
                "SELECT sample_count FROM voice_profiles WHERE account_id=$1 AND id=$2"
            )
            .bind(ACCOUNT)
            .bind(profile)
            .fetch_one(repo.pool())
            .await
            .unwrap(),
            3,
            "cross-recording match-only attachment must not grow the representative"
        );
        assert_eq!(
            sqlx::query_scalar::<_, i64>(
                "SELECT count(*) FROM voice_profile_revisions WHERE account_id=$1"
            )
            .bind(ACCOUNT)
            .fetch_one(repo.pool())
            .await
            .unwrap(),
            revisions_before
        );
        assert!(sqlx::query_scalar::<_,bool>("SELECT bool_and(derivation_version=3) FROM voice_profile_revisions WHERE account_id=$1")
            .bind(ACCOUNT).fetch_one(repo.pool()).await.unwrap(), "stability decisions must record their derivation version");
        assert_projection_source_unchanged(repo, ACCOUNT).await;
        cleanup(fixture).await;
    }

    #[tokio::test]
    async fn global_voice_matching_refuses_expired_support_and_a_different_domain() {
        let Some(fixture) = super::super::tests::test_persistence().await else {
            return;
        };
        let repo = &fixture.persistence;
        const ACCOUNT: &str = "recurring-retained-domain";
        repo.set_voice_identity_cohort(VoiceCohort::All, &[])
            .await
            .unwrap();
        for i in 1..=3 {
            seed_voice_observation(
                repo,
                ACCOUNT,
                "first-recording",
                &format!("event-{i}"),
                i,
                i,
            )
            .await;
            let claim = claim_one(repo, ACCOUNT).await;
            repo.settle_voice_embedding(&claim, outcome(0, SampleDecision::Enroll))
                .await
                .unwrap();
        }
        seed_voice_observation(repo, ACCOUNT, "other-domain", "event-4", 4, 4).await;
        sqlx::query("UPDATE capture_events SET audio_route='wired_headset' WHERE account_id=$1 AND event_id='event-4'")
            .bind(ACCOUNT).execute(repo.pool()).await.unwrap();
        let claim = claim_one(repo, ACCOUNT).await;
        let mut sample = outcome(0, SampleDecision::MatchOnly);
        if let VoiceEmbeddingOutcome::Sample { channel_domain, .. } = &mut sample {
            *channel_domain = "macos:wired_headset".into();
        }
        repo.settle_voice_embedding(&claim, sample).await.unwrap();
        assert_eq!(sqlx::query_scalar::<_,Option<i64>>("SELECT voice_profile_id FROM voice_samples WHERE account_id=$1 AND speaker_observation_id=4")
            .bind(ACCOUNT).fetch_one(repo.pool()).await.unwrap(), None,
            "account-wide matching must never cross acoustic domains");
        sqlx::query("UPDATE media_objects SET retain_until=clock_timestamp()-interval '1 second' WHERE account_id=$1 AND event_id='event-1'")
            .bind(ACCOUNT).execute(repo.pool()).await.unwrap();
        seed_voice_observation(repo, ACCOUNT, "expired-support", "event-5", 5, 5).await;
        let claim = claim_one(repo, ACCOUNT).await;
        repo.settle_voice_embedding(&claim, outcome(0, SampleDecision::MatchOnly))
            .await
            .unwrap();
        assert_eq!(sqlx::query_scalar::<_,Option<i64>>("SELECT voice_profile_id FROM voice_samples WHERE account_id=$1 AND speaker_observation_id=5")
            .bind(ACCOUNT).fetch_one(repo.pool()).await.unwrap(), None,
            "an expired centroid contribution must block global matching before maintenance runs");
        cleanup(fixture).await;
    }

    #[tokio::test]
    async fn voice_speaker_projection_attachment_and_propagation_refresh_every_memory() {
        let Some(fixture) = super::super::tests::test_persistence().await else {
            return;
        };
        let repo = &fixture.persistence;
        const ACCOUNT: &str = "voice-speaker-propagation";
        repo.set_voice_identity_cohort(VoiceCohort::All, &[])
            .await
            .unwrap();
        for i in 1..=2 {
            seed_voice_observation(repo, ACCOUNT, "session", &format!("event-{i}"), i, i).await;
            seed_voice_memory(repo, ACCOUNT, i, i).await;
            if i == 1 {
                sqlx::query("INSERT INTO episode_speaker_slots(account_id,id,episode_id,speaker_cluster_id,slot_ordinal) VALUES($1,100,1,1,5)").bind(ACCOUNT).execute(repo.pool()).await.unwrap();
            }
            let claim = claim_one(repo, ACCOUNT).await;
            repo.settle_voice_embedding(
                &claim,
                outcome(
                    0,
                    if i == 1 {
                        SampleDecision::Enroll
                    } else {
                        SampleDecision::MatchOnly
                    },
                ),
            )
            .await
            .unwrap();
        }
        let profile: i64 = sqlx::query_scalar(
            "SELECT voice_profile_id FROM speaker_clusters WHERE account_id=$1 AND id=1",
        )
        .bind(ACCOUNT)
        .fetch_one(repo.pool())
        .await
        .unwrap();
        assert_eq!(sqlx::query_as::<_,(i64,i64)>("SELECT episode_id,slot_ordinal FROM episode_speaker_slots WHERE account_id=$1 AND voice_profile_id=$2 AND status='active' ORDER BY episode_id").bind(ACCOUNT).bind(profile).fetch_all(repo.pool()).await.unwrap(), vec![(1,5),(2,0)], "voice attachment must synchronously upgrade existing cluster reservations and project every attached memory");
        seed_voice_observation(repo, ACCOUNT, "session", "event-3", 3, 3).await;
        seed_voice_memory(repo, ACCOUNT, 3, 3).await;
        super::super::identity_fusion_contract::intro(repo, ACCOUNT, 3, "Synthetic Person", false)
            .await;
        let claim = claim_one(repo, ACCOUNT).await;
        repo.settle_voice_embedding(&claim, outcome(0, SampleDecision::MatchOnly))
            .await
            .unwrap();
        for episode in 1..=3 {
            assert_eq!(projected_people(repo,ACCOUNT,episode).await, vec![1], "profile person propagation must refresh all previously attached memories before any reader prepares them");
        }
        assert_eq!(sqlx::query_scalar::<_,i64>("SELECT count(*) FROM episode_participants WHERE account_id=$1 AND state='active' AND derivation_version=2").bind(ACCOUNT).fetch_one(repo.pool()).await.unwrap(),3,"voice writer must persist current participant projections");
        assert_projection_source_unchanged(repo, ACCOUNT).await;
        cleanup(fixture).await;
    }

    #[tokio::test]
    async fn voice_speaker_projection_name_conflict_preserves_acoustics_and_withdraws_names() {
        let Some(fixture) = super::super::tests::test_persistence().await else {
            return;
        };
        let repo = &fixture.persistence;
        const ACCOUNT: &str = "voice-speaker-conflict";
        repo.set_voice_identity_cohort(VoiceCohort::All, &[])
            .await
            .unwrap();
        seed_voice_observation(repo, ACCOUNT, "session", "event-1", 1, 1).await;
        seed_voice_memory(repo, ACCOUNT, 1, 1).await;
        let first = claim_one(repo, ACCOUNT).await;
        repo.settle_voice_embedding(&first, outcome(0, SampleDecision::Enroll))
            .await
            .unwrap();
        let profile: i64 = sqlx::query_scalar(
            "SELECT voice_profile_id FROM speaker_clusters WHERE account_id=$1 AND id=1",
        )
        .bind(ACCOUNT)
        .fetch_one(repo.pool())
        .await
        .unwrap();
        for i in 2..=3 {
            seed_voice_observation(repo, ACCOUNT, "session", &format!("event-{i}"), i, i).await;
            seed_voice_memory(repo, ACCOUNT, i, i).await;
            super::super::identity_fusion_contract::intro(
                repo,
                ACCOUNT,
                i,
                if i == 2 {
                    "Synthetic One"
                } else {
                    "Synthetic Two"
                },
                false,
            )
            .await;
            let claim = claim_one(repo, ACCOUNT).await;
            repo.settle_voice_embedding(&claim, outcome(0, SampleDecision::MatchOnly))
                .await
                .unwrap();
            if i == 2 {
                assert_eq!(projected_people(repo, ACCOUNT, 1).await, vec![1]);
            }
        }
        for episode in 1..=3 {
            assert!(
                projected_people(repo, ACCOUNT, episode).await.is_empty(),
                "name conflict must synchronously withdraw all cached profile names"
            );
        }
        assert!(
            sqlx::query_scalar::<_, bool>(
                "SELECT status<>'quarantined' FROM voice_profiles WHERE account_id=$1 AND id=$2"
            )
            .bind(ACCOUNT)
            .bind(profile)
            .fetch_one(repo.pool())
            .await
            .unwrap(),
            "conflicting spoken names must preserve a healthy acoustic profile"
        );
        assert!(sqlx::query_scalar::<_,bool>("SELECT status='quarantined' FROM profile_name_bindings WHERE account_id=$1 AND profile_id=$2").bind(ACCOUNT).bind(profile).fetch_one(repo.pool()).await.unwrap(),"conflicting introductions must quarantine only the name binding");
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT count(*) FROM people WHERE account_id=$1")
                .bind(ACCOUNT)
                .fetch_one(repo.pool())
                .await
                .unwrap(),
            2,
            "name conflict must retain both source person nodes"
        );
        assert!(sqlx::query_scalar::<_,bool>("SELECT state='ready' AND lease_token IS NULL FROM voice_embedding_jobs WHERE account_id=$1 AND id=3").bind(ACCOUNT).fetch_one(repo.pool()).await.unwrap(),"quarantine projection refresh must release its settled voice lease");
        assert_projection_source_unchanged(repo, ACCOUNT).await;
        cleanup(fixture).await;
    }

    #[tokio::test]
    async fn voice_speaker_projection_erasure_refreshes_surviving_and_source_empty_memories() {
        let Some(fixture) = super::super::tests::test_persistence().await else {
            return;
        };
        let repo = &fixture.persistence;
        const ACCOUNT: &str = "voice-speaker-erasure";
        repo.set_voice_identity_cohort(VoiceCohort::All, &[])
            .await
            .unwrap();
        for i in 1..=2 {
            seed_voice_observation(repo, ACCOUNT, "session", &format!("event-{i}"), i, i).await;
            seed_voice_memory(repo, ACCOUNT, i, i).await;
            if i == 1 {
                sqlx::query("INSERT INTO people(account_id,id,display_name,status) VALUES($1,1,'Synthetic Person','identified')").bind(ACCOUNT).execute(repo.pool()).await.unwrap();
                sqlx::query("UPDATE speaker_clusters SET person_id=1,attribution_state='person_bound' WHERE account_id=$1 AND id=1").bind(ACCOUNT).execute(repo.pool()).await.unwrap();
            }
            let claim = claim_one(repo, ACCOUNT).await;
            repo.settle_voice_embedding(
                &claim,
                outcome(
                    0,
                    if i == 1 {
                        SampleDecision::Enroll
                    } else {
                        SampleDecision::MatchOnly
                    },
                ),
            )
            .await
            .unwrap();
        }
        assert_eq!(projected_people(repo, ACCOUNT, 2).await, vec![1]);
        // Historical contradictory direct evidence must not abort erasure.
        sqlx::query("INSERT INTO people(account_id,id,display_name,status) VALUES($1,2,'Different Direct Person','identified')").bind(ACCOUNT).execute(repo.pool()).await.unwrap();
        sqlx::query("UPDATE speaker_observations SET person_id=2 WHERE account_id=$1 AND id=2")
            .bind(ACCOUNT)
            .execute(repo.pool())
            .await
            .unwrap();
        sqlx::query("UPDATE speaker_clusters SET person_id=1,attribution_state='person_bound' WHERE account_id=$1 AND id=2").bind(ACCOUNT).execute(repo.pool()).await.unwrap();
        let mut tx = repo.pool().begin().await.unwrap();
        lock_account(&mut tx, ACCOUNT).await.unwrap();
        let profiles = erase_event_samples(&mut tx, ACCOUNT, &["event-1".into()])
            .await
            .unwrap();
        sqlx::query("DELETE FROM capture_events WHERE account_id=$1 AND event_id='event-1'")
            .bind(ACCOUNT)
            .execute(&mut *tx)
            .await
            .unwrap();
        recompute_erased_profiles(&mut tx, ACCOUNT, &profiles)
            .await
            .unwrap();
        tx.commit().await.unwrap();
        assert!(projected_people(repo,ACCOUNT,2).await.is_empty(),"erasure quarantine must synchronously clear profile-derived people in all surviving memories");
        assert!(
            projected_people(repo, ACCOUNT, 1).await.is_empty(),
            "erasure must clear cached named participants after their last observation disappears"
        );
        assert_eq!(sqlx::query_scalar::<_,i64>("SELECT count(*) FROM episode_participants WHERE account_id=$1 AND episode_id=2 AND state='active' AND participant_key LIKE 'voice_profile:%' AND person_id IS NULL").bind(ACCOUNT).fetch_one(repo.pool()).await.unwrap(),1,"erasure must retain an anonymous persisted participant for surviving voice evidence");
        assert!(sqlx::query_scalar::<_,bool>("SELECT bool_and(status='quarantined' AND octet_length(centroid)=0) FROM voice_profiles WHERE account_id=$1").bind(ACCOUNT).fetch_one(repo.pool()).await.unwrap(),"speaker refresh must not roll back biometric erasure");
        assert_projection_source_unchanged(repo, ACCOUNT).await;
        cleanup(fixture).await;
    }

    #[tokio::test]
    async fn leases_expiry_fences_and_cas_are_provider_free() {
        let Some(fixture) = super::super::tests::test_persistence().await else {
            return;
        };
        let repo = &fixture.persistence;
        repo.set_voice_identity_cohort(VoiceCohort::All, &[])
            .await
            .unwrap();
        seed_voice_observation(repo, "voice-lease", "session", "expired", 1, 1).await;
        seed_voice_observation(repo, "voice-lease", "session", "live", 2, 2).await;
        sqlx::query("UPDATE media_objects SET retain_until=clock_timestamp()-interval '1 second' WHERE account_id='voice-lease' AND event_id='expired'").execute(repo.pool()).await.unwrap();
        let batch = repo
            .claim_voice_embeddings("voice-lease", "first")
            .await
            .unwrap();
        assert_eq!(
            batch.expired_count, 1,
            "expired voice media must terminalize before provider access"
        );
        assert_eq!(batch.claims.len(), 1);
        let claim = &batch.claims[0];
        assert!(
            repo.claim_voice_embeddings("voice-lease", "second")
                .await
                .unwrap()
                .claims
                .is_empty(),
            "replicas must not overtake a live voice batch"
        );
        let mut stale = claim.clone();
        stale.lease_token = "stale-token".into();
        assert!(
            !repo
                .settle_voice_embedding(&stale, outcome(0, SampleDecision::Enroll))
                .await
                .unwrap(),
            "stale voice lease must not write a sample"
        );
        repo.set_voice_identity_paused(true).await.unwrap();
        repo.settle_voice_embedding(claim, outcome(0, SampleDecision::Enroll))
            .await
            .unwrap();
        let row=sqlx::query("SELECT state,attempt_count,lease_owner,lease_token,lease_until::text AS lease_until FROM voice_embedding_jobs WHERE account_id='voice-lease' AND id=2").fetch_one(repo.pool()).await.unwrap();
        assert_eq!(
            row.get::<String, _>("state"),
            "retry_wait",
            "pause must freeze in-flight voice identity settlement"
        );
        assert_eq!(row.get::<i64, _>("attempt_count"), 0);
        assert!(row.get::<Option<String>, _>("lease_owner").is_none());
        assert!(row.get::<Option<String>, _>("lease_token").is_none());
        assert!(row.get::<Option<String>, _>("lease_until").is_none());
        assert_eq!(
            sqlx::query_scalar::<_, i64>(
                "SELECT count(*) FROM voice_samples WHERE account_id='voice-lease'"
            )
            .fetch_one(repo.pool())
            .await
            .unwrap(),
            0
        );
        repo.set_voice_identity_paused(false).await.unwrap();
        sqlx::query("UPDATE voice_embedding_jobs SET next_attempt_at=NULL,attempt_count=3 WHERE account_id='voice-lease' AND id=2").execute(repo.pool()).await.unwrap();
        assert_eq!(
            repo.claim_voice_embeddings("voice-lease", "third")
                .await
                .unwrap()
                .exhausted_count,
            1,
            "voice attempts must be bounded"
        );
        assert!(sqlx::query_scalar::<_,bool>("SELECT state='failed' AND lease_owner IS NULL AND lease_token IS NULL AND lease_until IS NULL FROM voice_embedding_jobs WHERE account_id='voice-lease' AND id=2").fetch_one(repo.pool()).await.unwrap(),"attempt exhaustion must release the complete voice lease");
        seed_voice_observation(repo, "voice-lease", "session", "short", 3, 3).await;
        let short = claim_one(repo, "voice-lease").await;
        repo.settle_voice_embedding(
            &short,
            VoiceEmbeddingOutcome::NoEmbedding {
                diagnostics: voice_quality::diagnose(&[0.1; 8000], false, &[]),
            },
        )
        .await
        .unwrap();
        assert!(sqlx::query_scalar::<_,bool>("SELECT state='ready' AND error_code='no_embedding' AND lease_owner IS NULL AND lease_token IS NULL AND lease_until IS NULL FROM voice_embedding_jobs WHERE account_id='voice-lease' AND id=3").fetch_one(repo.pool()).await.unwrap(),"no-embedding settlement must be terminal and release the complete lease");
        assert_eq!(
            sqlx::query_scalar::<_, i64>(
                "SELECT count(*) FROM voice_samples WHERE account_id='voice-lease'"
            )
            .fetch_one(repo.pool())
            .await
            .unwrap(),
            0,
            "no-embedding outcomes must not persist a sample"
        );
        cleanup(fixture).await;
    }
    #[tokio::test]
    async fn continuity_propagates_names_and_holds_name_conflicts_without_match_only_growth() {
        let Some(fixture) = super::super::tests::test_persistence().await else {
            return;
        };
        let repo = &fixture.persistence;
        repo.set_voice_identity_cohort(VoiceCohort::All, &[])
            .await
            .unwrap();
        seed_voice_observation(repo, "voice-continuity", "same-session", "one", 1, 1).await;
        let first = claim_one(repo, "voice-continuity").await;
        assert!(repo
            .settle_voice_embedding(&first, outcome(0, SampleDecision::Enroll))
            .await
            .unwrap());
        let profile:i64=sqlx::query_scalar("SELECT voice_profile_id FROM speaker_clusters WHERE account_id='voice-continuity' AND id=1").fetch_one(repo.pool()).await.unwrap();
        seed_voice_observation(repo, "voice-continuity", "same-session", "two", 2, 2).await;
        let second = claim_one(repo, "voice-continuity").await;
        repo.settle_voice_embedding(&second, outcome(0, SampleDecision::MatchOnly))
            .await
            .unwrap();
        let attached:i64=sqlx::query_scalar("SELECT voice_profile_id FROM speaker_clusters WHERE account_id='voice-continuity' AND id=2").fetch_one(repo.pool()).await.unwrap();
        assert_eq!(
            attached, profile,
            "same-session windows must attach to one voice profile"
        );
        assert_eq!(
            sqlx::query_scalar::<_, i64>(
                "SELECT count(*) FROM voice_profile_revisions WHERE account_id='voice-continuity'"
            )
            .fetch_one(repo.pool())
            .await
            .unwrap(),
            1,
            "match-only attachment must not create profile revisions"
        );
        assert_eq!(sqlx::query_scalar::<_,i64>("SELECT sample_count FROM voice_profiles WHERE account_id='voice-continuity' AND id=$1").bind(profile).fetch_one(repo.pool()).await.unwrap(),1,"match-only attachment must not grow a centroid");
        seed_voice_observation(repo, "voice-continuity", "same-session", "three", 3, 3).await;
        super::super::identity_fusion_contract::intro(
            repo,
            "voice-continuity",
            3,
            "Synthetic One",
            false,
        )
        .await;
        let third = claim_one(repo, "voice-continuity").await;
        repo.settle_voice_embedding(&third, outcome(0, SampleDecision::Enroll))
            .await
            .unwrap();
        assert_eq!(sqlx::query_scalar::<_,Option<i64>>("SELECT person_id FROM voice_profiles WHERE account_id='voice-continuity' AND id=$1").bind(profile).fetch_one(repo.pool()).await.unwrap(),Some(1),"person-bound clusters must propagate their profile identity");
        seed_voice_observation(repo, "voice-continuity", "same-session", "four", 4, 4).await;
        super::super::identity_fusion_contract::intro(
            repo,
            "voice-continuity",
            4,
            "Synthetic Two",
            false,
        )
        .await;
        let fourth = claim_one(repo, "voice-continuity").await;
        repo.settle_voice_embedding(&fourth, outcome(0, SampleDecision::Enroll))
            .await
            .unwrap();
        let status: String = sqlx::query_scalar(
            "SELECT status FROM voice_profiles WHERE account_id='voice-continuity' AND id=$1",
        )
        .bind(profile)
        .fetch_one(repo.pool())
        .await
        .unwrap();
        assert_eq!(
            status, "stable",
            "conflicting names must preserve the matched acoustic profile"
        );
        assert_eq!(sqlx::query_scalar::<_,Option<i64>>("SELECT voice_profile_id FROM voice_samples WHERE account_id='voice-continuity' AND speaker_observation_id=4").fetch_one(repo.pool()).await.unwrap(),Some(profile));
        assert!(sqlx::query_scalar::<_,bool>("SELECT status='quarantined' FROM profile_name_bindings WHERE account_id='voice-continuity' AND profile_id=$1").bind(profile).fetch_one(repo.pool()).await.unwrap(),"voice continuity must quarantine incompatible name evidence separately");
        let count: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM voice_samples WHERE account_id='voice-continuity'",
        )
        .fetch_one(repo.pool())
        .await
        .unwrap();
        assert!(!repo
            .settle_voice_embedding(&fourth, outcome(0, SampleDecision::Enroll))
            .await
            .unwrap());
        assert_eq!(
            sqlx::query_scalar::<_, i64>(
                "SELECT count(*) FROM voice_samples WHERE account_id='voice-continuity'"
            )
            .fetch_one(repo.pool())
            .await
            .unwrap(),
            count,
            "replayed settlement must not duplicate samples"
        );
        cleanup(fixture).await;
    }
    #[tokio::test]
    async fn sample_erasure_recomputes_then_quarantines_without_surviving_enrollment() {
        let Some(fixture) = super::super::tests::test_persistence().await else {
            return;
        };
        let repo = &fixture.persistence;
        repo.set_voice_identity_cohort(VoiceCohort::All, &[])
            .await
            .unwrap();
        for i in 1..=2 {
            seed_voice_observation(
                repo,
                "voice-erasure",
                "session",
                &format!("event-{i}"),
                i,
                i,
            )
            .await;
            let claim = claim_one(repo, "voice-erasure").await;
            let mut sample = outcome(0, SampleDecision::Enroll);
            if i == 2 {
                if let VoiceEmbeddingOutcome::Sample { embedding, .. } = &mut sample {
                    embedding[0] = 0.8;
                    embedding[1] = 0.6;
                }
            }
            repo.settle_voice_embedding(&claim, sample).await.unwrap();
        }
        let profile: i64 =
            sqlx::query_scalar("SELECT id FROM voice_profiles WHERE account_id='voice-erasure'")
                .fetch_one(repo.pool())
                .await
                .unwrap();
        for (event, expected_count, expected_status) in
            [("event-1", 1, "tentative"), ("event-2", 0, "quarantined")]
        {
            let mut tx = repo.pool().begin().await.unwrap();
            lock_account(&mut tx, "voice-erasure").await.unwrap();
            let profiles = erase_event_samples(&mut tx, "voice-erasure", &[event.into()])
                .await
                .unwrap();
            sqlx::query(
                "DELETE FROM capture_events WHERE account_id='voice-erasure' AND event_id=$1",
            )
            .bind(event)
            .execute(&mut *tx)
            .await
            .unwrap();
            recompute_erased_profiles(&mut tx, "voice-erasure", &profiles)
                .await
                .unwrap();
            tx.commit().await.unwrap();
            let row=sqlx::query("SELECT sample_count,status FROM voice_profiles WHERE account_id='voice-erasure' AND id=$1").bind(profile).fetch_one(repo.pool()).await.unwrap();
            assert_eq!(
                row.get::<i64, _>("sample_count"),
                expected_count,
                "erasure must recompute profile sample counts in its transaction"
            );
            assert_eq!(
                row.get::<String, _>("status"),
                expected_status,
                "erasure must quarantine a profile without enrollment evidence"
            );
            assert_eq!(sqlx::query_scalar::<_,i64>("SELECT count(*) FROM voice_profile_revisions WHERE account_id='voice-erasure' AND NOT active AND octet_length(centroid)>0").fetch_one(repo.pool()).await.unwrap(),0,"erased voice must be redacted from every historical revision centroid");
            let bytes:Vec<u8>=sqlx::query_scalar("SELECT centroid FROM voice_profile_revisions WHERE account_id='voice-erasure' AND active").fetch_one(repo.pool()).await.unwrap();
            if expected_count == 0 {
                assert!(
                    bytes.is_empty(),
                    "complete erasure must clear the current revision centroid"
                );
            } else {
                let current = voice_identity::decode_embedding(&bytes).unwrap();
                assert!((current[0]-0.8).abs()<0.0001 && (current[1]-0.6).abs()<0.0001,"partial erasure current revision must contain only surviving enrollment evidence");
            }
        }
        assert_eq!(sqlx::query_scalar::<_,i64>("SELECT count(*) FROM voice_profile_representatives WHERE account_id='voice-erasure'").fetch_one(repo.pool()).await.unwrap(),0);
        cleanup(fixture).await;
    }
    #[tokio::test]
    async fn session_domain_owner_and_quarantine_boundaries_keep_samples_unassigned() {
        let Some(fixture) = super::super::tests::test_persistence().await else {
            return;
        };
        let repo = &fixture.persistence;
        repo.set_voice_identity_cohort(VoiceCohort::All, &[])
            .await
            .unwrap();
        seed_voice_observation(repo, "voice-boundaries", "session-one", "one", 1, 1).await;
        let first = claim_one(repo, "voice-boundaries").await;
        repo.settle_voice_embedding(&first, outcome(0, SampleDecision::Enroll))
            .await
            .unwrap();
        seed_voice_observation(repo, "voice-boundaries", "session-two", "two", 2, 2).await;
        let second = claim_one(repo, "voice-boundaries").await;
        repo.settle_voice_embedding(&second, outcome(0, SampleDecision::MatchOnly))
            .await
            .unwrap();
        assert_eq!(sqlx::query_scalar::<_,Option<i64>>("SELECT voice_profile_id FROM voice_samples WHERE account_id='voice-boundaries' AND speaker_observation_id=2").fetch_one(repo.pool()).await.unwrap(),None,"continuity must not match voices across capture sessions");
        seed_voice_observation(repo, "voice-boundaries", "session-one", "three", 3, 3).await;
        sqlx::query("UPDATE speaker_clusters SET attribution_state='owner_transmit' WHERE account_id='voice-boundaries' AND id=3").execute(repo.pool()).await.unwrap();
        let third = claim_one(repo, "voice-boundaries").await;
        repo.settle_voice_embedding(&third, outcome(0, SampleDecision::Enroll))
            .await
            .unwrap();
        assert_eq!(sqlx::query_scalar::<_,Option<i64>>("SELECT voice_profile_id FROM voice_samples WHERE account_id='voice-boundaries' AND speaker_observation_id=3").fetch_one(repo.pool()).await.unwrap(),None,"owner-transmit samples must remain outside Phase 1 matching");
        seed_voice_observation(repo, "voice-boundaries", "session-one", "four", 4, 4).await;
        let fourth = claim_one(repo, "voice-boundaries").await;
        repo.settle_voice_embedding(&fourth, outcome(0, SampleDecision::Quarantine))
            .await
            .unwrap();
        assert!(!sqlx::query_scalar::<_,bool>("SELECT accepted FROM voice_samples WHERE account_id='voice-boundaries' AND speaker_observation_id=4").fetch_one(repo.pool()).await.unwrap(),"quarantine eligibility must never accept an enrollment sample");
        seed_voice_observation(repo, "voice-boundaries", "session-one", "five", 5, 5).await;
        sqlx::query("UPDATE voice_profiles SET channel_domain='ios:builtin_mic' WHERE account_id='voice-boundaries'").execute(repo.pool()).await.unwrap();
        let fifth = claim_one(repo, "voice-boundaries").await;
        repo.settle_voice_embedding(&fifth, outcome(0, SampleDecision::MatchOnly))
            .await
            .unwrap();
        assert_eq!(sqlx::query_scalar::<_,Option<i64>>("SELECT voice_profile_id FROM voice_samples WHERE account_id='voice-boundaries' AND speaker_observation_id=5").fetch_one(repo.pool()).await.unwrap(),None,"continuity must not match voices across acoustic domains");
        cleanup(fixture).await;
    }
    #[tokio::test]
    async fn deletion_fence_wins_expiry_and_inactive_account_settlement_restores_attempts() {
        let Some(fixture) = super::super::tests::test_persistence().await else {
            return;
        };
        let repo = &fixture.persistence;
        repo.set_voice_identity_cohort(VoiceCohort::All, &[])
            .await
            .unwrap();
        seed_voice_observation(repo, "voice-fence", "session", "one", 1, 1).await;
        sqlx::query("INSERT INTO episode_deletions(account_id,episode_id,state,purge,media_object_keys,utterance_ids,screenshot_ids,segment_ids,orphan_event_ids) VALUES('voice-fence',1,'pending','{}','[]','[]','[]','[]','[\"one\"]')").execute(repo.pool()).await.unwrap();
        sqlx::query("UPDATE media_objects SET retain_until=clock_timestamp()-interval '1 second' WHERE account_id='voice-fence'").execute(repo.pool()).await.unwrap();
        let batch = repo
            .claim_voice_embeddings("voice-fence", "worker")
            .await
            .unwrap();
        assert_eq!(
            batch.expired_count, 0,
            "pending deletion must skip rather than expire voice jobs"
        );
        assert!(batch.claims.is_empty());
        let row=sqlx::query("SELECT state,attempt_count,lease_token FROM voice_embedding_jobs WHERE account_id='voice-fence'").fetch_one(repo.pool()).await.unwrap();
        assert_eq!(row.get::<String, _>("state"), "retry_wait");
        assert_eq!(row.get::<i64, _>("attempt_count"), 0);
        assert!(row.get::<Option<String>, _>("lease_token").is_none());
        seed_voice_observation(repo, "voice-inactive", "session", "two", 2, 2).await;
        let claim = claim_one(repo, "voice-inactive").await;
        sqlx::query("UPDATE accounts SET status='deletion_requested' WHERE id='voice-inactive'")
            .execute(repo.pool())
            .await
            .unwrap();
        repo.settle_voice_embedding(&claim, outcome(0, SampleDecision::Enroll))
            .await
            .unwrap();
        let row=sqlx::query("SELECT state,attempt_count,lease_token FROM voice_embedding_jobs WHERE account_id='voice-inactive'").fetch_one(repo.pool()).await.unwrap();
        assert_eq!(
            row.get::<String, _>("state"),
            "retry_wait",
            "inactive account must not receive voice identity writes"
        );
        assert_eq!(row.get::<i64, _>("attempt_count"), 0);
        assert!(row.get::<Option<String>, _>("lease_token").is_none());
        cleanup(fixture).await;
    }
    #[tokio::test]
    async fn paged_deletion_inventory_fences_after_members_are_purged() {
        let Some(fixture) = super::super::tests::test_persistence().await else {
            return;
        };
        let repo = &fixture.persistence;
        repo.install_memory_reconciliation_activation_schema()
            .await
            .unwrap();
        repo.set_voice_identity_cohort(VoiceCohort::All, &[])
            .await
            .unwrap();
        let account = "voice-paged-fence";
        seed_voice_observation(repo, account, "session", "one", 1, 1).await;
        sqlx::query("INSERT INTO episodes(account_id,id,started_at,ended_at,title) VALUES($1,1,now(),now(),'Synthetic deletion target')").bind(account).execute(repo.pool()).await.unwrap();
        sqlx::query("INSERT INTO audio_segments(account_id,id,started_at,ended_at,duration_seconds,source_type) VALUES($1,1,now(),now()+interval '4 seconds',4,'mic')").bind(account).execute(repo.pool()).await.unwrap();
        sqlx::query("INSERT INTO utterances(account_id,id,audio_segment_id,start_offset_seconds,end_offset_seconds,text,speaker_label,speaker_observation_id) VALUES($1,1,1,0,4,'Synthetic fixture','Speaker',1)").bind(account).execute(repo.pool()).await.unwrap();
        sqlx::query("INSERT INTO episode_members(account_id,episode_id,record_type,record_id) VALUES($1,1,'utterance',1)").bind(account).execute(repo.pool()).await.unwrap();
        let claim = claim_one(repo, account).await;
        // A result may already exist in enclave memory when the independently
        // paged deletion advances beyond utterances but before source erasure.
        let wav = crate::cp::voice_memory::encode_mono_16khz_wav(&vec![0.1; 64000]).unwrap();
        let decoded = crate::cp::voice_memory::decode_mono_16khz(&wav, "audio/wav").unwrap();
        let decoded_outcome = VoiceEmbeddingOutcome::Sample {
            embedding: embedding(0),
            diagnostics: voice_quality::diagnose(&decoded, false, &[]),
            channel_domain: "macos:builtin_mic".into(),
        };
        seed_voice_observation(repo, account, "session", "two", 2, 2).await;
        seed_voice_observation(repo, account, "session", "three", 3, 3).await;
        // Only the root appears in planned events: its reference family must
        // still be fenced, including a new observation without old membership.
        sqlx::query("UPDATE capture_events SET media_disposition='reference',canonical_event_id='one',canonical_asset_id='one' WHERE account_id=$1 AND event_id='two'").bind(account).execute(repo.pool()).await.unwrap();
        sqlx::query("INSERT INTO episode_deletions(account_id,episode_id,state,purge,media_object_keys,utterance_ids,screenshot_ids,segment_ids,orphan_event_ids) VALUES($1,1,'pending','{}','[]','[]','[]','[]','[]')").bind(account).execute(repo.pool()).await.unwrap();
        sqlx::query("INSERT INTO persistence_feature_episode_deletion_progress(account_id,episode_id,phase,coordinate_sha256) VALUES($1,1,'purge_members',decode(repeat('00',32),'hex'))").bind(account).execute(repo.pool()).await.unwrap();
        sqlx::query("INSERT INTO persistence_feature_episode_deletion_roots(account_id,episode_id,root_event_id,disposition,coordinate_sha256,classified_at) SELECT $1,1,event_id,'orphan',decode(repeat('00',32),'hex'),now() FROM capture_events WHERE account_id=$1 AND event_id IN ('one','three')").bind(account).execute(repo.pool()).await.unwrap();
        sqlx::query("INSERT INTO persistence_feature_episode_deletion_events(account_id,episode_id,root_event_id,event_id,capture_session_id,stream_id,sequence,manifest_digest,coordinate_sha256) SELECT $1,1,event_id,event_id,capture_session_id,stream_id,sequence,manifest_digest,decode(repeat('00',32),'hex') FROM capture_events WHERE account_id=$1 AND event_id IN ('one','three')").bind(account).execute(repo.pool()).await.unwrap();
        sqlx::query("DELETE FROM episode_members WHERE account_id=$1")
            .bind(account)
            .execute(repo.pool())
            .await
            .unwrap();
        sqlx::query("DELETE FROM utterances WHERE account_id=$1")
            .bind(account)
            .execute(repo.pool())
            .await
            .unwrap();
        sqlx::query("UPDATE persistence_feature_episode_deletion_progress SET phase='tombstone_events' WHERE account_id=$1").bind(account).execute(repo.pool()).await.unwrap();
        assert!(sqlx::query_scalar::<_,bool>("SELECT retain_until>clock_timestamp() AND deleted_at IS NULL FROM media_objects WHERE account_id=$1 AND event_id='one'").bind(account).fetch_one(repo.pool()).await.unwrap(),"phase-gap fixture must retain already-decoded source media");
        assert!(repo
            .settle_voice_embedding(&claim, decoded_outcome)
            .await
            .unwrap());
        let row=sqlx::query("SELECT state,attempt_count,lease_owner IS NULL AND lease_token IS NULL AND lease_until IS NULL AS released FROM voice_embedding_jobs WHERE account_id=$1 AND id=1").bind(account).fetch_one(repo.pool()).await.unwrap();
        assert_eq!(
            row.get::<String, _>("state"),
            "retry_wait",
            "paged deletion inventory must fence decoded voice settlement after member purge"
        );
        assert_eq!(
            row.get::<i64, _>("attempt_count"),
            0,
            "paged deletion skip must restore the pre-deletion attempt"
        );
        assert!(
            row.get::<bool, _>("released"),
            "paged deletion skip must release the whole voice lease"
        );
        sqlx::query("UPDATE media_objects SET retain_until=clock_timestamp()-interval '1 second' WHERE account_id=$1 AND event_id='three'").bind(account).execute(repo.pool()).await.unwrap();
        let batch = repo
            .claim_voice_embeddings(account, "second-worker")
            .await
            .unwrap();
        assert!(
            batch.claims.is_empty(),
            "paged deletion inventory must fence new claims across canonical families"
        );
        assert_eq!(
            batch.expired_count, 0,
            "paged deletion inventory must take precedence over raw expiry after member purge"
        );
        assert_eq!(sqlx::query_scalar::<_,i64>("SELECT count(*) FROM voice_embedding_jobs WHERE account_id=$1 AND state='retry_wait' AND attempt_count=0 AND lease_owner IS NULL AND lease_token IS NULL AND lease_until IS NULL").bind(account).fetch_one(repo.pool()).await.unwrap(),3);
        assert_eq!(sqlx::query_scalar::<_,i64>("SELECT (SELECT count(*) FROM voice_samples WHERE account_id=$1)+(SELECT count(*) FROM voice_profiles WHERE account_id=$1)+(SELECT count(*) FROM speaker_clusters WHERE account_id=$1 AND voice_profile_id IS NOT NULL)").bind(account).fetch_one(repo.pool()).await.unwrap(),0,"pending paged deletion must prevent samples and all profile binding effects");
        cleanup(fixture).await;
    }
    #[tokio::test]
    async fn voice_lineage_ids_advance_past_rows_that_predate_counters() {
        let Some(fixture) = super::super::tests::test_persistence().await else {
            return;
        };
        let repo = &fixture.persistence;
        repo.set_voice_identity_cohort(VoiceCohort::All, &[])
            .await
            .unwrap();
        let account = "voice-legacy-ids";
        seed_voice_observation(repo, account, "session-one", "one", 1, 1).await;
        let first = claim_one(repo, account).await;
        repo.settle_voice_embedding(&first, outcome(0, SampleDecision::Enroll))
            .await
            .unwrap();
        // Voice lineage existed before the serving counter producer. All five
        // families must allocate beyond surviving rows when counters are absent.
        sqlx::query("DELETE FROM content_id_counters WHERE account_id=$1")
            .bind(account)
            .execute(repo.pool())
            .await
            .unwrap();
        seed_voice_observation(repo, account, "session-two", "two", 2, 2).await;
        let second = claim_one(repo, account).await;
        repo.settle_voice_embedding(&second, outcome(1, SampleDecision::Enroll))
            .await
            .expect("counterless legacy voice rows must not collide with serving allocations");
        let ids=sqlx::query("SELECT (SELECT max(id) FROM voice_samples WHERE account_id=$1) AS sample,(SELECT max(id) FROM voice_profiles WHERE account_id=$1) AS profile,(SELECT max(id) FROM voice_profile_revisions WHERE account_id=$1) AS revision,(SELECT max(id) FROM voice_profile_representatives WHERE account_id=$1) AS representative,(SELECT max(id) FROM voice_sample_profile_assignments WHERE account_id=$1) AS assignment").bind(account).fetch_one(repo.pool()).await.unwrap();
        for column in [
            "sample",
            "profile",
            "revision",
            "representative",
            "assignment",
        ] {
            assert_eq!(
                ids.get::<i64, _>(column),
                2,
                "each voice id family must advance beyond its counterless legacy rows"
            );
        }
        sqlx::query("UPDATE content_id_counters SET next_id=1 WHERE account_id=$1")
            .bind(account)
            .execute(repo.pool())
            .await
            .unwrap();
        let mut tx = repo.pool().begin().await.unwrap();
        lock_account(&mut tx, account).await.unwrap();
        let profiles = erase_event_samples(&mut tx, account, &["one".into()])
            .await
            .unwrap();
        recompute_erased_profiles(&mut tx, account, &profiles)
            .await
            .expect("erasure revisions must advance stale legacy counters");
        tx.commit().await.unwrap();
        assert_eq!(
            sqlx::query_scalar::<_, i64>(
                "SELECT max(id) FROM voice_profile_revisions WHERE account_id=$1"
            )
            .bind(account)
            .fetch_one(repo.pool())
            .await
            .unwrap(),
            3,
            "erasure must append beyond existing lineage revisions"
        );
        cleanup(fixture).await;
    }
    #[tokio::test]
    async fn erasure_scrubs_historical_assignments_and_legacy_direct_profile_links() {
        let Some(fixture) = super::super::tests::test_persistence().await else {
            return;
        };
        let repo = &fixture.persistence;
        repo.set_voice_identity_cohort(VoiceCohort::All, &[])
            .await
            .unwrap();
        let account = "voice-historical-erasure";
        seed_voice_observation(repo, account, "session", "one", 1, 1).await;
        let claim = claim_one(repo, account).await;
        repo.settle_voice_embedding(&claim, outcome(0, SampleDecision::Enroll))
            .await
            .unwrap();
        // A historical profile assignment and an old direct-only link may both
        // contain the erased sample even when neither is its current assignment.
        sqlx::query("INSERT INTO voice_profiles(account_id,id,label,embedding_space,channel_domain,centroid,sample_count,medoid_sample_id) SELECT account_id,n,'voice-profile-'||n,embedding_space,channel_domain,centroid,sample_count,medoid_sample_id FROM voice_profiles CROSS JOIN generate_series(2,3) n WHERE account_id=$1 AND id=1").bind(account).execute(repo.pool()).await.unwrap();
        sqlx::query("INSERT INTO voice_profile_revisions(account_id,id,profile_id,status,derivation_version,scorer_version,representative_kind,centroid,sample_count,medoid_sample_id,reason_code) SELECT account_id,id,id,status,1,scorer_version,representative_kind,centroid,sample_count,medoid_sample_id,'legacy_fixture' FROM voice_profiles WHERE account_id=$1 AND id IN (2,3)").bind(account).execute(repo.pool()).await.unwrap();
        sqlx::query("INSERT INTO voice_sample_profile_assignments(account_id,id,sample_id,profile_id,active) VALUES($1,2,1,2,false)").bind(account).execute(repo.pool()).await.unwrap();
        sqlx::query("UPDATE voice_samples SET voice_profile_id=3 WHERE account_id=$1 AND id=1")
            .bind(account)
            .execute(repo.pool())
            .await
            .unwrap();
        let mut tx = repo.pool().begin().await.unwrap();
        lock_account(&mut tx, account).await.unwrap();
        let profiles = erase_event_samples(&mut tx, account, &["one".into()])
            .await
            .unwrap();
        assert_eq!(
            profiles.profiles,
            vec![1, 2, 3],
            "erasure must include historical assignments and legacy direct profile links"
        );
        recompute_erased_profiles(&mut tx, account, &profiles)
            .await
            .unwrap();
        tx.commit().await.unwrap();
        assert_eq!(sqlx::query_scalar::<_,i64>("SELECT count(*) FROM voice_profile_revisions WHERE account_id=$1 AND octet_length(centroid)>0").bind(account).fetch_one(repo.pool()).await.unwrap(),0,"erasure must scrub biometrics from every historical profile owner");
        assert_eq!(sqlx::query_scalar::<_,i64>("SELECT count(*) FROM voice_profiles WHERE account_id=$1 AND status='quarantined' AND sample_count=0 AND octet_length(centroid)=0").bind(account).fetch_one(repo.pool()).await.unwrap(),3);
        cleanup(fixture).await;
    }
}
