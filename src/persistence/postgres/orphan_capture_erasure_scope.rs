//! Fixed orphan-only scope closure. Source/content commitments are calculated
//! within PostgreSQL; no plaintext projection is returned to the operator.

use serde::Serialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use sqlx::{PgConnection, Row};

use super::orphan_capture_erasure_authority::{sha256_label, ErasureCounts, ErasureTargets};
use crate::error::{EnclaveError, Result};

const SCOPE_SQL: &str = include_str!("orphan_capture_erasure_scope.sql");
const MAX_COMMITTED_ROWS: i64 = 100_000;

// Fixed compiled table/filter pairs, never a caller-selected SQL surface. Every
// row is classified once; comparing the survivor root across the mutation also
// catches unintended FK cascade/SET NULL effects and content changes.
const CONTENT_PARTITIONS: &[(&str, &str)] = &[
    ("capture_sessions", "($2->'sessions') ? t.id"),
    (
        "voice_enrollment_sessions",
        "($2->'sessions') ? t.capture_session_id",
    ),
    ("capture_streams", "($2->'streams') ? t.id"),
    ("capture_events", "($2->'events') ? t.event_id"),
    ("media_objects", "($2->'events') ? t.event_id"),
    ("recording_media_authority", "($2->'assets') ? t.asset_id"),
    ("browser_observations_v2", "($2->'events') ? t.event_id"),
    ("browser_states_v2", "($2->'browser_states') ? t.state_key"),
    ("browser_snapshots", "false"),
    ("browser_tabs", "false"),
    ("media_processing_jobs", "($2->'events') ? t.event_id"),
    ("media_work_units", "($2->'works') ? t.id"),
    ("media_work_members", "($2->'works') ? t.work_unit_id"),
    ("speaker_clusters", "($2->'clusters') ? t.id::text"),
    ("speaker_observations", "($2->'observations') ? t.id::text"),
    (
        "speaker_observation_sources",
        "($2->'observations') ? t.speaker_observation_id::text",
    ),
    ("visual_speaker_observations", "($2->'events') ? t.event_id"),
    (
        "voice_embedding_jobs",
        "($2->'observations') ? t.speaker_observation_id::text",
    ),
    ("utterances", "($2->'utterances') ? t.id::text"),
    ("audio_segments", "($2->'segments') ? t.id::text"),
    ("screenshots", "($2->'screenshots') ? t.id::text"),
    (
        "screen_observations",
        "($2->'screenshots') ? t.screenshot_id::text",
    ),
    (
        "outbox_events",
        "t.event_kind='capture_media_queued' AND ($2->'events') ? t.aggregate_id",
    ),
    (
        "capture_reference_batch_receipts",
        "($2->'batches') ? t.batch_id",
    ),
    (
        "capture_reference_batch_events",
        "($2->'batches') ? t.batch_id",
    ),
    (
        "capture_formation_receipts",
        "($2->'sessions') ? t.capture_session_id",
    ),
    (
        "capture_formation_pages",
        "($2->'sessions') ? t.capture_session_id",
    ),
    (
        "capture_formation_deleted_sequences",
        "($2->'sessions') ? t.capture_session_id",
    ),
    (
        "capture_formation_seal_events",
        "($2->'sessions') ? t.capture_session_id",
    ),
    ("episodes", "false"),
    ("episode_members", "false"),
    ("episode_final_briefs", "false"),
    ("screenshot_images", "false"),
    ("episode_screen_interpretations", "false"),
    ("episode_speaker_slots", "false"),
    ("episode_participants", "false"),
    ("people", "false"),
    ("person_name_claims", "false"),
    ("person_facts", "false"),
    ("identity_evidence", "false"),
    ("voice_samples", "false"),
    ("voice_profiles", "false"),
    ("voice_profile_proposals", "false"),
    ("voice_profile_proposal_samples", "false"),
    ("voice_profile_proposal_slots", "false"),
    ("voice_profile_revisions", "false"),
    ("voice_sample_profile_assignments", "false"),
    ("voice_profile_representatives", "false"),
    ("profile_identity_bindings", "false"),
    ("memory_handles", "false"),
    ("memory_archive_state", "false"),
    ("active_episode_members", "false"),
    ("memory_lineage_edges", "false"),
    ("memory_reconciliation_sources", "false"),
    ("memory_reconciliations", "false"),
    ("memory_reconciliation_jobs", "false"),
    ("memory_reconciliation_stages", "false"),
    ("content_id_counters", "false"),
    ("summary_window_claims", "false"),
    (
        "persistence_feature_reconciliation_neighborhood_scans",
        "false",
    ),
    (
        "persistence_feature_reconciliation_neighborhood_members",
        "false",
    ),
];

pub(super) struct OrphanScope {
    pub(super) identities: String,
    pub(super) report: OrphanScopeReport,
}

#[derive(Serialize)]
pub(super) struct OrphanScopeReport {
    pub(super) counts: ErasureCounts,
    pub(super) scope_sha256: String,
    pub(super) object_inventory_sha256: String,
    pub(super) provider_names_sha256: String,
    pub(super) provider_name_count: i64,
    pub(super) account_provider_names_sha256: String,
    pub(super) survivor_sha256: String,
    pub(super) protected_control_proof_sha256: String,
}

fn refuse_scope() -> EnclaveError {
    EnclaveError::Conflict(
        "capture erasure scope is changed, shared, oversized or not orphan-only".into(),
    )
}

pub(super) async fn require_quiescent(connection: &mut PgConnection, account: &str) -> Result<()> {
    // Voice inference may be disabled or paused after a worker crashes. A
    // well-formed expired lease has lost all settlement authority; requiring
    // that worker to restart would wedge erasure. Callers hold the ordinary
    // account/reconciliation fence, so it cannot be reclaimed during erasure.
    // Malformed/incomplete triples and every live lease still fail closed.
    let busy = sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS(SELECT 1 FROM capture_upload_intents WHERE account_id=$1) \
          OR EXISTS(SELECT 1 FROM recording_delivery_reservations WHERE account_id=$1) \
          OR EXISTS(SELECT 1 FROM capture_reference_batch_receipts WHERE account_id=$1 AND state<>'completed') \
          OR EXISTS(SELECT 1 FROM recording_retention_changes WHERE account_id=$1 AND state='delete_pending') \
          OR EXISTS(SELECT 1 FROM episode_deletions WHERE account_id=$1 AND state<>'complete') \
          OR EXISTS(SELECT 1 FROM vertex_usage_events WHERE account_id=$1 AND outcome='started') \
          OR EXISTS(SELECT 1 FROM media_work_units WHERE account_id=$1 AND (state='processing' \
             OR claim_token IS NOT NULL OR claim_until IS NOT NULL OR reservation_retained)) \
          OR EXISTS(SELECT 1 FROM media_processing_jobs WHERE account_id=$1 AND (state='processing' \
             OR lease_token IS NOT NULL OR lease_owner IS NOT NULL OR lease_until IS NOT NULL)) \
          OR EXISTS(SELECT 1 FROM voice_embedding_jobs WHERE account_id=$1 AND (state='processing' \
             OR lease_token IS NOT NULL OR lease_owner IS NOT NULL OR lease_until IS NOT NULL) \
             AND NOT (state='processing' AND lease_owner IS NOT NULL AND lease_token IS NOT NULL \
                      AND lease_until<=clock_timestamp())) \
          OR EXISTS(SELECT 1 FROM summary_window_claims WHERE account_id=$1 AND (state='processing' \
             OR claim_token IS NOT NULL OR claim_until IS NOT NULL)) \
          OR EXISTS(SELECT 1 FROM capture_formation_receipts WHERE account_id=$1 AND (state='processing' \
             OR claim_token IS NOT NULL OR claim_until IS NOT NULL OR claimed_revision IS NOT NULL \
             OR claimed_source_fingerprint IS NOT NULL)) \
          OR EXISTS(SELECT 1 FROM capture_formation_pages WHERE account_id=$1 AND (state='processing' \
             OR claim_token IS NOT NULL OR claim_until IS NOT NULL)) \
          OR EXISTS(SELECT 1 FROM memory_reconciliation_jobs WHERE account_id=$1 AND (state='processing' \
             OR claim_token IS NOT NULL OR claim_until IS NOT NULL OR state NOT IN ('complete','failed_terminal'))) \
          OR EXISTS(SELECT 1 FROM memory_reconciliation_stages WHERE account_id=$1) \
          OR EXISTS(SELECT 1 FROM episodes WHERE account_id=$1 AND (finalization_status='processing' \
             OR finalization_claim_token IS NOT NULL OR finalization_claim_until IS NOT NULL)) \
          OR EXISTS(SELECT 1 FROM outbox_events WHERE account_id=$1 AND (state='publishing' \
             OR claim_owner IS NOT NULL OR claim_token IS NOT NULL OR claim_until IS NOT NULL))",
    ).bind(account).fetch_one(connection).await?;
    if busy {
        return Err(EnclaveError::Conflict(
            "capture erasure refuses pre-existing upload, retention or worker authority".into(),
        ));
    }
    Ok(())
}

pub(super) async fn protected_control_proof(
    connection: &mut PgConnection,
    account: &str,
    episode: i64,
) -> Result<String> {
    let proof: Option<Vec<u8>> = sqlx::query_scalar(
        "SELECT sha256(convert_to(jsonb_build_object('episode',to_jsonb(e), \
          'handle',to_jsonb(h),'archive_revision',a.revision, \
          'members',(SELECT coalesce(jsonb_agg(to_jsonb(m) ORDER BY record_type,record_id),'[]') \
                     FROM episode_members m WHERE m.account_id=e.account_id AND m.episode_id=e.id))::text,'UTF8')) \
         FROM episodes e JOIN memory_handles h ON h.account_id=e.account_id AND h.episode_id=e.id \
         JOIN memory_archive_state a ON a.account_id=e.account_id \
         WHERE e.account_id=$1 AND e.id=$2 AND h.state='active' AND h.reconciliation_id IS NULL \
           AND h.origin_relation IS NULL AND a.revision=0 \
           AND NOT EXISTS(SELECT 1 FROM memory_lineage_edges l WHERE l.account_id=e.account_id \
                 AND (l.predecessor_episode_id=e.id OR l.successor_episode_id=e.id))",
    ).bind(account).bind(episode).fetch_optional(connection).await?;
    proof.map(|p| sha256_label(&p)).ok_or_else(refuse_scope)
}

pub(super) async fn partition_commitments(
    connection: &mut PgConnection,
    account: &str,
    identities: &str,
) -> Result<(String, String, i64)> {
    let mut target = Sha256::new();
    let mut survivor = Sha256::new();
    target.update(b"kioku.orphan-capture-source.v1\0");
    survivor.update(b"kioku.orphan-capture-survivors.v1\0");
    let mut total = 0_i64;
    let mut target_count = 0_i64;
    for &(table, predicate) in CONTENT_PARTITIONS {
        let predicate = predicate.replace("$2->", "$2::jsonb->");
        let query = format!(
            "WITH rows AS MATERIALIZED (SELECT coalesce(({predicate}),false) erased, \
               encode(sha256(convert_to(to_jsonb(t)::text,'UTF8')),'hex') digest \
               FROM {table} t WHERE account_id=$1 AND $2::jsonb IS NOT NULL LIMIT 100001) \
             SELECT count(*)::bigint count,count(*) FILTER(WHERE erased)::bigint erased_count, \
               sha256(convert_to(coalesce(string_agg(digest,'' ORDER BY digest) FILTER(WHERE erased),''),'UTF8')) erased, \
               sha256(convert_to(coalesce(string_agg(digest,'' ORDER BY digest) FILTER(WHERE NOT erased),''),'UTF8')) survivor FROM rows"
        );
        // Both identifiers are compile-time entries of CONTENT_PARTITIONS;
        // every account/scope value remains a bind parameter.
        let row = sqlx::query(sqlx::AssertSqlSafe(query))
            .bind(account)
            .bind(identities)
            .fetch_one(&mut *connection)
            .await?;
        total += row.try_get::<i64, _>("count")?;
        target_count += row.try_get::<i64, _>("erased_count")?;
        if total > MAX_COMMITTED_ROWS {
            return Err(refuse_scope());
        }
        for (hash, column) in [(&mut target, "erased"), (&mut survivor, "survivor")] {
            hash.update(table.as_bytes());
            hash.update([0]);
            hash.update(row.try_get::<Vec<u8>, _>(column)?);
        }
    }
    Ok((
        sha256_label(&target.finalize()),
        sha256_label(&survivor.finalize()),
        target_count,
    ))
}

pub(super) async fn inspect_scope(
    connection: &mut PgConnection,
    account: &str,
    targets: &ErasureTargets,
) -> Result<OrphanScope> {
    require_quiescent(connection, account).await?;
    let row = sqlx::query(SCOPE_SQL)
        .bind(account)
        .bind(&targets.capture_session_ids)
        .fetch_one(&mut *connection)
        .await?;
    if row.try_get::<i64, _>("violations")? != 0 {
        return Err(refuse_scope());
    }
    let identities: String = row.try_get("scope")?;
    let identity_value: Value = serde_json::from_str(&identities)?;
    let media = sqlx::query(
        "SELECT count(*)::bigint count, \
         count(*) FILTER(WHERE object_generation IS NULL OR object_generation<=0 OR deleted_at IS NOT NULL \
           OR object_backend IS DISTINCT FROM 'current' OR object_key NOT IN \
             ('raw/'||account_id||'/'||asset_id||'.enc','recordings/'||account_id||'/'||asset_id||'.enc'))::bigint invalid, \
         sha256(convert_to('kioku.orphan-capture-objects.v1'||E'\\n'||coalesce(string_agg( \
           object_key||E'\\t'||object_generation::text||E'\\t'||event_id||E'\\t'||asset_id||E'\\t'|| \
           byte_length::text||E'\\t'||sha256||E'\\n','' ORDER BY object_key),''),'UTF8')) digest \
         FROM media_objects WHERE account_id=$1 AND ($2::jsonb->'events') ? event_id",
    ).bind(account).bind(&identities).fetch_one(&mut *connection).await?;
    let objects: i64 = media.try_get("count")?;
    if media.try_get::<i64, _>("invalid")? != 0 || objects > 256 {
        return Err(refuse_scope());
    }
    // Both policy-selected names belong to the same canonical asset. A failed
    // PUT can leave older generations at the alternate name after a policy
    // change; database-live object counts must not pretend to enumerate them.
    let provider_names: Vec<u8> = sqlx::query_scalar(
        "SELECT sha256(convert_to('kioku.orphan-capture-provider-names.v1'||E'\\n'||coalesce( \
          string_agg(prefix||'/'||account_id||'/'||asset_id||'.enc'||E'\\n','' \
            ORDER BY prefix||'/'||account_id||'/'||asset_id||'.enc'),''),'UTF8')) \
          FROM media_objects CROSS JOIN (VALUES ('raw'),('recordings')) names(prefix) \
          WHERE account_id=$1 AND ($2::jsonb->'events') ? event_id",
    )
    .bind(account)
    .bind(&identities)
    .fetch_one(&mut *connection)
    .await?;
    let (scope_sha256, survivor_sha256, _) =
        partition_commitments(connection, account, &identities).await?;
    let count = |name: &str| -> Result<i64> {
        Ok(identity_value
            .get(name)
            .and_then(Value::as_array)
            .ok_or_else(refuse_scope)?
            .len() as i64)
    };
    let report = OrphanScopeReport {
        counts: ErasureCounts {
            sessions: count("sessions")?,
            streams: count("streams")?,
            events: count("events")?,
            objects,
            projections: count("utterances")? + count("screenshots")?,
        },
        scope_sha256,
        survivor_sha256,
        object_inventory_sha256: sha256_label(&media.try_get::<Vec<u8>, _>("digest")?),
        provider_names_sha256: sha256_label(&provider_names),
        provider_name_count: objects * 2,
        account_provider_names_sha256: account_provider_names(connection, account).await?,
        protected_control_proof_sha256: protected_control_proof(
            connection,
            account,
            targets.protected_episode_id,
        )
        .await?,
    };
    Ok(OrphanScope { identities, report })
}

/// Content-free classification authority for a read-only whole-account
/// provider listing. Unknown names are a refusal, never a deletion selector.
async fn account_provider_names(connection: &mut PgConnection, account: &str) -> Result<String> {
    let row = sqlx::query(
        "SELECT count(*) FILTER(WHERE asset_id !~ '^[a-zA-Z0-9_-]{1,128}$')::bigint invalid, \
         sha256(convert_to('kioku.orphan-capture-account-provider-names.v1'||E'\\n'||coalesce( \
          string_agg(prefix||'/'||account_id||'/'||asset_id||'.enc'||E'\\n','' \
            ORDER BY prefix||'/'||account_id||'/'||asset_id||'.enc'),''),'UTF8')) digest \
          FROM media_objects CROSS JOIN (VALUES ('raw'),('recordings')) names(prefix) WHERE account_id=$1",
    ).bind(account).fetch_one(connection).await?;
    if row.try_get::<i64, _>("invalid")? != 0 {
        return Err(refuse_scope());
    }
    Ok(sha256_label(&row.try_get::<Vec<u8>, _>("digest")?))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::persistence::{VoiceCohort, VoiceEmbeddingOutcome, VoiceIdentityRepository};
    #[tokio::test]
    async fn expired_voice_lease_cannot_wedge_paused_orphan_erasure() {
        let Some(fixture) = super::super::tests::test_persistence().await else {
            return;
        };
        let repo = &fixture.persistence;
        repo.install_memory_reconciliation_activation_schema()
            .await
            .unwrap();
        let account = "orphan-voice-lease";
        super::super::voice_identity::tests::seed_voice_observation(
            repo, account, "session", "event", 1, 1,
        )
        .await;
        repo.set_voice_identity_cohort(VoiceCohort::All, &[])
            .await
            .unwrap();
        require_quiescent(&mut repo.pool().acquire().await.unwrap(), account)
            .await
            .expect("otherwise idle orphan fixture is quiescent");
        let claim = repo
            .claim_voice_embeddings(account, "crashed-worker")
            .await
            .unwrap()
            .claims
            .remove(0);
        let mut connection = repo.pool().acquire().await.unwrap();
        assert!(
            require_quiescent(&mut connection, account).await.is_err(),
            "live voice lease must block orphan erasure"
        );
        repo.set_voice_identity_paused(true).await.unwrap();
        sqlx::query("UPDATE voice_embedding_jobs SET lease_until=clock_timestamp()-interval '1 second' WHERE account_id=$1").bind(account).execute(&mut *connection).await.unwrap();
        assert!(
            require_quiescent(&mut connection, account).await.is_ok(),
            "expired voice lease must not wedge paused orphan erasure"
        );
        assert!(
            !repo
                .settle_voice_embedding(&claim, VoiceEmbeddingOutcome::Retry)
                .await
                .unwrap(),
            "expired voice lease must have no settlement authority"
        );
        sqlx::query("UPDATE voice_embedding_jobs SET lease_owner=NULL,lease_token=NULL,lease_until=NULL WHERE account_id=$1").bind(account).execute(&mut *connection).await.unwrap();
        assert!(
            require_quiescent(&mut connection, account).await.is_err(),
            "malformed processing authority must fail closed"
        );
        drop(connection);
        repo.pool().close().await;
        sqlx::query(sqlx::AssertSqlSafe(format!(
            "DROP SCHEMA {} CASCADE",
            fixture.schema
        )))
        .execute(fixture.base.pool())
        .await
        .unwrap();
    }
}
