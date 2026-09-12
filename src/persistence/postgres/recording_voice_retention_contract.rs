//! Explicit recording-audio withdrawal erases biometrics without erasing memories.

use super::{
    tests::{test_persistence, ControlPlaneContractFixture},
    voice_identity::tests::{seed_voice_memory, seed_voice_observation},
    PostgresPersistence,
};
use crate::{
    cp::voice_quality::{self, SampleDecision},
    persistence::{
        RecordingRetentionChangeRequest, RecordingRetentionPolicy, RecordingRetentionPreference,
        RecordingRetentionPreview, RecordingRetentionRepository, VoiceCohort,
        VoiceEmbeddingOutcome, VoiceIdentityRepository, RECORDING_RETENTION_CONSENT_VERSION,
    },
};

const ACCOUNT: &str = "voice-recording-withdrawal";

async fn prepare() -> Option<(
    ControlPlaneContractFixture,
    RecordingRetentionPreference,
    RecordingRetentionPreview,
)> {
    let fixture = test_persistence().await?;
    let repo = &fixture.persistence;
    repo.set_voice_identity_cohort(VoiceCohort::All, &[])
        .await
        .unwrap();
    for (observation, event) in [(1, "removed-audio"), (2, "retained-audio")] {
        seed_voice_observation(repo, ACCOUNT, "session", event, observation, observation).await;
        seed_voice_memory(repo, ACCOUNT, observation, observation).await;
        let claim = repo
            .claim_voice_embeddings(ACCOUNT, "synthetic-worker")
            .await
            .unwrap()
            .claims
            .remove(0);
        let mut embedding = vec![0.; 256];
        embedding[0] = 1.;
        let mut diagnostics = voice_quality::diagnose(&vec![0.1; 64000], false, &[]);
        diagnostics.decision = SampleDecision::Enroll;
        assert!(repo
            .settle_voice_embedding(
                &claim,
                VoiceEmbeddingOutcome::Sample {
                    embedding,
                    diagnostics,
                    channel_domain: "macos:builtin_mic".into(),
                },
            )
            .await
            .unwrap());
    }
    let initial = repo.preference(ACCOUNT).await.unwrap();
    let inventory = repo.inventory(ACCOUNT, &initial).await.unwrap();
    let preview = repo
        .create_preview(
            ACCOUNT,
            RecordingRetentionPolicy::UntilDeleted,
            initial.revision,
            RECORDING_RETENTION_CONSENT_VERSION,
            false,
            inventory.clone(),
        )
        .await
        .unwrap();
    repo.change_policy(
        ACCOUNT,
        RecordingRetentionChangeRequest {
            policy: RecordingRetentionPolicy::UntilDeleted,
            expected_revision: initial.revision,
            consent_version: RECORDING_RETENTION_CONSENT_VERSION,
            promote_existing: false,
            preview_id: &preview.preview_id,
            inventory,
            idempotency_key: "voice-durable-policy",
        },
    )
    .await
    .unwrap();
    let preference = repo.preference(ACCOUNT).await.unwrap();
    let epoch = preference.policy_epoch.as_deref().unwrap();
    let key = repo
        .install_key_epoch(ACCOUNT, preference.revision, epoch, "synthetic-wrapped-key")
        .await
        .unwrap();
    sqlx::query("UPDATE media_objects SET object_key='recordings/'||$1||'/removed.enc',retain_until=NULL WHERE account_id=$1 AND event_id='removed-audio'")
        .bind(ACCOUNT).execute(repo.pool()).await.unwrap();
    sqlx::query("INSERT INTO recording_media_authority(account_id,asset_id,capture_policy_revision,retention_policy_revision,retention_policy_epoch,retention_decision,storage_backend,recording_key_epoch,recording_state,decision_at,updated_at) VALUES($1,'removed-audio',0,$2,$3,'until_deleted','recordings',$4,'durable',now(),now())")
        .bind(ACCOUNT).bind(preference.revision).bind(epoch).bind(key.key_epoch).execute(repo.pool()).await.unwrap();
    let inventory = repo.inventory(ACCOUNT, &preference).await.unwrap();
    assert_eq!(inventory.object_count, 1);
    let preview = repo
        .create_preview(
            ACCOUNT,
            RecordingRetentionPolicy::ProcessingWindow30d,
            preference.revision,
            RECORDING_RETENTION_CONSENT_VERSION,
            false,
            inventory,
        )
        .await
        .unwrap();
    Some((fixture, preference, preview))
}

async fn assert_erased_without_memory_loss(repo: &PostgresPersistence) {
    let samples: Vec<i64> = sqlx::query_scalar(
        "SELECT speaker_observation_id FROM voice_samples WHERE account_id=$1 ORDER BY speaker_observation_id",
    )
    .bind(ACCOUNT)
    .fetch_all(repo.pool())
    .await
    .unwrap();
    assert_eq!(
        samples,
        vec![2],
        "audio withdrawal must erase only samples supported by the removed recording"
    );
    let sample_count: i64 = sqlx::query_scalar(
        "SELECT sample_count FROM voice_profiles WHERE account_id=$1 AND status<>'superseded'",
    )
    .bind(ACCOUNT)
    .fetch_one(repo.pool())
    .await
    .unwrap();
    assert_eq!(
        sample_count, 1,
        "surviving voice support must be recomputed"
    );
    let historical_bytes: i64 = sqlx::query_scalar("SELECT count(*) FROM voice_profile_revisions r WHERE r.account_id=$1 AND octet_length(r.centroid)>0 AND r.id<>(SELECT max(last.id) FROM voice_profile_revisions last WHERE last.account_id=r.account_id AND last.profile_id=r.profile_id)")
        .bind(ACCOUNT).fetch_one(repo.pool()).await.unwrap();
    assert_eq!(
        historical_bytes, 0,
        "erased samples cannot survive in historical centroids"
    );
    let source_state: (i64, i64, i64) = sqlx::query_as("SELECT (SELECT count(*) FROM utterances WHERE account_id=$1 AND text='Synthetic fixture' AND speaker_label='Original source label'), (SELECT count(*) FROM episode_members WHERE account_id=$1), (SELECT revision FROM memory_archive_state WHERE account_id=$1)")
        .bind(ACCOUNT).fetch_one(repo.pool()).await.unwrap();
    assert_eq!(
        source_state,
        (2, 2, 9),
        "audio withdrawal must preserve source text, memory membership and archive revision"
    );
}

async fn cleanup(fixture: ControlPlaneContractFixture) {
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
async fn recording_voice_samples_are_erased_at_logical_withdrawal() {
    let Some((fixture, preference, preview)) = prepare().await else {
        return;
    };
    let repo = &fixture.persistence;
    let changed = repo
        .change_policy(
            ACCOUNT,
            RecordingRetentionChangeRequest {
                policy: RecordingRetentionPolicy::ProcessingWindow30d,
                expected_revision: preference.revision,
                consent_version: RECORDING_RETENTION_CONSENT_VERSION,
                promote_existing: false,
                preview_id: &preview.preview_id,
                inventory: preview.inventory.clone(),
                idempotency_key: "voice-withdrawal-policy",
            },
        )
        .await
        .unwrap();
    assert_eq!(changed.state, "delete_pending");
    assert_erased_without_memory_loss(repo).await;
    let still_pending: bool = sqlx::query_scalar("SELECT object_generation IS NOT NULL AND deleted_at IS NULL FROM media_objects WHERE account_id=$1 AND event_id='removed-audio'")
        .bind(ACCOUNT).fetch_one(repo.pool()).await.unwrap();
    assert!(
        still_pending,
        "biometrics must disappear before provider deletion finishes"
    );
    let completed = repo
        .complete_downgrade(ACCOUNT, &changed.operation_id)
        .await
        .unwrap();
    assert_eq!(completed.state, "physical_complete");
    assert_erased_without_memory_loss(repo).await;
    assert_eq!(
        repo.complete_downgrade(ACCOUNT, &changed.operation_id)
            .await
            .unwrap(),
        completed
    );
    cleanup(fixture).await;
}

#[tokio::test]
async fn recording_voice_completion_erases_before_source_authority_is_removed() {
    let Some((fixture, preference, _)) = prepare().await else {
        return;
    };
    let repo = &fixture.persistence;
    // Exercise a persisted pending operation directly, independently of the
    // change-policy entry point, as the completion reconciler receives it.
    let operation = format!("rrc_{}", "a".repeat(64));
    sqlx::query("UPDATE recording_retention_preferences SET policy='processing_window_30d',revision=revision+1,policy_epoch=NULL,revocation_cutoff=now() WHERE account_id=$1")
        .bind(ACCOUNT).execute(repo.pool()).await.unwrap();
    sqlx::query("UPDATE recording_key_epochs SET state='retired' WHERE account_id=$1")
        .bind(ACCOUNT)
        .execute(repo.pool())
        .await
        .unwrap();
    sqlx::query("INSERT INTO recording_retention_changes(account_id,idempotency_key_hash,request_fingerprint,preview_id,operation_id,resulting_revision,resulting_policy,state,created_at,updated_at) VALUES($1,repeat('a',64),repeat('b',64),'synthetic-preview',$2,$3,'processing_window_30d','delete_pending',now(),now())")
        .bind(ACCOUNT).bind(&operation).bind(preference.revision+1).execute(repo.pool()).await.unwrap();
    repo.complete_downgrade(ACCOUNT, &operation).await.unwrap();
    assert_erased_without_memory_loss(repo).await;
    let remaining_authority: i64 = sqlx::query_scalar("SELECT count(*) FROM recording_media_authority WHERE account_id=$1 AND storage_backend='recordings'")
        .bind(ACCOUNT).fetch_one(repo.pool()).await.unwrap();
    assert_eq!(remaining_authority, 0);
    cleanup(fixture).await;
}
