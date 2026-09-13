//! Standalone real-PostgreSQL owner enrollment and observation attribution contracts.
use super::{
    speaker_identity::{self, SpeakerMemoryScope, SpeakerUtteranceAlias},
    voice_identity, PostgresPersistence,
};
use crate::{
    cp::voice_quality::{self, SampleDecision},
    persistence::{
        VoiceCohort, VoiceEmbeddingClaim, VoiceEmbeddingOutcome, VoiceEnrollmentReason,
        VoiceEnrollmentState, VoiceIdentityRepository,
    },
};
use sqlx::Row;
use voice_identity::tests::{seed_voice_memory, seed_voice_observation};

async fn cleanup(fixture: super::tests::ControlPlaneContractFixture) {
    fixture.persistence.pool().close().await;
    sqlx::query(sqlx::AssertSqlSafe(format!(
        "DROP SCHEMA {} CASCADE",
        fixture.schema
    )))
    .execute(fixture.base.pool())
    .await
    .unwrap();
}
async fn turn(repo: &PostgresPersistence, account: &str, session: &str, id: i64, cluster: i64) {
    repo.install_memory_reconciliation_activation_schema()
        .await
        .unwrap();
    seed_voice_observation(repo, account, session, &format!("event-{id}"), id, cluster).await;
    // Distinct synthetic spans, rather than overlapping now()+id fixtures.
    sqlx::query("UPDATE capture_events SET started_at=to_timestamp(100000+$2::double precision*10),ended_at=to_timestamp(100004+$2::double precision*10) WHERE account_id=$1 AND event_id=$3")
        .bind(account).bind(id).bind(format!("event-{id}")).execute(repo.pool()).await.unwrap();
    sqlx::query("UPDATE speaker_observations SET started_at=to_timestamp(100000+$2::double precision*10),ended_at=to_timestamp(100004+$2::double precision*10) WHERE account_id=$1 AND id=$2")
        .bind(account).bind(id).execute(repo.pool()).await.unwrap();
    sqlx::query("INSERT INTO media_processing_jobs(account_id,event_id,job_kind,input_revision,processor_version,state) VALUES($1,$2,'gemini_audio',$2,1,'succeeded')")
        .bind(account).bind(format!("event-{id}")).execute(repo.pool()).await.unwrap();
    sqlx::query("UPDATE capture_streams SET committed_through_sequence=greatest(committed_through_sequence,$3) WHERE account_id=$1 AND capture_session_id=$2")
        .bind(account).bind(session).bind(id).execute(repo.pool()).await.unwrap();
    seed_voice_memory(repo, account, id, 1).await;
}
async fn designate(repo: &PostgresPersistence, account: &str, session: &str, revision: i64) {
    sqlx::query("INSERT INTO voice_enrollment_sessions(account_id,capture_session_id,designated,enrollment_revision,first_event_id,device_id,install_id,stream_id,state,channel_domain) SELECT $1,$2,true,$3,min(event_id),'synthetic-device','synthetic-install',$2,'recording','macos:builtin_mic' FROM capture_events WHERE account_id=$1 AND capture_session_id=$2")
        .bind(account).bind(session).bind(revision).execute(repo.pool()).await.unwrap();
}
async fn finish(repo: &PostgresPersistence, account: &str, session: &str) {
    sqlx::query(
        "UPDATE capture_sessions SET ended_at=clock_timestamp() WHERE account_id=$1 AND id=$2",
    )
    .bind(account)
    .bind(session)
    .execute(repo.pool())
    .await
    .unwrap();
    sqlx::query("INSERT INTO capture_formation_receipts(account_id,capture_session_id,source_revision,finish_requested_at,finish_request_provenance) VALUES($1,$2,1,clock_timestamp(),'finish_endpoint_v1') ON CONFLICT(account_id,capture_session_id) DO UPDATE SET finish_requested_at=excluded.finish_requested_at,finish_request_provenance=excluded.finish_request_provenance")
        .bind(account).bind(session).execute(repo.pool()).await.unwrap();
}
async fn claim(repo: &PostgresPersistence, account: &str) -> VoiceEmbeddingClaim {
    let mut claims = repo
        .claim_voice_embeddings(account, "owner-contract-worker")
        .await
        .unwrap()
        .claims;
    assert_eq!(
        claims.len(),
        1,
        "fixture admits one deterministic voice job at a time"
    );
    claims.remove(0)
}
fn sample(axis: usize, decision: SampleDecision) -> VoiceEmbeddingOutcome {
    let mut embedding = vec![0.0; 256];
    embedding[axis] = 1.0;
    let mut diagnostics = voice_quality::diagnose(&vec![0.1; 64000], false, &[]);
    diagnostics.decision = decision;
    VoiceEmbeddingOutcome::Sample {
        embedding,
        diagnostics,
        channel_domain: "macos:builtin_mic".into(),
    }
}
async fn embed(repo: &PostgresPersistence, account: &str, axis: usize) {
    let claim = claim(repo, account).await;
    assert!(repo
        .settle_voice_embedding(&claim, sample(axis, SampleDecision::Enroll))
        .await
        .unwrap());
}
async fn enroll(repo: &PostgresPersistence, account: &str, session: &str, id: i64) {
    repo.set_voice_identity_cohort(VoiceCohort::All, &[])
        .await
        .unwrap();
    turn(repo, account, session, id, id).await;
    designate(repo, account, session, 0).await;
    embed(repo, account, 0).await;
    finish(repo, account, session).await;
    repo.maintain_owner_voice_enrollment(account).await.unwrap();
}
async fn labels(
    repo: &PostgresPersistence,
    account: &str,
) -> Vec<(i64, String, Option<i64>, Option<String>)> {
    speaker_identity::prepare_account_speaker_projections(repo, account)
        .await
        .unwrap();
    let identity = speaker_identity::speaker_identity_join(
        SpeakerUtteranceAlias::U,
        SpeakerMemoryScope::Episode("1"),
    );
    let sql=format!("SELECT u.id,speaker_identity.speaker_label,speaker_identity.person_id,speaker_identity.attribution_kind FROM utterances u {identity} WHERE u.account_id=$1 ORDER BY u.id");
    sqlx::query(sqlx::AssertSqlSafe(sql))
        .bind(account)
        .fetch_all(repo.pool())
        .await
        .unwrap()
        .into_iter()
        .map(|r| {
            (
                r.get("id"),
                r.get("speaker_label"),
                r.get("person_id"),
                r.get("attribution_kind"),
            )
        })
        .collect()
}
async fn owner_profile(repo: &PostgresPersistence, account: &str) -> i64 {
    sqlx::query_scalar("SELECT profile.id FROM voice_profiles profile JOIN people owner ON owner.account_id=profile.account_id AND owner.id=profile.person_id AND owner.status='owner' WHERE profile.account_id=$1 ORDER BY profile.id LIMIT 1").bind(account).fetch_one(repo.pool()).await.unwrap()
}

#[tokio::test]
async fn owner_enrollment_finishes_without_four_hour_seal_and_preserves_source_bytes() {
    let Some(fixture) = super::tests::test_persistence().await else {
        return;
    };
    let repo = &fixture.persistence;
    let account = "owner-prompt";
    enroll(repo, account, "enrollment", 1).await;
    let status = repo.owner_voice_enrollment_status(account).await.unwrap();
    assert_eq!(
        status.latest_attempt.as_ref().unwrap().state,
        VoiceEnrollmentState::Enrolled,
        "finished eligible recording must enroll before the unrelated four-hour memory seal"
    );
    assert!(
        status.domains.iter().any(|d| d.recognized),
        "successful enrollment must create usable owner recognition"
    );
    assert_eq!(
        labels(repo, account).await,
        vec![(1, "Me".into(), None, Some("owner_voice".into()))],
        "owner presentation must use accepted observation evidence and hide the private person ID"
    );
    assert!(sqlx::query_scalar::<_,bool>("SELECT seal_finalized_at IS NULL AND seal_generation=0 FROM capture_formation_receipts WHERE account_id=$1").bind(account).fetch_one(repo.pool()).await.unwrap());
    assert_eq!(
        sqlx::query_scalar::<_, String>("SELECT speaker_label FROM utterances WHERE account_id=$1")
            .bind(account)
            .fetch_one(repo.pool())
            .await
            .unwrap(),
        "Original source label",
        "owner labeling must preserve frozen source transcription"
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT identity_revision FROM episodes WHERE account_id=$1")
            .bind(account)
            .fetch_one(repo.pool())
            .await
            .unwrap(),
        8,
        "accepted owner enrollment must advance the memory semantic identity revision once"
    );
    cleanup(fixture).await;
}

#[tokio::test]
async fn owner_enrollment_matches_first_and_suppresses_route_fallback_in_only_its_domain() {
    let Some(fixture) = super::tests::test_persistence().await else {
        return;
    };
    let repo = &fixture.persistence;
    let account = "owner-domain";
    enroll(repo, account, "enrollment", 1).await;
    let profile = owner_profile(repo, account).await;
    turn(repo, account, "ordinary", 2, 2).await;
    embed(repo, account, 0).await;
    assert_eq!(sqlx::query_scalar::<_,i64>("SELECT voice_profile_id FROM speaker_observations WHERE account_id=$1 AND id=2").bind(account).fetch_one(repo.pool()).await.unwrap(),profile,"ordinary cross-session speech must try the enrolled owner before creating a local anonymous profile");
    turn(repo, account, "ordinary", 3, 3).await;
    sqlx::query("UPDATE speaker_clusters SET attribution_state='owner_transmit' WHERE account_id=$1 AND id=3").bind(account).execute(repo.pool()).await.unwrap();
    let pending = labels(repo, account).await;
    assert!(
        pending[2].1.starts_with("Speaker "),
        "pending transmit speech in an enrolled domain must not inherit Me from its route"
    );
    embed(repo, account, 1).await;
    assert!(
        labels(repo, account).await[2].1.starts_with("Speaker "),
        "a different voice in an enrolled domain must stay a speaker despite transmit routing"
    );
    turn(repo, account, "other-domain", 4, 4).await;
    sqlx::query("UPDATE capture_events SET stream_kind='ios_mic' WHERE account_id=$1 AND event_id='event-4'").bind(account).execute(repo.pool()).await.unwrap();
    sqlx::query("UPDATE speaker_clusters SET attribution_state='owner_transmit' WHERE account_id=$1 AND id=4").bind(account).execute(repo.pool()).await.unwrap();
    assert_eq!(
        labels(repo, account).await[3].1,
        "Me",
        "an unenrolled acoustic domain must retain the existing route-only owner presentation"
    );
    cleanup(fixture).await;
}

#[tokio::test]
async fn owner_enrollment_mixed_cluster_keeps_turn_matches_and_excludes_all_cluster_updates() {
    let Some(fixture) = super::tests::test_persistence().await else {
        return;
    };
    let repo = &fixture.persistence;
    let account = "owner-mixed";
    enroll(repo, account, "enrollment", 1).await;
    let profile = owner_profile(repo, account).await;
    turn(repo, account, "ordinary", 2, 2).await;
    embed(repo, account, 0).await;
    turn(repo, account, "ordinary", 3, 2).await;
    embed(repo, account, 1).await;
    let rows = labels(repo, account).await;
    assert_eq!(
        rows[1].1, "Me",
        "a mixed diarization cluster must retain the owner's independently matched turn"
    );
    assert!(
        rows[2].1.starts_with("Speaker "),
        "a mixed diarization cluster must not label the other voice Me"
    );
    let row=sqlx::query("SELECT owner,profile_updates_quarantined,voice_profile_id,person_id FROM speaker_clusters WHERE account_id=$1 AND id=2").bind(account).fetch_one(repo.pool()).await.unwrap();
    assert!(row.get::<bool,_>("profile_updates_quarantined") && !row.get::<bool,_>("owner"),"mixed clusters must quarantine profile updates rather than promote the whole cluster to owner");
    assert!(
        row.get::<Option<i64>, _>("voice_profile_id").is_none()
            && row.get::<Option<i64>, _>("person_id").is_none()
    );
    assert_eq!(sqlx::query_scalar::<_,i64>("SELECT sample_count FROM voice_profiles WHERE account_id=$1 AND id=$2").bind(account).bind(profile).fetch_one(repo.pool()).await.unwrap(),1,"mixed-cluster discovery must remove its earlier contribution while retaining unrelated enrollment evidence");
    cleanup(fixture).await;
}

#[tokio::test]
async fn owner_enrollment_inconclusive_rerecord_preserves_previous_recognition_and_terminal_progress(
) {
    let Some(fixture) = super::tests::test_persistence().await else {
        return;
    };
    let repo = &fixture.persistence;
    let account = "owner-rerecord";
    enroll(repo, account, "good", 1).await;
    turn(repo, account, "bad", 2, 2).await;
    designate(repo, account, "bad", 0).await;
    let claim = claim(repo, account).await;
    repo.settle_voice_embedding(
        &claim,
        VoiceEmbeddingOutcome::NoEmbedding {
            diagnostics: voice_quality::diagnose(&[], false, &[]),
        },
    )
    .await
    .unwrap();
    finish(repo, account, "bad").await;
    repo.set_voice_identity_paused(true).await.unwrap();
    repo.set_voice_identity_cohort(VoiceCohort::None, &[])
        .await
        .unwrap();
    let status = repo.owner_voice_enrollment_status(account).await.unwrap();
    assert_eq!(status.latest_attempt.as_ref().unwrap().state,VoiceEnrollmentState::Inconclusive,"no-embedding completion must terminate enrollment even when inference is paused and disabled");
    assert!(
        status.domains.iter().any(|d| d.recognized),
        "an inconclusive new recording must not discard or hide an earlier valid owner profile"
    );
    assert_eq!(labels(repo, account).await[0].1, "Me");
    cleanup(fixture).await;
}

#[tokio::test]
async fn owner_enrollment_forget_erases_historical_biometrics_and_fences_queued_enrollment() {
    let Some(fixture) = super::tests::test_persistence().await else {
        return;
    };
    let repo = &fixture.persistence;
    let account = "owner-forget";
    enroll(repo, account, "good", 1).await;
    turn(repo, account, "unpublished", 3, 3).await;
    designate(repo, account, "unpublished", 0).await;
    embed(repo, account, 0).await;
    turn(repo, account, "queued", 2, 2).await;
    designate(repo, account, "queued", 0).await;
    let held = claim(repo, account).await;
    finish(repo, account, "queued").await;
    let status = repo.forget_owner_voice_enrollment(account).await.unwrap();
    assert_eq!(
        status.enrollment_revision, 1,
        "Forget must advance the account-wide offline enrollment fence"
    );
    assert!(
        status.domains.iter().all(|d| !d.recognized),
        "Forget must remove current owner recognition"
    );
    assert_eq!(sqlx::query_scalar::<_,i64>("SELECT count(*) FROM voice_samples WHERE account_id=$1 AND speaker_observation_id=3").bind(account).fetch_one(repo.pool()).await.unwrap(),0,"Forget must erase unpublished anonymous enrollment candidates as well as already-promoted owner samples");
    assert_eq!(sqlx::query_scalar::<_,i64>("SELECT count(*) FROM identity_evidence WHERE account_id=$1 AND kind IN ('owner_enrollment','owner_voice')").bind(account).fetch_one(repo.pool()).await.unwrap(),0,"Forget must erase owner identity evidence as well as live profiles");
    assert!(sqlx::query_scalar::<_,bool>("SELECT coalesce(bool_and(octet_length(centroid)=0),true) FROM voice_profile_revisions WHERE account_id=$1").bind(account).fetch_one(repo.pool()).await.unwrap(),"Forget must redact every historical anonymous centroid that contained the promoted owner sample");
    repo.settle_voice_embedding(&held, sample(0, SampleDecision::Enroll))
        .await
        .unwrap();
    repo.maintain_owner_voice_enrollment(account).await.unwrap();
    assert!(
        repo.owner_voice_enrollment_status(account)
            .await
            .unwrap()
            .domains
            .iter()
            .all(|d| !d.recognized),
        "an inference result already in flight before Forget must not recreate an owner enrollment"
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM utterances WHERE account_id=$1")
            .bind(account)
            .fetch_one(repo.pool())
            .await
            .unwrap(),
        3,
        "Forget must retain transcript and ordinary recording content"
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM media_objects WHERE account_id=$1")
            .bind(account)
            .fetch_one(repo.pool())
            .await
            .unwrap(),
        3
    );
    cleanup(fixture).await;
}

#[tokio::test]
async fn stored_owner_matching_holds_expired_support_beyond_the_cleanup_page() {
    let Some(fixture) = super::tests::test_persistence().await else {
        return;
    };
    let repo = &fixture.persistence;
    let account = "owner-cleanup-backlog";
    repo.set_voice_identity_cohort(VoiceCohort::All, &[])
        .await
        .unwrap();
    turn(repo, account, "old", 1, 1).await;
    repo.settle_voice_embedding(
        &claim(repo, account).await,
        sample(1, SampleDecision::Quarantine),
    )
    .await
    .unwrap();
    turn(repo, account, "queued", 4, 4).await;
    repo.settle_voice_embedding(
        &claim(repo, account).await,
        sample(0, SampleDecision::MatchOnly),
    )
    .await
    .unwrap();
    // A realistic retained-derivation backlog: older policy samples of one
    // expired source precede the ordinary owner-voice contribution by ID.
    sqlx::query("INSERT INTO voice_samples(account_id,id,speaker_observation_id,embedding_space,channel_domain,embedding,quality_score,diagnostics,quality_version,scorer_version,eligibility,accepted,embedding_job_id) SELECT s.account_id,copy.id,s.speaker_observation_id,s.embedding_space,s.channel_domain,s.embedding,s.quality_score,s.diagnostics,copy.id,s.scorer_version,s.eligibility,s.accepted,s.embedding_job_id FROM voice_samples s CROSS JOIN generate_series(10,508) copy(id) WHERE s.account_id=$1 AND s.speaker_observation_id=1").bind(account).execute(repo.pool()).await.unwrap();
    enroll(repo, account, "enrollment", 2).await;
    turn(repo, account, "ordinary", 3, 3).await;
    embed(repo, account, 0).await;
    sqlx::query("UPDATE media_objects SET retain_until=clock_timestamp()-interval '1 second' WHERE account_id=$1 AND event_id IN ('event-1','event-3')").bind(account).execute(repo.pool()).await.unwrap();
    repo.maintain_owner_voice_enrollment(account).await.unwrap();
    repo.maintain_voice_profiles(account).await.unwrap();
    assert_eq!(sqlx::query_scalar::<_,Option<i64>>("SELECT voice_profile_id FROM voice_samples WHERE account_id=$1 AND speaker_observation_id=4").bind(account).fetch_one(repo.pool()).await.unwrap(),None,
        "stored matching must hold an owner centroid with expired support beyond the cleanup page");
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT count(*) FROM voice_samples WHERE account_id=$1 AND speaker_observation_id=3"
        )
        .bind(account)
        .fetch_one(repo.pool())
        .await
        .unwrap(),
        1,
        "the expiry fixture must leave the stale owner contribution beyond the first page"
    );
    repo.maintain_voice_profiles(account).await.unwrap();
    assert!(sqlx::query_scalar::<_,bool>("SELECT o.owner_evidence_id IS NOT NULL FROM speaker_observations o WHERE o.account_id=$1 AND o.id=4").bind(account).fetch_one(repo.pool()).await.unwrap(),
        "stored matching may resume after the owner centroid has been recomputed from retained support");
    cleanup(fixture).await;
}

#[tokio::test]
async fn owner_enrollment_raw_expiry_recomputes_partial_then_complete_support() {
    let Some(fixture) = super::tests::test_persistence().await else {
        return;
    };
    let repo = &fixture.persistence;
    let account = "owner-expiry";
    repo.set_voice_identity_cohort(VoiceCohort::All, &[])
        .await
        .unwrap();
    turn(repo, account, "good", 1, 1).await;
    designate(repo, account, "good", 0).await;
    embed(repo, account, 0).await;
    turn(repo, account, "good", 2, 2).await;
    embed(repo, account, 0).await;
    finish(repo, account, "good").await;
    repo.maintain_owner_voice_enrollment(account).await.unwrap();
    let profile = owner_profile(repo, account).await;
    sqlx::query("UPDATE media_objects SET retain_until=clock_timestamp()-interval '1 second' WHERE account_id=$1 AND event_id='event-1'").bind(account).execute(repo.pool()).await.unwrap();
    repo.owner_voice_enrollment_status(account).await.unwrap();
    repo.maintain_voice_profiles(account).await.unwrap();
    let partial = repo.owner_voice_enrollment_status(account).await.unwrap();
    assert_eq!(
        partial.latest_attempt.as_ref().unwrap().reason,
        Some(VoiceEnrollmentReason::RawMediaExpired),
        "expired enrollment source must produce an explicit expired attempt"
    );
    assert!(
        partial.domains.iter().any(|d| d.recognized),
        "retained enrollment samples must preserve recognition after partial source expiry"
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT sample_count FROM voice_profiles WHERE account_id=$1 AND id=$2"
        )
        .bind(account)
        .bind(profile)
        .fetch_one(repo.pool())
        .await
        .unwrap(),
        1,
        "raw expiry must remove exactly its dependent enrollment contribution"
    );
    assert!(sqlx::query_scalar::<_,bool>("SELECT bool_and(octet_length(centroid)=0) FROM voice_profile_revisions WHERE account_id=$1 AND profile_id=$2 AND NOT active").bind(account).bind(profile).fetch_one(repo.pool()).await.unwrap(),"raw expiry must redact previous centroid payloads");
    sqlx::query("UPDATE media_objects SET retain_until=clock_timestamp()-interval '1 second' WHERE account_id=$1 AND event_id='event-2'").bind(account).execute(repo.pool()).await.unwrap();
    let complete = repo.owner_voice_enrollment_status(account).await.unwrap();
    assert!(complete.domains.iter().all(|d|!d.recognized),"later expiry must remove the final sample even when its enrollment attempt was already expired");
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM voice_samples WHERE account_id=$1")
            .bind(account)
            .fetch_one(repo.pool())
            .await
            .unwrap(),
        0
    );
    cleanup(fixture).await;
}

#[tokio::test]
async fn owner_enrollment_source_change_revokes_only_its_session_and_requeues_current_audio() {
    let Some(fixture) = super::tests::test_persistence().await else {
        return;
    };
    let repo = &fixture.persistence;
    let account = "owner-change";
    enroll(repo, account, "old", 1).await;
    enroll(repo, account, "new", 2).await;
    let mut tx = repo.pool().begin().await.unwrap();
    assert!(voice_identity::lock_account(&mut tx, account)
        .await
        .unwrap());
    super::voice_enrollment::invalidate_owner_enrollment(
        &mut tx,
        account,
        "new",
        VoiceEnrollmentReason::SourceChanged,
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();
    assert_eq!(sqlx::query_scalar::<_,String>("SELECT state FROM voice_enrollment_sessions WHERE account_id=$1 AND capture_session_id='new'").bind(account).fetch_one(repo.pool()).await.unwrap(),"processing","accepted source changes must withdraw a settled decision for reevaluation");
    assert_eq!(sqlx::query_scalar::<_,String>("SELECT state FROM voice_embedding_jobs WHERE account_id=$1 AND speaker_observation_id=2").bind(account).fetch_one(repo.pool()).await.unwrap(),"pending","retained source invalidation must permit fresh inference for the changed decision");
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM voice_samples WHERE account_id=$1")
            .bind(account)
            .fetch_one(repo.pool())
            .await
            .unwrap(),
        1,
        "source churn must erase only the changed session's contribution"
    );
    assert!(
        repo.owner_voice_enrollment_status(account)
            .await
            .unwrap()
            .domains
            .iter()
            .any(|d| d.recognized),
        "older valid enrollment must survive a later session's source change"
    );
    cleanup(fixture).await;
}

#[tokio::test]
async fn owner_enrollment_failed_rerecord_never_changes_the_existing_owner_graph() {
    let Some(fixture) = super::tests::test_persistence().await else {
        return;
    };
    let repo = &fixture.persistence;
    let account = "owner-failed-rerecord";
    enroll(repo, account, "old", 1).await;
    let profile = owner_profile(repo, account).await;
    let before: Vec<u8> =
        sqlx::query_scalar("SELECT centroid FROM voice_profiles WHERE account_id=$1 AND id=$2")
            .bind(account)
            .bind(profile)
            .fetch_one(repo.pool())
            .await
            .unwrap();
    turn(repo, account, "new", 2, 2).await;
    designate(repo, account, "new", 0).await;
    embed(repo, account, 0).await;
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT count(*) FROM voice_samples WHERE account_id=$1 AND voice_profile_id=$2"
        )
        .bind(account)
        .bind(profile)
        .fetch_one(repo.pool())
        .await
        .unwrap(),
        1,
        "a matching turn in an unfinished rerecord must not update the existing owner profile"
    );
    assert_eq!(sqlx::query_scalar::<_,i64>("SELECT count(*) FROM identity_evidence WHERE account_id=$1 AND kind IN ('owner_voice','owner_enrollment')").bind(account).fetch_one(repo.pool()).await.unwrap(),1,"an unfinished rerecord must not create owner evidence before full dominance validation");
    turn(repo, account, "new", 3, 3).await;
    embed(repo, account, 1).await;
    finish(repo, account, "new").await;
    let status = repo.owner_voice_enrollment_status(account).await.unwrap();
    assert_eq!(
        status.latest_attempt.unwrap().reason,
        Some(VoiceEnrollmentReason::NoDominantVoice),
        "two equal voices must make the rerecord inconclusive"
    );
    assert_eq!(
        sqlx::query_scalar::<_, Vec<u8>>(
            "SELECT centroid FROM voice_profiles WHERE account_id=$1 AND id=$2"
        )
        .bind(account)
        .bind(profile)
        .fetch_one(repo.pool())
        .await
        .unwrap(),
        before,
        "an inconclusive rerecord must leave earlier owner biometric bytes unchanged"
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT sample_count FROM voice_profiles WHERE account_id=$1 AND id=$2"
        )
        .bind(account)
        .bind(profile)
        .fetch_one(repo.pool())
        .await
        .unwrap(),
        1
    );
    cleanup(fixture).await;
}

#[tokio::test]
async fn owner_enrollment_forget_then_fresh_enrollment_rejects_old_lease_and_late_source() {
    let Some(fixture) = super::tests::test_persistence().await else {
        return;
    };
    let repo = &fixture.persistence;
    let account = "owner-revoked-lease";
    enroll(repo, account, "original", 1).await;
    turn(repo, account, "queued", 2, 2).await;
    designate(repo, account, "queued", 0).await;
    let old = claim(repo, account).await;
    repo.forget_owner_voice_enrollment(account).await.unwrap();
    assert!(
        sqlx::query_scalar::<_, bool>("SELECT state='failed' AND error_code='enrollment_revoked' AND lease_owner IS NULL AND lease_token IS NULL AND lease_until IS NULL FROM voice_embedding_jobs WHERE account_id=$1 AND id=$2")
            .bind(account)
            .bind(old.id)
            .fetch_one(repo.pool())
            .await
            .unwrap(),
        "Forget must cancel the designated in-flight lease before admitting a fresh enrollment"
    );
    turn(repo, account, "fresh", 3, 3).await;
    designate(repo, account, "fresh", 1).await;
    embed(repo, account, 0).await;
    finish(repo, account, "fresh").await;
    repo.maintain_owner_voice_enrollment(account).await.unwrap();
    assert!(
        repo.owner_voice_enrollment_status(account)
            .await
            .unwrap()
            .domains
            .iter()
            .any(|d| d.recognized),
        "fixture must establish a fresh post-withdrawal owner before the old result arrives"
    );
    assert!(
        !repo
            .settle_voice_embedding(&old, sample(0, SampleDecision::Enroll))
            .await
            .unwrap(),
        "Forget must revoke the old enrollment lease even after fresh recognition exists"
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT count(*) FROM voice_samples WHERE account_id=$1 AND speaker_observation_id=2"
        )
        .bind(account)
        .fetch_one(repo.pool())
        .await
        .unwrap(),
        0,
        "a pre-Forget result must not restore an erased enrollment sample into the fresh profile"
    );
    turn(repo, account, "queued", 4, 4).await;
    assert!(repo.claim_voice_embeddings(account,"late-worker").await.unwrap().claims.is_empty(),"later source in a withdrawn designated session must be rejected before biometric inference");
    assert_eq!(sqlx::query_scalar::<_,String>("SELECT error_code FROM voice_embedding_jobs WHERE account_id=$1 AND speaker_observation_id=4").bind(account).fetch_one(repo.pool()).await.unwrap(),"enrollment_revoked");
    cleanup(fixture).await;
}

#[tokio::test]
async fn owner_enrollment_pause_blocks_new_bindings_and_post_cutoff_work_does_not_hold_enrollment()
{
    let Some(fixture) = super::tests::test_persistence().await else {
        return;
    };
    let repo = &fixture.persistence;
    let account = "owner-cutoff-pause";
    repo.set_voice_identity_cohort(VoiceCohort::All, &[])
        .await
        .unwrap();
    turn(repo, account, "recording", 1, 1).await;
    designate(repo, account, "recording", 0).await;
    embed(repo, account, 0).await;
    turn(repo, account, "recording", 30, 30).await;
    sqlx::query("UPDATE media_processing_jobs SET state='failed_terminal' WHERE account_id=$1 AND event_id='event-30'").bind(account).execute(repo.pool()).await.unwrap();
    sqlx::query("INSERT INTO capture_upload_intents(account_id,event_id,token,asset_id,object_key,manifest_digest,expires_at) VALUES($1,'unrelated-upload',$1,'unrelated-asset','raw/'||$1||'/unrelated-asset.enc',repeat('a',64),clock_timestamp()+interval '10 minutes')")
        .bind(account).execute(repo.pool()).await.unwrap();
    // Keep a deliberate gap only after the first three minutes. Its ordinary
    // media and voice jobs retain their own independent terminal/pending state.
    sqlx::query("UPDATE capture_streams SET committed_through_sequence=1 WHERE account_id=$1")
        .bind(account)
        .execute(repo.pool())
        .await
        .unwrap();
    finish(repo, account, "recording").await;
    repo.set_voice_identity_paused(true).await.unwrap();
    let paused = repo.owner_voice_enrollment_status(account).await.unwrap();
    assert_eq!(
        paused.latest_attempt.unwrap().state,
        VoiceEnrollmentState::Processing,
        "paused successful enrollment must wait without creating new identity bindings"
    );
    assert!(
        paused.domains.iter().all(|d| !d.recognized),
        "Pause must freeze owner bindings even though cleanup maintenance continues"
    );
    repo.set_voice_identity_paused(false).await.unwrap();
    let resumed = repo.owner_voice_enrollment_status(account).await.unwrap();
    assert_eq!(resumed.latest_attempt.unwrap().state,VoiceEnrollmentState::Enrolled,"post-cutoff pending voice work, failed media work and sequence gaps must not hold valid first-three-minute enrollment");
    assert_eq!(sqlx::query_scalar::<_,String>("SELECT state FROM voice_embedding_jobs WHERE account_id=$1 AND speaker_observation_id=30").bind(account).fetch_one(repo.pool()).await.unwrap(),"pending","enrollment cutoff must leave ordinary later audio processing unchanged");
    assert_eq!(sqlx::query_scalar::<_,i64>("SELECT count(*) FROM identity_evidence WHERE account_id=$1 AND kind='owner_enrollment'").bind(account).fetch_one(repo.pool()).await.unwrap(),1);
    cleanup(fixture).await;
}

#[tokio::test]
async fn owner_enrollment_crossing_same_voice_is_matched_without_enrolling_post_cutoff_bytes() {
    let Some(fixture) = super::tests::test_persistence().await else {
        return;
    };
    let repo = &fixture.persistence;
    let account = "owner-crossing";
    repo.set_voice_identity_cohort(VoiceCohort::All, &[])
        .await
        .unwrap();
    turn(repo, account, "recording", 1, 1).await;
    designate(repo, account, "recording", 0).await;
    embed(repo, account, 0).await;
    turn(repo, account, "recording", 2, 1).await;
    // First source begins at100010: this second turn crosses its180s cutoff
    // from175s to205s and carries a full30s embedding, rather than clipped audio.
    sqlx::query("UPDATE capture_events SET started_at=to_timestamp(100185),ended_at=to_timestamp(100215) WHERE account_id=$1 AND event_id='event-2'").bind(account).execute(repo.pool()).await.unwrap();
    sqlx::query("UPDATE speaker_observations SET started_at=to_timestamp(100185),ended_at=to_timestamp(100215) WHERE account_id=$1 AND id=2").bind(account).execute(repo.pool()).await.unwrap();
    sqlx::query("UPDATE speaker_observation_sources SET window_end_ms=30000,event_end_ms=30000 WHERE account_id=$1 AND speaker_observation_id=2").bind(account).execute(repo.pool()).await.unwrap();
    sqlx::query(
        "UPDATE media_objects SET byte_length=960044 WHERE account_id=$1 AND event_id='event-2'",
    )
    .bind(account)
    .execute(repo.pool())
    .await
    .unwrap();
    let claim = claim(repo, account).await;
    let mut diagnostics = voice_quality::diagnose(&vec![0.1; 480000], false, &[]);
    diagnostics.decision = SampleDecision::Enroll;
    let mut embedding = vec![0.0; 256];
    embedding[0] = 1.0;
    repo.settle_voice_embedding(
        &claim,
        VoiceEmbeddingOutcome::Sample {
            embedding,
            diagnostics,
            channel_domain: "macos:builtin_mic".into(),
        },
    )
    .await
    .unwrap();
    finish(repo, account, "recording").await;
    let status = repo.owner_voice_enrollment_status(account).await.unwrap();
    assert_eq!(status.latest_attempt.unwrap().state,VoiceEnrollmentState::Enrolled,"a crossing turn of the same directly matched voice must not create a false mixed cluster that erases valid enrollment");
    assert_eq!(sqlx::query_scalar::<_,i64>("SELECT count(*) FROM identity_evidence WHERE account_id=$1 AND kind='owner_enrollment'").bind(account).fetch_one(repo.pool()).await.unwrap(),1,"post-cutoff embedding bytes must never become owner enrollment evidence");
    assert_eq!(sqlx::query_scalar::<_,String>("SELECT eligibility FROM voice_samples WHERE account_id=$1 AND speaker_observation_id=2").bind(account).fetch_one(repo.pool()).await.unwrap(),"match_only","crossing voice can be recognized only without centroid updates");
    let profile = owner_profile(repo, account).await;
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT sample_count FROM voice_profiles WHERE account_id=$1 AND id=$2"
        )
        .bind(account)
        .bind(profile)
        .fetch_one(repo.pool())
        .await
        .unwrap(),
        1
    );
    assert_eq!(
        labels(repo, account).await[1].1,
        "Me",
        "direct standard-threshold matching may recognize the crossing turn after valid closure"
    );
    cleanup(fixture).await;
}
