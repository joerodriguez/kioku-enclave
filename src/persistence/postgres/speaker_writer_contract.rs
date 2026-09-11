//! Standalone PostgreSQL contracts for synchronous speaker projection writers.
use super::{
    tests::{test_persistence, ControlPlaneContractFixture},
    PostgresPersistence,
};
use crate::persistence::{
    CaptureFormationSettlement, EpisodeInput, FinalizationClaimRequest, FinalizationRepository,
    MemoryFormationRepository, MemoryReconciliationRepository, ReconciliationPublish,
    ReconciliationPublishResult, SummaryWindowSettlement, CAPTURE_FORMATION_SCREENSHOT_PAGE_SIZE,
    CAPTURE_FORMATION_UTTERANCE_PAGE_SIZE,
};

const FROM: &str = "2026-08-01T10:00:00.000Z";
const TO: &str = "2026-08-01T10:10:00.000Z";

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

fn draft(id: Option<i64>, members: Vec<i64>, capture: bool) -> EpisodeInput {
    EpisodeInput {
        id,
        started_at: FROM.into(),
        ended_at: TO.into(),
        episode_type: Some("meeting".into()),
        title: "Synthetic speaker memory".into(),
        summary: Some("Synthetic writer evidence".into()),
        participants: Some(Vec::new()),
        languages: Some(vec!["en".into()]),
        action_items: Some(Vec::new()),
        model: Some(
            if capture {
                "conservative-capture-page-keep-v1"
            } else {
                "synthetic-summary"
            }
            .into(),
        ),
        substance: Some("normal".into()),
        visual_evidence: Some("none".into()),
        minute_summaries: Some(Vec::new()),
        member_utterance_ids: members,
        member_screenshot_ids: Vec::new(),
    }
}

async fn seed_turn(repo: &PostgresPersistence, account: &str, id: i64) {
    let event = format!("writer-event-{id}");
    super::voice_identity::tests::seed_voice_observation(
        repo,
        account,
        "writer-session",
        &event,
        id,
        id,
    )
    .await;
    sqlx::query("UPDATE capture_events SET sequence=$3-1,source_wall_at=$4::timestamptz,started_at=$4::timestamptz+make_interval(secs=>$3::double precision),ended_at=$4::timestamptz+make_interval(secs=>$3::double precision+4),received_at=clock_timestamp()-interval '1 hour' WHERE account_id=$1 AND event_id=$2").bind(account).bind(&event).bind(id).bind(FROM).execute(repo.pool()).await.unwrap();
    sqlx::query("UPDATE speaker_observations SET started_at=$3::timestamptz+make_interval(secs=>$2::double precision),ended_at=$3::timestamptz+make_interval(secs=>$2::double precision+4) WHERE account_id=$1 AND id=$2").bind(account).bind(id).bind(FROM).execute(repo.pool()).await.unwrap();
    sqlx::query("INSERT INTO audio_segments(account_id,id,started_at,ended_at,duration_seconds,source_type,transcription_status) VALUES($1,$2,$3::timestamptz,$4::timestamptz,600,'mic','ready')").bind(account).bind(id).bind(FROM).bind(TO).execute(repo.pool()).await.unwrap();
    sqlx::query("INSERT INTO utterances(account_id,id,audio_segment_id,start_offset_seconds,end_offset_seconds,text,speaker_label,speaker_observation_id,source_key) VALUES($1,$2,$2,$2::double precision,$2::double precision+4,'Synthetic writer speech','Original source label',$2,'cloud-v2:'||$3||':turn')").bind(account).bind(id).bind(&event).execute(repo.pool()).await.unwrap();
    sqlx::query("INSERT INTO media_processing_jobs(account_id,event_id,job_kind,input_revision,processor_version,state,updated_at) VALUES($1,$2,'gemini_audio','writer-input:'||$2,1,'succeeded',clock_timestamp()-interval '1 hour')").bind(account).bind(&event).execute(repo.pool()).await.unwrap();
}

async fn seed_capture_ready(repo: &PostgresPersistence, account: &str, count: i64) {
    for id in 1..=count {
        seed_turn(repo, account, id).await;
    }
    sqlx::query("UPDATE capture_sessions SET started_at=$2::timestamptz,last_event_at=$3::timestamptz,ended_at=$3::timestamptz WHERE account_id=$1 AND id='writer-session'").bind(account).bind(FROM).bind(TO).execute(repo.pool()).await.unwrap();
    sqlx::query("UPDATE capture_streams SET committed_through_sequence=$2-1,sealed_sequence=$2-1 WHERE account_id=$1 AND id='writer-session'").bind(account).bind(count).execute(repo.pool()).await.unwrap();
    sqlx::query("UPDATE accounts SET summarized_until=$2::timestamptz WHERE id=$1")
        .bind(account)
        .bind(TO)
        .execute(repo.pool())
        .await
        .unwrap();
    sqlx::query("INSERT INTO capture_formation_receipts(account_id,capture_session_id,source_revision,finish_requested_at,finish_request_provenance) VALUES($1,'writer-session',1,clock_timestamp()-interval '1 hour','finish_endpoint_v1') ON CONFLICT(account_id,capture_session_id) DO UPDATE SET finish_requested_at=excluded.finish_requested_at,finish_request_provenance=excluded.finish_request_provenance").bind(account).execute(repo.pool()).await.unwrap();
}

async fn form_capture(repo: &PostgresPersistence, account: &str, count: i64) -> Vec<i64> {
    seed_capture_ready(repo, account, count).await;
    let claim = repo
        .claim_capture_formation(account, 900)
        .await
        .unwrap()
        .expect("source-settled synthetic capture claim");
    let commitment = claim.page_source_commitment.clone();
    let settlement = CaptureFormationSettlement {
        claim,
        episodes: (1..=count).map(|id| draft(None, vec![id], true)).collect(),
    };
    let ids = repo
        .settle_capture_formation(settlement.clone())
        .await
        .unwrap();
    assert_eq!(
        repo.settle_capture_formation(settlement).await.unwrap(),
        ids,
        "capture formation replay must preserve memory and slot identities"
    );
    assert_eq!(sqlx::query_scalar::<_,Vec<u8>>("SELECT page_source_commitment FROM capture_formation_pages WHERE account_id=$1 AND page_index=0").bind(account).fetch_one(repo.pool()).await.unwrap(),commitment,"speaker projection must not rewrite the frozen capture page commitment");
    ids
}

async fn slots(
    repo: &PostgresPersistence,
    account: &str,
    episode: i64,
) -> Vec<(i64, Option<i64>, Option<i64>, i64)> {
    sqlx::query_as("SELECT id,voice_profile_id,speaker_cluster_id,slot_ordinal FROM episode_speaker_slots WHERE account_id=$1 AND episode_id=$2 AND status='active' ORDER BY slot_ordinal,id").bind(account).bind(episode).fetch_all(repo.pool()).await.unwrap()
}

#[tokio::test]
async fn speaker_writer_summary_settlement_persists_and_extends_slots_before_reads() {
    let Some(fixture) = test_persistence().await else {
        return;
    };
    let repo = &fixture.persistence;
    const ACCOUNT: &str = "speaker-summary-writer";
    seed_turn(repo, ACCOUNT, 1).await;
    let claim = repo
        .claim_summary_window(ACCOUNT, FROM, TO, TO, 900)
        .await
        .unwrap()
        .unwrap();
    let settlement = SummaryWindowSettlement {
        claim,
        episodes: vec![draft(None, vec![1], false)],
        cursor: None,
    };
    let first = repo
        .settle_summary_window(settlement.clone())
        .await
        .unwrap()[0];
    let initial = slots(repo, ACCOUNT, first).await;
    assert_eq!(
        initial.iter().map(|row| (row.2, row.3)).collect::<Vec<_>>(),
        vec![(Some(1), 0)],
        "summary settlement must persist anonymous slots before any lazy reader"
    );
    assert_eq!(
        repo.settle_summary_window(settlement).await.unwrap(),
        vec![first]
    );
    seed_turn(repo, ACCOUNT, 2).await;
    let claim = repo
        .claim_summary_window(ACCOUNT, FROM, "2026-08-01T10:11:00.000Z", TO, 900)
        .await
        .unwrap()
        .unwrap();
    let ids = repo
        .settle_summary_window(SummaryWindowSettlement {
            claim,
            episodes: vec![draft(Some(first), vec![2], false)],
            cursor: None,
        })
        .await
        .unwrap();
    assert_eq!(ids, vec![first]);
    let extended = slots(repo, ACCOUNT, first).await;
    assert_eq!(
        extended[0], initial[0],
        "retained summary memory must preserve its original slot identity and letter"
    );
    assert_eq!(
        extended
            .iter()
            .map(|row| (row.2, row.3))
            .collect::<Vec<_>>(),
        vec![(Some(1), 0), (Some(2), 1)],
        "summary extension must append a newly assigned voice synchronously"
    );
    cleanup(fixture).await;
}

#[tokio::test]
async fn speaker_writer_capture_settlement_persists_slots_before_reads() {
    let Some(fixture) = test_persistence().await else {
        return;
    };
    let repo = &fixture.persistence;
    const ACCOUNT: &str = "speaker-capture-writer";
    repo.install_memory_reconciliation_activation_schema()
        .await
        .unwrap();
    let ids = form_capture(repo, ACCOUNT, 2).await;
    for (index, episode) in ids.into_iter().enumerate() {
        assert_eq!(slots(repo,ACCOUNT,episode).await.iter().map(|row|(row.2,row.3)).collect::<Vec<_>>(),vec![(Some(index as i64+1),0)],"capture formation settlement must persist per-memory speaker slots before any lazy reader");
    }
    cleanup(fixture).await;
}

#[tokio::test]
async fn speaker_writer_summary_and_capture_contexts_use_live_identity_before_memory_creation() {
    let Some(fixture) = test_persistence().await else {
        return;
    };
    let repo = &fixture.persistence;
    const ACCOUNT: &str = "speaker-prompt-context";
    repo.install_memory_reconciliation_activation_schema()
        .await
        .unwrap();
    seed_capture_ready(repo, ACCOUNT, 3).await;
    sqlx::query("INSERT INTO people(account_id,id,display_name,status) VALUES($1,1,'Synthetic Person','identified')").bind(ACCOUNT).execute(repo.pool()).await.unwrap();
    sqlx::query("UPDATE speaker_clusters SET person_id=1,attribution_state='person_bound' WHERE account_id=$1 AND id=1").bind(ACCOUNT).execute(repo.pool()).await.unwrap();
    sqlx::query("UPDATE speaker_clusters SET attribution_state='owner_transmit' WHERE account_id=$1 AND id=2").bind(ACCOUNT).execute(repo.pool()).await.unwrap();
    let (summary, _) = repo
        .summary_evidence(ACCOUNT, FROM, TO, 100, 100)
        .await
        .unwrap();
    assert_eq!(
        summary
            .iter()
            .map(|turn| turn.speaker_label.as_str())
            .collect::<Vec<_>>(),
        vec!["Synthetic Person", "Me", "Speaker"],
        "forward summary context must use accepted names, owner Me and bare unowned Speaker"
    );
    let claim = repo
        .claim_capture_formation(ACCOUNT, 900)
        .await
        .unwrap()
        .unwrap();
    let (capture, _) = repo
        .capture_formation_evidence(
            &claim,
            CAPTURE_FORMATION_UTTERANCE_PAGE_SIZE,
            CAPTURE_FORMATION_SCREENSHOT_PAGE_SIZE,
        )
        .await
        .unwrap();
    assert_eq!(
        capture
            .iter()
            .map(|turn| turn.speaker_label.as_str())
            .collect::<Vec<_>>(),
        vec!["Synthetic Person", "Me", "Speaker"],
        "capture summary context must use accepted names, owner Me and bare unowned Speaker"
    );
    cleanup(fixture).await;
}

#[tokio::test]
async fn speaker_writer_finalizer_claim_uses_persisted_memory_speaker_labels() {
    let Some(fixture) = test_persistence().await else {
        return;
    };
    let repo = &fixture.persistence;
    const ACCOUNT: &str = "speaker-finalizer-context";
    seed_turn(repo, ACCOUNT, 1).await;
    let claim = repo
        .claim_summary_window(ACCOUNT, FROM, TO, TO, 900)
        .await
        .unwrap()
        .unwrap();
    let episode = repo
        .settle_summary_window(SummaryWindowSettlement {
            claim,
            episodes: vec![draft(None, vec![1], false)],
            cursor: None,
        })
        .await
        .unwrap()[0];
    sqlx::query(
        "UPDATE accounts SET summarized_until=$2::timestamptz+interval '5 hours' WHERE id=$1",
    )
    .bind(ACCOUNT)
    .bind(TO)
    .execute(repo.pool())
    .await
    .unwrap();
    let claim = repo
        .claim_finalization(FinalizationClaimRequest {
            account_id: ACCOUNT,
            target_episode_id: Some(episode),
            quiet_horizon_seconds: 1,
            finalization_version: 1,
            lease_seconds: 900,
        })
        .await
        .unwrap()
        .expect("synthetic finalizer claim");
    assert_eq!(
        claim
            .utterances
            .iter()
            .map(|turn| turn.speaker.as_str())
            .collect::<Vec<_>>(),
        vec!["Speaker A"],
        "finalizer claim transcript must use the selected memory's persisted speaker label"
    );
    cleanup(fixture).await;
}

async fn publish(repo: &PostgresPersistence, account: &str, retained: Option<i64>) -> Vec<i64> {
    let snapshot = repo
        .next_source_settled_cohort(account, 4 * 60 * 60, None, 32, 1000)
        .await
        .unwrap()
        .expect("synthetic reconciliation source-settled cohort");
    assert!(
        snapshot
            .atoms
            .iter()
            .all(|atom| atom.context.starts_with("[Speaker ")),
        "reconciler context must use persisted speaker labels for assigned memory evidence"
    );
    // Promote after read-boundary preparation but before publication, so
    // inherited reservations still carry their original cluster alias.
    sqlx::query("UPDATE speaker_clusters SET voice_profile_id=100,attribution_state='anonymous_profile' WHERE account_id=$1 AND id=1").bind(account).execute(repo.pool()).await.unwrap();
    let claim = repo
        .claim_reconciliation(&snapshot, 900)
        .await
        .unwrap()
        .expect("synthetic reconciliation claim");
    let mut write =
        super::memory_reconciliation::test_provider_stage_write(&snapshot, "speaker-writer")
            .unwrap();
    write.planned_outputs[0].retained_episode_id = retained;
    let guard = repo
        .acquire_provider_egress_guard(&claim)
        .await
        .unwrap()
        .expect("signed reconciliation egress guard");
    let staged = guard.stage_and_release(write).await.unwrap();
    let result = repo
        .publish_reconciliation(ReconciliationPublish {
            claim,
            reconciliation_id: format!("speaker-writer-{account}"),
            cohort_started_at: snapshot.cohort_started_at,
            cohort_ended_at: snapshot.cohort_ended_at,
            result_commitment: staged.result_commitment,
        })
        .await
        .unwrap();
    match result {
        ReconciliationPublishResult::Published {
            successor_episode_ids,
            ..
        } => successor_episode_ids,
        other => panic!("speaker writer reconciliation must publish: {other:?}"),
    }
}

#[tokio::test]
async fn speaker_writer_identity_presentation_preserves_reconciliation_fingerprints() {
    let Some(fixture) = test_persistence().await else {
        return;
    };
    let repo = &fixture.persistence;
    const ACCOUNT: &str = "speaker-fingerprint-writer";
    sqlx::query("INSERT INTO accounts(id,email,primary_provider,primary_subject) VALUES($1,'synthetic@example.test','google',$1)").bind(ACCOUNT).execute(repo.pool()).await.unwrap();
    super::activation::test_activate_speaker_writer_account(repo, ACCOUNT)
        .await
        .unwrap();
    form_capture(repo, ACCOUNT, 1).await;
    let before = repo
        .next_source_settled_cohort(ACCOUNT, 4 * 60 * 60, None, 32, 1000)
        .await
        .unwrap()
        .unwrap();
    assert!(before.atoms[0].context.starts_with("[Speaker A]"));
    sqlx::query("INSERT INTO people(account_id,id,display_name,status) VALUES($1,1,'Synthetic Name','identified')").bind(ACCOUNT).execute(repo.pool()).await.unwrap();
    sqlx::query("UPDATE speaker_clusters SET person_id=1,attribution_state='person_bound' WHERE account_id=$1 AND id=1").bind(ACCOUNT).execute(repo.pool()).await.unwrap();
    let after = repo
        .next_source_settled_cohort(ACCOUNT, 4 * 60 * 60, None, 32, 1000)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(after.source_fingerprint,before.source_fingerprint,"speaker presentation changes must not alter the established reconciliation source fingerprint");
    assert_eq!(
        after.topology_fingerprint, before.topology_fingerprint,
        "speaker presentation changes must not alter the established topology fingerprint"
    );
    assert!(
        after.atoms[0].context.starts_with("[Synthetic Name]"),
        "reconciler atoms must render the current accepted name after fingerprinting raw sources"
    );
    assert!(repo.claim_reconciliation(&before,900).await.unwrap().is_some(),"a presentation-only identity update must not invalidate an otherwise exact reconciliation claim");
    cleanup(fixture).await;
}

#[tokio::test]
async fn speaker_writer_reconciliation_retained_memory_preserves_slot_rows() {
    let Some(fixture) = test_persistence().await else {
        return;
    };
    let repo = &fixture.persistence;
    const ACCOUNT: &str = "speaker-retained-writer";
    sqlx::query("INSERT INTO accounts(id,email,primary_provider,primary_subject) VALUES($1,'synthetic@example.test','google',$1)").bind(ACCOUNT).execute(repo.pool()).await.unwrap();
    super::activation::test_activate_speaker_writer_account(repo, ACCOUNT)
        .await
        .unwrap();
    let first = form_capture(repo, ACCOUNT, 1).await[0];
    let before = slots(repo, ACCOUNT, first).await;
    assert!(
        !before.is_empty(),
        "retained reconciliation fixture must begin with a persisted speaker reservation"
    );
    sqlx::query("INSERT INTO voice_profiles(account_id,id,label,embedding_space,channel_domain,centroid) VALUES($1,100,'synthetic-voice',$2,'macos:builtin_mic',''::bytea)").bind(ACCOUNT).bind(crate::cp::voice_memory::EMBEDDING_SPACE).execute(repo.pool()).await.unwrap();
    assert_eq!(publish(repo, ACCOUNT, Some(first)).await, vec![first]);
    assert_eq!(
        slots(repo, ACCOUNT, first).await,
        vec![(before[0].0,Some(100),None,before[0].3)],
        "retained reconciliation must refresh a promoted voice while preserving its existing slot row and ordinal"
    );
    cleanup(fixture).await;
}

#[tokio::test]
async fn speaker_writer_reconciliation_replacement_inherits_cluster_alias_reservations() {
    let Some(fixture) = test_persistence().await else {
        return;
    };
    let repo = &fixture.persistence;
    const ACCOUNT: &str = "speaker-replacement-writer";
    sqlx::query("INSERT INTO accounts(id,email,primary_provider,primary_subject) VALUES($1,'synthetic@example.test','google',$1)").bind(ACCOUNT).execute(repo.pool()).await.unwrap();
    super::activation::test_activate_speaker_writer_account(repo, ACCOUNT)
        .await
        .unwrap();
    let predecessors = form_capture(repo, ACCOUNT, 2).await;
    sqlx::query(
        "UPDATE episode_speaker_slots SET slot_ordinal=5 WHERE account_id=$1 AND episode_id=$2",
    )
    .bind(ACCOUNT)
    .bind(predecessors[0])
    .execute(repo.pool())
    .await
    .unwrap();
    let before1 = slots(repo, ACCOUNT, predecessors[0]).await;
    let before2 = slots(repo, ACCOUNT, predecessors[1]).await;
    sqlx::query("INSERT INTO voice_profiles(account_id,id,label,embedding_space,channel_domain,centroid) VALUES($1,100,'synthetic-voice',$2,'macos:builtin_mic',''::bytea)").bind(ACCOUNT).bind(crate::cp::voice_memory::EMBEDDING_SPACE).execute(repo.pool()).await.unwrap();
    let successor = publish(repo, ACCOUNT, None).await[0];
    assert!(!predecessors.contains(&successor));
    let inherited = slots(repo, ACCOUNT, successor).await;
    assert_eq!(inherited.iter().map(|row|(row.1,row.2,row.3)).collect::<Vec<_>>(),vec![(None,Some(2),0),(Some(100),None,5)],"replacement reconciliation must inherit predecessor ordinals through cluster-to-profile promotion");
    assert!(
        inherited
            .iter()
            .all(|row| row.0 != before1[0].0 && row.0 != before2[0].0),
        "replacement speaker reservations must receive new account-global row IDs"
    );
    // Transfer completes before ordinary draft cleanup cascades predecessor
    // slots. Future revisions use the successor's new persisted reservations.
    assert!(sqlx::query_scalar::<_,bool>("SELECT NOT EXISTS(SELECT 1 FROM episodes WHERE account_id=$1 AND id=ANY($2)) AND (SELECT count(*) FROM memory_handles WHERE account_id=$1 AND episode_id=ANY($2) AND state='superseded')=cardinality($2::bigint[])").bind(ACCOUNT).bind(&predecessors).fetch_one(repo.pool()).await.unwrap(),"replacement publication must retain superseded handles without resurrecting obsolete draft content");
    cleanup(fixture).await;
}
