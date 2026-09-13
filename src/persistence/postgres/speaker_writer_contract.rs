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
        authored_labels: Default::default(),
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
        authored_labels: Default::default(),
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
            authored_labels: Default::default(),
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
        vec!["Synthetic Person", "Me", "Speaker A"],
        "forward summary context must use accepted names, owner Me and the frozen anonymous Speaker A namespace"
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
        vec!["Synthetic Person", "Me", "Speaker A"],
        "capture summary context must use accepted names, owner Me and the frozen anonymous Speaker A namespace"
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
            authored_labels: Default::default(),
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
    assert_eq!(
        after.drafts[0].identity_revision,
        before.drafts[0].identity_revision + 1,
        "an accepted name must advance identity while preserving raw source commitments"
    );
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

#[tokio::test]
async fn identity_presentation_formation_freezes_actual_local_speakers_and_keeps_old_minute_maps() {
    use crate::persistence::{MinuteBucket, SummaryUtterance};
    let Some(fixture) = test_persistence().await else {
        return;
    };
    let repo = &fixture.persistence;
    let account = "identity-formation-writer";
    seed_turn(repo, account, 1).await;
    seed_turn(repo, account, 2).await;
    let (utterances, _) = repo
        .summary_evidence(account, FROM, TO, 500, 500)
        .await
        .unwrap();
    assert_eq!(
        utterances
            .iter()
            .map(|u| u.speaker_label.as_str())
            .collect::<Vec<_>>(),
        vec!["Speaker A", "Speaker B"],
        "formation must supply distinct graph-bound anonymous labels before any memory exists"
    );
    let labels = SummaryUtterance::authored_labels(&utterances);
    assert_eq!(labels.labels[0].utterance_ids, vec![1]);
    let claim = repo
        .claim_summary_window(account, FROM, TO, TO, 900)
        .await
        .unwrap()
        .unwrap();
    let mut first = draft(None, vec![1, 2], false);
    first.title = "Speaker A and Speaker B planned work".into();
    first.minute_summaries = Some(vec![MinuteBucket {
        start: FROM.into(),
        gist: "Speaker A planned work".into(),
    }]);
    let ids = repo
        .settle_summary_window(SummaryWindowSettlement {
            claim,
            authored_labels: labels.clone(),
            episodes: vec![first],
            cursor: None,
        })
        .await
        .unwrap();
    let episode = ids[0];
    let mut tx = repo.pool().begin().await.unwrap();
    let stored:String=sqlx::query_scalar("SELECT minute_labels::text FROM episode_identity_presentations WHERE account_id=$1 AND episode_id=$2").bind(account).bind(episode).fetch_one(&mut *tx).await.unwrap();
    let stored: serde_json::Value = serde_json::from_str(&stored).unwrap();
    assert_eq!(
        stored[FROM],
        serde_json::to_value(&labels).unwrap(),
        "formation must persist exactly the label map used by its authoring input"
    );
    // A later authored bucket may use a different namespace. Keep the old
    // bucket's map while adopting the new title/action and minute maps.
    let mut later = labels.clone();
    later.labels[0].label = "Speaker B".into();
    later.labels[1].label = "Speaker A".into();
    let later_start = "2026-08-01T10:05:00.000Z";
    sqlx::query("UPDATE episodes SET minute_summaries=minute_summaries||$3::jsonb WHERE account_id=$1 AND id=$2").bind(account).bind(episode).bind(serde_json::json!([{"start":later_start,"gist":"Speaker A agreed"}]).to_string()).execute(&mut *tx).await.unwrap();
    super::identity_presentation::save_formation_labels(
        &mut tx,
        account,
        episode,
        &later,
        &[MinuteBucket {
            start: later_start.into(),
            gist: "Speaker A agreed".into(),
        }],
    )
    .await
    .unwrap();
    let maps:String=sqlx::query_scalar("SELECT minute_labels::text FROM episode_identity_presentations WHERE account_id=$1 AND episode_id=$2").bind(account).bind(episode).fetch_one(&mut *tx).await.unwrap();
    let maps: serde_json::Value = serde_json::from_str(&maps).unwrap();
    assert_eq!(maps[FROM],stored[FROM],"retained minute buckets must keep their original authoring maps when a later namespace is saved");
    assert_eq!(maps[later_start], serde_json::to_value(&later).unwrap());
    tx.rollback().await.unwrap();
    cleanup(fixture).await;
}

#[tokio::test]
async fn identity_presentation_forward_context_separates_local_memory_namespaces() {
    use crate::persistence::{MemoryQueryRepository, SummaryUtterance};
    let Some(fixture) = test_persistence().await else {
        return;
    };
    let repo = &fixture.persistence;
    let account = "identity-context-writer";
    for id in 1..=3 {
        seed_turn(repo, account, id).await;
    }
    let claim = repo
        .claim_summary_window(account, FROM, TO, TO, 900)
        .await
        .unwrap()
        .unwrap();
    let ids = repo
        .settle_summary_window(SummaryWindowSettlement {
            claim,
            authored_labels: Default::default(),
            episodes: vec![draft(None, vec![1], false), draft(None, vec![2], false)],
            cursor: None,
        })
        .await
        .unwrap();
    let mut tx = repo.pool().begin().await.unwrap();
    for (episode, utterance) in ids.iter().zip([1, 2]) {
        let labels = super::identity_presentation::authored_labels(
            &mut tx,
            account,
            Some(*episode),
            &[utterance],
        )
        .await
        .unwrap();
        assert_eq!(labels.labels[0].label, "Speaker A");
        sqlx::query("UPDATE episodes SET title='Speaker A planned work',summary='Speaker A said \"Speaker A agrees\"' WHERE account_id=$1 AND id=$2")
            .bind(account).bind(episode).execute(&mut *tx).await.unwrap();
        super::identity_presentation::save_formation_labels(
            &mut tx,
            account,
            *episode,
            &labels,
            &[],
        )
        .await
        .unwrap();
    }
    tx.commit().await.unwrap();
    let (mut new, _) = repo
        .summary_evidence(account, FROM, TO, 500, 500)
        .await
        .unwrap();
    assert_eq!(new.len(), 1);
    assert_eq!(new[0].id, 3);
    let open = repo
        .open_episodes(account, FROM, TO, 100, &mut new)
        .await
        .unwrap();
    assert_eq!(
        new[0].speaker_label, "Speaker C",
        "new evidence and open memories must share one collision-free authoring namespace"
    );
    assert_eq!(open[0].title, "Speaker A planned work");
    assert_eq!(
        open[1].title, "Speaker B planned work",
        "a local Speaker A in another memory must be projected through its own frozen anchors"
    );
    assert_eq!(
        open[1].summary.as_deref(),
        Some("Speaker B said \"Speaker A agrees\"")
    );
    let labels = SummaryUtterance::authored_labels(&new);
    assert_eq!(labels.labels[0].utterance_ids, vec![3]);
    assert_eq!(open[1].authored_labels.labels[0].utterance_ids, vec![2]);
    sqlx::query("UPDATE episode_identity_presentations SET timeline_labels='{\"labels\":[]}' WHERE account_id=$1 AND episode_id=$2")
        .bind(account).bind(ids[1]).execute(repo.pool()).await.unwrap();
    let unbound = repo
        .open_episodes(account, FROM, TO, 100, &mut new)
        .await
        .unwrap();
    assert_eq!(
        unbound[1].title, "Speaker planned work",
        "unmapped historical context must not borrow a different voice's reserved slot"
    );
    let page = repo
        .list_episodes(
            account,
            &crate::persistence::EpisodeListRequest {
                from: None,
                to: None,
                limit: 50,
                include_low: true,
                episode_id: Some(ids[1]),
                before_started_at: None,
                before_id: None,
                probe_for_more: false,
            },
        )
        .await
        .unwrap();
    assert_eq!(
        page.episodes[0]["title"], "Speaker A planned work",
        "neutral provider context must not rewrite or invent a public historical authoring map"
    );
    cleanup(fixture).await;
}

#[tokio::test]
async fn identity_presentation_embedding_cas_rejects_late_identity_and_source_results() {
    use crate::persistence::{EpisodeEmbeddingWrite, EpisodeListRequest, MemoryQueryRepository};
    let Some(fixture) = test_persistence().await else {
        return;
    };
    let repo = &fixture.persistence;
    let account = "identity-embedding-writer";
    seed_turn(repo, account, 1).await;
    let (utterances, _) = repo
        .summary_evidence(account, FROM, TO, 500, 500)
        .await
        .unwrap();
    let labels = crate::persistence::SummaryUtterance::authored_labels(&utterances);
    let claim = repo
        .claim_summary_window(account, FROM, TO, TO, 900)
        .await
        .unwrap()
        .unwrap();
    let mut input = draft(None, vec![1], false);
    input.title = "Speaker A planned work".into();
    let id = repo
        .settle_summary_window(SummaryWindowSettlement {
            claim,
            authored_labels: labels,
            episodes: vec![input],
            cursor: None,
        })
        .await
        .unwrap()[0];
    let old = repo
        .episode_embedding_sources(account, &[id])
        .await
        .unwrap()
        .remove(0);
    // A local letter change is intentionally not a semantic identity change,
    // but it changes the encoder input and must still reject the old result.
    let revision_before: i64 =
        sqlx::query_scalar("SELECT identity_revision FROM episodes WHERE account_id=$1 AND id=$2")
            .bind(account)
            .bind(id)
            .fetch_one(repo.pool())
            .await
            .unwrap();
    sqlx::query(
        "UPDATE episode_speaker_slots SET slot_ordinal=1 WHERE account_id=$1 AND episode_id=$2",
    )
    .bind(account)
    .bind(id)
    .execute(repo.pool())
    .await
    .unwrap();
    let relabelled = repo
        .episode_embedding_sources(account, &[id])
        .await
        .unwrap()
        .remove(0);
    assert!(relabelled.text.contains("Speaker B planned work"));
    assert_ne!(
        old.source_revision, relabelled.source_revision,
        "the commitment must include the actual resolved encoder text"
    );
    repo.write_episode_embeddings(
        account,
        &[EpisodeEmbeddingWrite {
            id,
            source_revision: old.source_revision.clone(),
            embedding: vec![0.0; 384],
        }],
    )
    .await
    .unwrap();
    assert!(sqlx::query_scalar::<_,bool>("SELECT embedding IS NULL AND identity_revision=$3 FROM episodes WHERE account_id=$1 AND id=$2").bind(account).bind(id).bind(revision_before).fetch_one(repo.pool()).await.unwrap(),"a slot-only relabelling must reject the late vector without inventing an identity revision");
    sqlx::query(
        "INSERT INTO people(account_id,id,display_name,status) VALUES($1,20,'Ana','identified')",
    )
    .bind(account)
    .execute(repo.pool())
    .await
    .unwrap();
    sqlx::query("UPDATE speaker_clusters SET person_id=20,attribution_state='person_bound' WHERE account_id=$1 AND id=1").bind(account).execute(repo.pool()).await.unwrap();
    repo.list_episodes(
        account,
        &EpisodeListRequest {
            from: None,
            to: None,
            limit: 50,
            include_low: true,
            episode_id: Some(id),
            before_started_at: None,
            before_id: None,
            probe_for_more: false,
        },
    )
    .await
    .unwrap();
    repo.write_episode_embeddings(
        account,
        &[EpisodeEmbeddingWrite {
            id,
            source_revision: old.source_revision,
            embedding: vec![0.0; 384],
        }],
    )
    .await
    .unwrap();
    assert!(
        sqlx::query_scalar::<_, bool>(
            "SELECT embedding IS NULL FROM episodes WHERE account_id=$1 AND id=$2"
        )
        .bind(account)
        .bind(id)
        .fetch_one(repo.pool())
        .await
        .unwrap(),
        "a late encoder result must not overwrite a newer identity projection"
    );
    let current = repo
        .episode_embedding_sources(account, &[id])
        .await
        .unwrap()
        .remove(0);
    assert!(
        current.text.contains("Ana planned work"),
        "embedding input must use current authored-label presentation"
    );
    let before: String =
        sqlx::query_scalar("SELECT updated_at::text FROM episodes WHERE account_id=$1 AND id=$2")
            .bind(account)
            .bind(id)
            .fetch_one(repo.pool())
            .await
            .unwrap();
    repo.write_episode_embeddings(
        account,
        &[EpisodeEmbeddingWrite {
            id,
            source_revision: current.source_revision,
            embedding: vec![0.0; 384],
        }],
    )
    .await
    .unwrap();
    assert!(sqlx::query_scalar::<_,bool>("SELECT embedding IS NOT NULL AND updated_at::text=$3 FROM episodes WHERE account_id=$1 AND id=$2").bind(account).bind(id).bind(before).fetch_one(repo.pool()).await.unwrap(),"derived embedding writes must preserve source timestamps");
    let prior = repo
        .episode_embedding_sources(account, &[id])
        .await
        .unwrap()
        .remove(0);
    sqlx::query(
        "UPDATE episodes SET title='A new objective',embedding=NULL WHERE account_id=$1 AND id=$2",
    )
    .bind(account)
    .bind(id)
    .execute(repo.pool())
    .await
    .unwrap();
    repo.write_episode_embeddings(
        account,
        &[EpisodeEmbeddingWrite {
            id,
            source_revision: prior.source_revision,
            embedding: vec![0.0; 384],
        }],
    )
    .await
    .unwrap();
    assert!(
        sqlx::query_scalar::<_, bool>(
            "SELECT embedding IS NULL FROM episodes WHERE account_id=$1 AND id=$2"
        )
        .bind(account)
        .bind(id)
        .fetch_one(repo.pool())
        .await
        .unwrap(),
        "a late encoder result must not overwrite newer authored source text"
    );
    sqlx::query("INSERT INTO episode_final_briefs(account_id,episode_id,overview,decisions,action_items,important_links,open_questions) VALUES($1,$2,'Original brief','[]','[]','[]','[]')").bind(account).bind(id).execute(repo.pool()).await.unwrap();
    let before_brief = repo
        .episode_embedding_sources(account, &[id])
        .await
        .unwrap()
        .remove(0);
    let mut finalizer = repo.pool().begin().await.unwrap();
    super::advisory_transaction_lock(&mut finalizer, "memory-reconciliation", account)
        .await
        .unwrap();
    let blocker: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut *finalizer)
        .await
        .unwrap();
    sqlx::query("SELECT id FROM episodes WHERE account_id=$1 AND id=$2 FOR UPDATE")
        .bind(account)
        .bind(id)
        .fetch_one(&mut *finalizer)
        .await
        .unwrap();
    let writer_repo = repo.clone();
    let writer = tokio::spawn(async move {
        writer_repo
            .write_episode_embeddings(
                account,
                &[EpisodeEmbeddingWrite {
                    id,
                    source_revision: before_brief.source_revision,
                    embedding: vec![0.0; 384],
                }],
            )
            .await
    });
    let mut blocked = false;
    for _ in 0..200 {
        blocked = sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE $1=ANY(pg_blocking_pids(pid)))",
        )
        .bind(blocker)
        .fetch_one(repo.pool())
        .await
        .unwrap();
        if blocked {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    assert!(
        blocked,
        "the writer must actually wait behind the concurrent finalizer"
    );
    sqlx::query("UPDATE episode_final_briefs SET overview='A newly completed brief' WHERE account_id=$1 AND episode_id=$2").bind(account).bind(id).execute(&mut *finalizer).await.unwrap();
    sqlx::query("UPDATE episodes SET title=title WHERE account_id=$1 AND id=$2")
        .bind(account)
        .bind(id)
        .execute(&mut *finalizer)
        .await
        .unwrap();
    finalizer.commit().await.unwrap();
    writer.await.unwrap().unwrap();
    assert!(
        sqlx::query_scalar::<_, bool>(
            "SELECT embedding IS NULL FROM episodes WHERE account_id=$1 AND id=$2"
        )
        .bind(account)
        .bind(id)
        .fetch_one(repo.pool())
        .await
        .unwrap(),
        "the comparison after a lock wait must see the new separately stored brief"
    );
    cleanup(fixture).await;
}

#[tokio::test]
async fn identity_presentation_reconciliation_preserves_finalized_retained_maps() {
    use crate::persistence::{
        identity_presentation::AuthoredLabelMap, EpisodeListRequest, MemoryQueryRepository,
    };
    let Some(fixture) = test_persistence().await else {
        return;
    };
    let repo = &fixture.persistence;
    let account = "identity-retained-finalized-map";
    sqlx::query("INSERT INTO accounts(id,email,primary_provider,primary_subject) VALUES($1,'synthetic@example.test','google',$1)").bind(account).execute(repo.pool()).await.unwrap();
    super::activation::test_activate_speaker_writer_account(repo, account)
        .await
        .unwrap();
    let ids = form_capture(repo, account, 2).await;
    let retained = ids[1];
    let mut tx = repo.pool().begin().await.unwrap();
    let original =
        super::identity_presentation::authored_labels(&mut tx, account, Some(retained), &[2])
            .await
            .unwrap();
    assert_eq!(original.labels[0].label, "Speaker A");
    sqlx::query("UPDATE episodes SET title='Speaker A kept the plan',summary='Speaker A kept the summary',action_items='[\"Speaker A will follow up\"]',minute_summaries='[{\"start\":\"minute\",\"gist\":\"Speaker A kept the minute\"}]',minutes_text='Speaker A kept the minute',structure_state='reconciled',finalized_at=clock_timestamp(),finalization_status='complete' WHERE account_id=$1 AND id=$2").bind(account).bind(retained).execute(&mut *tx).await.unwrap();
    sqlx::query("UPDATE episode_identity_presentations SET timeline_labels=$3::jsonb,action_labels=$3::jsonb,brief_labels=$3::jsonb,minute_labels=jsonb_build_object('minute',$3::jsonb) WHERE account_id=$1 AND episode_id=$2").bind(account).bind(retained).bind(serde_json::to_string(&original).unwrap()).execute(&mut *tx).await.unwrap();
    let old_maps:String=sqlx::query_scalar("SELECT jsonb_build_array(timeline_labels,action_labels,brief_labels,minute_labels)::text FROM episode_identity_presentations WHERE account_id=$1 AND episode_id=$2").bind(account).bind(retained).fetch_one(&mut *tx).await.unwrap();
    tx.commit().await.unwrap();
    let snapshot = repo
        .next_source_settled_cohort(account, 4 * 60 * 60, None, 32, 1000)
        .await
        .unwrap()
        .unwrap();
    let claim = repo
        .claim_reconciliation(&snapshot, 900)
        .await
        .unwrap()
        .unwrap();
    let mut write = super::memory_reconciliation::test_provider_stage_write(
        &snapshot,
        "preserve-finalized-map",
    )
    .unwrap();
    let template = write.planned_outputs[0].clone();
    write.planned_outputs = snapshot
        .drafts
        .iter()
        .enumerate()
        .map(|(ordinal, draft)| {
            let mut output = template.clone();
            output.output_ordinal = ordinal as i64;
            output.retained_episode_id = Some(draft.id);
            output.predecessor_episode_ids = vec![draft.id];
            output.member_source_ids = draft.member_source_ids.clone();
            output.started_at = draft.started_at.clone();
            output.ended_at = draft.ended_at.clone();
            output.authored_labels = AuthoredLabelMap::from_labels(
                snapshot
                    .authored_labels
                    .labels
                    .iter()
                    .filter(|label| {
                        label
                            .utterance_ids
                            .iter()
                            .any(|id| draft.member_source_ids.contains(&format!("utterance:{id}")))
                    })
                    .cloned(),
            );
            output
        })
        .collect();
    assert_eq!(
        write
            .planned_outputs
            .iter()
            .find(|output| output.retained_episode_id == Some(retained))
            .unwrap()
            .authored_labels
            .labels[0]
            .label,
        "Speaker B",
        "the new organizer input must use a different namespace from the retained memory"
    );
    let guard = repo
        .acquire_provider_egress_guard(&claim)
        .await
        .unwrap()
        .unwrap();
    let staged = guard.stage_and_release(write).await.unwrap();
    let published = repo
        .publish_reconciliation(ReconciliationPublish {
            claim,
            reconciliation_id: "preserved-finalized-map".into(),
            cohort_started_at: snapshot.cohort_started_at,
            cohort_ended_at: snapshot.cohort_ended_at,
            result_commitment: staged.result_commitment,
        })
        .await
        .unwrap();
    assert!(matches!(
        published,
        ReconciliationPublishResult::Published { .. }
    ));
    let after:String=sqlx::query_scalar("SELECT jsonb_build_array(timeline_labels,action_labels,brief_labels,minute_labels)::text FROM episode_identity_presentations WHERE account_id=$1 AND episode_id=$2").bind(account).bind(retained).fetch_one(repo.pool()).await.unwrap();
    assert_eq!(
        after, old_maps,
        "retaining finalized authored bytes must preserve every original label map"
    );
    sqlx::query(
        "INSERT INTO people(account_id,id,display_name,status) VALUES($1,20,'Ana','identified')",
    )
    .bind(account)
    .execute(repo.pool())
    .await
    .unwrap();
    sqlx::query("UPDATE speaker_clusters SET person_id=20,attribution_state='person_bound' WHERE account_id=$1 AND id=2").bind(account).execute(repo.pool()).await.unwrap();
    let page = repo
        .list_episodes(
            account,
            &EpisodeListRequest {
                from: None,
                to: None,
                limit: 50,
                include_low: true,
                episode_id: Some(retained),
                before_started_at: None,
                before_id: None,
                probe_for_more: false,
            },
        )
        .await
        .unwrap();
    assert_eq!(page.episodes[0]["title"], "Ana kept the plan");
    assert_eq!(
        page.episodes[0]["minute_summaries"][0]["gist"],
        "Ana kept the minute"
    );
    cleanup(fixture).await;
}
