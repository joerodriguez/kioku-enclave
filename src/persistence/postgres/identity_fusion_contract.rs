//! Synthetic PostgreSQL contracts for the source-backed Phase 4 reducer.
use super::{identity_fusion, voice_identity, PostgresPersistence};
use crate::{
    cp::{
        media::{AudioTurn, PersonFact},
        voice_memory::EMBEDDING_SPACE,
        voice_quality::SCORER_VERSION,
    },
    persistence::{
        MediaProcessingClaim, MediaProcessingClass, MemoryQueryRepository, PeopleListRequest,
        PublicPersonStatus, VoiceCohort,
    },
};
use sqlx::Row;
use std::collections::HashMap;

pub(super) async fn seed(
    repo: &PostgresPersistence,
    account: &str,
    observation: i64,
    profile: i64,
    domain: &str,
) {
    let event = format!("event-{observation}");
    voice_identity::tests::seed_voice_observation(
        repo,
        account,
        "session",
        &event,
        observation,
        observation,
    )
    .await;
    voice_identity::tests::seed_voice_memory(repo, account, observation, observation).await;
    let mut vector = vec![0.0; 256];
    vector[0] = 1.0;
    let bytes = crate::cp::voice_identity::encode_embedding(&vector).unwrap();
    let mut tx = repo.pool().begin().await.unwrap();
    assert!(voice_identity::lock_account(&mut tx, account)
        .await
        .unwrap());
    sqlx::query("INSERT INTO voice_profiles(account_id,id,label,embedding_space,channel_domain,centroid,scorer_version) VALUES($1,$2,$3,$4,$5,$6,$7) ON CONFLICT DO NOTHING")
        .bind(account).bind(profile).bind(format!("profile-{profile}")).bind(EMBEDDING_SPACE).bind(domain).bind(&bytes).bind(SCORER_VERSION).execute(&mut *tx).await.unwrap();
    sqlx::query("INSERT INTO voice_samples(account_id,id,speaker_observation_id,embedding_space,channel_domain,embedding,quality_score,quality_version,scorer_version,eligibility,duration_ms,accepted,embedding_job_id) VALUES($1,$2,$2,$3,$4,$5,1,1,$6,'enroll',4000,true,$2)")
        .bind(account).bind(observation).bind(EMBEDDING_SPACE).bind(domain).bind(bytes).bind(SCORER_VERSION).execute(&mut *tx).await.unwrap();
    super::owner_voice::assign_sample(&mut tx, account, observation, observation, profile, None)
        .await
        .unwrap();
    super::owner_voice::refresh_clusters(&mut tx, account, &[observation])
        .await
        .unwrap();
    voice_identity::recompute_profile(&mut tx, account, profile, "synthetic_seed")
        .await
        .unwrap();
    sqlx::query("UPDATE voice_embedding_jobs SET state='ready' WHERE account_id=$1 AND id=$2")
        .bind(account)
        .bind(observation)
        .execute(&mut *tx)
        .await
        .unwrap();
    tx.commit().await.unwrap();
}
pub(super) async fn intro(
    repo: &PostgresPersistence,
    account: &str,
    observation: i64,
    name: &str,
    fact: bool,
) {
    let text = format!("My name is {name}. I work at Example");
    sqlx::query("UPDATE speaker_observations SET transcript_text=$3 WHERE account_id=$1 AND id=$2")
        .bind(account)
        .bind(observation)
        .bind(&text)
        .execute(repo.pool())
        .await
        .unwrap();
    let turn = AudioTurn {
        turn_id: "turn-a".into(),
        start_ms: 0,
        end_ms: 4000,
        speaker_local_id: "speaker-a".into(),
        text,
        language: Some("en".into()),
        speaker_name: Some(name.into()),
        speaker_name_confidence: Some(0.99),
        speaker_name_evidence: Some(format!("My name is {name}")),
        speaker_name_kind: Some("self_identification".into()),
        speaker_name_subject_turn_id: Some("turn-a".into()),
        speaker_name_target_turn_id: None,
        person_facts: if fact {
            vec![PersonFact {
                predicate: "organization".into(),
                value: "Example".into(),
                evidence: "I work at Example".into(),
                confidence: Some(0.63),
                replacement_of: None,
            }]
        } else {
            vec![]
        },
        overlap: false,
        quality_flags: vec![],
    };
    let claim = MediaProcessingClaim {
        account_id: account.into(),
        work_unit_id: format!("event-{observation}"),
        class: MediaProcessingClass::Audio,
        claim_token: "synthetic".into(),
        claim_until: "2099-01-01T00:00:00Z".into(),
        jobs: vec![],
        provider_attempt_number: 1,
        staged_response: None,
    };
    let mut tx = repo.pool().begin().await.unwrap();
    assert!(voice_identity::lock_account(&mut tx, account)
        .await
        .unwrap());
    identity_fusion::record_audio(
        &mut tx,
        account,
        &claim,
        &[turn],
        &HashMap::from([("turn-a".into(), observation)]),
        false,
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();
}
pub(super) async fn reduce(repo: &PostgresPersistence, account: &str, profiles: &[i64]) {
    let mut tx = repo.pool().begin().await.unwrap();
    assert!(voice_identity::lock_account(&mut tx, account)
        .await
        .unwrap());
    let mut changed_profiles = profiles.to_vec();
    changed_profiles.extend(
        identity_fusion::reconcile_profiles(&mut tx, account, profiles, true)
            .await
            .unwrap(),
    );
    identity_fusion::enrich_facts(&mut tx, account, true)
        .await
        .unwrap();
    voice_identity::refresh_affected_speaker_projections(
        &mut tx,
        account,
        &[],
        &changed_profiles,
        &[],
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();
}

#[tokio::test]
async fn same_names_stay_separate_and_fact_confidence_survives_real_storage() {
    let Some(fixture) = super::tests::test_persistence().await else {
        return;
    };
    let repo = &fixture.persistence;
    let account = "fusion-same-name";
    repo.set_voice_identity_cohort(VoiceCohort::All, &[])
        .await
        .unwrap();
    seed(repo, account, 1, 1, "macos:builtin_mic").await;
    seed(repo, account, 2, 2, "ios:builtin_mic").await;
    intro(repo, account, 1, "Sam Lee", true).await;
    intro(repo, account, 2, "Sam Lee", false).await;
    reduce(repo, account, &[1, 2]).await;
    let people:Vec<i64>=sqlx::query_scalar("SELECT person_id FROM profile_name_bindings WHERE account_id=$1 AND status='accepted' ORDER BY profile_id").bind(account).fetch_all(repo.pool()).await.unwrap();
    assert_eq!(
        people.len(),
        2,
        "each independently named voice must receive its own accepted binding"
    );
    assert_ne!(
        people[0], people[1],
        "the same full name across domains must never join opaque people"
    );
    let fact = sqlx::query(
        "SELECT person_id,confidence FROM person_facts WHERE account_id=$1 AND status='active'",
    )
    .bind(account)
    .fetch_one(repo.pool())
    .await
    .unwrap();
    assert_eq!(
        fact.get::<i64, _>("person_id"),
        people[0],
        "facts must follow their source voice's accepted person"
    );
    assert_eq!(
        fact.get::<f64, _>("confidence"),
        0.63,
        "PostgreSQL enrichment must retain actual fact confidence instead of hardcoding one"
    );
    let count: i64 =
        sqlx::query_scalar("SELECT count(*) FROM profile_name_claims WHERE account_id=$1")
            .bind(account)
            .fetch_one(repo.pool())
            .await
            .unwrap();
    reduce(repo, account, &[2, 1]).await;
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT count(*) FROM profile_name_claims WHERE account_id=$1"
        )
        .bind(account)
        .fetch_one(repo.pool())
        .await
        .unwrap(),
        count,
        "unchanged evidence must not append duplicate name decisions"
    );
    let exported = repo.export(account).await.unwrap();
    let other_export = repo.export("other-fusion-tenant").await.unwrap();
    for table in [
        "identity_name_inputs",
        "profile_name_bindings",
        "profile_name_claims",
        "person_fact_candidates",
    ] {
        assert!(
            exported[table]
                .as_array()
                .is_some_and(|rows| !rows.is_empty()),
            "identity export must include every populated name/fact family: {table}"
        );
        assert!(
            other_export[table].as_array().is_some_and(Vec::is_empty),
            "identity export must never expose another account's name/fact rows: {table}"
        );
    }
    sqlx::query("DELETE FROM accounts WHERE id=$1")
        .bind(account)
        .execute(repo.pool())
        .await
        .unwrap();
    for table in [
        "identity_name_inputs",
        "profile_name_bindings",
        "profile_name_claims",
        "person_fact_candidates",
    ] {
        assert_eq!(
            sqlx::query_scalar::<_, i64>(sqlx::AssertSqlSafe(format!(
                "SELECT count(*) FROM {table} WHERE account_id=$1"
            )))
            .bind(account)
            .fetch_one(repo.pool())
            .await
            .unwrap(),
            0,
            "account erasure must cascade through every name/fact family: {table}"
        );
    }
    fixture.persistence.pool().close().await;
    sqlx::query(sqlx::AssertSqlSafe(format!(
        "DROP SCHEMA {} CASCADE",
        fixture.schema
    )))
    .execute(fixture.base.pool())
    .await
    .unwrap();
    fixture.base.pool().close().await;
}

#[tokio::test]
async fn incompatible_names_quarantine_binding_while_acoustic_profile_survives() {
    let Some(fixture) = super::tests::test_persistence().await else {
        return;
    };
    let repo = &fixture.persistence;
    let account = "fusion-name-conflict";
    repo.set_voice_identity_cohort(VoiceCohort::All, &[])
        .await
        .unwrap();
    seed(repo, account, 1, 1, "macos:builtin_mic").await;
    intro(repo, account, 1, "Sam", false).await;
    reduce(repo, account, &[1]).await;
    let person: i64 = sqlx::query_scalar(
        "SELECT person_id FROM profile_name_bindings WHERE account_id=$1 AND profile_id=1",
    )
    .bind(account)
    .fetch_one(repo.pool())
    .await
    .unwrap();
    seed(repo, account, 2, 1, "macos:builtin_mic").await;
    intro(repo, account, 2, "Sam Lee", false).await;
    reduce(repo, account, &[1]).await;
    assert_eq!(
        sqlx::query_scalar::<_, String>(
            "SELECT display_name FROM people WHERE account_id=$1 AND id=$2"
        )
        .bind(account)
        .bind(person)
        .fetch_one(repo.pool())
        .await
        .unwrap(),
        "Sam Lee",
        "a fuller introduction on the same voice must refine its existing opaque person"
    );
    let page = repo
        .list_people(
            account,
            &PeopleListRequest {
                kind: PublicPersonStatus::Identified,
                after_id: 0,
                limit: 100,
                query: None,
            },
        )
        .await
        .unwrap();
    assert_eq!(
        page.people.iter().map(|p| p.id).collect::<Vec<_>>(),
        vec![person],
        "same-voice name refinement must retire the temporary public introduction person"
    );
    seed(repo, account, 3, 1, "macos:builtin_mic").await;
    intro(repo, account, 3, "Alex Jones", false).await;
    reduce(repo, account, &[1]).await;
    let row=sqlx::query("SELECT p.status,p.sample_count,b.status binding_status FROM voice_profiles p JOIN profile_name_bindings b ON b.account_id=p.account_id AND b.profile_id=p.id WHERE p.account_id=$1 AND p.id=1").bind(account).fetch_one(repo.pool()).await.unwrap();
    assert_eq!(
        row.get::<String, _>("binding_status"),
        "quarantined",
        "incompatible accepted names must quarantine the name binding"
    );
    assert_eq!(
        row.get::<String, _>("status"),
        "stable",
        "name conflict must preserve a healthy acoustic matching profile"
    );
    assert_eq!(
        row.get::<i64, _>("sample_count"),
        3,
        "name conflict must retain the profile's actual acoustic support"
    );
    let people:Vec<i64>=sqlx::query_scalar("SELECT person_id FROM episode_participants WHERE account_id=$1 AND state='active' AND person_id IS NOT NULL").bind(account).fetch_all(repo.pool()).await.unwrap();
    assert!(
        people.is_empty(),
        "a conflicted profile must not leak cached direct names into public participants"
    );
    assert!(sqlx::query_scalar::<_,i64>("SELECT count(*) FROM person_name_claims WHERE account_id=$1 AND evidence_kind='name_fusion' AND supersedes_id IS NOT NULL").bind(account).fetch_one(repo.pool()).await.unwrap()>0,"name transitions must append claim history with predecessors");
    fixture.persistence.pool().close().await;
    sqlx::query(sqlx::AssertSqlSafe(format!(
        "DROP SCHEMA {} CASCADE",
        fixture.schema
    )))
    .execute(fixture.base.pool())
    .await
    .unwrap();
    fixture.base.pool().close().await;
}

#[tokio::test]
async fn owner_assignment_retires_temporary_public_introduction_without_memory_refresh() {
    let Some(fixture) = super::tests::test_persistence().await else {
        return;
    };
    let repo = &fixture.persistence;
    let account = "fusion-owner-retirement";
    repo.set_voice_identity_cohort(VoiceCohort::All, &[])
        .await
        .unwrap();
    seed(repo, account, 1, 1, "macos:builtin_mic").await;
    intro(repo, account, 1, "Sam Lee", true).await;
    reduce(repo, account, &[1]).await;
    let temporary: i64 = sqlx::query_scalar(
        "SELECT person_id FROM profile_name_bindings WHERE account_id=$1 AND profile_id=1",
    )
    .bind(account)
    .fetch_one(repo.pool())
    .await
    .unwrap();
    let mut tx = repo.pool().begin().await.unwrap();
    assert!(voice_identity::lock_account(&mut tx, account)
        .await
        .unwrap());
    sqlx::query("INSERT INTO people(account_id,id,status) VALUES($1,900,'owner')")
        .bind(account)
        .execute(&mut *tx)
        .await
        .unwrap();
    sqlx::query("UPDATE voice_profiles SET person_id=900 WHERE account_id=$1 AND id=1")
        .bind(account)
        .execute(&mut *tx)
        .await
        .unwrap();
    sqlx::query("DELETE FROM episode_members WHERE account_id=$1")
        .bind(account)
        .execute(&mut *tx)
        .await
        .unwrap();
    super::owner_voice::assign_sample(&mut tx, account, 1, 1, 1, Some("owner_voice"))
        .await
        .unwrap();
    tx.commit().await.unwrap();
    let page = repo
        .list_people(
            account,
            &PeopleListRequest {
                kind: PublicPersonStatus::Identified,
                after_id: 0,
                limit: 100,
                query: None,
            },
        )
        .await
        .unwrap();
    assert!(page.people.is_empty(),"owner attribution must retire temporary public introduction identities without a memory refresh");
    assert!(
        matches!(
            repo.person_profile(account, temporary).await,
            Err(crate::error::EnclaveError::NotFound)
        ),
        "the retired owner introduction must not remain a public People detail"
    );
    assert!(
        matches!(
            repo.person_evidence(account, temporary, None, 100).await,
            Err(crate::error::EnclaveError::NotFound)
        ),
        "retired owner introduction evidence must not remain publicly addressable"
    );
    assert_eq!(sqlx::query_scalar::<_,i64>("SELECT count(*) FROM person_facts WHERE account_id=$1 AND person_id=$2 AND status='active'").bind(account).bind(temporary).fetch_one(repo.pool()).await.unwrap(),0,"owner assignment must withdraw facts from the temporary person");
    fixture.persistence.pool().close().await;
    sqlx::query(sqlx::AssertSqlSafe(format!(
        "DROP SCHEMA {} CASCADE",
        fixture.schema
    )))
    .execute(fixture.base.pool())
    .await
    .unwrap();
    fixture.base.pool().close().await;
}

#[tokio::test]
async fn explicit_replacement_retires_all_prior_support_and_erasure_restores_survivors() {
    let Some(fixture) = super::tests::test_persistence().await else {
        return;
    };
    let repo = &fixture.persistence;
    let account = "fusion-fact-replacement";
    repo.set_voice_identity_cohort(VoiceCohort::All, &[])
        .await
        .unwrap();
    for id in 1..=3 {
        seed(repo, account, id, 1, "macos:builtin_mic").await;
        intro(repo, account, id, "Sam Lee", true).await;
    }
    sqlx::query("UPDATE person_fact_candidates SET observed_at='2026-01-01T00:00:00Z'::timestamptz+make_interval(secs=>speaker_observation_id::double precision),value=CASE WHEN speaker_observation_id=3 THEN 'Next' ELSE 'Example' END,replacement_of=CASE WHEN speaker_observation_id=3 THEN 'Example' END,value_key=CASE WHEN speaker_observation_id=3 THEN 'next' ELSE 'example' END,replacement_key=CASE WHEN speaker_observation_id=3 THEN 'example' END,literal_evidence=CASE WHEN speaker_observation_id=3 THEN 'I left Example and now work at Next' ELSE literal_evidence END WHERE account_id=$1").bind(account).execute(repo.pool()).await.unwrap();
    reduce(repo, account, &[1]).await;
    let person: i64 = sqlx::query_scalar(
        "SELECT person_id FROM profile_name_bindings WHERE account_id=$1 AND profile_id=1",
    )
    .bind(account)
    .fetch_one(repo.pool())
    .await
    .unwrap();
    let detail = repo.person_profile(account, person).await.unwrap();
    assert_eq!(
        detail
            .facts
            .iter()
            .filter(|f| f.value == "Example" && f.status == "active")
            .count(),
        0,
        "explicit replacement must retire every earlier support for the replaced organization"
    );
    assert_eq!(
        detail
            .facts
            .iter()
            .filter(|f| f.value == "Next" && f.status == "active")
            .count(),
        1
    );
    let mut tx = repo.pool().begin().await.unwrap();
    assert!(voice_identity::lock_account(&mut tx, account)
        .await
        .unwrap());
    let affected = voice_identity::erase_event_samples(&mut tx, account, &["event-3".into()])
        .await
        .unwrap();
    sqlx::query("DELETE FROM capture_events WHERE account_id=$1 AND event_id='event-3'")
        .bind(account)
        .execute(&mut *tx)
        .await
        .unwrap();
    voice_identity::recompute_erased_profiles(&mut tx, account, &affected)
        .await
        .unwrap();
    tx.commit().await.unwrap();
    let detail = repo.person_profile(account, person).await.unwrap();
    assert_eq!(
        detail
            .facts
            .iter()
            .filter(|f| f.value == "Example" && f.status == "active")
            .count(),
        2,
        "erasing a replacement source must restore every surviving prior support"
    );
    assert!(
        !detail.facts.iter().any(|f| f.value == "Next"),
        "erasure must remove the fact and its replacement source"
    );
    fixture.persistence.pool().close().await;
    sqlx::query(sqlx::AssertSqlSafe(format!(
        "DROP SCHEMA {} CASCADE",
        fixture.schema
    )))
    .execute(fixture.base.pool())
    .await
    .unwrap();
    fixture.base.pool().close().await;
}

async fn vocative_input(repo: &PostgresPersistence, account: &str, source: i64, target: i64) {
    let turns: Vec<AudioTurn> = serde_json::from_value(serde_json::json!([
        {"turn_id":"address","speaker_local_id":"voter","start_ms":0,"end_ms":4000,
         "text":"Sam Lee, what do you think?","speaker_name":"Sam Lee","speaker_name_confidence":0.8,
         "speaker_name_evidence":"Sam Lee","speaker_name_kind":"vocative_address",
         "speaker_name_subject_turn_id":"reply","speaker_name_target_turn_id":"reply"},
        {"turn_id":"reply","speaker_local_id":"target","start_ms":5000,"end_ms":9000,"text":"Thanks"}
    ])).unwrap();
    let claim = MediaProcessingClaim {
        account_id: account.into(),
        work_unit_id: format!("vote-{source}"),
        class: MediaProcessingClass::Audio,
        claim_token: "synthetic".into(),
        claim_until: "2099-01-01T00:00:00Z".into(),
        jobs: vec![],
        provider_attempt_number: 1,
        staged_response: None,
    };
    let mut tx = repo.pool().begin().await.unwrap();
    assert!(voice_identity::lock_account(&mut tx, account)
        .await
        .unwrap());
    identity_fusion::record_audio(
        &mut tx,
        account,
        &claim,
        &turns,
        &HashMap::from([("address".into(), source), ("reply".into(), target)]),
        false,
    )
    .await
    .unwrap();
    assert_eq!(sqlx::query_scalar::<_,i64>("SELECT count(*) FROM identity_name_inputs WHERE account_id=$1 AND kind='vocative' AND source_observation_id=$2 AND subject_observation_id=$3")
        .bind(account).bind(source).bind(target).fetch_one(&mut *tx).await.unwrap(),1,
        "audio extraction must retain a grounded vocative addressed to a later turn");
    tx.commit().await.unwrap();
}

#[tokio::test]
async fn vocative_votes_require_current_retained_source_and_voter_authority() {
    let Some(fixture) = super::tests::test_persistence().await else {
        return;
    };
    let repo = &fixture.persistence;
    let account = "fusion-voter-authority";
    repo.set_voice_identity_cohort(VoiceCohort::All, &[])
        .await
        .unwrap();
    seed(repo, account, 1, 1, "macos:remote_received").await;
    for (id, profile) in [(11, 2), (12, 2), (13, 3)] {
        seed(repo, account, id, profile, "macos:builtin_mic").await;
        vocative_input(repo, account, id, 1).await;
    }
    reduce(repo, account, &[1]).await;
    assert_eq!(
        sqlx::query_scalar::<_, String>(
            "SELECT status FROM profile_name_bindings WHERE account_id=$1 AND profile_id=1"
        )
        .bind(account)
        .fetch_one(repo.pool())
        .await
        .unwrap(),
        "accepted",
        "three grounded votes from two current voices and memories must bind"
    );
    let mutations=[
        ("inactive voter assignment", "UPDATE voice_sample_profile_assignments SET active=false WHERE account_id=$1 AND sample_id=13"),
        ("rejected voter sample", "UPDATE voice_samples SET accepted=false WHERE account_id=$1 AND id=13"),
        ("expired addressing source", "UPDATE media_objects SET retain_until=clock_timestamp()-interval '1 second' WHERE account_id=$1 AND event_id='event-13'"),
        ("pending addressing deletion", "INSERT INTO episode_deletions(account_id,episode_id,state,purge,media_object_keys,utterance_ids,screenshot_ids,segment_ids,orphan_event_ids) VALUES($1,13,'pending','{}','[]','[]','[]','[]','[]')"),
        ("stale voter observation pointer", "UPDATE speaker_observations SET voice_sample_id=NULL WHERE account_id=$1 AND id=13"),
        ("mixed addressing cluster", "UPDATE speaker_clusters SET profile_updates_quarantined=true WHERE account_id=$1 AND id=13"),
        ("expired target source", "UPDATE media_objects SET retain_until=clock_timestamp()-interval '1 second' WHERE account_id=$1 AND event_id='event-1'"),
    ];
    let mut wrongly_accepted = Vec::new();
    for (label, sql) in mutations {
        let mut tx = repo.pool().begin().await.unwrap();
        assert!(voice_identity::lock_account(&mut tx, account)
            .await
            .unwrap());
        sqlx::query(sqlx::AssertSqlSafe(sql))
            .bind(account)
            .execute(&mut *tx)
            .await
            .unwrap();
        identity_fusion::reconcile_profiles(&mut tx, account, &[1], true)
            .await
            .unwrap();
        let status: String = sqlx::query_scalar(
            "SELECT status FROM profile_name_bindings WHERE account_id=$1 AND profile_id=1",
        )
        .bind(account)
        .fetch_one(&mut *tx)
        .await
        .unwrap();
        if status == "accepted" {
            wrongly_accepted.push(label);
        }
        tx.rollback().await.unwrap();
    }
    assert!(wrongly_accepted.is_empty(),"name votes must reject expired, deleted or stale source/voter authority: {wrongly_accepted:?}");
    fixture.persistence.pool().close().await;
    sqlx::query(sqlx::AssertSqlSafe(format!(
        "DROP SCHEMA {} CASCADE",
        fixture.schema
    )))
    .execute(fixture.base.pool())
    .await
    .unwrap();
    fixture.base.pool().close().await;
}

#[tokio::test]
async fn bounded_maintenance_reaches_names_after_empty_profiles() {
    let Some(fixture) = super::tests::test_persistence().await else {
        return;
    };
    let repo = &fixture.persistence;
    let account = "fusion-fair-maintenance";
    repo.set_voice_identity_cohort(VoiceCohort::All, &[])
        .await
        .unwrap();
    for id in 1..=18 {
        seed(repo, account, id, id, "macos:builtin_mic").await;
    }
    intro(repo, account, 18, "Sam Lee", false).await;
    for _ in 0..3 {
        let mut tx = repo.pool().begin().await.unwrap();
        assert!(voice_identity::lock_account(&mut tx, account)
            .await
            .unwrap());
        identity_fusion::maintain(&mut tx, account, true)
            .await
            .unwrap();
        tx.commit().await.unwrap();
    }
    assert!(sqlx::query_scalar::<_,bool>("SELECT EXISTS(SELECT 1 FROM profile_name_bindings WHERE account_id=$1 AND profile_id=18 AND status='accepted')").bind(account).fetch_one(repo.pool()).await.unwrap(),"empty earlier profiles must not starve later name evidence in bounded maintenance");
    fixture.persistence.pool().close().await;
    sqlx::query(sqlx::AssertSqlSafe(format!(
        "DROP SCHEMA {} CASCADE",
        fixture.schema
    )))
    .execute(fixture.base.pool())
    .await
    .unwrap();
    fixture.base.pool().close().await;
}

async fn screen_input(
    repo: &PostgresPersistence,
    account: &str,
    id: i64,
    target: i64,
    active: bool,
) {
    voice_identity::tests::seed_voice_observation(
        repo,
        account,
        "session",
        &format!("event-{id}"),
        id,
        id,
    )
    .await;
    sqlx::query(
        "UPDATE capture_events SET stream_kind='mac_screen' WHERE account_id=$1 AND event_id=$2",
    )
    .bind(account)
    .bind(format!("event-{id}"))
    .execute(repo.pool())
    .await
    .unwrap();
    sqlx::query("INSERT INTO screenshots(account_id,id,captured_at) SELECT $1,$2,coalesce((SELECT started_at FROM speaker_observations WHERE account_id=$1 AND id=$3),'2026-01-01T00:00:00Z'::timestamptz+make_interval(secs=>$3::double precision*10))+interval '1 second'").bind(account).bind(id).bind(target).execute(repo.pool()).await.unwrap();
    sqlx::query("INSERT INTO visual_speaker_observations(account_id,id,event_id,screenshot_id,observed_at,platform,displayed_name,normalized_name,highlight_state,confidence) SELECT account_id,id,$3,id,captured_at,'meeting','Sam Lee','sam lee',$4,0.99 FROM screenshots WHERE account_id=$1 AND id=$2")
        .bind(account).bind(id).bind(format!("event-{id}")).bind(if active {"active_speaker_box"} else {"none"}).execute(repo.pool()).await.unwrap();
    sqlx::query("INSERT INTO identity_evidence(account_id,id,source_event_id,observed_at,kind,claimed_name,evidence,score,status) SELECT account_id,id,event_id,observed_at,'screen_display_name',displayed_name,'{}',confidence,'proposed' FROM visual_speaker_observations WHERE account_id=$1 AND id=$2").bind(account).bind(id).execute(repo.pool()).await.unwrap();
    sqlx::query("INSERT INTO episode_members(account_id,episode_id,record_type,record_id) SELECT $1,$2,'screenshot',$3 WHERE EXISTS(SELECT 1 FROM episodes WHERE account_id=$1 AND id=$2)").bind(account).bind(target).bind(id).execute(repo.pool()).await.unwrap();
    let mut tx = repo.pool().begin().await.unwrap();
    assert!(voice_identity::lock_account(&mut tx, account)
        .await
        .unwrap());
    identity_fusion::record_screen(&mut tx, account, id, id, active, true)
        .await
        .unwrap();
    tx.commit().await.unwrap();
}

#[tokio::test]
async fn exact_screen_joins_revalidate_frame_source_and_current_turns() {
    let Some(fixture) = super::tests::test_persistence().await else {
        return;
    };
    let repo = &fixture.persistence;
    let account = "fusion-screen-authority";
    repo.set_voice_identity_cohort(VoiceCohort::All, &[])
        .await
        .unwrap();
    for id in 1..=2 {
        seed(repo, account, id, 1, "macos:remote_received").await;
        sqlx::query("UPDATE speaker_observations SET started_at='2026-01-01T00:00:00Z'::timestamptz+make_interval(secs=>id::double precision*10),ended_at='2026-01-01T00:00:00Z'::timestamptz+make_interval(secs=>id::double precision*10+4) WHERE account_id=$1 AND id=$2").bind(account).bind(id).execute(repo.pool()).await.unwrap();
        sqlx::query("UPDATE capture_events SET stream_kind='system_audio',audio_role='remote_received' WHERE account_id=$1 AND event_id=$2").bind(account).bind(format!("event-{id}")).execute(repo.pool()).await.unwrap();
    }
    screen_input(repo, account, 101, 1, true).await;
    screen_input(repo, account, 102, 1, true).await;
    screen_input(repo, account, 103, 2, true).await;
    reduce(repo, account, &[1]).await;
    assert_eq!(
        sqlx::query_scalar::<_, String>(
            "SELECT status FROM profile_name_bindings WHERE account_id=$1 AND profile_id=1"
        )
        .bind(account)
        .fetch_one(repo.pool())
        .await
        .unwrap(),
        "accepted",
        "three exact frames across two remote turns must bind"
    );
    let mutations=[
        ("half-open end boundary", "UPDATE visual_speaker_observations SET observed_at=(SELECT ended_at FROM speaker_observations WHERE account_id=$1 AND id=2) WHERE account_id=$1 AND id=103"),
        ("nonremote role", "UPDATE capture_events SET audio_role='ambient' WHERE account_id=$1 AND event_id='event-2'"),
        ("microphone source", "UPDATE capture_events SET stream_kind='mic' WHERE account_id=$1 AND event_id='event-2'"),
        ("different device", "UPDATE capture_events SET device_id='another-device' WHERE account_id=$1 AND event_id='event-103'"),
        ("overlapping turn", "UPDATE speaker_observations SET overlap=true WHERE account_id=$1 AND id=2"),
        ("expired frame", "UPDATE media_objects SET retain_until=clock_timestamp()-interval '1 second' WHERE account_id=$1 AND event_id='event-103'"),
        ("frame deletion inventory", "INSERT INTO episode_deletions(account_id,episode_id,state,purge,media_object_keys,utterance_ids,screenshot_ids,segment_ids,orphan_event_ids) VALUES($1,900,'pending','{}','[]','[]','[]','[]','[\"event-103\"]')"),
        ("inactive target assignment", "UPDATE voice_sample_profile_assignments SET active=false WHERE account_id=$1 AND sample_id=2"),
    ];
    let mut wrongly_accepted = Vec::new();
    for (label, sql) in mutations {
        let mut tx = repo.pool().begin().await.unwrap();
        assert!(voice_identity::lock_account(&mut tx, account)
            .await
            .unwrap());
        sqlx::query(sqlx::AssertSqlSafe(sql))
            .bind(account)
            .execute(&mut *tx)
            .await
            .unwrap();
        identity_fusion::reconcile_profiles(&mut tx, account, &[1], true)
            .await
            .unwrap();
        if sqlx::query_scalar::<_, String>(
            "SELECT status FROM profile_name_bindings WHERE account_id=$1 AND profile_id=1",
        )
        .bind(account)
        .fetch_one(&mut *tx)
        .await
        .unwrap()
            == "accepted"
        {
            wrongly_accepted.push(label);
        }
        tx.rollback().await.unwrap();
    }
    assert!(
        wrongly_accepted.is_empty(),
        "screen naming must reject invalid exact-frame/source/turn authority: {wrongly_accepted:?}"
    );
    fixture.persistence.pool().close().await;
    sqlx::query(sqlx::AssertSqlSafe(format!(
        "DROP SCHEMA {} CASCADE",
        fixture.schema
    )))
    .execute(fixture.base.pool())
    .await
    .unwrap();
    fixture.base.pool().close().await;
}

#[tokio::test]
async fn attendee_corroboration_requires_two_current_retained_memories() {
    let Some(fixture) = super::tests::test_persistence().await else {
        return;
    };
    let repo = &fixture.persistence;
    let account = "fusion-context-authority";
    repo.set_voice_identity_cohort(VoiceCohort::All, &[])
        .await
        .unwrap();
    for id in 1..=2 {
        seed(repo, account, id, 1, "macos:remote_received").await;
        sqlx::query("UPDATE speaker_observations SET started_at='2026-01-01T00:00:00Z'::timestamptz+make_interval(secs=>id::double precision*10),ended_at='2026-01-01T00:00:00Z'::timestamptz+make_interval(secs=>id::double precision*10+4) WHERE account_id=$1 AND id=$2").bind(account).bind(id).execute(repo.pool()).await.unwrap();
        sqlx::query("UPDATE capture_events SET stream_kind='system_audio',audio_role='remote_received' WHERE account_id=$1 AND event_id=$2").bind(account).bind(format!("event-{id}")).execute(repo.pool()).await.unwrap();
    }
    screen_input(repo, account, 101, 1, true).await;
    screen_input(repo, account, 201, 1, false).await;
    screen_input(repo, account, 202, 2, false).await;
    reduce(repo, account, &[1]).await;
    assert_eq!(
        sqlx::query_scalar::<_, String>(
            "SELECT status FROM profile_name_bindings WHERE account_id=$1 AND profile_id=1"
        )
        .bind(account)
        .fetch_one(repo.pool())
        .await
        .unwrap(),
        "accepted",
        "two current attendee contexts may corroborate one probationary screen name"
    );
    let mutations=[
        ("stale context voice assignment", "UPDATE voice_sample_profile_assignments SET active=false WHERE account_id=$1 AND sample_id=2"),
        ("expired context frame", "UPDATE media_objects SET retain_until=clock_timestamp()-interval '1 second' WHERE account_id=$1 AND event_id='event-202'"),
        ("expired context audio", "UPDATE media_objects SET retain_until=clock_timestamp()-interval '1 second' WHERE account_id=$1 AND event_id='event-2'"),
        ("deleted context memory", "INSERT INTO episode_deletions(account_id,episode_id,state,purge,media_object_keys,utterance_ids,screenshot_ids,segment_ids,orphan_event_ids) VALUES($1,2,'pending','{}','[]','[]','[]','[]','[]')"),
        ("inactive context memory", "DELETE FROM episode_members WHERE account_id=$1 AND episode_id=2"),
    ];
    let mut wrongly_accepted = Vec::new();
    for (label, sql) in mutations {
        let mut tx = repo.pool().begin().await.unwrap();
        assert!(voice_identity::lock_account(&mut tx, account)
            .await
            .unwrap());
        sqlx::query(sqlx::AssertSqlSafe(sql))
            .bind(account)
            .execute(&mut *tx)
            .await
            .unwrap();
        identity_fusion::reconcile_profiles(&mut tx, account, &[1], true)
            .await
            .unwrap();
        if sqlx::query_scalar::<_, String>(
            "SELECT status FROM profile_name_bindings WHERE account_id=$1 AND profile_id=1",
        )
        .bind(account)
        .fetch_one(&mut *tx)
        .await
        .unwrap()
            == "accepted"
        {
            wrongly_accepted.push(label);
        }
        tx.rollback().await.unwrap();
    }
    assert!(
        wrongly_accepted.is_empty(),
        "attendee corroboration must reject stale or deleted context support: {wrongly_accepted:?}"
    );
    fixture.persistence.pool().close().await;
    sqlx::query(sqlx::AssertSqlSafe(format!(
        "DROP SCHEMA {} CASCADE",
        fixture.schema
    )))
    .execute(fixture.base.pool())
    .await
    .unwrap();
    fixture.base.pool().close().await;
}

#[tokio::test]
async fn public_facts_revalidate_attribution_ahead_of_bounded_enrichment() {
    let Some(fixture) = super::tests::test_persistence().await else {
        return;
    };
    let repo = &fixture.persistence;
    let account = "fusion-public-fact-authority";
    repo.set_voice_identity_cohort(VoiceCohort::All, &[])
        .await
        .unwrap();
    seed(repo, account, 1, 1, "macos:builtin_mic").await;
    seed(repo, account, 2, 2, "ios:builtin_mic").await;
    intro(repo, account, 1, "Sam Lee", false).await;
    intro(repo, account, 2, "Alex Jones", false).await;
    reduce(repo, account, &[1, 2]).await;
    let person: i64 = sqlx::query_scalar(
        "SELECT person_id FROM profile_name_bindings WHERE account_id=$1 AND profile_id=1",
    )
    .bind(account)
    .fetch_one(repo.pool())
    .await
    .unwrap();
    // A previously attributed batch is larger than the worker's 128-row page.
    // Current source voice is Alex; all cached fact person pointers still say Sam.
    sqlx::query("INSERT INTO person_facts(account_id,id,person_id,predicate,value,evidence,derivation_version,status,source_event_id,speaker_observation_id,observed_at,literal_evidence,confidence) SELECT $1,n,$2,'organization','Example','{}',2,'active','event-2',2,clock_timestamp(),'I work at Example',0.63 FROM generate_series(1000,1999) n").bind(account).bind(person).execute(repo.pool()).await.unwrap();
    sqlx::query("INSERT INTO person_fact_candidates(account_id,id,source_event_id,speaker_observation_id,ordinal,predicate,value,value_key,literal_evidence,confidence,observed_at,extraction_version,derived_fact_id) SELECT $1,n,'event-2',2,n,'organization','Example','example','I work at Example',0.63,clock_timestamp(),2,n FROM generate_series(1000,1999) n").bind(account).execute(repo.pool()).await.unwrap();
    let page = repo
        .list_people(
            account,
            &PeopleListRequest {
                kind: PublicPersonStatus::Identified,
                after_id: 0,
                limit: 100,
                query: None,
            },
        )
        .await
        .unwrap();
    assert_eq!(
        page.people
            .iter()
            .find(|p| p.id == person)
            .unwrap()
            .fact_count,
        0,
        "People counts must not expose stale attribution beyond the enrichment page"
    );
    let detail = repo.person_profile(account, person).await.unwrap();
    assert!(
        detail.facts.is_empty(),
        "People detail must revalidate each fact against current source attribution"
    );
    fixture.persistence.pool().close().await;
    sqlx::query(sqlx::AssertSqlSafe(format!(
        "DROP SCHEMA {} CASCADE",
        fixture.schema
    )))
    .execute(fixture.base.pool())
    .await
    .unwrap();
    fixture.base.pool().close().await;
}

#[tokio::test]
async fn acoustic_same_name_collision_holds_both_bindings_without_merging_people() {
    let Some(fixture) = super::tests::test_persistence().await else {
        return;
    };
    let repo = &fixture.persistence;
    let account = "fusion-acoustic-name-collision";
    repo.set_voice_identity_cohort(VoiceCohort::All, &[])
        .await
        .unwrap();
    for id in 1..=6 {
        seed(
            repo,
            account,
            id,
            if id <= 3 { 1 } else { 2 },
            "macos:builtin_mic",
        )
        .await;
    }
    intro(repo, account, 1, "Sam Lee", false).await;
    intro(repo, account, 4, "Sam Lee", false).await;
    reduce(repo, account, &[1, 2]).await;
    let people: Vec<i64> =
        sqlx::query_scalar("SELECT person_id FROM voice_profiles WHERE account_id=$1 ORDER BY id")
            .bind(account)
            .fetch_all(repo.pool())
            .await
            .unwrap();
    let before: Vec<(i64, Vec<u8>, i64)> = sqlx::query_as(
        "SELECT id,centroid,sample_count FROM voice_profiles WHERE account_id=$1 ORDER BY id",
    )
    .bind(account)
    .fetch_all(repo.pool())
    .await
    .unwrap();
    let mut tx = repo.pool().begin().await.unwrap();
    assert!(voice_identity::lock_account(&mut tx, account)
        .await
        .unwrap());
    super::voice_profile_reconciliation::reconcile(&mut tx, account)
        .await
        .unwrap();
    tx.commit().await.unwrap();
    let states: Vec<String> = sqlx::query_scalar(
        "SELECT status FROM profile_name_bindings WHERE account_id=$1 ORDER BY profile_id",
    )
    .bind(account)
    .fetch_all(repo.pool())
    .await
    .unwrap();
    assert_eq!(
        states,
        vec!["quarantined", "quarantined"],
        "a same-name acoustic merge candidate must quarantine both name bindings"
    );
    assert_ne!(
        people[0], people[1],
        "same-name collision must retain distinct opaque person nodes"
    );
    assert_eq!(
        sqlx::query_as::<_, (i64, Vec<u8>, i64)>(
            "SELECT id,centroid,sample_count FROM voice_profiles WHERE account_id=$1 ORDER BY id"
        )
        .bind(account)
        .fetch_all(repo.pool())
        .await
        .unwrap(),
        before,
        "name collision must preserve acoustic profiles and complete sample support"
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT count(*) FROM voice_profile_proposals WHERE account_id=$1 AND state='applied'"
        )
        .bind(account)
        .fetch_one(repo.pool())
        .await
        .unwrap(),
        0,
        "binding quarantine must block automatic merge after people become anonymous"
    );
    let claims: i64 =
        sqlx::query_scalar("SELECT count(*) FROM profile_name_claims WHERE account_id=$1")
            .bind(account)
            .fetch_one(repo.pool())
            .await
            .unwrap();
    reduce(repo, account, &[2, 1]).await;
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT count(*) FROM profile_name_claims WHERE account_id=$1"
        )
        .bind(account)
        .fetch_one(repo.pool())
        .await
        .unwrap(),
        claims,
        "unchanged same-name collision must not toggle or append duplicate decisions"
    );
    // Only the peer's sources change: erase the old introduction and retain a
    // newly introduced observation through the real erasure/recompute helpers.
    seed(repo, account, 7, 2, "macos:builtin_mic").await;
    intro(repo, account, 7, "Alex Jones", false).await;
    let mut tx = repo.pool().begin().await.unwrap();
    assert!(voice_identity::lock_account(&mut tx, account)
        .await
        .unwrap());
    let affected = voice_identity::erase_event_samples(&mut tx, account, &["event-4".into()])
        .await
        .unwrap();
    sqlx::query("DELETE FROM capture_events WHERE account_id=$1 AND event_id='event-4'")
        .bind(account)
        .execute(&mut *tx)
        .await
        .unwrap();
    voice_identity::recompute_erased_profiles(&mut tx, account, &affected)
        .await
        .unwrap();
    tx.commit().await.unwrap();
    let peer_person:Option<i64>=sqlx::query_scalar("SELECT person_id FROM episode_participants WHERE account_id=$1 AND episode_id=1 AND state='active' AND participant_key<>'owner' ORDER BY id LIMIT 1").bind(account).fetch_one(repo.pool()).await.unwrap();
    assert_eq!(peer_person,Some(people[0]),"peer source erasure must refresh the untouched voice's cached participant in the same transaction");
    reduce(repo, account, &[2]).await;
    let restored: Vec<String> = sqlx::query_scalar(
        "SELECT status FROM profile_name_bindings WHERE account_id=$1 ORDER BY profile_id",
    )
    .bind(account)
    .fetch_all(repo.pool())
    .await
    .unwrap();
    assert_eq!(
        restored,
        vec!["accepted", "accepted"],
        "a peer-only name change must release both same-name holds from current evidence"
    );
    assert_eq!(
        sqlx::query_scalar::<_, Vec<i64>>(
            "SELECT array_agg(person_id ORDER BY id) FROM voice_profiles WHERE account_id=$1"
        )
        .bind(account)
        .fetch_one(repo.pool())
        .await
        .unwrap(),
        people,
        "name hold and recovery must preserve both original person identities"
    );
    fixture.persistence.pool().close().await;
    sqlx::query(sqlx::AssertSqlSafe(format!(
        "DROP SCHEMA {} CASCADE",
        fixture.schema
    )))
    .execute(fixture.base.pool())
    .await
    .unwrap();
    fixture.base.pool().close().await;
}

#[tokio::test]
async fn paused_pending_names_cannot_starve_withdrawal_of_an_existing_binding() {
    let Some(fixture) = super::tests::test_persistence().await else {
        return;
    };
    let repo = &fixture.persistence;
    let account = "fusion-paused-fairness";
    repo.set_voice_identity_cohort(VoiceCohort::All, &[])
        .await
        .unwrap();
    for id in 1..=17 {
        seed(repo, account, id, id, "macos:builtin_mic").await;
    }
    intro(repo, account, 17, "Existing Person", false).await;
    reduce(repo, account, &[17]).await;
    for id in 1..=16 {
        intro(repo, account, id, &format!("Pending Name{id}"), false).await;
    }
    sqlx::query("UPDATE voice_profiles SET updated_at=clock_timestamp()-interval '1 day' WHERE account_id=$1 AND id<=16").bind(account).execute(repo.pool()).await.unwrap();
    sqlx::query("UPDATE media_objects SET retain_until=clock_timestamp()-interval '1 second' WHERE account_id=$1 AND event_id='event-17'").bind(account).execute(repo.pool()).await.unwrap();
    for _ in 0..3 {
        let mut tx = repo.pool().begin().await.unwrap();
        assert!(voice_identity::lock_account(&mut tx, account)
            .await
            .unwrap());
        identity_fusion::maintain(&mut tx, account, false)
            .await
            .unwrap();
        tx.commit().await.unwrap();
    }
    assert_ne!(
        sqlx::query_scalar::<_, String>(
            "SELECT status FROM profile_name_bindings WHERE account_id=$1 AND profile_id=17"
        )
        .bind(account)
        .fetch_one(repo.pool())
        .await
        .unwrap(),
        "accepted",
        "paused valid pending names must rotate so an expired existing binding can be withdrawn"
    );
    assert_eq!(sqlx::query_scalar::<_,i64>("SELECT count(*) FROM profile_name_bindings WHERE account_id=$1 AND profile_id<=16 AND status='accepted'").bind(account).fetch_one(repo.pool()).await.unwrap(),0,"paused rotation must not admit the pending names");
    fixture.persistence.pool().close().await;
    sqlx::query(sqlx::AssertSqlSafe(format!(
        "DROP SCHEMA {} CASCADE",
        fixture.schema
    )))
    .execute(fixture.base.pool())
    .await
    .unwrap();
    fixture.base.pool().close().await;
}

#[tokio::test]
async fn erasing_an_acoustic_competitor_withdraws_untouched_peer_projections_atomically() {
    let Some(fixture) = super::tests::test_persistence().await else {
        return;
    };
    let repo = &fixture.persistence;
    let account = "fusion-peer-erasure-projection";
    repo.set_voice_identity_cohort(VoiceCohort::All, &[])
        .await
        .unwrap();
    for id in 1..=9 {
        seed(repo, account, id, (id - 1) / 3 + 1, "macos:builtin_mic").await;
    }
    // Each voice has sufficient acoustic support but only one memory, so
    // recurrence cannot incidentally repair a dropped peer projection target.
    sqlx::query("UPDATE episode_members SET episode_id=((episode_id-1)/3)*3+1 WHERE account_id=$1 AND record_type='utterance'")
        .bind(account).execute(repo.pool()).await.unwrap();
    intro(repo, account, 1, "Sam Lee", false).await;
    intro(repo, account, 4, "Sam Lee", false).await;
    reduce(repo, account, &[1, 2, 3]).await;
    assert_eq!(sqlx::query_scalar::<_,i64>("SELECT count(*) FROM episode_participants WHERE account_id=$1 AND episode_id IN (1,4) AND state='active' AND person_id IS NOT NULL").bind(account).fetch_one(repo.pool()).await.unwrap(),2,"a complete tied competitor population must preserve the two independent names");
    let mut tx = repo.pool().begin().await.unwrap();
    assert!(voice_identity::lock_account(&mut tx, account)
        .await
        .unwrap());
    let events = vec!["event-7".into(), "event-8".into(), "event-9".into()];
    let affected = voice_identity::erase_event_samples(&mut tx, account, &events)
        .await
        .unwrap();
    sqlx::query("DELETE FROM capture_events WHERE account_id=$1 AND event_id=ANY($2::text[])")
        .bind(account)
        .bind(&events)
        .execute(&mut *tx)
        .await
        .unwrap();
    voice_identity::recompute_erased_profiles(&mut tx, account, &affected)
        .await
        .unwrap();
    tx.commit().await.unwrap();
    assert_eq!(sqlx::query_scalar::<_,i64>("SELECT count(*) FROM profile_name_bindings WHERE account_id=$1 AND profile_id IN (1,2) AND status='quarantined'").bind(account).fetch_one(repo.pool()).await.unwrap(),2,"removing the competitor must expose the same-name acoustic collision");
    assert_eq!(sqlx::query_scalar::<_,i64>("SELECT count(*) FROM episode_participants WHERE account_id=$1 AND episode_id IN (1,4) AND state='active' AND person_id IS NOT NULL").bind(account).fetch_one(repo.pool()).await.unwrap(),0,"erasure must withdraw untouched peers' cached participants in the same transaction");
    fixture.persistence.pool().close().await;
    sqlx::query(sqlx::AssertSqlSafe(format!(
        "DROP SCHEMA {} CASCADE",
        fixture.schema
    )))
    .execute(fixture.base.pool())
    .await
    .unwrap();
    fixture.base.pool().close().await;
}

#[tokio::test]
async fn screen_first_and_audio_first_converge_without_reextracting_evidence() {
    let Some(fixture) = super::tests::test_persistence().await else {
        return;
    };
    let repo = &fixture.persistence;
    repo.set_voice_identity_cohort(VoiceCohort::All, &[])
        .await
        .unwrap();
    let mut decisions = Vec::new();
    for screen_first in [true, false] {
        let account = if screen_first {
            "fusion-screen-first"
        } else {
            "fusion-audio-first"
        };
        for screen_step in [screen_first, !screen_first] {
            if screen_step {
                for (frame, target) in [(101, 1), (102, 1), (103, 2)] {
                    screen_input(repo, account, frame, target, true).await;
                }
            } else {
                for id in 1..=2 {
                    seed(repo, account, id, 1, "macos:remote_received").await;
                    sqlx::query("UPDATE speaker_observations SET started_at='2026-01-01T00:00:00Z'::timestamptz+make_interval(secs=>id::double precision*10),ended_at='2026-01-01T00:00:00Z'::timestamptz+make_interval(secs=>id::double precision*10+4) WHERE account_id=$1 AND id=$2")
                        .bind(account).bind(id).execute(repo.pool()).await.unwrap();
                    sqlx::query("UPDATE capture_events SET stream_kind='system_audio',audio_role='remote_received' WHERE account_id=$1 AND event_id=$2")
                        .bind(account).bind(format!("event-{id}")).execute(repo.pool()).await.unwrap();
                }
            }
            let mut tx = repo.pool().begin().await.unwrap();
            assert!(voice_identity::lock_account(&mut tx, account)
                .await
                .unwrap());
            identity_fusion::maintain(&mut tx, account, true)
                .await
                .unwrap();
            tx.commit().await.unwrap();
        }
        reduce(repo, account, &[1]).await;
        let row=sqlx::query("SELECT b.status,p.display_name FROM profile_name_bindings b JOIN people p ON p.account_id=b.account_id AND p.id=b.person_id WHERE b.account_id=$1 AND b.profile_id=1")
            .bind(account).fetch_optional(repo.pool()).await.unwrap();
        assert!(
            row.is_some(),
            "both audio/screen arrival orders must produce a source-backed name binding"
        );
        let row = row.unwrap();
        decisions.push((
            row.get::<String, _>("status"),
            row.get::<Option<String>, _>("display_name"),
        ));
        let before:i64=sqlx::query_scalar("SELECT count(*) FROM person_name_claims WHERE account_id=$1 AND evidence_kind='name_fusion'")
            .bind(account).fetch_one(repo.pool()).await.unwrap();
        reduce(repo, account, &[1]).await;
        assert_eq!(sqlx::query_scalar::<_,i64>("SELECT count(*) FROM person_name_claims WHERE account_id=$1 AND evidence_kind='name_fusion'").bind(account).fetch_one(repo.pool()).await.unwrap(),before,
            "unchanged arrival-order replay must not append a second name decision");
    }
    assert_eq!(
        decisions,
        vec![("accepted".into(), Some("Sam Lee".into())); 2],
        "screen-first and audio-first extraction must converge to the same accepted full name"
    );
    fixture.persistence.pool().close().await;
    sqlx::query(sqlx::AssertSqlSafe(format!(
        "DROP SCHEMA {} CASCADE",
        fixture.schema
    )))
    .execute(fixture.base.pool())
    .await
    .unwrap();
    fixture.base.pool().close().await;
}

#[tokio::test]
async fn deleting_only_name_sources_withdraws_their_remote_target_in_the_same_transaction() {
    let Some(fixture) = super::tests::test_persistence().await else {
        return;
    };
    let repo = &fixture.persistence;
    repo.install_memory_reconciliation_activation_schema()
        .await
        .unwrap();
    repo.set_voice_identity_cohort(VoiceCohort::All, &[])
        .await
        .unwrap();
    for screen in [true, false] {
        let account = if screen {
            "fusion-delete-frame"
        } else {
            "fusion-delete-vocative"
        };
        seed(repo, account, 1, 1, "macos:remote_received").await;
        seed(repo, account, 2, 1, "macos:remote_received").await;
        for id in 1..=2 {
            sqlx::query("UPDATE speaker_observations SET started_at='2026-01-01T00:00:00Z'::timestamptz+make_interval(secs=>id::double precision*10),ended_at='2026-01-01T00:00:00Z'::timestamptz+make_interval(secs=>id::double precision*10+4) WHERE account_id=$1 AND id=$2").bind(account).bind(id).execute(repo.pool()).await.unwrap();
            sqlx::query("UPDATE capture_events SET stream_kind='system_audio',audio_role='remote_received' WHERE account_id=$1 AND event_id=$2").bind(account).bind(format!("event-{id}")).execute(repo.pool()).await.unwrap();
        }
        let removed = if screen {
            screen_input(repo, account, 101, 1, true).await;
            screen_input(repo, account, 102, 1, true).await;
            screen_input(repo, account, 103, 2, true).await;
            // The erased frame is independent of either target's audio memory.
            sqlx::query("INSERT INTO episodes(account_id,id,started_at,ended_at) VALUES($1,103,'2026-01-01T00:00:20Z','2026-01-01T00:00:24Z')").bind(account).execute(repo.pool()).await.unwrap();
            sqlx::query("UPDATE episode_members SET episode_id=103 WHERE account_id=$1 AND record_type='screenshot' AND record_id=103").bind(account).execute(repo.pool()).await.unwrap();
            "event-103"
        } else {
            for (id, profile) in [(11, 2), (12, 2), (13, 3)] {
                seed(repo, account, id, profile, "ios:builtin_mic").await;
                vocative_input(repo, account, id, 1).await;
            }
            "event-13"
        };
        reduce(repo, account, &[1]).await;
        assert_eq!(sqlx::query_scalar::<_,i64>("SELECT count(*) FROM episode_participants WHERE account_id=$1 AND episode_id IN (1,2) AND state='active' AND person_id IS NOT NULL").bind(account).fetch_one(repo.pool()).await.unwrap(),2,"independent name sources must initially name both target memories");
        let before: (i64, Vec<u8>) = sqlx::query_as(
            "SELECT sample_count,centroid FROM voice_profiles WHERE account_id=$1 AND id=1",
        )
        .bind(account)
        .fetch_one(repo.pool())
        .await
        .unwrap();
        let mut tx = repo.pool().begin().await.unwrap();
        assert!(voice_identity::lock_account(&mut tx, account)
            .await
            .unwrap());
        if screen {
            sqlx::query("INSERT INTO episode_deletions(account_id,episode_id,state,purge,media_object_keys,utterance_ids,screenshot_ids,segment_ids,orphan_event_ids) VALUES($1,103,'pending','{}','[]','[]','[103]','[]','[]')").bind(account).execute(&mut *tx).await.unwrap();
            sqlx::query("INSERT INTO persistence_feature_episode_deletion_progress(account_id,episode_id,phase,coordinate_sha256) VALUES($1,103,'purge_members',decode(repeat('0',64),'hex'))").bind(account).execute(&mut *tx).await.unwrap();
            sqlx::query("INSERT INTO persistence_feature_episode_deletion_members(account_id,episode_id,record_type,record_id,coordinate_sha256) VALUES($1,103,'screenshot',103,decode(repeat('0',64),'hex'))").bind(account).execute(&mut *tx).await.unwrap();
            super::episode_deletion::test_purge_paged_identity_members(&mut tx, account, 103)
                .await
                .unwrap();
        } else {
            let affected = voice_identity::erase_event_samples(&mut tx, account, &[removed.into()])
                .await
                .unwrap();
            sqlx::query("INSERT INTO episode_deletions(account_id,episode_id,state,purge,media_object_keys,utterance_ids,screenshot_ids,segment_ids,orphan_event_ids) VALUES($1,13,'pending','{}','[]','[]','[]','[]',jsonb_build_array($2::text))")
                .bind(account).bind(removed).execute(&mut *tx).await.unwrap();
            sqlx::query("INSERT INTO capture_formation_deleted_sequences(account_id,capture_session_id,stream_id,sequence,event_id,original_manifest_digest,deletion_episode_id,provenance) SELECT account_id,capture_session_id,stream_id,sequence,event_id,manifest_digest,13,'episode_deletion_v1' FROM capture_events WHERE account_id=$1 AND event_id=$2")
                .bind(account).bind(removed).execute(&mut *tx).await.unwrap();
            sqlx::query("DELETE FROM capture_events WHERE account_id=$1 AND event_id=$2")
                .bind(account)
                .bind(removed)
                .execute(&mut *tx)
                .await
                .unwrap();
            voice_identity::recompute_erased_profiles(&mut tx, account, &affected)
                .await
                .unwrap();
        }
        tx.commit().await.unwrap();
        assert_ne!(sqlx::query_scalar::<_,String>("SELECT status FROM profile_name_bindings WHERE account_id=$1 AND profile_id=1").bind(account).fetch_one(repo.pool()).await.unwrap(),"accepted",
            "deleting only a frame or addressing source must withdraw its remote target name immediately");
        assert_eq!(sqlx::query_scalar::<_,i64>("SELECT count(*) FROM episode_participants WHERE account_id=$1 AND episode_id IN (1,2) AND state='active' AND person_id IS NOT NULL").bind(account).fetch_one(repo.pool()).await.unwrap(),0,
            "name-source erasure must refresh target memories before returning");
        assert_eq!(
            sqlx::query_as::<_, (i64, Vec<u8>)>(
                "SELECT sample_count,centroid FROM voice_profiles WHERE account_id=$1 AND id=1"
            )
            .bind(account)
            .fetch_one(repo.pool())
            .await
            .unwrap(),
            before,
            "erasing a name source must preserve unrelated target acoustic evidence"
        );
    }
    fixture.persistence.pool().close().await;
    sqlx::query(sqlx::AssertSqlSafe(format!(
        "DROP SCHEMA {} CASCADE",
        fixture.schema
    )))
    .execute(fixture.base.pool())
    .await
    .unwrap();
    fixture.base.pool().close().await;
}

#[tokio::test]
async fn large_fact_history_applies_replacement_and_restores_after_successor_erasure() {
    let Some(fixture) = super::tests::test_persistence().await else {
        return;
    };
    let repo = &fixture.persistence;
    let account = "fusion-large-fact-history";
    repo.set_voice_identity_cohort(VoiceCohort::All, &[])
        .await
        .unwrap();
    seed(repo, account, 1, 1, "macos:builtin_mic").await;
    seed(repo, account, 2, 1, "macos:builtin_mic").await;
    intro(repo, account, 1, "Sam Lee", false).await;
    reduce(repo, account, &[1]).await;
    let person: i64 = sqlx::query_scalar(
        "SELECT person_id FROM profile_name_bindings WHERE account_id=$1 AND profile_id=1",
    )
    .bind(account)
    .fetch_one(repo.pool())
    .await
    .unwrap();
    sqlx::query("INSERT INTO person_facts(account_id,id,person_id,predicate,value,evidence,derivation_version,status,source_event_id,speaker_observation_id,observed_at,literal_evidence,confidence) SELECT $1,n,$2,'organization','Example','{}',2,'active','event-1',1,'2026-01-01T00:00:00Z','I work at Example',0.63 FROM generate_series(10000,14999) n").bind(account).bind(person).execute(repo.pool()).await.unwrap();
    sqlx::query("INSERT INTO person_fact_candidates(account_id,id,source_event_id,speaker_observation_id,ordinal,predicate,value,value_key,literal_evidence,confidence,observed_at,extraction_version,derived_fact_id) SELECT $1,n,'event-1',1,n,'organization','Example','example','I work at Example',0.63,'2026-01-01T00:00:00Z',2,n FROM generate_series(10000,14999) n").bind(account).execute(repo.pool()).await.unwrap();
    intro(repo, account, 2, "Sam Lee", true).await;
    sqlx::query("UPDATE person_fact_candidates SET value='Next',value_key='next',replacement_of='Example',replacement_key='example',literal_evidence='I left Example and now work at Next',observed_at='2026-01-02T00:00:00Z',evaluated_at='2000-01-01T00:00:00Z' WHERE account_id=$1 AND speaker_observation_id=2").bind(account).execute(repo.pool()).await.unwrap();
    reduce(repo, account, &[1]).await;
    assert_eq!(sqlx::query_scalar::<_,i64>("SELECT count(*) FROM person_facts WHERE account_id=$1 AND value='Example' AND status='active'").bind(account).fetch_one(repo.pool()).await.unwrap(),0,
        "an explicit replacement must retire all prior support even beyond 4096 facts");
    assert_eq!(sqlx::query_scalar::<_,i64>("SELECT count(*) FROM person_facts WHERE account_id=$1 AND value='Next' AND status='active' AND supersedes_id IS NOT NULL").bind(account).fetch_one(repo.pool()).await.unwrap(),1,
        "a large fact history must preserve the replacement's predecessor");
    // More unrelated queued work than both erasure-time enrichment pages.
    // Explicit affected-person reachability must bypass candidate scheduling.
    seed(repo, account, 3, 2, "ios:builtin_mic").await;
    sqlx::query("INSERT INTO person_fact_candidates(account_id,id,source_event_id,speaker_observation_id,ordinal,predicate,value,value_key,literal_evidence,confidence,observed_at,extraction_version,evaluated_at) SELECT $1,n,'event-3',3,n,'organization','Unrelated','unrelated','I work at Unrelated',0.63,'2026-01-01T00:00:00Z',2,'1900-01-01T00:00:00Z' FROM generate_series(20000,20511) n").bind(account).execute(repo.pool()).await.unwrap();
    let mut tx = repo.pool().begin().await.unwrap();
    assert!(voice_identity::lock_account(&mut tx, account)
        .await
        .unwrap());
    let affected = voice_identity::erase_event_samples(&mut tx, account, &["event-2".into()])
        .await
        .unwrap();
    sqlx::query("DELETE FROM capture_events WHERE account_id=$1 AND event_id='event-2'")
        .bind(account)
        .execute(&mut *tx)
        .await
        .unwrap();
    voice_identity::recompute_erased_profiles(&mut tx, account, &affected)
        .await
        .unwrap();
    tx.commit().await.unwrap();
    assert_eq!(sqlx::query_scalar::<_,i64>("SELECT count(*) FROM person_facts WHERE account_id=$1 AND value='Example' AND status='active'").bind(account).fetch_one(repo.pool()).await.unwrap(),5000,
        "successor erasure must restore every surviving fact beyond 4096 while new naming is paused");
    fixture.persistence.pool().close().await;
    sqlx::query(sqlx::AssertSqlSafe(format!(
        "DROP SCHEMA {} CASCADE",
        fixture.schema
    )))
    .execute(fixture.base.pool())
    .await
    .unwrap();
    fixture.base.pool().close().await;
}
