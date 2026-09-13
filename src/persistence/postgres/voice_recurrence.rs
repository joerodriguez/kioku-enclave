//! Versioned recurring-person promotion from current retained voice attribution.
use super::voice_identity;
use crate::{
    cp::voice_memory::EMBEDDING_SPACE,
    cp::voice_quality::{QUALITY_VERSION, SCORER_VERSION},
    error::Result,
};
use sqlx::{PgConnection, Postgres, Row, Transaction};

pub(super) const POLICY_VERSION: i64 = 1;
const MIN_MEMORIES: i64 = 3;
const MIN_SPEECH_MS: i64 = 1_200_000;

#[derive(Clone, Debug)]
pub(super) struct Support {
    pub profile: i64,
    pub memory_count: i64,
    pub memories: Vec<i64>,
    pub speech_ms: i64,
    pub first_heard: i64,
    pub last_heard: i64,
}

/// Aggregate repeated windows and duplicate memory memberships by source timeline.
/// Matching samples may contribute speech, but only a stable enrollment profile
/// can make a person public. No transcript text is inspected or returned here.
pub(super) async fn support(
    tx: &mut PgConnection,
    account: &str,
    profiles: &[i64],
) -> Result<Vec<Support>> {
    let fence = voice_identity::source_fence(tx).await?;
    let retained = voice_identity::RETAINED.replace("clock_timestamp()", "transaction_timestamp()");
    let sql = format!("WITH qualified AS (
      SELECT DISTINCT p.id profile,o.id observation,e.capture_session_id timeline,o.started_at,o.ended_at,m.episode_id
      FROM voice_profiles p
      JOIN voice_profile_revisions revision ON revision.account_id=p.account_id AND revision.profile_id=p.id AND revision.active AND revision.status='stable' AND revision.derivation_version=$6
      JOIN voice_sample_profile_assignments assignment ON assignment.account_id=p.account_id AND assignment.profile_id=p.id AND assignment.active
      JOIN voice_samples s ON s.account_id=assignment.account_id AND s.id=assignment.sample_id AND s.voice_profile_id=p.id AND s.accepted AND s.eligibility IN ('enroll','match_only')
      JOIN speaker_observations o ON o.account_id=s.account_id AND o.id=s.speaker_observation_id AND o.voice_profile_id=p.id AND o.voice_sample_id=s.id
      JOIN capture_events e ON e.account_id=o.account_id AND e.event_id=o.event_id
      JOIN utterances u ON u.account_id=o.account_id AND u.speaker_observation_id=o.id
      JOIN active_episode_members m ON m.account_id=u.account_id AND m.record_type='utterance' AND m.record_id=u.id
      JOIN memory_handles h ON h.account_id=m.account_id AND h.episode_id=m.episode_id AND h.state='active'
      WHERE p.account_id=$1 AND p.id=ANY($2::bigint[]) AND p.status='stable' AND p.embedding_space=$3 AND p.scorer_version=$4
        AND s.embedding_space=p.embedding_space AND s.scorer_version=p.scorer_version AND s.quality_version=$5 AND s.channel_domain=p.channel_domain
        AND NOT o.overlap AND o.ended_at>o.started_at AND ({retained}) AND NOT ({fence})
        AND NOT EXISTS(SELECT 1 FROM voice_sample_profile_assignments a JOIN voice_samples sample ON sample.account_id=a.account_id AND sample.id=a.sample_id JOIN speaker_observations o ON o.account_id=sample.account_id AND o.id=sample.speaker_observation_id WHERE a.account_id=p.account_id AND a.profile_id=p.id AND a.active AND (NOT ({retained}) OR ({fence})))
        AND NOT EXISTS(SELECT 1 FROM speaker_clusters c WHERE c.account_id=o.account_id AND c.id=o.cluster_id AND c.profile_updates_quarantined)
        AND NOT EXISTS(SELECT 1 FROM voice_enrollment_sessions enrollment WHERE enrollment.account_id=e.account_id AND enrollment.capture_session_id=e.capture_session_id AND enrollment.designated AND enrollment.state<>'enrolled')
      ), per_timeline AS (
        SELECT profile,timeline,range_agg(tstzrange(started_at,ended_at,'[)')) spans FROM qualified GROUP BY profile,timeline
      ), duration AS (
        SELECT profile, floor(sum(extract(epoch FROM upper(span)-lower(span)))*1000)::bigint speech_ms
        FROM per_timeline CROSS JOIN LATERAL unnest(spans) span GROUP BY profile
      ) SELECT q.profile,count(DISTINCT episode_id)::bigint memory_count,array_agg(DISTINCT episode_id) memories,d.speech_ms,floor(extract(epoch FROM min(started_at))*1000)::bigint first_heard,floor(extract(epoch FROM max(ended_at))*1000)::bigint last_heard
        FROM qualified q JOIN duration d ON d.profile=q.profile GROUP BY q.profile,d.speech_ms ORDER BY q.profile");
    let rows = sqlx::query(sqlx::AssertSqlSafe(sql))
        .bind(account)
        .bind(profiles)
        .bind(EMBEDDING_SPACE)
        .bind(SCORER_VERSION)
        .bind(QUALITY_VERSION)
        .bind(crate::cp::voice_identity::IDENTITY_DERIVATION_VERSION)
        .fetch_all(&mut *tx)
        .await?;
    rows.into_iter()
        .map(|r| {
            Ok(Support {
                profile: r.try_get("profile")?,
                memory_count: r.try_get("memory_count")?,
                memories: r.try_get("memories")?,
                speech_ms: r.try_get("speech_ms")?,
                first_heard: r.try_get("first_heard")?,
                last_heard: r.try_get("last_heard")?,
            })
        })
        .collect()
}

/// Called under the ordinary account/reconciliation locks before projecting labels.
/// Returns changed profile IDs so every affected memory can refresh in the same
/// transaction. It never calls the projector itself (no recursive maintenance).
pub(super) async fn refresh(tx: &mut Transaction<'_, Postgres>, account: &str) -> Result<Vec<i64>> {
    // Previously public people must always be reconsidered with all their profiles.
    // A crowded anonymous candidate pool may hold new promotions, never withdrawal.
    let mut rows = sqlx::query("SELECT p.id,p.person_id,person.status person_status FROM voice_profiles p JOIN people person ON person.account_id=p.account_id AND person.id=p.person_id WHERE p.account_id=$1 AND person.status IN ('recurring','unknown') AND (person.status='recurring' OR EXISTS(SELECT 1 FROM identity_evidence evidence WHERE evidence.account_id=person.account_id AND evidence.person_id=person.id AND evidence.kind='voice_recurrence')) ORDER BY p.id")
        .bind(account).fetch_all(&mut **tx).await?;
    let candidates = sqlx::query("SELECT p.id,p.person_id,person.status person_status FROM voice_profiles p LEFT JOIN people person ON person.account_id=p.account_id AND person.id=p.person_id WHERE p.account_id=$1 AND (p.person_id IS NULL OR (person.status='unknown' AND NOT EXISTS(SELECT 1 FROM identity_evidence evidence WHERE evidence.account_id=person.account_id AND evidence.person_id=person.id AND evidence.kind='voice_recurrence'))) ORDER BY p.id LIMIT 513")
        .bind(account).fetch_all(&mut **tx).await?;
    if candidates.len() <= 512 {
        rows.extend(candidates);
    }
    let profiles = rows
        .iter()
        .map(|r| r.get::<i64, _>("id"))
        .collect::<Vec<_>>();
    let supports = support(tx, account, &profiles).await?;
    let bindings = rows
        .iter()
        .map(|r| (r.get::<i64, _>("id"), r.get::<Option<i64>, _>("person_id")))
        .collect::<std::collections::BTreeMap<_, _>>();
    let admitted = voice_identity::controls_admit(tx, account).await?.0;
    let mut changed = Vec::new();
    for row in rows {
        let profile: i64 = row.try_get("id")?;
        let person: Option<i64> = row.try_get("person_id")?;
        let status: Option<String> = row.try_get("person_status")?;
        let valid = supports
            .iter()
            .find(|s| s.profile == profile)
            .filter(|s| s.memory_count >= MIN_MEMORIES || s.speech_ms >= MIN_SPEECH_MS);
        if let Some(support) = valid {
            if !admitted {
                continue;
            }
            let person = if let Some(id) = person {
                id
            } else {
                let id = voice_identity::allocate_voice_id(tx, account, "person").await?;
                sqlx::query("INSERT INTO people(account_id,id,status) VALUES($1,$2,'recurring')")
                    .bind(account)
                    .bind(id)
                    .execute(&mut **tx)
                    .await?;
                sqlx::query("UPDATE voice_profiles SET person_id=$3,updated_at=clock_timestamp() WHERE account_id=$1 AND id=$2").bind(account).bind(profile).bind(id).execute(&mut **tx).await?;
                id
            };
            let evidence = serde_json::json!({"policy_version":POLICY_VERSION,"minimum_memories":MIN_MEMORIES,"minimum_speech_ms":MIN_SPEECH_MS,"memory_count":support.memory_count,"speech_ms":support.speech_ms,"first_heard_at":crate::cp::isotime::format_epoch_millis(support.first_heard),"last_heard_at":crate::cp::isotime::format_epoch_millis(support.last_heard)});
            let same:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM identity_evidence WHERE account_id=$1 AND person_id=$2 AND voice_profile_id=$3 AND kind='voice_recurrence' AND status='accepted' AND evidence=$4::jsonb)").bind(account).bind(person).bind(profile).bind(evidence.to_string()).fetch_one(&mut **tx).await?;
            if !same || status.as_deref() != Some("recurring") {
                sqlx::query("UPDATE people SET status='recurring',updated_at=clock_timestamp() WHERE account_id=$1 AND id=$2 AND status IN ('recurring','unknown')").bind(account).bind(person).execute(&mut **tx).await?;
                sqlx::query("UPDATE identity_evidence SET status='quarantined' WHERE account_id=$1 AND voice_profile_id=$2 AND kind='voice_recurrence' AND status='accepted'").bind(account).bind(profile).execute(&mut **tx).await?;
                let id =
                    voice_identity::allocate_voice_id(tx, account, "identity_evidence").await?;
                sqlx::query("INSERT INTO identity_evidence(account_id,id,person_id,voice_profile_id,kind,evidence,status) VALUES($1,$2,$3,$4,'voice_recurrence',$5::jsonb,'accepted')").bind(account).bind(id).bind(person).bind(profile).bind(evidence.to_string()).execute(&mut **tx).await?;
                voice_identity::append_revision(tx, account, profile, "recurrence_promotion")
                    .await?;
                changed.push(profile);
            }
        } else if status.as_deref() == Some("recurring") {
            // Another independently supported profile may keep this person public.
            let person = person.expect("recurring person is bound");
            let supported_elsewhere = supports.iter().any(|s| {
                s.profile != profile
                    && (s.memory_count >= MIN_MEMORIES || s.speech_ms >= MIN_SPEECH_MS)
                    && bindings.get(&s.profile) == Some(&Some(person))
            });
            if !supported_elsewhere {
                sqlx::query("UPDATE people SET status='unknown',updated_at=clock_timestamp() WHERE account_id=$1 AND id=$2 AND status='recurring'").bind(account).bind(person).execute(&mut **tx).await?;
            }
            sqlx::query("UPDATE identity_evidence SET status='quarantined' WHERE account_id=$1 AND voice_profile_id=$2 AND kind='voice_recurrence' AND status='accepted'").bind(account).bind(profile).execute(&mut **tx).await?;
            changed.push(profile);
        }
    }
    Ok(changed)
}

pub(super) async fn summary(
    tx: &mut PgConnection,
    account: &str,
    person: i64,
) -> Result<(i64, crate::persistence::PersonRecurrence)> {
    use crate::persistence::{
        PersonRecurrence, RecurringVoiceCoParticipant, RecurringVoiceContext,
    };
    let profiles:Vec<i64>=sqlx::query_scalar("SELECT p.id FROM voice_profiles p JOIN people person ON person.account_id=p.account_id AND person.id=p.person_id AND person.status='recurring' WHERE p.account_id=$1 AND p.person_id=$2 AND p.status='stable' ORDER BY p.id").bind(account).bind(person).fetch_all(&mut *tx).await?;
    let supports = support(tx, account, &profiles).await?;
    let Some(first) = supports.iter().map(|s| s.first_heard).min() else {
        return Err(crate::error::EnclaveError::NotFound);
    };
    let last = supports.iter().map(|s| s.last_heard).max().unwrap_or(first);
    let memories = supports
        .iter()
        .flat_map(|s| s.memories.iter().copied())
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    let rows=sqlx::query("SELECT left(btrim(s.active_app),80) label,count(DISTINCT m.episode_id)::bigint memory_count FROM active_episode_members m JOIN screenshots s ON s.account_id=m.account_id AND s.id=m.record_id WHERE m.account_id=$1 AND m.episode_id=ANY($2::bigint[]) AND m.record_type='screenshot' AND nullif(btrim(s.active_app),'') IS NOT NULL GROUP BY left(btrim(s.active_app),80) ORDER BY memory_count DESC,label LIMIT 3").bind(account).bind(&memories).fetch_all(&mut *tx).await?;
    let contexts = rows
        .into_iter()
        .map(|r| {
            Ok(RecurringVoiceContext {
                label: r.try_get("label")?,
                memory_count: r.try_get("memory_count")?,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let rows=sqlx::query("SELECT person.id,person.display_name,count(DISTINCT p.episode_id)::bigint memory_count FROM episode_participants p JOIN people person ON person.account_id=p.account_id AND person.id=p.person_id AND person.status='identified' AND nullif(btrim(person.display_name),'') IS NOT NULL WHERE p.account_id=$1 AND p.episode_id=ANY($2::bigint[]) AND p.person_id<>$3 AND p.state='active' AND p.derivation_version>=2 GROUP BY person.account_id,person.id ORDER BY memory_count DESC,person.id LIMIT 3").bind(account).bind(&memories).bind(person).fetch_all(&mut *tx).await?;
    let co_participants = rows
        .into_iter()
        .map(|r| {
            Ok(RecurringVoiceCoParticipant {
                person_id: r.try_get("id")?,
                display_name: r.try_get("display_name")?,
                memory_count: r.try_get("memory_count")?,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    Ok((
        supports.len() as i64,
        PersonRecurrence {
            memory_count: memories.len() as i64,
            first_heard_at: crate::cp::isotime::format_epoch_millis(first),
            last_heard_at: crate::cp::isotime::format_epoch_millis(last),
            contexts,
            co_participants,
        },
    ))
}

#[cfg(test)]
mod tests {
    use super::super::{
        tests::ControlPlaneContractFixture,
        voice_identity::tests::{seed_voice_memory, seed_voice_observation},
        PostgresPersistence,
    };
    use crate::{
        cp::voice_quality::{self, SampleDecision},
        persistence::{
            MemoryQueryRepository, PeopleListRequest, PlaybackRepository, PublicPersonStatus,
            VoiceCohort, VoiceEmbeddingOutcome, VoiceIdentityRepository,
        },
    };

    async fn fixture() -> Option<ControlPlaneContractFixture> {
        super::super::tests::test_persistence().await
    }
    async fn close(f: ControlPlaneContractFixture) {
        f.persistence.pool().close().await;
        sqlx::query(sqlx::AssertSqlSafe(format!(
            "DROP SCHEMA {} CASCADE",
            f.schema
        )))
        .execute(f.base.pool())
        .await
        .unwrap();
    }
    async fn turn(repo: &PostgresPersistence, account: &str, id: i64, memory: i64) {
        turn_axis(repo, account, id, memory, 0).await;
    }
    async fn turn_axis(
        repo: &PostgresPersistence,
        account: &str,
        id: i64,
        memory: i64,
        axis: usize,
    ) {
        seed_voice_observation(repo, account, "recording", &format!("event-{id}"), id, id).await;
        seed_voice_memory(repo, account, id, memory).await;
        let claim = repo
            .claim_voice_embeddings(account, "synthetic-recurrence")
            .await
            .unwrap()
            .claims
            .remove(0);
        let mut diagnostics = voice_quality::diagnose(&vec![0.1; 64000], false, &[]);
        diagnostics.decision = SampleDecision::Enroll;
        let mut embedding = vec![0.0; 256];
        embedding[axis] = 1.0;
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
    }
    async fn people(
        repo: &PostgresPersistence,
        account: &str,
    ) -> Vec<(i64, String, Option<String>)> {
        sqlx::query_as("SELECT id,status,display_name FROM people WHERE account_id=$1 ORDER BY id")
            .bind(account)
            .fetch_all(repo.pool())
            .await
            .unwrap()
    }
    #[tokio::test]
    async fn recurring_people_api_preserves_slots_and_paginates_independently() {
        let Some(f) = fixture().await else {
            return;
        };
        let repo = &f.persistence;
        let account = "recurring-public";
        repo.set_voice_identity_cohort(VoiceCohort::All, &[])
            .await
            .unwrap();
        for id in 1..=6 {
            turn_axis(repo, account, id, id, if id <= 3 { 0 } else { 1 }).await;
        }
        repo.maintain_voice_profiles(account).await.unwrap();
        let recurring_ids = people(repo, account)
            .await
            .into_iter()
            .map(|p| p.0)
            .collect::<Vec<_>>();
        assert_eq!(
            recurring_ids.len(),
            2,
            "independent stable voices must keep distinct recurring identities"
        );
        sqlx::query("INSERT INTO people(account_id,id,status,display_name) VALUES($1,100,'identified','Alex Chen'),($1,101,'identified','Alex Chen'),($1,200,'owner',NULL),($1,201,'unknown',NULL),($1,202,'quarantined',NULL)").bind(account).execute(repo.pool()).await.unwrap();
        let page = repo
            .list_people(
                account,
                &PeopleListRequest {
                    kind: PublicPersonStatus::Identified,
                    after_id: 0,
                    limit: 1,
                    query: None,
                },
            )
            .await
            .unwrap();
        assert_eq!(
            (page.people[0].id, page.next_cursor),
            (100, Some(100)),
            "identified pagination must return its last visible ID rather than the lookahead"
        );
        assert_eq!(
            page.people[0].recurrence, None,
            "identified people must carry a null recurrence object"
        );
        let first = repo
            .list_people(
                account,
                &PeopleListRequest {
                    kind: PublicPersonStatus::Recurring,
                    after_id: 0,
                    limit: 1,
                    query: None,
                },
            )
            .await
            .unwrap();
        assert_eq!(
            (first.people[0].id, first.next_cursor),
            (recurring_ids[0], Some(recurring_ids[0])),
            "recurring pagination must be independent of larger identified IDs"
        );
        let second = repo
            .list_people(
                account,
                &PeopleListRequest {
                    kind: PublicPersonStatus::Recurring,
                    after_id: recurring_ids[0],
                    limit: 1,
                    query: None,
                },
            )
            .await
            .unwrap();
        assert_eq!(
            (second.people[0].id, second.next_cursor),
            (recurring_ids[1], None),
            "recurring tail pages must neither skip the lookahead nor repeat a row"
        );
        assert!(
            repo.list_people(
                account,
                &PeopleListRequest {
                    kind: PublicPersonStatus::Recurring,
                    after_id: 0,
                    limit: 10,
                    query: Some("Unnamed voice".into())
                }
            )
            .await
            .is_err(),
            "recurring presentation labels must never become name search keys"
        );
        for (id, memory) in [(7, 1), (8, 2)] {
            turn_axis(repo, account, id, memory, 2).await;
            sqlx::query(
                "UPDATE speaker_observations SET person_id=100 WHERE account_id=$1 AND id=$2",
            )
            .bind(account)
            .bind(id)
            .execute(repo.pool())
            .await
            .unwrap();
        }
        sqlx::query("INSERT INTO screenshots(account_id,id,captured_at,active_app) VALUES($1,10,now(),'Zoom'),($1,11,now(),'Zoom'),($1,12,now(),'Notes'),($1,13,now(),'Calls')").bind(account).execute(repo.pool()).await.unwrap();
        sqlx::query("INSERT INTO episode_members(account_id,episode_id,record_type,record_id) VALUES($1,1,'screenshot',10),($1,2,'screenshot',11),($1,1,'screenshot',12),($1,3,'screenshot',13)").bind(account).execute(repo.pool()).await.unwrap();
        let detail = repo
            .person_profile(account, recurring_ids[0])
            .await
            .unwrap();
        assert_eq!(
            (
                detail.person.status,
                detail.person.display_name.as_str(),
                detail.person.recurrence.as_ref().unwrap().memory_count
            ),
            (PublicPersonStatus::Recurring, "Unnamed voice", 3),
            "recurring detail must expose current source support with an honest presentation label"
        );
        assert!(
            detail.voice_labels.is_empty()
                && detail.aliases.is_empty()
                && detail.facts.is_empty()
                && detail.person.fact_count == 0,
            "unnamed detail must not expose internal voice labels or unaccepted names and facts"
        );
        let recurrence = detail.person.recurrence.as_ref().unwrap();
        assert_eq!(
            recurrence
                .contexts
                .iter()
                .map(|c| (c.label.as_str(), c.memory_count))
                .collect::<Vec<_>>(),
            vec![("Zoom", 2), ("Calls", 1), ("Notes", 1)],
            "recurring contexts must count current distinct memories in deterministic order"
        );
        assert_eq!(recurrence.co_participants.iter().map(|p| (p.person_id,p.memory_count)).collect::<Vec<_>>(), vec![(100,2)], "recurring co-participants must expose only identified people in their shared current memories");
        use super::super::speaker_identity::{
            speaker_identity_join, SpeakerMemoryScope, SpeakerUtteranceAlias,
        };
        let identity =
            speaker_identity_join(SpeakerUtteranceAlias::U, SpeakerMemoryScope::Episode("1"));
        let label:(String,Option<i64>,Option<String>)=sqlx::query_as(sqlx::AssertSqlSafe(format!("SELECT speaker_identity.speaker_label,speaker_identity.person_id,speaker_identity.attribution_kind FROM utterances u {identity} WHERE u.account_id=$1 AND u.id=1"))).bind(account).fetch_one(repo.pool()).await.unwrap();
        assert_eq!(
            label,
            (
                "Speaker A".into(),
                Some(recurring_ids[0]),
                Some("verified_voice".into())
            ),
            "a recurring public link must retain its original memory-local Speaker letter"
        );
        assert_eq!(
            detail.recent_statements.len(),
            3,
            "recurring detail must include its attributed statements"
        );
        assert!(
            repo.person_memories(account, recurring_ids[0], None, 50, None)
                .await
                .is_ok(),
            "recurring opaque IDs must open their person memory route"
        );
        for id in [200, 201, 202] {
            assert!(
                matches!(
                    repo.person_profile(account, id).await,
                    Err(crate::error::EnclaveError::NotFound)
                ),
                "owner and private person statuses must remain404 on detail"
            );
            assert!(
                matches!(
                    repo.person_evidence(account, id, None, 50).await,
                    Err(crate::error::EnclaveError::NotFound)
                ),
                "owner and private person statuses must remain404 on evidence"
            );
            assert!(
                matches!(
                    repo.person_statements(account, id, None, 50).await,
                    Err(crate::error::EnclaveError::NotFound)
                ),
                "owner and private person statuses must remain404 on statements"
            );
            assert!(
                matches!(
                    repo.person_memories(account, id, None, 50, None).await,
                    Err(crate::error::EnclaveError::NotFound)
                ),
                "owner and private person statuses must remain404 on memories"
            );
        }
        // Local presentation text filters a slot, not a globally resolved recurring person.
        sqlx::query("UPDATE episode_speaker_slots SET slot_ordinal=25 WHERE account_id=$1 AND episode_id=2 AND slot_ordinal=0")
            .bind(account).execute(repo.pool()).await.unwrap();
        let vector = serde_json::to_string(&vec![1.0; 384]).unwrap();
        sqlx::query(
            "UPDATE episodes SET title='Synthetic filter',embedding=$2::vector WHERE account_id=$1",
        )
        .bind(account)
        .bind(&vector)
        .execute(repo.pool())
        .await
        .unwrap();
        sqlx::query("UPDATE utterances SET text='Synthetic filter',embedding=$2::vector WHERE account_id=$1")
            .bind(account).bind(&vector).execute(repo.pool()).await.unwrap();
        for kind in ["episode", "utterance"] {
            for (query, embedding) in [
                ("", None),
                ("Synthetic", None),
                ("unmatchedlexicalfixture", Some(vec![1.0; 384])),
            ] {
                for (selector, expected) in [
                    ("Speaker A".to_owned(), vec![1, 3, 4, 5, 6]),
                    ("Speaker Z".to_owned(), vec![2]),
                    (format!("id:{}", recurring_ids[0]), vec![1, 2, 3]),
                    ("Unnamed voice".to_owned(), vec![]),
                ] {
                    let request = crate::persistence::SearchRequest {
                        query: query.into(),
                        speaker: Some(selector.clone()),
                        time_start: None,
                        time_end: None,
                        limit: 20,
                        offset: 0,
                        kinds: vec![kind.into()],
                        query_embedding: embedding.clone(),
                    };
                    let hits = serde_json::to_value(repo.search(account, &request).await.unwrap())
                        .unwrap();
                    let mut actual = hits
                        .as_array()
                        .unwrap()
                        .iter()
                        .map(|hit| hit["id"].as_i64().unwrap())
                        .collect::<Vec<_>>();
                    actual.sort_unstable();
                    assert_eq!(actual, expected, "{kind} {query:?} {selector} must distinguish local recurring labels from opaque person selection");
                }
            }
        }
        close(f).await;
    }

    #[tokio::test]
    async fn recurrence_withdrawal_survives_candidate_overflow_while_paused() {
        let Some(f) = fixture().await else {
            return;
        };
        let repo = &f.persistence;
        let account = "recurrence-overflow";
        repo.set_voice_identity_cohort(VoiceCohort::All, &[])
            .await
            .unwrap();
        for id in 1..=3 {
            turn(repo, account, id, id).await;
        }
        repo.maintain_voice_profiles(account).await.unwrap();
        let person = people(repo, account).await[0].0;
        sqlx::query("INSERT INTO voice_profiles(account_id,id,label,embedding_space,channel_domain,centroid) SELECT $1,id,'voice-profile-'||id,'synthetic','synthetic',decode('00','hex') FROM generate_series(1000,1512) id").bind(account).execute(repo.pool()).await.unwrap();
        repo.set_voice_identity_paused(true).await.unwrap();
        sqlx::query("UPDATE media_objects SET retain_until=clock_timestamp()-interval '1 second' WHERE account_id=$1").bind(account).execute(repo.pool()).await.unwrap();
        repo.maintain_voice_profiles(account).await.unwrap();
        assert_eq!(
            people(repo, account).await[0].1,
            "unknown",
            "candidate overflow must never suppress paused recurrence withdrawal"
        );
        assert_eq!(sqlx::query_scalar::<_,i64>("SELECT count(*) FROM identity_evidence WHERE account_id=$1 AND kind='voice_recurrence' AND status='accepted'").bind(account).fetch_one(repo.pool()).await.unwrap(),0,"expired recurrence evidence must be withdrawn despite candidate overflow");
        let page = repo
            .list_people(
                account,
                &PeopleListRequest {
                    kind: PublicPersonStatus::Recurring,
                    after_id: 0,
                    limit: 1,
                    query: None,
                },
            )
            .await
            .expect("withdrawal must leave a valid empty People page");
        assert!(
            page.people.is_empty() && page.next_cursor.is_none(),
            "expired crowded roster must remain a valid empty page"
        );
        assert!(
            matches!(
                repo.person_profile(account, person).await,
                Err(crate::error::EnclaveError::NotFound)
            ),
            "expired recurring detail must be404 despite candidate overflow"
        );
        assert!(
            matches!(
                repo.person_evidence(account, person, None, 10).await,
                Err(crate::error::EnclaveError::NotFound)
            ),
            "expired recurring evidence must be404 despite candidate overflow"
        );
        assert!(
            matches!(
                repo.person_statements(account, person, None, 10).await,
                Err(crate::error::EnclaveError::NotFound)
            ),
            "expired recurring statements must be404 despite candidate overflow"
        );
        assert!(
            matches!(
                repo.person_memories(account, person, None, 10, None).await,
                Err(crate::error::EnclaveError::NotFound)
            ),
            "expired recurring memories must be404 despite candidate overflow"
        );
        close(f).await;
    }

    #[tokio::test]
    async fn recurring_people_reads_share_one_snapshot_during_withdrawal_and_naming() {
        use super::super::speaker_query_contract::arm;
        use std::time::Duration;
        let Some(f) = fixture().await else {
            return;
        };
        let repo = &f.persistence;
        let account = "recurrence-snapshot";
        repo.set_voice_identity_cohort(VoiceCohort::All, &[])
            .await
            .unwrap();
        for id in 1..=6 {
            turn_axis(repo, account, id, id, if id <= 3 { 0 } else { 1 }).await;
        }
        repo.maintain_voice_profiles(account).await.unwrap();
        let ids = people(repo, account)
            .await
            .into_iter()
            .map(|p| p.0)
            .collect::<Vec<_>>();
        assert_eq!(
            ids.len(),
            2,
            "snapshot fixture must contain a returned voice and a lookahead"
        );
        for (stage, naming, lookahead) in [
            ("people-list", false, false),
            ("people-detail", false, false),
            ("people-evidence", false, false),
            ("people-statements", false, false),
            ("people-list", true, false),
            ("people-detail", true, false),
            ("people-list", false, true),
        ] {
            sqlx::query(
                "UPDATE people SET status='recurring',display_name=NULL WHERE account_id=$1",
            )
            .bind(account)
            .execute(repo.pool())
            .await
            .unwrap();
            sqlx::query("UPDATE voice_profiles SET status='stable' WHERE account_id=$1")
                .bind(account)
                .execute(repo.pool())
                .await
                .unwrap();
            sqlx::query("UPDATE identity_evidence SET status='accepted' WHERE account_id=$1 AND kind='voice_recurrence'").bind(account).execute(repo.pool()).await.unwrap();
            let gate = arm(account, stage);
            let read = async {
                match stage {
                    "people-list" => {
                        let page=repo.list_people(account,&PeopleListRequest{kind:PublicPersonStatus::Recurring,after_id:0,limit:1,query:None}).await.expect("People list must retain its selected snapshot during concurrent identity changes");
                        assert_eq!(
                            page.people.len(),
                            1,
                            "People list must retain the selected public row"
                        );
                        assert_eq!((page.people[0].id,page.next_cursor),(ids[0],Some(ids[0])),"concurrent lookahead changes must not corrupt cursor or page membership");
                        assert_eq!(
                            page.people[0].recurrence.as_ref().unwrap().memory_count,
                            3,
                            "People support must share the selected metadata snapshot"
                        );
                    }
                    "people-detail" => {
                        let page=repo.person_profile(account,ids[0]).await.expect("People detail must retain its selected snapshot during concurrent identity changes");
                        assert_eq!(
                            page.person.status,
                            PublicPersonStatus::Recurring,
                            "People metadata must retain its selected status"
                        );
                        assert_eq!(
                            page.person.recurrence.as_ref().unwrap().memory_count,
                            3,
                            "People detail support must share its metadata snapshot"
                        );
                        assert_eq!(
                            page.recent_statements.len(),
                            3,
                            "People detail statements must share its metadata snapshot"
                        );
                    }
                    "people-evidence" => {
                        let page = repo
                            .person_evidence(account, ids[0], None, 100)
                            .await
                            .expect("People evidence must retain its public eligibility snapshot");
                        assert!(
                            page.evidence.iter().any(|e| e.status == "accepted"),
                            "People evidence must share the public eligibility snapshot"
                        );
                    }
                    "people-statements" => {
                        let page = repo
                            .person_statements(account, ids[0], None, 100)
                            .await
                            .expect(
                                "People statements must retain their public eligibility snapshot",
                            );
                        assert_eq!(
                            page.statements.len(),
                            3,
                            "People statements must share the public eligibility snapshot"
                        );
                    }
                    _ => unreachable!(),
                }
            };
            let change = async {
                tokio::time::timeout(Duration::from_secs(10), gate.reached.notified())
                    .await
                    .expect("People read must reach metadata checkpoint");
                let changed = ids[usize::from(lookahead)];
                let mut tx = repo.pool().begin().await.unwrap();
                if naming {
                    sqlx::query("UPDATE people SET status='identified',display_name='Alex Chen' WHERE account_id=$1 AND id=$2").bind(account).bind(changed).execute(&mut *tx).await.unwrap();
                } else {
                    sqlx::query("UPDATE people SET status='unknown' WHERE account_id=$1 AND id=$2")
                        .bind(account)
                        .bind(changed)
                        .execute(&mut *tx)
                        .await
                        .unwrap();
                    sqlx::query("UPDATE voice_profiles SET status='quarantined' WHERE account_id=$1 AND person_id=$2").bind(account).bind(changed).execute(&mut *tx).await.unwrap();
                    sqlx::query("UPDATE identity_evidence SET status='quarantined' WHERE account_id=$1 AND person_id=$2").bind(account).bind(changed).execute(&mut *tx).await.unwrap();
                }
                tx.commit().await.unwrap();
                gate.resume.notify_one();
            };
            tokio::time::timeout(Duration::from_secs(30), async {
                tokio::join!(read, change);
            })
            .await
            .expect("People read and writer must complete without lock inversion");
            assert_eq!(
                gate.settings.lock().unwrap().clone().unwrap(),
                ("on".into(), "repeatable read".into()),
                "People response transaction must be read-only repeatable read"
            );
            let changed = ids[usize::from(lookahead)];
            if naming {
                assert_eq!(
                    repo.person_profile(account, changed)
                        .await
                        .unwrap()
                        .person
                        .status,
                    PublicPersonStatus::Identified,
                    "later People requests must observe committed naming"
                );
            } else {
                assert!(
                    matches!(
                        repo.person_profile(account, changed).await,
                        Err(crate::error::EnclaveError::NotFound)
                    ),
                    "later People requests must observe committed withdrawal"
                );
            }
        }
        close(f).await;
    }

    #[tokio::test]
    async fn recurrence_requires_three_current_memories_and_reuses_its_opaque_identity() {
        let Some(f) = fixture().await else {
            return;
        };
        let repo = &f.persistence;
        let account = "recurrence-memories";
        repo.set_voice_identity_cohort(VoiceCohort::All, &[])
            .await
            .unwrap();
        for id in 1..=2 {
            turn(repo, account, id, id).await;
        }
        repo.maintain_voice_profiles(account).await.unwrap();
        assert!(
            people(repo, account).await.is_empty(),
            "two current memories must not invent a recurring person"
        );
        turn(repo, account, 3, 3).await;
        repo.maintain_voice_profiles(account).await.unwrap();
        let published = people(repo, account).await;
        assert_eq!(
            published.len(),
            1,
            "three current memories of one stable voice must publish exactly one person"
        );
        assert_eq!(
            (published[0].1.as_str(), &published[0].2),
            ("recurring", &None),
            "recurring identity must remain unnamed in storage"
        );
        let person = published[0].0;
        sqlx::query("DELETE FROM active_episode_members WHERE account_id=$1 AND episode_id=3")
            .bind(account)
            .execute(repo.pool())
            .await
            .unwrap();
        repo.maintain_voice_profiles(account).await.unwrap();
        assert_eq!(
            people(repo, account).await[0].1,
            "unknown",
            "retired memory membership must withdraw unsupported recurrence"
        );
        sqlx::query("INSERT INTO active_episode_members(account_id,episode_id,record_type,record_id) VALUES($1,3,'utterance',3)").bind(account).execute(repo.pool()).await.unwrap();
        repo.maintain_voice_profiles(account).await.unwrap();
        assert_eq!(
            people(repo, account).await,
            vec![(person, "recurring".into(), None)],
            "restored recurrence must reuse its original opaque identity"
        );
        sqlx::query("UPDATE people SET status='identified',display_name='Alex Chen' WHERE account_id=$1 AND id=$2").bind(account).bind(person).execute(repo.pool()).await.unwrap();
        sqlx::query("DELETE FROM active_episode_members WHERE account_id=$1")
            .bind(account)
            .execute(repo.pool())
            .await
            .unwrap();
        repo.maintain_voice_profiles(account).await.unwrap();
        assert_eq!(
            people(repo, account).await[0].1,
            "identified",
            "recurrence loss must not demote an independently identified person"
        );
        close(f).await;
    }
    #[tokio::test]
    async fn recurrence_speech_uses_timeline_union_and_exact_twenty_minute_boundary() {
        let Some(f) = fixture().await else {
            return;
        };
        let repo = &f.persistence;
        let account = "recurrence-duration";
        repo.set_voice_identity_cohort(VoiceCohort::All, &[])
            .await
            .unwrap();
        for id in 1..=3 {
            turn(repo, account, id, 1).await;
        }
        sqlx::query("UPDATE speaker_observations SET started_at=to_timestamp(100000),ended_at=to_timestamp(100400) WHERE account_id=$1").bind(account).execute(repo.pool()).await.unwrap();
        repo.maintain_voice_profiles(account).await.unwrap();
        assert!(
            people(repo, account).await.is_empty(),
            "overlapping attributed windows must not manufacture twenty minutes"
        );
        sqlx::query("UPDATE speaker_observations SET started_at=to_timestamp(100000+(id-1)*400),ended_at=to_timestamp(100000+id*400)-CASE WHEN id=3 THEN interval '1 millisecond' ELSE interval '0 seconds' END WHERE account_id=$1").bind(account).execute(repo.pool()).await.unwrap();
        repo.maintain_voice_profiles(account).await.unwrap();
        assert!(
            people(repo, account).await.is_empty(),
            "nineteen minutes and 59999 milliseconds must remain below recurrence threshold"
        );
        sqlx::query("UPDATE speaker_observations SET ended_at=ended_at+interval '1 millisecond' WHERE account_id=$1 AND id=3").bind(account).execute(repo.pool()).await.unwrap();
        repo.maintain_voice_profiles(account).await.unwrap();
        assert_eq!(
            people(repo, account).await.len(),
            1,
            "exactly twenty attributed minutes must qualify in one current memory"
        );
        assert_eq!(sqlx::query_scalar::<_,i64>("SELECT (evidence->>'speech_ms')::bigint FROM identity_evidence WHERE account_id=$1 AND kind='voice_recurrence' AND status='accepted'").bind(account).fetch_one(repo.pool()).await.unwrap(),1_200_000,"recurrence evidence must record union speech rather than capped embedding duration");
        close(f).await;
    }
}
