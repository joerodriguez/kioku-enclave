//! Real PostgreSQL reader parity and concurrent identity snapshot contracts.
use super::{
    tests::{test_persistence, ControlPlaneContractFixture},
    voice_identity::tests::{seed_voice_memory, seed_voice_observation},
    PostgresPersistence,
};
use crate::persistence::{
    EpisodeListRequest, McpContextRequest, McpTimeRangeRequest, McpTranscriptSearchRequest,
    MemoryFeedRequest, MemoryQueryRepository, PlaybackRepository, SearchHit, SearchRequest,
};
use serde_json::{json, Value};
use sqlx::PgConnection;
use std::{
    collections::HashMap,
    sync::{Arc, Mutex, OnceLock},
    time::Duration,
};
use tokio::sync::Notify;

#[derive(Default)]
struct ReaderGate {
    reached: Notify,
    resume: Notify,
    settings: Mutex<Option<(String, String)>>,
}
type ReaderGateRegistry = HashMap<(String, &'static str), Arc<ReaderGate>>;
static READER_GATES: OnceLock<Mutex<ReaderGateRegistry>> = OnceLock::new();
fn gates() -> &'static Mutex<ReaderGateRegistry> {
    READER_GATES.get_or_init(Default::default)
}
fn arm(account: &str, stage: &'static str) -> Arc<ReaderGate> {
    let gate = Arc::new(ReaderGate::default());
    assert!(gates()
        .lock()
        .unwrap()
        .insert((account.to_owned(), stage), gate.clone())
        .is_none());
    gate
}
// This hook exists only in test builds and cannot pause another account's reader.
pub(super) async fn reader_checkpoint(
    account: &str,
    stage: &'static str,
    connection: &mut PgConnection,
) {
    let gate = gates().lock().unwrap().remove(&(account.to_owned(), stage));
    if let Some(gate) = gate {
        let read_only: String = sqlx::query_scalar("SHOW transaction_read_only")
            .fetch_one(&mut *connection)
            .await
            .unwrap();
        let isolation: String = sqlx::query_scalar("SHOW transaction_isolation")
            .fetch_one(&mut *connection)
            .await
            .unwrap();
        *gate.settings.lock().unwrap() = Some((read_only, isolation));
        gate.reached.notify_one();
        gate.resume.notified().await;
    }
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
fn search_request(query: &str, speaker: Option<&str>) -> SearchRequest {
    SearchRequest {
        query: query.into(),
        speaker: speaker.map(str::to_owned),
        time_start: None,
        time_end: None,
        limit: 20,
        offset: 0,
        kinds: vec!["utterance".into()],
        query_embedding: None,
    }
}
fn list_request() -> EpisodeListRequest {
    EpisodeListRequest {
        from: None,
        to: None,
        limit: 50,
        include_low: false,
        episode_id: None,
        before_started_at: None,
        before_id: None,
        probe_for_more: false,
    }
}
async fn seed_named(repo: &PostgresPersistence, account: &str, id: i64, episode: i64) {
    seed_voice_observation(repo, account, "session", &format!("event-{id}"), id, id).await;
    seed_voice_memory(repo, account, id, episode).await;
    sqlx::query("INSERT INTO people(account_id,id,display_name,status) VALUES($1,10,'Current Person','identified') ON CONFLICT DO NOTHING").bind(account).execute(repo.pool()).await.unwrap();
    sqlx::query("INSERT INTO voice_profiles(account_id,id,person_id,label,embedding_space,channel_domain,centroid,status) VALUES($1,1,10,'Private profile label','reader-test','ambient_mic','\\x1234'::bytea,'stable') ON CONFLICT DO NOTHING").bind(account).execute(repo.pool()).await.unwrap();
    sqlx::query("UPDATE speaker_clusters SET voice_profile_id=1,attribution_state='anonymous_profile' WHERE account_id=$1 AND id=$2").bind(account).bind(id).execute(repo.pool()).await.unwrap();
}
fn utterance_label(hit: &SearchHit) -> (&str, Option<i64>, Option<&str>) {
    match hit {
        SearchHit::Utterance {
            speaker_label,
            person_id,
            attribution_kind,
            ..
        } => (speaker_label, *person_id, attribution_kind.as_deref()),
        _ => panic!("reader fixture must return utterances"),
    }
}

#[tokio::test]
async fn canonical_query_readers_agree_without_rewriting_sources() {
    let Some(fixture) = test_persistence().await else {
        return;
    };
    let repo = &fixture.persistence;
    let account = "41000000-0000-0000-0000-000000000001";
    seed_named(repo, account, 1, 1).await;
    seed_named(repo, account, 2, 1).await;
    for id in 3..=6 {
        seed_voice_observation(repo, account, "session", &format!("event-{id}"), id, id).await;
        seed_voice_memory(repo, account, id, 1).await;
    }
    sqlx::query("UPDATE speaker_clusters SET attribution_state='owner_transmit',person_id=10 WHERE account_id=$1 AND id=3").bind(account).execute(repo.pool()).await.unwrap();
    sqlx::query("UPDATE speaker_observations SET person_id=10 WHERE account_id=$1 AND id=3")
        .bind(account)
        .execute(repo.pool())
        .await
        .unwrap();
    sqlx::query("INSERT INTO voice_profiles(account_id,id,label,embedding_space,channel_domain,centroid,status) VALUES($1,2,'Another private label','reader-test','ambient_mic','\\x5678'::bytea,'stable')").bind(account).execute(repo.pool()).await.unwrap();
    sqlx::query("UPDATE speaker_clusters SET voice_profile_id=2,attribution_state='anonymous_profile' WHERE account_id=$1 AND id=4").bind(account).execute(repo.pool()).await.unwrap();
    sqlx::query("UPDATE utterances SET speaker_observation_id=NULL,speaker_label='Legacy Label' WHERE account_id=$1 AND id=5").bind(account).execute(repo.pool()).await.unwrap();
    sqlx::query("DELETE FROM episode_members WHERE account_id=$1 AND record_id=6")
        .bind(account)
        .execute(repo.pool())
        .await
        .unwrap();
    let statements = repo
        .person_statements(account, 10, None, 100)
        .await
        .unwrap();
    assert_eq!(statements.statements.len(), 2, "recent statements must include accepted profile-only turns and suppress malformed owner person IDs");
    assert!(statements
        .statements
        .iter()
        .all(|row| row.episode_id == Some(1)));
    let original: Vec<String> = sqlx::query_scalar(
        "SELECT to_jsonb(u)::text FROM utterances u WHERE account_id=$1 ORDER BY id",
    )
    .bind(account)
    .fetch_all(repo.pool())
    .await
    .unwrap();
    // First slot-dependent read is a filter: unseen memories must acquire slots first.
    let first = repo
        .search(account, &search_request("", Some("Speaker A")))
        .await
        .unwrap();
    assert_eq!(
        first.len(),
        1,
        "speaker-only search must prepare an unseen memory before filtering"
    );
    assert_eq!(
        utterance_label(&first[0]),
        ("Speaker A", None, Some("verified_voice")),
        "speaker-only enrichment must retain the canonical anonymous slot"
    );
    let expected = [
        (1, "Current Person", Some(10)),
        (2, "Current Person", Some(10)),
        (3, "Me", None),
        (4, "Speaker A", None),
        (5, "Legacy Label", None),
        (6, "Speaker", None),
    ];
    let search = repo
        .search(account, &search_request("Synthetic", None))
        .await
        .unwrap();
    assert_eq!(search.len(), 6);
    for (id, label, person) in expected {
        let hit = search
            .iter()
            .find(|hit| matches!(hit, SearchHit::Utterance { id: found, .. } if *found==id))
            .unwrap();
        assert_eq!(
            (utterance_label(hit).0, utterance_label(hit).1),
            (label, person),
            "search must use current graph identity for utterance {id}"
        );
    }
    let named = repo
        .search(
            account,
            &search_request("Synthetic", Some("Current Person")),
        )
        .await
        .unwrap();
    assert_eq!(
        named.len(),
        2,
        "FTS speaker filter must follow accepted profile identity"
    );
    let mut vector_request = search_request("unmatchedlexicalfixture", Some("Speaker A"));
    vector_request.query_embedding = Some(vec![1.0; 384]);
    sqlx::query("UPDATE utterances SET embedding=($2::real[])::vector WHERE account_id=$1")
        .bind(account)
        .bind(vec![1.0_f32; 384])
        .execute(repo.pool())
        .await
        .unwrap();
    let hybrid = repo.search(account, &vector_request).await.unwrap();
    assert_eq!(
        hybrid.len(),
        1,
        "vector-only speaker filter must follow the same stable slot"
    );
    assert_eq!(utterance_label(&hybrid[0]).0, "Speaker A");
    // Reset only the test-added query vectors before the immutable-source comparison.
    sqlx::query("UPDATE utterances SET embedding=NULL WHERE account_id=$1")
        .bind(account)
        .execute(repo.pool())
        .await
        .unwrap();
    let members = repo.episode_members(account, 1).await.unwrap();
    let page = repo.list_episodes(account, &list_request()).await.unwrap();
    assert_eq!(
        page.episodes[0]["participant_details"], members["participant_details"],
        "list/member participant labels must agree"
    );
    for (id, label, person) in expected.into_iter().filter(|(id, _, _)| *id != 6) {
        let member = members["members"]
            .as_array()
            .unwrap()
            .iter()
            .find(|m| m["record_id"] == id)
            .unwrap();
        assert_eq!(
            member["speaker_label"], label,
            "members must suppress stale raw labels"
        );
        assert_eq!(member["display_name"], label);
        assert_eq!(member["person_id"], json!(person));
    }
    let feed = repo
        .feed(
            account,
            &MemoryFeedRequest {
                from: None,
                to: None,
                limit: 20,
                before: None,
            },
        )
        .await
        .unwrap();
    for (id, label, person) in expected {
        let row = feed
            .records
            .iter()
            .find(|r| r.kind == "utterance" && r.id == id)
            .unwrap();
        assert_eq!(
            row.speaker_label.as_deref(),
            Some(label),
            "feed must derive labels"
        );
        assert_eq!(row.person_id, person);
    }
    let start: String = sqlx::query_scalar("SELECT to_char(min(started_at)-interval '1 hour','YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"') FROM audio_segments WHERE account_id=$1").bind(account).fetch_one(repo.pool()).await.unwrap();
    let end: String = sqlx::query_scalar("SELECT to_char(max(ended_at)+interval '1 hour','YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"') FROM audio_segments WHERE account_id=$1").bind(account).fetch_one(repo.pool()).await.unwrap();
    let center: String = sqlx::query_scalar("SELECT to_char(min(started_at),'YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"') FROM audio_segments WHERE account_id=$1").bind(account).fetch_one(repo.pool()).await.unwrap();
    let mcp_search = repo
        .mcp_search_transcripts(
            account,
            &McpTranscriptSearchRequest {
                query: "Synthetic".into(),
                from: None,
                to: None,
                limit: 20,
            },
        )
        .await
        .unwrap();
    let context = repo
        .mcp_context(
            account,
            &McpContextRequest {
                at: center,
                window_seconds: 3600,
                limit: Some(20),
            },
        )
        .await
        .unwrap();
    let range = repo
        .mcp_time_range(
            account,
            &McpTimeRangeRequest {
                from: start,
                to: end,
                limit: Some(20),
            },
        )
        .await
        .unwrap();
    let mut expected_labels = expected
        .iter()
        .map(|(_, label, _)| label.to_string())
        .collect::<Vec<_>>();
    expected_labels.sort();
    for (response, field, key) in [
        (&mcp_search, "results", "speaker_label"),
        (&context, "utterances", "speaker_label"),
        (&range, "digest", "speaker"),
    ] {
        let mut labels = response[field]
            .as_array()
            .unwrap()
            .iter()
            .map(|row| row[key].as_str().unwrap().to_owned())
            .collect::<Vec<_>>();
        labels.sort();
        assert_eq!(
            labels, expected_labels,
            "all three MCP tools must use canonical labels without changing shape"
        );
    }
    let export = repo.export(account).await.unwrap();
    for (id, label, _) in expected {
        let row = export["utterances"]
            .as_array()
            .unwrap()
            .iter()
            .find(|r| r["id"] == id)
            .unwrap();
        assert_eq!(
            row["speaker_label"], label,
            "export must derive speaker labels"
        );
        assert!(row.get("account_id").is_none());
    }
    assert!(
        export["voice_profiles"]
            .as_array()
            .unwrap()
            .iter()
            .all(|p| p.get("centroid").is_none()),
        "derived export must preserve biometric byte omission"
    );
    assert!(export.get("voice_identity_controls").is_none());
    let playback = repo.dataset(account, 1, None).await.unwrap().unwrap();
    let session = repo
        .session_dataset(account, "session", None)
        .await
        .unwrap()
        .unwrap();
    for (dataset, is_session) in [(&playback, false), (&session, true)] {
        for row in &dataset.utterances {
            let (_, label, person) = expected
                .iter()
                .find(|(id, _, _)| *id == row.utterance_id)
                .unwrap();
            assert_eq!(
                row.fallback_label, *label,
                "playback source labels must agree with query readers, session={is_session}"
            );
            assert_eq!(row.person_id, *person);
        }
        assert!(dataset
            .utterances
            .iter()
            .any(|row| row.fallback_label == "Current Person"));
    }
    let people = repo
        .person_memories(account, 10, None, 20, None)
        .await
        .unwrap();
    assert_eq!(
        people.memories.len(),
        1,
        "profile-only accepted identity must link its memory"
    );
    assert_eq!(people.memories[0].attributed_utterance_count, 2);
    assert_eq!(
        original,
        sqlx::query_scalar::<_, String>(
            "SELECT to_jsonb(u)::text FROM utterances u WHERE account_id=$1 ORDER BY id"
        )
        .bind(account)
        .fetch_all(repo.pool())
        .await
        .unwrap(),
        "presentation readers must not rewrite raw source labels"
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT identity_revision FROM episodes WHERE account_id=$1 AND id=1"
        )
        .bind(account)
        .fetch_one(repo.pool())
        .await
        .unwrap(),
        7
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT revision FROM memory_archive_state WHERE account_id=$1"
        )
        .bind(account)
        .fetch_one(repo.pool())
        .await
        .unwrap(),
        9
    );
    cleanup(fixture).await;
}

#[tokio::test]
async fn quarantine_and_structural_legacy_guards_remove_stale_person_links() {
    let Some(fixture) = test_persistence().await else {
        return;
    };
    let repo = &fixture.persistence;
    let account = "41000000-0000-0000-0000-000000000002";
    seed_named(repo, account, 1, 1).await;
    seed_named(repo, account, 2, 1).await;
    sqlx::query("UPDATE speaker_observations SET person_id=10 WHERE account_id=$1 AND id=1")
        .bind(account)
        .execute(repo.pool())
        .await
        .unwrap();
    repo.episode_members(account, 1).await.unwrap();
    sqlx::query("UPDATE voice_profiles SET status='quarantined' WHERE account_id=$1 AND id=1")
        .bind(account)
        .execute(repo.pool())
        .await
        .unwrap();
    let members = repo.episode_members(account, 1).await.unwrap();
    let rows = members["members"].as_array().unwrap();
    let direct = rows.iter().find(|r| r["record_id"] == 1).unwrap();
    let propagated = rows.iter().find(|r| r["record_id"] == 2).unwrap();
    assert_eq!(
        direct["display_name"], "Current Person",
        "profile quarantine must preserve independent direct identity"
    );
    assert_eq!(
        propagated["display_name"], "Speaker A",
        "profile quarantine must suppress a stale propagated name"
    );
    assert_eq!(propagated["person_id"], Value::Null);
    let linked = repo
        .person_memories(account, 10, None, 20, None)
        .await
        .unwrap();
    assert_eq!(
        linked.memories[0].attributed_utterance_count, 1,
        "person memories must count only current accepted turn identities"
    );
    let profile = repo.person_profile(account, 10).await.unwrap();
    assert_eq!(
        profile.person.voice_profile_count, 0,
        "direct quarantine must suppress profile coverage without relying on revision rows"
    );
    assert!(profile.voice_labels.is_empty());
    assert_eq!(
        profile.recent_statements.len(),
        1,
        "quarantine must remove propagated recent statements while preserving direct evidence"
    );
    assert_eq!(profile.recent_statements[0].speaker_observation_id, 1);
    // Current observations remain but have no usable graph identities. A stale
    // cached participant must not resurrect the suppressed source name/person.
    sqlx::query(
        "UPDATE speaker_observations SET cluster_id=NULL,person_id=NULL WHERE account_id=$1",
    )
    .bind(account)
    .execute(repo.pool())
    .await
    .unwrap();
    sqlx::query("INSERT INTO episode_participants(account_id,id,episode_id,participant_key,person_id,source_claimed_name,attribution_kind,derivation_version) VALUES($1,999,1,'legacy-poison',10,'Stale claimed name','verified_voice',1)").bind(account).execute(repo.pool()).await.unwrap();
    let empty = repo.episode_members(account, 1).await.unwrap();
    assert!(
        empty["participant_details"].as_array().unwrap().is_empty(),
        "observed but unresolved memory must never fall back to stale named participants"
    );
    assert!(empty["members"]
        .as_array()
        .unwrap()
        .iter()
        .all(|r| r["display_name"] == "Speaker" && r["person_id"].is_null()));
    assert!(
        repo.person_memories(account, 10, None, 20, None)
            .await
            .unwrap()
            .memories
            .is_empty(),
        "stale cached person links must be suppressed when observed identity disappears"
    );
    // A genuinely observationless owner projection is also never a person link,
    // even if its historical key/person ID is malformed.
    sqlx::query("INSERT INTO episodes(account_id,id,started_at,ended_at) VALUES($1,2,now(),now()+interval '1 minute')").bind(account).execute(repo.pool()).await.unwrap();
    sqlx::query("INSERT INTO episode_participants(account_id,id,episode_id,participant_key,person_id,source_claimed_name,attribution_kind) VALUES($1,1000,2,'malformed-owner',10,'Unsafe owner label','owner_source_role')").bind(account).execute(repo.pool()).await.unwrap();
    assert!(
        repo.person_memories(account, 10, None, 20, None)
            .await
            .unwrap()
            .memories
            .is_empty(),
        "malformed legacy owner attribution must never expose a person-memory link"
    );
    let owner = repo.episode_members(account, 2).await.unwrap();
    assert_eq!(owner["participant_details"][0]["display_name"], "Me");
    assert!(owner["participant_details"][0]["person_id"].is_null());
    cleanup(fixture).await;
}

#[tokio::test]
async fn speaker_filter_and_participant_enrichment_share_read_only_snapshots() {
    let Some(fixture) = test_persistence().await else {
        return;
    };
    let repo = &fixture.persistence;
    let account = "41000000-0000-0000-0000-000000000003";
    seed_named(repo, account, 1, 1).await;
    for stage in ["search", "members", "list"] {
        sqlx::query("UPDATE voice_profiles SET status='stable' WHERE account_id=$1")
            .bind(account)
            .execute(repo.pool())
            .await
            .unwrap();
        let gate = arm(account, stage);
        let read = async {
            match stage {
                "search" => {
                    let hits = repo
                        .search(
                            account,
                            &search_request("Synthetic", Some("Current Person")),
                        )
                        .await
                        .unwrap();
                    assert_eq!(hits.len(),1,"speaker candidate selected before quarantine must remain in its original snapshot");
                    assert_eq!(
                        utterance_label(&hits[0]).0,
                        "Current Person",
                        "speaker-filtered enrichment must not mix a later quarantine snapshot"
                    );
                }
                "members" => {
                    let result = repo.episode_members(account, 1).await.unwrap();
                    assert_eq!(result["members"][0]["display_name"], "Current Person");
                    assert_eq!(
                        result["participant_details"][0]["display_name"], "Current Person",
                        "member participant enrichment must share the turn snapshot"
                    );
                }
                "list" => {
                    let result = repo.list_episodes(account, &list_request()).await.unwrap();
                    assert_eq!(
                        result.episodes[0]["participant_details"][0]["display_name"],
                        "Current Person",
                        "list participant enrichment must share the episode snapshot"
                    );
                }
                _ => unreachable!(),
            }
        };
        let change = async {
            tokio::time::timeout(Duration::from_secs(10), gate.reached.notified())
                .await
                .expect("reader must reach candidate/participant checkpoint");
            let settings = gate.settings.lock().unwrap().clone().unwrap();
            assert_eq!(
                settings,
                ("on".into(), "repeatable read".into()),
                "presentation snapshot must remain read-only repeatable read"
            );
            sqlx::query("UPDATE voice_profiles SET status='quarantined' WHERE account_id=$1")
                .bind(account)
                .execute(repo.pool())
                .await
                .unwrap();
            gate.resume.notify_one();
        };
        tokio::time::timeout(Duration::from_secs(20), async {
            tokio::join!(read, change);
        })
        .await
        .expect("reader and concurrent quarantine must complete without lock inversion");
        assert!(
            repo.search(
                account,
                &search_request("Synthetic", Some("Current Person"))
            )
            .await
            .unwrap()
            .is_empty(),
            "a later request must observe committed quarantine"
        );
    }
    sqlx::query("UPDATE voice_profiles SET person_id=NULL,status='stable' WHERE account_id=$1")
        .bind(account)
        .execute(repo.pool())
        .await
        .unwrap();
    let gate = arm(account, "feed");
    let request = MemoryFeedRequest {
        from: None,
        to: None,
        limit: 20,
        before: None,
    };
    let read = async {
        let result = repo.feed(account, &request).await.unwrap();
        assert_eq!(
            result.records[0].speaker_label.as_deref(),
            Some("Speaker A")
        );
        assert_eq!(
            result.records[0].episode_id,
            Some(1),
            "feed labels and memory association must share the pre-publication snapshot"
        );
    };
    let publish = async {
        tokio::time::timeout(Duration::from_secs(10), gate.reached.notified())
            .await
            .expect("feed must reach membership checkpoint");
        assert_eq!(
            gate.settings.lock().unwrap().clone().unwrap(),
            ("on".into(), "repeatable read".into())
        );
        let mut tx = repo.pool().begin().await.unwrap();
        sqlx::query("INSERT INTO episodes(account_id,id,started_at,ended_at) VALUES($1,2,now(),now()+interval '1 minute')").bind(account).execute(&mut *tx).await.unwrap();
        sqlx::query("INSERT INTO episode_speaker_slots(account_id,id,episode_id,voice_profile_id,slot_ordinal,status) VALUES($1,1000,2,1,1,'active')").bind(account).execute(&mut *tx).await.unwrap();
        sqlx::query("UPDATE episode_members SET episode_id=2 WHERE account_id=$1 AND episode_id=1")
            .bind(account)
            .execute(&mut *tx)
            .await
            .unwrap();
        tx.commit().await.unwrap();
        gate.resume.notify_one();
    };
    tokio::time::timeout(Duration::from_secs(20), async {
        tokio::join!(read, publish);
    })
    .await
    .expect("feed and fixture topology publication must complete");
    let later = repo.feed(account, &request).await.unwrap();
    assert_eq!(later.records[0].speaker_label.as_deref(), Some("Speaker B"));
    assert_eq!(
        later.records[0].episode_id,
        Some(2),
        "next feed must observe committed replacement ownership"
    );
    cleanup(fixture).await;
}

#[tokio::test]
async fn canonical_reader_identity_is_tenant_qualified() {
    let Some(fixture) = test_persistence().await else {
        return;
    };
    let repo = &fixture.persistence;
    let first = "41000000-0000-0000-0000-000000000004";
    let second = "41000000-0000-0000-0000-000000000005";
    seed_named(repo, first, 1, 1).await;
    seed_named(repo, second, 1, 1).await;
    sqlx::query("UPDATE people SET display_name='Other Tenant Person' WHERE account_id=$1")
        .bind(second)
        .execute(repo.pool())
        .await
        .unwrap();
    for (account, label, absent) in [
        (first, "Current Person", "Other Tenant Person"),
        (second, "Other Tenant Person", "Current Person"),
    ] {
        let hits = repo
            .search(account, &search_request("Synthetic", Some(label)))
            .await
            .unwrap();
        assert_eq!(
            hits.len(),
            1,
            "tenant's own speaker filter must return exactly its one row"
        );
        assert_eq!(
            utterance_label(&hits[0]).0,
            label,
            "identical cross-tenant IDs must not cross-bind identities"
        );
        assert!(
            repo.search(account, &search_request("Synthetic", Some(absent)))
                .await
                .unwrap()
                .is_empty(),
            "speaker filters must not accept another tenant's identity"
        );
        let members = repo.episode_members(account, 1).await.unwrap();
        assert_eq!(members["participant_details"][0]["display_name"], label);
        let exported = repo.export(account).await.unwrap();
        assert_eq!(exported["utterances"][0]["speaker_label"], label);
        assert!(!exported.to_string().contains(absent));
    }
    cleanup(fixture).await;
}
