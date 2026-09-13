//! Account-qualified graph resolution for immutable authored label maps.
use super::speaker_identity::{speaker_identity_join, SpeakerMemoryScope, SpeakerUtteranceAlias};
use crate::error::{EnclaveError, Result};
use crate::persistence::identity_presentation::{
    participant_meaning_changed, AuthoredLabel, AuthoredLabelMap, EpisodeLabelProjection,
    LabelProjection, LabelTarget, SpeakerMeaning, UtteranceIdentity,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sqlx::{PgConnection, Postgres, Row, Transaction};
use std::collections::{BTreeMap, BTreeSet};

struct CurrentTurn {
    id: i64,
    target: Option<LabelTarget>,
    label: String,
    slot: Option<i64>,
    meaning: SpeakerMeaning,
}

async fn current_turns(
    connection: &mut PgConnection,
    account: &str,
    episode: Option<i64>,
    utterance_ids: Option<&[i64]>,
) -> Result<Vec<CurrentTurn>> {
    let identity =
        speaker_identity_join(SpeakerUtteranceAlias::U, SpeakerMemoryScope::Episode("$2"));
    let fence = super::voice_identity::source_fence(connection).await?;
    let sql = format!(
        "SELECT u.id,speaker_identity.voice_profile_id,speaker_identity.speaker_cluster_id,\
        speaker_identity.speaker_label,speaker_identity.slot_ordinal,speaker_identity.owner_source,\
        speaker_identity.person_id,speaker_identity.person_name \
        FROM utterances u JOIN speaker_observations o ON o.account_id=u.account_id \
            AND o.id=u.speaker_observation_id {identity} \
        WHERE u.account_id=$1 AND ($3::bigint[] IS NULL OR u.id=ANY($3)) \
            AND NOT ({fence}) \
            AND ($2::bigint IS NULL OR EXISTS(SELECT 1 FROM episode_members member \
                WHERE member.account_id=u.account_id AND member.episode_id=$2 \
                AND member.record_type='utterance' AND member.record_id=u.id)) \
        ORDER BY o.started_at,u.id"
    );
    sqlx::query(sqlx::AssertSqlSafe(sql))
        .bind(account)
        .bind(episode)
        .bind(utterance_ids)
        .fetch_all(connection)
        .await?
        .into_iter()
        .map(|row| {
            let profile: Option<i64> = row.try_get("voice_profile_id")?;
            let cluster: Option<i64> = row.try_get("speaker_cluster_id")?;
            Ok(CurrentTurn {
                id: row.try_get("id")?,
                target: profile
                    .map(LabelTarget::Profile)
                    .or_else(|| cluster.map(LabelTarget::Cluster)),
                label: row.try_get("speaker_label")?,
                slot: row.try_get("slot_ordinal")?,
                meaning: SpeakerMeaning {
                    owner: row.try_get("owner_source")?,
                    person_id: row.try_get("person_id")?,
                    name: row.try_get("person_name")?,
                },
            })
        })
        .collect()
}

fn slot_label(mut ordinal: i64) -> String {
    if ordinal < 0 {
        return "Speaker".into();
    }
    let mut letters = Vec::new();
    loop {
        letters.push(char::from(b'A' + (ordinal % 26) as u8));
        ordinal = ordinal / 26 - 1;
        if ordinal < 0 {
            break;
        }
    }
    format!("Speaker {}", letters.into_iter().rev().collect::<String>())
}

#[derive(Serialize, Deserialize)]
struct SemanticTransactionBaseline {
    initialized: bool,
    state: Vec<UtteranceIdentity>,
    revision: i64,
    refresh_status: Option<String>,
}

/// Initialize only missing semantic snapshots before an identity writer changes
/// the graph. Existing snapshots stay untouched. The ordinary account lock
/// serializes this with formation; bounded pages avoid loading the archive at once.
/// This is current presentation metadata, not a source or topology backfill.
pub(super) async fn initialize_account_semantics(
    tx: &mut Transaction<'_, Postgres>,
    account: &str,
) -> Result<()> {
    let mut after = -1_i64;
    loop {
        let ids: Vec<i64> = sqlx::query_scalar("SELECT e.id FROM episodes e LEFT JOIN episode_identity_presentations p ON p.account_id=e.account_id AND p.episode_id=e.id WHERE e.account_id=$1 AND e.id>$2 AND NOT coalesce(p.semantic_initialized,false) ORDER BY e.id LIMIT 64")
            .bind(account).bind(after).fetch_all(&mut **tx).await?;
        if ids.is_empty() {
            break;
        }
        for episode in ids {
            refresh_semantic_revision(tx, account, episode).await?;
            after = episode;
        }
    }
    Ok(())
}

/// Caller owns the normal account/activation lock ladder. Initializing an
/// existing memory must precede the first graph mutation. Later refreshes use
/// the committed snapshot, including an immutable transaction-entry baseline.
/// This coalesces A→B→C into one revision and A→B→A into no committed change.
pub(super) async fn refresh_semantic_revision(
    tx: &mut Transaction<'_, Postgres>,
    account: &str,
    episode: i64,
) -> Result<bool> {
    let current = current_turns(tx, account, Some(episode), None)
        .await?
        .into_iter()
        .map(|turn| UtteranceIdentity {
            utterance_id: turn.id,
            meaning: turn.meaning,
        })
        .collect::<Vec<_>>();
    sqlx::query("INSERT INTO episode_identity_presentations(account_id,episode_id) VALUES($1,$2) ON CONFLICT DO NOTHING")
        .bind(account).bind(episode).execute(&mut **tx).await?;
    let row = sqlx::query(
        "SELECT presentation.semantic_initialized,presentation.semantic_state::text,\
        presentation.semantic_transaction_baseline::text,\
        presentation.semantic_transaction_xid IS NOT DISTINCT FROM pg_current_xact_id() AS same_transaction,\
        episode.identity_revision,episode.identity_refresh_status \
        FROM episode_identity_presentations presentation JOIN episodes episode \
            ON episode.account_id=presentation.account_id AND episode.id=presentation.episode_id \
        WHERE presentation.account_id=$1 AND presentation.episode_id=$2 FOR UPDATE OF presentation,episode",
    )
    .bind(account)
    .bind(episode)
    .fetch_one(&mut **tx)
    .await?;
    let decode_error =
        || EnclaveError::Store("stored identity presentation state is invalid".into());
    let same_transaction: bool = row.try_get("same_transaction")?;
    let baseline: SemanticTransactionBaseline = if same_transaction {
        serde_json::from_str(&row.try_get::<String, _>("semantic_transaction_baseline")?)
            .map_err(|_| decode_error())?
    } else {
        let initialized: bool = row.try_get("semantic_initialized")?;
        SemanticTransactionBaseline {
            // First initialization is the pre-mutation baseline for every
            // subsequent refresh in this transaction, without a fake upgrade.
            initialized: true,
            state: if initialized {
                serde_json::from_str(&row.try_get::<String, _>("semantic_state")?)
                    .map_err(|_| decode_error())?
            } else {
                current.clone()
            },
            revision: row.try_get("identity_revision")?,
            refresh_status: row.try_get("identity_refresh_status")?,
        }
    };
    let changed = baseline.initialized && participant_meaning_changed(&baseline.state, &current);
    let revision = baseline
        .revision
        .checked_add(i64::from(changed))
        .ok_or_else(|| EnclaveError::Store("identity revision is exhausted".into()))?;
    let previous_revision: i64 = row.try_get("identity_revision")?;
    if revision != previous_revision {
        // updated_at and archive_revision describe authored/source topology.
        // Restoring a transaction-entry value remains invisible until commit.
        sqlx::query("UPDATE episodes SET identity_revision=$3,identity_refresh_status=$4 WHERE account_id=$1 AND id=$2")
            .bind(account).bind(episode).bind(revision)
            .bind(if changed { Some("queued") } else { baseline.refresh_status.as_deref() })
            .execute(&mut **tx).await?;
    }
    let state = serde_json::to_string(&current)
        .map_err(|_| EnclaveError::Store("identity presentation state cannot be encoded".into()))?;
    let baseline = serde_json::to_string(&baseline).map_err(|_| {
        EnclaveError::Store("identity transaction baseline cannot be encoded".into())
    })?;
    sqlx::query("UPDATE episode_identity_presentations SET semantic_initialized=true,semantic_state=$3::jsonb,\
        semantic_transaction_xid=pg_current_xact_id(),semantic_transaction_baseline=$4::jsonb \
        WHERE account_id=$1 AND episode_id=$2 AND (NOT semantic_initialized OR semantic_state IS DISTINCT FROM $3::jsonb \
        OR semantic_transaction_xid IS DISTINCT FROM pg_current_xact_id())")
        .bind(account).bind(episode).bind(state).bind(baseline).execute(&mut **tx).await?;
    Ok(revision != previous_revision)
}

/// Freeze with the same read snapshot as the provider's actual utterance input.
/// Before a memory exists, first-speech local slots keep anonymous voices apart.
pub(super) async fn authored_labels(
    connection: &mut PgConnection,
    account: &str,
    episode: Option<i64>,
    utterance_ids: &[i64],
) -> Result<AuthoredLabelMap> {
    let rows = current_turns(connection, account, episode, Some(utterance_ids)).await?;
    Ok(labels_for_turns(rows))
}

/// One temporary namespace for a provider request spanning multiple memories.
/// Local memory slot ordinals are deliberately not shared between those memories.
pub(super) async fn authoring_context(
    connection: &mut PgConnection,
    account: &str,
    utterance_ids: &[i64],
    episode_ids: &[i64],
) -> Result<AuthoredLabelMap> {
    let mut ids = utterance_ids.iter().copied().collect::<BTreeSet<_>>();
    let members: Vec<i64> = sqlx::query_scalar("SELECT DISTINCT record_id FROM episode_members WHERE account_id=$1 AND episode_id=ANY($2) AND record_type='utterance' ORDER BY record_id LIMIT 80001")
        .bind(account).bind(episode_ids).fetch_all(&mut *connection).await?;
    ids.extend(members);
    if ids.len() > 80_000 {
        return Err(EnclaveError::Store(
            "authoring identity context exceeds its source bound".into(),
        ));
    }
    let mut rows = current_turns(
        connection,
        account,
        None,
        Some(&ids.into_iter().collect::<Vec<_>>()),
    )
    .await?;
    for row in &mut rows {
        row.slot = None;
        if !row.meaning.owner && row.meaning.name.is_none() {
            row.label = "Speaker".into();
        }
    }
    Ok(labels_for_turns(rows))
}

pub(super) fn apply_authoring_context(
    utterances: &mut [crate::persistence::SummaryUtterance],
    labels: &AuthoredLabelMap,
) {
    let by_id = labels
        .labels
        .iter()
        .flat_map(|label| label.utterance_ids.iter().map(move |id| (*id, label)))
        .collect::<BTreeMap<_, _>>();
    for utterance in utterances {
        if let Some(label) = by_id.get(&utterance.id) {
            utterance.speaker_label.clone_from(&label.label);
            utterance.authored_label = Some(AuthoredLabel {
                label: label.label.clone(),
                target: label.target.clone(),
                fallback_label: label.fallback_label.clone(),
                utterance_ids: vec![utterance.id],
            });
        }
    }
}

/// Attach the same frozen graph labels that the provider will actually see.
pub(super) async fn prepare_authoring_utterances(
    connection: &mut PgConnection,
    account: &str,
    utterances: &mut [crate::persistence::SummaryUtterance],
) -> Result<()> {
    let ids = utterances.iter().map(|row| row.id).collect::<Vec<_>>();
    let labels = authoring_context(connection, account, &ids, &[]).await?;
    apply_authoring_context(utterances, &labels);
    Ok(())
}

/// New title/summary/actions share this attempt's namespace. Retained minute
/// buckets keep their existing maps; only incoming, nonempty buckets replace it.
pub(super) async fn save_formation_labels(
    tx: &mut Transaction<'_, Postgres>,
    account: &str,
    episode: i64,
    authored: &AuthoredLabelMap,
    new_minutes: &[crate::persistence::MinuteBucket],
) -> Result<()> {
    let members: Vec<i64> = sqlx::query_scalar("SELECT record_id FROM episode_members WHERE account_id=$1 AND episode_id=$2 AND record_type='utterance'")
        .bind(account).bind(episode).fetch_all(&mut **tx).await?;
    let members = members.into_iter().collect::<BTreeSet<_>>();
    let mut labels = authored.clone();
    for label in &mut labels.labels {
        label.utterance_ids.retain(|id| members.contains(id));
    }
    labels
        .labels
        .retain(|label| !label.utterance_ids.is_empty());
    let labels = serde_json::to_value(labels)?;
    let minutes = new_minutes
        .iter()
        .filter(|minute| !minute.gist.trim().is_empty())
        .map(|minute| (minute.start.clone(), labels.clone()))
        .collect::<serde_json::Map<_, _>>();
    sqlx::query("INSERT INTO episode_identity_presentations(account_id,episode_id) VALUES($1,$2) ON CONFLICT DO NOTHING")
        .bind(account).bind(episode).execute(&mut **tx).await?;
    sqlx::query("UPDATE episode_identity_presentations SET timeline_labels=$3::jsonb,action_labels=$3::jsonb,minute_labels=(SELECT coalesce(jsonb_object_agg(entry.key,entry.value),'{}'::jsonb) FROM jsonb_each(minute_labels||$4::jsonb) entry WHERE EXISTS(SELECT 1 FROM episodes e CROSS JOIN jsonb_array_elements(e.minute_summaries) minute WHERE e.account_id=$1 AND e.id=$2 AND minute->>'start'=entry.key)) WHERE account_id=$1 AND episode_id=$2")
        .bind(account).bind(episode).bind(labels.to_string()).bind(Value::Object(minutes).to_string()).execute(&mut **tx).await?;
    Ok(())
}

fn labels_for_turns(rows: Vec<CurrentTurn>) -> AuthoredLabelMap {
    let mut local_slots = BTreeMap::<LabelTarget, i64>::new();
    let mut used_ordinals = rows
        .iter()
        .filter_map(|row| row.slot)
        .collect::<BTreeSet<_>>();
    let mut next_ordinal = 0;
    let mut labels = BTreeMap::<(String, LabelTarget), AuthoredLabel>::new();
    for row in rows {
        let Some(target) = row.target else { continue };
        let fallback = if let Some(ordinal) = row.slot {
            slot_label(ordinal)
        } else if row.label == "Speaker" {
            let ordinal = *local_slots.entry(target.clone()).or_insert_with(|| {
                while used_ordinals.contains(&next_ordinal) {
                    next_ordinal += 1;
                }
                used_ordinals.insert(next_ordinal);
                next_ordinal
            });
            slot_label(ordinal)
        } else {
            "Speaker".into()
        };
        let label = if row.label == "Speaker" {
            fallback.clone()
        } else {
            row.label
        };
        let entry = labels
            .entry((label.clone(), target.clone()))
            .or_insert_with(|| AuthoredLabel {
                label,
                target,
                fallback_label: fallback,
                utterance_ids: Vec::new(),
            });
        entry.utterance_ids.push(row.id);
    }
    AuthoredLabelMap {
        labels: labels.into_values().collect(),
    }
}

/// Resolve by surviving structured authoring anchors under the caller's current
/// read snapshot. The canonical graph owns biometric/retention/name authority;
/// this resolver adds the same deletion fence, never a second identity policy.
/// Retired profile IDs alone never authorize a name after source erasure.
#[cfg(test)]
pub(super) async fn resolve_labels(
    connection: &mut PgConnection,
    account: &str,
    episode: i64,
    authored: &AuthoredLabelMap,
) -> Result<LabelProjection> {
    let ids = authored
        .labels
        .iter()
        .flat_map(|entry| entry.utterance_ids.iter().copied())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    let current = current_turns(connection, account, Some(episode), Some(&ids))
        .await?
        .into_iter()
        .map(|turn| (turn.id, turn.label))
        .collect::<BTreeMap<_, _>>();
    Ok(resolve_with_current(authored, &current))
}

fn resolve_with_current(
    authored: &AuthoredLabelMap,
    current: &BTreeMap<i64, String>,
) -> LabelProjection {
    let mut labels_by_target = BTreeMap::<LabelTarget, BTreeSet<String>>::new();
    for entry in &authored.labels {
        let labels = labels_by_target.entry(entry.target.clone()).or_default();
        for id in &entry.utterance_ids {
            if let Some(label) = current.get(id) {
                labels.insert(label.clone());
            }
        }
    }
    let mut resolved = BTreeMap::new();
    for (target, labels) in labels_by_target {
        if labels.is_empty() {
            continue;
        }
        resolved.insert(
            target,
            if labels.len() == 1 {
                labels.into_iter().next().unwrap()
            } else {
                "Speaker".into()
            },
        );
    }
    LabelProjection::new(authored, &resolved)
}

/// Load and resolve all authored blocks in the caller's consistent read snapshot.
pub(super) async fn episode_presentation(
    connection: &mut PgConnection,
    account: &str,
    episode: i64,
) -> Result<EpisodeLabelProjection> {
    episode_presentation_in_context(connection, account, episode, None).await
}

async fn unmapped_episode_context(
    connection: &mut PgConnection,
    account: &str,
    episode: i64,
) -> Result<EpisodeLabelProjection> {
    let raw: Option<String> = sqlx::query_scalar("SELECT jsonb_build_object('title',title,'summary',summary,'action_items',action_items,'minute_summaries',minute_summaries)::text FROM episodes WHERE account_id=$1 AND id=$2")
        .bind(account).bind(episode).fetch_optional(&mut *connection).await?;
    let raw: Value = serde_json::from_str(raw.as_deref().unwrap_or("{}"))?;
    let neutral = LabelProjection::unmapped_context(&raw);
    let minutes = raw
        .get("minute_summaries")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|minute| minute.get("start").and_then(Value::as_str))
        .map(|start| (start.to_owned(), neutral.clone()))
        .collect();
    Ok(EpisodeLabelProjection {
        timeline: neutral.clone(),
        actions: neutral.clone(),
        brief: neutral,
        minutes,
    })
}

pub(super) async fn episode_presentation_in_context(
    connection: &mut PgConnection,
    account: &str,
    episode: i64,
    namespace: Option<&AuthoredLabelMap>,
) -> Result<EpisodeLabelProjection> {
    let Some(row) = sqlx::query("SELECT timeline_labels::text,minute_labels::text,action_labels::text,brief_labels::text FROM episode_identity_presentations WHERE account_id=$1 AND episode_id=$2")
        .bind(account).bind(episode).fetch_optional(&mut *connection).await? else {
        return if namespace.is_some() {
            unmapped_episode_context(connection, account, episode).await
        } else { Ok(EpisodeLabelProjection::default()) };
    };
    let decode = |name| -> Result<AuthoredLabelMap> {
        let mut map = decode_labels(serde_json::from_str(&row.try_get::<String, _>(name)?)?)?;
        if namespace.is_some() {
            for label in &mut map.labels {
                label.fallback_label = "Speaker".into();
            }
        }
        Ok(map)
    };
    let timeline = decode("timeline_labels")?;
    let actions = decode("action_labels")?;
    let brief = decode("brief_labels")?;
    let mut stored: BTreeMap<String, AuthoredLabelMap> =
        serde_json::from_str(&row.try_get::<String, _>("minute_labels")?)
            .map_err(|_| EnclaveError::Store("stored minute authoring maps are invalid".into()))?;
    if namespace.is_some() {
        for map in stored.values_mut() {
            for label in &mut map.labels {
                label.fallback_label = "Speaker".into();
            }
        }
    }
    // Resolve the union once per memory, not once per minute bucket.
    let ids = [&timeline, &actions, &brief]
        .into_iter()
        .chain(stored.values())
        .flat_map(|map| {
            map.labels
                .iter()
                .flat_map(|label| label.utterance_ids.iter().copied())
        })
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    let namespace_by_id = namespace.map(|map| {
        map.labels
            .iter()
            .flat_map(|label| {
                label
                    .utterance_ids
                    .iter()
                    .map(move |id| (*id, label.label.as_str()))
            })
            .collect::<BTreeMap<_, _>>()
    });
    let current = current_turns(connection, account, Some(episode), Some(&ids))
        .await?
        .into_iter()
        .map(|turn| {
            let label = namespace_by_id.as_ref().map_or(turn.label, |map| {
                map.get(&turn.id).copied().unwrap_or("Speaker").to_owned()
            });
            (turn.id, label)
        })
        .collect();
    let mut projection = EpisodeLabelProjection {
        timeline: resolve_with_current(&timeline, &current),
        actions: resolve_with_current(&actions, &current),
        brief: resolve_with_current(&brief, &current),
        minutes: stored
            .iter()
            .map(|(start, map)| (start.clone(), resolve_with_current(map, &current)))
            .collect(),
    };
    if namespace.is_some() {
        let unmapped = unmapped_episode_context(connection, account, episode).await?;
        if timeline.is_empty() {
            projection.timeline = unmapped.timeline;
        }
        if actions.is_empty() {
            projection.actions = unmapped.actions;
        }
        if brief.is_empty() {
            projection.brief = unmapped.brief;
        }
        for (start, neutral) in unmapped.minutes {
            if stored.get(&start).is_none_or(AuthoredLabelMap::is_empty) {
                projection.minutes.insert(start, neutral);
            }
        }
    }
    Ok(projection)
}

pub(super) fn decode_labels(value: Value) -> Result<AuthoredLabelMap> {
    serde_json::from_value(value)
        .map_err(|_| EnclaveError::Store("stored authoring label map is invalid".into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn authoring_slots_only_count_anonymous_voices_without_reservations() {
        let rows = [
            (1, "Me", None),
            (2, "Sam", None),
            (3, "Speaker", None),
            (4, "Speaker", None),
            (5, "Taylor", Some(7)),
        ]
        .into_iter()
        .map(|(id, label, slot)| CurrentTurn {
            id,
            target: Some(LabelTarget::Cluster(id)),
            label: label.into(),
            slot,
            meaning: SpeakerMeaning::default(),
        })
        .collect();
        let labels = labels_for_turns(rows);
        let by_id = labels
            .labels
            .iter()
            .map(|entry| (entry.utterance_ids[0], entry))
            .collect::<BTreeMap<_, _>>();
        assert_eq!(
            by_id[&3].label, "Speaker A",
            "owner and named voices must not consume anonymous authoring letters"
        );
        assert_eq!(by_id[&4].label, "Speaker B");
        assert_eq!(by_id[&5].fallback_label, "Speaker H");
        let mixed = labels_for_turns(vec![
            CurrentTurn {
                id: 6,
                target: Some(LabelTarget::Cluster(6)),
                label: "Speaker A".into(),
                slot: Some(0),
                meaning: SpeakerMeaning::default(),
            },
            CurrentTurn {
                id: 7,
                target: Some(LabelTarget::Cluster(7)),
                label: "Speaker".into(),
                slot: None,
                meaning: SpeakerMeaning::default(),
            },
        ]);
        assert_eq!(
            mixed
                .labels
                .iter()
                .find(|entry| entry.utterance_ids == [7])
                .unwrap()
                .label,
            "Speaker B",
            "temporary authoring letters must not collide with a reserved slot"
        );
        let erased = LabelProjection::new(&labels, &BTreeMap::new());
        assert_eq!(
            erased.text("Me and Sam spoke to Taylor."),
            "Speaker and Sam spoke to Taylor.",
            "withdrawn owner tokens use generic Speaker; already named prose remains authored history"
        );
    }
    async fn seed_presentation(repo: &super::super::PostgresPersistence, account: &str) {
        for id in 1..=2 {
            super::super::voice_identity::tests::seed_voice_observation(
                repo,
                account,
                "session",
                &format!("event-{id}"),
                id,
                id,
            )
            .await;
            super::super::voice_identity::tests::seed_voice_memory(repo, account, id, 1).await;
        }
        sqlx::query("INSERT INTO people(account_id,id,display_name,status) VALUES($1,20,'Sarah','identified'),($1,21,'Ana','identified'),($1,22,'Bao','identified')")
            .bind(account).execute(repo.pool()).await.unwrap();
    }
    async fn revision(tx: &mut Transaction<'_, Postgres>, account: &str) -> (i64, Option<String>) {
        sqlx::query_as("SELECT identity_revision,identity_refresh_status FROM episodes WHERE account_id=$1 AND id=1")
            .bind(account).fetch_one(&mut **tx).await.unwrap()
    }
    async fn bind_person(
        tx: &mut Transaction<'_, Postgres>,
        account: &str,
        cluster: i64,
        person: i64,
    ) {
        sqlx::query("UPDATE speaker_clusters SET person_id=$3,attribution_state='person_bound' WHERE account_id=$1 AND id=$2")
            .bind(account).bind(cluster).bind(person).execute(&mut **tx).await.unwrap();
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
        fixture.base.pool().close().await;
    }

    #[tokio::test]
    async fn identity_presentation_transaction_baseline_coalesces_only_committed_participant_changes(
    ) {
        let Some(fixture) = super::super::tests::test_persistence().await else {
            return;
        };
        let repo = &fixture.persistence;
        let account = "presentation-transactions";
        seed_presentation(repo, account).await;
        sqlx::query("DELETE FROM episode_members WHERE account_id=$1 AND episode_id=1 AND record_type='utterance' AND record_id=2")
            .bind(account).execute(repo.pool()).await.unwrap();
        let mut tx = repo.pool().begin().await.unwrap();
        assert!(super::super::voice_identity::lock_account(&mut tx, account)
            .await
            .unwrap());
        let before = revision(&mut tx, account).await;
        assert!(
            !refresh_semantic_revision(&mut tx, account, 1)
                .await
                .unwrap(),
            "initial semantic snapshot must not manufacture an identity upgrade"
        );
        sqlx::query("INSERT INTO episode_members(account_id,episode_id,record_type,record_id) VALUES($1,1,'utterance',2)")
            .bind(account).execute(&mut *tx).await.unwrap();
        assert!(!refresh_semantic_revision(&mut tx, account, 1)
            .await
            .unwrap());
        bind_person(&mut tx, account, 2, 20).await;
        refresh_semantic_revision(&mut tx, account, 1)
            .await
            .unwrap();
        assert_eq!(revision(&mut tx, account).await, before,
            "a source added and attributed within one transaction is not an existing participant upgrade");
        tx.commit().await.unwrap();

        let topology_sql = "SELECT jsonb_build_array(to_jsonb(e)-'identity_revision'-'identity_refresh_status',(SELECT jsonb_agg(to_jsonb(u) ORDER BY u.id) FROM utterances u WHERE u.account_id=e.account_id),(SELECT jsonb_agg(to_jsonb(m) ORDER BY m.record_id) FROM episode_members m WHERE m.account_id=e.account_id AND m.episode_id=e.id),(SELECT revision FROM memory_archive_state a WHERE a.account_id=e.account_id))::text FROM episodes e WHERE e.account_id=$1 AND e.id=1";
        let topology: String = sqlx::query_scalar(topology_sql)
            .bind(account)
            .fetch_one(repo.pool())
            .await
            .unwrap();
        let mut tx = repo.pool().begin().await.unwrap();
        assert!(super::super::voice_identity::lock_account(&mut tx, account)
            .await
            .unwrap());
        bind_person(&mut tx, account, 2, 21).await;
        assert!(refresh_semantic_revision(&mut tx, account, 1)
            .await
            .unwrap());
        assert_eq!(revision(&mut tx, account).await.0, before.0 + 1);
        bind_person(&mut tx, account, 2, 20).await;
        refresh_semantic_revision(&mut tx, account, 1)
            .await
            .unwrap();
        assert_eq!(revision(&mut tx, account).await, before,
            "A to B to A within one transaction must preserve the committed revision and refresh state");
        tx.commit().await.unwrap();

        let mut tx = repo.pool().begin().await.unwrap();
        assert!(super::super::voice_identity::lock_account(&mut tx, account)
            .await
            .unwrap());
        bind_person(&mut tx, account, 2, 21).await;
        refresh_semantic_revision(&mut tx, account, 1)
            .await
            .unwrap();
        bind_person(&mut tx, account, 2, 22).await;
        refresh_semantic_revision(&mut tx, account, 1)
            .await
            .unwrap();
        assert_eq!(
            revision(&mut tx, account).await,
            (before.0 + 1, Some("queued".into())),
            "multiple lasting participant changes in one transaction must advance identity once"
        );
        tx.commit().await.unwrap();
        assert_eq!(sqlx::query_scalar::<_, String>(topology_sql).bind(account).fetch_one(repo.pool()).await.unwrap(),topology,
            "identity presentation must preserve authored bytes, IDs, source times, membership and archive revision");
        cleanup(fixture).await;
    }

    #[tokio::test]
    async fn identity_presentation_resolves_original_turn_anchors_with_tenant_and_erasure_fences() {
        let Some(fixture) = super::super::tests::test_persistence().await else {
            return;
        };
        let repo = &fixture.persistence;
        let account = "presentation-anchors";
        seed_presentation(repo, account).await;
        let mut tx = repo.pool().begin().await.unwrap();
        assert!(super::super::voice_identity::lock_account(&mut tx, account)
            .await
            .unwrap());
        super::super::speaker_identity::refresh_episode_speaker_projections(
            &mut tx,
            account,
            &[super::super::speaker_identity::SpeakerProjectionTarget::current(1)],
            &[],
        )
        .await
        .unwrap();
        let map = authored_labels(&mut tx, account, Some(1), &[1, 2])
            .await
            .unwrap();
        let map = decode_labels(serde_json::to_value(&map).unwrap()).unwrap();
        assert_eq!(map.labels.len(), 2);
        let raw = "Speaker A asked Speaker B to call Sarah from accounting.";
        bind_person(&mut tx, account, 1, 20).await;
        assert_eq!(resolve_labels(&mut tx, account, 1, &map).await.unwrap().text(raw),
            "Sarah asked Speaker B to call Sarah from accounting.",
            "current names must resolve from exact retained authoring turns without relabelling mentions");
        // Follow the retained turn after its current cluster assignment changes.
        bind_person(&mut tx, account, 2, 21).await;
        sqlx::query("UPDATE speaker_observations SET cluster_id=2 WHERE account_id=$1 AND id=1")
            .bind(account)
            .execute(&mut *tx)
            .await
            .unwrap();
        assert_eq!(resolve_labels(&mut tx, account, 1, &map).await.unwrap().text(raw),
            "Ana asked Ana to call Sarah from accounting.",
            "retained turn anchors must follow current assignment instead of a retired graph target");
        sqlx::query("DELETE FROM utterances WHERE account_id=$1 AND id=1")
            .bind(account)
            .execute(&mut *tx)
            .await
            .unwrap();
        assert_eq!(
            resolve_labels(&mut tx, account, 1, &map)
                .await
                .unwrap()
                .text(raw),
            "Speaker A asked Ana to call Sarah from accounting.",
            "erased authoring anchors must fall back without resurrecting their old person"
        );
        tx.commit().await.unwrap();
        seed_presentation(repo, "presentation-other-tenant").await;
        let mut tx = repo.pool().begin().await.unwrap();
        let other_map = AuthoredLabelMap {
            labels: vec![AuthoredLabel {
                label: "Speaker Z".into(),
                target: LabelTarget::Cluster(999),
                fallback_label: "Speaker Z".into(),
                utterance_ids: vec![999],
            }],
        };
        // A real foreign turn exists, but its ID is absent from this account.
        sqlx::query(
            "UPDATE utterances SET id=999 WHERE account_id='presentation-other-tenant' AND id=1",
        )
        .execute(&mut *tx)
        .await
        .unwrap();
        sqlx::query("UPDATE episode_members SET record_id=999 WHERE account_id='presentation-other-tenant' AND record_type='utterance' AND record_id=1")
            .execute(&mut *tx).await.unwrap();
        bind_person(&mut tx, "presentation-other-tenant", 1, 20).await;
        assert_eq!(
            resolve_labels(&mut tx, account, 1, &other_map)
                .await
                .unwrap()
                .text("Speaker Z spoke"),
            "Speaker Z spoke",
            "foreign authoring anchors must never resolve another account's person"
        );
        tx.rollback().await.unwrap();
        cleanup(fixture).await;
    }
}
