//! Canonical current speaker presentation and deletion-fenced, stable memory slots.
use super::{
    activation::lock_activation_contract_key_share_if_installed, advisory_transaction_lock,
    allocate_content_id, current_schema_relation_exists, PostgresPersistence,
};
use crate::error::{EnclaveError, Result};
use serde_json::{json, Value};
use sqlx::{PgConnection, Postgres, Row, Transaction};
use std::collections::{BTreeMap, BTreeSet, HashMap};

pub(super) const SPEAKER_PROJECTION_VERSION: i64 = 2;
pub(super) const SPEAKER_PREPARE_PAGE_SIZE: usize = 128;
#[derive(Clone, Copy)]
pub(super) enum SpeakerUtteranceAlias {
    U,
    Utterance,
}
#[derive(Clone, Copy)]
pub(super) enum SpeakerMemoryScope {
    None,
    LatestActive,
    Episode(&'static str),
}

pub(super) fn speaker_identity_join(
    utterance: SpeakerUtteranceAlias,
    memory: SpeakerMemoryScope,
) -> String {
    let alias = match utterance {
        SpeakerUtteranceAlias::U => "u",
        SpeakerUtteranceAlias::Utterance => "utterance",
    };
    let memory = match memory {
        SpeakerMemoryScope::None => "NULL::bigint".to_owned(),
        SpeakerMemoryScope::Episode(expression) => format!("({expression})::bigint"),
        SpeakerMemoryScope::LatestActive => format!("(SELECT e.id FROM active_episode_members member JOIN episodes e ON e.account_id=member.account_id AND e.id=member.episode_id WHERE member.account_id={alias}.account_id AND member.record_type='utterance' AND member.record_id={alias}.id AND e.substance<>'none' ORDER BY e.started_at DESC,e.id DESC LIMIT 1)"),
    };
    include_str!("speaker_identity.sql")
        .replace("__UTTERANCE__", alias)
        .replace("__MEMORY__", &memory)
        .replace(
            "__EMBEDDING_SPACE__",
            crate::cp::voice_memory::EMBEDDING_SPACE,
        )
        .replace(
            "__SCORER_VERSION__",
            &crate::cp::voice_quality::SCORER_VERSION.to_string(),
        )
}

/// Static aliases only. Legacy participants are eligible only when no assigned
/// observation exists and no graph-derived participant has ever been recorded.
pub(super) fn legacy_participant_eligible_sql(
    episode_alias: &'static str,
    participant_alias: &'static str,
) -> String {
    let e = episode_alias;
    let p = participant_alias;
    format!("{p}.state='active' AND {p}.derivation_version<2 AND NOT EXISTS(SELECT 1 FROM episode_participants current WHERE current.account_id={e}.account_id AND current.episode_id={e}.id AND current.derivation_version>=2) AND NOT EXISTS(SELECT 1 FROM episode_members legacy_member JOIN utterances legacy_utterance ON legacy_utterance.account_id=legacy_member.account_id AND legacy_utterance.id=legacy_member.record_id JOIN speaker_observations legacy_observation ON legacy_observation.account_id=legacy_utterance.account_id AND legacy_observation.id=legacy_utterance.speaker_observation_id WHERE legacy_member.account_id={e}.account_id AND legacy_member.episode_id={e}.id AND legacy_member.record_type='utterance')")
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub(super) enum SpeakerVoiceKey {
    Profile(i64),
    Cluster(i64),
}
#[derive(Clone, Debug)]
pub(super) struct SpeakerSlotReservation {
    pub episode_id: i64,
    pub id: i64,
    pub key: Option<SpeakerVoiceKey>,
    pub ordinal: i64,
}
#[derive(Clone, Debug)]
pub(super) struct SpeakerProjectionTarget {
    pub episode_id: i64,
    pub inherit_from: Vec<i64>,
}
impl SpeakerProjectionTarget {
    pub fn current(episode_id: i64) -> Self {
        Self {
            episode_id,
            inherit_from: Vec::new(),
        }
    }
}
#[derive(Default, Debug)]
pub(super) struct SpeakerProjectionRefresh {
    pub changed_episode_ids: Vec<i64>,
    pub inserted_slots: u64,
    pub superseded_slots: u64,
}
#[derive(Default, Debug)]
pub(super) struct SpeakerPreparationPage {
    pub prepared_episode_ids: Vec<i64>,
    pub has_more: bool,
}

pub(super) async fn snapshot_speaker_slot_reservations(
    tx: &mut Transaction<'_, Postgres>,
    account_id: &str,
    episode_ids: &[i64],
) -> Result<Vec<SpeakerSlotReservation>> {
    let rows=sqlx::query("SELECT episode_id,id,voice_profile_id,speaker_cluster_id,slot_ordinal FROM episode_speaker_slots WHERE account_id=$1 AND episode_id=ANY($2) ORDER BY episode_id,slot_ordinal,id").bind(account_id).bind(episode_ids).fetch_all(&mut **tx).await?;
    rows.into_iter()
        .map(|row| {
            let profile: Option<i64> = row.try_get("voice_profile_id")?;
            let cluster: Option<i64> = row.try_get("speaker_cluster_id")?;
            Ok(SpeakerSlotReservation {
                episode_id: row.try_get("episode_id")?,
                id: row.try_get("id")?,
                key: profile
                    .map(SpeakerVoiceKey::Profile)
                    .or_else(|| cluster.map(SpeakerVoiceKey::Cluster)),
                ordinal: row.try_get("slot_ordinal")?,
            })
        })
        .collect()
}

#[derive(Clone, Debug)]
struct Evidence {
    utterance_id: i64,
    started_ms: i64,
    key: Option<SpeakerVoiceKey>,
    cluster_id: Option<i64>,
    person_id: Option<i64>,
    has_accepted_name: bool,
    participant_key: Option<String>,
    attribution: Option<String>,
    owner: bool,
}
async fn evidence(
    connection: &mut PgConnection,
    account: &str,
    episode: i64,
) -> Result<Vec<Evidence>> {
    let identity =
        speaker_identity_join(SpeakerUtteranceAlias::U, SpeakerMemoryScope::Episode("$2"));
    let sql=format!("SELECT u.id,floor(extract(epoch FROM coalesce(o.started_at,a.started_at+u.start_offset_seconds*interval '1 second'))*1000)::bigint AS started_ms,speaker_identity.* FROM episode_members m JOIN utterances u ON u.account_id=m.account_id AND u.id=m.record_id JOIN audio_segments a ON a.account_id=u.account_id AND a.id=u.audio_segment_id LEFT JOIN speaker_observations o ON o.account_id=u.account_id AND o.id=u.speaker_observation_id {identity} WHERE m.account_id=$1 AND m.episode_id=$2 AND m.record_type='utterance' AND o.id IS NOT NULL ORDER BY started_ms,u.id");
    sqlx::query(sqlx::AssertSqlSafe(sql))
        .bind(account)
        .bind(episode)
        .fetch_all(connection)
        .await?
        .into_iter()
        .map(|row| {
            let profile: Option<i64> = row.try_get("voice_profile_id")?;
            let cluster: Option<i64> = row.try_get("speaker_cluster_id")?;
            Ok(Evidence {
                utterance_id: row.try_get("id")?,
                started_ms: row.try_get("started_ms")?,
                key: profile
                    .map(SpeakerVoiceKey::Profile)
                    .or_else(|| cluster.map(SpeakerVoiceKey::Cluster)),
                cluster_id: cluster,
                person_id: row.try_get("person_id")?,
                has_accepted_name: row.try_get::<Option<String>, _>("person_name")?.is_some(),
                participant_key: row.try_get("participant_key")?,
                attribution: row.try_get("attribution_kind")?,
                owner: row.try_get("owner_source")?,
            })
        })
        .collect()
}

#[derive(Clone, Debug)]
struct VoiceGroup {
    key: SpeakerVoiceKey,
    aliases: BTreeSet<i64>,
    first: (i64, i64),
    needs_slot: bool,
}
fn voice_groups(evidence: &[Evidence]) -> Vec<VoiceGroup> {
    let mut groups = BTreeMap::<SpeakerVoiceKey, VoiceGroup>::new();
    for row in evidence {
        let Some(key) = row.key else { continue };
        let group = groups.entry(key).or_insert_with(|| VoiceGroup {
            key,
            aliases: BTreeSet::new(),
            first: (row.started_ms, row.utterance_id),
            needs_slot: false,
        });
        group.first = group.first.min((row.started_ms, row.utterance_id));
        group.needs_slot |= !row.owner && !row.has_accepted_name;
        group.aliases.extend(row.cluster_id);
    }
    let mut groups = groups.into_values().collect::<Vec<_>>();
    groups.sort_by_key(|group| (group.first, group.key));
    groups
}
fn matches_group(reservation: &SpeakerSlotReservation, group: &VoiceGroup) -> bool {
    reservation.key == Some(group.key)
        || matches!(reservation.key,Some(SpeakerVoiceKey::Cluster(id)) if group.aliases.contains(&id))
}
#[derive(Clone, Debug)]
struct PlannedSlot {
    key: SpeakerVoiceKey,
    id: Option<i64>,
    ordinal: i64,
}
fn plan_slots(
    groups: &[VoiceGroup],
    current: &[SpeakerSlotReservation],
    inherited: &[SpeakerSlotReservation],
    parents: &[i64],
) -> Result<Vec<PlannedSlot>> {
    // Reserve applicable donor letters before assigning any new voice or
    // collision loser. Otherwise an earlier newcomer can steal a later A, or
    // a duplicate-A loser can steal an independently inherited B.
    let inherited_max = groups
        .iter()
        .filter(|group| !current.iter().any(|own| matches_group(own, group)))
        .filter_map(|group| {
            inherited
                .iter()
                .filter(|donor| parents.contains(&donor.episode_id) && matches_group(donor, group))
                .min_by_key(|donor| (donor.ordinal, donor.episode_id, donor.id))
                .map(|donor| donor.ordinal)
        })
        .max();
    let mut next = current
        .iter()
        .map(|r| r.ordinal)
        .chain(inherited_max)
        .max()
        .unwrap_or(-1)
        .checked_add(1)
        .ok_or_else(|| EnclaveError::Store("speaker slot ordinal overflow".into()))?;
    let mut used = BTreeSet::new();
    let mut result = Vec::new();
    for group in groups {
        let own = current
            .iter()
            .filter(|r| matches_group(r, group))
            .min_by_key(|r| (r.ordinal, r.id));
        let donor = inherited
            .iter()
            .filter(|r| parents.contains(&r.episode_id) && matches_group(r, group))
            .min_by_key(|r| (r.ordinal, r.episode_id, r.id));
        if !group.needs_slot && own.is_none() && donor.is_none() {
            continue;
        }
        if let Some(reservation) = own {
            if used.insert(reservation.ordinal) {
                result.push(PlannedSlot {
                    key: group.key,
                    id: Some(reservation.id),
                    ordinal: reservation.ordinal,
                });
                continue;
            }
        }
        let ordinal = if let Some(donor) = donor.filter(|r| {
            !used.contains(&r.ordinal) && !current.iter().any(|own| own.ordinal == r.ordinal)
        }) {
            donor.ordinal
        } else {
            while used.contains(&next) {
                next = next
                    .checked_add(1)
                    .ok_or_else(|| EnclaveError::Store("speaker slot ordinal overflow".into()))?;
            }
            let ordinal = next;
            next = next
                .checked_add(1)
                .ok_or_else(|| EnclaveError::Store("speaker slot ordinal overflow".into()))?;
            ordinal
        };
        used.insert(ordinal);
        next = next.max(
            ordinal
                .checked_add(1)
                .ok_or_else(|| EnclaveError::Store("speaker slot ordinal overflow".into()))?,
        );
        result.push(PlannedSlot {
            key: group.key,
            id: None,
            ordinal,
        });
    }
    Ok(result)
}

async fn account_writable(tx: &mut Transaction<'_, Postgres>, account: &str) -> Result<bool> {
    let active =
        sqlx::query_scalar::<_, String>("SELECT status FROM accounts WHERE id=$1 FOR UPDATE")
            .bind(account)
            .fetch_optional(&mut **tx)
            .await?
            .as_deref()
            == Some("active");
    if !active {
        return Ok(false);
    }
    Ok(!sqlx::query_scalar::<_,bool>("SELECT EXISTS(SELECT 1 FROM orphan_capture_erasure_operations WHERE account_id=$1 AND capture_upload_fenced)").bind(account).fetch_one(&mut **tx).await?)
}
async fn episode_fence_sql(tx: &mut Transaction<'_, Postgres>) -> Result<String> {
    let paged =
        current_schema_relation_exists(tx, "persistence_feature_episode_deletion_events").await?;
    if !paged
        && current_schema_relation_exists(tx, "persistence_feature_activation_contracts").await?
    {
        return Err(EnclaveError::Config(
            "speaker projection paged deletion inventory is missing".into(),
        ));
    }
    let paged_clause = if paged {
        "OR EXISTS(SELECT 1 FROM persistence_feature_episode_deletion_events planned JOIN episode_deletions deletion ON deletion.account_id=planned.account_id AND deletion.episode_id=planned.episode_id AND deletion.state='pending' WHERE planned.account_id=event.account_id AND (planned.event_id=event.event_id OR planned.event_id=coalesce(event.canonical_event_id,event.event_id) OR planned.root_event_id=coalesce(event.canonical_event_id,event.event_id)))"
    } else {
        ""
    };
    Ok(format!("NOT EXISTS(SELECT 1 FROM episode_deletions deletion WHERE deletion.account_id=e.account_id AND deletion.episode_id=e.id AND deletion.state='pending') AND NOT EXISTS(SELECT 1 FROM episode_members member JOIN utterances utterance ON utterance.account_id=member.account_id AND utterance.id=member.record_id JOIN speaker_observations observation ON observation.account_id=utterance.account_id AND observation.id=utterance.speaker_observation_id JOIN capture_events event ON event.account_id=observation.account_id AND (event.event_id=observation.event_id OR EXISTS(SELECT 1 FROM speaker_observation_sources source WHERE source.account_id=observation.account_id AND source.speaker_observation_id=observation.id AND source.event_id=event.event_id)) WHERE member.account_id=e.account_id AND member.episode_id=e.id AND member.record_type='utterance' AND (EXISTS(SELECT 1 FROM episode_deletions deletion WHERE deletion.account_id=event.account_id AND deletion.state='pending' AND (deletion.orphan_event_ids ? event.event_id OR deletion.orphan_event_ids ? coalesce(event.canonical_event_id,event.event_id))) OR EXISTS(SELECT 1 FROM orphan_capture_erasure_sessions erased WHERE erased.account_id=event.account_id AND erased.capture_session_id=event.capture_session_id) {paged_clause}))"))
}

// Cache invalidation only: bind the current source graph, actual reservations and
// actual participant projection. Unlike a version marker, this detects old writers
// appending members or deleting/replacing slots during a mixed release.
fn projection_signature_sql() -> &'static str {
    "encode(sha256(convert_to(jsonb_build_array(\
      (SELECT coalesce(jsonb_agg(jsonb_build_array(u.id,u.speaker_observation_id,o.started_at,o.cluster_id,o.person_id,o.direct_evidence_id,o.voice_profile_id,o.voice_sample_id,o.owner_evidence_id,c.voice_profile_id,c.person_id,c.attribution_state,c.owner,c.profile_updates_quarantined,c.channel_domain,v.person_id,v.status,v.sample_count,owner_evidence.status,owner_sample.accepted,op.status,op.display_name,cp.status,cp.display_name,vp.status,vp.display_name) ORDER BY u.id),'[]'::jsonb) FROM episode_members m JOIN utterances u ON u.account_id=m.account_id AND u.id=m.record_id LEFT JOIN speaker_observations o ON o.account_id=u.account_id AND o.id=u.speaker_observation_id LEFT JOIN speaker_clusters c ON c.account_id=o.account_id AND c.id=o.cluster_id LEFT JOIN voice_profiles v ON v.account_id=c.account_id AND v.id=coalesce(o.voice_profile_id,c.voice_profile_id) LEFT JOIN identity_evidence owner_evidence ON owner_evidence.account_id=o.account_id AND owner_evidence.id=o.owner_evidence_id LEFT JOIN voice_samples owner_sample ON owner_sample.account_id=o.account_id AND owner_sample.id=o.voice_sample_id LEFT JOIN people op ON op.account_id=o.account_id AND op.id=o.person_id LEFT JOIN people cp ON cp.account_id=c.account_id AND cp.id=c.person_id LEFT JOIN people vp ON vp.account_id=v.account_id AND vp.id=v.person_id WHERE m.account_id=e.account_id AND m.episode_id=e.id AND m.record_type='utterance'),\
      (SELECT coalesce(jsonb_agg(jsonb_build_array(owner_profile.id,owner_profile.channel_domain,owner_profile.status,owner_profile.sample_count,owner_profile.embedding_space,owner_profile.scorer_version) ORDER BY owner_profile.id),'[]'::jsonb) FROM voice_profiles owner_profile JOIN people owner ON owner.account_id=owner_profile.account_id AND owner.id=owner_profile.person_id AND owner.status='owner' WHERE owner_profile.account_id=e.account_id),\
      (SELECT coalesce(jsonb_agg(jsonb_build_array(s.id,s.voice_profile_id,s.speaker_cluster_id,s.slot_ordinal,s.status) ORDER BY s.id),'[]'::jsonb) FROM episode_speaker_slots s WHERE s.account_id=e.account_id AND s.episode_id=e.id),\
      (SELECT coalesce(jsonb_agg(jsonb_build_array(p.id,p.participant_key,p.person_id,p.speaker_slot_id,p.attribution_kind,p.state,p.derivation_version,p.source_claimed_name) ORDER BY p.id),'[]'::jsonb) FROM episode_participants p WHERE p.account_id=e.account_id AND p.episode_id=e.id)\
    )::text,'UTF8')),'hex')"
}
async fn signature(connection: &mut PgConnection, account: &str, episode: i64) -> Result<String> {
    let sql = format!(
        "SELECT {} FROM episodes e WHERE e.account_id=$1 AND e.id=$2",
        projection_signature_sql()
    );
    Ok(sqlx::query_scalar(sqlx::AssertSqlSafe(sql))
        .bind(account)
        .bind(episode)
        .fetch_one(connection)
        .await?)
}
async fn allocate_projection_id(
    tx: &mut Transaction<'_, Postgres>,
    account: &str,
    kind: &str,
) -> Result<i64> {
    let table = match kind {
        "episode_speaker_slot" => "episode_speaker_slots",
        "episode_participant" => "episode_participants",
        _ => {
            return Err(EnclaveError::Store(
                "speaker projection id family is invalid".into(),
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
fn key_columns(key: SpeakerVoiceKey) -> (Option<i64>, Option<i64>) {
    match key {
        SpeakerVoiceKey::Profile(id) => (Some(id), None),
        SpeakerVoiceKey::Cluster(id) => (None, Some(id)),
    }
}
fn priority(kind: &str) -> u8 {
    match kind {
        "owner_voice" | "owner_source_role" | "direct_identity_evidence" => 3,
        "verified_voice" => 2,
        _ => 1,
    }
}

/// Caller owns the ordinary activation/account reconciliation lock ladder.
/// Identity ambiguity is presentation abstention, never a reason to roll back a
/// valid profile quarantine or sample-erasure transaction.
pub(super) async fn refresh_episode_speaker_projections(
    tx: &mut Transaction<'_, Postgres>,
    account_id: &str,
    targets: &[SpeakerProjectionTarget],
    inherited: &[SpeakerSlotReservation],
) -> Result<SpeakerProjectionRefresh> {
    let mut report = SpeakerProjectionRefresh::default();
    if targets.is_empty() || !account_writable(tx, account_id).await? {
        return Ok(report);
    }
    super::identity_presentation::initialize_account_semantics(tx, account_id).await?;
    let changed_domains = super::owner_voice::prepare_domains(tx, account_id).await?;
    let profile_ids:Vec<i64>=sqlx::query_scalar("SELECT DISTINCT o.voice_profile_id FROM episode_members m JOIN utterances u ON u.account_id=m.account_id AND u.id=m.record_id JOIN speaker_observations o ON o.account_id=u.account_id AND o.id=u.speaker_observation_id WHERE m.account_id=$1 AND m.episode_id=ANY($2::bigint[]) AND m.record_type='utterance' AND o.voice_profile_id IS NOT NULL")
        .bind(account_id).bind(targets.iter().map(|target|target.episode_id).collect::<Vec<_>>()).fetch_all(&mut **tx).await?;
    let admitted = super::voice_identity::controls_admit(tx, account_id)
        .await?
        .0;
    let mut changed_profiles =
        super::identity_fusion::reconcile_profiles(tx, account_id, &profile_ids, admitted).await?;
    super::identity_fusion::enrich_facts(tx, account_id, admitted).await?;
    changed_profiles.extend(super::voice_recurrence::refresh(tx, account_id).await?);
    let mut targets = targets.to_vec();
    if !changed_profiles.is_empty() || !changed_domains.is_empty() {
        let affected = super::voice_identity::affected_speaker_projection_targets(
            tx,
            account_id,
            &changed_domains,
            &changed_profiles,
            &[],
        )
        .await?;
        for target in affected {
            if !targets
                .iter()
                .any(|existing| existing.episode_id == target.episode_id)
            {
                targets.push(target);
            }
        }
    }
    let fence = episode_fence_sql(tx).await?;
    let ids = targets
        .iter()
        .map(|target| target.episode_id)
        .collect::<Vec<_>>();
    let allowed_sql=format!("SELECT e.id FROM episodes e WHERE e.account_id=$1 AND e.id=ANY($2) AND ({fence}) ORDER BY e.id");
    let allowed = sqlx::query_scalar::<_, i64>(sqlx::AssertSqlSafe(allowed_sql))
        .bind(account_id)
        .bind(&ids)
        .fetch_all(&mut **tx)
        .await?;
    for target in targets
        .iter()
        .filter(|target| allowed.contains(&target.episode_id))
    {
        let episode = target.episode_id;
        let before = signature(tx, account_id, episode).await?;
        let rows = evidence(tx, account_id, episode).await?;
        // A truly legacy memory keeps its legacy participant projection. Once a
        // graph projection existed, absence of observations must not resurrect it.
        let observed:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM episode_members m JOIN utterances u ON u.account_id=m.account_id AND u.id=m.record_id JOIN speaker_observations o ON o.account_id=u.account_id AND o.id=u.speaker_observation_id WHERE m.account_id=$1 AND m.episode_id=$2 AND m.record_type='utterance')").bind(account_id).bind(episode).fetch_one(&mut **tx).await?;
        let projected:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM episode_participants WHERE account_id=$1 AND episode_id=$2 AND derivation_version=$3)").bind(account_id).bind(episode).bind(SPEAKER_PROJECTION_VERSION).fetch_one(&mut **tx).await?;
        if !observed && !projected {
            continue;
        }
        let current = snapshot_speaker_slot_reservations(tx, account_id, &[episode]).await?;
        let plan = plan_slots(
            &voice_groups(&rows),
            &current,
            inherited,
            &target.inherit_from,
        )?;
        let keep = plan.iter().filter_map(|slot| slot.id).collect::<Vec<_>>();
        let superseded=sqlx::query("UPDATE episode_speaker_slots SET status='superseded',updated_at=clock_timestamp() WHERE account_id=$1 AND episode_id=$2 AND status='active' AND NOT(id=ANY($3::bigint[]))").bind(account_id).bind(episode).bind(&keep).execute(&mut **tx).await?.rows_affected();
        report.superseded_slots += superseded;
        let mut slot_ids = BTreeMap::new();
        for slot in plan {
            let (profile, cluster) = key_columns(slot.key);
            let id = if let Some(id) = slot.id {
                sqlx::query("UPDATE episode_speaker_slots SET voice_profile_id=$3,speaker_cluster_id=$4,status='active',updated_at=clock_timestamp() WHERE account_id=$1 AND id=$2 AND (voice_profile_id IS DISTINCT FROM $3 OR speaker_cluster_id IS DISTINCT FROM $4 OR status<>'active')").bind(account_id).bind(id).bind(profile).bind(cluster).execute(&mut **tx).await?;
                id
            } else {
                let id = allocate_projection_id(tx, account_id, "episode_speaker_slot").await?;
                sqlx::query("INSERT INTO episode_speaker_slots(account_id,id,episode_id,voice_profile_id,speaker_cluster_id,slot_ordinal) VALUES($1,$2,$3,$4,$5,$6)").bind(account_id).bind(id).bind(episode).bind(profile).bind(cluster).bind(slot.ordinal).execute(&mut **tx).await?;
                report.inserted_slots += 1;
                id
            };
            slot_ids.insert(slot.key, id);
        }
        let mut participants = BTreeMap::<String, (Option<i64>, Option<i64>, String)>::new();
        for row in rows {
            let Some(key) = row.participant_key else {
                continue;
            };
            let kind = row.attribution.unwrap_or_else(|| "context_inferred".into());
            let candidate = (
                row.person_id,
                row.key.and_then(|voice| slot_ids.get(&voice).copied()),
                kind,
            );
            if participants
                .get(&key)
                .is_none_or(|old| priority(&candidate.2) > priority(&old.2))
            {
                participants.insert(key, candidate);
            }
        }
        let keys = participants.keys().cloned().collect::<Vec<_>>();
        sqlx::query("UPDATE episode_participants SET state='superseded',derivation_version=$4,updated_at=clock_timestamp() WHERE account_id=$1 AND episode_id=$2 AND NOT(participant_key=ANY($3::text[])) AND (state<>'superseded' OR derivation_version<>$4)").bind(account_id).bind(episode).bind(&keys).bind(SPEAKER_PROJECTION_VERSION).execute(&mut **tx).await?;
        for (key, (person, slot, kind)) in participants {
            let existing:Option<i64>=sqlx::query_scalar("SELECT id FROM episode_participants WHERE account_id=$1 AND episode_id=$2 AND participant_key=$3").bind(account_id).bind(episode).bind(&key).fetch_optional(&mut **tx).await?;
            if let Some(id) = existing {
                sqlx::query("UPDATE episode_participants SET person_id=$3,speaker_slot_id=$4,attribution_kind=$5,state='active',derivation_version=$6,source_claimed_name=NULL,updated_at=clock_timestamp() WHERE account_id=$1 AND id=$2 AND (person_id IS DISTINCT FROM $3 OR speaker_slot_id IS DISTINCT FROM $4 OR attribution_kind<>$5 OR state<>'active' OR derivation_version<>$6 OR source_claimed_name IS NOT NULL)").bind(account_id).bind(id).bind(person).bind(slot).bind(&kind).bind(SPEAKER_PROJECTION_VERSION).execute(&mut **tx).await?;
            } else {
                let id = allocate_projection_id(tx, account_id, "episode_participant").await?;
                sqlx::query("INSERT INTO episode_participants(account_id,id,episode_id,participant_key,person_id,speaker_slot_id,attribution_kind,derivation_version) VALUES($1,$2,$3,$4,$5,$6,$7,$8)").bind(account_id).bind(id).bind(episode).bind(key).bind(person).bind(slot).bind(kind).bind(SPEAKER_PROJECTION_VERSION).execute(&mut **tx).await?;
            }
        }
        let after = signature(tx, account_id, episode).await?;
        let evidence =
            json!({"derivation":"assigned_utterance_identity","speaker_signature":after});
        let changed=sqlx::query("UPDATE episode_participants SET evidence=$3::jsonb WHERE account_id=$1 AND episode_id=$2 AND derivation_version=$4 AND evidence IS DISTINCT FROM $3::jsonb").bind(account_id).bind(episode).bind(evidence.to_string()).bind(SPEAKER_PROJECTION_VERSION).execute(&mut **tx).await?.rows_affected();
        let identity_changed =
            super::identity_presentation::refresh_semantic_revision(tx, account_id, episode)
                .await?;
        if before != after || changed > 0 || identity_changed {
            report.changed_episode_ids.push(episode);
        }
    }
    Ok(report)
}

/// Repairs actual source/projection mismatches, not merely an absent version
/// marker. Selection excludes durable deletion fences before its page limit.
pub(super) async fn prepare_speaker_projection_page(
    persistence: &PostgresPersistence,
    account_id: &str,
    episode_ids: Option<&[i64]>,
    after_episode_id: Option<i64>,
) -> Result<SpeakerPreparationPage> {
    if episode_ids.is_some_and(|ids| ids.is_empty()) {
        return Ok(SpeakerPreparationPage::default());
    }
    let mut tx = persistence.pool().begin().await?;
    lock_activation_contract_key_share_if_installed(&mut tx).await?;
    advisory_transaction_lock(&mut tx, "memory-reconciliation", account_id).await?;
    if !account_writable(&mut tx, account_id).await? {
        tx.commit().await?;
        return Ok(SpeakerPreparationPage::default());
    }
    super::identity_presentation::initialize_account_semantics(&mut tx, account_id).await?;
    let changed_domains = super::owner_voice::prepare_domains(&mut tx, account_id).await?;
    let domain_targets = super::voice_identity::affected_speaker_projection_targets(
        &mut tx,
        account_id,
        &changed_domains,
        &[],
        &[],
    )
    .await?;
    refresh_episode_speaker_projections(&mut tx, account_id, &domain_targets, &[]).await?;
    let fence = episode_fence_sql(&mut tx).await?;
    let sql=format!("SELECT e.id FROM episodes e WHERE e.account_id=$1 AND ($2::bigint[] IS NULL OR e.id=ANY($2)) AND ($3::bigint IS NULL OR e.id>$3) AND ({fence}) AND (EXISTS(SELECT 1 FROM episode_participants p WHERE p.account_id=e.account_id AND p.episode_id=e.id AND p.derivation_version=2) OR EXISTS(SELECT 1 FROM episode_members m JOIN utterances u ON u.account_id=m.account_id AND u.id=m.record_id JOIN speaker_observations o ON o.account_id=u.account_id AND o.id=u.speaker_observation_id LEFT JOIN speaker_clusters c ON c.account_id=o.account_id AND c.id=o.cluster_id LEFT JOIN people person ON person.account_id=o.account_id AND person.id=o.person_id AND person.status='identified' AND nullif(btrim(person.display_name),'') IS NOT NULL WHERE m.account_id=e.account_id AND m.episode_id=e.id AND m.record_type='utterance' AND (c.id IS NOT NULL OR person.id IS NOT NULL OR EXISTS(SELECT 1 FROM episode_participants p WHERE p.account_id=e.account_id AND p.episode_id=e.id)))) AND NOT EXISTS(SELECT 1 FROM episode_participants p WHERE p.account_id=e.account_id AND p.episode_id=e.id AND p.derivation_version=2 AND p.evidence->>'speaker_signature'={signature}) ORDER BY e.id LIMIT $4",signature=projection_signature_sql());
    let mut ids = sqlx::query_scalar::<_, i64>(sqlx::AssertSqlSafe(sql))
        .bind(account_id)
        .bind(episode_ids)
        .bind(after_episode_id)
        .bind((SPEAKER_PREPARE_PAGE_SIZE + 1) as i64)
        .fetch_all(&mut *tx)
        .await?;
    let has_more = ids.len() > SPEAKER_PREPARE_PAGE_SIZE;
    ids.truncate(SPEAKER_PREPARE_PAGE_SIZE);
    let targets = ids
        .iter()
        .copied()
        .map(SpeakerProjectionTarget::current)
        .collect::<Vec<_>>();
    refresh_episode_speaker_projections(&mut tx, account_id, &targets, &[]).await?;
    tx.commit().await?;
    Ok(SpeakerPreparationPage {
        prepared_episode_ids: ids,
        has_more,
    })
}
pub(super) async fn prepare_account_speaker_projections(
    persistence: &PostgresPersistence,
    account_id: &str,
) -> Result<()> {
    let mut cursor = None;
    loop {
        let page = prepare_speaker_projection_page(persistence, account_id, None, cursor).await?;
        if !page.has_more {
            return Ok(());
        }
        let next_episode_id = page.prepared_episode_ids.last().copied();
        if next_episode_id.is_none() || next_episode_id == cursor {
            return Err(EnclaveError::Store(
                "speaker projection preparation made no progress".into(),
            ));
        }
        cursor = next_episode_id;
    }
}

/// Read-only. Graph-backed memories never fall back to stale cached identities.
/// Call on the same repeatable snapshot as the associated turns/header.
pub(super) async fn load_episode_participant_details(
    connection: &mut PgConnection,
    account_id: &str,
    episode_ids: &[i64],
) -> Result<HashMap<i64, Vec<Value>>> {
    let mut result = HashMap::new();
    if episode_ids.is_empty() {
        return Ok(result);
    }
    let identity = speaker_identity_join(
        SpeakerUtteranceAlias::U,
        SpeakerMemoryScope::Episode("m.episode_id"),
    );
    let sql=format!("SELECT m.episode_id,speaker_identity.participant_key,speaker_identity.display_name,speaker_identity.person_id,speaker_identity.attribution_kind,speaker_identity.slot_ordinal,floor(extract(epoch FROM o.started_at)*1000)::bigint AS first_ms,u.id FROM episode_members m JOIN utterances u ON u.account_id=m.account_id AND u.id=m.record_id JOIN speaker_observations o ON o.account_id=u.account_id AND o.id=u.speaker_observation_id {identity} WHERE m.account_id=$1 AND m.episode_id=ANY($2) AND m.record_type='utterance' ORDER BY m.episode_id,o.started_at,u.id");
    let rows = sqlx::query(sqlx::AssertSqlSafe(sql))
        .bind(account_id)
        .bind(episode_ids)
        .fetch_all(&mut *connection)
        .await?;
    let mut graph_episodes = BTreeSet::new();
    let mut entries = BTreeMap::<(i64, String), (u8, (i64, i64), Value)>::new();
    for row in rows {
        let episode: i64 = row.try_get("episode_id")?;
        graph_episodes.insert(episode);
        let Some(key) = row.try_get::<Option<String>, _>("participant_key")? else {
            continue;
        };
        let kind: Option<String> = row.try_get("attribution_kind")?;
        let kind = kind.unwrap_or_else(|| "context_inferred".into());
        let entry = json!({"participant_key":key,"display_name":row.try_get::<String,_>("display_name")?,"person_id":row.try_get::<Option<i64>,_>("person_id")?,"attribution_kind":kind,"state":"active"});
        let priority = priority(&kind);
        let lookup = (episode, key);
        let first = (
            row.try_get::<i64, _>("first_ms")?,
            row.try_get::<i64, _>("id")?,
        );
        match entries.get_mut(&lookup) {
            Some(old) => {
                old.1 = old.1.min(first);
                if priority > old.0 {
                    old.0 = priority;
                    old.2 = entry;
                }
            }
            None => {
                entries.insert(lookup, (priority, first, entry));
            }
        }
    }
    let mut ordered = entries.into_iter().collect::<Vec<_>>();
    ordered.sort_by_key(|((episode, key), (_, first, _))| (*episode, *first, key.clone()));
    for ((episode, _), (_, _, entry)) in ordered {
        result.entry(episode).or_insert_with(Vec::new).push(entry);
    }
    let legacy = episode_ids
        .iter()
        .filter(|id| !graph_episodes.contains(id))
        .copied()
        .collect::<Vec<_>>();
    if !legacy.is_empty() {
        let eligible = legacy_participant_eligible_sql("e", "p");
        let sql=format!("SELECT p.episode_id,p.participant_key,p.attribution_kind,person.id AS person_id,person.display_name,p.source_claimed_name FROM episode_participants p JOIN episodes e ON e.account_id=p.account_id AND e.id=p.episode_id LEFT JOIN people person ON person.account_id=p.account_id AND person.id=p.person_id AND person.status='identified' AND nullif(btrim(person.display_name),'') IS NOT NULL WHERE p.account_id=$1 AND p.episode_id=ANY($2) AND ({eligible}) ORDER BY p.episode_id,p.id");
        let rows = sqlx::query(sqlx::AssertSqlSafe(sql))
            .bind(account_id)
            .bind(&legacy)
            .fetch_all(&mut *connection)
            .await?;
        for row in rows {
            let episode: i64 = row.try_get("episode_id")?;
            let key: String = row.try_get("participant_key")?;
            let kind: String = row.try_get("attribution_kind")?;
            let owner = key == "owner"
                || matches!(
                    kind.as_str(),
                    "owner" | "owner_presentation" | "owner_source_role" | "owner_voice"
                );
            let name = if owner {
                "Me".to_owned()
            } else {
                row.try_get::<Option<String>, _>("display_name")?
                    .or(row.try_get("source_claimed_name")?)
                    .unwrap_or_else(|| "Speaker".into())
            };
            result.entry(episode).or_insert_with(Vec::new).push(json!({"participant_key":key,"display_name":name,"person_id":if owner {None} else {row.try_get::<Option<i64>,_>("person_id")?},"attribution_kind":kind,"state":"active"}));
        }
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::super::voice_identity::tests::{seed_voice_memory, seed_voice_observation};
    use super::*;

    fn reservation(
        episode: i64,
        id: i64,
        key: SpeakerVoiceKey,
        ordinal: i64,
    ) -> SpeakerSlotReservation {
        SpeakerSlotReservation {
            episode_id: episode,
            id,
            key: Some(key),
            ordinal,
        }
    }
    fn group(key: SpeakerVoiceKey, aliases: &[i64], first: i64, needs_slot: bool) -> VoiceGroup {
        VoiceGroup {
            key,
            aliases: aliases.iter().copied().collect(),
            first: (first, first),
            needs_slot,
        }
    }
    #[test]
    fn speaker_slots_preserve_hidden_and_superseded_reservations_then_append() {
        let current = vec![
            reservation(1, 90, SpeakerVoiceKey::Cluster(8), 0),
            reservation(1, 91, SpeakerVoiceKey::Profile(7), 3),
        ];
        let groups = vec![
            group(SpeakerVoiceKey::Cluster(9), &[9], 0, true),
            group(SpeakerVoiceKey::Profile(7), &[7], 1, false),
            group(SpeakerVoiceKey::Cluster(8), &[8], 2, true),
        ];
        let actual = plan_slots(&groups, &current, &[], &[]).unwrap();
        assert_eq!(actual.iter().map(|p|(p.key,p.id,p.ordinal)).collect::<Vec<_>>(),vec![(SpeakerVoiceKey::Cluster(9),None,4),(SpeakerVoiceKey::Profile(7),Some(91),3),(SpeakerVoiceKey::Cluster(8),Some(90),0)],"new earlier speech must append after all reservations; named and returning voices retain their original IDs and letters");
    }
    #[test]
    fn speaker_slots_promote_cluster_across_replacement_and_resolve_merge_collisions() {
        let donors = vec![
            reservation(10, 1, SpeakerVoiceKey::Cluster(3), 2),
            reservation(20, 2, SpeakerVoiceKey::Profile(4), 2),
            reservation(99, 3, SpeakerVoiceKey::Profile(5), 0),
        ];
        let groups = vec![
            group(SpeakerVoiceKey::Profile(30), &[3], 1, false),
            group(SpeakerVoiceKey::Profile(4), &[4], 2, true),
            group(SpeakerVoiceKey::Profile(5), &[5], 3, true),
        ];
        let actual = plan_slots(&groups, &[], &donors, &[10, 20]).unwrap();
        assert_eq!(actual.iter().map(|p|(p.id,p.ordinal)).collect::<Vec<_>>(),vec![(None,2),(None,3),(None,4)],"a named promoted profile must inherit its cluster reservation with a new memory-local ID; first speech wins a merge collision; unrelated parents cannot donate");
        let current = vec![
            reservation(10, 1, SpeakerVoiceKey::Cluster(3), 2),
            reservation(10, 2, SpeakerVoiceKey::Profile(30), 5),
        ];
        let same = plan_slots(&groups[..1], &current, &[], &[]).unwrap();
        assert_eq!((same[0].id,same[0].ordinal),(Some(1),2),"in-memory promotion must preserve the earliest cluster alias ID and supersede a duplicate profile reservation");
    }
    #[test]
    fn speaker_slots_reserve_later_inherited_ordinals_before_new_voices() {
        let donors = vec![reservation(10, 1, SpeakerVoiceKey::Profile(4), 0)];
        let groups = vec![
            group(SpeakerVoiceKey::Cluster(9), &[9], 0, true),
            group(SpeakerVoiceKey::Profile(4), &[4], 1, true),
        ];
        let actual = plan_slots(&groups, &[], &donors, &[10]).unwrap();
        assert_eq!(actual.iter().map(|p|(p.key,p.ordinal)).collect::<Vec<_>>(),vec![(SpeakerVoiceKey::Cluster(9),1),(SpeakerVoiceKey::Profile(4),0)],"a new earlier voice must not steal a later inherited voice's reserved letter when no genuine donor collision exists");
        let donors = vec![
            reservation(10, 1, SpeakerVoiceKey::Profile(1), 0),
            reservation(20, 2, SpeakerVoiceKey::Profile(2), 0),
            reservation(30, 3, SpeakerVoiceKey::Profile(3), 1),
        ];
        let groups = vec![
            group(SpeakerVoiceKey::Profile(1), &[1], 0, true),
            group(SpeakerVoiceKey::Profile(2), &[2], 1, true),
            group(SpeakerVoiceKey::Profile(3), &[3], 2, true),
        ];
        let actual = plan_slots(&groups, &[], &donors, &[10, 20, 30]).unwrap();
        assert_eq!(actual.iter().map(|p|p.ordinal).collect::<Vec<_>>(),vec![0,2,1],"a genuine donor collision loser must append after all inherited reservations instead of stealing the later B reservation");
    }
    #[test]
    fn speaker_voice_groups_use_first_speech_and_keep_direct_identity_independent() {
        let row = |id, started, key, cluster, person, owner| Evidence {
            utterance_id: id,
            started_ms: started,
            key: Some(key),
            cluster_id: Some(cluster),
            person_id: person,
            has_accepted_name: person.is_some(),
            participant_key: None,
            attribution: None,
            owner,
        };
        let groups = voice_groups(&[
            row(1, 30, SpeakerVoiceKey::Cluster(1), 1, None, false),
            row(99, 10, SpeakerVoiceKey::Profile(9), 9, Some(1), false),
            row(2, 20, SpeakerVoiceKey::Profile(9), 2, Some(2), false),
            row(3, 0, SpeakerVoiceKey::Cluster(3), 3, None, true),
        ]);
        assert_eq!(groups.iter().map(|g|(g.key,g.needs_slot)).collect::<Vec<_>>(),vec![(SpeakerVoiceKey::Cluster(3),false),(SpeakerVoiceKey::Profile(9),false),(SpeakerVoiceKey::Cluster(1),true)],"IDs must not determine first speech, owner roles consume no anonymous slot, and differing direct people may share a voice group without aborting");
        assert_eq!(
            groups[1].aliases,
            BTreeSet::from([2, 9]),
            "profile grouping must retain every cluster alias for successor inheritance"
        );
        let mut recurring = row(4, 40, SpeakerVoiceKey::Profile(10), 10, Some(7), false);
        recurring.has_accepted_name = false;
        assert!(
            voice_groups(&[recurring])[0].needs_slot,
            "a linkable recurring person still needs a memory-local anonymous slot"
        );
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
    async fn seed(repo: &PostgresPersistence, account: &str, id: i64, episode: i64) {
        seed_voice_observation(repo, account, "session", &format!("event-{id}"), id, id).await;
        seed_voice_memory(repo, account, id, episode).await;
        sqlx::query("UPDATE speaker_observations SET started_at='2026-01-01'::timestamptz+make_interval(secs=>$2::double precision),ended_at='2026-01-01'::timestamptz+make_interval(secs=>$2::double precision)+interval '4 seconds' WHERE account_id=$1 AND id=$2").bind(account).bind(id).execute(repo.pool()).await.unwrap();
    }
    async fn profile(repo: &PostgresPersistence, account: &str, id: i64, person: Option<i64>) {
        sqlx::query("INSERT INTO voice_profiles(account_id,id,person_id,label,embedding_space,channel_domain,centroid) VALUES($1,$2,$3,'Synthetic voice '||$2,'synthetic','synthetic',decode('00','hex'))").bind(account).bind(id).bind(person).execute(repo.pool()).await.unwrap();
    }
    async fn labels(
        repo: &PostgresPersistence,
        account: &str,
        episode: i64,
    ) -> BTreeMap<i64, (String, Option<i64>, Option<String>)> {
        let identity =
            speaker_identity_join(SpeakerUtteranceAlias::U, SpeakerMemoryScope::Episode("$2"));
        let rows=sqlx::query(sqlx::AssertSqlSafe(format!("SELECT u.id,speaker_identity.speaker_label,speaker_identity.person_id,speaker_identity.attribution_kind FROM episode_members m JOIN utterances u ON u.account_id=m.account_id AND u.id=m.record_id {identity} WHERE m.account_id=$1 AND m.episode_id=$2 AND m.record_type='utterance' ORDER BY u.id"))).bind(account).bind(episode).fetch_all(repo.pool()).await.unwrap();
        rows.into_iter()
            .map(|r| {
                (
                    r.get("id"),
                    (
                        r.get("speaker_label"),
                        r.get("person_id"),
                        r.get("attribution_kind"),
                    ),
                )
            })
            .collect()
    }
    async fn refresh(repo: &PostgresPersistence, account: &str, ids: &[i64]) {
        let mut tx = repo.pool().begin().await.unwrap();
        lock_activation_contract_key_share_if_installed(&mut tx)
            .await
            .unwrap();
        advisory_transaction_lock(&mut tx, "memory-reconciliation", account)
            .await
            .unwrap();
        let targets = ids
            .iter()
            .copied()
            .map(SpeakerProjectionTarget::current)
            .collect::<Vec<_>>();
        refresh_episode_speaker_projections(&mut tx, account, &targets, &[])
            .await
            .unwrap();
        tx.commit().await.unwrap();
    }
    #[tokio::test]
    async fn speaker_identity_postgres_matrix_and_quarantine_abstention() {
        let Some(fixture) = super::super::tests::test_persistence().await else {
            return;
        };
        let repo = &fixture.persistence;
        let account = "speaker-matrix";
        for id in 1..=10 {
            seed(repo, account, id, 1).await;
        }
        sqlx::query("INSERT INTO people(account_id,id,display_name,status) VALUES($1,1,'Alice','identified'),($1,2,'Bob','identified'),($1,3,'Removed','quarantined')").bind(account).execute(repo.pool()).await.unwrap();
        profile(repo, account, 100, Some(1)).await;
        profile(repo, account, 101, None).await;
        sqlx::query("UPDATE speaker_clusters SET voice_profile_id=100 WHERE account_id=$1 AND id IN (1,2,4,5)").bind(account).execute(repo.pool()).await.unwrap();
        sqlx::query("UPDATE speaker_clusters SET attribution_state='owner_transmit',person_id=2 WHERE account_id=$1 AND id=1").bind(account).execute(repo.pool()).await.unwrap();
        sqlx::query(
            "UPDATE speaker_clusters SET voice_profile_id=101 WHERE account_id=$1 AND id=3",
        )
        .bind(account)
        .execute(repo.pool())
        .await
        .unwrap();
        sqlx::query(
            "UPDATE speaker_clusters SET person_id=2 WHERE account_id=$1 AND id IN (4,5,10)",
        )
        .bind(account)
        .execute(repo.pool())
        .await
        .unwrap();
        sqlx::query(
            "UPDATE speaker_observations SET person_id=1 WHERE account_id=$1 AND id IN (1,5,6)",
        )
        .bind(account)
        .execute(repo.pool())
        .await
        .unwrap();
        sqlx::query(
            "UPDATE speaker_observations SET cluster_id=NULL WHERE account_id=$1 AND id IN (6,8)",
        )
        .bind(account)
        .execute(repo.pool())
        .await
        .unwrap();
        sqlx::query("UPDATE speaker_observations SET person_id=3 WHERE account_id=$1 AND id=8")
            .bind(account)
            .execute(repo.pool())
            .await
            .unwrap();
        sqlx::query("UPDATE utterances SET speaker_observation_id=NULL,speaker_label='Legacy source' WHERE account_id=$1 AND id=7").bind(account).execute(repo.pool()).await.unwrap();
        prepare_account_speaker_projections(repo, account)
            .await
            .unwrap();
        let actual = labels(repo, account, 1).await;
        let expected = [
            (1, ("Me", None, Some("owner_source_role"))),
            (2, ("Alice", Some(1), Some("verified_voice"))),
            (3, ("Speaker B", None, Some("verified_voice"))),
            (4, ("Bob", Some(2), Some("direct_identity_evidence"))),
            (5, ("Speaker A", None, Some("verified_voice"))),
            (6, ("Alice", Some(1), Some("direct_identity_evidence"))),
            (7, ("Legacy source", None, None)),
            (8, ("Speaker", None, Some("context_inferred"))),
            (9, ("Speaker C", None, Some("context_inferred"))),
            (10, ("Bob", Some(2), Some("direct_identity_evidence"))),
        ];
        for (id, (label, person, kind)) in expected {
            assert_eq!(
                actual.get(&id),
                Some(&(label.to_owned(), person, kind.map(str::to_owned))),
                "canonical identity matrix disagrees for synthetic utterance {id}"
            );
        }
        assert_eq!(actual[&4].1,Some(2),"accepted direct cluster identity must take precedence over an inconsistent active profile's propagated person");
        let mut connection = repo.pool().acquire().await.unwrap();
        let participants = load_episode_participant_details(&mut connection, account, &[1])
            .await
            .unwrap();
        assert_eq!(
            participants[&1][0]["display_name"], "Me",
            "participant order must follow first speech rather than key order"
        );
        drop(connection);
        let mut tx = repo.pool().begin().await.unwrap();
        sqlx::query(
            "UPDATE voice_profiles SET status='quarantined' WHERE account_id=$1 AND id=100",
        )
        .bind(account)
        .execute(&mut *tx)
        .await
        .unwrap();
        refresh_episode_speaker_projections(
            &mut tx,
            account,
            &[SpeakerProjectionTarget::current(1)],
            &[],
        )
        .await
        .expect("semantic identity conflict must never roll back profile quarantine");
        tx.commit().await.unwrap();
        let after = labels(repo, account, 1).await;
        assert_eq!(
            after[&2],
            ("Speaker A".into(), None, Some("verified_voice".into())),
            "quarantined profile person must disappear while its anonymous voice remains stable"
        );
        assert_eq!(
            after[&6].1,
            Some(1),
            "independent accepted direct evidence must survive profile quarantine"
        );
        assert_eq!(
            after[&1].0, "Me",
            "owner source must suppress every person and profile label"
        );
        assert!(
            prepare_speaker_projection_page(repo, account, None, None)
                .await
                .unwrap()
                .prepared_episode_ids
                .is_empty(),
            "a complete unchanged projection must require no write-page refresh"
        );
        // Move this reservation into an otherwise empty memory so every
        // valid ordinal can be exercised without violating the unique slot key.
        sqlx::query("INSERT INTO episodes(account_id,id,started_at,ended_at,identity_revision) VALUES($1,2,now(),now(),7)").bind(account).execute(repo.pool()).await.unwrap();
        sqlx::query("UPDATE episode_members SET episode_id=2 WHERE account_id=$1 AND record_id=9")
            .bind(account)
            .execute(repo.pool())
            .await
            .unwrap();
        sqlx::query("UPDATE episode_speaker_slots SET episode_id=2 WHERE account_id=$1 AND speaker_cluster_id=9").bind(account).execute(repo.pool()).await.unwrap();
        for (ordinal, label) in [
            (0, "Speaker A"),
            (25, "Speaker Z"),
            (26, "Speaker AA"),
            (51, "Speaker AZ"),
            (52, "Speaker BA"),
        ] {
            sqlx::query("UPDATE episode_speaker_slots SET slot_ordinal=$2 WHERE account_id=$1 AND episode_id=2").bind(account).bind(ordinal as i64).execute(repo.pool()).await.unwrap();
            prepare_account_speaker_projections(repo, account)
                .await
                .unwrap();
            assert_eq!(labels(repo,account,2).await[&9].0,label,"valid persisted slot ordinal {ordinal} must render stable spreadsheet-style letters without exposing database IDs");
        }
        assert_eq!(
            sqlx::query_scalar::<_, i64>(
                "SELECT identity_revision FROM episodes WHERE account_id=$1 AND id=1"
            )
            .bind(account)
            .fetch_one(repo.pool())
            .await
            .unwrap(),
            8,
            "profile quarantine must advance identity revision once; anonymous slot changes must not"
        );
        cleanup(fixture).await;
    }
    #[tokio::test]
    async fn speaker_identity_repairs_old_writer_mutations_and_preserves_slot_ids() {
        let Some(fixture) = super::super::tests::test_persistence().await else {
            return;
        };
        let repo = &fixture.persistence;
        let account = "speaker-old-writer";
        seed(repo, account, 9, 1).await;
        prepare_account_speaker_projections(repo, account)
            .await
            .unwrap();
        let original: i64 =
            sqlx::query_scalar("SELECT id FROM episode_speaker_slots WHERE account_id=$1")
                .bind(account)
                .fetch_one(repo.pool())
                .await
                .unwrap();
        seed(repo, account, 1, 1).await;
        // Domain preparation may repair this memory before the ordinary page
        // selection. The canonical rows below must still expose the new voice.
        prepare_speaker_projection_page(repo, account, None, None)
            .await
            .unwrap();
        let current = labels(repo, account, 1).await;
        assert_eq!(
            (&current[&9].0, &current[&1].0),
            (&"Speaker A".to_owned(), &"Speaker B".to_owned()),
            "late earlier speech must not renumber an already visible voice"
        );
        let retained: i64 = sqlx::query_scalar(
            "SELECT id FROM episode_speaker_slots WHERE account_id=$1 AND speaker_cluster_id=9",
        )
        .bind(account)
        .fetch_one(repo.pool())
        .await
        .unwrap();
        assert_eq!(
            retained, original,
            "repair must preserve existing memory-local slot IDs"
        );
        profile(repo, account, 100, None).await;
        sqlx::query(
            "UPDATE speaker_clusters SET voice_profile_id=100 WHERE account_id=$1 AND id=9",
        )
        .bind(account)
        .execute(repo.pool())
        .await
        .unwrap();
        prepare_account_speaker_projections(repo, account)
            .await
            .unwrap();
        let promoted:(i64,i64)=sqlx::query_as("SELECT id,slot_ordinal FROM episode_speaker_slots WHERE account_id=$1 AND voice_profile_id=100 AND status='active'").bind(account).fetch_one(repo.pool()).await.unwrap();
        assert_eq!(
            promoted,
            (original, 0),
            "mixed-writer profile attachment must promote the prior cluster reservation in place"
        );
        sqlx::query("UPDATE episode_participants SET person_id=NULL,source_claimed_name='Old writer cache' WHERE account_id=$1").bind(account).execute(repo.pool()).await.unwrap();
        assert_eq!(
            prepare_speaker_projection_page(repo, account, None, None)
                .await
                .unwrap()
                .prepared_episode_ids,
            vec![1],
            "actual participant corruption must invalidate the dynamic completeness signature"
        );
        assert!(
            prepare_speaker_projection_page(repo, account, None, None)
                .await
                .unwrap()
                .prepared_episode_ids
                .is_empty(),
            "repair must converge after mixed-writer graph and participant changes"
        );
        cleanup(fixture).await;
    }
    #[tokio::test]
    async fn speaker_identity_legacy_fallback_requires_structural_absence() {
        let Some(fixture) = super::super::tests::test_persistence().await else {
            return;
        };
        let repo = &fixture.persistence;
        let account = "speaker-legacy";
        seed(repo, account, 1, 1).await;
        seed(repo, account, 2, 2).await;
        sqlx::query("INSERT INTO people(account_id,id,display_name,status) VALUES($1,1,'Stale person','quarantined')").bind(account).execute(repo.pool()).await.unwrap();
        sqlx::query(
            "UPDATE speaker_observations SET cluster_id=NULL,person_id=1 WHERE account_id=$1",
        )
        .bind(account)
        .execute(repo.pool())
        .await
        .unwrap();
        sqlx::query(
            "UPDATE utterances SET speaker_observation_id=NULL WHERE account_id=$1 AND id=2",
        )
        .bind(account)
        .execute(repo.pool())
        .await
        .unwrap();
        sqlx::query("INSERT INTO episode_participants(account_id,id,episode_id,participant_key,person_id,source_claimed_name,attribution_kind) VALUES($1,90,1,'person:1',1,'Cached observed name','direct_identity_evidence'),($1,91,2,'legacy',NULL,'Genuine legacy name','context_inferred')").bind(account).execute(repo.pool()).await.unwrap();
        let eligible = legacy_participant_eligible_sql("e", "p");
        let legacy_links:i64=sqlx::query_scalar(sqlx::AssertSqlSafe(format!("SELECT count(*) FROM episodes e JOIN episode_participants p ON p.account_id=e.account_id AND p.episode_id=e.id WHERE e.account_id=$1 AND e.id=1 AND ({eligible})"))).bind(account).fetch_one(repo.pool()).await.unwrap();
        assert_eq!(legacy_links,0,"the shared person-memory predicate must reject cached legacy links whenever any assigned observation exists");
        let mut connection = repo.pool().acquire().await.unwrap();
        let before = load_episode_participant_details(&mut connection, account, &[1, 2])
            .await
            .unwrap();
        assert!(!before.contains_key(&1),"an observed but unresolved voice must never resurrect a cached legacy name or person ID");
        assert_eq!(
            before[&2][0]["display_name"], "Genuine legacy name",
            "true legacy memories retain their explicit compatibility fallback"
        );
        drop(connection);
        prepare_account_speaker_projections(repo, account)
            .await
            .unwrap();
        sqlx::query(
            "UPDATE utterances SET speaker_observation_id=NULL WHERE account_id=$1 AND id=1",
        )
        .bind(account)
        .execute(repo.pool())
        .await
        .unwrap();
        refresh(repo, account, &[1]).await;
        let mut connection = repo.pool().acquire().await.unwrap();
        let after = load_episode_participant_details(&mut connection, account, &[1, 2])
            .await
            .unwrap();
        assert!(!after.contains_key(&1),"removing all observations must not turn a previously derived v2 memory back into legacy identity evidence");
        drop(connection);
        assert_eq!(sqlx::query_scalar::<_,i64>("SELECT count(*) FROM episode_participants WHERE account_id=$1 AND episode_id=1 AND state='active'").bind(account).fetch_one(repo.pool()).await.unwrap(),0,"explicit source-empty refresh must remove cached participant links");
        cleanup(fixture).await;
    }
    async fn projection_write_count(repo: &PostgresPersistence, account: &str) -> i64 {
        sqlx::query_scalar("SELECT (SELECT count(*) FROM episode_speaker_slots WHERE account_id=$1)+(SELECT count(*) FROM episode_participants WHERE account_id=$1)+(SELECT count(*) FROM content_id_counters WHERE account_id=$1 AND entity_kind IN ('episode_speaker_slot','episode_participant'))").bind(account).fetch_one(repo.pool()).await.unwrap()
    }
    #[tokio::test]
    async fn speaker_identity_fenced_accounts_never_allocate_or_loop() {
        let Some(fixture) = super::super::tests::test_persistence().await else {
            return;
        };
        let repo = &fixture.persistence;
        for (account, status) in [
            ("speaker-inactive", "deletion_requested"),
            ("speaker-deleting", "deleting"),
        ] {
            seed(repo, account, 1, 1).await;
            sqlx::query("UPDATE accounts SET status=$2 WHERE id=$1")
                .bind(account)
                .bind(status)
                .execute(repo.pool())
                .await
                .unwrap();
            let page = prepare_speaker_projection_page(repo, account, None, None)
                .await
                .unwrap();
            assert!(
                page.prepared_episode_ids.is_empty() && !page.has_more,
                "inactive accounts must yield a terminal empty repair page"
            );
            refresh(repo, account, &[1]).await;
            assert_eq!(
                projection_write_count(repo, account).await,
                0,
                "inactive accounts must receive no slot, participant, or allocation counter writes"
            );
        }
        assert!(
            prepare_speaker_projection_page(repo, "missing-speaker-account", None, None)
                .await
                .unwrap()
                .prepared_episode_ids
                .is_empty(),
            "a missing account cannot create projection authority"
        );
        let account = "speaker-orphan-fence";
        seed(repo, account, 1, 1).await;
        use sha2::Digest as _;
        let empty_objects = sha2::Sha256::digest(b"kioku.orphan-capture-objects.v1\n").to_vec();
        let empty_names =
            sha2::Sha256::digest(b"kioku.orphan-capture-provider-names.v1\n").to_vec();
        let mut preparing = repo.pool().begin().await.unwrap();
        sqlx::query("INSERT INTO orphan_capture_erasure_operations(account_id,operation_id,request_sha256,request_signature,request_key_sha256,scope_sha256,object_inventory_sha256,survivor_sha256,activation_generation,candidate_image_digest,activation_contract_sha256,activation_catalog_sha256,activation_receipt_sha256,provider_authority_sha256,protected_control_proof_sha256,session_count,stream_count,event_count,object_count,projection_count,provider_names_sha256,provider_name_count,account_provider_names_sha256) VALUES($1,'synthetic-operation',$2,$3,$2,$2,$4,$2,1,'sha256:'||repeat('1',64),$2,$2,$2,$2,$2,1,1,1,0,0,$5,0,$2)").bind(account).bind(vec![1_u8;32]).bind(vec![2_u8;64]).bind(empty_objects).bind(empty_names).execute(&mut *preparing).await.unwrap();
        sqlx::query("INSERT INTO orphan_capture_erasure_sessions(account_id,capture_session_id,operation_id) VALUES($1,'erased-session','synthetic-operation')").bind(account).execute(&mut *preparing).await.unwrap();
        sqlx::query("INSERT INTO orphan_capture_erasure_streams(account_id,stream_id,capture_session_id,operation_id) VALUES($1,'erased-stream','erased-session','synthetic-operation')").bind(account).execute(&mut *preparing).await.unwrap();
        sqlx::query("INSERT INTO orphan_capture_erasure_events(account_id,event_id,asset_id,stream_id,capture_session_id,operation_id) VALUES($1,'erased-event','erased-asset','erased-stream','erased-session','synthetic-operation')").bind(account).execute(&mut *preparing).await.unwrap();
        sqlx::query("UPDATE orphan_capture_erasure_operations SET state='provider_pending' WHERE account_id=$1").bind(account).execute(&mut *preparing).await.unwrap();
        preparing.commit().await.unwrap();
        for provider_verified in [false, true] {
            if provider_verified {
                sqlx::query("UPDATE orphan_capture_erasure_operations SET state='provider_verified',provider_ack_request_sha256=decode(repeat('5',64),'hex'),provider_ack_signature=decode(repeat('6',128),'hex'),provider_receipt_sha256=decode(repeat('7',64),'hex') WHERE account_id=$1").bind(account).execute(repo.pool()).await.unwrap();
            }
            let before:String=sqlx::query_scalar("SELECT to_jsonb(operation)::text FROM orphan_capture_erasure_operations operation WHERE account_id=$1").bind(account).fetch_one(repo.pool()).await.unwrap();
            let page = prepare_speaker_projection_page(repo, account, None, None)
                .await
                .unwrap();
            assert!(!page.has_more&&page.prepared_episode_ids.is_empty(),"durable orphan provider phases must terminate repair selection without a busy retry page");
            refresh(repo, account, &[1]).await;
            assert_eq!(
                projection_write_count(repo, account).await,
                0,
                "orphan source/survivor commitments forbid even projection counter allocation"
            );
            let after:String=sqlx::query_scalar("SELECT to_jsonb(operation)::text FROM orphan_capture_erasure_operations operation WHERE account_id=$1").bind(account).fetch_one(repo.pool()).await.unwrap();
            assert_eq!(
                before, after,
                "read preparation must leave every prepared erasure commitment unchanged"
            );
        }
        cleanup(fixture).await;
    }
    #[tokio::test]
    async fn speaker_identity_waits_for_account_deletion_admission() {
        let Some(fixture) = super::super::tests::test_persistence().await else {
            return;
        };
        let repo = &fixture.persistence;
        let account = "speaker-admission-race";
        seed(repo, account, 1, 1).await;
        let mut admission = repo.pool().begin().await.unwrap();
        let admission_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
            .fetch_one(&mut *admission)
            .await
            .unwrap();
        sqlx::query("UPDATE accounts SET status='deletion_requested' WHERE id=$1")
            .bind(account)
            .execute(&mut *admission)
            .await
            .unwrap();
        let reader = repo.clone();
        let preparing = tokio::spawn(async move {
            prepare_speaker_projection_page(&reader, account, None, None).await
        });
        let waited=tokio::time::timeout(std::time::Duration::from_secs(5),async {
            loop {
                let blocked:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE $1=ANY(pg_blocking_pids(pid)) AND query LIKE '%FROM accounts WHERE id=$1 FOR UPDATE%')").bind(admission_pid).fetch_one(repo.pool()).await.unwrap();
                if blocked {break true;}
                if preparing.is_finished() {break false;}
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        }).await.unwrap_or(false);
        admission.commit().await.unwrap();
        let page = preparing.await.unwrap().unwrap();
        assert!(waited,"speaker repair must wait on the account row held by deletion admission, not inspect an older active-account snapshot");
        assert!(
            page.prepared_episode_ids.is_empty(),
            "after admission commits, repair must observe the now-inactive account"
        );
        assert_eq!(
            projection_write_count(repo, account).await,
            0,
            "the admission race must not create slots, participants, or counters"
        );
        cleanup(fixture).await;
    }
    #[tokio::test]
    async fn speaker_identity_paged_event_inventory_fences_other_memory_after_member_purge() {
        let Some(fixture) = super::super::tests::test_persistence().await else {
            return;
        };
        let repo = &fixture.persistence;
        repo.install_memory_reconciliation_activation_schema()
            .await
            .unwrap();
        let account = "speaker-paged-fence";
        for id in 1..=3 {
            seed(repo, account, id, id).await;
        }
        sqlx::query("UPDATE capture_events SET media_disposition='reference',canonical_event_id='event-1',canonical_asset_id='event-1' WHERE account_id=$1 AND event_id='event-2'").bind(account).execute(repo.pool()).await.unwrap();
        sqlx::query("UPDATE speaker_observation_sources SET event_id='event-1' WHERE account_id=$1 AND speaker_observation_id=3").bind(account).execute(repo.pool()).await.unwrap();
        sqlx::query("INSERT INTO episode_deletions(account_id,episode_id,state,purge,media_object_keys,utterance_ids,screenshot_ids,segment_ids,orphan_event_ids) VALUES($1,1,'pending','{}','[]','[]','[]','[]','[]')").bind(account).execute(repo.pool()).await.unwrap();
        sqlx::query("INSERT INTO persistence_feature_episode_deletion_progress(account_id,episode_id,phase,coordinate_sha256) VALUES($1,1,'purge_members',decode(repeat('00',32),'hex'))").bind(account).execute(repo.pool()).await.unwrap();
        sqlx::query("INSERT INTO persistence_feature_episode_deletion_roots(account_id,episode_id,root_event_id,disposition,coordinate_sha256,classified_at) VALUES($1,1,'event-1','orphan',decode(repeat('00',32),'hex'),now())").bind(account).execute(repo.pool()).await.unwrap();
        sqlx::query("INSERT INTO persistence_feature_episode_deletion_events(account_id,episode_id,root_event_id,event_id,capture_session_id,stream_id,sequence,manifest_digest,coordinate_sha256) SELECT $1,1,event_id,event_id,capture_session_id,stream_id,sequence,manifest_digest,decode(repeat('00',32),'hex') FROM capture_events WHERE account_id=$1 AND event_id='event-1'").bind(account).execute(repo.pool()).await.unwrap();
        sqlx::query("DELETE FROM episode_members WHERE account_id=$1 AND episode_id=1")
            .bind(account)
            .execute(repo.pool())
            .await
            .unwrap();
        sqlx::query("DELETE FROM utterances WHERE account_id=$1 AND id=1")
            .bind(account)
            .execute(repo.pool())
            .await
            .unwrap();
        sqlx::query("UPDATE persistence_feature_episode_deletion_progress SET phase='tombstone_events' WHERE account_id=$1").bind(account).execute(repo.pool()).await.unwrap();
        let page = prepare_speaker_projection_page(repo, account, None, None)
            .await
            .unwrap();
        assert!(page.prepared_episode_ids.is_empty()&&!page.has_more,"paged source inventory must fence canonical-family and alternate-source evidence after the deleting memory loses its members");
        refresh(repo, account, &[1, 2, 3]).await;
        assert_eq!(projection_write_count(repo,account).await,0,"explicit writer refresh must recheck the same durable event fences before allocating slots or participant links");
        cleanup(fixture).await;
    }
}
