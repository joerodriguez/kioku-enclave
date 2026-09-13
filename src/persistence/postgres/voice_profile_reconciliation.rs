//! Account-locked acoustic proposals. Only derived assignments and reservations
//! change; source observations, utterances and memory membership stay intact.
use super::voice_identity::{self as store, allocate_voice_id};
use crate::{
    cp::{
        voice_identity,
        voice_memory::EMBEDDING_SPACE,
        voice_quality::SCORER_VERSION,
        voice_reconciliation::{self as policy, Profile},
    },
    error::Result,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use sqlx::{Postgres, Row, Transaction};
use std::collections::{BTreeMap, BTreeSet};

struct Member {
    sample: i64,
    observation: i64,
    cluster: Option<i64>,
    assignment: i64,
}
struct Candidate {
    policy: Profile,
    bound_person: Option<i64>,
    revision: i64,
    derivation: i64,
    members: Vec<Member>,
}
fn digest(value: &Value) -> String {
    format!("{:x}", Sha256::digest(value.to_string().as_bytes()))
}
fn membership(candidate: &Candidate) -> String {
    digest(&json!(candidate
        .members
        .iter()
        .map(|m| (m.sample, m.assignment))
        .collect::<Vec<_>>()))
}

async fn load(
    tx: &mut Transaction<'_, Postgres>,
    account: &str,
    id: i64,
) -> Result<Option<Candidate>> {
    load_support(tx, account, id, Some(policy::MAX_SAMPLES)).await
}

async fn load_support(
    tx: &mut Transaction<'_, Postgres>,
    account: &str,
    id: i64,
    limit: Option<usize>,
) -> Result<Option<Candidate>> {
    let Some(row) = sqlx::query("SELECT p.*,r.id revision,r.derivation_version derivation,person.status person_status FROM voice_profiles p JOIN voice_profile_revisions r ON r.account_id=p.account_id AND r.profile_id=p.id AND r.active LEFT JOIN people person ON person.account_id=p.account_id AND person.id=p.person_id WHERE p.account_id=$1 AND p.id=$2")
        .bind(account).bind(id).fetch_optional(&mut **tx).await? else {return Ok(None)};
    let fence = store::source_fence(tx).await?;
    let sql=format!("SELECT s.id,s.speaker_observation_id,s.embedding,s.eligibility,o.cluster_id,a.id assignment, \
      (s.accepted AND NOT o.overlap AND s.eligibility IN ('enroll','match_only') AND s.quality_version=$3 \
       AND s.embedding_space=p.embedding_space AND s.scorer_version=p.scorer_version AND s.channel_domain=p.channel_domain \
       AND s.voice_profile_id=p.id AND o.voice_profile_id=p.id AND o.voice_sample_id=s.id \
       AND ({retained}) AND NOT ({withdrawn}) AND NOT ({fence}) \
       AND NOT EXISTS(SELECT 1 FROM speaker_clusters c WHERE c.account_id=o.account_id AND c.id=o.cluster_id AND c.profile_updates_quarantined) \
       AND NOT EXISTS(SELECT 1 FROM capture_events e JOIN voice_enrollment_sessions enrollment ON enrollment.account_id=e.account_id AND enrollment.capture_session_id=e.capture_session_id WHERE e.account_id=o.account_id AND e.event_id=o.event_id AND enrollment.designated AND enrollment.state<>'enrolled')) valid \
      FROM voice_sample_profile_assignments a JOIN voice_samples s ON s.account_id=a.account_id AND s.id=a.sample_id \
      JOIN speaker_observations o ON o.account_id=s.account_id AND o.id=s.speaker_observation_id \
      JOIN voice_profiles p ON p.account_id=a.account_id AND p.id=a.profile_id \
      WHERE a.account_id=$1 AND a.profile_id=$2 AND a.active ORDER BY s.id LIMIT $4",
      retained=store::RETAINED,withdrawn=store::WITHDRAWN);
    let rows = sqlx::query(sqlx::AssertSqlSafe(sql))
        .bind(account)
        .bind(id)
        .bind(crate::cp::voice_quality::QUALITY_VERSION)
        .bind(limit.map(|n| (n + 1) as i64))
        .fetch_all(&mut **tx)
        .await?;
    let centroid: Vec<u8> = row.try_get("centroid")?;
    if centroid.is_empty() {
        return Ok(None);
    }
    let mut complete = limit.is_none_or(|cap| rows.len() <= cap) && !rows.is_empty();
    let mut samples = Vec::new();
    let mut members = Vec::new();
    for member in rows {
        complete &= member.try_get::<Option<bool>, _>("valid")? == Some(true);
        let observation = member.try_get("speaker_observation_id")?;
        if member.try_get::<String, _>("eligibility")? == "enroll" {
            samples.push((
                observation,
                voice_identity::decode_embedding(&member.try_get::<Vec<u8>, _>("embedding")?)?,
            ));
        }
        members.push(Member {
            sample: member.try_get("id")?,
            observation,
            cluster: member.try_get("cluster_id")?,
            assignment: member.try_get("assignment")?,
        });
    }
    // All accepted direct bindings participate in conflict checks, independently
    // of display-name spelling or a profile's current anonymous public node.
    let identities:Vec<(i64,String)>=sqlx::query_as("SELECT DISTINCT person.id,person.status FROM people person WHERE person.account_id=$1 AND person.status IN ('identified','owner','quarantined') AND (person.id=(SELECT person_id FROM voice_profiles WHERE account_id=$1 AND id=$2) OR EXISTS(SELECT 1 FROM voice_sample_profile_assignments a JOIN voice_samples s ON s.account_id=a.account_id AND s.id=a.sample_id JOIN speaker_observations o ON o.account_id=s.account_id AND o.id=s.speaker_observation_id LEFT JOIN speaker_clusters c ON c.account_id=o.account_id AND c.id=o.cluster_id WHERE a.account_id=$1 AND a.profile_id=$2 AND a.active AND (o.person_id=person.id OR c.person_id=person.id))) ORDER BY person.id")
        .bind(account).bind(id).fetch_all(&mut **tx).await?;
    let mut person = row.try_get("person_id")?;
    let mut person_status = row.try_get("person_status")?;
    if identities.len() > 1 {
        complete = false;
    }
    if let Some((id, status)) = identities.first() {
        person = Some(*id);
        person_status = Some(status.clone());
    }
    Ok(Some(Candidate {
        bound_person: row.try_get("person_id")?,
        policy: Profile {
            id,
            space: row.try_get("embedding_space")?,
            scorer: row.try_get("scorer_version")?,
            domain: row.try_get("channel_domain")?,
            person,
            person_status,
            centroid: voice_identity::decode_embedding(&row.try_get::<Vec<u8>, _>("centroid")?)?,
            samples,
            membership_complete: complete,
        },
        revision: row.try_get("revision")?,
        derivation: row.try_get("derivation")?,
        members,
    }))
}

async fn population(tx: &mut Transaction<'_, Postgres>, account: &str) -> Result<Vec<Candidate>> {
    let ids:Vec<i64>=sqlx::query_scalar("SELECT p.id FROM voice_profiles p JOIN voice_profile_revisions r ON r.account_id=p.account_id AND r.profile_id=p.id AND r.active LEFT JOIN people person ON person.account_id=p.account_id AND person.id=p.person_id WHERE p.account_id=$1 AND p.status<>'quarantined' AND (p.status='stable' OR person.status='owner') AND p.embedding_space=$2 AND p.scorer_version=$3 AND p.sample_count>0 ORDER BY p.id LIMIT $4")
        .bind(account).bind(EMBEDDING_SPACE).bind(SCORER_VERSION).bind((policy::MAX_PROFILES+1) as i64).fetch_all(&mut **tx).await?;
    let mut candidates = Vec::new();
    for id in ids {
        if let Some(mut c) = load(tx, account, id).await? {
            // Pending policy adoption changes merge eligibility, never the
            // existence of a compatible runner-up. Owner recognition has its
            // own current enrollment policy and is always a competitor.
            if c.derivation != voice_identity::IDENTITY_DERIVATION_VERSION
                && c.policy.person_status.as_deref() != Some("owner")
            {
                c.policy.membership_complete = false;
            }
            candidates.push(c);
        }
    }
    Ok(candidates)
}

pub(super) struct NamePairSnapshot {
    pub(super) pairs: Vec<(i64, i64)>,
    pub(super) complete: bool,
    pub(super) commitment: String,
    pub(super) people: BTreeMap<i64, Option<i64>>,
}

/// Uses the reconciler's complete current acoustic population before its
/// distinct-person permission veto. Binding-induced revisions/statuses are
/// excluded from this commitment so a hold cannot trigger its own successor.
pub(super) async fn name_pair_snapshot(
    tx: &mut Transaction<'_, Postgres>,
    account: &str,
) -> Result<NamePairSnapshot> {
    let candidates = population(tx, account).await?;
    let complete = candidates.len() <= policy::MAX_PROFILES
        && candidates.iter().all(|c| c.policy.membership_complete);
    let profiles = candidates
        .iter()
        .map(|c| c.policy.clone())
        .collect::<Vec<_>>();
    let pairs = policy::acoustic_pairs(&profiles)
        .into_iter()
        .map(|p| (p.left, p.right))
        .collect();
    let commitment = digest(
        &json!({"policy":policy::POLICY_VERSION,"profiles":candidates.iter().map(|c| {
        json!([c.policy.id,c.policy.space,c.policy.scorer,c.policy.domain,c.policy.centroid,c.policy.samples,
            c.policy.membership_complete,matches!(c.policy.person_status.as_deref(),Some("owner"|"quarantined")),membership(c)])
    }).collect::<Vec<_>>()}),
    );
    Ok(NamePairSnapshot {
        pairs,
        complete,
        commitment,
        people: candidates
            .iter()
            .map(|c| (c.policy.id, c.bound_person))
            .collect(),
    })
}

async fn held_name_profiles(
    tx: &mut Transaction<'_, Postgres>,
    account: &str,
) -> Result<BTreeSet<i64>> {
    Ok(sqlx::query_scalar::<_, i64>(
        "SELECT profile_id FROM profile_name_bindings WHERE account_id=$1 AND status='quarantined'",
    )
    .bind(account)
    .fetch_all(&mut **tx)
    .await?
    .into_iter()
    .collect())
}

pub(super) async fn adopt_current_policy(
    tx: &mut Transaction<'_, Postgres>,
    account: &str,
) -> Result<()> {
    let ids:Vec<i64>=sqlx::query_scalar("SELECT p.id FROM voice_profiles p JOIN voice_profile_revisions r ON r.account_id=p.account_id AND r.profile_id=p.id AND r.active LEFT JOIN people person ON person.account_id=p.account_id AND person.id=p.person_id WHERE p.account_id=$1 AND p.status<>'quarantined' AND coalesce(person.status,'') NOT IN ('owner','quarantined') AND p.embedding_space=$2 AND p.scorer_version=$3 AND r.derivation_version<$4 ORDER BY p.updated_at,p.id LIMIT 16")
        .bind(account).bind(EMBEDDING_SPACE).bind(SCORER_VERSION).bind(voice_identity::IDENTITY_DERIVATION_VERSION).fetch_all(&mut **tx).await?;
    let mut changed = Vec::new();
    for id in ids {
        if load_support(tx, account, id, None)
            .await?
            .is_some_and(|c| c.policy.membership_complete)
        {
            store::recompute_profile(tx, account, id, "current_policy_adoption").await?;
            changed.push(id);
        } else {
            sqlx::query("UPDATE voice_profiles SET updated_at=clock_timestamp() WHERE account_id=$1 AND id=$2").bind(account).bind(id).execute(&mut **tx).await?;
        }
    }
    store::refresh_affected_speaker_projections(tx, account, &[], &changed, &[]).await
}

async fn identity_commitment(
    tx: &mut Transaction<'_, Postgres>,
    account: &str,
    people: &[i64],
) -> Result<Value> {
    // Store a commitment, never a second copy of source names/facts that could
    // survive erasure of the evidence that produced them.
    let value:String=sqlx::query_scalar("SELECT jsonb_build_object('people',(SELECT jsonb_agg(to_jsonb(p)-'updated_at' ORDER BY id) FROM people p WHERE account_id=$1 AND id=ANY($2)), 'names',(SELECT jsonb_agg(to_jsonb(n) ORDER BY id) FROM person_name_claims n WHERE account_id=$1 AND person_id=ANY($2)), 'facts',(SELECT jsonb_agg(to_jsonb(f) ORDER BY id) FROM person_facts f WHERE account_id=$1 AND person_id=ANY($2)), 'evidence',(SELECT jsonb_agg(to_jsonb(e) ORDER BY id) FROM identity_evidence e WHERE account_id=$1 AND person_id=ANY($2)))::text")
        .bind(account).bind(people).fetch_one(&mut **tx).await?;
    Ok(json!({"people":people,"sha256":format!("{:x}",Sha256::digest(value.as_bytes()))}))
}

async fn revision(
    tx: &mut Transaction<'_, Postgres>,
    account: &str,
    profile: i64,
    proposal: i64,
    superseded: bool,
) -> Result<i64> {
    store::append_revision(
        tx,
        account,
        profile,
        if superseded {
            "proposal_superseded"
        } else {
            "proposal_result"
        },
    )
    .await?;
    let id:i64=sqlx::query_scalar("UPDATE voice_profile_revisions SET proposal_id=$3,status=CASE WHEN $4 THEN 'superseded' ELSE status END WHERE account_id=$1 AND profile_id=$2 AND active RETURNING id")
        .bind(account).bind(profile).bind(proposal).bind(superseded).fetch_one(&mut **tx).await?;
    Ok(id)
}

async fn reassign(
    tx: &mut Transaction<'_, Postgres>,
    account: &str,
    member: &Member,
    profile: i64,
    proposal: i64,
) -> Result<()> {
    sqlx::query("UPDATE voice_sample_profile_assignments SET active=false WHERE account_id=$1 AND id=$2 AND active")
        .bind(account).bind(member.assignment).execute(&mut **tx).await?;
    let id = allocate_voice_id(tx, account, "voice_sample_profile_assignment").await?;
    sqlx::query("INSERT INTO voice_sample_profile_assignments(account_id,id,sample_id,profile_id,proposal_id,predecessor_assignment_id) VALUES($1,$2,$3,$4,$5,$6)")
        .bind(account).bind(id).bind(member.sample).bind(profile).bind(proposal).bind(member.assignment).execute(&mut **tx).await?;
    sqlx::query("UPDATE voice_samples SET voice_profile_id=$3 WHERE account_id=$1 AND id=$2")
        .bind(account)
        .bind(member.sample)
        .bind(profile)
        .execute(&mut **tx)
        .await?;
    sqlx::query("UPDATE speaker_observations SET voice_profile_id=$3 WHERE account_id=$1 AND id=$2 AND voice_sample_id=$4").bind(account).bind(member.observation).bind(profile).bind(member.sample).execute(&mut **tx).await?;
    Ok(())
}

async fn slot_commitment(
    tx: &mut Transaction<'_, Postgres>,
    account: &str,
    proposal: i64,
) -> Result<(i64, String)> {
    let slots:String=sqlx::query_scalar("SELECT coalesce(jsonb_agg(jsonb_build_array(slot_id,episode_id,source_profile_id,source_cluster_id,slot_ordinal,source_status,applied_status) ORDER BY slot_id),'[]'::jsonb)::text FROM voice_profile_proposal_slots WHERE account_id=$1 AND proposal_id=$2")
        .bind(account).bind(proposal).fetch_one(&mut **tx).await?;
    let slots: Value = serde_json::from_str(&slots)?;
    Ok((
        slots.as_array().map_or(0, |a| a.len()) as i64,
        digest(&slots),
    ))
}

async fn apply(
    tx: &mut Transaction<'_, Postgres>,
    account: &str,
    expected_left: &Candidate,
    expected_right: &Candidate,
) -> Result<Option<i64>> {
    // Re-evaluate current names before the exact application recheck, including
    // peer changes since the scheduling pass. Holds leave acoustic competitors.
    let name_changed = super::identity_fusion::reconcile_profiles(
        tx,
        account,
        &[expected_left.policy.id, expected_right.policy.id],
        true,
    )
    .await?;
    store::refresh_affected_speaker_projections(tx, account, &[], &name_changed, &[]).await?;
    let held = held_name_profiles(tx, account).await?;
    if held.contains(&expected_left.policy.id) || held.contains(&expected_right.policy.id) {
        return Ok(None);
    }
    // Re-read exact revisions and memberships even though normal workers hold
    // the account lock: a saved proposal can never authorize a later graph.
    let current = population(tx, account).await?;
    let Some(left) = current
        .iter()
        .find(|c| c.policy.id == expected_left.policy.id)
    else {
        return Ok(None);
    };
    let Some(right) = current
        .iter()
        .find(|c| c.policy.id == expected_right.policy.id)
    else {
        return Ok(None);
    };
    if left.revision != expected_left.revision
        || right.revision != expected_right.revision
        || membership(left) != membership(expected_left)
        || membership(right) != membership(expected_right)
        || left.members.len() + right.members.len() > policy::MAX_SAMPLES
        || !store::controls_admit(tx, account).await?.0
    {
        return Ok(None);
    }
    let profiles = current.iter().map(|c| c.policy.clone()).collect::<Vec<_>>();
    let Some(pair) = policy::merge_pairs(&profiles)
        .into_iter()
        .find(|p| p.left == left.policy.id && p.right == right.policy.id)
    else {
        return Ok(None);
    };
    let already:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM voice_profile_proposals WHERE account_id=$1 AND left_profile_id=$2 AND right_profile_id=$3 AND left_revision_id=$4 AND right_revision_id=$5 AND policy_version=$6)")
        .bind(account).bind(pair.left).bind(pair.right).bind(left.revision).bind(right.revision).bind(policy::POLICY_VERSION).fetch_one(&mut **tx).await?;
    if already {
        return Ok(None);
    }
    let people = [
        left.bound_person,
        right.bound_person,
        left.policy.person,
        right.policy.person,
    ]
    .into_iter()
    .flatten()
    .collect::<BTreeSet<_>>()
    .into_iter()
    .collect::<Vec<_>>();
    let source_people = identity_commitment(tx, account, &people).await?;
    let proposal = allocate_voice_id(tx, account, "voice_profile_proposal").await?;
    sqlx::query("INSERT INTO voice_profile_proposals(account_id,id,kind,policy_version,embedding_space,scorer_version,channel_domain,left_profile_id,right_profile_id,left_revision_id,right_revision_id,left_member_count,right_member_count,left_members_sha256,right_members_sha256,left_person_id,right_person_id,source_person_state,state,reason,decision) VALUES($1,$2,'merge',$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17::jsonb,'proposed','mutual_clean_support',$18::jsonb)")
        .bind(account).bind(proposal).bind(policy::POLICY_VERSION).bind(&left.policy.space).bind(left.policy.scorer).bind(&left.policy.domain).bind(pair.left).bind(pair.right).bind(left.revision).bind(right.revision).bind(left.members.len() as i64).bind(right.members.len() as i64).bind(membership(left)).bind(membership(right)).bind(left.bound_person).bind(right.bound_person).bind(source_people.to_string()).bind(json!({"minimum_score":pair.minimum_score,"minimum_margin":pair.minimum_margin}).to_string()).execute(&mut **tx).await?;
    for candidate in [left, right] {
        for m in &candidate.members {
            sqlx::query("INSERT INTO voice_profile_proposal_samples(account_id,proposal_id,source_profile_id,sample_id,source_assignment_id) VALUES($1,$2,$3,$4,$5)")
            .bind(account).bind(proposal).bind(candidate.policy.id).bind(m.sample).bind(m.assignment).execute(&mut **tx).await?;
        }
    }
    let clusters = left
        .members
        .iter()
        .chain(&right.members)
        .filter_map(|m| m.cluster)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    sqlx::query("INSERT INTO voice_profile_proposal_slots(account_id,proposal_id,slot_id,episode_id,source_profile_id,source_cluster_id,slot_ordinal,source_status) SELECT account_id,$2,id,episode_id,voice_profile_id,speaker_cluster_id,slot_ordinal,status FROM episode_speaker_slots WHERE account_id=$1 AND (voice_profile_id=ANY($3) OR speaker_cluster_id=ANY($4))")
        .bind(account).bind(proposal).bind([pair.left,pair.right].as_slice()).bind(&clusters).execute(&mut **tx).await?;
    let result = allocate_voice_id(tx, account, "voice_profile").await?;
    let person = [left, right]
        .into_iter()
        .find(|c| c.policy.person_status.as_deref() == Some("identified"))
        .and_then(|c| c.policy.person)
        .or_else(|| {
            [left.policy.person, right.policy.person]
                .into_iter()
                .flatten()
                .min()
        });
    sqlx::query("INSERT INTO voice_profiles(account_id,id,person_id,label,embedding_space,channel_domain,centroid,scorer_version) VALUES($1,$2,$3,$4,$5,$6,''::bytea,$7)")
        .bind(account).bind(result).bind(person).bind(format!("voice-profile-{result}")).bind(&left.policy.space).bind(&left.policy.domain).bind(left.policy.scorer).execute(&mut **tx).await?;
    for m in left.members.iter().chain(&right.members) {
        reassign(tx, account, m, result, proposal).await?;
    }
    // Reservation IDs and ordinals survive; the normal projector keeps the
    // earliest reservation when both source voices appeared in one memory.
    sqlx::query("UPDATE episode_speaker_slots s SET voice_profile_id=$3,speaker_cluster_id=NULL WHERE s.account_id=$1 AND EXISTS(SELECT 1 FROM voice_profile_proposal_slots p WHERE p.account_id=s.account_id AND p.proposal_id=$2 AND p.slot_id=s.id)")
        .bind(account).bind(proposal).bind(result).execute(&mut **tx).await?;
    let mut source_revisions = Vec::new();
    for source in [pair.left, pair.right] {
        sqlx::query("UPDATE voice_profiles SET status='quarantined',centroid=''::bytea,sample_count=0,medoid_sample_id=NULL,updated_at=clock_timestamp() WHERE account_id=$1 AND id=$2").bind(account).bind(source).execute(&mut **tx).await?;
        sqlx::query(
            "DELETE FROM voice_profile_representatives WHERE account_id=$1 AND profile_id=$2",
        )
        .bind(account)
        .bind(source)
        .execute(&mut **tx)
        .await?;
        source_revisions.push(revision(tx, account, source, proposal, true).await?);
    }
    super::owner_voice::refresh_clusters(tx, account, &clusters).await?;
    store::recompute_profile(tx, account, result, "proposal_result").await?;
    super::voice_recurrence::refresh(tx, account).await?;

    store::refresh_affected_speaker_projections(
        tx,
        account,
        &clusters,
        &[pair.left, pair.right, result],
        &people,
    )
    .await?;
    sqlx::query("UPDATE voice_profile_proposal_slots p SET applied_status=s.status FROM episode_speaker_slots s WHERE p.account_id=$1 AND p.proposal_id=$2 AND s.account_id=p.account_id AND s.id=p.slot_id").bind(account).bind(proposal).execute(&mut **tx).await?;
    let (slot_count, slots_hash) = slot_commitment(tx, account, proposal).await?;
    let result_revision = revision(tx, account, result, proposal, false).await?;
    let result_candidate = load(tx, account, result)
        .await?
        .ok_or_else(|| crate::error::EnclaveError::Config("proposal result is absent".into()))?;
    let mut people = people;
    if let Some(person) = result_candidate.bound_person {
        people.push(person);
        people.sort_unstable();
        people.dedup();
    }
    let applied_people = identity_commitment(tx, account, &people).await?;
    sqlx::query("UPDATE voice_profile_proposals SET state='applied',result_profile_id=$3,result_revision_id=$4,result_members_sha256=$5,left_superseded_revision_id=$6,right_superseded_revision_id=$7,slot_count=$8,slots_sha256=$9,applied_person_state=$10::jsonb,updated_at=clock_timestamp() WHERE account_id=$1 AND id=$2")
        .bind(account).bind(proposal).bind(result).bind(result_revision).bind(membership(&result_candidate)).bind(source_revisions[0]).bind(source_revisions[1]).bind(slot_count).bind(slots_hash).bind(applied_people.to_string()).execute(&mut **tx).await?;
    Ok(Some(proposal))
}

async fn reverse(tx: &mut Transaction<'_, Postgres>, account: &str, proposal: i64) -> Result<bool> {
    let Some(row) = sqlx::query(
        "SELECT p.*,p.applied_person_state::text applied_person_text FROM voice_profile_proposals p WHERE account_id=$1 AND id=$2 AND state='applied'",
    )
    .bind(account)
    .bind(proposal)
    .fetch_optional(&mut **tx)
    .await?
    else {
        return Ok(false);
    };
    let Some(result): Option<i64> = row.try_get("result_profile_id")? else {
        return Ok(false);
    };
    let Some(current) = load(tx, account, result).await? else {
        return Ok(false);
    };
    if !current.policy.membership_complete
        || Some(current.revision) != row.try_get::<Option<i64>, _>("result_revision_id")?
        || Some(membership(&current))
            != row.try_get::<Option<String>, _>("result_members_sha256")?
        || !store::controls_admit(tx, account).await?.0
    {
        return Ok(false);
    }
    let left: i64 = row.try_get("left_profile_id")?;
    let right: i64 = row.try_get("right_profile_id")?;
    let original=sqlx::query("SELECT m.source_profile_id,m.sample_id,m.source_assignment_id, \
      coalesce(a.profile_id=m.source_profile_id AND NOT a.active AND current.proposal_id=$2 AND current.predecessor_assignment_id=a.id,false) valid \
      FROM voice_profile_proposal_samples m LEFT JOIN voice_sample_profile_assignments a ON a.account_id=m.account_id AND a.id=m.source_assignment_id \
      LEFT JOIN voice_sample_profile_assignments current ON current.account_id=m.account_id AND current.sample_id=m.sample_id AND current.active \
      WHERE m.account_id=$1 AND m.proposal_id=$2 ORDER BY m.sample_id")
        .bind(account).bind(proposal).fetch_all(&mut **tx).await?;
    if original.len() != current.members.len()
        || original.iter().any(|m| !m.get::<bool, _>("valid"))
    {
        return Ok(false);
    }
    for (profile, count_key, hash_key, revision_key, person_key) in [
        (
            left,
            "left_member_count",
            "left_members_sha256",
            "left_superseded_revision_id",
            "left_person_id",
        ),
        (
            right,
            "right_member_count",
            "right_members_sha256",
            "right_superseded_revision_id",
            "right_person_id",
        ),
    ] {
        let members = original
            .iter()
            .filter(|m| m.get::<i64, _>("source_profile_id") == profile)
            .map(|m| {
                (
                    m.get::<i64, _>("sample_id"),
                    m.get::<i64, _>("source_assignment_id"),
                )
            })
            .collect::<Vec<_>>();
        if members.len() as i64 != row.try_get::<i64, _>(count_key)?
            || digest(&json!(members)) != row.try_get::<String, _>(hash_key)?
        {
            return Ok(false);
        }
        let intact:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM voice_profiles p JOIN voice_profile_revisions r ON r.account_id=p.account_id AND r.profile_id=p.id AND r.active WHERE p.account_id=$1 AND p.id=$2 AND p.status='quarantined' AND p.sample_count=0 AND p.person_id IS NOT DISTINCT FROM $5 AND r.id=$3 AND r.status='superseded' AND r.proposal_id=$4 AND NOT EXISTS(SELECT 1 FROM voice_sample_profile_assignments a WHERE a.account_id=p.account_id AND a.profile_id=p.id AND a.active))")
            .bind(account).bind(profile).bind(row.try_get::<Option<i64>,_>(revision_key)?).bind(proposal).bind(row.try_get::<Option<i64>,_>(person_key)?).fetch_one(&mut **tx).await?;
        if !intact {
            return Ok(false);
        }
    }
    let (count, hash) = slot_commitment(tx, account, proposal).await?;
    if count != row.try_get::<i64, _>("slot_count")?
        || Some(hash) != row.try_get::<Option<String>, _>("slots_sha256")?
    {
        return Ok(false);
    }
    let slots_intact:bool=sqlx::query_scalar("SELECT NOT EXISTS(SELECT 1 FROM voice_profile_proposal_slots p LEFT JOIN episode_speaker_slots s ON s.account_id=p.account_id AND s.id=p.slot_id WHERE p.account_id=$1 AND p.proposal_id=$2 AND (s.id IS NULL OR s.episode_id<>p.episode_id OR s.slot_ordinal<>p.slot_ordinal OR s.voice_profile_id IS DISTINCT FROM $3 OR s.speaker_cluster_id IS NOT NULL OR s.status IS DISTINCT FROM p.applied_status)) AND NOT EXISTS(SELECT 1 FROM episode_speaker_slots s WHERE s.account_id=$1 AND s.voice_profile_id=ANY($4) AND NOT EXISTS(SELECT 1 FROM voice_profile_proposal_slots p WHERE p.account_id=s.account_id AND p.proposal_id=$2 AND p.slot_id=s.id))")
        .bind(account).bind(proposal).bind(result).bind([left,right,result].as_slice()).fetch_one(&mut **tx).await?;
    if !slots_intact {
        return Ok(false);
    }
    let expected: Value = serde_json::from_str(&row.try_get::<String, _>("applied_person_text")?)?;
    let Some(people) = expected
        .get("people")
        .and_then(Value::as_array)
        .and_then(|ids| ids.iter().map(Value::as_i64).collect::<Option<Vec<_>>>())
    else {
        return Ok(false);
    };
    if identity_commitment(tx, account, &people).await? != expected {
        return Ok(false);
    }
    if current
        .members
        .iter()
        .map(|m| m.sample)
        .collect::<BTreeSet<_>>()
        != original
            .iter()
            .map(|m| m.get::<i64, _>("sample_id"))
            .collect::<BTreeSet<_>>()
    {
        return Ok(false);
    }
    // All refusal checks precede writes. New assignments point to the merge's
    // successors; no historical row is reactivated and no deleted bytes return.
    let mut clusters = BTreeSet::new();
    for member in &current.members {
        let Some(source) = original
            .iter()
            .find(|m| m.get::<i64, _>("sample_id") == member.sample)
        else {
            return Ok(false);
        };
        reassign(
            tx,
            account,
            member,
            source.try_get("source_profile_id")?,
            proposal,
        )
        .await?;
        clusters.extend(member.cluster);
    }
    sqlx::query("UPDATE episode_speaker_slots s SET voice_profile_id=p.source_profile_id,speaker_cluster_id=p.source_cluster_id,status=p.source_status,updated_at=clock_timestamp() FROM voice_profile_proposal_slots p WHERE s.account_id=$1 AND p.account_id=s.account_id AND p.proposal_id=$2 AND p.slot_id=s.id")
        .bind(account).bind(proposal).execute(&mut **tx).await?;
    let clusters = clusters.into_iter().collect::<Vec<_>>();
    // Unquarantine only this exact superseded source, never arbitrary profiles.
    for source in [left, right] {
        sqlx::query("UPDATE voice_profiles SET status='tentative' WHERE account_id=$1 AND id=$2")
            .bind(account)
            .bind(source)
            .execute(&mut **tx)
            .await?;
    }
    super::owner_voice::refresh_clusters(tx, account, &clusters).await?;
    for source in [left, right] {
        store::recompute_profile(tx, account, source, "proposal_reversal").await?;
        revision(tx, account, source, proposal, false).await?;
    }
    sqlx::query("UPDATE voice_profiles SET status='quarantined',centroid=''::bytea,sample_count=0,medoid_sample_id=NULL WHERE account_id=$1 AND id=$2").bind(account).bind(result).execute(&mut **tx).await?;
    sqlx::query("DELETE FROM voice_profile_representatives WHERE account_id=$1 AND profile_id=$2")
        .bind(account)
        .bind(result)
        .execute(&mut **tx)
        .await?;
    revision(tx, account, result, proposal, true).await?;
    super::voice_recurrence::refresh(tx, account).await?;
    store::refresh_affected_speaker_projections(
        tx,
        account,
        &clusters,
        &[left, right, result],
        &people,
    )
    .await?;
    sqlx::query("UPDATE voice_profile_proposals SET state='reversed',reason='new_competitor',updated_at=clock_timestamp() WHERE account_id=$1 AND id=$2")
        .bind(account).bind(proposal).execute(&mut **tx).await?;
    Ok(true)
}

/// Reconsider the original partition when a new current competitor removes
/// its mutual margin. Reversal still needs the exact untouched applied state.
async fn reconsider(
    tx: &mut Transaction<'_, Postgres>,
    account: &str,
    proposal: i64,
) -> Result<bool> {
    let row=sqlx::query("SELECT left_profile_id,right_profile_id,result_profile_id FROM voice_profile_proposals WHERE account_id=$1 AND id=$2 AND state='applied'").bind(account).bind(proposal).fetch_one(&mut **tx).await?;
    let Some(result): Option<i64> = row.try_get("result_profile_id")? else {
        return Ok(false);
    };
    let Some(current) = load(tx, account, result).await? else {
        return Ok(false);
    };
    if !current.policy.membership_complete {
        return Ok(false);
    }
    let candidates = population(tx, account).await?;
    if candidates.len() > policy::MAX_PROFILES - 1 {
        return Ok(false);
    }
    let mut profiles = candidates
        .into_iter()
        .filter(|c| c.policy.id != result)
        .map(|c| c.policy)
        .collect::<Vec<_>>();
    for key in ["left_profile_id", "right_profile_id"] {
        let source: i64 = row.try_get(key)?;
        let observations:Vec<i64>=sqlx::query_scalar("SELECT s.speaker_observation_id FROM voice_profile_proposal_samples m JOIN voice_samples s ON s.account_id=m.account_id AND s.id=m.sample_id WHERE m.account_id=$1 AND m.proposal_id=$2 AND m.source_profile_id=$3 ORDER BY m.sample_id")
            .bind(account).bind(proposal).bind(source).fetch_all(&mut **tx).await?;
        let samples = current
            .policy
            .samples
            .iter()
            .filter(|s| observations.contains(&s.0))
            .cloned()
            .collect::<Vec<_>>();
        let Some(representative) = voice_identity::representative(&samples)? else {
            return Ok(false);
        };
        let mut original = current.policy.clone();
        original.id = source;
        original.samples = samples;
        original.centroid = representative.centroid;
        profiles.push(original);
    }
    let left: i64 = row.try_get("left_profile_id")?;
    let right: i64 = row.try_get("right_profile_id")?;
    if policy::merge_pairs(&profiles)
        .iter()
        .any(|p| p.left == left && p.right == right)
    {
        return Ok(false);
    }
    reverse(tx, account, proposal).await
}

pub(super) async fn reconcile(
    tx: &mut Transaction<'_, Postgres>,
    account: &str,
) -> Result<Vec<&'static str>> {
    let mut outcomes = Vec::new();
    let changed = super::identity_fusion::reconcile_profiles(tx, account, &[], true).await?;
    store::refresh_affected_speaker_projections(tx, account, &[], &changed, &[]).await?;
    let applied:Vec<i64>=sqlx::query_scalar("SELECT id FROM voice_profile_proposals WHERE account_id=$1 AND state='applied' ORDER BY updated_at,id LIMIT $2")
        .bind(account).bind(policy::MAX_PROPOSALS as i64).fetch_all(&mut **tx).await?;
    for proposal in applied {
        if reconsider(tx, account, proposal).await? {
            outcomes.push("profile_merge_reversed");
        }
        sqlx::query("UPDATE voice_profile_proposals SET updated_at=clock_timestamp() WHERE account_id=$1 AND id=$2").bind(account).bind(proposal).execute(&mut **tx).await?;
    }
    for _ in 0..policy::MAX_PROPOSALS {
        let candidates = population(tx, account).await?;
        let profiles = candidates
            .iter()
            .map(|c| c.policy.clone())
            .collect::<Vec<_>>();
        if profiles.len() > policy::MAX_PROFILES {
            outcomes.push("profile_merge_population_held");
            break;
        }
        // All profiles remain acoustic competitors. Only scheduling filters a
        // pair whose complete assigned support exceeds the application bound.
        let held = held_name_profiles(tx, account).await?;
        let Some(pair) = policy::merge_pairs(&profiles).into_iter().find(|pair| {
            !held.contains(&pair.left)
                && !held.contains(&pair.right)
                && candidates
                    .iter()
                    .filter(|c| c.policy.id == pair.left || c.policy.id == pair.right)
                    .map(|c| c.members.len())
                    .sum::<usize>()
                    <= policy::MAX_SAMPLES
        }) else {
            break;
        };
        let left = candidates
            .iter()
            .find(|c| c.policy.id == pair.left)
            .expect("policy candidate");
        let right = candidates
            .iter()
            .find(|c| c.policy.id == pair.right)
            .expect("policy candidate");
        if apply(tx, account, left, right).await?.is_some() {
            outcomes.push("profile_merge_applied");
        } else {
            outcomes.push("profile_merge_state_held");
            break;
        }
    }
    Ok(outcomes)
}

#[cfg(test)]
mod tests {
    use super::super::{tests::ControlPlaneContractFixture, PostgresPersistence};
    use super::*;
    use crate::persistence::{MemoryQueryRepository, VoiceCohort, VoiceIdentityRepository};
    const ACCOUNT: &str = "synthetic-profile-proposals";
    fn vector(a: f32, b: f32) -> Vec<f32> {
        let mut v = vec![0.; 256];
        v[0] = a;
        v[1] = b;
        v
    }
    async fn sample(repo: &PostgresPersistence, profile: i64, id: i64, memory: i64, v: &[f32]) {
        super::super::voice_identity::tests::seed_voice_observation(
            repo,
            ACCOUNT,
            "recording",
            &format!("event-{id}"),
            id,
            id,
        )
        .await;
        super::super::voice_identity::tests::seed_voice_memory(repo, ACCOUNT, id, memory).await;
        let mut tx = repo.pool().begin().await.unwrap();
        assert!(store::lock_account(&mut tx, ACCOUNT).await.unwrap());
        sqlx::query("INSERT INTO voice_profiles(account_id,id,label,embedding_space,channel_domain,centroid,scorer_version) VALUES($1,$2,$3,$4,'macos:builtin_mic',$5,$6) ON CONFLICT DO NOTHING")
            .bind(ACCOUNT).bind(profile).bind(format!("voice-profile-{profile}")).bind(EMBEDDING_SPACE).bind(voice_identity::encode_embedding(v).unwrap()).bind(SCORER_VERSION).execute(&mut *tx).await.unwrap();
        sqlx::query("INSERT INTO voice_samples(account_id,id,speaker_observation_id,embedding_space,channel_domain,embedding,quality_score,quality_version,scorer_version,eligibility,duration_ms,accepted,embedding_job_id) VALUES($1,$2,$2,$3,'macos:builtin_mic',$4,1,$5,$6,'enroll',4000,true,$2)")
            .bind(ACCOUNT).bind(id).bind(EMBEDDING_SPACE).bind(voice_identity::encode_embedding(v).unwrap()).bind(crate::cp::voice_quality::QUALITY_VERSION).bind(SCORER_VERSION).execute(&mut *tx).await.unwrap();
        super::super::owner_voice::assign_sample(&mut tx, ACCOUNT, id, id, profile, None)
            .await
            .unwrap();
        super::super::owner_voice::refresh_clusters(&mut tx, ACCOUNT, &[id])
            .await
            .unwrap();
        store::recompute_profile(&mut tx, ACCOUNT, profile, "synthetic_seed")
            .await
            .unwrap();
        store::refresh_affected_speaker_projections(&mut tx, ACCOUNT, &[id], &[profile], &[])
            .await
            .unwrap();
        sqlx::query("UPDATE voice_embedding_jobs SET state='ready' WHERE account_id=$1 AND id=$2")
            .bind(ACCOUNT)
            .bind(id)
            .execute(&mut *tx)
            .await
            .unwrap();
        tx.commit().await.unwrap();
    }
    async fn pair() -> Option<ControlPlaneContractFixture> {
        pair_at(1).await
    }
    async fn pair_at(first: i64) -> Option<ControlPlaneContractFixture> {
        let f = super::super::tests::test_persistence().await?;
        f.persistence
            .set_voice_identity_cohort(VoiceCohort::All, &[])
            .await
            .unwrap();
        for (profile, a, b, memories) in
            [(first, 1., 0., [1, 2, 3]), (first + 1, 0.8, 0.6, [1, 4, 5])]
        {
            for (n, memory) in memories.into_iter().enumerate() {
                sample(
                    &f.persistence,
                    profile,
                    profile * 100 + n as i64 + 1,
                    memory,
                    &vector(a, b),
                )
                .await;
            }
        }
        Some(f)
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
        f.base.pool().close().await;
    }
    async fn source(repo: &PostgresPersistence) -> String {
        sqlx::query_scalar("SELECT jsonb_build_object('turns',(SELECT jsonb_agg(to_jsonb(u) ORDER BY id) FROM utterances u WHERE account_id=$1),'members',(SELECT jsonb_agg(to_jsonb(m) ORDER BY episode_id,record_id) FROM episode_members m WHERE account_id=$1),'archive',(SELECT revision FROM memory_archive_state WHERE account_id=$1))::text").bind(ACCOUNT).fetch_one(repo.pool()).await.unwrap()
    }
    async fn proposal(repo: &PostgresPersistence) -> (i64, i64) {
        sqlx::query_as("SELECT id,result_profile_id FROM voice_profile_proposals WHERE account_id=$1 AND state='applied' ORDER BY id LIMIT 1").bind(ACCOUNT).fetch_one(repo.pool()).await.unwrap()
    }
    async fn reverse_now(repo: &PostgresPersistence, id: i64) -> bool {
        let mut tx = repo.pool().begin().await.unwrap();
        assert!(store::lock_account(&mut tx, ACCOUNT).await.unwrap());
        let result = reverse(&mut tx, ACCOUNT, id).await.unwrap();
        tx.commit().await.unwrap();
        result
    }

    #[tokio::test]
    async fn exact_merge_and_reversal_preserve_source_letters_and_append_only_lineage() {
        let Some(f) = pair().await else { return };
        let repo = &f.persistence;
        let before = source(repo).await;
        let before_revisions: Vec<(i64, i64)> = sqlx::query_as(
            "SELECT id,identity_revision FROM episodes WHERE account_id=$1 ORDER BY id",
        )
        .bind(ACCOUNT)
        .fetch_all(repo.pool())
        .await
        .unwrap();
        let slots:Vec<(i64,i64,i64)>=sqlx::query_as("SELECT id,episode_id,slot_ordinal FROM episode_speaker_slots WHERE account_id=$1 ORDER BY id").bind(ACCOUNT).fetch_all(repo.pool()).await.unwrap();
        let (a, b) = tokio::join!(
            repo.maintain_voice_profiles(ACCOUNT),
            repo.maintain_voice_profiles(ACCOUNT)
        );
        a.unwrap();
        b.unwrap();
        let proposals: i64 =
            sqlx::query_scalar("SELECT count(*) FROM voice_profile_proposals WHERE account_id=$1")
                .bind(ACCOUNT)
                .fetch_one(repo.pool())
                .await
                .unwrap();
        assert_eq!(
            proposals, 1,
            "concurrent maintenance must apply one exact profile proposal"
        );
        let (id, result) = proposal(repo).await;
        assert_eq!(sqlx::query_scalar::<_,i64>("SELECT count(*) FROM voice_sample_profile_assignments WHERE account_id=$1 AND profile_id=$2 AND active AND proposal_id=$3 AND predecessor_assignment_id IS NOT NULL").bind(ACCOUNT).bind(result).bind(id).fetch_one(repo.pool()).await.unwrap(),6,"every merged sample must preserve its exact assignment predecessor");
        assert_eq!(sqlx::query_as::<_,(i64,i64,i64)>("SELECT id,episode_id,slot_ordinal FROM episode_speaker_slots WHERE account_id=$1 ORDER BY id").bind(ACCOUNT).fetch_all(repo.pool()).await.unwrap(),slots,"merging profiles must preserve every original letter reservation");
        assert_eq!(sqlx::query_scalar::<_,i64>("SELECT slot_ordinal FROM episode_speaker_slots WHERE account_id=$1 AND episode_id=1 AND status='active'").bind(ACCOUNT).fetch_one(repo.pool()).await.unwrap(),0,"a shared memory must keep the earliest existing speaker letter");
        assert_eq!(
            source(repo).await,
            before,
            "profile merge must not rewrite source turns, membership or archive coordinates"
        );
        let merged_revisions: Vec<(i64, i64)> = sqlx::query_as(
            "SELECT id,identity_revision FROM episodes WHERE account_id=$1 ORDER BY id",
        )
        .bind(ACCOUNT)
        .fetch_all(repo.pool())
        .await
        .unwrap();
        let expected_revisions = before_revisions
            .iter()
            .map(|(id, revision)| (*id, revision + i64::from([1, 4, 5].contains(id))))
            .collect::<Vec<_>>();
        assert_eq!(
            merged_revisions, expected_revisions,
            "merging public identity advances only memories whose participant meaning changed"
        );
        assert!(
            reverse_now(repo, id).await,
            "an exact untouched proposal must remain reversible"
        );
        assert_eq!(sqlx::query_scalar::<_,i64>("SELECT count(*) FROM voice_sample_profile_assignments WHERE account_id=$1 AND active AND profile_id IN (1,2) AND proposal_id=$2 AND predecessor_assignment_id IS NOT NULL").bind(ACCOUNT).bind(id).fetch_one(repo.pool()).await.unwrap(),6,"reversal must append restorative assignments for every retained sample");
        assert_eq!(sqlx::query_scalar::<_,i64>("SELECT count(*) FROM episode_speaker_slots WHERE account_id=$1 AND episode_id=1 AND status='active'").bind(ACCOUNT).fetch_one(repo.pool()).await.unwrap(),2,"reversal must restore both original speaker letters in a shared memory");
        assert_eq!(
            source(repo).await,
            before,
            "profile reversal must preserve immutable source and archive topology"
        );
        let reversed_revisions: Vec<(i64, i64)> = sqlx::query_as(
            "SELECT id,identity_revision FROM episodes WHERE account_id=$1 ORDER BY id",
        )
        .bind(ACCOUNT)
        .fetch_all(repo.pool())
        .await
        .unwrap();
        let expected_revisions = before_revisions
            .iter()
            .map(|(id, revision)| (*id, revision + 2 * i64::from([1, 4, 5].contains(id))))
            .collect::<Vec<_>>();
        assert_eq!(
            reversed_revisions, expected_revisions,
            "reversing public identity advances the affected presentation revisions again"
        );
        let export = repo.export(ACCOUNT).await.unwrap();
        assert_eq!(
            export["voice_profile_proposals"].as_array().unwrap().len(),
            1,
            "export must include proposal provenance"
        );
        assert_eq!(
            export["voice_profile_proposal_samples"]
                .as_array()
                .unwrap()
                .len(),
            6,
            "export must include exact proposal membership"
        );
        assert!(
            export["voice_profiles"]
                .as_array()
                .unwrap()
                .iter()
                .all(|row| row.get("centroid").is_none())
                && export["voice_samples"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .all(|row| row.get("embedding").is_none()),
            "proposal export must never expose biometric vectors"
        );
        close(f).await;
    }

    #[tokio::test]
    async fn proposal_reversal_refuses_later_samples_identity_changes_and_erased_members() {
        let Some(f) = pair().await else { return };
        let repo = &f.persistence;
        repo.maintain_voice_profiles(ACCOUNT).await.unwrap();
        let (id, result) = proposal(repo).await;
        for mutation in [
            "UPDATE voice_profile_proposals SET result_revision_id=left_revision_id WHERE account_id=$1",
            "UPDATE voice_profile_proposals SET left_members_sha256=repeat('0',64) WHERE account_id=$1",
            "DELETE FROM voice_profile_proposal_samples WHERE account_id=$1 AND sample_id=101",
            "UPDATE episode_speaker_slots SET slot_ordinal=slot_ordinal+10 WHERE account_id=$1",
            "DELETE FROM voice_profile_proposal_slots WHERE account_id=$1 AND slot_id=(SELECT min(slot_id) FROM voice_profile_proposal_slots WHERE account_id=$1)",
            "UPDATE people SET display_name='Later accepted name',status='identified' WHERE account_id=$1 AND id=(SELECT person_id FROM voice_profiles WHERE account_id=$1 AND id=(SELECT result_profile_id FROM voice_profile_proposals WHERE account_id=$1 LIMIT 1))",
        ]{
            let mut tx=repo.pool().begin().await.unwrap();assert!(store::lock_account(&mut tx,ACCOUNT).await.unwrap());
            sqlx::query(sqlx::AssertSqlSafe(mutation)).bind(ACCOUNT).execute(&mut *tx).await.unwrap();
            assert!(!reverse(&mut tx,ACCOUNT,id).await.unwrap(),"stale proposal commitments must refuse reversal without partial writes: {mutation}");
            tx.rollback().await.unwrap();
        }
        sample(repo, result, 701, 7, &vector(1., 0.)).await;
        assert!(
            !reverse_now(repo, id).await,
            "later samples must never be orphaned by reversing an old proposal"
        );
        assert_eq!(sqlx::query_scalar::<_,i64>("SELECT count(*) FROM voice_sample_profile_assignments WHERE account_id=$1 AND profile_id=$2 AND active").bind(ACCOUNT).bind(result).fetch_one(repo.pool()).await.unwrap(),7,"refused reversal must preserve all current sample assignments");
        sqlx::query("DELETE FROM capture_events WHERE account_id=$1 AND event_id='event-101'")
            .bind(ACCOUNT)
            .execute(repo.pool())
            .await
            .unwrap();
        assert!(
            !reverse_now(repo, id).await,
            "erased source samples must not be reconstructed from proposal history"
        );
        close(f).await;
    }

    #[tokio::test]
    async fn stale_apply_and_same_name_identities_are_held() {
        let Some(f) = pair().await else { return };
        let repo = &f.persistence;
        let mut tx = repo.pool().begin().await.unwrap();
        assert!(store::lock_account(&mut tx, ACCOUNT).await.unwrap());
        let left = load(&mut tx, ACCOUNT, 1).await.unwrap().unwrap();
        let right = load(&mut tx, ACCOUNT, 2).await.unwrap().unwrap();
        sqlx::query(
            "UPDATE voice_profiles SET person_id=NULL,sample_count=4 WHERE account_id=$1 AND id=1",
        )
        .bind(ACCOUNT)
        .execute(&mut *tx)
        .await
        .unwrap();
        store::append_revision(&mut tx, ACCOUNT, 1, "synthetic_later_revision")
            .await
            .unwrap();
        assert!(
            apply(&mut tx, ACCOUNT, &left, &right)
                .await
                .unwrap()
                .is_none(),
            "an earlier profile revision must never authorize a later merge"
        );
        tx.rollback().await.unwrap();
        sqlx::query("INSERT INTO people(account_id,id,display_name,status) VALUES($1,11,'Same Name','identified'),($1,12,'Same Name','identified')").bind(ACCOUNT).execute(repo.pool()).await.unwrap();
        sqlx::query("UPDATE voice_profiles SET person_id=id+10 WHERE account_id=$1")
            .bind(ACCOUNT)
            .execute(repo.pool())
            .await
            .unwrap();
        repo.maintain_voice_profiles(ACCOUNT).await.unwrap();
        assert_eq!(sqlx::query_scalar::<_,i64>("SELECT count(*) FROM voice_profile_proposals WHERE account_id=$1").bind(ACCOUNT).fetch_one(repo.pool()).await.unwrap(),0,"identical names on different opaque people must never permit acoustic identity merging");
        close(f).await;
    }

    #[tokio::test]
    async fn new_competitor_reverses_only_the_untouched_original_partition() {
        let Some(f) = pair().await else { return };
        let repo = &f.persistence;
        repo.maintain_voice_profiles(ACCOUNT).await.unwrap();
        let (id, _) = proposal(repo).await;
        for n in 1..=3 {
            sample(repo, 10, 1000 + n, 10 + n, &vector(1., 0.)).await;
        }
        repo.maintain_voice_profiles(ACCOUNT).await.unwrap();
        assert_eq!(
            sqlx::query_scalar::<_, String>(
                "SELECT state FROM voice_profile_proposals WHERE account_id=$1 AND id=$2"
            )
            .bind(ACCOUNT)
            .bind(id)
            .fetch_one(repo.pool())
            .await
            .unwrap(),
            "reversed",
            "a new competing voice must reevaluate and reverse an untouched ambiguous merge"
        );
        assert_eq!(sqlx::query_scalar::<_,i64>("SELECT count(*) FROM voice_sample_profile_assignments WHERE account_id=$1 AND active").bind(ACCOUNT).fetch_one(repo.pool()).await.unwrap(),9,"automatic reevaluation must keep every original and later competing sample assigned");
        close(f).await;
    }

    #[tokio::test]
    async fn old_profile_adoption_quarantines_two_modes_without_reinference() {
        let Some(f) = super::super::tests::test_persistence().await else {
            return;
        };
        let repo = &f.persistence;
        repo.set_voice_identity_cohort(VoiceCohort::All, &[])
            .await
            .unwrap();
        for n in 1..=6 {
            sample(
                repo,
                1,
                n,
                n,
                &if n <= 3 {
                    vector(1., 0.)
                } else {
                    vector(0., 1.)
                },
            )
            .await;
        }
        // Reconstruct the previous policy's stored state, then exercise only
        // provider-free current maintenance on the retained samples.
        sqlx::query("UPDATE voice_profiles SET status='stable' WHERE account_id=$1")
            .bind(ACCOUNT)
            .execute(repo.pool())
            .await
            .unwrap();
        sqlx::query("UPDATE voice_profile_revisions SET derivation_version=2,status='stable' WHERE account_id=$1 AND active").bind(ACCOUNT).execute(repo.pool()).await.unwrap();
        let samples_before: i64 =
            sqlx::query_scalar("SELECT count(*) FROM voice_samples WHERE account_id=$1")
                .bind(ACCOUNT)
                .fetch_one(repo.pool())
                .await
                .unwrap();
        repo.maintain_voice_profiles(ACCOUNT).await.unwrap();
        assert_eq!(sqlx::query_scalar::<_,String>("SELECT status FROM voice_profiles WHERE account_id=$1 AND id=1").bind(ACCOUNT).fetch_one(repo.pool()).await.unwrap(),"quarantined","current policy adoption must quarantine two clean separated modes without splitting them");
        assert!(sqlx::query_scalar::<_,bool>("SELECT derivation_version=3 AND reason_code='bimodal_support' FROM voice_profile_revisions WHERE account_id=$1 AND profile_id=1 AND active").bind(ACCOUNT).fetch_one(repo.pool()).await.unwrap(),"stored older profiles must record the current quarantine policy revision");
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT count(*) FROM voice_samples WHERE account_id=$1")
                .bind(ACCOUNT)
                .fetch_one(repo.pool())
                .await
                .unwrap(),
            samples_before,
            "policy adoption must reuse retained samples without new inference"
        );
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT count(*) FROM voice_profiles WHERE account_id=$1")
                .bind(ACCOUNT)
                .fetch_one(repo.pool())
                .await
                .unwrap(),
            1,
            "bimodal quarantine must never automatically split a profile"
        );
        close(f).await;
    }

    #[tokio::test]
    async fn proposal_source_erasure_invalidates_reversal_and_scrubs_all_ancestral_biometrics() {
        let Some(f) = pair().await else { return };
        let repo = &f.persistence;
        repo.maintain_voice_profiles(ACCOUNT).await.unwrap();
        let (id, result) = proposal(repo).await;
        let mut probe = repo.pool().begin().await.unwrap();
        assert!(store::lock_account(&mut probe, ACCOUNT).await.unwrap());
        assert!(
            reverse(&mut probe, ACCOUNT, id).await.unwrap(),
            "the retained original proposal must be reversible before erasure"
        );
        probe.rollback().await.unwrap();
        let mut tx = repo.pool().begin().await.unwrap();
        assert!(store::lock_account(&mut tx, ACCOUNT).await.unwrap());
        let affected = store::erase_event_samples(&mut tx, ACCOUNT, &["event-101".into()])
            .await
            .unwrap();
        sqlx::query("DELETE FROM capture_events WHERE account_id=$1 AND event_id='event-101'")
            .bind(ACCOUNT)
            .execute(&mut *tx)
            .await
            .unwrap();
        store::recompute_erased_profiles(&mut tx, ACCOUNT, &affected)
            .await
            .unwrap();
        tx.commit().await.unwrap();
        assert!(
            !reverse_now(repo, id).await,
            "erasing one original proposal member must invalidate exact reversal"
        );
        assert!(sqlx::query_scalar::<_,bool>("SELECT NOT EXISTS(SELECT 1 FROM voice_profile_revisions WHERE account_id=$1 AND profile_id=ANY($2) AND NOT active AND octet_length(centroid)>0)").bind(ACCOUNT).bind([1,result].as_slice()).fetch_one(repo.pool()).await.unwrap(),"source erasure must scrub every historical centroid touched by the deleted sample");
        assert_eq!(sqlx::query_scalar::<_,i64>("SELECT left_member_count FROM voice_profile_proposals WHERE account_id=$1 AND id=$2").bind(ACCOUNT).bind(id).fetch_one(repo.pool()).await.unwrap(),3,"deletion must not rewrite a proposal's original membership commitment");
        sqlx::query("INSERT INTO accounts(id,email,primary_provider,primary_subject) VALUES('other-proposal-tenant','other@example.test','google','other-proposal-tenant')").execute(repo.pool()).await.unwrap();
        let other = repo.export("other-proposal-tenant").await.unwrap();
        for name in [
            "voice_profile_proposals",
            "voice_profile_proposal_samples",
            "voice_profile_proposal_slots",
        ] {
            assert!(
                other[name].as_array().unwrap().is_empty(),
                "proposal export must be tenant-qualified: {name}"
            );
        }
        sqlx::query("DELETE FROM accounts WHERE id=$1")
            .bind(ACCOUNT)
            .execute(repo.pool())
            .await
            .unwrap();
        assert_eq!(sqlx::query_scalar::<_,i64>("SELECT (SELECT count(*) FROM voice_profile_proposals)+(SELECT count(*) FROM voice_profile_proposal_samples)+(SELECT count(*) FROM voice_profile_proposal_slots)").fetch_one(repo.pool()).await.unwrap(),0,"account erasure must cascade through every proposal metadata family");
        assert!(
            sqlx::query_scalar::<_, bool>(
                "SELECT EXISTS(SELECT 1 FROM accounts WHERE id='other-proposal-tenant')"
            )
            .fetch_one(repo.pool())
            .await
            .unwrap(),
            "proposal erasure must preserve another tenant"
        );
        close(f).await;
    }

    #[tokio::test]
    async fn older_owner_and_pending_nonowner_profiles_remain_competitors() {
        let Some(f) = pair().await else { return };
        let repo = &f.persistence;
        for n in 1..=3 {
            sample(repo, 10, 1000 + n, 10 + n, &vector(1., 0.)).await;
        }
        sqlx::query("UPDATE voice_profile_revisions SET derivation_version=2 WHERE account_id=$1 AND profile_id=10 AND active").bind(ACCOUNT).execute(repo.pool()).await.unwrap();
        let mut tx = repo.pool().begin().await.unwrap();
        assert!(store::lock_account(&mut tx, ACCOUNT).await.unwrap());
        let candidates = population(&mut tx, ACCOUNT).await.unwrap();
        assert!(
            candidates
                .iter()
                .any(|c| c.policy.id == 10 && !c.policy.membership_complete),
            "a pending older profile must remain a runner-up while ineligible to merge"
        );
        assert!(
            reconcile(&mut tx, ACCOUNT).await.unwrap().is_empty(),
            "a closer pending-adoption voice must prevent an incomplete-population merge"
        );
        tx.rollback().await.unwrap();
        sqlx::query("INSERT INTO people(account_id,id,status) VALUES($1,55,'owner')")
            .bind(ACCOUNT)
            .execute(repo.pool())
            .await
            .unwrap();
        sqlx::query("UPDATE voice_profiles SET person_id=55 WHERE account_id=$1 AND id=10")
            .bind(ACCOUNT)
            .execute(repo.pool())
            .await
            .unwrap();
        sqlx::query("UPDATE voice_profile_revisions SET person_id=55 WHERE account_id=$1 AND profile_id=10 AND active").bind(ACCOUNT).execute(repo.pool()).await.unwrap();
        repo.maintain_voice_profiles(ACCOUNT).await.unwrap();
        assert_eq!(
            sqlx::query_scalar::<_, i64>(
                "SELECT count(*) FROM voice_profile_proposals WHERE account_id=$1"
            )
            .bind(ACCOUNT)
            .fetch_one(repo.pool())
            .await
            .unwrap(),
            0,
            "an older usable owner must remain a competitor against nonowner fragment merging"
        );
        close(f).await;
    }

    #[tokio::test]
    async fn large_old_profiles_adopt_complete_support_and_still_detect_two_modes() {
        for mixed in [false, true] {
            let Some(f) = super::super::tests::test_persistence().await else {
                return;
            };
            let repo = &f.persistence;
            repo.set_voice_identity_cohort(VoiceCohort::All, &[])
                .await
                .unwrap();
            for id in 1..=3 {
                sample(repo, 1, id, id, &vector(1., 0.)).await;
            }
            // Large synthetic stored-support fixture. This tests policy over
            // accepted observations, not a claim about real recorded speakers.
            sqlx::query("INSERT INTO speaker_observations(account_id,id,event_id,turn_id,speaker_local_id,started_at,ended_at,transcript_text,cluster_id,voice_profile_id) SELECT o.account_id,n,o.event_id,'synthetic-turn-'||n,o.speaker_local_id,o.started_at,o.ended_at,o.transcript_text,o.cluster_id,1 FROM speaker_observations o CROSS JOIN generate_series(4,260) n WHERE o.account_id=$1 AND o.id=1")
                .bind(ACCOUNT).execute(repo.pool()).await.unwrap();
            sqlx::query("INSERT INTO speaker_observation_sources(account_id,speaker_observation_id,event_id,window_start_ms,window_end_ms,event_start_ms,event_end_ms) SELECT account_id,n,event_id,window_start_ms,window_end_ms,event_start_ms,event_end_ms FROM speaker_observation_sources CROSS JOIN generate_series(4,260) n WHERE account_id=$1 AND speaker_observation_id=1")
                .bind(ACCOUNT).execute(repo.pool()).await.unwrap();
            sqlx::query("INSERT INTO voice_samples(account_id,id,speaker_observation_id,voice_profile_id,embedding_space,channel_domain,embedding,quality_score,quality_version,scorer_version,eligibility,duration_ms,accepted) SELECT account_id,n,n,1,embedding_space,channel_domain,CASE WHEN n>130 AND $2 THEN $3 ELSE embedding END,quality_score,quality_version,scorer_version,'enroll',4000,true FROM voice_samples CROSS JOIN generate_series(4,260) n WHERE account_id=$1 AND id=1")
                .bind(ACCOUNT).bind(mixed).bind(voice_identity::encode_embedding(&vector(0.,1.)).unwrap()).execute(repo.pool()).await.unwrap();
            sqlx::query("INSERT INTO voice_sample_profile_assignments(account_id,id,sample_id,profile_id) SELECT $1,10000+n,n,1 FROM generate_series(4,260) n").bind(ACCOUNT).execute(repo.pool()).await.unwrap();
            sqlx::query(
                "UPDATE speaker_observations SET voice_sample_id=id WHERE account_id=$1 AND id>=4",
            )
            .bind(ACCOUNT)
            .execute(repo.pool())
            .await
            .unwrap();
            sqlx::query("UPDATE voice_profile_revisions SET derivation_version=2 WHERE account_id=$1 AND active").bind(ACCOUNT).execute(repo.pool()).await.unwrap();
            repo.maintain_voice_profiles(ACCOUNT).await.unwrap();
            let (version,status):(i64,String)=sqlx::query_as("SELECT r.derivation_version,p.status FROM voice_profiles p JOIN voice_profile_revisions r ON r.account_id=p.account_id AND r.profile_id=p.id AND r.active WHERE p.account_id=$1 AND p.id=1").bind(ACCOUNT).fetch_one(repo.pool()).await.unwrap();
            assert_eq!(version,3,"complete older support above the proposal sample bound must still adopt the current policy");
            assert_eq!(
                status,
                if mixed { "quarantined" } else { "stable" },
                "complete large support must detect two modes while preserving a coherent voice"
            );
            assert_eq!(
                sqlx::query_scalar::<_, i64>(
                    "SELECT count(*) FROM voice_samples WHERE account_id=$1"
                )
                .bind(ACCOUNT)
                .fetch_one(repo.pool())
                .await
                .unwrap(),
                260,
                "large-profile adoption must not infer or discard stored samples"
            );
            close(f).await;
        }
    }

    #[tokio::test]
    async fn proposal_budget_cannot_reverse_an_unchanged_partition() {
        let Some(f) = pair_at(100).await else { return };
        let repo = &f.persistence;
        repo.maintain_voice_profiles(ACCOUNT).await.unwrap();
        let (id, _) = proposal(repo).await;
        for profile in 1..=8 {
            for n in 1..=3 {
                sample(
                    repo,
                    profile,
                    profile * 100 + n,
                    profile * 100 + n,
                    &if profile % 2 == 1 {
                        vector(1., 0.)
                    } else {
                        vector(0.8, 0.6)
                    },
                )
                .await;
            }
            let domain = format!("synthetic-domain-{}", (profile - 1) / 2);
            sqlx::query(
                "UPDATE voice_profiles SET channel_domain=$3 WHERE account_id=$1 AND id=$2",
            )
            .bind(ACCOUNT)
            .bind(profile)
            .bind(&domain)
            .execute(repo.pool())
            .await
            .unwrap();
            sqlx::query("UPDATE voice_samples SET channel_domain=$3 WHERE account_id=$1 AND voice_profile_id=$2").bind(ACCOUNT).bind(profile).bind(&domain).execute(repo.pool()).await.unwrap();
        }
        let mut tx = repo.pool().begin().await.unwrap();
        assert!(store::lock_account(&mut tx, ACCOUNT).await.unwrap());
        assert!(
            !reconsider(&mut tx, ACCOUNT, id).await.unwrap(),
            "four earlier proposals must not invalidate an unchanged high-ID merge"
        );
        assert_eq!(
            sqlx::query_scalar::<_, String>(
                "SELECT state FROM voice_profile_proposals WHERE account_id=$1 AND id=$2"
            )
            .bind(ACCOUNT)
            .bind(id)
            .fetch_one(&mut *tx)
            .await
            .unwrap(),
            "applied",
            "proposal scheduling must never masquerade as new acoustic evidence"
        );
        tx.commit().await.unwrap();
        close(f).await;
    }

    #[tokio::test]
    async fn oversized_pair_cannot_starve_a_later_applicable_merge() {
        for eligibility in ["enroll", "match_only"] {
            let Some(f) = pair_at(100).await else { return };
            let repo = &f.persistence;
            sqlx::query("UPDATE voice_profiles SET channel_domain='synthetic-later-domain' WHERE account_id=$1")
                .bind(ACCOUNT).execute(repo.pool()).await.unwrap();
            sqlx::query("UPDATE voice_samples SET channel_domain='synthetic-later-domain' WHERE account_id=$1")
                .bind(ACCOUNT).execute(repo.pool()).await.unwrap();
            for profile in [1, 2] {
                for n in 1..=3 {
                    sample(
                        repo,
                        profile,
                        profile * 100 + n,
                        profile * 100 + n,
                        &if profile == 1 {
                            vector(1., 0.)
                        } else {
                            vector(0.8, 0.6)
                        },
                    )
                    .await;
                }
                // Each profile is individually within the proposal bound, but
                // their combined assigned membership is 264. Match-only support
                // counts toward that bound even though it never grows centroids.
                sqlx::query("INSERT INTO speaker_observations(account_id,id,event_id,turn_id,speaker_local_id,started_at,ended_at,transcript_text,cluster_id,voice_profile_id) SELECT o.account_id,$2::bigint*1000+n,o.event_id,'synthetic-extra-'||n,o.speaker_local_id,o.started_at,o.ended_at,o.transcript_text,o.cluster_id,$2 FROM speaker_observations o CROSS JOIN generate_series(1,129) n WHERE o.account_id=$1 AND o.id=$2::bigint*100+1")
                    .bind(ACCOUNT).bind(profile).execute(repo.pool()).await.unwrap();
                sqlx::query("INSERT INTO speaker_observation_sources(account_id,speaker_observation_id,event_id,window_start_ms,window_end_ms,event_start_ms,event_end_ms) SELECT account_id,$2::bigint*1000+n,event_id,window_start_ms,window_end_ms,event_start_ms,event_end_ms FROM speaker_observation_sources CROSS JOIN generate_series(1,129) n WHERE account_id=$1 AND speaker_observation_id=$2::bigint*100+1")
                    .bind(ACCOUNT).bind(profile).execute(repo.pool()).await.unwrap();
                sqlx::query("INSERT INTO voice_samples(account_id,id,speaker_observation_id,voice_profile_id,embedding_space,channel_domain,embedding,quality_score,quality_version,scorer_version,eligibility,duration_ms,accepted) SELECT account_id,$2::bigint*1000+n,$2::bigint*1000+n,$2,embedding_space,channel_domain,embedding,quality_score,quality_version,scorer_version,$3,4000,true FROM voice_samples CROSS JOIN generate_series(1,129) n WHERE account_id=$1 AND id=$2::bigint*100+1")
                    .bind(ACCOUNT).bind(profile).bind(eligibility).execute(repo.pool()).await.unwrap();
                sqlx::query("INSERT INTO voice_sample_profile_assignments(account_id,id,sample_id,profile_id) SELECT $1,1000000+$2::bigint*1000+n,$2::bigint*1000+n,$2 FROM generate_series(1,129) n")
                    .bind(ACCOUNT).bind(profile).execute(repo.pool()).await.unwrap();
                sqlx::query("UPDATE speaker_observations SET voice_sample_id=id WHERE account_id=$1 AND id BETWEEN $2::bigint*1000+1 AND $2::bigint*1000+129")
                    .bind(ACCOUNT).bind(profile).execute(repo.pool()).await.unwrap();
                let mut tx = repo.pool().begin().await.unwrap();
                assert!(store::lock_account(&mut tx, ACCOUNT).await.unwrap());
                store::recompute_profile(&mut tx, ACCOUNT, profile, "synthetic_large_pair")
                    .await
                    .unwrap();
                tx.commit().await.unwrap();
            }
            repo.maintain_voice_profiles(ACCOUNT).await.unwrap();
            assert_eq!(sqlx::query_as::<_,(i64,i64)>("SELECT left_profile_id,right_profile_id FROM voice_profile_proposals WHERE account_id=$1 AND state='applied' ORDER BY id")
                .bind(ACCOUNT).fetch_all(repo.pool()).await.unwrap(),vec![(100,101)],
                "an oversized earlier pair must not starve an independent applicable merge: {eligibility}");
            assert_eq!(sqlx::query_scalar::<_,i64>("SELECT count(*) FROM voice_sample_profile_assignments WHERE account_id=$1 AND active AND profile_id IN (1,2)")
                .bind(ACCOUNT).fetch_one(repo.pool()).await.unwrap(),264,
                "skipping an oversized pair must preserve every original assignment");
            close(f).await;
        }
    }
}
