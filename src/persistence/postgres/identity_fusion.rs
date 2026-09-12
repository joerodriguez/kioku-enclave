//! Source-backed name inputs and deterministic profile/fact maintenance.
use std::collections::{BTreeMap, BTreeSet, HashMap};

use serde_json::json;
use sha2::{Digest, Sha256};
use sqlx::{Postgres, Row, Transaction};

use super::{allocate_content_id, voice_identity};
use crate::{
    cp::{
        identity_fusion::{self as policy, Input, Kind, Status},
        media::AudioTurn,
    },
    error::Result,
    persistence::{
        is_supported_self_identification, names_form_refinement, prefer_claimed_display_name,
        MediaProcessingClaim,
    },
};

fn literal_words(text: &str) -> Vec<String> {
    text.split_whitespace()
        .map(|word| {
            word.trim_matches(|c: char| !c.is_alphanumeric())
                .to_lowercase()
        })
        .filter(|word| !word.is_empty())
        .collect()
}
fn grounded(text: &str, evidence: &str) -> bool {
    let text = literal_words(text);
    let evidence = literal_words(evidence);
    !evidence.is_empty() && text.windows(evidence.len()).any(|words| words == evidence)
}

/// Runs after all work-unit observations exist, so a forward target is as valid
/// as an earlier target. Source and named subject are separate typed edges.
pub(super) async fn record_audio(
    tx: &mut Transaction<'_, Postgres>,
    account: &str,
    claim: &MediaProcessingClaim,
    turns: &[AudioTurn],
    observations: &HashMap<String, i64>,
    owner_source: bool,
) -> Result<()> {
    let mut direct = BTreeMap::<i64, Vec<(i64, String)>>::new();
    for turn in turns {
        let observation = observations[&turn.turn_id];
        let row = sqlx::query(
            "SELECT event_id,cluster_id FROM speaker_observations WHERE account_id=$1 AND id=$2",
        )
        .bind(account)
        .bind(observation)
        .fetch_one(&mut **tx)
        .await?;
        let event: String = row.try_get("event_id")?;
        let cluster: i64 = row.try_get("cluster_id")?;
        for (ordinal, fact) in turn.person_facts.iter().enumerate() {
            let Some(score) = fact
                .confidence
                .filter(|s| s.is_finite() && (0.0..=1.0).contains(s))
            else {
                continue;
            };
            if !grounded(&turn.text, &fact.evidence) {
                continue;
            }
            let replacement = fact.replacement_of.as_deref().filter(|old| {
                matches!(fact.predicate.as_str(), "role" | "organization")
                    && grounded(&fact.evidence, old)
                    && grounded(&fact.evidence, &fact.value)
            });
            let id = allocate_content_id(tx, account, "person_fact_candidate").await?;
            sqlx::query("INSERT INTO person_fact_candidates(account_id,id,source_event_id,speaker_observation_id,ordinal,predicate,value,literal_evidence,confidence,replacement_of,observed_at,extraction_version,value_key,replacement_key) SELECT $1,$2,event_id,id,$4,$5,$6,$7,$8,$9,started_at,2,$10,$11 FROM speaker_observations WHERE account_id=$1 AND id=$3 ON CONFLICT(account_id,speaker_observation_id,ordinal) DO NOTHING")
                .bind(account).bind(id).bind(observation).bind(ordinal as i64).bind(&fact.predicate).bind(&fact.value).bind(&fact.evidence).bind(score).bind(replacement).bind(policy::normalized_name(&fact.value)).bind(replacement.map(policy::normalized_name)).execute(&mut **tx).await?;
        }
        let (Some(name), Some(score), Some(evidence)) = (
            turn.speaker_name.as_deref(),
            turn.speaker_name_confidence,
            turn.speaker_name_evidence.as_deref(),
        ) else {
            continue;
        };
        if !score.is_finite()
            || !(0.0..=1.0).contains(&score)
            || !grounded(&turn.text, evidence)
            || !grounded(evidence, name)
        {
            continue;
        }
        let self_identified = !owner_source && is_supported_self_identification(turn, turns);
        let (kind, subject) = if self_identified {
            ("self_introduction", observation)
        } else {
            let target = match turn.speaker_name_kind.as_deref() {
                Some("vocative_address") => turn.speaker_name_target_turn_id.as_deref(),
                Some("third_party_mention") => turn.speaker_name_subject_turn_id.as_deref(),
                _ => None,
            };
            let Some(target) =
                target.and_then(|id| turns.iter().find(|candidate| candidate.turn_id == id))
            else {
                continue;
            };
            if target.speaker_local_id == turn.speaker_local_id
                || turn.speaker_name_subject_turn_id.as_deref() != Some(target.turn_id.as_str())
            {
                continue;
            }
            (
                if turn.speaker_name_kind.as_deref() == Some("vocative_address") {
                    "vocative"
                } else {
                    "mention"
                },
                observations[&target.turn_id],
            )
        };
        let mut person = None;
        if self_identified {
            let prior = direct.entry(cluster).or_default();
            let existing = prior
                .iter()
                .find(|(_, previous)| names_form_refinement(previous, name))
                .cloned();
            let id = if let Some((id, display)) = existing {
                if prefer_claimed_display_name(&display, name) {
                    sqlx::query("UPDATE people SET display_name=$3,normalized_name=$4,updated_at=clock_timestamp() WHERE account_id=$1 AND id=$2 AND status='identified'")
                        .bind(account).bind(id).bind(name).bind(policy::normalized_name(name)).execute(&mut **tx).await?;
                }
                id
            } else {
                let id = voice_identity::allocate_voice_id(tx, account, "person").await?;
                sqlx::query("INSERT INTO people(account_id,id,display_name,normalized_name,status) VALUES($1,$2,$3,$4,'identified')")
                    .bind(account).bind(id).bind(name).bind(policy::normalized_name(name)).execute(&mut **tx).await?;
                id
            };
            prior.push((id, name.to_owned()));
            person = Some(id);
        }
        let evidence_id =
            voice_identity::allocate_voice_id(tx, account, "identity_evidence").await?;
        let metadata = json!({"work_unit_id":claim.work_unit_id,"event_id":event,"turn_id":turn.turn_id,"evidence":evidence,"extraction_version":2});
        let evidence_kind = match kind {
            "self_introduction" => "audio_self_identification",
            "vocative" => "audio_vocative_address",
            _ => "audio_third_party_mention",
        };
        sqlx::query("INSERT INTO identity_evidence(account_id,id,person_id,source_event_id,observed_at,speaker_observation_id,kind,claimed_name,evidence,score,status) SELECT $1,$2,$4,event_id,started_at,id,$5,$6,$7::jsonb,$8,$9 FROM speaker_observations WHERE account_id=$1 AND id=$3")
            .bind(account).bind(evidence_id).bind(observation).bind(person).bind(evidence_kind).bind(name).bind(metadata.to_string()).bind(score).bind(if self_identified {"accepted"} else {"proposed"}).execute(&mut **tx).await?;
        sqlx::query("INSERT INTO identity_name_inputs(account_id,evidence_id,kind,source_observation_id,subject_observation_id,extraction_version) VALUES($1,$2,$3,$4,$5,2)")
            .bind(account).bind(evidence_id).bind(kind).bind(observation).bind(subject).execute(&mut **tx).await?;
        if let Some(person) = person {
            let claim_id =
                voice_identity::allocate_voice_id(tx, account, "person_name_claim").await?;
            sqlx::query("INSERT INTO person_name_claims(account_id,id,person_id,name,normalized_name,source_event_id,speaker_observation_id,observed_at,evidence_kind,evidence,confidence,status) SELECT $1,$2,$4,$5,$6,event_id,id,started_at,'audio_self_identification',$7::jsonb,$8,'accepted' FROM speaker_observations WHERE account_id=$1 AND id=$3")
                .bind(account).bind(claim_id).bind(observation).bind(person).bind(name).bind(policy::normalized_name(name)).bind(metadata.to_string()).bind(score).execute(&mut **tx).await?;
            sqlx::query("UPDATE speaker_observations SET person_id=$3,direct_evidence_id=$4 WHERE account_id=$1 AND id=$2")
                .bind(account).bind(observation).bind(person).bind(evidence_id).execute(&mut **tx).await?;
        }
    }
    for (cluster, names) in direct {
        let people: BTreeSet<_> = names.iter().map(|(person, _)| *person).collect();
        let person = (people.len() == 1).then(|| *people.first().unwrap());
        sqlx::query("UPDATE speaker_clusters SET person_id=$3,attribution_state=CASE WHEN $3::bigint IS NULL THEN 'request_local' ELSE 'person_bound' END,updated_at=clock_timestamp() WHERE account_id=$1 AND id=$2 AND attribution_state<>'owner_transmit'")
            .bind(account).bind(cluster).bind(person).execute(&mut **tx).await?;
    }
    Ok(())
}

pub(super) async fn record_screen(
    tx: &mut Transaction<'_, Postgres>,
    account: &str,
    evidence: i64,
    visual: i64,
    active: bool,
    meeting: bool,
) -> Result<()> {
    if !meeting {
        return Ok(());
    }
    sqlx::query("INSERT INTO identity_name_inputs(account_id,evidence_id,kind,visual_observation_id,extraction_version) VALUES($1,$2,$3,$4,2)")
        .bind(account).bind(evidence).bind(if active {"screen"} else {"context"}).bind(visual).execute(&mut **tx).await?;
    Ok(())
}

/// Capture dependent names before deletion removes their source/subject edges.
/// These are projection dependencies, never authority to erase target biometrics.
pub(super) async fn profiles_depending_on_events(
    tx: &mut Transaction<'_, Postgres>,
    account: &str,
    events: &[String],
) -> Result<Vec<i64>> {
    let rows=sqlx::query_scalar("WITH erased_inputs AS (
        SELECT i.* FROM identity_name_inputs i
        JOIN identity_evidence e ON e.account_id=i.account_id AND e.id=i.evidence_id
        LEFT JOIN speaker_observations source ON source.account_id=i.account_id AND source.id=i.source_observation_id
        LEFT JOIN visual_speaker_observations visual ON visual.account_id=i.account_id AND visual.id=i.visual_observation_id
        LEFT JOIN capture_events frame ON frame.account_id=visual.account_id AND frame.event_id=visual.event_id
        WHERE i.account_id=$1 AND (e.source_event_id=ANY($2::text[]) OR source.event_id=ANY($2::text[])
          OR EXISTS(SELECT 1 FROM speaker_observation_sources part WHERE part.account_id=source.account_id AND part.speaker_observation_id=source.id AND part.event_id=ANY($2::text[]))
          OR frame.event_id=ANY($2::text[]) OR frame.canonical_event_id=ANY($2::text[])))
        SELECT subject.voice_profile_id FROM erased_inputs i
          JOIN speaker_observations subject ON subject.account_id=i.account_id AND subject.id=i.subject_observation_id
          WHERE subject.voice_profile_id IS NOT NULL
        UNION SELECT subject.voice_profile_id FROM erased_inputs i
          JOIN visual_speaker_observations visual ON visual.account_id=i.account_id AND visual.id=i.visual_observation_id
          JOIN episode_members screen ON screen.account_id=visual.account_id AND screen.record_type='screenshot' AND screen.record_id=visual.screenshot_id
          JOIN episode_members audio ON audio.account_id=screen.account_id AND audio.episode_id=screen.episode_id AND audio.record_type='utterance'
          JOIN utterances u ON u.account_id=audio.account_id AND u.id=audio.record_id
          JOIN speaker_observations subject ON subject.account_id=u.account_id AND subject.id=u.speaker_observation_id
          WHERE i.kind='context' AND subject.voice_profile_id IS NOT NULL ORDER BY voice_profile_id")
        .bind(account).bind(events).fetch_all(&mut **tx).await?;
    Ok(rows)
}

pub(super) async fn fact_people_depending_on_events(
    tx: &mut Transaction<'_, Postgres>,
    account: &str,
    events: &[String],
) -> Result<Vec<i64>> {
    Ok(sqlx::query_scalar("SELECT DISTINCT f.person_id FROM person_fact_candidates c
        JOIN person_facts f ON f.account_id=c.account_id AND f.id=c.derived_fact_id
        WHERE c.account_id=$1 AND (c.source_event_id=ANY($2::text[]) OR EXISTS(
          SELECT 1 FROM speaker_observation_sources source WHERE source.account_id=c.account_id
            AND source.speaker_observation_id=c.speaker_observation_id AND source.event_id=ANY($2::text[]))) ORDER BY f.person_id")
        .bind(account).bind(events).fetch_all(&mut **tx).await?)
}

/// Exact half-open frame/turn joins within one device and capture session.
/// Updating a missing join is provider-free and converges in either arrival order.
async fn join_screen_inputs(tx: &mut Transaction<'_, Postgres>, account: &str) -> Result<()> {
    sqlx::query("WITH matches AS (
        SELECT i.evidence_id,CASE WHEN count(o.id)=1 THEN min(o.id) END subject
        FROM identity_name_inputs i
        JOIN visual_speaker_observations v ON v.account_id=i.account_id AND v.id=i.visual_observation_id
        JOIN capture_events frame ON frame.account_id=v.account_id AND frame.event_id=v.event_id
        LEFT JOIN speaker_observations o ON o.account_id=i.account_id AND NOT o.overlap
          AND o.started_at<=v.observed_at AND v.observed_at<o.ended_at
          AND EXISTS(SELECT 1 FROM capture_events audio WHERE audio.account_id=o.account_id AND audio.event_id=o.event_id
             AND audio.capture_session_id=frame.capture_session_id AND audio.device_id=frame.device_id
             AND audio.stream_kind='system_audio' AND audio.audio_role='remote_received')
          AND NOT EXISTS(SELECT 1 FROM speaker_observations other
             JOIN capture_events audio ON audio.account_id=other.account_id AND audio.event_id=other.event_id
             WHERE other.account_id=o.account_id AND other.id<>o.id
               AND audio.capture_session_id=frame.capture_session_id AND audio.device_id=frame.device_id
               AND audio.stream_kind='system_audio' AND audio.audio_role='remote_received'
               AND other.started_at<o.ended_at AND other.ended_at>o.started_at)
        WHERE i.account_id=$1 AND i.kind='screen' GROUP BY i.evidence_id)
        UPDATE identity_name_inputs i SET subject_observation_id=m.subject FROM matches m
        WHERE i.account_id=$1 AND i.evidence_id=m.evidence_id AND i.subject_observation_id IS DISTINCT FROM m.subject")
        .bind(account).execute(&mut **tx).await?;
    Ok(())
}

/// A visible label is evidence only while its exact canonical frame is retained
/// and outside every current deletion inventory. Static aliases are internal.
async fn frame_authority(tx: &mut Transaction<'_, Postgres>) -> Result<String> {
    let paged = if super::current_schema_relation_exists(
        tx,
        "persistence_feature_episode_deletion_events",
    )
    .await?
    {
        "AND NOT EXISTS(SELECT 1 FROM persistence_feature_episode_deletion_events planned JOIN episode_deletions d ON d.account_id=planned.account_id AND d.episode_id=planned.episode_id AND d.state='pending' WHERE planned.account_id=frame.account_id AND (planned.event_id=frame.event_id OR planned.event_id=coalesce(frame.canonical_event_id,frame.event_id) OR planned.root_event_id=coalesce(frame.canonical_event_id,frame.event_id)))"
    } else {
        ""
    };
    Ok(format!("EXISTS(SELECT 1 FROM media_objects m WHERE m.account_id=frame.account_id AND m.event_id=coalesce(frame.canonical_event_id,frame.event_id)
        AND m.deleted_at IS NULL AND m.processing_state<>'pruned' AND m.object_generation>0 AND m.object_backend='current'
        AND (m.retain_until IS NULL OR m.retain_until>clock_timestamp())
        AND NOT EXISTS(SELECT 1 FROM recording_media_authority authority WHERE authority.account_id=m.account_id AND authority.asset_id=m.asset_id AND authority.storage_backend='recordings'
            AND NOT EXISTS(SELECT 1 FROM recording_retention_preferences preference WHERE preference.account_id=authority.account_id AND preference.policy='until_deleted' AND preference.revision=authority.retention_policy_revision AND preference.policy_epoch=authority.retention_policy_epoch AND preference.revocation_cutoff IS NULL)))
        AND NOT EXISTS(SELECT 1 FROM episode_members member JOIN episode_deletions d ON d.account_id=member.account_id AND d.episode_id=member.episode_id AND d.state='pending' WHERE member.account_id=visual.account_id AND member.record_type='screenshot' AND member.record_id=visual.screenshot_id)
        AND NOT EXISTS(SELECT 1 FROM episode_deletions d WHERE d.account_id=frame.account_id AND d.state='pending' AND (d.orphan_event_ids ? frame.event_id OR d.orphan_event_ids ? coalesce(frame.canonical_event_id,frame.event_id)))
        AND NOT EXISTS(SELECT 1 FROM orphan_capture_erasure_operations operation WHERE operation.account_id=frame.account_id AND operation.capture_upload_fenced)
        AND NOT EXISTS(SELECT 1 FROM orphan_capture_erasure_sessions erased WHERE erased.account_id=frame.account_id AND erased.capture_session_id=frame.capture_session_id) {paged}"))
}

async fn load_inputs(
    tx: &mut Transaction<'_, Postgres>,
    account: &str,
    profile: i64,
) -> Result<Vec<Input>> {
    let fence = voice_identity::source_fence(tx).await?;
    let voter_fence = fence.replace("o.", "voter.");
    let voter_retained = voice_identity::RETAINED.replace("o.", "voter.");
    let voter_withdrawn = voice_identity::WITHDRAWN.replace("o.", "voter.");
    let identity = super::speaker_identity::speaker_identity_join(
        super::speaker_identity::SpeakerUtteranceAlias::U,
        super::speaker_identity::SpeakerMemoryScope::None,
    );
    let frame_authority = frame_authority(tx).await?;
    let query=format!("SELECT i.evidence_id,e.claimed_name,e.score,i.kind,o.id subject,
          CASE WHEN i.kind='screen' THEN coalesce(frame.canonical_event_id,frame.event_id) ELSE i.source_observation_id::text END source,
          ARRAY(SELECT DISTINCT m.episode_id FROM utterances u JOIN active_episode_members m
             ON m.account_id=u.account_id AND m.record_type='utterance' AND m.record_id=u.id
             JOIN memory_handles h ON h.account_id=m.account_id AND h.episode_id=m.episode_id AND h.state='active'
             WHERE u.account_id=o.account_id AND u.speaker_observation_id=CASE WHEN i.kind='vocative' THEN i.source_observation_id ELSE o.id END ORDER BY m.episode_id) memories,
          CASE WHEN speaker_identity.owner_source AND (voter_profile.id IS NOT NULL OR speaker_identity.attribution_kind='owner_source_role') THEN 'owner'
               WHEN voter_profile.id IS NOT NULL AND voter_profile.id<>profile.id THEN 'profile:'||voter_profile.id END voter
        FROM identity_name_inputs i JOIN identity_evidence e ON e.account_id=i.account_id AND e.id=i.evidence_id
        JOIN speaker_observations o ON o.account_id=i.account_id AND o.id=i.subject_observation_id
        JOIN voice_samples sample ON sample.account_id=o.account_id AND sample.id=o.voice_sample_id AND sample.speaker_observation_id=o.id AND sample.voice_profile_id=o.voice_profile_id AND sample.accepted
        JOIN voice_sample_profile_assignments assignment ON assignment.account_id=sample.account_id AND assignment.sample_id=sample.id AND assignment.profile_id=o.voice_profile_id AND assignment.active
        JOIN voice_profiles profile ON profile.account_id=sample.account_id AND profile.id=assignment.profile_id AND profile.embedding_space=sample.embedding_space AND profile.scorer_version=sample.scorer_version AND profile.channel_domain=sample.channel_domain
        LEFT JOIN speaker_observations voter ON voter.account_id=i.account_id AND voter.id=i.source_observation_id
        LEFT JOIN speaker_clusters voter_cluster ON voter_cluster.account_id=voter.account_id AND voter_cluster.id=voter.cluster_id
        LEFT JOIN voice_samples voter_sample ON voter_sample.account_id=voter.account_id AND voter_sample.id=voter.voice_sample_id
            AND voter_sample.speaker_observation_id=voter.id AND voter_sample.voice_profile_id=voter.voice_profile_id
            AND voter_sample.accepted AND voter_sample.quality_version={quality} AND voter_sample.eligibility IN ('enroll','match_only')
        LEFT JOIN voice_sample_profile_assignments voter_assignment ON voter_assignment.account_id=voter_sample.account_id
            AND voter_assignment.sample_id=voter_sample.id AND voter_assignment.profile_id=voter.voice_profile_id AND voter_assignment.active
        LEFT JOIN voice_profiles voter_profile ON voter_profile.account_id=voter.account_id AND voter_profile.id=voter_assignment.profile_id
            AND voter_profile.status<>'quarantined' AND voter_profile.sample_count>0
            AND voter_profile.embedding_space=voter_sample.embedding_space AND voter_profile.scorer_version=voter_sample.scorer_version
            AND voter_profile.channel_domain=voter_sample.channel_domain
        LEFT JOIN utterances u ON u.account_id=voter.account_id AND u.speaker_observation_id=voter.id
        {identity}
        LEFT JOIN visual_speaker_observations visual ON visual.account_id=i.account_id AND visual.id=i.visual_observation_id
        LEFT JOIN capture_events frame ON frame.account_id=visual.account_id AND frame.event_id=visual.event_id
        WHERE i.account_id=$1 AND assignment.profile_id=$2 AND i.kind<>'context'
          AND NOT o.overlap AND sample.quality_version={quality} AND sample.eligibility IN ('enroll','match_only')
          AND NOT ({fence}) AND ({retained}) AND NOT ({withdrawn})
          AND NOT EXISTS(SELECT 1 FROM speaker_clusters c WHERE c.account_id=o.account_id AND c.id=o.cluster_id AND c.profile_updates_quarantined)
          AND (i.kind='screen' OR (voter.id IS NOT NULL AND NOT voter.overlap AND ({voter_retained}) AND NOT ({voter_fence}) AND NOT ({voter_withdrawn}) AND NOT coalesce(voter_cluster.profile_updates_quarantined,false)))
          AND (i.kind<>'screen' OR ({frame_authority}))
        ORDER BY i.evidence_id LIMIT $3",retained=voice_identity::RETAINED,withdrawn=voice_identity::WITHDRAWN,quality=crate::cp::voice_quality::QUALITY_VERSION);
    let rows = sqlx::query(sqlx::AssertSqlSafe(query))
        .bind(account)
        .bind(profile)
        .bind((policy::MAX_INPUTS + 1) as i64)
        .fetch_all(&mut **tx)
        .await?;
    let mut inputs = Vec::new();
    for row in rows {
        let kind = match row.try_get::<String, _>("kind")?.as_str() {
            "self_introduction" => Kind::SelfIntroduction,
            "screen" => Kind::Screen,
            "vocative" => Kind::Vocative,
            _ => Kind::Mention,
        };
        inputs.push(Input {
            id: row.try_get("evidence_id")?,
            name: row.try_get("claimed_name")?,
            confidence: row.try_get::<Option<f64>, _>("score")?.unwrap_or(-1.0),
            kind,
            subject: row.try_get("subject")?,
            source: row.try_get("source")?,
            memories: row
                .try_get::<Vec<i64>, _>("memories")?
                .into_iter()
                .collect(),
            voter: row.try_get("voter")?,
        });
    }
    // Visible attendee context is tied to actual screen and voice membership in
    // the same current memory. Titles, URLs and vocabulary alone do not enter.
    let rows=sqlx::query(sqlx::AssertSqlSafe(format!("SELECT i.evidence_id,e.claimed_name,e.score,coalesce(frame.canonical_event_id,frame.event_id) source,
        array_agg(DISTINCT sm.episode_id ORDER BY sm.episode_id) memories,min(o.id) subject
        FROM identity_name_inputs i JOIN identity_evidence e ON e.account_id=i.account_id AND e.id=i.evidence_id
        JOIN visual_speaker_observations visual ON visual.account_id=i.account_id AND visual.id=i.visual_observation_id
        JOIN capture_events frame ON frame.account_id=visual.account_id AND frame.event_id=visual.event_id
        JOIN active_episode_members sm ON sm.account_id=visual.account_id AND sm.record_type='screenshot' AND sm.record_id=visual.screenshot_id
        JOIN memory_handles h ON h.account_id=sm.account_id AND h.episode_id=sm.episode_id AND h.state='active'
        JOIN active_episode_members am ON am.account_id=sm.account_id AND am.episode_id=sm.episode_id AND am.record_type='utterance'
        JOIN utterances u ON u.account_id=am.account_id AND u.id=am.record_id
        JOIN speaker_observations o ON o.account_id=u.account_id AND o.id=u.speaker_observation_id
        JOIN voice_samples sample ON sample.account_id=o.account_id AND sample.id=o.voice_sample_id
            AND sample.speaker_observation_id=o.id AND sample.voice_profile_id=o.voice_profile_id AND sample.accepted
        JOIN voice_sample_profile_assignments assignment ON assignment.account_id=sample.account_id AND assignment.sample_id=sample.id
            AND assignment.profile_id=o.voice_profile_id AND assignment.active
        JOIN voice_profiles profile ON profile.account_id=sample.account_id AND profile.id=assignment.profile_id
            AND profile.embedding_space=sample.embedding_space AND profile.scorer_version=sample.scorer_version AND profile.channel_domain=sample.channel_domain
        WHERE i.account_id=$1 AND i.kind='context' AND assignment.profile_id=$2
          AND NOT o.overlap AND sample.quality_version={quality} AND sample.eligibility IN ('enroll','match_only')
          AND ({retained}) AND NOT ({withdrawn}) AND NOT ({fence}) AND ({frame_authority})
          AND NOT EXISTS(SELECT 1 FROM speaker_clusters c WHERE c.account_id=o.account_id AND c.id=o.cluster_id AND c.profile_updates_quarantined)
        GROUP BY i.evidence_id,e.claimed_name,e.score,frame.canonical_event_id,frame.event_id ORDER BY i.evidence_id LIMIT $3",retained=voice_identity::RETAINED,withdrawn=voice_identity::WITHDRAWN,quality=crate::cp::voice_quality::QUALITY_VERSION)))
        .bind(account).bind(profile).bind((policy::MAX_INPUTS+1) as i64).fetch_all(&mut **tx).await?;
    for row in rows {
        inputs.push(Input {
            id: row.try_get("evidence_id")?,
            name: row.try_get("claimed_name")?,
            confidence: row.try_get::<Option<f64>, _>("score")?.unwrap_or(-1.0),
            kind: Kind::Context,
            subject: row.try_get("subject")?,
            source: row.try_get("source")?,
            memories: row
                .try_get::<Vec<i64>, _>("memories")?
                .into_iter()
                .collect(),
            voter: None,
        });
    }
    inputs.sort_by_key(|input| input.id);
    Ok(inputs)
}

/// Called under the shared account/reconciliation transaction. It never calls
/// the projector recursively and never changes source turns or sample authority.
/// Retire only introduction-local people whose complete typed support now belongs
/// to this voice. The evidence stays immutable; established people supported by
/// another profile or still-unassigned introduction are never merged by name.
pub(super) async fn retire_introduction_people(
    tx: &mut Transaction<'_, Postgres>,
    account: &str,
    profile: i64,
    canonical_person: Option<i64>,
) -> Result<()> {
    let retired:Vec<i64>=sqlx::query_scalar("UPDATE people p SET status='unknown',updated_at=clock_timestamp()
        WHERE p.account_id=$1 AND p.status='identified' AND p.id IS DISTINCT FROM $3
          AND EXISTS(SELECT 1 FROM identity_name_inputs i JOIN identity_evidence e ON e.account_id=i.account_id AND e.id=i.evidence_id
              JOIN speaker_observations o ON o.account_id=i.account_id AND o.id=i.subject_observation_id
              WHERE i.account_id=p.account_id AND i.kind='self_introduction' AND e.person_id=p.id AND o.voice_profile_id=$2)
          AND NOT EXISTS(SELECT 1 FROM voice_profiles other WHERE other.account_id=p.account_id AND other.person_id=p.id AND other.id<>$2)
          AND NOT EXISTS(SELECT 1 FROM identity_name_inputs i JOIN identity_evidence e ON e.account_id=i.account_id AND e.id=i.evidence_id
              JOIN speaker_observations o ON o.account_id=i.account_id AND o.id=i.subject_observation_id
              WHERE i.account_id=p.account_id AND i.kind='self_introduction' AND e.person_id=p.id AND o.voice_profile_id IS DISTINCT FROM $2)
        RETURNING p.id")
        .bind(account).bind(profile).bind(canonical_person).fetch_all(&mut **tx).await?;
    sqlx::query("UPDATE person_facts SET status='conflicted' WHERE account_id=$1 AND person_id=ANY($2::bigint[]) AND status='active'")
        .bind(account).bind(&retired).execute(&mut **tx).await?;
    Ok(())
}

pub(super) async fn reconcile_profiles(
    tx: &mut Transaction<'_, Postgres>,
    account: &str,
    profiles: &[i64],
    allow_new: bool,
) -> Result<Vec<i64>> {
    join_screen_inputs(tx, account).await?;
    let acoustic = super::voice_profile_reconciliation::name_pair_snapshot(tx, account).await?;
    let prior_holds:Vec<(i64,Vec<i64>)>=sqlx::query_as("SELECT profile_id,conflict_peers FROM profile_name_bindings WHERE account_id=$1 AND cardinality(conflict_peers)>0 ORDER BY profile_id LIMIT 65")
        .bind(account).fetch_all(&mut **tx).await?;
    let complete = acoustic.complete && prior_holds.len() <= 64;
    let mut selected = profiles.iter().copied().collect::<BTreeSet<_>>();
    selected.extend(
        acoustic
            .pairs
            .iter()
            .flat_map(|(left, right)| [*left, *right]),
    );
    selected.extend(prior_holds.iter().map(|(profile, _)| *profile));
    let mut local_inputs = BTreeMap::new();
    let mut local_decisions = BTreeMap::new();
    for &profile in &selected {
        let inputs = load_inputs(tx, account, profile).await?;
        local_decisions.insert(profile, policy::fuse(&inputs));
        local_inputs.insert(profile, inputs);
    }
    let mut changed = Vec::new();
    for &profile in &selected {
        let Some(row)=sqlx::query("SELECT p.person_id,p.status,person.status person_status,b.input_sha256,b.status binding_status,b.current_claim_id,coalesce(b.conflict_peers,'{}'::bigint[]) conflict_peers FROM voice_profiles p LEFT JOIN people person ON person.account_id=p.account_id AND person.id=p.person_id LEFT JOIN profile_name_bindings b ON b.account_id=p.account_id AND b.profile_id=p.id WHERE p.account_id=$1 AND p.id=$2")
            .bind(account).bind(profile).fetch_optional(&mut **tx).await? else {continue};
        if row
            .try_get::<Option<String>, _>("person_status")?
            .as_deref()
            == Some("owner")
        {
            retire_introduction_people(tx, account, profile, row.try_get("person_id")?).await?;
            continue;
        }
        let inputs = &local_inputs[&profile];
        let local = &local_decisions[&profile];
        let peers = acoustic
            .pairs
            .iter()
            .filter_map(|(left, right)| {
                if *left == profile {
                    Some(*right)
                } else if *right == profile {
                    Some(*left)
                } else {
                    None
                }
            })
            .collect::<Vec<_>>();
        let mut conflict_peers = peers
            .iter()
            .copied()
            .filter(|peer| {
                let other = &local_decisions[peer];
                let same_person = acoustic
                    .people
                    .get(&profile)
                    .copied()
                    .flatten()
                    .is_some_and(|person| {
                        acoustic.people.get(peer).copied().flatten() == Some(person)
                    });
                !same_person
                    && local.status == Status::Accepted
                    && other.status == Status::Accepted
                    && local.name.as_deref().map(policy::normalized_name)
                        == other.name.as_deref().map(policy::normalized_name)
            })
            .collect::<Vec<_>>();
        if !complete {
            conflict_peers.extend(row.try_get::<Vec<i64>, _>("conflict_peers")?);
            conflict_peers.sort_unstable();
            conflict_peers.dedup();
        }
        let hash = format!(
            "{:x}",
            Sha256::digest(
                format!(
                    "{}:{}:{:?}:{}:{:?}:{:?}",
                    policy::POLICY_VERSION,
                    row.try_get::<String, _>("status")?,
                    inputs,
                    acoustic.commitment,
                    peers
                        .iter()
                        .map(|peer| (*peer, &local_inputs[peer]))
                        .collect::<Vec<_>>(),
                    conflict_peers
                )
                .as_bytes()
            )
        );
        let previous_hash: Option<String> = row.try_get("input_sha256")?;
        if previous_hash.as_deref() == Some(&hash) {
            sqlx::query("UPDATE profile_name_bindings SET evaluated_at=clock_timestamp() WHERE account_id=$1 AND profile_id=$2").bind(account).bind(profile).execute(&mut **tx).await?;
            continue;
        }
        let mut decision = local.clone();
        if !conflict_peers.is_empty() {
            decision.status = Status::Quarantined;
            decision.name = None;
        }
        if row.try_get::<String, _>("status")? == "quarantined" {
            decision.status = Status::Unbound;
            decision.name = None;
        }
        if !allow_new && decision.status == Status::Accepted {
            // Admission pause is not a scheduling pause. Preserve the current
            // decision/hash while advancing the existing row's work cursor.
            sqlx::query("UPDATE profile_name_bindings SET evaluated_at=clock_timestamp() WHERE account_id=$1 AND profile_id=$2")
                .bind(account).bind(profile).execute(&mut **tx).await?;
            sqlx::query("UPDATE voice_profiles p SET updated_at=clock_timestamp() WHERE p.account_id=$1 AND p.id=$2 AND NOT EXISTS(SELECT 1 FROM profile_name_bindings b WHERE b.account_id=p.account_id AND b.profile_id=p.id)")
                .bind(account).bind(profile).execute(&mut **tx).await?;
            continue;
        }
        // Do not turn unrelated historical fixture/legacy profiles into empty
        // bindings. A prior fusion decision must still be withdrawn if erased.
        if inputs.is_empty() && previous_hash.is_none() {
            let has_typed_source:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM identity_name_inputs i LEFT JOIN speaker_observations o ON o.account_id=i.account_id AND o.id=i.subject_observation_id WHERE i.account_id=$1 AND (o.voice_profile_id=$2 OR i.kind='context'))")
                .bind(account).bind(profile).fetch_one(&mut **tx).await?;
            if !has_typed_source {
                continue;
            }
        }
        let current_person: Option<i64> = row.try_get("person_id")?;
        let mut person = current_person;
        if let Some(name) = local.name.as_deref() {
            if person.is_none() {
                // Reuse only an introduction attached to this actual profile.
                person=sqlx::query_scalar("SELECT e.person_id FROM identity_name_inputs i JOIN identity_evidence e ON e.account_id=i.account_id AND e.id=i.evidence_id JOIN speaker_observations o ON o.account_id=i.account_id AND o.id=i.subject_observation_id JOIN people p ON p.account_id=e.account_id AND p.id=e.person_id AND p.status='identified' WHERE i.account_id=$1 AND o.voice_profile_id=$2 AND i.kind='self_introduction' AND i.evidence_id=ANY($3::bigint[]) ORDER BY i.evidence_id LIMIT 1")
                    .bind(account).bind(profile).bind(inputs.iter().filter(|input|names_form_refinement(&input.name,name)).map(|input|input.id).collect::<Vec<_>>()).fetch_optional(&mut **tx).await?.flatten();
            }
            if person.is_none() {
                let id = voice_identity::allocate_voice_id(tx, account, "person").await?;
                sqlx::query("INSERT INTO people(account_id,id,status) VALUES($1,$2,'unknown')")
                    .bind(account)
                    .bind(id)
                    .execute(&mut **tx)
                    .await?;
                person = Some(id);
            }
            if decision.status == Status::Accepted {
                sqlx::query("UPDATE people SET display_name=$3,normalized_name=$4,status='identified',updated_at=clock_timestamp() WHERE account_id=$1 AND id=$2 AND status<>'owner'")
                    .bind(account).bind(person).bind(name).bind(policy::normalized_name(name)).execute(&mut **tx).await?;
            }
        }
        let previous_claim: Option<i64> = row.try_get("current_claim_id")?;
        let mut selected_claim = None;
        for candidate in &decision.candidates {
            let Some(anchor) = inputs.iter().find(|input| {
                policy::normalized_name(&input.name) == policy::normalized_name(&candidate.name)
            }) else {
                continue;
            };
            let claim_id =
                voice_identity::allocate_voice_id(tx, account, "person_name_claim").await?;
            let predecessor:Option<i64>=sqlx::query_scalar("SELECT c.id FROM profile_name_claims lineage JOIN person_name_claims c ON c.account_id=lineage.account_id AND c.id=lineage.claim_id WHERE lineage.account_id=$1 AND lineage.profile_id=$2 AND c.normalized_name=$3 ORDER BY c.id DESC LIMIT 1")
                .bind(account).bind(profile).bind(policy::normalized_name(&candidate.name)).fetch_optional(&mut **tx).await?;
            let claim_person = if decision.status == Status::Accepted {
                person
            } else {
                None
            };
            let state = if decision.status == Status::Quarantined && candidate.accepted {
                "conflicted"
            } else if candidate.accepted && decision.status == Status::Accepted {
                "accepted"
            } else {
                "probationary"
            };
            let evidence = json!({"policy_version":policy::POLICY_VERSION,"input_sha256":hash,"input_ids":candidate.sources,
                "acoustic_commitment":acoustic.commitment,"conflict_peers":conflict_peers,
                "reason":if conflict_peers.is_empty() {"local_evidence"} else {"same_name_acoustic_pair"}});
            sqlx::query("INSERT INTO person_name_claims(account_id,id,person_id,name,normalized_name,source_event_id,speaker_observation_id,observed_at,evidence_kind,evidence,confidence,status,supersedes_id) SELECT $1,$2,$4,$5,$6,source_event_id,speaker_observation_id,coalesce(observed_at,clock_timestamp()),'name_fusion',$7::jsonb,coalesce(score,0),$8,$9 FROM identity_evidence WHERE account_id=$1 AND id=$3")
                .bind(account).bind(claim_id).bind(anchor.id).bind(claim_person).bind(&candidate.name).bind(policy::normalized_name(&candidate.name)).bind(evidence.to_string()).bind(state).bind(predecessor.or(previous_claim)).execute(&mut **tx).await?;
            sqlx::query("INSERT INTO profile_name_claims(account_id,profile_id,claim_id,policy_version,input_sha256) VALUES($1,$2,$3,$4,$5)")
                .bind(account).bind(profile).bind(claim_id).bind(policy::POLICY_VERSION).bind(&hash).execute(&mut **tx).await?;
            if decision.name.as_deref() == Some(&candidate.name) {
                selected_claim = Some(claim_id)
            }
        }
        // Keep an opaque recurring person available when the name is withdrawn;
        // the recurrence pass separately decides its current public eligibility.
        if decision.status != Status::Accepted {
            if let Some(person) = person {
                sqlx::query("UPDATE people SET status='unknown',updated_at=clock_timestamp() WHERE account_id=$1 AND id=$2 AND status='identified' AND NOT EXISTS(SELECT 1 FROM profile_name_bindings b WHERE b.account_id=$1 AND b.person_id=$2 AND b.profile_id<>$3 AND b.status='accepted')")
                    .bind(account).bind(person).bind(profile).execute(&mut **tx).await?;
            }
        }
        sqlx::query("INSERT INTO profile_name_bindings(account_id,profile_id,person_id,current_claim_id,status,policy_version,input_sha256,conflict_peers) VALUES($1,$2,$3,$4,$5,$6,$7,$8) ON CONFLICT(account_id,profile_id) DO UPDATE SET person_id=excluded.person_id,current_claim_id=excluded.current_claim_id,status=excluded.status,policy_version=excluded.policy_version,input_sha256=excluded.input_sha256,conflict_peers=excluded.conflict_peers,evaluated_at=clock_timestamp()")
            .bind(account).bind(profile).bind(person).bind(selected_claim).bind(decision.status.as_str()).bind(policy::POLICY_VERSION).bind(&hash).bind(&conflict_peers).execute(&mut **tx).await?;
        sqlx::query("UPDATE voice_profiles SET person_id=$3,updated_at=clock_timestamp() WHERE account_id=$1 AND id=$2").bind(account).bind(profile).bind(person).execute(&mut **tx).await?;
        retire_introduction_people(tx, account, profile, person).await?;
        voice_identity::append_revision(tx, account, profile, "name_fusion").await?;
        changed.push(profile);
    }
    Ok(changed)
}

pub(super) async fn maintain(
    tx: &mut Transaction<'_, Postgres>,
    account: &str,
    allow_new: bool,
) -> Result<Vec<i64>> {
    join_screen_inputs(tx, account).await?;
    let ids:Vec<i64>=sqlx::query_scalar("SELECT p.id FROM voice_profiles p LEFT JOIN profile_name_bindings b ON b.account_id=p.account_id AND b.profile_id=p.id LEFT JOIN people person ON person.account_id=p.account_id AND person.id=p.person_id WHERE p.account_id=$1 AND coalesce(person.status,'')<>'owner'
        AND (b.profile_id IS NOT NULL OR EXISTS(SELECT 1 FROM identity_name_inputs i JOIN speaker_observations o ON o.account_id=i.account_id AND o.id=i.subject_observation_id WHERE i.account_id=p.account_id AND o.voice_profile_id=p.id)
            OR EXISTS(SELECT 1 FROM identity_name_inputs i JOIN visual_speaker_observations v ON v.account_id=i.account_id AND v.id=i.visual_observation_id JOIN active_episode_members sm ON sm.account_id=v.account_id AND sm.record_type='screenshot' AND sm.record_id=v.screenshot_id JOIN active_episode_members am ON am.account_id=sm.account_id AND am.episode_id=sm.episode_id AND am.record_type='utterance' JOIN utterances u ON u.account_id=am.account_id AND u.id=am.record_id JOIN speaker_observations o ON o.account_id=u.account_id AND o.id=u.speaker_observation_id WHERE i.account_id=p.account_id AND i.kind='context' AND o.voice_profile_id=p.id))
        ORDER BY coalesce(b.evaluated_at,p.updated_at),p.id LIMIT $2")
        .bind(account).bind(policy::MAINTENANCE_PROFILES).fetch_all(&mut **tx).await?;
    let changed = reconcile_profiles(tx, account, &ids, allow_new).await?;
    enrich_facts(tx, account, allow_new).await?;
    Ok(changed)
}

/// All attribution comes from the same graph as transcript/People presentation.
/// Rotating candidates provides bounded provider-free work even before binding.
pub(super) async fn enrich_facts(
    tx: &mut Transaction<'_, Postgres>,
    account: &str,
    allow_new: bool,
) -> Result<()> {
    enrich_facts_for_people(tx, account, allow_new, &[]).await
}

pub(super) async fn enrich_facts_for_people(
    tx: &mut Transaction<'_, Postgres>,
    account: &str,
    allow_new: bool,
    affected_people: &[i64],
) -> Result<()> {
    use super::speaker_identity::{
        speaker_identity_join, SpeakerMemoryScope, SpeakerUtteranceAlias,
    };
    let identity = speaker_identity_join(SpeakerUtteranceAlias::U, SpeakerMemoryScope::None);
    let fence = voice_identity::source_fence(tx).await?;
    let query=format!("SELECT candidate.*,speaker_identity.person_id expected_person,old.person_id old_person,
        CASE WHEN ({fence}) THEN false ELSE true END usable
        FROM person_fact_candidates candidate JOIN speaker_observations o ON o.account_id=candidate.account_id AND o.id=candidate.speaker_observation_id
        JOIN utterances u ON u.account_id=o.account_id AND u.speaker_observation_id=o.id
        {identity} LEFT JOIN person_facts old ON old.account_id=candidate.account_id AND old.id=candidate.derived_fact_id
        WHERE candidate.account_id=$1 ORDER BY candidate.evaluated_at,candidate.id LIMIT 128");
    let rows = sqlx::query(sqlx::AssertSqlSafe(query))
        .bind(account)
        .fetch_all(&mut **tx)
        .await?;
    let mut people: BTreeSet<i64> = affected_people.iter().copied().collect();
    for row in rows {
        let candidate: i64 = row.try_get("id")?;
        let old: Option<i64> = row.try_get("derived_fact_id")?;
        let old_person: Option<i64> = row.try_get("old_person")?;
        let expected = if row.try_get::<bool, _>("usable")? {
            row.try_get::<Option<i64>, _>("expected_person")?
        } else {
            None
        };
        if let Some(person) = old_person {
            people.insert(person);
        }
        if old_person != expected {
            if let Some(old) = old {
                sqlx::query(
                    "UPDATE person_facts SET status='conflicted' WHERE account_id=$1 AND id=$2",
                )
                .bind(account)
                .bind(old)
                .execute(&mut **tx)
                .await?;
            }
        }
        if let Some(person) = expected.filter(|_| allow_new) {
            people.insert(person);
            if old_person != Some(person) || old.is_none() {
                let fact = voice_identity::allocate_voice_id(tx, account, "person_fact").await?;
                sqlx::query("INSERT INTO person_facts(account_id,id,person_id,predicate,value,evidence,derivation_version,status,source_event_id,speaker_observation_id,observed_at,literal_evidence,confidence) SELECT $1,$2,$4,predicate,value,jsonb_build_object('candidate_id',id,'extraction_version',extraction_version),2,'active',source_event_id,speaker_observation_id,observed_at,literal_evidence,confidence FROM person_fact_candidates WHERE account_id=$1 AND id=$3")
                    .bind(account).bind(fact).bind(candidate).bind(person).execute(&mut **tx).await?;
                sqlx::query("UPDATE person_fact_candidates SET derived_fact_id=$3 WHERE account_id=$1 AND id=$2").bind(account).bind(candidate).bind(fact).execute(&mut **tx).await?;
            }
        }
        sqlx::query("UPDATE person_fact_candidates SET evaluated_at=clock_timestamp() WHERE account_id=$1 AND id=$2").bind(account).bind(candidate).execute(&mut **tx).await?;
    }
    // Candidate admission is paged; history truth covers the complete surviving
    // set in PostgreSQL. A large archive must never skip replacement or restoration.
    for person in people {
        let authority = public_fact_authority(tx).await?;
        let query=format!("WITH surviving AS MATERIALIZED (
            SELECT f.id,f.predicate,c.value_key,c.replacement_key,f.observed_at
            FROM person_fact_candidates c JOIN person_facts f ON f.account_id=c.account_id AND f.id=c.derived_fact_id
            WHERE f.account_id=$1 AND f.person_id=$2 AND ({authority})),
          latest_replacement AS (
            SELECT predicate,replacement_key,max(observed_at) changed_at FROM surviving
            WHERE replacement_key IS NOT NULL GROUP BY predicate,replacement_key),
          states AS (
            SELECT entry.id,CASE WHEN entry.observed_at<replacement.changed_at THEN 'superseded' ELSE 'active' END status,
              (SELECT prior.id FROM surviving prior WHERE entry.replacement_key IS NOT NULL
                 AND prior.predicate=entry.predicate AND prior.value_key=entry.replacement_key
                 AND prior.observed_at<entry.observed_at ORDER BY prior.observed_at DESC,prior.id DESC LIMIT 1) predecessor
            FROM surviving entry LEFT JOIN latest_replacement replacement
              ON replacement.predicate=entry.predicate AND replacement.replacement_key=entry.value_key)
          UPDATE person_facts f SET status=states.status,supersedes_id=states.predecessor,conflicts_with_id=NULL
          FROM states WHERE f.account_id=$1 AND f.id=states.id
            AND (f.status<>states.status OR f.supersedes_id IS DISTINCT FROM states.predecessor OR f.conflicts_with_id IS NOT NULL)");
        sqlx::query(sqlx::AssertSqlSafe(query))
            .bind(account)
            .bind(person)
            .execute(&mut **tx)
            .await?;
    }

    Ok(())
}

/// Public fact projections cannot wait for the bounded enrichment queue to move
/// an old attribution. Historical statuses remain visible only for the same
/// currently resolved person. The alias f is private to the query adapter.
pub(super) async fn public_fact_authority(tx: &mut sqlx::PgConnection) -> Result<String> {
    use super::speaker_identity::{
        speaker_identity_join, SpeakerMemoryScope, SpeakerUtteranceAlias,
    };
    let identity = speaker_identity_join(SpeakerUtteranceAlias::U, SpeakerMemoryScope::None);
    let fence = voice_identity::source_fence(tx).await?;
    Ok(format!("(f.derivation_version<2 OR EXISTS(SELECT 1 FROM person_fact_candidates candidate
        JOIN speaker_observations o ON o.account_id=candidate.account_id AND o.id=candidate.speaker_observation_id
        JOIN utterances u ON u.account_id=o.account_id AND u.speaker_observation_id=o.id {identity}
        WHERE candidate.account_id=f.account_id AND candidate.derived_fact_id=f.id
          AND speaker_identity.person_id=f.person_id AND NOT ({fence})
          AND (o.voice_profile_id IS NULL OR EXISTS(SELECT 1 FROM voice_samples sample
              JOIN voice_sample_profile_assignments assignment ON assignment.account_id=sample.account_id AND assignment.sample_id=sample.id AND assignment.profile_id=o.voice_profile_id AND assignment.active
              JOIN voice_profiles profile ON profile.account_id=assignment.account_id AND profile.id=assignment.profile_id
              WHERE sample.account_id=o.account_id AND sample.id=o.voice_sample_id AND sample.speaker_observation_id=o.id
                AND sample.voice_profile_id=o.voice_profile_id AND sample.accepted
                AND sample.embedding_space=profile.embedding_space AND sample.scorer_version=profile.scorer_version AND sample.channel_domain=profile.channel_domain
                AND ({retained}) AND NOT ({withdrawn})))) )", retained=voice_identity::RETAINED, withdrawn=voice_identity::WITHDRAWN))
}
