//! Observation-level voice attribution and conservative cluster summaries.
use super::voice_identity;
use crate::{
    cp::{voice_memory::EMBEDDING_SPACE, voice_quality::SCORER_VERSION},
    error::Result,
};
use sqlx::{Postgres, Row, Transaction};

/// Old clusters acquire their acoustic domain from their accepted source, using
/// the same mapper as inference. New audio writes it before any lazy read.
pub(super) async fn prepare_domains(
    tx: &mut Transaction<'_, Postgres>,
    account: &str,
) -> Result<()> {
    let mut after = 0_i64;
    loop {
        let rows = sqlx::query("SELECT c.id,e.stream_kind,e.audio_role,e.audio_route FROM speaker_clusters c JOIN LATERAL(SELECT e.stream_kind,e.audio_role,e.audio_route FROM speaker_observations o JOIN capture_events e ON e.account_id=o.account_id AND e.event_id=o.event_id WHERE o.account_id=c.account_id AND o.cluster_id=c.id ORDER BY o.started_at,o.id LIMIT 1) e ON TRUE WHERE c.account_id=$1 AND c.channel_domain IS NULL AND c.id>$2 ORDER BY c.id LIMIT 512")
            .bind(account).bind(after).fetch_all(&mut **tx).await?;
        if rows.is_empty() {
            break;
        }
        for row in rows {
            after = row.try_get("id")?;
            let domain = crate::cp::voice_identity::channel_domain(
                &row.try_get::<String, _>("stream_kind")?,
                row.try_get::<Option<String>, _>("audio_role")?.as_deref(),
                row.try_get::<Option<String>, _>("audio_route")?.as_deref(),
            );
            sqlx::query("UPDATE speaker_clusters SET channel_domain=$3 WHERE account_id=$1 AND id=$2 AND channel_domain IS NULL")
                .bind(account).bind(after).bind(domain).execute(&mut **tx).await?;
        }
    }
    Ok(())
}

pub(super) async fn domain_recognized(
    tx: &mut Transaction<'_, Postgres>,
    account: &str,
    domain: &str,
) -> Result<bool> {
    Ok(sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM voice_profiles p JOIN people owner ON owner.account_id=p.account_id AND owner.id=p.person_id AND owner.status='owner' WHERE p.account_id=$1 AND p.channel_domain=$2 AND p.embedding_space=$3 AND p.scorer_version=$4 AND p.status<>'quarantined' AND p.sample_count>0)")
        .bind(account).bind(domain).bind(EMBEDDING_SPACE).bind(SCORER_VERSION)
        .fetch_one(&mut **tx).await?)
}

pub(super) async fn owner_profiles(
    tx: &mut Transaction<'_, Postgres>,
    account: &str,
    domain: &str,
    space: &str,
    scorer: i64,
) -> Result<Vec<(i64, Vec<u8>)>> {
    let fence = voice_identity::source_fence(tx).await?;
    let retained = voice_identity::RETAINED;
    let withdrawn = voice_identity::WITHDRAWN;
    let rows=sqlx::query(sqlx::AssertSqlSafe(format!("SELECT p.id,p.centroid FROM voice_profiles p JOIN people owner ON owner.account_id=p.account_id AND owner.id=p.person_id AND owner.status='owner' WHERE p.account_id=$1 AND p.channel_domain=$2 AND p.embedding_space=$3 AND p.scorer_version=$4 AND p.status<>'quarantined' AND p.sample_count>0 AND NOT EXISTS(SELECT 1 FROM voice_sample_profile_assignments assignment JOIN voice_samples s ON s.account_id=assignment.account_id AND s.id=assignment.sample_id JOIN speaker_observations o ON o.account_id=s.account_id AND o.id=s.speaker_observation_id WHERE assignment.account_id=p.account_id AND assignment.profile_id=p.id AND assignment.active AND (NOT ({retained}) OR ({fence}) OR ({withdrawn}))) ORDER BY p.id")))
        .bind(account).bind(domain).bind(space).bind(scorer).fetch_all(&mut **tx).await?;
    rows.into_iter()
        .map(|r| Ok((r.try_get("id")?, r.try_get("centroid")?)))
        .collect()
}

/// Keep the precise assignment even when Gemini grouped two real voices into
/// one cluster. Only owner evidence can replace an observation's person with
/// the private owner node; direct spoken-name evidence is retained separately.
pub(super) async fn assign_sample(
    tx: &mut Transaction<'_, Postgres>,
    account: &str,
    observation: i64,
    sample: i64,
    profile: i64,
    owner_kind: Option<&str>,
) -> Result<()> {
    let previous:Option<i64>=sqlx::query_scalar("SELECT profile_id FROM voice_sample_profile_assignments WHERE account_id=$1 AND sample_id=$2 AND active")
        .bind(account).bind(sample).fetch_optional(&mut **tx).await?;
    if previous != Some(profile) {
        sqlx::query("UPDATE voice_sample_profile_assignments SET active=false WHERE account_id=$1 AND sample_id=$2 AND active")
            .bind(account).bind(sample).execute(&mut **tx).await?;
        let id = voice_identity::allocate_voice_id(tx, account, "voice_sample_profile_assignment")
            .await?;
        sqlx::query("INSERT INTO voice_sample_profile_assignments(account_id,id,sample_id,profile_id) VALUES($1,$2,$3,$4)")
            .bind(account).bind(id).bind(sample).bind(profile).execute(&mut **tx).await?;
    }
    sqlx::query("UPDATE voice_samples SET voice_profile_id=$3 WHERE account_id=$1 AND id=$2")
        .bind(account)
        .bind(sample)
        .bind(profile)
        .execute(&mut **tx)
        .await?;
    sqlx::query("UPDATE speaker_observations SET voice_profile_id=$3,voice_sample_id=$4 WHERE account_id=$1 AND id=$2")
        .bind(account).bind(observation).bind(profile).bind(sample).execute(&mut **tx).await?;
    if let Some(kind) = owner_kind {
        let owner:i64=sqlx::query_scalar("SELECT person.id FROM voice_profiles profile JOIN people person ON person.account_id=profile.account_id AND person.id=profile.person_id AND person.status='owner' WHERE profile.account_id=$1 AND profile.id=$2")
            .bind(account).bind(profile).fetch_one(&mut **tx).await?;
        let existing:Option<i64>=sqlx::query_scalar("SELECT evidence.id FROM identity_evidence evidence WHERE evidence.account_id=$1 AND evidence.speaker_observation_id=$2 AND evidence.voice_profile_id=$3 AND evidence.kind=$4 AND evidence.status='accepted' AND evidence.evidence->>'voice_sample_id'=$5 ORDER BY evidence.id LIMIT 1")
            .bind(account).bind(observation).bind(profile).bind(kind).bind(sample.to_string()).fetch_optional(&mut **tx).await?;
        let evidence = if let Some(id) = existing {
            id
        } else {
            let id = voice_identity::allocate_voice_id(tx, account, "identity_evidence").await?;
            sqlx::query("INSERT INTO identity_evidence(account_id,id,person_id,voice_profile_id,source_event_id,observed_at,speaker_observation_id,kind,evidence,status) SELECT account_id,$3,$4,$5,event_id,started_at,id,$6,jsonb_build_object('voice_sample_id',$7::bigint),'accepted' FROM speaker_observations WHERE account_id=$1 AND id=$2")
                .bind(account).bind(observation).bind(id).bind(owner).bind(profile).bind(kind).bind(sample).execute(&mut **tx).await?;
            id
        };
        sqlx::query("UPDATE speaker_observations SET person_id=$3,owner_evidence_id=$4 WHERE account_id=$1 AND id=$2")
            .bind(account).bind(observation).bind(owner).bind(evidence).execute(&mut **tx).await?;
        super::identity_fusion::retire_introduction_people(tx, account, profile, Some(owner))
            .await?;
    }
    Ok(())
}

pub(super) async fn clear_sample_attribution(
    tx: &mut Transaction<'_, Postgres>,
    account: &str,
    samples: &[i64],
) -> Result<()> {
    let observations:Vec<i64>=sqlx::query_scalar("SELECT speaker_observation_id FROM voice_samples WHERE account_id=$1 AND id=ANY($2::bigint[])")
        .bind(account).bind(samples).fetch_all(&mut **tx).await?;
    sqlx::query("UPDATE speaker_observations o SET person_id=CASE WHEN EXISTS(SELECT 1 FROM people owner WHERE owner.account_id=o.account_id AND owner.id=o.person_id AND owner.status='owner') THEN (SELECT evidence.person_id FROM identity_evidence evidence JOIN people person ON person.account_id=evidence.account_id AND person.id=evidence.person_id AND person.status='identified' WHERE evidence.account_id=o.account_id AND evidence.id=o.direct_evidence_id AND evidence.status='accepted') ELSE o.person_id END,voice_sample_id=NULL,voice_profile_id=NULL,owner_evidence_id=NULL WHERE o.account_id=$1 AND o.id=ANY($2::bigint[])")
        .bind(account).bind(&observations).execute(&mut **tx).await?;
    sqlx::query("DELETE FROM identity_evidence WHERE account_id=$1 AND speaker_observation_id=ANY($2::bigint[]) AND kind IN ('owner_enrollment','owner_voice')")
        .bind(account).bind(&observations).execute(&mut **tx).await?;
    Ok(())
}

/// An ambiguous cluster is excluded from centroid maintenance, including its
/// earlier samples. Its valid per-turn matches remain available for rendering.
pub(super) async fn refresh_clusters(
    tx: &mut Transaction<'_, Postgres>,
    account: &str,
    clusters: &[i64],
) -> Result<()> {
    for cluster in clusters {
        let row=sqlx::query("SELECT count(DISTINCT o.voice_profile_id)::bigint profiles, min(o.voice_profile_id) profile, count(*)::bigint matched, coalesce(bool_and(coalesce(person.status='owner',false) AND p.status<>'quarantined' AND p.sample_count>0),false) all_owner FROM speaker_observations o JOIN voice_samples sample ON sample.account_id=o.account_id AND sample.id=o.voice_sample_id AND sample.accepted JOIN voice_profiles p ON p.account_id=o.account_id AND p.id=o.voice_profile_id LEFT JOIN people person ON person.account_id=p.account_id AND person.id=p.person_id WHERE o.account_id=$1 AND o.cluster_id=$2 AND o.voice_profile_id IS NOT NULL")
            .bind(account).bind(cluster).fetch_one(&mut **tx).await?;
        let mixed = row.try_get::<i64, _>("profiles")? > 1;
        let owner =
            row.try_get::<i64, _>("matched")? > 0 && row.try_get::<bool, _>("all_owner")? && !mixed;
        let profile: Option<i64> = if mixed { None } else { row.try_get("profile")? };
        let newly_mixed:bool=sqlx::query_scalar("SELECT NOT profile_updates_quarantined FROM speaker_clusters WHERE account_id=$1 AND id=$2")
            .bind(account).bind(cluster).fetch_one(&mut **tx).await?;
        sqlx::query("UPDATE speaker_clusters SET owner=$3,profile_updates_quarantined=profile_updates_quarantined OR $4,voice_profile_id=$5,person_id=CASE WHEN $4 THEN NULL ELSE person_id END,attribution_state=CASE WHEN $4 THEN 'request_local' WHEN $5::bigint IS NOT NULL AND attribution_state='request_local' THEN 'anonymous_profile' ELSE attribution_state END,updated_at=clock_timestamp() WHERE account_id=$1 AND id=$2")
            .bind(account).bind(cluster).bind(owner).bind(mixed).bind(profile).execute(&mut **tx).await?;
        if mixed && newly_mixed {
            let profiles:Vec<i64>=sqlx::query_scalar("SELECT DISTINCT assignment.profile_id FROM voice_sample_profile_assignments assignment JOIN voice_samples sample ON sample.account_id=assignment.account_id AND sample.id=assignment.sample_id JOIN speaker_observations observation ON observation.account_id=sample.account_id AND observation.id=sample.speaker_observation_id WHERE assignment.account_id=$1 AND observation.cluster_id=$2 ORDER BY assignment.profile_id")
                .bind(account).bind(cluster).fetch_all(&mut **tx).await?;
            // Old centroids contain now-excluded cluster contributions too.
            sqlx::query("UPDATE voice_profile_revisions SET centroid=''::bytea WHERE account_id=$1 AND profile_id=ANY($2::bigint[])")
                .bind(account).bind(&profiles).execute(&mut **tx).await?;
            for profile in &profiles {
                voice_identity::recompute_profile(tx, account, *profile, "mixed_cluster_recompute")
                    .await?;
            }
            voice_identity::refresh_affected_speaker_projections(
                tx,
                account,
                &[*cluster],
                &profiles,
                &[],
            )
            .await?;
        }
    }
    Ok(())
}

/// Recognition changes also affect route-only observations with no matched
/// profile. Refresh their domain together with ordinary profile reachability.
pub(super) async fn refresh_domains(
    tx: &mut Transaction<'_, Postgres>,
    account: &str,
    domains: &[String],
) -> Result<()> {
    prepare_domains(tx, account).await?;
    let clusters:Vec<i64>=sqlx::query_scalar("SELECT id FROM speaker_clusters WHERE account_id=$1 AND channel_domain=ANY($2::text[]) ORDER BY id")
        .bind(account).bind(domains).fetch_all(&mut **tx).await?;
    voice_identity::refresh_affected_speaker_projections(tx, account, &clusters, &[], &[]).await
}
