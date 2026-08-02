use crate::{
    cp::{tokens::sha256_hex, voice_quality},
    error::{EnclaveError, Result},
};
use rusqlite::{params, Connection, OptionalExtension};
use std::collections::{BTreeMap, BTreeSet};

const MAX_PROPOSAL_PROFILES: usize = 32;
const MAX_SPLIT_PARTITIONS: usize = 16;
const MAX_PROPOSAL_SAMPLES: usize = 1_000;
const LINEAGE_DERIVATION_VERSION: i64 = 1;

#[derive(Debug, Clone)]
struct ProfileMeta {
    id: i64,
    person_id: Option<i64>,
    embedding_space: String,
    channel_domain: String,
    scorer_version: i64,
    status: String,
}

struct ResultProfileSpec<'a> {
    proposal_id: i64,
    partition_ordinal: i64,
    template: &'a ProfileMeta,
    person_id: Option<i64>,
    sample_ids: &'a [i64],
    scorer_version: i64,
    derivation_version: i64,
}

/// Populate append-only lineage for profiles/samples created by older images.
/// Existing history is never reactivated: a sample is backfilled only when it
/// has no assignment row at all.
pub fn backfill_profile_lineage(conn: &Connection) -> Result<()> {
    conn.execute(
        "INSERT INTO voice_profile_revisions \
         (profile_id,status,derivation_version,scorer_version,representative_kind,centroid,\
          sample_count,medoid_sample_id,person_id,reason_code,active) \
         SELECT v.id,v.status,?1,v.scorer_version,v.representative_kind,v.centroid,\
                v.sample_count,v.medoid_sample_id,v.person_id,'schema_backfill',1 \
         FROM voice_profiles v \
         WHERE NOT EXISTS (SELECT 1 FROM voice_profile_revisions r WHERE r.profile_id=v.id)",
        [LINEAGE_DERIVATION_VERSION],
    )?;
    conn.execute(
        "INSERT INTO voice_sample_profile_assignments(sample_id,profile_id,active) \
         SELECT s.id,s.voice_profile_id,1 FROM voice_samples s \
         WHERE s.voice_profile_id IS NOT NULL \
           AND NOT EXISTS (SELECT 1 FROM voice_sample_profile_assignments a WHERE a.sample_id=s.id)",
        [],
    )?;
    Ok(())
}

#[cfg(test)]
fn effective_profile_status(conn: &Connection, profile_id: i64) -> Result<String> {
    backfill_profile_lineage(conn)?;
    conn.query_row(
        "SELECT status FROM voice_profile_revisions WHERE profile_id=?1 AND active=1",
        [profile_id],
        |row| row.get(0),
    )
    .optional()?
    .ok_or(EnclaveError::NotFound)
}

pub fn active_sample_ids(conn: &Connection, profile_id: i64) -> Result<Vec<i64>> {
    backfill_profile_lineage(conn)?;
    let mut statement = conn.prepare(
        "SELECT sample_id FROM voice_sample_profile_assignments \
         WHERE profile_id=?1 AND active=1 ORDER BY sample_id",
    )?;
    let sample_ids = statement
        .query_map([profile_id], |row| row.get::<_, i64>(0))?
        .collect::<std::result::Result<Vec<_>, _>>()?;
    Ok(sample_ids)
}

/// Register a newly stored sample in the append-only assignment graph.
pub(crate) fn record_sample_assignment(
    conn: &Connection,
    profile_id: i64,
    sample_id: i64,
) -> Result<()> {
    backfill_profile_lineage(conn)?;
    conn.execute(
        "INSERT INTO voice_sample_profile_assignments(sample_id,profile_id,active) \
         SELECT ?1,?2,1 WHERE NOT EXISTS \
         (SELECT 1 FROM voice_sample_profile_assignments WHERE sample_id=?1)",
        params![sample_id, profile_id],
    )?;
    Ok(())
}

/// Snapshot an in-place representative/status update without losing its prior
/// state. Superseded/split overlays are never silently revived by enrollment.
pub(crate) fn refresh_profile_revision(
    conn: &Connection,
    profile_id: i64,
    reason_code: &str,
) -> Result<()> {
    validate_reason_code(reason_code)?;
    backfill_profile_lineage(conn)?;
    let current = conn.query_row(
        "SELECT id,status,scorer_version,representative_kind,centroid,sample_count,\
                medoid_sample_id,person_id \
         FROM voice_profile_revisions WHERE profile_id=?1 AND active=1",
        [profile_id],
        |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, Vec<u8>>(4)?,
                row.get::<_, i64>(5)?,
                row.get::<_, Option<i64>>(6)?,
                row.get::<_, Option<i64>>(7)?,
            ))
        },
    )?;
    if matches!(current.1.as_str(), "superseded" | "split") {
        return Ok(());
    }
    let profile = conn.query_row(
        "SELECT status,scorer_version,representative_kind,centroid,sample_count,\
                medoid_sample_id,person_id FROM voice_profiles WHERE id=?1",
        [profile_id],
        |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, Vec<u8>>(3)?,
                row.get::<_, i64>(4)?,
                row.get::<_, Option<i64>>(5)?,
                row.get::<_, Option<i64>>(6)?,
            ))
        },
    )?;
    if current.1 == profile.0
        && current.2 == profile.1
        && current.3 == profile.2
        && current.4 == profile.3
        && current.5 == profile.4
        && current.6 == profile.5
        && current.7 == profile.6
    {
        return Ok(());
    }
    append_revision(
        conn,
        profile_id,
        &profile.0,
        LINEAGE_DERIVATION_VERSION,
        None,
        reason_code,
    )?;
    Ok(())
}

/// Persist a deterministic merge proposal after a calibrated scorer has
/// supplied its exact source set. Deliberately not called by the uncalibrated
/// runtime; release-corpus calibration is the producer boundary.
#[cfg_attr(not(test), allow(dead_code))]
pub fn propose_merge(
    conn: &Connection,
    profile_ids: &[i64],
    scorer_version: i64,
    derivation_version: i64,
    reason_code: &str,
) -> Result<i64> {
    validate_versions(scorer_version, derivation_version)?;
    validate_reason_code(reason_code)?;
    backfill_profile_lineage(conn)?;
    let mut sources = profile_ids.to_vec();
    sources.sort_unstable();
    sources.dedup();
    if sources.len() < 2
        || sources.len() != profile_ids.len()
        || sources.len() > MAX_PROPOSAL_PROFILES
    {
        return Err(invalid("merge requires 2-32 distinct profiles"));
    }

    let tx = conn.unchecked_transaction()?;
    let profiles = validate_source_profiles(&tx, &sources, scorer_version)?;
    let person_ids = profiles
        .iter()
        .filter_map(|profile| profile.person_id)
        .collect::<BTreeSet<_>>();
    if person_ids.len() > 1 {
        return Err(invalid(
            "merge profiles have conflicting accepted identities",
        ));
    }
    let samples = proposal_samples_for_profiles(&tx, &sources)?;
    if samples.is_empty() || samples.len() > MAX_PROPOSAL_SAMPLES {
        return Err(invalid("merge sample set is empty or exceeds its bound"));
    }
    validate_observation_identities(
        &tx,
        &samples
            .iter()
            .map(|(_, sample_id)| *sample_id)
            .collect::<Vec<_>>(),
        person_ids.first().copied(),
    )?;
    validate_partition_has_enrollment(
        &tx,
        &samples
            .iter()
            .map(|(_, sample_id)| *sample_id)
            .collect::<Vec<_>>(),
        profiles
            .first()
            .expect("validated merge profiles are nonempty"),
        scorer_version,
    )?;
    let key = proposal_key(
        "merge",
        &sources,
        &[samples.iter().map(|(_, sample_id)| *sample_id).collect()],
        scorer_version,
        derivation_version,
        reason_code,
    );
    if let Some(id) = proposal_id_by_key(&tx, &key)? {
        tx.commit()?;
        return Ok(id);
    }
    tx.execute(
        "INSERT INTO voice_profile_proposals \
         (proposal_key,kind,state,scorer_version,derivation_version,reason_code) \
         VALUES (?1,'merge','proposed',?2,?3,?4)",
        params![key, scorer_version, derivation_version, reason_code],
    )?;
    let proposal_id = tx.last_insert_rowid();
    for source in &sources {
        tx.execute(
            "INSERT INTO voice_profile_proposal_profiles \
             (proposal_id,profile_id,role,partition_ordinal) VALUES (?1,?2,'source',0)",
            params![proposal_id, source],
        )?;
    }
    for (source_profile_id, sample_id) in samples {
        tx.execute(
            "INSERT INTO voice_profile_proposal_samples \
             (proposal_id,sample_id,source_profile_id,partition_ordinal) VALUES (?1,?2,?3,0)",
            params![proposal_id, sample_id, source_profile_id],
        )?;
    }
    tx.commit()?;
    Ok(proposal_id)
}

/// Persist an exact, exhaustive split proposal from a calibrated scorer.
/// Anonymous-only validation prevents guessed identity propagation.
#[cfg_attr(not(test), allow(dead_code))]
pub fn propose_split(
    conn: &Connection,
    profile_id: i64,
    partitions: &[Vec<i64>],
    scorer_version: i64,
    derivation_version: i64,
    reason_code: &str,
) -> Result<i64> {
    validate_versions(scorer_version, derivation_version)?;
    validate_reason_code(reason_code)?;
    backfill_profile_lineage(conn)?;
    if !(2..=MAX_SPLIT_PARTITIONS).contains(&partitions.len()) {
        return Err(invalid("split requires 2-16 partitions"));
    }
    let mut canonical_partitions = Vec::with_capacity(partitions.len());
    let mut proposed_samples = BTreeSet::new();
    for partition in partitions {
        let mut ids = partition.clone();
        ids.sort_unstable();
        ids.dedup();
        if ids.is_empty() || ids.len() != partition.len() {
            return Err(invalid("split partitions must be nonempty and disjoint"));
        }
        for sample_id in &ids {
            if !proposed_samples.insert(*sample_id) {
                return Err(invalid("split partitions must be nonempty and disjoint"));
            }
        }
        canonical_partitions.push(ids);
    }
    canonical_partitions.sort_by_key(|partition| partition[0]);
    if proposed_samples.len() > MAX_PROPOSAL_SAMPLES {
        return Err(invalid("split sample set exceeds its bound"));
    }

    let tx = conn.unchecked_transaction()?;
    let profiles = validate_source_profiles(&tx, &[profile_id], scorer_version)?;
    if profiles[0].person_id.is_some() {
        return Err(invalid(
            "identified profiles require identity-aware correction before splitting",
        ));
    }
    let active = active_sample_ids(&tx, profile_id)?
        .into_iter()
        .collect::<BTreeSet<_>>();
    if active != proposed_samples {
        return Err(invalid(
            "split partitions must cover every active sample exactly once",
        ));
    }
    validate_observation_identities(
        &tx,
        &proposed_samples.iter().copied().collect::<Vec<_>>(),
        None,
    )?;
    for partition in &canonical_partitions {
        validate_partition_has_enrollment(
            &tx,
            partition,
            profiles
                .first()
                .expect("validated split profile is nonempty"),
            scorer_version,
        )?;
    }
    let key = proposal_key(
        "split",
        &[profile_id],
        &canonical_partitions,
        scorer_version,
        derivation_version,
        reason_code,
    );
    if let Some(id) = proposal_id_by_key(&tx, &key)? {
        tx.commit()?;
        return Ok(id);
    }
    tx.execute(
        "INSERT INTO voice_profile_proposals \
         (proposal_key,kind,state,scorer_version,derivation_version,reason_code) \
         VALUES (?1,'split','proposed',?2,?3,?4)",
        params![key, scorer_version, derivation_version, reason_code],
    )?;
    let proposal_id = tx.last_insert_rowid();
    tx.execute(
        "INSERT INTO voice_profile_proposal_profiles \
         (proposal_id,profile_id,role,partition_ordinal) VALUES (?1,?2,'source',0)",
        params![proposal_id, profile_id],
    )?;
    for (partition_ordinal, partition) in canonical_partitions.iter().enumerate() {
        for sample_id in partition {
            tx.execute(
                "INSERT INTO voice_profile_proposal_samples \
                 (proposal_id,sample_id,source_profile_id,partition_ordinal) \
                 VALUES (?1,?2,?3,?4)",
                params![proposal_id, sample_id, profile_id, partition_ordinal as i64],
            )?;
        }
    }
    tx.commit()?;
    Ok(proposal_id)
}

pub fn apply_proposal(conn: &Connection, proposal_id: i64) -> Result<Vec<i64>> {
    backfill_profile_lineage(conn)?;
    let tx = conn.unchecked_transaction()?;
    let (kind, state, scorer_version, derivation_version) = proposal_header(&tx, proposal_id)?;
    if state == "applied" {
        let results = proposal_result_profiles(&tx, proposal_id)?;
        tx.commit()?;
        return Ok(results);
    }
    if !matches!(state.as_str(), "proposed" | "approved") {
        return Err(EnclaveError::Conflict(format!(
            "voice profile proposal is {state}"
        )));
    }
    let sources = proposal_source_profiles(&tx, proposal_id)?;
    let profiles = validate_source_profiles(&tx, &sources, scorer_version)?;
    validate_proposal_is_current(&tx, proposal_id, &sources)?;

    let rows = proposal_sample_rows(&tx, proposal_id)?;
    let mut partitions = BTreeMap::<i64, Vec<(i64, i64)>>::new();
    for (sample_id, source_profile_id, partition_ordinal) in rows {
        partitions
            .entry(partition_ordinal)
            .or_default()
            .push((sample_id, source_profile_id));
    }
    let inherited_person = if kind == "merge" {
        profiles.iter().find_map(|profile| profile.person_id)
    } else {
        None
    };
    let template = profiles
        .first()
        .ok_or_else(|| invalid("proposal has no source"))?;
    let source_status = if kind == "merge" {
        "superseded"
    } else {
        "split"
    };
    let mut results = Vec::with_capacity(partitions.len());
    for (partition_ordinal, samples) in &partitions {
        let sample_ids = samples
            .iter()
            .map(|(sample_id, _)| *sample_id)
            .collect::<Vec<_>>();
        let result_id = create_result_profile(
            &tx,
            ResultProfileSpec {
                proposal_id,
                partition_ordinal: *partition_ordinal,
                template,
                person_id: inherited_person,
                sample_ids: &sample_ids,
                scorer_version,
                derivation_version,
            },
        )?;
        for (sample_id, source_profile_id) in samples {
            move_sample_assignment(&tx, *sample_id, *source_profile_id, result_id, proposal_id)?;
        }
        relabel_samples(&tx, &sample_ids, result_id, inherited_person)?;
        results.push(result_id);
    }
    for source in sources {
        append_revision(
            &tx,
            source,
            source_status,
            derivation_version,
            Some(proposal_id),
            if kind == "merge" {
                "merge_applied"
            } else {
                "split_applied"
            },
        )?;
    }
    tx.execute(
        "UPDATE voice_profile_proposals SET state='applied',\
         updated_at=strftime('%Y-%m-%dT%H:%M:%fZ','now') \
         WHERE id=?1 AND state IN ('proposed','approved')",
        [proposal_id],
    )?;
    tx.commit()?;
    Ok(results)
}

pub fn revert_proposal(conn: &Connection, proposal_id: i64) -> Result<()> {
    backfill_profile_lineage(conn)?;
    let tx = conn.unchecked_transaction()?;
    let (_, state, _, derivation_version) = proposal_header(&tx, proposal_id)?;
    if state == "reverted" {
        tx.commit()?;
        return Ok(());
    }
    if !matches!(state.as_str(), "applied" | "revert_requested") {
        return Err(EnclaveError::Conflict(format!(
            "voice profile proposal is {state}"
        )));
    }
    let sources = proposal_source_profiles(&tx, proposal_id)?;
    let results = proposal_result_profiles(&tx, proposal_id)?;
    let rows = proposal_sample_rows(&tx, proposal_id)?;
    let proposed_samples = rows
        .iter()
        .map(|(sample_id, _, _)| *sample_id)
        .collect::<BTreeSet<_>>();
    let mut current_result_samples = BTreeSet::new();
    for result in &results {
        current_result_samples.extend(active_sample_ids(&tx, *result)?);
    }
    if current_result_samples != proposed_samples {
        return Err(EnclaveError::Conflict(
            "proposal results changed after apply; bounded revert refused".into(),
        ));
    }
    let result_set = results.iter().copied().collect::<BTreeSet<_>>();
    for (sample_id, source_profile_id, _) in rows {
        let (current_assignment_id, current_profile_id) = tx.query_row(
            "SELECT id,profile_id FROM voice_sample_profile_assignments \
             WHERE sample_id=?1 AND active=1",
            [sample_id],
            |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)),
        )?;
        if !result_set.contains(&current_profile_id) {
            return Err(EnclaveError::Conflict(
                "proposal sample is no longer assigned to its result".into(),
            ));
        }
        tx.execute(
            "UPDATE voice_sample_profile_assignments SET active=0 WHERE id=?1 AND active=1",
            [current_assignment_id],
        )?;
        tx.execute(
            "INSERT INTO voice_sample_profile_assignments \
             (sample_id,profile_id,proposal_id,predecessor_assignment_id,active) \
             VALUES (?1,?2,?3,?4,1)",
            params![
                sample_id,
                source_profile_id,
                proposal_id,
                current_assignment_id
            ],
        )?;
        let source_person_id = tx.query_row(
            "SELECT person_id FROM voice_profiles WHERE id=?1",
            [source_profile_id],
            |row| row.get::<_, Option<i64>>(0),
        )?;
        relabel_samples(&tx, &[sample_id], source_profile_id, source_person_id)?;
    }
    for result in results {
        append_revision(
            &tx,
            result,
            "superseded",
            derivation_version,
            Some(proposal_id),
            "proposal_reverted",
        )?;
    }
    for source in sources {
        let prior_status = tx.query_row(
            "SELECT predecessor.status FROM voice_profile_revisions current \
             JOIN voice_profile_revisions predecessor ON predecessor.id=current.predecessor_revision_id \
             WHERE current.profile_id=?1 AND current.active=1",
            [source],
            |row| row.get::<_, String>(0),
        )?;
        append_revision(
            &tx,
            source,
            &prior_status,
            derivation_version,
            Some(proposal_id),
            "proposal_reverted",
        )?;
    }
    tx.execute(
        "UPDATE voice_profile_proposals SET state='reverted',\
         updated_at=strftime('%Y-%m-%dT%H:%M:%fZ','now') \
         WHERE id=?1 AND state IN ('applied','revert_requested')",
        [proposal_id],
    )?;
    tx.commit()?;
    Ok(())
}

/// Process only externally calibrated/approved lineage actions. The default
/// proposal state is inert, so the current fixed matcher thresholds cannot
/// activate a merge or split. Invalid/stale approved actions are rejected
/// content-free; database failures remain visible to the caller.
pub fn process_lineage_actions(conn: &Connection, limit: usize) -> Result<usize> {
    if limit == 0 {
        return Ok(0);
    }
    let mut statement = conn.prepare(
        "SELECT id,state FROM voice_profile_proposals \
         WHERE state IN ('approved','revert_requested') ORDER BY id LIMIT ?1",
    )?;
    let actions = statement
        .query_map([1_i64], |row| {
            Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?))
        })?
        .collect::<std::result::Result<Vec<_>, _>>()?;
    drop(statement);
    let mut processed = 0;
    for (proposal_id, state) in actions {
        let result = if state == "approved" {
            apply_proposal(conn, proposal_id).map(|_| ())
        } else {
            revert_proposal(conn, proposal_id)
        };
        match result {
            Ok(()) => processed += 1,
            Err(EnclaveError::InvalidRequest(_) | EnclaveError::Conflict(_)) => {
                let fallback_state = if state == "approved" {
                    "rejected"
                } else {
                    "applied"
                };
                conn.execute(
                    "UPDATE voice_profile_proposals SET state=?1,\
                     updated_at=strftime('%Y-%m-%dT%H:%M:%fZ','now') \
                     WHERE id=?2 AND state IN ('approved','revert_requested')",
                    params![fallback_state, proposal_id],
                )?;
                processed += 1;
            }
            Err(error) => return Err(error),
        }
    }
    Ok(processed)
}

fn validate_versions(scorer_version: i64, derivation_version: i64) -> Result<()> {
    if scorer_version <= 0 || derivation_version <= 0 {
        return Err(invalid("voice profile versions must be positive"));
    }
    Ok(())
}

fn validate_reason_code(reason_code: &str) -> Result<()> {
    if reason_code.is_empty()
        || reason_code.len() > 64
        || !reason_code
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
    {
        return Err(invalid("voice profile reason_code is invalid"));
    }
    Ok(())
}

fn invalid(message: &str) -> EnclaveError {
    EnclaveError::InvalidRequest(message.into())
}

fn proposal_key(
    kind: &str,
    profiles: &[i64],
    partitions: &[Vec<i64>],
    scorer_version: i64,
    derivation_version: i64,
    reason_code: &str,
) -> String {
    let mut canonical = format!(
        "{kind}|{scorer_version}|{derivation_version}|{reason_code}|{:?}|",
        profiles
    );
    for partition in partitions {
        canonical.push_str(&format!("{partition:?}|"));
    }
    sha256_hex(&canonical)
}

fn proposal_id_by_key(conn: &Connection, key: &str) -> Result<Option<i64>> {
    Ok(conn
        .query_row(
            "SELECT id FROM voice_profile_proposals WHERE proposal_key=?1",
            [key],
            |row| row.get(0),
        )
        .optional()?)
}

fn profile_meta(conn: &Connection, profile_id: i64) -> Result<ProfileMeta> {
    conn.query_row(
        "SELECT v.id,v.person_id,v.embedding_space,v.channel_domain,v.scorer_version,r.status \
         FROM voice_profiles v JOIN voice_profile_revisions r \
           ON r.profile_id=v.id AND r.active=1 WHERE v.id=?1",
        [profile_id],
        |row| {
            Ok(ProfileMeta {
                id: row.get(0)?,
                person_id: row.get(1)?,
                embedding_space: row.get(2)?,
                channel_domain: row.get(3)?,
                scorer_version: row.get(4)?,
                status: row.get(5)?,
            })
        },
    )
    .optional()?
    .ok_or(EnclaveError::NotFound)
}

fn validate_source_profiles(
    conn: &Connection,
    source_ids: &[i64],
    scorer_version: i64,
) -> Result<Vec<ProfileMeta>> {
    let mut profiles = Vec::with_capacity(source_ids.len());
    for source_id in source_ids {
        let profile = profile_meta(conn, *source_id)?;
        if !matches!(profile.status.as_str(), "tentative" | "stable") {
            return Err(EnclaveError::Conflict(format!(
                "voice profile {} is {}",
                profile.id, profile.status
            )));
        }
        if profile.scorer_version != scorer_version {
            return Err(invalid(
                "proposal scorer_version does not match source profiles",
            ));
        }
        profiles.push(profile);
    }
    let template = profiles
        .first()
        .ok_or_else(|| invalid("proposal has no source"))?;
    if profiles.iter().any(|profile| {
        profile.embedding_space != template.embedding_space
            || profile.channel_domain != template.channel_domain
            || profile.scorer_version != template.scorer_version
    }) {
        return Err(invalid(
            "proposal profiles must share embedding space, acoustic domain, and scorer",
        ));
    }
    Ok(profiles)
}

fn proposal_samples_for_profiles(
    conn: &Connection,
    profile_ids: &[i64],
) -> Result<Vec<(i64, i64)>> {
    let mut samples = Vec::new();
    for profile_id in profile_ids {
        for sample_id in active_sample_ids(conn, *profile_id)? {
            samples.push((*profile_id, sample_id));
        }
    }
    samples.sort_unstable_by_key(|(profile_id, sample_id)| (*profile_id, *sample_id));
    Ok(samples)
}

fn proposal_header(conn: &Connection, proposal_id: i64) -> Result<(String, String, i64, i64)> {
    conn.query_row(
        "SELECT kind,state,scorer_version,derivation_version \
         FROM voice_profile_proposals WHERE id=?1",
        [proposal_id],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
    )
    .optional()?
    .ok_or(EnclaveError::NotFound)
}

fn proposal_source_profiles(conn: &Connection, proposal_id: i64) -> Result<Vec<i64>> {
    proposal_profiles(conn, proposal_id, "source")
}

fn proposal_result_profiles(conn: &Connection, proposal_id: i64) -> Result<Vec<i64>> {
    proposal_profiles(conn, proposal_id, "result")
}

fn proposal_profiles(conn: &Connection, proposal_id: i64, role: &str) -> Result<Vec<i64>> {
    let mut statement = conn.prepare(
        "SELECT profile_id FROM voice_profile_proposal_profiles \
         WHERE proposal_id=?1 AND role=?2 ORDER BY partition_ordinal,profile_id",
    )?;
    let profiles = statement
        .query_map(params![proposal_id, role], |row| row.get::<_, i64>(0))?
        .collect::<std::result::Result<Vec<_>, _>>()?;
    Ok(profiles)
}

fn proposal_sample_rows(conn: &Connection, proposal_id: i64) -> Result<Vec<(i64, i64, i64)>> {
    let mut statement = conn.prepare(
        "SELECT sample_id,source_profile_id,partition_ordinal \
         FROM voice_profile_proposal_samples WHERE proposal_id=?1 \
         ORDER BY partition_ordinal,sample_id",
    )?;
    let rows = statement
        .query_map([proposal_id], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?))
        })?
        .collect::<std::result::Result<Vec<_>, _>>()?;
    Ok(rows)
}

fn validate_proposal_is_current(
    conn: &Connection,
    proposal_id: i64,
    sources: &[i64],
) -> Result<()> {
    let expected = proposal_sample_rows(conn, proposal_id)?
        .into_iter()
        .map(|(sample_id, source_profile_id, _)| (source_profile_id, sample_id))
        .collect::<BTreeSet<_>>();
    let current = proposal_samples_for_profiles(conn, sources)?
        .into_iter()
        .collect::<BTreeSet<_>>();
    if expected != current {
        return Err(EnclaveError::Conflict(
            "voice profile proposal is stale after sample membership changed".into(),
        ));
    }
    Ok(())
}

fn validate_partition_has_enrollment(
    conn: &Connection,
    sample_ids: &[i64],
    template: &ProfileMeta,
    scorer_version: i64,
) -> Result<()> {
    let mut has_enrollment = false;
    for sample_id in sample_ids {
        let (space, domain, scorer, eligibility, outlier, accepted) = conn.query_row(
            "SELECT embedding_space,channel_domain,scorer_version,eligibility,outlier,accepted \
             FROM voice_samples WHERE id=?1",
            [sample_id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, i64>(4)?,
                    row.get::<_, i64>(5)?,
                ))
            },
        )?;
        if space != template.embedding_space
            || domain != template.channel_domain
            || scorer != scorer_version
        {
            return Err(invalid("proposal contains an incompatible voice sample"));
        }
        has_enrollment |= eligibility == "enroll" && outlier == 0 && accepted == 1;
    }
    if !has_enrollment {
        return Err(invalid(
            "every result profile requires an accepted enrollment sample",
        ));
    }
    Ok(())
}

fn validate_observation_identities(
    conn: &Connection,
    sample_ids: &[i64],
    expected_person_id: Option<i64>,
) -> Result<()> {
    for sample_id in sample_ids {
        let observation_person_id = conn.query_row(
            "SELECT o.person_id FROM voice_samples s \
             JOIN speaker_observations o ON o.id=s.speaker_observation_id WHERE s.id=?1",
            [sample_id],
            |row| row.get::<_, Option<i64>>(0),
        )?;
        if observation_person_id.is_some() && observation_person_id != expected_person_id {
            return Err(invalid(
                "proposal conflicts with accepted speaker-observation identity",
            ));
        }
    }
    Ok(())
}

fn create_result_profile(conn: &Connection, spec: ResultProfileSpec<'_>) -> Result<i64> {
    let ResultProfileSpec {
        proposal_id,
        partition_ordinal,
        template,
        person_id,
        sample_ids,
        scorer_version,
        derivation_version,
    } = spec;
    let mut vectors = Vec::with_capacity(sample_ids.len());
    let mut representative_sample_ids = Vec::with_capacity(sample_ids.len());
    for sample_id in sample_ids {
        let (blob, sample_space, sample_domain, sample_scorer, eligibility, outlier, accepted) =
            conn.query_row(
                "SELECT embedding,embedding_space,channel_domain,scorer_version,eligibility,outlier,accepted \
                 FROM voice_samples WHERE id=?1",
                [sample_id],
                |row| {
                    Ok((
                        row.get::<_, Vec<u8>>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, i64>(3)?,
                        row.get::<_, String>(4)?,
                        row.get::<_, i64>(5)?,
                        row.get::<_, i64>(6)?,
                    ))
                },
            )?;
        if sample_space != template.embedding_space
            || sample_domain != template.channel_domain
            || sample_scorer != scorer_version
        {
            return Err(invalid("proposal contains an incompatible voice sample"));
        }
        if eligibility == "enroll" && outlier == 0 && accepted == 1 {
            vectors.push(decode_embedding(&blob)?);
            representative_sample_ids.push(*sample_id);
        }
    }
    if vectors.is_empty() {
        return Err(invalid(
            "every result profile requires an accepted enrollment sample",
        ));
    }
    let representative = voice_quality::robust_representative(&vectors)?;
    let sample_count =
        representative_sample_ids.len() as i64 - representative.excluded_indices.len() as i64;
    let legacy_status = if sample_count >= 3 {
        "stable"
    } else {
        "tentative"
    };
    let medoid_sample_id = representative_sample_ids[representative.medoid_index];
    let temporary_label = format!("pending-proposal-{proposal_id}-{partition_ordinal}");
    conn.execute(
        "INSERT INTO voice_profiles \
         (person_id,label,embedding_space,channel_domain,centroid,sample_count,scorer_version,\
          representative_kind,medoid_sample_id,status) \
         VALUES (?1,?2,?3,?4,?5,?6,?7,'medoid_trimmed_centroid',?8,?9)",
        params![
            person_id,
            temporary_label,
            template.embedding_space,
            template.channel_domain,
            encode_embedding(&representative.centroid),
            sample_count,
            scorer_version,
            medoid_sample_id,
            legacy_status
        ],
    )?;
    let result_id = conn.last_insert_rowid();
    conn.execute(
        "UPDATE voice_profiles SET label=?1 WHERE id=?2",
        params![format!("Voice {result_id}"), result_id],
    )?;
    conn.execute(
        "INSERT INTO voice_profile_revisions \
         (profile_id,status,derivation_version,scorer_version,representative_kind,centroid,\
          sample_count,medoid_sample_id,person_id,proposal_id,reason_code,active) \
         SELECT id,?1,?2,scorer_version,representative_kind,centroid,sample_count,\
                medoid_sample_id,person_id,?3,'proposal_result',1 \
         FROM voice_profiles WHERE id=?4",
        params![legacy_status, derivation_version, proposal_id, result_id],
    )?;
    conn.execute(
        "INSERT INTO voice_profile_proposal_profiles \
         (proposal_id,profile_id,role,partition_ordinal) VALUES (?1,?2,'result',?3)",
        params![proposal_id, result_id, partition_ordinal],
    )?;
    if let Some(person_id) = person_id {
        conn.execute(
            "INSERT INTO profile_identity_bindings \
             (voice_profile_id,person_id,evidence_count,confidence,state,derivation_version,evidence_json) \
             VALUES (?1,?2,1,1.0,'accepted',?3,?4)",
            params![
                result_id,
                person_id,
                derivation_version,
                format!("{{\"kind\":\"profile_merge\",\"proposal_id\":{proposal_id}}}")
            ],
        )?;
    }
    Ok(result_id)
}

fn move_sample_assignment(
    conn: &Connection,
    sample_id: i64,
    expected_source: i64,
    target: i64,
    proposal_id: i64,
) -> Result<()> {
    let (assignment_id, current_profile) = conn.query_row(
        "SELECT id,profile_id FROM voice_sample_profile_assignments \
         WHERE sample_id=?1 AND active=1",
        [sample_id],
        |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)),
    )?;
    if current_profile != expected_source {
        return Err(EnclaveError::Conflict(
            "voice sample assignment changed after proposal".into(),
        ));
    }
    conn.execute(
        "UPDATE voice_sample_profile_assignments SET active=0 WHERE id=?1 AND active=1",
        [assignment_id],
    )?;
    conn.execute(
        "INSERT INTO voice_sample_profile_assignments \
         (sample_id,profile_id,proposal_id,predecessor_assignment_id,active) \
         VALUES (?1,?2,?3,?4,1)",
        params![sample_id, target, proposal_id, assignment_id],
    )?;
    Ok(())
}

fn relabel_samples(
    conn: &Connection,
    sample_ids: &[i64],
    profile_id: i64,
    person_id: Option<i64>,
) -> Result<()> {
    let has_utterances: bool = conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='utterances')",
        [],
        |row| row.get(0),
    )?;
    let label = conn.query_row(
        "SELECT COALESCE(p.display_name,v.label) FROM voice_profiles v \
         LEFT JOIN people p ON p.id=?2 WHERE v.id=?1",
        params![profile_id, person_id],
        |row| row.get::<_, String>(0),
    )?;
    for sample_id in sample_ids {
        let (observation_id, event_id, turn_id) = conn.query_row(
            "SELECT o.id,o.event_id,o.turn_id FROM voice_samples s \
             JOIN speaker_observations o ON o.id=s.speaker_observation_id WHERE s.id=?1",
            [sample_id],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                ))
            },
        )?;
        conn.execute(
            "UPDATE speaker_observations SET person_id=?1 WHERE id=?2",
            params![person_id, observation_id],
        )?;
        if has_utterances {
            conn.execute(
                "UPDATE utterances SET speaker_label=?1 WHERE source_key=?2",
                params![label, format!("cloud-v2:{event_id}:{turn_id}")],
            )?;
        }
    }
    Ok(())
}

fn append_revision(
    conn: &Connection,
    profile_id: i64,
    status: &str,
    derivation_version: i64,
    proposal_id: Option<i64>,
    reason_code: &str,
) -> Result<i64> {
    validate_reason_code(reason_code)?;
    if !matches!(
        status,
        "tentative" | "stable" | "quarantined" | "superseded" | "split"
    ) {
        return Err(invalid("voice profile revision status is invalid"));
    }
    let predecessor_id = conn.query_row(
        "SELECT id FROM voice_profile_revisions WHERE profile_id=?1 AND active=1",
        [profile_id],
        |row| row.get::<_, i64>(0),
    )?;
    conn.execute(
        "UPDATE voice_profile_revisions SET active=0 WHERE id=?1 AND active=1",
        [predecessor_id],
    )?;
    conn.execute(
        "INSERT INTO voice_profile_revisions \
         (profile_id,status,derivation_version,scorer_version,representative_kind,centroid,\
          sample_count,medoid_sample_id,person_id,proposal_id,predecessor_revision_id,reason_code,active) \
         SELECT id,?1,?2,scorer_version,representative_kind,centroid,sample_count,\
                medoid_sample_id,person_id,?3,?4,?5,1 FROM voice_profiles WHERE id=?6",
        params![
            status,
            derivation_version,
            proposal_id,
            predecessor_id,
            reason_code,
            profile_id
        ],
    )?;
    Ok(conn.last_insert_rowid())
}

fn decode_embedding(blob: &[u8]) -> Result<Vec<f32>> {
    if blob.is_empty() || !blob.len().is_multiple_of(4) {
        return Err(invalid("voice embedding blob is invalid"));
    }
    let vector = blob
        .chunks_exact(4)
        .map(|bytes| f32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
        .collect::<Vec<_>>();
    if vector.iter().any(|value| !value.is_finite()) {
        return Err(invalid("voice embedding blob is invalid"));
    }
    Ok(vector)
}

fn encode_embedding(vector: &[f32]) -> Vec<u8> {
    vector
        .iter()
        .flat_map(|value| value.to_le_bytes())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cp::{media::init_schema, voice_quality};
    use rusqlite::{params, Connection};

    fn unit(index: usize) -> Vec<u8> {
        let mut vector = vec![0.0_f32; 256];
        vector[index] = 1.0;
        vector
            .into_iter()
            .flat_map(f32::to_le_bytes)
            .collect::<Vec<_>>()
    }

    fn voice_db() -> Connection {
        let conn = Connection::open_in_memory().unwrap();
        init_schema(&conn).unwrap();
        conn.execute(
            "INSERT INTO capture_sessions(id,device_id,install_id,started_at,last_event_at,schema_version) \
             VALUES ('s','d','i','2026-01-01T00:00:00Z','2026-01-01T00:00:08Z',2)",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO capture_streams(id,capture_session_id,device_id,stream_kind) \
             VALUES ('st','s','d','mic')",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO capture_events(event_id,device_id,install_id,capture_session_id,stream_id,stream_kind,sequence, \
             source_wall_at,source_monotonic_ns,started_at,ended_at,timezone_id,utc_offset_minutes,clock_uncertainty_ms, \
             asset_id,manifest_digest) VALUES ('e','d','i','s','st','mic',0,'2026-01-01T00:00:00Z','1', \
             '2026-01-01T00:00:00Z','2026-01-01T00:00:08Z','UTC',0,1,'a', \
             'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa')",
            [],
        )
        .unwrap();
        for ordinal in 1..=8 {
            conn.execute(
                "INSERT INTO speaker_observations(event_id,turn_id,speaker_local_id,started_at,ended_at,transcript_text) \
                 VALUES ('e',?1,'speaker-1','2026-01-01T00:00:00Z','2026-01-01T00:00:01Z','x')",
                [format!("t{ordinal}")],
            )
            .unwrap();
        }
        conn
    }

    fn add_profile(
        conn: &Connection,
        label: &str,
        domain: &str,
        person_id: Option<i64>,
        observation_ids: &[i64],
        vector_index: usize,
    ) -> i64 {
        conn.execute(
            "INSERT INTO voice_profiles(person_id,label,embedding_space,channel_domain,centroid,sample_count,scorer_version,status) \
             VALUES (?1,?2,'wespeaker-resnet34-vox-v1',?3,?4,?5,?6,'stable')",
            params![
                person_id,
                label,
                domain,
                unit(vector_index),
                observation_ids.len() as i64,
                voice_quality::SCORER_VERSION
            ],
        )
        .unwrap();
        let profile_id = conn.last_insert_rowid();
        for observation_id in observation_ids {
            conn.execute(
                "INSERT INTO voice_samples(speaker_observation_id,voice_profile_id,embedding_space,channel_domain,embedding, \
                 quality_score,scorer_version,eligibility,duration_ms,speech_ratio,snr_proxy_db,embedding_norm,accepted) \
                 VALUES (?1,?2,'wespeaker-resnet34-vox-v1',?3,?4,1.0,?5,'enroll',4000,1.0,30.0,1.0,1)",
                params![
                    observation_id,
                    profile_id,
                    domain,
                    unit(vector_index),
                    voice_quality::SCORER_VERSION
                ],
            )
            .unwrap();
        }
        backfill_profile_lineage(conn).unwrap();
        profile_id
    }

    fn add_sample_to_profile(
        conn: &Connection,
        profile_id: i64,
        observation_id: i64,
        domain: &str,
        vector_index: usize,
    ) -> i64 {
        conn.execute(
            "INSERT INTO voice_samples(speaker_observation_id,voice_profile_id,embedding_space,channel_domain,embedding, \
             quality_score,scorer_version,eligibility,duration_ms,speech_ratio,snr_proxy_db,embedding_norm,accepted) \
             VALUES (?1,?2,'wespeaker-resnet34-vox-v1',?3,?4,1.0,?5,'enroll',4000,1.0,30.0,1.0,1)",
            params![
                observation_id,
                profile_id,
                domain,
                unit(vector_index),
                voice_quality::SCORER_VERSION
            ],
        )
        .unwrap();
        let sample_id = conn.last_insert_rowid();
        record_sample_assignment(conn, profile_id, sample_id).unwrap();
        sample_id
    }

    #[test]
    fn schema_backfill_is_idempotent_and_preserves_existing_profile_membership() {
        let conn = voice_db();
        let profile_id = add_profile(&conn, "Voice A", "mac-mic", None, &[1, 2], 0);

        backfill_profile_lineage(&conn).unwrap();
        assert_eq!(
            effective_profile_status(&conn, profile_id).unwrap(),
            "stable"
        );
        assert_eq!(
            conn.query_row(
                "SELECT COUNT(*) FROM voice_profile_revisions WHERE profile_id=?1 AND active=1",
                [profile_id],
                |row| row.get::<_, i64>(0),
            )
            .unwrap(),
            1
        );
        assert_eq!(active_sample_ids(&conn, profile_id).unwrap(), vec![1, 2]);
    }

    #[test]
    fn merge_is_idempotent_reversible_and_never_erases_source_lineage() {
        let conn = voice_db();
        let left = add_profile(&conn, "Voice A", "mac-mic", None, &[1, 2], 0);
        let right = add_profile(&conn, "Voice B", "mac-mic", None, &[3, 4], 0);

        let proposal = propose_merge(
            &conn,
            &[right, left],
            voice_quality::SCORER_VERSION,
            1,
            "calibrated_duplicate_cluster",
        )
        .unwrap();
        assert_eq!(
            proposal,
            propose_merge(
                &conn,
                &[left, right],
                voice_quality::SCORER_VERSION,
                1,
                "calibrated_duplicate_cluster",
            )
            .unwrap()
        );

        let targets = apply_proposal(&conn, proposal).unwrap();
        assert_eq!(targets.len(), 1);
        assert_eq!(apply_proposal(&conn, proposal).unwrap(), targets);
        assert_eq!(effective_profile_status(&conn, left).unwrap(), "superseded");
        assert_eq!(
            effective_profile_status(&conn, right).unwrap(),
            "superseded"
        );
        assert_eq!(
            active_sample_ids(&conn, targets[0]).unwrap(),
            vec![1, 2, 3, 4]
        );
        assert_eq!(
            conn.query_row(
                "SELECT COUNT(*) FROM voice_profile_revisions WHERE profile_id IN (?1,?2)",
                params![left, right],
                |row| row.get::<_, i64>(0),
            )
            .unwrap(),
            4
        );

        revert_proposal(&conn, proposal).unwrap();
        revert_proposal(&conn, proposal).unwrap();
        assert_eq!(effective_profile_status(&conn, left).unwrap(), "stable");
        assert_eq!(effective_profile_status(&conn, right).unwrap(), "stable");
        assert_eq!(
            effective_profile_status(&conn, targets[0]).unwrap(),
            "superseded"
        );
        assert_eq!(active_sample_ids(&conn, left).unwrap(), vec![1, 2]);
        assert_eq!(active_sample_ids(&conn, right).unwrap(), vec![3, 4]);
    }

    #[test]
    fn merge_rejects_cross_domain_or_conflicting_identity_sources_atomically() {
        let conn = voice_db();
        conn.execute(
            "INSERT INTO people(display_name,normalized_name,status) VALUES ('A','a','identified')",
            [],
        )
        .unwrap();
        let person_a = conn.last_insert_rowid();
        conn.execute(
            "INSERT INTO people(display_name,normalized_name,status) VALUES ('B','b','identified')",
            [],
        )
        .unwrap();
        let person_b = conn.last_insert_rowid();
        let a = add_profile(&conn, "Voice A", "mac-mic", Some(person_a), &[1], 0);
        let b = add_profile(&conn, "Voice B", "mac-mic", Some(person_b), &[2], 0);
        let room = add_profile(&conn, "Voice C", "iphone-room", Some(person_a), &[3], 0);

        assert!(propose_merge(
            &conn,
            &[a, b],
            voice_quality::SCORER_VERSION,
            1,
            "identity_conflict",
        )
        .is_err());
        assert!(propose_merge(
            &conn,
            &[a, room],
            voice_quality::SCORER_VERSION,
            1,
            "domain_conflict",
        )
        .is_err());
        assert_eq!(
            conn.query_row("SELECT COUNT(*) FROM voice_profile_proposals", [], |row| {
                row.get::<_, i64>(0)
            })
            .unwrap(),
            0
        );
    }

    #[test]
    fn split_requires_an_exact_disjoint_partition_and_is_reversible() {
        let conn = voice_db();
        let source = add_profile(&conn, "Voice A", "mac-mic", None, &[1, 2, 3, 4], 0);

        assert!(propose_split(
            &conn,
            source,
            &[vec![1, 2], vec![2, 3]],
            voice_quality::SCORER_VERSION,
            1,
            "calibrated_bimodal_cluster",
        )
        .is_err());
        assert!(propose_split(
            &conn,
            source,
            &[vec![1, 2], vec![3]],
            voice_quality::SCORER_VERSION,
            1,
            "calibrated_bimodal_cluster",
        )
        .is_err());

        let proposal = propose_split(
            &conn,
            source,
            &[vec![4, 3], vec![2, 1]],
            voice_quality::SCORER_VERSION,
            1,
            "calibrated_bimodal_cluster",
        )
        .unwrap();
        let targets = apply_proposal(&conn, proposal).unwrap();
        assert_eq!(targets.len(), 2);
        assert_eq!(effective_profile_status(&conn, source).unwrap(), "split");
        assert_eq!(active_sample_ids(&conn, targets[0]).unwrap(), vec![1, 2]);
        assert_eq!(active_sample_ids(&conn, targets[1]).unwrap(), vec![3, 4]);

        revert_proposal(&conn, proposal).unwrap();
        assert_eq!(effective_profile_status(&conn, source).unwrap(), "stable");
        assert_eq!(active_sample_ids(&conn, source).unwrap(), vec![1, 2, 3, 4]);
        assert!(targets
            .iter()
            .all(|target| effective_profile_status(&conn, *target).unwrap() == "superseded"));
    }

    #[test]
    fn stale_or_quality_invalid_proposals_fail_atomically() {
        let conn = voice_db();
        let left = add_profile(&conn, "Voice A", "mac-mic", None, &[1], 0);
        let right = add_profile(&conn, "Voice B", "mac-mic", None, &[2], 0);
        let proposal = propose_merge(
            &conn,
            &[left, right],
            voice_quality::SCORER_VERSION,
            1,
            "calibrated_duplicate_cluster",
        )
        .unwrap();
        add_sample_to_profile(&conn, left, 3, "mac-mic", 0);

        assert!(apply_proposal(&conn, proposal).is_err());
        assert_eq!(effective_profile_status(&conn, left).unwrap(), "stable");
        assert_eq!(effective_profile_status(&conn, right).unwrap(), "stable");
        assert_eq!(
            conn.query_row("SELECT COUNT(*) FROM voice_profiles", [], |row| {
                row.get::<_, i64>(0)
            })
            .unwrap(),
            2
        );
        assert_eq!(
            conn.query_row(
                "SELECT state FROM voice_profile_proposals WHERE id=?1",
                [proposal],
                |row| row.get::<_, String>(0),
            )
            .unwrap(),
            "proposed"
        );
        conn.execute(
            "UPDATE voice_profile_proposals SET state='approved' WHERE id=?1",
            [proposal],
        )
        .unwrap();
        assert_eq!(process_lineage_actions(&conn, 10).unwrap(), 1);
        assert_eq!(
            conn.query_row(
                "SELECT state FROM voice_profile_proposals WHERE id=?1",
                [proposal],
                |row| row.get::<_, String>(0),
            )
            .unwrap(),
            "rejected"
        );

        conn.execute(
            "UPDATE voice_samples SET eligibility='match_only' WHERE voice_profile_id IN (?1,?2)",
            params![left, right],
        )
        .unwrap();
        assert!(propose_merge(
            &conn,
            &[left, right],
            voice_quality::SCORER_VERSION,
            2,
            "no_enrollment_evidence",
        )
        .is_err());
    }

    #[test]
    fn revert_refuses_to_orphan_samples_learned_after_a_merge() {
        let conn = voice_db();
        let left = add_profile(&conn, "Voice A", "mac-mic", None, &[1], 0);
        let right = add_profile(&conn, "Voice B", "mac-mic", None, &[2], 0);
        let proposal = propose_merge(
            &conn,
            &[left, right],
            voice_quality::SCORER_VERSION,
            1,
            "calibrated_duplicate_cluster",
        )
        .unwrap();
        let target = apply_proposal(&conn, proposal).unwrap()[0];
        let later_sample = add_sample_to_profile(&conn, target, 3, "mac-mic", 0);

        assert!(revert_proposal(&conn, proposal).is_err());
        assert_eq!(
            effective_profile_status(&conn, target).unwrap(),
            "tentative"
        );
        assert!(active_sample_ids(&conn, target)
            .unwrap()
            .contains(&later_sample));
        assert_eq!(
            conn.query_row(
                "SELECT state FROM voice_profile_proposals WHERE id=?1",
                [proposal],
                |row| row.get::<_, String>(0),
            )
            .unwrap(),
            "applied"
        );
        conn.execute(
            "UPDATE voice_profile_proposals SET state='revert_requested' WHERE id=?1",
            [proposal],
        )
        .unwrap();
        assert_eq!(process_lineage_actions(&conn, 10).unwrap(), 1);
        assert_eq!(
            conn.query_row(
                "SELECT state FROM voice_profile_proposals WHERE id=?1",
                [proposal],
                |row| row.get::<_, String>(0),
            )
            .unwrap(),
            "applied"
        );
    }

    #[test]
    fn merge_preserves_one_accepted_identity_while_identified_split_abstains() {
        let conn = voice_db();
        conn.execute(
            "INSERT INTO people(display_name,normalized_name,status) \
             VALUES ('John Garcia','john garcia','identified')",
            [],
        )
        .unwrap();
        let person_id = conn.last_insert_rowid();
        let left = add_profile(&conn, "Voice A", "mac-mic", Some(person_id), &[1, 2], 0);
        let right = add_profile(&conn, "Voice B", "mac-mic", Some(person_id), &[3, 4], 0);
        conn.execute(
            "UPDATE speaker_observations SET person_id=?1 WHERE id BETWEEN 1 AND 4",
            [person_id],
        )
        .unwrap();

        assert!(propose_split(
            &conn,
            left,
            &[vec![1], vec![2]],
            voice_quality::SCORER_VERSION,
            1,
            "calibrated_bimodal_cluster",
        )
        .is_err());
        let proposal = propose_merge(
            &conn,
            &[left, right],
            voice_quality::SCORER_VERSION,
            1,
            "calibrated_duplicate_cluster",
        )
        .unwrap();
        let target = apply_proposal(&conn, proposal).unwrap()[0];
        assert_eq!(
            conn.query_row(
                "SELECT person_id FROM voice_profiles WHERE id=?1",
                [target],
                |row| row.get::<_, Option<i64>>(0),
            )
            .unwrap(),
            Some(person_id)
        );
        assert_eq!(
            conn.query_row(
                "SELECT COUNT(*) FROM profile_identity_bindings \
                 WHERE voice_profile_id=?1 AND person_id=?2 AND state='accepted'",
                params![target, person_id],
                |row| row.get::<_, i64>(0),
            )
            .unwrap(),
            1
        );
        assert_eq!(
            conn.query_row(
                "SELECT COUNT(*) FROM speaker_observations \
                 WHERE id BETWEEN 1 AND 4 AND person_id=?1",
                [person_id],
                |row| row.get::<_, i64>(0),
            )
            .unwrap(),
            4
        );

        revert_proposal(&conn, proposal).unwrap();
        assert_eq!(
            conn.query_row(
                "SELECT COUNT(*) FROM speaker_observations \
                 WHERE id BETWEEN 1 AND 4 AND person_id=?1",
                [person_id],
                |row| row.get::<_, i64>(0),
            )
            .unwrap(),
            4
        );
    }

    #[test]
    fn bounded_processor_ignores_proposed_and_runs_only_explicit_actions() {
        let conn = voice_db();
        let left = add_profile(&conn, "Voice A", "mac-mic", None, &[1], 0);
        let right = add_profile(&conn, "Voice B", "mac-mic", None, &[2], 0);
        let proposal = propose_merge(
            &conn,
            &[left, right],
            voice_quality::SCORER_VERSION,
            1,
            "calibrated_duplicate_cluster",
        )
        .unwrap();

        assert_eq!(process_lineage_actions(&conn, 10).unwrap(), 0);
        assert_eq!(effective_profile_status(&conn, left).unwrap(), "stable");
        conn.execute(
            "UPDATE voice_profile_proposals SET state='approved' WHERE id=?1",
            [proposal],
        )
        .unwrap();
        assert_eq!(process_lineage_actions(&conn, 1).unwrap(), 1);
        assert_eq!(process_lineage_actions(&conn, 10).unwrap(), 0);
        assert_eq!(effective_profile_status(&conn, left).unwrap(), "superseded");

        conn.execute(
            "UPDATE voice_profile_proposals SET state='revert_requested' WHERE id=?1",
            [proposal],
        )
        .unwrap();
        assert_eq!(process_lineage_actions(&conn, 10).unwrap(), 1);
        assert_eq!(effective_profile_status(&conn, left).unwrap(), "stable");
        assert_eq!(
            conn.query_row(
                "SELECT state FROM voice_profile_proposals WHERE id=?1",
                [proposal],
                |row| row.get::<_, String>(0),
            )
            .unwrap(),
            "reverted"
        );
    }
}
