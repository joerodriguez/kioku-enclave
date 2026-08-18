//! Typed identity resolution, stable non-compacting episode speaker slots,
//! and structured evidence evaluation.

use crate::error::{EnclaveError, Result};
use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};

pub const UNIDENTIFIED_SPEAKER_LABEL: &str = "Unidentified voice";
pub const OWNER_DISPLAY_NAME: &str = "Me";

/// Typed speaker attribution kind returned by `resolve_speaker_attribution`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AttributionKind {
    /// Resolved to an identified person via direct evidence or accepted profile binding.
    Person,
    /// Presentation-only attribution for the authenticated account owner on a qualified call track.
    OwnerSourceRole,
    /// Stable anonymous speaker slot bound to a persistent voice profile.
    AnonymousProfile,
    /// Stable anonymous speaker slot bound to a request-local speaker cluster.
    RequestLocal,
    /// Fallback for unsegmented or completely unidentified audio.
    Unsegmented,
}

impl AttributionKind {
    pub fn to_participant_attribution_kind(self, has_direct_evidence: bool) -> &'static str {
        match self {
            AttributionKind::Person => {
                if has_direct_evidence {
                    "direct_identity_evidence"
                } else {
                    "verified_voice"
                }
            }
            AttributionKind::OwnerSourceRole => "owner",
            AttributionKind::AnonymousProfile
            | AttributionKind::RequestLocal
            | AttributionKind::Unsegmented => "context_inferred",
        }
    }
}

/// Structured attribution projection for an utterance or observation.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ResolvedAttribution {
    pub display_label: String,
    pub attribution_kind: AttributionKind,
    pub person_id: Option<i64>,
    pub profile_state: Option<String>,
    pub slot_ordinal: Option<i32>,
    /// True when the person was resolved via Tier 1 (direct accepted observation evidence)
    /// rather than Tier 2 (profile binding). Used to write the correct `attribution_kind`
    /// value (`"direct_identity_evidence"` vs `"verified_voice"`) into `episode_participants`.
    pub has_direct_evidence: bool,
}

/// Convert a zero-based slot ordinal into a permanent letter identifier:
/// 0 -> "A", 1 -> "B", ..., 25 -> "Z", 26 -> "AA", 27 -> "AB", ...
pub fn format_slot_ordinal(ordinal: i32) -> String {
    if ordinal < 0 {
        return "A".to_string();
    }
    let mut num = ordinal as u32;
    let mut result = Vec::new();
    loop {
        let rem = (num % 26) as u8;
        result.push((b'A' + rem) as char);
        if num < 26 {
            break;
        }
        num = (num / 26) - 1;
    }
    result.into_iter().rev().collect()
}

/// Permanent non-compacting slot allocator.
///
/// Ensures an episode speaker slot is allocated deterministically on first
/// appearance and is NEVER renumbered or compacted if another slot is merged
/// or superseded.
pub fn allocate_or_lookup_slot(
    conn: &Connection,
    episode_id: i64,
    profile_id: Option<i64>,
    cluster_id: Option<i64>,
) -> Result<i32> {
    if let Some(pid) = profile_id {
        let existing: Option<i32> = conn
            .query_row(
                "SELECT slot_ordinal FROM episode_speaker_slots \
                 WHERE episode_id = ?1 AND voice_profile_id = ?2 AND status = 'active'",
                params![episode_id, pid],
                |r| r.get(0),
            )
            .optional()?;
        if let Some(ordinal) = existing {
            return Ok(ordinal);
        }
    }

    if let Some(cid) = cluster_id {
        let existing: Option<i32> = conn
            .query_row(
                "SELECT slot_ordinal FROM episode_speaker_slots \
                 WHERE episode_id = ?1 AND speaker_cluster_id = ?2 AND status = 'active'",
                params![episode_id, cid],
                |r| r.get(0),
            )
            .optional()?;
        if let Some(ordinal) = existing {
            return Ok(ordinal);
        }
    }

    // Allocate next monotonic slot ordinal for this episode
    let max_ordinal: Option<i32> = conn
        .query_row(
            "SELECT MAX(slot_ordinal) FROM episode_speaker_slots WHERE episode_id = ?1",
            [episode_id],
            |r| r.get(0),
        )
        .optional()?
        .flatten();

    let next_ordinal = max_ordinal.map_or(0, |max| max + 1);

    if let Some(pid) = profile_id {
        conn.execute(
            "INSERT INTO episode_speaker_slots (episode_id, voice_profile_id, slot_ordinal, status) \
             VALUES (?1, ?2, ?3, 'active')",
            params![episode_id, pid, next_ordinal],
        )?;
    } else if let Some(cid) = cluster_id {
        conn.execute(
            "INSERT INTO episode_speaker_slots (episode_id, speaker_cluster_id, slot_ordinal, status) \
             VALUES (?1, ?2, ?3, 'active')",
            params![episode_id, cid, next_ordinal],
        )?;
    }

    Ok(next_ordinal)
}

/// Transition an active cluster slot to a voice profile without renumbering any slots.
pub fn transition_cluster_slot_to_profile(
    conn: &Connection,
    episode_id: i64,
    cluster_id: i64,
    profile_id: i64,
) -> Result<()> {
    let cluster_slot: Option<(i64, i32)> = conn
        .query_row(
            "SELECT id, slot_ordinal FROM episode_speaker_slots \
             WHERE episode_id = ?1 AND speaker_cluster_id = ?2 AND status = 'active'",
            params![episode_id, cluster_id],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?;

    let profile_slot: Option<i64> = conn
        .query_row(
            "SELECT id FROM episode_speaker_slots \
             WHERE episode_id = ?1 AND voice_profile_id = ?2 AND status = 'active'",
            params![episode_id, profile_id],
            |r| r.get(0),
        )
        .optional()?;

    match (cluster_slot, profile_slot) {
        (Some((c_slot_id, _)), Some(_p_slot_id)) => {
            // Profile already has an active slot in this episode. Tombstone the cluster slot.
            conn.execute(
                "UPDATE episode_speaker_slots SET status = 'superseded', updated_at = strftime('%Y-%m-%dT%H:%M:%fZ','now') \
                 WHERE id = ?1",
                [c_slot_id],
            )?;
        }
        (Some((c_slot_id, _)), None) => {
            // Profile has no slot in this episode yet. Transition cluster slot in place.
            conn.execute(
                "UPDATE episode_speaker_slots \
                 SET speaker_cluster_id = NULL, voice_profile_id = ?1, updated_at = strftime('%Y-%m-%dT%H:%M:%fZ','now') \
                 WHERE id = ?2",
                params![profile_id, c_slot_id],
            )?;
        }
        (None, _) => {}
    }

    Ok(())
}

/// Resolve typed speaker attribution across the strict 5-tier authority hierarchy.
pub fn resolve_speaker_attribution(
    conn: &Connection,
    observation_id: i64,
    episode_id: Option<i64>,
) -> Result<ResolvedAttribution> {
    // 1. Direct accepted observation evidence
    let direct_evidence: Option<(i64, String)> = conn
        .query_row(
            "SELECT p.id, p.display_name \
             FROM speaker_observations o \
             JOIN identity_evidence e ON e.id = o.direct_evidence_id \
             JOIN people p ON p.id = e.person_id \
             WHERE o.id = ?1 AND e.status = 'accepted' AND e.speaker_observation_id = o.id \
               AND p.status <> 'quarantined'",
            [observation_id],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?;

    if let Some((person_id, display_name)) = direct_evidence {
        // Carry the existing episode slot ordinal (if any) so the reconciler can find
        // and update the old anonymous participant row rather than orphaning it.
        let existing_slot: Option<i32> = episode_id
            .and_then(|ep_id| {
                conn.query_row(
                    "SELECT slot_ordinal FROM episode_speaker_slots \
                     WHERE episode_id = ?1 AND status = 'active' AND (\
                         speaker_cluster_id IN (\
                             SELECT cluster_id FROM speaker_observations WHERE id = ?2 AND cluster_id IS NOT NULL\
                         ) OR voice_profile_id IN (\
                             SELECT a.profile_id FROM voice_samples s \
                             JOIN voice_sample_profile_assignments a ON a.sample_id = s.id AND a.active = 1 \
                             WHERE s.speaker_observation_id = ?2 AND s.accepted = 1 AND s.outlier = 0 \
                             LIMIT 1\
                         )\
                     ) LIMIT 1",
                    params![ep_id, observation_id],
                    |r| r.get(0),
                )
                .optional()
                .ok()
                .flatten()
            });
        return Ok(ResolvedAttribution {
            display_label: display_name,
            attribution_kind: AttributionKind::Person,
            person_id: Some(person_id),
            profile_state: None,
            slot_ordinal: existing_slot,
            has_direct_evidence: true,
        });
    }

    // 2. Accepted profile identity binding via active voice sample assignment or cluster
    let profile_binding: Option<(i64, String, String)> = {
        let from_sample: Option<(i64, String, String)> = conn
            .query_row(
                "SELECT p.id, p.display_name, v.status \
                 FROM voice_samples s \
                 JOIN voice_sample_profile_assignments a ON a.sample_id = s.id AND a.active = 1 \
                 JOIN voice_profiles v ON v.id = a.profile_id AND v.status <> 'quarantined' \
                 JOIN profile_identity_bindings b ON b.voice_profile_id = v.id AND b.active = 1 AND b.state = 'accepted' \
                 JOIN people p ON p.id = b.person_id AND p.status <> 'quarantined' \
                 WHERE s.speaker_observation_id = ?1 AND s.accepted = 1 AND s.outlier = 0 \
                 ORDER BY s.id DESC LIMIT 1",
                [observation_id],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .optional()?;

        if from_sample.is_some() {
            from_sample
        } else {
            conn.query_row(
                "SELECT p.id, p.display_name, v.status \
                 FROM speaker_observations o \
                 JOIN speaker_clusters c ON c.id = o.cluster_id \
                 JOIN voice_profiles v ON v.id = c.voice_profile_id AND v.status <> 'quarantined' \
                 JOIN profile_identity_bindings b ON b.voice_profile_id = v.id AND b.active = 1 AND b.state = 'accepted' \
                 JOIN people p ON p.id = b.person_id AND p.status <> 'quarantined' \
                 WHERE o.id = ?1",
                [observation_id],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .optional()?
        }
    };

    if let Some((person_id, display_name, profile_status)) = profile_binding {
        // Carry the existing episode slot ordinal so the reconciler can find the old
        // anonymous participant row and update it in-place rather than creating a duplicate.
        let existing_slot: Option<i32> = episode_id
            .and_then(|ep_id| {
                conn.query_row(
                    "SELECT slot_ordinal FROM episode_speaker_slots \
                     WHERE episode_id = ?1 AND status = 'active' AND (\
                         speaker_cluster_id IN (\
                             SELECT cluster_id FROM speaker_observations WHERE id = ?2 AND cluster_id IS NOT NULL\
                         ) OR voice_profile_id IN (\
                             SELECT a.profile_id FROM voice_samples s \
                             JOIN voice_sample_profile_assignments a ON a.sample_id = s.id AND a.active = 1 \
                             WHERE s.speaker_observation_id = ?2 AND s.accepted = 1 AND s.outlier = 0 \
                             LIMIT 1\
                         )\
                     ) LIMIT 1",
                    params![ep_id, observation_id],
                    |r| r.get(0),
                )
                .optional()
                .ok()
                .flatten()
            });
        return Ok(ResolvedAttribution {
            display_label: display_name,
            attribution_kind: AttributionKind::Person,
            person_id: Some(person_id),
            profile_state: Some(profile_status),
            slot_ordinal: existing_slot,
            has_direct_evidence: false,
        });
    }

    // Load observation metadata (cluster_id, attribution_state)
    let obs_meta: Option<(Option<i64>, Option<String>, Option<i64>)> = conn
        .query_row(
            "SELECT c.id, c.attribution_state, c.voice_profile_id \
             FROM speaker_observations o \
             LEFT JOIN speaker_clusters c ON c.id = o.cluster_id \
             WHERE o.id = ?1",
            [observation_id],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .optional()?;

    let (cluster_id, attribution_state, cluster_profile_id) =
        obs_meta.unwrap_or((None, None, None));

    let effective_profile_id = cluster_profile_id.or_else(|| {
        conn.query_row(
            "SELECT a.profile_id FROM voice_samples s \
             JOIN voice_sample_profile_assignments a ON a.sample_id = s.id AND a.active = 1 \
             WHERE s.speaker_observation_id = ?1 AND s.accepted = 1 AND s.outlier = 0 \
             ORDER BY s.id DESC LIMIT 1",
            [observation_id],
            |r| r.get(0),
        )
        .optional()
        .ok()
        .flatten()
    });

    // 3. Source-role presentation attribution ('owner_transmit' single-speaker)
    if attribution_state.as_deref() == Some("owner_transmit") {
        return Ok(ResolvedAttribution {
            display_label: OWNER_DISPLAY_NAME.to_string(),
            attribution_kind: AttributionKind::OwnerSourceRole,
            person_id: None,
            profile_state: None,
            slot_ordinal: None,
            has_direct_evidence: false,
        });
    }

    // 4. Stable anonymous speaker slot or profile label
    if let Some(ep_id) = episode_id {
        let slot_ordinal: Option<(i32, bool)> = if let Some(pid) = effective_profile_id {
            conn.query_row(
                "SELECT slot_ordinal, 1 FROM episode_speaker_slots \
                 WHERE episode_id = ?1 AND voice_profile_id = ?2 AND status = 'active'",
                params![ep_id, pid],
                |r| Ok((r.get(0)?, true)),
            )
            .optional()?
        } else if let Some(cid) = cluster_id {
            conn.query_row(
                "SELECT slot_ordinal, 0 FROM episode_speaker_slots \
                 WHERE episode_id = ?1 AND speaker_cluster_id = ?2 AND status = 'active'",
                params![ep_id, cid],
                |r| Ok((r.get(0)?, false)),
            )
            .optional()?
        } else {
            None
        };

        if let Some((ordinal, is_profile)) = slot_ordinal {
            let letter = format_slot_ordinal(ordinal);
            return Ok(ResolvedAttribution {
                display_label: format!("Unknown speaker {letter}"),
                attribution_kind: if is_profile {
                    AttributionKind::AnonymousProfile
                } else {
                    AttributionKind::RequestLocal
                },
                person_id: None,
                profile_state: None,
                slot_ordinal: Some(ordinal),
                has_direct_evidence: false,
            });
        }
    } else if let Some(pid) = effective_profile_id {
        let label: Option<String> = conn
            .query_row(
                "SELECT label FROM voice_profiles WHERE id = ?1",
                [pid],
                |r| r.get(0),
            )
            .optional()?;
        if let Some(label) = label {
            return Ok(ResolvedAttribution {
                display_label: label,
                attribution_kind: AttributionKind::AnonymousProfile,
                person_id: None,
                profile_state: None,
                slot_ordinal: None,
                has_direct_evidence: false,
            });
        }
    }

    // 5. Unsegmented fallback
    Ok(ResolvedAttribution {
        display_label: UNIDENTIFIED_SPEAKER_LABEL.to_string(),
        attribution_kind: AttributionKind::Unsegmented,
        person_id: None,
        profile_state: None,
        slot_ordinal: None,
        has_direct_evidence: false,
    })
}

/// Resolve or generate a persistent, opaque TypeID participant key (`part_01J...`).
pub fn resolve_or_create_stable_participant_key(
    conn: &Connection,
    episode_id: i64,
    person_id: Option<i64>,
    speaker_slot_id: Option<i64>,
    claimed_name: Option<&str>,
) -> Result<String> {
    if let Some(pid) = person_id {
        let existing: Option<String> = conn
            .query_row(
                "SELECT participant_key FROM episode_participants \
                 WHERE episode_id = ?1 AND person_id = ?2 \
                 ORDER BY id ASC LIMIT 1",
                params![episode_id, pid],
                |r| r.get(0),
            )
            .optional()?;
        if let Some(key) = existing {
            return Ok(key);
        }
    }

    if let Some(slot_id) = speaker_slot_id {
        let existing: Option<String> = conn
            .query_row(
                "SELECT participant_key FROM episode_participants \
                 WHERE episode_id = ?1 AND speaker_slot_id = ?2 \
                 ORDER BY id ASC LIMIT 1",
                params![episode_id, slot_id],
                |r| r.get(0),
            )
            .optional()?;
        if let Some(key) = existing {
            return Ok(key);
        }
    }

    if let Some(name) = claimed_name {
        let existing: Option<String> = conn
            .query_row(
                "SELECT participant_key FROM episode_participants \
                 WHERE episode_id = ?1 AND source_claimed_name = ?2 \
                 ORDER BY id ASC LIMIT 1",
                params![episode_id, name],
                |r| r.get(0),
            )
            .optional()?;
        if let Some(key) = existing {
            return Ok(key);
        }
    }

    // Generate a fresh random participant key
    let uuid_str = crate::cp::tokens::new_uuid().replace('-', "");
    Ok(format!("part_{uuid_str}"))
}

/// Reconciles speaker slots for an episode, allocating new monotonic non-compacting slots
/// for any unslotted cluster or profile and transitioning merged cluster slots in-place,
/// and synchronizing episode_participants and the participants JSON list.
pub fn reconcile_episode_speaker_slots(conn: &Connection, episode_id: i64) -> Result<()> {
    let mut stmt = conn.prepare(
        "SELECT DISTINCT o.cluster_id, c.voice_profile_id, c.attribution_state \
         FROM episode_members m \
         JOIN utterances u ON u.id = m.record_id \
         JOIN speaker_observations o ON o.id = u.speaker_observation_id \
         LEFT JOIN speaker_clusters c ON c.id = o.cluster_id \
         WHERE m.episode_id = ?1 AND m.record_type = 'utterance'",
    )?;

    let rows = stmt
        .query_map([episode_id], |r| {
            Ok((
                r.get::<_, Option<i64>>(0)?,
                r.get::<_, Option<i64>>(1)?,
                r.get::<_, Option<String>>(2)?,
            ))
        })?
        .collect::<std::result::Result<Vec<_>, rusqlite::Error>>()?;

    for (cluster_id, profile_id, attr_state) in rows {
        if attr_state.as_deref() == Some("owner_transmit") {
            continue;
        }

        if cluster_id.is_none() && profile_id.is_none() {
            continue;
        }

        if let (Some(cid), Some(pid)) = (cluster_id, profile_id) {
            transition_cluster_slot_to_profile(conn, episode_id, cid, pid)?;
            allocate_or_lookup_slot(conn, episode_id, Some(pid), None)?;
        } else if let Some(pid) = profile_id {
            allocate_or_lookup_slot(conn, episode_id, Some(pid), None)?;
        } else if let Some(cid) = cluster_id {
            allocate_or_lookup_slot(conn, episode_id, None, Some(cid))?;
        }
    }

    // Now resolve speaker attribution for all utterances in the episode
    let mut utt_stmt = conn.prepare(
        "SELECT u.id, u.speaker_observation_id \
         FROM episode_members m \
         JOIN utterances u ON u.id = m.record_id \
         WHERE m.episode_id = ?1 AND m.record_type = 'utterance' \
         ORDER BY u.start_offset_seconds ASC, u.id ASC",
    )?;

    let obs_list = utt_stmt
        .query_map([episode_id], |r| {
            Ok((r.get::<_, i64>(0)?, r.get::<_, Option<i64>>(1)?))
        })?
        .collect::<std::result::Result<Vec<_>, rusqlite::Error>>()?;

    let mut active_participant_keys = Vec::new();
    let mut participant_names = Vec::new();
    for (utt_id, obs_id_opt) in obs_list {
        if let Some(obs_id) = obs_id_opt {
            let attribution = resolve_speaker_attribution(conn, obs_id, Some(episode_id))?;
            conn.execute(
                "UPDATE utterances SET speaker_label = ?1 WHERE id = ?2",
                params![attribution.display_label, utt_id],
            )?;

            // Owner and Unsegmented attributions have no stable slot or person; use
            // well-known sentinel keys so they never generate unbounded duplicate rows.
            let participant_key = match attribution.attribution_kind {
                AttributionKind::OwnerSourceRole => "owner".to_string(),
                AttributionKind::Unsegmented => "unsegmented".to_string(),
                _ => {
                    let slot_id: Option<i64> = if let Some(ordinal) = attribution.slot_ordinal {
                        conn.query_row(
                            "SELECT id FROM episode_speaker_slots \
                             WHERE episode_id = ?1 AND slot_ordinal = ?2 AND status = 'active'",
                            params![episode_id, ordinal],
                            |r| r.get(0),
                        )
                        .optional()?
                    } else {
                        None
                    };
                    resolve_or_create_stable_participant_key(
                        conn,
                        episode_id,
                        attribution.person_id,
                        slot_id,
                        None,
                    )?
                }
            };

            let slot_id: Option<i64> = if let Some(ordinal) = attribution.slot_ordinal {
                conn.query_row(
                    "SELECT id FROM episode_speaker_slots \
                     WHERE episode_id = ?1 AND slot_ordinal = ?2 AND status = 'active'",
                    params![episode_id, ordinal],
                    |r| r.get(0),
                )
                .optional()?
            } else {
                None
            };

            conn.execute(
                "INSERT INTO episode_participants \
                 (episode_id, participant_key, person_id, speaker_slot_id, source_claimed_name, attribution_kind, state) \
                 VALUES (?1, ?2, ?3, ?4, NULL, ?5, 'active') \
                 ON CONFLICT(episode_id, participant_key) DO UPDATE SET \
                     person_id = COALESCE(excluded.person_id, episode_participants.person_id), \
                     speaker_slot_id = COALESCE(excluded.speaker_slot_id, episode_participants.speaker_slot_id), \
                     attribution_kind = excluded.attribution_kind, \
                     state = 'active'",
                params![
                    episode_id,
                    participant_key,
                    attribution.person_id,
                    slot_id,
                    attribution.attribution_kind.to_participant_attribution_kind(attribution.has_direct_evidence)
                ],
            )?;

            if !active_participant_keys.contains(&participant_key) {
                active_participant_keys.push(participant_key);
            }
            if !participant_names.contains(&attribution.display_label) {
                participant_names.push(attribution.display_label);
            }
        }
    }

    if !active_participant_keys.is_empty() {
        let placeholders = active_participant_keys
            .iter()
            .map(|_| "?")
            .collect::<Vec<_>>()
            .join(",");
        let query = format!(
            "UPDATE episode_participants SET state = 'superseded', updated_at = strftime('%Y-%m-%dT%H:%M:%fZ','now') \
             WHERE episode_id = ? AND participant_key NOT IN ({placeholders})"
        );
        let mut params_vec: Vec<&dyn rusqlite::ToSql> = Vec::new();
        params_vec.push(&episode_id);
        for key in &active_participant_keys {
            params_vec.push(key);
        }
        conn.execute(&query, rusqlite::params_from_iter(params_vec))?;
    }

    // Preserve existing contextual participant names from the episode summary
    let existing_participants: Vec<String> = conn
        .query_row(
            "SELECT participants FROM episodes WHERE id = ?1",
            [episode_id],
            |r| r.get::<_, Option<String>>(0),
        )
        .optional()?
        .flatten()
        .and_then(|raw| serde_json::from_str::<Vec<String>>(&raw).ok())
        .unwrap_or_default();

    for existing_name in existing_participants {
        if !participant_names.contains(&existing_name)
            && !existing_name.starts_with("Unknown speaker ")
            && existing_name != UNIDENTIFIED_SPEAKER_LABEL
        {
            participant_names.push(existing_name);
        }
    }

    // Synchronize participants JSON cache on episodes without prematurely advancing
    // finalized_identity_revision (which must only be advanced by the finalizer upon full re-generation)
    let participants_json =
        serde_json::to_string(&participant_names).unwrap_or_else(|_| "[]".to_string());
    conn.execute(
        "UPDATE episodes \
         SET participants = ?1, \
             updated_at = strftime('%Y-%m-%dT%H:%M:%fZ','now') \
         WHERE id = ?2",
        params![participants_json, episode_id],
    )?;

    Ok(())
}

/// Outcome of a `bind_profile_to_person` attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BindOutcome {
    /// The binding is now (or already was) the active accepted binding.
    Accepted,
    /// A different person already holds the active accepted binding; the
    /// proposal was recorded as `conflicted` and the accepted edge preserved.
    Conflicted,
}

/// Binds a voice profile to a Person with conflict protection.
/// If an active accepted binding already exists for this profile to a DIFFERENT person,
/// the proposed binding is recorded as `'conflicted'` (`active = 0`) with `conflicts_with_id` set,
/// preserving the existing active accepted binding.
pub fn bind_profile_to_person(
    conn: &Connection,
    profile_id: i64,
    person_id: i64,
    operation_id: &str,
    evidence_json: &str,
    confidence: f64,
) -> Result<BindOutcome> {
    // 1. Idempotency check: if operation_id already recorded for this profile
    let existing: Option<(i64, String)> = conn
        .query_row(
            "SELECT person_id, state FROM profile_identity_bindings \
             WHERE voice_profile_id = ?1 AND operation_id = ?2",
            params![profile_id, operation_id],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?;

    if let Some((existing_pid, existing_state)) = existing {
        if existing_pid == person_id {
            return Ok(if existing_state == "conflicted" {
                BindOutcome::Conflicted
            } else {
                BindOutcome::Accepted
            });
        }
        return Err(EnclaveError::Conflict(format!(
            "idempotency conflict on profile {profile_id} for operation {operation_id}"
        )));
    }

    // 2. Conflict check: is there an active accepted binding for this profile to someone else?
    let active_accepted: Option<(i64, i64)> = conn
        .query_row(
            "SELECT id, person_id FROM profile_identity_bindings \
             WHERE voice_profile_id = ?1 AND active = 1 AND state = 'accepted'",
            [profile_id],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?;

    if let Some((accepted_id, accepted_pid)) = active_accepted {
        if accepted_pid != person_id {
            // Record conflicted proposal linking to preserved accepted edge
            conn.execute(
                "INSERT INTO profile_identity_bindings \
                 (voice_profile_id, person_id, evidence_count, confidence, state, derivation_version, evidence_json, operation_id, active, conflicts_with_id) \
                 VALUES (?1, ?2, 1, ?3, 'conflicted', 1, ?4, ?5, 0, ?6)",
                params![profile_id, person_id, confidence, evidence_json, operation_id, accepted_id],
            )?;
            return Ok(BindOutcome::Conflicted);
        }
    }

    // 3. No conflict: deactivate prior bindings and insert new accepted binding
    conn.execute(
        "UPDATE profile_identity_bindings SET active = 0 WHERE voice_profile_id = ?1",
        [profile_id],
    )?;

    conn.execute(
        "INSERT INTO profile_identity_bindings \
         (voice_profile_id, person_id, evidence_count, confidence, state, derivation_version, evidence_json, operation_id, active) \
         VALUES (?1, ?2, 1, ?3, 'accepted', 1, ?4, ?5, 1)",
        params![profile_id, person_id, confidence, evidence_json, operation_id],
    )?;

    // Update the voice_profiles cache column
    conn.execute(
        "UPDATE voice_profiles SET person_id = ?1, updated_at = strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE id = ?2",
        params![person_id, profile_id],
    )?;

    // Queue identity refresh for all episodes containing this profile
    queue_episode_identity_refresh_for_profile(conn, profile_id)?;

    Ok(BindOutcome::Accepted)
}

/// Queues identity refresh for all episodes containing observations from the given profile.
pub fn queue_episode_identity_refresh_for_profile(
    conn: &Connection,
    profile_id: i64,
) -> Result<usize> {
    let count = conn.execute(
        "UPDATE episodes \
         SET identity_revision = identity_revision + 1, \
             identity_refresh_status = 'queued', \
             updated_at = strftime('%Y-%m-%dT%H:%M:%fZ','now') \
         WHERE id IN ( \
             SELECT DISTINCT em.episode_id \
             FROM episode_members em \
             JOIN utterances u ON u.id = em.record_id AND em.record_type = 'utterance' \
             JOIN speaker_observations o ON o.id = u.speaker_observation_id \
             LEFT JOIN speaker_clusters c ON c.id = o.cluster_id \
             LEFT JOIN voice_samples s ON s.speaker_observation_id = o.id \
             LEFT JOIN voice_sample_profile_assignments a ON a.sample_id = s.id AND a.active = 1 \
             WHERE c.voice_profile_id = ?1 OR a.profile_id = ?1 \
         )",
        [profile_id],
    )?;
    Ok(count)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_slot_ordinal_produces_non_compacting_letters() {
        assert_eq!(format_slot_ordinal(0), "A");
        assert_eq!(format_slot_ordinal(1), "B");
        assert_eq!(format_slot_ordinal(25), "Z");
        assert_eq!(format_slot_ordinal(26), "AA");
        assert_eq!(format_slot_ordinal(27), "AB");
        assert_eq!(format_slot_ordinal(51), "AZ");
        assert_eq!(format_slot_ordinal(52), "BA");
    }

    #[test]
    fn slot_allocation_is_deterministic_and_non_compacting() {
        let mut conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE episodes (id INTEGER PRIMARY KEY);
             CREATE TABLE voice_profiles (id INTEGER PRIMARY KEY);
             CREATE TABLE speaker_clusters (id INTEGER PRIMARY KEY);
             CREATE TABLE episode_speaker_slots (
                 id INTEGER PRIMARY KEY AUTOINCREMENT,
                 episode_id INTEGER NOT NULL REFERENCES episodes(id) ON DELETE CASCADE,
                 voice_profile_id INTEGER REFERENCES voice_profiles(id) ON DELETE RESTRICT,
                 speaker_cluster_id INTEGER REFERENCES speaker_clusters(id) ON DELETE RESTRICT,
                 slot_ordinal INTEGER NOT NULL CHECK (slot_ordinal >= 0),
                 status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'superseded')),
                 created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
                 updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
                 CHECK ((status = 'active' AND ((voice_profile_id IS NULL) != (speaker_cluster_id IS NULL))) OR status = 'superseded')
             );
             CREATE UNIQUE INDEX idx_slot_ordinal ON episode_speaker_slots(episode_id, slot_ordinal);
             INSERT INTO episodes VALUES (1);
             INSERT INTO speaker_clusters VALUES (1), (2), (3);
             INSERT INTO voice_profiles VALUES (10);",
        )
        .unwrap();

        let tx = conn.transaction().unwrap();
        let slot_a = allocate_or_lookup_slot(&tx, 1, None, Some(1)).unwrap();
        let slot_b = allocate_or_lookup_slot(&tx, 1, None, Some(2)).unwrap();
        let slot_c = allocate_or_lookup_slot(&tx, 1, None, Some(3)).unwrap();

        assert_eq!(slot_a, 0); // "A"
        assert_eq!(slot_b, 1); // "B"
        assert_eq!(slot_c, 2); // "C"

        // Cluster 1 resolves to Profile 10
        transition_cluster_slot_to_profile(&tx, 1, 1, 10).unwrap();

        // Looking up Profile 10 returns original slot 0
        let slot_p10 = allocate_or_lookup_slot(&tx, 1, Some(10), None).unwrap();
        assert_eq!(slot_p10, 0);

        // Cluster 2 ALSO resolves to Profile 10 (merge of A and B)
        transition_cluster_slot_to_profile(&tx, 1, 2, 10).unwrap();

        // Slot C remains unchanged (ordinal 2 -> "C", never compacted to "B")
        let slot_c_after = allocate_or_lookup_slot(&tx, 1, None, Some(3)).unwrap();
        assert_eq!(slot_c_after, 2);

        tx.commit().unwrap();
    }

    #[test]
    fn episode_identity_propagation_updates_prior_conversations_automatically() {
        let conn = Connection::open_in_memory().unwrap();
        crate::cp::media::init_schema(&conn).unwrap();

        // 1. Create Episode 335
        conn.execute(
            "INSERT INTO episodes (id, started_at, ended_at, type, title, summary, participants, finalization_status, identity_revision, finalized_identity_revision, identity_refresh_status) \
             VALUES (335, '2026-07-26T20:00:00.000Z', '2026-07-26T20:30:00.000Z', 'conversation', 'Launch Sync', 'Discussion on launch', '[]', 'complete', 1, 1, 'ready')",
            [],
        ).unwrap();

        // 2. Audio segment
        conn.execute(
            "INSERT INTO audio_segments (id, started_at, ended_at, duration_seconds, source_type, audio_format, transcription_status) \
             VALUES (1, '2026-07-26T20:00:00.000Z', '2026-07-26T20:30:00.000Z', 1800.0, 'system', 'audio/wav', 'done')",
            [],
        ).unwrap();

        // 3. Work unit
        conn.execute(
            "INSERT INTO media_work_units (id, work_class, processor_version, state, started_at, ended_at, reserved_output_tokens) \
             VALUES ('wu-1', 'audio', 1, 'succeeded', '2026-07-26T20:00:00.000Z', '2026-07-26T20:30:00.000Z', 1024)",
            [],
        ).unwrap();

        // 4. Create speaker cluster for Frankie's voice before name is known
        conn.execute(
            "INSERT INTO speaker_clusters (id, work_unit_id, speaker_local_id, voice_profile_id, attribution_state) \
             VALUES (100, 'wu-1', 'speaker-frankie', NULL, 'request_local')",
            [],
        ).unwrap();

        // 5. Speaker observation for Turn 1 (owner on mic)
        conn.execute(
            "INSERT INTO capture_sessions (id, device_id, install_id, started_at, last_event_at, schema_version) \
             VALUES ('s-1', 'd-1', 'i-1', '2026-07-26T20:00:00.000Z', '2026-07-26T20:30:00.000Z', 2)",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO capture_streams (id, capture_session_id, device_id, stream_kind) \
             VALUES ('st-1', 's-1', 'd-1', 'mic')",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO capture_events (event_id, device_id, install_id, capture_session_id, stream_id, stream_kind, sequence, source_wall_at, source_monotonic_ns, started_at, ended_at, timezone_id, utc_offset_minutes, clock_uncertainty_ms, asset_id, manifest_digest) \
             VALUES ('ev-1', 'd-1', 'i-1', 's-1', 'st-1', 'mic', 0, '2026-07-26T20:00:00.000Z', '0', '2026-07-26T20:00:00.000Z', '2026-07-26T20:30:00.000Z', 'UTC', 0, 0, 'asset-1', 'digest-1')",
            [],
        ).unwrap();

        conn.execute(
            "INSERT INTO speaker_clusters (id, work_unit_id, speaker_local_id, voice_profile_id, attribution_state) \
             VALUES (101, 'wu-1', 'speaker-owner', NULL, 'owner_transmit')",
            [],
        ).unwrap();

        conn.execute(
            "INSERT INTO speaker_observations (id, event_id, turn_id, speaker_local_id, started_at, ended_at, transcript_text, cluster_id) \
             VALUES (1, 'ev-1', 't-1', 'speaker-owner', '2026-07-26T20:00:05.000Z', '2026-07-26T20:00:10.000Z', 'Hey how is the deployment going?', 101)",
            [],
        ).unwrap();

        conn.execute(
            "INSERT INTO utterances (id, audio_segment_id, start_offset_seconds, end_offset_seconds, text, speaker_label, source_key, speaker_observation_id) \
             VALUES (1, 1, 5.0, 10.0, 'Hey how is the deployment going?', 'Me', 'cloud-v2:ev-1:t-1', 1)",
            [],
        ).unwrap();

        // 6. Speaker observation for Turn 2 (Frankie on remote audio, unnamed)
        conn.execute(
            "INSERT INTO speaker_observations (id, event_id, turn_id, speaker_local_id, started_at, ended_at, transcript_text, cluster_id) \
             VALUES (2, 'ev-1', 't-2', 'speaker-frankie', '2026-07-26T20:00:11.000Z', '2026-07-26T20:00:20.000Z', 'All green on our end!', 100)",
            [],
        ).unwrap();

        conn.execute(
            "INSERT INTO utterances (id, audio_segment_id, start_offset_seconds, end_offset_seconds, text, speaker_label, source_key, speaker_observation_id) \
             VALUES (2, 1, 11.0, 20.0, 'All green on our end!', 'Unidentified voice', 'cloud-v2:ev-1:t-2', 2)",
            [],
        ).unwrap();

        // 7. Bind episode members
        conn.execute(
            "INSERT INTO episode_members (episode_id, record_id, record_type) VALUES (335, 1, 'utterance'), (335, 2, 'utterance')",
            [],
        ).unwrap();

        // Initial reconciliation
        reconcile_episode_speaker_slots(&conn, 335).unwrap();

        let participants: String = conn
            .query_row(
                "SELECT participants FROM episodes WHERE id = 335",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(participants, "[\"Me\",\"Unknown speaker A\"]");

        let turn2_label: String = conn
            .query_row(
                "SELECT speaker_label FROM utterances WHERE id = 2",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(turn2_label, "Unknown speaker A");

        // 8. Later: Kioku learns that cluster 100 is Frankie via voice profile 42
        conn.execute(
            "INSERT INTO people (id, display_name, kind) VALUES (20, 'Frankie', 'person')",
            [],
        )
        .unwrap();

        conn.execute(
            "INSERT INTO voice_profiles (id, label, channel_domain, embedding_space, scorer_version, representative_kind, centroid) \
             VALUES (42, 'Frankie', 'remote_playback', 'voice-v1', 1, 'centroid', X'0000803f')",
            [],
        ).unwrap();

        bind_profile_to_person(&conn, 42, 20, "op_frankie", "{\"source\":\"test\"}", 0.99).unwrap();

        conn.execute(
            "UPDATE speaker_clusters SET voice_profile_id = 42, attribution_state = 'person_bound' WHERE id = 100",
            [],
        ).unwrap();

        // 9. Propagate identity refresh to affected episodes
        let queued_count = queue_episode_identity_refresh_for_profile(&conn, 42).unwrap();
        assert_eq!(queued_count, 1);

        let refresh_status: String = conn
            .query_row(
                "SELECT identity_refresh_status FROM episodes WHERE id = 335",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(refresh_status, "queued");

        // 10. Background worker reconciles episode
        reconcile_episode_speaker_slots(&conn, 335).unwrap();

        let updated_participants: String = conn
            .query_row(
                "SELECT participants FROM episodes WHERE id = 335",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(updated_participants, "[\"Me\",\"Frankie\"]");

        let updated_turn2_label: String = conn
            .query_row(
                "SELECT speaker_label FROM utterances WHERE id = 2",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(updated_turn2_label, "Frankie");

        // finalized_identity_revision is NOT prematurely advanced by lightweight reconciler
        let (identity_rev, fin_identity_rev): (i64, i64) = conn
            .query_row(
                "SELECT identity_revision, finalized_identity_revision FROM episodes WHERE id = 335",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert!(fin_identity_rev < identity_rev);
    }

    #[test]
    fn bind_profile_to_person_protects_accepted_identity_from_conflicting_proposals() {
        let conn = Connection::open_in_memory().unwrap();
        crate::cp::media::init_schema(&conn).unwrap();

        conn.execute(
            "INSERT INTO people (id, display_name, kind) VALUES (10, 'Frankie', 'person'), (20, 'Alex', 'person')",
            [],
        )
        .unwrap();

        conn.execute(
            "INSERT INTO voice_profiles (id, label, channel_domain, embedding_space, scorer_version, representative_kind, centroid) \
             VALUES (1, 'Voice 1', 'mic', 'voice-v1', 1, 'centroid', X'0000803f')",
            [],
        )
        .unwrap();

        // 1. Initial accepted binding to Frankie (person 10)
        bind_profile_to_person(
            &conn,
            1,
            10,
            "op_initial",
            "{\"evidence\":\"self_id\"}",
            0.95,
        )
        .unwrap();

        let bound_pid: Option<i64> = conn
            .query_row(
                "SELECT person_id FROM profile_identity_bindings WHERE voice_profile_id = 1 AND active = 1 AND state = 'accepted'",
                [],
                |r| r.get(0),
            )
            .optional()
            .unwrap();
        assert_eq!(bound_pid, Some(10));

        // 2. Conflicting proposal to bind profile 1 to Alex (person 20)
        bind_profile_to_person(
            &conn,
            1,
            20,
            "op_mistaken",
            "{\"evidence\":\"screen\"}",
            0.90,
        )
        .unwrap();

        // Active accepted binding must STILL belong to Frankie (person 10)
        let active_pid_after: Option<i64> = conn
            .query_row(
                "SELECT person_id FROM profile_identity_bindings WHERE voice_profile_id = 1 AND active = 1 AND state = 'accepted'",
                [],
                |r| r.get(0),
            )
            .optional()
            .unwrap();
        assert_eq!(
            active_pid_after,
            Some(10),
            "accepted edge must not be deactivated on conflict"
        );

        // Conflicted proposal is recorded with state = 'conflicted', active = 0, and conflicts_with_id set
        let (conflicted_pid, conflicted_state, conflicted_active, conflicts_with_id): (
            i64,
            String,
            i64,
            Option<i64>,
        ) = conn
            .query_row(
                "SELECT person_id, state, active, conflicts_with_id FROM profile_identity_bindings WHERE voice_profile_id = 1 AND operation_id = 'op_mistaken'",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
            )
            .unwrap();
        assert_eq!(conflicted_pid, 20);
        assert_eq!(conflicted_state, "conflicted");
        assert_eq!(conflicted_active, 0);
        assert!(conflicts_with_id.is_some());

        // 3. Idempotent replay of op_initial succeeds without creating duplicate rows
        bind_profile_to_person(
            &conn,
            1,
            10,
            "op_initial",
            "{\"evidence\":\"self_id\"}",
            0.95,
        )
        .unwrap();

        // 4. Idempotent replay of op_mistaken succeeds without creating duplicate rows
        bind_profile_to_person(
            &conn,
            1,
            20,
            "op_mistaken",
            "{\"evidence\":\"screen\"}",
            0.90,
        )
        .unwrap();

        let total_binding_rows: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM profile_identity_bindings WHERE voice_profile_id = 1",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(total_binding_rows, 2);

        // 5. Operation ID collision with a DIFFERENT person_id errors as Conflict
        let collision_res = bind_profile_to_person(
            &conn,
            1,
            999,
            "op_initial",
            "{\"evidence\":\"tamper\"}",
            0.95,
        );
        assert!(collision_res.is_err());

        // Cached voice_profiles.person_id remains Frankie
        let profile_pid: Option<i64> = conn
            .query_row(
                "SELECT person_id FROM voice_profiles WHERE id = 1",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(profile_pid, Some(10));
    }
}
