//! Source-settled memory topology reconciliation.
//!
//! PostgreSQL discovers the complete fixed-point cohort, proves source
//! settlement, owns claims/stages, and publishes with a topology CAS. This
//! module is deliberately the pure policy layer around that authority: it
//! renders bounded evidence, validates an exhaustive model partition, selects
//! exact one-to-one identity retention, and orchestrates at most one settled
//! cohort before finalization.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tracing::{info, warn};

use crate::error::{EnclaveError, Result};
use crate::persistence::{
    reconciliation_outputs_commitment, ReconciledMemoryWrite, ReconciliationClaim,
    ReconciliationDraft, ReconciliationEvidenceAtom, ReconciliationPublish,
    ReconciliationPublishResult, ReconciliationSnapshot, ReconciliationStageWrite,
    StagedReconciliation,
};

use super::{isotime, vertex, CpState};

const RECONCILIATION_VERSION: i64 = 1;
const PROMPT_VERSION: i64 = 1;
const PARTITION_SCHEMA_VERSION: i64 = 1;
const VALIDATOR_VERSION: i64 = 1;
const QUIET_HORIZON_MS: i64 = 4 * 60 * 60 * 1_000;
const MAX_COHORT_DRAFTS: i64 = 32;
const MAX_COHORT_ATOMS: i64 = 4_000;
const MAX_OUTPUTS: usize = 32;
const MAX_TITLE_CHARS: usize = 180;
const MAX_SUMMARY_CHARS: usize = 4_000;
const MAX_GIST_CHARS: usize = 800;
const MAX_CONTEXT_CHARS: usize = 1_200;
const MAX_CONTEXT_TOTAL_CHARS: usize = 256 * 1_024;
const MAX_MODEL_INPUT_BYTES: usize = 1_024 * 1_024;
const RECONCILIATION_OUTPUT_TOKENS: u32 = 8_192;
const CLAIM_LEASE_SECONDS: i64 = 5 * 60;
const MODEL_ATTEMPTS_BEFORE_CONSERVATIVE_KEEP: i64 = 3;

const SYSTEM_PROMPT: &str = r#"You reconcile provisional personal-memory drafts after all nearby source evidence has settled.

Recording sessions are transport boundaries, never automatic memory boundaries. Group evidence by the same concrete objective, conversation, decision, or workflow. Two recordings 30 minutes apart may be one memory when the person resumed the same goal. A shared broad topic alone is not enough: separate distinct goals even when the people, application, or subject overlap. One recording may contain several memories.

Return one complete partition of the supplied opaque source_ids. Every source_id must occur exactly once in one memory. Never invent an id, duplicate evidence, omit evidence, or infer facts not supported by the supplied atoms. Prefer the existing draft partition when the evidence does not clearly justify a change. Titles, summaries, actions, people, languages, and timeline gists must be grounded in the assigned evidence. Timeline entries cite only source_ids assigned to their memory."#;

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
struct ModelTimelineItem {
    source_ids: Vec<String>,
    gist: String,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
struct ModelMemory {
    source_ids: Vec<String>,
    #[serde(rename = "type")]
    episode_type: String,
    title: String,
    summary: String,
    participants: Vec<String>,
    languages: Vec<String>,
    action_items: Vec<String>,
    timeline: Vec<ModelTimelineItem>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
struct ModelPartition {
    memories: Vec<ModelMemory>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct PlannedMemory {
    retained_episode_id: Option<i64>,
    predecessor_episode_ids: Vec<i64>,
    started_at: String,
    ended_at: String,
    episode_type: String,
    title: String,
    summary: String,
    participants: Vec<String>,
    languages: Vec<String>,
    action_items: Vec<String>,
    minute_summaries: Value,
    minutes_text: String,
    substance: String,
    visual_evidence: String,
    member_source_ids: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ValidatedPartition {
    model: ModelPartition,
    outputs: Vec<PlannedMemory>,
    result_commitment: Vec<u8>,
}

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|value| value.as_millis() as i64)
        .unwrap_or(0)
}

fn bounded(value: &str, cap: usize) -> String {
    let mut chars = value.trim().chars();
    let mut output: String = chars.by_ref().take(cap).collect();
    if chars.next().is_some() {
        output.push('…');
    }
    output
}

fn canonical_strings(values: &[String], item_cap: usize, count_cap: usize) -> Vec<String> {
    let mut seen = HashSet::new();
    values
        .iter()
        .map(|value| bounded(value, item_cap))
        .filter(|value| !value.is_empty() && seen.insert(value.clone()))
        .take(count_cap)
        .collect()
}

fn valid_episode_type(value: &str) -> bool {
    matches!(
        value,
        "meeting" | "lesson" | "call" | "coding" | "browsing" | "break" | "other"
    )
}

fn reconciled_substance(predecessors: &[&ReconciliationDraft]) -> &'static str {
    if predecessors.iter().any(|draft| draft.substance == "normal") {
        "normal"
    } else if predecessors.iter().any(|draft| draft.substance == "low") {
        "low"
    } else {
        "none"
    }
}

fn response_schema() -> Value {
    json!({
        "type": "OBJECT",
        "properties": {
            "memories": {
                "type": "ARRAY",
                "maxItems": MAX_OUTPUTS,
                "items": {
                    "type": "OBJECT",
                    "properties": {
                        "source_ids": {"type":"ARRAY", "items":{"type":"STRING"}},
                        "type": {"type":"STRING", "enum":["meeting","lesson","call","coding","browsing","break","other"]},
                        "title": {"type":"STRING"},
                        "summary": {"type":"STRING"},
                        "participants": {"type":"ARRAY", "items":{"type":"STRING"}},
                        "languages": {"type":"ARRAY", "items":{"type":"STRING"}},
                        "action_items": {"type":"ARRAY", "items":{"type":"STRING"}},
                        "timeline": {
                            "type":"ARRAY",
                            "items": {
                                "type":"OBJECT",
                                "properties": {
                                    "source_ids":{"type":"ARRAY", "items":{"type":"STRING"}},
                                    "gist":{"type":"STRING"}
                                },
                                "required":["source_ids","gist"]
                            }
                        }
                    },
                    "required":["source_ids","type","title","summary","participants","languages","action_items","timeline"]
                }
            }
        },
        "required":["memories"]
    })
}

fn render_model_input(snapshot: &ReconciliationSnapshot) -> Result<String> {
    #[derive(Serialize)]
    struct PromptDraft<'a> {
        id: i64,
        started_at: &'a str,
        ended_at: &'a str,
        title: String,
        summary: String,
        participants: Vec<String>,
        action_items: Vec<String>,
        source_ids: &'a [String],
    }
    #[derive(Serialize)]
    struct PromptAtom<'a> {
        source_id: &'a str,
        started_at: &'a str,
        ended_at: &'a str,
        context: String,
    }
    let drafts = snapshot
        .drafts
        .iter()
        .map(|draft| PromptDraft {
            id: draft.id,
            started_at: &draft.started_at,
            ended_at: &draft.ended_at,
            title: bounded(&draft.title, MAX_TITLE_CHARS),
            summary: bounded(
                draft.summary.as_deref().unwrap_or_default(),
                MAX_SUMMARY_CHARS,
            ),
            participants: canonical_strings(&draft.participants, 120, 64),
            action_items: canonical_strings(&draft.action_items, 500, 64),
            source_ids: &draft.member_source_ids,
        })
        .collect::<Vec<_>>();
    let mut context_budget = MAX_CONTEXT_TOTAL_CHARS;
    let atoms = snapshot
        .atoms
        .iter()
        .map(|atom| {
            let cap = MAX_CONTEXT_CHARS.min(context_budget);
            let context = if cap == 0 {
                String::new()
            } else {
                bounded(&atom.context, cap)
            };
            context_budget = context_budget.saturating_sub(context.chars().count());
            PromptAtom {
                source_id: &atom.source_id,
                started_at: &atom.started_at,
                ended_at: &atom.ended_at,
                context,
            }
        })
        .collect::<Vec<_>>();
    let encoded = serde_json::to_string(&json!({
        "provisional_drafts": drafts,
        "evidence_atoms": atoms,
    }))?;
    if encoded.len() > MAX_MODEL_INPUT_BYTES {
        return Err(EnclaveError::Config(
            "memory reconciliation model input bound exceeded".into(),
        ));
    }
    Ok(encoded)
}

fn timeline_product(
    memory: &ModelMemory,
    assigned: &BTreeSet<String>,
    atom_by_id: &HashMap<String, &ReconciliationEvidenceAtom>,
    fallback_start: &str,
) -> (Value, String) {
    let mut by_start = BTreeMap::new();
    for item in &memory.timeline {
        let Some(start) = item
            .source_ids
            .iter()
            .filter(|source_id| assigned.contains(*source_id))
            .filter_map(|source_id| atom_by_id.get(source_id).copied())
            .map(|atom| atom.started_at.as_str())
            .min()
        else {
            continue;
        };
        let gist = bounded(&item.gist, MAX_GIST_CHARS);
        if !gist.is_empty() {
            by_start.entry(start.to_string()).or_insert(gist);
        }
    }
    if by_start.is_empty() {
        by_start.insert(
            fallback_start.to_string(),
            bounded(&memory.summary, MAX_GIST_CHARS),
        );
    }
    let rows = by_start
        .iter()
        .map(|(start, gist)| json!({"start":start, "gist":gist}))
        .collect::<Vec<_>>();
    let text = by_start.values().cloned().collect::<Vec<_>>().join("\n");
    (Value::Array(rows), text)
}

fn validate_partition(
    snapshot: &ReconciliationSnapshot,
    model: ModelPartition,
) -> Result<ValidatedPartition> {
    if snapshot.drafts.is_empty() || snapshot.atoms.is_empty() || model.memories.is_empty() {
        return Err(EnclaveError::Config(
            "memory reconciliation requires non-empty drafts, evidence, and outputs".into(),
        ));
    }
    if model.memories.len() > MAX_OUTPUTS {
        return Err(EnclaveError::Config(
            "memory reconciliation output bound exceeded".into(),
        ));
    }
    let expected = snapshot
        .atoms
        .iter()
        .map(|atom| atom.source_id.clone())
        .collect::<BTreeSet<_>>();
    if expected.len() != snapshot.atoms.len() {
        return Err(EnclaveError::Config(
            "memory reconciliation snapshot contains duplicate evidence".into(),
        ));
    }
    let draft_ids = snapshot
        .drafts
        .iter()
        .map(|draft| draft.id)
        .collect::<BTreeSet<_>>();
    let predecessor_ids = snapshot
        .predecessor_episode_ids
        .iter()
        .copied()
        .collect::<BTreeSet<_>>();
    if draft_ids.len() != snapshot.drafts.len()
        || predecessor_ids.len() != snapshot.predecessor_episode_ids.len()
        || draft_ids != predecessor_ids
        || snapshot
            .drafts
            .iter()
            .any(|draft| draft.member_source_ids.is_empty())
    {
        return Err(EnclaveError::Store(
            "memory reconciliation snapshot has invalid predecessors".into(),
        ));
    }
    let atom_by_id = snapshot
        .atoms
        .iter()
        .map(|atom| (atom.source_id.clone(), atom))
        .collect::<HashMap<_, _>>();
    let predecessor_sources = snapshot
        .drafts
        .iter()
        .map(|draft| {
            (
                draft.id,
                draft
                    .member_source_ids
                    .iter()
                    .cloned()
                    .collect::<BTreeSet<_>>(),
            )
        })
        .collect::<HashMap<_, _>>();
    let mut owned_sources = HashSet::new();
    for draft in &snapshot.drafts {
        for source_id in &draft.member_source_ids {
            if !expected.contains(source_id) || !owned_sources.insert(source_id) {
                return Err(EnclaveError::Store(
                    "memory reconciliation snapshot has invalid active ownership".into(),
                ));
            }
        }
    }

    let mut seen = BTreeSet::new();
    let mut output_sets = Vec::with_capacity(model.memories.len());
    for memory in &model.memories {
        if memory.source_ids.is_empty()
            || !valid_episode_type(&memory.episode_type)
            || memory.title.trim().is_empty()
            || memory.summary.trim().is_empty()
        {
            return Err(EnclaveError::Config(
                "memory reconciliation output is invalid".into(),
            ));
        }
        let mut output = BTreeSet::new();
        for source_id in &memory.source_ids {
            if !expected.contains(source_id)
                || !output.insert(source_id.clone())
                || !seen.insert(source_id.clone())
            {
                return Err(EnclaveError::Config(
                    "memory reconciliation source is unknown or duplicated".into(),
                ));
            }
        }
        for item in &memory.timeline {
            if item.source_ids.is_empty()
                || item.gist.trim().is_empty()
                || item.source_ids.iter().any(|id| !output.contains(id))
            {
                return Err(EnclaveError::Config(
                    "memory reconciliation timeline is not grounded in its memory".into(),
                ));
            }
        }
        output_sets.push(output);
    }
    if seen != expected {
        return Err(EnclaveError::Config(
            "memory reconciliation omitted source evidence".into(),
        ));
    }

    let mut contributing = Vec::with_capacity(output_sets.len());
    let mut predecessor_outputs: HashMap<i64, Vec<usize>> = HashMap::new();
    for (ordinal, output) in output_sets.iter().enumerate() {
        let mut predecessor_ids = snapshot
            .drafts
            .iter()
            .filter(|draft| !predecessor_sources[&draft.id].is_disjoint(output))
            .map(|draft| draft.id)
            .collect::<Vec<_>>();
        if predecessor_ids.is_empty() {
            let output_start = output
                .iter()
                .filter_map(|id| atom_by_id.get(id))
                .filter_map(|atom| isotime::parse_epoch_millis(&atom.started_at))
                .min()
                .ok_or_else(|| EnclaveError::Config("memory output has no timestamp".into()))?;
            let nearest = snapshot
                .drafts
                .iter()
                .min_by_key(|draft| {
                    let start = isotime::parse_epoch_millis(&draft.started_at).unwrap_or(0);
                    let end = isotime::parse_epoch_millis(&draft.ended_at).unwrap_or(start);
                    let distance = if output_start < start {
                        start.saturating_sub(output_start)
                    } else if output_start > end {
                        output_start.saturating_sub(end)
                    } else {
                        0
                    };
                    (distance, draft.id)
                })
                .ok_or_else(|| EnclaveError::Config("memory cohort has no draft".into()))?;
            predecessor_ids.push(nearest.id);
        }
        for predecessor_id in &predecessor_ids {
            predecessor_outputs
                .entry(*predecessor_id)
                .or_default()
                .push(ordinal);
        }
        contributing.push(predecessor_ids);
    }

    let mut outputs = Vec::with_capacity(model.memories.len());
    for (ordinal, memory) in model.memories.iter().enumerate() {
        let sources = &output_sets[ordinal];
        let predecessor_ids = &contributing[ordinal];
        let retained_episode_id = if predecessor_ids.len() == 1
            && predecessor_outputs
                .get(&predecessor_ids[0])
                .is_some_and(|ordinals| ordinals.as_slice() == [ordinal])
            && predecessor_sources
                .get(&predecessor_ids[0])
                .is_some_and(|members| members.is_subset(sources))
        {
            Some(predecessor_ids[0])
        } else {
            None
        };
        let assigned_atoms = sources
            .iter()
            .filter_map(|id| atom_by_id.get(id).copied())
            .collect::<Vec<_>>();
        let started_ms = assigned_atoms
            .iter()
            .filter_map(|atom| isotime::parse_epoch_millis(&atom.started_at))
            .min()
            .ok_or_else(|| EnclaveError::Config("memory output has no start".into()))?;
        let ended_ms = assigned_atoms
            .iter()
            .filter_map(|atom| isotime::parse_epoch_millis(&atom.ended_at))
            .max()
            .ok_or_else(|| EnclaveError::Config("memory output has no end".into()))?
            .max(started_ms.saturating_add(1));
        let started_at = isotime::format_epoch_millis(started_ms);
        let ended_at = isotime::format_epoch_millis(ended_ms);
        let (minute_summaries, minutes_text) =
            timeline_product(memory, sources, &atom_by_id, &started_at);
        let predecessor_rows = predecessor_ids
            .iter()
            .filter_map(|id| snapshot.drafts.iter().find(|draft| draft.id == *id))
            .collect::<Vec<_>>();
        let substance = reconciled_substance(&predecessor_rows);
        let visual_evidence = if assigned_atoms
            .iter()
            .any(|atom| atom.record_type == "screenshot")
        {
            "useful"
        } else {
            "none"
        };
        outputs.push(PlannedMemory {
            retained_episode_id,
            predecessor_episode_ids: predecessor_ids.clone(),
            started_at,
            ended_at,
            episode_type: memory.episode_type.clone(),
            title: bounded(&memory.title, MAX_TITLE_CHARS),
            summary: bounded(&memory.summary, MAX_SUMMARY_CHARS),
            participants: canonical_strings(&memory.participants, 120, 64),
            languages: canonical_strings(&memory.languages, 32, 16),
            action_items: canonical_strings(&memory.action_items, 500, 64),
            minute_summaries,
            minutes_text,
            substance: substance.into(),
            visual_evidence: visual_evidence.into(),
            member_source_ids: sources.iter().cloned().collect(),
        });
    }

    // Commit the exact JSON value representation passed to PostgreSQL. This
    // keeps application validation and stage admission on one canonical byte
    // identity even if Rust struct field order differs from JSONB map order.
    let normalized = serde_json::to_vec(&serde_json::to_value(&model)?)?;
    Ok(ValidatedPartition {
        model,
        outputs,
        result_commitment: Sha256::digest(normalized).to_vec(),
    })
}

fn conservative_partition(snapshot: &ReconciliationSnapshot) -> Result<ModelPartition> {
    let mut memories = snapshot
        .drafts
        .iter()
        .map(|draft| ModelMemory {
            source_ids: draft.member_source_ids.clone(),
            episode_type: draft.episode_type.clone().unwrap_or_else(|| "other".into()),
            title: draft.title.clone(),
            summary: draft.summary.clone().unwrap_or_default(),
            participants: draft.participants.clone(),
            languages: draft.languages.clone(),
            action_items: draft.action_items.clone(),
            timeline: Vec::new(),
        })
        .collect::<Vec<_>>();
    let owned = memories
        .iter()
        .flat_map(|memory| memory.source_ids.iter().cloned())
        .collect::<HashSet<_>>();
    for atom in snapshot
        .atoms
        .iter()
        .filter(|atom| !owned.contains(&atom.source_id))
    {
        let atom_start = isotime::parse_epoch_millis(&atom.started_at).unwrap_or(0);
        let nearest = snapshot
            .drafts
            .iter()
            .enumerate()
            .min_by_key(|(_, draft)| {
                let start = isotime::parse_epoch_millis(&draft.started_at).unwrap_or(0);
                let end = isotime::parse_epoch_millis(&draft.ended_at).unwrap_or(start);
                let distance = if atom_start < start {
                    start.saturating_sub(atom_start)
                } else if atom_start > end {
                    atom_start.saturating_sub(end)
                } else {
                    0
                };
                (distance, draft.id)
            })
            .map(|(index, _)| index)
            .ok_or_else(|| EnclaveError::Config("memory cohort has no draft".into()))?;
        memories[nearest].source_ids.push(atom.source_id.clone());
    }
    for memory in &mut memories {
        memory.source_ids.sort();
        memory.source_ids.dedup();
        if !valid_episode_type(&memory.episode_type) {
            memory.episode_type = "other".into();
        }
        if memory.title.trim().is_empty() {
            memory.title = "Memory".into();
        }
        if memory.summary.trim().is_empty() {
            memory.summary = "Memory draft".into();
        }
    }
    Ok(ModelPartition { memories })
}

fn reconciliation_id(snapshot: &ReconciliationSnapshot, result_commitment: &[u8]) -> String {
    let mut digest = Sha256::new();
    digest.update(b"kioku:postgres-memory-reconciliation:v1\0");
    digest.update(&snapshot.source_fingerprint);
    digest.update(result_commitment);
    format!("rec_{:x}", digest.finalize())
}

fn retry_at(claim_attempt_count: i64, now: i64) -> String {
    let delay = if claim_attempt_count <= 1 {
        10 * 60 * 1_000
    } else {
        60 * 60 * 1_000
    };
    isotime::format_epoch_millis(now.saturating_add(delay))
}

fn finalization_may_continue(writer_enabled: bool, eligible_cohort_exists: bool) -> bool {
    !writer_enabled || !eligible_cohort_exists
}

async fn reserve_output(state: &CpState, account_id: &str) -> Result<()> {
    let reserved = super::limits::reserve_vertex_output_tokens_for_class(
        &state.repositories,
        account_id,
        super::limits::VertexWorkClass::DerivedText,
        i64::from(RECONCILIATION_OUTPUT_TOKENS),
        state.config.quota_vertex_output_tokens_per_day,
    )
    .await?;
    if reserved {
        Ok(())
    } else {
        Err(EnclaveError::Config("vertex_daily_budget".into()))
    }
}

async fn release_for_retry(
    state: &CpState,
    claim: &ReconciliationClaim,
    error_code: &'static str,
    consume_model_attempt: bool,
) -> Result<()> {
    let now = now_ms();
    let released_at = isotime::format_epoch_millis(now);
    let retry_at = retry_at(claim.attempt_count, now);
    state
        .repositories
        .memory_reconciliation()
        .release_reconciliation(
            claim,
            &released_at,
            Some(&retry_at),
            error_code,
            false,
            consume_model_attempt,
        )
        .await
}

fn validate_stage(
    snapshot: &ReconciliationSnapshot,
    staged: &StagedReconciliation,
) -> Result<ValidatedPartition> {
    if staged.account_id != snapshot.account_id
        || staged.source_fingerprint != snapshot.source_fingerprint
        || staged.predecessor_episode_ids != snapshot.predecessor_episode_ids
        || staged.reconciliation_version != RECONCILIATION_VERSION
        || staged.prompt_version != PROMPT_VERSION
        || staged.partition_schema_version != PARTITION_SCHEMA_VERSION
        || staged.validator_version != VALIDATOR_VERSION
    {
        return Err(EnclaveError::Conflict(
            "memory reconciliation staged contract changed".into(),
        ));
    }
    if (staged.model == "conservative-v1") != staged.vertex_event_id.is_none() {
        return Err(EnclaveError::Store(
            "memory reconciliation staged model provenance is invalid".into(),
        ));
    }
    let model: ModelPartition = serde_json::from_value(staged.normalized_partition.clone())?;
    let partition = validate_partition(snapshot, model)?;
    if partition.result_commitment != staged.result_commitment {
        return Err(EnclaveError::Store(
            "memory reconciliation staged commitment mismatch".into(),
        ));
    }
    let expected_outputs = publication_outputs(partition.clone(), &staged.model)?;
    if expected_outputs != staged.planned_outputs
        || reconciliation_outputs_commitment(&expected_outputs)?
            != staged.planned_outputs_commitment
    {
        return Err(EnclaveError::Store(
            "memory reconciliation staged mutation product mismatch".into(),
        ));
    }
    Ok(partition)
}

fn stage_contract_is_current(staged: &StagedReconciliation) -> bool {
    producer_contract_is_current(
        staged.reconciliation_version,
        staged.prompt_version,
        staged.partition_schema_version,
        staged.validator_version,
    )
}

fn stage_model_is_current(staged_model: &str, configured_model: &str, model_attempts: i64) -> bool {
    staged_model == configured_model
        || (staged_model == "conservative-v1"
            && model_attempts >= MODEL_ATTEMPTS_BEFORE_CONSERVATIVE_KEEP)
}

fn producer_contract_is_current(
    reconciliation_version: i64,
    prompt_version: i64,
    partition_schema_version: i64,
    validator_version: i64,
) -> bool {
    reconciliation_version == RECONCILIATION_VERSION
        && prompt_version == PROMPT_VERSION
        && partition_schema_version == PARTITION_SCHEMA_VERSION
        && validator_version == VALIDATOR_VERSION
}

fn publication_outputs(
    partition: ValidatedPartition,
    model: &str,
) -> Result<Vec<ReconciledMemoryWrite>> {
    partition
        .outputs
        .into_iter()
        .enumerate()
        .map(|(ordinal, output)| {
            Ok(ReconciledMemoryWrite {
                output_ordinal: i64::try_from(ordinal).map_err(|_| {
                    EnclaveError::Config("memory reconciliation output ordinal overflow".into())
                })?,
                retained_episode_id: output.retained_episode_id,
                predecessor_episode_ids: output.predecessor_episode_ids,
                started_at: output.started_at,
                ended_at: output.ended_at,
                episode_type: Some(output.episode_type),
                title: output.title,
                summary: Some(output.summary),
                participants: output.participants,
                languages: output.languages,
                action_items: output.action_items,
                model: Some(model.to_string()),
                minute_summaries: output.minute_summaries,
                minutes_text: Some(output.minutes_text),
                substance: output.substance,
                visual_evidence: output.visual_evidence,
                member_source_ids: output.member_source_ids,
            })
        })
        .collect()
}

async fn publish_staged(
    state: &CpState,
    snapshot: &ReconciliationSnapshot,
    claim: ReconciliationClaim,
    staged: StagedReconciliation,
) -> Result<Vec<i64>> {
    validate_stage(snapshot, &staged)?;
    let reconciliation_id = reconciliation_id(snapshot, &staged.result_commitment);
    let result = state
        .repositories
        .memory_reconciliation()
        .publish_reconciliation(ReconciliationPublish {
            claim,
            reconciliation_id,
            cohort_started_at: snapshot.cohort_started_at.clone(),
            cohort_ended_at: snapshot.cohort_ended_at.clone(),
            result_commitment: staged.result_commitment,
        })
        .await?;
    Ok(match result {
        ReconciliationPublishResult::Published {
            successor_episode_ids,
            ..
        }
        | ReconciliationPublishResult::Replayed {
            successor_episode_ids,
            ..
        } => successor_episode_ids,
    })
}

/// Reconcile at most one oldest, source-settled cohort for an account.
///
/// `Ok(true)` means finalization may continue because the writer is dark or no
/// eligible cohort exists. `Ok(false)` means PostgreSQL reports in-flight,
/// retrying, or newly published work; enrichment waits for a later sweep so it
/// can never skip a second eligible cohort. No process-local lock participates
/// in correctness.
pub async fn reconcile_user_episodes(state: &CpState, account_id: &str) -> Result<bool> {
    if !state.config.memory_reconciliation_writer_enabled {
        return Ok(finalization_may_continue(false, false));
    }
    let repository = state.repositories.memory_reconciliation();
    let quiet_before = isotime::format_epoch_millis(now_ms().saturating_sub(QUIET_HORIZON_MS));
    let Some(snapshot) = repository
        .next_source_settled_cohort(
            account_id,
            &quiet_before,
            MAX_COHORT_DRAFTS,
            MAX_COHORT_ATOMS,
        )
        .await?
    else {
        return Ok(finalization_may_continue(true, false));
    };
    if snapshot.account_id != account_id
        || snapshot.predecessor_episode_ids.is_empty()
        || snapshot.drafts.len() > MAX_COHORT_DRAFTS as usize
        || snapshot.atoms.len() > MAX_COHORT_ATOMS as usize
    {
        return Err(EnclaveError::Store(
            "memory reconciliation repository returned an invalid cohort".into(),
        ));
    }
    let claimed_at = isotime::format_epoch_millis(now_ms());
    let Some(claim) = repository
        .claim_reconciliation(&snapshot, &claimed_at, CLAIM_LEASE_SECONDS)
        .await?
    else {
        return Ok(false);
    };

    if let Some(staged) = repository
        .staged_result(account_id, &snapshot.source_fingerprint)
        .await?
    {
        if staged.account_id != snapshot.account_id
            || staged.source_fingerprint != snapshot.source_fingerprint
            || staged.predecessor_episode_ids != snapshot.predecessor_episode_ids
        {
            return Err(EnclaveError::Store(
                "memory reconciliation staged identity mismatch".into(),
            ));
        }
        if stage_contract_is_current(&staged)
            && stage_model_is_current(
                &staged.model,
                &state.config.vertex_reconciliation_model,
                claim.model_attempt_count,
            )
        {
            let successor_ids = publish_staged(state, &snapshot, claim, staged).await?;
            super::summarizer::embed_episodes(state, account_id, &successor_ids).await;
            info!(
                account_id,
                outputs = successor_ids.len(),
                "memory cohort reconciled from durable stage"
            );
            return Ok(finalization_may_continue(true, true));
        }
        info!(
            account_id,
            staged_reconciliation_version = staged.reconciliation_version,
            staged_prompt_version = staged.prompt_version,
            staged_partition_schema_version = staged.partition_schema_version,
            staged_validator_version = staged.validator_version,
            staged_model = staged.model,
            configured_model = state.config.vertex_reconciliation_model,
            model_attempts = claim.model_attempt_count,
            "memory reconciliation stage uses an obsolete producer or model contract"
        );
    }

    let (partition, selected_model, vertex_event_id) = if claim.model_attempt_count
        >= MODEL_ATTEMPTS_BEFORE_CONSERVATIVE_KEEP
    {
        (
            validate_partition(&snapshot, conservative_partition(&snapshot)?)?,
            "conservative-v1".to_string(),
            None,
        )
    } else {
        let current = repository
            .revalidate_source_fingerprint(
                account_id,
                &snapshot.predecessor_episode_ids,
                &snapshot.source_fingerprint,
            )
            .await?;
        if !current {
            release_for_retry(state, &claim, "source_changed_before_egress", false).await?;
            return Ok(false);
        }
        let input = match render_model_input(&snapshot) {
            Ok(input) => input,
            Err(error) => {
                release_for_retry(state, &claim, "input_encoding_failed", false).await?;
                warn!(account_id, error = %error, "memory reconciliation input refused");
                return Ok(false);
            }
        };
        if let Err(error) = reserve_output(state, account_id).await {
            release_for_retry(state, &claim, "quota_unavailable", false).await?;
            warn!(account_id, error = %error, "memory reconciliation quota unavailable");
            return Ok(false);
        }
        let current = repository
            .revalidate_source_fingerprint(
                account_id,
                &snapshot.predecessor_episode_ids,
                &snapshot.source_fingerprint,
            )
            .await?;
        if !current {
            release_for_retry(state, &claim, "source_changed_before_egress", false).await?;
            return Ok(false);
        }
        let selected_model = state.config.vertex_reconciliation_model.clone();
        info!(
            account_id,
            requested_model = state
                .config
                .vertex_reconciliation_model_requested
                .as_deref()
                .unwrap_or(&state.config.vertex_model),
            resolved_model = selected_model,
            explicitly_requested = state.config.vertex_reconciliation_model_requested.is_some(),
            "memory reconciliation model selected"
        );
        let generation = match vertex::generate_custom_with_model(
            state,
            account_id,
            vertex::CustomTextGenerationRequest {
                operation: vertex::VertexOperation::EpisodeReconciliation,
                system: SYSTEM_PROMPT,
                user_message: &input,
                schema: response_schema(),
                max_output_tokens: RECONCILIATION_OUTPUT_TOKENS,
                model: &selected_model,
            },
        )
        .await
        {
            Ok(generation) => generation,
            Err(error) => {
                release_for_retry(state, &claim, "provider_unavailable", true).await?;
                warn!(account_id, error = %error, "memory reconciliation model unavailable");
                return Ok(false);
            }
        };
        let model: ModelPartition = match serde_json::from_str(&generation.text) {
            Ok(model) => model,
            Err(error) => {
                release_for_retry(state, &claim, "invalid_json", true).await?;
                warn!(account_id, error = %error, "memory reconciliation response was not JSON");
                return Ok(false);
            }
        };
        let partition = match validate_partition(&snapshot, model) {
            Ok(partition) => partition,
            Err(error) => {
                release_for_retry(state, &claim, "invalid_partition", true).await?;
                warn!(account_id, error = %error, "memory reconciliation partition refused");
                return Ok(false);
            }
        };
        (partition, selected_model, Some(generation.event_id))
    };

    let planned_outputs = publication_outputs(partition.clone(), &selected_model)?;
    let staged = repository
        .stage_reconciliation(
            &claim,
            ReconciliationStageWrite {
                normalized_partition: serde_json::to_value(&partition.model)?,
                result_commitment: partition.result_commitment.clone(),
                planned_outputs,
                model: selected_model,
                vertex_event_id,
                reconciliation_version: RECONCILIATION_VERSION,
                prompt_version: PROMPT_VERSION,
                partition_schema_version: PARTITION_SCHEMA_VERSION,
                validator_version: VALIDATOR_VERSION,
            },
        )
        .await?;
    let successor_ids = publish_staged(state, &snapshot, claim, staged).await?;
    super::summarizer::embed_episodes(state, account_id, &successor_ids).await;
    info!(
        account_id,
        outputs = successor_ids.len(),
        "memory cohort reconciled"
    );
    Ok(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn atom(id: i64, started_ms: i64) -> ReconciliationEvidenceAtom {
        ReconciliationEvidenceAtom {
            source_id: format!("utterance:{id}"),
            record_type: "utterance".into(),
            record_id: id,
            started_at: isotime::format_epoch_millis(started_ms),
            ended_at: isotime::format_epoch_millis(started_ms + 1_000),
            context: format!("utterance {id}"),
        }
    }

    fn draft(id: i64, sources: &[&str]) -> ReconciliationDraft {
        ReconciliationDraft {
            id,
            started_at: "2026-08-30T12:00:00.000Z".into(),
            ended_at: "2026-08-30T12:30:00.000Z".into(),
            episode_type: Some("other".into()),
            title: format!("Draft {id}"),
            summary: Some(format!("Summary {id}")),
            participants: Vec::new(),
            languages: Vec::new(),
            action_items: Vec::new(),
            model: None,
            minute_summaries: Value::Array(Vec::new()),
            minutes_text: Some(String::new()),
            substance: "normal".into(),
            visual_evidence: "none".into(),
            updated_at: None,
            identity_revision: 0,
            member_source_ids: sources.iter().map(|value| (*value).into()).collect(),
        }
    }

    fn snapshot(
        drafts: Vec<ReconciliationDraft>,
        atoms: Vec<ReconciliationEvidenceAtom>,
    ) -> ReconciliationSnapshot {
        ReconciliationSnapshot {
            account_id: "account".into(),
            cohort_started_at: "2026-08-30T12:00:00.000Z".into(),
            cohort_ended_at: "2026-08-30T13:00:00.000Z".into(),
            predecessor_episode_ids: drafts.iter().map(|draft| draft.id).collect(),
            drafts,
            atoms,
            source_fingerprint: vec![6; 32],
            topology_fingerprint: vec![7; 32],
            archive_revision: 0,
        }
    }

    fn memory(sources: &[&str], title: &str) -> ModelMemory {
        ModelMemory {
            source_ids: sources.iter().map(|value| (*value).into()).collect(),
            episode_type: "other".into(),
            title: title.into(),
            summary: format!("{title} summary"),
            participants: Vec::new(),
            languages: Vec::new(),
            action_items: Vec::new(),
            timeline: Vec::new(),
        }
    }

    #[test]
    fn exact_one_to_one_assignment_retains_the_existing_id() {
        let source = snapshot(
            vec![draft(10, &["utterance:1", "utterance:2"])],
            vec![atom(1, 1), atom(2, 2)],
        );
        let result = validate_partition(
            &source,
            ModelPartition {
                memories: vec![memory(&["utterance:1", "utterance:2"], "Same")],
            },
        )
        .unwrap();
        assert_eq!(result.outputs[0].retained_episode_id, Some(10));
    }

    #[test]
    fn merge_split_and_repartition_never_retain_an_ambiguous_id() {
        let source = snapshot(
            vec![
                draft(10, &["utterance:1", "utterance:2"]),
                draft(11, &["utterance:3"]),
            ],
            vec![atom(1, 1), atom(2, 2), atom(3, 3)],
        );
        let merged = validate_partition(
            &source,
            ModelPartition {
                memories: vec![memory(
                    &["utterance:1", "utterance:2", "utterance:3"],
                    "Merged",
                )],
            },
        )
        .unwrap();
        assert!(merged.outputs[0].retained_episode_id.is_none());

        let repartitioned = validate_partition(
            &source,
            ModelPartition {
                memories: vec![
                    memory(&["utterance:1", "utterance:3"], "A"),
                    memory(&["utterance:2"], "B"),
                ],
            },
        )
        .unwrap();
        assert!(repartitioned
            .outputs
            .iter()
            .all(|output| output.retained_episode_id.is_none()));
    }

    #[test]
    fn partition_must_be_exhaustive_unique_and_grounded() {
        let source = snapshot(
            vec![draft(10, &["utterance:1", "utterance:2"])],
            vec![atom(1, 1), atom(2, 2)],
        );
        for invalid in [
            ModelPartition {
                memories: vec![memory(&["utterance:1"], "Missing")],
            },
            ModelPartition {
                memories: vec![
                    memory(&["utterance:1"], "Duplicate A"),
                    memory(&["utterance:1", "utterance:2"], "Duplicate B"),
                ],
            },
            ModelPartition {
                memories: vec![memory(&["utterance:1", "utterance:9"], "Unknown")],
            },
        ] {
            assert!(validate_partition(&source, invalid).is_err());
        }
    }

    #[test]
    fn snapshot_predecessors_and_active_ownership_must_be_exact() {
        let source = snapshot(
            vec![draft(10, &["utterance:1"]), draft(11, &["utterance:1"])],
            vec![atom(1, 1)],
        );
        assert!(validate_partition(
            &source,
            ModelPartition {
                memories: vec![memory(&["utterance:1"], "Duplicate owner")],
            }
        )
        .is_err());

        let mut source = snapshot(vec![draft(10, &["utterance:1"])], vec![atom(1, 1)]);
        source.predecessor_episode_ids = vec![99];
        assert!(validate_partition(
            &source,
            ModelPartition {
                memories: vec![memory(&["utterance:1"], "Wrong predecessor")],
            }
        )
        .is_err());
    }

    #[test]
    fn conservative_fallback_retains_one_to_one_id_when_adding_late_evidence() {
        let source = snapshot(
            vec![draft(10, &["utterance:1"])],
            vec![atom(1, 1), atom(2, 2)],
        );
        let fallback = conservative_partition(&source).unwrap();
        let result = validate_partition(&source, fallback).unwrap();
        assert_eq!(result.outputs.len(), 1);
        assert_eq!(
            result.outputs[0].member_source_ids,
            vec!["utterance:1", "utterance:2"]
        );
        assert_eq!(result.outputs[0].retained_episode_id, Some(10));
    }

    #[test]
    fn evidence_uses_interval_end_not_only_atom_start() {
        let mut evidence = atom(1, 1_000);
        evidence.ended_at = isotime::format_epoch_millis(9_000);
        let source = snapshot(vec![draft(10, &["utterance:1"])], vec![evidence]);
        let result = validate_partition(
            &source,
            ModelPartition {
                memories: vec![memory(&["utterance:1"], "Interval")],
            },
        )
        .unwrap();
        assert_eq!(
            result.outputs[0].ended_at,
            isotime::format_epoch_millis(9_000)
        );
    }

    #[test]
    fn zero_duration_screen_memory_gets_a_minimal_valid_interval() {
        let instant = isotime::format_epoch_millis(5_000);
        let evidence = ReconciliationEvidenceAtom {
            source_id: "screenshot:1".into(),
            record_type: "screenshot".into(),
            record_id: 1,
            started_at: instant.clone(),
            ended_at: instant,
            context: "screen evidence".into(),
        };
        let source = snapshot(vec![draft(10, &["screenshot:1"])], vec![evidence]);
        let result = validate_partition(
            &source,
            ModelPartition {
                memories: vec![memory(&["screenshot:1"], "Screen")],
            },
        )
        .unwrap();
        assert_eq!(
            result.outputs[0].started_at,
            isotime::format_epoch_millis(5_000)
        );
        assert_eq!(
            result.outputs[0].ended_at,
            isotime::format_epoch_millis(5_001)
        );
    }

    #[test]
    fn reconciliation_preserves_the_strongest_existing_substance_class() {
        for (classes, expected) in [
            (vec!["none", "none"], "none"),
            (vec!["none", "low"], "low"),
            (vec!["low", "normal"], "normal"),
        ] {
            let mut drafts = vec![draft(10, &["utterance:1"]), draft(11, &["utterance:2"])];
            drafts[0].substance = classes[0].into();
            drafts[1].substance = classes[1].into();
            let source = snapshot(drafts, vec![atom(1, 1), atom(2, 2)]);
            let result = validate_partition(
                &source,
                ModelPartition {
                    memories: vec![memory(&["utterance:1", "utterance:2"], "Merged")],
                },
            )
            .unwrap();
            assert_eq!(result.outputs[0].substance, expected);
        }
    }

    #[test]
    fn finalization_waits_for_every_enabled_cohort_including_new_publication() {
        assert!(finalization_may_continue(false, true));
        assert!(finalization_may_continue(true, false));
        assert!(!finalization_may_continue(true, true));
    }

    #[test]
    fn reconciliation_has_a_distinct_vertex_usage_operation() {
        assert_eq!(
            vertex::VertexOperation::EpisodeReconciliation.as_str(),
            "episode_reconciliation"
        );
    }

    #[test]
    fn obsolete_staged_producer_contract_requires_fresh_inference() {
        assert!(producer_contract_is_current(
            RECONCILIATION_VERSION,
            PROMPT_VERSION,
            PARTITION_SCHEMA_VERSION,
            VALIDATOR_VERSION,
        ));
        assert!(!producer_contract_is_current(
            RECONCILIATION_VERSION,
            PROMPT_VERSION,
            PARTITION_SCHEMA_VERSION,
            VALIDATOR_VERSION + 1,
        ));
        assert!(!producer_contract_is_current(
            RECONCILIATION_VERSION + 1,
            PROMPT_VERSION,
            PARTITION_SCHEMA_VERSION,
            VALIDATOR_VERSION,
        ));
    }

    #[test]
    fn staged_model_must_match_current_policy_or_exact_fallback_threshold() {
        assert!(stage_model_is_current("gemini-strong", "gemini-strong", 0));
        assert!(!stage_model_is_current("gemini-old", "gemini-strong", 9));
        assert!(!stage_model_is_current(
            "conservative-v1",
            "gemini-strong",
            MODEL_ATTEMPTS_BEFORE_CONSERVATIVE_KEEP - 1,
        ));
        assert!(stage_model_is_current(
            "conservative-v1",
            "gemini-strong",
            MODEL_ATTEMPTS_BEFORE_CONSERVATIVE_KEEP,
        ));
    }
}
