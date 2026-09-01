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
    oversized_keep_policy_commitment, reconciliation_outputs_commitment,
    reconciliation_provider_attempt_identity, vertex_invocation_fingerprint,
    OversizedKeepPromotionPolicy, OversizedKeepPromotionResult, ReconciledMemoryWrite,
    ReconciliationClaim, ReconciliationDraft, ReconciliationEgressGuard,
    ReconciliationEvidenceAtom, ReconciliationPublish, ReconciliationPublishResult,
    ReconciliationSnapshot, ReconciliationStageWrite, StagedReconciliation,
};

use super::{isotime, vertex, CpState};

// v2 adds durable provider-attempt fencing and terminal conservative handling
// for ambiguous responses. A v1 stage must never cross that policy boundary.
const RECONCILIATION_VERSION: i64 = 2;
const PROMPT_VERSION: i64 = 1;
const PARTITION_SCHEMA_VERSION: i64 = 1;
const VALIDATOR_VERSION: i64 = 1;
const QUIET_HORIZON_SECONDS: i64 = 4 * 60 * 60;
pub(crate) const MAX_COHORT_DRAFTS: i64 = 32;
const MAX_COHORT_ATOMS: i64 = 4_000;
// A single reconciliation may never create more active leaves than the
// memory-handle resolver can traverse. Keep this tied to the 32-predecessor
// topology/storage bound instead of maintaining an independent fanout value.
pub(crate) const MAX_OUTPUTS: usize = MAX_COHORT_DRAFTS as usize;
const MAX_TITLE_CHARS: usize = 180;
const MAX_SUMMARY_CHARS: usize = 4_000;
const MAX_GIST_CHARS: usize = 800;
const MAX_CONTEXT_CHARS: usize = 1_200;
const MAX_CONTEXT_TOTAL_CHARS: usize = 256 * 1_024;
const MAX_MODEL_INPUT_BYTES: usize = 1_024 * 1_024;
pub(crate) const RECONCILIATION_OUTPUT_TOKENS: u32 = 8_192;
const CLAIM_LEASE_SECONDS: i64 = 5 * 60;
const MODEL_ATTEMPTS_BEFORE_CONSERVATIVE_KEEP: i64 = 3;
const CONSERVATIVE_MODEL: &str = "conservative-v1";
const CONSERVATIVE_AMBIGUITY_MODEL: &str = "conservative-ambiguity-v1";

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

/// Commitment signed by the activation authority before the topology writer
/// may become active. The model and location are deployment inputs; every
/// other field is compiled policy. Any prompt, schema, validator, bounded
/// rendering, or Vertex request-setting change therefore requires an explicit
/// new activation receipt rather than silently changing the live producer.
pub(crate) fn producer_contract_commitment(model: &str, location: &str) -> Result<[u8; 32]> {
    if model.is_empty()
        || model.trim() != model
        || model.chars().count() > 256
        || location.is_empty()
        || location.trim() != location
        || location.chars().count() > 128
    {
        return Err(EnclaveError::Config(
            "memory reconciliation producer model/location is invalid".into(),
        ));
    }
    let contract = json!({
        "contract": "kioku.memory-reconciliation.vertex-producer",
        "contract_version": 1,
        "model": model,
        "location": location,
        "vertex": {
            "api_version": vertex::GENERATE_CONTENT_API_VERSION,
            "publisher": vertex::GENERATE_CONTENT_PUBLISHER,
            "method": vertex::GENERATE_CONTENT_METHOD,
            "operation": vertex::VertexOperation::EpisodeReconciliation.as_str(),
            "generation_config": {
                "maxOutputTokens": RECONCILIATION_OUTPUT_TOKENS,
                "responseMimeType": vertex::JSON_RESPONSE_MIME_TYPE,
                "thinkingConfig": {"thinkingBudget": vertex::THINKING_BUDGET},
            },
        },
        "versions": {
            "reconciliation": RECONCILIATION_VERSION,
            "prompt": PROMPT_VERSION,
            "partition_schema": PARTITION_SCHEMA_VERSION,
            "validator": VALIDATOR_VERSION,
        },
        "system_prompt": SYSTEM_PROMPT,
        "response_schema": response_schema(),
        "bounds": {
            "cohort_drafts": MAX_COHORT_DRAFTS,
            "cohort_atoms": MAX_COHORT_ATOMS,
            "outputs": MAX_OUTPUTS,
            "title_chars": MAX_TITLE_CHARS,
            "summary_chars": MAX_SUMMARY_CHARS,
            "gist_chars": MAX_GIST_CHARS,
            "context_chars": MAX_CONTEXT_CHARS,
            "context_total_chars": MAX_CONTEXT_TOTAL_CHARS,
            "model_input_bytes": MAX_MODEL_INPUT_BYTES,
        },
        "fallback": {
            "confirmed_attempts_before_conservative_keep": MODEL_ATTEMPTS_BEFORE_CONSERVATIVE_KEEP,
            "no_provider_model": CONSERVATIVE_MODEL,
            "ambiguous_provider_model": CONSERVATIVE_AMBIGUITY_MODEL,
            "ambiguous_provider_resend": false,
            "oversized_keep_policy_commitment": oversized_keep_policy_commitment(),
        },
        "request_body_commitment": "sha256-serde-json-value-v1",
        "provider_attempt_identity": "source-fingerprint-activation-generation-producer-contract-model-attempt-v2",
    });
    let encoded = serde_json::to_vec(&contract)?;
    let mut digest = Sha256::new();
    digest.update(b"kioku.memory-reconciliation.producer-contract.v1\0");
    digest.update(encoded);
    Ok(digest.finalize().into())
}

pub(crate) fn producer_contract_sha256_label(model: &str, location: &str) -> Result<String> {
    let digest = producer_contract_commitment(model, location)?;
    let mut encoded = String::with_capacity("sha256:".len() + digest.len() * 2);
    encoded.push_str("sha256:");
    for byte in digest {
        use std::fmt::Write as _;
        write!(&mut encoded, "{byte:02x}")
            .map_err(|_| EnclaveError::Store("producer contract digest encoding failed".into()))?;
    }
    Ok(encoded)
}

fn claim_producer_matches_process(
    claim: &ReconciliationClaim,
    configured_model: &str,
    configured_location: &str,
) -> Result<bool> {
    Ok(claim.reconciliation_model == configured_model
        && claim.vertex_location == configured_location
        && claim.producer_contract_sha256
            == producer_contract_commitment(configured_model, configured_location)?.as_slice())
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

#[cfg(test)]
pub(crate) fn test_reconciliation_provider_commitments(
    snapshot: &ReconciliationSnapshot,
    claim: &ReconciliationClaim,
) -> Result<([u8; 32], [u8; 32], [u8; 32])> {
    let input = render_model_input(snapshot)?;
    let request = vertex::CustomTextGenerationRequest {
        operation: vertex::VertexOperation::EpisodeReconciliation,
        system: SYSTEM_PROMPT,
        user_message: &input,
        schema: response_schema(),
        max_output_tokens: RECONCILIATION_OUTPUT_TOKENS,
        model: &claim.reconciliation_model,
    };
    let caller_anchor = vertex::custom_text_request_caller_anchor(&request)?;
    let attempt_identity = reconciliation_provider_attempt_identity(
        &snapshot.source_fingerprint,
        claim.activation_generation,
        &claim.producer_contract_sha256,
        claim.model_attempt_count,
    )?;
    let invocation_fingerprint = vertex_invocation_fingerprint(
        &claim.account_id,
        vertex::VertexOperation::EpisodeReconciliation,
        &claim.reconciliation_model,
        &claim.vertex_location,
        &caller_anchor,
    );
    Ok((attempt_identity, caller_anchor, invocation_fingerprint))
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ProviderFailureAction {
    RetrySameAttempt,
    RetryWithNewAttempt,
    ConservativeKeep,
}

fn provider_failure_action(
    disposition: vertex::VertexGenerationFailureDisposition,
) -> ProviderFailureAction {
    match disposition {
        vertex::VertexGenerationFailureDisposition::RetryableBeforeEgress => {
            ProviderFailureAction::RetrySameAttempt
        }
        vertex::VertexGenerationFailureDisposition::RetryableNotBilled
        | vertex::VertexGenerationFailureDisposition::ConfirmedInvalid => {
            ProviderFailureAction::RetryWithNewAttempt
        }
        vertex::VertexGenerationFailureDisposition::AmbiguousTerminal => {
            ProviderFailureAction::ConservativeKeep
        }
    }
}

fn stage_model_provenance_is_valid(model: &str, vertex_event_id: Option<&str>) -> bool {
    match model {
        CONSERVATIVE_MODEL => vertex_event_id.is_none(),
        CONSERVATIVE_AMBIGUITY_MODEL => vertex_event_id.is_some(),
        _ => vertex_event_id.is_some(),
    }
}

fn retry_delay_seconds(claim_attempt_count: i64) -> i64 {
    if claim_attempt_count <= 1 {
        10 * 60
    } else {
        60 * 60
    }
}

fn inactive_phase_allows_legacy_finalization(
    phase: crate::persistence::MemoryReconciliationActivationPhase,
) -> Option<bool> {
    use crate::persistence::MemoryReconciliationActivationPhase;

    match phase {
        MemoryReconciliationActivationPhase::Preactive
        | MemoryReconciliationActivationPhase::Installed => Some(true),
        MemoryReconciliationActivationPhase::Draining
        | MemoryReconciliationActivationPhase::Paused => Some(false),
        MemoryReconciliationActivationPhase::Active => None,
    }
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
    state
        .repositories
        .memory_reconciliation()
        .release_reconciliation(
            claim,
            Some(retry_delay_seconds(claim.attempt_count)),
            error_code,
            false,
            consume_model_attempt,
        )
        .await
}

async fn abort_provider_egress_guard(
    guard: &mut Option<Box<dyn ReconciliationEgressGuard>>,
) -> Result<()> {
    if let Some(guard) = guard.take() {
        guard.abort().await?;
    }
    Ok(())
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
    if !stage_model_provenance_is_valid(&staged.model, staged.vertex_event_id.as_deref()) {
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
        || staged_model == CONSERVATIVE_AMBIGUITY_MODEL
        || (staged_model == CONSERVATIVE_MODEL
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
/// `Ok(true)` means the durable activation authority still permits legacy
/// finalization (`Preactive`/`Installed`), or an active account has no eligible
/// cohort. `Ok(false)` means PostgreSQL is draining/paused or reports in-flight,
/// retrying, or newly published work; enrichment waits for a later sweep so it
/// can never skip a second eligible cohort. No process-local switch
/// participates in correctness.
pub async fn reconcile_user_episodes(state: &CpState, account_id: &str) -> Result<bool> {
    let phase = state
        .repositories
        .memory_reconciliation_activation()
        .memory_reconciliation_activation_status()
        .await?
        .phase;
    if let Some(may_finalize) = inactive_phase_allows_legacy_finalization(phase) {
        return Ok(may_finalize);
    }
    let repository = state.repositories.memory_reconciliation();
    // A complete held component (for example, one above the providerless
    // source ceiling) must not head-of-line block disconnected work. Search a
    // bounded number of later components in the same sweep; the held drafts
    // remain `draft` and therefore stay fenced from finalization.
    let mut resume_after_component_ended_at = None;
    for _ in 0..8 {
        match repository
            .promote_oversized_source_settled_prefix(
                account_id,
                QUIET_HORIZON_SECONDS,
                resume_after_component_ended_at.as_deref(),
                OversizedKeepPromotionPolicy {
                    draft_limit: MAX_COHORT_DRAFTS,
                    atom_limit: MAX_COHORT_ATOMS,
                    reconciliation_version: RECONCILIATION_VERSION,
                    prompt_version: PROMPT_VERSION,
                    partition_schema_version: PARTITION_SCHEMA_VERSION,
                    validator_version: VALIDATOR_VERSION,
                },
            )
            .await?
        {
            OversizedKeepPromotionResult::NotOversized => break,
            OversizedKeepPromotionResult::Held {
                resume_after_component_ended_at: Some(boundary),
            } => resume_after_component_ended_at = Some(boundary),
            OversizedKeepPromotionResult::Held {
                resume_after_component_ended_at: None,
            } => return Ok(false),
            OversizedKeepPromotionResult::Promoted {
                episode_ids,
                reconciliation_id,
                archive_revision,
            } => {
                info!(
                    account_id,
                    reconciliation_id,
                    archive_revision,
                    episodes = episode_ids.len(),
                    "oversized memory cohort conservatively promoted without provider egress"
                );
                return Ok(false);
            }
        }
    }
    let Some(snapshot) = repository
        .next_source_settled_cohort(
            account_id,
            QUIET_HORIZON_SECONDS,
            resume_after_component_ended_at.as_deref(),
            MAX_COHORT_DRAFTS,
            MAX_COHORT_ATOMS,
        )
        .await?
    else {
        return Ok(true);
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
    let Some(claim) = repository
        .claim_reconciliation(&snapshot, CLAIM_LEASE_SECONDS)
        .await?
    else {
        return Ok(false);
    };
    if !claim_producer_matches_process(
        &claim,
        &state.config.vertex_reconciliation_model,
        &state.config.vertex_location,
    )? {
        release_for_retry(state, &claim, "producer_authority_mismatch", false).await?;
        warn!(
            account_id,
            "memory reconciliation producer authority does not match this process"
        );
        return Ok(false);
    }

    if let Some(staged) = repository.staged_result(&claim).await? {
        if staged.account_id != snapshot.account_id
            || staged.source_fingerprint != snapshot.source_fingerprint
            || staged.predecessor_episode_ids != snapshot.predecessor_episode_ids
            || staged.activation_generation != claim.activation_generation
            || staged.producer_contract_sha256 != claim.producer_contract_sha256
            || staged.reconciliation_model != claim.reconciliation_model
            || staged.vertex_location != claim.vertex_location
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
            return Ok(false);
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

    let mut provider_egress_guard: Option<Box<dyn ReconciliationEgressGuard>> = None;
    let (
        partition,
        selected_model,
        vertex_event_id,
        provider_attempt_identity,
        provider_invocation_fingerprint,
    ) = if claim.model_attempt_count >= MODEL_ATTEMPTS_BEFORE_CONSERVATIVE_KEEP {
        (
            validate_partition(&snapshot, conservative_partition(&snapshot)?)?,
            CONSERVATIVE_MODEL.to_string(),
            None,
            None,
            None,
        )
    } else {
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
        let attempt_identity = reconciliation_provider_attempt_identity(
            &snapshot.source_fingerprint,
            claim.activation_generation,
            &claim.producer_contract_sha256,
            claim.model_attempt_count,
        )?;
        let provider_request = vertex::CustomTextGenerationRequest {
            operation: vertex::VertexOperation::EpisodeReconciliation,
            system: SYSTEM_PROMPT,
            user_message: &input,
            schema: response_schema(),
            max_output_tokens: RECONCILIATION_OUTPUT_TOKENS,
            model: &selected_model,
        };
        let caller_anchor = vertex::custom_text_request_caller_anchor(&provider_request)?;
        let invocation_fingerprint = vertex_invocation_fingerprint(
            account_id,
            vertex::VertexOperation::EpisodeReconciliation,
            &selected_model,
            &claim.vertex_location,
            &caller_anchor,
        );
        // Build and durably admit the exact request before taking the topology
        // guard. This avoids acquiring account-lifecycle behind the account
        // reconciliation lock. No provider-visible action occurs yet.
        let prepared = vertex::prepare_custom_with_model_attempt(
            state,
            account_id,
            provider_request,
            &attempt_identity,
        )
        .await;
        let generation = match prepared {
            Ok(prepared) => {
                // The guard is the final database-authoritative source and
                // activation revalidation before provider egress. It remains
                // open through usage settlement and durable stage persistence.
                let egress_guard = match repository.acquire_provider_egress_guard(&claim).await {
                    Ok(Some(guard)) => guard,
                    Ok(None) => {
                        prepared.reject_before_egress(state, account_id).await?;
                        release_for_retry(state, &claim, "source_changed_before_egress", true)
                            .await?;
                        return Ok(false);
                    }
                    Err(error) => {
                        prepared.reject_before_egress(state, account_id).await?;
                        return Err(error);
                    }
                };
                provider_egress_guard = Some(egress_guard);
                prepared.send(state, account_id).await
            }
            Err(error) => Err(error),
        };
        match generation {
            Ok(generation) => {
                let model: ModelPartition = match serde_json::from_str(&generation.text) {
                    Ok(model) => model,
                    Err(error) => {
                        abort_provider_egress_guard(&mut provider_egress_guard).await?;
                        release_for_retry(state, &claim, "invalid_json", true).await?;
                        warn!(account_id, error = %error, "memory reconciliation response was not JSON");
                        return Ok(false);
                    }
                };
                let partition = match validate_partition(&snapshot, model) {
                    Ok(partition) => partition,
                    Err(error) => {
                        abort_provider_egress_guard(&mut provider_egress_guard).await?;
                        release_for_retry(state, &claim, "invalid_partition", true).await?;
                        warn!(account_id, error = %error, "memory reconciliation partition refused");
                        return Ok(false);
                    }
                };
                (
                    partition,
                    selected_model,
                    Some(generation.event_id),
                    Some(attempt_identity.to_vec()),
                    Some(invocation_fingerprint.to_vec()),
                )
            }
            Err(error) => match provider_failure_action(error.disposition) {
                ProviderFailureAction::RetrySameAttempt => {
                    abort_provider_egress_guard(&mut provider_egress_guard).await?;
                    release_for_retry(state, &claim, "provider_preflight", false).await?;
                    warn!(account_id, error = %error, "memory reconciliation provider preflight unavailable");
                    return Ok(false);
                }
                ProviderFailureAction::RetryWithNewAttempt => {
                    let error_code = match error.disposition {
                        vertex::VertexGenerationFailureDisposition::RetryableNotBilled => {
                            "provider_not_billed"
                        }
                        vertex::VertexGenerationFailureDisposition::ConfirmedInvalid => {
                            "provider_invalid_response"
                        }
                        _ => unreachable!("provider failure action checked above"),
                    };
                    abort_provider_egress_guard(&mut provider_egress_guard).await?;
                    release_for_retry(state, &claim, error_code, true).await?;
                    warn!(account_id, error = %error, "memory reconciliation provider attempt refused");
                    return Ok(false);
                }
                ProviderFailureAction::ConservativeKeep => {
                    let event_id = error.event_id.clone().ok_or_else(|| {
                        EnclaveError::Store(
                            "ambiguous reconciliation provider attempt has no event id".into(),
                        )
                    })?;
                    warn!(
                        account_id,
                        vertex_event_id = event_id,
                        error = %error,
                        "ambiguous memory reconciliation response will not be resent"
                    );
                    (
                        validate_partition(&snapshot, conservative_partition(&snapshot)?)?,
                        CONSERVATIVE_AMBIGUITY_MODEL.to_string(),
                        Some(event_id),
                        Some(attempt_identity.to_vec()),
                        Some(invocation_fingerprint.to_vec()),
                    )
                }
            },
        }
    };

    let planned_outputs = publication_outputs(partition.clone(), &selected_model)?;
    let stage = ReconciliationStageWrite {
        normalized_partition: serde_json::to_value(&partition.model)?,
        result_commitment: partition.result_commitment.clone(),
        planned_outputs,
        model: selected_model,
        vertex_event_id,
        provider_attempt_identity,
        provider_invocation_fingerprint,
        reconciliation_version: RECONCILIATION_VERSION,
        prompt_version: PROMPT_VERSION,
        partition_schema_version: PARTITION_SCHEMA_VERSION,
        validator_version: VALIDATOR_VERSION,
    };
    let staged = if let Some(egress_guard) = provider_egress_guard.take() {
        egress_guard.stage_and_release(stage).await?
    } else {
        // Providerless conservative promotion has no external-effect window;
        // it uses the ordinary lock-ordered staging transaction.
        repository.stage_reconciliation(&claim, stage).await?
    };
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
            capture_session_ids: vec!["capture-session".into()],
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
    fn output_fanout_never_exceeds_the_handle_leaf_bound() {
        assert_eq!(MAX_OUTPUTS, 32);
        assert_eq!(response_schema()["properties"]["memories"]["maxItems"], 32);
        let source = snapshot(vec![draft(10, &["utterance:1"])], vec![atom(1, 1)]);
        let oversized = ModelPartition {
            memories: (0..=MAX_OUTPUTS)
                .map(|ordinal| memory(&["utterance:1"], &format!("Output {ordinal}")))
                .collect(),
        };
        assert!(validate_partition(&source, oversized)
            .unwrap_err()
            .to_string()
            .contains("output bound exceeded"));
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
    fn durable_phase_is_the_only_reconciliation_and_finalization_selector() {
        use crate::persistence::MemoryReconciliationActivationPhase;

        assert_eq!(
            inactive_phase_allows_legacy_finalization(
                MemoryReconciliationActivationPhase::Preactive
            ),
            Some(true)
        );
        assert_eq!(
            inactive_phase_allows_legacy_finalization(
                MemoryReconciliationActivationPhase::Installed
            ),
            Some(true)
        );
        assert_eq!(
            inactive_phase_allows_legacy_finalization(
                MemoryReconciliationActivationPhase::Draining
            ),
            Some(false)
        );
        assert_eq!(
            inactive_phase_allows_legacy_finalization(MemoryReconciliationActivationPhase::Paused),
            Some(false)
        );
        assert_eq!(
            inactive_phase_allows_legacy_finalization(MemoryReconciliationActivationPhase::Active),
            None
        );
    }

    #[test]
    fn reconciliation_has_a_distinct_vertex_usage_operation() {
        assert_eq!(
            vertex::VertexOperation::EpisodeReconciliation.as_str(),
            "episode_reconciliation"
        );
    }

    #[test]
    fn activation_commitment_binds_explicit_model_location_and_compiled_producer() {
        let commitment = producer_contract_commitment("gemini-reconciliation", "us-central1")
            .expect("valid explicit producer");
        assert_eq!(
            commitment,
            producer_contract_commitment("gemini-reconciliation", "us-central1").unwrap(),
            "the signed producer contract must be deterministic"
        );
        assert_ne!(
            commitment,
            producer_contract_commitment("gemini-reconciliation-v2", "us-central1").unwrap()
        );
        assert_ne!(
            commitment,
            producer_contract_commitment("gemini-reconciliation", "europe-west4").unwrap()
        );
        for (model, location) in [
            ("", "us-central1"),
            (" gemini-reconciliation", "us-central1"),
            ("gemini-reconciliation", ""),
            ("gemini-reconciliation", "us-central1 "),
        ] {
            assert!(producer_contract_commitment(model, location).is_err());
        }
    }

    #[test]
    fn provider_egress_requires_claim_authority_to_match_this_process() {
        let model = "gemini-reconciliation";
        let location = "us-central1";
        let commitment = producer_contract_commitment(model, location).unwrap();
        let claim = ReconciliationClaim {
            account_id: "account".into(),
            source_fingerprint: vec![1; 32],
            topology_fingerprint: vec![2; 32],
            predecessor_episode_ids: vec![7],
            claim_token: "claim".into(),
            lease_until: "2026-08-31T12:00:00.000Z".into(),
            attempt_count: 1,
            model_attempt_count: 0,
            activation_generation: 9,
            producer_contract_sha256: commitment.to_vec(),
            reconciliation_model: model.into(),
            vertex_location: location.into(),
        };
        assert!(claim_producer_matches_process(&claim, model, location).unwrap());
        assert!(!claim_producer_matches_process(&claim, "gemini-other", location).unwrap());
        assert!(!claim_producer_matches_process(&claim, model, "europe-west4").unwrap());
        let mut wrong_digest = claim;
        wrong_digest.producer_contract_sha256[0] ^= 1;
        assert!(!claim_producer_matches_process(&wrong_digest, model, location).unwrap());
    }

    #[test]
    fn provider_egress_guard_is_the_final_database_check_before_http() {
        let source = include_str!("reconciler.rs");
        let revalidate_call = [".revalidate_source_", "fingerprint("].concat();
        let prepare_call = ["vertex::prepare_custom_", "with_model_attempt("].concat();
        let guard_call = [".acquire_provider_egress_", "guard(&claim)"].concat();
        let provider_call = ["prepared.send(state, account_", "id)"].concat();
        let preliminary = source
            .find(&revalidate_call)
            .expect("worker must perform its preliminary source revalidation");
        assert_eq!(
            source.matches(&revalidate_call).count(),
            1,
            "a second source transaction while the egress guard is held can self-deadlock"
        );
        let guard = source
            .find(&guard_call)
            .expect("worker must acquire durable provider-egress authority");
        let prepare = source
            .find(&prepare_call)
            .expect("worker must durably admit the provider attempt before its guard");
        let provider = source
            .find(&provider_call)
            .expect("worker must name its provider boundary");
        assert!(
            preliminary < prepare && prepare < guard && guard < provider,
            "preliminary/admission work must precede the final guard and HTTP must follow it"
        );
        let guarded_prefix = &source[guard..provider];
        assert!(
            !guarded_prefix.contains(&revalidate_call),
            "the held guard forbids a second transaction over its locked cohort"
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
            CONSERVATIVE_MODEL,
            "gemini-strong",
            MODEL_ATTEMPTS_BEFORE_CONSERVATIVE_KEEP - 1,
        ));
        assert!(stage_model_is_current(
            CONSERVATIVE_MODEL,
            "gemini-strong",
            MODEL_ATTEMPTS_BEFORE_CONSERVATIVE_KEEP,
        ));
        assert!(stage_model_is_current(
            CONSERVATIVE_AMBIGUITY_MODEL,
            "gemini-strong",
            0,
        ));
    }

    #[test]
    fn ambiguous_attempts_are_terminal_while_confirmed_outcomes_advance_identity() {
        assert_eq!(
            provider_failure_action(
                vertex::VertexGenerationFailureDisposition::RetryableBeforeEgress
            ),
            ProviderFailureAction::RetrySameAttempt
        );
        for disposition in [
            vertex::VertexGenerationFailureDisposition::RetryableNotBilled,
            vertex::VertexGenerationFailureDisposition::ConfirmedInvalid,
        ] {
            assert_eq!(
                provider_failure_action(disposition),
                ProviderFailureAction::RetryWithNewAttempt
            );
        }
        assert_eq!(
            provider_failure_action(vertex::VertexGenerationFailureDisposition::AmbiguousTerminal),
            ProviderFailureAction::ConservativeKeep
        );

        let source = vec![0x42; 32];
        let producer = vec![0x24; 32];
        let first = reconciliation_provider_attempt_identity(&source, 7, &producer, 0).unwrap();
        assert_eq!(
            first,
            reconciliation_provider_attempt_identity(&source, 7, &producer, 0).unwrap()
        );
        assert_ne!(
            first,
            reconciliation_provider_attempt_identity(&source, 7, &producer, 1).unwrap()
        );
        assert_ne!(
            first,
            reconciliation_provider_attempt_identity(&source, 8, &producer, 0).unwrap()
        );
        assert!(reconciliation_provider_attempt_identity(&source[..31], 7, &producer, 0).is_err());
        assert!(reconciliation_provider_attempt_identity(&source, 0, &producer, 0).is_err());
        assert!(reconciliation_provider_attempt_identity(&source, 7, &producer[..31], 0).is_err());
        assert!(reconciliation_provider_attempt_identity(&source, 7, &producer, -1).is_err());
    }

    #[test]
    fn conservative_stage_provenance_distinguishes_no_call_from_ambiguity() {
        assert!(stage_model_provenance_is_valid(CONSERVATIVE_MODEL, None));
        assert!(!stage_model_provenance_is_valid(
            CONSERVATIVE_MODEL,
            Some("vtx_attempt")
        ));
        assert!(stage_model_provenance_is_valid(
            CONSERVATIVE_AMBIGUITY_MODEL,
            Some("vtx_attempt")
        ));
        assert!(!stage_model_provenance_is_valid(
            CONSERVATIVE_AMBIGUITY_MODEL,
            None
        ));
        assert!(stage_model_provenance_is_valid(
            "gemini-strong",
            Some("vtx_attempt")
        ));
        assert!(!stage_model_provenance_is_valid("gemini-strong", None));
    }
}
