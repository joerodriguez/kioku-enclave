use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::error::Result;

pub(crate) const OVERSIZED_KEEP_MODEL: &str = "conservative-oversized-keep-v1";
pub(crate) const MAX_OVERSIZED_KEEP_SOURCES: i64 = 250_000;
pub(crate) const OVERSIZED_KEEP_SOURCE_PAGE_SIZE: i64 = 2_048;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct OversizedKeepPromotionPolicy {
    pub(crate) draft_limit: i64,
    pub(crate) atom_limit: i64,
    pub(crate) reconciliation_version: i64,
    pub(crate) prompt_version: i64,
    pub(crate) partition_schema_version: i64,
    pub(crate) validator_version: i64,
}

/// Canonical compiled policy for the providerless oversized escape hatch.
/// The activation producer commitment includes these bytes, so changing its
/// mutation semantics or operational bound requires a newly signed authority.
pub(crate) fn oversized_keep_policy_commitment() -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(b"kioku.memory-reconciliation.oversized-keep-policy.v1\0");
    digest.update(OVERSIZED_KEEP_MODEL.as_bytes());
    digest.update(MAX_OVERSIZED_KEEP_SOURCES.to_be_bytes());
    digest.update(OVERSIZED_KEEP_SOURCE_PAGE_SIZE.to_be_bytes());
    digest.update(b"oldest-connected-prefix|max-32|exact-episode-and-member-keep|structure-state-only|no-provider|all-raw-sources-owned|formation-current");
    digest.finalize().into()
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub(crate) struct ReconciliationDraft {
    pub(crate) id: i64,
    pub(crate) started_at: String,
    pub(crate) ended_at: String,
    pub(crate) episode_type: Option<String>,
    pub(crate) title: String,
    pub(crate) summary: Option<String>,
    pub(crate) participants: Vec<String>,
    pub(crate) languages: Vec<String>,
    pub(crate) action_items: Vec<String>,
    pub(crate) model: Option<String>,
    pub(crate) minute_summaries: Value,
    pub(crate) minutes_text: Option<String>,
    pub(crate) substance: String,
    pub(crate) visual_evidence: String,
    pub(crate) updated_at: Option<String>,
    pub(crate) identity_revision: i64,
    pub(crate) member_source_ids: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct ReconciliationEvidenceAtom {
    pub(crate) source_id: String,
    pub(crate) record_type: String,
    pub(crate) record_id: i64,
    pub(crate) started_at: String,
    pub(crate) ended_at: String,
    pub(crate) context: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub(crate) struct ReconciliationSnapshot {
    pub(crate) account_id: String,
    pub(crate) cohort_started_at: String,
    pub(crate) cohort_ended_at: String,
    pub(crate) predecessor_episode_ids: Vec<i64>,
    pub(crate) drafts: Vec<ReconciliationDraft>,
    pub(crate) atoms: Vec<ReconciliationEvidenceAtom>,
    /// Complete connected capture-session closure whose exact formation and
    /// seal receipts are committed by `source_fingerprint`.
    pub(crate) capture_session_ids: Vec<String>,
    /// Commitment to the complete, model-visible, source-settled projection.
    pub(crate) source_fingerprint: Vec<u8>,
    /// CAS over the active owners, episode revisions, and archive revision.
    pub(crate) topology_fingerprint: Vec<u8>,
    pub(crate) archive_revision: i64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ReconciliationClaim {
    pub(crate) account_id: String,
    pub(crate) source_fingerprint: Vec<u8>,
    pub(crate) topology_fingerprint: Vec<u8>,
    pub(crate) predecessor_episode_ids: Vec<i64>,
    pub(crate) claim_token: String,
    pub(crate) lease_until: String,
    pub(crate) attempt_count: i64,
    pub(crate) model_attempt_count: i64,
    /// Exact signed activation authority under which provider work may occur.
    /// A claim cannot be staged or published after any of these fields change.
    pub(crate) activation_generation: i64,
    pub(crate) producer_contract_sha256: Vec<u8>,
    pub(crate) reconciliation_model: String,
    pub(crate) vertex_location: String,
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct ReconciliationStageWrite {
    pub(crate) normalized_partition: Value,
    pub(crate) result_commitment: Vec<u8>,
    /// Exact validated mutation product. PostgreSQL stages and later publishes
    /// these bytes; publication cannot substitute a different topology payload
    /// while reusing the model-result commitment.
    pub(crate) planned_outputs: Vec<ReconciledMemoryWrite>,
    pub(crate) model: String,
    pub(crate) vertex_event_id: Option<String>,
    /// Exact durable attempt and request commitments. Providerless KEEP has
    /// neither; provider-backed stages must carry both and are checked against
    /// the terminal usage-ledger row before persistence.
    pub(crate) provider_attempt_identity: Option<Vec<u8>>,
    pub(crate) provider_invocation_fingerprint: Option<Vec<u8>>,
    pub(crate) reconciliation_version: i64,
    pub(crate) prompt_version: i64,
    pub(crate) partition_schema_version: i64,
    pub(crate) validator_version: i64,
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct StagedReconciliation {
    pub(crate) account_id: String,
    pub(crate) source_fingerprint: Vec<u8>,
    pub(crate) topology_fingerprint: Vec<u8>,
    pub(crate) predecessor_episode_ids: Vec<i64>,
    pub(crate) normalized_partition: Value,
    pub(crate) result_commitment: Vec<u8>,
    pub(crate) planned_outputs: Vec<ReconciledMemoryWrite>,
    pub(crate) planned_outputs_commitment: Vec<u8>,
    pub(crate) model: String,
    pub(crate) vertex_event_id: Option<String>,
    pub(crate) provider_attempt_identity: Option<Vec<u8>>,
    pub(crate) provider_invocation_fingerprint: Option<Vec<u8>>,
    pub(crate) reconciliation_version: i64,
    pub(crate) prompt_version: i64,
    pub(crate) partition_schema_version: i64,
    pub(crate) validator_version: i64,
    pub(crate) activation_generation: i64,
    pub(crate) producer_contract_sha256: Vec<u8>,
    pub(crate) reconciliation_model: String,
    pub(crate) vertex_location: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub(crate) struct ReconciledMemoryWrite {
    pub(crate) output_ordinal: i64,
    /// One-to-one reconciliation keeps this id. Merge, split, and repartition
    /// outputs use `None` and receive a fresh tenant-local episode id.
    pub(crate) retained_episode_id: Option<i64>,
    pub(crate) predecessor_episode_ids: Vec<i64>,
    pub(crate) started_at: String,
    pub(crate) ended_at: String,
    pub(crate) episode_type: Option<String>,
    pub(crate) title: String,
    pub(crate) summary: Option<String>,
    pub(crate) participants: Vec<String>,
    pub(crate) languages: Vec<String>,
    pub(crate) action_items: Vec<String>,
    pub(crate) model: Option<String>,
    pub(crate) minute_summaries: Value,
    pub(crate) minutes_text: Option<String>,
    pub(crate) substance: String,
    pub(crate) visual_evidence: String,
    pub(crate) member_source_ids: Vec<String>,
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct ReconciliationPublish {
    pub(crate) claim: ReconciliationClaim,
    pub(crate) reconciliation_id: String,
    pub(crate) cohort_started_at: String,
    pub(crate) cohort_ended_at: String,
    pub(crate) result_commitment: Vec<u8>,
}

pub(crate) fn reconciliation_outputs_commitment(
    outputs: &[ReconciledMemoryWrite],
) -> Result<Vec<u8>> {
    let mut digest = Sha256::new();
    digest.update(b"kioku.memory-reconciliation.planned-outputs.v1\0");
    digest.update(serde_json::to_vec(&serde_json::to_value(outputs)?)?);
    Ok(digest.finalize().to_vec())
}

pub(crate) fn reconciliation_provider_attempt_identity(
    source_fingerprint: &[u8],
    activation_generation: i64,
    producer_contract_sha256: &[u8],
    model_attempt_count: i64,
) -> Result<[u8; 32]> {
    if source_fingerprint.len() != 32
        || activation_generation <= 0
        || producer_contract_sha256.len() != 32
        || model_attempt_count < 0
    {
        return Err(crate::error::EnclaveError::Store(
            "memory reconciliation provider attempt identity is invalid".into(),
        ));
    }
    let mut digest = Sha256::new();
    digest.update(b"kioku.memory-reconciliation.provider-attempt.v2\0");
    digest.update(source_fingerprint);
    digest.update(activation_generation.to_be_bytes());
    digest.update(producer_contract_sha256);
    digest.update(model_attempt_count.to_be_bytes());
    Ok(digest.finalize().into())
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum ReconciliationPublishResult {
    Published {
        successor_episode_ids: Vec<i64>,
        archive_revision: i64,
    },
    Replayed {
        successor_episode_ids: Vec<i64>,
        archive_revision: i64,
    },
}

/// Result of the providerless escape hatch for a cohort which cannot fit the
/// model contract. `Held` is deliberately distinct from `NotOversized`: the
/// caller must not fall through to Vertex when PostgreSQL has proved that the
/// oldest component is oversized but cannot yet prove an exact safe KEEP.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum OversizedKeepPromotionResult {
    NotOversized,
    Held {
        /// End of the complete held temporal component. When present, the
        /// caller may safely search strictly after its quiet-horizon boundary
        /// in the same sweep without partially processing that component.
        resume_after_component_ended_at: Option<String>,
    },
    Promoted {
        episode_ids: Vec<i64>,
        reconciliation_id: String,
        archive_revision: i64,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum MemoryHandleState {
    Active,
    Superseded,
    Retired,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct MemoryHandleResolution {
    pub(crate) requested_episode_id: i64,
    pub(crate) state: MemoryHandleState,
    pub(crate) origin_relation: Option<String>,
    pub(crate) active_episode_ids: Vec<i64>,
    pub(crate) archive_revision: i64,
}

/// Database-backed fence retained from the final provider authority/source
/// revalidation through provider settlement and durable stage persistence.
/// While it is live, an Active -> Paused transition cannot update the signed
/// activation contract row.
#[async_trait]
pub(crate) trait ReconciliationEgressGuard: Send {
    /// Persist the provider result and commit the held activation/account/source
    /// fence in one transaction. A provider-backed stage must never escape to
    /// the repository's separate providerless staging transaction.
    async fn stage_and_release(
        self: Box<Self>,
        staged: ReconciliationStageWrite,
    ) -> Result<StagedReconciliation>;

    /// Explicitly roll back the fence before retry bookkeeping starts a new
    /// transaction that follows the same activation/account lock order.
    async fn abort(self: Box<Self>) -> Result<()>;
}

#[async_trait]
pub(crate) trait MemoryReconciliationRepository: Send + Sync {
    /// Promote at most `draft_limit` oldest drafts without provider egress when
    /// their connected component or evidence set exceeds the model bounds.
    /// PostgreSQL performs the source/formation proof and exact KEEP mutation
    /// in one serializable transaction.
    async fn promote_oversized_source_settled_prefix(
        &self,
        account_id: &str,
        quiet_horizon_seconds: i64,
        resume_after_component_ended_at: Option<&str>,
        policy: OversizedKeepPromotionPolicy,
    ) -> Result<OversizedKeepPromotionResult>;

    async fn next_source_settled_cohort(
        &self,
        account_id: &str,
        quiet_horizon_seconds: i64,
        resume_after_component_ended_at: Option<&str>,
        draft_limit: i64,
        atom_limit: i64,
    ) -> Result<Option<ReconciliationSnapshot>>;

    async fn revalidate_source_fingerprint(
        &self,
        account_id: &str,
        predecessor_episode_ids: &[i64],
        expected_source_fingerprint: &[u8],
    ) -> Result<bool>;

    async fn acquire_provider_egress_guard(
        &self,
        claim: &ReconciliationClaim,
    ) -> Result<Option<Box<dyn ReconciliationEgressGuard>>>;

    async fn claim_reconciliation(
        &self,
        snapshot: &ReconciliationSnapshot,
        lease_seconds: i64,
    ) -> Result<Option<ReconciliationClaim>>;

    async fn staged_result(
        &self,
        claim: &ReconciliationClaim,
    ) -> Result<Option<StagedReconciliation>>;

    async fn stage_reconciliation(
        &self,
        claim: &ReconciliationClaim,
        staged: ReconciliationStageWrite,
    ) -> Result<StagedReconciliation>;

    async fn release_reconciliation(
        &self,
        claim: &ReconciliationClaim,
        retry_delay_seconds: Option<i64>,
        error_code: &str,
        terminal: bool,
        consume_model_attempt: bool,
    ) -> Result<()>;

    async fn publish_reconciliation(
        &self,
        command: ReconciliationPublish,
    ) -> Result<ReconciliationPublishResult>;

    async fn resolve_memory_handle(
        &self,
        account_id: &str,
        episode_id: i64,
        max_leaves: i64,
    ) -> Result<MemoryHandleResolution>;
}
