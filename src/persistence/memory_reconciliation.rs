use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::error::Result;

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
    pub(crate) reconciliation_version: i64,
    pub(crate) prompt_version: i64,
    pub(crate) partition_schema_version: i64,
    pub(crate) validator_version: i64,
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

#[async_trait]
pub(crate) trait MemoryReconciliationRepository: Send + Sync {
    async fn next_source_settled_cohort(
        &self,
        account_id: &str,
        quiet_before: &str,
        draft_limit: i64,
        atom_limit: i64,
    ) -> Result<Option<ReconciliationSnapshot>>;

    async fn revalidate_source_fingerprint(
        &self,
        account_id: &str,
        predecessor_episode_ids: &[i64],
        expected_source_fingerprint: &[u8],
    ) -> Result<bool>;

    async fn claim_reconciliation(
        &self,
        snapshot: &ReconciliationSnapshot,
        claimed_at: &str,
        lease_seconds: i64,
    ) -> Result<Option<ReconciliationClaim>>;

    async fn staged_result(
        &self,
        account_id: &str,
        source_fingerprint: &[u8],
    ) -> Result<Option<StagedReconciliation>>;

    async fn stage_reconciliation(
        &self,
        claim: &ReconciliationClaim,
        staged: ReconciliationStageWrite,
    ) -> Result<StagedReconciliation>;

    async fn release_reconciliation(
        &self,
        claim: &ReconciliationClaim,
        released_at: &str,
        retry_at: Option<&str>,
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
