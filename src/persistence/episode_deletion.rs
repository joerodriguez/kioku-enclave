use async_trait::async_trait;

use crate::{error::Result, persistence::EpisodePurge};

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub(crate) struct EpisodeDeletionPlan {
    pub(crate) episode_id: i64,
    pub(crate) purge: EpisodePurge,
    /// Encrypted objects that must be absent before structured state is
    /// physically removed. Deletion is idempotent and retried on resume.
    pub(crate) media_object_keys: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum EpisodeDeletionStart {
    NotFound,
    Pending(EpisodeDeletionPlan),
    Complete(EpisodePurge),
}

#[async_trait]
pub(crate) trait EpisodeDeletionRepository: Send + Sync {
    /// Atomically freezes an episode and records the exact content/media
    /// inventory that the provider step must erase.
    async fn begin_episode_deletion(
        &self,
        account_id: &str,
        episode_id: i64,
    ) -> Result<EpisodeDeletionStart>;

    /// Return a bounded batch left pending by an interrupted request or
    /// worker. Provider deletion remains outside the structured transaction.
    async fn pending_episode_deletions(
        &self,
        limit: usize,
    ) -> Result<Vec<(String, EpisodeDeletionPlan)>>;

    /// Atomically purges the frozen content and records a replayable receipt.
    /// The caller must first delete every object from the returned plan.
    async fn complete_episode_deletion(
        &self,
        account_id: &str,
        plan: &EpisodeDeletionPlan,
    ) -> Result<EpisodePurge>;
}
