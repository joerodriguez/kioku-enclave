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
    /// Atomically freezes an episode. A signed post-install fleet may then
    /// inventory the exact content/media authority in durable bounded pages;
    /// callers must treat `Pending` as a resumable receipt, not completeness.
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

    /// Acknowledge the exact bounded provider-object page, or advance one
    /// bounded structured page. In-progress advancement returns a retryable
    /// conflict; after exact structured closure this returns one replayable,
    /// bounded source-key page. Only explicit page acknowledgements may reach
    /// the atomic episode deletion and terminal receipt.
    async fn complete_episode_deletion(
        &self,
        account_id: &str,
        plan: &EpisodeDeletionPlan,
    ) -> Result<EpisodePurge>;

    /// Acknowledge one exact source-key page only after the caller has removed
    /// that page from its local authority. The opaque cursor is single-step,
    /// revision-bound, and idempotent for a lost response. The durable episode
    /// receipt remains pending until the final page is acknowledged.
    async fn acknowledge_episode_deletion_source_keys(
        &self,
        account_id: &str,
        episode_id: i64,
        source_key_cursor: &str,
    ) -> Result<EpisodePurge>;
}
