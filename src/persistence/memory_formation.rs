use async_trait::async_trait;

use crate::{episodes::EpisodeInput, error::Result};

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SummaryUtterance {
    pub(crate) id: i64,
    pub(crate) started_at: String,
    pub(crate) speaker_label: String,
    pub(crate) language: Option<String>,
    pub(crate) text: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SummaryScreenshot {
    pub(crate) id: i64,
    pub(crate) captured_at: String,
    pub(crate) active_app: Option<String>,
    pub(crate) window_title: Option<String>,
    pub(crate) ocr_text: Option<String>,
    pub(crate) salient_ocr_text: Option<String>,
    pub(crate) url: Option<String>,
    pub(crate) is_duplicate: i64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct OpenEpisode {
    pub(crate) id: i64,
    pub(crate) started_at: String,
    pub(crate) ended_at: String,
    pub(crate) episode_type: Option<String>,
    pub(crate) title: String,
    pub(crate) summary: Option<String>,
    pub(crate) participants: Vec<String>,
    pub(crate) action_items: Vec<String>,
    pub(crate) recent_minutes: Option<String>,
    pub(crate) utt_count: i64,
    pub(crate) scr_count: i64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SummaryWindowClaim {
    pub(crate) account_id: String,
    pub(crate) from: String,
    pub(crate) to: String,
    pub(crate) claim_token: String,
}

#[derive(Clone, Debug)]
pub(crate) struct SummaryWindowSettlement {
    pub(crate) claim: SummaryWindowClaim,
    pub(crate) episodes: Vec<EpisodeInput>,
    /// `None` deliberately holds the forward-only cursor. A value advances it
    /// atomically with the episode writes and durable operation receipt.
    pub(crate) cursor: Option<String>,
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct EpisodeEmbeddingSource {
    pub(crate) id: i64,
    pub(crate) text: String,
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct EpisodeEmbeddingWrite {
    pub(crate) id: i64,
    pub(crate) embedding: Vec<f32>,
}

/// PostgreSQL-owned memory formation boundary. Durable claims make one
/// summarizer window single-owner across the application fleet without
/// holding a database transaction open over a model call.
#[async_trait]
pub(crate) trait MemoryFormationRepository: Send + Sync {
    async fn claim_summary_window(
        &self,
        account_id: &str,
        from: &str,
        to: &str,
        claimed_at: &str,
        lease_seconds: i64,
    ) -> Result<Option<SummaryWindowClaim>>;

    async fn release_summary_window(
        &self,
        claim: &SummaryWindowClaim,
        released_at: &str,
        error_code: Option<&str>,
    ) -> Result<()>;

    async fn summary_evidence(
        &self,
        account_id: &str,
        from: &str,
        to: &str,
        utterance_limit: i64,
        screenshot_limit: i64,
    ) -> Result<(Vec<SummaryUtterance>, Vec<SummaryScreenshot>)>;

    async fn open_episodes(
        &self,
        account_id: &str,
        from: &str,
        to: &str,
        limit: i64,
    ) -> Result<Vec<OpenEpisode>>;

    async fn settle_summary_window(&self, settlement: SummaryWindowSettlement) -> Result<Vec<i64>>;

    async fn episode_embedding_sources(
        &self,
        account_id: &str,
        ids: &[i64],
    ) -> Result<Vec<EpisodeEmbeddingSource>>;

    async fn write_episode_embeddings(
        &self,
        account_id: &str,
        writes: &[EpisodeEmbeddingWrite],
    ) -> Result<()>;

    async fn session_tail_is_settled(&self, account_id: &str, recent_after: &str) -> Result<bool>;
}
