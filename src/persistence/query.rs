use async_trait::async_trait;
use serde_json::Value;

use crate::error::Result;
use crate::search::{SearchHit, SearchRequest};

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct EpisodeListRequest {
    pub(crate) from: Option<String>,
    pub(crate) to: Option<String>,
    pub(crate) limit: i64,
    pub(crate) include_low: bool,
    pub(crate) episode_id: Option<i64>,
    pub(crate) before_started_at: Option<String>,
    pub(crate) before_id: Option<i64>,
    pub(crate) probe_for_more: bool,
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct EpisodeListPage {
    pub(crate) episodes: Vec<Value>,
    pub(crate) hidden_count: i64,
    pub(crate) has_more: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
pub(crate) struct CaptureStatus {
    pub(crate) total_utterances: i64,
    pub(crate) total_screenshots: i64,
    pub(crate) episode_count: i64,
    pub(crate) last_utterance_at: Option<String>,
    pub(crate) last_screenshot_at: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct MemoryFeedRequest {
    pub(crate) from: Option<String>,
    pub(crate) to: Option<String>,
    pub(crate) limit: usize,
    pub(crate) before: Option<String>,
}

#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
pub(crate) struct MemoryFeedRecord {
    pub(crate) kind: String,
    pub(crate) id: i64,
    pub(crate) at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) speaker_label: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) text: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) active_app: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) window_title: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) ocr_excerpt: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) observation_status: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) literal_description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) screen_state: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) source_key: Option<String>,
    pub(crate) episode_id: Option<i64>,
}

#[derive(Clone, Debug, PartialEq, serde::Serialize)]
pub(crate) struct MemoryFeedPage {
    pub(crate) records: Vec<MemoryFeedRecord>,
    pub(crate) next_before: Option<String>,
}

/// Backend-neutral structured-memory query boundary.
///
/// Query embedding and response fusion remain application behavior; candidate
/// retrieval and tenant filtering are owned by the selected persistence
/// implementation.
#[async_trait]
pub(crate) trait MemoryQueryRepository: Send + Sync {
    async fn search(&self, account_id: &str, request: &SearchRequest) -> Result<Vec<SearchHit>>;
    async fn list_episodes(
        &self,
        account_id: &str,
        request: &EpisodeListRequest,
    ) -> Result<EpisodeListPage>;
    async fn capture_status(&self, account_id: &str) -> Result<CaptureStatus>;
    async fn feed(&self, account_id: &str, request: &MemoryFeedRequest) -> Result<MemoryFeedPage>;
}
