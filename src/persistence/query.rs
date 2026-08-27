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

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct McpTranscriptSearchRequest {
    pub(crate) query: String,
    pub(crate) from: Option<String>,
    pub(crate) to: Option<String>,
    pub(crate) limit: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct McpContextRequest {
    pub(crate) at: String,
    pub(crate) window_seconds: u64,
    pub(crate) limit: Option<usize>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct McpTimeRangeRequest {
    pub(crate) from: String,
    pub(crate) to: String,
    pub(crate) limit: Option<usize>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct PeopleListRequest {
    pub(crate) after_id: i64,
    pub(crate) limit: usize,
    pub(crate) query: Option<String>,
}

#[derive(Clone, Debug, PartialEq, serde::Serialize)]
pub(crate) struct PeopleListPage {
    pub(crate) people: Vec<PersonSummary>,
    pub(crate) next_cursor: Option<i64>,
}

#[derive(Clone, Debug, PartialEq, serde::Serialize)]
pub(crate) struct PersonSummary {
    pub(crate) id: i64,
    pub(crate) display_name: String,
    pub(crate) voice_profile_count: i64,
    pub(crate) fact_count: i64,
    pub(crate) updated_at: String,
}

#[derive(Clone, Debug, PartialEq, serde::Serialize)]
pub(crate) struct PersonProfile {
    pub(crate) person: PersonSummary,
    pub(crate) voice_labels: Vec<String>,
    pub(crate) voice_coverage: String,
    pub(crate) aliases: Vec<PersonNameView>,
    pub(crate) facts: Vec<PersonFactView>,
    pub(crate) evidence: Vec<PersonEvidenceView>,
    pub(crate) recent_statements: Vec<PersonStatementView>,
}

#[derive(Clone, Debug, PartialEq, serde::Serialize)]
pub(crate) struct PersonFactView {
    pub(crate) id: i64,
    pub(crate) predicate: String,
    pub(crate) value: String,
    pub(crate) status: String,
    pub(crate) evidence: Value,
    pub(crate) source_event_id: Option<String>,
    pub(crate) speaker_observation_id: Option<i64>,
    pub(crate) observed_at: Option<String>,
    pub(crate) literal_evidence: Option<String>,
    pub(crate) confidence: f64,
    pub(crate) supersedes_id: Option<i64>,
    pub(crate) created_at: String,
}

#[derive(Clone, Debug, PartialEq, serde::Serialize)]
pub(crate) struct PersonNameView {
    pub(crate) id: i64,
    pub(crate) name: String,
    pub(crate) status: String,
    pub(crate) evidence_kind: String,
    pub(crate) confidence: f64,
    pub(crate) observed_at: String,
    pub(crate) source_event_id: Option<String>,
}

#[derive(Clone, Debug, PartialEq, serde::Serialize)]
pub(crate) struct PersonEvidenceView {
    pub(crate) id: i64,
    pub(crate) kind: String,
    pub(crate) claimed_name: Option<String>,
    pub(crate) score: Option<f64>,
    pub(crate) status: String,
    pub(crate) observed_at: Option<String>,
    pub(crate) source_event_id: Option<String>,
    pub(crate) speaker_observation_id: Option<i64>,
    pub(crate) evidence: Value,
}

#[derive(Clone, Debug, PartialEq, serde::Serialize)]
pub(crate) struct PersonStatementView {
    pub(crate) speaker_observation_id: i64,
    pub(crate) started_at: String,
    pub(crate) ended_at: String,
    pub(crate) text: String,
    pub(crate) source_event_id: String,
    pub(crate) episode_id: Option<i64>,
    pub(crate) episode_title: Option<String>,
}

#[derive(Clone, Debug, PartialEq, serde::Serialize)]
pub(crate) struct PersonEvidencePage {
    pub(crate) evidence: Vec<PersonEvidenceView>,
    pub(crate) next_cursor: Option<i64>,
}

#[derive(Clone, Debug, PartialEq, serde::Serialize)]
pub(crate) struct PersonStatementPage {
    pub(crate) statements: Vec<PersonStatementView>,
    pub(crate) next_cursor: Option<i64>,
}

/// Backend-neutral structured-memory query boundary.
///
/// Query embedding and response fusion remain application behavior; candidate
/// retrieval and tenant filtering are owned by the selected persistence
/// implementation.
#[async_trait]
pub(crate) trait MemoryQueryRepository: Send + Sync {
    async fn export(&self, account_id: &str) -> Result<Value>;
    async fn search(&self, account_id: &str, request: &SearchRequest) -> Result<Vec<SearchHit>>;
    async fn list_episodes(
        &self,
        account_id: &str,
        request: &EpisodeListRequest,
    ) -> Result<EpisodeListPage>;
    async fn capture_status(&self, account_id: &str) -> Result<CaptureStatus>;
    async fn feed(&self, account_id: &str, request: &MemoryFeedRequest) -> Result<MemoryFeedPage>;
    async fn mcp_search_transcripts(
        &self,
        account_id: &str,
        request: &McpTranscriptSearchRequest,
    ) -> Result<Value>;
    async fn mcp_context(&self, account_id: &str, request: &McpContextRequest) -> Result<Value>;
    async fn mcp_time_range(
        &self,
        account_id: &str,
        request: &McpTimeRangeRequest,
    ) -> Result<Value>;
    async fn browser_snapshot(&self, account_id: &str, source_key: &str) -> Result<Option<Value>>;
    async fn episode_members(&self, account_id: &str, episode_id: i64) -> Result<Value>;
    async fn list_people(
        &self,
        account_id: &str,
        request: &PeopleListRequest,
    ) -> Result<PeopleListPage>;
    async fn person_profile(&self, account_id: &str, person_id: i64) -> Result<PersonProfile>;
    async fn person_evidence(
        &self,
        account_id: &str,
        person_id: i64,
        before_id: Option<i64>,
        limit: usize,
    ) -> Result<PersonEvidencePage>;
    async fn person_statements(
        &self,
        account_id: &str,
        person_id: i64,
        before_id: Option<i64>,
        limit: usize,
    ) -> Result<PersonStatementPage>;
}
