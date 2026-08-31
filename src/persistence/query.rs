use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::error::Result;

#[derive(Debug, Clone, Deserialize)]
pub(crate) struct SearchRequest {
    pub(crate) query: String,
    #[serde(default)]
    pub(crate) speaker: Option<String>,
    pub(crate) time_start: Option<String>,
    pub(crate) time_end: Option<String>,
    #[serde(default = "default_search_limit")]
    pub(crate) limit: usize,
    #[serde(default)]
    pub(crate) offset: usize,
    #[serde(default)]
    pub(crate) kinds: Vec<String>,
    pub(crate) query_embedding: Option<Vec<f32>>,
}

fn default_search_limit() -> usize {
    20
}

#[derive(Debug, Serialize)]
#[serde(tag = "kind")]
pub(crate) enum SearchHit {
    Utterance {
        id: i64,
        text: String,
        speaker_label: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        person_id: Option<i64>,
        #[serde(skip_serializing_if = "Option::is_none")]
        attribution_kind: Option<String>,
        started_at: String,
        start_offset_seconds: f64,
        end_offset_seconds: f64,
        source_at: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        memory_id: Option<i64>,
        #[serde(skip_serializing_if = "Option::is_none")]
        episode_id: Option<i64>,
        #[serde(skip_serializing_if = "Option::is_none")]
        episode_title: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        score: Option<f64>,
    },
    Screenshot {
        id: i64,
        captured_at: String,
        active_app: Option<String>,
        window_title: Option<String>,
        ocr_text: Option<String>,
        url: Option<String>,
        observation_status: Option<String>,
        literal_description: Option<String>,
        screen_state: Option<String>,
        content_type: Option<String>,
        source_at: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        memory_id: Option<i64>,
        #[serde(skip_serializing_if = "Option::is_none")]
        episode_id: Option<i64>,
        #[serde(skip_serializing_if = "Option::is_none")]
        episode_title: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        match_source: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        match_text: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        score: Option<f64>,
    },
    Episode {
        id: i64,
        memory_id: i64,
        started_at: String,
        ended_at: String,
        title: Option<String>,
        summary: Option<String>,
        minute_summaries: Value,
        #[serde(skip_serializing_if = "Option::is_none")]
        final_brief: Option<Value>,
        #[serde(skip_serializing_if = "Option::is_none")]
        snippet: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        match_source: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        score: Option<f64>,
    },
}

/// Pull a `speaker:Name` or `speaker:"Multi Word"` token out of a query.
pub(crate) fn extract_speaker_filter(query: &str) -> (String, Option<String>) {
    let lower = query.to_lowercase();
    let Some(pos) = lower.find("speaker:") else {
        return (query.to_string(), None);
    };
    let after = &query[pos + "speaker:".len()..];
    let (speaker, rest) = if let Some(stripped) = after.strip_prefix('"') {
        match stripped.find('"') {
            Some(end) => (&stripped[..end], &stripped[end + 1..]),
            None => (stripped, ""),
        }
    } else {
        match after.find(char::is_whitespace) {
            Some(end) => (&after[..end], &after[end..]),
            None => (after, ""),
        }
    };
    let cleaned = format!("{} {}", query[..pos].trim_end(), rest.trim())
        .trim()
        .to_string();
    let speaker = speaker.trim();
    if speaker.is_empty() {
        (cleaned, None)
    } else {
        (cleaned, Some(speaker.to_string()))
    }
}

/// Merge ranked candidate lists with reciprocal-rank fusion (k = 60).
pub(crate) fn rrf_merge(fts_rows: &[i64], knn_rows: &[(i64, f64)]) -> Vec<(i64, f64)> {
    const RRF_K: f64 = 60.0;
    let mut scores = std::collections::HashMap::<i64, f64>::new();
    for (rank, row_id) in fts_rows.iter().enumerate() {
        *scores.entry(*row_id).or_default() += 1.0 / (RRF_K + rank as f64 + 1.0);
    }
    for (rank, (row_id, _)) in knn_rows.iter().enumerate() {
        *scores.entry(*row_id).or_default() += 1.0 / (RRF_K + rank as f64 + 1.0);
    }
    let mut ranked: Vec<_> = scores.into_iter().collect();
    ranked.sort_by(|left, right| {
        right
            .1
            .total_cmp(&left.1)
            .then_with(|| left.0.cmp(&right.0))
    });
    ranked
}

#[cfg(test)]
mod rrf_tests {
    use super::rrf_merge;

    #[test]
    fn equal_scores_use_a_deterministic_id_tie_breaker() {
        let ranked = rrf_merge(&[9], &[(4, 0.0)]);
        assert_eq!(ranked.iter().map(|(id, _)| *id).collect::<Vec<_>>(), [4, 9]);
    }

    #[test]
    fn evidence_in_both_lists_still_ranks_first() {
        let ranked = rrf_merge(&[9, 4], &[(4, 0.1), (9, 0.2)]);
        assert_eq!(ranked[0].0, 4);
    }
}

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
    /// Account-local memory topology epoch captured in the same PostgreSQL
    /// snapshot as the rows and facets on this page.
    pub(crate) archive_revision: i64,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
pub(crate) struct CaptureStatus {
    pub(crate) total_utterances: i64,
    pub(crate) total_screenshots: i64,
    pub(crate) episode_count: i64,
    pub(crate) last_utterance_at: Option<String>,
    pub(crate) last_screenshot_at: Option<String>,
}

/// Authoritative encrypted screenshot object resolved from structured state.
///
/// Canonical capture objects require an exact current generation and the v2
/// bound-blob envelope.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum ScreenshotMediaLocator {
    Canonical {
        object_key: String,
        generation: i64,
        byte_length: i64,
        sha256: String,
    },
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
    pub(crate) person_id: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) attribution_kind: Option<String>,
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
    async fn screenshot_media(
        &self,
        account_id: &str,
        public_id: &str,
    ) -> Result<Option<ScreenshotMediaLocator>>;
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
