use async_trait::async_trait;
use serde_json::Value;

use crate::error::Result;

#[derive(Debug, Clone)]
pub(crate) struct FinalizationEpisode {
    pub(crate) id: i64,
    pub(crate) started_at: String,
    pub(crate) ended_at: String,
    pub(crate) episode_type: Option<String>,
    pub(crate) title: String,
    pub(crate) summary: Option<String>,
    pub(crate) participants: Option<String>,
    pub(crate) languages: Option<String>,
    pub(crate) action_items: Option<String>,
    pub(crate) structure_state: String,
    pub(crate) minute_summaries: Value,
    pub(crate) minutes_text: Option<String>,
}

#[derive(Debug, Clone)]
pub(crate) struct FinalizationUtterance {
    pub(crate) id: i64,
    pub(crate) at: String,
    pub(crate) at_ms: i64,
    pub(crate) speaker: String,
    pub(crate) source_type: String,
    pub(crate) text: String,
}

#[derive(Debug, Clone)]
pub(crate) struct FinalizationScreenshot {
    pub(crate) id: i64,
    pub(crate) captured_at: String,
    pub(crate) captured_at_ms: i64,
    pub(crate) active_app: Option<String>,
    pub(crate) window_title: Option<String>,
    pub(crate) url: Option<String>,
    pub(crate) ocr_text: Option<String>,
    pub(crate) salient_ocr_text: Option<String>,
    pub(crate) is_duplicate: bool,
    pub(crate) elided: bool,
    pub(crate) source_key: String,
    pub(crate) capture_status: String,
    pub(crate) visible_until: Option<String>,
    pub(crate) display_id: Option<i64>,
    pub(crate) primary_bundle_id: Option<String>,
    pub(crate) visible_windows: Value,
    pub(crate) browser_context: Value,
    pub(crate) visual_signals: Value,
}

#[derive(Debug, Clone)]
pub(crate) struct FinalizationClaim {
    pub(crate) account_id: String,
    pub(crate) claim_token: String,
    pub(crate) episode: FinalizationEpisode,
    pub(crate) utterances: Vec<FinalizationUtterance>,
    pub(crate) screenshots: Vec<FinalizationScreenshot>,
    pub(crate) input_identity_revision: i64,
    pub(crate) attempt_count: i64,
}

#[derive(Debug, Clone)]
pub(crate) struct FinalizationScreenResult {
    pub(crate) screenshot_id: i64,
    pub(crate) observation_revision: String,
    pub(crate) literal_description: String,
    pub(crate) screen_state: String,
    pub(crate) content_type: String,
    pub(crate) visible_text_summary: Option<String>,
    pub(crate) notable_items_json: String,
    pub(crate) activity_summary: Option<String>,
    pub(crate) relevance_level: i64,
    pub(crate) relevance_reason: String,
    pub(crate) milestone_type: String,
    pub(crate) base_score: i64,
    pub(crate) key_rank: Option<i64>,
    pub(crate) is_key_screen: bool,
    pub(crate) semantic_group: String,
}

#[derive(Debug, Clone)]
pub(crate) struct FinalizationSettlement {
    pub(crate) claim: FinalizationClaim,
    pub(crate) vertex_event_id: String,
    pub(crate) model_name: String,
    pub(crate) analysis_revision: String,
    pub(crate) title: String,
    pub(crate) summary: String,
    pub(crate) minute_summaries_json: String,
    pub(crate) minutes_text: String,
    pub(crate) action_items_json: String,
    pub(crate) overview: String,
    pub(crate) decisions_json: String,
    pub(crate) important_links_json: String,
    pub(crate) open_questions_json: String,
    pub(crate) ranked_screens: Vec<FinalizationScreenResult>,
    pub(crate) webhook_destinations: Vec<(String, String)>,
    pub(crate) email_preference_include_content: Option<bool>,
    pub(crate) push_destinations: Vec<(String, String, String, String)>,
    pub(crate) finalization_version: i64,
    pub(crate) observation_version: i64,
    pub(crate) observation_prompt_version: i64,
    pub(crate) interpretation_version: i64,
    pub(crate) interpretation_prompt_version: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum FinalizationRequest {
    NotFound,
    LowSignal,
    AwaitingReconciliation,
    AlreadyComplete { status: String },
    AlreadyQueued { status: String },
    Queued,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct FinalizationClaimRequest<'a> {
    pub(crate) account_id: &'a str,
    pub(crate) target_episode_id: Option<i64>,
    pub(crate) now: &'a str,
    pub(crate) horizon_before: &'a str,
    pub(crate) finalization_version: i64,
    pub(crate) lease_seconds: i64,
    pub(crate) require_reconciled: bool,
}

#[async_trait]
pub(crate) trait FinalizationRepository: Send + Sync {
    /// Atomically inspect and queue a user-requested episode finalization.
    /// This prevents two application replicas from deriving competing queue
    /// transitions from a stale process-local snapshot.
    async fn request_finalization(
        &self,
        account_id: &str,
        episode_id: i64,
        finalization_version: i64,
        require_reconciled: bool,
    ) -> Result<FinalizationRequest>;

    async fn claim_finalization(
        &self,
        request: FinalizationClaimRequest<'_>,
    ) -> Result<Option<FinalizationClaim>>;

    async fn defer_finalization(
        &self,
        claim: &FinalizationClaim,
        status: &str,
        error_code: Option<&str>,
        retry_at: Option<&str>,
        deferred_at: &str,
        count_attempt: bool,
    ) -> Result<()>;

    async fn settle_finalization(&self, result: FinalizationSettlement) -> Result<usize>;
}
