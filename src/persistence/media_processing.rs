use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{cp::media::AudioTurn, error::Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum MediaProcessingClass {
    Audio,
    Screen,
}

impl MediaProcessingClass {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Audio => "audio",
            Self::Screen => "screen",
        }
    }

    pub(crate) const fn job_kind(self) -> &'static str {
        match self {
            Self::Audio => "gemini_audio",
            Self::Screen => "gemini_screen",
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct MediaProcessingJob {
    pub(crate) id: i64,
    pub(crate) event_id: String,
    pub(crate) job_kind: String,
    pub(crate) object_key: String,
    pub(crate) object_generation: i64,
    pub(crate) mime_type: String,
    pub(crate) codec: String,
    pub(crate) byte_length: i64,
    pub(crate) sample_rate: Option<i64>,
    pub(crate) channels: Option<i64>,
    pub(crate) width: Option<i64>,
    pub(crate) height: Option<i64>,
    pub(crate) sha256: String,
    pub(crate) started_at: String,
    pub(crate) ended_at: String,
    pub(crate) stream_kind: String,
    pub(crate) capture_session_id: String,
    pub(crate) stream_id: String,
    pub(crate) sequence: i64,
    pub(crate) context: Option<Value>,
    pub(crate) audio_role: Option<String>,
    pub(crate) audio_route: Option<String>,
    pub(crate) route_epoch: Option<i64>,
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct MediaProcessingClaim {
    pub(crate) account_id: String,
    pub(crate) work_unit_id: String,
    pub(crate) class: MediaProcessingClass,
    pub(crate) claim_token: String,
    pub(crate) claim_until: String,
    pub(crate) jobs: Vec<MediaProcessingJob>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub(crate) struct MediaPersonEvidence {
    pub(crate) name: String,
    pub(crate) evidence: String,
    pub(crate) confidence: f64,
    pub(crate) is_active_speaker: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub(crate) struct MediaScreenProjection {
    pub(crate) event_id: String,
    pub(crate) literal_description: String,
    pub(crate) screen_state: String,
    pub(crate) content_type: String,
    pub(crate) visible_text: String,
    pub(crate) salient_text: String,
    pub(crate) people: Vec<MediaPersonEvidence>,
}

#[derive(Debug, Clone)]
pub(crate) struct MediaUsageSettlement {
    pub(crate) claim: MediaProcessingClaim,
    pub(crate) usage: Value,
}

#[derive(Debug, Clone)]
pub(crate) struct AudioMediaSettlement {
    pub(crate) claim: MediaProcessingClaim,
    pub(crate) turns: Vec<AudioTurn>,
}

#[derive(Debug, Clone)]
pub(crate) struct ScreenMediaSettlement {
    pub(crate) claim: MediaProcessingClaim,
    pub(crate) results: Vec<MediaScreenProjection>,
}

#[async_trait]
pub(crate) trait MediaProcessingRepository: Send + Sync {
    async fn pending_classes(&self, account_id: &str, now: &str) -> Result<(bool, bool)>;

    async fn claim(
        &self,
        account_id: &str,
        class: MediaProcessingClass,
        claimed_at: &str,
        lease_seconds: i64,
        scan_limit: i64,
    ) -> Result<Option<MediaProcessingClaim>>;

    async fn candidate_name_vocabulary(&self, account_id: &str) -> Result<Vec<String>>;

    async fn record_reservation(
        &self,
        claim: &MediaProcessingClaim,
        reserved_output_tokens: i64,
        reserved_at: &str,
    ) -> Result<()>;

    async fn settle_usage(&self, command: MediaUsageSettlement) -> Result<()>;

    async fn settle_audio(&self, command: AudioMediaSettlement) -> Result<()>;

    async fn settle_screens(&self, command: ScreenMediaSettlement) -> Result<()>;

    async fn settle_failure(
        &self,
        claim: &MediaProcessingClaim,
        error_code: &str,
        failed_at: &str,
        max_attempts: i64,
        budget_retry_seconds: i64,
        resurrection_window_seconds: i64,
    ) -> Result<()>;

    async fn resurrect_recent_failures(
        &self,
        account_id: &str,
        now: &str,
        delay_seconds: i64,
        total_attempt_cap: i64,
        window_seconds: i64,
        limit: i64,
    ) -> Result<u64>;

    async fn span_has_recoverable_media(
        &self,
        account_id: &str,
        from: &str,
        to: &str,
        resurrection_window_start: &str,
        memory_hold_attempts: i64,
    ) -> Result<bool>;
}
