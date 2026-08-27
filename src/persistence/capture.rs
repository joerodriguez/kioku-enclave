use async_trait::async_trait;

use crate::{
    cp::media::{CaptureEventManifest, RecordingMediaAuthorityDecision},
    error::Result,
};

#[derive(Debug, Clone, serde::Serialize, PartialEq, Eq)]
pub(crate) struct CaptureEventStatus {
    pub(crate) event_id: String,
    pub(crate) processing_state: String,
    pub(crate) error_code: Option<String>,
    pub(crate) attempt_count: i64,
}

#[derive(Debug, Clone, serde::Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum CaptureSessionStage {
    Received,
    Processing,
    Organizing,
    PreparingRecap,
    Ready,
    NeedsAttention,
    NoMemory,
}

#[derive(Debug, Clone, serde::Serialize, PartialEq, Eq)]
pub(crate) struct CaptureSessionEvidence {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) audio_minutes: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) voice_count: Option<i64>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub(crate) top_contexts: Vec<String>,
}

#[derive(Debug, Clone, serde::Serialize, PartialEq, Eq)]
pub(crate) struct CaptureSessionProcessing {
    pub(crate) queued: i64,
    pub(crate) processing: i64,
    pub(crate) retry_wait: i64,
    pub(crate) ready: i64,
    pub(crate) failed: i64,
}

#[derive(Debug, Clone, serde::Serialize, PartialEq, Eq)]
pub(crate) struct CaptureSessionMemory {
    pub(crate) id: i64,
    pub(crate) title: Option<String>,
    pub(crate) started_at: String,
    pub(crate) ended_at: String,
    pub(crate) finalization_status: String,
    pub(crate) finalized_at: Option<String>,
}

#[derive(Debug, Clone, serde::Serialize, PartialEq, Eq)]
pub(crate) struct CaptureSessionStatus {
    pub(crate) capture_session_id: String,
    pub(crate) device_id: String,
    pub(crate) started_at: String,
    pub(crate) last_event_at: String,
    pub(crate) ended_at: Option<String>,
    pub(crate) event_count: i64,
    pub(crate) stage: CaptureSessionStage,
    pub(crate) processing: CaptureSessionProcessing,
    pub(crate) evidence: CaptureSessionEvidence,
    pub(crate) memories: Vec<CaptureSessionMemory>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CapturePreflight {
    New,
    Duplicate { committed_through_sequence: i64 },
}

#[derive(Debug, Clone)]
pub(crate) struct CaptureCommit {
    pub(crate) account_id: String,
    pub(crate) manifest: CaptureEventManifest,
    pub(crate) manifest_digest: String,
    pub(crate) object_key: Option<String>,
    pub(crate) object_generation: Option<i64>,
    pub(crate) media_authority: Option<RecordingMediaAuthorityDecision>,
    pub(crate) committed_at: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct CaptureCommitResult {
    pub(crate) duplicate: bool,
    pub(crate) committed_through_sequence: i64,
}

#[derive(Debug, Clone)]
pub(crate) struct ReferenceBatchCommit {
    pub(crate) account_id: String,
    pub(crate) batch_id: String,
    pub(crate) events: Vec<CaptureEventManifest>,
    pub(crate) manifest_digests: Vec<String>,
    pub(crate) committed_at: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ReferenceBatchCommitResult {
    pub(crate) new_count: usize,
    pub(crate) duplicate_count: usize,
    pub(crate) committed_through_sequence: i64,
}

/// Atomic structured-state boundary for capture ingestion.
///
/// GCS upload happens before `commit_event`; this port owns the durable
/// operation receipt, media reference, contiguous stream acknowledgement,
/// and processing work creation in one database transaction. A retry with
/// the same event ID and fingerprint returns the recorded result. Reuse with
/// different content fails closed.
#[async_trait]
pub(crate) trait CaptureRepository: Send + Sync {
    async fn preflight_event(
        &self,
        account_id: &str,
        manifest: &CaptureEventManifest,
        manifest_digest: &str,
        allowed_object_keys: Option<&[String]>,
    ) -> Result<CapturePreflight>;

    async fn commit_event(&self, command: CaptureCommit) -> Result<CaptureCommitResult>;

    async fn commit_reference_batch(
        &self,
        command: ReferenceBatchCommit,
    ) -> Result<ReferenceBatchCommitResult>;

    async fn stream_ack(&self, account_id: &str, stream_id: &str) -> Result<i64>;

    async fn event_status(
        &self,
        account_id: &str,
        event_id: &str,
    ) -> Result<Option<CaptureEventStatus>>;

    async fn session_status(
        &self,
        account_id: &str,
        capture_session_id: &str,
        summarized_until_ms: Option<i64>,
    ) -> Result<Option<CaptureSessionStatus>>;

    async fn recent_sessions(
        &self,
        account_id: &str,
        window_hours: i64,
        max_sessions: i64,
        summarized_until_ms: Option<i64>,
    ) -> Result<Vec<CaptureSessionStatus>>;

    async fn finish_session(
        &self,
        account_id: &str,
        capture_session_id: &str,
    ) -> Result<Option<CaptureSessionStatus>>;
}
