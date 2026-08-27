use async_trait::async_trait;

use crate::{
    cp::media::{CaptureEventManifest, RecordingMediaAuthorityDecision},
    error::Result,
};

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
}
