use async_trait::async_trait;

use crate::{
    cp::{
        billing::{VertexCoverageSnapshot, VertexUsageEvent},
        vertex::{VertexMetadata, VertexOperation},
    },
    error::Result,
};

#[derive(Clone, Debug)]
pub(crate) struct ClaimedVertexUsageBatch {
    pub(crate) claim_id: String,
    pub(crate) events: Vec<VertexUsageEvent>,
}

#[derive(Clone, Debug)]
pub(crate) struct ClaimedVertexCoverage {
    pub(crate) claim_id: String,
    pub(crate) snapshot: VertexCoverageSnapshot,
}

/// Durable accounting for paid Vertex invocations and their billing outbox.
///
/// Implementations must commit the invocation intent before returning from
/// `begin_invocation`. Provider I/O happens outside this interface. Terminal
/// settlement and delivery acknowledgement are idempotent by event id.
#[async_trait]
pub(crate) trait ModelUsageRepository: Send + Sync {
    async fn begin_invocation(
        &self,
        account_id: &str,
        operation: VertexOperation,
        requested_model: &str,
        location: &str,
        caller_anchor: &[u8; 32],
    ) -> Result<String>;

    async fn settle_response(
        &self,
        account_id: &str,
        event_id: &str,
        metadata: &VertexMetadata,
    ) -> Result<()>;

    async fn settle_ambiguous(
        &self,
        account_id: &str,
        event_id: &str,
        http_status: Option<u16>,
    ) -> Result<()>;

    async fn settle_not_billed(
        &self,
        account_id: &str,
        event_id: &str,
        http_status: u16,
    ) -> Result<()>;

    /// Reconcile stale starts and return one bounded, deliverable batch.
    /// `force_started_ambiguous` is used only while deletion owns admission.
    async fn pending_events(
        &self,
        account_id: &str,
        billing_account_id: &str,
        force_started_ambiguous: bool,
    ) -> Result<Option<ClaimedVertexUsageBatch>>;

    async fn complete_delivery(
        &self,
        account_id: &str,
        claim_id: &str,
        event_ids: &[String],
    ) -> Result<()>;
    async fn note_delivery_failure(
        &self,
        account_id: &str,
        claim_id: &str,
        event_ids: &[String],
    ) -> Result<()>;

    async fn pending_coverage(
        &self,
        account_id: &str,
        billing_account_id: &str,
    ) -> Result<Vec<ClaimedVertexCoverage>>;

    /// Replace a local coverage predecessor with the billing authority's
    /// reconciled value. Implementations must reject a stale predecessor.
    async fn persist_coverage_snapshot(
        &self,
        account_id: &str,
        claim_id: &str,
        predecessor: &VertexCoverageSnapshot,
        replacement: &VertexCoverageSnapshot,
    ) -> Result<()>;

    async fn complete_coverage(
        &self,
        account_id: &str,
        claim_id: &str,
        period: &str,
        sequence: u64,
    ) -> Result<()>;

    async fn invalidate_stale_coverage(
        &self,
        account_id: &str,
        claim_id: &str,
        period: &str,
        sequence: u64,
    ) -> Result<()>;
}
