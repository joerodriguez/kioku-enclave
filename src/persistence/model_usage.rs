use async_trait::async_trait;
use sha2::{Digest, Sha256};

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

/// Admission result for one durable provider-attempt identity.
///
/// Only `Send` authorizes provider egress. Replaying an attempt whose outcome
/// is already durable never authorizes another send: an explicit not-billed
/// response lets the owning worker advance to a new attempt identity, while
/// every other replay is conservatively ambiguous because response bytes are
/// not recoverable from the usage ledger.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum VertexInvocationAdmission {
    Send,
    ConfirmedNotBilled,
    AmbiguousTerminal,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct VertexInvocationAttempt {
    pub(crate) event_id: String,
    pub(crate) admission: VertexInvocationAdmission,
}

pub(crate) fn vertex_attempt_event_id(attempt_identity: &[u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut digest = Sha256::new();
    digest.update(b"kioku.vertex-invocation-attempt.v1\0");
    digest.update(attempt_identity);
    let digest: [u8; 32] = digest.finalize().into();
    let mut value = String::with_capacity(68);
    value.push_str("vtx_");
    for byte in digest {
        value.push(char::from(HEX[usize::from(byte >> 4)]));
        value.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    value
}

/// Canonical commitment written to `vertex_usage_events.request_fingerprint`.
/// Callers may independently bind a durable provider stage to the exact
/// request contract without reimplementing the ledger's byte domain.
pub(crate) fn vertex_invocation_fingerprint(
    account_id: &str,
    operation: VertexOperation,
    requested_model: &str,
    location: &str,
    caller_anchor: &[u8; 32],
) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(b"kioku.vertex-invocation.v1\0");
    digest.update(account_id.as_bytes());
    digest.update([0]);
    digest.update(format!("{operation:?}").as_bytes());
    digest.update([0]);
    digest.update(requested_model.as_bytes());
    digest.update([0]);
    digest.update(location.as_bytes());
    digest.update([0]);
    digest.update(caller_anchor);
    digest.finalize().into()
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

    /// Commit one explicitly numbered provider attempt before egress.
    ///
    /// `caller_anchor` commits to the exact request body. `attempt_identity`
    /// is a separate durable identity owned by the caller's retry state. A
    /// confirmed retry must use a new attempt identity while retaining the
    /// same caller anchor. Replaying an identity returns a non-`Send`
    /// admission and therefore cannot duplicate an ambiguous provider call.
    async fn begin_invocation_attempt(
        &self,
        account_id: &str,
        operation: VertexOperation,
        requested_model: &str,
        location: &str,
        caller_anchor: &[u8; 32],
        attempt_identity: &[u8; 32],
    ) -> Result<VertexInvocationAttempt>;

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

    /// Settle an invocation intent that was durably created but was then
    /// rejected by the caller's final local egress fence. No HTTP request was
    /// sent, so fabricating a provider status would corrupt the usage ledger.
    async fn settle_pre_egress_not_billed(&self, account_id: &str, event_id: &str) -> Result<()>;

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
