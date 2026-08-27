use async_trait::async_trait;

use crate::error::Result;

#[derive(Debug, Clone, PartialEq)]
pub struct RecordingLeaseRequestRow {
    pub requested_lease_id: Option<String>,
    pub issued_lease_id: String,
    pub expires_at: String,
    pub state: String,
    pub summary: Option<serde_json::Value>,
    pub denial_code: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VertexCoverageAnchor {
    pub period: String,
    pub sequence: u64,
    pub pending_events: u64,
    pub lost_events: u64,
    pub observed_at: String,
}

/// Tenant-scoped inputs used to allocate shared service cost. Storage is a
/// backend-defined logical byte count, not a physical provider billing value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountDriverMetrics {
    pub storage_bytes: u64,
    pub accepted_email_count: u64,
    pub vertex_coverage: Option<VertexCoverageAnchor>,
}

/// Content-free owner reporting totals. This shape deliberately cannot carry
/// account identifiers or signup timestamps across the admin API boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RetainedAccountMetrics {
    pub retained_active_accounts: u64,
    pub new_retained_active_accounts_mtd: u64,
}

#[async_trait]
pub(crate) trait BillingRepository: Send + Sync {
    async fn billing_account_id(&self, account_id: &str) -> Result<String>;
    async fn billing_account_id_for_deletion(&self, account_id: &str) -> Result<String>;

    async fn active_identities_for_billing_accounts(
        &self,
        billing_account_ids: Vec<String>,
    ) -> Result<Vec<(String, String, String)>>;
    async fn retained_active_account_metrics(&self, period: &str)
        -> Result<RetainedAccountMetrics>;
    async fn active_vertex_coverage_complete(&self, period: &str) -> Result<bool>;
    async fn reconcile_vertex_coverage(
        &self,
        account_id: &str,
        period: &str,
        sequence: u64,
        pending_events: u64,
        lost_events: u64,
        observed_at: &str,
    ) -> Result<VertexCoverageAnchor>;
    async fn vertex_coverage_anchor(
        &self,
        account_id: &str,
        period: &str,
    ) -> Result<Option<VertexCoverageAnchor>>;
    async fn account_driver_metrics(
        &self,
        account_id: &str,
        period: &str,
    ) -> Result<AccountDriverMetrics>;

    async fn pending_billing_detach_ids(&self, limit: i64) -> Result<Vec<String>>;
    async fn complete_billing_detach(&self, billing_account_id: &str) -> Result<()>;
    async fn record_billing_detach_failure(&self, billing_account_id: &str) -> Result<()>;

    async fn offline_recording_usage_receipt(
        &self,
        account_id: &str,
        request_id: &str,
    ) -> Result<bool>;
    async fn complete_offline_recording_usage(
        &self,
        account_id: &str,
        request_id: &str,
    ) -> Result<bool>;
    async fn reserve_recording_delivery(
        &self,
        account_id: &str,
        event_id: &str,
        media_bytes: i64,
    ) -> Result<bool>;
    #[allow(clippy::too_many_arguments)]
    async fn reserve_recording_delivery_batch(
        &self,
        account_id: &str,
        batch_id: &str,
        manifest_digest: &str,
        stream_id: &str,
        first_sequence: i64,
        last_sequence: i64,
        event_ids: &[String],
        new_event_ids: &[String],
    ) -> Result<bool>;
    async fn complete_recording_delivery_batch(
        &self,
        account_id: &str,
        batch_id: &str,
        manifest_digest: &str,
        event_ids: &[String],
    ) -> Result<()>;
    async fn complete_recording_delivery(&self, account_id: &str, event_id: &str) -> Result<()>;

    async fn recording_lease_receipt(
        &self,
        account_id: &str,
        request_id: &str,
    ) -> Result<Option<RecordingLeaseRequestRow>>;
    async fn active_recording_lease(&self, account_id: &str) -> Result<Option<(String, String)>>;
    async fn pending_recording_lease_request(
        &self,
        account_id: &str,
    ) -> Result<Option<(String, RecordingLeaseRequestRow)>>;
    async fn begin_recording_lease_request(
        &self,
        account_id: &str,
        request_id: &str,
        requested_lease_id: Option<&str>,
        issued_lease_id: &str,
        expires_at: &str,
    ) -> Result<()>;
    async fn deny_recording_lease_request(
        &self,
        account_id: &str,
        request_id: &str,
        denial_code: &str,
        summary: &serde_json::Value,
    ) -> Result<()>;
    async fn complete_recording_lease(
        &self,
        account_id: &str,
        request_id: &str,
        retry_now_ms: Option<i64>,
        summary: &serde_json::Value,
    ) -> Result<(String, String)>;
    async fn conflict_recording_lease_request(
        &self,
        account_id: &str,
        request_id: &str,
    ) -> Result<()>;
}
