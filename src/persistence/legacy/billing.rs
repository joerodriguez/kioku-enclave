use std::sync::Arc;

use async_trait::async_trait;

use crate::cp::control_store::ControlStore;
use crate::error::Result;

use super::super::billing::{
    BillingRepository, RecordingLeaseRequestRow, RetainedAccountMetrics, VertexCoverageAnchor,
};

pub(crate) struct LegacyBillingRepository {
    control: Arc<ControlStore>,
}

impl LegacyBillingRepository {
    pub(crate) fn new(control: Arc<ControlStore>) -> Self {
        Self { control }
    }
}

#[async_trait]
impl BillingRepository for LegacyBillingRepository {
    async fn billing_account_id(&self, account_id: &str) -> Result<String> {
        self.control.billing_account_id(account_id).await
    }

    async fn billing_account_id_for_deletion(&self, account_id: &str) -> Result<String> {
        self.control
            .billing_account_id_for_deletion(account_id)
            .await
    }

    async fn active_identities_for_billing_accounts(
        &self,
        billing_account_ids: Vec<String>,
    ) -> Result<Vec<(String, String, String)>> {
        self.control
            .active_identities_for_billing_accounts(billing_account_ids)
            .await
    }

    async fn retained_active_account_metrics(
        &self,
        period: &str,
    ) -> Result<RetainedAccountMetrics> {
        self.control.retained_active_account_metrics(period).await
    }

    async fn active_vertex_coverage_complete(&self, period: &str) -> Result<bool> {
        self.control.active_vertex_coverage_complete(period).await
    }

    async fn reconcile_vertex_coverage(
        &self,
        account_id: &str,
        period: &str,
        sequence: u64,
        pending_events: u64,
        lost_events: u64,
        observed_at: &str,
    ) -> Result<VertexCoverageAnchor> {
        self.control
            .reconcile_vertex_coverage(
                account_id,
                period,
                sequence,
                pending_events,
                lost_events,
                observed_at,
            )
            .await
    }

    async fn vertex_coverage_anchor(
        &self,
        account_id: &str,
        period: &str,
    ) -> Result<Option<VertexCoverageAnchor>> {
        self.control
            .vertex_coverage_anchor(account_id, period)
            .await
    }

    async fn pending_billing_detach_ids(&self, limit: i64) -> Result<Vec<String>> {
        self.control.pending_billing_detach_ids(limit).await
    }

    async fn complete_billing_detach(&self, billing_account_id: &str) -> Result<()> {
        self.control
            .complete_billing_detach(billing_account_id)
            .await
    }

    async fn record_billing_detach_failure(&self, billing_account_id: &str) -> Result<()> {
        self.control
            .record_billing_detach_failure(billing_account_id)
            .await
    }

    async fn offline_recording_usage_receipt(
        &self,
        account_id: &str,
        request_id: &str,
    ) -> Result<bool> {
        self.control
            .offline_recording_usage_receipt(account_id, request_id)
            .await
    }

    async fn complete_offline_recording_usage(
        &self,
        account_id: &str,
        request_id: &str,
    ) -> Result<bool> {
        self.control
            .complete_offline_recording_usage(account_id, request_id)
            .await
    }

    async fn reserve_recording_delivery(
        &self,
        account_id: &str,
        event_id: &str,
        media_bytes: i64,
    ) -> Result<bool> {
        self.control
            .reserve_recording_delivery(account_id, event_id, media_bytes)
            .await
    }

    async fn recording_lease_receipt(
        &self,
        account_id: &str,
        request_id: &str,
    ) -> Result<Option<RecordingLeaseRequestRow>> {
        self.control
            .recording_lease_receipt(account_id, request_id)
            .await
    }

    async fn active_recording_lease(&self, account_id: &str) -> Result<Option<(String, String)>> {
        self.control.active_recording_lease(account_id).await
    }

    async fn pending_recording_lease_request(
        &self,
        account_id: &str,
    ) -> Result<Option<(String, RecordingLeaseRequestRow)>> {
        self.control
            .pending_recording_lease_request(account_id)
            .await
    }

    async fn begin_recording_lease_request(
        &self,
        account_id: &str,
        request_id: &str,
        requested_lease_id: Option<&str>,
        issued_lease_id: &str,
        expires_at: &str,
    ) -> Result<()> {
        self.control
            .begin_recording_lease_request(
                account_id,
                request_id,
                requested_lease_id,
                issued_lease_id,
                expires_at,
            )
            .await
    }

    async fn deny_recording_lease_request(
        &self,
        account_id: &str,
        request_id: &str,
        denial_code: &str,
        summary: &serde_json::Value,
    ) -> Result<()> {
        self.control
            .deny_recording_lease_request(account_id, request_id, denial_code, summary)
            .await
    }

    async fn complete_recording_lease(
        &self,
        account_id: &str,
        request_id: &str,
        retry_now_ms: Option<i64>,
        summary: &serde_json::Value,
    ) -> Result<(String, String)> {
        self.control
            .complete_recording_lease(account_id, request_id, retry_now_ms, summary)
            .await
    }

    async fn conflict_recording_lease_request(
        &self,
        account_id: &str,
        request_id: &str,
    ) -> Result<()> {
        self.control
            .conflict_recording_lease_request(account_id, request_id)
            .await
    }
}
