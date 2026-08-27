use std::sync::Arc;

use async_trait::async_trait;

use crate::cp::control_store::ControlStore;
use crate::error::{EnclaveError, Result};
use crate::store::Store;

use super::super::billing::{
    AccountDriverMetrics, BillingRepository, RecordingLeaseRequestRow, RetainedAccountMetrics,
    VertexCoverageAnchor,
};

pub(crate) struct LegacyBillingRepository {
    control: Arc<ControlStore>,
    store: Arc<Store>,
}

impl LegacyBillingRepository {
    pub(crate) fn new(control: Arc<ControlStore>, store: Arc<Store>) -> Self {
        Self { control, store }
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

    async fn account_driver_metrics(
        &self,
        account_id: &str,
        period: &str,
    ) -> Result<AccountDriverMetrics> {
        let account_id = account_id.to_string();
        let period = period.to_string();
        self.store
            .wal_authoritative_read(&account_id, move |conn| {
                use rusqlite::OptionalExtension;

                let page_count: i64 = conn.query_row("PRAGMA page_count", [], |row| row.get(0))?;
                let page_size: i64 = conn.query_row("PRAGMA page_size", [], |row| row.get(0))?;
                let media_bytes: i64 = conn.query_row(
                    "SELECT COALESCE(SUM(byte_length),0) FROM media_objects",
                    [],
                    |row| row.get(0),
                )?;
                let accepted_email_count: i64 = conn.query_row(
                    "SELECT count(*) FROM email_deliveries \
                     WHERE state='accepted' AND substr(updated_at,1,7)=?1",
                    [&period],
                    |row| row.get(0),
                )?;
                let storage_bytes = page_count
                    .checked_mul(page_size)
                    .and_then(|value| value.checked_add(media_bytes))
                    .and_then(|value| u64::try_from(value).ok())
                    .ok_or_else(|| EnclaveError::Config("storage size overflow".into()))?;
                let accepted_email_count = u64::try_from(accepted_email_count)
                    .map_err(|_| EnclaveError::Config("email delivery count overflow".into()))?;
                let coverage: Option<(i64, i64, i64, String)> = conn
                    .query_row(
                        "SELECT sequence,pending_events,lost_events,updated_at \
                         FROM vertex_usage_coverage WHERE period=?1",
                        [&period],
                        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
                    )
                    .optional()?;
                let vertex_coverage = coverage
                    .map(|(sequence, pending_events, lost_events, observed_at)| {
                        Ok::<VertexCoverageAnchor, EnclaveError>(VertexCoverageAnchor {
                            period: period.clone(),
                            sequence: u64::try_from(sequence).map_err(|_| {
                                EnclaveError::Config("coverage sequence overflow".into())
                            })?,
                            pending_events: u64::try_from(pending_events).map_err(|_| {
                                EnclaveError::Config("coverage pending count overflow".into())
                            })?,
                            lost_events: u64::try_from(lost_events).map_err(|_| {
                                EnclaveError::Config("coverage lost count overflow".into())
                            })?,
                            observed_at,
                        })
                    })
                    .transpose()?;
                Ok(AccountDriverMetrics {
                    storage_bytes,
                    accepted_email_count,
                    vertex_coverage,
                })
            })
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
    ) -> Result<bool> {
        self.control
            .reserve_recording_delivery_batch(
                account_id,
                batch_id,
                manifest_digest,
                stream_id,
                first_sequence,
                last_sequence,
                event_ids,
                new_event_ids,
            )
            .await
    }

    async fn complete_recording_delivery_batch(
        &self,
        account_id: &str,
        batch_id: &str,
        manifest_digest: &str,
        event_ids: &[String],
    ) -> Result<()> {
        self.control
            .complete_recording_delivery_batch(account_id, batch_id, manifest_digest, event_ids)
            .await
    }

    async fn complete_recording_delivery(&self, account_id: &str, event_id: &str) -> Result<()> {
        self.control
            .complete_recording_delivery(account_id, event_id)
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
