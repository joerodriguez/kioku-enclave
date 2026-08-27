use std::sync::Arc;

use async_trait::async_trait;

use crate::{
    cp::{
        billing::VertexCoverageSnapshot,
        model_usage,
        vertex::{VertexMetadata, VertexOperation},
    },
    error::Result,
    persistence::{ClaimedVertexCoverage, ClaimedVertexUsageBatch, ModelUsageRepository},
    store::Store,
};

/// Compatibility adapter for the encrypted per-user SQLite/WAL ledger.
pub(crate) struct LegacyModelUsageRepository {
    store: Arc<Store>,
}

impl LegacyModelUsageRepository {
    pub(crate) fn new(store: Arc<Store>) -> Self {
        Self { store }
    }
}

#[async_trait]
impl ModelUsageRepository for LegacyModelUsageRepository {
    async fn begin_invocation(
        &self,
        account_id: &str,
        operation: VertexOperation,
        requested_model: &str,
        location: &str,
        caller_anchor: &[u8; 32],
    ) -> Result<String> {
        model_usage::legacy_begin_invocation(
            &self.store,
            account_id,
            operation,
            requested_model,
            location,
            caller_anchor,
        )
        .await
    }

    async fn settle_response(
        &self,
        account_id: &str,
        event_id: &str,
        metadata: &VertexMetadata,
    ) -> Result<()> {
        model_usage::legacy_settle_response(&self.store, account_id, event_id, metadata).await
    }

    async fn settle_ambiguous(
        &self,
        account_id: &str,
        event_id: &str,
        http_status: Option<u16>,
    ) -> Result<()> {
        model_usage::legacy_settle_ambiguous(&self.store, account_id, event_id, http_status).await
    }

    async fn settle_not_billed(
        &self,
        account_id: &str,
        event_id: &str,
        http_status: u16,
    ) -> Result<()> {
        model_usage::legacy_settle_not_billed(&self.store, account_id, event_id, http_status).await
    }

    async fn pending_events(
        &self,
        account_id: &str,
        billing_account_id: &str,
        force_started_ambiguous: bool,
    ) -> Result<Option<ClaimedVertexUsageBatch>> {
        let events = model_usage::legacy_pending_events(
            &self.store,
            account_id,
            billing_account_id,
            force_started_ambiguous,
        )
        .await?;
        Ok((!events.is_empty()).then(|| ClaimedVertexUsageBatch {
            claim_id: crate::cp::tokens::random_token_hex(),
            events,
        }))
    }

    async fn complete_delivery(
        &self,
        account_id: &str,
        _claim_id: &str,
        event_ids: &[String],
    ) -> Result<()> {
        model_usage::legacy_complete_delivery(&self.store, account_id, event_ids).await
    }

    async fn note_delivery_failure(
        &self,
        account_id: &str,
        _claim_id: &str,
        event_ids: &[String],
    ) -> Result<()> {
        model_usage::legacy_note_delivery_failure(&self.store, account_id, event_ids).await
    }

    async fn pending_coverage(
        &self,
        account_id: &str,
        billing_account_id: &str,
    ) -> Result<Vec<ClaimedVertexCoverage>> {
        Ok(
            model_usage::legacy_pending_coverage(&self.store, account_id, billing_account_id)
                .await?
                .into_iter()
                .map(|snapshot| ClaimedVertexCoverage {
                    claim_id: crate::cp::tokens::random_token_hex(),
                    snapshot,
                })
                .collect(),
        )
    }

    async fn persist_coverage_snapshot(
        &self,
        account_id: &str,
        _claim_id: &str,
        predecessor: &VertexCoverageSnapshot,
        replacement: &VertexCoverageSnapshot,
    ) -> Result<()> {
        model_usage::legacy_persist_coverage_snapshot(
            &self.store,
            account_id,
            predecessor,
            replacement,
        )
        .await
    }

    async fn complete_coverage(
        &self,
        account_id: &str,
        _claim_id: &str,
        period: &str,
        sequence: u64,
    ) -> Result<()> {
        model_usage::legacy_complete_coverage(&self.store, account_id, period, sequence).await
    }

    async fn invalidate_stale_coverage(
        &self,
        account_id: &str,
        _claim_id: &str,
        period: &str,
        sequence: u64,
    ) -> Result<()> {
        model_usage::legacy_invalidate_stale_coverage(&self.store, account_id, period, sequence)
            .await
    }
}
