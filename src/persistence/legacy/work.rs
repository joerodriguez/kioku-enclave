use std::sync::Arc;

use async_trait::async_trait;

use crate::{
    cp::control_store::ControlStore,
    error::Result,
    persistence::{
        EmailFenceOutcome, EmailProviderOutcome, EmailSendFence, EmailSendFenceDisposition,
        PushControlCancellation, PushProviderOutcome, PushProviderReceipt, PushSendFence,
        PushSendFenceDisposition, WebhookProviderOutcome, WebhookSendFence,
        WebhookSendFenceDisposition, WorkRepository,
    },
};

pub(crate) struct LegacyWorkRepository {
    control: Arc<ControlStore>,
}

impl LegacyWorkRepository {
    pub(crate) fn new(control: Arc<ControlStore>) -> Self {
        Self { control }
    }
}

#[async_trait]
impl WorkRepository for LegacyWorkRepository {
    async fn webhook_outbox_deletion_owned(&self, account_id: &str) -> Result<bool> {
        self.control.webhook_outbox_deletion_owned(account_id).await
    }

    async fn begin_webhook_send_fence(
        &self,
        requested: &WebhookSendFence,
        decision_at: &str,
    ) -> Result<WebhookSendFenceDisposition> {
        self.control
            .begin_webhook_send_fence(requested, decision_at)
            .await
    }

    async fn get_webhook_send_fence(
        &self,
        account_id: &str,
        event_id: &str,
    ) -> Result<Option<WebhookSendFence>> {
        self.control
            .get_webhook_send_fence(account_id, event_id)
            .await
    }

    async fn list_webhook_send_fences(&self, account_id: &str) -> Result<Vec<WebhookSendFence>> {
        self.control.list_webhook_send_fences(account_id).await
    }

    async fn validate_webhook_send_fence(
        &self,
        fence: &WebhookSendFence,
        minimum_valid_at_millis: i64,
    ) -> Result<bool> {
        self.control
            .validate_webhook_send_fence(fence, minimum_valid_at_millis)
            .await
    }

    async fn record_webhook_send_outcome(
        &self,
        fence: &WebhookSendFence,
        outcome: WebhookProviderOutcome,
        outcome_at: &str,
    ) -> Result<()> {
        self.control
            .record_webhook_send_outcome(fence, outcome, outcome_at)
            .await
    }

    async fn close_webhook_send_fence(&self, fence: &WebhookSendFence) -> Result<()> {
        self.control.close_webhook_send_fence(fence).await
    }

    async fn email_outbox_deletion_owned(&self, account_id: &str) -> Result<bool> {
        self.control.email_outbox_deletion_owned(account_id).await
    }

    async fn begin_email_send_fence(
        &self,
        requested: &EmailSendFence,
        decision_at: &str,
    ) -> Result<EmailSendFenceDisposition> {
        self.control
            .begin_email_send_fence(requested, decision_at)
            .await
    }

    async fn get_email_send_fence(
        &self,
        account_id: &str,
        delivery_id: &str,
    ) -> Result<Option<EmailSendFence>> {
        self.control
            .get_email_send_fence(account_id, delivery_id)
            .await
    }

    async fn list_email_send_fences(&self, account_id: &str) -> Result<Vec<EmailSendFence>> {
        self.control.list_email_send_fences(account_id).await
    }

    async fn validate_email_send_fence(
        &self,
        fence: &EmailSendFence,
        minimum_valid_at_millis: i64,
    ) -> Result<bool> {
        self.control
            .validate_email_send_fence(fence, minimum_valid_at_millis)
            .await
    }

    async fn record_email_send_outcome(
        &self,
        fence: &EmailSendFence,
        outcome: EmailProviderOutcome,
        outcome_at: &str,
    ) -> Result<()> {
        self.control
            .record_email_send_outcome(fence, outcome, outcome_at)
            .await
    }

    async fn finish_email_send_fence(
        &self,
        fence: &EmailSendFence,
        archive_outcome: EmailFenceOutcome,
    ) -> Result<()> {
        self.control
            .finish_email_send_fence(fence, archive_outcome)
            .await
    }

    async fn push_outbox_deletion_owned(&self, account_id: &str) -> Result<bool> {
        self.control.push_outbox_deletion_owned(account_id).await
    }

    async fn begin_push_send_fence(
        &self,
        account_id: &str,
        installation_id: &str,
        token_generation: i64,
        claim_id: &str,
        lease_expires_at: &str,
        decision_at: &str,
    ) -> Result<PushSendFenceDisposition> {
        self.control
            .begin_push_send_fence(
                account_id,
                installation_id,
                token_generation,
                claim_id,
                lease_expires_at,
                decision_at,
            )
            .await
    }

    async fn get_push_send_fence(
        &self,
        account_id: &str,
        installation_id: &str,
    ) -> Result<Option<PushSendFence>> {
        self.control
            .get_push_send_fence(account_id, installation_id)
            .await
    }

    async fn list_push_send_fences(&self, account_id: &str) -> Result<Vec<PushSendFence>> {
        self.control.list_push_send_fences(account_id).await
    }

    async fn validate_push_send_fence(
        &self,
        account_id: &str,
        installation_id: &str,
        token_generation: i64,
        claim_id: &str,
        lease_expires_at: &str,
        minimum_valid_at_millis: i64,
    ) -> Result<bool> {
        self.control
            .validate_push_send_fence(
                account_id,
                installation_id,
                token_generation,
                claim_id,
                lease_expires_at,
                minimum_valid_at_millis,
            )
            .await
    }

    async fn record_push_send_outcome(
        &self,
        account_id: &str,
        installation_id: &str,
        token_generation: i64,
        claim_id: &str,
        lease_expires_at: &str,
        receipt: PushProviderReceipt,
    ) -> Result<()> {
        self.control
            .record_push_send_outcome(
                account_id,
                installation_id,
                token_generation,
                claim_id,
                lease_expires_at,
                receipt,
            )
            .await
    }

    async fn finish_push_send_fence(
        &self,
        fence: &PushSendFence,
        archive_outcome: PushProviderOutcome,
    ) -> Result<()> {
        self.control
            .finish_push_send_fence(fence, archive_outcome)
            .await
    }

    async fn finish_push_cancellation_fence(
        &self,
        fence: &PushSendFence,
        cancellation: PushControlCancellation,
    ) -> Result<()> {
        self.control
            .finish_push_cancellation_fence(fence, cancellation)
            .await
    }
}
