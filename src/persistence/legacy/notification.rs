use std::sync::Arc;

use async_trait::async_trait;

use crate::cp::control_store::ControlStore;
use crate::error::Result;

use super::super::notification::{
    EpisodeEmailPreference, NotificationRepository, PushInstallation, WebhookSubscription,
};

pub(crate) struct LegacyNotificationRepository {
    control: Arc<ControlStore>,
}

impl LegacyNotificationRepository {
    pub(crate) fn new(control: Arc<ControlStore>) -> Self {
        Self { control }
    }
}

#[async_trait]
impl NotificationRepository for LegacyNotificationRepository {
    async fn list_webhook_subscriptions(
        &self,
        account_id: &str,
    ) -> Result<Vec<WebhookSubscription>> {
        self.control.list_webhook_subscriptions(account_id).await
    }

    async fn get_webhook_subscription(
        &self,
        account_id: &str,
        subscription_id: &str,
    ) -> Result<Option<WebhookSubscription>> {
        self.control
            .get_webhook_subscription(account_id, subscription_id)
            .await
    }

    async fn create_webhook_subscription(&self, subscription: WebhookSubscription) -> Result<()> {
        self.control.create_webhook_subscription(subscription).await
    }

    async fn disable_webhook_subscription(
        &self,
        account_id: &str,
        subscription_id: &str,
    ) -> Result<()> {
        self.control
            .disable_webhook_subscription(account_id, subscription_id)
            .await
    }

    async fn delete_webhook_subscription(
        &self,
        account_id: &str,
        subscription_id: &str,
    ) -> Result<bool> {
        self.control
            .delete_webhook_subscription(account_id, subscription_id)
            .await
    }

    async fn get_email_preference(&self, account_id: &str) -> Result<EpisodeEmailPreference> {
        self.control.get_email_preference(account_id).await
    }

    async fn set_email_preference(
        &self,
        account_id: &str,
        enabled: bool,
        include_content: bool,
    ) -> Result<EpisodeEmailPreference> {
        self.control
            .set_email_preference(account_id, enabled, include_content)
            .await
    }

    async fn upsert_push_installation(
        &self,
        installation: PushInstallation,
    ) -> Result<PushInstallation> {
        self.control.upsert_push_installation(installation).await
    }

    async fn list_push_installations(&self, account_id: &str) -> Result<Vec<PushInstallation>> {
        self.control.list_push_installations(account_id).await
    }

    async fn delete_push_installation(
        &self,
        account_id: &str,
        installation_id: &str,
    ) -> Result<bool> {
        self.control
            .delete_push_installation(account_id, installation_id)
            .await
    }
}
