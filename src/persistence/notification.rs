use async_trait::async_trait;

use crate::error::Result;

#[derive(Clone, serde::Deserialize, PartialEq, Eq)]
pub struct WebhookSubscription {
    pub id: String,
    pub user_id: String,
    pub name: String,
    pub endpoint_url: String,
    pub signing_secret: String,
    pub include_content: bool,
    pub enabled: bool,
    pub created_at: String,
}

impl std::fmt::Debug for WebhookSubscription {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("WebhookSubscription(<redacted>)")
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct EpisodeEmailPreference {
    pub enabled: bool,
    pub include_content: bool,
    pub recipient_email: String,
    pub consented_at: Option<String>,
    pub updated_at: String,
}

#[derive(Clone, PartialEq, Eq)]
pub struct PushInstallation {
    pub id: String,
    pub user_id: String,
    pub platform: String,
    pub topic: String,
    pub environment: String,
    pub device_token: String,
    pub token_generation: i64,
    pub enabled: bool,
}

impl std::fmt::Debug for PushInstallation {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PushInstallation")
            .field("id", &"<opaque>")
            .field("platform", &self.platform)
            .field("topic", &self.topic)
            .field("environment", &self.environment)
            .field("token_generation", &self.token_generation)
            .field("enabled", &self.enabled)
            .finish()
    }
}

/// User-controlled notification destinations and consent.
///
/// Provider-send claims and outcomes belong to `WorkRepository`; this port
/// only owns destination configuration. Implementations still serialize
/// changes against in-flight send fences in the same database transaction.
#[async_trait]
pub(crate) trait NotificationRepository: Send + Sync {
    async fn list_webhook_subscriptions(
        &self,
        account_id: &str,
    ) -> Result<Vec<WebhookSubscription>>;

    async fn get_webhook_subscription(
        &self,
        account_id: &str,
        subscription_id: &str,
    ) -> Result<Option<WebhookSubscription>>;

    async fn create_webhook_subscription(&self, subscription: WebhookSubscription) -> Result<()>;

    async fn disable_webhook_subscription(
        &self,
        account_id: &str,
        subscription_id: &str,
    ) -> Result<()>;

    async fn delete_webhook_subscription(
        &self,
        account_id: &str,
        subscription_id: &str,
    ) -> Result<bool>;

    async fn get_email_preference(&self, account_id: &str) -> Result<EpisodeEmailPreference>;

    async fn set_email_preference(
        &self,
        account_id: &str,
        enabled: bool,
        include_content: bool,
    ) -> Result<EpisodeEmailPreference>;

    async fn upsert_push_installation(
        &self,
        installation: PushInstallation,
    ) -> Result<PushInstallation>;

    async fn list_push_installations(&self, account_id: &str) -> Result<Vec<PushInstallation>>;

    async fn delete_push_installation(
        &self,
        account_id: &str,
        installation_id: &str,
    ) -> Result<bool>;
}
