use async_trait::async_trait;

use crate::{cp::delivery::FinalizedEpisode, error::Result};

use super::EmailProviderOutcome;
use super::WebhookProviderOutcome;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct EmailDeliveryCandidate {
    pub(crate) account_id: String,
    pub(crate) episode_id: i64,
    pub(crate) delivery_version: i64,
    pub(crate) delivery_id: String,
    pub(crate) attempt_count: i64,
    pub(crate) include_content: bool,
    pub(crate) recipient_email: String,
    pub(crate) episode: FinalizedEpisode,
}

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct FrozenEmailDelivery {
    pub(crate) recipient_email: String,
    pub(crate) include_content: bool,
    pub(crate) subject: String,
    pub(crate) text_body: String,
    pub(crate) html_body: String,
}

impl std::fmt::Debug for FrozenEmailDelivery {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("FrozenEmailDelivery(<redacted>)")
    }
}

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct EmailDeliveryClaim {
    pub(crate) account_id: String,
    pub(crate) episode_id: i64,
    pub(crate) delivery_version: i64,
    pub(crate) delivery_id: String,
    pub(crate) claim_token: String,
    pub(crate) lease_expires_at: String,
    pub(crate) attempt_count: i64,
    pub(crate) request: FrozenEmailDelivery,
}

impl std::fmt::Debug for EmailDeliveryClaim {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("EmailDeliveryClaim(<redacted>)")
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct WebhookDeliveryCandidate {
    pub(crate) account_id: String,
    pub(crate) episode_id: i64,
    pub(crate) subscription_id: String,
    pub(crate) delivery_version: i64,
    pub(crate) event_id: String,
    pub(crate) attempt_count: i64,
    pub(crate) include_content: bool,
    pub(crate) endpoint_url: String,
    pub(crate) signing_secret: String,
    pub(crate) episode: FinalizedEpisode,
}

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct FrozenWebhookDelivery {
    pub(crate) endpoint_url: String,
    pub(crate) signing_secret: String,
    pub(crate) include_content: bool,
    pub(crate) event_body: String,
}

impl std::fmt::Debug for FrozenWebhookDelivery {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("FrozenWebhookDelivery(<redacted>)")
    }
}

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct WebhookDeliveryClaim {
    pub(crate) account_id: String,
    pub(crate) episode_id: i64,
    pub(crate) subscription_id: String,
    pub(crate) delivery_version: i64,
    pub(crate) event_id: String,
    pub(crate) claim_token: String,
    pub(crate) lease_expires_at: String,
    pub(crate) attempt_count: i64,
    pub(crate) request: FrozenWebhookDelivery,
}

impl std::fmt::Debug for WebhookDeliveryClaim {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("WebhookDeliveryClaim(<redacted>)")
    }
}

/// Fleet-safe access to outbound delivery rows.
///
/// Candidate reads perform no external effects. `claim_email` atomically
/// freezes the exact provider request, acquires the service-wide provider
/// lane, and publishes the durable send authority. A process must never call
/// the provider without a returned claim.
#[async_trait]
pub(crate) trait DeliveryRepository: Send + Sync {
    async fn next_email_candidate(
        &self,
        account_id: &str,
    ) -> Result<Option<EmailDeliveryCandidate>>;

    async fn claim_email(
        &self,
        candidate: &EmailDeliveryCandidate,
        request: FrozenEmailDelivery,
        lease_seconds: i64,
    ) -> Result<Option<EmailDeliveryClaim>>;

    async fn settle_email(
        &self,
        claim: &EmailDeliveryClaim,
        outcome: EmailProviderOutcome,
        circuit_seconds: Option<i64>,
    ) -> Result<()>;

    async fn next_webhook_candidate(
        &self,
        account_id: &str,
    ) -> Result<Option<WebhookDeliveryCandidate>>;

    async fn claim_webhook(
        &self,
        candidate: &WebhookDeliveryCandidate,
        request: FrozenWebhookDelivery,
        lease_seconds: i64,
    ) -> Result<Option<WebhookDeliveryClaim>>;

    async fn settle_webhook(
        &self,
        claim: &WebhookDeliveryClaim,
        outcome: WebhookProviderOutcome,
        circuit_seconds: Option<i64>,
    ) -> Result<()>;
}
