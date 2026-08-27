use async_trait::async_trait;

use crate::{
    cp::isotime,
    error::{EnclaveError, Result},
};

use super::{EpisodeEmailPreference, PushInstallation, WebhookSubscription};

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum WebhookControlCancellation {
    AccountInactive,
    SubscriptionMissing,
    SubscriptionDisabled,
    DestinationChanged,
}

impl WebhookControlCancellation {
    pub(crate) const fn kind(&self) -> &'static str {
        match self {
            Self::AccountInactive => "cancel_account_inactive",
            Self::SubscriptionMissing => "cancel_subscription_missing",
            Self::SubscriptionDisabled => "cancel_subscription_disabled",
            Self::DestinationChanged => "cancel_destination_changed",
        }
    }

    pub(crate) fn from_kind(kind: &str) -> Option<Self> {
        match kind {
            "cancel_account_inactive" => Some(Self::AccountInactive),
            "cancel_subscription_missing" => Some(Self::SubscriptionMissing),
            "cancel_subscription_disabled" => Some(Self::SubscriptionDisabled),
            "cancel_destination_changed" => Some(Self::DestinationChanged),
            _ => None,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum WebhookProviderOutcome {
    Sent {
        status: i64,
    },
    Retry {
        status: Option<i64>,
        code: String,
        retry_at: String,
    },
    Ambiguous,
    Failed {
        status: Option<i64>,
        code: String,
    },
}

impl WebhookProviderOutcome {
    pub(crate) const fn kind(&self) -> &'static str {
        match self {
            Self::Sent { .. } => "sent",
            Self::Retry { .. } => "retry",
            Self::Ambiguous => "ambiguous",
            Self::Failed { .. } => "failed",
        }
    }

    pub(crate) fn fields(&self) -> (Option<i64>, Option<&str>, Option<&str>) {
        match self {
            Self::Sent { status } => (Some(*status), None, None),
            Self::Retry {
                status,
                code,
                retry_at,
            } => (*status, Some(code), Some(retry_at)),
            Self::Ambiguous => (None, None, None),
            Self::Failed { status, code } => (*status, Some(code), None),
        }
    }

    pub(crate) fn is_valid(&self) -> bool {
        match self {
            Self::Sent { status } => (200..=299).contains(status),
            Self::Retry {
                status,
                code,
                retry_at,
            } => {
                status.is_none_or(|status| (100..=599).contains(&status))
                    && valid_fence_text(code, 256)
                    && valid_fence_timestamp(retry_at)
            }
            Self::Ambiguous => true,
            Self::Failed { status, code } => {
                status.is_none_or(|status| (100..=599).contains(&status))
                    && valid_fence_text(code, 256)
            }
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum WebhookFenceOutcome {
    Provider(WebhookProviderOutcome),
    Cancellation(WebhookControlCancellation),
}

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct WebhookSendFence {
    pub(crate) user_id: String,
    pub(crate) event_id: String,
    pub(crate) subscription_id: String,
    pub(crate) claim_id: String,
    pub(crate) lease_expires_at: String,
    pub(crate) endpoint_url: String,
    pub(crate) signing_secret: String,
    pub(crate) include_content: bool,
    pub(crate) outcome: Option<WebhookFenceOutcome>,
    pub(crate) outcome_at: Option<String>,
}

impl std::fmt::Debug for WebhookSendFence {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("WebhookSendFence(<redacted>)")
    }
}

pub(crate) enum WebhookSendFenceDisposition {
    Authorized(WebhookSubscription),
    DeletionOwned,
    Recorded(WebhookSendFence),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum EmailControlCancellation {
    AccountInactive,
    PreferenceDisabled,
    RecipientChanged,
    ContentConsentChanged,
}

impl EmailControlCancellation {
    pub(crate) const fn kind(&self) -> &'static str {
        match self {
            Self::AccountInactive => "cancel_account_inactive",
            Self::PreferenceDisabled => "cancel_preference_disabled",
            Self::RecipientChanged => "cancel_recipient_changed",
            Self::ContentConsentChanged => "cancel_content_consent_changed",
        }
    }

    pub(crate) fn from_kind(kind: &str) -> Option<Self> {
        match kind {
            "cancel_account_inactive" => Some(Self::AccountInactive),
            "cancel_preference_disabled" => Some(Self::PreferenceDisabled),
            "cancel_recipient_changed" => Some(Self::RecipientChanged),
            "cancel_content_consent_changed" => Some(Self::ContentConsentChanged),
            _ => None,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum EmailProviderOutcome {
    Accepted {
        status: i64,
        provider_message_id: String,
    },
    Retry {
        status: Option<i64>,
        code: String,
        retry_at: String,
    },
    Ambiguous,
    Failed {
        status: Option<i64>,
        code: String,
    },
}

impl EmailProviderOutcome {
    pub(crate) const fn kind(&self) -> &'static str {
        match self {
            Self::Accepted { .. } => "accepted",
            Self::Retry { .. } => "retry",
            Self::Ambiguous => "ambiguous",
            Self::Failed { .. } => "failed",
        }
    }

    pub(crate) fn fields(&self) -> (Option<i64>, Option<&str>, Option<&str>, Option<&str>) {
        match self {
            Self::Accepted {
                status,
                provider_message_id,
            } => (Some(*status), Some(provider_message_id), None, None),
            Self::Retry {
                status,
                code,
                retry_at,
            } => (*status, None, Some(code), Some(retry_at)),
            Self::Ambiguous => (None, None, None, None),
            Self::Failed { status, code } => (*status, None, Some(code), None),
        }
    }

    pub(crate) fn is_valid(&self) -> bool {
        match self {
            Self::Accepted {
                status,
                provider_message_id,
            } => (200..=299).contains(status) && valid_fence_text(provider_message_id, 512),
            Self::Retry {
                status,
                code,
                retry_at,
            } => {
                status.is_none_or(|status| (100..=599).contains(&status))
                    && valid_fence_text(code, 256)
                    && valid_fence_timestamp(retry_at)
            }
            Self::Ambiguous => true,
            Self::Failed { status, code } => {
                status.is_none_or(|status| (100..=599).contains(&status))
                    && valid_fence_text(code, 256)
            }
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum EmailFenceOutcome {
    Provider(EmailProviderOutcome),
    Cancellation(EmailControlCancellation),
}

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct EmailSendFence {
    pub(crate) user_id: String,
    pub(crate) delivery_id: String,
    pub(crate) claim_id: String,
    pub(crate) lease_expires_at: String,
    pub(crate) recipient_email: String,
    pub(crate) include_content: bool,
    pub(crate) outcome: Option<EmailFenceOutcome>,
    pub(crate) outcome_at: Option<String>,
}

impl std::fmt::Debug for EmailSendFence {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("EmailSendFence(<redacted>)")
    }
}

pub(crate) enum EmailSendFenceDisposition {
    Authorized(EpisodeEmailPreference),
    DeletionOwned,
    Recorded(EmailSendFence),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PushControlCancellation {
    AccountInactive,
    InstallationMissing,
    InstallationDisabled,
    TokenGenerationChanged,
}

impl PushControlCancellation {
    pub(crate) const fn code(self) -> &'static str {
        match self {
            Self::AccountInactive => "account_inactive",
            Self::InstallationMissing => "installation_missing",
            Self::InstallationDisabled => "installation_disabled",
            Self::TokenGenerationChanged => "token_generation_changed",
        }
    }

    pub(crate) const fn kind(self) -> &'static str {
        match self {
            Self::AccountInactive => "cancel_account_inactive",
            Self::InstallationMissing => "cancel_installation_missing",
            Self::InstallationDisabled => "cancel_installation_disabled",
            Self::TokenGenerationChanged => "cancel_token_generation_changed",
        }
    }

    pub(crate) fn from_kind(kind: &str) -> Option<Self> {
        match kind {
            "cancel_account_inactive" => Some(Self::AccountInactive),
            "cancel_installation_missing" => Some(Self::InstallationMissing),
            "cancel_installation_disabled" => Some(Self::InstallationDisabled),
            "cancel_token_generation_changed" => Some(Self::TokenGenerationChanged),
            _ => None,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum PushProviderOutcome {
    Accepted {
        status: i64,
    },
    Retry {
        status: Option<i64>,
        code: String,
        retry_at: String,
    },
    Ambiguous,
    Failed {
        status: Option<i64>,
        code: String,
    },
    TokenTerminal {
        status: i64,
        code: String,
    },
}

impl PushProviderOutcome {
    pub(crate) const fn kind(&self) -> &'static str {
        match self {
            Self::Accepted { .. } => "accepted",
            Self::Retry { .. } => "retry",
            Self::Ambiguous => "ambiguous",
            Self::Failed { .. } => "failed",
            Self::TokenTerminal { .. } => "token_terminal",
        }
    }

    pub(crate) fn fields(&self) -> (Option<i64>, Option<&str>, Option<&str>) {
        match self {
            Self::Accepted { status } => (Some(*status), None, None),
            Self::Retry {
                status,
                code,
                retry_at,
            } => (*status, Some(code), Some(retry_at)),
            Self::Ambiguous => (None, None, None),
            Self::Failed { status, code } => (*status, Some(code), None),
            Self::TokenTerminal { status, code } => (Some(*status), Some(code), None),
        }
    }

    pub(crate) fn is_valid(&self) -> bool {
        let status_valid = |status: i64| (100..=599).contains(&status);
        let code_valid = |code: &str| valid_fence_text(code, 256);
        match self {
            Self::Accepted { status } | Self::TokenTerminal { status, .. }
                if !status_valid(*status) =>
            {
                false
            }
            Self::Retry {
                status,
                code,
                retry_at,
            } => {
                status.is_none_or(status_valid)
                    && code_valid(code)
                    && valid_fence_timestamp(retry_at)
            }
            Self::Failed { status, code } => status.is_none_or(status_valid) && code_valid(code),
            Self::TokenTerminal { code, .. } => code_valid(code),
            Self::Accepted { status } => *status == 200,
            Self::Ambiguous => true,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct PushProviderReceipt {
    pub(crate) outcome: PushProviderOutcome,
    pub(crate) outcome_at: String,
}

impl PushProviderReceipt {
    pub(crate) fn new(outcome: PushProviderOutcome, outcome_at: String) -> Result<Self> {
        if !outcome.is_valid() || !valid_fence_timestamp(&outcome_at) {
            return Err(EnclaveError::Store(
                "push provider receipt is invalid".into(),
            ));
        }
        Ok(Self {
            outcome,
            outcome_at,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum PushFenceOutcome {
    Provider(PushProviderOutcome),
    Cancellation(PushControlCancellation),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct PushSendFence {
    pub(crate) user_id: String,
    pub(crate) installation_id: String,
    pub(crate) token_generation: i64,
    pub(crate) claim_id: String,
    pub(crate) lease_expires_at: String,
    pub(crate) outcome: Option<PushFenceOutcome>,
    pub(crate) outcome_at: Option<String>,
}

pub(crate) enum PushSendFenceDisposition {
    Authorized(PushInstallation),
    DeletionOwned,
    Recorded(PushSendFence),
}

/// Durable provider-send authority shared by every application process.
///
/// No method holds a database transaction over provider I/O. Callers first
/// acquire an exact disclosure capability, execute the provider request, then
/// persist and reconcile its typed outcome.
#[async_trait]
pub(crate) trait WorkRepository: Send + Sync {
    async fn active_account_ids(&self) -> Result<Vec<String>>;
    async fn summarized_until(&self, account_id: &str) -> Result<Option<String>>;
    async fn set_summarized_until(&self, account_id: &str, value: &str) -> Result<()>;

    async fn webhook_outbox_deletion_owned(&self, account_id: &str) -> Result<bool>;
    async fn begin_webhook_send_fence(
        &self,
        requested: &WebhookSendFence,
        decision_at: &str,
    ) -> Result<WebhookSendFenceDisposition>;
    async fn get_webhook_send_fence(
        &self,
        account_id: &str,
        event_id: &str,
    ) -> Result<Option<WebhookSendFence>>;
    async fn list_webhook_send_fences(&self, account_id: &str) -> Result<Vec<WebhookSendFence>>;
    async fn validate_webhook_send_fence(
        &self,
        fence: &WebhookSendFence,
        minimum_valid_at_millis: i64,
    ) -> Result<bool>;
    async fn record_webhook_send_outcome(
        &self,
        fence: &WebhookSendFence,
        outcome: WebhookProviderOutcome,
        outcome_at: &str,
    ) -> Result<()>;
    async fn close_webhook_send_fence(&self, fence: &WebhookSendFence) -> Result<()>;

    async fn email_outbox_deletion_owned(&self, account_id: &str) -> Result<bool>;
    async fn begin_email_send_fence(
        &self,
        requested: &EmailSendFence,
        decision_at: &str,
    ) -> Result<EmailSendFenceDisposition>;
    async fn get_email_send_fence(
        &self,
        account_id: &str,
        delivery_id: &str,
    ) -> Result<Option<EmailSendFence>>;
    async fn list_email_send_fences(&self, account_id: &str) -> Result<Vec<EmailSendFence>>;
    async fn validate_email_send_fence(
        &self,
        fence: &EmailSendFence,
        minimum_valid_at_millis: i64,
    ) -> Result<bool>;
    async fn record_email_send_outcome(
        &self,
        fence: &EmailSendFence,
        outcome: EmailProviderOutcome,
        outcome_at: &str,
    ) -> Result<()>;
    async fn finish_email_send_fence(
        &self,
        fence: &EmailSendFence,
        archive_outcome: EmailFenceOutcome,
    ) -> Result<()>;

    async fn push_outbox_deletion_owned(&self, account_id: &str) -> Result<bool>;
    async fn begin_push_send_fence(
        &self,
        account_id: &str,
        installation_id: &str,
        token_generation: i64,
        claim_id: &str,
        lease_expires_at: &str,
        decision_at: &str,
    ) -> Result<PushSendFenceDisposition>;
    async fn get_push_send_fence(
        &self,
        account_id: &str,
        installation_id: &str,
    ) -> Result<Option<PushSendFence>>;
    async fn list_push_send_fences(&self, account_id: &str) -> Result<Vec<PushSendFence>>;
    async fn validate_push_send_fence(
        &self,
        account_id: &str,
        installation_id: &str,
        token_generation: i64,
        claim_id: &str,
        lease_expires_at: &str,
        minimum_valid_at_millis: i64,
    ) -> Result<bool>;
    async fn record_push_send_outcome(
        &self,
        account_id: &str,
        installation_id: &str,
        token_generation: i64,
        claim_id: &str,
        lease_expires_at: &str,
        receipt: PushProviderReceipt,
    ) -> Result<()>;
    async fn finish_push_send_fence(
        &self,
        fence: &PushSendFence,
        archive_outcome: PushProviderOutcome,
    ) -> Result<()>;
    async fn finish_push_cancellation_fence(
        &self,
        fence: &PushSendFence,
        cancellation: PushControlCancellation,
    ) -> Result<()>;
}

pub(crate) fn valid_claim_id(value: &str) -> bool {
    value.len() == 36
        && value.bytes().enumerate().all(|(index, byte)| {
            if matches!(index, 8 | 13 | 18 | 23) {
                byte == b'-'
            } else {
                byte.is_ascii_hexdigit()
            }
        })
}

pub(crate) fn valid_fence_text(value: &str, maximum: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum
        && !value
            .bytes()
            .any(|byte| byte == 0 || byte.is_ascii_control())
}

pub(crate) fn valid_fence_timestamp(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && isotime::parse_epoch_millis(value)
            .is_some_and(|millis| isotime::format_epoch_millis(millis) == value)
}
