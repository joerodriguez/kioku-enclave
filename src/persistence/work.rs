use async_trait::async_trait;

use crate::{cp::isotime, error::Result};

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
    pub(crate) fn is_valid(&self) -> bool {
        match self {
            Self::Sent { status } => (200..=299).contains(status),
            Self::Retry {
                status,
                code,
                retry_at,
            } => {
                status.is_none_or(|status| (100..=599).contains(&status))
                    && valid_provider_text(code, 256)
                    && valid_provider_timestamp(retry_at)
            }
            Self::Ambiguous => true,
            Self::Failed { status, code } => {
                status.is_none_or(|status| (100..=599).contains(&status))
                    && valid_provider_text(code, 256)
            }
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
    pub(crate) fn is_valid(&self) -> bool {
        match self {
            Self::Accepted {
                status,
                provider_message_id,
            } => (200..=299).contains(status) && valid_provider_text(provider_message_id, 512),
            Self::Retry {
                status,
                code,
                retry_at,
            } => {
                status.is_none_or(|status| (100..=599).contains(&status))
                    && valid_provider_text(code, 256)
                    && valid_provider_timestamp(retry_at)
            }
            Self::Ambiguous => true,
            Self::Failed { status, code } => {
                status.is_none_or(|status| (100..=599).contains(&status))
                    && valid_provider_text(code, 256)
            }
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
    pub(crate) fn is_valid(&self) -> bool {
        let status_valid = |status: i64| (100..=599).contains(&status);
        let code_valid = |code: &str| valid_provider_text(code, 256);
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
                    && valid_provider_timestamp(retry_at)
            }
            Self::Failed { status, code } => status.is_none_or(status_valid) && code_valid(code),
            Self::TokenTerminal { code, .. } => code_valid(code),
            Self::Accepted { status } => *status == 200,
            Self::Ambiguous => true,
        }
    }
}

/// Fleet-safe account enumeration and scheduler cursor storage.
#[async_trait]
pub(crate) trait WorkRepository: Send + Sync {
    async fn active_account_ids(&self) -> Result<Vec<String>>;
    async fn summarized_until(&self, account_id: &str) -> Result<Option<String>>;
    async fn set_summarized_until(&self, account_id: &str, value: &str) -> Result<()>;
}

fn valid_provider_text(value: &str, maximum: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum
        && !value
            .bytes()
            .any(|byte| byte == 0 || byte.is_ascii_control())
}

fn valid_provider_timestamp(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && isotime::parse_epoch_millis(value)
            .is_some_and(|millis| isotime::format_epoch_millis(millis) == value)
}
