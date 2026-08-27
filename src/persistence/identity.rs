use std::sync::Arc;

use async_trait::async_trait;

use crate::cp::control_store::ControlStore;
use crate::error::Result;

/// The account fields required by authentication and session issuance.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Account {
    pub(crate) id: String,
    pub(crate) email: String,
}

/// Lifecycle states that affect authentication admission.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum AccountStatus {
    Active,
    Deleting,
    Deleted,
    Unavailable,
}

impl AccountStatus {
    fn from_legacy(value: &str) -> Self {
        match value {
            "active" => Self::Active,
            "deleting" => Self::Deleting,
            "deleted" => Self::Deleted,
            _ => Self::Unavailable,
        }
    }
}

/// Account and credential operations used by authentication/session flows.
///
/// Methods represent complete application operations. Implementations do not
/// expose a database connection or transaction callback to callers.
#[async_trait]
pub(crate) trait IdentitySessionRepository: Send + Sync {
    async fn account_status(&self, account_id: &str) -> Result<Option<AccountStatus>>;

    /// Create or refresh an account for a canonical, verified subject.
    ///
    /// Callers namespace non-consumer identities before this boundary. The
    /// subject, account derivation, signup-budget reservation, and identity
    /// record are one application transaction.
    async fn upsert_subject_account(
        &self,
        subject: &str,
        email: &str,
        signup_limit_per_day: i64,
    ) -> Result<Account>;
}

/// Behavior-preserving adapter over the current encrypted control store.
pub(super) struct LegacyIdentitySessionRepository {
    control: Arc<ControlStore>,
}

impl LegacyIdentitySessionRepository {
    pub(super) fn new(control: Arc<ControlStore>) -> Self {
        Self { control }
    }
}

#[async_trait]
impl IdentitySessionRepository for LegacyIdentitySessionRepository {
    async fn account_status(&self, account_id: &str) -> Result<Option<AccountStatus>> {
        Ok(self
            .control
            .user_status(account_id)
            .await?
            .as_deref()
            .map(AccountStatus::from_legacy))
    }

    async fn upsert_subject_account(
        &self,
        subject: &str,
        email: &str,
        signup_limit_per_day: i64,
    ) -> Result<Account> {
        let user = self
            .control
            .upsert_user(subject, email, signup_limit_per_day)
            .await?;
        Ok(Account {
            id: user.id,
            email: user.email,
        })
    }
}
