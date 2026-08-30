use async_trait::async_trait;

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
    DeletionRequested,
    Deleting,
    Deleted,
    Unavailable,
}

impl AccountStatus {
    pub(super) fn from_database(value: &str) -> Self {
        match value {
            "active" => Self::Active,
            "deletion_requested" => Self::DeletionRequested,
            "deleting" => Self::Deleting,
            "deleted" => Self::Deleted,
            _ => Self::Unavailable,
        }
    }
}

/// One coherent account/session view returned to first-party clients.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct AccountSession {
    pub(crate) account: Account,
    pub(crate) providers: Vec<String>,
}

/// A server-verified Apple authorization grant ready for durable settlement.
///
/// Deliberately does not implement `Debug`: the refresh token must never be
/// formatted into logs, panic messages, or test failure output.
pub(crate) struct AppleAccountGrant {
    pub(crate) subject: String,
    pub(crate) email: String,
    pub(crate) client_id: String,
    pub(crate) refresh_token: String,
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

    async fn upsert_apple_account(
        &self,
        grant: AppleAccountGrant,
        signup_limit_per_day: i64,
    ) -> Result<Account>;

    async fn link_apple_identity(&self, account_id: &str, grant: AppleAccountGrant) -> Result<()>;

    async fn account_session(&self, account_id: &str) -> Result<Option<AccountSession>>;
}
