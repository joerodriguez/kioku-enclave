use std::sync::Arc;

use async_trait::async_trait;

use crate::cp::control_store::ControlStore;
use crate::error::Result;

use super::super::identity::{
    Account, AccountSession, AccountStatus, AppleAccountGrant, IdentitySessionRepository,
};

/// Behavior-preserving adapter over the current encrypted control store.
pub(crate) struct LegacyIdentitySessionRepository {
    control: Arc<ControlStore>,
}

impl LegacyIdentitySessionRepository {
    pub(crate) fn new(control: Arc<ControlStore>) -> Self {
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

    async fn upsert_apple_account(
        &self,
        grant: AppleAccountGrant,
        signup_limit_per_day: i64,
    ) -> Result<Account> {
        let user = self
            .control
            .upsert_apple_user(
                &grant.subject,
                &grant.email,
                &grant.client_id,
                &grant.refresh_token,
                signup_limit_per_day,
            )
            .await?;
        Ok(Account {
            id: user.id,
            email: user.email,
        })
    }

    async fn link_apple_identity(&self, account_id: &str, grant: AppleAccountGrant) -> Result<()> {
        self.control
            .link_apple_identity(
                account_id,
                &grant.subject,
                &grant.email,
                &grant.client_id,
                &grant.refresh_token,
            )
            .await
    }

    async fn account_session(&self, account_id: &str) -> Result<Option<AccountSession>> {
        let Some(email) = self.control.user_email(account_id).await? else {
            return Ok(None);
        };
        let providers = self.control.linked_providers(account_id).await?;
        Ok(Some(AccountSession {
            account: Account {
                id: account_id.to_string(),
                email,
            },
            providers,
        }))
    }
}
