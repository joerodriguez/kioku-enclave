use std::sync::Arc;

use async_trait::async_trait;

use crate::{
    cp::control_store::ControlStore,
    error::Result,
    persistence::{AccountDeletionOperation, AccountLifecycleRepository},
};

pub(crate) struct LegacyAccountLifecycleRepository {
    control: Arc<ControlStore>,
}

impl LegacyAccountLifecycleRepository {
    pub(crate) fn new(control: Arc<ControlStore>) -> Self {
        Self { control }
    }
}

#[async_trait]
impl AccountLifecycleRepository for LegacyAccountLifecycleRepository {
    async fn account_deletion_operation(
        &self,
        account_id: &str,
    ) -> Result<Option<AccountDeletionOperation>> {
        self.control.account_deletion_operation(account_id).await
    }

    async fn begin_account_deletion(
        &self,
        account_id: &str,
    ) -> Result<Option<AccountDeletionOperation>> {
        self.control.begin_user_deletion(account_id).await
    }

    async fn update_account_deletion_status(
        &self,
        account_id: &str,
        reason: &str,
        retry_after_seconds: Option<u64>,
        hard_delete_time: Option<&str>,
    ) -> Result<AccountDeletionOperation> {
        self.control
            .update_user_deletion_status(account_id, reason, retry_after_seconds, hard_delete_time)
            .await
    }

    async fn finalize_account_deletion(
        &self,
        account_id: &str,
    ) -> Result<AccountDeletionOperation> {
        self.control.finalize_user_deletion(account_id).await
    }

    async fn deleting_account_ids(&self, limit: usize) -> Result<Vec<String>> {
        self.control.deleting_user_ids(limit).await
    }

    async fn apple_refresh_credentials(&self, account_id: &str) -> Result<Vec<(String, String)>> {
        self.control.apple_refresh_credentials(account_id).await
    }

    async fn mark_apple_credential_revoked(&self, account_id: &str, client_id: &str) -> Result<()> {
        self.control
            .mark_apple_credential_revoked(account_id, client_id)
            .await
    }
}

// Legacy lifecycle tests and archive-deletion helpers already own a concrete
// `ControlStore`. Implementing the port on that type keeps those tests on the
// exact same transaction authority while serving code receives the private
// adapter through `RepositorySet`.
#[async_trait]
impl AccountLifecycleRepository for ControlStore {
    async fn account_deletion_operation(
        &self,
        account_id: &str,
    ) -> Result<Option<AccountDeletionOperation>> {
        ControlStore::account_deletion_operation(self, account_id).await
    }

    async fn begin_account_deletion(
        &self,
        account_id: &str,
    ) -> Result<Option<AccountDeletionOperation>> {
        self.begin_user_deletion(account_id).await
    }

    async fn update_account_deletion_status(
        &self,
        account_id: &str,
        reason: &str,
        retry_after_seconds: Option<u64>,
        hard_delete_time: Option<&str>,
    ) -> Result<AccountDeletionOperation> {
        self.update_user_deletion_status(account_id, reason, retry_after_seconds, hard_delete_time)
            .await
    }

    async fn finalize_account_deletion(
        &self,
        account_id: &str,
    ) -> Result<AccountDeletionOperation> {
        self.finalize_user_deletion(account_id).await
    }

    async fn deleting_account_ids(&self, limit: usize) -> Result<Vec<String>> {
        self.deleting_user_ids(limit).await
    }

    async fn apple_refresh_credentials(&self, account_id: &str) -> Result<Vec<(String, String)>> {
        ControlStore::apple_refresh_credentials(self, account_id).await
    }

    async fn mark_apple_credential_revoked(&self, account_id: &str, client_id: &str) -> Result<()> {
        ControlStore::mark_apple_credential_revoked(self, account_id, client_id).await
    }
}
