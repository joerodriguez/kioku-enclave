use async_trait::async_trait;

use crate::error::Result;

/// Content-free, durable status for an account-deletion operation.
#[derive(Debug, Clone, serde::Serialize, PartialEq, Eq)]
pub struct AccountDeletionOperation {
    pub operation_id: String,
    pub status: String,
    pub reason: String,
    pub retry_after_seconds: Option<u64>,
    pub hard_delete_time: Option<String>,
}

/// Account tombstoning and identity cleanup shared by routes and workers.
///
/// Content/media deletion happens between `begin_account_deletion` and
/// `finalize_account_deletion`. Both boundary transitions are transactional,
/// durable, and refuse while an exact provider disclosure fence is open.
#[async_trait]
pub(crate) trait AccountLifecycleRepository: Send + Sync {
    async fn account_deletion_operation(
        &self,
        account_id: &str,
    ) -> Result<Option<AccountDeletionOperation>>;

    async fn begin_account_deletion(
        &self,
        account_id: &str,
    ) -> Result<Option<AccountDeletionOperation>>;

    async fn update_account_deletion_status(
        &self,
        account_id: &str,
        reason: &str,
        retry_after_seconds: Option<u64>,
        hard_delete_time: Option<&str>,
    ) -> Result<AccountDeletionOperation>;

    async fn finalize_account_deletion(&self, account_id: &str)
        -> Result<AccountDeletionOperation>;

    async fn deleting_account_ids(&self, limit: usize) -> Result<Vec<String>>;

    /// Return only live Apple refresh credentials needed for provider
    /// revocation immediately before content deletion.
    async fn apple_refresh_credentials(&self, account_id: &str) -> Result<Vec<(String, String)>>;

    async fn mark_apple_credential_revoked(&self, account_id: &str, client_id: &str) -> Result<()>;
}
