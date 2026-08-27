use async_trait::async_trait;

use crate::{error::Result, store::GcsGetResponse};

/// Encrypted large-object storage. Structured ownership and processing state
/// live in the selected database; this port owns only exact GCS bytes and
/// generations.
#[async_trait]
pub(crate) trait MediaObjectStore: Send + Sync {
    async fn put_current(
        &self,
        account_id: &str,
        object_name: &str,
        ciphertext: &[u8],
        wrapped_dek_b64: &str,
    ) -> Result<i64>;

    async fn get_compatible(&self, object_name: &str) -> Result<GcsGetResponse>;
    async fn get_current(&self, object_name: &str) -> Result<GcsGetResponse>;
    async fn get_current_generation(
        &self,
        object_name: &str,
        generation: i64,
    ) -> Result<GcsGetResponse>;
    async fn delete_compatible(&self, object_name: &str) -> Result<()>;

    /// Delete and verify every GCS generation under this account's exact
    /// processing, legacy, and durable-recording prefixes.
    async fn purge_account(&self, account_id: &str) -> Result<()>;
}
