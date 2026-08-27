use std::sync::Arc;

use async_trait::async_trait;

use crate::{
    error::Result,
    persistence::MediaObjectStore,
    store::{GcsGetResponse, Store},
};

pub(crate) struct LegacyMediaObjectStore {
    store: Arc<Store>,
}

impl LegacyMediaObjectStore {
    pub(crate) fn new(store: Arc<Store>) -> Self {
        Self { store }
    }
}

#[async_trait]
impl MediaObjectStore for LegacyMediaObjectStore {
    async fn put_current(
        &self,
        account_id: &str,
        object_name: &str,
        ciphertext: &[u8],
        wrapped_dek_b64: &str,
    ) -> Result<i64> {
        self.store
            .put_user_media(account_id, object_name, ciphertext, wrapped_dek_b64)
            .await
    }

    async fn get_compatible(&self, object_name: &str) -> Result<GcsGetResponse> {
        self.store.get_media(object_name).await
    }

    async fn get_current(&self, object_name: &str) -> Result<GcsGetResponse> {
        self.store.get_current_media(object_name).await
    }

    async fn get_current_generation(
        &self,
        object_name: &str,
        generation: i64,
    ) -> Result<GcsGetResponse> {
        self.store
            .get_current_media_generation(object_name, generation)
            .await
    }

    async fn delete_compatible(&self, object_name: &str) -> Result<()> {
        self.store.delete_media(object_name).await
    }

    async fn purge_account(&self, account_id: &str) -> Result<()> {
        self.store.delete_user(account_id).await
    }
}
