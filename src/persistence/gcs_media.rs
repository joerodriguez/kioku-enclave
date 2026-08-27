use std::sync::Arc;

use async_trait::async_trait;

use crate::{
    error::{EnclaveError, Result},
    persistence::MediaObjectStore,
    store::{GcsClient, GcsGetResponse},
};

/// GCS implementation used with PostgreSQL structured state.
pub(crate) struct GcsMediaObjectStore {
    current: Arc<dyn GcsClient>,
    legacy: Arc<dyn GcsClient>,
}

impl GcsMediaObjectStore {
    pub(crate) fn new(current: Arc<dyn GcsClient>, legacy: Arc<dyn GcsClient>) -> Self {
        Self { current, legacy }
    }
}

#[async_trait]
impl MediaObjectStore for GcsMediaObjectStore {
    async fn put_current(
        &self,
        _account_id: &str,
        object_name: &str,
        ciphertext: &[u8],
        wrapped_dek_b64: &str,
    ) -> Result<i64> {
        self.current
            .put_object(object_name, ciphertext, wrapped_dek_b64, 0)
            .await
    }

    async fn get_compatible(&self, object_name: &str) -> Result<GcsGetResponse> {
        match self.current.get_object(object_name).await {
            Ok(object) => Ok(object),
            Err(EnclaveError::NotFound) => self.legacy.get_object(object_name).await,
            Err(error) => Err(error),
        }
    }

    async fn get_current(&self, object_name: &str) -> Result<GcsGetResponse> {
        self.current.get_object(object_name).await
    }

    async fn get_current_generation(
        &self,
        object_name: &str,
        generation: i64,
    ) -> Result<GcsGetResponse> {
        if generation <= 0 {
            return Err(EnclaveError::Store(
                "canonical capture generation must be positive".into(),
            ));
        }
        self.current
            .get_object_generation(object_name, generation)
            .await
    }

    async fn delete_compatible(&self, object_name: &str) -> Result<()> {
        match self.current.delete_object(object_name).await {
            Ok(()) | Err(EnclaveError::NotFound) => {}
            Err(error) => return Err(error),
        }
        if !Arc::ptr_eq(&self.current, &self.legacy) {
            match self.legacy.delete_object(object_name).await {
                Ok(()) | Err(EnclaveError::NotFound) => {}
                Err(error) => return Err(error),
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::tests::FakeGcs;

    #[tokio::test]
    async fn current_writes_and_legacy_reads_are_explicit() {
        let current: Arc<dyn GcsClient> = Arc::new(FakeGcs::new());
        let legacy: Arc<dyn GcsClient> = Arc::new(FakeGcs::new());
        legacy
            .put_object("media/legacy", b"old", "wrapped-old", 0)
            .await
            .unwrap();
        let media = GcsMediaObjectStore::new(Arc::clone(&current), Arc::clone(&legacy));

        assert_eq!(
            media
                .get_compatible("media/legacy")
                .await
                .unwrap()
                .ciphertext,
            b"old"
        );
        let generation = media
            .put_current("account", "media/current", b"new", "wrapped-new")
            .await
            .unwrap();
        assert!(generation > 0);
        assert_eq!(
            media
                .get_current_generation("media/current", generation)
                .await
                .unwrap()
                .ciphertext,
            b"new"
        );
        media.delete_compatible("media/legacy").await.unwrap();
        assert!(matches!(
            legacy.get_object("media/legacy").await,
            Err(EnclaveError::NotFound)
        ));
    }
}
