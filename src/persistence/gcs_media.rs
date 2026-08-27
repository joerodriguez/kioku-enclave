use std::sync::Arc;

use async_trait::async_trait;

use crate::{
    error::{DeletionPending, DeletionPendingReason, EnclaveError, Result},
    persistence::MediaObjectStore,
    store::{GcsClient, GcsGetResponse},
};

const MAX_PURGE_PAGES: usize = 10_000;

async fn purge_prefix(gcs: &dyn GcsClient, prefix: &str) -> Result<Option<String>> {
    for _ in 0..MAX_PURGE_PAGES {
        let page = gcs.list_object_versions(prefix, None).await?;
        if page.versions.is_empty() {
            if page.next_page_token.is_some() {
                return Err(EnclaveError::Gcs(
                    "media version listing returned an empty partial page".into(),
                ));
            }
            break;
        }
        for version in page.versions {
            if !version.name.starts_with(prefix) || version.generation <= 0 {
                return Err(EnclaveError::Gcs(
                    "media version listing escaped its account prefix".into(),
                ));
            }
            gcs.delete_object_generation(&version.name, version.generation)
                .await?;
        }
    }
    let remaining = gcs.list_object_versions(prefix, None).await?;
    if !remaining.versions.is_empty() || remaining.next_page_token.is_some() {
        return Err(EnclaveError::Gcs(
            "media version deletion exceeded its bounded inventory".into(),
        ));
    }
    let live = gcs.list_live_objects(prefix, None).await?;
    if !live.versions.is_empty() || live.next_page_token.is_some() {
        return Err(EnclaveError::Gcs(
            "live account media remains after generation deletion".into(),
        ));
    }

    let mut page_token = None;
    let mut hard_delete_time: Option<String> = None;
    for _ in 0..MAX_PURGE_PAGES {
        let page = gcs
            .list_soft_deleted_objects(prefix, page_token.as_deref())
            .await?;
        for version in page.versions {
            if !version.name.starts_with(prefix) {
                return Err(EnclaveError::Gcs(
                    "soft-deleted media listing escaped its account prefix".into(),
                ));
            }
            if let Some(candidate) = version.hard_delete_time {
                if hard_delete_time
                    .as_ref()
                    .is_none_or(|current| candidate > *current)
                {
                    hard_delete_time = Some(candidate);
                }
            }
        }
        match page.next_page_token {
            None => return Ok(hard_delete_time),
            Some(next) if page_token.as_deref() != Some(next.as_str()) => page_token = Some(next),
            Some(_) => {
                return Err(EnclaveError::Gcs(
                    "soft-deleted media listing repeated a page cursor".into(),
                ));
            }
        }
    }
    Err(EnclaveError::Gcs(
        "soft-deleted media listing exceeded its page bound".into(),
    ))
}

/// GCS implementation used with PostgreSQL structured state.
#[allow(dead_code)]
pub(crate) struct GcsMediaObjectStore {
    current: Arc<dyn GcsClient>,
    legacy: Arc<dyn GcsClient>,
}

impl GcsMediaObjectStore {
    #[allow(dead_code)]
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

    async fn purge_recordings(&self, account_id: &str) -> Result<()> {
        crate::store::validate_user_id(account_id)?;
        let prefix = format!("recordings/{account_id}/");
        let providers = if Arc::ptr_eq(&self.current, &self.legacy) {
            vec![Arc::clone(&self.current)]
        } else {
            vec![Arc::clone(&self.current), Arc::clone(&self.legacy)]
        };
        let mut hard_delete_time: Option<String> = None;
        for provider in providers {
            if let Some(candidate) = purge_prefix(provider.as_ref(), &prefix).await? {
                if hard_delete_time
                    .as_ref()
                    .is_none_or(|current| candidate > *current)
                {
                    hard_delete_time = Some(candidate);
                }
            }
        }
        if hard_delete_time.is_some() {
            return Err(EnclaveError::DeletionPending(DeletionPending {
                reason: DeletionPendingReason::SoftDeleteRetention,
                retry_after_seconds: Some(3600),
                hard_delete_time,
            }));
        }
        Ok(())
    }

    async fn purge_account(&self, account_id: &str) -> Result<()> {
        crate::store::validate_user_id(account_id)?;
        let prefixes = [
            format!("raw/{account_id}/"),
            format!("media/{account_id}/"),
            format!("recordings/{account_id}/"),
        ];
        let providers = if Arc::ptr_eq(&self.current, &self.legacy) {
            vec![Arc::clone(&self.current)]
        } else {
            vec![Arc::clone(&self.current), Arc::clone(&self.legacy)]
        };
        let mut hard_delete_time: Option<String> = None;
        for provider in providers {
            for prefix in &prefixes {
                if let Some(candidate) = purge_prefix(provider.as_ref(), prefix).await? {
                    if hard_delete_time
                        .as_ref()
                        .is_none_or(|current| candidate > *current)
                    {
                        hard_delete_time = Some(candidate);
                    }
                }
            }
        }
        if hard_delete_time.is_some() {
            return Err(EnclaveError::DeletionPending(DeletionPending {
                reason: DeletionPendingReason::SoftDeleteRetention,
                retry_after_seconds: Some(3600),
                hard_delete_time,
            }));
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

    #[tokio::test]
    async fn account_purge_covers_every_owned_prefix_on_both_providers() {
        let current: Arc<dyn GcsClient> = Arc::new(FakeGcs::new());
        let legacy: Arc<dyn GcsClient> = Arc::new(FakeGcs::new());
        for (provider, name) in [
            (&current, "raw/account-1/capture.enc"),
            (&current, "recordings/account-1/audio.enc"),
            (&legacy, "media/account-1/legacy.enc"),
        ] {
            provider
                .put_object(name, b"ciphertext", "wrapped", 0)
                .await
                .unwrap();
        }
        current
            .put_object("raw/account-2/keep.enc", b"other", "wrapped", 0)
            .await
            .unwrap();
        let media = GcsMediaObjectStore::new(Arc::clone(&current), Arc::clone(&legacy));

        media.purge_account("account-1").await.unwrap();

        for (provider, prefix) in [
            (&current, "raw/account-1/"),
            (&current, "recordings/account-1/"),
            (&legacy, "media/account-1/"),
        ] {
            assert!(provider
                .list_object_versions(prefix, None)
                .await
                .unwrap()
                .versions
                .is_empty());
        }
        assert!(current.get_object("raw/account-2/keep.enc").await.is_ok());
    }
}
