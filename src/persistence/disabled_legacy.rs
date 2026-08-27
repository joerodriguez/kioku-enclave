//! Fail-closed placeholders for legacy fields that remain in `CpState` while
//! the application finishes removing their concrete types. PostgreSQL mode
//! never gives these placeholders a provider client, so an accidentally
//! missed legacy call cannot read or mutate the old GCS authority.

use async_trait::async_trait;

use crate::{
    error::{EnclaveError, Result},
    store::{GcsClient, GcsGenerationCopy, GcsGetResponse, GcsListVersionsResponse},
};

#[derive(Debug, Default)]
pub(crate) struct DisabledLegacyGcs;

fn disabled<T>() -> Result<T> {
    Err(EnclaveError::Store(
        "legacy SQLite/GCS authority is disabled in PostgreSQL mode".into(),
    ))
}

#[async_trait]
impl GcsClient for DisabledLegacyGcs {
    async fn trusted_time_millis(&self, _: &str, _: i64) -> Result<i64> {
        disabled()
    }

    async fn get_object(&self, _: &str) -> Result<GcsGetResponse> {
        disabled()
    }

    async fn get_object_generation(&self, _: &str, _: i64) -> Result<GcsGetResponse> {
        disabled()
    }

    async fn put_object(&self, _: &str, _: &[u8], _: &str, _: i64) -> Result<i64> {
        disabled()
    }

    async fn copy_generation_if_absent(
        &self,
        _: &str,
        _: i64,
        _: &str,
    ) -> Result<GcsGenerationCopy> {
        disabled()
    }

    async fn delete_object(&self, _: &str) -> Result<()> {
        disabled()
    }

    async fn list_object_versions(
        &self,
        _: &str,
        _: Option<&str>,
    ) -> Result<GcsListVersionsResponse> {
        disabled()
    }

    async fn list_live_objects(&self, _: &str, _: Option<&str>) -> Result<GcsListVersionsResponse> {
        disabled()
    }

    async fn delete_object_generation(&self, _: &str, _: i64) -> Result<()> {
        disabled()
    }

    async fn list_soft_deleted_objects(
        &self,
        _: &str,
        _: Option<&str>,
    ) -> Result<GcsListVersionsResponse> {
        disabled()
    }
}
