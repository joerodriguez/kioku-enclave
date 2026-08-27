use async_trait::async_trait;

use crate::{
    cp::control_store::{
        RecordingKeyEpoch, RecordingRetentionChange, RecordingRetentionInventory,
        RecordingRetentionPolicy, RecordingRetentionPreference, RecordingRetentionPreview,
    },
    error::Result,
};

#[derive(Debug, Clone)]
pub(crate) struct RecordingRetentionChangeRequest<'a> {
    pub(crate) policy: RecordingRetentionPolicy,
    pub(crate) expected_revision: i64,
    pub(crate) consent_version: i64,
    pub(crate) promote_existing: bool,
    pub(crate) preview_id: &'a str,
    pub(crate) inventory: RecordingRetentionInventory,
    pub(crate) idempotency_key: &'a str,
}

#[async_trait]
pub(crate) trait RecordingRetentionRepository: Send + Sync {
    async fn preference(&self, account_id: &str) -> Result<RecordingRetentionPreference>;
    async fn inventory(
        &self,
        account_id: &str,
        preference: &RecordingRetentionPreference,
    ) -> Result<RecordingRetentionInventory>;
    async fn create_preview(
        &self,
        account_id: &str,
        policy: RecordingRetentionPolicy,
        expected_revision: i64,
        consent_version: i64,
        promote_existing: bool,
        inventory: RecordingRetentionInventory,
    ) -> Result<RecordingRetentionPreview>;
    async fn change_policy(
        &self,
        account_id: &str,
        request: RecordingRetentionChangeRequest<'_>,
    ) -> Result<RecordingRetentionChange>;
    async fn change(
        &self,
        account_id: &str,
        operation_id: &str,
    ) -> Result<Option<RecordingRetentionChange>>;
    async fn pending_changes(&self, limit: usize) -> Result<Vec<(String, String)>>;
    async fn complete_downgrade(
        &self,
        account_id: &str,
        operation_id: &str,
    ) -> Result<RecordingRetentionChange>;
    async fn install_key_epoch(
        &self,
        account_id: &str,
        policy_revision: i64,
        policy_epoch: &str,
        candidate_wrapped_dek: &str,
    ) -> Result<RecordingKeyEpoch>;
    async fn key_epoch(
        &self,
        account_id: &str,
        key_epoch: i64,
        policy_epoch: &str,
    ) -> Result<Option<RecordingKeyEpoch>>;
}
