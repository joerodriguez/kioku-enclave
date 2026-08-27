use std::sync::Arc;

use async_trait::async_trait;

use crate::{
    cp::control_store::{
        ControlStore, RecordingKeyEpoch, RecordingRetentionChange, RecordingRetentionInventory,
        RecordingRetentionPolicy, RecordingRetentionPreference, RecordingRetentionPreview,
    },
    error::Result,
    persistence::{RecordingRetentionChangeRequest, RecordingRetentionRepository},
    store::Store,
};

pub(crate) struct LegacyRecordingRetentionRepository {
    control: Arc<ControlStore>,
    store: Arc<Store>,
}

impl LegacyRecordingRetentionRepository {
    pub(crate) fn new(control: Arc<ControlStore>, store: Arc<Store>) -> Self {
        Self { control, store }
    }
}

#[async_trait]
impl RecordingRetentionRepository for LegacyRecordingRetentionRepository {
    async fn preference(&self, account_id: &str) -> Result<RecordingRetentionPreference> {
        self.control
            .get_recording_retention_preference(account_id)
            .await
    }

    async fn inventory(
        &self,
        account_id: &str,
        preference: &RecordingRetentionPreference,
    ) -> Result<RecordingRetentionInventory> {
        let (policy_revision, policy_epoch) = match preference.policy {
            RecordingRetentionPolicy::UntilDeleted => (
                Some(preference.revision),
                Some(preference.policy_epoch.clone().ok_or_else(|| {
                    crate::error::EnclaveError::Store(
                        "durable recording policy lost its epoch".into(),
                    )
                })?),
            ),
            RecordingRetentionPolicy::ProcessingWindow30d
                if preference.operation_state.is_some() =>
            {
                (None, None)
            }
            RecordingRetentionPolicy::ProcessingWindow30d => {
                return Ok(crate::cp::retention::empty_recording_inventory());
            }
        };
        let account_id = account_id.to_owned();
        self.store
            .wal_authoritative_read(&account_id.clone(), move |connection| {
                crate::cp::retention::recording_inventory_conn(
                    connection,
                    &account_id,
                    policy_revision,
                    policy_epoch.as_deref(),
                )
            })
            .await
    }

    async fn create_preview(
        &self,
        account_id: &str,
        policy: RecordingRetentionPolicy,
        expected_revision: i64,
        consent_version: i64,
        promote_existing: bool,
        inventory: RecordingRetentionInventory,
    ) -> Result<RecordingRetentionPreview> {
        self.control
            .create_recording_retention_preview(
                account_id,
                policy,
                expected_revision,
                consent_version,
                promote_existing,
                inventory,
            )
            .await
    }

    async fn change_policy(
        &self,
        account_id: &str,
        request: RecordingRetentionChangeRequest<'_>,
    ) -> Result<RecordingRetentionChange> {
        self.control
            .change_recording_retention_policy(
                account_id,
                request.policy,
                request.expected_revision,
                request.consent_version,
                request.promote_existing,
                request.preview_id,
                request.inventory,
                request.idempotency_key,
            )
            .await
    }

    async fn change(
        &self,
        account_id: &str,
        operation_id: &str,
    ) -> Result<Option<RecordingRetentionChange>> {
        self.control
            .recording_retention_change(account_id, operation_id)
            .await
    }

    async fn pending_changes(&self, limit: usize) -> Result<Vec<(String, String)>> {
        self.control
            .pending_recording_retention_changes(limit)
            .await
    }

    async fn complete_downgrade(
        &self,
        account_id: &str,
        operation_id: &str,
    ) -> Result<RecordingRetentionChange> {
        self.control
            .reconcile_recording_retention_change(account_id, operation_id)
            .await
    }

    async fn install_key_epoch(
        &self,
        account_id: &str,
        policy_revision: i64,
        policy_epoch: &str,
        _candidate_wrapped_dek: &str,
    ) -> Result<RecordingKeyEpoch> {
        self.control
            .load_or_create_recording_key_epoch(account_id, policy_revision, policy_epoch)
            .await
    }

    async fn key_epoch(
        &self,
        account_id: &str,
        key_epoch: i64,
        policy_epoch: &str,
    ) -> Result<Option<RecordingKeyEpoch>> {
        self.control
            .recording_key_epoch(account_id, key_epoch, policy_epoch)
            .await
    }
}
