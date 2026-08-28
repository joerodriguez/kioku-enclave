use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error::{EnclaveError, Result};

pub const RECORDING_RETENTION_CONSENT_VERSION: i64 = 1;

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RecordingRetentionPolicy {
    ProcessingWindow30d,
    UntilDeleted,
}

impl RecordingRetentionPolicy {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ProcessingWindow30d => "processing_window_30d",
            Self::UntilDeleted => "until_deleted",
        }
    }

    pub(crate) fn from_db(value: &str) -> Result<Self> {
        match value {
            "processing_window_30d" => Ok(Self::ProcessingWindow30d),
            "until_deleted" => Ok(Self::UntilDeleted),
            _ => Err(EnclaveError::Store(
                "recording retention policy is invalid".into(),
            )),
        }
    }
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct RecordingRetentionPreference {
    pub policy: RecordingRetentionPolicy,
    pub consent_version: i64,
    pub revision: i64,
    pub policy_epoch: Option<String>,
    pub effective_at: String,
    pub revocation_cutoff: Option<String>,
    pub active_operation_id: Option<String>,
    pub operation_state: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct RecordingKeyEpoch {
    pub(crate) key_epoch: i64,
    pub(crate) policy_epoch: String,
    pub(crate) wrapped_dek_b64: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct RecordingRetentionInventory {
    pub inventory_fingerprint: String,
    pub object_count: i64,
    pub byte_count: i64,
    pub recording_count: i64,
}

impl RecordingRetentionInventory {
    pub(crate) fn empty() -> Self {
        Self {
            inventory_fingerprint: format!(
                "{:x}",
                Sha256::digest(b"kioku.recording-retention-inventory.v1\0")
            ),
            object_count: 0,
            byte_count: 0,
            recording_count: 0,
        }
    }

    pub(crate) fn validate(&self) -> Result<()> {
        if self.object_count < 0
            || self.byte_count < 0
            || self.recording_count < 0
            || self.inventory_fingerprint.len() != 64
            || !self
                .inventory_fingerprint
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit())
        {
            return Err(EnclaveError::InvalidRequest(
                "invalid recording retention inventory".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct RecordingRetentionPreview {
    pub preview_id: String,
    pub target_policy: RecordingRetentionPolicy,
    pub expected_revision: i64,
    pub consent_version: i64,
    pub promote_existing: bool,
    pub inventory: RecordingRetentionInventory,
    pub request_fingerprint: String,
    pub expires_at: String,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct RecordingRetentionChange {
    pub operation_id: String,
    pub policy: RecordingRetentionPolicy,
    pub revision: i64,
    pub state: String,
    pub updated_at: String,
}

pub(crate) fn valid_retention_idempotency_key(value: &str) -> bool {
    (8..=128).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
}

pub(crate) fn recording_retention_request_fingerprint(
    policy: RecordingRetentionPolicy,
    expected_revision: i64,
    consent_version: i64,
    promote_existing: bool,
    preview_id: &str,
    inventory_fingerprint: &str,
) -> String {
    let mut digest = Sha256::new();
    digest.update(b"kioku.recording-retention-change.v1\0");
    for value in [
        policy.as_str().as_bytes(),
        &expected_revision.to_be_bytes(),
        &consent_version.to_be_bytes(),
        &[u8::from(promote_existing)],
        preview_id.as_bytes(),
        inventory_fingerprint.as_bytes(),
    ] {
        digest.update((value.len() as u64).to_be_bytes());
        digest.update(value);
    }
    format!("{:x}", digest.finalize())
}

pub(crate) fn recording_retention_preview_fingerprint(
    policy: RecordingRetentionPolicy,
    expected_revision: i64,
    consent_version: i64,
    promote_existing: bool,
    inventory_fingerprint: &str,
) -> String {
    let mut digest = Sha256::new();
    digest.update(b"kioku.recording-retention-preview.v1\0");
    for value in [
        policy.as_str().as_bytes(),
        &expected_revision.to_be_bytes(),
        &consent_version.to_be_bytes(),
        &[u8::from(promote_existing)],
        inventory_fingerprint.as_bytes(),
    ] {
        digest.update((value.len() as u64).to_be_bytes());
        digest.update(value);
    }
    format!("{:x}", digest.finalize())
}

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
