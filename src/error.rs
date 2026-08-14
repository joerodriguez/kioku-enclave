use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;
use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeletionPendingReason {
    SoftDeleteRetention,
    LegacySnapshotTooLarge,
    LegacyGenerationUnavailable,
    LegacyInventoryIncomplete,
    LegacyWriteIntentUnsettled,
}

impl DeletionPendingReason {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SoftDeleteRetention => "soft_delete_retention",
            Self::LegacySnapshotTooLarge => "legacy_snapshot_too_large",
            Self::LegacyGenerationUnavailable => "legacy_generation_unavailable",
            Self::LegacyInventoryIncomplete => "legacy_inventory_incomplete",
            Self::LegacyWriteIntentUnsettled => "legacy_write_intent_unsettled",
        }
    }
}

impl std::fmt::Display for DeletionPendingReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CaptureReferenceFailureReason {
    CanonicalUnavailable,
    ContextFingerprintMismatch,
    TargetMismatch,
    CanonicalContextUnavailable,
    ContextTransition,
}

impl CaptureReferenceFailureReason {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::CanonicalUnavailable => "canonical_unavailable",
            Self::ContextFingerprintMismatch => "context_fingerprint_mismatch",
            Self::TargetMismatch => "target_mismatch",
            Self::CanonicalContextUnavailable => "canonical_context_unavailable",
            Self::ContextTransition => "context_transition",
        }
    }
}

impl std::fmt::Display for CaptureReferenceFailureReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeletionPending {
    pub reason: DeletionPendingReason,
    pub retry_after_seconds: Option<u64>,
    pub hard_delete_time: Option<String>,
}

impl std::fmt::Display for DeletionPending {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "account deletion pending: {}", self.reason)
    }
}

#[derive(Debug, Error)]
pub enum EnclaveError {
    #[error("crypto error: {0}")]
    Crypto(String),

    #[error("store error: {0}")]
    Store(String),

    #[error("KMS error: {0}")]
    Kms(String),

    #[error("GCS error: {0}")]
    Gcs(String),

    #[error("database error: {0}")]
    Db(#[from] rusqlite::Error),

    #[error("serialisation error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("http client error: {0}")]
    Http(#[from] reqwest::Error),

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("attestation error: {0}")]
    Attestation(String),

    #[error("auth error: {0}")]
    Auth(String),

    #[error("embedding error: {0}")]
    Embedding(String),

    #[error("config error: {0}")]
    Config(String),

    #[error("invalid request: {0}")]
    InvalidRequest(String),

    #[error("screen reference must be rebased: {0}")]
    CaptureReference(CaptureReferenceFailureReason),

    #[error(
        "screen reference batch item {index} at sequence {sequence} must be rebased: {reason}"
    )]
    CaptureReferenceBatch {
        reason: CaptureReferenceFailureReason,
        index: usize,
        sequence: i64,
    },

    #[error("not found")]
    NotFound,

    #[error("conflict: {0}")]
    Conflict(String),

    #[error("{0}")]
    DeletionPending(DeletionPending),
}

impl IntoResponse for EnclaveError {
    fn into_response(self) -> Response {
        if let EnclaveError::CaptureReference(reason) = &self {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({
                    "error": "screen_reference_rebase_required",
                    "reason": reason.as_str(),
                })),
            )
                .into_response();
        }
        if let EnclaveError::CaptureReferenceBatch {
            reason,
            index,
            sequence,
        } = &self
        {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({
                    "error": "screen_reference_rebase_required",
                    "reason": reason.as_str(),
                    "index": index,
                    "sequence": sequence,
                })),
            )
                .into_response();
        }
        let (status, message) = match &self {
            EnclaveError::InvalidRequest(_) => (StatusCode::BAD_REQUEST, self.to_string()),
            EnclaveError::CaptureReference(_) | EnclaveError::CaptureReferenceBatch { .. } => {
                unreachable!("handled above")
            }
            EnclaveError::NotFound => (StatusCode::NOT_FOUND, self.to_string()),
            EnclaveError::Conflict(_) | EnclaveError::DeletionPending(_) => {
                (StatusCode::CONFLICT, self.to_string())
            }
            // Intentionally vague externally — log internally
            _ => {
                tracing::error!(error = %self, "internal enclave error");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "internal error".to_string(),
                )
            }
        };
        (status, Json(json!({ "error": message }))).into_response()
    }
}

pub type Result<T> = std::result::Result<T, EnclaveError>;
