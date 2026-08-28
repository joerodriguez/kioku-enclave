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
}

impl DeletionPendingReason {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SoftDeleteRetention => "soft_delete_retention",
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

    #[error("PostgreSQL error: {0}")]
    Postgres(#[from] sqlx::Error),

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

    /// The service-wide daily new-account budget is exhausted. Existing
    /// accounts are unaffected; only creation is refused.
    #[error("signup limit reached")]
    SignupLimited,

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
        if matches!(self, EnclaveError::SignupLimited) {
            return (
                StatusCode::TOO_MANY_REQUESTS,
                Json(json!({"error": "signup_limit_reached"})),
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

#[cfg(test)]
mod tests {
    use super::*;

    async fn response_body(response: Response) -> serde_json::Value {
        let bytes = axum::body::to_bytes(response.into_body(), 4 * 1024)
            .await
            .expect("the error body is small and complete");
        serde_json::from_slice(&bytes).expect("the error body is JSON")
    }

    #[tokio::test]
    async fn internal_errors_remain_opaque() {
        let response = EnclaveError::Store("sensitive detail".into()).into_response();
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let body = response_body(response).await;
        assert_eq!(body["error"], "internal error");
    }

    #[tokio::test]
    async fn soft_delete_retention_is_a_retryable_conflict() {
        let response = EnclaveError::DeletionPending(DeletionPending {
            reason: DeletionPendingReason::SoftDeleteRetention,
            retry_after_seconds: Some(3600),
            hard_delete_time: Some("2099-01-01T00:00:00Z".into()),
        })
        .into_response();
        assert_eq!(response.status(), StatusCode::CONFLICT);
        assert_eq!(
            response_body(response).await["error"],
            "account deletion pending: soft_delete_retention"
        );
    }
}
