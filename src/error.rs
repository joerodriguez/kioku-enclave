use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;
use thiserror::Error;

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

    #[error("config error: {0}")]
    Config(String),

    #[error("invalid request: {0}")]
    InvalidRequest(String),

    #[error("not found")]
    NotFound,

    #[error("conflict: {0}")]
    Conflict(String),
}

impl IntoResponse for EnclaveError {
    fn into_response(self) -> Response {
        let (status, message) = match &self {
            EnclaveError::InvalidRequest(_) => (StatusCode::BAD_REQUEST, self.to_string()),
            EnclaveError::NotFound => (StatusCode::NOT_FOUND, self.to_string()),
            EnclaveError::Conflict(_) => (StatusCode::CONFLICT, self.to_string()),
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
