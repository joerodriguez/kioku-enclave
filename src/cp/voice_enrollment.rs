//! Authenticated owner-voice settings. Enrollment itself is an ordinary capture session.

use std::sync::Arc;

use axum::{
    extract::State,
    http::{header, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    routing::get,
    Extension, Json, Router,
};
use serde_json::json;

use crate::{
    error::{EnclaveError, Result},
    persistence::OwnerVoiceEnrollmentStatus,
};

use super::{auth::AuthUser, CpState};

pub(crate) fn router() -> Router<Arc<CpState>> {
    Router::new().route(
        "/api/voice/enrollment",
        get(enrollment_status).delete(forget_enrollment),
    )
}

async fn enrollment_status(
    State(state): State<Arc<CpState>>,
    Extension(user): Extension<AuthUser>,
) -> Response {
    enrollment_response(
        state
            .repositories
            .voice_identity()
            .owner_voice_enrollment_status(&user.0)
            .await,
    )
}

async fn forget_enrollment(
    State(state): State<Arc<CpState>>,
    Extension(user): Extension<AuthUser>,
) -> Response {
    enrollment_response(
        state
            .repositories
            .voice_identity()
            .forget_owner_voice_enrollment(&user.0)
            .await,
    )
}

fn enrollment_response(result: Result<OwnerVoiceEnrollmentStatus>) -> Response {
    let mut response = match result {
        Ok(status) => Json(status).into_response(),
        Err(EnclaveError::NotFound) => {
            (StatusCode::NOT_FOUND, Json(json!({"error": "not_found"}))).into_response()
        }
        Err(EnclaveError::Auth(_)) => (
            StatusCode::UNAUTHORIZED,
            Json(json!({"error": "unauthorized"})),
        )
            .into_response(),
        Err(error) => super::routed_read_unavailable("owner_voice_enrollment", &error),
    };
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("private, no-store, max-age=0"),
    );
    response
        .headers_mut()
        .insert(header::PRAGMA, HeaderValue::from_static("no-cache"));
    response
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn enrollment_settings_do_not_cache_status_or_expose_storage_errors() {
        let response = enrollment_response(Ok(OwnerVoiceEnrollmentStatus {
            enrollment_revision: 3,
            domains: vec![],
            latest_attempt: None,
        }));
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers().get(header::CACHE_CONTROL).unwrap(),
            "private, no-store, max-age=0",
            "owner voice status must not survive in an HTTP cache after Forget"
        );
        let body = axum::body::to_bytes(response.into_body(), 4096)
            .await
            .unwrap();
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&body).unwrap(),
            json!({"enrollment_revision": 3, "domains": [], "latest_attempt": null}),
            "settings expose only enrollment status and the withdrawal revision"
        );

        let response = enrollment_response(Err(EnclaveError::Store(
            "private observation and profile details".into(),
        )));
        assert_eq!(
            response.status(),
            StatusCode::SERVICE_UNAVAILABLE,
            "an unreadable enrollment is unavailable, not an empty successful status"
        );
        assert_eq!(
            response.headers().get(header::CACHE_CONTROL).unwrap(),
            "private, no-store, max-age=0",
            "failed owner voice responses must also be uncacheable"
        );
        let body = axum::body::to_bytes(response.into_body(), 4096)
            .await
            .unwrap();
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&body).unwrap(),
            json!({"error": "enclave_unavailable"}),
            "public enrollment errors must not contain storage or biometric details"
        );
    }
}
