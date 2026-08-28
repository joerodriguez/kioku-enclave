//! Account-wide durable-recording retention settings.
//!
//! The HTTP surface is intentionally a two-step preview/confirm contract. A
//! preview is bound to a settled Control revision and a fingerprint of the
//! exact user-store recording inventory; the confirming request recomputes
//! that inventory while holding the same per-user lifecycle gate as capture.

use std::{sync::Arc, time::Duration};

use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Json, Response},
    routing::{get, post},
    Extension, Router,
};
use serde::Deserialize;
use serde_json::json;

use crate::error::EnclaveError;
use crate::persistence::{
    RecordingRetentionChangeRequest, RecordingRetentionInventory, RecordingRetentionPolicy,
    RecordingRetentionPreference, RECORDING_RETENTION_CONSENT_VERSION,
};

use super::{
    auth::{AuthEvidence, AuthUser},
    CpState,
};

const RECENT_DESTRUCTIVE_AUTH_MAX_AGE: Duration = Duration::from_secs(10 * 60);
const RECONCILE_INTERVAL: Duration = Duration::from_secs(60);
const RECONCILE_BATCH_SIZE: usize = 8;

pub fn router() -> Router<Arc<CpState>> {
    Router::new()
        .route(
            "/api/v2/settings/recording-retention",
            get(get_recording_retention),
        )
        .route(
            "/api/v2/settings/recording-retention/preview",
            post(preview_recording_retention),
        )
        .route(
            "/api/v2/settings/recording-retention/changes",
            post(change_recording_retention),
        )
        .route(
            "/api/v2/settings/recording-retention/changes/{operation_id}",
            get(get_recording_retention_change),
        )
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RetentionPreviewRequest {
    target_policy: RecordingRetentionPolicy,
    expected_revision: i64,
    consent_version: i64,
    #[serde(default)]
    promote_existing: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RetentionChangeRequest {
    preview_id: String,
    target_policy: RecordingRetentionPolicy,
    expected_revision: i64,
    consent_version: i64,
    #[serde(default)]
    promote_existing: bool,
}

fn no_store_json(status: StatusCode, value: serde_json::Value) -> Response {
    (
        status,
        [
            ("cache-control", "private, no-store, max-age=0"),
            ("pragma", "no-cache"),
        ],
        Json(value),
    )
        .into_response()
}

fn retention_error(error: EnclaveError) -> Response {
    match error {
        EnclaveError::InvalidRequest(message) => {
            no_store_json(StatusCode::BAD_REQUEST, json!({"error": message}))
        }
        EnclaveError::Conflict(message) => {
            no_store_json(StatusCode::CONFLICT, json!({"error": message}))
        }
        EnclaveError::NotFound => {
            no_store_json(StatusCode::NOT_FOUND, json!({"error": "not_found"}))
        }
        EnclaveError::Auth(_) => {
            no_store_json(StatusCode::UNAUTHORIZED, json!({"error": "unauthorized"}))
        }
        error => {
            tracing::error!(error = %error, "recording retention request failed");
            no_store_json(
                StatusCode::SERVICE_UNAVAILABLE,
                json!({"error": "enclave_unavailable"}),
            )
        }
    }
}

fn retention_response(
    state: &CpState,
    preference: &RecordingRetentionPreference,
    inventory: &RecordingRetentionInventory,
) -> serde_json::Value {
    json!({
        "capability": {
            "id": "recording_retention_v1",
            "available": durable_recording_retention_available(state),
            "consent_version": RECORDING_RETENTION_CONSENT_VERSION,
            "prospective_enablement": true,
            "promotion_available": false,
        },
        "policy": preference.policy,
        "consent_version": preference.consent_version,
        "revision": preference.revision,
        "policy_epoch": preference.policy_epoch,
        "effective_at": preference.effective_at,
        "revocation_cutoff": preference.revocation_cutoff,
        "active_operation": preference.active_operation_id.as_ref().map(|operation_id| json!({
            "operation_id": operation_id,
            "state": preference.operation_state,
        })),
        "inventory": inventory,
    })
}

fn durable_recording_retention_available(state: &CpState) -> bool {
    state.durable_recording_storage_bound
}

async fn get_recording_retention(
    State(state): State<Arc<CpState>>,
    Extension(user): Extension<AuthUser>,
) -> Response {
    let preference = match state
        .repositories
        .recording_retention()
        .preference(&user.0)
        .await
    {
        Ok(preference) => preference,
        Err(error) => return retention_error(error),
    };
    let inventory = match state
        .repositories
        .recording_retention()
        .inventory(&user.0, &preference)
        .await
    {
        Ok(inventory) => inventory,
        Err(error) => return retention_error(error),
    };
    no_store_json(
        StatusCode::OK,
        retention_response(&state, &preference, &inventory),
    )
}

async fn preview_recording_retention(
    State(state): State<Arc<CpState>>,
    Extension(user): Extension<AuthUser>,
    Json(request): Json<RetentionPreviewRequest>,
) -> Response {
    if request.target_policy == RecordingRetentionPolicy::UntilDeleted
        && !durable_recording_retention_available(&state)
    {
        return no_store_json(
            StatusCode::PRECONDITION_FAILED,
            json!({"error": "recording_retention_unavailable"}),
        );
    }
    let preference = match state
        .repositories
        .recording_retention()
        .preference(&user.0)
        .await
    {
        Ok(preference) => preference,
        Err(error) => return retention_error(error),
    };
    let inventory = match state
        .repositories
        .recording_retention()
        .inventory(&user.0, &preference)
        .await
    {
        Ok(inventory) => inventory,
        Err(error) => return retention_error(error),
    };
    match state
        .repositories
        .recording_retention()
        .create_preview(
            &user.0,
            request.target_policy,
            request.expected_revision,
            request.consent_version,
            request.promote_existing,
            inventory,
        )
        .await
    {
        Ok(preview) => no_store_json(StatusCode::OK, json!(preview)),
        Err(error) => retention_error(error),
    }
}

async fn change_recording_retention(
    State(state): State<Arc<CpState>>,
    Extension(user): Extension<AuthUser>,
    evidence: Option<Extension<AuthEvidence>>,
    headers: HeaderMap,
    Json(request): Json<RetentionChangeRequest>,
) -> Response {
    if request.target_policy == RecordingRetentionPolicy::UntilDeleted
        && !durable_recording_retention_available(&state)
    {
        return no_store_json(
            StatusCode::PRECONDITION_FAILED,
            json!({"error": "recording_retention_unavailable"}),
        );
    }
    if request.target_policy == RecordingRetentionPolicy::ProcessingWindow30d
        && !evidence
            .map(|Extension(value)| value.is_recent_provider_auth(RECENT_DESTRUCTIVE_AUTH_MAX_AGE))
            .unwrap_or(false)
    {
        return no_store_json(
            StatusCode::PRECONDITION_REQUIRED,
            json!({
                "error": "recent_authentication_required",
                "max_age_seconds": RECENT_DESTRUCTIVE_AUTH_MAX_AGE.as_secs(),
            }),
        );
    }
    let Some(idempotency_key) = headers
        .get("idempotency-key")
        .and_then(|value| value.to_str().ok())
    else {
        return no_store_json(
            StatusCode::BAD_REQUEST,
            json!({"error": "idempotency_key_required"}),
        );
    };

    let preference = match state
        .repositories
        .recording_retention()
        .preference(&user.0)
        .await
    {
        Ok(preference) => preference,
        Err(error) => return retention_error(error),
    };
    let inventory = match state
        .repositories
        .recording_retention()
        .inventory(&user.0, &preference)
        .await
    {
        Ok(inventory) => inventory,
        Err(error) => return retention_error(error),
    };
    let change = match state
        .repositories
        .recording_retention()
        .change_policy(
            &user.0,
            RecordingRetentionChangeRequest {
                policy: request.target_policy,
                expected_revision: request.expected_revision,
                consent_version: request.consent_version,
                promote_existing: request.promote_existing,
                preview_id: &request.preview_id,
                inventory,
                idempotency_key,
            },
        )
        .await
    {
        Ok(change) => change,
        Err(error) => return retention_error(error),
    };

    if change.policy == RecordingRetentionPolicy::UntilDeleted {
        let preference = match state
            .repositories
            .recording_retention()
            .preference(&user.0)
            .await
        {
            Ok(preference) => preference,
            Err(error) => return retention_error(error),
        };
        let Some(policy_epoch) = preference.policy_epoch.as_deref() else {
            return retention_error(EnclaveError::Store(
                "durable recording policy lost its key epoch".into(),
            ));
        };
        let candidate = match crate::crypto::generate_and_wrap_dek(state.kms.as_ref()).await {
            Ok((_, wrapped)) => wrapped,
            Err(error) => return retention_error(error),
        };
        if let Err(error) = state
            .repositories
            .recording_retention()
            .install_key_epoch(&user.0, preference.revision, policy_epoch, &candidate)
            .await
        {
            return retention_error(error);
        }
        return no_store_json(StatusCode::OK, json!(change));
    }

    let completion = match state
        .repositories
        .media_objects()
        .purge_recordings(&user.0)
        .await
    {
        Ok(()) => {
            state
                .repositories
                .recording_retention()
                .complete_downgrade(&user.0, &change.operation_id)
                .await
        }
        Err(error) => Err(error),
    };
    match completion {
        Ok(completed) => no_store_json(StatusCode::OK, json!(completed)),
        Err(error) => {
            tracing::warn!(error = %error, "recording retention deletion remains pending");
            no_store_json(StatusCode::ACCEPTED, json!(change))
        }
    }
}

async fn get_recording_retention_change(
    State(state): State<Arc<CpState>>,
    Extension(user): Extension<AuthUser>,
    Path(operation_id): Path<String>,
) -> Response {
    match state
        .repositories
        .recording_retention()
        .change(&user.0, &operation_id)
        .await
    {
        Ok(Some(change)) => no_store_json(StatusCode::OK, json!(change)),
        Ok(None) => no_store_json(StatusCode::NOT_FOUND, json!({"error": "not_found"})),
        Err(error) => retention_error(error),
    }
}

pub(crate) fn spawn_reconciler(state: Arc<CpState>) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(RECONCILE_INTERVAL);
        loop {
            interval.tick().await;
            let pending = match state
                .repositories
                .recording_retention()
                .pending_changes(RECONCILE_BATCH_SIZE)
                .await
            {
                Ok(pending) => pending,
                Err(error) => {
                    tracing::warn!(error = %error, "recording retention reconciliation scan failed");
                    continue;
                }
            };
            for (user_id, operation_id) in pending {
                let result = match state
                    .repositories
                    .media_objects()
                    .purge_recordings(&user_id)
                    .await
                {
                    Ok(()) => {
                        state
                            .repositories
                            .recording_retention()
                            .complete_downgrade(&user_id, &operation_id)
                            .await
                    }
                    Err(error) => Err(error),
                };
                if let Err(error) = result {
                    tracing::warn!(error = %error, "recording retention reconciliation deferred");
                }
            }
        }
    });
}
