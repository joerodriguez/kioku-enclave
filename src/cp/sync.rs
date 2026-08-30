//! Device sync tombstone, export, and PostgreSQL-authoritative account deletion.

use std::{sync::Arc, time::Duration};

use axum::{
    extract::State,
    http::{header, HeaderValue, StatusCode},
    response::{IntoResponse, Json, Response},
    routing::{delete, get, post},
    Extension, Router,
};
use serde_json::json;
use tracing::warn;

use crate::{
    error::{EnclaveError, Result as EnclaveResult},
    persistence::{AccountDeletionOperation, AccountLifecycleRepository, AccountStatus},
};

use super::{auth::AuthUser, CpState, ReviewerAuthConfig};

const DELETION_RECONCILE_INTERVAL: Duration = Duration::from_secs(300);
const DELETION_RECONCILE_BATCH_SIZE: usize = 64;
const DELETION_ATTEMPT_UNCONFIRMED: &str = "content_deletion_attempt_unconfirmed";

pub fn router() -> Router<Arc<CpState>> {
    Router::new()
        .route("/api/sync/batch", post(sync_batch_retired))
        .route("/api/sync/status", get(sync_status))
        .route("/api/export", get(export))
        .route("/api/account", delete(delete_account))
        .route("/api/account/deletion", get(account_deletion_status))
}

async fn sync_batch_retired() -> Response {
    (
        StatusCode::GONE,
        Json(json!({
            "error": "local_sync_retired",
            "message": "Update Kioku to record with cloud capture."
        })),
    )
        .into_response()
}

async fn sync_status(
    State(state): State<Arc<CpState>>,
    Extension(user): Extension<AuthUser>,
) -> Response {
    let email = state
        .repositories
        .identity_sessions()
        .account_session(&user.0)
        .await
        .ok()
        .flatten()
        .map(|session| session.account.email);
    match state
        .repositories
        .memory_queries()
        .capture_status(&user.0)
        .await
    {
        Ok(stats) => Json(json!({
            "email": email,
            "counts": {
                "utterances": stats.total_utterances,
                "screenshots": stats.total_screenshots,
                "episodes": stats.episode_count
            },
            "latest": {
                "utterance_at": stats.last_utterance_at,
                "screenshot_at": stats.last_screenshot_at
            },
        }))
        .into_response(),
        Err(error) => super::routed_read_unavailable("api.sync_status", &error),
    }
}

async fn export(
    State(state): State<Arc<CpState>>,
    Extension(user): Extension<AuthUser>,
) -> Response {
    match state.repositories.memory_queries().export(&user.0).await {
        Ok(data) => export_success_response(data),
        Err(error) => {
            warn!(error = %error, metric = super::ROUTED_READ_UNAVAILABLE_REASON, context = "api.export", "export failed");
            (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({"error": "export_failed"})),
            )
                .into_response()
        }
    }
}

fn export_success_response(data: serde_json::Value) -> Response {
    (
        [
            (
                header::CONTENT_TYPE,
                "application/json; charset=utf-8".to_string(),
            ),
            (
                header::CONTENT_DISPOSITION,
                "attachment; filename=\"kioku-export.json\"".to_string(),
            ),
        ],
        Json(data),
    )
        .into_response()
}

async fn delete_account(
    State(state): State<Arc<CpState>>,
    Extension(user): Extension<AuthUser>,
) -> Response {
    let user_id = user.0;
    if let Some(response) = reviewer_deletion_guard(state.config.reviewer_auth.as_ref(), &user_id) {
        return response;
    }
    let account_status = match state
        .repositories
        .identity_sessions()
        .account_status(&user_id)
        .await
    {
        Ok(Some(status)) => status,
        Ok(None) => return account_unavailable(),
        Err(error) => {
            warn!(error = %error, "failed to load account deletion status");
            return deletion_init_failed();
        }
    };
    if !matches!(
        account_status,
        AccountStatus::Active
            | AccountStatus::DeletionRequested
            | AccountStatus::Deleting
            | AccountStatus::Deleted
    ) {
        return account_unavailable();
    }
    if account_status == AccountStatus::Deleted {
        return match state
            .repositories
            .lifecycle()
            .account_deletion_operation(&user_id)
            .await
        {
            Ok(Some(operation)) => deletion_delete_response(operation),
            _ => account_unavailable(),
        };
    }

    // First commit the local deletion request. This closes account admission
    // without erasing identity/content and makes a lost billing-fence response
    // discoverable by the reconciler.
    let requested = match state
        .repositories
        .lifecycle()
        .request_account_deletion(&user_id)
        .await
    {
        Ok(Some(operation)) => operation,
        Ok(None) => return account_unavailable(),
        Err(error) => {
            warn!(error = %error, "failed to persist account deletion request");
            return deletion_init_failed();
        }
    };
    if requested.status == "physical_complete"
        || deletion_operation_requires_remediation(&requested)
    {
        return deletion_delete_response(requested);
    }
    match state
        .repositories
        .lifecycle()
        .account_deletion_preflight_complete(&user_id)
        .await
    {
        Ok(true) => {}
        Ok(false) => return deletion_delete_response(requested),
        Err(error) => {
            warn!(error = %error, "account deletion preflight is unavailable");
            return deletion_delete_response(requested);
        }
    }

    // Final usage settlement happens only after new local work is gated and
    // before the billing service's one-way deletion fence. Both remote steps
    // are idempotent; any failure leaves the durable request pending.
    if let Err(error) = state.settle_before_deletion(&user_id).await {
        warn!(error = %error, "failed to settle and fence billing before deletion");
        return deletion_delete_response(requested);
    }

    // Only after the billing fence is acknowledged does PostgreSQL transition
    // the durable request into the existing identity/content deletion flow.
    let operation = match state
        .repositories
        .lifecycle()
        .begin_account_deletion(&user_id)
        .await
    {
        Ok(Some(operation)) => operation,
        Ok(None) => return deletion_delete_response(requested),
        Err(error) => {
            warn!(error = %error, "failed to initialize account deletion");
            return deletion_delete_response(requested);
        }
    };
    if operation.status == "physical_complete"
        || deletion_operation_requires_remediation(&operation)
    {
        return deletion_delete_response(operation);
    }

    let operation = match state
        .repositories
        .lifecycle()
        .update_account_deletion_status(&user_id, DELETION_ATTEMPT_UNCONFIRMED, None, None)
        .await
    {
        Ok(operation) => operation,
        Err(_) => return deletion_delete_response(operation),
    };
    if revoke_apple_before_content_delete(
        state.repositories.lifecycle(),
        state.apple_provider.as_ref(),
        &user_id,
    )
    .await
    .is_err()
    {
        warn!("Apple credential revocation prerequisite unavailable during account deletion");
        return deletion_delete_response(operation);
    }

    if let Err(error) = state
        .repositories
        .media_objects()
        .purge_account(&user_id)
        .await
    {
        let (reason, retry_after_seconds, hard_delete_time) = deletion_failure(&error);
        let operation = persist_deletion_status(
            state.repositories.lifecycle(),
            &user_id,
            operation,
            reason,
            retry_after_seconds,
            hard_delete_time,
        )
        .await;
        return deletion_delete_response(operation);
    }

    match state
        .repositories
        .lifecycle()
        .finalize_account_deletion(&user_id)
        .await
    {
        Ok(operation) => deletion_delete_response(operation),
        Err(_) => {
            let operation = persist_deletion_status(
                state.repositories.lifecycle(),
                &user_id,
                operation,
                "identity_cleanup_in_progress",
                Some(30),
                None,
            )
            .await;
            deletion_delete_response(operation)
        }
    }
}

fn reviewer_deletion_guard(
    reviewer_auth: Option<&ReviewerAuthConfig>,
    account_id: &str,
) -> Option<Response> {
    let protected = reviewer_auth.is_some_and(|reviewer| reviewer.account_id() == account_id);
    if !protected {
        return None;
    }
    tracing::warn!(
        target: "kioku::reviewer",
        metric_schema = "reviewer_account_v1",
        stage = "account_deletion",
        outcome = "refused",
        "reviewer account deletion refused"
    );
    Some(
        (
            StatusCode::FORBIDDEN,
            Json(json!({"error": "reviewer_account_protected"})),
        )
            .into_response(),
    )
}

async fn account_deletion_status(
    State(state): State<Arc<CpState>>,
    Extension(user): Extension<AuthUser>,
) -> Response {
    match state
        .repositories
        .lifecycle()
        .account_deletion_operation(&user.0)
        .await
    {
        Ok(Some(operation)) => deletion_operation_response(StatusCode::OK, operation),
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(json!({"error": "deletion_not_started"})),
        )
            .into_response(),
        Err(_) => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"error": "deletion_status_unavailable"})),
        )
            .into_response(),
    }
}

async fn persist_deletion_status(
    lifecycle: &dyn AccountLifecycleRepository,
    user_id: &str,
    durable_fallback: AccountDeletionOperation,
    reason: &str,
    retry_after_seconds: Option<u64>,
    hard_delete_time: Option<&str>,
) -> AccountDeletionOperation {
    match lifecycle
        .update_account_deletion_status(user_id, reason, retry_after_seconds, hard_delete_time)
        .await
    {
        Ok(operation) => operation,
        Err(_) => durable_fallback,
    }
}

async fn revoke_apple_before_content_delete(
    lifecycle: &dyn AccountLifecycleRepository,
    apple_provider: Option<&Arc<super::apple::AppleIdentityProvider>>,
    user_id: &str,
) -> EnclaveResult<()> {
    let credentials = lifecycle.apple_refresh_credentials(user_id).await?;
    if credentials.is_empty() {
        return Ok(());
    }
    let provider = apple_provider.ok_or_else(|| {
        EnclaveError::Store("Apple credential revocation provider is unavailable".into())
    })?;
    for (client_id, refresh_token) in credentials {
        provider
            .revoke_refresh_token(&client_id, &refresh_token)
            .await
            .map_err(|_| EnclaveError::Store("Apple credential revocation failed".into()))?;
        lifecycle
            .mark_apple_credential_revoked(user_id, &client_id)
            .await?;
    }
    Ok(())
}

#[derive(Debug, Default, PartialEq, Eq)]
struct DeletionReconcileSummary {
    attempted: usize,
    completed: usize,
    pending: usize,
    failed_retryable: usize,
    failures: usize,
}

fn deletion_operation_requires_remediation(operation: &AccountDeletionOperation) -> bool {
    operation.status == "failed_retryable"
}

fn deletion_failure(error: &EnclaveError) -> (&str, Option<u64>, Option<&str>) {
    match error {
        EnclaveError::DeletionPending(pending) => (
            pending.reason.as_str(),
            pending.retry_after_seconds,
            pending.hard_delete_time.as_deref(),
        ),
        _ => ("content_store_unavailable", Some(30), None),
    }
}

async fn reconcile_pending_account_deletions(
    state: &CpState,
) -> EnclaveResult<DeletionReconcileSummary> {
    reconcile_pending_account_deletions_with(
        state.repositories.lifecycle(),
        state.repositories.media_objects(),
        state,
        state.apple_provider.as_ref(),
    )
    .await
}

#[async_trait::async_trait]
trait AccountDeletionAccounting: Send + Sync {
    async fn settle_before_deletion(&self, user_id: &str) -> EnclaveResult<()>;
}

#[async_trait::async_trait]
impl AccountDeletionAccounting for CpState {
    async fn settle_before_deletion(&self, user_id: &str) -> EnclaveResult<()> {
        let account_id = self
            .repositories
            .billing()
            .billing_account_id_for_deletion(user_id)
            .await?;
        let settlement =
            super::model_usage::settle_for_account_deletion(self, user_id, &account_id).await?;
        let fence = self
            .billing
            .deletion_fence(&account_id)
            .await
            .map_err(|error| {
                crate::error::EnclaveError::Config(format!(
                    "billing deletion fence unavailable: {error}"
                ))
            })?;
        if !fence.fenced {
            return Err(crate::error::EnclaveError::Config(
                "billing deletion fence returned an invalid response".into(),
            ));
        }
        if settlement == super::model_usage::AccountDeletionSettlement::AlreadyFenced {
            tracing::info!("billing deletion fence was already active during retry");
        }
        Ok(())
    }
}

async fn reconcile_pending_account_deletions_with(
    lifecycle: &dyn AccountLifecycleRepository,
    media_objects: &dyn crate::persistence::MediaObjectStore,
    accounting: &dyn AccountDeletionAccounting,
    apple_provider: Option<&Arc<super::apple::AppleIdentityProvider>>,
) -> EnclaveResult<DeletionReconcileSummary> {
    let user_ids = lifecycle
        .deleting_account_ids(DELETION_RECONCILE_BATCH_SIZE)
        .await?;
    let mut summary = DeletionReconcileSummary::default();
    for user_id in user_ids {
        summary.attempted += 1;
        let requested = match lifecycle.request_account_deletion(&user_id).await {
            Ok(Some(operation)) => operation,
            Ok(None) | Err(_) => {
                summary.failures += 1;
                continue;
            }
        };
        if requested.status == "physical_complete" {
            summary.failures += 1;
            continue;
        }
        if deletion_operation_requires_remediation(&requested) {
            summary.failed_retryable += 1;
            continue;
        }
        if !matches!(
            lifecycle
                .account_deletion_preflight_complete(&user_id)
                .await,
            Ok(true)
        ) {
            summary.pending += 1;
            continue;
        }
        if accounting.settle_before_deletion(&user_id).await.is_err() {
            summary.pending += 1;
            continue;
        }
        let operation = match lifecycle.begin_account_deletion(&user_id).await {
            Ok(Some(operation)) => operation,
            Ok(None) | Err(_) => {
                summary.pending += 1;
                continue;
            }
        };
        if revoke_apple_before_content_delete(lifecycle, apple_provider, &user_id)
            .await
            .is_err()
        {
            summary.pending += 1;
            continue;
        }
        if operation.reason == "identity_cleanup_in_progress" {
            match lifecycle.finalize_account_deletion(&user_id).await {
                Ok(_) => summary.completed += 1,
                Err(_) => summary.pending += 1,
            }
            continue;
        }
        if lifecycle
            .update_account_deletion_status(&user_id, DELETION_ATTEMPT_UNCONFIRMED, None, None)
            .await
            .is_err()
        {
            summary.failures += 1;
            continue;
        }
        match media_objects.purge_account(&user_id).await {
            Ok(()) => match lifecycle.finalize_account_deletion(&user_id).await {
                Ok(_) => summary.completed += 1,
                Err(_) => {
                    if lifecycle
                        .update_account_deletion_status(
                            &user_id,
                            "identity_cleanup_in_progress",
                            Some(30),
                            None,
                        )
                        .await
                        .is_ok()
                    {
                        summary.pending += 1;
                    } else {
                        summary.failures += 1;
                    }
                }
            },
            Err(error) => {
                let (reason, retry, hard_delete) = deletion_failure(&error);
                match lifecycle
                    .update_account_deletion_status(&user_id, reason, retry, hard_delete)
                    .await
                {
                    Ok(operation) if operation.status == "failed_retryable" => {
                        summary.failed_retryable += 1
                    }
                    Ok(_) => summary.pending += 1,
                    Err(_) => summary.failures += 1,
                }
            }
        }
    }
    Ok(summary)
}

pub fn spawn_account_deletion_reconciler(state: Arc<CpState>) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(DELETION_RECONCILE_INTERVAL);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            interval.tick().await;
            match reconcile_pending_account_deletions(&state).await {
                Ok(summary) if summary.attempted > 0 => tracing::info!(
                    attempted = summary.attempted,
                    completed = summary.completed,
                    pending = summary.pending,
                    failed_retryable = summary.failed_retryable,
                    failures = summary.failures,
                    "account deletion reconciliation sweep"
                ),
                Ok(_) => {}
                Err(_) => warn!("account deletion reconciliation sweep unavailable"),
            }
        }
    });
}

fn deletion_operation_response(
    status_code: StatusCode,
    operation: AccountDeletionOperation,
) -> Response {
    let deleted = operation.status == "physical_complete";
    let retry_after_seconds = operation.retry_after_seconds;
    let mut response = (
        status_code,
        Json(json!({
            "deleted": deleted,
            "operation_id": operation.operation_id,
            "status": operation.status,
            "reason": operation.reason,
            "retry_after_seconds": retry_after_seconds,
            "hard_delete_time": operation.hard_delete_time,
        })),
    )
        .into_response();
    if let Some(seconds) = retry_after_seconds {
        if let Ok(value) = HeaderValue::from_str(&seconds.to_string()) {
            response.headers_mut().insert(header::RETRY_AFTER, value);
        }
    }
    response
}

fn deletion_delete_response(operation: AccountDeletionOperation) -> Response {
    let status = if operation.status == "physical_complete" {
        StatusCode::OK
    } else {
        StatusCode::ACCEPTED
    };
    deletion_operation_response(status, operation)
}

fn account_unavailable() -> Response {
    (
        StatusCode::CONFLICT,
        Json(json!({"error": "account_unavailable"})),
    )
        .into_response()
}

fn deletion_init_failed() -> Response {
    (
        StatusCode::SERVICE_UNAVAILABLE,
        Json(json!({"error": "deletion_init_failed"})),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use std::sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Mutex,
    };

    use super::*;
    use crate::{
        error::{DeletionPending, DeletionPendingReason},
        gcs::GcsGetResponse,
        persistence::MediaObjectStore,
    };

    struct FakeLifecycleState {
        operation: AccountDeletionOperation,
        apple_credentials: Vec<(String, String)>,
        revoked_client_ids: Vec<String>,
        request_calls: usize,
        begin_calls: usize,
        begin_failures_remaining: usize,
        preflight_pending_once: bool,
    }

    struct FakeLifecycle {
        user_id: String,
        state: Mutex<FakeLifecycleState>,
    }

    impl FakeLifecycle {
        fn new(user_id: &str, apple_credentials: Vec<(String, String)>) -> Self {
            Self {
                user_id: user_id.into(),
                state: Mutex::new(FakeLifecycleState {
                    operation: AccountDeletionOperation {
                        operation_id: "del_test".into(),
                        status: "pending".into(),
                        reason: "billing_fence_in_progress".into(),
                        retry_after_seconds: Some(30),
                        hard_delete_time: None,
                    },
                    apple_credentials,
                    revoked_client_ids: Vec::new(),
                    request_calls: 0,
                    begin_calls: 0,
                    begin_failures_remaining: 0,
                    preflight_pending_once: false,
                }),
            }
        }

        fn operation(&self) -> AccountDeletionOperation {
            self.state.lock().unwrap().operation.clone()
        }

        fn fail_next_begin(&self) {
            self.state.lock().unwrap().begin_failures_remaining = 1;
        }

        fn hold_preflight_once(&self) {
            self.state.lock().unwrap().preflight_pending_once = true;
        }
    }

    #[async_trait::async_trait]
    impl AccountLifecycleRepository for FakeLifecycle {
        async fn account_deletion_operation(
            &self,
            account_id: &str,
        ) -> EnclaveResult<Option<AccountDeletionOperation>> {
            assert_eq!(account_id, self.user_id);
            Ok(Some(self.operation()))
        }

        async fn request_account_deletion(
            &self,
            account_id: &str,
        ) -> EnclaveResult<Option<AccountDeletionOperation>> {
            assert_eq!(account_id, self.user_id);
            let mut state = self.state.lock().unwrap();
            state.request_calls += 1;
            Ok(Some(state.operation.clone()))
        }

        async fn account_deletion_preflight_complete(
            &self,
            account_id: &str,
        ) -> EnclaveResult<bool> {
            assert_eq!(account_id, self.user_id);
            let mut state = self.state.lock().unwrap();
            let ready = !state.preflight_pending_once;
            state.preflight_pending_once = false;
            Ok(ready)
        }

        async fn begin_account_deletion(
            &self,
            account_id: &str,
        ) -> EnclaveResult<Option<AccountDeletionOperation>> {
            assert_eq!(account_id, self.user_id);
            let mut state = self.state.lock().unwrap();
            state.begin_calls += 1;
            if state.begin_failures_remaining > 0 {
                state.begin_failures_remaining -= 1;
                return Err(EnclaveError::Store(
                    "simulated lifecycle initialization failure".into(),
                ));
            }
            if state.operation.reason == "billing_fence_in_progress" {
                state.operation.reason = "content_deletion_in_progress".into();
            }
            Ok(Some(state.operation.clone()))
        }

        async fn update_account_deletion_status(
            &self,
            account_id: &str,
            reason: &str,
            retry_after_seconds: Option<u64>,
            hard_delete_time: Option<&str>,
        ) -> EnclaveResult<AccountDeletionOperation> {
            assert_eq!(account_id, self.user_id);
            let mut state = self.state.lock().unwrap();
            state.operation.status = "pending".into();
            state.operation.reason = reason.into();
            state.operation.retry_after_seconds = retry_after_seconds;
            state.operation.hard_delete_time = hard_delete_time.map(str::to_owned);
            Ok(state.operation.clone())
        }

        async fn finalize_account_deletion(
            &self,
            account_id: &str,
        ) -> EnclaveResult<AccountDeletionOperation> {
            assert_eq!(account_id, self.user_id);
            let mut state = self.state.lock().unwrap();
            state.operation.status = "physical_complete".into();
            state.operation.reason = "physical_complete".into();
            state.operation.retry_after_seconds = None;
            state.operation.hard_delete_time = None;
            Ok(state.operation.clone())
        }

        async fn deleting_account_ids(&self, limit: usize) -> EnclaveResult<Vec<String>> {
            assert!(limit > 0);
            Ok((self.operation().status != "physical_complete")
                .then(|| self.user_id.clone())
                .into_iter()
                .collect())
        }

        async fn apple_refresh_credentials(
            &self,
            account_id: &str,
        ) -> EnclaveResult<Vec<(String, String)>> {
            assert_eq!(account_id, self.user_id);
            Ok(self.state.lock().unwrap().apple_credentials.clone())
        }

        async fn mark_apple_credential_revoked(
            &self,
            account_id: &str,
            client_id: &str,
        ) -> EnclaveResult<()> {
            assert_eq!(account_id, self.user_id);
            self.state
                .lock()
                .unwrap()
                .revoked_client_ids
                .push(client_id.into());
            Ok(())
        }
    }

    struct FakeAccounting {
        calls: AtomicUsize,
        fail_once: AtomicBool,
    }

    #[async_trait::async_trait]
    impl AccountDeletionAccounting for FakeAccounting {
        async fn settle_before_deletion(&self, _user_id: &str) -> EnclaveResult<()> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            if self.fail_once.swap(false, Ordering::SeqCst) {
                return Err(EnclaveError::Store(
                    "simulated ambiguous billing-fence outcome".into(),
                ));
            }
            Ok(())
        }
    }

    struct FakeMediaObjects {
        pending_once: AtomicBool,
        purge_calls: AtomicUsize,
    }

    impl FakeMediaObjects {
        fn new(pending_once: bool) -> Self {
            Self {
                pending_once: AtomicBool::new(pending_once),
                purge_calls: AtomicUsize::new(0),
            }
        }

        fn unused<T>() -> EnclaveResult<T> {
            Err(EnclaveError::Store("unused media fake method".into()))
        }
    }

    #[async_trait::async_trait]
    impl MediaObjectStore for FakeMediaObjects {
        async fn put_current(
            &self,
            _account_id: &str,
            _object_name: &str,
            _ciphertext: &[u8],
            _wrapped_dek_b64: &str,
        ) -> EnclaveResult<i64> {
            Self::unused()
        }

        async fn get_current(&self, _object_name: &str) -> EnclaveResult<GcsGetResponse> {
            Self::unused()
        }

        async fn get_current_generation(
            &self,
            _object_name: &str,
            _generation: i64,
        ) -> EnclaveResult<GcsGetResponse> {
            Self::unused()
        }

        async fn delete_current(&self, _object_name: &str) -> EnclaveResult<()> {
            Self::unused()
        }

        async fn purge_recordings(&self, _account_id: &str) -> EnclaveResult<()> {
            Self::unused()
        }

        async fn purge_account(&self, _account_id: &str) -> EnclaveResult<()> {
            self.purge_calls.fetch_add(1, Ordering::SeqCst);
            if self.pending_once.swap(false, Ordering::SeqCst) {
                return Err(EnclaveError::DeletionPending(DeletionPending {
                    reason: DeletionPendingReason::SoftDeleteRetention,
                    retry_after_seconds: Some(3600),
                    hard_delete_time: Some("2099-01-01T00:00:00.000Z".into()),
                }));
            }
            Ok(())
        }
    }

    #[test]
    fn deletion_response_preserves_retry_contract() {
        let response = deletion_delete_response(AccountDeletionOperation {
            operation_id: "del_test".into(),
            status: "pending".into(),
            reason: "content_deletion_in_progress".into(),
            retry_after_seconds: Some(30),
            hard_delete_time: None,
        });
        assert_eq!(response.status(), StatusCode::ACCEPTED);
        assert_eq!(response.headers()[header::RETRY_AFTER], "30");
    }

    #[tokio::test]
    async fn configured_reviewer_deletion_is_refused_before_lifecycle_work() {
        let reviewer = ReviewerAuthConfig {
            api_key: "test-api-key".into(),
            uid: "persistent-reviewer-uid".into(),
            email: "reviewer@example.com".into(),
        };
        let reviewer_account_id = reviewer.account_id();
        let response = reviewer_deletion_guard(Some(&reviewer), &reviewer_account_id)
            .expect("the configured reviewer must be protected");
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        let body = axum::body::to_bytes(response.into_body(), 4 * 1024)
            .await
            .unwrap();
        let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(body["error"], "reviewer_account_protected");

        assert!(
            reviewer_deletion_guard(Some(&reviewer), "00000000-0000-4000-8000-000000000001")
                .is_none()
        );
        assert!(reviewer_deletion_guard(None, &reviewer_account_id).is_none());
    }

    #[tokio::test]
    async fn deletion_restart_waits_for_soft_deleted_media_before_physical_completion() {
        let user_id = "00000000-0000-4000-8000-000000000001";
        let lifecycle = FakeLifecycle::new(user_id, Vec::new());
        let media = FakeMediaObjects::new(true);
        let accounting = FakeAccounting {
            calls: AtomicUsize::new(0),
            fail_once: AtomicBool::new(false),
        };

        let first = reconcile_pending_account_deletions_with(&lifecycle, &media, &accounting, None)
            .await
            .unwrap();
        assert_eq!(
            first,
            DeletionReconcileSummary {
                attempted: 1,
                pending: 1,
                ..DeletionReconcileSummary::default()
            }
        );
        let pending = lifecycle.operation();
        assert_eq!(pending.status, "pending");
        assert_eq!(pending.reason, "soft_delete_retention");
        assert_eq!(pending.retry_after_seconds, Some(3600));
        assert_eq!(
            pending.hard_delete_time.as_deref(),
            Some("2099-01-01T00:00:00.000Z")
        );

        let resumed =
            reconcile_pending_account_deletions_with(&lifecycle, &media, &accounting, None)
                .await
                .unwrap();
        assert_eq!(
            resumed,
            DeletionReconcileSummary {
                attempted: 1,
                completed: 1,
                ..DeletionReconcileSummary::default()
            }
        );
        assert_eq!(lifecycle.operation().status, "physical_complete");
        assert_eq!(media.purge_calls.load(Ordering::SeqCst), 2);

        let replay =
            reconcile_pending_account_deletions_with(&lifecycle, &media, &accounting, None)
                .await
                .unwrap();
        assert_eq!(replay, DeletionReconcileSummary::default());
        assert_eq!(media.purge_calls.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn deletion_without_apple_revocation_provider_stays_pending_before_media_purge() {
        let user_id = "00000000-0000-4000-8000-000000000002";
        let lifecycle = FakeLifecycle::new(
            user_id,
            vec![("com.example.kioku".into(), "refresh-token".into())],
        );
        let media = FakeMediaObjects::new(false);
        let accounting = FakeAccounting {
            calls: AtomicUsize::new(0),
            fail_once: AtomicBool::new(false),
        };

        let summary =
            reconcile_pending_account_deletions_with(&lifecycle, &media, &accounting, None)
                .await
                .unwrap();
        assert_eq!(
            summary,
            DeletionReconcileSummary {
                attempted: 1,
                pending: 1,
                ..DeletionReconcileSummary::default()
            }
        );
        assert_eq!(lifecycle.operation().status, "pending");
        assert_eq!(media.purge_calls.load(Ordering::SeqCst), 0);
        assert_eq!(accounting.calls.load(Ordering::SeqCst), 1);
        assert!(lifecycle
            .state
            .lock()
            .unwrap()
            .revoked_client_ids
            .is_empty());
    }

    #[tokio::test]
    async fn deletion_reconciler_retries_a_lost_billing_fence_response_before_beginning() {
        let user_id = "00000000-0000-4000-8000-000000000003";
        let lifecycle = FakeLifecycle::new(user_id, Vec::new());
        let media = FakeMediaObjects::new(false);
        let accounting = FakeAccounting {
            calls: AtomicUsize::new(0),
            fail_once: AtomicBool::new(true),
        };

        let first = reconcile_pending_account_deletions_with(&lifecycle, &media, &accounting, None)
            .await
            .unwrap();
        assert_eq!(
            first,
            DeletionReconcileSummary {
                attempted: 1,
                pending: 1,
                ..DeletionReconcileSummary::default()
            }
        );
        {
            let state = lifecycle.state.lock().unwrap();
            assert_eq!(state.operation.reason, "billing_fence_in_progress");
            assert_eq!(state.request_calls, 1);
            assert_eq!(state.begin_calls, 0);
        }
        assert_eq!(media.purge_calls.load(Ordering::SeqCst), 0);

        let retry = reconcile_pending_account_deletions_with(&lifecycle, &media, &accounting, None)
            .await
            .unwrap();
        assert_eq!(
            retry,
            DeletionReconcileSummary {
                attempted: 1,
                completed: 1,
                ..DeletionReconcileSummary::default()
            }
        );
        assert_eq!(accounting.calls.load(Ordering::SeqCst), 2);
        assert_eq!(media.purge_calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn deletion_reconciler_waits_for_local_work_after_gating_new_admission() {
        let user_id = "00000000-0000-4000-8000-000000000005";
        let lifecycle = FakeLifecycle::new(user_id, Vec::new());
        lifecycle.hold_preflight_once();
        let media = FakeMediaObjects::new(false);
        let accounting = FakeAccounting {
            calls: AtomicUsize::new(0),
            fail_once: AtomicBool::new(false),
        };

        let first = reconcile_pending_account_deletions_with(&lifecycle, &media, &accounting, None)
            .await
            .unwrap();
        assert_eq!(
            first,
            DeletionReconcileSummary {
                attempted: 1,
                pending: 1,
                ..DeletionReconcileSummary::default()
            }
        );
        {
            let state = lifecycle.state.lock().unwrap();
            assert_eq!(state.request_calls, 1);
            assert_eq!(state.begin_calls, 0);
            assert_eq!(state.operation.reason, "billing_fence_in_progress");
        }
        assert_eq!(accounting.calls.load(Ordering::SeqCst), 0);
        assert_eq!(media.purge_calls.load(Ordering::SeqCst), 0);

        let retry = reconcile_pending_account_deletions_with(&lifecycle, &media, &accounting, None)
            .await
            .unwrap();
        assert_eq!(
            retry,
            DeletionReconcileSummary {
                attempted: 1,
                completed: 1,
                ..DeletionReconcileSummary::default()
            }
        );
        assert_eq!(accounting.calls.load(Ordering::SeqCst), 1);
        assert_eq!(media.purge_calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn deletion_reconciler_recovers_when_begin_fails_after_the_billing_fence() {
        let user_id = "00000000-0000-4000-8000-000000000004";
        let lifecycle = FakeLifecycle::new(user_id, Vec::new());
        lifecycle.fail_next_begin();
        let media = FakeMediaObjects::new(false);
        let accounting = FakeAccounting {
            calls: AtomicUsize::new(0),
            fail_once: AtomicBool::new(false),
        };

        let first = reconcile_pending_account_deletions_with(&lifecycle, &media, &accounting, None)
            .await
            .unwrap();
        assert_eq!(
            first,
            DeletionReconcileSummary {
                attempted: 1,
                pending: 1,
                ..DeletionReconcileSummary::default()
            }
        );
        assert_eq!(lifecycle.operation().reason, "billing_fence_in_progress");
        assert_eq!(media.purge_calls.load(Ordering::SeqCst), 0);

        let retry = reconcile_pending_account_deletions_with(&lifecycle, &media, &accounting, None)
            .await
            .unwrap();
        assert_eq!(
            retry,
            DeletionReconcileSummary {
                attempted: 1,
                completed: 1,
                ..DeletionReconcileSummary::default()
            }
        );
        let state = lifecycle.state.lock().unwrap();
        assert_eq!(state.begin_calls, 2);
        assert_eq!(state.operation.status, "physical_complete");
    }
}
