//! Backend-neutral application persistence boundaries.
//!
//! Product code depends on the typed ports exposed here, never on a database
//! connection or SQL callback. The legacy adapter delegates to the existing
//! SQLite/GCS stores while the PostgreSQL implementation is built vertically.

mod billing;
mod capture;
mod entitlement;
mod identity;
mod legacy;
mod lifecycle;
mod notification;
mod oauth;
mod query;
mod work;
// PostgreSQL is compiled and contract-tested now, but production construction
// stays disabled until the interface freeze makes one whole repository set
// selectable without split authority.
#[allow(dead_code)]
mod postgres;

use std::sync::Arc;

pub(crate) use capture::{
    CaptureCommit, CaptureCommitResult, CapturePreflight, CaptureRepository, ReferenceBatchCommit,
    ReferenceBatchCommitResult,
};
pub(crate) use entitlement::{EntitlementRepository, VertexWorkClass};
pub(crate) use identity::{AccountStatus, AppleAccountGrant, IdentitySessionRepository};
pub use lifecycle::AccountDeletionOperation;
pub(crate) use lifecycle::AccountLifecycleRepository;
pub(crate) use notification::NotificationRepository;
pub use notification::{EpisodeEmailPreference, PushInstallation, WebhookSubscription};
pub(crate) use oauth::{
    AuthorizationCodeExchange, ConsentApproval, DirectAuthorizationCode, NativeSessionRefresh,
    OAuthClient, OAuthClientDefinition, OAuthClientRegistration, OAuthClientRegistrationRequest,
    OAuthRepository, PendingConsent, RefreshTokenRotation,
};
pub(crate) use postgres::PostgresPersistence;
pub(crate) use query::{CaptureStatus, EpisodeListPage, EpisodeListRequest, MemoryQueryRepository};
pub(crate) use work::{
    EmailControlCancellation, EmailFenceOutcome, EmailProviderOutcome, EmailSendFence,
    EmailSendFenceDisposition, PushControlCancellation, PushFenceOutcome, PushProviderOutcome,
    PushProviderReceipt, PushSendFence, PushSendFenceDisposition, WebhookControlCancellation,
    WebhookFenceOutcome, WebhookProviderOutcome, WebhookSendFence, WebhookSendFenceDisposition,
    WorkRepository,
};

use self::legacy::{
    LegacyAccountLifecycleRepository, LegacyBillingRepository, LegacyCaptureRepository,
    LegacyEntitlementRepository, LegacyIdentitySessionRepository, LegacyMemoryQueryRepository,
    LegacyNotificationRepository, LegacyOAuthRepository, LegacyWorkRepository,
};
use crate::cp::control_store::ControlStore;
use crate::store::Store;

/// The persistence dependencies injected into application code.
///
/// This starts with authentication because it is the first vertical slice.
/// Additional ports join this set as their handlers and workers are extracted.
#[derive(Clone)]
pub(crate) struct RepositorySet {
    identity_sessions: Arc<dyn IdentitySessionRepository>,
    lifecycle: Arc<dyn AccountLifecycleRepository>,
    billing: Arc<dyn BillingRepository>,
    captures: Arc<dyn CaptureRepository>,
    oauth: Arc<dyn OAuthRepository>,
    entitlements: Arc<dyn EntitlementRepository>,
    notifications: Arc<dyn NotificationRepository>,
    memory_queries: Arc<dyn MemoryQueryRepository>,
    work: Arc<dyn WorkRepository>,
}

impl RepositorySet {
    pub(crate) fn legacy(control: Arc<ControlStore>, store: Arc<Store>) -> Self {
        Self {
            identity_sessions: Arc::new(LegacyIdentitySessionRepository::new(Arc::clone(&control))),
            lifecycle: Arc::new(LegacyAccountLifecycleRepository::new(Arc::clone(&control))),
            billing: Arc::new(LegacyBillingRepository::new(Arc::clone(&control))),
            captures: Arc::new(LegacyCaptureRepository::new(Arc::clone(&store))),
            oauth: Arc::new(LegacyOAuthRepository::new(Arc::clone(&control))),
            entitlements: Arc::new(LegacyEntitlementRepository::new(Arc::clone(&control))),
            notifications: Arc::new(LegacyNotificationRepository::new(Arc::clone(&control))),
            memory_queries: Arc::new(LegacyMemoryQueryRepository::new(store)),
            work: Arc::new(LegacyWorkRepository::new(control)),
        }
    }

    #[allow(dead_code)]
    pub(crate) fn postgres(persistence: Arc<PostgresPersistence>) -> Self {
        Self {
            identity_sessions: Arc::clone(&persistence) as Arc<dyn IdentitySessionRepository>,
            lifecycle: Arc::clone(&persistence) as Arc<dyn AccountLifecycleRepository>,
            billing: Arc::clone(&persistence) as Arc<dyn BillingRepository>,
            captures: Arc::clone(&persistence) as Arc<dyn CaptureRepository>,
            oauth: Arc::clone(&persistence) as Arc<dyn OAuthRepository>,
            entitlements: Arc::clone(&persistence) as Arc<dyn EntitlementRepository>,
            notifications: Arc::clone(&persistence) as Arc<dyn NotificationRepository>,
            memory_queries: Arc::clone(&persistence) as Arc<dyn MemoryQueryRepository>,
            work: persistence,
        }
    }

    pub(crate) fn identity_sessions(&self) -> &dyn IdentitySessionRepository {
        self.identity_sessions.as_ref()
    }

    pub(crate) fn lifecycle(&self) -> &dyn AccountLifecycleRepository {
        self.lifecycle.as_ref()
    }

    pub(crate) fn billing(&self) -> &dyn BillingRepository {
        self.billing.as_ref()
    }

    pub(crate) fn captures(&self) -> &dyn CaptureRepository {
        self.captures.as_ref()
    }

    pub(crate) fn oauth(&self) -> &dyn OAuthRepository {
        self.oauth.as_ref()
    }

    pub(crate) fn entitlements(&self) -> &dyn EntitlementRepository {
        self.entitlements.as_ref()
    }

    pub(crate) fn notifications(&self) -> &dyn NotificationRepository {
        self.notifications.as_ref()
    }

    pub(crate) fn memory_queries(&self) -> &dyn MemoryQueryRepository {
        self.memory_queries.as_ref()
    }

    pub(crate) fn work(&self) -> &dyn WorkRepository {
        self.work.as_ref()
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::{AccountStatus, PushInstallation, RepositorySet, WebhookSubscription};
    use crate::cp::control_store::{ControlStore, TEST_SIGNUP_LIMIT};
    use crate::store::tests::{FakeGcs, FakeKms};

    #[tokio::test]
    async fn legacy_identity_port_preserves_signup_and_status_behavior() {
        let kms: Arc<dyn crate::crypto::KmsClient> = Arc::new(FakeKms);
        let gcs: Arc<dyn crate::store::GcsClient> = Arc::new(FakeGcs::new());
        let control = Arc::new(ControlStore::new(Arc::clone(&kms), Arc::clone(&gcs)));
        let store = Arc::new(crate::store::Store::new(kms, gcs));
        let repositories = RepositorySet::legacy(control, store);

        let account = repositories
            .identity_sessions()
            .upsert_subject_account(
                "postgres-interface-subject",
                "owner@example.com",
                TEST_SIGNUP_LIMIT,
            )
            .await
            .unwrap();

        assert_eq!(account.email, "owner@example.com");
        assert_eq!(
            repositories
                .identity_sessions()
                .account_status(&account.id)
                .await
                .unwrap(),
            Some(AccountStatus::Active)
        );

        let webhook = WebhookSubscription {
            id: "11111111-1111-4111-8111-111111111111".into(),
            user_id: account.id.clone(),
            name: "Legacy contract".into(),
            endpoint_url: "https://hooks.example/legacy".into(),
            signing_secret: "secret".into(),
            include_content: false,
            enabled: true,
            created_at: "2026-08-27T12:00:00.000Z".into(),
        };
        repositories
            .notifications()
            .create_webhook_subscription(webhook.clone())
            .await
            .unwrap();
        assert_eq!(
            repositories
                .notifications()
                .list_webhook_subscriptions(&account.id)
                .await
                .unwrap(),
            vec![webhook]
        );

        let installation = PushInstallation {
            id: "22222222-2222-4222-8222-222222222222".into(),
            user_id: account.id.clone(),
            platform: "ios".into(),
            topic: "com.kioku.ios".into(),
            environment: "sandbox".into(),
            device_token: "a".repeat(64),
            token_generation: 1,
            enabled: true,
        };
        let installed = repositories
            .notifications()
            .upsert_push_installation(installation)
            .await
            .unwrap();
        assert!(installed.token_generation > 0);
    }
}
pub(crate) use billing::BillingRepository;
pub use billing::{RecordingLeaseRequestRow, RetainedAccountMetrics, VertexCoverageAnchor};
