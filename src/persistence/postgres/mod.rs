//! PostgreSQL implementation of the ADR-0040 application persistence ports.
//!
//! This module is compiled while extraction proceeds, but serving startup does
//! not select it until every application domain has a PostgreSQL port. That
//! keeps the intermediate releases single-authority.

mod billing;
mod capture;
mod entitlement;
mod identity;
mod lifecycle;
mod notification;
mod oauth;
mod query;
mod work;

use std::str::FromStr;
use std::time::Duration;

use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
use sqlx::{PgPool, Row};

use crate::error::{EnclaveError, Result};

pub(crate) const EXPECTED_SCHEMA_VERSION: i64 = 9;

#[derive(Clone)]
pub(crate) struct PostgresPersistence {
    pool: PgPool,
}

pub(crate) struct PostgresPoolConfig {
    pub(crate) database_url: String,
    /// PEM-encoded root used to verify the private Cloud SQL server
    /// certificate. Tests against a local PostgreSQL instance may omit it.
    pub(crate) root_ca_pem: Option<Vec<u8>>,
    pub(crate) max_connections: u32,
    pub(crate) acquire_timeout: Duration,
    pub(crate) statement_timeout: Duration,
}

impl PostgresPersistence {
    pub(crate) async fn connect(config: PostgresPoolConfig) -> Result<Self> {
        if config.max_connections == 0 {
            return Err(EnclaveError::Config(
                "PostgreSQL max_connections must be positive".into(),
            ));
        }
        let mut options = PgConnectOptions::from_str(&config.database_url)
            .map_err(|error| EnclaveError::Config(format!("invalid PostgreSQL URL: {error}")))?;
        if let Some(root_ca_pem) = config.root_ca_pem {
            if root_ca_pem.is_empty() {
                return Err(EnclaveError::Config(
                    "PostgreSQL root CA must not be empty".into(),
                ));
            }
            options = options.ssl_root_cert_from_pem(root_ca_pem);
        }
        let statement_timeout_ms =
            i64::try_from(config.statement_timeout.as_millis()).map_err(|_| {
                EnclaveError::Config("PostgreSQL statement timeout is too large".into())
            })?;
        let pool = PgPoolOptions::new()
            .max_connections(config.max_connections)
            .acquire_timeout(config.acquire_timeout)
            .after_connect(move |connection, _metadata| {
                Box::pin(async move {
                    sqlx::query("SET TIME ZONE 'UTC'")
                        .execute(&mut *connection)
                        .await?;
                    sqlx::query("SELECT set_config('statement_timeout', $1, false)")
                        .bind(statement_timeout_ms.to_string())
                        .execute(&mut *connection)
                        .await?;
                    Ok(())
                })
            })
            .connect_with(options)
            .await?;
        Ok(Self { pool })
    }

    pub(crate) fn from_pool(pool: PgPool) -> Self {
        Self { pool }
    }

    pub(crate) fn pool(&self) -> &PgPool {
        &self.pool
    }

    /// Apply reviewed migrations from an explicit release operation.
    /// Serving startup calls `verify_schema`, never this method.
    pub(crate) async fn migrate(&self) -> Result<()> {
        let mut transaction = self.pool.begin().await?;
        advisory_transaction_lock(&mut transaction, "schema", "adr-0040").await?;
        let installed = sqlx::query_scalar::<_, bool>(
            "SELECT to_regclass('public.persistence_schema') IS NOT NULL",
        )
        .fetch_one(&mut *transaction)
        .await?;
        if !installed {
            sqlx::raw_sql(include_str!("../../../migrations/0001_identity_oauth.sql"))
                .execute(&mut *transaction)
                .await?;
        }
        let mut version = sqlx::query_scalar::<_, i64>(
            "SELECT version FROM persistence_schema WHERE singleton = true",
        )
        .fetch_one(&mut *transaction)
        .await?;
        if version == 1 {
            sqlx::raw_sql(include_str!("../../../migrations/0002_entitlements.sql"))
                .execute(&mut *transaction)
                .await?;
            version = 2;
        }
        if version == 2 {
            sqlx::raw_sql(include_str!(
                "../../../migrations/0003_notification_configuration.sql"
            ))
            .execute(&mut *transaction)
            .await?;
            version = 3;
        }
        if version == 3 {
            sqlx::raw_sql(include_str!(
                "../../../migrations/0004_billing_recording.sql"
            ))
            .execute(&mut *transaction)
            .await?;
            version = 4;
        }
        if version == 4 {
            sqlx::raw_sql(include_str!(
                "../../../migrations/0005_account_lifecycle.sql"
            ))
            .execute(&mut *transaction)
            .await?;
            version = 5;
        }
        if version == 5 {
            sqlx::raw_sql(include_str!("../../../migrations/0006_worker_cursors.sql"))
                .execute(&mut *transaction)
                .await?;
            version = 6;
        }
        if version == 6 {
            sqlx::raw_sql(include_str!("../../../migrations/0007_content_search.sql"))
                .execute(&mut *transaction)
                .await?;
            version = 7;
        }
        if version == 7 {
            sqlx::raw_sql(include_str!(
                "../../../migrations/0008_capture_ingestion.sql"
            ))
            .execute(&mut *transaction)
            .await?;
            version = 8;
        }
        if version == 8 {
            sqlx::raw_sql(include_str!(
                "../../../migrations/0009_episode_query_contract.sql"
            ))
            .execute(&mut *transaction)
            .await?;
        }
        transaction.commit().await?;
        self.verify_schema().await
    }

    pub(crate) async fn verify_schema(&self) -> Result<()> {
        let row = sqlx::query("SELECT version FROM persistence_schema WHERE singleton = true")
            .fetch_optional(&self.pool)
            .await?;
        let Some(row) = row else {
            return Err(EnclaveError::Config(
                "PostgreSQL persistence schema marker is missing".into(),
            ));
        };
        let version: i64 = row.try_get("version")?;
        if version != EXPECTED_SCHEMA_VERSION {
            return Err(EnclaveError::Config(format!(
                "PostgreSQL schema version {version} does not match expected {EXPECTED_SCHEMA_VERSION}"
            )));
        }
        Ok(())
    }
}

pub(super) fn duration_seconds(duration: Duration) -> Result<f64> {
    let seconds = duration.as_secs();
    if seconds > i64::MAX as u64 {
        return Err(EnclaveError::Store(
            "persistence duration exceeds PostgreSQL interval range".into(),
        ));
    }
    Ok(seconds as f64)
}

pub(super) async fn advisory_transaction_lock(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    namespace: &str,
    value: &str,
) -> Result<()> {
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 12648430))")
        .bind(format!("{namespace}\u{1f}{value}"))
        .execute(&mut **transaction)
        .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::Duration;

    use super::{PostgresPersistence, PostgresPoolConfig};
    use crate::persistence::identity::{AccountStatus, AppleAccountGrant};
    use crate::persistence::oauth::{
        AuthorizationCodeExchange, ConsentApproval, OAuthClientDefinition, PendingConsent,
        RefreshTokenRotation,
    };
    use crate::persistence::RepositorySet;
    use crate::persistence::{
        CaptureCommit, CapturePreflight, EmailFenceOutcome, EmailProviderOutcome, EmailSendFence,
        EmailSendFenceDisposition, EpisodeListRequest, MemoryFeedRequest, PushInstallation,
        PushProviderOutcome, PushProviderReceipt, PushSendFenceDisposition, WebhookProviderOutcome,
        WebhookSendFence, WebhookSendFenceDisposition, WebhookSubscription,
    };
    use crate::search::{SearchHit, SearchRequest};

    async fn test_persistence() -> Option<PostgresPersistence> {
        let database_url = match std::env::var("KIOKU_TEST_POSTGRES_URL") {
            Ok(value) => value,
            Err(_) => {
                eprintln!("KIOKU_TEST_POSTGRES_URL is unset; skipping real PostgreSQL contract");
                return None;
            }
        };
        let persistence = PostgresPersistence::connect(PostgresPoolConfig {
            database_url,
            root_ca_pem: None,
            max_connections: 8,
            acquire_timeout: Duration::from_secs(5),
            statement_timeout: Duration::from_secs(10),
        })
        .await
        .unwrap();
        persistence.migrate().await.unwrap();
        persistence.verify_schema().await.unwrap();
        sqlx::raw_sql(
            "TRUNCATE account_deletion_operations, offline_recording_usage_receipts, recording_delivery_reservations, \
             recording_delivery_balances, recording_lease_denials, recording_lease_requests, \
             recording_leases, vertex_coverage_anchors, billing_detach_outbox, billing_accounts, \
             push_send_fences, push_installations, email_send_fences, \
             episode_email_preferences, webhook_send_fences, webhook_subscriptions, \
             usage_daily, refresh_tokens, oauth_authorization_codes, oauth_consents, \
             oauth_clients, apple_credentials, auth_identities, deleted_identities, \
             deleted_accounts, signup_daily, accounts CASCADE",
        )
        .execute(persistence.pool())
        .await
        .unwrap();
        Some(persistence)
    }

    #[tokio::test]
    async fn postgres_control_plane_contract() {
        let Some(persistence) = test_persistence().await else {
            return;
        };
        let persistence = Arc::new(persistence);
        let pool = persistence.pool().clone();
        let repositories = Arc::new(RepositorySet::postgres(persistence));

        let mut signups = Vec::new();
        for _ in 0..16 {
            let repositories = Arc::clone(&repositories);
            signups.push(tokio::spawn(async move {
                repositories
                    .identity_sessions()
                    .upsert_subject_account("concurrent-subject", "owner@example.com", 1)
                    .await
            }));
        }
        let mut account_id = None;
        for signup in signups {
            let account = signup.await.unwrap().unwrap();
            assert_eq!(account.email, "owner@example.com");
            match &account_id {
                Some(expected) => assert_eq!(&account.id, expected),
                None => account_id = Some(account.id),
            }
        }
        let account_id = account_id.unwrap();
        assert_eq!(
            repositories
                .identity_sessions()
                .account_status(&account_id)
                .await
                .unwrap(),
            Some(AccountStatus::Active)
        );
        assert_eq!(
            repositories.work().active_account_ids().await.unwrap(),
            vec![account_id.clone()]
        );

        let canonical: crate::cp::media::CaptureEventManifest =
            serde_json::from_value(serde_json::json!({
                "schema_version": 2,
                "event_id": "capture-contract-0",
                "device_id": "device-contract",
                "install_id": "install-contract",
                "capture_session_id": "session-contract",
                "stream_id": "screen-contract",
                "stream_kind": "mac_screen",
                "sequence": 0,
                "source_wall_at": "2026-08-27T12:00:00.000Z",
                "source_monotonic_ns": 1000_u64,
                "started_at": "2026-08-27T12:00:00.000Z",
                "ended_at": "2026-08-27T12:00:02.000Z",
                "timezone_id": "America/New_York",
                "utc_offset_minutes": -240,
                "clock_uncertainty_ms": 10,
                "media": {
                    "asset_id": "capture-asset-contract",
                    "mime_type": "image/jpeg",
                    "codec": "jpeg",
                    "byte_length": 12,
                    "sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                    "width": 1280,
                    "height": 720
                },
                "context": {
                    "capture_status": "stable",
                    "active_app": "Safari",
                    "primary_bundle_id": "com.apple.Safari",
                    "primary_window_id": 7,
                    "window_title": "Contract",
                    "display_id": 1,
                    "active_url": "https://example.com/contract",
                    "active_url_title": "Contract",
                    "browser_permission_status": "granted"
                }
            }))
            .unwrap();
        let canonical_digest = crate::cp::media::manifest_digest(&canonical).unwrap();
        let object_key = crate::store::canonical_capture_media_object_key(
            &account_id,
            &canonical.media.as_ref().unwrap().asset_id,
        )
        .unwrap();
        let canonical_command = CaptureCommit {
            account_id: account_id.clone(),
            manifest: canonical.clone(),
            manifest_digest: canonical_digest.clone(),
            object_key: Some(object_key.clone()),
            object_generation: Some(1),
            media_authority: Some(
                crate::cp::media::RecordingMediaAuthorityDecision::ProcessingWindow30d {
                    capture_policy_revision: 0,
                    decision_at: "2026-08-27T12:00:03.000Z".into(),
                },
            ),
            committed_at: "2026-08-27T12:00:03.000Z".into(),
        };
        let committed = repositories
            .captures()
            .commit_event(canonical_command.clone())
            .await
            .unwrap();
        assert!(!committed.duplicate);
        assert_eq!(committed.committed_through_sequence, 0);
        assert!(matches!(
            repositories
                .captures()
                .preflight_event(
                    &account_id,
                    &canonical,
                    &canonical_digest,
                    Some(std::slice::from_ref(&object_key)),
                )
                .await
                .unwrap(),
            CapturePreflight::Duplicate {
                committed_through_sequence: 0
            }
        ));
        assert!(
            repositories
                .captures()
                .commit_event(canonical_command)
                .await
                .unwrap()
                .duplicate
        );

        let mut reference = canonical.clone();
        reference.event_id = "capture-contract-1".into();
        reference.sequence = 1;
        reference.source_monotonic_ns = 2000;
        reference.media_disposition = crate::cp::media::MediaDisposition::Reference;
        let canonical_media = reference.media.take().unwrap();
        let context = reference.context.as_ref().unwrap();
        reference.reference = Some(crate::cp::media::ScreenReferenceDescriptor {
            canonical_event_id: canonical.event_id.clone(),
            canonical_asset_id: canonical_media.asset_id,
            canonical_media_sha256: canonical_media.sha256,
            perceptual_hash: "0123456789abcdef".into(),
            hamming_distance: 1,
            pixel_change_ratio: 0.001,
            context_fingerprint: crate::cp::media::semantic_context_fingerprint(context, 1)
                .unwrap(),
            dedupe_version: 1,
        });
        let reference_digest = crate::cp::media::manifest_digest(&reference).unwrap();
        let referenced = repositories
            .captures()
            .commit_event(CaptureCommit {
                account_id: account_id.clone(),
                manifest: reference,
                manifest_digest: reference_digest,
                object_key: None,
                object_generation: None,
                media_authority: None,
                committed_at: "2026-08-27T12:00:04.000Z".into(),
            })
            .await
            .unwrap();
        assert!(!referenced.duplicate);
        assert_eq!(referenced.committed_through_sequence, 1);
        assert_eq!(
            sqlx::query_scalar::<_, i64>(
                "SELECT count(*) FROM media_processing_jobs WHERE account_id=$1",
            )
            .bind(&account_id)
            .fetch_one(&pool)
            .await
            .unwrap(),
            1
        );
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT count(*) FROM outbox_events WHERE account_id=$1",)
                .bind(&account_id)
                .fetch_one(&pool)
                .await
                .unwrap(),
            1
        );
        assert_eq!(
            repositories
                .work()
                .summarized_until(&account_id)
                .await
                .unwrap(),
            None
        );
        repositories
            .work()
            .set_summarized_until(&account_id, "2026-08-27T12:34:56.789Z")
            .await
            .unwrap();
        assert_eq!(
            repositories
                .work()
                .summarized_until(&account_id)
                .await
                .unwrap()
                .as_deref(),
            Some("2026-08-27T12:34:56.789Z")
        );
        assert!(matches!(
            repositories
                .identity_sessions()
                .upsert_subject_account("second-subject", "second@example.com", 1)
                .await,
            Err(crate::error::EnclaveError::SignupLimited)
        ));

        repositories
            .identity_sessions()
            .link_apple_identity(
                &account_id,
                AppleAccountGrant {
                    subject: "apple-subject".into(),
                    email: "OWNER@EXAMPLE.COM".into(),
                    client_id: "com.kiokuu.app".into(),
                    refresh_token: "private-refresh".into(),
                },
            )
            .await
            .unwrap();
        let session = repositories
            .identity_sessions()
            .account_session(&account_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(session.providers, vec!["apple", "google"]);

        let mut reservations = Vec::new();
        for _ in 0..8 {
            let repositories = Arc::clone(&repositories);
            let account_id = account_id.clone();
            reservations.push(tokio::spawn(async move {
                repositories
                    .entitlements()
                    .reserve_vertex_output_tokens_for_class(
                        &account_id,
                        crate::persistence::VertexWorkClass::Audio,
                        100,
                        400,
                    )
                    .await
                    .unwrap()
                    .allowed
            }));
        }
        let mut allowed = 0;
        for reservation in reservations {
            allowed += usize::from(reservation.await.unwrap());
        }
        assert_eq!(allowed, 2, "the protected audio budget is fleet-wide");

        let mut billing_lookups = Vec::new();
        for _ in 0..8 {
            let repositories = Arc::clone(&repositories);
            let account_id = account_id.clone();
            billing_lookups.push(tokio::spawn(async move {
                repositories
                    .billing()
                    .billing_account_id(&account_id)
                    .await
                    .unwrap()
            }));
        }
        let mut billing_account_id = None;
        for lookup in billing_lookups {
            let observed = lookup.await.unwrap();
            match &billing_account_id {
                Some(expected) => assert_eq!(&observed, expected),
                None => billing_account_id = Some(observed),
            }
        }
        assert!(billing_account_id.unwrap().starts_with("acct_"));

        let coverage = repositories
            .billing()
            .reconcile_vertex_coverage(&account_id, "2026-08", 1, 0, 0, "2026-08-27T12:00:00.000Z")
            .await
            .unwrap();
        assert_eq!(coverage.sequence, 1);
        assert!(repositories
            .billing()
            .active_vertex_coverage_complete("2026-08")
            .await
            .unwrap());

        repositories
            .billing()
            .begin_recording_lease_request(
                &account_id,
                "lease-request-one",
                None,
                "lease_contract_one",
                "2026-08-27T12:01:00.000Z",
            )
            .await
            .unwrap();
        assert_eq!(
            repositories
                .billing()
                .pending_recording_lease_request(&account_id)
                .await
                .unwrap()
                .unwrap()
                .0,
            "lease-request-one"
        );
        let lease = repositories
            .billing()
            .complete_recording_lease(
                &account_id,
                "lease-request-one",
                None,
                &serde_json::json!({"recording":{"allowed":true}}),
            )
            .await
            .unwrap();
        assert_eq!(lease.0, "lease_contract_one");
        assert_eq!(
            repositories
                .billing()
                .active_recording_lease(&account_id)
                .await
                .unwrap()
                .unwrap(),
            lease
        );
        assert!(repositories
            .billing()
            .reserve_recording_delivery(&account_id, "event-one", 1024)
            .await
            .unwrap());
        assert!(repositories
            .billing()
            .complete_offline_recording_usage(&account_id, "offline-one")
            .await
            .unwrap());
        assert!(!repositories
            .billing()
            .complete_offline_recording_usage(&account_id, "offline-one")
            .await
            .unwrap());

        repositories
            .billing()
            .begin_recording_lease_request(
                &account_id,
                "lease-request-denied",
                None,
                "lease_contract_denied",
                "2026-08-27T12:02:00.000Z",
            )
            .await
            .unwrap();
        repositories
            .billing()
            .deny_recording_lease_request(
                &account_id,
                "lease-request-denied",
                "allowance_exhausted",
                &serde_json::json!({"recording":{"allowed":false}}),
            )
            .await
            .unwrap();
        assert_eq!(
            repositories
                .billing()
                .recording_lease_receipt(&account_id, "lease-request-denied")
                .await
                .unwrap()
                .unwrap()
                .state,
            "denied"
        );

        let webhook = WebhookSubscription {
            id: "22222222-2222-4222-8222-222222222222".into(),
            user_id: account_id.clone(),
            name: "Contract hook".into(),
            endpoint_url: "https://hooks.example/kioku".into(),
            signing_secret: "private-signing-secret".into(),
            include_content: true,
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
                .list_webhook_subscriptions(&account_id)
                .await
                .unwrap(),
            vec![webhook.clone()]
        );
        repositories
            .notifications()
            .disable_webhook_subscription(&account_id, &webhook.id)
            .await
            .unwrap();
        assert!(
            !repositories
                .notifications()
                .get_webhook_subscription(&account_id, &webhook.id)
                .await
                .unwrap()
                .unwrap()
                .enabled
        );

        let default_email = repositories
            .notifications()
            .get_email_preference(&account_id)
            .await
            .unwrap();
        assert!(!default_email.enabled);
        let opted_in = repositories
            .notifications()
            .set_email_preference(&account_id, true, true)
            .await
            .unwrap();
        assert!(opted_in.enabled && opted_in.include_content);
        assert!(opted_in.consented_at.is_some());

        let installation = PushInstallation {
            id: "33333333-3333-4333-8333-333333333333".into(),
            user_id: account_id.clone(),
            platform: "ios".into(),
            topic: "com.kioku.ios".into(),
            environment: "sandbox".into(),
            device_token: "a".repeat(64),
            token_generation: 1,
            enabled: true,
        };
        let installed = repositories
            .notifications()
            .upsert_push_installation(installation.clone())
            .await
            .unwrap();
        let repeated = repositories
            .notifications()
            .upsert_push_installation(installation)
            .await
            .unwrap();
        assert_eq!(installed.token_generation, repeated.token_generation);
        assert_eq!(
            repositories
                .notifications()
                .list_push_installations(&account_id)
                .await
                .unwrap(),
            vec![repeated]
        );

        let fence_webhook = WebhookSubscription {
            id: "44444444-4444-4444-8444-444444444444".into(),
            user_id: account_id.clone(),
            name: "Fence contract hook".into(),
            endpoint_url: "https://hooks.example/fence".into(),
            signing_secret: "fence-signing-secret".into(),
            include_content: false,
            enabled: true,
            created_at: "2026-08-27T12:03:00.000Z".into(),
        };
        repositories
            .notifications()
            .create_webhook_subscription(fence_webhook.clone())
            .await
            .unwrap();
        let webhook_fence = WebhookSendFence {
            user_id: account_id.clone(),
            event_id: "event-contract".into(),
            subscription_id: fence_webhook.id.clone(),
            claim_id: "55555555-5555-4555-8555-555555555555".into(),
            lease_expires_at: "2026-08-27T12:10:00.000Z".into(),
            endpoint_url: fence_webhook.endpoint_url.clone(),
            signing_secret: fence_webhook.signing_secret.clone(),
            include_content: false,
            outcome: None,
            outcome_at: None,
        };
        let mut webhook_begins = Vec::new();
        for _ in 0..8 {
            let repositories = Arc::clone(&repositories);
            let webhook_fence = webhook_fence.clone();
            webhook_begins.push(tokio::spawn(async move {
                repositories
                    .work()
                    .begin_webhook_send_fence(&webhook_fence, "2026-08-27T12:04:00.000Z")
                    .await
            }));
        }
        for begin in webhook_begins {
            assert!(matches!(
                begin.await.unwrap().unwrap(),
                WebhookSendFenceDisposition::Authorized(_)
            ));
        }
        let mut conflicting_webhook = webhook_fence.clone();
        conflicting_webhook.claim_id = "88888888-8888-4888-8888-888888888888".into();
        assert!(matches!(
            repositories
                .work()
                .begin_webhook_send_fence(&conflicting_webhook, "2026-08-27T12:04:00.000Z",)
                .await,
            Err(crate::error::EnclaveError::Conflict(_))
        ));
        assert!(repositories
            .work()
            .validate_webhook_send_fence(
                &webhook_fence,
                crate::cp::isotime::parse_epoch_millis("2026-08-27T12:09:00.000Z").unwrap(),
            )
            .await
            .unwrap());
        let webhook_outcome = WebhookProviderOutcome::Sent { status: 204 };
        repositories
            .work()
            .record_webhook_send_outcome(
                &webhook_fence,
                webhook_outcome.clone(),
                "2026-08-27T12:05:00.000Z",
            )
            .await
            .unwrap();
        let completed_webhook = repositories
            .work()
            .get_webhook_send_fence(&account_id, &webhook_fence.event_id)
            .await
            .unwrap()
            .unwrap();
        repositories
            .work()
            .record_webhook_send_outcome(
                &webhook_fence,
                webhook_outcome,
                "2026-08-27T12:05:00.000Z",
            )
            .await
            .unwrap();
        repositories
            .work()
            .close_webhook_send_fence(&completed_webhook)
            .await
            .unwrap();

        let email_fence = EmailSendFence {
            user_id: account_id.clone(),
            delivery_id: "delivery-contract".into(),
            claim_id: "66666666-6666-4666-8666-666666666666".into(),
            lease_expires_at: "2026-08-27T12:10:00.000Z".into(),
            recipient_email: "owner@example.com".into(),
            include_content: true,
            outcome: None,
            outcome_at: None,
        };
        assert!(matches!(
            repositories
                .work()
                .begin_email_send_fence(&email_fence, "2026-08-27T12:04:00.000Z")
                .await
                .unwrap(),
            EmailSendFenceDisposition::Authorized(_)
        ));
        let email_outcome = EmailProviderOutcome::Accepted {
            status: 202,
            provider_message_id: "provider-message-contract".into(),
        };
        repositories
            .work()
            .record_email_send_outcome(
                &email_fence,
                email_outcome.clone(),
                "2026-08-27T12:05:00.000Z",
            )
            .await
            .unwrap();
        let completed_email = repositories
            .work()
            .get_email_send_fence(&account_id, &email_fence.delivery_id)
            .await
            .unwrap()
            .unwrap();
        repositories
            .work()
            .finish_email_send_fence(&completed_email, EmailFenceOutcome::Provider(email_outcome))
            .await
            .unwrap();

        assert!(matches!(
            repositories
                .work()
                .begin_push_send_fence(
                    &account_id,
                    &installed.id,
                    installed.token_generation,
                    "77777777-7777-4777-8777-777777777777",
                    "2026-08-27T12:10:00.000Z",
                    "2026-08-27T12:04:00.000Z",
                )
                .await
                .unwrap(),
            PushSendFenceDisposition::Authorized(_)
        ));
        let push_outcome = PushProviderOutcome::Accepted { status: 200 };
        repositories
            .work()
            .record_push_send_outcome(
                &account_id,
                &installed.id,
                installed.token_generation,
                "77777777-7777-4777-8777-777777777777",
                "2026-08-27T12:10:00.000Z",
                PushProviderReceipt::new(push_outcome.clone(), "2026-08-27T12:05:00.000Z".into())
                    .unwrap(),
            )
            .await
            .unwrap();
        let completed_push = repositories
            .work()
            .get_push_send_fence(&account_id, &installed.id)
            .await
            .unwrap()
            .unwrap();
        repositories
            .work()
            .finish_push_send_fence(&completed_push, push_outcome)
            .await
            .unwrap();

        let client_id = "11111111-1111-4111-8111-111111111111";
        repositories
            .oauth()
            .ensure_client(OAuthClientDefinition {
                id: client_id.into(),
                name: "Contract Client".into(),
                redirect_uris: vec!["https://client.example/callback".into()],
                allow_empty_redirect_upgrade: false,
            })
            .await
            .unwrap();
        assert!(repositories
            .oauth()
            .store_pending_consent(PendingConsent {
                consent_hash: "consent".into(),
                account_id: account_id.clone(),
                client_id: client_id.into(),
                redirect_uri: "https://client.example/callback".into(),
                ttl: Duration::from_secs(300),
            })
            .await
            .unwrap());
        assert!(repositories
            .oauth()
            .approve_consent(ConsentApproval {
                consent_hash: "consent".into(),
                authorization_code_hash: "code".into(),
                account_id: account_id.clone(),
                client_id: client_id.into(),
                redirect_uri: "https://client.example/callback".into(),
                code_ttl: Duration::from_secs(300),
            })
            .await
            .unwrap());
        assert!(!repositories
            .oauth()
            .approve_consent(ConsentApproval {
                consent_hash: "consent".into(),
                authorization_code_hash: "other-code".into(),
                account_id: account_id.clone(),
                client_id: client_id.into(),
                redirect_uri: "https://client.example/callback".into(),
                code_ttl: Duration::from_secs(300),
            })
            .await
            .unwrap());
        assert!(repositories
            .oauth()
            .exchange_authorization_code(AuthorizationCodeExchange {
                authorization_code_hash: "code".into(),
                account_id: account_id.clone(),
                client_id: client_id.into(),
                refresh_token_hash: "refresh-one".into(),
                refresh_ttl: Duration::from_secs(3600),
            })
            .await
            .unwrap());
        assert_eq!(
            repositories
                .oauth()
                .rotate_refresh_token(RefreshTokenRotation {
                    old_token_hash: "refresh-one".into(),
                    client_id: client_id.into(),
                    new_token_hash: "refresh-two".into(),
                    refresh_ttl: Duration::from_secs(3600),
                })
                .await
                .unwrap(),
            Some(account_id.clone())
        );
        assert_eq!(
            repositories
                .oauth()
                .rotate_refresh_token(RefreshTokenRotation {
                    old_token_hash: "refresh-one".into(),
                    client_id: client_id.into(),
                    new_token_hash: "refresh-three".into(),
                    refresh_ttl: Duration::from_secs(3600),
                })
                .await
                .unwrap(),
            None
        );

        // The same tenant-local ids may exist for different accounts. Search
        // must bind the authenticated account at every candidate and row
        // retrieval step, including vector-only matches.
        let other_account = repositories
            .identity_sessions()
            .upsert_subject_account("other-tenant-subject", "other@example.com", 2)
            .await
            .unwrap();
        let embedding = format!(
            "[{}]",
            std::iter::repeat_n((1.0_f32 / 384.0_f32.sqrt()).to_string(), 384)
                .collect::<Vec<_>>()
                .join(",")
        );
        for (tenant, text) in [
            (&account_id, "PostgreSQL private memory alpha"),
            (&other_account.id, "other tenant private memory"),
        ] {
            sqlx::query(
                "INSERT INTO audio_segments(account_id,id,started_at,ended_at,duration_seconds,source_type) \
                 VALUES($1,1,'2026-08-27T12:00:00Z','2026-08-27T12:01:00Z',60,'mic')",
            )
            .bind(tenant)
            .execute(&pool)
            .await
            .unwrap();
            sqlx::query(
                "INSERT INTO utterances(account_id,id,audio_segment_id,start_offset_seconds, \
                                        end_offset_seconds,text,speaker_label,embedding) \
                 VALUES($1,1,1,0,5,$2,'Lynn',$3::vector)",
            )
            .bind(tenant)
            .bind(text)
            .bind(&embedding)
            .execute(&pool)
            .await
            .unwrap();
        }
        sqlx::query(
            "INSERT INTO screenshots(account_id,id,captured_at,ocr_text,url,embedding) \
             VALUES($1,1,'2026-08-27T12:02:00Z','PostgreSQL diagram','https://example.com/db',$2::vector)",
        )
        .bind(&account_id)
        .bind(&embedding)
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO episodes(account_id,id,started_at,ended_at,title,summary,participants, \
                                  minute_summaries,minutes_text,embedding) \
             VALUES($1,1,'2026-08-27T12:00:00Z','2026-08-27T12:03:00Z', \
                    'PostgreSQL rollout','Shipped the database boundary','[\"Lynn\"]'::jsonb, \
                    '[]'::jsonb,'database boundary',$2::vector)",
        )
        .bind(&account_id)
        .bind(&embedding)
        .execute(&pool)
        .await
        .unwrap();
        let search = repositories
            .memory_queries()
            .search(
                &account_id,
                &SearchRequest {
                    user_id: account_id.clone(),
                    query: "PostgreSQL".into(),
                    speaker: None,
                    time_start: None,
                    time_end: None,
                    limit: 20,
                    offset: 0,
                    kinds: Vec::new(),
                    query_embedding: None,
                },
            )
            .await
            .unwrap();
        assert_eq!(search.len(), 3);
        assert!(!serde_json::to_string(&search)
            .unwrap()
            .contains("other tenant"));
        let hybrid = repositories
            .memory_queries()
            .search(
                &account_id,
                &SearchRequest {
                    user_id: account_id.clone(),
                    query: "not-in-the-document".into(),
                    speaker: None,
                    time_start: None,
                    time_end: None,
                    limit: 5,
                    offset: 0,
                    kinds: vec!["utterance".into()],
                    query_embedding: Some(vec![1.0_f32 / 384.0_f32.sqrt(); 384]),
                },
            )
            .await
            .unwrap();
        assert!(matches!(
            hybrid.as_slice(),
            [SearchHit::Utterance {
                id: 1,
                score: Some(_),
                ..
            }]
        ));
        sqlx::query(
            "INSERT INTO episode_members(account_id,episode_id,record_type,record_id) \
             VALUES($1,1,'utterance',1),($1,1,'screenshot',1)",
        )
        .bind(&account_id)
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO episode_final_briefs(account_id,episode_id,overview,decisions,action_items,important_links,open_questions) \
             VALUES($1,1,'Ready','[]'::jsonb,'[\"Ship\"]'::jsonb,'[]'::jsonb,'[]'::jsonb)",
        )
        .bind(&account_id)
        .execute(&pool)
        .await
        .unwrap();
        let episode_page = repositories
            .memory_queries()
            .list_episodes(
                &account_id,
                &EpisodeListRequest {
                    from: None,
                    to: None,
                    limit: 20,
                    include_low: false,
                    episode_id: None,
                    before_started_at: None,
                    before_id: None,
                    probe_for_more: true,
                },
            )
            .await
            .unwrap();
        assert_eq!(episode_page.episodes.len(), 1);
        assert!(!episode_page.has_more);
        assert_eq!(episode_page.episodes[0]["member_count"], 2);
        assert_eq!(episode_page.episodes[0]["top_domains"][0], "example.com");
        assert_eq!(episode_page.episodes[0]["final_brief"]["overview"], "Ready");
        let capture_status = repositories
            .memory_queries()
            .capture_status(&account_id)
            .await
            .unwrap();
        assert_eq!(capture_status.total_utterances, 1);
        assert_eq!(capture_status.total_screenshots, 1);
        assert_eq!(capture_status.episode_count, 1);
        let feed = repositories
            .memory_queries()
            .feed(
                &account_id,
                &MemoryFeedRequest {
                    from: None,
                    to: None,
                    limit: 20,
                    before: None,
                },
            )
            .await
            .unwrap();
        assert_eq!(feed.records.len(), 2);
        assert_eq!(feed.records[0].kind, "screenshot");
        assert_eq!(feed.records[0].episode_id, Some(1));
        assert_eq!(feed.records[1].kind, "utterance");
        assert_eq!(feed.records[1].episode_id, Some(1));

        let billing_detach_id = repositories
            .billing()
            .billing_account_id_for_deletion(&account_id)
            .await
            .unwrap();
        let deletion = repositories
            .lifecycle()
            .begin_account_deletion(&account_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(deletion.status, "pending");
        assert_eq!(
            repositories
                .lifecycle()
                .begin_account_deletion(&account_id)
                .await
                .unwrap()
                .unwrap()
                .operation_id,
            deletion.operation_id
        );
        assert_eq!(
            repositories
                .identity_sessions()
                .account_status(&account_id)
                .await
                .unwrap(),
            Some(AccountStatus::Deleting)
        );
        let active = repositories.work().active_account_ids().await.unwrap();
        assert!(!active.contains(&account_id));
        assert!(active.contains(&other_account.id));
        let credentials = repositories
            .lifecycle()
            .apple_refresh_credentials(&account_id)
            .await
            .unwrap();
        assert_eq!(credentials.len(), 1);
        repositories
            .lifecycle()
            .mark_apple_credential_revoked(&account_id, &credentials[0].0)
            .await
            .unwrap();
        let pending = repositories
            .lifecycle()
            .update_account_deletion_status(
                &account_id,
                "identity_cleanup_in_progress",
                Some(30),
                None,
            )
            .await
            .unwrap();
        assert_eq!(pending.operation_id, deletion.operation_id);
        let completed = repositories
            .lifecycle()
            .finalize_account_deletion(&account_id)
            .await
            .unwrap();
        assert_eq!(completed.status, "physical_complete");
        assert_eq!(completed.reason, "content_deleted");
        assert_eq!(
            repositories
                .identity_sessions()
                .account_status(&account_id)
                .await
                .unwrap(),
            Some(AccountStatus::Deleted)
        );
        assert_eq!(
            repositories
                .billing()
                .pending_billing_detach_ids(10)
                .await
                .unwrap(),
            vec![billing_detach_id]
        );
        assert!(matches!(
            repositories
                .identity_sessions()
                .upsert_subject_account("concurrent-subject", "owner@example.com", 10)
                .await,
            Err(crate::error::EnclaveError::Auth(_))
        ));
    }
}
