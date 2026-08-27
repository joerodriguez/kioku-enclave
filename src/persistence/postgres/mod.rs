//! PostgreSQL implementation of the ADR-0040 application persistence ports.
//!
//! This module is compiled while extraction proceeds, but serving startup does
//! not select it until every application domain has a PostgreSQL port. That
//! keeps the intermediate releases single-authority.

mod billing;
mod capture;
mod delivery_outbox;
mod entitlement;
mod episode_deletion;
mod finalization;
mod identity;
mod lifecycle;
mod media_processing;
mod memory_formation;
mod model_usage;
mod notification;
mod oauth;
mod playback;
mod query;
mod recording_retention;
mod work;

use std::str::FromStr;
use std::time::Duration;

use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
use sqlx::{PgPool, Row};

use crate::error::{EnclaveError, Result};

pub(crate) const EXPECTED_SCHEMA_VERSION: i64 = 21;

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
            version = 9;
        }
        if version == 9 {
            sqlx::raw_sql(include_str!(
                "../../../migrations/0010_browser_snapshot_query.sql"
            ))
            .execute(&mut *transaction)
            .await?;
            version = 10;
        }
        if version == 10 {
            sqlx::raw_sql(include_str!(
                "../../../migrations/0011_episode_evidence_query.sql"
            ))
            .execute(&mut *transaction)
            .await?;
            version = 11;
        }
        if version == 11 {
            sqlx::raw_sql(include_str!(
                "../../../migrations/0012_people_voice_queries.sql"
            ))
            .execute(&mut *transaction)
            .await?;
            version = 12;
        }
        if version == 12 {
            sqlx::raw_sql(include_str!(
                "../../../migrations/0013_vertex_usage_ledger.sql"
            ))
            .execute(&mut *transaction)
            .await?;
            version = 13;
        }
        if version == 13 {
            sqlx::raw_sql(include_str!(
                "../../../migrations/0014_media_processing.sql"
            ))
            .execute(&mut *transaction)
            .await?;
            version = 14;
        }
        if version == 14 {
            sqlx::raw_sql(include_str!(
                "../../../migrations/0015_memory_formation.sql"
            ))
            .execute(&mut *transaction)
            .await?;
            version = 15;
        }
        if version == 15 {
            sqlx::raw_sql(include_str!(
                "../../../migrations/0016_finalization_delivery.sql"
            ))
            .execute(&mut *transaction)
            .await?;
            version = 16;
        }
        if version == 16 {
            sqlx::raw_sql(include_str!("../../../migrations/0017_delivery_claims.sql"))
                .execute(&mut *transaction)
                .await?;
            version = 17;
        }
        if version == 17 {
            sqlx::raw_sql(include_str!(
                "../../../migrations/0018_capture_upload_admission.sql"
            ))
            .execute(&mut *transaction)
            .await?;
            version = 18;
        }
        if version == 18 {
            sqlx::raw_sql(include_str!(
                "../../../migrations/0019_voice_lineage_export.sql"
            ))
            .execute(&mut *transaction)
            .await?;
            version = 19;
        }
        if version == 19 {
            sqlx::raw_sql(include_str!(
                "../../../migrations/0020_episode_deletion.sql"
            ))
            .execute(&mut *transaction)
            .await?;
            version = 20;
        }
        if version == 20 {
            sqlx::raw_sql(include_str!(
                "../../../migrations/0021_recording_retention.sql"
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

pub(super) async fn allocate_content_id(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    account_id: &str,
    entity_kind: &str,
) -> Result<i64> {
    if entity_kind.is_empty()
        || entity_kind.len() > 64
        || !entity_kind
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte == b'_')
    {
        return Err(EnclaveError::Store(
            "content id counter kind is invalid".into(),
        ));
    }
    Ok(sqlx::query_scalar(
        "INSERT INTO content_id_counters(account_id,entity_kind,next_id) \
         VALUES($1,$2,2) ON CONFLICT(account_id,entity_kind) DO UPDATE \
         SET next_id=content_id_counters.next_id+1 RETURNING next_id-1",
    )
    .bind(account_id)
    .bind(entity_kind)
    .fetch_one(&mut **transaction)
    .await?)
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
    use crate::cp::control_store::{RecordingRetentionPolicy, RECORDING_RETENTION_CONSENT_VERSION};
    use crate::cp::vertex::{VertexMetadata, VertexOperation, VertexUsage};
    use crate::episodes::EpisodeInput;
    use crate::persistence::identity::{AccountStatus, AppleAccountGrant};
    use crate::persistence::oauth::{
        AuthorizationCodeExchange, ConsentApproval, OAuthClientDefinition, PendingConsent,
        RefreshTokenRotation,
    };
    use crate::persistence::{
        CaptureCommit, CapturePreflight, CaptureSessionStage, EmailFenceOutcome,
        EmailProviderOutcome, EmailSendFence, EmailSendFenceDisposition, EpisodeDeletionStart,
        EpisodeListRequest, FinalizationRequest, FinalizationScreenResult, FinalizationSettlement,
        FrozenEmailDelivery, FrozenPushDelivery, FrozenWebhookDelivery, McpContextRequest,
        McpTimeRangeRequest, McpTranscriptSearchRequest, MediaProcessingClass,
        MediaScreenProjection, MediaUsageSettlement, MemoryFeedRequest, PeopleListRequest,
        PushInstallation, PushProviderOutcome, PushProviderReceipt, PushSendFenceDisposition,
        RecordingRetentionChangeRequest, ScreenMediaSettlement, ScreenshotMediaLocator,
        SummaryWindowSettlement, WebhookProviderOutcome, WebhookSendFence,
        WebhookSendFenceDisposition, WebhookSubscription,
    };
    use crate::persistence::{GcsMediaObjectStore, MediaObjectStore, RepositorySet};
    use crate::search::{SearchHit, SearchRequest};
    use crate::store::tests::FakeGcs;

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
            "TRUNCATE vertex_usage_events, vertex_usage_coverage, account_deletion_operations, offline_recording_usage_receipts, recording_delivery_reservations, \
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
        let media_gcs: Arc<dyn crate::store::GcsClient> = Arc::new(FakeGcs::new());
        let media_objects: Arc<dyn MediaObjectStore> =
            Arc::new(GcsMediaObjectStore::new(Arc::clone(&media_gcs), media_gcs));
        let repositories = Arc::new(RepositorySet::postgres(persistence, media_objects));

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
        assert!(repositories
            .captures()
            .media_dek_wrapped(&account_id)
            .await
            .unwrap()
            .is_none());

        let initial_retention = repositories
            .recording_retention()
            .preference(&account_id)
            .await
            .unwrap();
        assert_eq!(initial_retention.revision, 0);
        assert_eq!(
            initial_retention.policy,
            RecordingRetentionPolicy::ProcessingWindow30d
        );
        let initial_inventory = repositories
            .recording_retention()
            .inventory(&account_id, &initial_retention)
            .await
            .unwrap();
        assert_eq!(initial_inventory.object_count, 0);
        let durable_preview = repositories
            .recording_retention()
            .create_preview(
                &account_id,
                RecordingRetentionPolicy::UntilDeleted,
                0,
                RECORDING_RETENTION_CONSENT_VERSION,
                false,
                initial_inventory.clone(),
            )
            .await
            .unwrap();
        let durable_change_request = RecordingRetentionChangeRequest {
            policy: RecordingRetentionPolicy::UntilDeleted,
            expected_revision: 0,
            consent_version: RECORDING_RETENTION_CONSENT_VERSION,
            promote_existing: false,
            preview_id: &durable_preview.preview_id,
            inventory: initial_inventory,
            idempotency_key: "retention-contract-1",
        };
        let durable_change = repositories
            .recording_retention()
            .change_policy(&account_id, durable_change_request.clone())
            .await
            .unwrap();
        assert_eq!(durable_change.state, "settled");
        assert_eq!(
            repositories
                .recording_retention()
                .change_policy(&account_id, durable_change_request)
                .await
                .unwrap(),
            durable_change
        );
        let durable_preference = repositories
            .recording_retention()
            .preference(&account_id)
            .await
            .unwrap();
        let policy_epoch = durable_preference.policy_epoch.clone().unwrap();
        let installed_key = repositories
            .recording_retention()
            .install_key_epoch(
                &account_id,
                durable_preference.revision,
                &policy_epoch,
                "wrapped-retention-key",
            )
            .await
            .unwrap();
        assert_eq!(
            repositories
                .recording_retention()
                .key_epoch(&account_id, installed_key.key_epoch, &policy_epoch)
                .await
                .unwrap()
                .unwrap(),
            installed_key
        );
        let durable_inventory = repositories
            .recording_retention()
            .inventory(&account_id, &durable_preference)
            .await
            .unwrap();
        let downgrade_preview = repositories
            .recording_retention()
            .create_preview(
                &account_id,
                RecordingRetentionPolicy::ProcessingWindow30d,
                durable_preference.revision,
                RECORDING_RETENTION_CONSENT_VERSION,
                false,
                durable_inventory.clone(),
            )
            .await
            .unwrap();
        let downgrade = repositories
            .recording_retention()
            .change_policy(
                &account_id,
                RecordingRetentionChangeRequest {
                    policy: RecordingRetentionPolicy::ProcessingWindow30d,
                    expected_revision: durable_preference.revision,
                    consent_version: RECORDING_RETENTION_CONSENT_VERSION,
                    promote_existing: false,
                    preview_id: &downgrade_preview.preview_id,
                    inventory: durable_inventory,
                    idempotency_key: "retention-contract-2",
                },
            )
            .await
            .unwrap();
        assert_eq!(downgrade.state, "delete_pending");
        repositories
            .media_objects()
            .purge_recordings(&account_id)
            .await
            .unwrap();
        let completed_downgrade = repositories
            .recording_retention()
            .complete_downgrade(&account_id, &downgrade.operation_id)
            .await
            .unwrap();
        assert_eq!(completed_downgrade.state, "physical_complete");
        assert!(repositories
            .recording_retention()
            .key_epoch(&account_id, installed_key.key_epoch, &policy_epoch)
            .await
            .unwrap()
            .is_none());
        let first_media_key = repositories
            .captures()
            .install_media_dek(
                &account_id,
                "wrapped-media-key-1",
                &crate::crypto::Dek([7; 32]),
            )
            .await
            .unwrap();
        assert_eq!(first_media_key, "wrapped-media-key-1");
        let raced_media_key = repositories
            .captures()
            .install_media_dek(
                &account_id,
                "wrapped-media-key-2",
                &crate::crypto::Dek([8; 32]),
            )
            .await
            .unwrap();
        assert_eq!(raced_media_key, first_media_key);
        assert_eq!(
            repositories.work().active_account_ids().await.unwrap(),
            vec![account_id.clone()]
        );

        let mut canonical: crate::cp::media::CaptureEventManifest =
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
                    "active_url": "https://meet.google.com/abc?authuser=0#frag",
                    "active_url_title": "Meeting",
                    "browser_permission_status": "granted"
                }
            }))
            .unwrap();
        let browser_state_key = "device-contract:browser-v2:43206e42c20fd24a9372605a13b6792245ed53e50edf6c1735cfba4053be30f3";
        let context = canonical.context.as_mut().unwrap();
        context.browser_state_key = Some(browser_state_key.into());
        context.browser_snapshot = Some(crate::cp::media::BrowserSnapshot {
            state_key: browser_state_key.into(),
            browser_bundle_id: "com.apple.Safari".into(),
            browser_name: "Safari".into(),
            permission_status: "granted".into(),
            active_window_index: Some(1),
            active_tab_index: Some(1),
            reported_tab_count: 2,
            truncated: false,
            ambient_tab_collection_enabled: Some(true),
            content_hash: "43206e42c20fd24a9372605a13b6792245ed53e50edf6c1735cfba4053be30f3".into(),
            tabs: vec![
                crate::cp::media::BrowserTab {
                    window_index: 1,
                    tab_index: 1,
                    title: Some("Meeting".into()),
                    url: Some("https://meet.google.com/abc?authuser=0#frag".into()),
                    url_scheme: Some("https".into()),
                    is_active: true,
                    is_loading: None,
                },
                crate::cp::media::BrowserTab {
                    window_index: 1,
                    tab_index: 2,
                    title: Some("Document".into()),
                    url: Some("https://docs.google.com/document/d/exact/edit?tab=t.0".into()),
                    url_scheme: Some("https".into()),
                    is_active: false,
                    is_loading: None,
                },
            ],
        });
        let canonical_digest = crate::cp::media::manifest_digest(&canonical).unwrap();
        let object_key = crate::store::canonical_capture_media_object_key(
            &account_id,
            &canonical.media.as_ref().unwrap().asset_id,
        )
        .unwrap();
        let upload_token = repositories
            .captures()
            .reserve_media_upload(
                &account_id,
                &canonical.event_id,
                &canonical.media.as_ref().unwrap().asset_id,
                &object_key,
                &canonical_digest,
            )
            .await
            .unwrap();
        let canonical_command = CaptureCommit {
            account_id: account_id.clone(),
            manifest: canonical.clone(),
            manifest_digest: canonical_digest.clone(),
            object_key: Some(object_key.clone()),
            object_generation: Some(1),
            upload_token,
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
                upload_token: None,
                media_authority: None,
                committed_at: "2026-08-27T12:00:04.000Z".into(),
            })
            .await
            .unwrap();
        assert!(!referenced.duplicate);
        assert_eq!(referenced.committed_through_sequence, 1);
        assert_eq!(
            repositories
                .captures()
                .stream_ack(&account_id, "screen-contract")
                .await
                .unwrap(),
            1
        );
        let event_status = repositories
            .captures()
            .event_status(&account_id, "capture-contract-0")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(event_status.processing_state, "queued");
        assert_eq!(event_status.attempt_count, 0);
        let media = repositories
            .media_processing()
            .expect("PostgreSQL media repository");
        assert_eq!(
            media
                .pending_classes(&account_id, "2026-08-27T12:00:05.000Z")
                .await
                .unwrap(),
            (false, true)
        );
        let screen_claim = media
            .claim(
                &account_id,
                MediaProcessingClass::Screen,
                "2026-08-27T12:00:05.000Z",
                300,
                128,
            )
            .await
            .unwrap()
            .expect("screen work claim");
        assert!(media
            .claim(
                &account_id,
                MediaProcessingClass::Screen,
                "2026-08-27T12:00:06.000Z",
                300,
                128,
            )
            .await
            .unwrap()
            .is_none());
        media
            .record_reservation(&screen_claim, 1_024, "2026-08-27T12:00:06.000Z")
            .await
            .unwrap();
        media
            .settle_usage(MediaUsageSettlement {
                claim: screen_claim.clone(),
                usage: serde_json::json!({
                    "work_unit_id": screen_claim.work_unit_id,
                    "reservation_state": "reserved",
                    "actual_output_tokens": 42,
                    "outcome": "model_returned"
                }),
            })
            .await
            .unwrap();
        let screen_projection = MediaScreenProjection {
            event_id: canonical.event_id.clone(),
            literal_description: "Database diagram".into(),
            screen_state: "focused".into(),
            content_type: "document".into(),
            visible_text: "PostgreSQL diagram".into(),
            salient_text: "PostgreSQL architecture".into(),
            people: Vec::new(),
        };
        media
            .settle_screens(ScreenMediaSettlement {
                claim: screen_claim.clone(),
                results: vec![screen_projection.clone()],
            })
            .await
            .unwrap();
        // Lost-response replay is a no-op, and the durable result remains
        // authoritative even after the original lease deadline.
        media
            .settle_screens(ScreenMediaSettlement {
                claim: screen_claim,
                results: vec![screen_projection],
            })
            .await
            .unwrap();
        assert_eq!(
            repositories
                .captures()
                .event_status(&account_id, "capture-contract-0")
                .await
                .unwrap()
                .unwrap()
                .processing_state,
            "ready"
        );
        let screenshot_locator = repositories
            .memory_queries()
            .screenshot_media(
                &account_id,
                &format!("capture-v2:{}", canonical.media.as_ref().unwrap().asset_id),
            )
            .await
            .unwrap()
            .expect("canonical screenshot locator");
        assert!(matches!(
            screenshot_locator,
            ScreenshotMediaLocator::Canonical {
                generation: 1,
                byte_length: 12,
                ..
            }
        ));
        assert!(repositories
            .memory_queries()
            .screenshot_media(&account_id, "legacy-evidence-id")
            .await
            .unwrap()
            .is_none());
        let session_status = repositories
            .captures()
            .session_status(&account_id, "session-contract", None)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(session_status.event_count, 2);
        assert_eq!(session_status.processing.queued, 0);
        assert_eq!(session_status.processing.ready, 2);
        assert_eq!(session_status.stage, CaptureSessionStage::Received);
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
        let memory = repositories
            .memory_formation()
            .expect("PostgreSQL memory formation repository");
        let claim = memory
            .claim_summary_window(
                &account_id,
                "2026-08-27T11:59:00.000Z",
                "2026-08-27T12:10:00.000Z",
                "2026-08-27T12:10:01.000Z",
                900,
            )
            .await
            .unwrap()
            .expect("summary window claim");
        assert!(memory
            .claim_summary_window(
                &account_id,
                "2026-08-27T11:59:00.000Z",
                "2026-08-27T12:10:00.000Z",
                "2026-08-27T12:10:02.000Z",
                900,
            )
            .await
            .unwrap()
            .is_none());
        let (summary_utterances, summary_screenshots) = memory
            .summary_evidence(
                &account_id,
                "2026-08-27T11:59:00.000Z",
                "2026-08-27T12:10:00.000Z",
                100,
                100,
            )
            .await
            .unwrap();
        assert!(summary_utterances.is_empty());
        assert_eq!(summary_screenshots.len(), 1);
        assert!(memory
            .open_episodes(
                &account_id,
                "2026-08-27T11:00:00.000Z",
                "2026-08-27T12:10:00.000Z",
                100,
            )
            .await
            .unwrap()
            .is_empty());
        let settlement = SummaryWindowSettlement {
            claim: claim.clone(),
            episodes: vec![EpisodeInput {
                id: None,
                started_at: "2026-08-27T12:00:00.000Z".into(),
                ended_at: "2026-08-27T12:00:02.000Z".into(),
                episode_type: Some("work".into()),
                title: "PostgreSQL architecture".into(),
                summary: Some("Reviewed the database design.".into()),
                participants: Some(Vec::new()),
                languages: Some(vec!["en".into()]),
                action_items: Some(vec!["Implement the repository".into()]),
                substance: Some("normal".into()),
                visual_evidence: Some("useful".into()),
                minute_summaries: Some(Vec::new()),
                model: Some("contract-model".into()),
                member_utterance_ids: Vec::new(),
                member_screenshot_ids: vec![summary_screenshots[0].id],
            }],
            cursor: Some("2026-08-27T12:00:02.000Z".into()),
        };
        let episode_ids = memory
            .settle_summary_window(settlement.clone())
            .await
            .unwrap();
        assert_eq!(episode_ids.len(), 1);
        assert_eq!(
            memory.settle_summary_window(settlement).await.unwrap(),
            episode_ids
        );
        assert!(memory
            .claim_summary_window(
                &account_id,
                "2026-08-27T11:59:00.000Z",
                "2026-08-27T12:10:00.000Z",
                "2026-08-27T12:20:00.000Z",
                900,
            )
            .await
            .unwrap()
            .is_none());
        let embedding_sources = memory
            .episode_embedding_sources(&account_id, &episode_ids)
            .await
            .unwrap();
        assert_eq!(embedding_sources.len(), 1);
        assert!(embedding_sources[0]
            .text
            .contains("PostgreSQL architecture"));
        assert_eq!(
            repositories
                .work()
                .summarized_until(&account_id)
                .await
                .unwrap(),
            Some("2026-08-27T12:00:02.000Z".into())
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
        repositories
            .work()
            .set_summarized_until(&account_id, "2026-08-27T17:00:00.000Z")
            .await
            .unwrap();
        let finalization = repositories
            .finalization()
            .expect("PostgreSQL finalization repository");
        assert_eq!(
            finalization
                .request_finalization(&account_id, episode_ids[0], 5)
                .await
                .unwrap(),
            FinalizationRequest::Queued
        );
        assert_eq!(
            finalization
                .request_finalization(&account_id, episode_ids[0], 5)
                .await
                .unwrap(),
            FinalizationRequest::AlreadyQueued {
                status: "queued".into()
            }
        );
        let finalization_claim = finalization
            .claim_finalization(
                &account_id,
                Some(episode_ids[0]),
                "2026-08-27T20:00:00.000Z",
                "2026-08-27T16:00:00.000Z",
                5,
                900,
            )
            .await
            .unwrap()
            .expect("finalization claim");
        assert!(finalization
            .claim_finalization(
                &account_id,
                Some(episode_ids[0]),
                "2026-08-27T20:00:01.000Z",
                "2026-08-27T16:00:00.000Z",
                5,
                900,
            )
            .await
            .unwrap()
            .is_none());
        assert_eq!(finalization_claim.screenshots.len(), 1);
        let finalization_event = repositories
            .model_usage()
            .begin_invocation(
                &account_id,
                VertexOperation::FinalEpisodeAnalysis,
                "contract-model",
                "us-central1",
                &[0x66; 32],
            )
            .await
            .unwrap();
        repositories
            .model_usage()
            .settle_response(
                &account_id,
                &finalization_event,
                &VertexMetadata {
                    usage: None,
                    model_version: Some("contract-model".into()),
                    traffic_type: None,
                },
            )
            .await
            .unwrap();
        let finalization_settlement = FinalizationSettlement {
            claim: finalization_claim,
            vertex_event_id: finalization_event.clone(),
            model_name: "contract-model".into(),
            analysis_revision: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
                .into(),
            title: "Final PostgreSQL architecture".into(),
            summary: "Completed the database architecture review.".into(),
            minute_summaries_json: "[]".into(),
            minutes_text: "Reviewed PostgreSQL".into(),
            action_items_json: "[]".into(),
            overview: "The persistence boundary is complete.".into(),
            decisions_json: "[]".into(),
            important_links_json: "[]".into(),
            open_questions_json: "[]".into(),
            ranked_screens: vec![FinalizationScreenResult {
                screenshot_id: summary_screenshots[0].id,
                observation_revision: "contract-observation".into(),
                literal_description: "A PostgreSQL architecture diagram".into(),
                screen_state: "content".into(),
                content_type: "document".into(),
                visible_text_summary: Some("PostgreSQL".into()),
                notable_items_json: "[]".into(),
                activity_summary: Some("Reviewed the data model".into()),
                relevance_level: 3,
                relevance_reason: "Primary design artifact".into(),
                milestone_type: "decision".into(),
                base_score: 100,
                key_rank: Some(1),
                is_key_screen: true,
                semantic_group: "contract-group".into(),
            }],
            webhook_destinations: vec![(
                "22222222-2222-4222-8222-222222222222".into(),
                "contract-event".into(),
            )],
            email_preference_include_content: Some(true),
            push_destinations: vec![(
                "p1:33333333-3333-4333-8333-333333333333:1".into(),
                "contract-push-delivery".into(),
                "contract-handoff".into(),
                "contract-collapse".into(),
            )],
            finalization_version: 5,
            observation_version: 2,
            observation_prompt_version: 2,
            interpretation_version: 1,
            interpretation_prompt_version: 1,
        };
        assert_eq!(
            finalization
                .settle_finalization(finalization_settlement.clone())
                .await
                .unwrap(),
            3
        );
        assert_eq!(
            finalization
                .settle_finalization(finalization_settlement)
                .await
                .unwrap(),
            3
        );
        assert_eq!(
            sqlx::query_scalar::<_, i64>(
                "SELECT (SELECT count(*) FROM webhook_deliveries WHERE account_id=$1)+\
                        (SELECT count(*) FROM email_deliveries WHERE account_id=$1)+\
                        (SELECT count(*) FROM push_deliveries WHERE account_id=$1)",
            )
            .bind(&account_id)
            .fetch_one(&pool)
            .await
            .unwrap(),
            3
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
        let email_candidate = repositories
            .deliveries()
            .expect("PostgreSQL delivery repository")
            .next_email_candidate(&account_id)
            .await
            .unwrap()
            .expect("finalization email candidate");
        assert!(email_candidate.include_content);
        let email_claim = repositories
            .deliveries()
            .unwrap()
            .claim_email(
                &email_candidate,
                FrozenEmailDelivery {
                    recipient_email: email_candidate.recipient_email.clone(),
                    include_content: email_candidate.include_content,
                    subject: "PostgreSQL delivery contract".into(),
                    text_body: "Text contract".into(),
                    html_body: "<p>HTML contract</p>".into(),
                },
                60,
            )
            .await
            .unwrap()
            .expect("email claim");
        assert!(repositories
            .deliveries()
            .unwrap()
            .next_email_candidate(&account_id)
            .await
            .unwrap()
            .is_none());
        let accepted_email = EmailProviderOutcome::Accepted {
            status: 202,
            provider_message_id: "msg_postgres_contract".into(),
        };
        repositories
            .deliveries()
            .unwrap()
            .settle_email(&email_claim, accepted_email.clone(), None)
            .await
            .unwrap();
        repositories
            .deliveries()
            .unwrap()
            .settle_email(&email_claim, accepted_email, None)
            .await
            .unwrap();
        assert_eq!(
            sqlx::query_scalar::<_, String>(
                "SELECT state FROM email_deliveries WHERE account_id=$1 AND delivery_id=$2",
            )
            .bind(&account_id)
            .bind(&email_claim.delivery_id)
            .fetch_one(&pool)
            .await
            .unwrap(),
            "delivered"
        );
        sqlx::query("UPDATE webhook_subscriptions SET enabled=true WHERE account_id=$1 AND id=$2")
            .bind(&account_id)
            .bind(&webhook.id)
            .execute(&pool)
            .await
            .unwrap();
        let webhook_candidate = repositories
            .deliveries()
            .unwrap()
            .next_webhook_candidate(&account_id)
            .await
            .unwrap()
            .expect("finalization webhook candidate");
        let webhook_claim = repositories
            .deliveries()
            .unwrap()
            .claim_webhook(
                &webhook_candidate,
                FrozenWebhookDelivery {
                    endpoint_url: webhook_candidate.endpoint_url.clone(),
                    signing_secret: webhook_candidate.signing_secret.clone(),
                    include_content: webhook_candidate.include_content,
                    event_body: "{\"contract\":true}".into(),
                },
                60,
            )
            .await
            .unwrap()
            .expect("webhook claim");
        let sent_webhook = WebhookProviderOutcome::Sent { status: 204 };
        repositories
            .deliveries()
            .unwrap()
            .settle_webhook(&webhook_claim, sent_webhook.clone(), None)
            .await
            .unwrap();
        repositories
            .deliveries()
            .unwrap()
            .settle_webhook(&webhook_claim, sent_webhook, None)
            .await
            .unwrap();
        assert_eq!(
            sqlx::query_scalar::<_, String>(
                "SELECT state FROM webhook_deliveries WHERE account_id=$1 AND event_id=$2",
            )
            .bind(&account_id)
            .bind(&webhook_claim.event_id)
            .fetch_one(&pool)
            .await
            .unwrap(),
            "delivered"
        );
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
        let push_candidate = repositories
            .deliveries()
            .unwrap()
            .next_push_candidate(&account_id)
            .await
            .unwrap()
            .expect("finalization push candidate");
        assert_eq!(push_candidate.token_generation, installed.token_generation);
        let push_claim = repositories
            .deliveries()
            .unwrap()
            .claim_push(
                &push_candidate,
                FrozenPushDelivery {
                    topic: push_candidate.topic.clone(),
                    environment: push_candidate.environment.clone(),
                    device_token: push_candidate.device_token.clone(),
                    token_generation: push_candidate.token_generation,
                },
                60,
            )
            .await
            .unwrap()
            .expect("push claim");
        let accepted_push = PushProviderOutcome::Accepted { status: 200 };
        repositories
            .deliveries()
            .unwrap()
            .settle_push(&push_claim, accepted_push.clone(), None)
            .await
            .unwrap();
        repositories
            .deliveries()
            .unwrap()
            .settle_push(&push_claim, accepted_push, None)
            .await
            .unwrap();
        assert_eq!(
            sqlx::query_scalar::<_, String>(
                "SELECT state FROM push_deliveries WHERE account_id=$1 AND delivery_id=$2",
            )
            .bind(&account_id)
            .bind(&push_claim.delivery_id)
            .fetch_one(&pool)
            .await
            .unwrap(),
            "delivered"
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
                 VALUES($1,1,'2026-08-27T11:59:00Z','2026-08-27T11:59:59Z',59,'mic')",
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
            "UPDATE screenshots SET url='https://example.com/db', \
                    browser_snapshot_source_key='capture-v2-browser:capture-contract-0', \
                    embedding=$2::vector WHERE account_id=$1 AND id=1",
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
                    '[]'::jsonb,'database boundary',$2::vector) \
             ON CONFLICT(account_id,id) DO UPDATE SET \
                    started_at=excluded.started_at,ended_at=excluded.ended_at,\
                    title=excluded.title,summary=excluded.summary,\
                    participants=excluded.participants,minute_summaries=excluded.minute_summaries,\
                    minutes_text=excluded.minutes_text,embedding=excluded.embedding",
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
             VALUES($1,1,'utterance',1),($1,1,'screenshot',1) \
             ON CONFLICT DO NOTHING",
        )
        .bind(&account_id)
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(
            "UPDATE screen_observations SET notable_items='[\"schema\"]'::jsonb \
             WHERE account_id=$1 AND screenshot_id=1",
        )
        .bind(&account_id)
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO episode_screen_interpretations \
             (account_id,episode_id,screenshot_id,episode_revision,interpretation_version,status, \
             activity_summary,relevance_level,relevance_reason,milestone_type,base_score,key_rank, \
              is_key_screen,semantic_group,prompt_version) \
             VALUES($1,1,1,'episode-1',1,'ready','Reviewing the schema',3,'central evidence', \
                    'decision',95,1,true,'database',1) \
             ON CONFLICT(account_id,episode_id,screenshot_id) DO UPDATE SET \
                    episode_revision=excluded.episode_revision,\
                    interpretation_version=excluded.interpretation_version,\
                    status=excluded.status,activity_summary=excluded.activity_summary,\
                    relevance_level=excluded.relevance_level,relevance_reason=excluded.relevance_reason,\
                    milestone_type=excluded.milestone_type,base_score=excluded.base_score,\
                    key_rank=excluded.key_rank,is_key_screen=excluded.is_key_screen,\
                    semantic_group=excluded.semantic_group,prompt_version=excluded.prompt_version",
        )
        .bind(&account_id)
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO screenshot_images \
             (account_id,id,screenshot_id,episode_id,source_key,captured_at,object_key,mime_type, \
              width,height,byte_length,sha256) \
             VALUES($1,'img_contract',1,1,'cloud-v2:capture-contract-0','2026-08-27T12:00:00Z', \
                    'screenshots/contract.jpg','image/jpeg',1280,720,12, \
                    'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb')",
        )
        .bind(&account_id)
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO people(account_id,id,display_name,normalized_name,status) \
             VALUES($1,1,'Lynn','lynn','identified')",
        )
        .bind(&account_id)
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO speaker_observations \
             (account_id,id,person_id,event_id,turn_id,speaker_local_id,started_at,ended_at, \
              transcript_text,language,voice_eligibility) \
             VALUES($1,1,1,'capture-contract-0','turn-contract','speaker-1', \
                    '2026-08-27T12:00:00Z','2026-08-27T12:00:05Z', \
                    'PostgreSQL private memory alpha','en','enroll')",
        )
        .bind(&account_id)
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO speaker_observation_sources \
             (account_id,speaker_observation_id,event_id,window_start_ms,window_end_ms,event_start_ms,event_end_ms) \
             VALUES($1,1,'capture-contract-0',0,5000,0,5000)",
        )
        .bind(&account_id)
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(
            "UPDATE utterances SET source_key='cloud-v2:capture-contract-0:turn-contract', \
                    speaker_observation_id=1 WHERE account_id=$1 AND id=1",
        )
        .bind(&account_id)
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO voice_profiles \
             (account_id,id,person_id,label,embedding_space,channel_domain,centroid,sample_count,status) \
             VALUES($1,1,1,'Lynn','voice-v1','mic',decode('00','hex'),1,'stable')",
        )
        .bind(&account_id)
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO voice_samples \
             (account_id,id,speaker_observation_id,voice_profile_id,embedding_space,channel_domain, \
              embedding,quality_score,eligibility,outlier,accepted) \
             VALUES($1,1,1,1,'voice-v1','mic',decode('00','hex'),0.99,'enroll',false,true)",
        )
        .bind(&account_id)
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO voice_profile_revisions \
             (account_id,id,profile_id,status,derivation_version,scorer_version,representative_kind, \
              centroid,sample_count,medoid_sample_id,person_id,reason_code,active) \
             VALUES($1,1,1,'stable',1,2,'medoid_trimmed_centroid',decode('00','hex'),1,1,1, \
                    'contract',true)",
        )
        .bind(&account_id)
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO voice_sample_profile_assignments \
             (account_id,id,sample_id,profile_id,active) VALUES($1,1,1,1,true)",
        )
        .bind(&account_id)
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO person_name_claims \
             (account_id,id,person_id,name,normalized_name,source_event_id,speaker_observation_id, \
              observed_at,evidence_kind,evidence,confidence,status) \
             VALUES($1,1,1,'Lynn','lynn','capture-contract-0',1,'2026-08-27T12:00:01Z', \
                    'self_identification','{\"literal\":true}'::jsonb,0.99,'accepted')",
        )
        .bind(&account_id)
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO identity_evidence \
             (account_id,id,person_id,voice_profile_id,source_event_id,observed_at, \
              speaker_observation_id,kind,claimed_name,evidence,score,status) \
             VALUES($1,1,1,1,'capture-contract-0','2026-08-27T12:00:01Z',1, \
                    'self_identification','Lynn','{\"literal\":true}'::jsonb,0.99,'accepted')",
        )
        .bind(&account_id)
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO person_facts \
             (account_id,id,person_id,predicate,value,evidence,derivation_version,status, \
              source_event_id,speaker_observation_id,observed_at,literal_evidence,confidence) \
             VALUES($1,1,1,'role','staff engineer','{\"literal\":true}'::jsonb,1,'active', \
                    'capture-contract-0',1,'2026-08-27T12:00:02Z','I am a staff engineer',0.98)",
        )
        .bind(&account_id)
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO episode_speaker_slots \
             (account_id,id,episode_id,voice_profile_id,slot_ordinal) VALUES($1,1,1,1,0)",
        )
        .bind(&account_id)
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO episode_participants \
             (account_id,id,episode_id,participant_key,person_id,speaker_slot_id,attribution_kind) \
             VALUES($1,1,1,'person:1',1,1,'verified_voice')",
        )
        .bind(&account_id)
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO episode_final_briefs(account_id,episode_id,overview,decisions,action_items,important_links,open_questions) \
             VALUES($1,1,'Ready','[]'::jsonb,'[\"Ship\"]'::jsonb,'[]'::jsonb,'[]'::jsonb) \
             ON CONFLICT(account_id,episode_id) DO UPDATE SET \
               overview=excluded.overview,decisions=excluded.decisions, \
               action_items=excluded.action_items,important_links=excluded.important_links, \
               open_questions=excluded.open_questions",
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
        let evidence = repositories
            .memory_queries()
            .episode_members(&account_id, 1)
            .await
            .unwrap();
        assert_eq!(evidence["member_count"], 2);
        assert_eq!(evidence["participant_details"][0]["display_name"], "Lynn");
        assert_eq!(evidence["members"][1]["cloud_image_id"], "img_contract");
        assert_eq!(
            evidence["members"][1]["activity_summary"],
            "Reviewing the schema"
        );
        let people = repositories
            .memory_queries()
            .list_people(
                &account_id,
                &PeopleListRequest {
                    after_id: 0,
                    limit: 50,
                    query: Some("lynn".into()),
                },
            )
            .await
            .unwrap();
        assert_eq!(people.people.len(), 1);
        assert_eq!(people.people[0].voice_profile_count, 1);
        assert_eq!(people.people[0].fact_count, 1);
        let person = repositories
            .memory_queries()
            .person_profile(&account_id, 1)
            .await
            .unwrap();
        assert_eq!(person.voice_labels, vec!["Lynn"]);
        assert_eq!(
            person.voice_coverage,
            "Recognized from 1 high-quality samples across 1 stable acoustic profiles"
        );
        assert_eq!(person.aliases[0].name, "Lynn");
        assert_eq!(person.facts[0].value, "staff engineer");
        assert_eq!(person.evidence[0].claimed_name.as_deref(), Some("Lynn"));
        assert_eq!(person.recent_statements[0].episode_id, Some(1));
        let evidence_page = repositories
            .memory_queries()
            .person_evidence(&account_id, 1, None, 50)
            .await
            .unwrap();
        assert_eq!(evidence_page.evidence.len(), 1);
        let statement_page = repositories
            .memory_queries()
            .person_statements(&account_id, 1, None, 50)
            .await
            .unwrap();
        assert_eq!(statement_page.statements.len(), 1);
        assert_eq!(
            statement_page.statements[0].episode_title.as_deref(),
            Some("PostgreSQL rollout")
        );
        let person_memories = repositories
            .playback()
            .person_memories(&account_id, 1, None, 25, None)
            .await
            .unwrap();
        assert_eq!(person_memories.memories.len(), 1);
        assert_eq!(person_memories.memories[0].memory_id, 1);
        sqlx::query(
            "UPDATE capture_sessions SET last_event_at=now() WHERE account_id=$1 AND id=$2",
        )
        .bind(&account_id)
        .bind("session-contract")
        .execute(&pool)
        .await
        .unwrap();
        let recent_sessions = repositories
            .captures()
            .recent_sessions(&account_id, 8, 5, None)
            .await
            .unwrap();
        assert_eq!(recent_sessions.len(), 1);
        assert_eq!(recent_sessions[0].memories.len(), 1);
        let finished = repositories
            .captures()
            .finish_session(&account_id, "session-contract")
            .await
            .unwrap()
            .unwrap();
        assert!(finished.ended_at.is_some());
        assert_eq!(finished.memories.len(), 1);
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
        let browser = repositories
            .memory_queries()
            .browser_snapshot(&account_id, "capture-v2-browser:capture-contract-0")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(browser["browser_name"], "Safari");
        assert_eq!(browser["tabs"].as_array().unwrap().len(), 2);
        assert_eq!(browser["tabs"][0]["is_active"], true);
        let mcp_search = repositories
            .memory_queries()
            .mcp_search_transcripts(
                &account_id,
                &McpTranscriptSearchRequest {
                    query: "PostgreSQL".into(),
                    from: Some("2026-08-27T07:00:00-04:00".into()),
                    to: Some("2026-08-27T09:00:00-04:00".into()),
                    limit: 10,
                },
            )
            .await
            .unwrap();
        assert_eq!(mcp_search["count"], 1);
        assert_eq!(mcp_search["results"][0]["speaker"], "Lynn");
        assert!(!serde_json::to_string(&mcp_search)
            .unwrap()
            .contains("other tenant"));
        let mcp_context = repositories
            .memory_queries()
            .mcp_context(
                &account_id,
                &McpContextRequest {
                    at: "2026-08-27T08:00:00-04:00".into(),
                    window_seconds: 300,
                    limit: Some(10),
                },
            )
            .await
            .unwrap();
        assert_eq!(mcp_context["utterances"].as_array().unwrap().len(), 1);
        let mcp_range = repositories
            .memory_queries()
            .mcp_time_range(
                &account_id,
                &McpTimeRangeRequest {
                    from: "2026-08-27T07:00:00-04:00".into(),
                    to: "2026-08-27T09:00:00-04:00".into(),
                    limit: Some(10),
                },
            )
            .await
            .unwrap();
        assert_eq!(mcp_range["episodes"].as_array().unwrap().len(), 1);

        let billing_account = repositories
            .billing()
            .billing_account_id(&account_id)
            .await
            .unwrap();
        let invocation = repositories
            .model_usage()
            .begin_invocation(
                &account_id,
                VertexOperation::EpisodeSummary,
                "gemini-contract",
                "us-central1",
                &[7; 32],
            )
            .await
            .unwrap();
        assert_eq!(
            repositories
                .model_usage()
                .begin_invocation(
                    &account_id,
                    VertexOperation::EpisodeSummary,
                    "gemini-contract",
                    "us-central1",
                    &[7; 32],
                )
                .await
                .unwrap(),
            invocation
        );
        repositories
            .model_usage()
            .settle_response(
                &account_id,
                &invocation,
                &VertexMetadata {
                    model_version: Some("gemini-contract".into()),
                    traffic_type: Some("ON_DEMAND".into()),
                    usage: Some(VertexUsage {
                        prompt_details_present: true,
                        cache_details_present: true,
                        prompt_tokens: Some(10),
                        input_text_tokens: Some(10),
                        input_audio_tokens: Some(0),
                        input_image_tokens: Some(0),
                        cached_input_tokens: Some(0),
                        cached_input_text_tokens: Some(0),
                        cached_input_audio_tokens: Some(0),
                        cached_input_image_tokens: Some(0),
                        output_tokens: Some(4),
                        tool_use_prompt_tokens: Some(0),
                        thought_tokens: Some(0),
                        total_tokens: Some(14),
                    }),
                },
            )
            .await
            .unwrap();
        let usage_claim = repositories
            .model_usage()
            .pending_events(&account_id, &billing_account, false)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(usage_claim.events.len(), 2);
        assert!(usage_claim
            .events
            .iter()
            .any(|event| event.event_id == invocation));
        assert!(usage_claim
            .events
            .iter()
            .any(|event| event.event_id == finalization_event));
        assert!(repositories
            .model_usage()
            .pending_events(&account_id, &billing_account, false)
            .await
            .unwrap()
            .is_none());
        repositories
            .model_usage()
            .complete_delivery(
                &account_id,
                &usage_claim.claim_id,
                &usage_claim
                    .events
                    .iter()
                    .map(|event| event.event_id.clone())
                    .collect::<Vec<_>>(),
            )
            .await
            .unwrap();
        let coverage = repositories
            .model_usage()
            .pending_coverage(&account_id, &billing_account)
            .await
            .unwrap();
        assert_eq!(coverage.len(), 1);
        assert_eq!(coverage[0].snapshot.pending_events, 0);
        repositories
            .model_usage()
            .complete_coverage(
                &account_id,
                &coverage[0].claim_id,
                &coverage[0].snapshot.period,
                coverage[0].snapshot.sequence,
            )
            .await
            .unwrap();

        let export = repositories
            .memory_queries()
            .export(&account_id)
            .await
            .unwrap();
        let playback = repositories
            .playback()
            .dataset(&account_id, episode_ids[0], None)
            .await
            .unwrap()
            .expect("PostgreSQL playback dataset");
        assert_eq!(playback.memory_id, episode_ids[0]);
        assert!(playback.projection_revision > 0);
        assert_eq!(
            export
                .get("capture_events")
                .and_then(serde_json::Value::as_array)
                .map(Vec::len),
            Some(2)
        );
        assert!(export
            .get("capture_events")
            .and_then(serde_json::Value::as_array)
            .and_then(|events| events.first())
            .and_then(serde_json::Value::as_object)
            .is_some_and(|event| !event.contains_key("account_id")));
        assert_eq!(
            export
                .get("voice_profile_representatives")
                .and_then(serde_json::Value::as_array)
                .map(Vec::len),
            Some(0)
        );

        let episode_deletions = repositories
            .episode_deletions()
            .expect("PostgreSQL episode deletion repository");
        let plan = match episode_deletions
            .begin_episode_deletion(&account_id, episode_ids[0])
            .await
            .unwrap()
        {
            EpisodeDeletionStart::Pending(plan) => plan,
            other => panic!("expected pending episode deletion, got {other:?}"),
        };
        assert_eq!(plan.purge.deleted_utterances, 1);
        assert_eq!(plan.purge.deleted_screenshots, 1);
        assert_eq!(plan.purge.deleted_segments, 1);
        assert_eq!(
            plan.media_object_keys,
            vec![object_key.clone(), "screenshots/contract.jpg".into()]
        );
        assert!(matches!(
            episode_deletions
                .begin_episode_deletion(&account_id, episode_ids[0])
                .await
                .unwrap(),
            EpisodeDeletionStart::Pending(replayed) if replayed == plan
        ));
        let purge = episode_deletions
            .complete_episode_deletion(&account_id, &plan)
            .await
            .unwrap();
        assert_eq!(purge, plan.purge);
        assert!(matches!(
            episode_deletions
                .begin_episode_deletion(&account_id, episode_ids[0])
                .await
                .unwrap(),
            EpisodeDeletionStart::Complete(replayed) if replayed == purge
        ));
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT count(*) FROM episodes WHERE account_id=$1",)
                .bind(&account_id)
                .fetch_one(&pool)
                .await
                .unwrap(),
            0
        );
        assert_eq!(
            sqlx::query_scalar::<_, i64>(
                "SELECT count(*) FROM capture_events WHERE account_id=$1",
            )
            .bind(&account_id)
            .fetch_one(&pool)
            .await
            .unwrap(),
            0
        );

        let billing_detach_id = repositories
            .billing()
            .billing_account_id_for_deletion(&account_id)
            .await
            .unwrap();
        let deletion_upload = repositories
            .captures()
            .reserve_media_upload(
                &account_id,
                "deletion-race-event",
                "deletion-race-asset",
                &crate::store::canonical_capture_media_object_key(
                    &account_id,
                    "deletion-race-asset",
                )
                .unwrap(),
                &"d".repeat(64),
            )
            .await
            .unwrap();
        assert!(deletion_upload.is_some());
        assert!(matches!(
            repositories
                .lifecycle()
                .begin_account_deletion(&account_id)
                .await,
            Err(crate::error::EnclaveError::Conflict(_))
        ));
        sqlx::query(
            "UPDATE capture_upload_intents SET expires_at=now()-interval '1 second' \
              WHERE account_id=$1 AND event_id='deletion-race-event'",
        )
        .bind(&account_id)
        .execute(&pool)
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
