//! PostgreSQL implementation of the ADR-0040 application persistence ports.
//!
//! Serving startup selects this complete implementation as one authority. It
//! never constructs a readable or writable legacy SQLite/GCS authority.

mod activation;
mod admission;
mod aggregate_audit;
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
mod memory_reconciliation;
mod model_usage;
mod notification;
mod oauth;
mod playback;
mod query;
mod recording_retention;
mod schema_release;
mod work;

use std::str::FromStr;
use std::time::Duration;

use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
use sqlx::{PgPool, Row};

use crate::error::{EnclaveError, Result};

pub(crate) use aggregate_audit::{parse_postgres_audit_since, AggregateAuditFailure};
#[cfg(test)]
use schema_release::SchemaReleaseStatus;
pub(crate) use schema_release::{
    verify_memory_reconciliation_activation_authorization,
    verify_schema_finalization_authorization, MemoryReconciliationActivationReceipt,
    MemoryReconciliationActivationSignature, SchemaFinalizationReceipt,
    SchemaFinalizationSignature, VerifiedMemoryReconciliationActivationReceipt,
    VerifiedSchemaFinalizationReceipt,
};

pub(crate) const EXPECTED_SCHEMA_VERSION: i64 = 26;
pub(crate) const MEMORY_RECONCILIATION_ACTIVATION_SCHEMA_VERSION: i64 = 27;
const MEMORY_RECONCILIATION_EXPAND_FROM_VERSION: i64 = 24;

// The two real-PostgreSQL contract tests deliberately exercise the same
// production session-scoped release lock. Rust may schedule those tests in
// parallel, so serialize only their release setup while leaving the product
// lock fail-closed and independently covered by the concurrency fixtures.
#[cfg(test)]
static POSTGRES_RELEASE_CONTRACT_MUTEX: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct InstalledSchemaState {
    version: i64,
    expanded_through_version: Option<i64>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ServingSchemaState {
    ExpandedTransition,
    Finalized,
}

fn classify_serving_schema(state: InstalledSchemaState) -> Result<ServingSchemaState> {
    match (state.version, state.expanded_through_version) {
        (MEMORY_RECONCILIATION_EXPAND_FROM_VERSION, Some(EXPECTED_SCHEMA_VERSION)) => {
            Ok(ServingSchemaState::ExpandedTransition)
        }
        (EXPECTED_SCHEMA_VERSION, Some(EXPECTED_SCHEMA_VERSION)) => {
            Ok(ServingSchemaState::Finalized)
        }
        _ => Err(EnclaveError::Config(format!(
            "PostgreSQL schema marker {}/{} is not compatible with finalized version {} or its receipted {}/{} expand",
            state.version,
            state
                .expanded_through_version
                .map(|version| version.to_string())
                .unwrap_or_else(|| "none".into()),
            EXPECTED_SCHEMA_VERSION,
            MEMORY_RECONCILIATION_EXPAND_FROM_VERSION,
            EXPECTED_SCHEMA_VERSION,
        ))),
    }
}

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

fn installed_schema_state_from_row(row: &sqlx::postgres::PgRow) -> Result<InstalledSchemaState> {
    Ok(InstalledSchemaState {
        version: row.try_get("version")?,
        expanded_through_version: row.try_get("expanded_through_version")?,
    })
}

async fn transaction_schema_state(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
) -> Result<InstalledSchemaState> {
    let row = sqlx::query(
        "SELECT version, \
                (to_jsonb(schema_marker)->>'expanded_through_version')::bigint \
                    AS expanded_through_version \
           FROM persistence_schema schema_marker WHERE singleton=true",
    )
    .fetch_optional(&mut **transaction)
    .await?;
    row.as_ref()
        .map(installed_schema_state_from_row)
        .transpose()?
        .ok_or_else(|| {
            EnclaveError::Config("PostgreSQL persistence schema marker is missing".into())
        })
}

impl PostgresPersistence {
    #[cfg(test)]
    pub(crate) fn disconnected_test_instance() -> Self {
        let options =
            PgConnectOptions::from_str("postgresql://kioku-test:unused@127.0.0.1:1/kioku_test")
                .expect("static test PostgreSQL URL");
        Self {
            pool: PgPoolOptions::new()
                .max_connections(1)
                .connect_lazy_with(options),
        }
    }

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

    pub(crate) fn pool(&self) -> &PgPool {
        &self.pool
    }

    /// Build a complete disposable contract database. Production releases use
    /// the separately confirmed expand/finalize methods below; serving startup
    /// calls `verify_schema` and never either mutation path.
    #[cfg(test)]
    pub(crate) async fn migrate(&self) -> Result<()> {
        self.migrate_to_version(EXPECTED_SCHEMA_VERSION).await
    }

    #[cfg(test)]
    async fn migrate_to_memory_reconciliation_predecessor(&self) -> Result<()> {
        self.migrate_to_version(MEMORY_RECONCILIATION_EXPAND_FROM_VERSION)
            .await
    }

    #[cfg(test)]
    async fn migrate_to_version(&self, target_version: i64) -> Result<()> {
        if !matches!(
            target_version,
            MEMORY_RECONCILIATION_EXPAND_FROM_VERSION | EXPECTED_SCHEMA_VERSION
        ) {
            return Err(EnclaveError::Config(format!(
                "unsupported PostgreSQL migration target {target_version}"
            )));
        }
        let mut transaction = self.pool.begin().await?;
        advisory_transaction_lock(&mut transaction, "schema", "adr-0040").await?;
        let installed = sqlx::query_scalar::<_, bool>(
            "SELECT to_regclass(format('%I.%I',current_schema(),'persistence_schema')) IS NOT NULL",
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
            version = 21;
        }
        if version == 21 {
            sqlx::raw_sql(include_str!(
                "../../../migrations/0022_reference_batch_billing.sql"
            ))
            .execute(&mut *transaction)
            .await?;
            version = 22;
        }
        if version == 22 {
            sqlx::raw_sql(include_str!(
                "../../../migrations/0023_reviewer_fixture.sql"
            ))
            .execute(&mut *transaction)
            .await?;
            version = 23;
        }
        if version == 23 {
            sqlx::raw_sql(include_str!("../../../migrations/0024_fleet_admission.sql"))
                .execute(&mut *transaction)
                .await?;
        }
        transaction.commit().await?;
        if target_version == EXPECTED_SCHEMA_VERSION {
            loop {
                let result = self.expand_memory_reconciliation_release_schema().await?;
                match result.status {
                    SchemaReleaseStatus::ExpandInProgress => continue,
                    SchemaReleaseStatus::Expanded | SchemaReleaseStatus::AlreadyExpanded => {
                        let authorization = schema_release::test_finalization_authorization();
                        self.finalize_memory_reconciliation_release_schema(&authorization)
                            .await?;
                        break;
                    }
                    SchemaReleaseStatus::AlreadyFinalized => break,
                    SchemaReleaseStatus::Finalized => {
                        return Err(EnclaveError::Store(
                            "expand returned an impossible finalized result".into(),
                        ));
                    }
                }
            }
            self.verify_schema().await
        } else {
            let row = sqlx::query(
                "SELECT version, \
                        (to_jsonb(schema_marker)->>'expanded_through_version')::bigint \
                            AS expanded_through_version \
                   FROM persistence_schema schema_marker WHERE singleton=true",
            )
            .fetch_one(&self.pool)
            .await?;
            let state = installed_schema_state_from_row(&row)?;
            if state
                != (InstalledSchemaState {
                    version: MEMORY_RECONCILIATION_EXPAND_FROM_VERSION,
                    expanded_through_version: None,
                })
            {
                return Err(EnclaveError::Store(
                    "PostgreSQL predecessor migration did not stop at pristine schema 24".into(),
                ));
            }
            Ok(())
        }
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

    use sqlx::Row;

    use super::{
        advisory_transaction_lock, classify_serving_schema, media_processing, InstalledSchemaState,
        PostgresPersistence, PostgresPoolConfig, SchemaReleaseStatus, ServingSchemaState,
        EXPECTED_SCHEMA_VERSION, MEMORY_RECONCILIATION_EXPAND_FROM_VERSION,
    };
    use crate::cp::media::AudioTurn;
    use crate::cp::vertex::{VertexMetadata, VertexOperation, VertexUsage};
    use crate::error::{CaptureReferenceFailureReason, EnclaveError};
    use crate::gcs::FakeGcs;
    use crate::persistence::identity::{AccountStatus, AppleAccountGrant};
    use crate::persistence::oauth::{
        AuthorizationCodeExchange, ConsentApproval, DirectAuthorizationCode, OAuthClientDefinition,
        PendingConsent, RefreshTokenRotation,
    };
    use crate::persistence::{
        AudioMediaSettlement, CaptureCommit, CapturePreflight, CaptureSessionStage,
        EmailProviderOutcome, EpisodeDeletionStart, EpisodeInput, EpisodeListRequest,
        FinalizationRequest, FinalizationScreenResult, FinalizationSettlement, FrozenEmailDelivery,
        FrozenPushDelivery, FrozenWebhookDelivery, McpContextRequest, McpTimeRangeRequest,
        McpTranscriptSearchRequest, MediaProcessingClass, MediaScreenProjection,
        MediaUsageSettlement, MemoryFeedRequest, PeopleListRequest, PushInstallation,
        PushProviderOutcome, RecordingRetentionChangeRequest, ReferenceBatchCommit,
        ScreenMediaSettlement, ScreenshotMediaLocator, SummaryWindowSettlement,
        VertexInvocationAdmission, WebhookProviderOutcome, WebhookSubscription,
    };
    use crate::persistence::{GcsMediaObjectStore, MediaObjectStore, RepositorySet};
    use crate::persistence::{RecordingRetentionPolicy, RECORDING_RETENTION_CONSENT_VERSION};
    use crate::persistence::{SearchHit, SearchRequest};

    async fn test_persistence() -> Option<PostgresPersistence> {
        let contract_required =
            std::env::var("KIOKU_REQUIRE_POSTGRES_CONTRACT").as_deref() == Ok("1");
        let database_url = match std::env::var("KIOKU_TEST_POSTGRES_URL") {
            Ok(value) => value,
            Err(_) => {
                assert!(
                    !contract_required,
                    "KIOKU_TEST_POSTGRES_URL is required by the real PostgreSQL contract gate"
                );
                eprintln!("KIOKU_TEST_POSTGRES_URL is unset; skipping real PostgreSQL contract");
                return None;
            }
        };
        let _release_contract_guard = super::POSTGRES_RELEASE_CONTRACT_MUTEX.lock().await;
        let persistence = PostgresPersistence::connect(PostgresPoolConfig {
            database_url,
            root_ca_pem: None,
            max_connections: 8,
            acquire_timeout: Duration::from_secs(5),
            statement_timeout: Duration::from_secs(10),
        })
        .await
        .unwrap();
        let schema_was_installed = sqlx::query_scalar::<_, bool>(
            "SELECT to_regclass(format('%I.%I',current_schema(),'persistence_schema')) IS NOT NULL",
        )
        .fetch_one(persistence.pool())
        .await
        .unwrap();
        if schema_was_installed {
            persistence.migrate().await.unwrap();
        } else {
            // A fresh real-PostgreSQL contract proves the populated production
            // release shape rather than jumping directly from an empty database
            // to finalized v26. The legacy row must survive expand/backfill, the
            // marker must remain 24 for predecessor readiness, and the writer
            // must stay fenced until the separate finalize phase.
            persistence
                .migrate_to_memory_reconciliation_predecessor()
                .await
                .unwrap();
            sqlx::raw_sql(
                "INSERT INTO accounts(id,email,primary_provider,primary_subject) \
                 VALUES('schema-release-contract','schema-release@example.com','google','schema-release-subject'); \
                 INSERT INTO screenshots(account_id,id,captured_at,ocr_text,source_key) \
                 VALUES('schema-release-contract',1,'2026-08-30T12:00:00Z','legacy source','schema-release-shot'); \
                 INSERT INTO episodes(account_id,id,started_at,ended_at,type,title,summary,finalized_at,updated_at) \
                 VALUES('schema-release-contract',1,'2026-08-30T12:00:00Z','2026-08-30T12:01:00Z', \
                        'work','Legacy memory','Preserved across expand','2026-08-30T12:02:00Z',now()), \
                       ('schema-release-contract',2,'2026-08-30T12:03:00Z','2026-08-30T12:04:00Z', \
                        'work','Ambiguous legacy duplicate','Preflight must refuse this row',NULL,now()); \
                 INSERT INTO episode_members(account_id,episode_id,record_type,record_id) \
                 VALUES('schema-release-contract',1,'screenshot',1), \
                       ('schema-release-contract',2,'screenshot',1);",
            )
            .execute(persistence.pool())
            .await
            .unwrap();
            let refused = persistence
                .expand_memory_reconciliation_release_schema()
                .await
                .unwrap_err();
            assert!(
                refused
                    .to_string()
                    .contains("repair any source assigned to more than one legacy episode"),
                "unexpected duplicate-source preflight error: {refused}"
            );
            assert_eq!(
                sqlx::query_as::<_, (i64, bool, bool, String)>(
                    "SELECT version, \
                            EXISTS(SELECT 1 FROM information_schema.columns \
                                    WHERE table_schema=current_schema() \
                                      AND table_name='persistence_schema' \
                                      AND column_name='expanded_through_version'), \
                            to_regclass('public.memory_handles') IS NOT NULL, \
                            (SELECT phase FROM persistence_schema_releases \
                              WHERE release_version=26) \
                       FROM persistence_schema WHERE singleton=true"
                )
                .fetch_one(persistence.pool())
                .await
                .unwrap(),
                (24, true, false, "installing".into()),
                "failed ownership guard must retain the receipted account-status expansion and resumable release ledger while leaving the predecessor marker untouched"
            );
            assert!(sqlx::query_scalar::<_, String>(
                "SELECT pg_get_constraintdef(oid) FROM pg_constraint \
                  WHERE conrelid='accounts'::regclass AND conname='accounts_status_check'"
            )
            .fetch_one(persistence.pool())
            .await
            .unwrap()
            .contains("deletion_requested"));
            sqlx::query(
                "UPDATE accounts SET status='deletion_requested' \
                  WHERE id='schema-release-contract'",
            )
            .execute(persistence.pool())
            .await
            .unwrap();
            sqlx::query("UPDATE accounts SET status='active' WHERE id='schema-release-contract'")
                .execute(persistence.pool())
                .await
                .unwrap();
            assert_eq!(
                sqlx::query_scalar::<_, i64>(
                    "SELECT version FROM persistence_schema WHERE singleton=true"
                )
                .fetch_one(persistence.pool())
                .await
                .unwrap(),
                24,
                "the receipted account-status expansion must remain writable without advancing the v24 predecessor marker"
            );
            sqlx::query("DELETE FROM episodes WHERE account_id='schema-release-contract' AND id=2")
                .execute(persistence.pool())
                .await
                .unwrap();
            sqlx::raw_sql(
                "ALTER TABLE vertex_usage_events \
                     DROP CONSTRAINT vertex_usage_events_operation_check; \
                 ALTER TABLE vertex_usage_events \
                     ADD CONSTRAINT vertex_usage_events_operation_check \
                     CHECK (operation IN ( \
                         'audio_understanding','screen_understanding', \
                         'episode_summarization','episode_finalization','unexpected_operation'));",
            )
            .execute(persistence.pool())
            .await
            .unwrap();
            let drifted_vertex_constraint = persistence
                .expand_memory_reconciliation_release_schema()
                .await
                .unwrap_err();
            assert!(drifted_vertex_constraint.to_string().contains(
                "schema-24 Vertex operation constraint is not the validated predecessor contract"
            ));
            assert_eq!(
                sqlx::query_as::<_, (i64, Option<i64>, i64)>(
                    "SELECT marker.version,marker.expanded_through_version, \
                            count(step.step_name) FILTER (WHERE step.step_name='vertex_operation') \
                       FROM persistence_schema marker \
                       LEFT JOIN persistence_schema_release_steps step ON true \
                      WHERE marker.singleton=true \
                      GROUP BY marker.version,marker.expanded_through_version"
                )
                .fetch_one(persistence.pool())
                .await
                .unwrap(),
                (24, None, 0),
                "a drifted predecessor constraint must not advance or receipt the Vertex step"
            );
            sqlx::raw_sql(
                "ALTER TABLE vertex_usage_events \
                     DROP CONSTRAINT vertex_usage_events_operation_check; \
                 ALTER TABLE vertex_usage_events \
                     ADD CONSTRAINT vertex_usage_events_operation_check \
                     CHECK (operation IN ( \
                         'audio_understanding','screen_understanding', \
                         'episode_summarization','episode_finalization'));",
            )
            .execute(persistence.pool())
            .await
            .unwrap();
            assert_eq!(
                persistence
                    .expand_memory_reconciliation_release_schema_with_batch_budget(1)
                    .await
                    .unwrap()
                    .status,
                SchemaReleaseStatus::ExpandInProgress
            );
            assert_eq!(
                sqlx::query_as::<_, (i64, Option<i64>, String)>(
                    "SELECT marker.version,marker.expanded_through_version,release.phase \
                       FROM persistence_schema marker \
                       JOIN persistence_schema_releases release ON release.release_version=26 \
                      WHERE marker.singleton=true"
                )
                .fetch_one(persistence.pool())
                .await
                .unwrap(),
                (24, None, "backfilling".into()),
                "an interrupted bounded expand must retain predecessor readiness"
            );
            assert_eq!(
                persistence
                    .expand_memory_reconciliation_release_schema()
                    .await
                    .unwrap()
                    .status,
                SchemaReleaseStatus::Expanded
            );
            let marker = sqlx::query_as::<_, (i64, Option<i64>)>(
                "SELECT version,expanded_through_version FROM persistence_schema WHERE singleton=true",
            )
            .fetch_one(persistence.pool())
            .await
            .unwrap();
            assert_eq!(marker, (24, Some(26)));
            assert_eq!(
                sqlx::query_scalar::<_, i64>(
                    "SELECT version FROM persistence_schema WHERE singleton=true"
                )
                .fetch_one(persistence.pool())
                .await
                .unwrap(),
                24,
                "the v24 predecessor must continue to observe its exact marker"
            );
            assert_eq!(
                sqlx::query_as::<_, (String, String, i64)>(
                    "SELECT episode.structure_state,handle.state,count(member.record_id) \
                       FROM episodes episode \
                       JOIN memory_handles handle ON handle.account_id=episode.account_id AND handle.episode_id=episode.id \
                       LEFT JOIN active_episode_members member ON member.account_id=episode.account_id AND member.episode_id=episode.id \
                      WHERE episode.account_id='schema-release-contract' AND episode.id=1 \
                      GROUP BY episode.structure_state,handle.state"
                )
                .fetch_one(persistence.pool())
                .await
                .unwrap(),
                ("reconciled".into(), "active".into(), 1)
            );
            persistence.verify_schema().await.unwrap();
            assert!(persistence
                .verify_reconciliation_runtime_schema(
                    Some("test-model"),
                    "us-central1",
                    Some(&[0_u8; 32]),
                )
                .await
                .is_err());
            let mut invalid_fleet_receipt = super::schema_release::test_finalization_receipt();
            invalid_fleet_receipt.predecessor_instances = 1;
            assert!(
                super::schema_release::test_verify_finalization_receipt(invalid_fleet_receipt)
                    .is_err()
            );
            assert!(
                super::schema_release::test_reject_tampered_finalization_signature(
                    super::schema_release::test_finalization_receipt()
                )
                .is_err()
            );
            assert_eq!(
                sqlx::query_scalar::<_, i64>(
                    "SELECT version FROM persistence_schema WHERE singleton=true"
                )
                .fetch_one(persistence.pool())
                .await
                .unwrap(),
                24,
                "invalid fleet evidence must not mutate the predecessor marker"
            );
            let fleet_authorization = super::schema_release::test_finalization_authorization();
            assert_eq!(
                persistence
                    .finalize_memory_reconciliation_release_schema(&fleet_authorization)
                    .await
                    .unwrap()
                    .status,
                SchemaReleaseStatus::Finalized
            );
            persistence
                .verify_reconciliation_runtime_schema(
                    Some("test-model"),
                    "us-central1",
                    Some(&[0_u8; 32]),
                )
                .await
                .unwrap();
            assert_eq!(
                persistence
                    .finalize_memory_reconciliation_release_schema(&fleet_authorization)
                    .await
                    .unwrap()
                    .status,
                SchemaReleaseStatus::AlreadyFinalized
            );
        }
        persistence.verify_schema().await.unwrap();
        // Reset every business table so this contract proves a database can be
        // reused across repeated local/full-suite runs. A hand-maintained list
        // silently missed newly added content and delivery tables and made the
        // second run observe stale terminal receipts. Keep only SQLx's migration
        // ledger and the release schema-version receipt.
        sqlx::raw_sql(
            "DO $$
             DECLARE tables_to_reset text;
             BEGIN
               SELECT string_agg(format('%I.%I', schemaname, tablename), ', ')
                 INTO tables_to_reset
                 FROM pg_tables
                WHERE schemaname = 'public'
                  AND tablename NOT IN ( \
                      '_sqlx_migrations','persistence_schema','persistence_schema_releases', \
                      'persistence_schema_release_steps');
               IF tables_to_reset IS NOT NULL THEN
                 EXECUTE 'TRUNCATE TABLE ' || tables_to_reset || ' RESTART IDENTITY CASCADE';
               END IF;
             END
             $$;
             ALTER SEQUENCE push_token_generation_seq RESTART WITH 1;
             INSERT INTO provider_send_lanes(provider)
             VALUES ('email'), ('webhook'), ('push');",
        )
        .execute(persistence.pool())
        .await
        .unwrap();
        Some(persistence)
    }

    #[test]
    fn serving_accepts_only_the_receipted_expand_or_finalized_schema() {
        assert_eq!(
            classify_serving_schema(InstalledSchemaState {
                version: MEMORY_RECONCILIATION_EXPAND_FROM_VERSION,
                expanded_through_version: Some(EXPECTED_SCHEMA_VERSION),
            })
            .unwrap(),
            ServingSchemaState::ExpandedTransition
        );
        assert_eq!(
            classify_serving_schema(InstalledSchemaState {
                version: EXPECTED_SCHEMA_VERSION,
                expanded_through_version: Some(EXPECTED_SCHEMA_VERSION),
            })
            .unwrap(),
            ServingSchemaState::Finalized
        );
        for refused in [
            InstalledSchemaState {
                version: MEMORY_RECONCILIATION_EXPAND_FROM_VERSION,
                expanded_through_version: None,
            },
            InstalledSchemaState {
                version: EXPECTED_SCHEMA_VERSION,
                expanded_through_version: None,
            },
            InstalledSchemaState {
                version: MEMORY_RECONCILIATION_EXPAND_FROM_VERSION,
                expanded_through_version: Some(EXPECTED_SCHEMA_VERSION + 1),
            },
            InstalledSchemaState {
                version: EXPECTED_SCHEMA_VERSION + 1,
                expanded_through_version: Some(EXPECTED_SCHEMA_VERSION + 1),
            },
        ] {
            assert!(classify_serving_schema(refused).is_err());
        }
    }

    #[test]
    fn memory_reconciliation_release_is_online_receipted_then_marker_finalized() {
        let account_deletion =
            include_str!("../../../migrations/0026_account_deletion_compatibility.sql");
        let cold_objects = include_str!("../../../migrations/0026_memory_reconciliation.sql");
        let unique_guard = include_str!(
            "../../../migrations/0026_memory_reconciliation_episode_members_unique_index.sql"
        );
        let capture_sessions = include_str!(
            "../../../migrations/0026_memory_reconciliation_capture_sessions_index.sql"
        );
        let expand =
            include_str!("../../../migrations/0026_memory_reconciliation_expand_receipt.sql");
        let finalize = include_str!("../../../migrations/0026_memory_reconciliation_finalize.sql");
        let normalized_cold_objects = cold_objects
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ");
        assert!(unique_guard.contains("CREATE UNIQUE INDEX CONCURRENTLY"));
        assert!(account_deletion.contains("schema-24 account status constraint"));
        assert!(account_deletion.contains("deletion_requested"));
        assert!(!account_deletion.contains("UPDATE persistence_schema"));
        assert!(capture_sessions.contains("CREATE INDEX CONCURRENTLY"));
        assert!(!normalized_cold_objects.contains("UPDATE episodes"));
        assert!(!normalized_cold_objects
            .contains("INSERT INTO memory_handles(account_id,episode_id,state) SELECT"));
        assert!(!cold_objects.contains("IF NOT EXISTS"));
        assert!(!cold_objects.contains("CREATE OR REPLACE"));
        assert!(expand.contains("SET expanded_through_version=26"));
        assert!(!expand.contains("SET version=26"));
        assert!(finalize.contains("finalization_receipt=$1::jsonb"));
        assert!(finalize.contains("finalization_receipt_sha256=$2"));
        assert!(finalize.contains("finalization_receipt_signature=$3"));
        assert!(finalize.contains("finalization_receipt_key_sha256=$4"));
        assert!(finalize.contains("clock_timestamp()+interval '60 seconds'"));
        assert!(finalize.contains("SET version=26"));
        assert!(!finalize.contains("CREATE TABLE"));
        assert!(!finalize.contains("ALTER TABLE"));
    }

    #[tokio::test]
    async fn postgres_control_plane_contract() {
        let Some(persistence) = test_persistence().await else {
            return;
        };
        let persistence = Arc::new(persistence);
        let pool = persistence.pool().clone();

        // Migration 0026 must stop rather than arbitrarily assign a raw source
        // that legacy data linked to two memories. Exercise its PostgreSQL
        // exception contract against a temporary legacy-shaped projection.
        let mut duplicate_preflight = pool.begin().await.unwrap();
        sqlx::raw_sql(
            "CREATE TEMP TABLE episode_members( \
                 account_id text NOT NULL,episode_id bigint NOT NULL, \
                 record_type text NOT NULL,record_id bigint NOT NULL) ON COMMIT DROP; \
             INSERT INTO episode_members VALUES \
                 ('duplicate-contract',1,'screenshot',7), \
                 ('duplicate-contract',2,'screenshot',7);",
        )
        .execute(&mut *duplicate_preflight)
        .await
        .unwrap();
        let duplicate_error = sqlx::raw_sql(
            "CREATE UNIQUE INDEX duplicate_contract_source_guard \
             ON episode_members(account_id,record_type,record_id)",
        )
        .execute(&mut *duplicate_preflight)
        .await
        .unwrap_err();
        assert_eq!(
            duplicate_error
                .as_database_error()
                .and_then(|error| error.code())
                .map(|code| code.into_owned())
                .as_deref(),
            Some("23505")
        );
        duplicate_preflight.rollback().await.unwrap();

        let media_gcs: Arc<dyn crate::gcs::GcsClient> = Arc::new(FakeGcs::new());
        let media_objects: Arc<dyn MediaObjectStore> =
            Arc::new(GcsMediaObjectStore::new(media_gcs));
        let repositories = Arc::new(RepositorySet::postgres(
            Arc::clone(&persistence),
            media_objects,
        ));

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

        let admission = repositories.admission();
        assert!(admission
            .consume_rate("contract-rate", &account_id, 2.0, 0.000_001)
            .await
            .unwrap());
        assert!(admission
            .consume_rate("contract-rate", &account_id, 2.0, 0.000_001)
            .await
            .unwrap());
        assert!(!admission
            .consume_rate("contract-rate", &account_id, 2.0, 0.000_001)
            .await
            .unwrap());
        assert!(admission
            .acquire_concurrency(
                "contract-concurrency",
                "holder-a",
                2,
                Duration::from_secs(60)
            )
            .await
            .unwrap());
        assert!(admission
            .acquire_concurrency(
                "contract-concurrency",
                "holder-b",
                2,
                Duration::from_secs(60)
            )
            .await
            .unwrap());
        assert!(!admission
            .acquire_concurrency(
                "contract-concurrency",
                "holder-c",
                2,
                Duration::from_secs(60)
            )
            .await
            .unwrap());
        admission
            .release_concurrency("contract-concurrency", "holder-a")
            .await
            .unwrap();
        assert!(admission
            .acquire_concurrency(
                "contract-concurrency",
                "holder-c",
                2,
                Duration::from_secs(60)
            )
            .await
            .unwrap());

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
            .install_media_dek(&account_id, "wrapped-media-key-1")
            .await
            .unwrap();
        assert_eq!(first_media_key, "wrapped-media-key-1");
        let raced_media_key = repositories
            .captures()
            .install_media_dek(&account_id, "wrapped-media-key-2")
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
        let object_key = crate::gcs::canonical_capture_media_object_key(
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

        let mut first_batch_reference = reference.clone();
        first_batch_reference.event_id = "capture-contract-batch-1".into();
        let mut invalid_second_reference = reference.clone();
        invalid_second_reference.event_id = "capture-contract-batch-2".into();
        invalid_second_reference.sequence = 2;
        invalid_second_reference.source_monotonic_ns = 3000;
        invalid_second_reference
            .reference
            .as_mut()
            .unwrap()
            .canonical_event_id = "capture-contract-missing-canonical".into();
        let first_batch_digest = crate::cp::media::manifest_digest(&first_batch_reference).unwrap();
        let invalid_second_digest =
            crate::cp::media::manifest_digest(&invalid_second_reference).unwrap();
        let batch_error = repositories
            .captures()
            .commit_reference_batch(ReferenceBatchCommit {
                account_id: account_id.clone(),
                events: vec![first_batch_reference, invalid_second_reference],
                manifest_digests: vec![first_batch_digest, invalid_second_digest],
                committed_at: "2026-08-27T12:00:03.500Z".into(),
            })
            .await
            .unwrap_err();
        assert!(matches!(
            batch_error,
            EnclaveError::CaptureReferenceBatch {
                reason: CaptureReferenceFailureReason::CanonicalUnavailable,
                index: 1,
                sequence: 2,
            }
        ));
        for event_id in ["capture-contract-batch-1", "capture-contract-batch-2"] {
            assert!(repositories
                .captures()
                .event_status(&account_id, event_id)
                .await
                .unwrap()
                .is_none());
        }
        assert_eq!(
            repositories
                .captures()
                .stream_ack(&account_id, "screen-contract")
                .await
                .unwrap(),
            0,
            "the invalid second item must roll back the valid first item"
        );

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
        let media = repositories.media_processing();
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
        let screen_attempt = media_processing::test_stage_media_provider_success(
            persistence.as_ref(),
            &screen_claim,
            1_024,
        )
        .await
        .unwrap();
        let screen_usage_event_id = screen_attempt.event_id.clone();
        media
            .settle_usage(MediaUsageSettlement {
                claim: screen_claim.clone(),
                provider_attempt: screen_attempt.clone(),
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
                provider_attempt: screen_attempt.clone(),
                results: vec![screen_projection.clone()],
            })
            .await
            .unwrap();
        // Lost-response replay is a no-op, and the durable result remains
        // authoritative even after the original lease deadline.
        media
            .settle_screens(ScreenMediaSettlement {
                claim: screen_claim,
                provider_attempt: screen_attempt,
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
        let memory = repositories.memory_formation();
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
                model: Some("contract-model".into()),
                substance: Some("normal".into()),
                visual_evidence: Some("useful".into()),
                minute_summaries: Some(Vec::new()),
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

        // The activation-capable candidate must remain dark while the durable
        // v27 contract is absent. Even source-settled drafts on schema 26 must
        // not be claimed or sent to the reconciliation provider. The isolated
        // v27 contract below exercises the active protocol after a signed
        // transition.
        let reconciliation_account_id = "reconciliation-contract-account".to_owned();
        sqlx::query(
            "INSERT INTO accounts(id,email,primary_provider,primary_subject) \
             VALUES($1,'reconciliation@example.com','google','reconciliation-contract-subject')",
        )
        .bind(&reconciliation_account_id)
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO screenshots(account_id,id,captured_at,active_app,ocr_text,source_key) \
             VALUES($1,1,'2026-08-27T10:00:00Z','Notes','first topic','reconciliation-shot-1'), \
                   ($1,2,'2026-08-27T10:30:00Z','Notes','continued topic','reconciliation-shot-2')",
        )
        .bind(&reconciliation_account_id)
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO episodes(account_id,id,started_at,ended_at,type,title,summary,substance,visual_evidence,updated_at) \
             VALUES($1,1,'2026-08-27T10:00:00Z','2026-08-27T10:01:00Z','work','Draft one','First half','normal','useful',now()), \
                   ($1,2,'2026-08-27T10:30:00Z','2026-08-27T10:31:00Z','work','Draft two','Second half','normal','useful',now())",
        )
        .bind(&reconciliation_account_id)
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO episode_members(account_id,episode_id,record_type,record_id) \
             VALUES($1,1,'screenshot',1),($1,2,'screenshot',2)",
        )
        .bind(&reconciliation_account_id)
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO content_id_counters(account_id,entity_kind,next_id) VALUES($1,'episodes',3) \
             ON CONFLICT(account_id,entity_kind) DO UPDATE SET next_id=greatest(content_id_counters.next_id,3)",
        )
        .bind(&reconciliation_account_id)
        .execute(&pool)
        .await
        .unwrap();
        let reconciliation = repositories.memory_reconciliation();
        assert!(
            reconciliation
                .next_source_settled_cohort(
                    &reconciliation_account_id,
                    4 * 60 * 60,
                    None,
                    32,
                    4_000,
                )
                .await
                .unwrap()
                .is_none(),
            "schema-26 candidate must keep reconciliation dark"
        );
        sqlx::query("DELETE FROM accounts WHERE id=$1")
            .bind(&reconciliation_account_id)
            .execute(&pool)
            .await
            .unwrap();

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
        let finalization = repositories.finalization();
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
            .claim_finalization(crate::persistence::FinalizationClaimRequest {
                account_id: &account_id,
                target_episode_id: Some(episode_ids[0]),
                quiet_horizon_seconds: 4 * 60 * 60,
                finalization_version: 5,
                lease_seconds: 900,
            })
            .await
            .unwrap()
            .expect("finalization claim");
        assert!(finalization
            .claim_finalization(crate::persistence::FinalizationClaimRequest {
                account_id: &account_id,
                target_episode_id: Some(episode_ids[0]),
                quiet_horizon_seconds: 4 * 60 * 60,
                finalization_version: 5,
                lease_seconds: 900,
            })
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
            }));
        }
        let mut allowed = 0;
        for reservation in reservations {
            allowed += usize::from(reservation.await.unwrap());
        }
        assert_eq!(allowed, 2, "the protected audio budget is fleet-wide");

        let mut billing_lookups = Vec::new();
        assert_eq!(
            repositories
                .billing()
                .existing_billing_account_id(&account_id)
                .await
                .unwrap(),
            None
        );
        assert_eq!(
            sqlx::query_scalar::<_, i64>(
                "SELECT count(*) FROM billing_accounts WHERE account_id=$1"
            )
            .bind(&account_id)
            .fetch_one(&pool)
            .await
            .unwrap(),
            0,
            "lookup-only billing resolution must not provision a mapping"
        );
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
        let billing_account_id = billing_account_id.unwrap();
        assert!(billing_account_id.starts_with("acct_"));
        assert_eq!(
            repositories
                .billing()
                .existing_billing_account_id(&account_id)
                .await
                .unwrap()
                .as_deref(),
            Some(billing_account_id.as_str())
        );
        assert_eq!(
            sqlx::query_scalar::<_, i64>(
                "SELECT count(*) FROM billing_accounts WHERE account_id=$1"
            )
            .bind(&account_id)
            .fetch_one(&pool)
            .await
            .unwrap(),
            1,
            "purchase-time billing resolution must still provision one stable mapping"
        );
        assert_eq!(
            repositories
                .billing()
                .active_identities_for_billing_accounts(vec![
                    billing_account_id.clone(),
                    "acct_absent_from_application".into(),
                ])
                .await
                .unwrap(),
            vec![(
                account_id.clone(),
                "owner@example.com".into(),
                billing_account_id,
            )]
        );

        // Coverage is created with the invocation, so reporting must use that
        // durable row rather than sampling the wall clock again. Force the row
        // across a month boundary to pin the regression deterministically.
        let original_billing_period = sqlx::query_scalar::<_, String>(
            "SELECT period FROM vertex_usage_coverage WHERE account_id=$1",
        )
        .bind(&account_id)
        .fetch_one(&pool)
        .await
        .unwrap();
        let rollover_billing_period = sqlx::query_scalar::<_, String>(
            "UPDATE vertex_usage_coverage \
                SET period=to_char(to_date(period,'YYYY-MM')-interval '1 month','YYYY-MM'), \
                    updated_at=updated_at-interval '1 month' \
              WHERE account_id=$1 \
              RETURNING period",
        )
        .bind(&account_id)
        .fetch_one(&pool)
        .await
        .unwrap();
        let (billing_period, billing_observed_at) = sqlx::query_as::<_, (String, String)>(
            "SELECT period, \
                    to_char(updated_at AT TIME ZONE 'UTC', \
                            'YYYY-MM-DD\"T\"HH24:MI:SS.MS\"Z\"') \
               FROM vertex_usage_coverage \
              WHERE account_id=$1 \
              ORDER BY updated_at DESC,period DESC \
              LIMIT 1",
        )
        .bind(&account_id)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(billing_period, rollover_billing_period);
        let coverage = repositories
            .billing()
            .reconcile_vertex_coverage(&account_id, &billing_period, 1, 0, 0, &billing_observed_at)
            .await
            .unwrap();
        assert_eq!(coverage.sequence, 1);
        assert!(repositories
            .billing()
            .active_vertex_coverage_complete(&billing_period)
            .await
            .unwrap());
        let account_drivers = repositories
            .billing()
            .account_driver_metrics(&account_id, &billing_period)
            .await
            .unwrap();
        assert!(account_drivers.storage_bytes > 0);
        assert_eq!(account_drivers.accepted_email_count, 0);
        assert!(account_drivers.vertex_coverage.unwrap().sequence >= coverage.sequence);
        sqlx::query("DELETE FROM vertex_coverage_anchors WHERE account_id=$1 AND period=$2")
            .bind(&account_id)
            .bind(&billing_period)
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query(
            "UPDATE vertex_usage_coverage \
                SET period=$3,updated_at=clock_timestamp() \
              WHERE account_id=$1 AND period=$2",
        )
        .bind(&account_id)
        .bind(&billing_period)
        .bind(&original_billing_period)
        .execute(&pool)
        .await
        .unwrap();

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
        let batch_id = "b".repeat(64);
        let batch_digest = "c".repeat(64);
        let batch_events = vec!["batch-event-one".into(), "batch-event-two".into()];
        assert!(repositories
            .billing()
            .reserve_recording_delivery_batch(
                &account_id,
                &batch_id,
                &batch_digest,
                "screen-contract",
                10,
                11,
                &batch_events,
                &batch_events,
            )
            .await
            .unwrap());
        assert!(repositories
            .billing()
            .reserve_recording_delivery_batch(
                &account_id,
                &batch_id,
                &batch_digest,
                "screen-contract",
                10,
                11,
                &batch_events,
                &batch_events,
            )
            .await
            .unwrap());
        repositories
            .billing()
            .complete_recording_delivery_batch(&account_id, &batch_id, &batch_digest, &batch_events)
            .await
            .unwrap();
        assert_eq!(
            sqlx::query_scalar::<_, String>(
                "SELECT state FROM capture_reference_batch_receipts \
                  WHERE account_id=$1 AND batch_id=$2",
            )
            .bind(&account_id)
            .bind(&batch_id)
            .fetch_one(&pool)
            .await
            .unwrap(),
            "completed"
        );
        repositories
            .billing()
            .complete_recording_delivery(&account_id, "event-one")
            .await
            .unwrap();
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
            .next_email_candidate(&account_id)
            .await
            .unwrap()
            .expect("finalization email candidate");
        assert!(email_candidate.include_content);
        let email_request = FrozenEmailDelivery {
            recipient_email: email_candidate.recipient_email.clone(),
            include_content: email_candidate.include_content,
            subject: "PostgreSQL delivery contract".into(),
            text_body: "Text contract".into(),
            html_body: "<p>HTML contract</p>".into(),
        };
        let claim_barrier = Arc::new(tokio::sync::Barrier::new(3));
        let mut claim_attempts = Vec::new();
        for _ in 0..2 {
            let repositories = Arc::clone(&repositories);
            let email_candidate = email_candidate.clone();
            let email_request = email_request.clone();
            let claim_barrier = Arc::clone(&claim_barrier);
            claim_attempts.push(tokio::spawn(async move {
                claim_barrier.wait().await;
                repositories
                    .deliveries()
                    .claim_email(&email_candidate, email_request, 60)
                    .await
            }));
        }
        claim_barrier.wait().await;
        let mut claim_results = Vec::new();
        for attempt in claim_attempts {
            claim_results.push(attempt.await.unwrap().unwrap());
        }
        assert_eq!(
            claim_results.iter().filter(|claim| claim.is_some()).count(),
            1,
            "exactly one concurrent email claimant must receive provider authority"
        );
        assert_eq!(
            claim_results.iter().filter(|claim| claim.is_none()).count(),
            1,
            "the losing concurrent email claimant must receive no claim"
        );
        let email_claim = claim_results
            .into_iter()
            .flatten()
            .next()
            .expect("single concurrent email claim winner");
        assert_eq!(
            sqlx::query_as::<_, (String, Option<String>, i64)>(
                "SELECT state,claim_token,attempt_count FROM email_deliveries \
                   WHERE account_id=$1 AND delivery_id=$2",
            )
            .bind(&account_id)
            .bind(&email_claim.delivery_id)
            .fetch_one(&pool)
            .await
            .unwrap(),
            (
                "processing".into(),
                Some(email_claim.claim_token.clone()),
                1,
            )
        );
        assert_eq!(
            sqlx::query_scalar::<_, i64>(
                "SELECT count(*) FROM email_send_fences \
                   WHERE account_id=$1 AND delivery_id=$2",
            )
            .bind(&account_id)
            .bind(&email_claim.delivery_id)
            .fetch_one(&pool)
            .await
            .unwrap(),
            1
        );
        assert!(repositories
            .deliveries()
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
            .settle_email(&email_claim, accepted_email.clone(), None)
            .await
            .unwrap();
        repositories
            .deliveries()
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

        sqlx::query(
            "UPDATE email_deliveries SET state='pending',attempt_count=0, \
                    next_attempt_at=clock_timestamp(),claim_token=NULL,claim_until=NULL, \
                    completed_claim_token=NULL,last_error=NULL,error_code=NULL \
              WHERE account_id=$1 AND delivery_id=$2",
        )
        .bind(&account_id)
        .bind(&email_claim.delivery_id)
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(
            "UPDATE provider_send_lanes SET owner_token=NULL,lease_until=NULL, \
                    next_send_at=clock_timestamp(),circuit_until=NULL WHERE provider='email'",
        )
        .execute(&pool)
        .await
        .unwrap();
        let disclosed_email_candidate = repositories
            .deliveries()
            .next_email_candidate(&account_id)
            .await
            .unwrap()
            .expect("email candidate for disclosed-expiry contract");
        let disclosed_email_claim = repositories
            .deliveries()
            .claim_email(
                &disclosed_email_candidate,
                FrozenEmailDelivery {
                    recipient_email: disclosed_email_candidate.recipient_email.clone(),
                    include_content: disclosed_email_candidate.include_content,
                    subject: "Disclosed-expiry contract".into(),
                    text_body: "Disclosed-expiry text".into(),
                    html_body: "<p>Disclosed-expiry HTML</p>".into(),
                },
                60,
            )
            .await
            .unwrap()
            .expect("email disclosed-expiry claim");
        assert!(matches!(
            repositories
                .lifecycle()
                .begin_account_deletion(&account_id)
                .await,
            Err(crate::error::EnclaveError::Conflict(message))
                if message == "account has an in-flight email send"
        ));
        sqlx::query(
            "UPDATE email_deliveries SET claim_until=clock_timestamp()-interval '1 second' \
              WHERE account_id=$1 AND delivery_id=$2 AND claim_token=$3",
        )
        .bind(&account_id)
        .bind(&disclosed_email_claim.delivery_id)
        .bind(&disclosed_email_claim.claim_token)
        .execute(&pool)
        .await
        .unwrap();
        assert!(repositories
            .deliveries()
            .next_email_candidate(&account_id)
            .await
            .unwrap()
            .is_none());
        assert_eq!(
            sqlx::query_as::<_, (String, Option<String>, i64, Option<String>, Option<String>,)>(
                "SELECT state,error_code,attempt_count,claim_token,completed_claim_token \
                   FROM email_deliveries WHERE account_id=$1 AND delivery_id=$2",
            )
            .bind(&account_id)
            .bind(&disclosed_email_claim.delivery_id)
            .fetch_one(&pool)
            .await
            .unwrap(),
            (
                "ambiguous".into(),
                Some("claim_expired_after_disclosure".into()),
                1,
                None,
                Some(disclosed_email_claim.claim_token.clone()),
            )
        );
        assert_eq!(
            sqlx::query_scalar::<_, i64>(
                "SELECT count(*) FROM email_send_fences WHERE account_id=$1 AND delivery_id=$2",
            )
            .bind(&account_id)
            .bind(&disclosed_email_claim.delivery_id)
            .fetch_one(&pool)
            .await
            .unwrap(),
            0
        );
        sqlx::query("UPDATE webhook_subscriptions SET enabled=true WHERE account_id=$1 AND id=$2")
            .bind(&account_id)
            .bind(&webhook.id)
            .execute(&pool)
            .await
            .unwrap();
        let webhook_candidate = repositories
            .deliveries()
            .next_webhook_candidate(&account_id)
            .await
            .unwrap()
            .expect("finalization webhook candidate");
        let webhook_claim = repositories
            .deliveries()
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
            .settle_webhook(&webhook_claim, sent_webhook.clone(), None)
            .await
            .unwrap();
        repositories
            .deliveries()
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
        let webhook_status = repositories
            .deliveries()
            .webhook_delivery_status(&account_id, &webhook.id)
            .await
            .unwrap();
        assert_eq!(webhook_status.sent, 1);
        assert_eq!(webhook_status.latest.unwrap().outcome, "sent");
        repositories
            .deliveries()
            .cancel_webhook_deliveries(&account_id, &webhook.id)
            .await
            .unwrap();

        sqlx::query(
            "UPDATE webhook_deliveries SET state='pending',attempt_count=0, \
                    next_attempt_at=clock_timestamp(),claim_token=NULL,claim_until=NULL, \
                    completed_claim_token=NULL,last_error=NULL,error_code=NULL \
              WHERE account_id=$1 AND event_id=$2",
        )
        .bind(&account_id)
        .bind(&webhook_claim.event_id)
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(
            "UPDATE provider_send_lanes SET owner_token=NULL,lease_until=NULL, \
                    next_send_at=clock_timestamp(),circuit_until=NULL WHERE provider='webhook'",
        )
        .execute(&pool)
        .await
        .unwrap();
        let takeover_webhook_candidate = repositories
            .deliveries()
            .next_webhook_candidate(&account_id)
            .await
            .unwrap()
            .expect("webhook candidate for takeover contract");
        let stale_webhook_claim = repositories
            .deliveries()
            .claim_webhook(
                &takeover_webhook_candidate,
                FrozenWebhookDelivery {
                    endpoint_url: takeover_webhook_candidate.endpoint_url.clone(),
                    signing_secret: takeover_webhook_candidate.signing_secret.clone(),
                    include_content: takeover_webhook_candidate.include_content,
                    event_body: "{\"takeover\":1}".into(),
                },
                60,
            )
            .await
            .unwrap()
            .expect("initial webhook takeover claim");
        sqlx::query(
            "DELETE FROM webhook_send_fences \
              WHERE account_id=$1 AND event_id=$2 AND claim_id=$3",
        )
        .bind(&account_id)
        .bind(&stale_webhook_claim.event_id)
        .bind(&stale_webhook_claim.claim_token)
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(
            "UPDATE webhook_deliveries SET claim_until=clock_timestamp()-interval '1 second' \
              WHERE account_id=$1 AND event_id=$2 AND claim_token=$3",
        )
        .bind(&account_id)
        .bind(&stale_webhook_claim.event_id)
        .bind(&stale_webhook_claim.claim_token)
        .execute(&pool)
        .await
        .unwrap();
        let recovered_webhook_candidate = repositories
            .deliveries()
            .next_webhook_candidate(&account_id)
            .await
            .unwrap()
            .expect("expired undisclosed webhook claim becomes retryable");
        assert_eq!(recovered_webhook_candidate.attempt_count, 1);
        let successor_webhook_claim = repositories
            .deliveries()
            .claim_webhook(
                &recovered_webhook_candidate,
                FrozenWebhookDelivery {
                    endpoint_url: recovered_webhook_candidate.endpoint_url.clone(),
                    signing_secret: recovered_webhook_candidate.signing_secret.clone(),
                    include_content: recovered_webhook_candidate.include_content,
                    event_body: "{\"takeover\":2}".into(),
                },
                60,
            )
            .await
            .unwrap()
            .expect("successor webhook claim");
        assert_eq!(successor_webhook_claim.attempt_count, 2);
        assert!(matches!(
            repositories
                .deliveries()
                .settle_webhook(
                    &stale_webhook_claim,
                    WebhookProviderOutcome::Sent { status: 204 },
                    None,
                )
                .await,
            Err(crate::error::EnclaveError::Conflict(message))
                if message == "webhook delivery claim is no longer authoritative"
        ));
        assert_eq!(
            sqlx::query_as::<_, (String, Option<String>, Option<String>, i64)>(
                "SELECT state,claim_token,completed_claim_token,attempt_count \
                   FROM webhook_deliveries WHERE account_id=$1 AND event_id=$2",
            )
            .bind(&account_id)
            .bind(&successor_webhook_claim.event_id)
            .fetch_one(&pool)
            .await
            .unwrap(),
            (
                "processing".into(),
                Some(successor_webhook_claim.claim_token.clone()),
                None,
                2,
            )
        );
        repositories
            .deliveries()
            .settle_webhook(
                &successor_webhook_claim,
                WebhookProviderOutcome::Sent { status: 204 },
                None,
            )
            .await
            .unwrap();
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
            .next_push_candidate(&account_id)
            .await
            .unwrap()
            .expect("finalization push candidate");
        assert_eq!(push_candidate.token_generation, installed.token_generation);
        let push_claim = repositories
            .deliveries()
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
            .settle_push(&push_claim, accepted_push.clone(), None)
            .await
            .unwrap();
        repositories
            .deliveries()
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
        assert_eq!(
            repositories
                .deliveries()
                .resolve_push_handoff(&account_id, &push_claim.handoff_handle)
                .await
                .unwrap(),
            Some(push_claim.episode_id)
        );

        sqlx::query(
            "UPDATE push_deliveries SET state='pending',attempt_count=0, \
                    next_attempt_at=clock_timestamp(),claim_token=NULL,claim_until=NULL, \
                    completed_claim_token=NULL,last_error=NULL,error_code=NULL \
              WHERE account_id=$1 AND delivery_id=$2",
        )
        .bind(&account_id)
        .bind(&push_claim.delivery_id)
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(
            "UPDATE provider_send_lanes SET owner_token=NULL,lease_until=NULL, \
                    next_send_at=clock_timestamp(),circuit_until=NULL WHERE provider='push'",
        )
        .execute(&pool)
        .await
        .unwrap();
        let takeover_push_candidate = repositories
            .deliveries()
            .next_push_candidate(&account_id)
            .await
            .unwrap()
            .expect("push candidate for takeover contract");
        let stale_push_claim = repositories
            .deliveries()
            .claim_push(
                &takeover_push_candidate,
                FrozenPushDelivery {
                    topic: takeover_push_candidate.topic.clone(),
                    environment: takeover_push_candidate.environment.clone(),
                    device_token: takeover_push_candidate.device_token.clone(),
                    token_generation: takeover_push_candidate.token_generation,
                },
                60,
            )
            .await
            .unwrap()
            .expect("initial push takeover claim");
        sqlx::query("DELETE FROM push_send_fences WHERE account_id=$1 AND claim_id=$2")
            .bind(&account_id)
            .bind(&stale_push_claim.claim_token)
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query(
            "UPDATE push_deliveries SET claim_until=clock_timestamp()-interval '1 second' \
              WHERE account_id=$1 AND delivery_id=$2 AND claim_token=$3",
        )
        .bind(&account_id)
        .bind(&stale_push_claim.delivery_id)
        .bind(&stale_push_claim.claim_token)
        .execute(&pool)
        .await
        .unwrap();
        let recovered_push_candidate = repositories
            .deliveries()
            .next_push_candidate(&account_id)
            .await
            .unwrap()
            .expect("expired undisclosed push claim becomes retryable");
        assert_eq!(recovered_push_candidate.attempt_count, 1);
        let successor_push_claim = repositories
            .deliveries()
            .claim_push(
                &recovered_push_candidate,
                FrozenPushDelivery {
                    topic: recovered_push_candidate.topic.clone(),
                    environment: recovered_push_candidate.environment.clone(),
                    device_token: recovered_push_candidate.device_token.clone(),
                    token_generation: recovered_push_candidate.token_generation,
                },
                60,
            )
            .await
            .unwrap()
            .expect("successor push claim");
        assert_eq!(successor_push_claim.attempt_count, 2);
        assert!(matches!(
            repositories
                .deliveries()
                .settle_push(
                    &stale_push_claim,
                    PushProviderOutcome::Accepted { status: 200 },
                    None,
                )
                .await,
            Err(crate::error::EnclaveError::Conflict(message))
                if message == "push delivery claim is no longer authoritative"
        ));
        assert_eq!(
            sqlx::query_as::<_, (String, Option<String>, Option<String>, i64)>(
                "SELECT state,claim_token,completed_claim_token,attempt_count \
                   FROM push_deliveries WHERE account_id=$1 AND delivery_id=$2",
            )
            .bind(&account_id)
            .bind(&successor_push_claim.delivery_id)
            .fetch_one(&pool)
            .await
            .unwrap(),
            (
                "processing".into(),
                Some(successor_push_claim.claim_token.clone()),
                None,
                2,
            )
        );
        repositories
            .deliveries()
            .settle_push(
                &successor_push_claim,
                PushProviderOutcome::Accepted { status: 200 },
                None,
            )
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
        // Even a malformed legacy owner row carrying a person ID must remain
        // inert at every public navigation surface.
        sqlx::query(
            "INSERT INTO episode_participants \
             (account_id,id,episode_id,participant_key,person_id,attribution_kind) \
             VALUES($1,2,1,'owner',1,'owner')",
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
        let enriched_embedding_sources = repositories
            .memory_formation()
            .episode_embedding_sources(&account_id, &[1])
            .await
            .unwrap();
        assert_eq!(enriched_embedding_sources.len(), 1);
        assert!(enriched_embedding_sources[0].text.contains("Ready"));
        assert!(enriched_embedding_sources[0].text.contains("Ship"));
        assert!(!enriched_embedding_sources[0].text.contains("action_items"));

        let final_brief_hits = repositories
            .memory_queries()
            .search(
                &account_id,
                &SearchRequest {
                    query: "Ship".into(),
                    speaker: None,
                    time_start: None,
                    time_end: None,
                    limit: 10,
                    offset: 0,
                    kinds: vec!["episode".into()],
                    query_embedding: None,
                },
            )
            .await
            .unwrap();
        let final_brief_hits = serde_json::to_value(&final_brief_hits).unwrap();
        assert_eq!(final_brief_hits[0]["memory_id"], 1);
        assert_eq!(final_brief_hits[0]["match_source"], "brief");
        assert_eq!(
            final_brief_hits[0]["final_brief"]["action_items"][0],
            "Ship"
        );
        let schema_key_hits = repositories
            .memory_queries()
            .search(
                &account_id,
                &SearchRequest {
                    query: "action_items".into(),
                    speaker: None,
                    time_start: None,
                    time_end: None,
                    limit: 10,
                    offset: 0,
                    kinds: vec!["episode".into()],
                    query_embedding: None,
                },
            )
            .await
            .unwrap();
        assert!(schema_key_hits.is_empty());

        let linked_utterance_hits = repositories
            .memory_queries()
            .search(
                &account_id,
                &SearchRequest {
                    query: "PostgreSQL".into(),
                    speaker: None,
                    time_start: None,
                    time_end: None,
                    limit: 10,
                    offset: 0,
                    kinds: vec!["utterance".into()],
                    query_embedding: None,
                },
            )
            .await
            .unwrap();
        let linked_utterance_hits = serde_json::to_value(&linked_utterance_hits).unwrap();
        assert_eq!(linked_utterance_hits[0]["person_id"], 1);
        assert_eq!(linked_utterance_hits[0]["memory_id"], 1);
        assert_eq!(linked_utterance_hits[0]["episode_id"], 1);
        assert_eq!(
            linked_utterance_hits[0]["source_at"],
            "2026-08-27T12:00:00.000Z"
        );
        let pre_observation_hits = repositories
            .memory_queries()
            .search(
                &account_id,
                &SearchRequest {
                    query: "PostgreSQL".into(),
                    speaker: None,
                    time_start: None,
                    time_end: Some("2026-08-27T11:59:59Z".into()),
                    limit: 10,
                    offset: 0,
                    kinds: vec!["utterance".into()],
                    query_embedding: None,
                },
            )
            .await
            .unwrap();
        assert!(pre_observation_hits.is_empty());

        let interpretation_hits = repositories
            .memory_queries()
            .search(
                &account_id,
                &SearchRequest {
                    query: "central evidence".into(),
                    speaker: None,
                    time_start: None,
                    time_end: None,
                    limit: 10,
                    offset: 0,
                    kinds: vec!["screenshot".into()],
                    query_embedding: None,
                },
            )
            .await
            .unwrap();
        let interpretation_hits = serde_json::to_value(&interpretation_hits).unwrap();
        assert_eq!(
            interpretation_hits[0]["match_source"],
            "episode_interpretation"
        );
        assert_eq!(interpretation_hits[0]["memory_id"], 1);
        assert_eq!(interpretation_hits[0]["episode_id"], 1);
        assert!(interpretation_hits[0]["match_text"]
            .as_str()
            .is_some_and(|text| text.contains("central") && text.chars().count() <= 400));

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
        assert_eq!(
            episode_page.episodes[0]["participant_details"][0]["person_id"],
            1
        );
        assert_eq!(
            episode_page.episodes[0]["participant_details"][1]["display_name"],
            "Me"
        );
        assert!(episode_page.episodes[0]["participant_details"][1]["person_id"].is_null());
        let evidence = repositories
            .memory_queries()
            .episode_members(&account_id, 1)
            .await
            .unwrap();
        assert_eq!(evidence["member_count"], 2);
        assert_eq!(evidence["participant_details"][0]["display_name"], "Lynn");
        assert_eq!(evidence["participant_details"][0]["person_id"], 1);
        assert_eq!(evidence["participant_details"][1]["display_name"], "Me");
        assert!(evidence["participant_details"][1]["person_id"].is_null());
        assert_eq!(
            evidence["members"][0]["started_at"],
            "2026-08-27T12:00:00.000Z"
        );
        assert_eq!(evidence["members"][0]["display_name"], "Lynn");
        assert_eq!(evidence["members"][0]["person_id"], 1);
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
        assert_eq!(person_memories.person_id, 1);
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
        assert_eq!(feed.records[1].person_id, Some(1));
        assert_eq!(
            feed.records[1].attribution_kind.as_deref(),
            Some("direct_identity_evidence")
        );
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
        assert_eq!(mcp_search["results"][0]["kind"], "utterance");
        assert_eq!(mcp_search["results"][0]["speaker_label"], "Lynn");
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
        assert_eq!(mcp_context["utterances"][0]["speaker_label"], "Lynn");
        assert_eq!(mcp_context["utterances"][0]["source_type"], "mic");
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
        assert_eq!(mcp_range["counts"]["utterances"], 1);
        assert_eq!(mcp_range["counts"]["screenshots"], 1);
        assert_eq!(mcp_range["digest"].as_array().unwrap().len(), 1);
        assert_eq!(mcp_range["digest"][0]["speaker"], "Lynn");

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

        // Reclaiming an unresolved durable attempt makes ambiguity terminal.
        // A late HTTP completion from the original owner must not overwrite it
        // or authorize staging provider bytes.
        let late_response_attempt = repositories
            .model_usage()
            .begin_invocation_attempt(
                &account_id,
                VertexOperation::EpisodeReconciliation,
                "gemini-contract",
                "us-central1",
                &[0x31; 32],
                &[0x41; 32],
            )
            .await
            .unwrap();
        assert_eq!(
            late_response_attempt.admission,
            VertexInvocationAdmission::Send
        );
        let reclaimed = repositories
            .model_usage()
            .begin_invocation_attempt(
                &account_id,
                VertexOperation::EpisodeReconciliation,
                "gemini-contract",
                "us-central1",
                &[0x31; 32],
                &[0x41; 32],
            )
            .await
            .unwrap();
        assert_eq!(
            reclaimed.admission,
            VertexInvocationAdmission::AmbiguousTerminal
        );
        let late_response = repositories
            .model_usage()
            .settle_response(
                &account_id,
                &late_response_attempt.event_id,
                &VertexMetadata {
                    model_version: Some("gemini-contract".into()),
                    traffic_type: Some("ON_DEMAND".into()),
                    usage: Some(VertexUsage {
                        prompt_details_present: true,
                        cache_details_present: false,
                        prompt_tokens: Some(1),
                        input_text_tokens: Some(1),
                        input_audio_tokens: Some(0),
                        input_image_tokens: Some(0),
                        cached_input_tokens: Some(0),
                        cached_input_text_tokens: Some(0),
                        cached_input_audio_tokens: Some(0),
                        cached_input_image_tokens: Some(0),
                        output_tokens: Some(1),
                        tool_use_prompt_tokens: Some(0),
                        thought_tokens: Some(0),
                        total_tokens: Some(2),
                    }),
                },
            )
            .await
            .unwrap_err();
        assert!(matches!(late_response, EnclaveError::Conflict(_)));

        let late_not_billed_attempt = repositories
            .model_usage()
            .begin_invocation_attempt(
                &account_id,
                VertexOperation::EpisodeReconciliation,
                "gemini-contract",
                "us-central1",
                &[0x32; 32],
                &[0x42; 32],
            )
            .await
            .unwrap();
        assert_eq!(
            late_not_billed_attempt.admission,
            VertexInvocationAdmission::Send
        );
        let reclaimed = repositories
            .model_usage()
            .begin_invocation_attempt(
                &account_id,
                VertexOperation::EpisodeReconciliation,
                "gemini-contract",
                "us-central1",
                &[0x32; 32],
                &[0x42; 32],
            )
            .await
            .unwrap();
        assert_eq!(
            reclaimed.admission,
            VertexInvocationAdmission::AmbiguousTerminal
        );
        let late_not_billed = repositories
            .model_usage()
            .settle_not_billed(&account_id, &late_not_billed_attempt.event_id, 503)
            .await
            .unwrap_err();
        assert!(matches!(late_not_billed, EnclaveError::Conflict(_)));
        let usage_claim = repositories
            .model_usage()
            .pending_events(&account_id, &billing_account, false)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(usage_claim.events.len(), 5);
        assert!(usage_claim
            .events
            .iter()
            .any(|event| event.event_id == invocation));
        assert!(usage_claim
            .events
            .iter()
            .any(|event| event.event_id == finalization_event));
        assert!(usage_claim.events.iter().any(|event| {
            event.event_id == screen_usage_event_id
                && event.operation == "screen_understanding"
                && event.outcome == "usage_missing"
                && event.http_status == Some(200)
        }));
        assert!(usage_claim.events.iter().any(|event| {
            event.event_id == late_response_attempt.event_id && event.outcome == "ambiguous"
        }));
        assert!(usage_claim.events.iter().any(|event| {
            event.event_id == late_not_billed_attempt.event_id && event.outcome == "ambiguous"
        }));
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
        assert_eq!(coverage[0].snapshot.lost_events, 0);
        let first_coverage = &coverage[0];
        let accepted_anchor = repositories
            .billing()
            .reconcile_vertex_coverage(
                &account_id,
                &first_coverage.snapshot.period,
                first_coverage.snapshot.sequence,
                first_coverage.snapshot.pending_events,
                first_coverage.snapshot.lost_events,
                &first_coverage.snapshot.observed_at,
            )
            .await
            .unwrap();
        assert_eq!(accepted_anchor.sequence, first_coverage.snapshot.sequence);
        assert_eq!(accepted_anchor.pending_events, 0);
        assert_eq!(accepted_anchor.lost_events, 0);

        // Model a process loss after billing durably accepted coverage but
        // before the worker persisted its acknowledgement. A new repository
        // instance takes over the expired PostgreSQL claim and replays the
        // exact snapshot without manufacturing a rollback loss.
        assert_eq!(
            sqlx::query(
                "UPDATE vertex_usage_coverage
                    SET delivery_claim_expires_at=CURRENT_TIMESTAMP - interval '1 second'
                  WHERE account_id=$1 AND period=$2 AND delivery_claim_id=$3",
            )
            .bind(&account_id)
            .bind(&first_coverage.snapshot.period)
            .bind(&first_coverage.claim_id)
            .execute(&pool)
            .await
            .unwrap()
            .rows_affected(),
            1
        );
        let recovered_gcs: Arc<dyn crate::gcs::GcsClient> = Arc::new(FakeGcs::new());
        let recovered_repositories = RepositorySet::postgres(
            Arc::clone(&persistence),
            Arc::new(GcsMediaObjectStore::new(recovered_gcs)),
        );
        let recovered_coverage = recovered_repositories
            .model_usage()
            .pending_coverage(&account_id, &billing_account)
            .await
            .unwrap();
        assert_eq!(recovered_coverage.len(), 1);
        assert_ne!(recovered_coverage[0].claim_id, first_coverage.claim_id);
        assert_eq!(recovered_coverage[0].snapshot, first_coverage.snapshot);
        let replayed_anchor = recovered_repositories
            .billing()
            .reconcile_vertex_coverage(
                &account_id,
                &recovered_coverage[0].snapshot.period,
                recovered_coverage[0].snapshot.sequence,
                recovered_coverage[0].snapshot.pending_events,
                recovered_coverage[0].snapshot.lost_events,
                &recovered_coverage[0].snapshot.observed_at,
            )
            .await
            .unwrap();
        assert_eq!(replayed_anchor.sequence, first_coverage.snapshot.sequence);
        assert_eq!(replayed_anchor.pending_events, 0);
        assert_eq!(replayed_anchor.lost_events, 0);
        recovered_repositories
            .model_usage()
            .complete_coverage(
                &account_id,
                &recovered_coverage[0].claim_id,
                &recovered_coverage[0].snapshot.period,
                recovered_coverage[0].snapshot.sequence,
            )
            .await
            .unwrap();

        let rollback_event = recovered_repositories
            .model_usage()
            .begin_invocation(
                &account_id,
                VertexOperation::EpisodeSummary,
                "gemini-contract",
                "us-central1",
                &[8; 32],
            )
            .await
            .unwrap();
        recovered_repositories
            .model_usage()
            .settle_not_billed(&account_id, &rollback_event, 400)
            .await
            .unwrap();
        let stale_coverage = recovered_repositories
            .model_usage()
            .pending_coverage(&account_id, &billing_account)
            .await
            .unwrap();
        assert_eq!(stale_coverage.len(), 1);
        assert_eq!(stale_coverage[0].snapshot.pending_events, 0);
        assert_eq!(stale_coverage[0].snapshot.lost_events, 0);
        let ahead_sequence = stale_coverage[0].snapshot.sequence.checked_add(1).unwrap();
        let ahead_anchor = recovered_repositories
            .billing()
            .reconcile_vertex_coverage(
                &account_id,
                &stale_coverage[0].snapshot.period,
                ahead_sequence,
                0,
                0,
                &stale_coverage[0].snapshot.observed_at,
            )
            .await
            .unwrap();
        assert_eq!(ahead_anchor.sequence, ahead_sequence);
        assert_eq!(ahead_anchor.lost_events, 0);

        // A genuinely stale producer predecessor must remain fail-closed. The
        // authority advances it once and records one conservative loss; after
        // that replacement is durable, another process can only replay the
        // exact absolute value and may neither increment nor clear it.
        let fail_closed_anchor = recovered_repositories
            .billing()
            .reconcile_vertex_coverage(
                &account_id,
                &stale_coverage[0].snapshot.period,
                stale_coverage[0].snapshot.sequence,
                stale_coverage[0].snapshot.pending_events,
                stale_coverage[0].snapshot.lost_events,
                &stale_coverage[0].snapshot.observed_at,
            )
            .await
            .unwrap();
        assert_eq!(fail_closed_anchor.sequence, ahead_sequence + 1);
        assert_eq!(fail_closed_anchor.pending_events, 0);
        assert_eq!(fail_closed_anchor.lost_events, 1);
        let fail_closed_snapshot = crate::cp::billing::VertexCoverageSnapshot {
            account_id: stale_coverage[0].snapshot.account_id.clone(),
            period: fail_closed_anchor.period,
            sequence: fail_closed_anchor.sequence,
            pending_events: fail_closed_anchor.pending_events,
            lost_events: fail_closed_anchor.lost_events,
            observed_at: fail_closed_anchor.observed_at,
        };
        recovered_repositories
            .model_usage()
            .persist_coverage_snapshot(
                &account_id,
                &stale_coverage[0].claim_id,
                &stale_coverage[0].snapshot,
                &fail_closed_snapshot,
            )
            .await
            .unwrap();
        assert_eq!(
            sqlx::query(
                "UPDATE vertex_usage_coverage
                    SET delivery_claim_expires_at=CURRENT_TIMESTAMP - interval '1 second'
                  WHERE account_id=$1 AND period=$2 AND delivery_claim_id=$3",
            )
            .bind(&account_id)
            .bind(&fail_closed_snapshot.period)
            .bind(&stale_coverage[0].claim_id)
            .execute(&pool)
            .await
            .unwrap()
            .rows_affected(),
            1
        );
        let recovered_again = recovered_repositories
            .model_usage()
            .pending_coverage(&account_id, &billing_account)
            .await
            .unwrap();
        assert_eq!(recovered_again.len(), 1);
        assert_ne!(recovered_again[0].claim_id, stale_coverage[0].claim_id);
        assert_eq!(recovered_again[0].snapshot, fail_closed_snapshot);
        let stable_fail_closed_anchor = recovered_repositories
            .billing()
            .reconcile_vertex_coverage(
                &account_id,
                &recovered_again[0].snapshot.period,
                recovered_again[0].snapshot.sequence,
                recovered_again[0].snapshot.pending_events,
                recovered_again[0].snapshot.lost_events,
                &recovered_again[0].snapshot.observed_at,
            )
            .await
            .unwrap();
        assert_eq!(
            stable_fail_closed_anchor.sequence,
            fail_closed_snapshot.sequence
        );
        assert_eq!(stable_fail_closed_anchor.pending_events, 0);
        assert_eq!(stable_fail_closed_anchor.lost_events, 1);
        recovered_repositories
            .model_usage()
            .complete_coverage(
                &account_id,
                &recovered_again[0].claim_id,
                &recovered_again[0].snapshot.period,
                recovered_again[0].snapshot.sequence,
            )
            .await
            .unwrap();
        let final_coverage = sqlx::query(
            "SELECT sequence,lost_events,delivery_state
               FROM vertex_usage_coverage WHERE account_id=$1 AND period=$2",
        )
        .bind(&account_id)
        .bind(&fail_closed_snapshot.period)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(
            final_coverage.try_get::<i64, _>("sequence").unwrap(),
            i64::try_from(fail_closed_snapshot.sequence).unwrap()
        );
        assert_eq!(final_coverage.try_get::<i64, _>("lost_events").unwrap(), 1);
        assert_eq!(
            final_coverage
                .try_get::<String, _>("delivery_state")
                .unwrap(),
            "delivered"
        );

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

        let episode_deletions = repositories.episode_deletions();
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

        let reviewer_subject = crate::cp::reviewer_identity_subject("contract-reviewer-uid");
        let reviewer_account = repositories
            .identity_sessions()
            .upsert_subject_account(&reviewer_subject, "reviewer@example.com", i64::MAX)
            .await
            .unwrap();
        assert_eq!(
            reviewer_account.id,
            crate::cp::tokens::derive_stable_uuid(&reviewer_subject)
        );
        assert!(repositories
            .memory_formation()
            .ensure_reviewer_fixture(&reviewer_account.id)
            .await
            .unwrap());
        assert!(!repositories
            .memory_formation()
            .ensure_reviewer_fixture(&reviewer_account.id)
            .await
            .unwrap());
        assert_eq!(
            sqlx::query_scalar::<_, i64>(
                "SELECT count(*) FROM episodes WHERE account_id=$1 AND model='synthetic-review'",
            )
            .bind(&reviewer_account.id)
            .fetch_one(&pool)
            .await
            .unwrap(),
            4
        );

        let reviewer_episodes = repositories
            .memory_queries()
            .list_episodes(
                &reviewer_account.id,
                &EpisodeListRequest {
                    from: Some("2026-07-22T00:00:00Z".into()),
                    to: Some("2026-07-22T12:00:00Z".into()),
                    limit: 20,
                    include_low: false,
                    episode_id: None,
                    before_started_at: None,
                    before_id: None,
                    probe_for_more: false,
                },
            )
            .await
            .unwrap();
        assert_eq!(reviewer_episodes.episodes.len(), 3);
        let reviewer_titles = reviewer_episodes
            .episodes
            .iter()
            .map(|episode| episode["title"].as_str().unwrap())
            .collect::<Vec<_>>();
        assert_eq!(
            reviewer_titles,
            vec![
                "Vendor renewal page",
                "Dashboard cache invalidation fix",
                "Launch planning and QA decision",
            ]
        );
        assert!(!serde_json::to_string(&reviewer_episodes.episodes)
            .unwrap()
            .contains("French lesson"));

        let reviewer_launch = repositories
            .memory_queries()
            .mcp_search_transcripts(
                &reviewer_account.id,
                &McpTranscriptSearchRequest {
                    query: "launch".into(),
                    from: Some("2026-07-22T09:00:00Z".into()),
                    to: Some("2026-07-22T09:35:00Z".into()),
                    limit: 10,
                },
            )
            .await
            .unwrap();
        assert!(reviewer_launch["results"]
            .as_array()
            .unwrap()
            .iter()
            .any(|result| result["text"]
                .as_str()
                .is_some_and(|text| text.contains("August 19"))));
        assert!(reviewer_launch["results"]
            .as_array()
            .unwrap()
            .iter()
            .all(|result| result["speaker_label"] == "Maya"));

        let reviewer_context = repositories
            .memory_queries()
            .mcp_context(
                &reviewer_account.id,
                &McpContextRequest {
                    at: "2026-07-22T09:01:30Z".into(),
                    window_seconds: 300,
                    limit: Some(10),
                },
            )
            .await
            .unwrap();
        let context_utterances = reviewer_context["utterances"].as_array().unwrap();
        assert_eq!(context_utterances.len(), 2);
        assert_eq!(context_utterances[0]["speaker_label"], "Maya");
        assert_eq!(context_utterances[0]["source_type"], "mic");
        assert!(context_utterances[0]["text"]
            .as_str()
            .unwrap()
            .contains("August 19"));
        assert!(context_utterances[1]["text"]
            .as_str()
            .unwrap()
            .contains("launch checklist"));

        let renewal_hits = repositories
            .memory_queries()
            .search(
                &reviewer_account.id,
                &SearchRequest {
                    query: "renewal".into(),
                    speaker: None,
                    time_start: Some("2026-07-22T11:00:00Z".into()),
                    time_end: Some("2026-07-22T12:00:00Z".into()),
                    limit: 10,
                    offset: 0,
                    kinds: vec!["screenshot".into()],
                    query_embedding: None,
                },
            )
            .await
            .unwrap();
        assert!(matches!(
            renewal_hits.as_slice(),
            [SearchHit::Screenshot {
                active_app: Some(active_app),
                window_title: Some(window_title),
                url: Some(url),
                match_source: Some(match_source),
                ..
            }] if active_app == "Google Chrome"
                && window_title == "Vendor renewal checklist"
                && url == "https://example.com/renewal"
                && match_source == "salient_ocr"
        ));

        let reviewer_french = repositories
            .memory_queries()
            .mcp_time_range(
                &reviewer_account.id,
                &McpTimeRangeRequest {
                    from: "2026-07-22T14:00:00Z".into(),
                    to: "2026-07-22T15:00:00Z".into(),
                    limit: Some(10),
                },
            )
            .await
            .unwrap();
        assert_eq!(reviewer_french["counts"]["utterances"], 2);
        assert_eq!(reviewer_french["counts"]["screenshots"], 0);
        assert_eq!(reviewer_french["languages"], serde_json::json!(["en"]));
        assert_eq!(reviewer_french["apps_seen"], serde_json::json!([]));
        let french_digest = reviewer_french["digest"].as_array().unwrap();
        assert_eq!(french_digest.len(), 2);
        assert!(french_digest[0]["text"]
            .as_str()
            .unwrap()
            .contains("depuis"));
        assert!(french_digest[1]["text"]
            .as_str()
            .unwrap()
            .contains("pendant"));
        assert!(french_digest
            .windows(2)
            .all(|pair| pair[0]["at"].as_str() < pair[1]["at"].as_str()));

        assert!(repositories
            .oauth()
            .store_direct_authorization_code(DirectAuthorizationCode {
                authorization_code_hash: "reviewer-protected-code".into(),
                account_id: reviewer_account.id.clone(),
                client_id: client_id.into(),
                ttl: Duration::from_secs(300),
            })
            .await
            .unwrap());
        assert!(matches!(
            repositories
                .lifecycle()
                .request_account_deletion(&reviewer_account.id)
                .await,
            Err(crate::error::EnclaveError::Conflict(message))
                if message == "reviewer fixture accounts cannot be deleted"
        ));
        assert_eq!(
            repositories
                .identity_sessions()
                .account_status(&reviewer_account.id)
                .await
                .unwrap(),
            Some(AccountStatus::Active)
        );
        assert!(repositories
            .lifecycle()
            .account_deletion_operation(&reviewer_account.id)
            .await
            .unwrap()
            .is_none());
        assert_eq!(
            sqlx::query_scalar::<_, i64>(
                "SELECT count(*) FROM oauth_authorization_codes \
                   WHERE account_id=$1 AND code_hash=$2",
            )
            .bind(&reviewer_account.id)
            .bind("reviewer-protected-code")
            .fetch_one(&pool)
            .await
            .unwrap(),
            1
        );

        // Re-create one admitted provider call in every global lane, then
        // crash its worker after the durable disclosure fence commits. Once
        // account deletion owns admission, the active-only scheduler will no
        // longer visit these rows; deletion preflight must recover them.
        let deletion_delivery_episode_id = 9_001_i64;
        sqlx::query(
            "INSERT INTO episodes( \
                account_id,id,started_at,ended_at,type,title,participants,languages, \
                finalized_at,finalization_version,finalization_status) \
             VALUES($1,$2,clock_timestamp()-interval '2 minutes', \
                    clock_timestamp()-interval '1 minute','meeting','Deletion crash fixture', \
                    '[]'::jsonb,'[]'::jsonb,clock_timestamp(),1,'complete')",
        )
        .bind(&account_id)
        .bind(deletion_delivery_episode_id)
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO episode_final_briefs( \
                account_id,episode_id,overview,decisions,action_items,important_links,open_questions) \
             VALUES($1,$2,'Deletion crash fixture','[]'::jsonb,'[]'::jsonb, \
                    '[]'::jsonb,'[]'::jsonb)",
        )
        .bind(&account_id)
        .bind(deletion_delivery_episode_id)
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO email_deliveries( \
                account_id,episode_id,delivery_version,delivery_id,include_content,state) \
             VALUES($1,$2,1,'deliv_deletion_crash',true,'pending')",
        )
        .bind(&account_id)
        .bind(deletion_delivery_episode_id)
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO webhook_deliveries( \
                account_id,episode_id,subscription_id,delivery_version,event_id,state) \
             VALUES($1,$2,$3,1,'evt_deletion_crash','pending')",
        )
        .bind(&account_id)
        .bind(deletion_delivery_episode_id)
        .bind(&webhook.id)
        .execute(&pool)
        .await
        .unwrap();
        let deletion_push_binding = format!("p1:{}:{}", installed.id, installed.token_generation);
        sqlx::query(
            "INSERT INTO push_deliveries( \
                account_id,episode_id,installation_binding,delivery_version,delivery_id, \
                handoff_handle,collapse_id,state) \
             VALUES($1,$2,$3,1,'push_deletion_crash','handoff_deletion_crash', \
                    'collapse_deletion_crash','pending')",
        )
        .bind(&account_id)
        .bind(deletion_delivery_episode_id)
        .bind(&deletion_push_binding)
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(
            "UPDATE provider_send_lanes SET owner_token=NULL,lease_until=NULL, \
                    next_send_at=clock_timestamp(),circuit_until=NULL",
        )
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query("UPDATE webhook_subscriptions SET enabled=true WHERE account_id=$1 AND id=$2")
            .bind(&account_id)
            .bind(&webhook.id)
            .execute(&pool)
            .await
            .unwrap();

        let deletion_email_candidate = repositories
            .deliveries()
            .next_email_candidate(&account_id)
            .await
            .unwrap()
            .expect("email candidate before deletion admission closes");
        let deletion_email_claim = repositories
            .deliveries()
            .claim_email(
                &deletion_email_candidate,
                FrozenEmailDelivery {
                    recipient_email: deletion_email_candidate.recipient_email.clone(),
                    include_content: deletion_email_candidate.include_content,
                    subject: "Deletion crash contract".into(),
                    text_body: "Deletion crash contract".into(),
                    html_body: "<p>Deletion crash contract</p>".into(),
                },
                60,
            )
            .await
            .unwrap()
            .expect("email claim before deletion admission closes");
        let deletion_webhook_candidate = repositories
            .deliveries()
            .next_webhook_candidate(&account_id)
            .await
            .unwrap()
            .expect("webhook candidate before deletion admission closes");
        let deletion_webhook_claim = repositories
            .deliveries()
            .claim_webhook(
                &deletion_webhook_candidate,
                FrozenWebhookDelivery {
                    endpoint_url: deletion_webhook_candidate.endpoint_url.clone(),
                    signing_secret: deletion_webhook_candidate.signing_secret.clone(),
                    include_content: deletion_webhook_candidate.include_content,
                    event_body: "{\"deletion_crash\":true}".into(),
                },
                60,
            )
            .await
            .unwrap()
            .expect("webhook claim before deletion admission closes");
        let deletion_push_candidate = repositories
            .deliveries()
            .next_push_candidate(&account_id)
            .await
            .unwrap()
            .expect("push candidate before deletion admission closes");
        let deletion_push_claim = repositories
            .deliveries()
            .claim_push(
                &deletion_push_candidate,
                FrozenPushDelivery {
                    topic: deletion_push_candidate.topic.clone(),
                    environment: deletion_push_candidate.environment.clone(),
                    device_token: deletion_push_candidate.device_token.clone(),
                    token_generation: deletion_push_candidate.token_generation,
                },
                60,
            )
            .await
            .unwrap()
            .expect("push claim before deletion admission closes");

        let billing_detach_id = repositories
            .billing()
            .billing_account_id_for_deletion(&account_id)
            .await
            .unwrap();
        let deletion_race_invocation = repositories
            .model_usage()
            .begin_invocation(
                &account_id,
                VertexOperation::EpisodeSummary,
                "gemini-contract",
                "us-central1",
                &[0x91; 32],
            )
            .await
            .unwrap();
        let deletion_upload = repositories
            .captures()
            .reserve_media_upload(
                &account_id,
                "deletion-race-event",
                "deletion-race-asset",
                &crate::gcs::canonical_capture_media_object_key(&account_id, "deletion-race-asset")
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
        let requested = repositories
            .lifecycle()
            .request_account_deletion(&account_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(requested.status, "pending");
        assert_eq!(requested.reason, "billing_fence_in_progress");
        assert_eq!(
            repositories
                .lifecycle()
                .request_account_deletion(&account_id)
                .await
                .unwrap()
                .unwrap()
                .operation_id,
            requested.operation_id
        );
        assert_eq!(
            repositories
                .identity_sessions()
                .account_status(&account_id)
                .await
                .unwrap(),
            Some(AccountStatus::DeletionRequested)
        );
        // Reproduce each notification/deletion lock race deterministically.
        // Real configuration mutations own one of these advisory locks before
        // require_active_account locks the account row. Preflight must wait
        // here without already owning that row, or the transactions deadlock.
        for (namespace, value) in [
            ("email-preference", account_id.clone()),
            ("webhook-registry", account_id.clone()),
            ("push-registry", "global".into()),
        ] {
            let mut config_transaction = pool.begin().await.unwrap();
            advisory_transaction_lock(&mut config_transaction, namespace, &value)
                .await
                .unwrap();
            let preflight_repositories = Arc::clone(&repositories);
            let preflight_account_id = account_id.clone();
            let preflight_task = tokio::spawn(async move {
                preflight_repositories
                    .lifecycle()
                    .account_deletion_preflight_complete(&preflight_account_id)
                    .await
            });
            tokio::time::timeout(Duration::from_secs(2), async {
                loop {
                    let waiting = sqlx::query_scalar::<_, bool>(
                        "SELECT EXISTS(SELECT 1 FROM pg_locks \
                           WHERE locktype='advisory' AND NOT granted)",
                    )
                    .fetch_one(&pool)
                    .await
                    .unwrap();
                    if waiting {
                        break;
                    }
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            })
            .await
            .expect("deletion preflight did not reach the held provider advisory lock");
            let config_status = tokio::time::timeout(
                Duration::from_millis(500),
                sqlx::query_scalar::<_, String>(
                    "SELECT status FROM accounts WHERE id=$1 FOR UPDATE",
                )
                .bind(&account_id)
                .fetch_one(&mut *config_transaction),
            )
            .await
            .expect("provider configuration row check deadlocked with deletion preflight")
            .unwrap();
            assert_eq!(config_status, "deletion_requested", "{namespace}");
            config_transaction.rollback().await.unwrap();
            assert!(!preflight_task.await.unwrap().unwrap(), "{namespace}");
        }
        assert_eq!(
            sqlx::query_scalar::<_, i64>(
                "SELECT count(*) FROM provider_send_lanes WHERE owner_token IS NOT NULL",
            )
            .fetch_one(&pool)
            .await
            .unwrap(),
            3,
            "unexpired calls retain their exact provider authority"
        );
        assert!(matches!(
            repositories
                .model_usage()
                .begin_invocation(
                    &account_id,
                    VertexOperation::EpisodeSummary,
                    "gemini-contract",
                    "us-central1",
                    &[0x92; 32],
                )
                .await,
            Err(crate::error::EnclaveError::Auth(_))
        ));
        assert!(repositories
            .captures()
            .reserve_media_upload(
                &account_id,
                "post-deletion-request-event",
                "post-deletion-request-asset",
                &crate::gcs::canonical_capture_media_object_key(
                    &account_id,
                    "post-deletion-request-asset",
                )
                .unwrap(),
                &"e".repeat(64),
            )
            .await
            .is_err());
        sqlx::query(
            "UPDATE email_deliveries SET claim_until=clock_timestamp()-interval '1 second' \
              WHERE account_id=$1 AND delivery_id=$2 AND claim_token=$3",
        )
        .bind(&account_id)
        .bind(&deletion_email_claim.delivery_id)
        .bind(&deletion_email_claim.claim_token)
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(
            "UPDATE webhook_deliveries SET claim_until=clock_timestamp()-interval '1 second' \
              WHERE account_id=$1 AND event_id=$2 AND claim_token=$3",
        )
        .bind(&account_id)
        .bind(&deletion_webhook_claim.event_id)
        .bind(&deletion_webhook_claim.claim_token)
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(
            "UPDATE push_deliveries SET claim_until=clock_timestamp()-interval '1 second' \
              WHERE account_id=$1 AND delivery_id=$2 AND claim_token=$3",
        )
        .bind(&account_id)
        .bind(&deletion_push_claim.delivery_id)
        .bind(&deletion_push_claim.claim_token)
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(
            "UPDATE capture_upload_intents SET expires_at=now()-interval '1 second' \
              WHERE account_id=$1 AND event_id='deletion-race-event'",
        )
        .bind(&account_id)
        .execute(&pool)
        .await
        .unwrap();
        assert!(repositories
            .lifecycle()
            .account_deletion_preflight_complete(&account_id)
            .await
            .unwrap());
        assert_eq!(
            sqlx::query_scalar::<_, String>(
                "SELECT state FROM email_deliveries WHERE account_id=$1 AND delivery_id=$2",
            )
            .bind(&account_id)
            .bind(&deletion_email_claim.delivery_id)
            .fetch_one(&pool)
            .await
            .unwrap(),
            "ambiguous"
        );
        assert_eq!(
            sqlx::query_scalar::<_, String>(
                "SELECT state FROM webhook_deliveries WHERE account_id=$1 AND event_id=$2",
            )
            .bind(&account_id)
            .bind(&deletion_webhook_claim.event_id)
            .fetch_one(&pool)
            .await
            .unwrap(),
            "ambiguous"
        );
        assert_eq!(
            sqlx::query_scalar::<_, String>(
                "SELECT state FROM push_deliveries WHERE account_id=$1 AND delivery_id=$2",
            )
            .bind(&account_id)
            .bind(&deletion_push_claim.delivery_id)
            .fetch_one(&pool)
            .await
            .unwrap(),
            "ambiguous"
        );
        assert_eq!(
            sqlx::query_scalar::<_, i64>(
                "SELECT (SELECT count(*) FROM email_send_fences WHERE account_id=$1) + \
                        (SELECT count(*) FROM webhook_send_fences WHERE account_id=$1) + \
                        (SELECT count(*) FROM push_send_fences WHERE account_id=$1)",
            )
            .bind(&account_id)
            .fetch_one(&pool)
            .await
            .unwrap(),
            0
        );
        assert_eq!(
            sqlx::query_scalar::<_, i64>(
                "SELECT count(*) FROM provider_send_lanes WHERE owner_token IS NOT NULL",
            )
            .fetch_one(&pool)
            .await
            .unwrap(),
            0,
            "expired deletion-owned calls cannot globally wedge provider lanes"
        );
        assert!(matches!(
            repositories
                .lifecycle()
                .begin_account_deletion(&account_id)
                .await,
            Err(crate::error::EnclaveError::Conflict(message))
                if message == "account has an in-flight Vertex invocation"
        ));

        // A provider response racing restart recovery is acknowledged only as
        // an idempotent stale settlement; it cannot overwrite ambiguity or
        // reacquire/release a successor's global lane.
        repositories
            .deliveries()
            .settle_email(
                &deletion_email_claim,
                EmailProviderOutcome::Accepted {
                    status: 202,
                    provider_message_id: "late-after-deletion".into(),
                },
                None,
            )
            .await
            .unwrap();
        repositories
            .deliveries()
            .settle_webhook(
                &deletion_webhook_claim,
                WebhookProviderOutcome::Sent { status: 204 },
                None,
            )
            .await
            .unwrap();
        repositories
            .deliveries()
            .settle_push(
                &deletion_push_claim,
                PushProviderOutcome::Accepted { status: 200 },
                None,
            )
            .await
            .unwrap();
        assert_eq!(
            sqlx::query_scalar::<_, i64>(
                "SELECT (SELECT count(*) FROM email_deliveries \
                            WHERE account_id=$1 AND state='ambiguous') + \
                        (SELECT count(*) FROM webhook_deliveries \
                            WHERE account_id=$1 AND state='ambiguous') + \
                        (SELECT count(*) FROM push_deliveries \
                            WHERE account_id=$1 AND state='ambiguous')",
            )
            .bind(&account_id)
            .fetch_one(&pool)
            .await
            .unwrap(),
            3
        );

        let deletion_usage = repositories
            .model_usage()
            .pending_events(&account_id, &billing_detach_id, true)
            .await
            .unwrap()
            .expect("deletion-owned Vertex start must become deliverable");
        assert!(deletion_usage.events.iter().any(|event| {
            event.event_id == deletion_race_invocation && event.outcome == "ambiguous"
        }));
        let deletion_usage_ids = deletion_usage
            .events
            .iter()
            .map(|event| event.event_id.clone())
            .collect::<Vec<_>>();
        repositories
            .model_usage()
            .complete_delivery(&account_id, &deletion_usage.claim_id, &deletion_usage_ids)
            .await
            .unwrap();
        let deletion = repositories
            .lifecycle()
            .begin_account_deletion(&account_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(deletion.operation_id, requested.operation_id);
        assert_eq!(deletion.reason, "content_deletion_in_progress");
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

        // Account deletion must own every reconciliation row, including paid
        // staged plaintext and committed content-free lineage. These fixtures
        // intentionally survive until the account row is deleted so the real
        // PostgreSQL cascade graph is exercised instead of a hand-maintained
        // pre-delete cleanup list.
        let staged_source_fingerprint = vec![0x31_u8; 32];
        let staged_topology_fingerprint = vec![0x32_u8; 32];
        let staged_result_commitment = vec![0x33_u8; 32];
        let staged_outputs_commitment = vec![0x34_u8; 32];
        let committed_source_fingerprint = vec![0x41_u8; 32];
        let committed_topology_fingerprint = vec![0x42_u8; 32];
        let committed_result_commitment = vec![0x43_u8; 32];
        let predecessor_handle_id = 9_100_001_i64;
        let successor_handle_id = 9_100_002_i64;
        let mut reconciliation_fixture = pool.begin().await.unwrap();
        sqlx::query(
            "INSERT INTO memory_reconciliation_jobs(\
                 account_id,source_fingerprint,topology_fingerprint,\
                 predecessor_episode_ids,cohort_started_at,cohort_ended_at,state) \
             VALUES($1,$2,$3,$4,'2026-08-27T10:00:00Z','2026-08-27T10:05:00Z','pending')",
        )
        .bind(&account_id)
        .bind(&staged_source_fingerprint)
        .bind(&staged_topology_fingerprint)
        .bind(vec![predecessor_handle_id])
        .execute(&mut *reconciliation_fixture)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO memory_reconciliation_stages(\
                 account_id,source_fingerprint,topology_fingerprint,predecessor_episode_ids,\
                 normalized_partition,result_commitment,planned_outputs,planned_outputs_commitment,\
                 model,reconciliation_version,\
                 prompt_version,partition_schema_version,validator_version) \
             VALUES($1,$2,$3,$4,$5::jsonb,$6,'[]'::jsonb,$7,'contract-model',1,1,1,1)",
        )
        .bind(&account_id)
        .bind(&staged_source_fingerprint)
        .bind(&staged_topology_fingerprint)
        .bind(vec![predecessor_handle_id])
        .bind("{\"memories\":[]}")
        .bind(&staged_result_commitment)
        .bind(&staged_outputs_commitment)
        .execute(&mut *reconciliation_fixture)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO memory_reconciliations(\
                 account_id,id,reconciliation_version,model,prompt_version,\
                 cohort_started_at,cohort_ended_at,source_fingerprint,topology_fingerprint,\
                 result_commitment,archive_revision) \
             VALUES($1,'rec-account-delete-contract',1,'contract-model',1,\
                    '2026-08-27T11:00:00Z','2026-08-27T11:05:00Z',$2,$3,$4,1)",
        )
        .bind(&account_id)
        .bind(&committed_source_fingerprint)
        .bind(&committed_topology_fingerprint)
        .bind(&committed_result_commitment)
        .execute(&mut *reconciliation_fixture)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO memory_handles(\
                 account_id,episode_id,state,origin_relation,reconciliation_id,retired_at) \
             VALUES($1,$2,'superseded','merge','rec-account-delete-contract',now()),\
                   ($1,$3,'active',NULL,NULL,NULL)",
        )
        .bind(&account_id)
        .bind(predecessor_handle_id)
        .bind(successor_handle_id)
        .execute(&mut *reconciliation_fixture)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO memory_lineage_edges(\
                 account_id,reconciliation_id,predecessor_episode_id,successor_episode_id,ordinal) \
             VALUES($1,'rec-account-delete-contract',$2,$3,0)",
        )
        .bind(&account_id)
        .bind(predecessor_handle_id)
        .bind(successor_handle_id)
        .execute(&mut *reconciliation_fixture)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO memory_reconciliation_sources(\
                 account_id,reconciliation_id,record_type,record_id,successor_episode_id) \
             VALUES($1,'rec-account-delete-contract','screenshot',9100003,$2)",
        )
        .bind(&account_id)
        .bind(successor_handle_id)
        .execute(&mut *reconciliation_fixture)
        .await
        .unwrap();
        reconciliation_fixture.commit().await.unwrap();

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
                .account_status(&reviewer_account.id)
                .await
                .unwrap(),
            Some(AccountStatus::Active),
            "ordinary account deletion must not affect the persistent reviewer"
        );
        assert_eq!(
            repositories
                .identity_sessions()
                .account_status(&account_id)
                .await
                .unwrap(),
            Some(AccountStatus::Deleted)
        );
        assert_eq!(
            sqlx::query_scalar::<_, i64>(
                "SELECT count(*) FROM memory_reconciliation_stages WHERE account_id=$1",
            )
            .bind(&account_id)
            .fetch_one(&pool)
            .await
            .unwrap(),
            0,
            "staged reconciliation content must cascade with the account"
        );
        assert_eq!(
            sqlx::query_scalar::<_, i64>(
                "SELECT count(*) FROM memory_lineage_edges WHERE account_id=$1",
            )
            .bind(&account_id)
            .fetch_one(&pool)
            .await
            .unwrap(),
            0,
            "memory lineage must cascade with the account"
        );
        assert_eq!(
            sqlx::query_scalar::<_, i64>(
                "SELECT count(*) FROM memory_reconciliation_sources WHERE account_id=$1",
            )
            .bind(&account_id)
            .fetch_one(&pool)
            .await
            .unwrap(),
            0,
            "reconciliation source projections must cascade with the account"
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

        // A short answer to a direct name question may identify that answer's
        // speaker. A later speaker repeating or expanding the name must not
        // create a second Person, even if the model incorrectly labels the
        // expansion as that later speaker's self-identification.
        let identity_account = repositories
            .identity_sessions()
            .upsert_subject_account(
                "voice-name-regression-subject",
                "voice-name-regression@example.com",
                11,
            )
            .await
            .unwrap();
        let audio_manifest: crate::cp::media::CaptureEventManifest =
            serde_json::from_value(serde_json::json!({
                "schema_version": 2,
                "event_id": "voice-name-regression-event",
                "device_id": "voice-name-regression-device",
                "install_id": "voice-name-regression-install",
                "capture_session_id": "voice-name-regression-session",
                "stream_id": "voice-name-regression-stream",
                "stream_kind": "mic",
                "sequence": 0,
                "source_wall_at": "2026-08-27T13:00:00.000Z",
                "source_monotonic_ns": 1_000_u64,
                "started_at": "2026-08-27T13:00:00.000Z",
                "ended_at": "2026-08-27T13:00:05.000Z",
                "timezone_id": "America/New_York",
                "utc_offset_minutes": -240,
                "clock_uncertainty_ms": 10,
                "media": {
                    "asset_id": "voice-name-regression-asset",
                    "mime_type": "audio/mp4",
                    "codec": "aac",
                    "byte_length": 12,
                    "sha256": "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
                    "sample_rate": 48_000,
                    "channels": 1,
                    "frame_count": 240_000
                },
                "context": null,
                "audio_role": "mixed"
            }))
            .unwrap();
        audio_manifest.validate().unwrap();
        let audio_digest = crate::cp::media::manifest_digest(&audio_manifest).unwrap();
        let audio_object_key = crate::gcs::canonical_capture_media_object_key(
            &identity_account.id,
            &audio_manifest.media.as_ref().unwrap().asset_id,
        )
        .unwrap();
        let audio_upload_token = repositories
            .captures()
            .reserve_media_upload(
                &identity_account.id,
                &audio_manifest.event_id,
                &audio_manifest.media.as_ref().unwrap().asset_id,
                &audio_object_key,
                &audio_digest,
            )
            .await
            .unwrap();
        repositories
            .captures()
            .commit_event(CaptureCommit {
                account_id: identity_account.id.clone(),
                manifest: audio_manifest,
                manifest_digest: audio_digest,
                object_key: Some(audio_object_key),
                object_generation: Some(1),
                upload_token: audio_upload_token,
                media_authority: Some(
                    crate::cp::media::RecordingMediaAuthorityDecision::ProcessingWindow30d {
                        capture_policy_revision: 0,
                        decision_at: "2026-08-27T13:00:05.000Z".into(),
                    },
                ),
                committed_at: "2026-08-27T13:00:05.000Z".into(),
            })
            .await
            .unwrap();
        let identity_media = repositories.media_processing();
        let audio_claim = identity_media
            .claim(
                &identity_account.id,
                MediaProcessingClass::Audio,
                "2026-08-27T13:00:06.000Z",
                300,
                128,
            )
            .await
            .unwrap()
            .expect("audio identity regression claim");
        let audio_attempt = media_processing::test_stage_media_provider_success(
            persistence.as_ref(),
            &audio_claim,
            4_096,
        )
        .await
        .unwrap();
        identity_media
            .settle_usage(MediaUsageSettlement {
                claim: audio_claim.clone(),
                provider_attempt: audio_attempt.clone(),
                usage: serde_json::json!({
                    "work_unit_id": audio_claim.work_unit_id,
                    "reservation_state": "reserved",
                    "actual_output_tokens": 64,
                    "outcome": "model_returned"
                }),
            })
            .await
            .unwrap();
        let turns = vec![
            AudioTurn {
                turn_id: "name-question".into(),
                start_ms: 0,
                end_ms: 1_000,
                speaker_local_id: "joseph".into(),
                text: "What is your name?".into(),
                language: Some("en".into()),
                speaker_name: None,
                speaker_name_confidence: None,
                speaker_name_evidence: None,
                speaker_name_kind: None,
                speaker_name_subject_turn_id: None,
                speaker_name_target_turn_id: None,
                person_facts: Vec::new(),
                overlap: false,
                quality_flags: Vec::new(),
            },
            AudioTurn {
                turn_id: "name-answer".into(),
                start_ms: 1_100,
                end_ms: 1_900,
                speaker_local_id: "sarah".into(),
                text: "Sarah".into(),
                language: Some("en".into()),
                speaker_name: Some("Sarah".into()),
                speaker_name_confidence: Some(0.99),
                speaker_name_evidence: Some("Sarah".into()),
                speaker_name_kind: Some("self_identification".into()),
                speaker_name_subject_turn_id: Some("name-answer".into()),
                speaker_name_target_turn_id: None,
                person_facts: Vec::new(),
                overlap: false,
                quality_flags: Vec::new(),
            },
            AudioTurn {
                turn_id: "name-expansion".into(),
                start_ms: 2_000,
                end_ms: 3_200,
                speaker_local_id: "joseph".into(),
                text: "Mrs. Sarah Babetski, including her last name".into(),
                language: Some("en".into()),
                speaker_name: Some("Sarah Babetski".into()),
                speaker_name_confidence: Some(0.99),
                speaker_name_evidence: Some("Mrs. Sarah Babetski, including her last name".into()),
                speaker_name_kind: Some("self_identification".into()),
                speaker_name_subject_turn_id: Some("name-expansion".into()),
                speaker_name_target_turn_id: None,
                person_facts: Vec::new(),
                overlap: false,
                quality_flags: Vec::new(),
            },
        ];
        let audio_settlement = AudioMediaSettlement {
            claim: audio_claim,
            provider_attempt: audio_attempt,
            turns,
        };
        identity_media
            .settle_audio(audio_settlement.clone())
            .await
            .unwrap();
        identity_media.settle_audio(audio_settlement).await.unwrap();
        let identity_people = sqlx::query_as::<_, (i64, Option<String>)>(
            "SELECT id,display_name FROM people WHERE account_id=$1 ORDER BY id",
        )
        .bind(&identity_account.id)
        .fetch_all(&pool)
        .await
        .unwrap();
        assert_eq!(identity_people.len(), 1);
        assert_eq!(identity_people[0].1.as_deref(), Some("Sarah"));
        assert_eq!(
            sqlx::query_scalar::<_, i64>(
                "SELECT count(*) FROM person_name_claims WHERE account_id=$1",
            )
            .bind(&identity_account.id)
            .fetch_one(&pool)
            .await
            .unwrap(),
            1
        );
        assert!(sqlx::query_scalar::<_, Option<i64>>(
            "SELECT person_id FROM speaker_observations \
                 WHERE account_id=$1 AND turn_id='name-expansion'",
        )
        .bind(&identity_account.id)
        .fetch_one(&pool)
        .await
        .unwrap()
        .is_none());

        super::activation::test_real_pg_activation_contract(&persistence).await;
        super::aggregate_audit::test_real_pg_aggregate_audit(&persistence).await;
    }
}
