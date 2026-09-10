//! Synthetic real-PostgreSQL signed erasure, never owner data/provider I/O.

use super::{
    orphan_capture_erasure_authority::{
        sha256_label, test_verified_request, ErasureAction, ErasureActivationBinding,
        ErasureFenceRelease, ErasureFinalize, ErasureOperationBinding, ErasurePrepare,
        ErasureProviderAcknowledgement, ErasureTargets, OrphanErasureRequest,
    },
    PostgresPersistence,
};
use crate::{cp::isotime, error::Result, persistence::PlaybackRepository};

const ACCOUNT: &str = "orphan-controller-fixture";

async fn test_transaction_deadlines(persistence: &PostgresPersistence) -> Result<()> {
    let mut production = persistence.pool().begin().await?;
    super::orphan_capture_erasure_operator::configure_execution_limits(&mut production).await?;
    assert_eq!(
            sqlx::query_as::<_, (String, String, String, String, String, String)>(
                "SELECT current_setting('transaction_timeout'),current_setting('statement_timeout'), \
                 current_setting('idle_in_transaction_session_timeout'),current_setting('lock_timeout'), \
                 current_setting('synchronous_commit'),current_setting('fsync')",
            ).fetch_one(&mut *production).await?,
            ("45s".into(), "15s".into(), "15s".into(), "250ms".into(), "on".into(), "on".into())
        );
    production.rollback().await?;
    for (suffix, mode) in [("transaction", 0), ("idle", 1), ("statement", 2)] {
        let account = format!("orphan-deadline-{suffix}");
        let mut transaction = persistence.pool().begin().await?;
        // Exercise the same server mechanisms at shorter test-only thresholds,
        // retaining transaction > statement/idle so neither timeout is suppressed.
        // Configure once at transaction start: changing a nonzero transaction
        // timeout after its timer is armed does not restart the existing timer.
        super::orphan_capture_erasure_operator::configure_test_execution_limits(&mut transaction)
            .await?;
        sqlx::query("INSERT INTO accounts(id,email,primary_provider,primary_subject) VALUES($1,$1||'@example.invalid','google',$1)")
            .bind(&account).execute(&mut *transaction).await?;
        match mode {
            0 => {
                let mut terminated = false;
                for _ in 0..4 {
                    if sqlx::query("SELECT pg_sleep(0.8)")
                        .execute(&mut *transaction)
                        .await
                        .is_err()
                    {
                        terminated = true;
                        break;
                    }
                }
                assert!(
                    terminated,
                    "separate sub-deadline statements cannot outlive the transaction deadline"
                );
                assert!(transaction.commit().await.is_err());
            }
            1 => {
                tokio::time::sleep(std::time::Duration::from_millis(1500)).await;
                assert!(
                    transaction.commit().await.is_err(),
                    "a descheduled client cannot commit after the idle deadline"
                );
            }
            _ => {
                let error = sqlx::query("SELECT pg_sleep(1.3)")
                    .execute(&mut *transaction)
                    .await
                    .expect_err("each statement has its own enforced deadline");
                assert_eq!(
                    error
                        .as_database_error()
                        .and_then(|error| error.code())
                        .as_deref(),
                    Some("57014")
                );
                transaction.rollback().await?;
            }
        }
        assert!(
            !sqlx::query_scalar::<_, bool>("SELECT EXISTS(SELECT 1 FROM accounts WHERE id=$1)")
                .bind(&account)
                .fetch_one(persistence.pool())
                .await?,
            "timed-out mutations leave no durable sentinel"
        );
    }
    Ok(())
}

#[tokio::test]
async fn postgres_orphan_erasure_deadline_contract() {
    use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
    use std::{
        str::FromStr as _,
        time::{Duration, SystemTime, UNIX_EPOCH},
    };
    let required = std::env::var("KIOKU_REQUIRE_POSTGRES_CONTRACT").as_deref() == Ok("1");
    let Ok(database_url) = std::env::var("KIOKU_TEST_POSTGRES_URL") else {
        assert!(
            !required,
            "real PostgreSQL deadline contract requires its disposable database URL"
        );
        return;
    };
    // Concurrent index creation in the release contracts can wait for older
    // transactions database-wide, even when this sentinel is in another schema.
    // Keep deliberately stalled transactions outside those migration windows.
    let _release_contract_guard = super::POSTGRES_RELEASE_CONTRACT_MUTEX.lock().await;
    let base = PostgresPersistence::connect(super::PostgresPoolConfig {
        database_url: database_url.clone(),
        root_ca_pem: None,
        max_connections: 2,
        acquire_timeout: Duration::from_secs(5),
        statement_timeout: Duration::from_secs(30),
    })
    .await
    .expect("connect disposable deadline database");
    let schema = format!(
        "kioku_erasure_deadline_{}_{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );
    sqlx::raw_sql(sqlx::AssertSqlSafe(format!(
        "CREATE SCHEMA {schema}; CREATE TABLE {schema}.accounts( \
         id text PRIMARY KEY,email text,primary_provider text,primary_subject text)"
    )))
    .execute(base.pool())
    .await
    .expect("create isolated timeout sentinel fixture");
    let options = PgConnectOptions::from_str(&database_url)
        .unwrap()
        .options([("search_path", schema.clone())]);
    let pool = PgPoolOptions::new()
        .max_connections(2)
        .connect_with(options)
        .await
        .unwrap();
    let persistence = PostgresPersistence { pool: pool.clone() };
    let outcome =
        tokio::spawn(async move { Box::pin(test_transaction_deadlines(&persistence)).await }).await;
    pool.close().await;
    sqlx::query(sqlx::AssertSqlSafe(format!("DROP SCHEMA {schema} CASCADE")))
        .execute(base.pool())
        .await
        .expect("remove isolated timeout sentinel fixture");
    base.pool().close().await;
    outcome
        .expect("deadline contract must not panic")
        .expect("deadline rollback contract");
}

async fn fixture(persistence: &PostgresPersistence) -> Result<()> {
    sqlx::query("INSERT INTO accounts(id,email,primary_provider,primary_subject) VALUES($1,$1||'@example.invalid','google',$1)")
        .bind(ACCOUNT).execute(persistence.pool()).await?;
    sqlx::query("INSERT INTO episodes(account_id,id,started_at,ended_at,title,summary) \
       VALUES($1,1,now()-interval '12 days',now()-interval '11 days','protected fixture','unchanged fixture text')")
        .bind(ACCOUNT).execute(persistence.pool()).await?;
    sqlx::query("INSERT INTO capture_sessions(account_id,id,device_id,install_id,started_at,last_event_at,ended_at,schema_version) \
       SELECT $1,id,'device','install',now()-interval '10 days',now()-interval '8 days',now()-interval '8 days',2 \
       FROM unnest(ARRAY['session-a','session-b','session-keep']) item(id)")
        .bind(ACCOUNT).execute(persistence.pool()).await?;
    sqlx::query("INSERT INTO capture_streams(account_id,id,capture_session_id,device_id,stream_kind) \
       SELECT $1,id,session,'device','mac_screen' FROM (VALUES ('stream-a','session-a'),('stream-b','session-a'), \
        ('stream-c','session-b'),('stream-keep','session-keep')) fixture(id,session)")
        .bind(ACCOUNT).execute(persistence.pool()).await?;
    sqlx::query("INSERT INTO capture_events(account_id,event_id,device_id,install_id,capture_session_id,stream_id,stream_kind, \
       sequence,source_wall_at,source_monotonic_ns,started_at,ended_at,timezone_id,utc_offset_minutes,clock_uncertainty_ms, \
       asset_id,manifest_digest,media_disposition) \
       SELECT $1,'event-'||suffix,'device','install',session,'stream-'||suffix,'mac_screen',5, \
       now()-interval '9 days','100',now()-interval '9 days',now()-interval '8 days','UTC',0,0, \
       'asset-'||suffix,repeat('a',64),'canonical' FROM (VALUES ('a','session-a'),('b','session-a'), \
       ('c','session-b'),('keep','session-keep')) fixture(suffix,session)")
        .bind(ACCOUNT).execute(persistence.pool()).await?;
    sqlx::query("INSERT INTO media_objects(account_id,asset_id,event_id,object_key,object_generation,object_backend,mime_type,codec,byte_length,sha256) \
       SELECT account_id,asset_id,event_id,'raw/'||account_id||'/'||asset_id||'.enc',1,'current','image/jpeg','jpeg',5,repeat('b',64) \
       FROM capture_events WHERE account_id=$1")
        .bind(ACCOUNT).execute(persistence.pool()).await?;
    sqlx::query("INSERT INTO recording_media_authority(account_id,asset_id,capture_policy_revision,retention_policy_revision, \
        retention_decision,storage_backend,recording_state,decision_at,updated_at) \
        SELECT account_id,asset_id,0,0,'processing_window_30d','processing','processing_only',now(),now() \
        FROM media_objects WHERE account_id=$1")
        .bind(ACCOUNT).execute(persistence.pool()).await?;
    sqlx::query(
        "INSERT INTO screenshots(account_id,id,captured_at,source_key,ocr_text) \
       SELECT $1,id,now()-interval '9 days','cloud-v2:event-'||suffix,'fixture source' \
       FROM (VALUES (2,'a'),(3,'b'),(4,'c'),(5,'keep')) fixture(id,suffix)",
    )
    .bind(ACCOUNT)
    .execute(persistence.pool())
    .await?;
    sqlx::query(
        "INSERT INTO capture_formation_receipts(account_id,capture_session_id,source_revision) \
       SELECT account_id,id,1 FROM capture_sessions WHERE account_id=$1",
    )
    .bind(ACCOUNT)
    .execute(persistence.pool())
    .await?;
    Ok(())
}

pub(super) async fn test_signed_orphan_operator(
    persistence: &PostgresPersistence,
    activation: ErasureActivationBinding,
) -> Result<()> {
    fixture(persistence).await?;
    let now: i64 =
        sqlx::query_scalar("SELECT floor(extract(epoch FROM clock_timestamp())*1000)::bigint")
            .fetch_one(persistence.pool())
            .await?;
    let targets = ErasureTargets {
        capture_session_ids: vec!["session-a".into(), "session-b".into()],
        protected_episode_id: 1,
    };
    let mut request = OrphanErasureRequest {
        contract: "kioku.postgresql.orphan-capture-erasure.v1".into(),
        erasure_contract_sha256: sha256_label(&super::orphan_capture_erasure::contract_digest()),
        account_id: ACCOUNT.into(),
        operation_id: "exact-fixture-erasure".into(),
        activation,
        observed_at: isotime::format_epoch_millis(now - 1000),
        expires_at: isotime::format_epoch_millis(now + 14 * 60 * 1000),
        action: ErasureAction::Inspect(targets.clone()),
    };
    let inspect = test_verified_request(request.clone())?;
    let report = persistence
        .execute_orphan_capture_erasure_inner(&inspect)
        .await
        .expect("synthetic initial signed inspection")
        .scope
        .expect("inspect has only a content-free scope");
    assert_eq!(report.counts.sessions, 2);
    assert_eq!(report.counts.streams, 3);
    assert_eq!(report.counts.events, 3);
    assert_eq!(report.counts.projections, 3);
    assert_eq!(report.counts.objects, 3);
    assert_eq!(report.provider_name_count, 6);
    // Each canonical event must retain its exact source/provider authority;
    // absent rows are not evidence that the provider has no remaining object.
    for mutation in [
        "DELETE FROM media_objects WHERE account_id=$1 AND event_id='event-a'",
        "DELETE FROM media_objects WHERE account_id=$1 AND event_id IN ('event-a','event-b','event-c')",
        "DELETE FROM recording_media_authority WHERE account_id=$1 AND asset_id='asset-a'",
        "UPDATE recording_media_authority SET storage_backend='recordings' WHERE account_id=$1 AND asset_id='asset-a'",
        "UPDATE recording_media_authority SET retention_decision='until_deleted' WHERE account_id=$1 AND asset_id='asset-a'",
        "UPDATE capture_events SET canonical_asset_id='asset-keep' WHERE account_id=$1 AND event_id='event-a'",
        "UPDATE capture_events SET canonical_media_sha256=repeat('b',64) WHERE account_id=$1 AND event_id='event-a'",
        "UPDATE capture_events SET media_disposition='reference',canonical_event_id='event-b',canonical_asset_id='asset-b', \
             canonical_media_sha256=repeat('b',64) WHERE account_id=$1 AND event_id='event-a'",
    ] {
        let mut malformed = persistence.pool().begin().await?;
        sqlx::query(mutation).bind(ACCOUNT).execute(&mut *malformed).await?;
        assert!(super::orphan_capture_erasure_scope::inspect_scope(&mut malformed, ACCOUNT, &targets).await.is_err());
        malformed.rollback().await?;
    }
    let mut install = request.clone();
    install.action = ErasureAction::InstallSchema;
    install.account_id = "schema".into();
    install.operation_id = "install".into();
    assert_eq!(
        persistence
            .execute_orphan_capture_erasure_inner(&test_verified_request(install)?)
            .await?
            .state,
        "already_installed",
        "an installed namespace is never misrepresented as newly empty"
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM capture_sessions WHERE account_id=$1")
            .bind(ACCOUNT)
            .fetch_one(persistence.pool())
            .await?,
        3,
        "inspect never mutates source data"
    );

    // A source gaining an owner makes this narrow operation invalid, including
    // an overlap with the protected episode. Removing the fixture restores it.
    sqlx::query("INSERT INTO episode_members(account_id,episode_id,record_type,record_id) VALUES($1,1,'screenshot',2)")
        .bind(ACCOUNT).execute(persistence.pool()).await?;
    assert!(persistence
        .execute_orphan_capture_erasure(&inspect)
        .await
        .is_err());
    sqlx::query("DELETE FROM episode_members WHERE account_id=$1 AND record_id=2")
        .bind(ACCOUNT)
        .execute(persistence.pool())
        .await?;

    // A genuine cross-session family is refused, never cascade-erased.
    sqlx::query(
        "UPDATE capture_events SET media_disposition='reference',canonical_event_id='event-a' \
       WHERE account_id=$1 AND event_id='event-keep'",
    )
    .bind(ACCOUNT)
    .execute(persistence.pool())
    .await?;
    assert!(persistence
        .execute_orphan_capture_erasure(&inspect)
        .await
        .is_err());
    sqlx::query(
        "UPDATE capture_events SET media_disposition='canonical',canonical_event_id=NULL \
       WHERE account_id=$1 AND event_id='event-keep'",
    )
    .bind(ACCOUNT)
    .execute(persistence.pool())
    .await?;

    sqlx::query("UPDATE capture_events SET canonical_asset_id='asset-a' WHERE account_id=$1 AND event_id='event-keep'")
        .bind(ACCOUNT).execute(persistence.pool()).await?;
    assert!(
        persistence
            .execute_orphan_capture_erasure(&inspect)
            .await
            .is_err(),
        "malformed external asset references cannot survive erasure"
    );
    sqlx::query("UPDATE capture_events SET canonical_asset_id=NULL WHERE account_id=$1 AND event_id='event-keep'")
        .bind(ACCOUNT).execute(persistence.pool()).await?;

    request.action = ErasureAction::Prepare(ErasurePrepare {
        targets,
        scope_sha256: report.scope_sha256.clone(),
        object_inventory_sha256: report.object_inventory_sha256.clone(),
        provider_names_sha256: report.provider_names_sha256.clone(),
        provider_name_count: report.provider_name_count,
        account_provider_names_sha256: report.account_provider_names_sha256.clone(),
        provider_unclassified_objects: 0,
        survivor_sha256: report.survivor_sha256.clone(),
        protected_control_proof_sha256: report.protected_control_proof_sha256.clone(),
        provider_authority_sha256: sha256_label(&[3; 32]),
        provider_retention_clear: true,
        counts: report.counts.clone(),
    });
    let mut changed = request.clone();
    if let ErasureAction::Prepare(p) = &mut changed.action {
        p.counts.events += 1;
    }
    assert!(persistence
        .execute_orphan_capture_erasure(&test_verified_request(changed)?)
        .await
        .is_err());
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT count(*) FROM orphan_capture_erasure_operations WHERE account_id=$1"
        )
        .bind(ACCOUNT)
        .fetch_one(persistence.pool())
        .await?,
        0,
        "changed signed scope leaves no fence or journal"
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM capture_sessions WHERE account_id=$1")
            .bind(ACCOUNT)
            .fetch_one(persistence.pool())
            .await?,
        3
    );

    for session in ["session-a", "session-b", "session-keep"] {
        assert!(
            persistence
                .session_dataset(ACCOUNT, session, None)
                .await?
                .is_some(),
            "exact recordings are addressable before erasure preparation"
        );
    }
    let prepare = test_verified_request(request.clone())?;
    // A real late cascade failure occurs after projection removal and journal
    // creation. All source rows, the protected control and the fence roll back.
    sqlx::raw_sql(
        "CREATE FUNCTION erasure_test_late_failure() RETURNS trigger LANGUAGE plpgsql AS $$ \
        BEGIN RAISE EXCEPTION 'synthetic late erasure failure' USING ERRCODE='55000'; END $$; \
        CREATE TRIGGER erasure_test_late_failure AFTER DELETE ON capture_sessions \
        FOR EACH STATEMENT EXECUTE FUNCTION erasure_test_late_failure();",
    )
    .execute(persistence.pool())
    .await?;
    assert!(persistence
        .execute_orphan_capture_erasure(&prepare)
        .await
        .is_err());
    sqlx::raw_sql("DROP TRIGGER erasure_test_late_failure ON capture_sessions; DROP FUNCTION erasure_test_late_failure();")
        .execute(persistence.pool()).await?;
    let restored = persistence
        .execute_orphan_capture_erasure_inner(&inspect)
        .await?
        .scope
        .unwrap();
    assert_eq!(restored.scope_sha256, report.scope_sha256);
    assert_eq!(restored.survivor_sha256, report.survivor_sha256);
    assert_eq!(
        restored.protected_control_proof_sha256,
        report.protected_control_proof_sha256
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT count(*) FROM orphan_capture_erasure_operations WHERE account_id=$1"
        )
        .bind(ACCOUNT)
        .fetch_one(persistence.pool())
        .await?,
        0
    );
    let prepared = persistence
        .execute_orphan_capture_erasure_inner(&prepare)
        .await
        .expect("synthetic exact signed preparation");
    assert_eq!(prepared.state, "provider_pending");
    assert!(prepared.capture_upload_fenced);
    for session in ["session-a", "session-b"] {
        assert!(
            persistence
                .session_dataset(ACCOUNT, session, None)
                .await?
                .is_none(),
            "provider-pending erasure inventory must not authorize recording playback"
        );
    }
    assert!(
        persistence
            .session_dataset(ACCOUNT, "session-keep", None)
            .await?
            .is_some(),
        "the unselected recording remains addressable"
    );
    assert_eq!(
        persistence
            .execute_orphan_capture_erasure_inner(&prepare)
            .await?
            .state,
        "provider_pending"
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM capture_sessions WHERE account_id=$1")
            .bind(ACCOUNT)
            .fetch_one(persistence.pool())
            .await?,
        1
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM screenshots WHERE account_id=$1")
            .bind(ACCOUNT)
            .fetch_one(persistence.pool())
            .await?,
        1
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM media_objects WHERE account_id=$1")
            .bind(ACCOUNT)
            .fetch_one(persistence.pool())
            .await?,
        1
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT count(*) FROM orphan_capture_erasure_objects WHERE account_id=$1"
        )
        .bind(ACCOUNT)
        .fetch_one(persistence.pool())
        .await?,
        3
    );
    let mut connection = persistence.pool().acquire().await?;
    assert!(
        super::orphan_capture_erasure::require_no_pending_erasures(&mut connection)
            .await
            .is_err()
    );
    drop(connection);
    let pending_audit =
        super::orphan_capture_erasure_audit::snapshot(&mut *persistence.pool().acquire().await?)
            .await?;
    assert_eq!(pending_audit.pending_operations, 1);
    assert_eq!(pending_audit.inventory_objects, 3);
    assert_eq!(pending_audit.coherence_violations, 0);
    assert!(!pending_audit.complete());
    assert!(sqlx::query("UPDATE capture_sessions SET last_event_at=clock_timestamp() WHERE account_id=$1 AND id='session-keep'")
        .bind(ACCOUNT).execute(persistence.pool()).await.is_err(),"old serving cannot admit even an unrelated reference through existing parents while fenced");

    let operation = ErasureOperationBinding {
        prepare_request_sha256: sha256_label(&prepare.request_sha256),
        scope_sha256: report.scope_sha256,
        object_inventory_sha256: report.object_inventory_sha256,
        provider_names_sha256: report.provider_names_sha256,
        account_provider_names_sha256: report.account_provider_names_sha256,
    };
    request.action = ErasureAction::Finalize(ErasureFinalize {
        operation: operation.clone(),
        provider_ack_request_sha256: sha256_label(&[4; 32]),
        protected_episode_id: 1,
    });
    assert!(persistence
        .execute_orphan_capture_erasure(&test_verified_request(request.clone())?)
        .await
        .is_err());
    request.action = ErasureAction::AcknowledgeProvider(ErasureProviderAcknowledgement {
        operation: operation.clone(),
        provider_receipt_sha256: sha256_label(&[4; 32]),
        all_generations_absent: true,
        retention_clear: true,
        provider_unclassified_objects: 0,
    });
    let ack = test_verified_request(request.clone())?;
    let mut unclassified = request.clone();
    if let ErasureAction::AcknowledgeProvider(ack) = &mut unclassified.action {
        ack.provider_unclassified_objects = 1;
    }
    assert!(
        test_verified_request(unclassified).is_err(),
        "unknown provider objects cannot be acknowledged as complete"
    );
    assert_eq!(
        persistence
            .execute_orphan_capture_erasure_inner(&ack)
            .await?
            .state,
        "provider_verified"
    );
    assert_eq!(
        persistence
            .execute_orphan_capture_erasure_inner(&ack)
            .await?
            .state,
        "provider_verified"
    );
    request.action = ErasureAction::Finalize(ErasureFinalize {
        operation: operation.clone(),
        provider_ack_request_sha256: sha256_label(&ack.request_sha256),
        protected_episode_id: 1,
    });
    let finalize = test_verified_request(request.clone())?;
    let completed = persistence
        .execute_orphan_capture_erasure_inner(&finalize)
        .await?;
    assert_eq!(completed.state, "complete");
    assert!(
        completed.capture_upload_fenced,
        "completion cannot claim resumed capture"
    );
    assert_eq!(
        persistence
            .execute_orphan_capture_erasure_inner(&finalize)
            .await?
            .state,
        "complete"
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT count(*) FROM orphan_capture_erasure_objects WHERE account_id=$1"
        )
        .bind(ACCOUNT)
        .fetch_one(persistence.pool())
        .await?,
        0,
        "completion and private inventory scrub are one commit"
    );
    assert_eq!(
        sqlx::query_scalar::<_, String>(
            "SELECT summary FROM episodes WHERE account_id=$1 AND id=1"
        )
        .bind(ACCOUNT)
        .fetch_one(persistence.pool())
        .await?,
        "unchanged fixture text"
    );
    let mut connection = persistence.pool().acquire().await?;
    super::orphan_capture_erasure::require_no_pending_erasures(&mut connection).await?;
    drop(connection);
    let completed_audit =
        super::orphan_capture_erasure_audit::snapshot(&mut *persistence.pool().acquire().await?)
            .await?;
    assert_eq!(completed_audit.complete_fenced_operations, 1);
    assert!(completed_audit.complete() && !completed_audit.unfenced());
    // Use real signed transitions, not direct event insertion, to exercise
    // complete-fenced Active and the later homogeneous candidate rotation.
    request.activation =
        super::activation::test_erasure_activation_transition(persistence, "active", false).await?;
    request.action = ErasureAction::ReleaseFence(ErasureFenceRelease {
        operation,
        completion_request_sha256: sha256_label(&finalize.request_sha256),
        admission_contract_sha256:
            super::orphan_capture_erasure_authority::admission_contract_sha256(),
        fleet_evidence_sha256: sha256_label(&[7; 32]),
        protected_canary_evidence_sha256: sha256_label(&[8; 32]),
        candidate_instances: 2,
        predecessor_instances: 0,
        unavailable_instances: 0,
    });
    assert!(
        persistence
            .execute_orphan_capture_erasure(&test_verified_request(request.clone())?)
            .await
            .is_err(),
        "old serving Active cannot release the capture fence"
    );
    super::activation::test_erasure_activation_transition(persistence, "paused", false).await?;
    super::activation::test_erasure_activation_transition(persistence, "draining", true).await?;
    request.activation =
        super::activation::test_erasure_activation_transition(persistence, "active", false).await?;
    let release = test_verified_request(request)?;
    let released = persistence
        .execute_orphan_capture_erasure_inner(&release)
        .await?;
    assert_eq!(released.state, "complete");
    assert!(!released.capture_upload_fenced);
    assert!(
        !persistence
            .execute_orphan_capture_erasure_inner(&release)
            .await?
            .capture_upload_fenced
    );
    let released_audit =
        super::orphan_capture_erasure_audit::snapshot(&mut *persistence.pool().acquire().await?)
            .await?;
    assert_eq!(released_audit.released_operations, 1);
    assert!(released_audit.unfenced());
    assert_eq!(
        sqlx::query_scalar::<_, String>(
            "SELECT summary FROM episodes WHERE account_id=$1 AND id=1"
        )
        .bind(ACCOUNT)
        .fetch_one(persistence.pool())
        .await?,
        "unchanged fixture text"
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM screenshots WHERE account_id=$1")
            .bind(ACCOUNT)
            .fetch_one(persistence.pool())
            .await?,
        1
    );
    sqlx::query("DELETE FROM accounts WHERE id=$1")
        .bind(ACCOUNT)
        .execute(persistence.pool())
        .await?;
    Ok(())
}
