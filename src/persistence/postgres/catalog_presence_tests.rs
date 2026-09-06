//! Cross-connection DDL visibility on a reused prepared catalog probe.

use sqlx::{Acquire as _, Connection as _};

use super::{current_schema_relation_exists, PostgresPersistence};
use crate::error::Result;

async fn catalog_visibility(persistence: &PostgresPersistence) -> Result<()> {
    let mut observer = persistence.pool().acquire().await?;
    let observer_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut *observer)
        .await?;
    for name in [
        "persistence_feature_activation_contracts",
        "orphan_capture_erasure_contract",
    ] {
        // Exercise reuse beyond both initial and generic-plan executions.
        for _ in 0..6 {
            assert!(!current_schema_relation_exists(&mut observer, name).await?);
        }
        let mut installer = persistence.pool().begin().await?;
        sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,0))")
            .bind(super::activation::RELEASE_LOCK)
            .execute(&mut *installer)
            .await?;
        sqlx::query(sqlx::AssertSqlSafe(format!(
            "CREATE TABLE {name}(id bigint)"
        )))
        .execute(&mut *installer)
        .await?;
        let writer = tokio::spawn(async move {
            let mut transaction = observer.begin().await?;
            sqlx::query("SELECT pg_advisory_xact_lock_shared(hashtextextended($1,0))")
                .bind(super::activation::RELEASE_LOCK)
                .execute(&mut *transaction)
                .await?;
            // This must be the first command after the lock wake. A different
            // intervening catalog probe can mask the old name-resolution bug.
            assert!(current_schema_relation_exists(&mut transaction, name).await?);
            transaction.commit().await?;
            Ok::<_, crate::error::EnclaveError>(observer)
        });
        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            loop {
                if sqlx::query_scalar::<_, bool>(
                    "SELECT EXISTS(SELECT 1 FROM pg_catalog.pg_locks \
                     WHERE pid=$1 AND locktype='advisory' AND NOT granted)",
                )
                .bind(observer_pid)
                .fetch_one(&mut *installer)
                .await?
                {
                    return Ok::<_, crate::error::EnclaveError>(());
                }
                tokio::time::sleep(std::time::Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("the observer must actually wait behind installation")?;
        installer.commit().await?;
        observer = writer.await.expect("catalog observer must not panic")?;
        sqlx::query(sqlx::AssertSqlSafe(format!("DROP TABLE {name}")))
            .execute(persistence.pool())
            .await?;
        assert!(!current_schema_relation_exists(&mut observer, name).await?);

        // A wrong-kind relation is corruption, never the pre-install state.
        sqlx::query(sqlx::AssertSqlSafe(format!(
            "CREATE VIEW {name} AS SELECT 1::bigint AS id"
        )))
        .execute(persistence.pool())
        .await?;
        assert!(current_schema_relation_exists(&mut observer, name).await?);
        if name == "persistence_feature_activation_contracts" {
            assert!(super::activation::activation_contract_exists(&mut observer).await?);
            assert!(
                super::activation::verify_serving_activation_schema(&mut observer)
                    .await
                    .is_err()
            );
        } else {
            assert!(
                super::orphan_capture_erasure::verify_schema_if_installed(&mut observer)
                    .await
                    .is_err()
            );
        }
        sqlx::query(sqlx::AssertSqlSafe(format!("DROP VIEW {name}")))
            .execute(persistence.pool())
            .await?;
        assert!(!current_schema_relation_exists(&mut observer, name).await?);
    }
    Ok(())
}

#[tokio::test]
async fn postgres_catalog_presence_after_release_lock_contract() {
    use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
    use std::{str::FromStr as _, time::Duration};

    let required = std::env::var("KIOKU_REQUIRE_POSTGRES_CONTRACT").as_deref() == Ok("1");
    let Ok(database_url) = std::env::var("KIOKU_TEST_POSTGRES_URL") else {
        assert!(
            !required,
            "real catalog contract requires its disposable database URL"
        );
        return;
    };
    let _guard = super::POSTGRES_RELEASE_CONTRACT_MUTEX.lock().await;
    let mut base = sqlx::PgConnection::connect(&database_url)
        .await
        .expect("connect disposable catalog database");
    let schema = format!(
        "kioku_catalog_presence_{}_{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );
    sqlx::query(sqlx::AssertSqlSafe(format!("CREATE SCHEMA {schema}")))
        .execute(&mut base)
        .await
        .expect("create isolated catalog schema");
    let options = PgConnectOptions::from_str(&database_url)
        .unwrap()
        .options([("search_path", schema.clone())]);
    let pool = PgPoolOptions::new()
        .max_connections(2)
        .acquire_timeout(Duration::from_secs(5))
        .connect_with(options)
        .await
        .unwrap();
    let persistence = PostgresPersistence { pool: pool.clone() };
    let outcome = tokio::spawn(async move { catalog_visibility(&persistence).await }).await;
    pool.close().await;
    sqlx::query(sqlx::AssertSqlSafe(format!("DROP SCHEMA {schema} CASCADE")))
        .execute(&mut base)
        .await
        .expect("remove isolated catalog schema");
    base.close().await.unwrap();
    outcome
        .expect("catalog contract must not panic")
        .expect("catalog visibility contract");
}
