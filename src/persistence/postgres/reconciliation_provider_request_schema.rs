//! Direct organizer provider-request companion, installed only by the explicit
//! v36 migrator. Serving verifies immutable SQL and the owned catalog objects:
//! the frozen-request relation with its job foreign key and the receipt.
use super::{current_schema_relation_exists, PostgresPersistence};
use crate::error::{EnclaveError, Result};
use sha2::{Digest, Sha256};
use sqlx::{PgConnection, Row};

const INSTALL_SQL: &str =
    include_str!("../../../migrations/0036_reconciliation_provider_request.sql");
const REQUEST_TABLE: &str = "reconciliation_provider_requests";
const RECEIPT_TABLE: &str = "reconciliation_provider_request_schema";

fn contract_digest() -> String {
    format!("{:x}", Sha256::digest(INSTALL_SQL.as_bytes()))
}

async fn owned_relation_digest(connection: &mut PgConnection, table: &str) -> Result<String> {
    let relation: Option<String> = sqlx::query_scalar(
        "SELECT jsonb_build_object('kind',c.relkind,'persistence',c.relpersistence, \
           'rls',c.relrowsecurity,'force_rls',c.relforcerowsecurity, \
           'columns',(SELECT jsonb_agg(jsonb_build_array(a.attname,format_type(a.atttypid,a.atttypmod), \
              a.attnotnull,pg_get_expr(d.adbin,d.adrelid)) ORDER BY a.attnum) \
              FROM pg_attribute a LEFT JOIN pg_attrdef d ON d.adrelid=a.attrelid AND d.adnum=a.attnum \
              WHERE a.attrelid=c.oid AND a.attnum>0 AND NOT a.attisdropped), \
           'constraints',(SELECT jsonb_agg(jsonb_build_array(k.conname,pg_get_constraintdef(k.oid), \
              k.convalidated,k.condeferrable,k.condeferred) ORDER BY k.conname) \
              FROM pg_constraint k WHERE k.conrelid=c.oid), \
           'indexes',(SELECT jsonb_agg(jsonb_build_array(pg_get_indexdef(i.indexrelid),i.indisvalid, \
              i.indisready,i.indislive) ORDER BY pg_get_indexdef(i.indexrelid)) \
              FROM pg_index i WHERE i.indrelid=c.oid), \
           'triggers',(SELECT jsonb_agg(jsonb_build_array(pg_get_triggerdef(t.oid),t.tgenabled) \
              ORDER BY t.tgname) FROM pg_trigger t WHERE t.tgrelid=c.oid AND NOT t.tgisinternal))::text \
         FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace \
         WHERE n.nspname=current_schema() AND c.relname=$1 AND c.relkind='r'",
    )
    .bind(table)
    .fetch_optional(connection)
    .await?;
    relation.ok_or_else(|| {
        EnclaveError::Config("reconciliation provider request schema is incomplete".into())
    })
}

async fn catalog_digest(connection: &mut PgConnection) -> Result<String> {
    let requests = owned_relation_digest(&mut *connection, REQUEST_TABLE).await?;
    let receipt = owned_relation_digest(connection, RECEIPT_TABLE).await?;
    Ok(format!(
        "{:x}",
        Sha256::digest(format!("{requests}\0{receipt}"))
    ))
}

async fn verify(connection: &mut PgConnection) -> Result<()> {
    if !current_schema_relation_exists(connection, RECEIPT_TABLE).await? {
        return Err(EnclaveError::Config(
            "reconciliation provider request schema must be installed by the reviewed v36 migrator"
                .into(),
        ));
    }
    let rows = sqlx::query(
        "SELECT singleton,version,contract_sha256,catalog_sha256 \
           FROM reconciliation_provider_request_schema",
    )
    .fetch_all(&mut *connection)
    .await?;
    let [row] = rows.as_slice() else {
        return Err(EnclaveError::Config(
            "reconciliation provider request schema must have exactly one receipt".into(),
        ));
    };
    if !row.try_get::<bool, _>("singleton")?
        || row.try_get::<i64, _>("version")? != 36
        || row.try_get::<String, _>("contract_sha256")? != contract_digest()
        || row.try_get::<String, _>("catalog_sha256")? != catalog_digest(connection).await?
    {
        return Err(EnclaveError::Config(
            "reconciliation provider request schema receipt does not match".into(),
        ));
    }
    Ok(())
}

impl PostgresPersistence {
    pub(crate) async fn verify_reconciliation_provider_request_schema(&self) -> Result<()> {
        verify(&mut *self.pool().acquire().await?).await
    }
    pub(crate) async fn install_reconciliation_provider_request_schema(&self) -> Result<()> {
        self.verify_schema().await?;
        self.verify_memory_language_schema().await?;
        let mut tx = self.pool().begin().await?;
        sqlx::query("SET LOCAL lock_timeout='5s'")
            .execute(&mut *tx)
            .await?;
        sqlx::query(
            "SELECT pg_advisory_xact_lock(hashtextextended('kioku:reconciliation-provider-request:v36',0))",
        )
        .execute(&mut *tx)
        .await?;
        if current_schema_relation_exists(&mut tx, RECEIPT_TABLE).await? {
            verify(&mut tx).await?;
        } else {
            if current_schema_relation_exists(&mut tx, REQUEST_TABLE).await? {
                return Err(EnclaveError::Config(
                    "unreceipted reconciliation provider request relation exists".into(),
                ));
            }
            sqlx::raw_sql(INSTALL_SQL).execute(&mut *tx).await?;
            let catalog = catalog_digest(&mut tx).await?;
            sqlx::query("INSERT INTO reconciliation_provider_request_schema(singleton,version,contract_sha256,catalog_sha256) VALUES(true,36,$1,$2)").bind(contract_digest()).bind(catalog).execute(&mut *tx).await?;
            verify(&mut tx).await?;
        }
        tx.commit().await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    #[tokio::test]
    async fn reconciliation_provider_request_receipt_preserves_prior_state_and_rejects_owned_drift()
    {
        let Some(fixture) = super::super::tests::test_persistence().await else {
            return;
        };
        let repo = &fixture.persistence;
        let prior_sql = "SELECT jsonb_build_array((SELECT to_jsonb(s) FROM persistence_schema s),(SELECT to_jsonb(s) FROM identity_presentation_schema s),(SELECT to_jsonb(s) FROM authoring_language_schema s))::text";
        let before: String = sqlx::query_scalar(prior_sql)
            .fetch_one(repo.pool())
            .await
            .unwrap();
        repo.install_reconciliation_provider_request_schema()
            .await
            .unwrap();
        repo.verify_reconciliation_provider_request_schema()
            .await
            .unwrap();
        repo.verify_schema().await.unwrap();
        repo.verify_memory_language_schema().await.unwrap();
        assert_eq!(
            sqlx::query_scalar::<_, String>(prior_sql)
                .fetch_one(repo.pool())
                .await
                .unwrap(),
            before,
            "provider request installation must preserve all prior schema receipts"
        );
        // A frozen request needs its job: the foreign key refuses an orphan and
        // removes the request when the job leaves.
        assert!(
            sqlx::query("INSERT INTO reconciliation_provider_requests(account_id,source_fingerprint,provider_attempt_identity,provider_request,provider_request_sha256) VALUES('provider-request-schema',repeat('a',32)::bytea,repeat('b',32)::bytea,'{}',repeat('c',32)::bytea)")
                .execute(repo.pool())
                .await
                .is_err(),
            "a frozen request without its reconciliation job must be refused"
        );
        sqlx::raw_sql("INSERT INTO accounts(id,email,primary_provider,primary_subject) VALUES('provider-request-schema','synthetic@example.test','google','provider-request-schema'); \
             INSERT INTO memory_reconciliation_jobs(account_id,source_fingerprint,topology_fingerprint,predecessor_episode_ids,cohort_started_at,cohort_ended_at,state) VALUES('provider-request-schema',repeat('a',32)::bytea,repeat('t',32)::bytea,ARRAY[1]::bigint[],now(),now(),'pending'); \
             INSERT INTO reconciliation_provider_requests(account_id,source_fingerprint,provider_attempt_identity,provider_request,provider_request_sha256) VALUES('provider-request-schema',repeat('a',32)::bytea,repeat('b',32)::bytea,'{}',repeat('c',32)::bytea);")
            .execute(repo.pool()).await.unwrap();
        assert!(
            sqlx::query("UPDATE reconciliation_provider_requests SET provider_request='' WHERE account_id='provider-request-schema'")
                .execute(repo.pool())
                .await
                .is_err(),
            "an empty frozen request must be refused"
        );
        sqlx::query(
            "DELETE FROM memory_reconciliation_jobs WHERE account_id='provider-request-schema'",
        )
        .execute(repo.pool())
        .await
        .unwrap();
        assert_eq!(
            sqlx::query_scalar::<_, i64>(
                "SELECT count(*) FROM reconciliation_provider_requests WHERE account_id='provider-request-schema'"
            )
            .fetch_one(repo.pool())
            .await
            .unwrap(),
            0,
            "a frozen request must leave with its job"
        );
        for (change, restore) in [
            ("ALTER TABLE reconciliation_provider_requests ALTER COLUMN provider_request DROP NOT NULL", "ALTER TABLE reconciliation_provider_requests ALTER COLUMN provider_request SET NOT NULL"),
            ("ALTER TABLE reconciliation_provider_requests DROP CONSTRAINT reconciliation_provider_requests_job_fkey", "ALTER TABLE reconciliation_provider_requests ADD CONSTRAINT reconciliation_provider_requests_job_fkey FOREIGN KEY (account_id,source_fingerprint) REFERENCES memory_reconciliation_jobs(account_id,source_fingerprint) ON DELETE CASCADE"),
            ("ALTER TABLE reconciliation_provider_requests ADD COLUMN unexpected text", "ALTER TABLE reconciliation_provider_requests DROP COLUMN unexpected"),
            ("CREATE INDEX reconciliation_provider_requests_unexpected_idx ON reconciliation_provider_requests(frozen_at)", "DROP INDEX reconciliation_provider_requests_unexpected_idx"),
            ("ALTER TABLE reconciliation_provider_request_schema ADD COLUMN unexpected text", "ALTER TABLE reconciliation_provider_request_schema DROP COLUMN unexpected"),
        ] {
            sqlx::raw_sql(change).execute(repo.pool()).await.unwrap();
            assert!(repo.verify_reconciliation_provider_request_schema().await.is_err(),
                "provider request readiness must reject owned catalog drift: {change}");
            assert!(repo.install_reconciliation_provider_request_schema().await.is_err(),
                "an installed provider request companion must not accept altered owned schema");
            sqlx::raw_sql(restore).execute(repo.pool()).await.unwrap();
            repo.verify_reconciliation_provider_request_schema()
                .await
                .unwrap();
        }
        sqlx::query("DELETE FROM accounts WHERE id='provider-request-schema'")
            .execute(repo.pool())
            .await
            .unwrap();
        sqlx::query("DELETE FROM reconciliation_provider_request_schema")
            .execute(repo.pool())
            .await
            .unwrap();
        assert!(
            repo.verify_reconciliation_provider_request_schema()
                .await
                .is_err(),
            "provider request readiness must require its exact singleton receipt"
        );
        sqlx::raw_sql("DROP TABLE reconciliation_provider_request_schema;")
            .execute(repo.pool())
            .await
            .unwrap();
        assert!(
            repo.install_reconciliation_provider_request_schema()
                .await
                .is_err(),
            "an unreceipted preexisting request relation must not be adopted"
        );
        sqlx::raw_sql("DROP TABLE reconciliation_provider_requests;")
            .execute(repo.pool())
            .await
            .unwrap();
        assert!(
            repo.verify_reconciliation_provider_request_schema()
                .await
                .is_err(),
            "a missing companion must not verify"
        );
        repo.install_reconciliation_provider_request_schema()
            .await
            .unwrap();
        repo.verify_reconciliation_provider_request_schema()
            .await
            .unwrap();
        fixture.persistence.pool().close().await;
        sqlx::query(sqlx::AssertSqlSafe(format!(
            "DROP SCHEMA {} CASCADE",
            fixture.schema
        )))
        .execute(fixture.base.pool())
        .await
        .unwrap();
        fixture.base.pool().close().await;
    }
}
