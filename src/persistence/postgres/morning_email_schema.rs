//! Additive ADR-0045 companion schema. Installation belongs to the explicit
//! migrator; serving only verifies the exact installed contract and catalog.
//! The existing v26 base and v27 activation markers/receipts are not rewritten.

use sha2::{Digest, Sha256};
use sqlx::{PgConnection, Row};

use super::{current_schema_relation_exists, PostgresPersistence};
use crate::error::{EnclaveError, Result};

const INSTALL_SQL: &str = include_str!("../../../migrations/0028_morning_email.sql");
const TABLES: &[&str] = &[
    "morning_email_schedules",
    "morning_email_deliveries",
    "morning_email_sources",
];

const TRIGGERS: &[&str] = &[
    "kioku_morning_email_legacy_fence",
    "kioku_morning_email_legacy_enqueue",
    "kioku_morning_email_memory_delete",
    "kioku_morning_email_recipient_change",
];

fn contract_digest() -> String {
    format!("{:x}", Sha256::digest(INSTALL_SQL.as_bytes()))
}

async fn catalog_digest(connection: &mut PgConnection) -> Result<String> {
    let present: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace \
         WHERE n.nspname=current_schema() AND c.relname=ANY($1) AND c.relkind='r'",
    )
    .bind(TABLES)
    .fetch_one(&mut *connection)
    .await?;
    if present != TABLES.len() as i64 {
        return Err(EnclaveError::Config(
            "morning email schema is incomplete".into(),
        ));
    }
    let catalog: String = sqlx::query_scalar(
        "SELECT jsonb_agg(jsonb_build_object('table',c.relname, \
           'columns',(SELECT jsonb_agg(jsonb_build_array(a.attname,format_type(a.atttypid,a.atttypmod), \
              a.attnotnull,pg_get_expr(d.adbin,d.adrelid)) ORDER BY a.attnum) \
              FROM pg_attribute a LEFT JOIN pg_attrdef d ON d.adrelid=a.attrelid AND d.adnum=a.attnum \
              WHERE a.attrelid=c.oid AND a.attnum>0 AND NOT a.attisdropped), \
           'constraints',(SELECT jsonb_agg(jsonb_build_array(k.conname,pg_get_constraintdef(k.oid),k.convalidated) \
              ORDER BY k.conname) FROM pg_constraint k WHERE k.conrelid=c.oid), \
           'indexes',(SELECT jsonb_agg(pg_get_indexdef(i.indexrelid) ORDER BY pg_get_indexdef(i.indexrelid)) \
              FROM pg_index i WHERE i.indrelid=c.oid)) ORDER BY c.relname)::text \
         FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace \
         WHERE n.nspname=current_schema() AND c.relname=ANY($1)",
    )
    .bind(TABLES)
    .fetch_one(&mut *connection)
    .await?;
    let functions: Option<String> = sqlx::query_scalar(
        "SELECT jsonb_agg(pg_get_functiondef(p.oid) ORDER BY p.proname)::text FROM pg_proc p \
         JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname=current_schema() AND p.proname=ANY($1) \
         HAVING count(*)=4")
        .bind(TRIGGERS).fetch_optional(&mut *connection).await?.flatten();
    let triggers: Option<String> = sqlx::query_scalar(
        "SELECT jsonb_agg(jsonb_build_array(pg_get_triggerdef(t.oid),t.tgenabled) ORDER BY t.tgname)::text \
         FROM pg_trigger t JOIN pg_class c ON c.oid=t.tgrelid JOIN pg_namespace n ON n.oid=c.relnamespace \
         WHERE n.nspname=current_schema() AND t.tgname=ANY($1) HAVING count(*)=4")
        .bind(TRIGGERS).fetch_optional(&mut *connection).await?.flatten();
    let (Some(functions), Some(triggers)) = (functions, triggers) else {
        return Err(EnclaveError::Config(
            "morning email delivery/deletion guards are missing".into(),
        ));
    };
    let mut digest = Sha256::new();
    for item in [catalog, functions, triggers] {
        digest.update(item.as_bytes());
        digest.update([0]);
    }
    Ok(format!("{:x}", digest.finalize()))
}

pub(super) async fn verify(connection: &mut PgConnection) -> Result<()> {
    if !current_schema_relation_exists(connection, "morning_email_schema").await? {
        return Err(EnclaveError::Config(
            "morning email schema must be installed by the reviewed migrator".into(),
        ));
    }
    let row = sqlx::query(
        "SELECT version,contract_sha256,catalog_sha256 FROM morning_email_schema WHERE singleton=true",
    )
    .fetch_optional(&mut *connection)
    .await?
    .ok_or_else(|| EnclaveError::Config("morning email schema receipt is missing".into()))?;
    if row.try_get::<i64, _>("version")? != 28
        || row.try_get::<String, _>("contract_sha256")? != contract_digest()
        || row.try_get::<String, _>("catalog_sha256")? != catalog_digest(connection).await?
    {
        return Err(EnclaveError::Config(
            "morning email schema receipt does not match".into(),
        ));
    }
    Ok(())
}

impl PostgresPersistence {
    pub(crate) async fn verify_morning_email_schema(&self) -> Result<()> {
        verify(&mut *self.pool().acquire().await?).await
    }

    pub(crate) async fn install_morning_email_schema(&self) -> Result<()> {
        self.verify_schema().await?;
        let mut transaction = self.pool().begin().await?;
        sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended('kioku:morning-email:v28',0))")
            .execute(&mut *transaction)
            .await?;
        sqlx::query("SET LOCAL lock_timeout='5s'")
            .execute(&mut *transaction)
            .await?;
        if current_schema_relation_exists(&mut transaction, "morning_email_schema").await? {
            verify(&mut transaction).await?;
            transaction.commit().await?;
            return Ok(());
        }
        for table in TABLES {
            if current_schema_relation_exists(&mut transaction, table).await? {
                return Err(EnclaveError::Config(
                    "unreceipted morning email schema exists".into(),
                ));
            }
        }
        // Freeze both old claim creation and provider-send admission across the
        // migration's quiescence check and permanent legacy-claim trigger.
        sqlx::query("LOCK TABLE email_deliveries, email_send_fences, episode_email_preferences IN EXCLUSIVE MODE")
            .execute(&mut *transaction).await?;
        sqlx::raw_sql(INSTALL_SQL)
            .execute(&mut *transaction)
            .await?;
        sqlx::query(
            "CREATE TABLE morning_email_schema (singleton boolean PRIMARY KEY CHECK(singleton), \
            version bigint NOT NULL CHECK(version=28), contract_sha256 text NOT NULL, \
            catalog_sha256 text NOT NULL, installed_at timestamptz NOT NULL DEFAULT now())",
        )
        .execute(&mut *transaction)
        .await?;
        let catalog = catalog_digest(&mut transaction).await?;
        sqlx::query("INSERT INTO morning_email_schema(singleton,version,contract_sha256,catalog_sha256) VALUES(true,28,$1,$2)")
            .bind(contract_digest()).bind(catalog).execute(&mut *transaction).await?;
        transaction.commit().await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn populated_cutover_preserves_coverage_and_refuses_legacy_sends() {
        let Some(fixture) = super::super::tests::test_persistence().await else {
            return;
        };
        let repo = &fixture.persistence;
        let pool = repo.pool();
        // Restore only this disposable fixture to the real predecessor catalog.
        // The installer itself must migrate populated legacy rows atomically.
        sqlx::raw_sql(
            "DROP FUNCTION kioku_morning_email_legacy_fence() CASCADE; \
             DROP FUNCTION kioku_morning_email_legacy_enqueue() CASCADE; \
             DROP FUNCTION kioku_morning_email_memory_delete() CASCADE; \
             DROP FUNCTION kioku_morning_email_recipient_change() CASCADE; \
             DROP TABLE morning_email_sources,morning_email_deliveries,morning_email_schedules,morning_email_schema;",
        )
        .execute(pool)
        .await
        .unwrap();
        repo.verify_schema().await.unwrap();
        assert!(repo.verify_morning_email_schema().await.is_err());
        let base_marker: String = sqlx::query_scalar(
            "SELECT to_jsonb(s)::text FROM persistence_schema s WHERE singleton=true",
        )
        .fetch_one(pool)
        .await
        .unwrap();
        sqlx::raw_sql(
            "INSERT INTO accounts(id,email,primary_provider,primary_subject) VALUES \
                ('cutover-owner','cutover@example.invalid','google','cutover-owner'), \
                ('cutover-disabled','disabled@example.invalid','google','cutover-disabled'); \
             INSERT INTO episode_email_preferences(account_id,enabled,include_content) VALUES \
                ('cutover-owner',true,true),('cutover-disabled',false,false); \
             INSERT INTO screenshots(account_id,id,captured_at,ocr_text,source_key) \
                SELECT a.id,n,clock_timestamp()-interval '2 days','synthetic cutover evidence','shot-'||n \
                FROM accounts a CROSS JOIN generate_series(1,6) n; \
             INSERT INTO episodes(account_id,id,started_at,ended_at,title,summary,finalized_at,finalization_status) \
                SELECT account_id,id,captured_at-interval '1 hour',captured_at,'Synthetic memory','summary',clock_timestamp(),'complete' \
                FROM screenshots; \
             INSERT INTO episode_members(account_id,episode_id,record_type,record_id) \
                SELECT account_id,id,'screenshot',id FROM screenshots; \
             INSERT INTO email_deliveries(account_id,episode_id,delivery_version,delivery_id,include_content,state,attempt_count) VALUES \
                ('cutover-owner',1,1,'pending',true,'pending',0), \
                ('cutover-owner',2,1,'delivered',true,'delivered',1), \
                ('cutover-owner',2,2,'duplicate-pending',false,'pending',0), \
                ('cutover-owner',3,1,'ambiguous',false,'ambiguous',1), \
                ('cutover-owner',4,1,'attempted-retry',true,'retry_wait',1), \
                ('cutover-disabled',1,1,'disabled-pending',false,'pending',0);",
        )
        .execute(pool)
        .await
        .unwrap();
        let delivered_receipt: String = sqlx::query_scalar(
            "SELECT to_jsonb(d)::text FROM email_deliveries d WHERE delivery_id='delivered'",
        )
        .fetch_one(pool)
        .await
        .unwrap();
        sqlx::query("UPDATE email_deliveries SET state='processing' WHERE delivery_id='pending'")
            .execute(pool)
            .await
            .unwrap();
        assert!(repo.install_morning_email_schema().await.is_err());
        assert!(repo.verify_morning_email_schema().await.is_err());
        sqlx::raw_sql(
            "UPDATE email_deliveries SET state='pending' WHERE delivery_id='pending'; \
             INSERT INTO email_send_fences(account_id,delivery_id,claim_id,lease_expires_at,recipient_email,include_content) \
                VALUES('cutover-owner','pending','legacy-send',clock_timestamp()+interval '1 minute','cutover@example.invalid',true);",
        )
        .execute(pool)
        .await
        .unwrap();
        assert!(repo.install_morning_email_schema().await.is_err());
        assert!(repo.verify_morning_email_schema().await.is_err());
        sqlx::query("DELETE FROM email_send_fences WHERE claim_id='legacy-send'")
            .execute(pool)
            .await
            .unwrap();

        repo.install_morning_email_schema().await.unwrap();
        repo.install_morning_email_schema().await.unwrap();
        repo.verify_schema().await.unwrap();
        repo.verify_morning_email_schema().await.unwrap();
        let transferred = sqlx::query_as::<_, (String, i64, String, bool, Option<String>)>(
            "SELECT account_id,record_id,state,include_content,delivery_id FROM morning_email_sources \
             ORDER BY account_id,record_id",
        )
        .fetch_all(pool)
        .await
        .unwrap();
        assert_eq!(
            transferred,
            vec![
                (
                    "cutover-disabled".into(),
                    1,
                    "cancelled".into(),
                    false,
                    None
                ),
                ("cutover-owner".into(), 1, "pending".into(), true, None),
                (
                    "cutover-owner".into(),
                    2,
                    "delivered".into(),
                    true,
                    Some("delivered".into())
                ),
                (
                    "cutover-owner".into(),
                    3,
                    "ambiguous".into(),
                    false,
                    Some("ambiguous".into())
                ),
                (
                    "cutover-owner".into(),
                    4,
                    "ambiguous".into(),
                    true,
                    Some("attempted-retry".into())
                ),
            ],
            "only previously queued evidence transfers, preserving consent and no-resend coverage"
        );
        assert_eq!(
            sqlx::query_scalar::<_, i64>(
                "SELECT count(*) FROM morning_email_schedules WHERE timezone IS NULL AND next_due_at IS NULL",
            )
            .fetch_one(pool)
            .await
            .unwrap(),
            2,
            "cutover never invents an account timezone"
        );
        assert_eq!(
            sqlx::query_scalar::<_, String>(
                "SELECT to_jsonb(d)::text FROM email_deliveries d WHERE delivery_id='delivered'",
            )
            .fetch_one(pool)
            .await
            .unwrap(),
            delivered_receipt
        );
        assert_eq!(
            sqlx::query_scalar::<_, String>(
                "SELECT to_jsonb(s)::text FROM persistence_schema s WHERE singleton=true",
            )
            .fetch_one(pool)
            .await
            .unwrap(),
            base_marker
        );
        assert_eq!(
            sqlx::query_scalar::<_, i64>(
                "SELECT count(*) FROM email_deliveries WHERE state='cancelled' AND error_code='morning_digest_cutover'",
            )
            .fetch_one(pool)
            .await
            .unwrap(),
            4
        );
        assert!(sqlx::query(
            "UPDATE email_deliveries SET state='processing' WHERE delivery_id='pending'"
        )
        .execute(pool)
        .await
        .is_err());
        sqlx::raw_sql(
            "INSERT INTO email_deliveries(account_id,episode_id,delivery_version,delivery_id,include_content,state) VALUES \
                ('cutover-owner',6,1,'late-owner',true,'pending'), \
                ('cutover-disabled',2,1,'late-disabled',false,'pending');",
        )
        .execute(pool)
        .await
        .unwrap();
        assert_eq!(
            sqlx::query_as::<_, (String, i64)>(
                "SELECT account_id,record_id FROM morning_email_sources WHERE record_id=6 OR (account_id='cutover-disabled' AND record_id=2)",
            )
            .fetch_all(pool)
            .await
            .unwrap(),
            vec![("cutover-owner".into(), 6)]
        );
        let mut transaction = pool.begin().await.unwrap();
        assert!(
            super::super::schema_release::test_frozen_v0_9_16_verify_schema(&mut transaction)
                .await
                .is_err()
        );
        sqlx::query("DROP TABLE morning_email_schema")
            .execute(&mut *transaction)
            .await
            .unwrap();
        assert!(
            verify(&mut transaction).await.is_err(),
            "missing mandatory receipt is never ready"
        );
        transaction.rollback().await.unwrap();
        repo.verify_morning_email_schema().await.unwrap();
        pool.close().await;
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
