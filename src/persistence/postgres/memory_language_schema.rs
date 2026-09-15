//! Direct ADR-0049 memory-language companion, installed only by the explicit
//! v35 migrator. Serving verifies immutable SQL and the owned catalog objects:
//! the `capture_events.locale_id` column, its BCP-47 check, the partial
//! newest-stamp index, and the receipt.
use super::{current_schema_relation_exists, PostgresPersistence};
use crate::error::{EnclaveError, Result};
use sha2::{Digest, Sha256};
use sqlx::{PgConnection, Row};

const INSTALL_SQL: &str = include_str!("../../../migrations/0035_memory_language.sql");
const RECEIPT_TABLE: &str = "authoring_language_schema";
const COLUMN_CONSTRAINT: &str = "capture_events_locale_id_bcp47";
const LOCALE_INDEX: &str = "capture_events_locale_idx";

fn contract_digest() -> String {
    format!("{:x}", Sha256::digest(INSTALL_SQL.as_bytes()))
}

async fn locale_column_exists(connection: &mut PgConnection) -> Result<bool> {
    Ok(sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM pg_attribute WHERE attrelid='capture_events'::regclass AND attname='locale_id' AND NOT attisdropped)")
        .fetch_one(connection).await?)
}

async fn catalog_digest(connection: &mut PgConnection) -> Result<String> {
    let column: Option<String> = sqlx::query_scalar("SELECT jsonb_build_array(format_type(a.atttypid,a.atttypmod),a.attnotnull,a.attidentity,a.attgenerated,pg_get_expr(d.adbin,d.adrelid))::text FROM pg_attribute a LEFT JOIN pg_attrdef d ON d.adrelid=a.attrelid AND d.adnum=a.attnum WHERE a.attrelid='capture_events'::regclass AND a.attname='locale_id' AND NOT a.attisdropped")
        .fetch_optional(&mut *connection).await?;
    let constraint: Option<String> = sqlx::query_scalar("SELECT jsonb_build_array(pg_get_constraintdef(oid),convalidated)::text FROM pg_constraint WHERE conrelid='capture_events'::regclass AND conname=$1")
        .bind(COLUMN_CONSTRAINT)
        .fetch_optional(&mut *connection).await?;
    let index: Option<String> = sqlx::query_scalar("SELECT jsonb_build_array(pg_get_indexdef(i.indexrelid),i.indisvalid,i.indisready,i.indislive)::text FROM pg_index i JOIN pg_class c ON c.oid=i.indexrelid JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname=current_schema() AND c.relname=$1 AND i.indrelid='capture_events'::regclass")
        .bind(LOCALE_INDEX)
        .fetch_optional(&mut *connection).await?;
    let receipt: Option<String> = sqlx::query_scalar(
        "SELECT jsonb_build_object('kind',c.relkind,'persistence',c.relpersistence, \
           'rls',c.relrowsecurity,'force_rls',c.relforcerowsecurity, \
           'columns',(SELECT jsonb_agg(jsonb_build_array(a.attname,format_type(a.atttypid,a.atttypmod), \
              a.attnotnull,pg_get_expr(d.adbin,d.adrelid)) ORDER BY a.attnum) \
              FROM pg_attribute a LEFT JOIN pg_attrdef d ON d.adrelid=a.attrelid AND d.adnum=a.attnum \
              WHERE a.attrelid=c.oid AND a.attnum>0 AND NOT a.attisdropped), \
           'constraints',(SELECT jsonb_agg(jsonb_build_array(k.conname,pg_get_constraintdef(k.oid), \
              k.convalidated,k.condeferrable,k.condeferred) ORDER BY k.conname) \
              FROM pg_constraint k WHERE k.conrelid=c.oid), \
           'triggers',(SELECT jsonb_agg(jsonb_build_array(pg_get_triggerdef(t.oid),t.tgenabled) \
              ORDER BY t.tgname) FROM pg_trigger t WHERE t.tgrelid=c.oid AND NOT t.tgisinternal))::text \
         FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace \
         WHERE n.nspname=current_schema() AND c.relname=$1 AND c.relkind='r'",
    )
    .bind(RECEIPT_TABLE)
    .fetch_optional(connection)
    .await?;
    match (column, constraint, index, receipt) {
        (Some(column), Some(constraint), Some(index), Some(receipt)) => Ok(format!(
            "{:x}",
            Sha256::digest(format!("{column}\0{constraint}\0{index}\0{receipt}"))
        )),
        _ => Err(EnclaveError::Config(
            "memory language schema is incomplete".into(),
        )),
    }
}

async fn verify(connection: &mut PgConnection) -> Result<()> {
    if !current_schema_relation_exists(connection, RECEIPT_TABLE).await? {
        return Err(EnclaveError::Config(
            "memory language schema must be installed by the reviewed v35 migrator".into(),
        ));
    }
    let rows = sqlx::query(
        "SELECT singleton,version,contract_sha256,catalog_sha256 FROM authoring_language_schema",
    )
    .fetch_all(&mut *connection)
    .await?;
    let [row] = rows.as_slice() else {
        return Err(EnclaveError::Config(
            "memory language schema must have exactly one receipt".into(),
        ));
    };
    if !row.try_get::<bool, _>("singleton")?
        || row.try_get::<i64, _>("version")? != 35
        || row.try_get::<String, _>("contract_sha256")? != contract_digest()
        || row.try_get::<String, _>("catalog_sha256")? != catalog_digest(connection).await?
    {
        return Err(EnclaveError::Config(
            "memory language schema receipt does not match".into(),
        ));
    }
    Ok(())
}

impl PostgresPersistence {
    pub(crate) async fn verify_memory_language_schema(&self) -> Result<()> {
        verify(&mut *self.pool().acquire().await?).await
    }
    pub(crate) async fn install_memory_language_schema(&self) -> Result<()> {
        self.verify_schema().await?;
        self.verify_identity_presentation_schema().await?;
        let mut tx = self.pool().begin().await?;
        sqlx::query("SET LOCAL lock_timeout='5s'")
            .execute(&mut *tx)
            .await?;
        sqlx::query(
            "SELECT pg_advisory_xact_lock(hashtextextended('kioku:memory-language:v35',0))",
        )
        .execute(&mut *tx)
        .await?;
        if current_schema_relation_exists(&mut tx, RECEIPT_TABLE).await? {
            verify(&mut tx).await?;
        } else {
            if locale_column_exists(&mut tx).await? {
                return Err(EnclaveError::Config(
                    "unreceipted capture locale column exists".into(),
                ));
            }
            sqlx::raw_sql(INSTALL_SQL).execute(&mut *tx).await?;
            let catalog = catalog_digest(&mut tx).await?;
            sqlx::query("INSERT INTO authoring_language_schema(singleton,version,contract_sha256,catalog_sha256) VALUES(true,35,$1,$2)").bind(contract_digest()).bind(catalog).execute(&mut *tx).await?;
            verify(&mut tx).await?;
        }
        tx.commit().await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use sqlx::Row;

    #[tokio::test]
    async fn memory_language_receipt_preserves_prior_state_and_rejects_owned_drift() {
        let Some(fixture) = super::super::tests::test_persistence().await else {
            return;
        };
        let repo = &fixture.persistence;
        let prior_sql = "SELECT jsonb_build_array((SELECT to_jsonb(s) FROM persistence_schema s),(SELECT to_jsonb(s) FROM identity_fusion_schema s),(SELECT to_jsonb(s) FROM identity_presentation_schema s))::text";
        let before: String = sqlx::query_scalar(prior_sql)
            .fetch_one(repo.pool())
            .await
            .unwrap();
        repo.install_memory_language_schema().await.unwrap();
        repo.verify_memory_language_schema().await.unwrap();
        repo.verify_schema().await.unwrap();
        repo.verify_identity_presentation_schema().await.unwrap();
        assert_eq!(
            sqlx::query_scalar::<_, String>(prior_sql)
                .fetch_one(repo.pool())
                .await
                .unwrap(),
            before,
            "memory language installation must preserve all prior schema receipts"
        );
        // Pre-companion rows stay NULL; the check admits only BCP-47 syntax.
        sqlx::raw_sql("INSERT INTO accounts(id,email,primary_provider,primary_subject) VALUES('language-schema','synthetic@example.test','google','language-schema'); \
             INSERT INTO capture_sessions(account_id,id,device_id,install_id,started_at,last_event_at,ended_at,schema_version,created_at) VALUES('language-schema','session','device','install',now(),now(),now(),2,now()); \
             INSERT INTO capture_streams(account_id,id,capture_session_id,device_id,stream_kind) VALUES('language-schema','stream','session','device','ios_mic'); \
             INSERT INTO capture_events(account_id,event_id,device_id,install_id,capture_session_id,stream_id,stream_kind,sequence,source_wall_at,source_monotonic_ns,started_at,ended_at,timezone_id,utc_offset_minutes,clock_uncertainty_ms,asset_id,manifest_digest,media_disposition,received_at) \
             VALUES('language-schema','legacy','device','install','session','stream','ios_mic',0,now(),'0',now(),now()+interval '4 seconds','UTC',0,0,'asset',repeat('a',64),'canonical',now());")
            .execute(repo.pool()).await.unwrap();
        let legacy = sqlx::query("SELECT locale_id FROM capture_events WHERE account_id='language-schema' AND event_id='legacy'")
            .fetch_one(repo.pool()).await.unwrap();
        assert!(
            legacy.get::<Option<String>, _>("locale_id").is_none(),
            "a pre-companion capture event carries no language"
        );
        for rejected in [
            "",
            "e",
            "en_US",
            "english language",
            "en-",
            "-en",
            "en-abcdefgh-abcdefgh-abcdefgh-abcdefgh",
        ] {
            assert!(
                sqlx::query(
                    "UPDATE capture_events SET locale_id=$1 WHERE account_id='language-schema'"
                )
                .bind(rejected)
                .execute(repo.pool())
                .await
                .is_err(),
                "locale {rejected:?} must be refused by the BCP-47 check"
            );
        }
        for accepted in ["en", "fr-CA", "zh-Hant-TW", "pt-BR"] {
            sqlx::query(
                "UPDATE capture_events SET locale_id=$1 WHERE account_id='language-schema'",
            )
            .bind(accepted)
            .execute(repo.pool())
            .await
            .unwrap();
        }
        for (change, restore) in [
            ("ALTER TABLE capture_events ALTER COLUMN locale_id SET DEFAULT 'en'", "ALTER TABLE capture_events ALTER COLUMN locale_id DROP DEFAULT"),
            ("ALTER TABLE capture_events DROP CONSTRAINT capture_events_locale_id_bcp47", "ALTER TABLE capture_events ADD CONSTRAINT capture_events_locale_id_bcp47 CHECK (locale_id IS NULL OR (octet_length(locale_id)<=35 AND locale_id ~ '^[A-Za-z]{2,8}(-[A-Za-z0-9]{1,8})*$'))"),
            ("ALTER TABLE authoring_language_schema ADD COLUMN unexpected text", "ALTER TABLE authoring_language_schema DROP COLUMN unexpected"),
            ("DROP INDEX capture_events_locale_idx", "CREATE INDEX capture_events_locale_idx ON capture_events (account_id, started_at DESC, event_id DESC) WHERE locale_id IS NOT NULL"),
        ] {
            sqlx::raw_sql(change).execute(repo.pool()).await.unwrap();
            assert!(repo.verify_memory_language_schema().await.is_err(),
                "memory language readiness must reject owned catalog drift: {change}");
            assert!(repo.install_memory_language_schema().await.is_err(),
                "an installed memory language companion must not accept altered owned schema");
            sqlx::raw_sql(restore).execute(repo.pool()).await.unwrap();
            repo.verify_memory_language_schema().await.unwrap();
        }
        sqlx::query("DELETE FROM accounts WHERE id='language-schema'")
            .execute(repo.pool())
            .await
            .unwrap();
        sqlx::query("DELETE FROM authoring_language_schema")
            .execute(repo.pool())
            .await
            .unwrap();
        assert!(
            repo.verify_memory_language_schema().await.is_err(),
            "memory language readiness must require its exact singleton receipt"
        );
        sqlx::raw_sql("DROP INDEX capture_events_locale_idx; ALTER TABLE capture_events DROP CONSTRAINT capture_events_locale_id_bcp47; ALTER TABLE capture_events DROP COLUMN locale_id; DROP TABLE authoring_language_schema;")
            .execute(repo.pool()).await.unwrap();
        assert!(
            repo.verify_memory_language_schema().await.is_err(),
            "a missing companion must not verify"
        );
        repo.install_memory_language_schema().await.unwrap();
        repo.verify_memory_language_schema().await.unwrap();
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
