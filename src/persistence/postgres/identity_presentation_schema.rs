//! Direct ADR-0048 identity-presentation companion, installed only by the explicit
//! v34 migrator. Serving verifies immutable SQL and the owned catalog objects.
use super::{current_schema_relation_exists, PostgresPersistence};
use crate::error::{EnclaveError, Result};
use sha2::{Digest, Sha256};
use sqlx::{PgConnection, Row};

const INSTALL_SQL: &str = include_str!("../../../migrations/0034_identity_presentation.sql");
const TABLES: &[&str] = &[
    "episode_identity_presentations",
    "identity_presentation_schema",
];

async fn refinalized_column_exists(connection: &mut PgConnection) -> Result<bool> {
    Ok(sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM pg_attribute WHERE attrelid='episodes'::regclass AND attname='identity_refinalized_at' AND NOT attisdropped)")
        .fetch_one(connection).await?)
}

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
            "identity presentation schema is incomplete".into(),
        ));
    }
    let tables: String = sqlx::query_scalar(
        "SELECT jsonb_agg(jsonb_build_object('table',c.relname, \
           'kind',c.relkind,'persistence',c.relpersistence,'rls',c.relrowsecurity,'force_rls',c.relforcerowsecurity, \
           'columns',(SELECT jsonb_agg(jsonb_build_array(a.attname,format_type(a.atttypid,a.atttypmod), \
              a.attnotnull,pg_get_expr(d.adbin,d.adrelid)) ORDER BY a.attnum) \
              FROM pg_attribute a LEFT JOIN pg_attrdef d ON d.adrelid=a.attrelid AND d.adnum=a.attnum \
              WHERE a.attrelid=c.oid AND a.attnum>0 AND NOT a.attisdropped), \
           'constraints',(SELECT jsonb_agg(jsonb_build_array(k.conname,pg_get_constraintdef(k.oid), \
              k.convalidated,k.condeferrable,k.condeferred) ORDER BY k.conname) \
              FROM pg_constraint k WHERE k.conrelid=c.oid), \
           'indexes',(SELECT jsonb_agg(jsonb_build_array(pg_get_indexdef(i.indexrelid),i.indisvalid,i.indisready) \
              ORDER BY pg_get_indexdef(i.indexrelid)) FROM pg_index i WHERE i.indrelid=c.oid), \
           'triggers',(SELECT jsonb_agg(jsonb_build_array(pg_get_triggerdef(t.oid),t.tgenabled) ORDER BY t.tgname) \
              FROM pg_trigger t WHERE t.tgrelid=c.oid AND NOT t.tgisinternal)) ORDER BY c.relname)::text \
         FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace \
         WHERE n.nspname=current_schema() AND c.relname=ANY($1)",
    )
    .bind(TABLES)
    .fetch_one(&mut *connection)
    .await?;
    let column: Option<String> = sqlx::query_scalar("SELECT jsonb_build_array(format_type(a.atttypid,a.atttypmod),a.attnotnull,a.attidentity,a.attgenerated,pg_get_expr(d.adbin,d.adrelid))::text FROM pg_attribute a LEFT JOIN pg_attrdef d ON d.adrelid=a.attrelid AND d.adnum=a.attnum WHERE a.attrelid='episodes'::regclass AND a.attname='identity_refinalized_at' AND NOT a.attisdropped")
        .fetch_optional(connection).await?;
    let column = column.ok_or_else(|| {
        EnclaveError::Config("identity refresh timestamp column is missing".into())
    })?;
    Ok(format!(
        "{:x}",
        Sha256::digest(format!("{tables}\0{column}"))
    ))
}

async fn verify(connection: &mut PgConnection) -> Result<()> {
    if !current_schema_relation_exists(connection, "identity_presentation_schema").await? {
        return Err(EnclaveError::Config(
            "identity presentation schema must be installed by the reviewed v34 migrator".into(),
        ));
    }
    let rows = sqlx::query(
        "SELECT singleton,version,contract_sha256,catalog_sha256 FROM identity_presentation_schema",
    )
    .fetch_all(&mut *connection)
    .await?;
    let [row] = rows.as_slice() else {
        return Err(EnclaveError::Config(
            "identity presentation schema must have exactly one receipt".into(),
        ));
    };
    if !row.try_get::<bool, _>("singleton")?
        || row.try_get::<i64, _>("version")? != 34
        || row.try_get::<String, _>("contract_sha256")? != contract_digest()
        || row.try_get::<String, _>("catalog_sha256")? != catalog_digest(connection).await?
    {
        return Err(EnclaveError::Config(
            "identity presentation schema receipt does not match".into(),
        ));
    }
    Ok(())
}

impl PostgresPersistence {
    pub(crate) async fn verify_identity_presentation_schema(&self) -> Result<()> {
        verify(&mut *self.pool().acquire().await?).await
    }
    pub(crate) async fn install_identity_presentation_schema(&self) -> Result<()> {
        self.verify_schema().await?;
        self.verify_identity_fusion_schema().await?;
        let mut tx = self.pool().begin().await?;
        sqlx::query("SET LOCAL lock_timeout='5s'")
            .execute(&mut *tx)
            .await?;
        sqlx::query(
            "SELECT pg_advisory_xact_lock(hashtextextended('kioku:identity-presentation:v34',0))",
        )
        .execute(&mut *tx)
        .await?;
        if current_schema_relation_exists(&mut tx, "identity_presentation_schema").await? {
            verify(&mut tx).await?;
        } else {
            if refinalized_column_exists(&mut tx).await? {
                return Err(EnclaveError::Config(
                    "unreceipted identity refresh timestamp column exists".into(),
                ));
            }
            for name in TABLES.iter() {
                if current_schema_relation_exists(&mut tx, name).await? {
                    return Err(EnclaveError::Config(
                        "unreceipted identity presentation schema exists".into(),
                    ));
                }
            }
            sqlx::raw_sql(INSTALL_SQL).execute(&mut *tx).await?;
            let catalog = catalog_digest(&mut tx).await?;
            sqlx::query("INSERT INTO identity_presentation_schema(singleton,version,contract_sha256,catalog_sha256) VALUES(true,34,$1,$2)").bind(contract_digest()).bind(catalog).execute(&mut *tx).await?;
            verify(&mut tx).await?;
        }
        tx.commit().await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {

    #[tokio::test]
    async fn identity_presentation_receipt_preserves_prior_state_and_rejects_owned_drift() {
        let Some(fixture) = super::super::tests::test_persistence().await else {
            return;
        };
        let repo = &fixture.persistence;
        let prior_sql = "SELECT jsonb_build_array((SELECT to_jsonb(s) FROM persistence_schema s),(SELECT to_jsonb(s) FROM voice_identity_schema s),(SELECT to_jsonb(s) FROM voice_enrollment_schema s),(SELECT to_jsonb(s) FROM voice_recurrence_schema s),(SELECT to_jsonb(s) FROM identity_fusion_schema s))::text";
        let before: String = sqlx::query_scalar(prior_sql)
            .fetch_one(repo.pool())
            .await
            .unwrap();
        repo.install_identity_presentation_schema().await.unwrap();
        repo.verify_identity_presentation_schema().await.unwrap();
        repo.verify_schema().await.unwrap();
        repo.verify_identity_fusion_schema().await.unwrap();
        assert_eq!(
            sqlx::query_scalar::<_, String>(prior_sql)
                .fetch_one(repo.pool())
                .await
                .unwrap(),
            before,
            "identity presentation installation must preserve all prior schema receipts"
        );
        sqlx::raw_sql("INSERT INTO accounts(id,email,primary_provider,primary_subject) VALUES('presentation-schema','synthetic@example.test','google','presentation-schema'); INSERT INTO episodes(account_id,id,started_at,ended_at,title,identity_revision) VALUES('presentation-schema',1,now(),now(),'Speaker A explains',7); INSERT INTO episode_identity_presentations(account_id,episode_id) VALUES('presentation-schema',1);")
            .execute(repo.pool()).await.unwrap();
        let authored: (String, i64, bool) = sqlx::query_as("SELECT title,identity_revision,identity_refinalized_at IS NULL FROM episodes WHERE account_id='presentation-schema' AND id=1")
            .fetch_one(repo.pool()).await.unwrap();
        assert_eq!(
            authored,
            ("Speaker A explains".into(), 7, true),
            "presentation schema must not rewrite authored text or invent an identity refresh"
        );
        for (change, restore) in [
            ("ALTER TABLE episodes ALTER COLUMN identity_refinalized_at SET DEFAULT now()", "ALTER TABLE episodes ALTER COLUMN identity_refinalized_at DROP DEFAULT"),
            ("ALTER TABLE episode_identity_presentations ENABLE ROW LEVEL SECURITY", "ALTER TABLE episode_identity_presentations DISABLE ROW LEVEL SECURITY"),
            ("ALTER TABLE episode_identity_presentations ADD COLUMN unexpected text", "ALTER TABLE episode_identity_presentations DROP COLUMN unexpected"),
            ("ALTER TABLE episode_identity_presentations ALTER COLUMN timeline_labels DROP NOT NULL", "ALTER TABLE episode_identity_presentations ALTER COLUMN timeline_labels SET NOT NULL"),
        ] {
            sqlx::raw_sql(change).execute(repo.pool()).await.unwrap();
            assert!(repo.verify_identity_presentation_schema().await.is_err(),
                "identity presentation readiness must reject owned catalog drift: {change}");
            assert!(repo.install_identity_presentation_schema().await.is_err(),
                "an installed presentation companion must not accept altered owned schema");
            sqlx::raw_sql(restore).execute(repo.pool()).await.unwrap();
            repo.verify_identity_presentation_schema().await.unwrap();
        }
        sqlx::query("DELETE FROM accounts WHERE id='presentation-schema'")
            .execute(repo.pool())
            .await
            .unwrap();
        assert_eq!(sqlx::query_scalar::<_, i64>("SELECT count(*) FROM episode_identity_presentations WHERE account_id='presentation-schema'").fetch_one(repo.pool()).await.unwrap(),0,
            "account erasure must cascade every authored identity map");
        sqlx::query("DELETE FROM identity_presentation_schema")
            .execute(repo.pool())
            .await
            .unwrap();
        assert!(
            repo.verify_identity_presentation_schema().await.is_err(),
            "identity presentation readiness must require its exact singleton receipt"
        );
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
