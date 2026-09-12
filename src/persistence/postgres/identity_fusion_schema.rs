//! Direct ADR-0048 identity-fusion companion, installed only by the explicit
//! v33 migrator. Serving verifies immutable SQL and the owned catalog objects.
use super::{current_schema_relation_exists, PostgresPersistence};
use crate::error::{EnclaveError, Result};
use sha2::{Digest, Sha256};
use sqlx::{PgConnection, Row};

const INSTALL_SQL: &str = include_str!("../../../migrations/0033_identity_fusion.sql");
const TABLES: &[&str] = &[
    "identity_name_inputs",
    "profile_name_bindings",
    "profile_name_claims",
    "person_fact_candidates",
    "identity_fusion_schema",
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
            "identity fusion schema is incomplete".into(),
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
    Ok(format!("{:x}", Sha256::digest(tables.as_bytes())))
}

async fn verify(connection: &mut PgConnection) -> Result<()> {
    if !current_schema_relation_exists(connection, "identity_fusion_schema").await? {
        return Err(EnclaveError::Config(
            "identity fusion schema must be installed by the reviewed v33 migrator".into(),
        ));
    }
    let rows = sqlx::query(
        "SELECT singleton,version,contract_sha256,catalog_sha256 FROM identity_fusion_schema",
    )
    .fetch_all(&mut *connection)
    .await?;
    let [row] = rows.as_slice() else {
        return Err(EnclaveError::Config(
            "identity fusion schema must have exactly one receipt".into(),
        ));
    };
    if !row.try_get::<bool, _>("singleton")?
        || row.try_get::<i64, _>("version")? != 33
        || row.try_get::<String, _>("contract_sha256")? != contract_digest()
        || row.try_get::<String, _>("catalog_sha256")? != catalog_digest(connection).await?
    {
        return Err(EnclaveError::Config(
            "identity fusion schema receipt does not match".into(),
        ));
    }
    Ok(())
}

impl PostgresPersistence {
    pub(crate) async fn verify_identity_fusion_schema(&self) -> Result<()> {
        verify(&mut *self.pool().acquire().await?).await
    }
    pub(crate) async fn install_identity_fusion_schema(&self) -> Result<()> {
        self.verify_schema().await?;
        self.verify_voice_recurrence_schema().await?;
        let mut tx = self.pool().begin().await?;
        sqlx::query("SET LOCAL lock_timeout='5s'")
            .execute(&mut *tx)
            .await?;
        sqlx::query(
            "SELECT pg_advisory_xact_lock(hashtextextended('kioku:identity-fusion:v33',0))",
        )
        .execute(&mut *tx)
        .await?;
        if current_schema_relation_exists(&mut tx, "identity_fusion_schema").await? {
            verify(&mut tx).await?;
        } else {
            for name in TABLES.iter() {
                if current_schema_relation_exists(&mut tx, name).await? {
                    return Err(EnclaveError::Config(
                        "unreceipted identity fusion schema exists".into(),
                    ));
                }
            }
            sqlx::raw_sql(INSTALL_SQL).execute(&mut *tx).await?;
            let catalog = catalog_digest(&mut tx).await?;
            sqlx::query("INSERT INTO identity_fusion_schema(singleton,version,contract_sha256,catalog_sha256) VALUES(true,33,$1,$2)").bind(contract_digest()).bind(catalog).execute(&mut *tx).await?;
            verify(&mut tx).await?;
        }
        tx.commit().await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn identity_fusion_receipt_preserves_prior_catalogs_and_rejects_drift() {
        let Some(fixture) = super::super::tests::test_persistence().await else {
            return;
        };
        let repo = &fixture.persistence;
        const PRIOR:&str="SELECT jsonb_build_array((SELECT to_jsonb(s) FROM persistence_schema s),(SELECT to_jsonb(s) FROM voice_identity_schema s),(SELECT to_jsonb(s) FROM voice_enrollment_schema s),(SELECT to_jsonb(s) FROM voice_recurrence_schema s))::text";
        let before: String = sqlx::query_scalar(PRIOR)
            .fetch_one(repo.pool())
            .await
            .unwrap();
        repo.install_identity_fusion_schema().await.unwrap();
        repo.verify_identity_fusion_schema().await.unwrap();
        repo.verify_voice_recurrence_schema().await.unwrap();
        repo.verify_voice_enrollment_schema().await.unwrap();
        repo.verify_voice_identity_schema().await.unwrap();
        repo.verify_schema().await.unwrap();
        assert_eq!(
            sqlx::query_scalar::<_, String>(PRIOR)
                .fetch_one(repo.pool())
                .await
                .unwrap(),
            before,
            "identity fusion installation must preserve previous schema receipts"
        );
        for mutation in [
            "DELETE FROM identity_fusion_schema",
            "UPDATE identity_fusion_schema SET contract_sha256=repeat('0',64)",
            "UPDATE identity_fusion_schema SET catalog_sha256=repeat('0',64)",
            "ALTER TABLE identity_name_inputs ADD COLUMN unexpected text",
            "ALTER TABLE profile_name_bindings ENABLE ROW LEVEL SECURITY",
            "ALTER TABLE profile_name_claims ALTER COLUMN policy_version DROP NOT NULL",
            "ALTER TABLE person_fact_candidates DROP CONSTRAINT person_fact_candidates_confidence_check",
            "DROP INDEX identity_name_inputs_subject_idx",
        ] {
            let mut tx=repo.pool().begin().await.unwrap();sqlx::raw_sql(mutation).execute(&mut *tx).await.unwrap();
            assert!(verify(&mut tx).await.is_err(),"identity fusion readiness must reject owned receipt or catalog drift: {mutation}");tx.rollback().await.unwrap();
        }
        sqlx::query("DROP TABLE identity_fusion_schema")
            .execute(repo.pool())
            .await
            .unwrap();
        assert!(
            repo.install_identity_fusion_schema().await.is_err(),
            "identity fusion must refuse to adopt unreceipted pre-existing objects"
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
