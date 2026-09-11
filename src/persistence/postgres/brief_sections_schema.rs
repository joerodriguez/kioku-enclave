//! Additive brief sections; explicit migrator installation, read-only serving checks.
use super::{current_schema_relation_exists, PostgresPersistence};
use crate::error::{EnclaveError, Result};
use sha2::{Digest, Sha256};
use sqlx::{PgConnection, Row};

const INSTALL_SQL: &str = include_str!("../../../migrations/0029_dynamic_brief_sections.sql");
fn contract_digest() -> String {
    format!("{:x}", Sha256::digest(INSTALL_SQL.as_bytes()))
}
async fn column_exists(connection: &mut PgConnection) -> Result<bool> {
    Ok(sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM pg_attribute WHERE attrelid='episode_final_briefs'::regclass AND attname='sections' AND NOT attisdropped)")
        .fetch_one(connection).await?)
}
async fn catalog_digest(connection: &mut PgConnection) -> Result<String> {
    let column: Option<String> = sqlx::query_scalar("SELECT jsonb_build_array(format_type(a.atttypid,a.atttypmod),a.attnotnull,pg_get_expr(d.adbin,d.adrelid))::text FROM pg_attribute a LEFT JOIN pg_attrdef d ON d.adrelid=a.attrelid AND d.adnum=a.attnum WHERE a.attrelid='episode_final_briefs'::regclass AND a.attname='sections' AND NOT a.attisdropped")
        .fetch_optional(&mut *connection).await?;
    let constraint: Option<String> = sqlx::query_scalar("SELECT jsonb_build_array(pg_get_constraintdef(oid),convalidated)::text FROM pg_constraint WHERE conrelid='episode_final_briefs'::regclass AND conname='episode_final_briefs_sections_array'")
        .fetch_optional(connection).await?;
    match (column, constraint) {
        (Some(column), Some(constraint)) => Ok(format!(
            "{:x}",
            Sha256::digest(format!("{column}\0{constraint}"))
        )),
        _ => Err(EnclaveError::Config(
            "brief sections schema is incomplete".into(),
        )),
    }
}
async fn verify(connection: &mut PgConnection) -> Result<()> {
    if !current_schema_relation_exists(connection, "brief_sections_schema").await? {
        return Err(EnclaveError::Config(
            "brief sections require the reviewed v29 migrator".into(),
        ));
    }
    let row = sqlx::query("SELECT contract_sha256,catalog_sha256 FROM brief_sections_schema WHERE singleton=true AND version=29")
        .fetch_optional(&mut *connection).await?
        .ok_or_else(|| EnclaveError::Config("brief sections receipt is missing".into()))?;
    if row.try_get::<String, _>("contract_sha256")? != contract_digest()
        || row.try_get::<String, _>("catalog_sha256")? != catalog_digest(connection).await?
    {
        return Err(EnclaveError::Config(
            "brief sections schema receipt does not match".into(),
        ));
    }
    Ok(())
}
impl PostgresPersistence {
    pub(crate) async fn verify_brief_sections_schema(&self) -> Result<()> {
        verify(&mut *self.pool().acquire().await?).await
    }
    pub(crate) async fn install_brief_sections_schema(&self) -> Result<()> {
        self.verify_schema().await?;
        let mut tx = self.pool().begin().await?;
        sqlx::query("SET LOCAL lock_timeout='5s'")
            .execute(&mut *tx)
            .await?;
        sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended('kioku:brief-sections:v29',0))")
            .execute(&mut *tx)
            .await?;
        if current_schema_relation_exists(&mut tx, "brief_sections_schema").await? {
            verify(&mut tx).await?;
        } else {
            if column_exists(&mut tx).await? {
                return Err(EnclaveError::Config(
                    "unreceipted brief sections column exists".into(),
                ));
            }
            sqlx::raw_sql(INSTALL_SQL).execute(&mut *tx).await?;
            sqlx::query("CREATE TABLE brief_sections_schema(singleton boolean PRIMARY KEY CHECK(singleton),version bigint NOT NULL CHECK(version=29),contract_sha256 text NOT NULL,catalog_sha256 text NOT NULL,installed_at timestamptz NOT NULL DEFAULT now())").execute(&mut *tx).await?;
            let catalog = catalog_digest(&mut tx).await?;
            sqlx::query("INSERT INTO brief_sections_schema(singleton,version,contract_sha256,catalog_sha256) VALUES(true,29,$1,$2)").bind(contract_digest()).bind(catalog).execute(&mut *tx).await?;
        }
        tx.commit().await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn migration_preserves_legacy_data_and_refuses_tampering() {
        let Some(fixture) = super::super::tests::test_persistence().await else {
            return;
        };
        let repo = &fixture.persistence;
        let before: String =
            sqlx::query_scalar("SELECT row_to_json(p)::text FROM persistence_schema p")
                .fetch_one(repo.pool())
                .await
                .unwrap();
        repo.verify_brief_sections_schema().await.unwrap();
        repo.install_brief_sections_schema().await.unwrap();
        sqlx::raw_sql("DROP TABLE brief_sections_schema; ALTER TABLE episode_final_briefs DROP COLUMN sections;").execute(repo.pool()).await.unwrap();
        assert!(repo.verify_brief_sections_schema().await.is_err());
        sqlx::raw_sql("INSERT INTO accounts(id,email,primary_provider,primary_subject) VALUES('brief-test','synthetic@example.test','google','brief-test'); INSERT INTO episodes(account_id,id,started_at,ended_at,title) VALUES('brief-test',1,now(),now(),'Tour'); INSERT INTO episode_final_briefs(account_id,episode_id,overview,decisions) VALUES('brief-test',1,'Legacy overview','[{\"text\":\"Keep the pilot\"}]');").execute(repo.pool()).await.unwrap();
        repo.install_brief_sections_schema().await.unwrap();
        let row = sqlx::query("SELECT overview,decisions::text,sections::text FROM episode_final_briefs WHERE account_id='brief-test'").fetch_one(repo.pool()).await.unwrap();
        assert_eq!(row.get::<String, _>("overview"), "Legacy overview");
        assert!(row.get::<String, _>("decisions").contains("Keep the pilot"));
        assert!(row.get::<Option<String>, _>("sections").is_none());
        let after: String =
            sqlx::query_scalar("SELECT row_to_json(p)::text FROM persistence_schema p")
                .fetch_one(repo.pool())
                .await
                .unwrap();
        assert_eq!(before, after);
        assert!(sqlx::query("UPDATE episode_final_briefs SET sections='{}'")
            .execute(repo.pool())
            .await
            .is_err());
        sqlx::query(
            "ALTER TABLE episode_final_briefs ALTER COLUMN sections SET DEFAULT '[]'::jsonb",
        )
        .execute(repo.pool())
        .await
        .unwrap();
        assert!(repo.verify_brief_sections_schema().await.is_err());
        assert!(repo.install_brief_sections_schema().await.is_err());
        sqlx::query("ALTER TABLE episode_final_briefs ALTER COLUMN sections DROP DEFAULT")
            .execute(repo.pool())
            .await
            .unwrap();
        repo.verify_brief_sections_schema().await.unwrap();
        sqlx::query(
            "ALTER TABLE episode_final_briefs DROP CONSTRAINT episode_final_briefs_sections_array",
        )
        .execute(repo.pool())
        .await
        .unwrap();
        assert!(repo.verify_brief_sections_schema().await.is_err());
        sqlx::query("DROP TABLE brief_sections_schema")
            .execute(repo.pool())
            .await
            .unwrap();
        assert!(repo.install_brief_sections_schema().await.is_err());
        fixture.persistence.pool().close().await;
        sqlx::query(sqlx::AssertSqlSafe(format!(
            "DROP SCHEMA {} CASCADE",
            fixture.schema
        )))
        .execute(fixture.base.pool())
        .await
        .unwrap();
    }
}
