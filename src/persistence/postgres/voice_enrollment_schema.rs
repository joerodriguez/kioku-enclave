//! Direct ADR-0048 owner-enrollment companion, installed only by the explicit
//! v31 migrator. Serving verifies immutable SQL and the owned catalog objects.
use super::{current_schema_relation_exists, PostgresPersistence};
use crate::error::{EnclaveError, Result};
use sha2::{Digest, Sha256};
use sqlx::{PgConnection, Row};

const INSTALL_SQL: &str = include_str!("../../../migrations/0031_voice_enrollment.sql");
const TABLES: &[&str] = &["voice_enrollment_sessions", "voice_enrollment_schema"];
const INDEXES: &[&str] = &[
    "people_owner_account_key",
    "speaker_observations_voice_profile_idx",
    "voice_enrollment_sessions_pending_idx",
];
const COLUMNS: &[&str] = &[
    "accounts.enrollment_revision",
    "speaker_clusters.owner",
    "speaker_clusters.profile_updates_quarantined",
    "speaker_clusters.channel_domain",
    "speaker_observations.voice_profile_id",
    "speaker_observations.voice_sample_id",
    "speaker_observations.owner_evidence_id",
];
const CONSTRAINTS: &[&str] = &[
    "accounts_enrollment_revision_check",
    "people_status_check",
    "episode_participants_attribution_kind_check",
    "speaker_observations_voice_profile_fk",
    "speaker_observations_voice_sample_fk",
    "speaker_observations_owner_evidence_fk",
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
            "voice enrollment schema is incomplete".into(),
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
    let indexes: Option<String> = sqlx::query_scalar(
        "SELECT jsonb_agg(jsonb_build_array(c.relname,pg_get_indexdef(i.indexrelid), \
            i.indisvalid,i.indisready,i.indislive) ORDER BY c.relname)::text \
         FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace \
         JOIN pg_index i ON i.indexrelid=c.oid \
         WHERE n.nspname=current_schema() AND c.relname=ANY($1) AND c.relkind='i' HAVING count(*)=3",
    )
    .bind(INDEXES)
    .fetch_optional(&mut *connection)
    .await?
    .flatten();
    let indexes = indexes
        .ok_or_else(|| EnclaveError::Config("voice enrollment indexes are incomplete".into()))?;
    let columns: Option<String> = sqlx::query_scalar(
        "SELECT jsonb_agg(jsonb_build_array(c.relname,a.attname,format_type(a.atttypid,a.atttypmod), \
            a.attnotnull,pg_get_expr(d.adbin,d.adrelid)) ORDER BY c.relname,a.attname)::text \
         FROM pg_attribute a JOIN pg_class c ON c.oid=a.attrelid \
         JOIN pg_namespace n ON n.oid=c.relnamespace \
         LEFT JOIN pg_attrdef d ON d.adrelid=a.attrelid AND d.adnum=a.attnum \
         WHERE n.nspname=current_schema() AND NOT a.attisdropped \
           AND c.relname||'.'||a.attname=ANY($1) HAVING count(*)=7",
    ).bind(COLUMNS).fetch_optional(&mut *connection).await?.flatten();
    let columns = columns
        .ok_or_else(|| EnclaveError::Config("voice enrollment columns are incomplete".into()))?;
    let constraints: Option<String> = sqlx::query_scalar(
        "SELECT jsonb_agg(jsonb_build_array(c.relname,k.conname,pg_get_constraintdef(k.oid), \
            k.convalidated,k.condeferrable,k.condeferred) ORDER BY c.relname,k.conname)::text \
         FROM pg_constraint k JOIN pg_class c ON c.oid=k.conrelid \
         JOIN pg_namespace n ON n.oid=c.relnamespace \
         WHERE n.nspname=current_schema() AND k.conname=ANY($1) HAVING count(*)=6",
    )
    .bind(CONSTRAINTS)
    .fetch_optional(&mut *connection)
    .await?
    .flatten();
    let constraints = constraints.ok_or_else(|| {
        EnclaveError::Config("voice enrollment constraints are incomplete".into())
    })?;
    let mut digest = Sha256::new();
    for item in [tables, indexes, columns, constraints] {
        digest.update(item.as_bytes());
        digest.update([0]);
    }
    Ok(format!("{:x}", digest.finalize()))
}

async fn verify(connection: &mut PgConnection) -> Result<()> {
    if !current_schema_relation_exists(connection, "voice_enrollment_schema").await? {
        return Err(EnclaveError::Config(
            "voice enrollment schema must be installed by the reviewed v31 migrator".into(),
        ));
    }
    let rows = sqlx::query(
        "SELECT singleton,version,contract_sha256,catalog_sha256 FROM voice_enrollment_schema",
    )
    .fetch_all(&mut *connection)
    .await?;
    let [row] = rows.as_slice() else {
        return Err(EnclaveError::Config(
            "voice enrollment schema must have exactly one receipt".into(),
        ));
    };
    if !row.try_get::<bool, _>("singleton")?
        || row.try_get::<i64, _>("version")? != 31
        || row.try_get::<String, _>("contract_sha256")? != contract_digest()
        || row.try_get::<String, _>("catalog_sha256")? != catalog_digest(connection).await?
    {
        return Err(EnclaveError::Config(
            "voice enrollment schema receipt does not match".into(),
        ));
    }
    Ok(())
}

impl PostgresPersistence {
    pub(crate) async fn verify_voice_enrollment_schema(&self) -> Result<()> {
        verify(&mut *self.pool().acquire().await?).await
    }
    pub(crate) async fn install_voice_enrollment_schema(&self) -> Result<()> {
        self.verify_schema().await?;
        self.verify_voice_identity_schema().await?;
        let mut tx = self.pool().begin().await?;
        sqlx::query("SET LOCAL lock_timeout='5s'")
            .execute(&mut *tx)
            .await?;
        sqlx::query(
            "SELECT pg_advisory_xact_lock(hashtextextended('kioku:voice-enrollment:v31',0))",
        )
        .execute(&mut *tx)
        .await?;
        if current_schema_relation_exists(&mut tx, "voice_enrollment_schema").await? {
            verify(&mut tx).await?;
        } else {
            for name in std::iter::once(&"voice_enrollment_sessions").chain(INDEXES.iter()) {
                if current_schema_relation_exists(&mut tx, name).await? {
                    return Err(EnclaveError::Config(
                        "unreceipted voice enrollment schema exists".into(),
                    ));
                }
            }
            let partial: bool = sqlx::query_scalar(
                "SELECT EXISTS(SELECT 1 FROM pg_attribute a JOIN pg_class c ON c.oid=a.attrelid \
                 JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname=current_schema() \
                 AND NOT a.attisdropped AND c.relname||'.'||a.attname=ANY($1))",
            )
            .bind(COLUMNS)
            .fetch_one(&mut *tx)
            .await?;
            if partial {
                return Err(EnclaveError::Config(
                    "unreceipted voice enrollment columns exist".into(),
                ));
            }
            sqlx::raw_sql(INSTALL_SQL).execute(&mut *tx).await?;
            sqlx::query("CREATE TABLE voice_enrollment_schema(singleton boolean PRIMARY KEY CHECK(singleton),version bigint NOT NULL CHECK(version=31),contract_sha256 text NOT NULL,catalog_sha256 text NOT NULL,installed_at timestamptz NOT NULL DEFAULT now())").execute(&mut *tx).await?;
            let catalog = catalog_digest(&mut tx).await?;
            sqlx::query("INSERT INTO voice_enrollment_schema(singleton,version,contract_sha256,catalog_sha256) VALUES(true,31,$1,$2)").bind(contract_digest()).bind(catalog).execute(&mut *tx).await?;
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
    async fn enrollment_schema_receipt_rejects_drift_and_preserves_prior_contracts() {
        let Some(fixture) = super::super::tests::test_persistence().await else {
            return;
        };
        let repo = &fixture.persistence;
        repo.install_memory_reconciliation_activation_schema()
            .await
            .unwrap();
        const HISTORY:&str="SELECT jsonb_build_object('base',(SELECT to_jsonb(s) FROM persistence_schema s),'voice',(SELECT to_jsonb(s) FROM voice_identity_schema s),'activation',(SELECT jsonb_agg(to_jsonb(c) ORDER BY feature) FROM persistence_feature_activation_contracts c),'events',(SELECT jsonb_agg(to_jsonb(e) ORDER BY event_sequence) FROM persistence_feature_activation_events e))::text";
        let before: String = sqlx::query_scalar(HISTORY)
            .fetch_one(repo.pool())
            .await
            .unwrap();
        repo.install_voice_enrollment_schema().await.unwrap();
        repo.verify_voice_enrollment_schema().await.unwrap();
        repo.verify_voice_identity_schema().await.unwrap();
        repo.verify_schema().await.unwrap();
        let after: String = sqlx::query_scalar(HISTORY)
            .fetch_one(repo.pool())
            .await
            .unwrap();
        assert_eq!(
            before, after,
            "v31 installation must preserve earlier schema and signed activation receipts"
        );
        for mutation in [
            "DELETE FROM voice_enrollment_schema",
            "UPDATE voice_enrollment_schema SET contract_sha256='forged'",
            "UPDATE voice_enrollment_schema SET catalog_sha256='forged'",
            "ALTER TABLE voice_enrollment_sessions ADD COLUMN unexpected text",
            "ALTER TABLE voice_enrollment_sessions ENABLE ROW LEVEL SECURITY",
            "ALTER TABLE accounts ALTER COLUMN enrollment_revision SET DEFAULT 1",
            "ALTER TABLE speaker_clusters DROP COLUMN profile_updates_quarantined",
            "ALTER TABLE people DROP CONSTRAINT people_status_check",
            "ALTER TABLE episode_participants DROP CONSTRAINT episode_participants_attribution_kind_check",
            "ALTER TABLE speaker_observations DROP CONSTRAINT speaker_observations_voice_sample_fk",
            "DROP INDEX people_owner_account_key; CREATE INDEX people_owner_account_key ON people(account_id)",
            "DROP INDEX speaker_observations_voice_profile_idx",
        ] {
            let mut tx=repo.pool().begin().await.unwrap();sqlx::raw_sql(mutation).execute(&mut *tx).await.unwrap();
            assert!(verify(&mut tx).await.is_err(),"v31 readiness must reject owned catalog or receipt drift: {mutation}");
            tx.rollback().await.unwrap();
        }
        let receipt: String =
            sqlx::query_scalar("SELECT to_jsonb(r)::text FROM voice_enrollment_schema r")
                .fetch_one(repo.pool())
                .await
                .unwrap();
        sqlx::query("DROP TABLE voice_enrollment_schema")
            .execute(repo.pool())
            .await
            .unwrap();
        assert!(
            repo.install_voice_enrollment_schema().await.is_err(),
            "v31 must not adopt pre-existing unreceipted enrollment objects"
        );
        sqlx::query("CREATE TABLE voice_enrollment_schema(singleton boolean PRIMARY KEY CHECK(singleton),version bigint NOT NULL CHECK(version=31),contract_sha256 text NOT NULL,catalog_sha256 text NOT NULL,installed_at timestamptz NOT NULL DEFAULT now())").execute(repo.pool()).await.unwrap();
        sqlx::query("INSERT INTO voice_enrollment_schema SELECT * FROM jsonb_populate_record(NULL::voice_enrollment_schema,$1::jsonb)").bind(receipt).execute(repo.pool()).await.unwrap();
        repo.verify_voice_enrollment_schema().await.unwrap();
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

    #[tokio::test]
    async fn enrollment_schema_enforces_owner_uniqueness_and_tenant_observation_links() {
        let Some(fixture) = super::super::tests::test_persistence().await else {
            return;
        };
        let repo = &fixture.persistence;
        super::super::voice_identity::tests::seed_voice_observation(
            repo,
            "enrollment-schema-a",
            "session-a",
            "event-a",
            1,
            1,
        )
        .await;
        super::super::voice_identity::tests::seed_voice_observation(
            repo,
            "enrollment-schema-b",
            "session-b",
            "event-b",
            2,
            2,
        )
        .await;
        sqlx::query("INSERT INTO people(account_id,id,status) VALUES('enrollment-schema-a',1,'owner'),('enrollment-schema-b',1,'owner'),('enrollment-schema-a',2,'recurring')").execute(repo.pool()).await.unwrap();
        assert!(
            sqlx::query(
                "INSERT INTO people(account_id,id,status) VALUES('enrollment-schema-a',3,'owner')"
            )
            .execute(repo.pool())
            .await
            .is_err(),
            "each account must have exactly one possible owner identity"
        );
        sqlx::query("INSERT INTO voice_profiles(account_id,id,person_id,label,embedding_space,channel_domain,centroid) VALUES('enrollment-schema-b',9,1,'owner','test','macos:builtin_mic',decode('01','hex'))").execute(repo.pool()).await.unwrap();
        sqlx::query("INSERT INTO voice_samples(account_id,id,speaker_observation_id,voice_profile_id,embedding_space,channel_domain,embedding,quality_score) VALUES('enrollment-schema-b',9,2,9,'test','macos:builtin_mic',decode('01','hex'),1)").execute(repo.pool()).await.unwrap();
        sqlx::query("INSERT INTO identity_evidence(account_id,id,person_id,kind,evidence,status) VALUES('enrollment-schema-b',9,1,'owner_enrollment','{}','accepted')").execute(repo.pool()).await.unwrap();
        for statement in [
            "UPDATE speaker_observations SET voice_profile_id=9 WHERE account_id='enrollment-schema-a' AND id=1",
            "UPDATE speaker_observations SET voice_sample_id=9 WHERE account_id='enrollment-schema-a' AND id=1",
            "UPDATE speaker_observations SET owner_evidence_id=9 WHERE account_id='enrollment-schema-a' AND id=1",
        ] {assert!(sqlx::query(sqlx::AssertSqlSafe(statement)).execute(repo.pool()).await.is_err(),"owner observation evidence must never cross accounts");}
        sqlx::query("UPDATE speaker_observations SET voice_profile_id=9,voice_sample_id=9,owner_evidence_id=9 WHERE account_id='enrollment-schema-b' AND id=2").execute(repo.pool()).await.unwrap();
        sqlx::query("DELETE FROM voice_samples WHERE account_id='enrollment-schema-b' AND id=9")
            .execute(repo.pool())
            .await
            .unwrap();
        let row=sqlx::query("SELECT voice_profile_id,voice_sample_id,owner_evidence_id FROM speaker_observations WHERE account_id='enrollment-schema-b' AND id=2").fetch_one(repo.pool()).await.unwrap();
        assert_eq!(row.get::<Option<i64>, _>("voice_profile_id"), Some(9));
        assert!(
            row.get::<Option<i64>, _>("voice_sample_id").is_none(),
            "sample erasure must clear only its own per-observation link"
        );
        assert_eq!(row.get::<Option<i64>, _>("owner_evidence_id"), Some(9));
        assert!(
            sqlx::query(
                "UPDATE accounts SET enrollment_revision=-1 WHERE id='enrollment-schema-a'"
            )
            .execute(repo.pool())
            .await
            .is_err(),
            "the account withdrawal revision must remain nonnegative"
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
