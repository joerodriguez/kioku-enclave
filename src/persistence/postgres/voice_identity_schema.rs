//! ADR-0048 voice companion: immutable SQL/catalog receipt and operator controls.
//! Serving verifies the contract and reads controls; only the explicitly selected
//! digest-pinned migrator phases install it or mutate its cohort/pause state.

use sha2::{Digest, Sha256};
use sqlx::{PgConnection, Row};

use super::{current_schema_relation_exists, PostgresPersistence};
use crate::error::{EnclaveError, Result};
use crate::persistence::{VoiceCohort, VoiceIdentityControls};

const INSTALL_SQL: &str = include_str!("../../../migrations/0030_voice_identity.sql");
const TABLES: &[&str] = &["voice_identity_controls", "voice_identity_schema"];
const INDEXES: &[&str] = &[
    "voice_samples_observation_version_key",
    "voice_embedding_jobs_account_claim_idx",
];
const CONTROL_LOCK: &str = "kioku:voice-identity:v30";

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
            "voice identity schema is incomplete".into(),
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
         WHERE n.nspname=current_schema() AND c.relname=ANY($1) AND c.relkind='i' HAVING count(*)=2",
    )
    .bind(INDEXES)
    .fetch_optional(&mut *connection)
    .await?
    .flatten();
    let indexes = indexes
        .ok_or_else(|| EnclaveError::Config("voice identity indexes are incomplete".into()))?;
    let mut digest = Sha256::new();
    for item in [tables, indexes] {
        digest.update(item.as_bytes());
        digest.update([0]);
    }
    Ok(format!("{:x}", digest.finalize()))
}

async fn verify(connection: &mut PgConnection) -> Result<()> {
    if !current_schema_relation_exists(connection, "voice_identity_schema").await? {
        return Err(EnclaveError::Config(
            "voice identity schema must be installed by the reviewed v30 migrator".into(),
        ));
    }
    let rows = sqlx::query(
        "SELECT singleton,version,contract_sha256,catalog_sha256 FROM voice_identity_schema",
    )
    .fetch_all(&mut *connection)
    .await?;
    let [row] = rows.as_slice() else {
        return Err(EnclaveError::Config(
            "voice identity schema must have exactly one receipt".into(),
        ));
    };
    if !row.try_get::<bool, _>("singleton")?
        || row.try_get::<i64, _>("version")? != 30
        || row.try_get::<String, _>("contract_sha256")? != contract_digest()
        || row.try_get::<String, _>("catalog_sha256")? != catalog_digest(connection).await?
    {
        return Err(EnclaveError::Config(
            "voice identity schema receipt does not match".into(),
        ));
    }
    read_controls(connection).await?;
    Ok(())
}

fn validated_accounts(cohort: VoiceCohort, account_ids: &[String]) -> Result<Vec<String>> {
    if account_ids.len() > 1024
        || account_ids.iter().any(|id| !crate::cp::is_stable_uuid(id))
        || (cohort == VoiceCohort::Explicit) == account_ids.is_empty()
    {
        return Err(EnclaveError::Config("voice identity cohort requires none/all without IDs or explicit with 1..1024 stable UUIDs".into()));
    }
    let mut ids = account_ids.to_vec();
    ids.sort();
    ids.dedup();
    Ok(ids)
}

async fn read_controls(connection: &mut PgConnection) -> Result<VoiceIdentityControls> {
    let rows = sqlx::query("SELECT singleton,cohort,explicit_account_ids,paused,revision FROM voice_identity_controls LIMIT 2")
        .fetch_all(connection).await?;
    let [row] = rows.as_slice() else {
        return Err(EnclaveError::Config(
            "voice identity controls must have exactly one row".into(),
        ));
    };
    let cohort = VoiceCohort::parse(&row.try_get::<String, _>("cohort")?)?;
    let controls = VoiceIdentityControls {
        cohort,
        explicit_account_ids: validated_accounts(
            cohort,
            &row.try_get::<Vec<String>, _>("explicit_account_ids")?,
        )?,
        paused: row.try_get("paused")?,
        revision: row.try_get("revision")?,
    };
    if !row.try_get::<bool, _>("singleton")? || controls.revision < 0 {
        return Err(EnclaveError::Config(
            "voice identity controls are invalid".into(),
        ));
    }
    Ok(controls)
}

impl PostgresPersistence {
    pub(crate) async fn verify_voice_identity_schema(&self) -> Result<()> {
        verify(&mut *self.pool().acquire().await?).await
    }

    pub(crate) async fn install_voice_identity_schema(&self) -> Result<()> {
        self.verify_schema().await?;
        let mut tx = self.pool().begin().await?;
        sqlx::query("SET LOCAL lock_timeout='5s'")
            .execute(&mut *tx)
            .await?;
        sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,0))")
            .bind(CONTROL_LOCK)
            .execute(&mut *tx)
            .await?;
        if current_schema_relation_exists(&mut tx, "voice_identity_schema").await? {
            verify(&mut tx).await?;
        } else {
            for name in ["voice_identity_controls", INDEXES[0], INDEXES[1]] {
                if current_schema_relation_exists(&mut tx, name).await? {
                    return Err(EnclaveError::Config(
                        "unreceipted voice identity schema exists".into(),
                    ));
                }
            }
            sqlx::raw_sql(INSTALL_SQL).execute(&mut *tx).await?;
            sqlx::query("CREATE TABLE voice_identity_schema(singleton boolean PRIMARY KEY CHECK(singleton),version bigint NOT NULL CHECK(version=30),contract_sha256 text NOT NULL,catalog_sha256 text NOT NULL,installed_at timestamptz NOT NULL DEFAULT now())")
                .execute(&mut *tx).await?;
            let catalog = catalog_digest(&mut tx).await?;
            sqlx::query("INSERT INTO voice_identity_schema(singleton,version,contract_sha256,catalog_sha256) VALUES(true,30,$1,$2)")
                .bind(contract_digest()).bind(catalog).execute(&mut *tx).await?;
            verify(&mut tx).await?;
        }
        tx.commit().await?;
        Ok(())
    }

    /// One snapshot per worker sweep, before enumerating tenant work.
    pub(crate) async fn voice_identity_controls(&self) -> Result<VoiceIdentityControls> {
        read_controls(&mut *self.pool().acquire().await?).await
    }

    pub(crate) async fn set_voice_identity_cohort(
        &self,
        cohort: VoiceCohort,
        account_ids: &[String],
    ) -> Result<i64> {
        let ids = validated_accounts(cohort, account_ids)?;
        let mut tx = self.pool().begin().await?;
        sqlx::query("SET LOCAL lock_timeout='5s'")
            .execute(&mut *tx)
            .await?;
        sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,0))")
            .bind(CONTROL_LOCK)
            .execute(&mut *tx)
            .await?;
        verify(&mut tx).await?;
        let revision = sqlx::query_scalar("UPDATE voice_identity_controls SET cohort=$1,explicit_account_ids=$2,revision=revision+1,updated_at=clock_timestamp() WHERE singleton RETURNING revision")
            .bind(cohort.as_str()).bind(ids).fetch_one(&mut *tx).await?;
        tx.commit().await?;
        Ok(revision)
    }

    pub(crate) async fn set_voice_identity_paused(&self, paused: bool) -> Result<i64> {
        let mut tx = self.pool().begin().await?;
        sqlx::query("SET LOCAL lock_timeout='5s'")
            .execute(&mut *tx)
            .await?;
        sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,0))")
            .bind(CONTROL_LOCK)
            .execute(&mut *tx)
            .await?;
        verify(&mut tx).await?;
        let revision = sqlx::query_scalar("UPDATE voice_identity_controls SET paused=$1,revision=revision+1,updated_at=clock_timestamp() WHERE singleton RETURNING revision")
            .bind(paused).fetch_one(&mut *tx).await?;
        tx.commit().await?;
        Ok(revision)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn companion_install_preserves_history_and_refuses_drift() {
        let Some(fixture) = super::super::tests::test_persistence().await else {
            return;
        };
        let repo = &fixture.persistence;
        repo.install_memory_reconciliation_activation_schema()
            .await
            .unwrap();
        const HISTORY: &str = "SELECT jsonb_build_object( \
            'marker',(SELECT to_jsonb(s) FROM persistence_schema s), \
            'contracts',(SELECT jsonb_agg(to_jsonb(c) ORDER BY feature) FROM persistence_feature_activation_contracts c), \
            'events',(SELECT jsonb_agg(to_jsonb(e) ORDER BY event_sequence) FROM persistence_feature_activation_events e))::text";
        let before: String = sqlx::query_scalar(HISTORY)
            .fetch_one(repo.pool())
            .await
            .unwrap();
        sqlx::raw_sql("DROP TABLE voice_identity_schema,voice_identity_controls; DROP INDEX voice_samples_observation_version_key; DROP INDEX voice_embedding_jobs_account_claim_idx;")
            .execute(repo.pool()).await.unwrap();
        assert!(
            repo.verify_voice_identity_schema().await.is_err(),
            "missing voice companion must fail readiness"
        );
        repo.install_voice_identity_schema().await.unwrap();
        repo.install_voice_identity_schema().await.unwrap();
        repo.verify_voice_identity_schema().await.unwrap();
        repo.verify_schema().await.unwrap();
        let after: String = sqlx::query_scalar(HISTORY)
            .fetch_one(repo.pool())
            .await
            .unwrap();
        assert_eq!(
            before, after,
            "voice companion must preserve base and signed activation history"
        );
        let controls = repo.voice_identity_controls().await.unwrap();
        assert_eq!(
            controls.cohort,
            VoiceCohort::None,
            "voice identity must default to no enabled accounts"
        );
        assert!(!controls.paused);
        assert_eq!(controls.revision, 0);
        assert!(controls.explicit_account_ids.is_empty());

        for mutation in [
            "DELETE FROM voice_identity_schema",
            "UPDATE voice_identity_schema SET contract_sha256='forged'",
            "UPDATE voice_identity_schema SET catalog_sha256='forged'",
            "ALTER TABLE voice_identity_schema ADD COLUMN unexpected text",
            "ALTER TABLE voice_identity_controls ALTER COLUMN paused SET DEFAULT true",
            "ALTER TABLE voice_identity_controls ENABLE ROW LEVEL SECURITY",
            "ALTER TABLE voice_identity_controls DROP CONSTRAINT voice_identity_controls_cohort_check",
            "DELETE FROM voice_identity_controls",
            "DROP INDEX voice_samples_observation_version_key",
            "DROP INDEX voice_embedding_jobs_account_claim_idx",
            "DROP INDEX voice_samples_observation_version_key; CREATE INDEX voice_samples_observation_version_key ON voice_samples(account_id,speaker_observation_id,embedding_space,quality_version,scorer_version)",
            "DROP INDEX voice_embedding_jobs_account_claim_idx; CREATE INDEX voice_embedding_jobs_account_claim_idx ON voice_embedding_jobs(account_id,id)",
        ] {
            let mut tx = repo.pool().begin().await.unwrap();
            sqlx::raw_sql(mutation).execute(&mut *tx).await.unwrap();
            assert!(verify(&mut tx).await.is_err(), "voice companion must reject tampering: {mutation}");
            tx.rollback().await.unwrap();
        }
        sqlx::query("DROP TABLE voice_identity_schema")
            .execute(repo.pool())
            .await
            .unwrap();
        assert!(
            repo.install_voice_identity_schema().await.is_err(),
            "unreceipted voice objects must never be adopted"
        );
        // Index-only partial installation is also an unreceipted contract.
        sqlx::query("DROP TABLE voice_identity_controls")
            .execute(repo.pool())
            .await
            .unwrap();
        assert!(
            repo.install_voice_identity_schema().await.is_err(),
            "unreceipted voice index must never be adopted"
        );
        repo.pool().close().await;
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
    async fn control_mutations_validate_scope_and_serialize_revisions() {
        let Some(fixture) = super::super::tests::test_persistence().await else {
            return;
        };
        let repo = &fixture.persistence;
        let first = "11111111-1111-4111-8111-111111111111".to_owned();
        let second = "22222222-2222-4222-8222-222222222222".to_owned();
        assert_eq!(
            repo.set_voice_identity_cohort(
                VoiceCohort::Explicit,
                &[second.clone(), first.clone(), second.clone()]
            )
            .await
            .unwrap(),
            1
        );
        let controls = repo.voice_identity_controls().await.unwrap();
        assert_eq!(
            controls.explicit_account_ids,
            [first.clone(), second.clone()],
            "cohort IDs must be sorted and deduplicated"
        );
        assert!(controls.admits(&first));
        assert!(!controls.admits("33333333-3333-4333-8333-333333333333"));
        assert_eq!(repo.set_voice_identity_paused(true).await.unwrap(), 2);
        assert!(
            !repo.voice_identity_controls().await.unwrap().admits(&first),
            "pause must prevent even explicit cohort admission"
        );
        assert_eq!(repo.set_voice_identity_paused(false).await.unwrap(), 3);
        assert!(repo.voice_identity_controls().await.unwrap().admits(&first));
        for (cohort, ids) in [
            (VoiceCohort::Explicit, vec![]),
            (VoiceCohort::None, vec![first.clone()]),
            (VoiceCohort::All, vec![first.clone()]),
            (VoiceCohort::Explicit, vec!["not-a-stable-uuid".into()]),
            (VoiceCohort::Explicit, vec![first.clone(); 1025]),
        ] {
            assert!(
                repo.set_voice_identity_cohort(cohort, &ids).await.is_err(),
                "invalid voice scope must be refused before mutation"
            );
        }
        assert_eq!(
            repo.voice_identity_controls().await.unwrap().revision,
            3,
            "rejected requests must preserve control revision"
        );
        let (pause, cohort) = tokio::join!(
            repo.set_voice_identity_paused(true),
            repo.set_voice_identity_cohort(VoiceCohort::All, &[])
        );
        let mut revisions = [pause.unwrap(), cohort.unwrap()];
        revisions.sort();
        assert_eq!(
            revisions,
            [4, 5],
            "concurrent operator phases must serialize revisions"
        );
        let controls = repo.voice_identity_controls().await.unwrap();
        assert!(controls.paused);
        assert_eq!(controls.cohort, VoiceCohort::All);
        assert!(!controls.admits(&first));
        assert_eq!(repo.set_voice_identity_paused(false).await.unwrap(), 6);
        assert!(repo
            .voice_identity_controls()
            .await
            .unwrap()
            .admits(&second));
        assert_eq!(
            repo.set_voice_identity_cohort(VoiceCohort::None, &[])
                .await
                .unwrap(),
            7
        );
        assert!(!repo.voice_identity_controls().await.unwrap().admits(&first));
        for mutation in [
            "UPDATE voice_identity_controls SET cohort='unreviewed'",
            "UPDATE voice_identity_controls SET explicit_account_ids=array_fill('11111111-1111-4111-8111-111111111111'::text,ARRAY[1025])",
            "INSERT INTO voice_identity_controls(singleton) VALUES(false)",
        ] {
            assert!(sqlx::query(sqlx::AssertSqlSafe(mutation)).execute(repo.pool()).await.is_err(), "SQL must reject invalid control structure: {mutation}");
        }
        repo.verify_voice_identity_schema().await.unwrap();
        repo.pool().close().await;
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
