//! Exact companion contract for server-inferred interrupted capture finishes.
//! The one widened CHECK is verified independently before reconstructing the
//! original catalog projection used by immutable signed v27 history.

use sha2::{Digest, Sha256};
use sqlx::{PgConnection, Row};

use super::{activation, current_schema_relation_exists, PostgresPersistence};
use crate::error::{EnclaveError, Result};

const INSTALL_SQL: &str = include_str!("../../../migrations/0029_interrupted_capture_recovery.sql");
const CONSTRAINT_NAME: &str = "capture_formation_receipts_finish_request_provenance_check";
// The frozen v27 UNION inherits PostgreSQL's `name` type from relname,
// so its composite names are truncated to 63 bytes. Preserve that framing.
const CATALOG_KEY: &str = "capture_formation_receipts.capture_formation_receipts_finish_re";
const PRIOR_CHECK: &str = "CHECK (finish_request_provenance IS NULL OR (finish_request_provenance = ANY (ARRAY['event_finish_v1'::text, 'finish_endpoint_v1'::text, 'legacy_client_refinish_v1'::text, 'legacy_ended_v1'::text])))";
const CURRENT_CHECK: &str = "CHECK (finish_request_provenance IS NULL OR (finish_request_provenance = ANY (ARRAY['event_finish_v1'::text, 'finish_endpoint_v1'::text, 'legacy_client_refinish_v1'::text, 'legacy_ended_v1'::text, 'server_inactivity_v1'::text])))";

fn contract_digest() -> String {
    format!("{:x}", Sha256::digest(INSTALL_SQL.as_bytes()))
}

async fn require_check(connection: &mut PgConnection, expected: &str) -> Result<()> {
    let valid: bool = sqlx::query_scalar(
        "SELECT count(*)=1 AND coalesce(bool_and(k.contype='c' AND k.convalidated \
             AND NOT k.condeferrable AND NOT k.condeferred AND k.conislocal \
             AND k.coninhcount=0 AND pg_get_constraintdef(k.oid,true)=$2),false) \
           FROM pg_constraint k JOIN pg_class c ON c.oid=k.conrelid \
           JOIN pg_namespace n ON n.oid=c.relnamespace \
          WHERE n.nspname=current_schema() AND c.relname='capture_formation_receipts' \
            AND c.relkind='r' AND k.conname=$1",
    )
    .bind(CONSTRAINT_NAME)
    .bind(expected)
    .fetch_one(connection)
    .await?;
    if !valid {
        return Err(EnclaveError::Config(
            "interrupted capture provenance constraint does not match".into(),
        ));
    }
    Ok(())
}

async fn receipt_catalog_digest(connection: &mut PgConnection) -> Result<String> {
    let catalog: String = sqlx::query_scalar(
        "SELECT jsonb_build_object('kind',c.relkind,'persistence',c.relpersistence, \
           'rls',c.relrowsecurity,'force_rls',c.relforcerowsecurity, \
           'columns',(SELECT jsonb_agg(jsonb_build_array(a.attname,format_type(a.atttypid,a.atttypmod), \
              a.attnotnull,pg_get_expr(d.adbin,d.adrelid)) ORDER BY a.attnum) \
              FROM pg_attribute a LEFT JOIN pg_attrdef d ON d.adrelid=a.attrelid AND d.adnum=a.attnum \
              WHERE a.attrelid=c.oid AND a.attnum>0 AND NOT a.attisdropped), \
           'constraints',(SELECT jsonb_agg(jsonb_build_array(k.conname,pg_get_constraintdef(k.oid), \
              k.convalidated,k.condeferrable,k.condeferred) ORDER BY k.conname) \
              FROM pg_constraint k WHERE k.conrelid=c.oid), \
           'indexes',(SELECT jsonb_agg(pg_get_indexdef(i.indexrelid) ORDER BY pg_get_indexdef(i.indexrelid)) \
              FROM pg_index i WHERE i.indrelid=c.oid), \
           'triggers',(SELECT jsonb_agg(jsonb_build_array(pg_get_triggerdef(t.oid),t.tgenabled) \
              ORDER BY t.tgname) FROM pg_trigger t WHERE t.tgrelid=c.oid AND NOT t.tgisinternal))::text \
         FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace \
         WHERE n.nspname=current_schema() AND c.relname='interrupted_capture_schema' AND c.relkind='r'",
    )
    .fetch_one(connection)
    .await?;
    Ok(format!("{:x}", Sha256::digest(catalog.as_bytes())))
}

pub(super) async fn verify(connection: &mut PgConnection) -> Result<()> {
    if !current_schema_relation_exists(connection, "interrupted_capture_schema").await? {
        return Err(EnclaveError::Config(
            "interrupted capture schema must be installed by the reviewed migrator".into(),
        ));
    }
    require_check(connection, CURRENT_CHECK).await?;
    let rows = sqlx::query(
        "SELECT singleton,version,contract_sha256,catalog_sha256 FROM interrupted_capture_schema",
    )
    .fetch_all(&mut *connection)
    .await?;
    let [row] = rows.as_slice() else {
        return Err(EnclaveError::Config(
            "interrupted capture schema must have exactly one receipt".into(),
        ));
    };
    if !row.try_get::<bool, _>("singleton")?
        || row.try_get::<i64, _>("version")? != 29
        || row.try_get::<String, _>("contract_sha256")? != contract_digest()
        || row.try_get::<String, _>("catalog_sha256")? != receipt_catalog_digest(connection).await?
    {
        return Err(EnclaveError::Config(
            "interrupted capture schema receipt does not match".into(),
        ));
    }
    Ok(())
}

pub(super) async fn original_activation_catalog(
    connection: &mut PgConnection,
    current_evidence: String,
) -> Result<String> {
    if !current_schema_relation_exists(connection, "interrupted_capture_schema").await? {
        return Ok(current_evidence);
    }
    // A receipt alone cannot authorize masking any change: require the exact
    // new CHECK plus the independent companion catalog before substituting it.
    verify(connection).await?;
    let mut evidence: Vec<(String, String, String)> = serde_json::from_str(&current_evidence)?;
    let current = format!("c|true|false|false|{CURRENT_CHECK}");
    let prior = format!("c|true|false|false|{PRIOR_CHECK}");
    let mut replaced = 0;
    for (kind, name, definition) in &mut evidence {
        if kind == "constraint" && name == CATALOG_KEY {
            if *definition != current {
                return Err(EnclaveError::Config(
                    "interrupted capture activation catalog anchor changed".into(),
                ));
            }
            *definition = prior.clone();
            replaced += 1;
        }
    }
    if replaced != 1 {
        return Err(EnclaveError::Config(
            "interrupted capture activation catalog anchor is missing".into(),
        ));
    }
    // PostgreSQL, rather than a JSON encoder, supplies the exact old framing.
    Ok(sqlx::query_scalar("SELECT $1::jsonb::text")
        .bind(serde_json::to_string(&evidence)?)
        .fetch_one(connection)
        .await?)
}

impl PostgresPersistence {
    pub(crate) async fn verify_interrupted_capture_schema(&self) -> Result<()> {
        let mut transaction = self.pool().begin().await?;
        activation::lock_activation_contract_key_share_if_installed(&mut transaction).await?;
        verify(&mut transaction).await?;
        transaction.commit().await?;
        Ok(())
    }

    pub(crate) async fn install_interrupted_capture_schema(&self) -> Result<()> {
        let mut transaction = self.pool().begin().await?;
        sqlx::query("SET LOCAL lock_timeout='5s'")
            .execute(&mut *transaction)
            .await?;
        sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,0))")
            .bind(activation::RELEASE_LOCK)
            .execute(&mut *transaction)
            .await?;
        if !activation::activation_contract_exists(&mut transaction).await? {
            return Err(EnclaveError::Config(
                "interrupted capture recovery requires installed v27 activation schema".into(),
            ));
        }
        activation::verify_serving_activation_schema(&mut transaction).await?;
        if current_schema_relation_exists(&mut transaction, "interrupted_capture_schema").await? {
            verify(&mut transaction).await?;
            transaction.commit().await?;
            return Ok(());
        }
        sqlx::query("LOCK TABLE capture_formation_receipts IN ACCESS EXCLUSIVE MODE")
            .execute(&mut *transaction)
            .await?;
        require_check(&mut transaction, PRIOR_CHECK).await?;
        sqlx::raw_sql(INSTALL_SQL)
            .execute(&mut *transaction)
            .await?;
        require_check(&mut transaction, CURRENT_CHECK).await?;
        let catalog = receipt_catalog_digest(&mut transaction).await?;
        sqlx::query("INSERT INTO interrupted_capture_schema(singleton,version,contract_sha256,catalog_sha256) \
            VALUES(true,29,$1,$2)")
            .bind(contract_digest()).bind(catalog).execute(&mut *transaction).await?;
        verify(&mut transaction).await?;
        activation::verify_serving_activation_schema(&mut transaction).await?;
        transaction.commit().await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn populated_interrupted_capture_schema_preserves_history_and_refuses_drift() {
        let Some(fixture) = super::super::tests::test_persistence().await else {
            return;
        };
        let repo = &fixture.persistence;
        assert!(repo.install_interrupted_capture_schema().await.is_err());
        repo.install_memory_reconciliation_activation_schema()
            .await
            .unwrap();
        sqlx::raw_sql(
            "INSERT INTO accounts(id,email,primary_provider,primary_subject) \
             VALUES('interrupted-schema','schema@example.invalid','google','interrupted-schema'); \
             INSERT INTO capture_sessions(account_id,id,device_id,install_id,started_at,last_event_at,ended_at,schema_version) \
             VALUES('interrupted-schema','old-finished','device','install', \
                clock_timestamp()-interval '2 days',clock_timestamp()-interval '2 days', \
                clock_timestamp()-interval '2 days',2); \
             INSERT INTO capture_formation_receipts(account_id,capture_session_id,source_revision, \
                finish_requested_at,finish_request_provenance) \
             VALUES('interrupted-schema','old-finished',1,clock_timestamp()-interval '2 days','finish_endpoint_v1');",
        ).execute(repo.pool()).await.unwrap();
        const HISTORY: &str = "SELECT jsonb_build_object( \
            'marker',(SELECT to_jsonb(s) FROM persistence_schema s), \
            'contract',(SELECT jsonb_agg(to_jsonb(c) ORDER BY feature) FROM persistence_feature_activation_contracts c), \
            'events',(SELECT jsonb_agg(to_jsonb(e) ORDER BY event_sequence) FROM persistence_feature_activation_events e), \
            'formation',(SELECT to_jsonb(r) FROM capture_formation_receipts r WHERE account_id='interrupted-schema'))::text";
        let before: String = sqlx::query_scalar(HISTORY)
            .fetch_one(repo.pool())
            .await
            .unwrap();
        assert!(repo.verify_interrupted_capture_schema().await.is_err());
        repo.install_interrupted_capture_schema().await.unwrap();
        repo.install_interrupted_capture_schema().await.unwrap();
        repo.verify_schema().await.unwrap();
        repo.verify_interrupted_capture_schema().await.unwrap();
        activation::verify_serving_activation_schema(&mut repo.pool().acquire().await.unwrap())
            .await
            .unwrap();
        let after: String = sqlx::query_scalar(HISTORY)
            .fetch_one(repo.pool())
            .await
            .unwrap();
        assert_eq!(
            before, after,
            "installation must not rewrite source or signed history"
        );

        // Every mutation is rolled back. Neither a forged receipt, a weakened
        // CHECK, nor unrelated v27 drift may borrow the normalization path.
        for mutation in [
            "DELETE FROM interrupted_capture_schema",
            "UPDATE interrupted_capture_schema SET contract_sha256='forged'",
            "ALTER TABLE interrupted_capture_schema ADD COLUMN unexpected text",
            "ALTER TABLE capture_formation_receipts DROP CONSTRAINT capture_formation_receipts_finish_request_provenance_check",
            "ALTER TABLE capture_formation_receipts DROP CONSTRAINT capture_formation_receipts_finish_request_provenance_check; \
             ALTER TABLE capture_formation_receipts ADD CONSTRAINT capture_formation_receipts_finish_request_provenance_check CHECK (true)",
        ] {
            let mut tx = repo.pool().begin().await.unwrap();
            sqlx::raw_sql(mutation).execute(&mut *tx).await.unwrap();
            assert!(verify(&mut tx).await.is_err(), "must reject {mutation}");
            tx.rollback().await.unwrap();
        }
        let mut tx = repo.pool().begin().await.unwrap();
        sqlx::raw_sql("ALTER TABLE capture_formation_receipts ADD CONSTRAINT unexpected_companion_bypass CHECK (source_revision>=0)")
            .execute(&mut *tx).await.unwrap();
        assert!(activation::verify_serving_activation_schema(&mut tx)
            .await
            .is_err());
        tx.rollback().await.unwrap();

        let mut tx = repo.pool().begin().await.unwrap();
        sqlx::query("UPDATE capture_formation_receipts SET finish_request_provenance='server_inactivity_v1' \
            WHERE account_id='interrupted-schema'").execute(&mut *tx).await.unwrap();
        assert!(sqlx::query(
            "UPDATE capture_formation_receipts SET finish_request_provenance='unreviewed' \
            WHERE account_id='interrupted-schema'"
        )
        .execute(&mut *tx)
        .await
        .is_err());
        tx.rollback().await.unwrap();
        repo.verify_interrupted_capture_schema().await.unwrap();
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
