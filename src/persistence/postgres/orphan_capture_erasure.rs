//! Optional additive orphan-erasure admission. The signed migrator is the only
//! installer; serving never creates tables or performs a cleanup implicitly.

use sha2::{Digest, Sha256};
use sqlx::Row;

use crate::{
    error::{EnclaveError, Result},
    persistence::CaptureUploadIdentity,
};

const INSTALL_SQL: &str = include_str!("../../../migrations/0027_orphan_capture_erasure.sql");
const CATALOG_SQL: &str = include_str!("orphan_capture_erasure_catalog.sql");
const CONTRACT_DOMAIN: &[u8] = b"kioku.postgresql.orphan-capture-erasure.ddl.v1\0";

pub(super) fn contract_digest() -> Vec<u8> {
    let mut hash = Sha256::new();
    hash.update(CONTRACT_DOMAIN);
    hash.update(INSTALL_SQL.as_bytes());
    hash.finalize().to_vec()
}

async fn catalog_digest(connection: &mut sqlx::PgConnection) -> Result<Vec<u8>> {
    let evidence = sqlx::query_scalar::<_, String>(CATALOG_SQL)
        .fetch_one(connection)
        .await?;
    Ok(Sha256::digest(evidence.as_bytes()).to_vec())
}

/// The optional schema has an independent immutable receipt. A partially
/// installed or changed namespace is never treated as the pre-install state.
async fn schema_receipt_present(connection: &mut sqlx::PgConnection) -> Result<bool> {
    let present =
        super::current_schema_relation_exists(connection, "orphan_capture_erasure_contract")
            .await?;
    if !present {
        let unexpected = sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS(SELECT 1 FROM pg_class relation \
                 JOIN pg_namespace namespace ON namespace.oid=relation.relnamespace \
                 WHERE namespace.nspname=current_schema() \
                   AND relation.relname LIKE 'orphan\\_capture\\_erasure\\_%' ESCAPE '\\') \
                 OR EXISTS(SELECT 1 FROM pg_proc function_state \
                 JOIN pg_namespace namespace ON namespace.oid=function_state.pronamespace \
                 WHERE namespace.nspname=current_schema() \
                   AND function_state.proname LIKE 'orphan\\_capture\\_erasure\\_%' ESCAPE '\\') \
                 OR EXISTS(SELECT 1 FROM pg_trigger trigger_state \
                 JOIN pg_class relation ON relation.oid=trigger_state.tgrelid \
                 JOIN pg_namespace namespace ON namespace.oid=relation.relnamespace \
                 WHERE namespace.nspname=current_schema() AND NOT trigger_state.tgisinternal \
                   AND trigger_state.tgname LIKE 'orphan\\_capture\\_erasure\\_%' ESCAPE '\\')",
        )
        .fetch_one(connection)
        .await?;
        if unexpected {
            return Err(EnclaveError::Config(
                "orphan erasure namespace has no authority receipt".into(),
            ));
        }
    }
    Ok(present)
}

pub(super) async fn verify_schema_if_installed(
    connection: &mut sqlx::PgConnection,
) -> Result<bool> {
    if !schema_receipt_present(connection).await? {
        return Ok(false);
    }
    let receipt = sqlx::query(
        "SELECT ddl_sha256,catalog_sha256 FROM orphan_capture_erasure_contract WHERE singleton=true",
    )
    .fetch_optional(&mut *connection)
    .await?
    .ok_or_else(|| EnclaveError::Config("orphan erasure schema receipt is missing".into()))?;
    if receipt.try_get::<Vec<u8>, _>("ddl_sha256")? != contract_digest()
        || receipt.try_get::<Vec<u8>, _>("catalog_sha256")? != catalog_digest(connection).await?
    {
        return Err(EnclaveError::Config(
            "orphan erasure schema differs from its reviewed contract".into(),
        ));
    }
    Ok(true)
}

/// This image cannot serve without the independent replay-barrier contract.
/// Optional verification exists only for the migrator's pre-install inspection.
pub(super) async fn require_runtime_schema(connection: &mut sqlx::PgConnection) -> Result<()> {
    if !verify_schema_if_installed(connection).await? {
        return Err(EnclaveError::Config(
            "orphan erasure admission contract is not installed".into(),
        ));
    }
    Ok(())
}

pub(super) async fn require_no_pending_erasures(connection: &mut sqlx::PgConnection) -> Result<()> {
    require_runtime_schema(connection).await?;
    if sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS(SELECT 1 FROM orphan_capture_erasure_operations WHERE state<>'complete')",
    )
    .fetch_one(connection)
    .await?
    {
        return Err(EnclaveError::Conflict(
            "activation refuses incomplete owner-authorized capture erasure".into(),
        ));
    }
    Ok(())
}

/// Called only by the separately authorized migrator after it holds the
/// activation lock and verifies the signed operation. No serving caller.
pub(super) async fn install_schema_in_locked_transaction(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
) -> Result<()> {
    if verify_schema_if_installed(transaction).await? {
        return Ok(());
    }
    sqlx::raw_sql(INSTALL_SQL)
        .execute(&mut **transaction)
        .await?;
    let catalog = catalog_digest(transaction).await?;
    sqlx::query(
        "INSERT INTO orphan_capture_erasure_contract(singleton,ddl_sha256,catalog_sha256) \
         VALUES(true,$1,$2)",
    )
    .bind(contract_digest())
    .bind(catalog)
    .execute(&mut **transaction)
    .await?;
    verify_schema_if_installed(transaction).await?;
    Ok(())
}

/// Called by preflight before billing, and again by upload reservation while
/// holding the account row lock shared with erasure preparation. The latter
/// closes the preflight/prepare race before any external object write.
pub(super) async fn require_capture_admission(
    connection: &mut sqlx::PgConnection,
    account_id: &str,
    identity: CaptureUploadIdentity<'_>,
    canonical_event_id: Option<&str>,
) -> Result<()> {
    let installed = schema_receipt_present(connection).await?;
    if !installed {
        return Err(EnclaveError::Config(
            "orphan erasure admission contract is not installed".into(),
        ));
    }
    let fenced = sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS(SELECT 1 FROM orphan_capture_erasure_operations \
                       WHERE account_id=$1 AND capture_upload_fenced) \
             OR EXISTS(SELECT 1 FROM orphan_capture_erasure_sessions \
                        WHERE account_id=$1 AND capture_session_id=$2) \
             OR EXISTS(SELECT 1 FROM orphan_capture_erasure_streams \
                        WHERE account_id=$1 AND stream_id=$3) \
             OR EXISTS(SELECT 1 FROM orphan_capture_erasure_events \
                        WHERE account_id=$1 AND (event_id=$4 OR asset_id=$5 OR event_id=$6))",
    )
    .bind(account_id)
    .bind(identity.capture_session_id)
    .bind(identity.stream_id)
    .bind(identity.event_id)
    .bind(identity.asset_id)
    .bind(canonical_event_id)
    .fetch_one(connection)
    .await?;
    if fenced {
        return Err(EnclaveError::Conflict(
            "capture is fenced by owner-authorized erasure".into(),
        ));
    }
    Ok(())
}
