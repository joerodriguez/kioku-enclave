//! Signed, bounded migrator-only erasure. No provider credentials, arbitrary SQL,
//! raw export, public source identifiers, or implicit serving mutations.

use serde::Serialize;
use sqlx::{PgConnection, Postgres, Transaction};

use super::{
    orphan_capture_erasure as contract,
    orphan_capture_erasure_authority::{
        digest_bytes, sha256_label, ErasureAction, ErasureOperationBinding, ErasurePrepare,
        VerifiedOrphanErasureRequest,
    },
    orphan_capture_erasure_scope::{self as scope, OrphanScopeReport},
    PostgresPersistence,
};
use crate::error::{EnclaveError, Result};

#[derive(Serialize)]
pub(crate) struct OrphanErasureResult {
    contract: &'static str,
    request_sha256: String,
    erasure_contract_sha256: String,
    pub(super) state: String,
    pub(super) capture_upload_fenced: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) scope: Option<OrphanScopeReport>,
}

fn conflict() -> EnclaveError {
    EnclaveError::Conflict(
        "orphan erasure operation is stale or does not match its durable authority".into(),
    )
}

/// Server bounds remain effective while the client is descheduled. They do not
/// turn a lost COMMIT response into evidence of rollback: recover by exact replay.
pub(super) async fn configure_execution_limits(connection: &mut PgConnection) -> Result<()> {
    configure_execution_bounds(connection, "45s", "15s", "15s").await
}

#[cfg(test)]
pub(super) async fn configure_test_execution_limits(connection: &mut PgConnection) -> Result<()> {
    configure_execution_bounds(connection, "3s", "1s", "1s").await
}

async fn configure_execution_bounds(
    connection: &mut PgConnection,
    transaction_timeout: &'static str,
    statement_timeout: &'static str,
    idle_timeout: &'static str,
) -> Result<()> {
    sqlx::query(
        "SELECT set_config('transaction_timeout',$1,true), \
                set_config('statement_timeout',$2,true), \
                set_config('idle_in_transaction_session_timeout',$3,true), \
                set_config('lock_timeout','250ms',true), \
                set_config('synchronous_commit','on',true)",
    )
    .bind(transaction_timeout)
    .bind(statement_timeout)
    .bind(idle_timeout)
    .execute(&mut *connection)
    .await?;
    let durable: bool = sqlx::query_scalar(
        "SELECT current_setting('fsync')='on' AND current_setting('synchronous_commit')='on'",
    )
    .fetch_one(connection)
    .await?;
    if !durable {
        return Err(EnclaveError::Config(
            "orphan erasure requires synchronous local WAL durability".into(),
        ));
    }
    Ok(())
}

async fn acquire_release_lock(transaction: &mut Transaction<'_, Postgres>) -> Result<()> {
    let acquired: bool =
        sqlx::query_scalar("SELECT pg_try_advisory_xact_lock(hashtextextended($1,0))")
            .bind(super::activation::RELEASE_LOCK)
            .fetch_one(&mut **transaction)
            .await?;
    if !acquired {
        return Err(conflict());
    }
    Ok(())
}

async fn acquire_locks(transaction: &mut Transaction<'_, Postgres>, account: &str) -> Result<()> {
    acquire_release_lock(transaction).await?;
    // Do not wait under the exclusive activation lock for a worker which may
    // require its shared counterpart to settle. Retention precedes account row.
    for namespace in [
        "account-lifecycle",
        "memory-reconciliation",
        "recording-retention",
    ] {
        let acquired: bool =
            sqlx::query_scalar("SELECT pg_try_advisory_xact_lock(hashtextextended($1,12648430))")
                .bind(format!("{namespace}\u{1f}{account}"))
                .fetch_one(&mut **transaction)
                .await?;
        if !acquired {
            return Err(conflict());
        }
    }
    let active: Option<bool> =
        sqlx::query_scalar("SELECT status='active' FROM accounts WHERE id=$1 FOR UPDATE NOWAIT")
            .bind(account)
            .fetch_optional(&mut **transaction)
            .await?;
    if active != Some(true) {
        return Err(conflict());
    }
    Ok(())
}

async fn matching_replay(
    connection: &mut PgConnection,
    authority: &VerifiedOrphanErasureRequest,
) -> Result<bool> {
    if !contract::verify_schema_if_installed(connection).await? {
        return Ok(false);
    }
    let column = match &authority.request.action {
        ErasureAction::InstallSchema | ErasureAction::Inspect(_) => return Ok(false),
        ErasureAction::Prepare(_) => "request_sha256",
        ErasureAction::AcknowledgeProvider(_) => "provider_ack_request_sha256",
        ErasureAction::Finalize(_) => "completion_request_sha256",
        ErasureAction::ReleaseFence(_) => "fence_release_request_sha256",
    };
    // column is selected solely by the closed signed action enum above.
    let digest = sqlx::query_scalar::<_, Option<Vec<u8>>>(sqlx::AssertSqlSafe(format!(
        "SELECT {column} FROM orphan_capture_erasure_operations WHERE account_id=$1 AND operation_id=$2")))
        .bind(&authority.request.account_id).bind(&authority.request.operation_id)
        .fetch_optional(connection).await?.flatten();
    if let Some(digest) = digest {
        if digest != authority.request_sha256 {
            return Err(conflict());
        }
        return Ok(true);
    }
    Ok(false)
}

async fn require_operation(
    connection: &mut PgConnection,
    authority: &VerifiedOrphanErasureRequest,
    binding: &ErasureOperationBinding,
    expected_state: &str,
) -> Result<()> {
    contract::require_runtime_schema(connection).await?;
    let matched = sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS(SELECT 1 FROM orphan_capture_erasure_operations WHERE account_id=$1 AND operation_id=$2 \
          AND request_sha256=$3 AND scope_sha256=$4 AND object_inventory_sha256=$5 AND state=$6 \
          AND provider_names_sha256=$7 AND account_provider_names_sha256=$8 AND capture_upload_fenced)")
        .bind(&authority.request.account_id).bind(&authority.request.operation_id)
        .bind(digest_bytes(&binding.prepare_request_sha256)?).bind(digest_bytes(&binding.scope_sha256)?)
        .bind(digest_bytes(&binding.object_inventory_sha256)?).bind(expected_state)
        .bind(digest_bytes(&binding.provider_names_sha256)?)
        .bind(digest_bytes(&binding.account_provider_names_sha256)?).fetch_one(connection).await?;
    if !matched {
        return Err(conflict());
    }
    Ok(())
}

async fn require_structured_absence(
    connection: &mut PgConnection,
    account: &str,
    operation: &str,
) -> Result<()> {
    let remains: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM capture_sessions c JOIN orphan_capture_erasure_sessions e \
          ON e.account_id=c.account_id AND e.capture_session_id=c.id WHERE e.account_id=$1 AND e.operation_id=$2) \
          OR EXISTS(SELECT 1 FROM capture_streams c JOIN orphan_capture_erasure_streams e \
          ON e.account_id=c.account_id AND e.stream_id=c.id WHERE e.account_id=$1 AND e.operation_id=$2) \
          OR EXISTS(SELECT 1 FROM capture_events c JOIN orphan_capture_erasure_events e \
          ON e.account_id=c.account_id AND (e.event_id=c.event_id OR e.asset_id=c.asset_id \
            OR e.event_id=c.canonical_event_id OR e.asset_id=c.canonical_asset_id) WHERE e.account_id=$1 AND e.operation_id=$2) \
          OR EXISTS(SELECT 1 FROM media_objects m JOIN orphan_capture_erasure_events e \
          ON e.account_id=m.account_id AND e.asset_id=m.asset_id WHERE e.account_id=$1 AND e.operation_id=$2) \
          OR EXISTS(SELECT 1 FROM utterances u JOIN orphan_capture_erasure_events e \
          ON e.account_id=u.account_id AND e.event_id=split_part(substr(u.source_key,10),':',1) \
          WHERE e.account_id=$1 AND e.operation_id=$2 AND u.source_key LIKE 'cloud-v2:%') \
          OR EXISTS(SELECT 1 FROM screenshots s JOIN orphan_capture_erasure_events e \
          ON e.account_id=s.account_id AND e.event_id=substr(s.source_key,10) \
          WHERE e.account_id=$1 AND e.operation_id=$2 AND s.source_key LIKE 'cloud-v2:%')")
        .bind(account).bind(operation).fetch_one(connection).await?;
    if remains {
        return Err(conflict());
    }
    Ok(())
}

async fn prepare(
    transaction: &mut Transaction<'_, Postgres>,
    authority: &VerifiedOrphanErasureRequest,
    request: &ErasurePrepare,
) -> Result<()> {
    contract::require_runtime_schema(transaction).await?;
    let account = &authority.request.account_id;
    let operation = &authority.request.operation_id;
    let selected = scope::inspect_scope(transaction, account, &request.targets).await?;
    let evidence = &selected.report;
    if evidence.counts != request.counts
        || evidence.scope_sha256 != request.scope_sha256
        || evidence.object_inventory_sha256 != request.object_inventory_sha256
        || evidence.provider_names_sha256 != request.provider_names_sha256
        || evidence.provider_name_count != request.provider_name_count
        || evidence.account_provider_names_sha256 != request.account_provider_names_sha256
        || evidence.survivor_sha256 != request.survivor_sha256
        || evidence.protected_control_proof_sha256 != request.protected_control_proof_sha256
    {
        return Err(conflict());
    }
    let activation = &authority.request.activation;
    sqlx::query(
        "INSERT INTO orphan_capture_erasure_operations(account_id,operation_id,request_sha256,request_signature, \
          request_key_sha256,scope_sha256,object_inventory_sha256,survivor_sha256,activation_generation, \
          candidate_image_digest,activation_contract_sha256,activation_catalog_sha256,activation_receipt_sha256, \
          provider_authority_sha256,protected_control_proof_sha256,session_count,stream_count,event_count,object_count,projection_count, \
          provider_names_sha256,provider_name_count,account_provider_names_sha256) \
          VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23)")
        .bind(account).bind(operation).bind(&authority.request_sha256).bind(&authority.signature).bind(&authority.key_sha256)
        .bind(digest_bytes(&request.scope_sha256)?).bind(digest_bytes(&request.object_inventory_sha256)?)
        .bind(digest_bytes(&request.survivor_sha256)?).bind(activation.generation).bind(&activation.candidate_image_digest)
        .bind(digest_bytes(&activation.contract_sha256)?).bind(digest_bytes(&activation.catalog_sha256)?)
        .bind(digest_bytes(&activation.receipt_sha256)?).bind(digest_bytes(&request.provider_authority_sha256)?)
        .bind(digest_bytes(&request.protected_control_proof_sha256)?).bind(request.counts.sessions).bind(request.counts.streams)
        .bind(request.counts.events).bind(request.counts.objects).bind(request.counts.projections)
        .bind(digest_bytes(&request.provider_names_sha256)?).bind(request.provider_name_count)
        .bind(digest_bytes(&request.account_provider_names_sha256)?)
        .execute(&mut **transaction).await?;
    for query in [
        "INSERT INTO orphan_capture_erasure_sessions(account_id,capture_session_id,operation_id) \
         SELECT account_id,id,$2 FROM capture_sessions WHERE account_id=$1 AND ($3::jsonb->'sessions') ? id",
        "INSERT INTO orphan_capture_erasure_streams(account_id,stream_id,capture_session_id,operation_id) \
         SELECT account_id,id,capture_session_id,$2 FROM capture_streams WHERE account_id=$1 AND ($3::jsonb->'streams') ? id",
        "INSERT INTO orphan_capture_erasure_events(account_id,event_id,asset_id,stream_id,capture_session_id,operation_id) \
         SELECT account_id,event_id,asset_id,stream_id,capture_session_id,$2 FROM capture_events \
         WHERE account_id=$1 AND ($3::jsonb->'events') ? event_id",
        "INSERT INTO orphan_capture_erasure_objects(account_id,operation_id,object_key,object_generation,event_id,asset_id,byte_length,original_sha256) \
         SELECT account_id,$2,object_key,object_generation,event_id,asset_id,byte_length,sha256 FROM media_objects \
         WHERE account_id=$1 AND ($3::jsonb->'events') ? event_id",
    ] {
        sqlx::query(query).bind(account).bind(operation).bind(&selected.identities).execute(&mut **transaction).await?;
    }
    // References to projections are proven absent. Session parents own the
    // genuine cascade; no accepted-sequence tombstone or fabricated finish.
    for (table, predicate) in [
        ("utterances", "($2->'utterances') ? id::text"),
        ("audio_segments", "($2->'segments') ? id::text"),
        ("screenshots", "($2->'screenshots') ? id::text"),
        ("media_work_units", "($2->'works') ? id"),
        (
            "outbox_events",
            "event_kind='capture_media_queued' AND ($2->'events') ? aggregate_id",
        ),
        (
            "capture_reference_batch_receipts",
            "($2->'batches') ? batch_id",
        ),
        ("capture_sessions", "($2->'sessions') ? id"),
        ("browser_states_v2", "($2->'browser_states') ? state_key"),
    ] {
        // table/predicate are fixed literals; private selectors are bound JSON.
        let predicate = predicate.replace("$2->", "$2::jsonb->");
        sqlx::query(sqlx::AssertSqlSafe(format!(
            "DELETE FROM {table} WHERE account_id=$1 AND {predicate}"
        )))
        .bind(account)
        .bind(&selected.identities)
        .execute(&mut **transaction)
        .await?;
    }
    let (_, survivor, remaining) =
        scope::partition_commitments(transaction, account, &selected.identities).await?;
    if remaining != 0
        || survivor != request.survivor_sha256
        || scope::protected_control_proof(
            transaction,
            account,
            request.targets.protected_episode_id,
        )
        .await?
            != request.protected_control_proof_sha256
    {
        return Err(conflict());
    }
    sqlx::query("UPDATE orphan_capture_erasure_operations SET state='provider_pending' WHERE account_id=$1 AND operation_id=$2")
        .bind(account).bind(operation).execute(&mut **transaction).await?;
    Ok(())
}

impl PostgresPersistence {
    pub(crate) async fn execute_orphan_capture_erasure(
        &self,
        authority: &VerifiedOrphanErasureRequest,
    ) -> Result<OrphanErasureResult> {
        // Driver errors can contain private constraint values. The public
        // migrator deliberately emits only a fixed failure, never a SQL error.
        self.execute_orphan_capture_erasure_inner(authority).await.map_err(|_| {
            EnclaveError::Store("owner-authorized capture erasure refused; no unreceipted mutation is committed".into())
        })
    }

    // Keep the closed controller's comparatively large state on the heap,
    // including for callers that need its unredacted synthetic-test failures.
    pub(super) fn execute_orphan_capture_erasure_inner<'a>(
        &'a self,
        authority: &'a VerifiedOrphanErasureRequest,
    ) -> std::pin::Pin<
        Box<impl std::future::Future<Output = Result<OrphanErasureResult>> + Send + 'a>,
    > {
        Box::pin(async move {
            let mut transaction = self.pool().begin().await?;
            configure_execution_limits(&mut transaction).await?;
            let account = &authority.request.account_id;
            let operation = &authority.request.operation_id;
            let install_only = matches!(authority.request.action, ErasureAction::InstallSchema);
            if install_only {
                acquire_release_lock(&mut transaction).await?;
            } else {
                acquire_locks(&mut transaction, account).await?;
            }
            let replay = matching_replay(&mut transaction, authority).await?;
            let mut inspected = None;
            let mut installed = None;
            if !replay {
                authority.require_fresh(&mut transaction).await?;
                super::activation::verify_erasure_activation_binding(
                    &mut transaction,
                    &authority.request.activation,
                )
                .await?;
                match &authority.request.action {
                    ErasureAction::InstallSchema => {
                        let exists = contract::verify_schema_if_installed(&mut transaction).await?;
                        contract::install_schema_in_locked_transaction(&mut transaction).await?;
                        super::activation::verify_erasure_activation_binding(
                            &mut transaction,
                            &authority.request.activation,
                        )
                        .await?;
                        installed = Some(if exists {
                            "already_installed"
                        } else {
                            "installed"
                        });
                    }
                    ErasureAction::Inspect(targets) => {
                        inspected = Some(
                            scope::inspect_scope(&mut transaction, account, targets)
                                .await?
                                .report,
                        );
                    }
                    ErasureAction::Prepare(request) => {
                        prepare(&mut transaction, authority, request).await?
                    }
                    ErasureAction::AcknowledgeProvider(ack) => {
                        require_operation(
                            &mut transaction,
                            authority,
                            &ack.operation,
                            "provider_pending",
                        )
                        .await?;
                        require_structured_absence(&mut transaction, account, operation).await?;
                        sqlx::query("UPDATE orphan_capture_erasure_operations SET state='provider_verified', \
                      provider_ack_request_sha256=$3,provider_ack_signature=$4,provider_receipt_sha256=$5 \
                      WHERE account_id=$1 AND operation_id=$2")
                        .bind(account).bind(operation).bind(&authority.request_sha256).bind(&authority.signature)
                        .bind(digest_bytes(&ack.provider_receipt_sha256)?).execute(&mut *transaction).await?;
                    }
                    ErasureAction::Finalize(finalize) => {
                        require_operation(
                            &mut transaction,
                            authority,
                            &finalize.operation,
                            "provider_verified",
                        )
                        .await?;
                        require_structured_absence(&mut transaction, account, operation).await?;
                        let proof = scope::protected_control_proof(
                            &mut transaction,
                            account,
                            finalize.protected_episode_id,
                        )
                        .await?;
                        let matched: bool = sqlx::query_scalar("SELECT provider_ack_request_sha256=$3 AND protected_control_proof_sha256=$4 \
                        FROM orphan_capture_erasure_operations WHERE account_id=$1 AND operation_id=$2")
                        .bind(account).bind(operation).bind(digest_bytes(&finalize.provider_ack_request_sha256)?)
                        .bind(digest_bytes(&proof)?).fetch_one(&mut *transaction).await?;
                        if !matched {
                            return Err(conflict());
                        }
                        sqlx::query("DELETE FROM orphan_capture_erasure_objects WHERE account_id=$1 AND operation_id=$2")
                        .bind(account).bind(operation).execute(&mut *transaction).await?;
                        sqlx::query("UPDATE orphan_capture_erasure_operations SET state='complete',completion_request_sha256=$3,completion_signature=$4 \
                         WHERE account_id=$1 AND operation_id=$2")
                        .bind(account).bind(operation).bind(&authority.request_sha256).bind(&authority.signature)
                        .execute(&mut *transaction).await?;
                    }
                    ErasureAction::ReleaseFence(release) => {
                        require_operation(
                            &mut transaction,
                            authority,
                            &release.operation,
                            "complete",
                        )
                        .await?;
                        require_structured_absence(&mut transaction, account, operation).await?;
                        let matched: bool = sqlx::query_scalar("SELECT completion_request_sha256=$3 AND activation_generation<$4 \
                      AND candidate_image_digest<>$5 FROM orphan_capture_erasure_operations WHERE account_id=$1 AND operation_id=$2")
                        .bind(account).bind(operation).bind(digest_bytes(&release.completion_request_sha256)?)
                        .bind(authority.request.activation.generation).bind(&authority.request.activation.candidate_image_digest)
                        .fetch_one(&mut *transaction).await?;
                        if !matched {
                            return Err(conflict());
                        }
                        contract::require_no_pending_erasures(&mut transaction).await?;
                        sqlx::query("UPDATE orphan_capture_erasure_operations SET capture_upload_fenced=false, \
                      fence_release_request_sha256=$3,fence_release_signature=$4,fence_release_generation=$5, \
                      fence_release_candidate_image_digest=$6,fence_release_activation_receipt_sha256=$7, \
                      fence_release_fleet_evidence_sha256=$8,fence_release_protected_canary_sha256=$9, \
                      fence_release_admission_contract_sha256=$10 WHERE account_id=$1 AND operation_id=$2")
                        .bind(account).bind(operation).bind(&authority.request_sha256).bind(&authority.signature)
                        .bind(authority.request.activation.generation).bind(&authority.request.activation.candidate_image_digest)
                        .bind(digest_bytes(&authority.request.activation.receipt_sha256)?)
                        .bind(digest_bytes(&release.fleet_evidence_sha256)?)
                        .bind(digest_bytes(&release.protected_canary_evidence_sha256)?)
                        .bind(digest_bytes(&release.admission_contract_sha256)?)
                        .execute(&mut *transaction).await?;
                    }
                }
            }
            let (state, fenced) = if inspected.is_some() || installed.is_some() {
                let fenced = if contract::verify_schema_if_installed(&mut transaction).await? {
                    sqlx::query_scalar::<_,bool>("SELECT EXISTS(SELECT 1 FROM orphan_capture_erasure_operations WHERE ($2 OR account_id=$1) AND capture_upload_fenced)")
                    .bind(account).bind(install_only).fetch_one(&mut *transaction).await?
                } else {
                    false
                };
                (installed.unwrap_or("inspected").to_owned(), fenced)
            } else {
                sqlx::query_as::<_,(String,bool)>("SELECT state,capture_upload_fenced FROM orphan_capture_erasure_operations WHERE account_id=$1 AND operation_id=$2")
                .bind(account).bind(operation).fetch_one(&mut *transaction).await?
            };
            let result = OrphanErasureResult {
                contract: "kioku.postgresql.orphan-capture-erasure-result.v1",
                request_sha256: sha256_label(&authority.request_sha256),
                erasure_contract_sha256: sha256_label(&contract::contract_digest()),
                state,
                capture_upload_fenced: fenced,
                scope: inspected,
            };
            if !replay {
                // Scope hashing/DDL/cascades may take appreciable time. Admission
                // freshness is not a WAL deadline. Finish deferred checks before
                // rechecking database time, leaving only this read and COMMIT.
                sqlx::query("SET CONSTRAINTS ALL IMMEDIATE")
                    .execute(&mut *transaction)
                    .await?;
                authority.require_fresh(&mut transaction).await?;
            }
            transaction.commit().await?;
            Ok(result)
        })
    }
}
