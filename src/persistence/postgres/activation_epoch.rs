//! One-time signed v1 Draining/g1 -> v2 Draining/g2 catalog evolution.
//! Original contract row, installer, and historical event bytes are retained.
use super::*;
use serde_json::{json, Value};

const UPGRADE_SQL: &str =
    include_str!("../../../migrations/0027_memory_reconciliation_activation_epoch.sql");
const EPOCH_CATALOG_SQL: &str = include_str!("activation_epoch_catalog.sql");
const APPEND_FUNCTION_NAME: &str = "append_persistence_feature_activation_event.";

pub(super) fn contract_digest() -> Vec<u8> {
    let mut digest = Sha256::new();
    digest.update(b"kioku.postgresql.memory-reconciliation-activation.epoch.v2\0");
    for part in [
        activation_contract_digest(),
        UPGRADE_SQL.as_bytes().to_vec(),
        EPOCH_CATALOG_SQL.as_bytes().to_vec(),
    ] {
        digest.update((part.len() as u64).to_be_bytes());
        digest.update(part);
    }
    digest.finalize().to_vec()
}

pub(super) async fn present(connection: &mut PgConnection) -> Result<bool> {
    let present = super::super::current_schema_relation_exists(
        connection,
        "reconciliation_activation_epoch_contract",
    )
    .await?;
    if !present {
        let other_objects: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
              WHERE n.nspname=current_schema() AND c.relname LIKE 'reconciliation\\_activation\\_epoch\\_%' ESCAPE '\\')
             OR EXISTS(SELECT 1 FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
              WHERE n.nspname=current_schema() AND p.proname LIKE 'reconciliation\\_activation\\_epoch\\_%' ESCAPE '\\')
             OR EXISTS(SELECT 1 FROM pg_trigger t JOIN pg_class c ON c.oid=t.tgrelid
              JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname=current_schema()
               AND NOT t.tgisinternal AND t.tgname LIKE 'reconciliation\\_activation\\_epoch\\_%' ESCAPE '\\')
             OR EXISTS(SELECT 1 FROM pg_type t JOIN pg_namespace n ON n.oid=t.typnamespace
              WHERE n.nspname=current_schema() AND (t.typname LIKE 'reconciliation\\_activation\\_epoch\\_%' ESCAPE '\\'
                OR t.typname LIKE '\\_reconciliation\\_activation\\_epoch\\_%' ESCAPE '\\'))")
            .fetch_one(connection).await?;
        if other_objects {
            return Err(EnclaveError::Config(
                "activation epoch namespace is incomplete".into(),
            ));
        }
    }
    Ok(present)
}

pub(super) async fn catalog_digest(
    connection: &mut PgConnection,
    base_evidence: &str,
) -> Result<Vec<u8>> {
    let epoch_evidence: String = sqlx::query_scalar(EPOCH_CATALOG_SQL)
        .fetch_one(connection)
        .await?;
    let mut digest = Sha256::new();
    digest.update(b"kioku.postgresql.memory-reconciliation-activation.catalog.v2\0");
    for part in [base_evidence, epoch_evidence.as_str()] {
        digest.update((part.len() as u64).to_be_bytes());
        digest.update(part.as_bytes());
    }
    Ok(digest.finalize().to_vec())
}

async fn prior_catalog_digest(
    connection: &mut PgConnection,
    base_evidence: &str,
    prior_definition: &str,
) -> Result<Vec<u8>> {
    let mut evidence: Vec<(String, String, String)> = serde_json::from_str(base_evidence)?;
    let mut replaced = 0;
    for (kind, name, definition) in &mut evidence {
        if kind == "function" && name == APPEND_FUNCTION_NAME {
            *definition = prior_definition.into();
            replaced += 1;
        }
    }
    if replaced != 1 {
        return Err(EnclaveError::Config(
            "activation epoch original function anchor is missing".into(),
        ));
    }
    // Preserve PostgreSQL's original canonical jsonb text framing exactly.
    let prior: String = sqlx::query_scalar("SELECT $1::jsonb::text")
        .bind(serde_json::to_string(&evidence)?)
        .fetch_one(connection)
        .await?;
    Ok(Sha256::digest(prior.as_bytes()).to_vec())
}

pub(super) struct EpochContext {
    pub(super) prior_catalog: Vec<u8>,
    pub(super) current_catalog: Vec<u8>,
    pub(super) authorization: VerifiedMemoryReconciliationActivationReceipt,
}

pub(super) async fn verified_context(
    connection: &mut PgConnection,
    base_evidence: &str,
) -> Result<Option<EpochContext>> {
    if !present(connection).await? {
        return Ok(None);
    }
    let rows = sqlx::query("SELECT feature,generation,prior_append_definition,receipt::text,
        receipt_sha256,receipt_signature,receipt_key_sha256 FROM reconciliation_activation_epoch_contract")
        .fetch_all(&mut *connection).await?;
    let [row] = rows.as_slice() else {
        return Err(EnclaveError::Config(
            "activation epoch must contain exactly one authority".into(),
        ));
    };
    let receipt = serde_json::from_str(&row.try_get::<String, _>("receipt")?)?;
    let signature =
        MemoryReconciliationActivationSignature::from_bytes(row.try_get("receipt_signature")?)?;
    let authorization =
        super::super::schema_release::verify_memory_reconciliation_activation_authorization(
            receipt, signature,
        )?;
    let signed = authorization.receipt();
    let Some(prior) = &signed.epoch_upgrade else {
        return Err(EnclaveError::Config(
            "activation epoch upgrade binding is missing".into(),
        ));
    };
    let prior_catalog = prior_catalog_digest(
        connection,
        base_evidence,
        &row.try_get::<String, _>("prior_append_definition")?,
    )
    .await?;
    let current_catalog = catalog_digest(connection, base_evidence).await?;
    if row.try_get::<String, _>("feature")? != FEATURE
        || row.try_get::<i64, _>("generation")? != 2
        || signed.generation != 2
        || signed.contract_version != 2
        || prior.prior_contract_sha256 != sha256_label(&activation_contract_digest())
        || prior.prior_catalog_sha256 != sha256_label(&prior_catalog)
        || signed.activation_contract_sha256 != sha256_label(&contract_digest())
        || signed.activation_catalog_sha256 != sha256_label(&current_catalog)
        || row.try_get::<Vec<u8>, _>("receipt_sha256")?
            != Sha256::digest(authorization.canonical_bytes()).to_vec()
        || row.try_get::<Vec<u8>, _>("receipt_key_sha256")? != authorization.key_sha256()
    {
        return Err(EnclaveError::Config(
            "activation epoch catalog or signed authority changed".into(),
        ));
    }
    Ok(Some(EpochContext {
        prior_catalog,
        current_catalog,
        authorization,
    }))
}

fn require_dormant_predecessor(current: &ActivationState) -> Result<()> {
    if current.generation != 1 || current.phase != MemoryReconciliationActivationPhase::Draining {
        return Err(EnclaveError::Conflict(
            "activation epoch requires the original dormant Draining generation".into(),
        ));
    }
    Ok(())
}

async fn prior_definition(connection: &mut PgConnection) -> Result<String> {
    Ok(sqlx::query_scalar(
        "SELECT pg_get_functiondef(p.oid) FROM pg_proc p
        JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname=current_schema()
        AND p.proname='append_persistence_feature_activation_event' AND p.pronargs=0",
    )
    .fetch_one(connection)
    .await?)
}

pub(super) async fn prepare_upgrade(
    connection: &mut PgConnection,
    current: &ActivationState,
    signed: &super::super::schema_release::MemoryReconciliationActivationReceipt,
) -> Result<String> {
    require_dormant_predecessor(current)?;
    if present(connection).await? {
        return Err(EnclaveError::Conflict(
            "activation epoch already exists".into(),
        ));
    }
    let prior = signed.epoch_upgrade.as_ref().ok_or_else(|| {
        EnclaveError::Config("signed activation epoch predecessor is required".into())
    })?;
    if signed.contract_version != 2
        || signed.generation != 2
        || signed.previous_phase != "draining"
        || signed.requested_phase != "draining"
        || prior.prior_contract_sha256 != sha256_label(&activation_contract_digest())
        || prior.prior_catalog_sha256 != sha256_label(&super::catalog_digest(connection).await?)
        || current
            .receipt_sha256
            .as_deref()
            .map(sha256_label)
            .as_deref()
            != Some(&prior.prior_receipt_sha256)
        || current.candidate_fleet_image_digest.as_deref()
            != Some(&prior.prior_candidate_fleet_image_digest)
        || signed.rollout_basis_points != current.rollout_basis_points
        || signed.rollout_seed != current.rollout_seed
        || signed.explicit_canary_account_ids != current.explicit_canary_account_ids
        || current.reconciliation_producer_contract_sha256.as_deref()
            != Some(&signed.reconciliation_producer_contract_sha256)
        || current.reconciliation_model.as_deref() != Some(&signed.reconciliation_model)
        || current.vertex_location.as_deref() != Some(&signed.vertex_location)
    {
        return Err(EnclaveError::Conflict(
            "signed activation epoch does not preserve the exact predecessor".into(),
        ));
    }
    let prior_definition = prior_definition(connection).await?;
    sqlx::raw_sql(UPGRADE_SQL).execute(connection).await?;
    Ok(prior_definition)
}

pub(super) async fn append_authority(
    connection: &mut PgConnection,
    authorization: &VerifiedMemoryReconciliationActivationReceipt,
    prior_definition: &str,
) -> Result<()> {
    let receipt = std::str::from_utf8(authorization.canonical_bytes()).map_err(|_| {
        EnclaveError::Config("activation epoch receipt is not canonical UTF-8".into())
    })?;
    sqlx::query(
        "INSERT INTO reconciliation_activation_epoch_contract(feature,generation,
        prior_append_definition,receipt,receipt_sha256,receipt_signature,receipt_key_sha256)
        VALUES($1,2,$2,$3::jsonb,$4,$5,$6)",
    )
    .bind(FEATURE)
    .bind(prior_definition)
    .bind(receipt)
    .bind(Sha256::digest(authorization.canonical_bytes()).to_vec())
    .bind(authorization.signature_bytes())
    .bind(authorization.key_sha256())
    .execute(connection)
    .await?;
    Ok(())
}

impl PostgresPersistence {
    /// Transactional catalog preview only: fixed DDL, no event/data changes,
    /// and unconditional rollback before the content-free proposal is returned.
    pub(crate) async fn preview_memory_reconciliation_activation_epoch(&self) -> Result<Value> {
        // Hold the observer before beginning the DDL transaction so a pool
        // cannot recycle that transaction's physical backend for readback.
        let mut observer = self.pool().acquire().await?;
        let mut tx = self.pool().begin().await?;
        let observer_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
            .fetch_one(&mut *observer)
            .await?;
        let preview_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
            .fetch_one(&mut *tx)
            .await?;
        if observer_pid == preview_pid {
            return Err(EnclaveError::Config(
                "activation epoch preview requires a separate readback backend".into(),
            ));
        }
        sqlx::raw_sql(
            "SET LOCAL lock_timeout='2s'; SET LOCAL statement_timeout='15s';
            SET LOCAL idle_in_transaction_session_timeout='30s'",
        )
        .execute(&mut *tx)
        .await?;
        sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,0))")
            .bind(RELEASE_LOCK)
            .execute(&mut *tx)
            .await?;
        let result = async {
            let (base,current) = verify_activation_and_base_release(&mut tx).await?;
            require_dormant_predecessor(&current)?;
            if present(&mut tx).await? {
                return Err(EnclaveError::Conflict("activation epoch already exists".into()));
            }
            require_formation_backfill_complete(&mut tx, Some(1)).await?;
            require_finalization_claim_drain_complete(&mut tx, Some(1)).await?;
            let prior_catalog = super::catalog_digest(&mut tx).await?;
            let prior_definition = prior_definition(&mut tx).await?;
            sqlx::raw_sql(UPGRADE_SQL).execute(&mut *tx).await?;
            let prospective_catalog = super::catalog_digest(&mut tx).await?;
            let prospective_base = base_catalog_evidence(&mut tx).await?;
            if prior_catalog_digest(&mut tx, &prospective_base, &prior_definition).await? != prior_catalog {
                return Err(EnclaveError::Config("activation epoch preview changes the frozen v1 catalog subset".into()));
            }
            let proposal = json!({"contract":"kioku.postgresql.memory-reconciliation-activation-epoch-preview.v1",
                "previous_phase":"draining","previous_generation":1,"generation":2,
                "prior_receipt_sha256":current.receipt_sha256.as_deref().map(sha256_label),
                "prior_contract_sha256":sha256_label(&activation_contract_digest()),
                "prior_catalog_sha256":sha256_label(&prior_catalog),
                "prior_candidate_fleet_image_digest":current.candidate_fleet_image_digest,
                "activation_contract_sha256":sha256_label(&contract_digest()),
                "activation_catalog_sha256":sha256_label(&prospective_catalog),
                "base_finalization_receipt_sha256":sha256_label(&base),
                "upgrade_ddl_sha256":sha256_label(&Sha256::digest(UPGRADE_SQL.as_bytes())),
                "upgrade_catalog_query_sha256":sha256_label(&Sha256::digest(EPOCH_CATALOG_SQL.as_bytes())),
                "runtime_release_version":env!("CARGO_PKG_VERSION"),"rolled_back":true});
            Ok((proposal,current,prior_catalog))
        }.await;
        tx.rollback().await?;
        let (mut proposal, prior, prior_catalog) = result?;
        let (_, unchanged) = verify_activation_and_base_release(&mut observer).await?;
        if unchanged.generation != prior.generation
            || unchanged.phase != prior.phase
            || unchanged.receipt_sha256 != prior.receipt_sha256
            || epoch::present(&mut observer).await?
            || super::catalog_digest(&mut observer).await? != prior_catalog
        {
            return Err(EnclaveError::Conflict(
                "activation epoch preview rollback readback changed".into(),
            ));
        }
        proposal["rollback_readback_verified"] = Value::Bool(true);
        proposal["independent_backend_readback_verified"] = Value::Bool(true);
        Ok(proposal)
    }
}

#[cfg(test)]
pub(super) async fn test_epoch_contract_inner(persistence: &PostgresPersistence) -> Result<()> {
    use super::super::schema_release::{test_verify_activation_receipt, ActivationEpochUpgrade};
    const ACCOUNT: &str = "activation-epoch-contract-account";
    const MODEL: &str = "gemini-3.5-flash";
    const LOCATION: &str = "global";
    const OLD_IMAGE: &str =
        "sha256:dba7ceb3937b267786a24f778118084becabde481930ce1427d074527266d3e6";
    const OLD_PRODUCER: &str =
        "sha256:bbdae4ec761951ec0317feed36c40819419de1f8fac7db4f6f7298ca8d066e0c";
    persistence
        .install_memory_reconciliation_activation_schema()
        .await?;
    sqlx::query(
        "INSERT INTO accounts(id,email,primary_provider,primary_subject)
        VALUES($1,'epoch@example.com','google','epoch')",
    )
    .bind(ACCOUNT)
    .execute(persistence.pool())
    .await?;
    test_advance_activation_until_complete(persistence, false).await?;
    let draining = test_transition_authorization(
        persistence,
        1,
        "installed",
        "draining",
        10_000,
        Vec::new(),
        false,
    )
    .await?;
    let mut predecessor = draining.receipt().clone();
    predecessor.reconciliation_model = MODEL.into();
    predecessor.vertex_location = LOCATION.into();
    predecessor.reconciliation_producer_contract_sha256 = OLD_PRODUCER.into();
    let draining = test_verify_activation_receipt(predecessor)?;
    persistence
        .transition_memory_reconciliation_activation(&draining)
        .await?;
    test_advance_activation_until_complete(persistence, true).await?;
    async fn immutable_history(persistence: &PostgresPersistence) -> Result<String> {
        Ok(sqlx::query_scalar(
            "SELECT jsonb_build_object(
            'contract',(SELECT to_jsonb(c) FROM persistence_feature_activation_contracts c),
            'events',(SELECT jsonb_agg(to_jsonb(e) ORDER BY generation)
                FROM persistence_feature_activation_events e WHERE generation<2))::text",
        )
        .fetch_one(persistence.pool())
        .await?)
    }
    let original = immutable_history(persistence).await?;
    for hostile_ddl in [
        "CREATE TRIGGER reconciliation_activation_epoch_unreviewed BEFORE UPDATE ON accounts
         FOR EACH ROW EXECUTE FUNCTION deny_persistence_feature_activation_mutation()",
        "CREATE TYPE reconciliation_activation_epoch_unreviewed AS ENUM ('unreviewed')",
    ] {
        let mut tx = persistence.pool().begin().await?;
        sqlx::raw_sql(hostile_ddl).execute(&mut *tx).await?;
        assert!(
            present(&mut tx).await.is_err(),
            "partial epoch namespace must refuse preview/install"
        );
        tx.rollback().await?;
    }
    let proposal = persistence
        .preview_memory_reconciliation_activation_epoch()
        .await?;
    assert_eq!(proposal["rolled_back"], true);
    assert_eq!(proposal["rollback_readback_verified"], true);
    assert_eq!(proposal["independent_backend_readback_verified"], true);
    assert_eq!(immutable_history(persistence).await?, original);
    let label = |name: &str| proposal[name].as_str().unwrap().to_owned();
    let mut receipt = draining.receipt().clone();
    receipt.contract_version = 2;
    receipt.generation = 2;
    receipt.previous_phase = "draining".into();
    receipt.activation_contract_sha256 = label("activation_contract_sha256");
    receipt.activation_catalog_sha256 = label("activation_catalog_sha256");
    receipt.candidate_fleet_image_digest = OLD_IMAGE.into();
    receipt.epoch_upgrade = Some(ActivationEpochUpgrade {
        prior_receipt_sha256: label("prior_receipt_sha256"),
        prior_contract_sha256: label("prior_contract_sha256"),
        prior_catalog_sha256: label("prior_catalog_sha256"),
        prior_candidate_fleet_image_digest: label("prior_candidate_fleet_image_digest"),
    });
    for mutation in 0..4 {
        let mut bad = receipt.clone();
        match mutation {
            0 => {
                bad.epoch_upgrade.as_mut().unwrap().prior_receipt_sha256 =
                    format!("sha256:{}", "9".repeat(64))
            }
            1 => bad.activation_catalog_sha256 = format!("sha256:{}", "9".repeat(64)),
            2 => bad.reconciliation_model = "substituted-model".into(),
            _ => {
                bad.observed_at = "2020-01-01T00:00:00.000Z".into();
                bad.expires_at = "2020-01-01T00:10:00.000Z".into();
            }
        }
        let signed = test_verify_activation_receipt(bad)?;
        assert!(persistence
            .transition_memory_reconciliation_activation(&signed)
            .await
            .is_err());
        assert_eq!(immutable_history(persistence).await?, original);
        let mut connection = persistence.pool().acquire().await?;
        assert!(!present(&mut connection).await?);
        verify_activation_and_base_release(&mut connection).await?;
    }
    let signed = test_verify_activation_receipt(receipt.clone())?;
    // A signed epoch without its exact append event cannot be committed.
    let mut tx = persistence.pool().begin().await?;
    let (_, state) = verify_activation_and_base_release(&mut tx).await?;
    let definition = prepare_upgrade(&mut tx, &state, signed.receipt()).await?;
    append_authority(&mut tx, &signed, &definition).await?;
    assert!(
        tx.commit().await.is_err(),
        "deferred epoch/event FK must reject partial commit"
    );
    assert_eq!(immutable_history(persistence).await?, original);
    let result = persistence
        .transition_memory_reconciliation_activation(&signed)
        .await?;
    assert_eq!(result.generation, 2);
    assert_eq!(result.phase, "draining");
    assert!(!result.formation_backfill_complete);
    assert_eq!(immutable_history(persistence).await?, original);
    assert!(persistence
        .transition_memory_reconciliation_activation(&signed)
        .await
        .is_err());
    assert!(persistence
        .preview_memory_reconciliation_activation_epoch()
        .await
        .is_err());
    test_advance_activation_until_complete(persistence, true).await?;
    let mut active = receipt;
    active.generation = 3;
    active.epoch_upgrade = None;
    active.requested_phase = "active".into();
    let mut old_version = active.clone();
    old_version.contract_version = 1;
    assert!(persistence
        .transition_memory_reconciliation_activation(&test_verify_activation_receipt(old_version)?)
        .await
        .is_err());
    persistence
        .transition_memory_reconciliation_activation(&test_verify_activation_receipt(
            active.clone(),
        )?)
        .await?;
    assert_eq!(immutable_history(persistence).await?, original);
    test_partial_keep_preserves_unselected_draft(persistence, ACCOUNT).await?;
    for hostile_ddl in [
        "CREATE FUNCTION reconciliation_activation_epoch_unreviewed() RETURNS integer
        LANGUAGE SQL AS 'SELECT 1'",
        "CREATE INDEX arbitrary_name ON reconciliation_activation_epoch_contract(generation)",
        "CREATE TYPE reconciliation_activation_epoch_unreviewed AS ENUM ('unreviewed')",
        "CREATE DOMAIN reconciliation_activation_epoch_unreviewed AS integer CHECK (VALUE>0)",
    ] {
        let mut tx = persistence.pool().begin().await?;
        sqlx::raw_sql(hostile_ddl).execute(&mut *tx).await?;
        assert!(
            verify_activation_and_base_release(&mut tx).await.is_err(),
            "unreviewed epoch catalog object must be rejected"
        );
        tx.rollback().await?;
    }
    assert!(sqlx::query(
        "UPDATE reconciliation_activation_epoch_contract SET generation=generation"
    )
    .execute(persistence.pool())
    .await
    .is_err());
    assert!(
        sqlx::query("DELETE FROM reconciliation_activation_epoch_contract")
            .execute(persistence.pool())
            .await
            .is_err()
    );
    Box::pin(test_schema_correction_retry_cycle(persistence, active)).await?;
    assert_eq!(immutable_history(persistence).await?, original);
    Ok(())
}

#[cfg(test)]
async fn test_schema_correction_retry_cycle(
    persistence: &PostgresPersistence,
    mut active: super::super::schema_release::MemoryReconciliationActivationReceipt,
) -> Result<()> {
    use super::super::schema_release::test_verify_activation_receipt;
    use crate::persistence::MemoryReconciliationRepository;
    const ACCOUNT: &str = "activation-epoch-contract-account";
    const MODEL: &str = "gemini-3.5-flash";
    const LOCATION: &str = "global";
    // A known-not-billed failed attempt remains durable across the dark upgrade.
    let old_snapshot = persistence
        .next_source_settled_cohort(ACCOUNT, 14400, None, 32, 4000)
        .await?
        .expect("one unselected draft remains after partial KEEP");
    let old_claim = persistence
        .claim_reconciliation(&old_snapshot, 900)
        .await?
        .unwrap();
    persistence
        .release_reconciliation(&old_claim, Some(0), "provider_not_billed", false, true)
        .await?;
    let successor = crate::cp::reconciler::producer_contract_commitment(MODEL, LOCATION)?;
    assert!(
        persistence
            .verify_reconciliation_runtime_schema(Some(MODEL), LOCATION, Some(&successor))
            .await
            .is_err(),
        "the compatibility bridge never admits old Active"
    );
    active.generation = 4;
    active.previous_phase = "active".into();
    active.requested_phase = "paused".into();
    persistence
        .transition_memory_reconciliation_activation(&test_verify_activation_receipt(
            active.clone(),
        )?)
        .await?;
    persistence
        .verify_reconciliation_runtime_schema(Some(MODEL), LOCATION, Some(&successor))
        .await?;
    assert!(
        persistence
            .next_source_settled_cohort(ACCOUNT, 14400, None, 32, 4000)
            .await?
            .is_none(),
        "compatible readiness cannot grant Paused worker authority"
    );
    let retry_before: String = sqlx::query_scalar("SELECT to_jsonb(j)::text FROM memory_reconciliation_jobs j WHERE account_id=$1 AND source_fingerprint=$2")
        .bind(ACCOUNT).bind(&old_snapshot.source_fingerprint).fetch_one(persistence.pool()).await?;
    let retry: Value = serde_json::from_str(&retry_before)?;
    assert_eq!(retry["state"], "retry_wait");
    assert_eq!(retry["model_attempt_count"], 1);
    assert_eq!(retry["last_error_code"], "provider_not_billed");
    active.generation = 5;
    active.previous_phase = "paused".into();
    active.requested_phase = "draining".into();
    active.candidate_fleet_image_digest = format!("sha256:{}", "f".repeat(64));
    active.reconciliation_producer_contract_sha256 = sha256_label(&successor);
    let redrain = persistence
        .transition_memory_reconciliation_activation(&test_verify_activation_receipt(
            active.clone(),
        )?)
        .await?;
    assert!(!redrain.formation_backfill_complete);
    test_advance_activation_until_complete(persistence, true).await?;
    assert_eq!(sqlx::query_scalar::<_, String>("SELECT to_jsonb(j)::text FROM memory_reconciliation_jobs j WHERE account_id=$1 AND source_fingerprint=$2")
        .bind(ACCOUNT).bind(&old_snapshot.source_fingerprint).fetch_one(persistence.pool()).await?, retry_before,
        "redrain/backfill must not reset or discard the old attempt");
    persistence
        .verify_reconciliation_runtime_schema(Some(MODEL), LOCATION, Some(&successor))
        .await?;
    active.generation = 6;
    active.previous_phase = "draining".into();
    active.requested_phase = "active".into();
    persistence
        .transition_memory_reconciliation_activation(&test_verify_activation_receipt(active)?)
        .await?;
    let new_snapshot = persistence
        .next_source_settled_cohort(ACCOUNT, 14400, None, 32, 4000)
        .await?
        .unwrap();
    assert_ne!(
        new_snapshot.source_fingerprint,
        old_snapshot.source_fingerprint
    );
    let new_claim = persistence
        .claim_reconciliation(&new_snapshot, 900)
        .await?
        .unwrap();
    assert_eq!(new_claim.activation_generation, 6);
    assert_eq!(new_claim.producer_contract_sha256, successor.to_vec());
    let guard = persistence
        .acquire_provider_egress_guard(&new_claim)
        .await?
        .unwrap();
    let mut staged_write = super::super::memory_reconciliation::test_provider_stage_write(
        &new_snapshot,
        "schema-correction",
    )?;
    assert_eq!(new_snapshot.predecessor_episode_ids.len(), 1);
    staged_write.planned_outputs[0].retained_episode_id =
        Some(new_snapshot.predecessor_episode_ids[0]);
    let stage = guard.stage_and_release(staged_write).await?;
    let mut digest = Sha256::new();
    digest.update(b"kioku:postgres-memory-reconciliation:v1\0");
    digest.update(&new_snapshot.source_fingerprint);
    digest.update(&stage.result_commitment);
    let published = persistence
        .publish_reconciliation(crate::persistence::ReconciliationPublish {
            claim: new_claim,
            reconciliation_id: format!("rec_{:x}", digest.finalize()),
            cohort_started_at: new_snapshot.cohort_started_at,
            cohort_ended_at: new_snapshot.cohort_ended_at,
            result_commitment: stage.result_commitment,
        })
        .await?;
    assert!(matches!(
        published,
        crate::persistence::ReconciliationPublishResult::Published { .. }
    ));
    assert_eq!(sqlx::query_scalar::<_, i64>("SELECT count(*) FROM memory_reconciliation_jobs WHERE account_id=$1 AND (source_fingerprint=$2 OR state<>'complete')")
        .bind(ACCOUNT).bind(&old_snapshot.source_fingerprint).fetch_one(persistence.pool()).await?, 0,
        "normal publication retires the obsolete retry and leaves no unfinished jobs");
    Ok(())
}

#[cfg(test)]
async fn test_partial_keep_preserves_unselected_draft(
    persistence: &PostgresPersistence,
    account: &str,
) -> Result<()> {
    use crate::persistence::{
        MemoryReconciliationRepository, OversizedKeepPromotionPolicy, OversizedKeepPromotionResult,
    };
    let mut tx = persistence.pool().begin().await?;
    sqlx::query("INSERT INTO episodes(account_id,id,started_at,ended_at,type,title,summary)
        SELECT $1,id,'2026-07-01T10:00:00Z'::timestamptz+id*interval '1 minute',
            '2026-07-01T10:00:00Z'::timestamptz+id*interval '1 minute','note','Synthetic','Keep unchanged'
        FROM generate_series(1,33) id")
        .bind(account).execute(&mut *tx).await?;
    sqlx::query(
        "INSERT INTO screenshots(account_id,id,captured_at)
        SELECT account_id,id,started_at FROM episodes WHERE account_id=$1",
    )
    .bind(account)
    .execute(&mut *tx)
    .await?;
    sqlx::query(
        "INSERT INTO episode_members(account_id,episode_id,record_type,record_id)
        SELECT account_id,id,'screenshot',id FROM episodes WHERE account_id=$1",
    )
    .bind(account)
    .execute(&mut *tx)
    .await?;
    sqlx::query("INSERT INTO capture_sessions(account_id,id,device_id,install_id,started_at,last_event_at,ended_at,schema_version,created_at)
        SELECT $1,'partial-keep','device','install',min(started_at),max(ended_at),max(ended_at),2,min(started_at)
        FROM episodes WHERE account_id=$1")
        .bind(account).execute(&mut *tx).await?;
    sqlx::query("INSERT INTO capture_streams(account_id,id,capture_session_id,device_id,stream_kind,committed_through_sequence,sealed_sequence)
        VALUES($1,'partial-keep-stream','partial-keep','device','mac_screen',-1,-1)")
        .bind(account).execute(&mut *tx).await?;
    sqlx::query("INSERT INTO capture_formation_receipts(account_id,capture_session_id,source_revision,
        finish_requested_at,finish_request_provenance) VALUES($1,'partial-keep',1,'2026-07-01T11:00:00Z','finish_endpoint_v1')")
        .bind(account).execute(&mut *tx).await?;
    let fingerprint = super::super::memory_formation::capture_formation_source_fingerprint(
        &mut tx,
        account,
        "partial-keep",
        1,
    )
    .await?;
    sqlx::query(
        "UPDATE capture_formation_receipts SET state='complete',completed_revision=1,
        completed_outcome='accounted',completed_claim_token='synthetic-partial-keep',
        completed_source_fingerprint=$2,completed_at='2026-07-01T11:00:00Z'
        WHERE account_id=$1 AND capture_session_id='partial-keep'",
    )
    .bind(account)
    .bind(fingerprint)
    .execute(&mut *tx)
    .await?;
    sqlx::query("INSERT INTO capture_formation_seal_events(account_id,capture_session_id,seal_generation,
        source_revision,event_kind,stream_maxima_sha256,provenance)
        VALUES($1,'partial-keep',1,1,'seal',capture_formation_stream_maxima_sha256($1,'partial-keep'),'quiet_contiguous_v1')")
        .bind(account).execute(&mut *tx).await?;
    sqlx::query("UPDATE capture_formation_receipts SET seal_generation=1,seal_finalized_at='2026-07-01T11:00:00Z',
        seal_finalization_provenance='quiet_contiguous_v1' WHERE account_id=$1 AND capture_session_id='partial-keep'")
        .bind(account).execute(&mut *tx).await?;
    tx.commit().await?;
    async fn identities(persistence: &PostgresPersistence, account: &str) -> Result<String> {
        Ok(sqlx::query_scalar("SELECT jsonb_build_object(
            'episodes',(SELECT jsonb_agg(to_jsonb(e)-'structure_state' ORDER BY id) FROM episodes e WHERE account_id=$1),
            'members',(SELECT jsonb_agg(to_jsonb(m) ORDER BY episode_id,record_id) FROM episode_members m WHERE account_id=$1),
            'handles',(SELECT jsonb_agg(to_jsonb(h) ORDER BY episode_id) FROM memory_handles h WHERE account_id=$1),
            'outside',(SELECT to_jsonb(e) FROM episodes e WHERE account_id=$1 AND id=33))::text")
            .bind(account).fetch_one(persistence.pool()).await?)
    }
    let before = identities(persistence, account).await?;
    let policy = OversizedKeepPromotionPolicy {
        draft_limit: 32,
        atom_limit: 4000,
        reconciliation_version: 1,
        prompt_version: 1,
        partition_schema_version: 1,
        validator_version: 1,
    };
    let mut promoted = false;
    for _ in 0..8 {
        match persistence
            .promote_oversized_source_settled_prefix(account, 14400, None, policy)
            .await?
        {
            OversizedKeepPromotionResult::Promoted { episode_ids, .. } => {
                assert_eq!(episode_ids, (1..=32).collect::<Vec<i64>>());
                promoted = true;
                break;
            }
            OversizedKeepPromotionResult::Held { .. } => {}
            OversizedKeepPromotionResult::NotOversized => {
                panic!("33-source-closed-draft cohort is oversized")
            }
        }
    }
    assert!(
        promoted,
        "bounded full-component KEEP proof must make progress"
    );
    assert_eq!(
        identities(persistence, account).await?,
        before,
        "partial KEEP must preserve content, members, handles and the entire unselected draft"
    );
    let counts: (i64,i64,i64) = sqlx::query_as("SELECT
        (SELECT count(*) FROM episodes WHERE account_id=$1 AND structure_state='reconciled'),
        (SELECT count(*) FROM vertex_usage_events WHERE account_id=$1),
        (SELECT count(*) FROM memory_reconciliation_jobs WHERE account_id=$1 AND (state<>'complete' OR attempt_count<>0 OR model_attempt_count<>0))")
        .bind(account).fetch_one(persistence.pool()).await?;
    assert_eq!(counts, (32, 0, 0));
    Ok(())
}
