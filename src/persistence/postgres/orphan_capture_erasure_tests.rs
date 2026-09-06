//! Real PostgreSQL contracts for the inert additive erasure-schema draft.

use sha2::{Digest, Sha256};

use crate::{
    error::Result,
    persistence::{BillingRepository, CaptureRepository, CaptureUploadIdentity},
};

use super::PostgresPersistence;

const ACCOUNT: &str = "orphan-erasure-contract";
const OTHER: &str = "orphan-erasure-other";
const OPERATION: &str = "fixture-operation";
const INSERT_OPERATION: &str = "INSERT INTO orphan_capture_erasure_operations( \
    account_id,operation_id,request_sha256,request_signature,request_key_sha256, \
    scope_sha256,object_inventory_sha256,survivor_sha256,activation_generation, \
    candidate_image_digest,activation_contract_sha256,activation_catalog_sha256, \
    activation_receipt_sha256,provider_authority_sha256,protected_control_proof_sha256, \
    session_count,stream_count,event_count,object_count,projection_count,provider_names_sha256,provider_name_count,account_provider_names_sha256) \
    VALUES($1,$2,$3,$4,$3,$3,$5,$3,1,'sha256:'||repeat('1',64),$3,$3,$3,$3,$3,1,1,1,1,0,$6,2,$3)";

fn provider_names_root() -> Vec<u8> {
    Sha256::digest(format!("kioku.orphan-capture-provider-names.v1\nraw/{ACCOUNT}/asset.enc\nrecordings/{ACCOUNT}/asset.enc\n").as_bytes()).to_vec()
}

async fn operation(transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>) -> Result<()> {
    let object_line = format!(
        "kioku.orphan-capture-objects.v1\nraw/{ACCOUNT}/asset.enc\t1\tevent\tasset\t5\t{}\n",
        "a".repeat(64)
    );
    sqlx::query(INSERT_OPERATION)
        .bind(ACCOUNT)
        .bind(OPERATION)
        .bind(vec![1_u8; 32])
        .bind(vec![2_u8; 64])
        .bind(Sha256::digest(object_line.as_bytes()).to_vec())
        .bind(provider_names_root())
        .execute(&mut **transaction)
        .await?;
    Ok(())
}

pub(super) async fn test_real_pg_orphan_erasure_guards(
    persistence: &PostgresPersistence,
) -> Result<()> {
    for ddl in [
        "ALTER TABLE orphan_capture_erasure_operations RENAME TO orphan_capture_erasure_missing_operations",
        "ALTER TABLE capture_events DISABLE TRIGGER orphan_capture_erasure_events_admission",
        "ALTER TABLE orphan_capture_erasure_objects ALTER COLUMN object_key TYPE text COLLATE \"C\"",
        "DROP TABLE orphan_capture_erasure_contract",
    ] {
        let mut tamper = persistence.pool().begin().await?;
        sqlx::query(ddl).execute(&mut *tamper).await?;
        assert!(super::orphan_capture_erasure::require_runtime_schema(&mut tamper).await.is_err(),
            "the independent required catalog must reject structural/guard/collation loss");
        assert!(super::orphan_capture_erasure::require_no_pending_erasures(&mut tamper).await.is_err(),
            "compatible activation must also refuse partial or corrupt namespaces");
        tamper.rollback().await?;
    }
    let mut absent = persistence.pool().begin().await?;
    sqlx::query("SET LOCAL search_path=pg_catalog")
        .execute(&mut *absent)
        .await?;
    assert!(!super::orphan_capture_erasure::verify_schema_if_installed(&mut absent).await?);
    assert!(
        super::orphan_capture_erasure::require_runtime_schema(&mut absent)
            .await
            .is_err()
    );
    assert!(
        super::orphan_capture_erasure::require_no_pending_erasures(&mut absent)
            .await
            .is_ok(),
        "compatible predecessor activation permits verified whole-namespace absence"
    );
    assert!(
        super::orphan_capture_erasure::require_capture_admission(
            &mut absent,
            ACCOUNT,
            CaptureUploadIdentity {
                capture_session_id: "s",
                stream_id: "s",
                event_id: "e",
                asset_id: "a"
            },
            None
        )
        .await
        .is_err(),
        "whole namespace absence is not valid serving admission"
    );
    absent.rollback().await?;
    let mut reinstall = persistence.pool().begin().await?;
    let installed_at: String =
        sqlx::query_scalar("SELECT installed_at::text FROM orphan_capture_erasure_contract")
            .fetch_one(&mut *reinstall)
            .await?;
    super::orphan_capture_erasure::install_schema_in_locked_transaction(&mut reinstall).await?;
    assert_eq!(
        sqlx::query_scalar::<_, String>(
            "SELECT installed_at::text FROM orphan_capture_erasure_contract"
        )
        .fetch_one(&mut *reinstall)
        .await?,
        installed_at
    );
    reinstall.rollback().await?;
    sqlx::query(
        "INSERT INTO accounts(id,email,primary_provider,primary_subject) \
         SELECT value,value||'@example.com','google',value FROM unnest($1::text[]) item(value)",
    )
    .bind(vec![ACCOUNT, OTHER])
    .execute(persistence.pool())
    .await?;

    let mut unsealed = persistence.pool().begin().await?;
    operation(&mut unsealed).await?;
    assert!(
        unsealed.commit().await.is_err(),
        "preparing must never commit"
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM orphan_capture_erasure_operations")
            .fetch_one(persistence.pool())
            .await?,
        0
    );

    let mut prepare = persistence.pool().begin().await?;
    operation(&mut prepare).await?;
    // Two real transactions: operation INSERT itself holds the account row,
    // so the predecessor upload trigger cannot win a concurrent reservation.
    let mut competing = persistence.pool().begin().await?;
    sqlx::query("SET LOCAL lock_timeout='100ms'")
        .execute(&mut *competing)
        .await?;
    let blocked = sqlx::query("INSERT INTO capture_upload_intents(account_id,event_id,token,asset_id,object_key,manifest_digest,expires_at) \
        VALUES($1,'race-event','race-token','race-asset','raw/'||$1||'/race-asset.enc',repeat('a',64),now()+interval '1 minute')")
        .bind(ACCOUNT).execute(&mut *competing).await.expect_err("upload cannot pass an uncommitted preparation fence");
    assert_eq!(
        blocked
            .as_database_error()
            .and_then(|e| e.code())
            .as_deref(),
        Some("55P03")
    );
    competing.rollback().await?;
    sqlx::query(
        "INSERT INTO orphan_capture_erasure_sessions(account_id,capture_session_id,operation_id) \
         VALUES($1,'session',$2)",
    )
    .bind(ACCOUNT)
    .bind(OPERATION)
    .execute(&mut *prepare)
    .await?;
    sqlx::query("SAVEPOINT wrong_parent")
        .execute(&mut *prepare)
        .await?;
    assert!(sqlx::query(
        "INSERT INTO orphan_capture_erasure_streams(account_id,stream_id,capture_session_id,operation_id) \
         VALUES($1,'stream','not-the-session',$2)",
    )
    .bind(ACCOUNT)
    .bind(OPERATION)
    .execute(&mut *prepare)
    .await
    .is_err());
    sqlx::query("ROLLBACK TO SAVEPOINT wrong_parent")
        .execute(&mut *prepare)
        .await?;
    sqlx::query(
        "INSERT INTO orphan_capture_erasure_streams(account_id,stream_id,capture_session_id,operation_id) \
         VALUES($1,'stream','session',$2)",
    )
    .bind(ACCOUNT)
    .bind(OPERATION)
    .execute(&mut *prepare)
    .await?;
    sqlx::query(
        "INSERT INTO orphan_capture_erasure_events( \
             account_id,event_id,asset_id,stream_id,capture_session_id,operation_id) \
         VALUES($1,'event','asset','stream','session',$2)",
    )
    .bind(ACCOUNT)
    .bind(OPERATION)
    .execute(&mut *prepare)
    .await?;
    sqlx::query("SAVEPOINT wrong_object")
        .execute(&mut *prepare)
        .await?;
    assert!(sqlx::query(
        "INSERT INTO orphan_capture_erasure_objects( \
             account_id,operation_id,object_key,object_generation,event_id,asset_id,byte_length,original_sha256) \
         VALUES($1,$2,'raw/unrelated/asset.enc',1,'event','asset',5,repeat('a',64))",
    )
    .bind(ACCOUNT)
    .bind(OPERATION)
    .execute(&mut *prepare)
    .await
    .is_err());
    sqlx::query("ROLLBACK TO SAVEPOINT wrong_object")
        .execute(&mut *prepare)
        .await?;
    sqlx::query(
        "INSERT INTO orphan_capture_erasure_objects( \
             account_id,operation_id,object_key,object_generation,event_id,asset_id,byte_length,original_sha256) \
         VALUES($1,$2,'raw/'||$1||'/asset.enc',1,'event','asset',5,repeat('a',64))",
    )
    .bind(ACCOUNT)
    .bind(OPERATION)
    .execute(&mut *prepare)
    .await?;
    sqlx::query(
        "UPDATE orphan_capture_erasure_operations SET state='provider_pending' \
          WHERE account_id=$1 AND operation_id=$2",
    )
    .bind(ACCOUNT)
    .bind(OPERATION)
    .execute(&mut *prepare)
    .await?;
    prepare.commit().await?;
    let mut duplicate_fence = persistence.pool().begin().await?;
    let duplicated = sqlx::query(INSERT_OPERATION)
        .bind(ACCOUNT)
        .bind("another-operation")
        .bind(vec![1_u8; 32])
        .bind(vec![2_u8; 64])
        .bind(vec![3_u8; 32])
        .bind(provider_names_root())
        .execute(&mut *duplicate_fence)
        .await
        .expect_err("only one operation may fence an account");
    assert_eq!(
        duplicated
            .as_database_error()
            .and_then(|e| e.code())
            .as_deref(),
        Some("23505")
    );
    duplicate_fence.rollback().await?;
    async fn reject_projection_replay(persistence: &PostgresPersistence) -> Result<()> {
        for query in [
            "INSERT INTO screenshots(account_id,id,captured_at,source_key) VALUES($1,987,now(),'cloud-v2:event')",
            "INSERT INTO utterances(account_id,id,audio_segment_id,start_offset_seconds,end_offset_seconds,text,speaker_label,source_key) \
             VALUES($1,987,987,0,1,'synthetic late result','speaker','cloud-v2:event:turn')",
        ] {
            let error=sqlx::query(query).bind(ACCOUNT).execute(persistence.pool()).await.expect_err("erased projection must stay absent");
            assert_eq!(error.as_database_error().and_then(|e|e.code()).as_deref(),Some("55000"));
        }
        Ok(())
    }
    reject_projection_replay(persistence).await?;

    sqlx::query(
        "INSERT INTO recording_delivery_balances(account_id,event_credits,byte_credits) \
         VALUES($1,10,100)",
    )
    .bind(ACCOUNT)
    .execute(persistence.pool())
    .await?;
    assert!(persistence
        .reserve_recording_delivery(ACCOUNT, "fresh-event", 5)
        .await
        .is_err());
    assert_eq!(
        sqlx::query_as::<_, (i64,i64)>(
            "SELECT event_credits,byte_credits FROM recording_delivery_balances WHERE account_id=$1",
        ).bind(ACCOUNT).fetch_one(persistence.pool()).await?,
        (10,100),
        "predecessor billing transaction must roll back credits when its reservation is fenced"
    );
    assert!(persistence
        .reserve_recording_delivery_batch(
            ACCOUNT,
            &"a".repeat(64),
            &"b".repeat(64),
            "fresh-stream",
            0,
            0,
            &["fresh-event".into()],
            &["fresh-event".into()],
        )
        .await
        .is_err());
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT count(*) FROM capture_reference_batch_receipts WHERE account_id=$1",
        )
        .bind(ACCOUNT)
        .fetch_one(persistence.pool())
        .await?,
        0,
        "fenced reference preparation must not leave a partial batch receipt"
    );

    for statement in [
        "INSERT INTO orphan_capture_erasure_sessions(account_id,capture_session_id,operation_id) \
         VALUES($1,'extra-session','fixture-operation')",
        "INSERT INTO orphan_capture_erasure_objects( \
             account_id,operation_id,object_key,object_generation,event_id,asset_id,byte_length,original_sha256) \
         VALUES($1,'fixture-operation','recordings/'||$1||'/asset.enc',1,'event','asset',5,repeat('a',64))",
        "DELETE FROM orphan_capture_erasure_events WHERE account_id=$1",
        "DELETE FROM orphan_capture_erasure_objects WHERE account_id=$1",
        "UPDATE orphan_capture_erasure_operations SET capture_upload_fenced=false WHERE account_id=$1",
        "UPDATE orphan_capture_erasure_operations SET state='complete',completed_at=clock_timestamp(), \
             completion_request_sha256=decode(repeat('3',64),'hex'),completion_signature=decode(repeat('4',128),'hex') \
          WHERE account_id=$1",
    ] {
        assert!(sqlx::query(statement)
            .bind(ACCOUNT)
            .execute(persistence.pool())
            .await
            .is_err(), "sealed inventory and forward transitions must refuse mutation");
    }

    let insert_upload = "INSERT INTO capture_upload_intents( \
        account_id,event_id,token,asset_id,object_key,manifest_digest,expires_at) \
        VALUES($1,$2,$1||'-token','asset','raw/'||$1||'/asset.enc',repeat('a',64),now()+interval '10 minutes')";
    for statement in [
        "INSERT INTO recording_delivery_reservations(account_id,event_id,reserved_bytes) VALUES($1,'new-event',5)",
        "INSERT INTO capture_reference_batch_receipts( \
             account_id,batch_id,manifest_digest,stream_id,first_sequence,last_sequence,event_count,state) \
         VALUES($1,repeat('a',64),repeat('b',64),'new-stream',0,0,1,'awaiting_credit')",
        "INSERT INTO capture_sessions(account_id,id,device_id,install_id,started_at,last_event_at,schema_version) \
         VALUES($1,'session','device','install',now(),now(),2)",
    ] {
        assert!(sqlx::query(statement)
            .bind(ACCOUNT)
            .execute(persistence.pool())
            .await
            .is_err());
    }
    assert!(sqlx::query(insert_upload)
        .bind(ACCOUNT)
        .bind("new-event")
        .execute(persistence.pool())
        .await
        .is_err());
    sqlx::query(insert_upload)
        .bind(OTHER)
        .bind("event")
        .execute(persistence.pool())
        .await?;

    sqlx::query(
        "UPDATE orphan_capture_erasure_operations SET state='provider_verified', \
             provider_ack_request_sha256=decode(repeat('5',64),'hex'), \
             provider_ack_signature=decode(repeat('6',128),'hex'), \
             provider_receipt_sha256=decode(repeat('7',64),'hex') WHERE account_id=$1",
    )
    .bind(ACCOUNT)
    .execute(persistence.pool())
    .await?;
    async fn assert_runtime_tombstones(persistence: &PostgresPersistence) -> Result<()> {
        let mut admission_connection = persistence.pool().acquire().await?;
        for identity in [
            CaptureUploadIdentity {
                capture_session_id: "session",
                stream_id: "fresh-stream",
                event_id: "fresh-event",
                asset_id: "fresh-asset",
            },
            CaptureUploadIdentity {
                capture_session_id: "fresh-session",
                stream_id: "stream",
                event_id: "fresh-event",
                asset_id: "fresh-asset",
            },
            CaptureUploadIdentity {
                capture_session_id: "fresh-session",
                stream_id: "fresh-stream",
                event_id: "event",
                asset_id: "fresh-asset",
            },
            CaptureUploadIdentity {
                capture_session_id: "fresh-session",
                stream_id: "fresh-stream",
                event_id: "fresh-event",
                asset_id: "asset",
            },
        ] {
            assert!(super::orphan_capture_erasure::require_capture_admission(
                &mut admission_connection,
                ACCOUNT,
                identity,
                None,
            )
            .await
            .is_err());
            assert!(
                persistence
                    .reserve_media_upload(
                        ACCOUNT,
                        identity,
                        &format!("raw/{ACCOUNT}/{}.enc", identity.asset_id),
                        &"a".repeat(64),
                    )
                    .await
                    .is_err(),
                "late unseen event IDs must be refused before provider PUT, not just at commit"
            );
        }
        let fresh_identity = CaptureUploadIdentity {
            capture_session_id: "fresh-session",
            stream_id: "fresh-stream",
            event_id: "fresh-event",
            asset_id: "fresh-asset",
        };
        assert!(
            persistence
                .reserve_media_upload(
                    ACCOUNT,
                    fresh_identity,
                    &format!("raw/{ACCOUNT}/asset.enc"),
                    &"a".repeat(64)
                )
                .await
                .is_err(),
            "fresh identities cannot alias an erased canonical object key"
        );
        assert!(
            super::orphan_capture_erasure::require_capture_admission(
                &mut admission_connection,
                ACCOUNT,
                fresh_identity,
                Some("event"),
            )
            .await
            .is_err(),
            "references cannot charge credit for an erased canonical root"
        );
        super::orphan_capture_erasure::require_capture_admission(
            &mut admission_connection,
            ACCOUNT,
            fresh_identity,
            None,
        )
        .await?;
        drop(admission_connection);
        Ok(())
    }
    assert!(
        sqlx::query(
            "UPDATE orphan_capture_erasure_operations SET state='complete', \
             completion_request_sha256=decode(repeat('3',64),'hex'), \
             completion_signature=decode(repeat('4',128),'hex') WHERE account_id=$1",
        )
        .bind(ACCOUNT)
        .execute(persistence.pool())
        .await
        .is_err(),
        "complete cannot commit before the temporary inventory is scrubbed"
    );
    assert!(
        sqlx::query("DELETE FROM orphan_capture_erasure_objects WHERE account_id=$1")
            .bind(ACCOUNT)
            .execute(persistence.pool())
            .await
            .is_err(),
        "inventory cannot disappear in an incomplete operation"
    );
    let mut completion = persistence.pool().begin().await?;
    sqlx::query("DELETE FROM orphan_capture_erasure_objects WHERE account_id=$1")
        .bind(ACCOUNT)
        .execute(&mut *completion)
        .await?;
    sqlx::query(
        "UPDATE orphan_capture_erasure_operations SET state='complete', \
             completion_request_sha256=decode(repeat('3',64),'hex'), \
             completion_signature=decode(repeat('4',128),'hex') WHERE account_id=$1",
    )
    .bind(ACCOUNT)
    .execute(&mut *completion)
    .await?;
    completion.commit().await?;
    assert!(
        sqlx::query(insert_upload)
            .bind(ACCOUNT)
            .bind("new-event")
            .execute(persistence.pool())
            .await
            .is_err(),
        "provider-complete must keep the temporary fence"
    );
    sqlx::query(
        "UPDATE orphan_capture_erasure_operations SET capture_upload_fenced=false, \
             fence_release_request_sha256=decode(repeat('8',64),'hex'), \
             fence_release_signature=decode(repeat('9',128),'hex'),fence_release_generation=2, \
             fence_release_candidate_image_digest='sha256:'||repeat('2',64), \
             fence_release_activation_receipt_sha256=decode(repeat('8',64),'hex'), \
             fence_release_fleet_evidence_sha256=decode(repeat('8',64),'hex'), \
             fence_release_protected_canary_sha256=decode(repeat('8',64),'hex'), \
             fence_release_admission_contract_sha256=decode(repeat('8',64),'hex') WHERE account_id=$1",
    )
    .bind(ACCOUNT)
    .execute(persistence.pool())
    .await?;
    assert_runtime_tombstones(persistence).await?;
    reject_projection_replay(persistence).await?;
    assert!(
        sqlx::query(insert_upload)
            .bind(ACCOUNT)
            .bind("event")
            .execute(persistence.pool())
            .await
            .is_err(),
        "event and asset tombstones survive the temporary fence"
    );
    sqlx::query(
        "INSERT INTO capture_upload_intents( \
            account_id,event_id,token,asset_id,object_key,manifest_digest,expires_at) \
         VALUES($1,'unrelated-event','new-token','unrelated-asset','raw/'||$1||'/unrelated-asset.enc', \
                repeat('a',64),now()+interval '10 minutes')",
    )
    .bind(ACCOUNT)
    .execute(persistence.pool())
    .await?;
    sqlx::query("DELETE FROM accounts WHERE id=ANY($1::text[])")
        .bind(vec![ACCOUNT, OTHER])
        .execute(persistence.pool())
        .await?;
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM orphan_capture_erasure_operations")
            .fetch_one(persistence.pool())
            .await?,
        0,
        "normal whole-account erasure must retain its legitimate cascade"
    );
    Ok(())
}
