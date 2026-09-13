//! Synthetic PostgreSQL coverage, run under the ordinary signed Active fixture.

use sqlx::Row;

use crate::{
    cp::media::{manifest_digest, CaptureEventManifest, RecordingMediaAuthorityDecision},
    error::{EnclaveError, Result},
    persistence::{
        CaptureCommit, CaptureFormationSettlement, CaptureRepository as _, CaptureUploadIdentity,
        MemoryFormationRepository as _,
    },
};

use super::super::{advisory_transaction_lock, PostgresPersistence};

async fn account(persistence: &PostgresPersistence, id: &str) -> Result<()> {
    sqlx::query(
        "INSERT INTO accounts(id,email,primary_provider,primary_subject,summarized_until) \
         VALUES($1,$1||'@example.invalid','google',$1,clock_timestamp())",
    )
    .bind(id)
    .execute(persistence.pool())
    .await?;
    Ok(())
}

async fn upload(
    persistence: &PostgresPersistence,
    account_id: &str,
    session: &str,
    sequence: i64,
) -> Result<CaptureCommit> {
    let event = format!("{session}-event-{sequence}");
    let asset = format!("{session}-asset-{sequence}");
    let manifest: CaptureEventManifest = serde_json::from_value(serde_json::json!({
        "schema_version": 2,
        "event_id": event,
        "device_id": "interrupted-device",
        "install_id": "interrupted-install",
        "capture_session_id": session,
        "stream_id": format!("{session}-stream"),
        "stream_kind": "ios_mic",
        "sequence": sequence,
        "source_wall_at": "2026-08-01T10:00:00.000Z",
        "source_monotonic_ns": 1000_u64,
        "started_at": "2026-08-01T10:00:00.000Z",
        "ended_at": "2026-08-01T10:01:00.000Z",
        "timezone_id": "UTC",
        "utc_offset_minutes": 0,
        "clock_uncertainty_ms": 0,
        "media": {
            "asset_id": asset,
            "mime_type": "audio/wav",
            "codec": "pcm_s16le",
            "byte_length": 64,
            "sha256": "a".repeat(64),
            "sample_rate": 16000,
            "channels": 1,
            "frame_count": 960000
        }
    }))?;
    let digest = manifest_digest(&manifest)?;
    let object_key = crate::gcs::canonical_capture_media_object_key(account_id, &asset)?;
    let token = persistence
        .reserve_media_upload(
            account_id,
            CaptureUploadIdentity {
                capture_session_id: session,
                stream_id: &manifest.stream_id,
                event_id: &event,
                asset_id: &asset,
            },
            &object_key,
            &digest,
        )
        .await?;
    Ok(CaptureCommit {
        account_id: account_id.into(),
        manifest,
        manifest_digest: digest,
        object_key: Some(object_key),
        object_generation: Some(1),
        upload_token: token,
        media_authority: Some(RecordingMediaAuthorityDecision::ProcessingWindow30d {
            capture_policy_revision: 0,
            decision_at: "2026-08-01T10:01:01.000Z".into(),
        }),
        committed_at: "2026-08-01T10:01:01.000Z".into(),
    })
}

async fn age_received(persistence: &PostgresPersistence, account_id: &str) -> Result<()> {
    for statement in [
        "UPDATE capture_sessions SET created_at=clock_timestamp()-interval '5 hours' WHERE account_id=$1",
        "UPDATE capture_events SET received_at=clock_timestamp()-interval '5 hours' WHERE account_id=$1",
    ] {
        sqlx::query(statement)
            .bind(account_id)
            .execute(persistence.pool())
            .await?;
    }
    Ok(())
}

async fn settle_media(persistence: &PostgresPersistence, account_id: &str) -> Result<()> {
    for statement in [
        "UPDATE media_processing_jobs SET state='succeeded',updated_at=clock_timestamp()-interval '5 hours' WHERE account_id=$1",
        "UPDATE media_objects SET processing_state='ready' WHERE account_id=$1",
    ] {
        sqlx::query(statement)
            .bind(account_id)
            .execute(persistence.pool())
            .await?;
    }
    Ok(())
}

async fn age_finish(
    persistence: &PostgresPersistence,
    account_id: &str,
    seconds: f64,
) -> Result<()> {
    sqlx::query(
        "UPDATE capture_formation_receipts \
            SET finish_requested_at=clock_timestamp()-make_interval(secs=>$2) \
          WHERE account_id=$1 AND finish_requested_at IS NOT NULL",
    )
    .bind(account_id)
    .bind(seconds)
    .execute(persistence.pool())
    .await?;
    Ok(())
}

pub(in super::super) async fn test_real_pg_interrupted_capture_recovery(
    persistence: &PostgresPersistence,
) -> Result<()> {
    let original_catalog = super::super::activation::test_raw_base_catalog_evidence(
        &mut *persistence.pool().acquire().await?,
    )
    .await?;
    persistence.install_interrupted_capture_schema().await?;
    let widened_catalog = super::super::activation::test_raw_base_catalog_evidence(
        &mut *persistence.pool().acquire().await?,
    )
    .await?;
    assert_ne!(
        original_catalog, widened_catalog,
        "an old binary's raw signed catalog must refuse the widened CHECK"
    );
    super::super::activation::verify_serving_activation_schema(
        &mut *persistence.pool().acquire().await?,
    )
    .await?;
    const ACCOUNT: &str = "interrupted-recovery";
    const SESSION: &str = "missing-finish";
    account(persistence, ACCOUNT).await?;
    let first = upload(persistence, ACCOUNT, SESSION, 0).await?;
    assert!(!persistence.commit_event(first.clone()).await?.duplicate);
    settle_media(persistence, ACCOUNT).await?;
    assert_eq!(
        persistence.recover_inactive_sessions(ACCOUNT).await?,
        0,
        "old device timestamps cannot make a newly received recording inactive"
    );
    age_received(persistence, ACCOUNT).await?;
    sqlx::query("UPDATE capture_events SET received_at=clock_timestamp()-interval '29 minutes' WHERE account_id=$1")
        .bind(ACCOUNT)
        .execute(persistence.pool())
        .await?;
    assert_eq!(
        persistence.recover_inactive_sessions(ACCOUNT).await?,
        0,
        "newly accepted offline evidence protects an old session"
    );
    age_received(persistence, ACCOUNT).await?;
    sqlx::query("UPDATE media_processing_jobs SET state='pending' WHERE account_id=$1")
        .bind(ACCOUNT)
        .execute(persistence.pool())
        .await?;
    assert_eq!(
        persistence.recover_inactive_sessions(ACCOUNT).await?,
        0,
        "known unfinished media cannot be declared complete"
    );
    settle_media(persistence, ACCOUNT).await?;

    sqlx::query(
        "INSERT INTO episode_deletions(account_id,episode_id,state,purge,media_object_keys, \
        utterance_ids,screenshot_ids,segment_ids,orphan_event_ids) \
        VALUES($1,999,'pending','{}','[]','[]','[]','[]','[]')",
    )
    .bind(ACCOUNT)
    .execute(persistence.pool())
    .await?;
    assert_eq!(
        persistence.recover_inactive_sessions(ACCOUNT).await?,
        0,
        "pending episode deletion must hold recovery under the source lock"
    );
    sqlx::query("UPDATE episode_deletions SET state='complete',completed_at=clock_timestamp() WHERE account_id=$1")
        .bind(ACCOUNT).execute(persistence.pool()).await?;

    let reserved = upload(persistence, ACCOUNT, SESSION, 2).await?;
    assert_eq!(
        persistence.recover_inactive_sessions(ACCOUNT).await?,
        0,
        "a live canonical upload holds inactivity recovery"
    );
    sqlx::query("DELETE FROM capture_upload_intents WHERE account_id=$1")
        .bind(ACCOUNT)
        .execute(persistence.pool())
        .await?;
    assert!(persistence.commit_event(first.clone()).await?.duplicate);
    assert_eq!(
        persistence.recover_inactive_sessions(ACCOUNT).await?,
        1,
        "duplicate delivery must not reset server receipt inactivity"
    );
    let recovered = sqlx::query(
        "SELECT session.ended_at=session.last_event_at AS exact_horizon, \
                receipt.finish_request_provenance, \
                receipt.finish_requested_at>clock_timestamp()-interval '1 minute' AS server_timed, \
                receipt.seal_finalized_at IS NULL AS provisional \
           FROM capture_sessions session JOIN capture_formation_receipts receipt \
             ON receipt.account_id=session.account_id AND receipt.capture_session_id=session.id \
          WHERE session.account_id=$1 AND session.id=$2",
    )
    .bind(ACCOUNT)
    .bind(SESSION)
    .fetch_one(persistence.pool())
    .await?;
    assert!(recovered.try_get::<bool, _>("exact_horizon")?);
    assert!(recovered.try_get::<bool, _>("server_timed")?);
    assert!(recovered.try_get::<bool, _>("provisional")?);
    assert_eq!(
        recovered.try_get::<String, _>("finish_request_provenance")?,
        "server_inactivity_v1"
    );
    assert_eq!(persistence.recover_inactive_sessions(ACCOUNT).await?, 0);
    assert!(persistence
        .claim_capture_formation(ACCOUNT, 900)
        .await?
        .is_none());
    age_finish(persistence, ACCOUNT, 31.0).await?;
    let claim = persistence
        .claim_capture_formation(ACCOUNT, 900)
        .await?
        .ok_or_else(|| {
            EnclaveError::Store("interrupted source was not offered to formation".into())
        })?;
    assert_eq!(claim.capture_session_id, SESSION);
    // This synthetic media has no speech: the actual providerless no-memory
    // settlement must complete the revision without a fabricated model result.
    assert!(persistence
        .settle_capture_formation(CaptureFormationSettlement {
            authored_labels: Default::default(),
            claim,
            episodes: Vec::new(),
        })
        .await?
        .is_empty());
    let before_seal: bool = sqlx::query_scalar(
        "SELECT seal_finalized_at IS NULL AND state='complete' \
           FROM capture_formation_receipts WHERE account_id=$1 AND capture_session_id=$2",
    )
    .bind(ACCOUNT)
    .bind(SESSION)
    .fetch_one(persistence.pool())
    .await?;
    assert!(before_seal, "recovery cannot skip the four-hour quiet seal");
    age_finish(persistence, ACCOUNT, 5.0 * 3600.0).await?;
    assert!(persistence
        .claim_capture_formation(ACCOUNT, 900)
        .await?
        .is_none());
    assert_eq!(
        sqlx::query_as::<_, (i64, String)>(
            "SELECT seal_generation,seal_finalization_provenance FROM capture_formation_receipts \
          WHERE account_id=$1 AND capture_session_id=$2 AND seal_finalized_at IS NOT NULL",
        )
        .bind(ACCOUNT)
        .bind(SESSION)
        .fetch_one(persistence.pool())
        .await?,
        (1, "quiet_contiguous_v1".into())
    );

    // A client returning after the server finish/seal still uploads through the
    // ordinary admission path. Sequence two cannot acknowledge missing one.
    drop(reserved);
    let late = upload(persistence, ACCOUNT, SESSION, 2).await?;
    assert_eq!(
        persistence
            .commit_event(late)
            .await?
            .committed_through_sequence,
        0
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT count(*) FROM capture_formation_seal_events \
          WHERE account_id=$1 AND capture_session_id=$2 AND event_kind='reopen'",
        )
        .bind(ACCOUNT)
        .bind(SESSION)
        .fetch_one(persistence.pool())
        .await?,
        1
    );
    settle_media(persistence, ACCOUNT).await?;
    age_received(persistence, ACCOUNT).await?;
    assert!(
        persistence
            .claim_capture_formation(ACCOUNT, 900)
            .await?
            .is_none(),
        "an absent accepted sequence must keep the exact source boundary open"
    );
    let gap = upload(persistence, ACCOUNT, SESSION, 1).await?;
    assert_eq!(
        persistence
            .commit_event(gap)
            .await?
            .committed_through_sequence,
        2
    );
    assert!(
        persistence
            .claim_capture_formation(ACCOUNT, 900)
            .await?
            .is_none(),
        "recent accepted late media still needs its normal settlement"
    );
    settle_media(persistence, ACCOUNT).await?;
    age_received(persistence, ACCOUNT).await?;
    let late_claim = persistence
        .claim_capture_formation(ACCOUNT, 900)
        .await?
        .ok_or_else(|| {
            EnclaveError::Store("recovered late revision was not offered to formation".into())
        })?;
    persistence
        .settle_capture_formation(CaptureFormationSettlement {
            authored_labels: Default::default(),
            claim: late_claim,
            episodes: Vec::new(),
        })
        .await?;
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT seal_generation FROM capture_formation_receipts \
          WHERE account_id=$1 AND capture_session_id=$2 AND seal_finalized_at IS NOT NULL",
        )
        .bind(ACCOUNT)
        .bind(SESSION)
        .fetch_one(persistence.pool())
        .await?,
        2
    );

    // More held candidates than the entire batch cannot starve later ready
    // sessions; repeated process-independent passes drain the bounded remainder.
    const BATCH: &str = "interrupted-recovery-batch";
    account(persistence, BATCH).await?;
    for index in 0..35 {
        let command = upload(persistence, BATCH, &format!("batch-{index:02}"), 0).await?;
        persistence.commit_event(command).await?;
    }
    age_received(persistence, BATCH).await?;
    settle_media(persistence, BATCH).await?;
    sqlx::query("UPDATE media_processing_jobs SET state='pending' WHERE account_id=$1 AND event_id<'batch-33'")
        .bind(BATCH).execute(persistence.pool()).await?;
    assert_eq!(persistence.recover_inactive_sessions(BATCH).await?, 2);
    settle_media(persistence, BATCH).await?;
    assert_eq!(persistence.recover_inactive_sessions(BATCH).await?, 32);
    assert_eq!(persistence.recover_inactive_sessions(BATCH).await?, 1);
    assert_eq!(persistence.recover_inactive_sessions(BATCH).await?, 0);

    const GAP: &str = "interrupted-recovery-gap";
    account(persistence, GAP).await?;
    for sequence in [0, 2] {
        let command = upload(persistence, GAP, "open-gap", sequence).await?;
        persistence.commit_event(command).await?;
    }
    age_received(persistence, GAP).await?;
    settle_media(persistence, GAP).await?;
    assert_eq!(
        persistence.recover_inactive_sessions(GAP).await?,
        0,
        "inactivity cannot conceal an open session's missing sequence"
    );
    let missing = upload(persistence, GAP, "open-gap", 1).await?;
    persistence.commit_event(missing).await?;
    age_received(persistence, GAP).await?;
    settle_media(persistence, GAP).await?;
    assert_eq!(
        persistence.recover_inactive_sessions(GAP).await?,
        1,
        "a later pass recovers the now-contiguous source"
    );

    // The lifecycle lock precedes source/account locks. A deletion that wins
    // first must prevent the waiting recovery from writing a finish receipt.
    const DELETING: &str = "interrupted-recovery-deleting";
    account(persistence, DELETING).await?;
    let command = upload(persistence, DELETING, "deleting-session", 0).await?;
    persistence.commit_event(command).await?;
    age_received(persistence, DELETING).await?;
    settle_media(persistence, DELETING).await?;
    let mut deletion = persistence.pool().begin().await?;
    advisory_transaction_lock(&mut deletion, "account-lifecycle", DELETING).await?;
    sqlx::query("UPDATE accounts SET status='deletion_requested' WHERE id=$1")
        .bind(DELETING)
        .execute(&mut *deletion)
        .await?;
    let concurrent = persistence.clone();
    let mut recovery =
        tokio::spawn(async move { concurrent.recover_inactive_sessions(DELETING).await });
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(100), &mut recovery)
            .await
            .is_err()
    );
    deletion.commit().await?;
    assert_eq!(
        recovery
            .await
            .map_err(|error| EnclaveError::Store(error.to_string()))??,
        0
    );
    assert!(sqlx::query_scalar::<_, bool>(
        "SELECT finish_requested_at IS NULL FROM capture_formation_receipts WHERE account_id=$1",
    ).bind(DELETING).fetch_one(persistence.pool()).await?);
    for id in [ACCOUNT, BATCH, GAP, DELETING] {
        sqlx::query("DELETE FROM accounts WHERE id=$1")
            .bind(id)
            .execute(persistence.pool())
            .await?;
    }
    Ok(())
}
