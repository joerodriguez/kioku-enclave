use async_trait::async_trait;
use serde_json::json;
use sqlx::Row;

use crate::{
    cp::{
        isotime,
        media::{
            self, BrowserStateV2Envelope, CaptureContext, CaptureEventManifest, MediaDisposition,
            RecordingMediaAuthorityDecision,
        },
    },
    error::{CaptureReferenceFailureReason, EnclaveError, Result},
    persistence::{
        CaptureCommit, CaptureCommitResult, CaptureEventStatus, CapturePreflight,
        CaptureRepository, CaptureSessionEvidence, CaptureSessionMemory, CaptureSessionProcessing,
        CaptureSessionStage, CaptureSessionStatus, ReferenceBatchCommit,
        ReferenceBatchCommitResult,
    },
};

use super::{
    activation::lock_activation_contract_key_share_if_installed, advisory_transaction_lock,
    PostgresPersistence,
};

fn timestamp(value: &str, field: &str) -> Result<i64> {
    isotime::parse_epoch_millis(value).ok_or_else(|| {
        EnclaveError::InvalidRequest(format!("{field} must be a valid ISO-8601 timestamp"))
    })
}

fn disposition(value: MediaDisposition) -> &'static str {
    match value {
        MediaDisposition::Canonical => "canonical",
        MediaDisposition::Reference => "reference",
    }
}

fn stream_kind(value: media::StreamKind) -> &'static str {
    match value {
        media::StreamKind::Mic => "mic",
        media::StreamKind::SystemAudio => "system_audio",
        media::StreamKind::MacScreen => "mac_screen",
        media::StreamKind::IosMic => "ios_mic",
        media::StreamKind::IosImportedScreenshot => "ios_imported_screenshot",
        media::StreamKind::IosSharedPage => "ios_shared_page",
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StreamAdmission {
    Open,
    ProvisionalFinish,
    SealedGapFill,
    LateSealReopen,
}

fn stream_admission(
    session_ended: bool,
    provisional_finish_authorized: bool,
    late_seal_reopen_authorized: bool,
    sealed_sequence: Option<i64>,
    sequence: i64,
    session_finished: bool,
) -> Result<StreamAdmission> {
    if !session_ended {
        if sealed_sequence.is_some() {
            return Err(EnclaveError::Store(
                "open capture session contains a sealed stream".into(),
            ));
        }
        return Ok(StreamAdmission::Open);
    }
    let Some(sealed_sequence) = sealed_sequence else {
        if provisional_finish_authorized {
            return Ok(StreamAdmission::ProvisionalFinish);
        }
        return Err(EnclaveError::Conflict(
            "ended capture session has no authorized provisional finish request".into(),
        ));
    };
    if sequence > sealed_sequence && late_seal_reopen_authorized {
        return Ok(StreamAdmission::LateSealReopen);
    }
    if session_finished || sequence > sealed_sequence {
        return Err(EnclaveError::Conflict(
            "capture event exceeds the sealed stream boundary".into(),
        ));
    }
    Ok(StreamAdmission::SealedGapFill)
}

#[derive(Debug)]
struct SealReopen {
    generation: i64,
    sealed_stream_count: usize,
}

async fn capture_formation_contract_installed(connection: &mut sqlx::PgConnection) -> Result<bool> {
    Ok(
        sqlx::query_scalar("SELECT to_regclass('capture_formation_receipts') IS NOT NULL")
            .fetch_one(connection)
            .await?,
    )
}

fn provisional_finish_state_authorized(
    phase: Option<&str>,
    receipt_exists: bool,
    finish_requested: bool,
    seal_finalized: bool,
) -> bool {
    !seal_finalized
        && (phase == Some("installed")
            || finish_requested
            || (receipt_exists && matches!(phase, Some("draining" | "active" | "paused"))))
}

/// Schema 26 has no durable finish-request companion, so an ended session
/// with no seals remains provisionally writable during the dark binary-first
/// rollout. The v27 `installed` phase preserves that mixed-fleet behavior for
/// old Mac 0.8.42's trailing screenshot. Once predecessor drain begins,
/// historical `ended_at` is trusted finish intent. An existing unfinalized
/// receipt therefore remains provisionally writable across the signed
/// transition even before the bounded recurring importer has copied
/// `ended_at` into `finish_requested_at`; otherwise a legitimate offline
/// outbox item can race the importer and receive a 409.
async fn provisional_finish_authorized(
    connection: &mut sqlx::PgConnection,
    account_id: &str,
    capture_session_id: &str,
) -> Result<bool> {
    if !capture_formation_contract_installed(connection).await? {
        return Ok(true);
    }
    let state = sqlx::query(
        "SELECT (SELECT phase FROM persistence_feature_activation_events \
                   WHERE feature='episode_topology_reconciliation' \
                   ORDER BY generation DESC LIMIT 1) AS phase, \
                receipt.account_id IS NOT NULL AS receipt_exists, \
                receipt.finish_requested_at IS NOT NULL AS finish_requested, \
                receipt.seal_finalized_at IS NOT NULL AS seal_finalized \
           FROM (VALUES(1)) singleton(value) \
           LEFT JOIN capture_formation_receipts receipt \
             ON receipt.account_id=$1 AND receipt.capture_session_id=$2",
    )
    .bind(account_id)
    .bind(capture_session_id)
    .fetch_one(connection)
    .await?;
    Ok(provisional_finish_state_authorized(
        state.try_get::<Option<String>, _>("phase")?.as_deref(),
        state.try_get("receipt_exists")?,
        state.try_get("finish_requested")?,
        state.try_get("seal_finalized")?,
    ))
}

/// Return the append-only proof for the currently finalized seal. A non-null
/// stream boundary without this receipt/event pair is legacy or inconsistent
/// state and must not be reopened by the activation-capable writer.
async fn current_finalized_seal(
    connection: &mut sqlx::PgConnection,
    account_id: &str,
    capture_session_id: &str,
) -> Result<Option<SealReopen>> {
    if !capture_formation_contract_installed(connection).await? {
        return Ok(None);
    }
    let row = sqlx::query(
        "SELECT receipt.seal_generation \
           FROM capture_formation_receipts receipt \
           JOIN capture_formation_seal_events event \
             ON event.account_id=receipt.account_id \
            AND event.capture_session_id=receipt.capture_session_id \
            AND event.seal_generation=receipt.seal_generation \
            AND event.event_kind='seal' \
          WHERE receipt.account_id=$1 AND receipt.capture_session_id=$2 \
            AND receipt.seal_finalized_at IS NOT NULL \
            AND receipt.seal_generation>=1 \
            AND event.stream_maxima_sha256= \
                capture_formation_stream_maxima_sha256(receipt.account_id, \
                                                       receipt.capture_session_id) \
            AND NOT EXISTS(SELECT 1 FROM capture_formation_seal_events reopen \
                 WHERE reopen.account_id=receipt.account_id \
                   AND reopen.capture_session_id=receipt.capture_session_id \
                   AND reopen.seal_generation=receipt.seal_generation \
                   AND reopen.event_kind='reopen')",
    )
    .bind(account_id)
    .bind(capture_session_id)
    .fetch_optional(connection)
    .await?;
    row.map(|row| {
        Ok(SealReopen {
            generation: row.try_get("seal_generation")?,
            sealed_stream_count: 0,
        })
    })
    .transpose()
}

async fn validate_new_event_admission(
    connection: &mut sqlx::PgConnection,
    account_id: &str,
    manifest: &CaptureEventManifest,
) -> Result<()> {
    let session = sqlx::query(
        "SELECT device_id,install_id,ended_at IS NOT NULL AS ended \
           FROM capture_sessions WHERE account_id=$1 AND id=$2",
    )
    .bind(account_id)
    .bind(&manifest.capture_session_id)
    .fetch_optional(&mut *connection)
    .await?;
    let Some(session) = session else {
        return Ok(());
    };
    if session.try_get::<String, _>("device_id")? != manifest.device_id
        || session.try_get::<String, _>("install_id")? != manifest.install_id
    {
        return Err(EnclaveError::Conflict(
            "capture session ID was reused across devices or installs".into(),
        ));
    }
    let ended: bool = session.try_get("ended")?;
    let provisional_finish_authorized = if ended {
        provisional_finish_authorized(connection, account_id, &manifest.capture_session_id).await?
    } else {
        false
    };
    let late_seal_reopen_authorized = if ended {
        current_finalized_seal(connection, account_id, &manifest.capture_session_id)
            .await?
            .is_some()
    } else {
        false
    };
    let stream = sqlx::query(
        "SELECT capture_session_id,device_id,stream_kind,sealed_sequence \
           FROM capture_streams WHERE account_id=$1 AND id=$2",
    )
    .bind(account_id)
    .bind(&manifest.stream_id)
    .fetch_optional(&mut *connection)
    .await?;
    let Some(stream) = stream else {
        if ended && !provisional_finish_authorized && !late_seal_reopen_authorized {
            return Err(EnclaveError::Conflict(
                "ended capture session does not admit a new stream".into(),
            ));
        }
        return Ok(());
    };
    if stream.try_get::<String, _>("capture_session_id")? != manifest.capture_session_id
        || stream.try_get::<String, _>("device_id")? != manifest.device_id
        || stream.try_get::<String, _>("stream_kind")? != stream_kind(manifest.stream_kind)
    {
        return Err(EnclaveError::Conflict(
            "capture stream ID was reused with a different scope".into(),
        ));
    }
    stream_admission(
        ended,
        provisional_finish_authorized,
        late_seal_reopen_authorized,
        stream.try_get("sealed_sequence")?,
        manifest.sequence,
        manifest.session_finished.unwrap_or(false),
    )?;
    Ok(())
}

async fn require_active_account(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    account_id: &str,
) -> Result<()> {
    let status =
        sqlx::query_scalar::<_, String>("SELECT status FROM accounts WHERE id=$1 FOR UPDATE")
            .bind(account_id)
            .fetch_optional(&mut **transaction)
            .await?;
    match status.as_deref() {
        Some("active") => Ok(()),
        Some(_) => Err(EnclaveError::Conflict(
            "account does not admit capture writes".into(),
        )),
        None => Err(EnclaveError::NotFound),
    }
}

async fn stream_ack(
    executor: impl sqlx::Executor<'_, Database = sqlx::Postgres>,
    account_id: &str,
    stream_id: &str,
) -> Result<i64> {
    sqlx::query_scalar(
        "SELECT committed_through_sequence FROM capture_streams \
         WHERE account_id=$1 AND id=$2",
    )
    .bind(account_id)
    .bind(stream_id)
    .fetch_optional(executor)
    .await?
    .ok_or(EnclaveError::NotFound)
}

fn exact_deleted_event_replay(
    stored_stream_id: &str,
    stored_sequence: i64,
    stored_manifest_digest: &str,
    replay_stream_id: &str,
    replay_sequence: i64,
    replay_manifest_digest: &str,
) -> bool {
    stored_stream_id == replay_stream_id
        && stored_sequence == replay_sequence
        && stored_manifest_digest == replay_manifest_digest
}

async fn preflight(
    connection: &mut sqlx::PgConnection,
    account_id: &str,
    manifest: &CaptureEventManifest,
    manifest_digest: &str,
    allowed_object_keys: Option<&[String]>,
) -> Result<CapturePreflight> {
    let row = sqlx::query(
        "SELECT e.manifest_digest,m.object_key,e.stream_id,e.media_disposition \
           FROM capture_events e LEFT JOIN media_objects m \
             ON m.account_id=e.account_id AND m.event_id=e.event_id \
          WHERE e.account_id=$1 AND e.event_id=$2",
    )
    .bind(account_id)
    .bind(&manifest.event_id)
    .fetch_optional(&mut *connection)
    .await?;
    let Some(row) = row else {
        let deleted = if capture_formation_contract_installed(connection).await? {
            sqlx::query(
                "SELECT stream_id,sequence,original_manifest_digest \
                   FROM capture_formation_deleted_sequences \
                  WHERE account_id=$1 AND event_id=$2",
            )
            .bind(account_id)
            .bind(&manifest.event_id)
            .fetch_optional(&mut *connection)
            .await?
        } else {
            None
        };
        if let Some(deleted) = deleted {
            let stored_stream_id: String = deleted.try_get("stream_id")?;
            let stored_sequence: i64 = deleted.try_get("sequence")?;
            let stored_manifest_digest: String = deleted.try_get("original_manifest_digest")?;
            if !exact_deleted_event_replay(
                &stored_stream_id,
                stored_sequence,
                &stored_manifest_digest,
                &manifest.stream_id,
                manifest.sequence,
                manifest_digest,
            ) {
                return Err(EnclaveError::Conflict(
                    "idempotency conflict for erased capture event".into(),
                ));
            }
            return Ok(CapturePreflight::Duplicate {
                committed_through_sequence: stream_ack(
                    &mut *connection,
                    account_id,
                    &stored_stream_id,
                )
                .await?,
            });
        }
        validate_new_event_admission(connection, account_id, manifest).await?;
        return Ok(CapturePreflight::New);
    };
    let existing_digest: String = row.try_get("manifest_digest")?;
    let existing_object: Option<String> = row.try_get("object_key")?;
    let existing_stream: String = row.try_get("stream_id")?;
    let existing_disposition: String = row.try_get("media_disposition")?;
    let object_matches = match allowed_object_keys {
        Some(keys) => existing_object
            .as_deref()
            .is_some_and(|stored| keys.iter().any(|candidate| candidate == stored)),
        None => existing_object.is_none(),
    };
    if existing_digest != manifest_digest
        || existing_disposition != disposition(manifest.media_disposition)
        || !object_matches
    {
        return Err(EnclaveError::Conflict(
            "idempotency conflict for event_id".into(),
        ));
    }
    let committed_through_sequence = sqlx::query_scalar(
        "SELECT committed_through_sequence FROM capture_streams \
         WHERE account_id=$1 AND id=$2",
    )
    .bind(account_id)
    .bind(existing_stream)
    .fetch_optional(&mut *connection)
    .await?
    .ok_or_else(|| EnclaveError::Store("capture stream receipt is missing".into()))?;
    Ok(CapturePreflight::Duplicate {
        committed_through_sequence,
    })
}

async fn upsert_session_and_stream(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    account_id: &str,
    manifest: &CaptureEventManifest,
) -> Result<Option<SealReopen>> {
    let started_at_ms = timestamp(&manifest.started_at, "started_at")?;
    let ended_at_ms = timestamp(&manifest.ended_at, "ended_at")?;
    let session = sqlx::query(
        "SELECT device_id,install_id,ended_at IS NOT NULL AS ended \
           FROM capture_sessions WHERE account_id=$1 AND id=$2 FOR UPDATE",
    )
    .bind(account_id)
    .bind(&manifest.capture_session_id)
    .fetch_optional(&mut **transaction)
    .await?;
    let session_ended = if let Some(session) = session {
        if session.try_get::<String, _>("device_id")? != manifest.device_id
            || session.try_get::<String, _>("install_id")? != manifest.install_id
        {
            return Err(EnclaveError::Conflict(
                "capture session ID was reused across devices or installs".into(),
            ));
        }
        let ended = session.try_get("ended")?;
        sqlx::query(
            "UPDATE capture_sessions SET last_event_at=greatest(last_event_at, \
                    to_timestamp($3::double precision/1000.0)) \
              WHERE account_id=$1 AND id=$2",
        )
        .bind(account_id)
        .bind(&manifest.capture_session_id)
        .bind(ended_at_ms)
        .execute(&mut **transaction)
        .await?;
        ended
    } else {
        sqlx::query(
            "INSERT INTO capture_sessions \
             (account_id,id,device_id,install_id,started_at,last_event_at,schema_version,created_at) \
             VALUES ($1,$2,$3,$4,to_timestamp($5::double precision/1000.0), \
                     to_timestamp($6::double precision/1000.0),2,clock_timestamp())",
        )
        .bind(account_id)
        .bind(&manifest.capture_session_id)
        .bind(&manifest.device_id)
        .bind(&manifest.install_id)
        .bind(started_at_ms)
        .bind(ended_at_ms)
        .execute(&mut **transaction)
        .await?;
        false
    };

    let provisional_finish_authorized = if session_ended {
        provisional_finish_authorized(transaction, account_id, &manifest.capture_session_id).await?
    } else {
        false
    };
    let finalized_seal = if session_ended {
        current_finalized_seal(transaction, account_id, &manifest.capture_session_id).await?
    } else {
        None
    };
    let stream = sqlx::query(
        "SELECT capture_session_id,device_id,stream_kind,sealed_sequence \
           FROM capture_streams WHERE account_id=$1 AND id=$2 FOR UPDATE",
    )
    .bind(account_id)
    .bind(&manifest.stream_id)
    .fetch_optional(&mut **transaction)
    .await?;
    let stream_exists = stream.is_some();
    let sealed_sequence = if let Some(stream) = stream.as_ref() {
        if stream.try_get::<String, _>("capture_session_id")? != manifest.capture_session_id
            || stream.try_get::<String, _>("device_id")? != manifest.device_id
            || stream.try_get::<String, _>("stream_kind")? != stream_kind(manifest.stream_kind)
        {
            return Err(EnclaveError::Conflict(
                "capture stream ID was reused with a different scope".into(),
            ));
        }
        stream.try_get("sealed_sequence")?
    } else {
        if session_ended && !provisional_finish_authorized && finalized_seal.is_none() {
            return Err(EnclaveError::Conflict(
                "ended capture session does not admit a new stream".into(),
            ));
        }
        None
    };
    let admission = if !stream_exists && session_ended && finalized_seal.is_some() {
        StreamAdmission::LateSealReopen
    } else {
        stream_admission(
            session_ended,
            provisional_finish_authorized,
            finalized_seal.is_some(),
            sealed_sequence,
            manifest.sequence,
            manifest.session_finished.unwrap_or(false),
        )?
    };

    let seal_reopen = if admission == StreamAdmission::LateSealReopen {
        let finalized_seal = finalized_seal.ok_or_else(|| {
            EnclaveError::Conflict("capture seal reopen lost its audit authority".into())
        })?;
        let sealed_streams = sqlx::query(
            "SELECT stream.id,stream.sealed_sequence,stream.committed_through_sequence, \
                    capture_formation_stream_accepted_max(stream.account_id,stream.id) \
                        AS maximum_sequence, \
                    capture_formation_stream_contiguous_through(stream.account_id,stream.id) \
                        AS contiguous_through \
               FROM capture_streams stream \
              WHERE stream.account_id=$1 AND stream.capture_session_id=$2 \
              ORDER BY stream.id FOR UPDATE",
        )
        .bind(account_id)
        .bind(&manifest.capture_session_id)
        .fetch_all(&mut **transaction)
        .await?;
        if sealed_streams.is_empty()
            || sealed_streams.iter().any(|stream| {
                let sealed = stream.try_get::<Option<i64>, _>("sealed_sequence");
                let committed = stream.try_get::<i64, _>("committed_through_sequence");
                let maximum = stream.try_get::<Option<i64>, _>("maximum_sequence");
                let contiguous = stream.try_get::<Option<i64>, _>("contiguous_through");
                !matches!((sealed, committed, maximum, contiguous),
                    (Ok(Some(sealed)), Ok(committed), Ok(Some(maximum)), Ok(Some(contiguous)))
                        if sealed == committed && sealed == maximum && sealed == contiguous)
            })
        {
            return Err(EnclaveError::Conflict(
                "capture seal reopen found an inexact current stream boundary".into(),
            ));
        }
        Some(SealReopen {
            generation: finalized_seal.generation,
            sealed_stream_count: sealed_streams.len(),
        })
    } else {
        None
    };

    if !stream_exists {
        sqlx::query(
            "INSERT INTO capture_streams \
             (account_id,id,capture_session_id,device_id,stream_kind,created_at) \
             VALUES ($1,$2,$3,$4,$5,clock_timestamp())",
        )
        .bind(account_id)
        .bind(&manifest.stream_id)
        .bind(&manifest.capture_session_id)
        .bind(&manifest.device_id)
        .bind(stream_kind(manifest.stream_kind))
        .execute(&mut **transaction)
        .await?;
    }
    Ok(seal_reopen)
}

async fn record_provisional_finish(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    account_id: &str,
    capture_session_id: &str,
    ended_at_ms: Option<i64>,
    provenance: &str,
) -> Result<()> {
    if !matches!(
        provenance,
        "event_finish_v1" | "finish_endpoint_v1" | "legacy_client_refinish_v1"
    ) {
        return Err(EnclaveError::Store(
            "capture finish provenance is invalid".into(),
        ));
    }
    let has_stream = sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS(SELECT 1 FROM capture_streams \
          WHERE account_id=$1 AND capture_session_id=$2)",
    )
    .bind(account_id)
    .bind(capture_session_id)
    .fetch_one(&mut **transaction)
    .await?;
    if !has_stream {
        return Err(EnclaveError::Store(
            "capture session cannot finish without streams".into(),
        ));
    }
    let changed = sqlx::query(
        "UPDATE capture_sessions SET ended_at=coalesce(ended_at,CASE WHEN $3::bigint IS NULL \
                    THEN clock_timestamp() ELSE to_timestamp($3::double precision/1000.0) END) \
          WHERE account_id=$1 AND id=$2",
    )
    .bind(account_id)
    .bind(capture_session_id)
    .bind(ended_at_ms)
    .execute(&mut **transaction)
    .await?
    .rows_affected();
    if changed != 1 {
        return Err(EnclaveError::NotFound);
    }
    if !capture_formation_contract_installed(transaction).await? {
        return Ok(());
    }
    sqlx::query(
        "INSERT INTO capture_formation_receipts( \
             account_id,capture_session_id,source_revision,completed_revision,state, \
             finish_requested_at,finish_request_provenance,updated_at) \
         SELECT $1,$2,1,0,'pending', \
                CASE WHEN $3='legacy_client_refinish_v1' THEN session.ended_at \
                     ELSE clock_timestamp() END,$3,clock_timestamp() \
           FROM capture_sessions session \
          WHERE session.account_id=$1 AND session.id=$2 AND session.ended_at IS NOT NULL \
         ON CONFLICT(account_id,capture_session_id) DO UPDATE SET \
             finish_requested_at=coalesce(capture_formation_receipts.finish_requested_at, \
                                          excluded.finish_requested_at), \
             finish_request_provenance=coalesce(capture_formation_receipts.finish_request_provenance, \
                                                excluded.finish_request_provenance), \
             updated_at=clock_timestamp()",
    )
    .bind(account_id)
    .bind(capture_session_id)
    .bind(provenance)
    .execute(&mut **transaction)
    .await?;
    Ok(())
}

/// Mark exact capture-session formation work dirty when the additive v27
/// contract is installed. The activation-capable binary is deployed dark on
/// schema 26 first, so absence is an intentional no-op covered by the v27
/// install backfill; once present, every new accepted/materialized source
/// invalidates any older claim and reopens the session revision. The caller
/// must already hold the activation contract key-share fence followed by the
/// account reconciliation advisory lock.
pub(super) async fn mark_capture_formation_dirty(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    account_id: &str,
    capture_session_ids: &[String],
) -> Result<()> {
    let installed = sqlx::query_scalar::<_, bool>(
        "SELECT to_regclass('capture_formation_receipts') IS NOT NULL",
    )
    .fetch_one(&mut **transaction)
    .await?;
    if !installed {
        return Ok(());
    }
    let session_ids = capture_session_ids
        .iter()
        .map(String::as_str)
        .collect::<std::collections::BTreeSet<_>>();
    for capture_session_id in session_ids {
        sqlx::query(
            "INSERT INTO capture_formation_receipts( \
                 account_id,capture_session_id,source_revision,completed_revision,state,updated_at) \
             VALUES($1,$2,1,0,'pending',clock_timestamp()) \
             ON CONFLICT(account_id,capture_session_id) DO UPDATE SET \
                 source_revision=capture_formation_receipts.source_revision+1,state='pending', \
                 claimed_revision=NULL,claim_token=NULL,claim_until=NULL,next_attempt_at=NULL, \
                 claimed_source_fingerprint=NULL,completed_outcome=NULL, \
                 completed_claim_token=NULL,completed_source_fingerprint=NULL, \
                 completed_at=NULL,last_error_code=NULL, \
                 updated_at=clock_timestamp()",
        )
        .bind(account_id)
        .bind(capture_session_id)
        .execute(&mut **transaction)
        .await?;
        sqlx::query(
            "UPDATE capture_formation_pages page SET state='invalidated',claim_token=NULL, \
                    claim_until=NULL,provider_request=NULL,provider_request_sha256=NULL, \
                    staged_response=NULL,staged_response_sha256=NULL, \
                    staged_vertex_event_id=NULL,last_error_code='source_revision_invalidated', \
                    updated_at=clock_timestamp() \
              WHERE page.account_id=$1 AND page.capture_session_id=$2 \
                AND page.source_revision<(SELECT source_revision FROM capture_formation_receipts \
                      WHERE account_id=$1 AND capture_session_id=$2) \
                AND page.state<>'complete'",
        )
        .bind(account_id)
        .bind(capture_session_id)
        .execute(&mut **transaction)
        .await?;
    }
    super::memory_formation::invalidate_reconciliation_neighborhood_scan(transaction, account_id)
        .await?;
    Ok(())
}

async fn record_capture_seal_reopen(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    account_id: &str,
    capture_session_id: &str,
    trigger_event_id: &str,
    reopen: &SealReopen,
) -> Result<()> {
    if reopen.generation < 1 || reopen.sealed_stream_count == 0 {
        return Err(EnclaveError::Store(
            "capture seal reopen proof is malformed".into(),
        ));
    }
    let inserted = sqlx::query(
        "INSERT INTO capture_formation_seal_events( \
             account_id,capture_session_id,seal_generation,source_revision,event_kind, \
             stream_maxima_sha256,provenance,trigger_event_id,recorded_at) \
         SELECT receipt.account_id,receipt.capture_session_id,receipt.seal_generation, \
                receipt.source_revision,'reopen', \
                capture_formation_stream_maxima_sha256(receipt.account_id, \
                                                       receipt.capture_session_id), \
                'late_source_reopen_v1',$4,clock_timestamp() \
           FROM capture_formation_receipts receipt \
          WHERE receipt.account_id=$1 AND receipt.capture_session_id=$2 \
            AND receipt.seal_generation=$3 AND receipt.seal_finalized_at IS NOT NULL",
    )
    .bind(account_id)
    .bind(capture_session_id)
    .bind(reopen.generation)
    .bind(trigger_event_id)
    .execute(&mut **transaction)
    .await?
    .rows_affected();
    if inserted != 1 {
        return Err(EnclaveError::Conflict(
            "capture seal reopen lost its append-only audit claim".into(),
        ));
    }
    let cleared = sqlx::query(
        "UPDATE capture_streams SET sealed_sequence=NULL \
          WHERE account_id=$1 AND capture_session_id=$2 AND sealed_sequence IS NOT NULL",
    )
    .bind(account_id)
    .bind(capture_session_id)
    .execute(&mut **transaction)
    .await?
    .rows_affected();
    if usize::try_from(cleared).ok() != Some(reopen.sealed_stream_count) {
        return Err(EnclaveError::Conflict(
            "capture seal reopen did not clear every prior stream boundary".into(),
        ));
    }
    let changed = sqlx::query(
        "UPDATE capture_formation_receipts \
            SET seal_finalized_at=NULL,seal_finalization_provenance=NULL, \
                updated_at=clock_timestamp() \
          WHERE account_id=$1 AND capture_session_id=$2 \
            AND seal_generation=$3 AND seal_finalized_at IS NOT NULL",
    )
    .bind(account_id)
    .bind(capture_session_id)
    .bind(reopen.generation)
    .execute(&mut **transaction)
    .await?
    .rows_affected();
    if changed != 1 {
        return Err(EnclaveError::Conflict(
            "capture seal reopen lost its current receipt".into(),
        ));
    }
    Ok(())
}

async fn insert_browser_observation(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    account_id: &str,
    manifest: &CaptureEventManifest,
    committed_at_ms: i64,
) -> Result<()> {
    let Some(context) = manifest.context.as_ref() else {
        return Ok(());
    };
    if let Some(snapshot) = context.browser_snapshot.as_ref() {
        let tabs = if snapshot.state_key.contains(":browser-v2:") {
            serde_json::to_value(BrowserStateV2Envelope {
                schema_version: 2,
                active_window_index: snapshot.active_window_index,
                active_tab_index: snapshot.active_tab_index,
                reported_tab_count: snapshot.reported_tab_count,
                truncated: snapshot.truncated,
                ambient_tab_collection_enabled: snapshot
                    .ambient_tab_collection_enabled
                    .unwrap_or(false),
                tabs: snapshot.tabs.clone(),
            })?
        } else {
            serde_json::to_value(&snapshot.tabs)?
        };
        sqlx::query(
            "INSERT INTO browser_states_v2 \
             (account_id,state_key,browser_bundle_id,browser_name,permission_status,content_hash,tabs_json,created_at) \
             VALUES ($1,$2,$3,$4,$5,$6,$7::jsonb,to_timestamp($8::double precision/1000.0)) \
             ON CONFLICT (account_id,state_key) DO NOTHING",
        )
        .bind(account_id)
        .bind(&snapshot.state_key)
        .bind(&snapshot.browser_bundle_id)
        .bind(&snapshot.browser_name)
        .bind(&snapshot.permission_status)
        .bind(snapshot.content_hash.to_ascii_lowercase())
        .bind(serde_json::to_string(&tabs)?)
        .bind(committed_at_ms)
        .execute(&mut **transaction)
        .await?;
        let stored = sqlx::query(
            "SELECT browser_bundle_id,browser_name,permission_status,content_hash,tabs_json::text AS tabs_json \
             FROM browser_states_v2 WHERE account_id=$1 AND state_key=$2",
        )
        .bind(account_id)
        .bind(&snapshot.state_key)
        .fetch_one(&mut **transaction)
        .await?;
        let stored_tabs: serde_json::Value =
            serde_json::from_str(&stored.try_get::<String, _>("tabs_json")?)?;
        if stored.try_get::<String, _>("browser_bundle_id")? != snapshot.browser_bundle_id
            || stored.try_get::<String, _>("browser_name")? != snapshot.browser_name
            || stored.try_get::<String, _>("permission_status")? != snapshot.permission_status
            || stored.try_get::<String, _>("content_hash")?
                != snapshot.content_hash.to_ascii_lowercase()
            || stored_tabs != tabs
        {
            return Err(EnclaveError::Conflict(
                "browser state key was reused with different content".into(),
            ));
        }
    }
    if let Some(state_key) = context.browser_state_key.as_deref() {
        let exists = sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS(SELECT 1 FROM browser_states_v2 WHERE account_id=$1 AND state_key=$2)",
        )
        .bind(account_id)
        .bind(state_key)
        .fetch_one(&mut **transaction)
        .await?;
        if !exists {
            return Err(EnclaveError::InvalidRequest(
                "browser_state_key does not name an existing exact state".into(),
            ));
        }
    }
    sqlx::query(
        "INSERT INTO browser_observations_v2 \
         (account_id,observation_id,event_id,observed_at,state_key,context_status,active_url,active_title,created_at) \
         VALUES ($1,$2,$2,to_timestamp($3::double precision/1000.0),$4,$5,$6,$7, \
                 to_timestamp($8::double precision/1000.0))",
    )
    .bind(account_id)
    .bind(&manifest.event_id)
    .bind(timestamp(&manifest.source_wall_at, "source_wall_at")?)
    .bind(context.browser_state_key.as_deref())
    .bind(&context.capture_status)
    .bind(context.active_url.as_deref())
    .bind(context.active_url_title.as_deref())
    .bind(committed_at_ms)
    .execute(&mut **transaction)
    .await?;
    Ok(())
}

async fn advance_ack(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    account_id: &str,
    stream_id: &str,
) -> Result<i64> {
    let row = sqlx::query(
        "SELECT committed_through_sequence,sealed_sequence FROM capture_streams \
          WHERE account_id=$1 AND id=$2 FOR UPDATE",
    )
    .bind(account_id)
    .bind(stream_id)
    .fetch_optional(&mut **transaction)
    .await?
    .ok_or(EnclaveError::NotFound)?;
    let current: i64 = row.try_get("committed_through_sequence")?;
    let sealed_sequence: Option<i64> = row.try_get("sealed_sequence")?;
    if sealed_sequence.is_some_and(|sealed| current > sealed) {
        return Err(EnclaveError::Store(
            "capture acknowledgement exceeds its sealed stream boundary".into(),
        ));
    }
    let sequences = if capture_formation_contract_installed(transaction).await? {
        sqlx::query_scalar::<_, i64>(
            "SELECT accepted.sequence FROM ( \
                 SELECT sequence FROM capture_events \
                  WHERE account_id=$1 AND stream_id=$2 \
                 UNION \
                 SELECT sequence FROM capture_formation_deleted_sequences \
                  WHERE account_id=$1 AND stream_id=$2 \
             ) accepted \
             WHERE accepted.sequence>$3 \
               AND ($4::bigint IS NULL OR accepted.sequence<=$4) \
             ORDER BY accepted.sequence",
        )
        .bind(account_id)
        .bind(stream_id)
        .bind(current)
        .bind(sealed_sequence)
        .fetch_all(&mut **transaction)
        .await?
    } else {
        sqlx::query_scalar::<_, i64>(
            "SELECT sequence FROM capture_events \
             WHERE account_id=$1 AND stream_id=$2 AND sequence>$3 \
               AND ($4::bigint IS NULL OR sequence<=$4) ORDER BY sequence",
        )
        .bind(account_id)
        .bind(stream_id)
        .bind(current)
        .bind(sealed_sequence)
        .fetch_all(&mut **transaction)
        .await?
    };
    let advanced = contiguous_ack(current, sequences);
    if advanced > current {
        sqlx::query(
            "UPDATE capture_streams SET committed_through_sequence=$3 \
             WHERE account_id=$1 AND id=$2",
        )
        .bind(account_id)
        .bind(stream_id)
        .bind(advanced)
        .execute(&mut **transaction)
        .await?;
    }
    Ok(advanced)
}

fn contiguous_ack(current: i64, sequences: impl IntoIterator<Item = i64>) -> i64 {
    let mut advanced = current;
    for sequence in sequences {
        if sequence == advanced + 1 {
            advanced = sequence;
        } else if sequence > advanced + 1 {
            break;
        }
    }
    advanced
}

async fn insert_event(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    command: &CaptureCommit,
) -> Result<CaptureCommitResult> {
    let manifest = &command.manifest;
    manifest.validate()?;
    let allowed_keys = command.object_key.as_ref().map(|value| vec![value.clone()]);
    if let CapturePreflight::Duplicate {
        committed_through_sequence,
    } = preflight(
        transaction,
        &command.account_id,
        manifest,
        &command.manifest_digest,
        allowed_keys.as_deref(),
    )
    .await?
    {
        return Ok(CaptureCommitResult {
            duplicate: true,
            committed_through_sequence,
        });
    }
    match manifest.media_disposition {
        MediaDisposition::Canonical => {
            let media = manifest.media.as_ref().ok_or_else(|| {
                EnclaveError::InvalidRequest("canonical media is required".into())
            })?;
            let object_key = command.object_key.as_deref().ok_or_else(|| {
                EnclaveError::InvalidRequest("canonical capture object key is required".into())
            })?;
            let upload_token = command.upload_token.as_deref().ok_or_else(|| {
                EnclaveError::Conflict("canonical media upload admission is missing".into())
            })?;
            let admitted = sqlx::query_scalar::<_, bool>(
                "SELECT EXISTS(SELECT 1 FROM capture_upload_intents \
                  WHERE account_id=$1 AND event_id=$2 AND token=$3 AND asset_id=$4 \
                    AND object_key=$5 AND manifest_digest=$6 AND expires_at>now())",
            )
            .bind(&command.account_id)
            .bind(&manifest.event_id)
            .bind(upload_token)
            .bind(&media.asset_id)
            .bind(object_key)
            .bind(command.manifest_digest.to_ascii_lowercase())
            .fetch_one(&mut **transaction)
            .await?;
            if !admitted {
                return Err(EnclaveError::Conflict(
                    "canonical media upload admission is unavailable".into(),
                ));
            }
        }
        MediaDisposition::Reference if command.upload_token.is_some() => {
            return Err(EnclaveError::InvalidRequest(
                "reference capture cannot carry media upload admission".into(),
            ));
        }
        MediaDisposition::Reference => {}
    }
    let committed_at_ms = timestamp(&command.committed_at, "committed_at")?;
    let seal_reopen = upsert_session_and_stream(transaction, &command.account_id, manifest).await?;
    let sequence_used = if capture_formation_contract_installed(transaction).await? {
        sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS( \
                 SELECT 1 FROM capture_events \
                  WHERE account_id=$1 AND stream_id=$2 AND sequence=$3 \
                 UNION ALL \
                 SELECT 1 FROM capture_formation_deleted_sequences \
                  WHERE account_id=$1 AND stream_id=$2 AND sequence=$3)",
        )
        .bind(&command.account_id)
        .bind(&manifest.stream_id)
        .bind(manifest.sequence)
        .fetch_one(&mut **transaction)
        .await?
    } else {
        sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS(SELECT 1 FROM capture_events \
             WHERE account_id=$1 AND device_id=$2 AND stream_id=$3 AND sequence=$4)",
        )
        .bind(&command.account_id)
        .bind(&manifest.device_id)
        .bind(&manifest.stream_id)
        .bind(manifest.sequence)
        .fetch_one(&mut **transaction)
        .await?
    };
    if sequence_used {
        return Err(EnclaveError::Conflict(
            "idempotency conflict for stream sequence".into(),
        ));
    }

    let (asset_id, reference) = match manifest.media_disposition {
        MediaDisposition::Canonical => (
            manifest
                .media
                .as_ref()
                .ok_or_else(|| EnclaveError::InvalidRequest("canonical media is required".into()))?
                .asset_id
                .clone(),
            None,
        ),
        MediaDisposition::Reference => {
            let reference = manifest.reference.as_ref().ok_or_else(|| {
                EnclaveError::InvalidRequest("reference metadata is required".into())
            })?;
            let context = manifest.context.as_ref().ok_or_else(|| {
                EnclaveError::InvalidRequest("reference events require capture context".into())
            })?;
            if !reference.context_fingerprint.eq_ignore_ascii_case(
                &media::semantic_context_fingerprint(context, reference.dedupe_version)?,
            ) {
                return Err(EnclaveError::CaptureReference(
                    CaptureReferenceFailureReason::ContextFingerprintMismatch,
                ));
            }
            let pending_deletion = sqlx::query_scalar::<_, bool>(
                "SELECT EXISTS(SELECT 1 FROM episode_deletions deletion \
                  WHERE deletion.account_id=$1 AND deletion.state='pending' \
                    AND deletion.orphan_event_ids ? $2)",
            )
            .bind(&command.account_id)
            .bind(&reference.canonical_event_id)
            .fetch_one(&mut **transaction)
            .await?;
            if pending_deletion {
                return Err(EnclaveError::Conflict(
                    "capture reference target is pending episode deletion".into(),
                ));
            }
            let canonical = sqlx::query(
                "SELECT e.device_id,e.install_id,e.capture_session_id,e.stream_id,e.sequence, \
                        e.media_disposition,e.context_json::text AS context_json,m.asset_id,m.sha256 \
                   FROM capture_events e JOIN media_objects m \
                     ON m.account_id=e.account_id AND m.event_id=e.event_id \
                  WHERE e.account_id=$1 AND e.event_id=$2",
            )
            .bind(&command.account_id)
            .bind(&reference.canonical_event_id)
            .fetch_optional(&mut **transaction)
            .await?
            .ok_or(EnclaveError::CaptureReference(
                CaptureReferenceFailureReason::CanonicalUnavailable,
            ))?;
            if canonical.try_get::<String, _>("media_disposition")? != "canonical"
                || canonical.try_get::<String, _>("device_id")? != manifest.device_id
                || canonical.try_get::<String, _>("install_id")? != manifest.install_id
                || canonical.try_get::<String, _>("capture_session_id")?
                    != manifest.capture_session_id
                || canonical.try_get::<String, _>("stream_id")? != manifest.stream_id
                || canonical.try_get::<i64, _>("sequence")? >= manifest.sequence
                || canonical.try_get::<String, _>("asset_id")? != reference.canonical_asset_id
                || !canonical
                    .try_get::<String, _>("sha256")?
                    .eq_ignore_ascii_case(&reference.canonical_media_sha256)
            {
                return Err(EnclaveError::CaptureReference(
                    CaptureReferenceFailureReason::TargetMismatch,
                ));
            }
            let canonical_context: CaptureContext = canonical
                .try_get::<Option<String>, _>("context_json")?
                .ok_or(EnclaveError::CaptureReference(
                    CaptureReferenceFailureReason::CanonicalContextUnavailable,
                ))
                .and_then(|raw| {
                    serde_json::from_str(&raw).map_err(|_| {
                        EnclaveError::CaptureReference(
                            CaptureReferenceFailureReason::CanonicalContextUnavailable,
                        )
                    })
                })?;
            if media::semantic_context_value(&canonical_context, reference.dedupe_version)
                != media::semantic_context_value(context, reference.dedupe_version)
            {
                return Err(EnclaveError::CaptureReference(
                    CaptureReferenceFailureReason::ContextTransition,
                ));
            }
            (format!("reference-{}", manifest.event_id), Some(reference))
        }
    };
    let context_json = manifest
        .context
        .as_ref()
        .map(serde_json::to_string)
        .transpose()?;
    let source_monotonic_ns = manifest.source_monotonic_ns.to_string();
    sqlx::query(
        "INSERT INTO capture_events \
         (account_id,event_id,device_id,install_id,capture_session_id,stream_id,stream_kind,sequence, \
          source_wall_at,source_monotonic_ns,started_at,ended_at,timezone_id,utc_offset_minutes, \
          clock_uncertainty_ms,asset_id,manifest_digest,context_json,media_disposition, \
          canonical_event_id,canonical_asset_id,canonical_media_sha256,perceptual_hash, \
          hamming_distance,pixel_change_ratio,context_fingerprint,dedupe_version, \
          audio_role,audio_route,route_epoch,received_at) \
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,to_timestamp($9::double precision/1000.0),$10, \
                 to_timestamp($11::double precision/1000.0),to_timestamp($12::double precision/1000.0), \
                 $13,$14,$15,$16,$17,$18::jsonb,$19,$20,$21,$22,$23,$24,$25,$26,$27,$28,$29,$30, \
                 clock_timestamp())",
    )
    .bind(&command.account_id)
    .bind(&manifest.event_id)
    .bind(&manifest.device_id)
    .bind(&manifest.install_id)
    .bind(&manifest.capture_session_id)
    .bind(&manifest.stream_id)
    .bind(match manifest.stream_kind {
        media::StreamKind::Mic => "mic",
        media::StreamKind::SystemAudio => "system_audio",
        media::StreamKind::MacScreen => "mac_screen",
        media::StreamKind::IosMic => "ios_mic",
        media::StreamKind::IosImportedScreenshot => "ios_imported_screenshot",
        media::StreamKind::IosSharedPage => "ios_shared_page",
    })
    .bind(manifest.sequence)
    .bind(timestamp(&manifest.source_wall_at, "source_wall_at")?)
    .bind(source_monotonic_ns)
    .bind(timestamp(&manifest.started_at, "started_at")?)
    .bind(timestamp(&manifest.ended_at, "ended_at")?)
    .bind(&manifest.timezone_id)
    .bind(i64::from(manifest.utc_offset_minutes))
    .bind(i64::from(manifest.clock_uncertainty_ms))
    .bind(&asset_id)
    .bind(command.manifest_digest.to_ascii_lowercase())
    .bind(context_json)
    .bind(disposition(manifest.media_disposition))
    .bind(reference.map(|value| value.canonical_event_id.as_str()))
    .bind(reference.map(|value| value.canonical_asset_id.as_str()))
    .bind(reference.map(|value| value.canonical_media_sha256.to_ascii_lowercase()))
    .bind(reference.map(|value| value.perceptual_hash.to_ascii_lowercase()))
    .bind(reference.map(|value| i64::from(value.hamming_distance)))
    .bind(reference.map(|value| value.pixel_change_ratio))
    .bind(reference.map(|value| value.context_fingerprint.to_ascii_lowercase()))
    .bind(reference.map(|value| i64::from(value.dedupe_version)))
    .bind(manifest.audio_role.as_deref())
    .bind(manifest.audio_route.as_deref())
    .bind(manifest.route_epoch.map(|value| value as i64))
    .execute(&mut **transaction)
    .await?;

    if let MediaDisposition::Canonical = manifest.media_disposition {
        let media = manifest.media.as_ref().expect("validated canonical media");
        let object_key = command.object_key.as_deref().ok_or_else(|| {
            EnclaveError::InvalidRequest("canonical capture object key is required".into())
        })?;
        let generation = command
            .object_generation
            .filter(|value| *value > 0)
            .ok_or_else(|| {
                EnclaveError::InvalidRequest("canonical capture generation must be positive".into())
            })?;
        let authority = command.media_authority.as_ref().ok_or_else(|| {
            EnclaveError::InvalidRequest("canonical media authority is required".into())
        })?;
        let expected_object_key = if authority.is_durable() {
            crate::gcs::canonical_recording_media_object_key(&command.account_id, &media.asset_id)?
        } else {
            crate::gcs::canonical_capture_media_object_key(&command.account_id, &media.asset_id)?
        };
        if object_key != expected_object_key {
            return Err(EnclaveError::InvalidRequest(
                "object_key does not match the settled retention decision".into(),
            ));
        }
        let retain_until = match authority {
            RecordingMediaAuthorityDecision::ProcessingWindow30d { .. } => {
                Some(isotime::parse_epoch_millis(&isotime::add_seconds(
                    &manifest.ended_at,
                    30.0 * 86_400.0,
                )))
                .flatten()
            }
            RecordingMediaAuthorityDecision::UntilDeleted { .. } => None,
        };
        sqlx::query(
            "INSERT INTO media_objects \
             (account_id,asset_id,event_id,object_key,object_generation,object_backend,mime_type,codec, \
              byte_length,sha256,sample_rate,channels,frame_count,width,height,scale,orientation,retain_until,created_at) \
             VALUES ($1,$2,$3,$4,$5,'current',$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16, \
                     CASE WHEN $17::bigint IS NULL THEN NULL ELSE to_timestamp($17::double precision/1000.0) END, \
                     to_timestamp($18::double precision/1000.0))",
        )
        .bind(&command.account_id)
        .bind(&media.asset_id)
        .bind(&manifest.event_id)
        .bind(object_key)
        .bind(generation)
        .bind(&media.mime_type)
        .bind(&media.codec)
        .bind(media.byte_length)
        .bind(media.sha256.to_ascii_lowercase())
        .bind(media.sample_rate)
        .bind(media.channels)
        .bind(media.frame_count)
        .bind(media.width)
        .bind(media.height)
        .bind(media.scale)
        .bind(media.orientation.as_deref())
        .bind(retain_until)
        .bind(committed_at_ms)
        .execute(&mut **transaction)
        .await?;
        let (capture_revision, retention_revision, epoch, decision, backend, key_epoch, state, at) =
            match authority {
                RecordingMediaAuthorityDecision::ProcessingWindow30d {
                    capture_policy_revision,
                    decision_at,
                } => (
                    *capture_policy_revision,
                    0,
                    None,
                    "processing_window_30d",
                    "processing",
                    None,
                    "processing_only",
                    decision_at.as_str(),
                ),
                RecordingMediaAuthorityDecision::UntilDeleted {
                    capture_policy_revision,
                    retention_policy_revision,
                    retention_policy_epoch,
                    recording_key_epoch,
                    decision_at,
                } => (
                    *capture_policy_revision,
                    *retention_policy_revision,
                    Some(retention_policy_epoch.as_str()),
                    "until_deleted",
                    "recordings",
                    Some(*recording_key_epoch),
                    "durable",
                    decision_at.as_str(),
                ),
            };
        let authority_at = timestamp(at, "media authority decision_at")?;
        sqlx::query(
            "INSERT INTO recording_media_authority \
             (account_id,asset_id,capture_policy_revision,retention_policy_revision, \
              retention_policy_epoch,retention_decision,storage_backend,recording_key_epoch, \
              recording_state,decision_at,updated_at) \
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,to_timestamp($10::double precision/1000.0), \
                     to_timestamp($10::double precision/1000.0))",
        )
        .bind(&command.account_id)
        .bind(&media.asset_id)
        .bind(capture_revision)
        .bind(retention_revision)
        .bind(epoch)
        .bind(decision)
        .bind(backend)
        .bind(key_epoch)
        .bind(state)
        .bind(authority_at)
        .execute(&mut **transaction)
        .await?;
        insert_browser_observation(transaction, &command.account_id, manifest, committed_at_ms)
            .await?;
        let job_kind = if manifest.stream_kind.is_audio() {
            "gemini_audio"
        } else {
            "gemini_screen"
        };
        sqlx::query(
            "INSERT INTO media_processing_jobs \
             (account_id,event_id,job_kind,input_revision,processor_version,state,updated_at) \
             VALUES ($1,$2,$3,$4,1,'pending',clock_timestamp())",
        )
        .bind(&command.account_id)
        .bind(&manifest.event_id)
        .bind(job_kind)
        .bind(&command.manifest_digest)
        .execute(&mut **transaction)
        .await?;
        sqlx::query(
            "INSERT INTO outbox_events \
             (account_id,event_id,event_kind,aggregate_id,payload,created_at,available_at) \
             VALUES ($1,$2,'capture_media_queued',$3,$4::jsonb, \
                     to_timestamp($5::double precision/1000.0),to_timestamp($5::double precision/1000.0))",
        )
        .bind(&command.account_id)
        .bind(format!("capture:{}", manifest.event_id))
        .bind(&manifest.event_id)
        .bind(serde_json::to_string(&json!({
            "event_id": manifest.event_id,
            "job_kind": job_kind,
            "input_revision": command.manifest_digest,
        }))?)
        .bind(committed_at_ms)
        .execute(&mut **transaction)
        .await?;
    } else {
        insert_browser_observation(transaction, &command.account_id, manifest, committed_at_ms)
            .await?;
    }

    if let Some(upload_token) = command.upload_token.as_deref() {
        let deleted = sqlx::query(
            "DELETE FROM capture_upload_intents \
              WHERE account_id=$1 AND event_id=$2 AND token=$3",
        )
        .bind(&command.account_id)
        .bind(&manifest.event_id)
        .bind(upload_token)
        .execute(&mut **transaction)
        .await?
        .rows_affected();
        if deleted != 1 {
            return Err(EnclaveError::Conflict(
                "canonical media upload admission disappeared".into(),
            ));
        }
    }

    let mut committed_through_sequence =
        advance_ack(transaction, &command.account_id, &manifest.stream_id).await?;
    mark_capture_formation_dirty(
        transaction,
        &command.account_id,
        std::slice::from_ref(&manifest.capture_session_id),
    )
    .await?;
    if let Some(seal_reopen) = seal_reopen.as_ref() {
        record_capture_seal_reopen(
            transaction,
            &command.account_id,
            &manifest.capture_session_id,
            &manifest.event_id,
            seal_reopen,
        )
        .await?;
        // The first acknowledgement is deliberately evaluated against the
        // still-current seal so the append-only reopen event commits the exact
        // old-boundary/new-source mismatch. Once that proof clears the current
        // seals, advance again so a contiguous late event is immediately and
        // durably acknowledged.
        committed_through_sequence =
            advance_ack(transaction, &command.account_id, &manifest.stream_id).await?;
    }
    if manifest.session_finished == Some(true) {
        // A finish marker is a durable request, not an immediate immutable
        // boundary. Mac 0.8.42 can still have an in-flight screenshot after
        // its final audio event; the bounded quiet sealer closes all streams
        // only after that compatibility grace has proven complete.
        record_provisional_finish(
            transaction,
            &command.account_id,
            &manifest.capture_session_id,
            Some(timestamp(&manifest.ended_at, "ended_at")?),
            "event_finish_v1",
        )
        .await?;
    }
    Ok(CaptureCommitResult {
        duplicate: false,
        committed_through_sequence,
    })
}

#[allow(clippy::too_many_arguments)]
fn capture_session_stage(
    queued: i64,
    processing: i64,
    retry_wait: i64,
    failed: i64,
    has_ready_memory: bool,
    has_memories: bool,
    ended: bool,
    summarized_past_end: bool,
) -> CaptureSessionStage {
    if queued + processing > 0 {
        CaptureSessionStage::Processing
    } else if has_ready_memory {
        CaptureSessionStage::Ready
    } else if retry_wait > 0 {
        CaptureSessionStage::Processing
    } else if has_memories {
        CaptureSessionStage::PreparingRecap
    } else if failed > 0 {
        // Media failures are internal restartable work, not a user-repairable
        // condition. Keep the session visibly processing while the summarizer
        // cursor is held for automatic recovery; once that cursor has honestly
        // passed an ended session without a memory, report the zero-result
        // outcome instead of exposing worker state as an action item.
        if ended && summarized_past_end {
            CaptureSessionStage::NoMemory
        } else {
            CaptureSessionStage::Processing
        }
    } else if ended {
        if summarized_past_end {
            CaptureSessionStage::NoMemory
        } else {
            CaptureSessionStage::Organizing
        }
    } else {
        CaptureSessionStage::Received
    }
}

async fn postgres_session_status(
    persistence: &PostgresPersistence,
    account_id: &str,
    capture_session_id: &str,
    summarized_until_ms: Option<i64>,
) -> Result<Option<CaptureSessionStatus>> {
    let session = sqlx::query(
        "SELECT id,device_id, \
                floor(extract(epoch FROM started_at)*1000)::bigint AS started_at_ms, \
                floor(extract(epoch FROM last_event_at)*1000)::bigint AS last_event_at_ms, \
                floor(extract(epoch FROM ended_at)*1000)::bigint AS ended_at_ms \
           FROM capture_sessions WHERE account_id=$1 AND id=$2",
    )
    .bind(account_id)
    .bind(capture_session_id)
    .fetch_optional(persistence.pool())
    .await?;
    let Some(session) = session else {
        return Ok(None);
    };
    let started_at = isotime::format_epoch_millis(session.try_get("started_at_ms")?);
    let last_event_at = isotime::format_epoch_millis(session.try_get("last_event_at_ms")?);
    let ended_at_ms: Option<i64> = session.try_get("ended_at_ms")?;
    let ended_at = ended_at_ms.map(isotime::format_epoch_millis);

    let processing = sqlx::query(
        "SELECT count(*)::bigint AS event_count, \
                count(*) FILTER (WHERE coalesce(m.processing_state,'ready')='queued')::bigint AS queued, \
                count(*) FILTER (WHERE coalesce(m.processing_state,'ready')='processing')::bigint AS processing, \
                count(*) FILTER (WHERE coalesce(m.processing_state,'ready')='retry_wait')::bigint AS retry_wait, \
                count(*) FILTER (WHERE coalesce(m.processing_state,'ready') IN ('ready','pruned'))::bigint AS ready, \
                count(*) FILTER (WHERE coalesce(m.processing_state,'ready')='failed')::bigint AS failed \
           FROM capture_events e LEFT JOIN media_objects m \
             ON m.account_id=e.account_id AND m.event_id=e.event_id \
          WHERE e.account_id=$1 AND e.capture_session_id=$2",
    )
    .bind(account_id)
    .bind(capture_session_id)
    .fetch_one(persistence.pool())
    .await?;
    let event_count: i64 = processing.try_get("event_count")?;
    let queued: i64 = processing.try_get("queued")?;
    let processing_count: i64 = processing.try_get("processing")?;
    let retry_wait: i64 = processing.try_get("retry_wait")?;
    let ready: i64 = processing.try_get("ready")?;
    let failed: i64 = processing.try_get("failed")?;

    let memory_rows = sqlx::query(
        "SELECT DISTINCT e.id,e.title,e.finalization_status, \
                floor(extract(epoch FROM e.started_at)*1000)::bigint AS started_at_ms, \
                floor(extract(epoch FROM e.ended_at)*1000)::bigint AS ended_at_ms, \
                floor(extract(epoch FROM e.finalized_at)*1000)::bigint AS finalized_at_ms \
           FROM episodes e JOIN episode_members m \
             ON m.account_id=e.account_id AND m.episode_id=e.id \
           LEFT JOIN utterances u ON u.account_id=m.account_id \
             AND m.record_type='utterance' AND u.id=m.record_id \
           LEFT JOIN screenshots s ON s.account_id=m.account_id \
             AND m.record_type='screenshot' AND s.id=m.record_id \
           JOIN capture_events ce ON ce.account_id=e.account_id AND ce.capture_session_id=$2 \
             AND ((u.source_key LIKE 'cloud-v2:'||ce.event_id||':%') \
               OR s.source_key='cloud-v2:'||ce.event_id) \
          WHERE e.account_id=$1 AND e.substance!='none' \
          ORDER BY started_at_ms DESC,e.id DESC",
    )
    .bind(account_id)
    .bind(capture_session_id)
    .fetch_all(persistence.pool())
    .await?;
    let memories = memory_rows
        .iter()
        .map(|row| {
            Ok(CaptureSessionMemory {
                id: row.try_get("id")?,
                title: row.try_get("title")?,
                started_at: isotime::format_epoch_millis(row.try_get("started_at_ms")?),
                ended_at: isotime::format_epoch_millis(row.try_get("ended_at_ms")?),
                finalization_status: row.try_get("finalization_status")?,
                finalized_at: row
                    .try_get::<Option<i64>, _>("finalized_at_ms")?
                    .map(isotime::format_epoch_millis),
            })
        })
        .collect::<Result<Vec<_>>>()?;

    let audio_minutes = sqlx::query_scalar::<_, Option<i64>>(
        "SELECT round(max(kind_seconds)/60.0)::bigint FROM ( \
           SELECT sum(extract(epoch FROM (ended_at-started_at))) AS kind_seconds \
             FROM capture_events WHERE account_id=$1 AND capture_session_id=$2 \
              AND stream_kind IN ('mic','system_audio','ios_mic') GROUP BY stream_kind) kinds",
    )
    .bind(account_id)
    .bind(capture_session_id)
    .fetch_one(persistence.pool())
    .await?;
    let voice_count = sqlx::query_scalar::<_, i64>(
        "SELECT count(DISTINCT u.speaker_label)::bigint FROM capture_events ce JOIN utterances u \
           ON u.account_id=ce.account_id AND u.source_key LIKE 'cloud-v2:'||ce.event_id||':%' \
          WHERE ce.account_id=$1 AND ce.capture_session_id=$2 AND u.speaker_label!=''",
    )
    .bind(account_id)
    .bind(capture_session_id)
    .fetch_one(persistence.pool())
    .await?;
    let top_contexts = sqlx::query_scalar::<_, String>(
        "SELECT s.active_app FROM capture_events ce JOIN screenshots s \
           ON s.account_id=ce.account_id AND s.source_key='cloud-v2:'||ce.event_id \
          WHERE ce.account_id=$1 AND ce.capture_session_id=$2 \
            AND s.active_app IS NOT NULL AND s.active_app!='' \
          GROUP BY s.active_app ORDER BY count(*) DESC,s.active_app LIMIT 3",
    )
    .bind(account_id)
    .bind(capture_session_id)
    .fetch_all(persistence.pool())
    .await?;

    let has_ready_memory = memories
        .iter()
        .any(|memory| memory.finalization_status == "complete" && memory.finalized_at.is_some());
    let summarized_past_end = ended_at_ms
        .zip(summarized_until_ms)
        .is_some_and(|(ended, cursor)| cursor > ended);
    let stage = capture_session_stage(
        queued,
        processing_count,
        retry_wait,
        failed,
        has_ready_memory,
        !memories.is_empty(),
        ended_at.is_some(),
        summarized_past_end,
    );
    Ok(Some(CaptureSessionStatus {
        capture_session_id: session.try_get("id")?,
        device_id: session.try_get("device_id")?,
        started_at,
        last_event_at,
        ended_at,
        event_count,
        stage,
        processing: CaptureSessionProcessing {
            queued,
            processing: processing_count,
            retry_wait,
            ready,
            failed,
        },
        evidence: CaptureSessionEvidence {
            audio_minutes,
            voice_count: (voice_count > 0).then_some(voice_count),
            top_contexts,
        },
        memories,
    }))
}

#[async_trait]
impl CaptureRepository for PostgresPersistence {
    async fn preflight_event(
        &self,
        account_id: &str,
        manifest: &CaptureEventManifest,
        manifest_digest: &str,
        allowed_object_keys: Option<&[String]>,
    ) -> Result<CapturePreflight> {
        let mut connection = self.pool().acquire().await?;
        preflight(
            &mut connection,
            account_id,
            manifest,
            manifest_digest,
            allowed_object_keys,
        )
        .await
    }

    async fn reserve_media_upload(
        &self,
        account_id: &str,
        event_id: &str,
        asset_id: &str,
        object_key: &str,
        manifest_digest: &str,
    ) -> Result<Option<String>> {
        if event_id.is_empty()
            || asset_id.is_empty()
            || object_key.is_empty()
            || manifest_digest.len() != 64
            || !manifest_digest.bytes().all(|byte| byte.is_ascii_hexdigit())
        {
            return Err(EnclaveError::InvalidRequest(
                "canonical media upload admission is invalid".into(),
            ));
        }
        let mut transaction = self.pool().begin().await?;
        advisory_transaction_lock(&mut transaction, "capture-upload", event_id).await?;
        require_active_account(&mut transaction, account_id).await?;
        let candidate = format!("upl_{}", crate::cp::tokens::random_token_hex());
        let token = sqlx::query_scalar::<_, String>(
            "INSERT INTO capture_upload_intents \
                (account_id,event_id,token,asset_id,object_key,manifest_digest,expires_at) \
             VALUES ($1,$2,$3,$4,$5,$6,now()+interval '10 minutes') \
             ON CONFLICT (account_id,event_id) DO UPDATE SET \
                token=CASE WHEN capture_upload_intents.expires_at<=now() \
                           THEN EXCLUDED.token ELSE capture_upload_intents.token END, \
                expires_at=now()+interval '10 minutes' \
             WHERE capture_upload_intents.asset_id=EXCLUDED.asset_id \
               AND capture_upload_intents.object_key=EXCLUDED.object_key \
               AND capture_upload_intents.manifest_digest=EXCLUDED.manifest_digest \
             RETURNING token",
        )
        .bind(account_id)
        .bind(event_id)
        .bind(candidate)
        .bind(asset_id)
        .bind(object_key)
        .bind(manifest_digest.to_ascii_lowercase())
        .fetch_optional(&mut *transaction)
        .await?
        .ok_or_else(|| {
            EnclaveError::Conflict("idempotency conflict for media upload admission".into())
        })?;
        transaction.commit().await?;
        Ok(Some(token))
    }

    async fn media_dek_wrapped(&self, account_id: &str) -> Result<Option<String>> {
        Ok(sqlx::query_scalar(
            "SELECT k.wrapped_dek FROM account_media_keys k JOIN accounts a ON a.id=k.account_id \
              WHERE k.account_id=$1 AND a.status='active'",
        )
        .bind(account_id)
        .fetch_optional(self.pool())
        .await?)
    }

    async fn install_media_dek(&self, account_id: &str, candidate_wrapped: &str) -> Result<String> {
        if candidate_wrapped.is_empty() {
            return Err(EnclaveError::InvalidRequest(
                "wrapped media DEK must not be empty".into(),
            ));
        }
        let mut transaction = self.pool().begin().await?;
        require_active_account(&mut transaction, account_id).await?;
        sqlx::query(
            "INSERT INTO account_media_keys(account_id,wrapped_dek) VALUES($1,$2) \
             ON CONFLICT(account_id) DO NOTHING",
        )
        .bind(account_id)
        .bind(candidate_wrapped)
        .execute(&mut *transaction)
        .await?;
        let winner = sqlx::query_scalar::<_, String>(
            "SELECT wrapped_dek FROM account_media_keys WHERE account_id=$1 FOR UPDATE",
        )
        .bind(account_id)
        .fetch_one(&mut *transaction)
        .await?;
        transaction.commit().await?;
        Ok(winner)
    }

    async fn commit_event(&self, command: CaptureCommit) -> Result<CaptureCommitResult> {
        let mut transaction = self.pool().begin().await?;
        lock_activation_contract_key_share_if_installed(&mut transaction).await?;
        advisory_transaction_lock(
            &mut transaction,
            "memory-reconciliation",
            &command.account_id,
        )
        .await?;
        require_active_account(&mut transaction, &command.account_id).await?;
        let result = insert_event(&mut transaction, &command).await?;
        if result.duplicate {
            if let Some(upload_token) = command.upload_token.as_deref() {
                sqlx::query(
                    "DELETE FROM capture_upload_intents \
                      WHERE account_id=$1 AND event_id=$2 AND token=$3",
                )
                .bind(&command.account_id)
                .bind(&command.manifest.event_id)
                .bind(upload_token)
                .execute(&mut *transaction)
                .await?;
            }
        }
        transaction.commit().await?;
        Ok(result)
    }

    async fn commit_reference_batch(
        &self,
        command: ReferenceBatchCommit,
    ) -> Result<ReferenceBatchCommitResult> {
        if command.events.is_empty() || command.events.len() != command.manifest_digests.len() {
            return Err(EnclaveError::InvalidRequest(
                "reference batch digest count is invalid".into(),
            ));
        }
        let mut transaction = self.pool().begin().await?;
        lock_activation_contract_key_share_if_installed(&mut transaction).await?;
        advisory_transaction_lock(
            &mut transaction,
            "memory-reconciliation",
            &command.account_id,
        )
        .await?;
        require_active_account(&mut transaction, &command.account_id).await?;
        let mut new_count = 0usize;
        let mut duplicate_count = 0usize;
        let mut committed_through_sequence = -1;
        for (index, (manifest, digest)) in command
            .events
            .iter()
            .zip(&command.manifest_digests)
            .enumerate()
        {
            let result = insert_event(
                &mut transaction,
                &CaptureCommit {
                    account_id: command.account_id.clone(),
                    manifest: manifest.clone(),
                    manifest_digest: digest.clone(),
                    object_key: None,
                    object_generation: None,
                    upload_token: None,
                    media_authority: None,
                    committed_at: command.committed_at.clone(),
                },
            )
            .await
            .map_err(|error| error.for_capture_reference_batch_item(index, manifest.sequence))?;
            committed_through_sequence = result.committed_through_sequence;
            if result.duplicate {
                duplicate_count += 1;
            } else {
                new_count += 1;
            }
        }
        transaction.commit().await?;
        Ok(ReferenceBatchCommitResult {
            new_count,
            duplicate_count,
            committed_through_sequence,
        })
    }

    async fn stream_ack(&self, account_id: &str, stream_id: &str) -> Result<i64> {
        stream_ack(self.pool(), account_id, stream_id).await
    }

    async fn event_status(
        &self,
        account_id: &str,
        event_id: &str,
    ) -> Result<Option<CaptureEventStatus>> {
        let row = sqlx::query(
            "SELECT e.event_id,coalesce(m.processing_state,'ready') AS processing_state, \
                    j.error_code,coalesce(j.attempt_count,0)::bigint AS attempt_count \
               FROM capture_events e LEFT JOIN media_objects m \
                 ON m.account_id=e.account_id AND m.event_id=e.event_id \
               LEFT JOIN media_processing_jobs j \
                 ON j.account_id=e.account_id AND j.event_id=e.event_id \
              WHERE e.account_id=$1 AND e.event_id=$2",
        )
        .bind(account_id)
        .bind(event_id)
        .fetch_optional(self.pool())
        .await?;
        row.map(|row| {
            Ok(CaptureEventStatus {
                event_id: row.try_get("event_id")?,
                processing_state: row.try_get("processing_state")?,
                error_code: row.try_get("error_code")?,
                attempt_count: row.try_get("attempt_count")?,
            })
        })
        .transpose()
    }

    async fn session_status(
        &self,
        account_id: &str,
        capture_session_id: &str,
        summarized_until_ms: Option<i64>,
    ) -> Result<Option<CaptureSessionStatus>> {
        postgres_session_status(self, account_id, capture_session_id, summarized_until_ms).await
    }

    async fn recent_sessions(
        &self,
        account_id: &str,
        window_hours: i64,
        max_sessions: i64,
        summarized_until_ms: Option<i64>,
    ) -> Result<Vec<CaptureSessionStatus>> {
        if !(1..=24).contains(&window_hours) || !(1..=10).contains(&max_sessions) {
            return Err(EnclaveError::InvalidRequest(
                "capture session list bounds are invalid".into(),
            ));
        }
        let ids = sqlx::query_scalar::<_, String>(
            "SELECT id FROM capture_sessions WHERE account_id=$1 AND ( \
                 started_at>=now()-make_interval(hours=>$2::int) OR \
                 (ended_at IS NULL AND last_event_at>=now()-make_interval(hours=>$2::int))) \
             ORDER BY started_at DESC,id LIMIT $3",
        )
        .bind(account_id)
        .bind(window_hours)
        .bind(max_sessions)
        .fetch_all(self.pool())
        .await?;
        let mut sessions = Vec::with_capacity(ids.len());
        for id in ids {
            sessions.push(
                postgres_session_status(self, account_id, &id, summarized_until_ms)
                    .await?
                    .ok_or_else(|| {
                        EnclaveError::Store("capture session disappeared during listing".into())
                    })?,
            );
        }
        Ok(sessions)
    }

    async fn finish_session(
        &self,
        account_id: &str,
        capture_session_id: &str,
    ) -> Result<Option<CaptureSessionStatus>> {
        let mut transaction = self.pool().begin().await?;
        lock_activation_contract_key_share_if_installed(&mut transaction).await?;
        advisory_transaction_lock(&mut transaction, "memory-reconciliation", account_id).await?;
        let ended = sqlx::query_scalar::<_, bool>(
            "SELECT ended_at IS NOT NULL FROM capture_sessions \
              WHERE account_id=$1 AND id=$2 FOR UPDATE",
        )
        .bind(account_id)
        .bind(capture_session_id)
        .fetch_optional(&mut *transaction)
        .await?;
        let Some(ended) = ended else {
            transaction.rollback().await?;
            return Ok(None);
        };
        let provenance = if ended
            && capture_formation_contract_installed(&mut transaction).await?
            && !sqlx::query_scalar::<_, bool>(
                "SELECT EXISTS(SELECT 1 FROM capture_formation_receipts \
                  WHERE account_id=$1 AND capture_session_id=$2 \
                    AND finish_requested_at IS NOT NULL)",
            )
            .bind(account_id)
            .bind(capture_session_id)
            .fetch_one(&mut *transaction)
            .await?
        {
            // An explicit request makes old ended-session intent durable even
            // when legacy streams already contain exact pre-v27 boundaries.
            // The quiet sealer still appends the first auditable generation.
            "legacy_client_refinish_v1"
        } else {
            "finish_endpoint_v1"
        };
        record_provisional_finish(
            &mut transaction,
            account_id,
            capture_session_id,
            None,
            provenance,
        )
        .await?;
        transaction.commit().await?;
        postgres_session_status(self, account_id, capture_session_id, None).await
    }
}

#[cfg(test)]
mod tests {
    use super::{
        capture_session_stage, contiguous_ack, exact_deleted_event_replay,
        provisional_finish_state_authorized, stream_admission, StreamAdmission,
    };
    use crate::persistence::capture::CaptureSessionStage;

    #[test]
    fn capture_session_failure_stays_automatic_until_honest_zero_result() {
        assert_eq!(
            capture_session_stage(0, 0, 0, 1, false, false, true, false),
            CaptureSessionStage::Processing
        );
        assert_eq!(
            capture_session_stage(0, 0, 0, 1, false, false, false, false),
            CaptureSessionStage::Processing
        );
        assert_eq!(
            capture_session_stage(0, 0, 0, 1, false, false, true, true),
            CaptureSessionStage::NoMemory
        );
        assert_eq!(
            capture_session_stage(0, 0, 0, 1, true, true, true, true),
            CaptureSessionStage::Ready
        );
    }

    #[test]
    fn provisional_finish_accepts_late_sources_until_exact_seal() {
        assert_eq!(
            stream_admission(false, false, false, None, 0, false).unwrap(),
            StreamAdmission::Open
        );
        assert_eq!(
            stream_admission(true, true, false, None, 99, false).unwrap(),
            StreamAdmission::ProvisionalFinish
        );
        assert_eq!(
            stream_admission(true, true, false, None, 100, true).unwrap(),
            StreamAdmission::ProvisionalFinish,
            "a repeated finish marker remains provisional before quiet sealing"
        );
        assert!(stream_admission(true, false, false, None, 0, false).is_err());
    }

    #[test]
    fn signed_draining_transition_does_not_race_legacy_finish_import() {
        assert!(provisional_finish_state_authorized(
            Some("installed"),
            false,
            false,
            false
        ));
        for phase in ["draining", "active", "paused"] {
            assert!(provisional_finish_state_authorized(
                Some(phase),
                true,
                false,
                false
            ));
        }
        assert!(!provisional_finish_state_authorized(
            Some("draining"),
            false,
            false,
            false
        ));
        assert!(!provisional_finish_state_authorized(
            Some("draining"),
            true,
            false,
            true
        ));
        assert!(!provisional_finish_state_authorized(
            Some("installed"),
            true,
            false,
            true
        ));
    }

    #[test]
    fn exact_seal_allows_only_bounded_gap_fill() {
        assert_eq!(
            stream_admission(true, false, false, Some(4), 3, false).unwrap(),
            StreamAdmission::SealedGapFill
        );
        assert_eq!(
            stream_admission(true, false, false, Some(4), 4, false).unwrap(),
            StreamAdmission::SealedGapFill
        );
        assert!(stream_admission(true, false, false, Some(4), 5, false).is_err());
        assert!(stream_admission(true, false, false, Some(4), 4, true).is_err());
        assert!(stream_admission(false, false, false, Some(0), 0, false).is_err());
    }

    #[test]
    fn audited_final_seal_reopens_only_for_a_novel_later_sequence() {
        assert_eq!(
            stream_admission(true, false, true, Some(4), 5, false).unwrap(),
            StreamAdmission::LateSealReopen
        );
        assert!(stream_admission(true, false, false, Some(4), 5, false).is_err());
        assert_eq!(
            stream_admission(true, false, true, Some(4), 4, false).unwrap(),
            StreamAdmission::SealedGapFill,
            "duplicates are resolved before admission and sequence reuse remains a conflict"
        );
    }

    #[test]
    fn late_reopen_rechecks_ack_after_clearing_the_old_boundary() {
        assert_eq!(contiguous_ack(4, []), 4, "the old seal caps the first pass");
        assert_eq!(
            contiguous_ack(4, [5]),
            5,
            "the post-reopen pass immediately acknowledges a lone late event"
        );
        let source = include_str!("capture.rs");
        let insert = source
            .split("async fn insert_event(")
            .nth(1)
            .unwrap()
            .split("fn capture_session_stage(")
            .next()
            .unwrap();
        assert!(insert.contains("route_epoch,received_at"));
        assert!(insert.contains("clock_timestamp())"));
        assert!(!insert.contains("CURRENT_TIMESTAMP)"));
        let audit = insert.find("record_capture_seal_reopen(").unwrap();
        let after_audit = &insert[audit..];
        assert!(after_audit.contains("advance_ack(transaction"));

        let reopen = source
            .split("async fn record_capture_seal_reopen(")
            .nth(1)
            .unwrap()
            .split("async fn insert_browser_observation(")
            .next()
            .unwrap();
        let appended = reopen
            .find("INSERT INTO capture_formation_seal_events")
            .unwrap();
        let streams_cleared = reopen
            .find("UPDATE capture_streams SET sealed_sequence=NULL")
            .unwrap();
        let readiness_cleared = reopen.find("SET seal_finalized_at=NULL").unwrap();
        assert!(appended < streams_cleared && streams_cleared < readiness_cleared);
        assert!(reopen.contains("trigger_event_id"));
        assert!(reopen.contains("capture_formation_stream_maxima_sha256"));
    }

    #[test]
    fn exact_deleted_replay_is_duplicate_but_scope_or_digest_reuse_conflicts() {
        assert!(exact_deleted_event_replay(
            "stream-1", 7, "digest-1", "stream-1", 7, "digest-1"
        ));
        for replay in [
            ("stream-2", 7, "digest-1"),
            ("stream-1", 8, "digest-1"),
            ("stream-1", 7, "digest-2"),
        ] {
            assert!(!exact_deleted_event_replay(
                "stream-1", 7, "digest-1", replay.0, replay.1, replay.2
            ));
        }

        let source = include_str!("capture.rs");
        let preflight = source
            .split("async fn preflight(")
            .nth(1)
            .unwrap()
            .split("async fn upsert_session_and_stream(")
            .next()
            .unwrap();
        assert!(preflight.contains("capture_formation_deleted_sequences"));
        assert!(preflight.contains("original_manifest_digest"));
        assert!(preflight.contains("exact_deleted_event_replay"));
        assert!(preflight.contains("CapturePreflight::Duplicate"));
        assert!(preflight.contains("idempotency conflict for erased capture event"));

        let batch = source
            .split("async fn commit_reference_batch(")
            .nth(1)
            .unwrap()
            .split("async fn stream_ack(")
            .next()
            .unwrap();
        assert!(batch.contains("insert_event("));
        assert!(batch.contains("if result.duplicate"));
        assert!(batch.contains("duplicate_count += 1"));

        let ack = source
            .split("async fn advance_ack(")
            .nth(1)
            .unwrap()
            .split("fn contiguous_ack(")
            .next()
            .unwrap();
        assert!(ack.contains("UNION"));
        assert!(ack.contains("capture_formation_deleted_sequences"));

        let insert = source
            .split("async fn insert_event(")
            .nth(1)
            .unwrap()
            .split("fn capture_session_stage(")
            .next()
            .unwrap();
        assert!(insert.contains("capture_formation_deleted_sequences"));
        assert!(insert.contains("idempotency conflict for stream sequence"));
        assert!(insert.contains("deletion.state='pending'"));
        assert!(insert.contains("deletion.orphan_event_ids ? $2"));
        assert!(insert.contains("capture reference target is pending episode deletion"));

        let reopen = source
            .split("async fn upsert_session_and_stream(")
            .nth(1)
            .unwrap()
            .split("async fn record_provisional_finish(")
            .next()
            .unwrap();
        assert!(reopen.contains("capture_formation_stream_accepted_max"));
        assert!(reopen.contains("capture_formation_stream_contiguous_through"));
    }
}
