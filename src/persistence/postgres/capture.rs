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
        CaptureCommit, CaptureCommitResult, CapturePreflight, CaptureRepository,
        ReferenceBatchCommit, ReferenceBatchCommitResult,
    },
};

use super::PostgresPersistence;

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
    committed_at_ms: i64,
) -> Result<()> {
    let started_at_ms = timestamp(&manifest.started_at, "started_at")?;
    let ended_at_ms = timestamp(&manifest.ended_at, "ended_at")?;
    let row = sqlx::query(
        "INSERT INTO capture_sessions \
         (account_id,id,device_id,install_id,started_at,last_event_at,schema_version,ended_at,created_at) \
         VALUES ($1,$2,$3,$4,to_timestamp($5::double precision/1000.0), \
                 to_timestamp($6::double precision/1000.0),2, \
                 CASE WHEN $7 THEN to_timestamp($6::double precision/1000.0) ELSE NULL END, \
                 to_timestamp($8::double precision/1000.0)) \
         ON CONFLICT (account_id,id) DO UPDATE SET \
             last_event_at=GREATEST(capture_sessions.last_event_at,excluded.last_event_at), \
             ended_at=CASE WHEN $7 THEN COALESCE(capture_sessions.ended_at,excluded.ended_at) \
                           ELSE capture_sessions.ended_at END \
         WHERE capture_sessions.device_id=excluded.device_id \
           AND capture_sessions.install_id=excluded.install_id \
         RETURNING device_id,install_id",
    )
    .bind(account_id)
    .bind(&manifest.capture_session_id)
    .bind(&manifest.device_id)
    .bind(&manifest.install_id)
    .bind(started_at_ms)
    .bind(ended_at_ms)
    .bind(manifest.session_finished.unwrap_or(false))
    .bind(committed_at_ms)
    .fetch_optional(&mut **transaction)
    .await?;
    if row.is_none() {
        return Err(EnclaveError::Conflict(
            "capture session ID was reused across devices or installs".into(),
        ));
    }

    sqlx::query(
        "INSERT INTO capture_streams \
         (account_id,id,capture_session_id,device_id,stream_kind,created_at) \
         VALUES ($1,$2,$3,$4,$5,to_timestamp($6::double precision/1000.0)) \
         ON CONFLICT (account_id,id) DO NOTHING",
    )
    .bind(account_id)
    .bind(&manifest.stream_id)
    .bind(&manifest.capture_session_id)
    .bind(&manifest.device_id)
    .bind(match manifest.stream_kind {
        media::StreamKind::Mic => "mic",
        media::StreamKind::SystemAudio => "system_audio",
        media::StreamKind::MacScreen => "mac_screen",
        media::StreamKind::IosMic => "ios_mic",
        media::StreamKind::IosImportedScreenshot => "ios_imported_screenshot",
        media::StreamKind::IosSharedPage => "ios_shared_page",
    })
    .bind(committed_at_ms)
    .execute(&mut **transaction)
    .await?;
    let scope = sqlx::query(
        "SELECT capture_session_id,device_id,stream_kind FROM capture_streams \
         WHERE account_id=$1 AND id=$2",
    )
    .bind(account_id)
    .bind(&manifest.stream_id)
    .fetch_one(&mut **transaction)
    .await?;
    let expected_kind = match manifest.stream_kind {
        media::StreamKind::Mic => "mic",
        media::StreamKind::SystemAudio => "system_audio",
        media::StreamKind::MacScreen => "mac_screen",
        media::StreamKind::IosMic => "ios_mic",
        media::StreamKind::IosImportedScreenshot => "ios_imported_screenshot",
        media::StreamKind::IosSharedPage => "ios_shared_page",
    };
    if scope.try_get::<String, _>("capture_session_id")? != manifest.capture_session_id
        || scope.try_get::<String, _>("device_id")? != manifest.device_id
        || scope.try_get::<String, _>("stream_kind")? != expected_kind
    {
        return Err(EnclaveError::Conflict(
            "capture stream ID was reused with a different scope".into(),
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
    let current = stream_ack(&mut **transaction, account_id, stream_id).await?;
    let sequences = sqlx::query_scalar::<_, i64>(
        "SELECT sequence FROM capture_events \
         WHERE account_id=$1 AND stream_id=$2 AND sequence>$3 ORDER BY sequence",
    )
    .bind(account_id)
    .bind(stream_id)
    .bind(current)
    .fetch_all(&mut **transaction)
    .await?;
    let mut advanced = current;
    for sequence in sequences {
        if sequence == advanced + 1 {
            advanced = sequence;
        } else if sequence > advanced + 1 {
            break;
        }
    }
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
        &mut **transaction,
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
    let committed_at_ms = timestamp(&command.committed_at, "committed_at")?;
    upsert_session_and_stream(transaction, &command.account_id, manifest, committed_at_ms).await?;
    let sequence_used = sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS(SELECT 1 FROM capture_events \
         WHERE account_id=$1 AND device_id=$2 AND stream_id=$3 AND sequence=$4)",
    )
    .bind(&command.account_id)
    .bind(&manifest.device_id)
    .bind(&manifest.stream_id)
    .bind(manifest.sequence)
    .fetch_one(&mut **transaction)
    .await?;
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
                 to_timestamp($31::double precision/1000.0))",
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
    .bind(committed_at_ms)
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
            crate::store::canonical_recording_media_object_key(
                &command.account_id,
                &media.asset_id,
            )?
        } else {
            crate::store::canonical_capture_media_object_key(&command.account_id, &media.asset_id)?
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
             VALUES ($1,$2,$3,$4,1,'pending',to_timestamp($5::double precision/1000.0))",
        )
        .bind(&command.account_id)
        .bind(&manifest.event_id)
        .bind(job_kind)
        .bind(&command.manifest_digest)
        .bind(committed_at_ms)
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

    Ok(CaptureCommitResult {
        duplicate: false,
        committed_through_sequence: advance_ack(
            transaction,
            &command.account_id,
            &manifest.stream_id,
        )
        .await?,
    })
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

    async fn commit_event(&self, command: CaptureCommit) -> Result<CaptureCommitResult> {
        let mut transaction = self.pool().begin().await?;
        require_active_account(&mut transaction, &command.account_id).await?;
        let result = insert_event(&mut transaction, &command).await?;
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
        require_active_account(&mut transaction, &command.account_id).await?;
        let mut new_count = 0usize;
        let mut duplicate_count = 0usize;
        let mut committed_through_sequence = -1;
        for (manifest, digest) in command.events.iter().zip(&command.manifest_digests) {
            let result = insert_event(
                &mut transaction,
                &CaptureCommit {
                    account_id: command.account_id.clone(),
                    manifest: manifest.clone(),
                    manifest_digest: digest.clone(),
                    object_key: None,
                    object_generation: None,
                    media_authority: None,
                    committed_at: command.committed_at.clone(),
                },
            )
            .await?;
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
}
