//! Enrollment designation belongs to accepted capture, after replay checks.
//! Account/reconciliation locks serialize this with Forget and voice settlement.
use sqlx::{PgConnection, Postgres, Row, Transaction};

use super::voice_enrollment::invalidate_owner_enrollment;
use crate::cp::media::{CaptureEventManifest, StreamKind};
use crate::cp::voice_identity::channel_domain;
use crate::error::{EnclaveError, Result};
use crate::persistence::{CaptureEnrollmentStatus, VoiceEnrollmentReason, VoiceEnrollmentState};

pub(super) async fn designated(
    connection: &mut PgConnection,
    account: &str,
    session: &str,
) -> Result<bool> {
    Ok(sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM voice_enrollment_sessions WHERE account_id=$1 AND capture_session_id=$2 AND designated)")
        .bind(account).bind(session).fetch_one(connection).await?)
}

/// Enrollment keeps the audio from a second device only in a new stream;
/// existing stream identity and ordinary-session device scope stay immutable.
pub(super) async fn admits_new_device_stream(
    connection: &mut PgConnection,
    account: &str,
    manifest: &CaptureEventManifest,
) -> Result<bool> {
    if !designated(connection, account, &manifest.capture_session_id).await? {
        return Ok(false);
    }
    let exists: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM capture_streams WHERE account_id=$1 AND id=$2)",
    )
    .bind(account)
    .bind(&manifest.stream_id)
    .fetch_one(connection)
    .await?;
    Ok(!exists)
}

pub(super) async fn refuse_reference_batch(
    connection: &mut PgConnection,
    account: &str,
    session: &str,
) -> Result<()> {
    if designated(connection, account, session).await? {
        return Err(EnclaveError::InvalidRequest(
            "reference batches do not admit voice enrollment sessions".into(),
        ));
    }
    Ok(())
}

fn domain(manifest: &CaptureEventManifest) -> Option<String> {
    let kind = match manifest.stream_kind {
        StreamKind::Mic => "mic",
        StreamKind::IosMic => "ios_mic",
        _ => return None,
    };
    Some(channel_domain(
        kind,
        manifest.audio_role.as_deref(),
        manifest.audio_route.as_deref(),
    ))
}

fn terminal_admission_reason(reason: Option<VoiceEnrollmentReason>) -> bool {
    matches!(
        reason,
        Some(
            VoiceEnrollmentReason::MarkerMissing
                | VoiceEnrollmentReason::MarkerAfterOrdinaryStart
                | VoiceEnrollmentReason::UnsupportedStream
                | VoiceEnrollmentReason::MultipleStreams
                | VoiceEnrollmentReason::MultipleDevices
                | VoiceEnrollmentReason::RouteChanged
                | VoiceEnrollmentReason::EnrollmentRevoked
                | VoiceEnrollmentReason::RawMediaExpired
                | VoiceEnrollmentReason::SourceDeleted
                | VoiceEnrollmentReason::Forgotten
        )
    )
}

pub(super) async fn record_event(
    tx: &mut Transaction<'_, Postgres>,
    account: &str,
    manifest: &CaptureEventManifest,
    session_was_new: bool,
) -> Result<()> {
    let row = sqlx::query("SELECT designated,enrollment_revision,device_id,install_id,stream_id,state,reason,channel_domain FROM voice_enrollment_sessions WHERE account_id=$1 AND capture_session_id=$2 FOR UPDATE")
        .bind(account).bind(&manifest.capture_session_id).fetch_optional(&mut **tx).await?;
    if row.is_none() && manifest.enrollment.is_none() {
        return Ok(());
    }
    let current_revision: i64 =
        sqlx::query_scalar("SELECT enrollment_revision FROM accounts WHERE id=$1")
            .bind(account)
            .fetch_one(&mut **tx)
            .await?;
    let submitted_revision = manifest.enrollment_revision.unwrap_or(0);
    let event_domain = domain(manifest);
    let event_start = crate::cp::isotime::parse_epoch_millis(&manifest.started_at)
        .ok_or_else(|| EnclaveError::InvalidRequest("started_at must be ISO-8601".into()))?;
    let reason = if let Some(row) = row.as_ref() {
        let state = VoiceEnrollmentState::parse(&row.try_get::<String, _>("state")?)?;
        let previous_reason = row
            .try_get::<Option<String>, _>("reason")?
            .map(|value| VoiceEnrollmentReason::parse(&value))
            .transpose()?;
        // Forget/expiry and admission violations cannot be healed by queued input.
        if state == VoiceEnrollmentState::Expired || terminal_admission_reason(previous_reason) {
            return Ok(());
        }
        if row.try_get::<i64, _>("enrollment_revision")? != current_revision
            || submitted_revision != current_revision
        {
            Some(VoiceEnrollmentReason::EnrollmentRevoked)
        } else if manifest.enrollment.is_none() {
            Some(VoiceEnrollmentReason::MarkerMissing)
        } else if row.try_get::<String, _>("device_id")? != manifest.device_id
            || row.try_get::<String, _>("install_id")? != manifest.install_id
        {
            Some(VoiceEnrollmentReason::MultipleDevices)
        } else if row.try_get::<String, _>("stream_id")? != manifest.stream_id {
            Some(VoiceEnrollmentReason::MultipleStreams)
        } else if event_domain.is_none() {
            Some(VoiceEnrollmentReason::UnsupportedStream)
        } else if row.try_get::<Option<String>, _>("channel_domain")? != event_domain {
            Some(VoiceEnrollmentReason::RouteChanged)
        } else {
            None
        }
    } else if !session_was_new {
        Some(VoiceEnrollmentReason::MarkerAfterOrdinaryStart)
    } else if submitted_revision != current_revision {
        Some(VoiceEnrollmentReason::EnrollmentRevoked)
    } else if event_domain.is_none() {
        Some(VoiceEnrollmentReason::UnsupportedStream)
    } else {
        None
    };
    let state = if reason.is_some() {
        VoiceEnrollmentState::Inconclusive
    } else {
        VoiceEnrollmentState::Recording
    };
    if row.is_some() {
        invalidate_owner_enrollment(
            tx,
            account,
            &manifest.capture_session_id,
            reason.unwrap_or(VoiceEnrollmentReason::SourceChanged),
        )
        .await?;
        sqlx::query("UPDATE voice_enrollment_sessions SET state=$3,reason=$4, \
            timeline_started_at=CASE WHEN $4::text IS NULL THEN least(timeline_started_at,to_timestamp($5::double precision/1000.0)) ELSE timeline_started_at END, \
            timeline_cutoff_at=CASE WHEN $4::text IS NULL THEN least(timeline_started_at,to_timestamp($5::double precision/1000.0))+interval '180 seconds' ELSE timeline_cutoff_at END, \
            source_revision=NULL,seal_generation=NULL,updated_at=clock_timestamp() WHERE account_id=$1 AND capture_session_id=$2")
            .bind(account).bind(&manifest.capture_session_id).bind(state.as_str())
            .bind(reason.map(VoiceEnrollmentReason::as_str)).bind(event_start).execute(&mut **tx).await?;
    } else {
        sqlx::query("INSERT INTO voice_enrollment_sessions(account_id,capture_session_id,designated,enrollment_revision,first_event_id,device_id,install_id,stream_id,state,reason,channel_domain,timeline_started_at,timeline_cutoff_at) \
            VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,to_timestamp($12::double precision/1000.0),to_timestamp($12::double precision/1000.0)+interval '180 seconds')")
            .bind(account).bind(&manifest.capture_session_id).bind(session_was_new).bind(submitted_revision).bind(&manifest.event_id)
            .bind(&manifest.device_id).bind(&manifest.install_id).bind(&manifest.stream_id)
            .bind(state.as_str()).bind(reason.map(VoiceEnrollmentReason::as_str)).bind(event_domain)
            .bind(event_start).execute(&mut **tx).await?;
    }
    Ok(())
}

pub(super) async fn status(
    connection: &mut PgConnection,
    account: &str,
    session: &str,
) -> Result<Option<CaptureEnrollmentStatus>> {
    let row = sqlx::query("SELECT state,reason,channel_domain FROM voice_enrollment_sessions WHERE account_id=$1 AND capture_session_id=$2")
        .bind(account).bind(session).fetch_optional(connection).await?;
    row.map(|row| {
        Ok(CaptureEnrollmentStatus {
            state: VoiceEnrollmentState::parse(&row.try_get::<String, _>("state")?)?,
            reason: row
                .try_get::<Option<String>, _>("reason")?
                .map(|reason| VoiceEnrollmentReason::parse(&reason))
                .transpose()?,
            channel_domain: row.try_get("channel_domain")?,
        })
    })
    .transpose()
}
