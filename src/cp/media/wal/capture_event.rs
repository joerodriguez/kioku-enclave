#![allow(
    dead_code,
    reason = "inactive ADR-0022 canonical-capture codec is reviewed before its B upload boundary, launcher, or route ownership"
)]

//! Inactive canonical capture-event WAL domain.
//!
//! A future B boundary must finish encryption and an exact provider upload
//! before constructing this plan. The child commits only the corresponding
//! local event, media, browser, processing-job, session, stream, and contiguous
//! acknowledgement facts with its own bounded replay ledger. It has no media
//! bytes, DEK, provider, Store, billing, launcher, task, or acknowledgement
//! authority.

use rusqlite::{params, Connection, OptionalExtension, Transaction};
use zeroize::Zeroizing;

use crate::archive_v3_wal_idempotency::{
    DomainLedgerBounds, LogicalMutationResult, PreparedLogicalMutation, WalIdempotencyError,
    WalLogicalDomainLedger, WalLogicalDomainPlan, WalLogicalOperationId, WalOperationKind,
    WalReplayResult, MAX_ENCODED_REPLAY_RESULT_BYTES,
};
use crate::error::EnclaveError;

use super::super::{CaptureEventManifest, MediaDisposition, RecordOutcome};

const REQUEST_V1: u16 = 1;
const REQUEST_CANONICAL_CAPTURE: u8 = 2;
const OPERATION_SOURCE_DOMAIN: &[u8] = b"canonical-capture-event-v1\0";
const RESULT_V1: u16 = 1;
const RESULT_CANONICAL_CAPTURE: u8 = 2;
const MAX_ID_BYTES: usize = 128;
const MAX_OBJECT_KEY_BYTES: usize = 512;
const MAX_RESULT_FIELD_BYTES: usize = 512;
const SCHEMA_TABLE: &str = "archive_v3_wal_canonical_capture_event_schema";
const LEDGER_TABLE: &str = "archive_v3_wal_canonical_capture_event_operations";
const STATE_TABLE: &str = "archive_v3_wal_canonical_capture_event_state";
const MAX_ROWS: u32 = 1_048_576;
const MAX_RESULT_BYTES: u64 = 512 * 1024 * 1024;
const BOUNDS: DomainLedgerBounds = DomainLedgerBounds::new(MAX_ROWS, MAX_RESULT_BYTES);

type Result<T> = std::result::Result<T, WalIdempotencyError>;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct CanonicalCaptureEventOutcome {
    event_id: String,
    asset_id: String,
    stream_id: String,
    committed_through_sequence: i64,
}

impl CanonicalCaptureEventOutcome {
    pub(super) fn event_id(&self) -> &str {
        &self.event_id
    }

    pub(super) fn asset_id(&self) -> &str {
        &self.asset_id
    }

    pub(super) fn stream_id(&self) -> &str {
        &self.stream_id
    }

    pub(super) const fn committed_through_sequence(&self) -> i64 {
        self.committed_through_sequence
    }
}

/// Exact local half of an already durable canonical-media upload. The caller
/// event ID is stable before the future B upload attempt begins; object key and
/// positive provider generation are part of the immutable handoff.
pub(crate) struct CanonicalCaptureEventPlan {
    operation_id: WalLogicalOperationId,
    account_id: String,
    manifest: CaptureEventManifest,
    manifest_digest: String,
    object_key: String,
    object_generation: i64,
}

impl CanonicalCaptureEventPlan {
    pub(super) fn new(
        account_id: String,
        manifest: CaptureEventManifest,
        object_key: String,
        object_generation: i64,
    ) -> Result<Self> {
        Self::build(None, account_id, manifest, object_key, object_generation)
    }

    fn build(
        operation_id: Option<WalLogicalOperationId>,
        account_id: String,
        manifest: CaptureEventManifest,
        object_key: String,
        object_generation: i64,
    ) -> Result<Self> {
        super::super::validate_id("account_id", &account_id)
            .map_err(|_| WalIdempotencyError::Malformed)?;
        manifest
            .validate()
            .map_err(|_| WalIdempotencyError::Malformed)?;
        if manifest.media_disposition != MediaDisposition::Canonical || object_generation <= 0 {
            return Err(WalIdempotencyError::Malformed);
        }
        let media = manifest
            .media
            .as_ref()
            .ok_or(WalIdempotencyError::Malformed)?;
        let expected_object_key = format!("raw/{account_id}/{}.enc", media.asset_id);
        if object_key != expected_object_key
            || object_key.len() > MAX_OBJECT_KEY_BYTES
            || object_key.contains("..")
        {
            return Err(WalIdempotencyError::Malformed);
        }
        let manifest_digest =
            super::super::manifest_digest(&manifest).map_err(|_| WalIdempotencyError::Malformed)?;
        let operation_id = match operation_id {
            Some(value) => value,
            None => {
                let mut source = Vec::with_capacity(
                    OPERATION_SOURCE_DOMAIN
                        .len()
                        .saturating_add(manifest.event_id.len()),
                );
                source.extend_from_slice(OPERATION_SOURCE_DOMAIN);
                source.extend_from_slice(manifest.event_id.as_bytes());
                WalLogicalOperationId::from_stable_source(
                    WalOperationKind::MediaCaptureEvent,
                    &source,
                )?
            }
        };
        Ok(Self {
            operation_id,
            account_id,
            manifest,
            manifest_digest,
            object_key,
            object_generation,
        })
    }

    #[cfg(test)]
    fn with_operation_id(
        operation_id: WalLogicalOperationId,
        account_id: String,
        manifest: CaptureEventManifest,
        object_key: String,
        object_generation: i64,
    ) -> Result<Self> {
        Self::build(
            Some(operation_id),
            account_id,
            manifest,
            object_key,
            object_generation,
        )
    }

    fn expected_outcome(
        &self,
        committed_through_sequence: i64,
    ) -> Result<CanonicalCaptureEventOutcome> {
        let media = self
            .manifest
            .media
            .as_ref()
            .ok_or(WalIdempotencyError::Corrupt)?;
        Ok(CanonicalCaptureEventOutcome {
            event_id: self.manifest.event_id.clone(),
            asset_id: media.asset_id.clone(),
            stream_id: self.manifest.stream_id.clone(),
            committed_through_sequence,
        })
    }
}

pub(crate) struct CanonicalCaptureEventLedger;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum LedgerSchemaState {
    Absent,
    Present,
}

impl WalLogicalDomainPlan for CanonicalCaptureEventPlan {
    type Ledger = CanonicalCaptureEventLedger;
    type Output = CanonicalCaptureEventOutcome;

    fn kind(&self) -> WalOperationKind {
        WalOperationKind::MediaCaptureEvent
    }

    fn operation_id(&self) -> WalLogicalOperationId {
        self.operation_id
    }

    fn canonical_request(&self) -> Result<Zeroizing<Vec<u8>>> {
        let normalized =
            serde_json::to_vec(&self.manifest).map_err(|_| WalIdempotencyError::Malformed)?;
        let mut request = Zeroizing::new(Vec::with_capacity(
            normalized
                .len()
                .saturating_add(self.account_id.len())
                .saturating_add(self.object_key.len())
                .saturating_add(96),
        ));
        request.extend_from_slice(&REQUEST_V1.to_be_bytes());
        request.push(REQUEST_CANONICAL_CAPTURE);
        encode_string(&mut request, &self.account_id)?;
        encode_bytes(&mut request, &normalized)?;
        request.extend_from_slice(self.manifest_digest.as_bytes());
        encode_string(&mut request, &self.object_key)?;
        request.extend_from_slice(&self.object_generation.to_be_bytes());
        Ok(request)
    }

    fn apply(&self, transaction: &Transaction<'_>) -> Result<WalReplayResult> {
        ensure_domain_targets_absent(transaction, self)?;
        validate_existing_parents(transaction, self)?;
        let outcome = super::super::record_source_event_in_transaction(
            transaction,
            &self.account_id,
            &self.manifest,
            &self.manifest_digest,
            &self.object_key,
            Some(self.object_generation),
        )
        .map_err(map_domain_error)?;
        if outcome != RecordOutcome::Created {
            return Err(WalIdempotencyError::Corrupt);
        }
        validate_committed_rows(transaction, self)?;
        let committed_through_sequence =
            super::super::committed_through_sequence(transaction, &self.manifest.stream_id)
                .map_err(map_domain_error)?;
        encode_outcome(&self.expected_outcome(committed_through_sequence)?)
    }

    fn validate_replay(&self, result: &WalReplayResult) -> Result<()> {
        let outcome = decode_outcome(result)?;
        let media = self
            .manifest
            .media
            .as_ref()
            .ok_or(WalIdempotencyError::Corrupt)?;
        if outcome.event_id != self.manifest.event_id
            || outcome.asset_id != media.asset_id
            || outcome.stream_id != self.manifest.stream_id
            || outcome.committed_through_sequence < -1
        {
            return Err(WalIdempotencyError::Corrupt);
        }
        Ok(())
    }

    fn decode_output(&self, result: &WalReplayResult) -> Result<Self::Output> {
        self.validate_replay(result)?;
        decode_outcome(result)
    }
}

impl WalLogicalDomainLedger<CanonicalCaptureEventPlan> for CanonicalCaptureEventLedger {
    fn lookup(
        connection: &Connection,
        prepared: &PreparedLogicalMutation<CanonicalCaptureEventPlan>,
    ) -> Result<Option<WalReplayResult>> {
        require_kind(prepared)?;
        if schema_state(connection)? == LedgerSchemaState::Absent {
            return Ok(None);
        }
        validate_schema_marker(connection)?;
        let row = connection
            .query_row(
                "SELECT format_version,codec_version,request_fingerprint,
                        result_bytes,result_commitment
                 FROM archive_v3_wal_canonical_capture_event_operations
                 WHERE operation_id=?1",
                [prepared.operation_id_for_owner().as_bytes().as_slice()],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, Vec<u8>>(2)?,
                        row.get::<_, Vec<u8>>(3)?,
                        row.get::<_, Vec<u8>>(4)?,
                    ))
                },
            )
            .optional()
            .map_err(|_| WalIdempotencyError::Unavailable)?;
        let Some((format, codec, fingerprint, encoded, commitment)) = row else {
            return Ok(None);
        };
        let kind = WalOperationKind::MediaCaptureEvent;
        if format != i64::from(WalOperationKind::format_version())
            || codec != i64::from(kind.codec_version())
            || fingerprint.len() != 32
            || commitment.len() != 32
        {
            return Err(WalIdempotencyError::Corrupt);
        }
        if fingerprint.as_slice()
            != prepared
                .request_fingerprint_for_owner()
                .as_bytes()
                .as_slice()
        {
            return Err(WalIdempotencyError::FingerprintConflict);
        }
        let result = WalReplayResult::decode(kind, &encoded)?;
        if commitment.as_slice() != result.commitment(kind)?.as_slice() {
            return Err(WalIdempotencyError::Corrupt);
        }
        prepared.plan_for_domain_ledger().validate_replay(&result)?;
        Ok(Some(result))
    }

    fn resolve_or_apply(
        transaction: &Transaction<'_>,
        prepared: &PreparedLogicalMutation<CanonicalCaptureEventPlan>,
    ) -> Result<LogicalMutationResult> {
        require_kind(prepared)?;
        ensure_schema(transaction)?;
        if let Some(result) = Self::lookup(transaction, prepared)? {
            return Ok(LogicalMutationResult::Replayed(result));
        }
        let (row_count, result_bytes) = load_ledger_state(transaction)?;
        BOUNDS.admit(row_count, result_bytes, MAX_ENCODED_REPLAY_RESULT_BYTES)?;

        let kind = WalOperationKind::MediaCaptureEvent;
        let result = prepared.plan_for_domain_ledger().apply(transaction)?;
        prepared.plan_for_domain_ledger().validate_replay(&result)?;
        let encoded = result.encode(kind)?;
        let commitment = result.commitment(kind)?;
        transaction
            .execute(
                "INSERT INTO archive_v3_wal_canonical_capture_event_operations
                 (operation_id,format_version,codec_version,request_fingerprint,
                  result_bytes,result_commitment)
                 VALUES (?1,?2,?3,?4,?5,?6)",
                params![
                    prepared.operation_id_for_owner().as_bytes().as_slice(),
                    i64::from(WalOperationKind::format_version()),
                    i64::from(kind.codec_version()),
                    prepared
                        .request_fingerprint_for_owner()
                        .as_bytes()
                        .as_slice(),
                    encoded.as_slice(),
                    commitment.as_slice(),
                ],
            )
            .map_err(|_| WalIdempotencyError::Unavailable)?;
        let encoded_length =
            i64::try_from(encoded.len()).map_err(|_| WalIdempotencyError::Limit)?;
        let previous_result_bytes =
            i64::try_from(result_bytes).map_err(|_| WalIdempotencyError::Corrupt)?;
        let changed = transaction
            .execute(
                "UPDATE archive_v3_wal_canonical_capture_event_state
                 SET row_count=row_count+1,result_bytes=result_bytes+?1
                 WHERE singleton=1 AND row_count=?2 AND result_bytes=?3",
                params![encoded_length, i64::from(row_count), previous_result_bytes],
            )
            .map_err(|_| WalIdempotencyError::Unavailable)?;
        if changed != 1 {
            return Err(WalIdempotencyError::Corrupt);
        }
        Ok(LogicalMutationResult::Applied(result))
    }
}

fn require_kind(prepared: &PreparedLogicalMutation<CanonicalCaptureEventPlan>) -> Result<()> {
    (prepared.kind_for_owner() == WalOperationKind::MediaCaptureEvent)
        .then_some(())
        .ok_or(WalIdempotencyError::ResultUnsupported)
}

fn ensure_domain_targets_absent(
    connection: &Connection,
    plan: &CanonicalCaptureEventPlan,
) -> Result<()> {
    let media = plan
        .manifest
        .media
        .as_ref()
        .ok_or(WalIdempotencyError::Corrupt)?;
    let job_kind = job_kind(&plan.manifest);
    let collisions = connection
        .query_row(
            "SELECT
                EXISTS(SELECT 1 FROM capture_events WHERE event_id=?1),
                EXISTS(SELECT 1 FROM capture_events WHERE device_id=?2 AND stream_id=?3 AND sequence=?4),
                EXISTS(SELECT 1 FROM media_objects WHERE asset_id=?5),
                EXISTS(SELECT 1 FROM media_objects WHERE object_key=?6),
                EXISTS(SELECT 1 FROM media_processing_jobs
                       WHERE job_kind=?7 AND input_revision=?8 AND processor_version=1)",
            params![
                plan.manifest.event_id,
                plan.manifest.device_id,
                plan.manifest.stream_id,
                plan.manifest.sequence,
                media.asset_id,
                plan.object_key,
                job_kind,
                plan.manifest_digest,
            ],
            |row| {
                Ok([
                    row.get::<_, i64>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, i64>(4)?,
                ])
            },
        )
        .map_err(|_| WalIdempotencyError::Unavailable)?;
    if collisions.into_iter().any(|value| value != 0) {
        return Err(WalIdempotencyError::Precondition);
    }
    Ok(())
}

fn validate_existing_parents(
    connection: &Connection,
    plan: &CanonicalCaptureEventPlan,
) -> Result<()> {
    let session = connection
        .query_row(
            "SELECT device_id,install_id,started_at,last_event_at,ended_at,schema_version,created_at
             FROM capture_sessions WHERE id=?1",
            [&plan.manifest.capture_session_id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, Option<String>>(4)?,
                    row.get::<_, i64>(5)?,
                    row.get::<_, String>(6)?,
                ))
            },
        )
        .optional()
        .map_err(|_| WalIdempotencyError::Unavailable)?;
    if let Some((device, install, started, last, ended, schema, created)) = session {
        if device != plan.manifest.device_id || install != plan.manifest.install_id || schema != 2 {
            return Err(WalIdempotencyError::Precondition);
        }
        if !valid_timestamp(&started)
            || !valid_timestamp(&last)
            || ended
                .as_deref()
                .is_some_and(|value| !valid_timestamp(value))
            || !valid_timestamp(&created)
            || timestamp_millis(&last)? < timestamp_millis(&started)?
        {
            return Err(WalIdempotencyError::Corrupt);
        }
    }
    let stream = connection
        .query_row(
            "SELECT capture_session_id,device_id,stream_kind,committed_through_sequence,
                    sealed_sequence,created_at
             FROM capture_streams WHERE id=?1",
            [&plan.manifest.stream_id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, Option<i64>>(4)?,
                    row.get::<_, String>(5)?,
                ))
            },
        )
        .optional()
        .map_err(|_| WalIdempotencyError::Unavailable)?;
    if let Some((session, device, kind, committed, sealed, created)) = stream {
        if session != plan.manifest.capture_session_id
            || device != plan.manifest.device_id
            || kind != plan.manifest.stream_kind.as_str()
        {
            return Err(WalIdempotencyError::Precondition);
        }
        if committed < -1 || sealed.is_some() || !valid_timestamp(&created) {
            return Err(WalIdempotencyError::Corrupt);
        }
    }
    Ok(())
}

fn valid_timestamp(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && super::super::super::isotime::parse_epoch_millis(value).is_some()
}

fn timestamp_millis(value: &str) -> Result<i64> {
    super::super::super::isotime::parse_epoch_millis(value).ok_or(WalIdempotencyError::Corrupt)
}

struct StoredEvent {
    device_id: String,
    install_id: String,
    capture_session_id: String,
    stream_id: String,
    stream_kind: String,
    sequence: i64,
    source_wall_at: String,
    source_monotonic_ns: String,
    started_at: String,
    ended_at: String,
    timezone_id: String,
    utc_offset_minutes: i32,
    clock_uncertainty_ms: u32,
    asset_id: String,
    manifest_digest: String,
    context_json: Option<String>,
    media_disposition: String,
}

struct StoredMedia {
    event_id: String,
    object_key: String,
    object_generation: Option<i64>,
    object_backend: Option<String>,
    mime_type: String,
    codec: String,
    byte_length: i64,
    sha256: String,
    sample_rate: Option<i64>,
    channels: Option<i64>,
    frame_count: Option<i64>,
    width: Option<i64>,
    height: Option<i64>,
    scale: Option<f64>,
    orientation: Option<String>,
    processing_state: String,
    retain_until: Option<String>,
    deleted_at: Option<String>,
}

fn validate_committed_rows(
    connection: &Connection,
    plan: &CanonicalCaptureEventPlan,
) -> Result<()> {
    let media = plan
        .manifest
        .media
        .as_ref()
        .ok_or(WalIdempotencyError::Corrupt)?;
    let stored_event = connection
        .query_row(
            "SELECT device_id,install_id,capture_session_id,stream_id,stream_kind,sequence,
                    source_wall_at,source_monotonic_ns,started_at,ended_at,timezone_id,
                    utc_offset_minutes,clock_uncertainty_ms,asset_id,manifest_digest,
                    context_json,media_disposition
             FROM capture_events WHERE event_id=?1",
            [&plan.manifest.event_id],
            |row| {
                Ok(StoredEvent {
                    device_id: row.get(0)?,
                    install_id: row.get(1)?,
                    capture_session_id: row.get(2)?,
                    stream_id: row.get(3)?,
                    stream_kind: row.get(4)?,
                    sequence: row.get(5)?,
                    source_wall_at: row.get(6)?,
                    source_monotonic_ns: row.get(7)?,
                    started_at: row.get(8)?,
                    ended_at: row.get(9)?,
                    timezone_id: row.get(10)?,
                    utc_offset_minutes: row.get(11)?,
                    clock_uncertainty_ms: row.get(12)?,
                    asset_id: row.get(13)?,
                    manifest_digest: row.get(14)?,
                    context_json: row.get(15)?,
                    media_disposition: row.get(16)?,
                })
            },
        )
        .map_err(|_| WalIdempotencyError::Unavailable)?;
    let expected_context = plan
        .manifest
        .context
        .as_ref()
        .map(serde_json::to_string)
        .transpose()
        .map_err(|_| WalIdempotencyError::Corrupt)?;
    if stored_event.device_id != plan.manifest.device_id
        || stored_event.install_id != plan.manifest.install_id
        || stored_event.capture_session_id != plan.manifest.capture_session_id
        || stored_event.stream_id != plan.manifest.stream_id
        || stored_event.stream_kind != plan.manifest.stream_kind.as_str()
        || stored_event.sequence != plan.manifest.sequence
        || stored_event.source_wall_at != plan.manifest.source_wall_at
        || stored_event.source_monotonic_ns != plan.manifest.source_monotonic_ns.to_string()
        || stored_event.started_at != plan.manifest.started_at
        || stored_event.ended_at != plan.manifest.ended_at
        || stored_event.timezone_id != plan.manifest.timezone_id
        || stored_event.utc_offset_minutes != plan.manifest.utc_offset_minutes
        || stored_event.clock_uncertainty_ms != plan.manifest.clock_uncertainty_ms
        || stored_event.asset_id != media.asset_id
        || stored_event.manifest_digest != plan.manifest_digest
        || stored_event.context_json != expected_context
        || stored_event.media_disposition != "canonical"
    {
        return Err(WalIdempotencyError::Corrupt);
    }

    let stored_media = connection
        .query_row(
            "SELECT event_id,object_key,object_generation,object_backend,mime_type,codec,
                    byte_length,sha256,sample_rate,channels,frame_count,width,height,scale,
                    orientation,processing_state,retain_until,deleted_at
             FROM media_objects WHERE asset_id=?1",
            [&media.asset_id],
            |row| {
                Ok(StoredMedia {
                    event_id: row.get(0)?,
                    object_key: row.get(1)?,
                    object_generation: row.get(2)?,
                    object_backend: row.get(3)?,
                    mime_type: row.get(4)?,
                    codec: row.get(5)?,
                    byte_length: row.get(6)?,
                    sha256: row.get(7)?,
                    sample_rate: row.get(8)?,
                    channels: row.get(9)?,
                    frame_count: row.get(10)?,
                    width: row.get(11)?,
                    height: row.get(12)?,
                    scale: row.get(13)?,
                    orientation: row.get(14)?,
                    processing_state: row.get(15)?,
                    retain_until: row.get(16)?,
                    deleted_at: row.get(17)?,
                })
            },
        )
        .map_err(|_| WalIdempotencyError::Unavailable)?;
    let retain_until =
        super::super::super::isotime::add_seconds(&plan.manifest.ended_at, 30.0 * 86_400.0);
    if stored_media.event_id != plan.manifest.event_id
        || stored_media.object_key != plan.object_key
        || stored_media.object_generation != Some(plan.object_generation)
        || stored_media.object_backend.as_deref() != Some("current")
        || stored_media.mime_type != media.mime_type
        || stored_media.codec != media.codec
        || stored_media.byte_length != media.byte_length
        || !stored_media.sha256.eq_ignore_ascii_case(&media.sha256)
        || stored_media.sample_rate != media.sample_rate
        || stored_media.channels != media.channels
        || stored_media.frame_count != media.frame_count
        || stored_media.width != media.width
        || stored_media.height != media.height
        || stored_media.scale != media.scale
        || stored_media.orientation != media.orientation
        || stored_media.processing_state != "queued"
        || stored_media.retain_until.as_deref() != Some(retain_until.as_str())
        || stored_media.deleted_at.is_some()
    {
        return Err(WalIdempotencyError::Corrupt);
    }

    let stored_job = connection
        .query_row(
            "SELECT id,event_id,job_kind,input_revision,processor_version,state,
                    attempt_count,lease_until,error_code,model_id,prompt_version,
                    schema_version,usage_json
             FROM media_processing_jobs WHERE event_id=?1",
            [&plan.manifest.event_id],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, i64>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, i64>(6)?,
                    row.get::<_, Option<String>>(7)?,
                    row.get::<_, Option<String>>(8)?,
                    row.get::<_, Option<String>>(9)?,
                    row.get::<_, Option<i64>>(10)?,
                    row.get::<_, Option<i64>>(11)?,
                    row.get::<_, Option<String>>(12)?,
                ))
            },
        )
        .map_err(|_| WalIdempotencyError::Unavailable)?;
    if stored_job.0 <= 0
        || stored_job.1 != plan.manifest.event_id
        || stored_job.2 != job_kind(&plan.manifest)
        || stored_job.3 != plan.manifest_digest
        || stored_job.4 != 1
        || stored_job.5 != "pending"
        || stored_job.6 != 0
        || stored_job.7.is_some()
        || stored_job.8.is_some()
        || stored_job.9.is_some()
        || stored_job.10.is_some()
        || stored_job.11.is_some()
        || stored_job.12.is_some()
    {
        return Err(WalIdempotencyError::Corrupt);
    }
    Ok(())
}

fn job_kind(manifest: &CaptureEventManifest) -> &'static str {
    if manifest.stream_kind.is_audio() {
        "gemini_audio"
    } else {
        "gemini_screen"
    }
}

fn map_domain_error(error: EnclaveError) -> WalIdempotencyError {
    match error {
        EnclaveError::Conflict(_) | EnclaveError::NotFound => WalIdempotencyError::Precondition,
        EnclaveError::InvalidRequest(_) | EnclaveError::Json(_) => WalIdempotencyError::Corrupt,
        EnclaveError::Db(_)
        | EnclaveError::Crypto(_)
        | EnclaveError::Store(_)
        | EnclaveError::Kms(_)
        | EnclaveError::Gcs(_)
        | EnclaveError::Http(_)
        | EnclaveError::Io(_)
        | EnclaveError::Attestation(_)
        | EnclaveError::Auth(_)
        | EnclaveError::Embedding(_)
        | EnclaveError::Config(_)
        | EnclaveError::SignupLimited
        | EnclaveError::DeletionPending(_)
        | EnclaveError::CaptureReference(_)
        | EnclaveError::CaptureReferenceBatch { .. }
        // ADR-0022 D4: a deferred domain is unavailable, never corrupt and
        // never a definitive precondition failure -- it stays retryable.
        | EnclaveError::WalDomainUnmigrated(_) => WalIdempotencyError::Unavailable,
    }
}

fn encode_outcome(outcome: &CanonicalCaptureEventOutcome) -> Result<WalReplayResult> {
    let mut bytes = Vec::with_capacity(512);
    bytes.extend_from_slice(&RESULT_V1.to_be_bytes());
    bytes.push(RESULT_CANONICAL_CAPTURE);
    encode_string(&mut bytes, &outcome.event_id)?;
    encode_string(&mut bytes, &outcome.asset_id)?;
    encode_string(&mut bytes, &outcome.stream_id)?;
    bytes.extend_from_slice(&outcome.committed_through_sequence.to_be_bytes());
    WalReplayResult::canonical_response(WalOperationKind::MediaCaptureEvent, bytes)
}

fn decode_outcome(result: &WalReplayResult) -> Result<CanonicalCaptureEventOutcome> {
    let WalReplayResult::CanonicalResponse(bytes) = result else {
        return Err(WalIdempotencyError::ResultUnsupported);
    };
    let mut reader = Reader::new(bytes);
    if reader.take_u16()? != RESULT_V1 || reader.take_u8()? != RESULT_CANONICAL_CAPTURE {
        return Err(WalIdempotencyError::Corrupt);
    }
    let outcome = CanonicalCaptureEventOutcome {
        event_id: reader.take_string(MAX_ID_BYTES)?,
        asset_id: reader.take_string(MAX_ID_BYTES)?,
        stream_id: reader.take_string(MAX_ID_BYTES)?,
        committed_through_sequence: reader.take_i64()?,
    };
    if !reader.is_empty()
        || outcome.event_id.is_empty()
        || outcome.asset_id.is_empty()
        || outcome.stream_id.is_empty()
        || outcome.committed_through_sequence < -1
    {
        return Err(WalIdempotencyError::Corrupt);
    }
    Ok(outcome)
}

fn encode_string(destination: &mut Vec<u8>, value: &str) -> Result<()> {
    encode_bytes(destination, value.as_bytes())
}

fn encode_bytes(destination: &mut Vec<u8>, value: &[u8]) -> Result<()> {
    let length = u32::try_from(value.len()).map_err(|_| WalIdempotencyError::Limit)?;
    destination.extend_from_slice(&length.to_be_bytes());
    destination.extend_from_slice(value);
    Ok(())
}

struct Reader<'a> {
    remaining: &'a [u8],
}

impl<'a> Reader<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { remaining: bytes }
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8]> {
        if self.remaining.len() < length {
            return Err(WalIdempotencyError::Corrupt);
        }
        let (value, remaining) = self.remaining.split_at(length);
        self.remaining = remaining;
        Ok(value)
    }

    fn take_u8(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }

    fn take_u16(&mut self) -> Result<u16> {
        let bytes: [u8; 2] = self
            .take(2)?
            .try_into()
            .map_err(|_| WalIdempotencyError::Corrupt)?;
        Ok(u16::from_be_bytes(bytes))
    }

    fn take_i64(&mut self) -> Result<i64> {
        let bytes: [u8; 8] = self
            .take(8)?
            .try_into()
            .map_err(|_| WalIdempotencyError::Corrupt)?;
        Ok(i64::from_be_bytes(bytes))
    }

    fn take_string(&mut self, maximum: usize) -> Result<String> {
        let length: [u8; 4] = self
            .take(4)?
            .try_into()
            .map_err(|_| WalIdempotencyError::Corrupt)?;
        let length = usize::try_from(u32::from_be_bytes(length))
            .map_err(|_| WalIdempotencyError::Corrupt)?;
        if length == 0 || length > maximum || length > MAX_RESULT_FIELD_BYTES {
            return Err(WalIdempotencyError::Corrupt);
        }
        std::str::from_utf8(self.take(length)?)
            .map(str::to_owned)
            .map_err(|_| WalIdempotencyError::Corrupt)
    }

    const fn is_empty(&self) -> bool {
        self.remaining.is_empty()
    }
}

fn schema_state(connection: &Connection) -> Result<LedgerSchemaState> {
    let present = connection
        .query_row(
            "SELECT COUNT(*) FROM sqlite_schema
             WHERE type='table' AND name IN (?1,?2,?3)",
            params![SCHEMA_TABLE, LEDGER_TABLE, STATE_TABLE],
            |row| row.get::<_, i64>(0),
        )
        .map_err(|_| WalIdempotencyError::Unavailable)?;
    match present {
        0 => Ok(LedgerSchemaState::Absent),
        3 => Ok(LedgerSchemaState::Present),
        _ => Err(WalIdempotencyError::Corrupt),
    }
}

fn ensure_schema(transaction: &Transaction<'_>) -> Result<()> {
    match schema_state(transaction)? {
        LedgerSchemaState::Present => validate_schema_marker(transaction),
        LedgerSchemaState::Absent => {
            transaction
                .execute_batch(
                    "CREATE TABLE archive_v3_wal_canonical_capture_event_schema (
                        singleton INTEGER PRIMARY KEY CHECK(singleton=1),
                        format_version INTEGER NOT NULL CHECK(format_version=1),
                        codec_version INTEGER NOT NULL CHECK(codec_version=1)
                     ) STRICT;
                     CREATE TABLE archive_v3_wal_canonical_capture_event_operations (
                        operation_id BLOB PRIMARY KEY NOT NULL,
                        format_version INTEGER NOT NULL CHECK(format_version=1),
                        codec_version INTEGER NOT NULL CHECK(codec_version=1),
                        request_fingerprint BLOB NOT NULL,
                        result_bytes BLOB NOT NULL,
                        result_commitment BLOB NOT NULL,
                        CHECK(length(operation_id)=16 AND operation_id<>zeroblob(16)),
                        CHECK(length(request_fingerprint)=32 AND request_fingerprint<>zeroblob(32)),
                        CHECK(length(result_bytes) BETWEEN 9 AND 4105),
                        CHECK(length(result_commitment)=32 AND result_commitment<>zeroblob(32))
                     ) STRICT, WITHOUT ROWID;
                     CREATE TABLE archive_v3_wal_canonical_capture_event_state (
                        singleton INTEGER PRIMARY KEY CHECK(singleton=1),
                        row_count INTEGER NOT NULL CHECK(row_count BETWEEN 0 AND 1048576),
                        result_bytes INTEGER NOT NULL CHECK(result_bytes BETWEEN 0 AND 536870912)
                     ) STRICT;
                     INSERT INTO archive_v3_wal_canonical_capture_event_schema
                        (singleton,format_version,codec_version) VALUES (1,1,1);
                     INSERT INTO archive_v3_wal_canonical_capture_event_state
                        (singleton,row_count,result_bytes) VALUES (1,0,0);",
                )
                .map_err(|_| WalIdempotencyError::Unavailable)?;
            validate_schema_marker(transaction)
        }
    }
}

fn validate_schema_marker(connection: &Connection) -> Result<()> {
    let marker = connection
        .query_row(
            "SELECT format_version,codec_version
             FROM archive_v3_wal_canonical_capture_event_schema WHERE singleton=1",
            [],
            |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)),
        )
        .optional()
        .map_err(|_| WalIdempotencyError::Corrupt)?;
    if marker
        != Some((
            i64::from(WalOperationKind::format_version()),
            i64::from(WalOperationKind::MediaCaptureEvent.codec_version()),
        ))
    {
        return Err(WalIdempotencyError::Corrupt);
    }
    let _ = load_ledger_state(connection)?;
    Ok(())
}

fn load_ledger_state(connection: &Connection) -> Result<(u32, u64)> {
    let state = connection
        .query_row(
            "SELECT row_count,result_bytes
             FROM archive_v3_wal_canonical_capture_event_state WHERE singleton=1",
            [],
            |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)),
        )
        .optional()
        .map_err(|_| WalIdempotencyError::Corrupt)?
        .ok_or(WalIdempotencyError::Corrupt)?;
    let row_count = u32::try_from(state.0).map_err(|_| WalIdempotencyError::Corrupt)?;
    let result_bytes = u64::try_from(state.1).map_err(|_| WalIdempotencyError::Corrupt)?;
    if row_count > MAX_ROWS || result_bytes > MAX_RESULT_BYTES {
        return Err(WalIdempotencyError::Corrupt);
    }
    Ok((row_count, result_bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::archive_v3_wal_idempotency::{
        execute_prepared_for_owner, LogicalMutationDisposition,
    };
    use rusqlite::Connection;
    use serde_json::json;

    const ACCOUNT: &str = "account-1";

    fn connection() -> Connection {
        let connection = Connection::open_in_memory().unwrap();
        super::super::super::init_schema(&connection).unwrap();
        connection
    }

    fn operation_id(value: u8) -> WalLogicalOperationId {
        WalLogicalOperationId::from_bytes([value; 16]).unwrap()
    }

    fn manifest(sequence: i64, event_id: &str, asset_id: &str) -> CaptureEventManifest {
        serde_json::from_value(json!({
            "schema_version": 2,
            "event_id": event_id,
            "device_id": "device-1",
            "install_id": "install-1",
            "capture_session_id": "session-1",
            "stream_id": "screen-1",
            "stream_kind": "mac_screen",
            "sequence": sequence,
            "source_wall_at": "2026-08-15T14:00:00.000Z",
            "source_monotonic_ns": 9_000_000_000_u64 + u64::try_from(sequence).unwrap(),
            "started_at": "2026-08-15T14:00:00.000Z",
            "ended_at": "2026-08-15T14:00:02.000Z",
            "timezone_id": "America/New_York",
            "utc_offset_minutes": -240,
            "clock_uncertainty_ms": 24,
            "media": {
                "asset_id": asset_id,
                "mime_type": "image/jpeg",
                "codec": "jpeg",
                "byte_length": 12,
                "sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "width": 1280,
                "height": 720,
                "scale": 2.0,
                "orientation": "landscape"
            },
            "context": {
                "capture_status": "stable",
                "active_app": "Google Chrome",
                "primary_bundle_id": "com.google.Chrome",
                "primary_window_id": 9,
                "window_title": "Weekly planning",
                "display_id": 42,
                "active_url": "https://meet.google.com/abc-defg-hij?authuser=0",
                "active_url_title": "Weekly planning",
                "browser_permission_status": "granted",
                "visible_windows": [{"bundle_id":"com.google.Chrome","window_id":9}],
                "visible_windows_truncated": false
            }
        }))
        .unwrap()
    }

    fn object_key(manifest: &CaptureEventManifest) -> String {
        format!(
            "raw/{ACCOUNT}/{}.enc",
            manifest.media.as_ref().unwrap().asset_id
        )
    }

    fn plan(manifest: CaptureEventManifest) -> CanonicalCaptureEventPlan {
        let key = object_key(&manifest);
        CanonicalCaptureEventPlan::new(ACCOUNT.to_owned(), manifest, key, 41).unwrap()
    }

    fn forced_plan(value: u8, manifest: CaptureEventManifest) -> CanonicalCaptureEventPlan {
        let key = object_key(&manifest);
        CanonicalCaptureEventPlan::with_operation_id(
            operation_id(value),
            ACCOUNT.to_owned(),
            manifest,
            key,
            41,
        )
        .unwrap()
    }

    #[test]
    fn stable_event_identity_is_subtype_scoped_and_request_covers_upload_receipt() {
        let event = manifest(0, "screen-event-0", "screen-asset-0");
        let one = plan(event.clone());
        let replay = plan(event.clone());
        assert_eq!(one.operation_id(), replay.operation_id());
        assert_eq!(
            one.canonical_request().unwrap(),
            replay.canonical_request().unwrap()
        );
        assert_ne!(
            one.operation_id(),
            WalLogicalOperationId::from_stable_source(
                WalOperationKind::MediaCaptureEvent,
                event.event_id.as_bytes(),
            )
            .unwrap(),
            "the singular subtype must not collide with another media-capture identity"
        );
        let changed = CanonicalCaptureEventPlan::new(
            ACCOUNT.to_owned(),
            event,
            "raw/account-1/screen-asset-0.enc".to_owned(),
            42,
        )
        .unwrap();
        assert_eq!(one.operation_id(), changed.operation_id());
        assert_ne!(
            one.canonical_request().unwrap(),
            changed.canonical_request().unwrap()
        );
    }

    #[test]
    fn constructor_requires_canonical_media_and_exact_positive_provider_receipt() {
        let event = manifest(0, "screen-event-0", "screen-asset-0");
        assert!(CanonicalCaptureEventPlan::new(
            ACCOUNT.to_owned(),
            event.clone(),
            "wrong".to_owned(),
            41,
        )
        .is_err());
        assert!(CanonicalCaptureEventPlan::new(
            ACCOUNT.to_owned(),
            event.clone(),
            object_key(&event),
            0,
        )
        .is_err());
        let mut reference = event;
        reference.media_disposition = MediaDisposition::Reference;
        reference.media = None;
        assert!(CanonicalCaptureEventPlan::new(
            ACCOUNT.to_owned(),
            reference,
            "raw/account-1/screen-asset-0.enc".to_owned(),
            41,
        )
        .is_err());
    }

    #[test]
    fn commits_complete_local_capture_once_and_replays_exact_response_without_writes() {
        let mut connection = connection();
        let event = manifest(0, "screen-event-0", "screen-asset-0");
        let applied = execute_prepared_for_owner(
            &mut connection,
            PreparedLogicalMutation::prepare(plan(event.clone())).unwrap(),
        )
        .unwrap();
        assert_eq!(applied.disposition(), LogicalMutationDisposition::Applied);
        let outcome = applied.into_validated_result().release().unwrap();
        assert_eq!(outcome.event_id(), "screen-event-0");
        assert_eq!(outcome.asset_id(), "screen-asset-0");
        assert_eq!(outcome.stream_id(), "screen-1");
        assert_eq!(outcome.committed_through_sequence(), 0);
        assert_eq!(
            connection
                .query_row(
                    "SELECT object_generation FROM media_objects WHERE asset_id='screen-asset-0'",
                    [],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            41
        );
        assert_eq!(
            connection
                .query_row(
                    "SELECT COUNT(*) FROM browser_observations_v2 WHERE event_id='screen-event-0'",
                    [],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            1
        );
        let changes = connection.total_changes();
        let replay = execute_prepared_for_owner(
            &mut connection,
            PreparedLogicalMutation::prepare(plan(event)).unwrap(),
        )
        .unwrap();
        assert_eq!(replay.disposition(), LogicalMutationDisposition::Replayed);
        assert_eq!(replay.into_validated_result().release().unwrap(), outcome);
        assert_eq!(connection.total_changes(), changes);
    }

    #[test]
    fn changed_upload_generation_for_same_event_conflicts_before_domain_sql() {
        let mut connection = connection();
        let event = manifest(0, "screen-event-0", "screen-asset-0");
        execute_prepared_for_owner(
            &mut connection,
            PreparedLogicalMutation::prepare(plan(event.clone())).unwrap(),
        )
        .unwrap();
        let changed = CanonicalCaptureEventPlan::new(
            ACCOUNT.to_owned(),
            event,
            "raw/account-1/screen-asset-0.enc".to_owned(),
            42,
        )
        .unwrap();
        let error = execute_prepared_for_owner(
            &mut connection,
            PreparedLogicalMutation::prepare(changed).unwrap(),
        )
        .err()
        .unwrap();
        assert_eq!(error, WalIdempotencyError::FingerprintConflict);
        assert_eq!(
            connection
                .query_row(
                    "SELECT object_generation FROM media_objects WHERE asset_id='screen-asset-0'",
                    [],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            41
        );
    }

    #[test]
    fn existing_event_without_ledger_is_not_adopted_and_consumes_no_identity() {
        let mut connection = connection();
        let event = manifest(0, "screen-event-0", "screen-asset-0");
        let digest = super::super::super::manifest_digest(&event).unwrap();
        super::super::super::record_source_event_with_generation(
            &connection,
            ACCOUNT,
            &event,
            &digest,
            &object_key(&event),
            Some(41),
        )
        .unwrap();
        let error = execute_prepared_for_owner(
            &mut connection,
            PreparedLogicalMutation::prepare(plan(event)).unwrap(),
        )
        .err()
        .unwrap();
        assert_eq!(error, WalIdempotencyError::Precondition);
        assert_eq!(
            connection
                .query_row(
                    "SELECT COUNT(*) FROM sqlite_schema WHERE name=?1",
                    [LEDGER_TABLE],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            0
        );
    }

    #[test]
    fn mismatched_existing_session_or_stream_rolls_back_before_capture() {
        let mut connection = connection();
        connection
            .execute(
                "INSERT INTO capture_sessions
                 (id,device_id,install_id,started_at,last_event_at,schema_version)
                 VALUES ('session-1','other-device','install-1',?1,?1,2)",
                ["2026-08-15T13:00:00.000Z"],
            )
            .unwrap();
        let event = manifest(0, "screen-event-0", "screen-asset-0");
        let error = execute_prepared_for_owner(
            &mut connection,
            PreparedLogicalMutation::prepare(plan(event)).unwrap(),
        )
        .err()
        .unwrap();
        assert_eq!(error, WalIdempotencyError::Precondition);
        assert_eq!(
            connection
                .query_row("SELECT COUNT(*) FROM capture_events", [], |row| {
                    row.get::<_, i64>(0)
                })
                .unwrap(),
            0
        );
    }

    #[test]
    fn row_cap_rejects_before_capture_but_committed_replay_survives() {
        let mut connection = connection();
        let first = manifest(0, "screen-event-0", "screen-asset-0");
        execute_prepared_for_owner(
            &mut connection,
            PreparedLogicalMutation::prepare(forced_plan(8, first.clone())).unwrap(),
        )
        .unwrap();
        connection
            .execute(
                "UPDATE archive_v3_wal_canonical_capture_event_state SET row_count=?1",
                [i64::from(MAX_ROWS)],
            )
            .unwrap();
        let replay = execute_prepared_for_owner(
            &mut connection,
            PreparedLogicalMutation::prepare(forced_plan(8, first)).unwrap(),
        )
        .unwrap();
        assert_eq!(replay.disposition(), LogicalMutationDisposition::Replayed);
        let blocked = manifest(1, "screen-event-1", "screen-asset-1");
        let error = execute_prepared_for_owner(
            &mut connection,
            PreparedLogicalMutation::prepare(forced_plan(9, blocked)).unwrap(),
        )
        .err()
        .unwrap();
        assert_eq!(error, WalIdempotencyError::Limit);
        assert_eq!(
            connection
                .query_row(
                    "SELECT COUNT(*) FROM capture_events WHERE event_id='screen-event-1'",
                    [],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            0
        );
    }

    #[test]
    fn result_byte_cap_rejects_before_capture() {
        let mut connection = connection();
        let first = manifest(0, "screen-event-0", "screen-asset-0");
        execute_prepared_for_owner(
            &mut connection,
            PreparedLogicalMutation::prepare(forced_plan(13, first)).unwrap(),
        )
        .unwrap();
        let insufficient_capacity =
            MAX_RESULT_BYTES - u64::try_from(MAX_ENCODED_REPLAY_RESULT_BYTES).unwrap() + 1;
        connection
            .execute(
                "UPDATE archive_v3_wal_canonical_capture_event_state SET result_bytes=?1",
                [i64::try_from(insufficient_capacity).unwrap()],
            )
            .unwrap();
        let blocked = manifest(1, "screen-event-1", "screen-asset-1");
        let error = execute_prepared_for_owner(
            &mut connection,
            PreparedLogicalMutation::prepare(forced_plan(14, blocked)).unwrap(),
        )
        .err()
        .unwrap();
        assert_eq!(error, WalIdempotencyError::Limit);
        assert_eq!(
            connection
                .query_row(
                    "SELECT COUNT(*) FROM capture_events WHERE event_id='screen-event-1'",
                    [],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            0
        );
    }

    #[test]
    fn late_ledger_failure_rolls_back_event_media_job_browser_and_ack() {
        let mut connection = connection();
        let transaction = connection.unchecked_transaction().unwrap();
        ensure_schema(&transaction).unwrap();
        transaction.commit().unwrap();
        connection
            .execute_batch(
                "CREATE TRIGGER reject_capture_ledger
                 BEFORE INSERT ON archive_v3_wal_canonical_capture_event_operations
                 BEGIN SELECT RAISE(ABORT,'reject'); END;",
            )
            .unwrap();
        let event = manifest(0, "screen-event-0", "screen-asset-0");
        assert!(execute_prepared_for_owner(
            &mut connection,
            PreparedLogicalMutation::prepare(forced_plan(10, event)).unwrap(),
        )
        .is_err());
        for table in [
            "capture_sessions",
            "capture_streams",
            "capture_events",
            "media_objects",
            "media_processing_jobs",
            "browser_observations_v2",
        ] {
            assert_eq!(
                connection
                    .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
                        row.get::<_, i64>(0)
                    })
                    .unwrap(),
                0,
                "late ledger failure must roll back {table}"
            );
        }
    }

    #[test]
    fn reopened_database_replays_exact_event_and_admits_next_gap_filling_event() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("canonical-capture.db");
        let later = manifest(1, "screen-event-1", "screen-asset-1");
        let expected = {
            let mut connection = Connection::open(&path).unwrap();
            super::super::super::init_schema(&connection).unwrap();
            execute_prepared_for_owner(
                &mut connection,
                PreparedLogicalMutation::prepare(forced_plan(11, later.clone())).unwrap(),
            )
            .unwrap()
            .into_validated_result()
            .release()
            .unwrap()
        };
        assert_eq!(expected.committed_through_sequence(), -1);
        let mut reopened = Connection::open(&path).unwrap();
        let changes = reopened.total_changes();
        let replay = execute_prepared_for_owner(
            &mut reopened,
            PreparedLogicalMutation::prepare(forced_plan(11, later)).unwrap(),
        )
        .unwrap();
        assert_eq!(replay.disposition(), LogicalMutationDisposition::Replayed);
        assert_eq!(replay.into_validated_result().release().unwrap(), expected);
        assert_eq!(reopened.total_changes(), changes);

        let first = manifest(0, "screen-event-0", "screen-asset-0");
        let applied = execute_prepared_for_owner(
            &mut reopened,
            PreparedLogicalMutation::prepare(forced_plan(12, first)).unwrap(),
        )
        .unwrap();
        assert_eq!(applied.disposition(), LogicalMutationDisposition::Applied);
        assert_eq!(
            applied
                .into_validated_result()
                .release()
                .unwrap()
                .committed_through_sequence(),
            1
        );
    }

    #[test]
    fn partial_schema_and_tampered_replay_fail_closed() {
        let mut partial = connection();
        partial
            .execute_batch(
                "CREATE TABLE archive_v3_wal_canonical_capture_event_schema (
                    singleton INTEGER PRIMARY KEY,
                    format_version INTEGER,
                    codec_version INTEGER
                 );",
            )
            .unwrap();
        let event = manifest(0, "screen-event-0", "screen-asset-0");
        let error = execute_prepared_for_owner(
            &mut partial,
            PreparedLogicalMutation::prepare(forced_plan(15, event.clone())).unwrap(),
        )
        .err()
        .unwrap();
        assert_eq!(error, WalIdempotencyError::Corrupt);
        assert_eq!(
            partial
                .query_row("SELECT COUNT(*) FROM capture_events", [], |row| {
                    row.get::<_, i64>(0)
                })
                .unwrap(),
            0
        );

        let mut tampered = connection();
        execute_prepared_for_owner(
            &mut tampered,
            PreparedLogicalMutation::prepare(forced_plan(16, event.clone())).unwrap(),
        )
        .unwrap();
        tampered
            .execute(
                "UPDATE archive_v3_wal_canonical_capture_event_operations
                 SET result_bytes=x'000000000000000000'",
                [],
            )
            .unwrap();
        let error = execute_prepared_for_owner(
            &mut tampered,
            PreparedLogicalMutation::prepare(forced_plan(16, event)).unwrap(),
        )
        .err()
        .unwrap();
        assert_eq!(error, WalIdempotencyError::Corrupt);
    }
}
