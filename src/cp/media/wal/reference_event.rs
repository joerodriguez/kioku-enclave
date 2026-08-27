//! Single-event Mac screen-reference WAL domain.
//!
//! The metadata-only sibling of [`super::reference_batch`], for the one
//! reference event that arrives on `POST /api/v2/capture/events` rather than in
//! a batch. It commits exactly the rows the legacy reference writer commits --
//! the capture-session upsert, the stream insert-or-ignore, the full
//! `capture_events` row including every reference column, the browser
//! observation, and the contiguous-acknowledgement advance -- plus its own
//! distinct bounded permanent replay ledger. It has no media bytes, DEK,
//! provider, Store, billing, launcher, or task authority.
//!
//! # Why this is a separate family and not a one-event batch
//!
//! Reusing [`super::reference_batch::MediaReferenceBatchPlan`] *literally* for
//! a single event would not wedge anything: a Reference event is always
//! `mac_screen`, so a one-event batch validates; the batch id derives from the
//! ordered `(event_id, sequence)` pairs, so the two posts land on the same
//! operation id; and because literal reuse also carries that plan's
//! `canonical_request` and its `Output`, the fingerprint matches and
//! `validate_replay` accepts the stored outcome. That alias is correct
//! idempotent dedup, because the two posts ARE the same logical mutation.
//!
//! The hazard is the *bespoke* variant: a plan that reuses only the batch id
//! derivation while committing its own `Output`. It would land on the same
//! operation id under the same `WalOperationKind::MediaCaptureEvent` ordinal
//! with a mismatching fingerprint and a mismatching decoded outcome, and
//! `archive_v3_wal_publications` -- one row per archive under
//! `UNIQUE (archive_id, operation_kind, operation_id)`, resuming only when id
//! AND fingerprint AND kind all match, deriving its `session_id` from
//! `(archive_id, kind, operation_id)` alone -- would give the two families one
//! durable operation slot they can never share, plus one attempt ladder in
//! which each family's retries burn the other's budget.
//!
//! So this family takes its OWN operation-source subtype. A retry of one
//! request maps to the same id; the same event posted through the batch route
//! maps to a different one, because the subtype is framed first and the
//! `stable_operation_source` digest binds every field after it. Two ids, two
//! ledgers, two publication slots, no aliasing in either direction.

use rusqlite::{params, Connection, OptionalExtension, Transaction};
use zeroize::Zeroizing;

use crate::archive_v3_wal_idempotency::{
    stable_operation_source, DomainLedgerBounds, LogicalMutationResult, PreparedLogicalMutation,
    WalIdempotencyError, WalLogicalDomainLedger, WalLogicalDomainPlan, WalLogicalOperationId,
    WalOperationKind, WalReplayResult, MAX_ENCODED_REPLAY_RESULT_BYTES,
};
use crate::error::EnclaveError;

use super::super::{CaptureEventManifest, MediaDisposition, RecordOutcome};
use super::RebaseRefusalSink;

const REQUEST_V1: u16 = 1;
/// Request/result discriminator inside `WalOperationKind::MediaCaptureEvent`.
/// 1 is the reference batch, 2 the canonical capture receipt, 3 the media-DEK
/// install; this family is 4.
const REQUEST_REFERENCE_EVENT: u8 = 4;
const RESULT_V1: u16 = 1;
const RESULT_REFERENCE_EVENT: u8 = 4;
/// The operation-source domain, distinct from `reference-batch-v1` and
/// `canonical-capture-event-v1`. `test_plan_family_subtypes_are_declared_and_
/// pairwise_distinct` is what keeps it that way in review.
const SUBTYPE: &[u8] = b"adr-0022-single-reference-capture-event-v1";
const MAX_ID_BYTES: usize = 128;
const SCHEMA_TABLE: &str = "archive_v3_wal_media_reference_event_schema";
const LEDGER_TABLE: &str = "archive_v3_wal_media_reference_event_operations";
const STATE_TABLE: &str = "archive_v3_wal_media_reference_event_state";
const MAX_ROWS: u32 = 1_048_576;
const MAX_RESULT_BYTES: u64 = 512 * 1024 * 1024;
const BOUNDS: DomainLedgerBounds = DomainLedgerBounds::new(MAX_ROWS, MAX_RESULT_BYTES);

type Result<T> = std::result::Result<T, WalIdempotencyError>;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct MediaReferenceEventOutcome {
    event_id: String,
    asset_id: String,
    stream_id: String,
    /// A duplicate is a FIRST-CLASS outcome here, unlike the canonical family
    /// which treats one as corrupt. The legacy route answers 200 for a
    /// duplicate reference event, and the same event can legitimately arrive
    /// through both this route and the batch route, so refusing one would turn
    /// an ordinary re-post into a hard failure.
    duplicate: bool,
    committed_through_sequence: i64,
}

impl MediaReferenceEventOutcome {
    pub(in crate::cp::media) fn event_id(&self) -> &str {
        &self.event_id
    }

    pub(in crate::cp::media) fn asset_id(&self) -> &str {
        &self.asset_id
    }

    pub(in crate::cp::media) fn stream_id(&self) -> &str {
        &self.stream_id
    }

    pub(crate) const fn duplicate(&self) -> bool {
        self.duplicate
    }

    pub(crate) const fn committed_through_sequence(&self) -> i64 {
        self.committed_through_sequence
    }
}

pub(crate) struct MediaReferenceEventPlan {
    operation_id: WalLogicalOperationId,
    account_id: String,
    manifest: CaptureEventManifest,
    manifest_digest: String,
    asset_id: String,
    committed_at: String,
    refusal: RebaseRefusalSink,
}

impl MediaReferenceEventPlan {
    pub(crate) fn new(
        account_id: String,
        manifest: CaptureEventManifest,
        committed_at: String,
    ) -> Result<Self> {
        Self::build(None, account_id, manifest, committed_at)
    }

    fn build(
        operation_id: Option<WalLogicalOperationId>,
        account_id: String,
        manifest: CaptureEventManifest,
        committed_at: String,
    ) -> Result<Self> {
        super::super::validate_id("account_id", &account_id)
            .map_err(|_| WalIdempotencyError::Malformed)?;
        manifest
            .validate()
            .map_err(|_| WalIdempotencyError::Malformed)?;
        if manifest.media_disposition != MediaDisposition::Reference || manifest.media.is_some() {
            return Err(WalIdempotencyError::Malformed);
        }
        if !super::is_canonical_commit_stamp(&committed_at) {
            return Err(WalIdempotencyError::Malformed);
        }
        // `validate` already proved these are present for a Reference
        // disposition; re-taking them here keeps the plan total.
        let reference = manifest
            .reference
            .as_ref()
            .ok_or(WalIdempotencyError::Malformed)?;
        let asset_id = reference.canonical_asset_id.clone();
        let manifest_digest =
            super::super::manifest_digest(&manifest).map_err(|_| WalIdempotencyError::Malformed)?;
        let operation_id = match operation_id {
            Some(value) => value,
            None => {
                // The subtype is framed first and every field after it is
                // length-framed into the digest, so no combination of fields
                // can alias another family's source. `event_id` is fixed by
                // the caller before the first post and is unchanged by every
                // retry of it, so a retry derives the same id with no counter,
                // clock, or database lookup.
                let source = stable_operation_source(
                    SUBTYPE,
                    &[account_id.as_bytes(), manifest.event_id.as_bytes()],
                )?;
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
            asset_id,
            committed_at,
            refusal: RebaseRefusalSink::default(),
        })
    }

    #[cfg(test)]
    fn with_operation_id(
        operation_id: WalLogicalOperationId,
        account_id: String,
        manifest: CaptureEventManifest,
        committed_at: String,
    ) -> Result<Self> {
        Self::build(Some(operation_id), account_id, manifest, committed_at)
    }

    /// Handle on the rebase-required reason `apply()` refused with, taken by
    /// the route before `prepare` consumes the plan. See
    /// [`RebaseRefusalSink`].
    pub(crate) fn refusal_sink(&self) -> RebaseRefusalSink {
        self.refusal.clone()
    }

    /// The stamp bound in place of the live-clock column DEFAULTs on
    /// `capture_sessions.created_at`, `capture_streams.created_at`,
    /// `capture_events.received_at`, `browser_states_v2.created_at` and
    /// `browser_observations_v2.created_at`. Every one of those tables is
    /// declared ONLY in `cp::media::init_schema` (never in `SCHEMA_SQL`), every
    /// one of those columns carries
    /// `DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))`, and no legacy INSERT
    /// binds any of them.
    ///
    /// All five are ENCLAVE-side facts — `received_at` means enclave receipt,
    /// the `created_at` columns mean row creation. The device's own wall time
    /// keeps its own column (`capture_events.source_wall_at`) and its own
    /// observation time keeps `browser_observations_v2.observed_at`; neither
    /// is what these five mean.
    ///
    /// So this is the ENCLAVE-generated `committed_at` the route read once
    /// (`cp::media::enclave_commit_stamp`), never `manifest.source_wall_at`.
    /// It is fixed in the plan at construction, so `apply()` holds no live
    /// clock; and it is deliberately kept out of BOTH the operation identity
    /// and `canonical_request`, so the Mac outbox's re-post of one event —
    /// which necessarily mints a different stamp — still matches the stored
    /// fingerprint and settles as `Replayed` writing nothing, instead of
    /// becoming a `FingerprintConflict` the client can never clear. See
    /// `super::capture_event::CanonicalCaptureEventPlan::commit_stamp` for the
    /// full argument and the claim-lane wedge that makes a device-supplied
    /// stamp unsafe here.
    fn commit_stamp(&self) -> &str {
        &self.committed_at
    }
}

pub(crate) struct MediaReferenceEventLedger;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum LedgerSchemaState {
    Absent,
    Present,
}

impl WalLogicalDomainPlan for MediaReferenceEventPlan {
    type Ledger = MediaReferenceEventLedger;
    type Output = MediaReferenceEventOutcome;

    fn kind(&self) -> WalOperationKind {
        WalOperationKind::MediaCaptureEvent
    }

    fn operation_id(&self) -> WalLogicalOperationId {
        self.operation_id
    }

    /// The normalized manifest is committed BY HASH, never embedded: the
    /// fingerprint is derived over these bytes and a manifest can carry a
    /// browser snapshot with page titles and URLs in it.
    fn canonical_request(&self) -> Result<Zeroizing<Vec<u8>>> {
        let mut request = Zeroizing::new(Vec::with_capacity(
            self.account_id
                .len()
                .saturating_add(self.manifest.event_id.len())
                .saturating_add(128),
        ));
        request.extend_from_slice(&REQUEST_V1.to_be_bytes());
        request.push(REQUEST_REFERENCE_EVENT);
        encode_string(&mut request, &self.account_id)?;
        encode_string(&mut request, &self.manifest.event_id)?;
        encode_string(&mut request, &self.manifest_digest)?;
        // `committed_at` is deliberately NOT here, and not in the identity
        // either: it is a clock, and the Mac outbox re-posts one event many
        // times. See `commit_stamp` and the F2 precedent in
        // `model_usage::wal::coverage`.
        Ok(request)
    }

    fn apply(&self, transaction: &Transaction<'_>) -> Result<WalReplayResult> {
        validate_existing_parents(transaction, self)?;
        let outcome = match super::super::record_reference_event_in_transaction(
            transaction,
            &self.account_id,
            &self.manifest,
            &self.manifest_digest,
            Some(self.commit_stamp()),
        ) {
            Ok(outcome) => outcome,
            Err(EnclaveError::CaptureReference(reason)) => {
                // Strictly additive: the refusal still collapses to the same
                // `Precondition` it collapsed to before, and the transaction
                // still rolls back. Recording it lets the route answer the
                // documented `400 screen_reference_rebase_required` instead of
                // a content-free conflict the durable outbox would retry
                // forever without ever learning it must rebase. `None` for the
                // batch position: the single-event legacy branch reports the
                // bare reason, with no item index.
                self.refusal.record(reason, None);
                return Err(map_domain_error(EnclaveError::CaptureReference(reason)));
            }
            Err(error) => return Err(map_domain_error(error)),
        };
        if outcome == RecordOutcome::Created {
            validate_committed_rows(transaction, self)?;
        }
        let committed_through_sequence =
            super::super::committed_through_sequence(transaction, &self.manifest.stream_id)
                .map_err(map_domain_error)?;
        encode_outcome(&MediaReferenceEventOutcome {
            event_id: self.manifest.event_id.clone(),
            asset_id: self.asset_id.clone(),
            stream_id: self.manifest.stream_id.clone(),
            duplicate: outcome == RecordOutcome::Duplicate,
            committed_through_sequence,
        })
    }

    fn validate_replay(&self, result: &WalReplayResult) -> Result<()> {
        let outcome = decode_outcome(result)?;
        if outcome.event_id != self.manifest.event_id
            || outcome.asset_id != self.asset_id
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

impl WalLogicalDomainLedger<MediaReferenceEventPlan> for MediaReferenceEventLedger {
    fn lookup(
        connection: &Connection,
        prepared: &PreparedLogicalMutation<MediaReferenceEventPlan>,
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
                 FROM archive_v3_wal_media_reference_event_operations
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
        prepared: &PreparedLogicalMutation<MediaReferenceEventPlan>,
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
                "INSERT INTO archive_v3_wal_media_reference_event_operations
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
                "UPDATE archive_v3_wal_media_reference_event_state
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

fn require_kind(prepared: &PreparedLogicalMutation<MediaReferenceEventPlan>) -> Result<()> {
    (prepared.kind_for_owner() == WalOperationKind::MediaCaptureEvent)
        .then_some(())
        .ok_or(WalIdempotencyError::ResultUnsupported)
}

/// The legacy writer creates the session and stream with `ON CONFLICT DO
/// NOTHING`/`DO UPDATE`, so an existing row with the wrong device, install or
/// stream kind would silently adopt this event. Authenticate the bindings
/// before touching them.
fn validate_existing_parents(
    connection: &Connection,
    plan: &MediaReferenceEventPlan,
) -> Result<()> {
    let session = connection
        .query_row(
            "SELECT device_id,install_id,schema_version
             FROM capture_sessions WHERE id=?1",
            [&plan.manifest.capture_session_id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                ))
            },
        )
        .optional()
        .map_err(|_| WalIdempotencyError::Unavailable)?;
    if let Some((device, install, schema)) = session {
        if device != plan.manifest.device_id || install != plan.manifest.install_id || schema != 2 {
            return Err(WalIdempotencyError::Precondition);
        }
    }
    let stream = connection
        .query_row(
            "SELECT capture_session_id,device_id,stream_kind,committed_through_sequence,
                    sealed_sequence
             FROM capture_streams WHERE id=?1",
            [&plan.manifest.stream_id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, Option<i64>>(4)?,
                ))
            },
        )
        .optional()
        .map_err(|_| WalIdempotencyError::Unavailable)?;
    if let Some((session, device, kind, committed, sealed)) = stream {
        if session != plan.manifest.capture_session_id
            || device != plan.manifest.device_id
            || kind != plan.manifest.stream_kind.as_str()
        {
            return Err(WalIdempotencyError::Precondition);
        }
        if committed < -1 || sealed.is_some() {
            return Err(WalIdempotencyError::Corrupt);
        }
    }
    Ok(())
}

/// Read back the row this operation just created. Only the columns the plan
/// itself fixes are checked; the reference columns' own preconditions were
/// enforced by the writer before the INSERT.
fn validate_committed_rows(connection: &Connection, plan: &MediaReferenceEventPlan) -> Result<()> {
    let reference = plan
        .manifest
        .reference
        .as_ref()
        .ok_or(WalIdempotencyError::Corrupt)?;
    let stored = connection
        .query_row(
            "SELECT device_id,install_id,capture_session_id,stream_id,stream_kind,sequence,
                    source_wall_at,started_at,ended_at,manifest_digest,media_disposition,
                    canonical_event_id,canonical_asset_id,dedupe_version,received_at
             FROM capture_events WHERE event_id=?1",
            [&plan.manifest.event_id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, i64>(5)?,
                    row.get::<_, String>(6)?,
                    row.get::<_, String>(7)?,
                    row.get::<_, String>(8)?,
                    row.get::<_, String>(9)?,
                    row.get::<_, String>(10)?,
                    row.get::<_, Option<String>>(11)?,
                    row.get::<_, Option<String>>(12)?,
                    row.get::<_, Option<i64>>(13)?,
                    row.get::<_, String>(14)?,
                ))
            },
        )
        .map_err(|_| WalIdempotencyError::Unavailable)?;
    if stored.0 != plan.manifest.device_id
        || stored.1 != plan.manifest.install_id
        || stored.2 != plan.manifest.capture_session_id
        || stored.3 != plan.manifest.stream_id
        || stored.4 != plan.manifest.stream_kind.as_str()
        || stored.5 != plan.manifest.sequence
        || stored.6 != plan.manifest.source_wall_at
        || stored.7 != plan.manifest.started_at
        || stored.8 != plan.manifest.ended_at
        || stored.9 != plan.manifest_digest
        || stored.10 != "reference"
        || stored.11.as_deref() != Some(reference.canonical_event_id.as_str())
        || stored.12.as_deref() != Some(reference.canonical_asset_id.as_str())
        || stored.13 != Some(i64::from(reference.dedupe_version))
        // The bound commit stamp. A row still carrying `strftime('now')` means
        // the bind was dropped between the plan and the SQL and `apply()`
        // silently became a function of wall time again; a row carrying
        // `source_wall_at` means the DEVICE's clock reached an enclave-side
        // column and the claim lane is one poisoned stamp from wedging.
        || stored.14 != plan.committed_at
    {
        return Err(WalIdempotencyError::Corrupt);
    }
    let parents = connection
        .query_row(
            "SELECT
                (SELECT created_at FROM capture_sessions WHERE id=?1),
                (SELECT created_at FROM capture_streams WHERE id=?2)",
            params![plan.manifest.capture_session_id, plan.manifest.stream_id],
            |row| {
                Ok((
                    row.get::<_, Option<String>>(0)?,
                    row.get::<_, Option<String>>(1)?,
                ))
            },
        )
        .map_err(|_| WalIdempotencyError::Unavailable)?;
    // The session and the stream may pre-date this event, in which case their
    // stamp belongs to whichever operation created them and this plan neither
    // wrote nor may rewrite it. Their existence is the invariant here.
    if parents.0.is_none() || parents.1.is_none() {
        return Err(WalIdempotencyError::Corrupt);
    }
    Ok(())
}

fn map_domain_error(error: EnclaveError) -> WalIdempotencyError {
    match error {
        EnclaveError::CaptureReference(_)
        | EnclaveError::CaptureReferenceBatch { .. }
        | EnclaveError::Conflict(_)
        | EnclaveError::NotFound => WalIdempotencyError::Precondition,
        EnclaveError::InvalidRequest(_) | EnclaveError::Json(_) => WalIdempotencyError::Corrupt,
        EnclaveError::Db(_)
        | EnclaveError::Postgres(_)
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
        // ADR-0022 D4: a deferred domain is unavailable, never corrupt and
        // never a definitive precondition failure -- it stays retryable.
        | EnclaveError::WalDomainUnmigrated(_) => WalIdempotencyError::Unavailable,
    }
}

fn encode_outcome(outcome: &MediaReferenceEventOutcome) -> Result<WalReplayResult> {
    let mut bytes = Vec::with_capacity(512);
    bytes.extend_from_slice(&RESULT_V1.to_be_bytes());
    bytes.push(RESULT_REFERENCE_EVENT);
    encode_string(&mut bytes, &outcome.event_id)?;
    encode_string(&mut bytes, &outcome.asset_id)?;
    encode_string(&mut bytes, &outcome.stream_id)?;
    bytes.push(u8::from(outcome.duplicate));
    bytes.extend_from_slice(&outcome.committed_through_sequence.to_be_bytes());
    WalReplayResult::canonical_response(WalOperationKind::MediaCaptureEvent, bytes)
}

fn decode_outcome(result: &WalReplayResult) -> Result<MediaReferenceEventOutcome> {
    let WalReplayResult::CanonicalResponse(bytes) = result else {
        return Err(WalIdempotencyError::ResultUnsupported);
    };
    let mut reader = Reader::new(bytes);
    if reader.take_u16()? != RESULT_V1 || reader.take_u8()? != RESULT_REFERENCE_EVENT {
        return Err(WalIdempotencyError::Corrupt);
    }
    let event_id = reader.take_string()?;
    let asset_id = reader.take_string()?;
    let stream_id = reader.take_string()?;
    let duplicate = match reader.take_u8()? {
        0 => false,
        1 => true,
        _ => return Err(WalIdempotencyError::Corrupt),
    };
    let committed_through_sequence = reader.take_i64()?;
    if !reader.is_empty()
        || super::super::validate_id("event_id", &event_id).is_err()
        || super::super::validate_id("asset_id", &asset_id).is_err()
        || super::super::validate_id("stream_id", &stream_id).is_err()
        || committed_through_sequence < -1
    {
        return Err(WalIdempotencyError::Corrupt);
    }
    Ok(MediaReferenceEventOutcome {
        event_id,
        asset_id,
        stream_id,
        duplicate,
        committed_through_sequence,
    })
}

fn encode_string(destination: &mut Vec<u8>, value: &str) -> Result<()> {
    let length = u32::try_from(value.len()).map_err(|_| WalIdempotencyError::Limit)?;
    destination.extend_from_slice(&length.to_be_bytes());
    destination.extend_from_slice(value.as_bytes());
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

    fn take_string(&mut self) -> Result<String> {
        let length: [u8; 4] = self
            .take(4)?
            .try_into()
            .map_err(|_| WalIdempotencyError::Corrupt)?;
        let length = usize::try_from(u32::from_be_bytes(length))
            .map_err(|_| WalIdempotencyError::Corrupt)?;
        if length == 0 || length > MAX_ID_BYTES {
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
                    "CREATE TABLE archive_v3_wal_media_reference_event_schema (
                        singleton INTEGER PRIMARY KEY CHECK(singleton=1),
                        format_version INTEGER NOT NULL CHECK(format_version=1),
                        codec_version INTEGER NOT NULL CHECK(codec_version=1)
                     ) STRICT;
                     CREATE TABLE archive_v3_wal_media_reference_event_operations (
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
                     CREATE TABLE archive_v3_wal_media_reference_event_state (
                        singleton INTEGER PRIMARY KEY CHECK(singleton=1),
                        row_count INTEGER NOT NULL CHECK(row_count BETWEEN 0 AND 1048576),
                        result_bytes INTEGER NOT NULL CHECK(result_bytes BETWEEN 0 AND 536870912)
                     ) STRICT;
                     INSERT INTO archive_v3_wal_media_reference_event_schema
                        (singleton,format_version,codec_version) VALUES (1,1,1);
                     INSERT INTO archive_v3_wal_media_reference_event_state
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
             FROM archive_v3_wal_media_reference_event_schema WHERE singleton=1",
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
             FROM archive_v3_wal_media_reference_event_state WHERE singleton=1",
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
    use crate::cp::media::{MediaDisposition, ScreenReferenceDescriptor};
    use crate::error::CaptureReferenceFailureReason;
    use rusqlite::Connection;
    use serde_json::json;

    const ACCOUNT: &str = "account-1";
    const SOURCE_WALL_AT: &str = "2026-07-31T18:00:01.000Z";
    /// The ENCLAVE stamps the route mints -- one per submit. Both are
    /// deliberately DIFFERENT from every fixture's `source_wall_at`, so a test
    /// that confuses a device clock for an enclave one fails instead of
    /// coincidentally passing.
    const CANONICAL_COMMITTED_AT: &str = "2026-07-31T18:04:11.750Z";
    const REFERENCE_COMMITTED_AT: &str = "2026-07-31T18:04:12.125Z";

    fn connection() -> Connection {
        let connection = Connection::open_in_memory().unwrap();
        super::super::super::init_schema(&connection).unwrap();
        connection
    }

    fn canonical_manifest() -> CaptureEventManifest {
        serde_json::from_value(json!({
            "schema_version": 2,
            "event_id": "screen-event-0",
            "device_id": "device-1",
            "install_id": "install-1",
            "capture_session_id": "session-1",
            "stream_id": "screen-1",
            "stream_kind": "mac_screen",
            "sequence": 0,
            "source_wall_at": "2026-07-31T18:00:00.000Z",
            "source_monotonic_ns": 9_000_000_000_u64,
            "started_at": "2026-07-31T18:00:00.000Z",
            "ended_at": "2026-07-31T18:00:02.000Z",
            "timezone_id": "America/New_York",
            "utc_offset_minutes": -240,
            "clock_uncertainty_ms": 24,
            "media": {
                "asset_id": "screen-asset-0",
                "mime_type": "image/jpeg",
                "codec": "jpeg",
                "byte_length": 12,
                "sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "width": 1280,
                "height": 720
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

    fn reference_to(
        canonical: &CaptureEventManifest,
        sequence: i64,
        event_id: &str,
    ) -> CaptureEventManifest {
        let mut reference = canonical.clone();
        let media = canonical.media.as_ref().unwrap();
        let context = canonical.context.as_ref().unwrap();
        reference.event_id = event_id.to_owned();
        reference.sequence = sequence;
        reference.source_wall_at = SOURCE_WALL_AT.to_owned();
        reference.source_monotonic_ns = reference
            .source_monotonic_ns
            .checked_add(u64::try_from(sequence).unwrap() + 1)
            .unwrap();
        reference.media_disposition = MediaDisposition::Reference;
        reference.media = None;
        reference.reference = Some(ScreenReferenceDescriptor {
            canonical_event_id: canonical.event_id.clone(),
            canonical_asset_id: media.asset_id.clone(),
            canonical_media_sha256: media.sha256.clone(),
            perceptual_hash: "0123456789abcdef".to_owned(),
            hamming_distance: 2,
            pixel_change_ratio: 0.004,
            context_fingerprint: super::super::super::semantic_context_fingerprint(context, 1)
                .unwrap(),
            dedupe_version: 1,
        });
        reference
    }

    fn insert_canonical(connection: &Connection, canonical: &CaptureEventManifest) {
        super::super::super::record_source_event(
            connection,
            ACCOUNT,
            canonical,
            &super::super::super::manifest_digest(canonical).unwrap(),
            "object-0",
        )
        .unwrap();
    }

    fn plan(manifest: CaptureEventManifest) -> MediaReferenceEventPlan {
        MediaReferenceEventPlan::new(
            ACCOUNT.to_owned(),
            manifest,
            REFERENCE_COMMITTED_AT.to_owned(),
        )
        .unwrap()
    }

    fn settle(
        connection: &mut Connection,
        plan: MediaReferenceEventPlan,
    ) -> std::result::Result<
        (LogicalMutationDisposition, MediaReferenceEventOutcome),
        WalIdempotencyError,
    > {
        let prepared = PreparedLogicalMutation::prepare(plan)?;
        let executed = execute_prepared_for_owner(connection, prepared)?;
        let disposition = executed.disposition();
        Ok((disposition, executed.into_validated_result().release()?))
    }

    /// IDENTITY, first half: the SAME request retried maps to the same
    /// operation id and the same canonical request, so a lost acknowledgement
    /// replays instead of conflicting.
    ///
    /// Falsifiability, checked by sabotage: folding a clock or a counter into
    /// the stable source makes the two ids differ and the first assertion
    /// fails.
    #[test]
    fn a_retry_of_one_request_maps_to_the_same_id_and_fingerprint() {
        let canonical = canonical_manifest();
        let event = reference_to(&canonical, 1, "screen-event-1");
        let first = plan(event.clone());
        let retry = plan(event);
        assert_eq!(first.operation_id(), retry.operation_id());
        assert_eq!(
            first.canonical_request().unwrap(),
            retry.canonical_request().unwrap()
        );
    }

    /// IDENTITY, second half: different requests never collide, in every
    /// direction that matters here.
    ///
    ///   * a different event id under this family;
    ///   * a different ACCOUNT with the same event id;
    ///   * the SAME event through the batch route, which shares the
    ///     `MediaCaptureEvent` ordinal;
    ///   * the bare `reference_batch_id` derivation a bespoke plan would have
    ///     reused -- the collision this family exists to avoid;
    ///   * the canonical family's own domain for the same event id.
    ///
    /// Falsifiability, checked by sabotage: dropping `SUBTYPE` from the stable
    /// source (deriving from the bare event id) makes the canonical-domain and
    /// batch comparisons collide.
    #[test]
    fn different_requests_never_collide_with_each_other_or_the_neighbouring_families() {
        let canonical = canonical_manifest();
        let event = reference_to(&canonical, 1, "screen-event-1");
        let mine = plan(event.clone());

        let other_event = plan(reference_to(&canonical, 2, "screen-event-2"));
        assert_ne!(mine.operation_id(), other_event.operation_id());

        let other_account = MediaReferenceEventPlan::new(
            "account-2".to_owned(),
            event.clone(),
            REFERENCE_COMMITTED_AT.to_owned(),
        )
        .unwrap();
        assert_ne!(mine.operation_id(), other_account.operation_id());

        let batch_id =
            super::super::super::reference_batch_id(std::slice::from_ref(&event)).unwrap();
        let batch = super::super::MediaReferenceBatchPlan::new(
            ACCOUNT.to_owned(),
            batch_id.clone(),
            vec![event.clone()],
            REFERENCE_COMMITTED_AT.to_owned(),
        )
        .unwrap();
        assert_ne!(
            mine.operation_id(),
            batch.operation_id(),
            "the same event posted through the batch route must not alias this family"
        );

        // The bespoke-plan hazard, stated as an assertion: a plan that reused
        // only the batch id derivation while committing its own Output would
        // land here, on one `archive_v3_wal_publications` slot it could never
        // match a fingerprint for.
        assert_ne!(
            mine.operation_id(),
            WalLogicalOperationId::from_stable_source(
                WalOperationKind::MediaCaptureEvent,
                batch_id.as_bytes(),
            )
            .unwrap()
        );

        // The canonical family's domain, for the same event id.
        let mut canonical_source = b"canonical-capture-event-v1\0".to_vec();
        canonical_source.extend_from_slice(event.event_id.as_bytes());
        assert_ne!(
            mine.operation_id(),
            WalLogicalOperationId::from_stable_source(
                WalOperationKind::MediaCaptureEvent,
                &canonical_source,
            )
            .unwrap()
        );

        // A different manifest for the same event id keeps the id (it is the
        // same logical operation) but must NOT keep the fingerprint.
        let mut edited = event;
        edited.reference.as_mut().unwrap().hamming_distance = 3;
        let edited = plan(edited);
        assert_eq!(mine.operation_id(), edited.operation_id());
        assert_ne!(
            mine.canonical_request().unwrap(),
            edited.canonical_request().unwrap()
        );
    }

    /// The canonical request commits the manifest BY HASH. It is hashed into a
    /// durable fingerprint, and a manifest can carry browser titles and URLs.
    #[test]
    fn the_canonical_request_commits_the_manifest_by_hash_and_never_embeds_it() {
        let canonical = canonical_manifest();
        let event = reference_to(&canonical, 1, "screen-event-1");
        let plan = plan(event);
        let request = plan.canonical_request().unwrap();
        let bytes = request.as_slice();
        for secret in [
            b"meet.google.com".as_slice(),
            b"Weekly planning".as_slice(),
            b"com.google.Chrome".as_slice(),
        ] {
            assert!(
                !bytes.windows(secret.len()).any(|window| window == secret),
                "the manifest must be committed by digest, not embedded"
            );
        }
        assert!(bytes
            .windows(64)
            .any(|window| window == plan.manifest_digest.as_bytes()));
    }

    /// Every row this family claims to cover, in one transaction: the session
    /// upsert, the stream insert-or-ignore, the full reference event row, the
    /// browser observation, and the contiguous acknowledgement advance.
    #[test]
    fn one_apply_covers_the_session_stream_event_browser_and_acknowledgement_rows() {
        let mut connection = connection();
        let canonical = canonical_manifest();
        insert_canonical(&connection, &canonical);
        let event = reference_to(&canonical, 1, "screen-event-1");

        let (disposition, outcome) = settle(&mut connection, plan(event.clone())).unwrap();
        assert!(matches!(disposition, LogicalMutationDisposition::Applied));
        assert_eq!(outcome.event_id(), "screen-event-1");
        assert_eq!(outcome.asset_id(), "screen-asset-0");
        assert_eq!(outcome.stream_id(), "screen-1");
        assert!(!outcome.duplicate());
        assert_eq!(outcome.committed_through_sequence(), 1);

        let row: (String, String, Option<String>, Option<i64>, Option<f64>) = connection
            .query_row(
                "SELECT media_disposition,canonical_event_id,canonical_media_sha256,\
                        hamming_distance,pixel_change_ratio \
                 FROM capture_events WHERE event_id='screen-event-1'",
                [],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                    ))
                },
            )
            .unwrap();
        assert_eq!(row.0, "reference");
        assert_eq!(row.1, "screen-event-0");
        assert_eq!(
            row.2.as_deref(),
            Some(canonical.media.unwrap().sha256.as_str())
        );
        assert_eq!(row.3, Some(2));
        assert_eq!(row.4, Some(0.004));

        let observations: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM browser_observations_v2 WHERE event_id='screen-event-1'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(observations, 1);
        let committed: i64 = connection
            .query_row(
                "SELECT committed_through_sequence FROM capture_streams WHERE id='screen-1'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(committed, 1);
    }

    /// A duplicate is a FIRST-CLASS outcome. The legacy route answers 200 for a
    /// re-posted reference event, and the same event can legitimately arrive
    /// through both this route and the batch route, so refusing one would turn
    /// an ordinary re-post into a hard failure and wedge the client's outbox.
    ///
    /// Falsifiability, checked by sabotage: making `apply` refuse on
    /// `RecordOutcome::Duplicate` the way the canonical family does turns the
    /// settle below into `Err(Precondition)` and the assertions fail.
    #[test]
    fn an_event_already_written_by_the_batch_route_settles_as_a_duplicate() {
        let mut connection = connection();
        let canonical = canonical_manifest();
        insert_canonical(&connection, &canonical);
        let event = reference_to(&canonical, 1, "screen-event-1");
        // Written by the OTHER route, so no ledger row of this family exists
        // and the duplicate has to be recognised by the domain writer.
        super::super::super::record_reference_event(
            &connection,
            ACCOUNT,
            &event,
            &super::super::super::manifest_digest(&event).unwrap(),
        )
        .unwrap();

        let (disposition, outcome) = settle(&mut connection, plan(event)).unwrap();
        assert!(matches!(disposition, LogicalMutationDisposition::Applied));
        assert!(outcome.duplicate(), "a duplicate must not refuse");
        assert_eq!(outcome.committed_through_sequence(), 1);
        let events: i64 = connection
            .query_row("SELECT COUNT(*) FROM capture_events", [], |row| row.get(0))
            .unwrap();
        assert_eq!(events, 2, "the duplicate wrote no second row");
    }

    /// A second settle of the same request replays the exact stored outcome
    /// and writes nothing.
    #[test]
    fn a_replayed_request_returns_the_exact_outcome_and_writes_nothing() {
        let mut connection = connection();
        let canonical = canonical_manifest();
        insert_canonical(&connection, &canonical);
        let event = reference_to(&canonical, 1, "screen-event-1");
        let (_, first) = settle(&mut connection, plan(event.clone())).unwrap();
        let before: i64 = connection
            .query_row("SELECT COUNT(*) FROM capture_events", [], |row| row.get(0))
            .unwrap();

        let (disposition, replayed) = settle(&mut connection, plan(event)).unwrap();
        assert!(matches!(disposition, LogicalMutationDisposition::Replayed));
        assert_eq!(first, replayed);
        let after: i64 = connection
            .query_row("SELECT COUNT(*) FROM capture_events", [], |row| row.get(0))
            .unwrap();
        assert_eq!(before, after);
    }

    /// The REBASE-REQUIRED reason must reach the route.
    ///
    /// `apply` still refuses with the same `Precondition` it refused with
    /// before -- nothing is weakened, and the transaction still rolls back --
    /// but the reason is recorded on the plan's sink so the route can answer
    /// the documented `400 screen_reference_rebase_required` instead of a
    /// content-free conflict. Without it the Mac client's durable outbox
    /// re-posts an event only a rebase can fix, forever.
    ///
    /// Falsifiability, checked by sabotage: deleting the `self.refusal.record`
    /// call leaves `observed()` as `None` and the last three assertions fail
    /// while the `Precondition` assertion still passes -- which is exactly why
    /// the `Precondition` assertion alone was never enough.
    #[test]
    fn a_rebase_required_refusal_reaches_the_route_with_its_reason() {
        let mut connection = connection();
        let canonical = canonical_manifest();
        // Deliberately NOT inserted: the canonical target is missing, which is
        // what a real rebase race looks like.
        let event = reference_to(&canonical, 1, "screen-event-1");
        let plan = plan(event);
        let refusal = plan.refusal_sink();

        let error = settle(&mut connection, plan).unwrap_err();
        assert_eq!(error, WalIdempotencyError::Precondition);

        let observed = refusal.observed().expect("the reason must reach the route");
        assert!(matches!(
            observed,
            EnclaveError::CaptureReference(CaptureReferenceFailureReason::CanonicalUnavailable)
        ));
        let response = axum::response::IntoResponse::into_response(observed);
        assert_eq!(response.status(), axum::http::StatusCode::BAD_REQUEST);

        let rows: i64 = connection
            .query_row("SELECT COUNT(*) FROM capture_events", [], |row| row.get(0))
            .unwrap();
        assert_eq!(rows, 0, "the refused transaction must roll back");
    }

    /// Every reason the writer can refuse with survives the trip, not just the
    /// one the happy-path test happens to trigger.
    #[test]
    fn a_context_fingerprint_mismatch_survives_the_trip_too() {
        let mut connection = connection();
        let canonical = canonical_manifest();
        insert_canonical(&connection, &canonical);
        let mut event = reference_to(&canonical, 1, "screen-event-1");
        event.reference.as_mut().unwrap().context_fingerprint = "b".repeat(64);
        let plan = plan(event);
        let refusal = plan.refusal_sink();

        assert_eq!(
            settle(&mut connection, plan).unwrap_err(),
            WalIdempotencyError::Precondition
        );
        assert!(matches!(
            refusal.observed().unwrap(),
            EnclaveError::CaptureReference(
                CaptureReferenceFailureReason::ContextFingerprintMismatch
            )
        ));
    }

    /// TIMESTAMPS. Every clock DEFAULT on this row set is bound to the owning
    /// plan's ENCLAVE commit stamp instead of firing `strftime('now')` inside
    /// `apply()`, which would make the committed pages a function of wall time
    /// rather than of the plan.
    ///
    /// The second half of the property is the one that matters more: the stamp
    /// must be the ENCLAVE's, never the manifest's `source_wall_at`. Every
    /// column below is an enclave-side fact, and
    /// `media_processing_jobs.updated_at` in particular is compared as a raw
    /// string against an enclave `committed_at` by `MediaWorkClaimPlan::new` --
    /// a device stamp there wedges the account's whole media lane. The two
    /// enclave stamps and the two `source_wall_at` values are all four
    /// distinct, so every assertion below discriminates.
    ///
    /// Both families are exercised, because in practice a reference event
    /// always follows its canonical on the same stream: the session and stream
    /// rows are created by the CANONICAL arm and carry ITS stamp, while the
    /// reference event's own rows carry the reference's. Testing the reference
    /// arm alone would have left the canonical arm's seven bindings unpinned.
    ///
    /// Falsifiability, checked by sabotage: dropping the `Some(commit_stamp)`
    /// argument in either family (or passing `None`) leaves the columns at the
    /// live clock -- and each family's `validate_committed_rows` refuses the
    /// apply outright, so the sabotage cannot even settle. Re-binding either
    /// family's `commit_stamp` to `manifest.source_wall_at` fails the
    /// `assert_ne!` pair and then the per-column assertions.
    #[test]
    fn both_families_bind_their_enclave_commit_stamp_never_the_device_wall_clock() {
        let mut connection = connection();
        let canonical = canonical_manifest();
        let asset_id = canonical.media.as_ref().unwrap().asset_id.clone();
        let object_key = format!("raw/{ACCOUNT}/{asset_id}.enc");
        let canonical_plan = super::super::CanonicalCaptureEventPlan::new(
            ACCOUNT.to_owned(),
            canonical.clone(),
            object_key,
            17,
            CANONICAL_COMMITTED_AT.to_owned(),
        )
        .unwrap();
        let prepared = PreparedLogicalMutation::prepare(canonical_plan).unwrap();
        execute_prepared_for_owner(&mut connection, prepared).unwrap();

        let event = reference_to(&canonical, 1, "screen-event-1");
        settle(&mut connection, plan(event)).unwrap();

        // All four stamps in play are distinct, so no assertion below can pass
        // by coincidence: the two ENCLAVE stamps discriminate the two families
        // from each other, and neither may equal either DEVICE stamp.
        assert_ne!(CANONICAL_COMMITTED_AT, REFERENCE_COMMITTED_AT);
        assert_ne!(canonical.source_wall_at.as_str(), SOURCE_WALL_AT);
        for enclave in [CANONICAL_COMMITTED_AT, REFERENCE_COMMITTED_AT] {
            assert_ne!(enclave, canonical.source_wall_at.as_str());
            assert_ne!(enclave, SOURCE_WALL_AT);
        }

        let stamps: (String, String, String, String, String, String, String) = connection
            .query_row(
                "SELECT
                    (SELECT created_at FROM capture_sessions WHERE id='session-1'),
                    (SELECT created_at FROM capture_streams WHERE id='screen-1'),
                    (SELECT received_at FROM capture_events WHERE event_id='screen-event-0'),
                    (SELECT created_at FROM media_objects WHERE asset_id='screen-asset-0'),
                    (SELECT updated_at FROM media_processing_jobs
                     WHERE event_id='screen-event-0'),
                    (SELECT received_at FROM capture_events WHERE event_id='screen-event-1'),
                    (SELECT created_at FROM browser_observations_v2
                     WHERE event_id='screen-event-1')",
                [],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                        row.get(5)?,
                        row.get(6)?,
                    ))
                },
            )
            .unwrap();
        assert_eq!(
            stamps.0, CANONICAL_COMMITTED_AT,
            "capture_sessions.created_at"
        );
        assert_eq!(
            stamps.1, CANONICAL_COMMITTED_AT,
            "capture_streams.created_at"
        );
        assert_eq!(stamps.2, CANONICAL_COMMITTED_AT, "canonical received_at");
        assert_eq!(stamps.3, CANONICAL_COMMITTED_AT, "media_objects.created_at");
        assert_eq!(
            stamps.4, CANONICAL_COMMITTED_AT,
            "media_processing_jobs.updated_at"
        );
        assert_eq!(stamps.5, REFERENCE_COMMITTED_AT, "reference received_at");
        assert_eq!(
            stamps.6, REFERENCE_COMMITTED_AT,
            "browser_observations_v2.created_at"
        );

        // The device's own clocks are still recorded -- in the columns that
        // MEAN a device clock, and nowhere else.
        let device: (String, String, String) = connection
            .query_row(
                "SELECT
                    (SELECT source_wall_at FROM capture_events WHERE event_id='screen-event-0'),
                    (SELECT source_wall_at FROM capture_events WHERE event_id='screen-event-1'),
                    (SELECT observed_at FROM browser_observations_v2
                     WHERE event_id='screen-event-1')",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();
        assert_eq!(
            device.0, canonical.source_wall_at,
            "canonical source_wall_at"
        );
        assert_eq!(device.1, SOURCE_WALL_AT, "reference source_wall_at");
        assert_eq!(
            device.2, SOURCE_WALL_AT,
            "browser_observations_v2.observed_at"
        );
    }

    /// The tables this family writes carry those DEFAULTs today, and are
    /// declared ONLY in `cp::media::init_schema` -- never in `SCHEMA_SQL`. If
    /// either fact drifts, the binding above stops being the fix it claims to
    /// be, silently.
    #[test]
    fn the_capture_tables_still_declare_the_clock_defaults_this_family_binds() {
        let source = include_str!("../../media.rs");
        for (table, expected) in [
            ("capture_sessions", 1),
            ("capture_streams", 1),
            ("capture_events", 1),
            ("browser_states_v2", 1),
            ("browser_observations_v2", 1),
        ] {
            let start = source
                .find(&format!("CREATE TABLE IF NOT EXISTS {table} ("))
                .unwrap_or_else(|| panic!("{table} is declared in cp::media::init_schema"));
            let ddl = &source[start..start + source[start..].find(");").unwrap()];
            assert_eq!(
                ddl.matches("DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))")
                    .count(),
                expected,
                "{table} must still carry the live-clock DEFAULT this family binds"
            );
        }
        let store = include_str!("../../../store.rs");
        for table in [
            "capture_sessions",
            "capture_streams",
            "capture_events",
            "browser_states_v2",
            "browser_observations_v2",
        ] {
            assert!(!store.contains(&format!("CREATE TABLE IF NOT EXISTS {table} (")));
            assert!(!store.contains(&format!("CREATE TABLE {table} (")));
        }
    }

    /// The plan refuses a canonical manifest outright: the two dispositions
    /// have separate families and neither may adopt the other's rows.
    #[test]
    fn a_canonical_manifest_is_refused_before_admission() {
        let error = MediaReferenceEventPlan::new(
            ACCOUNT.to_owned(),
            canonical_manifest(),
            REFERENCE_COMMITTED_AT.to_owned(),
        )
        .err()
        .expect("a canonical manifest must be refused");
        assert_eq!(error, WalIdempotencyError::Malformed);
    }

    /// A stream that already exists under a different session, device or kind
    /// must not silently adopt this event through the writer's
    /// `ON CONFLICT DO NOTHING`.
    #[test]
    fn a_mismatched_existing_stream_binding_is_a_precondition_failure() {
        let mut connection = connection();
        let canonical = canonical_manifest();
        insert_canonical(&connection, &canonical);
        connection
            .execute(
                "UPDATE capture_streams SET device_id='device-other' WHERE id='screen-1'",
                [],
            )
            .unwrap();
        let event = reference_to(&canonical, 1, "screen-event-1");
        assert_eq!(
            settle(&mut connection, plan(event)).unwrap_err(),
            WalIdempotencyError::Precondition
        );
    }

    /// A forced operation id whose stored row was written for a different
    /// request is a fingerprint conflict, never a silent adoption.
    #[test]
    fn a_reused_operation_id_with_a_different_request_conflicts() {
        let mut connection = connection();
        let canonical = canonical_manifest();
        insert_canonical(&connection, &canonical);
        let forced = WalLogicalOperationId::from_bytes([7; 16]).unwrap();
        let first = MediaReferenceEventPlan::with_operation_id(
            forced,
            ACCOUNT.to_owned(),
            reference_to(&canonical, 1, "screen-event-1"),
            REFERENCE_COMMITTED_AT.to_owned(),
        )
        .unwrap();
        settle(&mut connection, first).unwrap();

        let second = MediaReferenceEventPlan::with_operation_id(
            forced,
            ACCOUNT.to_owned(),
            reference_to(&canonical, 2, "screen-event-2"),
            REFERENCE_COMMITTED_AT.to_owned(),
        )
        .unwrap();
        assert_eq!(
            settle(&mut connection, second).unwrap_err(),
            WalIdempotencyError::FingerprintConflict
        );
    }
}
