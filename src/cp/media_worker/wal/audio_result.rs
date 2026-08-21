//! Inactive deterministic audio-window transcript WAL subtype (ADR-0022
//! slice 11, plan B — bound-only; no unbound contract ships).
//!
//! The subtype accepts only a fully leased audio work unit whose provider
//! usage has already reached a terminal result, the sealed sibling B
//! boundary's permanent attempt binding, caller-fixed `sqlite_sequence`
//! pins, one fixed commit time, and transcript turns with no identity
//! evidence. It authenticates every work/member/job/capture/media
//! predecessor before atomically inserting the audio segment, speaker
//! clusters, speaker observations (plus exact source projections), and
//! utterances, settling the exact jobs, media rows, and work unit, and
//! retaining permanent replay. Every written row id derives from the
//! fingerprinted `sqlite_sequence` pins with the plain-INSERT +
//! derived-id-assert discipline. Person, identity, and voice mutation is
//! structurally absent — the plan has no constructor slot for speaker
//! names, person facts, or quality flags, and it never writes
//! `voice_embedding_jobs`. Provider calls, media reads, clocks, automatic
//! IDs, Store, launching, retries, and acknowledgement are deliberately
//! absent.

use rusqlite::{params, types::ValueRef, Connection, OptionalExtension, Row, Transaction};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::archive_v3_wal_idempotency::{
    DomainLedgerBounds, LogicalMutationResult, PreparedLogicalMutation, WalIdempotencyError,
    WalLogicalDomainLedger, WalLogicalDomainPlan, WalLogicalOperationId, WalOperationKind,
    WalReplayResult,
};
use crate::cp::identity::{OWNER_DISPLAY_NAME, UNIDENTIFIED_SPEAKER_LABEL};

const REQUEST_V1: u16 = 1;
const SUBTYPE: &[u8] = b"audio-window-transcript-v1-bound-attempt";
const BOUND_OPERATION_SOURCE_DOMAIN: &[u8] = b"audio-window-transcript-bound-v1\0";
const WORK_DOMAIN: &[u8] = b"archive-v3-audio-window-predecessor-v1\0";
const WORK_ATTEMPT_DOMAIN: &[u8] = b"archive-v3-audio-window-work-attempt-v1\0";
const VERTEX_ATTEMPT_DOMAIN: &[u8] = b"archive-v3-audio-window-vertex-attempt-row-v1\0";
const PROCESSOR_VERSION: i64 = 1;
/// `= media_worker::PROMPT_VERSION` — the audio prompt the owner sends.
const AUDIO_PROMPT_VERSION: i64 = 2;
const RESULT_SCHEMA_VERSION: i64 = 2;
/// The lease scan LIMIT (`media_worker.rs` lease query) — NEVER the
/// 12-frame screen cap; a 5-minute audio window routinely exceeds 12
/// members.
const MAX_AUDIO_MEMBERS: usize = 128;
/// Imported from `media.rs` so the transcript plan can never refuse a turn
/// vector `parse_audio_result` accepted.
const MAX_TURNS: usize = crate::cp::media::MAX_TURNS;
/// CHARS, matching `parse_audio_result`'s `chars().count()` cap — never
/// bytes: a maximal CJK turn is legal at up to ~80 KB of UTF-8.
const MAX_TEXT_CHARS: usize = crate::cp::media::MAX_TEXT_LEN;
/// Keeps the canonical request under the framework's 1 MiB cap.
const MAX_TURN_TOTAL_BYTES: usize = 512 * 1024;
const MAX_ID_BYTES: usize = 128;
const MAX_MODEL_BYTES: usize = 128;
const MAX_TIMESTAMP_BYTES: usize = 64;
const MAX_LANGUAGE_BYTES: usize = 32;
const MAX_CONTEXT_BYTES: usize = 256 * 1024;
const MIN_PROVIDER_ATTEMPT_WINDOW_MILLIS: i64 = 120_000;
const ENCODED_UNIT_RESULT_BYTES: usize = 9;
const SCHEMA_TABLE: &str = "archive_v3_wal_audio_transcript_result_schema";
const LEDGER_TABLE: &str = "archive_v3_wal_audio_transcript_result_operations";
const STATE_TABLE: &str = "archive_v3_wal_audio_transcript_result_state";
const MAX_ROWS: u32 = 1_048_576;
const MAX_RESULT_BYTES: u64 = 32 * 1024 * 1024;
const BOUNDS: DomainLedgerBounds = DomainLedgerBounds::new(MAX_ROWS, MAX_RESULT_BYTES);

type Result<T> = std::result::Result<T, WalIdempotencyError>;

/// The transcript projection of `media::AudioTurn`. The identity fields
/// (`speaker_name*`, `person_facts`, `quality_flags`) have NO constructor
/// slot — the sanctioned person/identity/voice exclusion is structural, at
/// the type.
#[derive(Clone, PartialEq, Eq)]
pub(in crate::cp::media_worker) struct AudioTurnFact {
    turn_id: String,
    start_ms: i64,
    end_ms: i64,
    speaker_local_id: String,
    text: String,
    language: Option<String>,
    overlap: bool,
}

impl std::fmt::Debug for AudioTurnFact {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("AudioTurnFact(<opaque>)")
    }
}

impl AudioTurnFact {
    pub(in crate::cp::media_worker) fn new(
        turn_id: String,
        start_ms: i64,
        end_ms: i64,
        speaker_local_id: String,
        text: String,
        language: Option<String>,
        overlap: bool,
    ) -> Result<Self> {
        validate_turn_id(&turn_id)?;
        validate_turn_id(&speaker_local_id)?;
        if text.is_empty()
            || text.chars().count() > MAX_TEXT_CHARS
            || text.contains('\0')
            || language.as_deref().is_some_and(|language| {
                language.is_empty()
                    || language.len() > MAX_LANGUAGE_BYTES
                    || language.contains('\0')
            })
        {
            return Err(WalIdempotencyError::Malformed);
        }
        Ok(Self {
            turn_id,
            start_ms,
            end_ms,
            speaker_local_id,
            text,
            language,
            overlap,
        })
    }

    fn carried_bytes(&self) -> usize {
        self.turn_id
            .len()
            .saturating_add(self.speaker_local_id.len())
            .saturating_add(self.text.len())
            .saturating_add(self.language.as_deref().map_or(0, str::len))
    }
}

/// The four `sqlite_sequence` pre-state pins, read by the owner's routed
/// pre-submit read and fingerprinted into the plan identity's request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::cp::media_worker) struct AudioSequencePins {
    audio_segments: i64,
    speaker_clusters: i64,
    speaker_observations: i64,
    utterances: i64,
}

impl AudioSequencePins {
    pub(in crate::cp::media_worker) const fn new(
        audio_segments: i64,
        speaker_clusters: i64,
        speaker_observations: i64,
        utterances: i64,
    ) -> Self {
        Self {
            audio_segments,
            speaker_clusters,
            speaker_observations,
            utterances,
        }
    }
}

pub(crate) struct AudioWindowTranscriptPlan {
    operation_id: WalLogicalOperationId,
    account_id: String,
    vertex_event_id: String,
    vertex_attempt_commitment: [u8; 32],
    attempt_binding_commitment: [u8; 32],
    work_unit_id: String,
    predecessor_commitment: [u8; 32],
    requested_model: String,
    committed_at: String,
    seq_pins: AudioSequencePins,
    turns: Vec<AudioTurnFact>,
}

impl std::fmt::Debug for AudioWindowTranscriptPlan {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("AudioWindowTranscriptPlan(<opaque>)")
    }
}

impl Clone for AudioWindowTranscriptPlan {
    fn clone(&self) -> Self {
        Self {
            operation_id: self.operation_id,
            account_id: self.account_id.clone(),
            vertex_event_id: self.vertex_event_id.clone(),
            vertex_attempt_commitment: self.vertex_attempt_commitment,
            attempt_binding_commitment: self.attempt_binding_commitment,
            work_unit_id: self.work_unit_id.clone(),
            predecessor_commitment: self.predecessor_commitment,
            requested_model: self.requested_model.clone(),
            committed_at: self.committed_at.clone(),
            seq_pins: self.seq_pins,
            turns: self.turns.clone(),
        }
    }
}

impl AudioWindowTranscriptPlan {
    #[allow(clippy::too_many_arguments)]
    pub(in crate::cp::media_worker) fn new(
        account_id: String,
        vertex_event_id: String,
        vertex_attempt_commitment: [u8; 32],
        attempt_binding_commitment: [u8; 32],
        work_unit_id: String,
        predecessor_commitment: [u8; 32],
        requested_model: String,
        committed_at: String,
        seq_pins: AudioSequencePins,
        turns: Vec<AudioTurnFact>,
    ) -> Result<Self> {
        crate::store::validate_user_id(&account_id).map_err(|_| WalIdempotencyError::Malformed)?;
        validate_prefixed_hex(&vertex_event_id, "vtx_")?;
        if !valid_lower_hex(&work_unit_id, 64)
            || vertex_attempt_commitment == [0; 32]
            || attempt_binding_commitment == [0; 32]
            || predecessor_commitment == [0; 32]
            || requested_model.is_empty()
            || requested_model.len() > MAX_MODEL_BYTES
            || !super::super::super::vertex_model_name_is_billing_safe(&requested_model)
        {
            return Err(WalIdempotencyError::Malformed);
        }
        validate_canonical_timestamp(&committed_at)?;
        if seq_pins.audio_segments < 0
            || seq_pins.speaker_clusters < 0
            || seq_pins.speaker_observations < 0
            || seq_pins.utterances < 0
        {
            return Err(WalIdempotencyError::Malformed);
        }
        // Turns MAY BE EMPTY: a silent window is a routine, legal capture
        // outcome (`parse_audio_result` has no minimum and the legacy path
        // settles it writing only the segment).
        if turns.len() > MAX_TURNS {
            return Err(WalIdempotencyError::Limit);
        }
        let mut carried_bytes = 0_usize;
        let mut previous_start = i64::MIN;
        for turn in &turns {
            if turn.start_ms < 0 || turn.end_ms <= turn.start_ms || turn.start_ms < previous_start {
                return Err(WalIdempotencyError::Malformed);
            }
            previous_start = turn.start_ms;
            carried_bytes = carried_bytes.saturating_add(turn.carried_bytes());
        }
        if has_duplicate(turns.iter().map(|turn| turn.turn_id.as_str())) {
            return Err(WalIdempotencyError::Malformed);
        }
        if carried_bytes > MAX_TURN_TOTAL_BYTES {
            return Err(WalIdempotencyError::Limit);
        }
        let mut source = Vec::with_capacity(
            BOUND_OPERATION_SOURCE_DOMAIN
                .len()
                .saturating_add(vertex_event_id.len()),
        );
        source.extend_from_slice(BOUND_OPERATION_SOURCE_DOMAIN);
        source.extend_from_slice(vertex_event_id.as_bytes());
        let operation_id = WalLogicalOperationId::from_stable_source(
            WalOperationKind::DeterministicMediaWorkResult,
            &source,
        )?;
        Ok(Self {
            operation_id,
            account_id,
            vertex_event_id,
            vertex_attempt_commitment,
            attempt_binding_commitment,
            work_unit_id,
            predecessor_commitment,
            requested_model,
            committed_at,
            seq_pins,
            turns,
        })
    }
}

pub(crate) struct AudioWindowTranscriptLedger;

impl WalLogicalDomainPlan for AudioWindowTranscriptPlan {
    type Ledger = AudioWindowTranscriptLedger;
    type Output = ();

    fn kind(&self) -> WalOperationKind {
        WalOperationKind::DeterministicMediaWorkResult
    }

    fn operation_id(&self) -> WalLogicalOperationId {
        self.operation_id
    }

    fn canonical_request(&self) -> Result<Zeroizing<Vec<u8>>> {
        let mut request = Zeroizing::new(Vec::with_capacity(64 * 1024));
        request.extend_from_slice(&REQUEST_V1.to_be_bytes());
        encode_bytes(&mut request, SUBTYPE)?;
        request.extend_from_slice(&self.attempt_binding_commitment);
        encode_string(&mut request, &self.account_id)?;
        encode_string(&mut request, &self.vertex_event_id)?;
        request.extend_from_slice(&self.vertex_attempt_commitment);
        encode_string(&mut request, &self.work_unit_id)?;
        request.extend_from_slice(&self.predecessor_commitment);
        encode_string(&mut request, &self.requested_model)?;
        encode_string(&mut request, &self.committed_at)?;
        request.extend_from_slice(&self.seq_pins.audio_segments.to_be_bytes());
        request.extend_from_slice(&self.seq_pins.speaker_clusters.to_be_bytes());
        request.extend_from_slice(&self.seq_pins.speaker_observations.to_be_bytes());
        request.extend_from_slice(&self.seq_pins.utterances.to_be_bytes());
        encode_len(&mut request, self.turns.len())?;
        for turn in &self.turns {
            encode_string(&mut request, &turn.turn_id)?;
            request.extend_from_slice(&turn.start_ms.to_be_bytes());
            request.extend_from_slice(&turn.end_ms.to_be_bytes());
            encode_string(&mut request, &turn.speaker_local_id)?;
            encode_string(&mut request, &turn.text)?;
            match turn.language.as_deref() {
                None => request.push(0x00),
                Some(language) => {
                    request.push(0x01);
                    encode_string(&mut request, language)?;
                }
            }
            request.push(u8::from(turn.overlap));
        }
        Ok(request)
    }

    fn apply(&self, transaction: &Transaction<'_>) -> Result<WalReplayResult> {
        // (1) The terminal Vertex attempt row is exactly the bound one.
        if current_audio_vertex_attempt_commitment(
            transaction,
            &self.vertex_event_id,
            &self.requested_model,
        )? != self.vertex_attempt_commitment
        {
            return Err(WalIdempotencyError::Precondition);
        }
        // (2) The complete terminal-stage leased work predecessor.
        let authenticated = load_audio_work(transaction, &self.work_unit_id)?;
        if authenticated.commitment != self.predecessor_commitment {
            return Err(WalIdempotencyError::Precondition);
        }
        // (3) The permanent sibling-B binding, then the CURRENT stable
        // attempt topology must still be the bound one — a stale plan
        // cannot poison a successor attempt's coordinate.
        let bound_attempt = super::audio_attempt::authenticate_audio_window_attempt_binding(
            transaction,
            &self.account_id,
            &self.vertex_event_id,
            &self.work_unit_id,
            &self.requested_model,
            &self.attempt_binding_commitment,
        )?;
        if hash_audio_work_attempt(transaction, &self.work_unit_id)? != bound_attempt {
            return Err(WalIdempotencyError::Precondition);
        }
        // (4) One fixed commit time, after every predecessor and inside
        // every live lease.
        validate_commit_time(transaction, self, &authenticated)?;
        // (5) The four live sqlite_sequence values are exactly the carried
        // pins.
        if read_audio_sequence_pins(transaction)? != self.seq_pins {
            return Err(WalIdempotencyError::Precondition);
        }
        // (6) The pure projection over authenticated members; the owner ran
        // it pre-submit on the same pinned inputs, so divergence here is an
        // impossible state.
        let projection = project_audio_window(&authenticated.members, &self.turns)
            .map_err(|_| WalIdempotencyError::Corrupt)?;
        // Migration-added target columns must exist; never create them here.
        ensure_target_columns(transaction)?;
        // (7) Every write target is absent (the speaker_observations
        // UNIQUE(event_id,turn_id) trap fails closed HERE, pre-write).
        ensure_audio_targets_absent(transaction, self, &projection)?;
        // (8) The segment row, id derived from the fingerprinted pin.
        write_segment(transaction, self, &projection)?;
        // (9) One cluster per distinct speaker in first-appearance order;
        // explicit created_at/updated_at defeat the strftime DEFAULTs.
        write_clusters(transaction, self, &projection)?;
        // (10)+(11) Observations with exact source projections, then
        // utterances bound to the derived observation ids. The
        // utterances_fts AFTER-INSERT trigger fires on these deterministic
        // rowids in-transaction; trusted, not re-proven.
        write_turns(transaction, self, &projection)?;
        // (12) Full-tuple settle of every member job and media row, in
        // ordinal order.
        for member in &authenticated.members {
            settle_job(transaction, self, member)?;
            settle_media(transaction, member)?;
        }
        // (13) Full-tuple settle of the work unit.
        settle_work(transaction, self, &authenticated.work)?;
        // (14) Exact re-read of every written row and settled tuple.
        verify_final_state(transaction, self, &authenticated, &projection)?;
        Ok(WalReplayResult::unit())
    }

    fn validate_replay(&self, result: &WalReplayResult) -> Result<()> {
        match result {
            WalReplayResult::UnitApplied => Ok(()),
            WalReplayResult::CanonicalResponse(_) => Err(WalIdempotencyError::ResultUnsupported),
        }
    }

    fn decode_output(&self, result: &WalReplayResult) -> Result<Self::Output> {
        self.validate_replay(result)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum LedgerSchemaState {
    Absent,
    Present,
}

impl WalLogicalDomainLedger<AudioWindowTranscriptPlan> for AudioWindowTranscriptLedger {
    fn lookup(
        connection: &Connection,
        prepared: &PreparedLogicalMutation<AudioWindowTranscriptPlan>,
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
                 FROM archive_v3_wal_audio_transcript_result_operations
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
        let kind = WalOperationKind::DeterministicMediaWorkResult;
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
        let plan = prepared.plan_for_domain_ledger();
        let _ = super::audio_attempt::authenticate_audio_window_attempt_binding(
            connection,
            &plan.account_id,
            &plan.vertex_event_id,
            &plan.work_unit_id,
            &plan.requested_model,
            &plan.attempt_binding_commitment,
        )?;
        Ok(Some(result))
    }

    fn resolve_or_apply(
        transaction: &Transaction<'_>,
        prepared: &PreparedLogicalMutation<AudioWindowTranscriptPlan>,
    ) -> Result<LogicalMutationResult> {
        require_kind(prepared)?;
        ensure_schema(transaction)?;
        if let Some(result) = Self::lookup(transaction, prepared)? {
            return Ok(LogicalMutationResult::Replayed(result));
        }
        let (row_count, result_bytes) = load_ledger_state(transaction)?;
        BOUNDS.admit(row_count, result_bytes, ENCODED_UNIT_RESULT_BYTES)?;
        if u64::from(row_count).saturating_mul(4) >= u64::from(MAX_ROWS).saturating_mul(3) {
            tracing::warn!(
                ledger = LEDGER_TABLE,
                row_count,
                "audio transcript result ledger is past three-quarters capacity"
            );
        }
        let kind = WalOperationKind::DeterministicMediaWorkResult;
        let result = prepared.plan_for_domain_ledger().apply(transaction)?;
        prepared.plan_for_domain_ledger().validate_replay(&result)?;
        let encoded = result.encode(kind)?;
        if encoded.len() != ENCODED_UNIT_RESULT_BYTES {
            return Err(WalIdempotencyError::Corrupt);
        }
        let commitment = result.commitment(kind)?;
        transaction
            .execute(
                "INSERT INTO archive_v3_wal_audio_transcript_result_operations
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
        let changed = transaction
            .execute(
                "UPDATE archive_v3_wal_audio_transcript_result_state
                 SET row_count=row_count+1,result_bytes=result_bytes+?1
                 WHERE singleton=1 AND row_count=?2 AND result_bytes=?3",
                params![
                    i64::try_from(encoded.len()).map_err(|_| WalIdempotencyError::Limit)?,
                    i64::from(row_count),
                    i64::try_from(result_bytes).map_err(|_| WalIdempotencyError::Corrupt)?,
                ],
            )
            .map_err(|_| WalIdempotencyError::Unavailable)?;
        if changed != 1 {
            return Err(WalIdempotencyError::Corrupt);
        }
        let Some(stored) = Self::lookup(transaction, prepared)? else {
            return Err(WalIdempotencyError::Corrupt);
        };
        if stored != result {
            return Err(WalIdempotencyError::Corrupt);
        }
        Ok(LogicalMutationResult::Applied(result))
    }
}

#[derive(Clone, PartialEq)]
struct StoredWork {
    work_class: String,
    processor_version: i64,
    state: String,
    started_at: String,
    ended_at: String,
    reserved_output_tokens: i64,
    reservation_retained: i64,
    attempt_count: i64,
    error_code: Option<String>,
    usage_json: Option<String>,
    created_at: String,
    updated_at: String,
}

#[derive(Clone, PartialEq)]
struct StoredJob {
    id: i64,
    event_id: String,
    job_kind: String,
    input_revision: String,
    processor_version: i64,
    state: String,
    attempt_count: i64,
    lease_until: Option<String>,
    error_code: Option<String>,
    model_id: Option<String>,
    prompt_version: Option<i64>,
    schema_version: Option<i64>,
    usage_json: Option<String>,
    updated_at: String,
}

#[derive(Clone, PartialEq)]
struct StoredMedia {
    asset_id: String,
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
    created_at: String,
}

#[derive(Clone, PartialEq)]
struct StoredMember {
    event_id: String,
    job_id: i64,
    ordinal: i64,
    window_start_ms: i64,
    window_end_ms: i64,
    capture_started_at: String,
    capture_ended_at: String,
    stream_kind: String,
    manifest_digest: String,
    context_json: Option<String>,
    media_disposition: String,
    canonical_event_id: Option<String>,
    canonical_asset_id: Option<String>,
    canonical_media_sha256: Option<String>,
    audio_role: Option<String>,
    audio_route: Option<String>,
    route_epoch: Option<i64>,
    job: StoredJob,
    media: StoredMedia,
}

/// Exact authenticated terminal-stage audio work predecessor, as observed
/// by the owner's routed pre-submit read and re-derived inside `apply`.
pub(in crate::cp::media_worker) struct AuthenticatedAudioWork {
    commitment: [u8; 32],
    work: StoredWork,
    members: Vec<StoredMember>,
}

impl std::fmt::Debug for AuthenticatedAudioWork {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("AuthenticatedAudioWork(<opaque>)")
    }
}

impl AuthenticatedAudioWork {
    pub(in crate::cp::media_worker) const fn commitment(&self) -> [u8; 32] {
        self.commitment
    }
}

pub(in crate::cp::media_worker) fn current_audio_vertex_attempt_commitment(
    connection: &Connection,
    event_id: &str,
    expected_model: &str,
) -> Result<[u8; 32]> {
    let mut statement = connection
        .prepare(
            "SELECT event_id,operation,requested_model,returned_model,location,traffic_type,
                    http_status,prompt_tokens,input_text_tokens,input_audio_tokens,
                    input_image_tokens,cached_input_tokens,cached_input_text_tokens,
                    cached_input_audio_tokens,cached_input_image_tokens,output_text_tokens,
                    thought_tokens,total_tokens,outcome,observed_at
             FROM vertex_usage_events WHERE event_id=?1",
        )
        .map_err(|_| WalIdempotencyError::Unavailable)?;
    let column_count = statement.column_count();
    let mut rows = statement
        .query([event_id])
        .map_err(|_| WalIdempotencyError::Unavailable)?;
    let Some(row) = rows.next().map_err(|_| WalIdempotencyError::Unavailable)? else {
        return Err(WalIdempotencyError::Precondition);
    };
    let operation = get_string(row, 1)?;
    let requested_model = get_string(row, 2)?;
    let returned_model = get_optional_string(row, 3)?;
    let location = get_string(row, 4)?;
    let traffic_type = get_string(row, 5)?;
    let http_status = row
        .get::<_, Option<i64>>(6)
        .map_err(|_| WalIdempotencyError::Unavailable)?;
    let outcome = get_string(row, 18)?;
    let observed_at = get_string(row, 19)?;
    if operation != "audio_understanding"
        || requested_model != expected_model
        || !matches!(outcome.as_str(), "metered" | "usage_missing")
        || http_status != Some(200)
        || location.is_empty()
        || location.len() > MAX_ID_BYTES
        || !matches!(
            traffic_type.as_str(),
            "on_demand" | "batch" | "provisioned_throughput"
        )
        || returned_model.as_deref().is_some_and(|model| {
            model.len() > MAX_MODEL_BYTES
                || !super::super::super::vertex_model_name_is_billing_safe(model)
        })
        || (outcome == "metered" && returned_model.is_none())
        || !valid_timestamp(&observed_at)
    {
        return Err(WalIdempotencyError::Precondition);
    }
    for index in 7..=17 {
        if row
            .get::<_, Option<i64>>(index)
            .map_err(|_| WalIdempotencyError::Unavailable)?
            .is_some_and(|value| value < 0)
        {
            return Err(WalIdempotencyError::Precondition);
        }
    }
    let mut hasher = Sha256::new();
    hasher.update(VERTEX_ATTEMPT_DOMAIN);
    for index in 0..column_count {
        hash_value(
            &mut hasher,
            row.get_ref(index)
                .map_err(|_| WalIdempotencyError::Unavailable)?,
        );
    }
    if rows
        .next()
        .map_err(|_| WalIdempotencyError::Unavailable)?
        .is_some()
    {
        return Err(WalIdempotencyError::Corrupt);
    }
    Ok(hasher.finalize().into())
}

/// Exact pre-provider state plus its stable attempt identity. The
/// predecessor covers every authenticated field. The attempt identity
/// excludes only the usage fields and work timestamp that the
/// already-reviewed post-provider usage settlement is expected to replace;
/// lease, counters, membership, inputs, and media provenance remain
/// covered.
pub(in crate::cp::media_worker) struct AudioWorkAttemptCommitments {
    predecessor: [u8; 32],
    attempt: [u8; 32],
}

impl std::fmt::Debug for AudioWorkAttemptCommitments {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("AudioWorkAttemptCommitments(<opaque>)")
    }
}

impl AudioWorkAttemptCommitments {
    pub(in crate::cp::media_worker) const fn predecessor(&self) -> [u8; 32] {
        self.predecessor
    }

    pub(in crate::cp::media_worker) const fn attempt(&self) -> [u8; 32] {
        self.attempt
    }
}

pub(in crate::cp::media_worker) fn current_audio_work_attempt_commitments(
    connection: &Connection,
    work_unit_id: &str,
    attempted_at: &str,
) -> Result<AudioWorkAttemptCommitments> {
    validate_canonical_timestamp(attempted_at)?;
    let (work, members) = load_audio_work_rows(connection, work_unit_id)?;
    validate_audio_work_for_stage(work_unit_id, &work, &members, AudioWorkStage::Reserved)?;
    validate_attempt_time(attempted_at, &work, &members)?;
    Ok(AudioWorkAttemptCommitments {
        predecessor: hash_audio_work(connection, work_unit_id)?,
        attempt: hash_audio_work_attempt(connection, work_unit_id)?,
    })
}

pub(in crate::cp::media_worker) fn load_audio_work(
    connection: &Connection,
    work_unit_id: &str,
) -> Result<AuthenticatedAudioWork> {
    let (work, members) = load_audio_work_rows(connection, work_unit_id)?;
    validate_audio_work_for_stage(work_unit_id, &work, &members, AudioWorkStage::Terminal)?;
    let commitment = hash_audio_work(connection, work_unit_id)?;
    Ok(AuthenticatedAudioWork {
        commitment,
        work,
        members,
    })
}

fn load_audio_work_rows(
    connection: &Connection,
    work_unit_id: &str,
) -> Result<(StoredWork, Vec<StoredMember>)> {
    let work = connection
        .query_row(
            "SELECT work_class,processor_version,state,started_at,ended_at,
                    reserved_output_tokens,reservation_retained,attempt_count,error_code,
                    usage_json,created_at,updated_at
             FROM media_work_units WHERE id=?1",
            [work_unit_id],
            stored_work_from_row,
        )
        .optional()
        .map_err(|_| WalIdempotencyError::Unavailable)?
        .ok_or(WalIdempotencyError::Precondition)?;
    let mut statement = connection
        .prepare(
            "SELECT wm.event_id,wm.job_id,wm.ordinal,wm.window_start_ms,wm.window_end_ms,
                    e.started_at,e.ended_at,e.stream_kind,e.manifest_digest,e.context_json,
                    e.media_disposition,e.canonical_event_id,e.canonical_asset_id,
                    e.canonical_media_sha256,e.audio_role,e.audio_route,e.route_epoch,
                    j.id,j.event_id,j.job_kind,j.input_revision,j.processor_version,j.state,
                    j.attempt_count,j.lease_until,j.error_code,j.model_id,j.prompt_version,
                    j.schema_version,j.usage_json,j.updated_at,
                    m.asset_id,m.event_id,m.object_key,m.object_generation,m.object_backend,
                    m.mime_type,m.codec,m.byte_length,m.sha256,m.sample_rate,m.channels,
                    m.frame_count,m.width,m.height,m.scale,m.orientation,m.processing_state,
                    m.retain_until,m.deleted_at,m.created_at
             FROM media_work_members wm
             JOIN capture_events e ON e.event_id=wm.event_id
             JOIN media_processing_jobs j ON j.id=wm.job_id AND j.event_id=wm.event_id
             JOIN media_objects m ON m.event_id=wm.event_id
             WHERE wm.work_unit_id=?1 ORDER BY wm.ordinal",
        )
        .map_err(|_| WalIdempotencyError::Unavailable)?;
    let members = statement
        .query_map([work_unit_id], stored_member_from_row)
        .map_err(|_| WalIdempotencyError::Unavailable)?
        .collect::<rusqlite::Result<Vec<_>>>()
        .map_err(|_| WalIdempotencyError::Unavailable)?;
    let raw_member_count = connection
        .query_row(
            "SELECT COUNT(*) FROM media_work_members WHERE work_unit_id=?1",
            [work_unit_id],
            |row| row.get::<_, i64>(0),
        )
        .map_err(|_| WalIdempotencyError::Unavailable)?;
    if usize::try_from(raw_member_count).map_err(|_| WalIdempotencyError::Corrupt)? != members.len()
    {
        return Err(WalIdempotencyError::Precondition);
    }
    Ok((work, members))
}

fn stored_work_from_row(row: &Row<'_>) -> rusqlite::Result<StoredWork> {
    Ok(StoredWork {
        work_class: row.get(0)?,
        processor_version: row.get(1)?,
        state: row.get(2)?,
        started_at: row.get(3)?,
        ended_at: row.get(4)?,
        reserved_output_tokens: row.get(5)?,
        reservation_retained: row.get(6)?,
        attempt_count: row.get(7)?,
        error_code: row.get(8)?,
        usage_json: row.get(9)?,
        created_at: row.get(10)?,
        updated_at: row.get(11)?,
    })
}

fn stored_member_from_row(row: &Row<'_>) -> rusqlite::Result<StoredMember> {
    Ok(StoredMember {
        event_id: row.get(0)?,
        job_id: row.get(1)?,
        ordinal: row.get(2)?,
        window_start_ms: row.get(3)?,
        window_end_ms: row.get(4)?,
        capture_started_at: row.get(5)?,
        capture_ended_at: row.get(6)?,
        stream_kind: row.get(7)?,
        manifest_digest: row.get(8)?,
        context_json: row.get(9)?,
        media_disposition: row.get(10)?,
        canonical_event_id: row.get(11)?,
        canonical_asset_id: row.get(12)?,
        canonical_media_sha256: row.get(13)?,
        audio_role: row.get(14)?,
        audio_route: row.get(15)?,
        route_epoch: row.get(16)?,
        job: StoredJob {
            id: row.get(17)?,
            event_id: row.get(18)?,
            job_kind: row.get(19)?,
            input_revision: row.get(20)?,
            processor_version: row.get(21)?,
            state: row.get(22)?,
            attempt_count: row.get(23)?,
            lease_until: row.get(24)?,
            error_code: row.get(25)?,
            model_id: row.get(26)?,
            prompt_version: row.get(27)?,
            schema_version: row.get(28)?,
            usage_json: row.get(29)?,
            updated_at: row.get(30)?,
        },
        media: StoredMedia {
            asset_id: row.get(31)?,
            event_id: row.get(32)?,
            object_key: row.get(33)?,
            object_generation: row.get(34)?,
            object_backend: row.get(35)?,
            mime_type: row.get(36)?,
            codec: row.get(37)?,
            byte_length: row.get(38)?,
            sha256: row.get(39)?,
            sample_rate: row.get(40)?,
            channels: row.get(41)?,
            frame_count: row.get(42)?,
            width: row.get(43)?,
            height: row.get(44)?,
            scale: row.get(45)?,
            orientation: row.get(46)?,
            processing_state: row.get(47)?,
            retain_until: row.get(48)?,
            deleted_at: row.get(49)?,
            created_at: row.get(50)?,
        },
    })
}

#[derive(Clone, Copy)]
enum AudioWorkStage {
    Reserved,
    Terminal,
}

fn validate_audio_work_for_stage(
    work_unit_id: &str,
    work: &StoredWork,
    members: &[StoredMember],
    stage: AudioWorkStage,
) -> Result<()> {
    if work.work_class != "audio"
        || work.processor_version != PROCESSOR_VERSION
        || work.state != "processing"
        // The reserved amount is the audio class constant (4096). The
        // in-function test-shape insert in the legacy persist (reserved
        // 1024, window_start_ms 0) is test scaffolding and must never be
        // accepted here.
        || work.reserved_output_tokens
            != i64::from(super::super::super::vertex::MAX_MEDIA_OUTPUT_TOKENS)
        || work.reservation_retained != 1
        || work.attempt_count <= 0
        || work.error_code.is_some()
        || members.is_empty()
        || members.len() > MAX_AUDIO_MEMBERS
        || !valid_timestamp(&work.started_at)
        || !valid_timestamp(&work.ended_at)
        || !valid_timestamp(&work.created_at)
        || !valid_timestamp(&work.updated_at)
        || timestamp_millis(&work.started_at)? > timestamp_millis(&work.ended_at)?
    {
        return Err(WalIdempotencyError::Precondition);
    }
    let work_start = timestamp_millis(&work.started_at)?;
    let work_end = timestamp_millis(&work.ended_at)?;
    let duration_ms = work_end
        .checked_sub(work_start)
        .ok_or(WalIdempotencyError::Precondition)?;
    if !(1..=super::super::super::media_planner::MAX_AUDIO_WINDOW_MS).contains(&duration_ms) {
        return Err(WalIdempotencyError::Precondition);
    }
    let usage = work
        .usage_json
        .as_deref()
        .ok_or(WalIdempotencyError::Precondition)?;
    match stage {
        AudioWorkStage::Reserved => validate_reserved_usage(usage, work_unit_id, members.len())?,
        AudioWorkStage::Terminal => validate_terminal_usage(usage, work_unit_id, members.len())?,
    }
    for (index, member) in members.iter().enumerate() {
        let ordinal = i64::try_from(index).map_err(|_| WalIdempotencyError::Limit)?;
        if member.ordinal != ordinal
            || member.job_id != member.job.id
            || member.event_id != member.job.event_id
            || member.event_id != member.media.event_id
            || member.job.job_kind != "gemini_audio"
            || member.job.input_revision != member.manifest_digest
            || member.job.processor_version != PROCESSOR_VERSION
            || member.job.state != "processing"
            || member.job.attempt_count <= 0
            || member.job.attempt_count != work.attempt_count
            || member
                .job
                .lease_until
                .as_deref()
                .is_none_or(|value| !valid_timestamp(value))
            || member.job.error_code.is_some()
            || member.job.model_id.is_some()
            || member.job.prompt_version.is_some()
            || member.job.schema_version.is_some()
            || member.job.usage_json.as_deref() != Some(usage)
            || !valid_timestamp(&member.job.updated_at)
            || member.media.asset_id.is_empty()
            || member.media.object_key.is_empty()
            || member.media.byte_length <= 0
            || !valid_lower_hex(&member.media.sha256, 64)
            || !member.media.mime_type.starts_with("audio/")
            || member.media.width.is_some()
            || member.media.height.is_some()
            // The lease/reservation path never guarantees sample_rate or
            // channels; requiring them would wedge a whole window's
            // transcripts behind a Precondition no retry can clear.
            || member.media.sample_rate.is_some_and(|value| value < 0)
            || member.media.channels.is_some_and(|value| value < 0)
            || member.media.processing_state != "processing"
            || member.media.deleted_at.is_some()
            || !valid_timestamp(&member.media.created_at)
            || member
                .media
                .object_generation
                .is_none_or(|value| value <= 0)
            || member.media.object_backend.as_deref() != Some("current")
            || member.media_disposition != "canonical"
            || member.canonical_event_id.is_some()
            || member.canonical_asset_id.is_some()
            || member.canonical_media_sha256.is_some()
            || !valid_timestamp(&member.capture_started_at)
            || !valid_timestamp(&member.capture_ended_at)
            || timestamp_millis(&member.capture_started_at)?
                > timestamp_millis(&member.capture_ended_at)?
            || timestamp_millis(&member.capture_started_at)? < work_start
            || timestamp_millis(&member.capture_ended_at)? > work_end
            || member.window_start_ms < 0
            || member.window_end_ms <= member.window_start_ms
            || member.window_start_ms
                != timestamp_millis(&member.capture_started_at)?
                    .checked_sub(work_start)
                    .ok_or(WalIdempotencyError::Precondition)?
            || member.window_end_ms
                != timestamp_millis(&member.capture_ended_at)?
                    .checked_sub(work_start)
                    .ok_or(WalIdempotencyError::Precondition)?
        {
            return Err(WalIdempotencyError::Precondition);
        }
    }
    Ok(())
}

fn validate_attempt_time(
    attempted_at: &str,
    work: &StoredWork,
    members: &[StoredMember],
) -> Result<()> {
    let attempted = timestamp_millis(attempted_at)?;
    let mut predecessors = vec![
        work.started_at.as_str(),
        work.ended_at.as_str(),
        work.created_at.as_str(),
        work.updated_at.as_str(),
    ];
    for member in members {
        if member
            .job
            .lease_until
            .as_deref()
            .and_then(super::super::super::isotime::parse_epoch_millis)
            .and_then(|lease_until| lease_until.checked_sub(attempted))
            .is_none_or(|remaining| remaining < MIN_PROVIDER_ATTEMPT_WINDOW_MILLIS)
        {
            return Err(WalIdempotencyError::Precondition);
        }
        predecessors.extend([
            member.capture_started_at.as_str(),
            member.capture_ended_at.as_str(),
            member.job.updated_at.as_str(),
            member.media.created_at.as_str(),
        ]);
    }
    if predecessors.into_iter().any(|value| {
        timestamp_millis(value)
            .ok()
            .is_none_or(|millis| millis > attempted)
    }) {
        return Err(WalIdempotencyError::Precondition);
    }
    Ok(())
}

fn validate_commit_time(
    connection: &Connection,
    plan: &AudioWindowTranscriptPlan,
    authenticated: &AuthenticatedAudioWork,
) -> Result<()> {
    let committed = timestamp_millis(&plan.committed_at)?;
    let vertex_observed = connection
        .query_row(
            "SELECT observed_at FROM vertex_usage_events WHERE event_id=?1",
            [&plan.vertex_event_id],
            |row| row.get::<_, String>(0),
        )
        .map_err(|_| WalIdempotencyError::Unavailable)?;
    let mut timestamps = vec![
        vertex_observed.as_str(),
        authenticated.work.started_at.as_str(),
        authenticated.work.ended_at.as_str(),
        authenticated.work.created_at.as_str(),
        authenticated.work.updated_at.as_str(),
    ];
    for member in &authenticated.members {
        if member
            .job
            .lease_until
            .as_deref()
            .and_then(super::super::super::isotime::parse_epoch_millis)
            .is_none_or(|lease_until| lease_until < committed)
        {
            return Err(WalIdempotencyError::Precondition);
        }
        timestamps.extend([
            member.capture_started_at.as_str(),
            member.capture_ended_at.as_str(),
            member.job.updated_at.as_str(),
            member.media.created_at.as_str(),
        ]);
    }
    if timestamps.into_iter().any(|value| {
        timestamp_millis(value)
            .ok()
            .is_none_or(|millis| millis > committed)
    }) {
        return Err(WalIdempotencyError::Precondition);
    }
    Ok(())
}

fn validate_reserved_usage(raw: &str, work_unit_id: &str, member_count: usize) -> Result<()> {
    if raw.len() > MAX_CONTEXT_BYTES || raw.contains('\0') {
        return Err(WalIdempotencyError::Precondition);
    }
    let value: serde_json::Value =
        serde_json::from_str(raw).map_err(|_| WalIdempotencyError::Precondition)?;
    let Some(object) = value.as_object() else {
        return Err(WalIdempotencyError::Precondition);
    };
    if object.len() != 6
        || value
            .get("work_unit_id")
            .and_then(serde_json::Value::as_str)
            != Some(work_unit_id)
        || value.get("work_class").and_then(serde_json::Value::as_str) != Some("audio")
        || value
            .get("member_count")
            .and_then(serde_json::Value::as_u64)
            != u64::try_from(member_count).ok()
        || value
            .get("reservation_state")
            .and_then(serde_json::Value::as_str)
            != Some("reserved")
        || value
            .get("reserved_output_tokens")
            .and_then(serde_json::Value::as_i64)
            != Some(i64::from(
                super::super::super::vertex::MAX_MEDIA_OUTPUT_TOKENS,
            ))
        || value
            .get("processor_version")
            .and_then(serde_json::Value::as_i64)
            != Some(PROCESSOR_VERSION)
    {
        return Err(WalIdempotencyError::Precondition);
    }
    Ok(())
}

fn validate_terminal_usage(raw: &str, work_unit_id: &str, member_count: usize) -> Result<()> {
    if raw.len() > MAX_CONTEXT_BYTES || raw.contains('\0') {
        return Err(WalIdempotencyError::Precondition);
    }
    let value: serde_json::Value =
        serde_json::from_str(raw).map_err(|_| WalIdempotencyError::Precondition)?;
    if value
        .get("work_unit_id")
        .and_then(serde_json::Value::as_str)
        != Some(work_unit_id)
        || value.get("work_class").and_then(serde_json::Value::as_str) != Some("audio")
        || value
            .get("member_count")
            .and_then(serde_json::Value::as_u64)
            != u64::try_from(member_count).ok()
        || value
            .get("reservation_state")
            .and_then(serde_json::Value::as_str)
            != Some("reserved")
        || value
            .get("processor_version")
            .and_then(serde_json::Value::as_i64)
            != Some(PROCESSOR_VERSION)
        || value.get("outcome").and_then(serde_json::Value::as_str) != Some("model_returned")
    {
        return Err(WalIdempotencyError::Precondition);
    }
    Ok(())
}

fn hash_audio_work(connection: &Connection, work_unit_id: &str) -> Result<[u8; 32]> {
    let mut hasher = Sha256::new();
    hasher.update(WORK_DOMAIN);
    for (marker, query) in [
        (
            b"work".as_slice(),
            "SELECT id,work_class,processor_version,state,started_at,ended_at,
                    reserved_output_tokens,reservation_retained,attempt_count,error_code,
                    usage_json,created_at,updated_at
             FROM media_work_units WHERE id=?1 ORDER BY id",
        ),
        (
            b"members".as_slice(),
            "SELECT work_unit_id,event_id,job_id,ordinal,window_start_ms,window_end_ms
             FROM media_work_members WHERE work_unit_id=?1 ORDER BY ordinal",
        ),
        (
            b"jobs".as_slice(),
            "SELECT j.id,j.event_id,j.job_kind,j.input_revision,j.processor_version,j.state,
                    j.attempt_count,j.lease_until,j.error_code,j.model_id,j.prompt_version,
                    j.schema_version,j.usage_json,j.updated_at
             FROM media_processing_jobs j JOIN media_work_members m ON m.job_id=j.id
             WHERE m.work_unit_id=?1 ORDER BY m.ordinal",
        ),
        (
            b"capture-events".as_slice(),
            "SELECT e.event_id,e.device_id,e.install_id,e.capture_session_id,e.stream_id,
                    e.stream_kind,e.sequence,e.source_wall_at,e.source_monotonic_ns,e.started_at,
                    e.ended_at,e.timezone_id,e.utc_offset_minutes,e.clock_uncertainty_ms,
                    e.asset_id,e.manifest_digest,e.context_json,e.media_disposition,
                    e.canonical_event_id,e.canonical_asset_id,e.canonical_media_sha256,
                    e.perceptual_hash,e.hamming_distance,e.pixel_change_ratio,
                    e.context_fingerprint,e.dedupe_version,e.received_at,
                    e.audio_role,e.audio_route,e.route_epoch
             FROM capture_events e JOIN media_work_members m ON m.event_id=e.event_id
             WHERE m.work_unit_id=?1 ORDER BY m.ordinal",
        ),
        (
            b"media".as_slice(),
            "SELECT o.asset_id,o.event_id,o.object_key,o.object_generation,o.object_backend,
                    o.mime_type,o.codec,o.byte_length,o.sha256,o.sample_rate,o.channels,
                    o.frame_count,o.width,o.height,o.scale,o.orientation,o.processing_state,
                    o.retain_until,o.deleted_at,o.created_at
             FROM media_objects o JOIN media_work_members m ON m.event_id=o.event_id
             WHERE m.work_unit_id=?1 ORDER BY m.ordinal",
        ),
    ] {
        hash_query(connection, &mut hasher, marker, query, work_unit_id)?;
    }
    Ok(hasher.finalize().into())
}

fn hash_audio_work_attempt(connection: &Connection, work_unit_id: &str) -> Result<[u8; 32]> {
    let mut hasher = Sha256::new();
    hasher.update(WORK_ATTEMPT_DOMAIN);
    for (marker, query) in [
        (
            b"work".as_slice(),
            "SELECT id,work_class,processor_version,state,started_at,ended_at,
                    reserved_output_tokens,reservation_retained,attempt_count,error_code,created_at
             FROM media_work_units WHERE id=?1 ORDER BY id",
        ),
        (
            b"members".as_slice(),
            "SELECT work_unit_id,event_id,job_id,ordinal,window_start_ms,window_end_ms
             FROM media_work_members WHERE work_unit_id=?1 ORDER BY ordinal",
        ),
        (
            b"jobs".as_slice(),
            "SELECT j.id,j.event_id,j.job_kind,j.input_revision,j.processor_version,j.state,
                    j.attempt_count,j.lease_until,j.error_code,j.model_id,j.prompt_version,
                    j.schema_version,j.updated_at
             FROM media_processing_jobs j JOIN media_work_members m ON m.job_id=j.id
             WHERE m.work_unit_id=?1 ORDER BY m.ordinal",
        ),
        (
            b"capture-events".as_slice(),
            "SELECT e.event_id,e.device_id,e.install_id,e.capture_session_id,e.stream_id,
                    e.stream_kind,e.sequence,e.source_wall_at,e.source_monotonic_ns,e.started_at,
                    e.ended_at,e.timezone_id,e.utc_offset_minutes,e.clock_uncertainty_ms,
                    e.asset_id,e.manifest_digest,e.context_json,e.media_disposition,
                    e.canonical_event_id,e.canonical_asset_id,e.canonical_media_sha256,
                    e.perceptual_hash,e.hamming_distance,e.pixel_change_ratio,
                    e.context_fingerprint,e.dedupe_version,e.received_at,
                    e.audio_role,e.audio_route,e.route_epoch
             FROM capture_events e JOIN media_work_members m ON m.event_id=e.event_id
             WHERE m.work_unit_id=?1 ORDER BY m.ordinal",
        ),
        (
            b"media".as_slice(),
            "SELECT o.asset_id,o.event_id,o.object_key,o.object_generation,o.object_backend,
                    o.mime_type,o.codec,o.byte_length,o.sha256,o.sample_rate,o.channels,
                    o.frame_count,o.width,o.height,o.scale,o.orientation,o.processing_state,
                    o.retain_until,o.deleted_at,o.created_at
             FROM media_objects o JOIN media_work_members m ON m.event_id=o.event_id
             WHERE m.work_unit_id=?1 ORDER BY m.ordinal",
        ),
    ] {
        hash_query(connection, &mut hasher, marker, query, work_unit_id)?;
    }
    Ok(hasher.finalize().into())
}

fn hash_query(
    connection: &Connection,
    hasher: &mut Sha256,
    marker: &[u8],
    query: &str,
    work_unit_id: &str,
) -> Result<()> {
    hasher.update((marker.len() as u64).to_be_bytes());
    hasher.update(marker);
    let mut statement = connection
        .prepare(query)
        .map_err(|_| WalIdempotencyError::Unavailable)?;
    let column_count = statement.column_count();
    let mut rows = statement
        .query([work_unit_id])
        .map_err(|_| WalIdempotencyError::Unavailable)?;
    let mut count = 0_u64;
    while let Some(row) = rows.next().map_err(|_| WalIdempotencyError::Unavailable)? {
        count = count.checked_add(1).ok_or(WalIdempotencyError::Limit)?;
        hasher.update([0x52]);
        for index in 0..column_count {
            hash_value(
                hasher,
                row.get_ref(index)
                    .map_err(|_| WalIdempotencyError::Unavailable)?,
            );
        }
    }
    hasher.update([0xff]);
    hasher.update(count.to_be_bytes());
    Ok(())
}

fn hash_value(hasher: &mut Sha256, value: ValueRef<'_>) {
    match value {
        ValueRef::Null => hasher.update([0]),
        ValueRef::Integer(value) => {
            hasher.update([1]);
            hasher.update(value.to_be_bytes());
        }
        ValueRef::Real(value) => {
            hasher.update([2]);
            hasher.update(value.to_bits().to_be_bytes());
        }
        ValueRef::Text(value) => {
            hasher.update([3]);
            hasher.update((value.len() as u64).to_be_bytes());
            hasher.update(value);
        }
        ValueRef::Blob(value) => {
            hasher.update([4]);
            hasher.update((value.len() as u64).to_be_bytes());
            hasher.update(value);
        }
    }
}

/// The four `sqlite_sequence` pre-state pins (COALESCE 0 when a table has
/// never allocated), in the fixed segments/clusters/observations/utterances
/// order.
pub(in crate::cp::media_worker) fn read_audio_sequence_pins(
    connection: &Connection,
) -> Result<AudioSequencePins> {
    let mut pins = [0_i64; 4];
    for (slot, table) in [
        "audio_segments",
        "speaker_clusters",
        "speaker_observations",
        "utterances",
    ]
    .iter()
    .enumerate()
    {
        pins[slot] = connection
            .query_row(
                "SELECT COALESCE((SELECT seq FROM sqlite_sequence WHERE name=?1),0)",
                [table],
                |row| row.get(0),
            )
            .map_err(|_| WalIdempotencyError::Unavailable)?;
    }
    Ok(AudioSequencePins {
        audio_segments: pins[0],
        speaker_clusters: pins[1],
        speaker_observations: pins[2],
        utterances: pins[3],
    })
}

struct ClusterProjection {
    speaker_local_id: String,
    attribution_state: &'static str,
}

struct ProjectedTurn {
    started_at: String,
    ended_at: String,
    anchor_event_id: String,
    cluster_index: usize,
    label: &'static str,
    source_key: String,
    intervals: Vec<super::super::super::media_planner::ProjectedInterval>,
}

struct AudioWindowProjection {
    window_started_at: String,
    window_ended_at: String,
    duration_ms: i64,
    source_type: &'static str,
    clusters: Vec<ClusterProjection>,
    turns: Vec<ProjectedTurn>,
}

/// PURE window/turn projection (no connection): run by the owner pre-submit
/// and by `apply` on authenticated members; divergence at apply is an
/// impossible state. Zero turns → zero clusters/observations/utterances;
/// the projection still validates the window and returns the segment
/// fields.
fn project_audio_window(
    members: &[StoredMember],
    turns: &[AudioTurnFact],
) -> Result<AudioWindowProjection> {
    let first = members.first().ok_or(WalIdempotencyError::Malformed)?;
    let window_start = timestamp_millis(&first.capture_started_at)?;
    let mut window_end = timestamp_millis(&first.capture_ended_at)?;
    let mut window_ended_at = first.capture_ended_at.clone();
    for member in members {
        // Ordinal 0 must be the earliest member; both hold under the lease's
        // started_at ordering.
        if timestamp_millis(&member.capture_started_at)? < window_start {
            return Err(WalIdempotencyError::Malformed);
        }
        let ended = timestamp_millis(&member.capture_ended_at)?;
        if ended > window_end {
            window_end = ended;
            window_ended_at = member.capture_ended_at.clone();
        }
    }
    let duration_ms = window_end
        .checked_sub(window_start)
        .ok_or(WalIdempotencyError::Malformed)?;
    if !(1..=super::super::super::media_planner::MAX_AUDIO_WINDOW_MS).contains(&duration_ms) {
        return Err(WalIdempotencyError::Malformed);
    }
    let sources = members
        .iter()
        .map(|member| {
            Ok(super::super::super::media_planner::SourceInterval::new(
                &member.event_id,
                timestamp_millis(&member.capture_started_at)?
                    .checked_sub(window_start)
                    .ok_or(WalIdempotencyError::Malformed)?,
                timestamp_millis(&member.capture_ended_at)?
                    .checked_sub(window_start)
                    .ok_or(WalIdempotencyError::Malformed)?,
            ))
        })
        .collect::<Result<Vec<_>>>()?;
    let mut clusters: Vec<ClusterProjection> = Vec::new();
    let mut cluster_indexes = Vec::with_capacity(turns.len());
    for turn in turns {
        let index = clusters
            .iter()
            .position(|cluster| cluster.speaker_local_id == turn.speaker_local_id);
        let index = match index {
            Some(index) => index,
            None => {
                clusters.push(ClusterProjection {
                    speaker_local_id: turn.speaker_local_id.clone(),
                    attribution_state: "request_local",
                });
                clusters.len() - 1
            }
        };
        cluster_indexes.push(index);
    }
    // The exact legacy predicate on the ordinal-0 member: local_transmit
    // capture with a single distinct voice presents as the owner.
    let attribution_state = if first.audio_role.as_deref() == Some("local_transmit")
        || first.stream_kind == "local_transmit"
    {
        if clusters.len() <= 1 {
            "owner_transmit"
        } else {
            "request_local"
        }
    } else {
        "request_local"
    };
    for cluster in &mut clusters {
        cluster.attribution_state = attribution_state;
    }
    let mut projected_turns = Vec::with_capacity(turns.len());
    for (turn, cluster_index) in turns.iter().zip(cluster_indexes) {
        if turn.end_ms > duration_ms {
            return Err(WalIdempotencyError::Malformed);
        }
        let intervals = super::super::super::media_planner::project_interval(
            &sources,
            turn.start_ms,
            turn.end_ms,
        );
        let anchor_event_id = intervals
            .first()
            .map(|interval| interval.event_id.clone())
            .ok_or(WalIdempotencyError::Malformed)?;
        // Only tiers 3 and 5 of resolve_speaker_attribution can fire on this
        // lane (no direct evidence, no voice rows, no episode, no profile),
        // so the label closed form is exactly owner-or-unidentified.
        let label = if clusters[cluster_index].attribution_state == "owner_transmit" {
            OWNER_DISPLAY_NAME
        } else {
            UNIDENTIFIED_SPEAKER_LABEL
        };
        projected_turns.push(ProjectedTurn {
            started_at: super::super::super::isotime::add_seconds(
                &first.capture_started_at,
                turn.start_ms as f64 / 1000.0,
            ),
            ended_at: super::super::super::isotime::add_seconds(
                &first.capture_started_at,
                turn.end_ms as f64 / 1000.0,
            ),
            source_key: format!("cloud-v2:{}:{}", anchor_event_id, turn.turn_id),
            anchor_event_id,
            cluster_index,
            label,
            intervals,
        });
    }
    Ok(AudioWindowProjection {
        window_started_at: first.capture_started_at.clone(),
        window_ended_at,
        duration_ms,
        source_type: if first.stream_kind == "system_audio" {
            "system"
        } else {
            "mic"
        },
        clusters,
        turns: projected_turns,
    })
}

/// Owner-facing pre-submit projection check: any failure surfaces as
/// `Malformed` (the owner maps it into the invalid-model-output ladder).
pub(in crate::cp::media_worker) fn project_audio_window_for_owner(
    work: &AuthenticatedAudioWork,
    turns: &[AudioTurnFact],
) -> Result<()> {
    project_audio_window(&work.members, turns).map(|_| ())
}

/// Owner-facing, read-only projection TARGETS: the exact
/// `(speaker_observations.event_id, turn_id)` pairs `apply` would insert.
///
/// Strictly additive — it runs the same pure projection as the check above and
/// touches no identity, codec, canonical request, ledger or mutation. It
/// exists so the owner's `transcript_target_conflict` pre-check cannot
/// disagree with the rows this sealed `apply` would write: a
/// `UNIQUE(event_id,turn_id)` violation inside `apply` surfaces as an opaque
/// `Unavailable` that is indistinguishable from a transient failure, and the
/// window would then fail closed permanently.
pub(in crate::cp::media_worker) fn project_audio_window_targets_for_owner(
    work: &AuthenticatedAudioWork,
    turns: &[AudioTurnFact],
) -> Result<Vec<(String, String)>> {
    let projection = project_audio_window(&work.members, turns)?;
    Ok(projection
        .turns
        .iter()
        .zip(turns)
        .map(|(projected, turn)| (projected.anchor_event_id.clone(), turn.turn_id.clone()))
        .collect())
}

/// The migration-added target columns must already exist; on a stale
/// archive this plan is Unavailable and NEVER creates schema.
fn ensure_target_columns(transaction: &Transaction<'_>) -> Result<()> {
    for (table, column) in [
        ("speaker_observations", "cluster_id"),
        ("utterances", "speaker_observation_id"),
    ] {
        let present = transaction
            .query_row(
                "SELECT COUNT(*) FROM pragma_table_info(?1) WHERE name=?2",
                params![table, column],
                |row| row.get::<_, i64>(0),
            )
            .map_err(|_| WalIdempotencyError::Unavailable)?;
        if present != 1 {
            return Err(WalIdempotencyError::Unavailable);
        }
    }
    Ok(())
}

fn ensure_audio_targets_absent(
    transaction: &Transaction<'_>,
    plan: &AudioWindowTranscriptPlan,
    projection: &AudioWindowProjection,
) -> Result<()> {
    let occupied = |count: i64| -> Result<()> {
        if count != 0 {
            return Err(WalIdempotencyError::Precondition);
        }
        Ok(())
    };
    occupied(
        transaction
            .query_row(
                "SELECT COUNT(*) FROM audio_segments WHERE id=?1",
                [plan.seq_pins.audio_segments + 1],
                |row| row.get(0),
            )
            .map_err(|_| WalIdempotencyError::Unavailable)?,
    )?;
    occupied(
        transaction
            .query_row(
                "SELECT COUNT(*) FROM speaker_clusters WHERE work_unit_id=?1",
                [&plan.work_unit_id],
                |row| row.get(0),
            )
            .map_err(|_| WalIdempotencyError::Unavailable)?,
    )?;
    for (index, cluster) in projection.clusters.iter().enumerate() {
        let cluster_id = plan
            .seq_pins
            .speaker_clusters
            .checked_add(1)
            .and_then(|base| base.checked_add(i64::try_from(index).ok()?))
            .ok_or(WalIdempotencyError::Limit)?;
        occupied(
            transaction
                .query_row(
                    "SELECT COUNT(*) FROM speaker_clusters
                     WHERE id=?1 OR (work_unit_id=?2 AND speaker_local_id=?3)",
                    params![cluster_id, plan.work_unit_id, cluster.speaker_local_id],
                    |row| row.get(0),
                )
                .map_err(|_| WalIdempotencyError::Unavailable)?,
        )?;
    }
    for (index, (turn, projected)) in plan.turns.iter().zip(&projection.turns).enumerate() {
        let observation_id = plan
            .seq_pins
            .speaker_observations
            .checked_add(1)
            .and_then(|base| base.checked_add(i64::try_from(index).ok()?))
            .ok_or(WalIdempotencyError::Limit)?;
        let utterance_id = plan
            .seq_pins
            .utterances
            .checked_add(1)
            .and_then(|base| base.checked_add(i64::try_from(index).ok()?))
            .ok_or(WalIdempotencyError::Limit)?;
        occupied(
            transaction
                .query_row(
                    "SELECT COUNT(*) FROM speaker_observations
                     WHERE id=?1 OR (event_id=?2 AND turn_id=?3)",
                    params![observation_id, projected.anchor_event_id, turn.turn_id],
                    |row| row.get(0),
                )
                .map_err(|_| WalIdempotencyError::Unavailable)?,
        )?;
        occupied(
            transaction
                .query_row(
                    "SELECT COUNT(*) FROM utterances WHERE id=?1 OR source_key=?2",
                    params![utterance_id, projected.source_key],
                    |row| row.get(0),
                )
                .map_err(|_| WalIdempotencyError::Unavailable)?,
        )?;
    }
    Ok(())
}

fn write_segment(
    transaction: &Transaction<'_>,
    plan: &AudioWindowTranscriptPlan,
    projection: &AudioWindowProjection,
) -> Result<()> {
    let changed = transaction
        .execute(
            // created_at is explicit for the same reason write_clusters does it:
            // the baseline declares a strftime DEFAULT (store.rs:5975), and a
            // clock inside apply would break byte-exact replay.
            "INSERT INTO audio_segments
             (started_at,ended_at,duration_seconds,source_type,audio_format,
              transcription_status,created_at)
             VALUES (?1,?2,?3,?4,'audio/wav','done',?5)",
            params![
                projection.window_started_at,
                projection.window_ended_at,
                projection.duration_ms as f64 / 1000.0,
                projection.source_type,
                plan.committed_at,
            ],
        )
        .map_err(|_| WalIdempotencyError::Unavailable)?;
    if changed != 1 || transaction.last_insert_rowid() != plan.seq_pins.audio_segments + 1 {
        return Err(WalIdempotencyError::Corrupt);
    }
    Ok(())
}

fn write_clusters(
    transaction: &Transaction<'_>,
    plan: &AudioWindowTranscriptPlan,
    projection: &AudioWindowProjection,
) -> Result<()> {
    for (index, cluster) in projection.clusters.iter().enumerate() {
        let expected_id = plan
            .seq_pins
            .speaker_clusters
            .checked_add(1)
            .and_then(|base| base.checked_add(i64::try_from(index).ok()?))
            .ok_or(WalIdempotencyError::Limit)?;
        let changed = transaction
            .execute(
                "INSERT INTO speaker_clusters
                 (work_unit_id,speaker_local_id,attribution_state,created_at,updated_at)
                 VALUES (?1,?2,?3,?4,?4)",
                params![
                    plan.work_unit_id,
                    cluster.speaker_local_id,
                    cluster.attribution_state,
                    plan.committed_at,
                ],
            )
            .map_err(|_| WalIdempotencyError::Unavailable)?;
        if changed != 1 || transaction.last_insert_rowid() != expected_id {
            return Err(WalIdempotencyError::Corrupt);
        }
    }
    Ok(())
}

fn write_turns(
    transaction: &Transaction<'_>,
    plan: &AudioWindowTranscriptPlan,
    projection: &AudioWindowProjection,
) -> Result<()> {
    for (index, (turn, projected)) in plan.turns.iter().zip(&projection.turns).enumerate() {
        let offset = i64::try_from(index).map_err(|_| WalIdempotencyError::Limit)?;
        let observation_id = plan
            .seq_pins
            .speaker_observations
            .checked_add(1)
            .and_then(|base| base.checked_add(offset))
            .ok_or(WalIdempotencyError::Limit)?;
        let cluster_id = plan
            .seq_pins
            .speaker_clusters
            .checked_add(1)
            .and_then(|base| base.checked_add(i64::try_from(projected.cluster_index).ok()?))
            .ok_or(WalIdempotencyError::Limit)?;
        let changed = transaction
            .execute(
                "INSERT INTO speaker_observations
                 (event_id,turn_id,speaker_local_id,started_at,ended_at,transcript_text,
                  language,overlap,cluster_id)
                 VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9)",
                params![
                    projected.anchor_event_id,
                    turn.turn_id,
                    turn.speaker_local_id,
                    projected.started_at,
                    projected.ended_at,
                    turn.text,
                    turn.language,
                    i64::from(turn.overlap),
                    cluster_id,
                ],
            )
            .map_err(|_| WalIdempotencyError::Unavailable)?;
        if changed != 1 || transaction.last_insert_rowid() != observation_id {
            return Err(WalIdempotencyError::Corrupt);
        }
        for interval in &projected.intervals {
            let changed = transaction
                .execute(
                    "INSERT INTO speaker_observation_sources
                     (speaker_observation_id,event_id,window_start_ms,window_end_ms,
                      event_start_ms,event_end_ms)
                     VALUES (?1,?2,?3,?4,?5,?6)",
                    params![
                        observation_id,
                        interval.event_id,
                        interval.window_start_ms,
                        interval.window_end_ms,
                        interval.event_start_ms,
                        interval.event_end_ms,
                    ],
                )
                .map_err(|_| WalIdempotencyError::Unavailable)?;
            if changed != 1 {
                return Err(WalIdempotencyError::Corrupt);
            }
        }
        let utterance_id = plan
            .seq_pins
            .utterances
            .checked_add(1)
            .and_then(|base| base.checked_add(offset))
            .ok_or(WalIdempotencyError::Limit)?;
        let changed = transaction
            .execute(
                "INSERT INTO utterances
                 (audio_segment_id,start_offset_seconds,end_offset_seconds,text,language,
                  confidence,speaker_label,source_key,speaker_observation_id,created_at)
                 VALUES (?1,?2,?3,?4,?5,NULL,?6,?7,?8,?9)",
                params![
                    plan.seq_pins.audio_segments + 1,
                    turn.start_ms as f64 / 1000.0,
                    turn.end_ms as f64 / 1000.0,
                    turn.text,
                    turn.language,
                    projected.label,
                    projected.source_key,
                    observation_id,
                    plan.committed_at,
                ],
            )
            .map_err(|_| WalIdempotencyError::Unavailable)?;
        if changed != 1 || transaction.last_insert_rowid() != utterance_id {
            return Err(WalIdempotencyError::Corrupt);
        }
    }
    Ok(())
}

fn settle_job(
    transaction: &Transaction<'_>,
    plan: &AudioWindowTranscriptPlan,
    member: &StoredMember,
) -> Result<()> {
    let job = &member.job;
    // model_id records the plan's requested_model — a documented divergence
    // from the legacy mark_succeeded's hard-coded "gemini-3.5-flash".
    let changed = transaction
        .execute(
            "UPDATE media_processing_jobs
             SET state='succeeded',lease_until=NULL,error_code=NULL,model_id=?1,
                 prompt_version=?2,schema_version=?3,updated_at=?4
             WHERE id=?5 AND event_id=?6 AND job_kind=?7 AND input_revision=?8
               AND processor_version=?9 AND state=?10 AND attempt_count=?11
               AND lease_until IS ?12 AND error_code IS ?13 AND model_id IS ?14
               AND prompt_version IS ?15 AND schema_version IS ?16
               AND usage_json IS ?17 AND updated_at=?18",
            params![
                plan.requested_model,
                AUDIO_PROMPT_VERSION,
                RESULT_SCHEMA_VERSION,
                plan.committed_at,
                job.id,
                job.event_id,
                job.job_kind,
                job.input_revision,
                job.processor_version,
                job.state,
                job.attempt_count,
                job.lease_until,
                job.error_code,
                job.model_id,
                job.prompt_version,
                job.schema_version,
                job.usage_json,
                job.updated_at,
            ],
        )
        .map_err(|_| WalIdempotencyError::Unavailable)?;
    if changed != 1 {
        return Err(WalIdempotencyError::Corrupt);
    }
    Ok(())
}

fn settle_media(transaction: &Transaction<'_>, member: &StoredMember) -> Result<()> {
    let media = &member.media;
    let changed = transaction
        .execute(
            "UPDATE media_objects SET processing_state='ready'
             WHERE asset_id=?1 AND event_id=?2 AND object_key=?3
               AND object_generation IS ?4 AND object_backend IS ?5 AND mime_type=?6
               AND codec=?7 AND byte_length=?8 AND sha256=?9 AND sample_rate IS ?10
               AND channels IS ?11 AND frame_count IS ?12 AND width IS ?13 AND height IS ?14
               AND scale IS ?15 AND orientation IS ?16 AND processing_state=?17
               AND retain_until IS ?18 AND deleted_at IS ?19 AND created_at=?20",
            params![
                media.asset_id,
                media.event_id,
                media.object_key,
                media.object_generation,
                media.object_backend,
                media.mime_type,
                media.codec,
                media.byte_length,
                media.sha256,
                media.sample_rate,
                media.channels,
                media.frame_count,
                media.width,
                media.height,
                media.scale,
                media.orientation,
                media.processing_state,
                media.retain_until,
                media.deleted_at,
                media.created_at,
            ],
        )
        .map_err(|_| WalIdempotencyError::Unavailable)?;
    if changed != 1 {
        return Err(WalIdempotencyError::Corrupt);
    }
    Ok(())
}

fn settle_work(
    transaction: &Transaction<'_>,
    plan: &AudioWindowTranscriptPlan,
    work: &StoredWork,
) -> Result<()> {
    let changed = transaction
        .execute(
            "UPDATE media_work_units SET state='succeeded',error_code=NULL,updated_at=?1
             WHERE id=?2 AND work_class=?3 AND processor_version=?4 AND state=?5
               AND started_at=?6 AND ended_at=?7 AND reserved_output_tokens=?8
               AND reservation_retained=?9 AND attempt_count=?10 AND error_code IS ?11
               AND usage_json IS ?12 AND created_at=?13 AND updated_at=?14",
            params![
                plan.committed_at,
                plan.work_unit_id,
                work.work_class,
                work.processor_version,
                work.state,
                work.started_at,
                work.ended_at,
                work.reserved_output_tokens,
                work.reservation_retained,
                work.attempt_count,
                work.error_code,
                work.usage_json,
                work.created_at,
                work.updated_at,
            ],
        )
        .map_err(|_| WalIdempotencyError::Unavailable)?;
    if changed != 1 {
        return Err(WalIdempotencyError::Corrupt);
    }
    Ok(())
}

#[allow(clippy::too_many_lines)]
fn verify_final_state(
    transaction: &Transaction<'_>,
    plan: &AudioWindowTranscriptPlan,
    authenticated: &AuthenticatedAudioWork,
    projection: &AudioWindowProjection,
) -> Result<()> {
    let segment_id = plan.seq_pins.audio_segments + 1;
    let segment = transaction
        .query_row(
            "SELECT started_at,ended_at,duration_seconds,source_type,audio_format,
                    transcription_status
             FROM audio_segments WHERE id=?1",
            [segment_id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, f64>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, Option<String>>(4)?,
                    row.get::<_, Option<String>>(5)?,
                ))
            },
        )
        .map_err(|_| WalIdempotencyError::Corrupt)?;
    if segment
        != (
            projection.window_started_at.clone(),
            projection.window_ended_at.clone(),
            projection.duration_ms as f64 / 1000.0,
            projection.source_type.to_owned(),
            Some("audio/wav".to_owned()),
            Some("done".to_owned()),
        )
    {
        return Err(WalIdempotencyError::Corrupt);
    }
    for (index, cluster) in projection.clusters.iter().enumerate() {
        let cluster_id = plan
            .seq_pins
            .speaker_clusters
            .checked_add(1)
            .and_then(|base| base.checked_add(i64::try_from(index).ok()?))
            .ok_or(WalIdempotencyError::Limit)?;
        let stored = transaction
            .query_row(
                "SELECT work_unit_id,speaker_local_id,voice_profile_id,person_id,
                        attribution_state,created_at,updated_at
                 FROM speaker_clusters WHERE id=?1",
                [cluster_id],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, Option<i64>>(2)?,
                        row.get::<_, Option<i64>>(3)?,
                        row.get::<_, String>(4)?,
                        row.get::<_, String>(5)?,
                        row.get::<_, String>(6)?,
                    ))
                },
            )
            .map_err(|_| WalIdempotencyError::Corrupt)?;
        if stored
            != (
                plan.work_unit_id.clone(),
                cluster.speaker_local_id.clone(),
                None,
                None,
                cluster.attribution_state.to_owned(),
                plan.committed_at.clone(),
                plan.committed_at.clone(),
            )
        {
            return Err(WalIdempotencyError::Corrupt);
        }
    }
    for (index, (turn, projected)) in plan.turns.iter().zip(&projection.turns).enumerate() {
        let offset = i64::try_from(index).map_err(|_| WalIdempotencyError::Limit)?;
        let observation_id = plan
            .seq_pins
            .speaker_observations
            .checked_add(1)
            .and_then(|base| base.checked_add(offset))
            .ok_or(WalIdempotencyError::Limit)?;
        let cluster_id = plan
            .seq_pins
            .speaker_clusters
            .checked_add(1)
            .and_then(|base| base.checked_add(i64::try_from(projected.cluster_index).ok()?))
            .ok_or(WalIdempotencyError::Limit)?;
        let observation = transaction
            .query_row(
                "SELECT person_id,event_id,turn_id,speaker_local_id,started_at,ended_at,
                        transcript_text,language,overlap,cluster_id
                 FROM speaker_observations WHERE id=?1",
                [observation_id],
                |row| {
                    Ok((
                        row.get::<_, Option<i64>>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, String>(4)?,
                        row.get::<_, String>(5)?,
                        row.get::<_, String>(6)?,
                        row.get::<_, Option<String>>(7)?,
                        row.get::<_, i64>(8)?,
                        row.get::<_, Option<i64>>(9)?,
                    ))
                },
            )
            .map_err(|_| WalIdempotencyError::Corrupt)?;
        if observation
            != (
                None,
                projected.anchor_event_id.clone(),
                turn.turn_id.clone(),
                turn.speaker_local_id.clone(),
                projected.started_at.clone(),
                projected.ended_at.clone(),
                turn.text.clone(),
                turn.language.clone(),
                i64::from(turn.overlap),
                Some(cluster_id),
            )
        {
            return Err(WalIdempotencyError::Corrupt);
        }
        let source_count = transaction
            .query_row(
                "SELECT COUNT(*) FROM speaker_observation_sources WHERE speaker_observation_id=?1",
                [observation_id],
                |row| row.get::<_, i64>(0),
            )
            .map_err(|_| WalIdempotencyError::Corrupt)?;
        if usize::try_from(source_count).map_err(|_| WalIdempotencyError::Corrupt)?
            != projected.intervals.len()
        {
            return Err(WalIdempotencyError::Corrupt);
        }
        for interval in &projected.intervals {
            let exact = transaction
                .query_row(
                    "SELECT COUNT(*) FROM speaker_observation_sources
                     WHERE speaker_observation_id=?1 AND event_id=?2 AND window_start_ms=?3
                       AND window_end_ms=?4 AND event_start_ms=?5 AND event_end_ms=?6",
                    params![
                        observation_id,
                        interval.event_id,
                        interval.window_start_ms,
                        interval.window_end_ms,
                        interval.event_start_ms,
                        interval.event_end_ms,
                    ],
                    |row| row.get::<_, i64>(0),
                )
                .map_err(|_| WalIdempotencyError::Corrupt)?;
            if exact != 1 {
                return Err(WalIdempotencyError::Corrupt);
            }
        }
        let utterance_id = plan
            .seq_pins
            .utterances
            .checked_add(1)
            .and_then(|base| base.checked_add(offset))
            .ok_or(WalIdempotencyError::Limit)?;
        let utterance = transaction
            .query_row(
                "SELECT audio_segment_id,start_offset_seconds,end_offset_seconds,text,language,
                        confidence,speaker_label,source_key,speaker_observation_id
                 FROM utterances WHERE id=?1",
                [utterance_id],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, Option<f64>>(1)?,
                        row.get::<_, Option<f64>>(2)?,
                        row.get::<_, Option<String>>(3)?,
                        row.get::<_, Option<String>>(4)?,
                        row.get::<_, Option<f64>>(5)?,
                        row.get::<_, Option<String>>(6)?,
                        row.get::<_, Option<String>>(7)?,
                        row.get::<_, Option<i64>>(8)?,
                    ))
                },
            )
            .map_err(|_| WalIdempotencyError::Corrupt)?;
        if utterance
            != (
                segment_id,
                Some(turn.start_ms as f64 / 1000.0),
                Some(turn.end_ms as f64 / 1000.0),
                Some(turn.text.clone()),
                turn.language.clone(),
                None,
                Some(projected.label.to_owned()),
                Some(projected.source_key.clone()),
                Some(observation_id),
            )
        {
            return Err(WalIdempotencyError::Corrupt);
        }
    }
    for member in &authenticated.members {
        let job = load_job(transaction, member.job.id)?;
        let mut expected_job = member.job.clone();
        expected_job.state = "succeeded".into();
        expected_job.lease_until = None;
        expected_job.error_code = None;
        expected_job.model_id = Some(plan.requested_model.clone());
        expected_job.prompt_version = Some(AUDIO_PROMPT_VERSION);
        expected_job.schema_version = Some(RESULT_SCHEMA_VERSION);
        expected_job.updated_at = plan.committed_at.clone();
        if job != expected_job {
            return Err(WalIdempotencyError::Corrupt);
        }
        let mut expected_media = member.media.clone();
        expected_media.processing_state = "ready".into();
        if load_media(transaction, &member.media.asset_id)? != expected_media {
            return Err(WalIdempotencyError::Corrupt);
        }
    }
    let work = transaction
        .query_row(
            "SELECT work_class,processor_version,state,started_at,ended_at,
                    reserved_output_tokens,reservation_retained,attempt_count,error_code,
                    usage_json,created_at,updated_at
             FROM media_work_units WHERE id=?1",
            [&plan.work_unit_id],
            stored_work_from_row,
        )
        .map_err(|_| WalIdempotencyError::Corrupt)?;
    let mut expected_work = authenticated.work.clone();
    expected_work.state = "succeeded".into();
    expected_work.error_code = None;
    expected_work.updated_at = plan.committed_at.clone();
    if work != expected_work {
        return Err(WalIdempotencyError::Corrupt);
    }
    let turn_count = i64::try_from(plan.turns.len()).map_err(|_| WalIdempotencyError::Limit)?;
    let cluster_count =
        i64::try_from(projection.clusters.len()).map_err(|_| WalIdempotencyError::Limit)?;
    let utterance_count = transaction
        .query_row(
            "SELECT COUNT(*) FROM utterances WHERE audio_segment_id=?1",
            [segment_id],
            |row| row.get::<_, i64>(0),
        )
        .map_err(|_| WalIdempotencyError::Corrupt)?;
    let observation_count = transaction
        .query_row(
            "SELECT COUNT(*) FROM speaker_observations WHERE id>?1",
            [plan.seq_pins.speaker_observations],
            |row| row.get::<_, i64>(0),
        )
        .map_err(|_| WalIdempotencyError::Corrupt)?;
    let stored_cluster_count = transaction
        .query_row(
            "SELECT COUNT(*) FROM speaker_clusters WHERE work_unit_id=?1",
            [&plan.work_unit_id],
            |row| row.get::<_, i64>(0),
        )
        .map_err(|_| WalIdempotencyError::Corrupt)?;
    if utterance_count != turn_count
        || observation_count != turn_count
        || stored_cluster_count != cluster_count
    {
        return Err(WalIdempotencyError::Corrupt);
    }
    // Every sqlite_sequence advanced by exactly its insert count (for zero
    // turns: only the segment, deltas 1/0/0/0).
    let expected = AudioSequencePins {
        audio_segments: plan.seq_pins.audio_segments + 1,
        speaker_clusters: plan
            .seq_pins
            .speaker_clusters
            .checked_add(cluster_count)
            .ok_or(WalIdempotencyError::Limit)?,
        speaker_observations: plan
            .seq_pins
            .speaker_observations
            .checked_add(turn_count)
            .ok_or(WalIdempotencyError::Limit)?,
        utterances: plan
            .seq_pins
            .utterances
            .checked_add(turn_count)
            .ok_or(WalIdempotencyError::Limit)?,
    };
    if read_audio_sequence_pins(transaction)? != expected {
        return Err(WalIdempotencyError::Corrupt);
    }
    Ok(())
}

fn load_media(connection: &Connection, asset_id: &str) -> Result<StoredMedia> {
    connection
        .query_row(
            "SELECT asset_id,event_id,object_key,object_generation,object_backend,mime_type,
                    codec,byte_length,sha256,sample_rate,channels,frame_count,width,height,
                    scale,orientation,processing_state,retain_until,deleted_at,created_at
             FROM media_objects WHERE asset_id=?1",
            [asset_id],
            |row| {
                Ok(StoredMedia {
                    asset_id: row.get(0)?,
                    event_id: row.get(1)?,
                    object_key: row.get(2)?,
                    object_generation: row.get(3)?,
                    object_backend: row.get(4)?,
                    mime_type: row.get(5)?,
                    codec: row.get(6)?,
                    byte_length: row.get(7)?,
                    sha256: row.get(8)?,
                    sample_rate: row.get(9)?,
                    channels: row.get(10)?,
                    frame_count: row.get(11)?,
                    width: row.get(12)?,
                    height: row.get(13)?,
                    scale: row.get(14)?,
                    orientation: row.get(15)?,
                    processing_state: row.get(16)?,
                    retain_until: row.get(17)?,
                    deleted_at: row.get(18)?,
                    created_at: row.get(19)?,
                })
            },
        )
        .map_err(|_| WalIdempotencyError::Corrupt)
}

fn load_job(connection: &Connection, id: i64) -> Result<StoredJob> {
    connection
        .query_row(
            "SELECT id,event_id,job_kind,input_revision,processor_version,state,attempt_count,
                    lease_until,error_code,model_id,prompt_version,schema_version,usage_json,updated_at
             FROM media_processing_jobs WHERE id=?1",
            [id],
            |row| {
                Ok(StoredJob {
                    id: row.get(0)?,
                    event_id: row.get(1)?,
                    job_kind: row.get(2)?,
                    input_revision: row.get(3)?,
                    processor_version: row.get(4)?,
                    state: row.get(5)?,
                    attempt_count: row.get(6)?,
                    lease_until: row.get(7)?,
                    error_code: row.get(8)?,
                    model_id: row.get(9)?,
                    prompt_version: row.get(10)?,
                    schema_version: row.get(11)?,
                    usage_json: row.get(12)?,
                    updated_at: row.get(13)?,
                })
            },
        )
        .map_err(|_| WalIdempotencyError::Corrupt)
}

fn require_kind(prepared: &PreparedLogicalMutation<AudioWindowTranscriptPlan>) -> Result<()> {
    (prepared.kind_for_owner() == WalOperationKind::DeterministicMediaWorkResult)
        .then_some(())
        .ok_or(WalIdempotencyError::ResultUnsupported)
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
                    "CREATE TABLE archive_v3_wal_audio_transcript_result_schema (
                        singleton INTEGER PRIMARY KEY CHECK(singleton=1),
                        format_version INTEGER NOT NULL CHECK(format_version=1),
                        codec_version INTEGER NOT NULL CHECK(codec_version=1)
                     ) STRICT;
                     CREATE TABLE archive_v3_wal_audio_transcript_result_operations (
                        operation_id BLOB PRIMARY KEY NOT NULL,
                        format_version INTEGER NOT NULL CHECK(format_version=1),
                        codec_version INTEGER NOT NULL CHECK(codec_version=1),
                        request_fingerprint BLOB NOT NULL,
                        result_bytes BLOB NOT NULL,
                        result_commitment BLOB NOT NULL,
                        CHECK(length(operation_id)=16 AND operation_id<>zeroblob(16)),
                        CHECK(length(request_fingerprint)=32 AND request_fingerprint<>zeroblob(32)),
                        CHECK(length(result_bytes)=9),
                        CHECK(length(result_commitment)=32 AND result_commitment<>zeroblob(32))
                     ) STRICT, WITHOUT ROWID;
                     CREATE TABLE archive_v3_wal_audio_transcript_result_state (
                        singleton INTEGER PRIMARY KEY CHECK(singleton=1),
                        row_count INTEGER NOT NULL CHECK(row_count BETWEEN 0 AND 1048576),
                        result_bytes INTEGER NOT NULL CHECK(result_bytes BETWEEN 0 AND 33554432)
                     ) STRICT;
                     INSERT INTO archive_v3_wal_audio_transcript_result_schema
                        (singleton,format_version,codec_version) VALUES (1,1,1);
                     INSERT INTO archive_v3_wal_audio_transcript_result_state
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
             FROM archive_v3_wal_audio_transcript_result_schema WHERE singleton=1",
            [],
            |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)),
        )
        .optional()
        .map_err(|_| WalIdempotencyError::Corrupt)?;
    if marker
        != Some((
            i64::from(WalOperationKind::format_version()),
            i64::from(WalOperationKind::DeterministicMediaWorkResult.codec_version()),
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
             FROM archive_v3_wal_audio_transcript_result_state WHERE singleton=1",
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

fn get_string(row: &Row<'_>, index: usize) -> Result<String> {
    row.get(index).map_err(|_| WalIdempotencyError::Unavailable)
}

fn get_optional_string(row: &Row<'_>, index: usize) -> Result<Option<String>> {
    row.get(index).map_err(|_| WalIdempotencyError::Unavailable)
}

/// The `media.rs` `validate_id` charset (alphanumeric plus `-` and `_`),
/// bounded by the shared 128-byte id cap.
fn validate_turn_id(value: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > MAX_ID_BYTES
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err(WalIdempotencyError::Malformed);
    }
    Ok(())
}

fn validate_prefixed_hex(value: &str, prefix: &str) -> Result<()> {
    let Some(suffix) = value.strip_prefix(prefix) else {
        return Err(WalIdempotencyError::Malformed);
    };
    if value.len() > MAX_ID_BYTES || !valid_lower_hex(suffix, 64) {
        return Err(WalIdempotencyError::Malformed);
    }
    Ok(())
}

fn valid_lower_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn has_duplicate<T: Ord>(values: impl Iterator<Item = T>) -> bool {
    let mut values = values.collect::<Vec<_>>();
    values.sort_unstable();
    values.windows(2).any(|pair| pair[0] == pair[1])
}

fn valid_timestamp(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_TIMESTAMP_BYTES
        && !value.contains('\0')
        && super::super::super::isotime::parse_epoch_millis(value).is_some()
}

fn timestamp_millis(value: &str) -> Result<i64> {
    super::super::super::isotime::parse_epoch_millis(value).ok_or(WalIdempotencyError::Malformed)
}

fn validate_canonical_timestamp(value: &str) -> Result<()> {
    let millis = timestamp_millis(value)?;
    if value.len() > MAX_TIMESTAMP_BYTES
        || value.contains('\0')
        || super::super::super::isotime::format_epoch_millis(millis) != value
    {
        return Err(WalIdempotencyError::Malformed);
    }
    Ok(())
}

fn encode_len(output: &mut Vec<u8>, length: usize) -> Result<()> {
    output.extend_from_slice(
        &u32::try_from(length)
            .map_err(|_| WalIdempotencyError::Limit)?
            .to_be_bytes(),
    );
    Ok(())
}

fn encode_bytes(output: &mut Vec<u8>, value: &[u8]) -> Result<()> {
    if value.is_empty() {
        return Err(WalIdempotencyError::Malformed);
    }
    encode_len(output, value.len())?;
    output.extend_from_slice(value);
    Ok(())
}

fn encode_string(output: &mut Vec<u8>, value: &str) -> Result<()> {
    encode_bytes(output, value.as_bytes())
}

#[cfg(test)]
pub(super) mod tests {
    use super::*;
    use crate::archive_v3_wal_idempotency::{
        execute_prepared_for_owner, ExecutedLogicalMutation, LogicalMutationDisposition,
    };
    use tempfile::tempdir;

    pub(in crate::cp::media_worker::wal) const ACCOUNT: &str =
        "11111111-1111-4111-8111-111111111111";
    pub(in crate::cp::media_worker::wal) const WORK_ONE: &str =
        "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
    pub(in crate::cp::media_worker::wal) const WORK_TWO: &str =
        "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";
    pub(in crate::cp::media_worker::wal) const MODEL: &str = "gemini-3.5-flash";
    pub(in crate::cp::media_worker::wal) const STARTED_AT: &str = "2026-08-15T15:00:00.000Z";
    pub(in crate::cp::media_worker::wal) const CREATED_AT: &str = "2026-08-15T14:59:59.000Z";
    pub(in crate::cp::media_worker::wal) const UPDATED_AT: &str = "2026-08-15T15:00:02.000Z";
    pub(in crate::cp::media_worker::wal) const LEASE_UNTIL: &str = "2026-08-15T15:05:00.000Z";

    pub(in crate::cp::media_worker::wal) fn attempted_at(count: usize) -> String {
        super::super::super::super::isotime::add_seconds(STARTED_AT, count as f64 + 2.0)
    }

    pub(in crate::cp::media_worker::wal) fn committed_at(count: usize) -> String {
        super::super::super::super::isotime::add_seconds(STARTED_AT, count as f64 + 3.0)
    }

    fn member_sha(base: i64, index: usize) -> String {
        format!("{:064x}", 0xa0_000 + base * 1_000 + index as i64)
    }

    /// Minimal audio fixture under the DESIGN-ASSUMED DDL: all four
    /// transcript tables AUTOINCREMENT (the `media.rs` declarations). T24
    /// separately checks the design assumption against the production
    /// baseline schema — and finds it broken there.
    pub(in crate::cp::media_worker::wal) fn install_schema(connection: &Connection) {
        connection
            .execute_batch(
                "PRAGMA foreign_keys=ON;
                 CREATE TABLE vertex_usage_events (
                    event_id TEXT PRIMARY KEY,operation TEXT NOT NULL,requested_model TEXT NOT NULL,
                    returned_model TEXT,location TEXT NOT NULL,traffic_type TEXT NOT NULL,
                    http_status INTEGER,prompt_tokens INTEGER,input_text_tokens INTEGER,
                    input_audio_tokens INTEGER,input_image_tokens INTEGER,cached_input_tokens INTEGER,
                    cached_input_text_tokens INTEGER,cached_input_audio_tokens INTEGER,
                    cached_input_image_tokens INTEGER,output_text_tokens INTEGER,thought_tokens INTEGER,
                    total_tokens INTEGER,outcome TEXT NOT NULL,delivery_state TEXT NOT NULL,
                    delivery_attempt_count INTEGER NOT NULL,observed_at TEXT NOT NULL,updated_at TEXT NOT NULL
                 ) STRICT;
                 CREATE TABLE vertex_usage_coverage (
                    period TEXT PRIMARY KEY,
                    sequence INTEGER NOT NULL,
                    pending_events INTEGER NOT NULL,
                    lost_events INTEGER NOT NULL,
                    delivery_state TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                 ) STRICT;
                 CREATE TABLE capture_events (
                    event_id TEXT PRIMARY KEY,device_id TEXT NOT NULL,install_id TEXT NOT NULL,
                    capture_session_id TEXT NOT NULL,stream_id TEXT NOT NULL,stream_kind TEXT NOT NULL,
                    sequence INTEGER NOT NULL,source_wall_at TEXT NOT NULL,source_monotonic_ns TEXT NOT NULL,
                    started_at TEXT NOT NULL,ended_at TEXT NOT NULL,timezone_id TEXT NOT NULL,
                    utc_offset_minutes INTEGER NOT NULL,clock_uncertainty_ms INTEGER NOT NULL,
                    asset_id TEXT NOT NULL,manifest_digest TEXT NOT NULL,context_json TEXT,
                    media_disposition TEXT NOT NULL,canonical_event_id TEXT,canonical_asset_id TEXT,
                    canonical_media_sha256 TEXT,perceptual_hash TEXT,hamming_distance INTEGER,
                    pixel_change_ratio REAL,context_fingerprint TEXT,dedupe_version INTEGER,
                    audio_role TEXT,audio_route TEXT,route_epoch INTEGER,
                    received_at TEXT NOT NULL
                 ) STRICT;
                 CREATE TABLE media_objects (
                    asset_id TEXT PRIMARY KEY,event_id TEXT NOT NULL UNIQUE,object_key TEXT NOT NULL,
                    object_generation INTEGER,object_backend TEXT,mime_type TEXT NOT NULL,codec TEXT NOT NULL,
                    byte_length INTEGER NOT NULL,sha256 TEXT NOT NULL,sample_rate INTEGER,channels INTEGER,
                    frame_count INTEGER,width INTEGER,height INTEGER,scale REAL,orientation TEXT,
                    processing_state TEXT NOT NULL,retain_until TEXT,deleted_at TEXT,created_at TEXT NOT NULL
                 ) STRICT;
                 CREATE TABLE media_processing_jobs (
                    id INTEGER PRIMARY KEY,event_id TEXT NOT NULL,job_kind TEXT NOT NULL,
                    input_revision TEXT NOT NULL,processor_version INTEGER NOT NULL,state TEXT NOT NULL,
                    attempt_count INTEGER NOT NULL,lease_until TEXT,error_code TEXT,model_id TEXT,
                    prompt_version INTEGER,schema_version INTEGER,usage_json TEXT,updated_at TEXT NOT NULL
                 ) STRICT;
                 CREATE TABLE media_work_units (
                    id TEXT PRIMARY KEY,work_class TEXT NOT NULL,processor_version INTEGER NOT NULL,
                    state TEXT NOT NULL,started_at TEXT NOT NULL,ended_at TEXT NOT NULL,
                    reserved_output_tokens INTEGER NOT NULL,reservation_retained INTEGER NOT NULL,
                    attempt_count INTEGER NOT NULL,error_code TEXT,usage_json TEXT,
                    created_at TEXT NOT NULL,updated_at TEXT NOT NULL
                 ) STRICT;
                 CREATE TABLE media_work_members (
                    work_unit_id TEXT NOT NULL,event_id TEXT NOT NULL,job_id INTEGER NOT NULL,
                    ordinal INTEGER NOT NULL,window_start_ms INTEGER NOT NULL,window_end_ms INTEGER NOT NULL,
                    PRIMARY KEY(work_unit_id,event_id),UNIQUE(work_unit_id,ordinal)
                 ) STRICT;
                 CREATE TABLE audio_segments (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    started_at TEXT NOT NULL,
                    ended_at TEXT NOT NULL,
                    duration_seconds REAL NOT NULL,
                    source_type TEXT NOT NULL,
                    audio_format TEXT,
                    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
                    transcription_status TEXT
                 );
                 CREATE TABLE speaker_clusters (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    work_unit_id TEXT NOT NULL,
                    speaker_local_id TEXT NOT NULL,
                    voice_profile_id INTEGER,
                    person_id INTEGER,
                    attribution_state TEXT NOT NULL CHECK (attribution_state IN ('owner_transmit','person_bound','anonymous_profile','request_local','unsegmented')),
                    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
                    updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
                    UNIQUE(work_unit_id, speaker_local_id)
                 );
                 CREATE TABLE speaker_observations (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    person_id INTEGER,
                    event_id TEXT NOT NULL,
                    turn_id TEXT NOT NULL,
                    speaker_local_id TEXT NOT NULL,
                    started_at TEXT NOT NULL,
                    ended_at TEXT NOT NULL,
                    transcript_text TEXT NOT NULL,
                    language TEXT,
                    overlap INTEGER NOT NULL DEFAULT 0,
                    voice_eligibility TEXT,
                    voice_diagnostics_json TEXT,
                    direct_evidence_id INTEGER,
                    cluster_id INTEGER,
                    UNIQUE(event_id, turn_id)
                 );
                 CREATE TABLE speaker_observation_sources (
                    speaker_observation_id INTEGER NOT NULL,
                    event_id TEXT NOT NULL,
                    window_start_ms INTEGER NOT NULL,
                    window_end_ms INTEGER NOT NULL,
                    event_start_ms INTEGER NOT NULL,
                    event_end_ms INTEGER NOT NULL,
                    PRIMARY KEY (speaker_observation_id,event_id,window_start_ms)
                 );
                 CREATE TABLE utterances (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    audio_segment_id INTEGER NOT NULL,
                    start_offset_seconds REAL,
                    end_offset_seconds REAL,
                    text TEXT,
                    language TEXT,
                    confidence REAL,
                    speaker_label TEXT,
                    source_key TEXT,
                    speaker_observation_id INTEGER,
                    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
                 );",
            )
            .unwrap();
    }

    /// The identity/voice/episode tables the legacy reconcile/recalculate
    /// helpers and the E1/E2 red-line assertions touch, in their
    /// production shapes, plus the utterances FTS index and triggers.
    fn install_identity_schema(connection: &Connection) {
        connection
            .execute_batch(
                "CREATE TABLE people (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    display_name TEXT,
                    normalized_name TEXT,
                    status TEXT NOT NULL DEFAULT 'unknown'
                 );
                 CREATE TABLE person_name_claims (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    person_id INTEGER,
                    name TEXT NOT NULL,
                    normalized_name TEXT NOT NULL,
                    source_event_id TEXT,
                    speaker_observation_id INTEGER,
                    observed_at TEXT NOT NULL,
                    evidence_kind TEXT NOT NULL,
                    evidence_json TEXT NOT NULL,
                    confidence REAL NOT NULL,
                    status TEXT NOT NULL
                 );
                 CREATE TABLE identity_evidence (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    person_id INTEGER,
                    source_event_id TEXT,
                    observed_at TEXT,
                    speaker_observation_id INTEGER,
                    kind TEXT,
                    claimed_name TEXT,
                    evidence_json TEXT,
                    score REAL,
                    status TEXT
                 );
                 CREATE TABLE person_facts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    person_id INTEGER,
                    predicate TEXT,
                    value TEXT,
                    status TEXT,
                    evidence_json TEXT,
                    source_event_id TEXT,
                    speaker_observation_id INTEGER
                 );
                 CREATE TABLE voice_profiles (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    person_id INTEGER,
                    label TEXT,
                    status TEXT NOT NULL DEFAULT 'tentative'
                 );
                 CREATE TABLE voice_samples (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    speaker_observation_id INTEGER NOT NULL,
                    voice_profile_id INTEGER,
                    accepted INTEGER NOT NULL DEFAULT 0,
                    outlier INTEGER NOT NULL DEFAULT 0
                 );
                 CREATE TABLE voice_sample_profile_assignments (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    sample_id INTEGER NOT NULL,
                    profile_id INTEGER NOT NULL,
                    active INTEGER NOT NULL DEFAULT 0
                 );
                 CREATE TABLE voice_profile_revisions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    profile_id INTEGER NOT NULL
                 );
                 CREATE TABLE voice_profile_representatives (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    profile_id INTEGER NOT NULL
                 );
                 CREATE TABLE profile_identity_bindings (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    voice_profile_id INTEGER NOT NULL,
                    person_id INTEGER NOT NULL,
                    active INTEGER NOT NULL DEFAULT 0,
                    state TEXT NOT NULL DEFAULT 'probationary'
                 );
                 CREATE TABLE voice_embedding_jobs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    speaker_observation_id INTEGER NOT NULL,
                    embedding_space TEXT NOT NULL,
                    processor_version INTEGER NOT NULL DEFAULT 1,
                    quality_version INTEGER NOT NULL DEFAULT 1,
                    scorer_version INTEGER NOT NULL DEFAULT 2,
                    state TEXT NOT NULL,
                    updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
                    UNIQUE(speaker_observation_id, embedding_space, processor_version, quality_version, scorer_version)
                 );
                 CREATE TABLE episodes (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    started_at TEXT,
                    ended_at TEXT,
                    speaker_processing_status TEXT NOT NULL DEFAULT 'ready',
                    updated_at TEXT
                 );
                 CREATE TABLE episode_members (
                    episode_id INTEGER NOT NULL,
                    record_id INTEGER NOT NULL,
                    record_type TEXT NOT NULL,
                    PRIMARY KEY (episode_id, record_type, record_id)
                 );
                 CREATE TABLE episode_speaker_slots (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    episode_id INTEGER NOT NULL,
                    voice_profile_id INTEGER,
                    speaker_cluster_id INTEGER,
                    slot_ordinal INTEGER NOT NULL,
                    status TEXT NOT NULL DEFAULT 'active'
                 );
                 CREATE VIRTUAL TABLE utterances_fts
                    USING fts5(text, content='utterances', content_rowid='id');
                 CREATE TRIGGER utterances_insert_fts AFTER INSERT ON utterances BEGIN
                    INSERT INTO utterances_fts(rowid, text) VALUES (new.id, new.text);
                 END;
                 CREATE TRIGGER utterances_delete_fts AFTER DELETE ON utterances BEGIN
                    INSERT INTO utterances_fts(utterances_fts, rowid, text) VALUES ('delete', old.id, old.text);
                 END;
                 CREATE TRIGGER utterances_update_fts AFTER UPDATE OF text ON utterances BEGIN
                    INSERT INTO utterances_fts(utterances_fts, rowid, text) VALUES ('delete', old.id, old.text);
                    INSERT INTO utterances_fts(rowid, text) VALUES (new.id, new.text);
                 END;",
            )
            .unwrap();
    }

    pub(in crate::cp::media_worker::wal) fn connection() -> Connection {
        let connection = Connection::open_in_memory().unwrap();
        install_schema(&connection);
        connection
    }

    fn identity_connection() -> Connection {
        let connection = connection();
        install_identity_schema(&connection);
        connection
    }

    pub(in crate::cp::media_worker::wal) fn reserved_usage(work: &str, count: usize) -> String {
        serde_json::json!({
            "work_unit_id": work,
            "work_class": "audio",
            "member_count": count,
            "reservation_state": "reserved",
            "reserved_output_tokens": 4096,
            "processor_version": 1,
        })
        .to_string()
    }

    fn terminal_usage(work: &str, count: usize) -> String {
        serde_json::json!({
            "work_unit_id": work,
            "work_class": "audio",
            "member_count": count,
            "reservation_state": "reserved",
            "reserved_output_tokens": 4096,
            "processor_version": 1,
            "outcome": "model_returned"
        })
        .to_string()
    }

    /// One reserved leased audio work unit whose members tile
    /// `[STARTED_AT, STARTED_AT + count s)` in one-second capture events.
    pub(in crate::cp::media_worker::wal) fn seed_reserved_audio_work_shaped(
        connection: &Connection,
        work: &str,
        base: i64,
        count: usize,
        stream_kind: &str,
        audio_role: Option<&str>,
    ) {
        let usage = reserved_usage(work, count);
        let ended_at = super::super::super::super::isotime::add_seconds(STARTED_AT, count as f64);
        connection
            .execute(
                "INSERT INTO media_work_units
                 (id,work_class,processor_version,state,started_at,ended_at,reserved_output_tokens,
                  reservation_retained,attempt_count,error_code,usage_json,created_at,updated_at)
                 VALUES (?1,'audio',1,'processing',?2,?3,4096,1,1,NULL,?4,?5,?6)",
                params![work, STARTED_AT, ended_at, usage, CREATED_AT, UPDATED_AT],
            )
            .unwrap();
        for index in 0..count {
            let number = base + i64::try_from(index).unwrap();
            let event = format!("audio-event-{number}");
            let asset = format!("audio-asset-{number}");
            let sha = member_sha(base, index);
            let capture_started =
                super::super::super::super::isotime::add_seconds(STARTED_AT, index as f64);
            let capture_ended =
                super::super::super::super::isotime::add_seconds(STARTED_AT, index as f64 + 1.0);
            connection
                .execute(
                    "INSERT INTO capture_events
                     (event_id,device_id,install_id,capture_session_id,stream_id,stream_kind,sequence,
                      source_wall_at,source_monotonic_ns,started_at,ended_at,timezone_id,
                      utc_offset_minutes,clock_uncertainty_ms,asset_id,manifest_digest,context_json,
                      media_disposition,canonical_event_id,canonical_asset_id,canonical_media_sha256,
                      perceptual_hash,hamming_distance,pixel_change_ratio,context_fingerprint,
                      dedupe_version,audio_role,audio_route,route_epoch,received_at)
                     VALUES (?1,'device','install','session','stream',?2,?3,?4,'1',?4,?5,
                             'America/New_York',-240,1,?6,?7,NULL,'canonical',NULL,NULL,NULL,
                             NULL,NULL,NULL,NULL,NULL,?8,'builtin_mic',1,?9)",
                    params![
                        event,
                        stream_kind,
                        number,
                        capture_started,
                        capture_ended,
                        asset,
                        sha,
                        audio_role,
                        CREATED_AT,
                    ],
                )
                .unwrap();
            connection
                .execute(
                    "INSERT INTO media_objects
                     (asset_id,event_id,object_key,object_generation,object_backend,mime_type,codec,
                      byte_length,sha256,sample_rate,channels,frame_count,width,height,scale,
                      orientation,processing_state,retain_until,deleted_at,created_at)
                     VALUES (?1,?2,?3,7,'current','audio/mp4','aac',1000,?4,NULL,NULL,NULL,
                             NULL,NULL,NULL,NULL,'processing',?5,NULL,?6)",
                    params![
                        asset,
                        event,
                        format!("raw/{ACCOUNT}/{asset}.enc"),
                        sha,
                        "2026-09-15T15:00:00.000Z",
                        CREATED_AT,
                    ],
                )
                .unwrap();
            connection
                .execute(
                    "INSERT INTO media_processing_jobs
                     (id,event_id,job_kind,input_revision,processor_version,state,attempt_count,
                      lease_until,error_code,model_id,prompt_version,schema_version,usage_json,updated_at)
                     VALUES (?1,?2,'gemini_audio',?3,1,'processing',1,?4,NULL,NULL,NULL,NULL,?5,?6)",
                    params![number, event, sha, LEASE_UNTIL, usage, UPDATED_AT],
                )
                .unwrap();
            connection
                .execute(
                    "INSERT INTO media_work_members
                     (work_unit_id,event_id,job_id,ordinal,window_start_ms,window_end_ms)
                     VALUES (?1,?2,?3,?4,?5,?6)",
                    params![
                        work,
                        event,
                        number,
                        i64::try_from(index).unwrap(),
                        i64::try_from(index).unwrap() * 1_000,
                        (i64::try_from(index).unwrap() + 1) * 1_000,
                    ],
                )
                .unwrap();
        }
    }

    pub(in crate::cp::media_worker::wal) fn seed_reserved_audio_work(
        connection: &Connection,
        work: &str,
        base: i64,
        count: usize,
    ) {
        seed_reserved_audio_work_shaped(connection, work, base, count, "mic", None);
    }

    pub(in crate::cp::media_worker::wal) fn settle_attempt(
        connection: &mut Connection,
        work: &str,
        count: usize,
    ) -> super::super::audio_attempt::AudioWindowAttemptReceipt {
        let at = attempted_at(count);
        let commitments = current_audio_work_attempt_commitments(connection, work, &at).unwrap();
        let plan = super::super::audio_attempt::AudioWindowAttemptPlan::new(
            ACCOUNT.to_owned(),
            work.to_owned(),
            commitments.predecessor(),
            commitments.attempt(),
            MODEL.to_owned(),
            "us-central1".to_owned(),
            at,
        )
        .unwrap();
        let prepared = PreparedLogicalMutation::prepare(plan).unwrap();
        execute_prepared_for_owner(connection, prepared)
            .unwrap()
            .into_validated_result()
            .release()
            .unwrap()
    }

    pub(in crate::cp::media_worker::wal) fn terminalize_attempt(
        connection: &Connection,
        work: &str,
        event_id: &str,
        count: usize,
    ) {
        let at = attempted_at(count);
        connection
            .execute(
                "UPDATE vertex_usage_events
                 SET returned_model=?1,http_status=200,prompt_tokens=100,
                     input_text_tokens=0,input_audio_tokens=100,input_image_tokens=0,
                     cached_input_tokens=0,cached_input_text_tokens=0,
                     cached_input_audio_tokens=0,cached_input_image_tokens=0,
                     output_text_tokens=50,thought_tokens=0,total_tokens=150,
                     outcome='metered',updated_at=?2
                 WHERE event_id=?3 AND outcome='started'",
                params![MODEL, at, event_id],
            )
            .unwrap();
        let usage = terminal_usage(work, count);
        connection
            .execute(
                "UPDATE media_work_units SET usage_json=?1,updated_at=?2 WHERE id=?3",
                params![usage, at, work],
            )
            .unwrap();
        connection
            .execute(
                "UPDATE media_processing_jobs SET usage_json=?1
                 WHERE id IN (SELECT job_id FROM media_work_members WHERE work_unit_id=?2)",
                params![usage, work],
            )
            .unwrap();
    }

    fn terminal_receipt(
        connection: &mut Connection,
        work: &str,
        count: usize,
    ) -> super::super::audio_attempt::AudioWindowAttemptReceipt {
        let receipt = settle_attempt(connection, work, count);
        terminalize_attempt(connection, work, receipt.event_id(), count);
        receipt
    }

    fn fact(turn_id: &str, start_ms: i64, end_ms: i64, speaker: &str, text: &str) -> AudioTurnFact {
        AudioTurnFact::new(
            turn_id.to_owned(),
            start_ms,
            end_ms,
            speaker.to_owned(),
            text.to_owned(),
            Some("en".to_owned()),
            false,
        )
        .unwrap()
    }

    fn transcript_plan(
        connection: &Connection,
        work: &str,
        receipt: &super::super::audio_attempt::AudioWindowAttemptReceipt,
        count: usize,
        turns: Vec<AudioTurnFact>,
    ) -> AudioWindowTranscriptPlan {
        AudioWindowTranscriptPlan::new(
            ACCOUNT.to_owned(),
            receipt.event_id().to_owned(),
            current_audio_vertex_attempt_commitment(connection, receipt.event_id(), MODEL).unwrap(),
            receipt.binding_commitment(),
            work.to_owned(),
            load_audio_work(connection, work).unwrap().commitment(),
            MODEL.to_owned(),
            committed_at(count),
            read_audio_sequence_pins(connection).unwrap(),
            turns,
        )
        .unwrap()
    }

    fn execute(
        connection: &mut Connection,
        plan: AudioWindowTranscriptPlan,
    ) -> std::result::Result<ExecutedLogicalMutation<AudioWindowTranscriptPlan>, WalIdempotencyError>
    {
        let prepared = PreparedLogicalMutation::prepare(plan)?;
        execute_prepared_for_owner(connection, prepared)
    }

    fn execute_error(
        connection: &mut Connection,
        plan: AudioWindowTranscriptPlan,
    ) -> WalIdempotencyError {
        match execute(connection, plan) {
            Ok(_) => panic!("mutation unexpectedly succeeded"),
            Err(error) => error,
        }
    }

    fn count_of(connection: &Connection, sql: &str) -> i64 {
        connection.query_row(sql, [], |row| row.get(0)).unwrap()
    }

    fn nothing_written(connection: &Connection) {
        for table in [
            "audio_segments",
            "speaker_clusters",
            "speaker_observations",
            "speaker_observation_sources",
            "utterances",
        ] {
            assert_eq!(
                count_of(connection, &format!("SELECT COUNT(*) FROM {table}")),
                0,
                "unexpected {table} rows"
            );
        }
    }

    // T9 — this family refuses screen-class work and non-terminal usage
    // (the mirror of the sealed screen family's audio rejection).
    #[test]
    fn t09_screen_class_and_nonterminal_usage_are_rejected() {
        let mut connection = connection();
        seed_reserved_audio_work(&connection, WORK_ONE, 1, 1);
        let receipt = terminal_receipt(&mut connection, WORK_ONE, 1);

        // Non-terminal usage: the reserved-stage object has no outcome.
        let reverted = reserved_usage(WORK_ONE, 1);
        connection
            .execute(
                "UPDATE media_work_units SET usage_json=?1 WHERE id=?2",
                params![reverted, WORK_ONE],
            )
            .unwrap();
        connection
            .execute(
                "UPDATE media_processing_jobs SET usage_json=?1",
                [&reverted],
            )
            .unwrap();
        assert_eq!(
            load_audio_work(&connection, WORK_ONE).unwrap_err(),
            WalIdempotencyError::Precondition
        );

        // Screen-class work refuses outright.
        terminalize_attempt(&connection, WORK_ONE, receipt.event_id(), 1);
        connection
            .execute("UPDATE media_work_units SET work_class='screen'", [])
            .unwrap();
        assert_eq!(
            load_audio_work(&connection, WORK_ONE).unwrap_err(),
            WalIdempotencyError::Precondition
        );

        // And the turn constructor refuses empty text at the type.
        assert!(AudioTurnFact::new(
            "turn-1".into(),
            0,
            100,
            "speaker_0".into(),
            String::new(),
            None,
            false,
        )
        .is_err());
    }

    // T10 — SILENT WINDOW: zero turns is a routine legal capture outcome.
    #[test]
    fn t10_silent_window_settles_segment_and_work_with_zero_turn_rows() {
        let mut connection = connection();
        seed_reserved_audio_work(&connection, WORK_ONE, 1, 1);
        let receipt = terminal_receipt(&mut connection, WORK_ONE, 1);
        let plan = transcript_plan(&connection, WORK_ONE, &receipt, 1, Vec::new());
        assert_eq!(
            execute(&mut connection, plan).unwrap().disposition(),
            LogicalMutationDisposition::Applied
        );
        assert_eq!(
            count_of(&connection, "SELECT COUNT(*) FROM audio_segments"),
            1
        );
        assert_eq!(
            count_of(&connection, "SELECT COUNT(*) FROM speaker_clusters"),
            0
        );
        assert_eq!(
            count_of(&connection, "SELECT COUNT(*) FROM speaker_observations"),
            0
        );
        assert_eq!(count_of(&connection, "SELECT COUNT(*) FROM utterances"), 0);
        assert_eq!(
            count_of(
                &connection,
                "SELECT COUNT(*) FROM media_processing_jobs WHERE state='succeeded'"
            ),
            1
        );
        assert_eq!(
            count_of(
                &connection,
                "SELECT COUNT(*) FROM media_objects WHERE processing_state='ready'"
            ),
            1
        );
        assert_eq!(
            count_of(
                &connection,
                "SELECT COUNT(*) FROM media_work_units WHERE state='succeeded'"
            ),
            1
        );
        assert_eq!(
            read_audio_sequence_pins(&connection).unwrap(),
            AudioSequencePins::new(1, 0, 0, 0)
        );
    }

    // T11 — MEMBER WIDTH: 13 and 128 members apply; 129 is refused when the
    // plan's predecessor is derived (the lease LIMIT is the only bound —
    // NEVER the 12-frame screen cap).
    #[test]
    fn t11_wide_windows_apply_and_129_members_refuse() {
        for count in [13_usize, 128] {
            let mut connection = connection();
            seed_reserved_audio_work(&connection, WORK_ONE, 1, count);
            let receipt = terminal_receipt(&mut connection, WORK_ONE, count);
            let turns = vec![fact("turn-1", 0, 900, "speaker_0", "wide window")];
            let plan = transcript_plan(&connection, WORK_ONE, &receipt, count, turns);
            assert_eq!(
                execute(&mut connection, plan).unwrap().disposition(),
                LogicalMutationDisposition::Applied,
                "count {count}"
            );
        }
        let connection = connection();
        seed_reserved_audio_work(&connection, WORK_ONE, 1, 129);
        assert_eq!(
            current_audio_work_attempt_commitments(&connection, WORK_ONE, &attempted_at(129))
                .unwrap_err(),
            WalIdempotencyError::Precondition
        );
        assert_eq!(
            load_audio_work(&connection, WORK_ONE).unwrap_err(),
            WalIdempotencyError::Precondition
        );
    }

    // T12 — MULTIBYTE TEXT: the cap counts CHARS exactly as
    // parse_audio_result does; a maximal CJK turn is legal at ~60 KB UTF-8.
    #[test]
    fn t12_multibyte_text_cap_counts_chars_not_bytes() {
        let text = "語".repeat(MAX_TEXT_CHARS);
        assert!(text.len() > 20_000);
        let mut connection = connection();
        seed_reserved_audio_work(&connection, WORK_ONE, 1, 1);
        let receipt = terminal_receipt(&mut connection, WORK_ONE, 1);
        let turn = AudioTurnFact::new(
            "turn-1".into(),
            0,
            900,
            "speaker_0".into(),
            text,
            Some("ja".into()),
            false,
        )
        .unwrap();
        let plan = transcript_plan(&connection, WORK_ONE, &receipt, 1, vec![turn]);
        assert_eq!(
            execute(&mut connection, plan).unwrap().disposition(),
            LogicalMutationDisposition::Applied
        );
        assert_eq!(
            AudioTurnFact::new(
                "turn-2".into(),
                0,
                900,
                "speaker_0".into(),
                "語".repeat(MAX_TEXT_CHARS + 1),
                None,
                false,
            )
            .unwrap_err(),
            WalIdempotencyError::Malformed
        );
    }

    // T13 — pin drift between the routed read and apply is genuine
    // conflict: Precondition, nothing written.
    #[test]
    fn t13_sequence_pin_drift_fails_closed_before_any_write() {
        let mut connection = connection();
        seed_reserved_audio_work(&connection, WORK_ONE, 1, 1);
        let receipt = terminal_receipt(&mut connection, WORK_ONE, 1);
        let plan = transcript_plan(
            &connection,
            WORK_ONE,
            &receipt,
            1,
            vec![fact("turn-1", 0, 900, "speaker_0", "drifted")],
        );
        connection
            .execute(
                "INSERT INTO audio_segments
                 (started_at,ended_at,duration_seconds,source_type,audio_format,transcription_status)
                 VALUES (?1,?1,1.0,'mic','audio/wav','done')",
                [STARTED_AT],
            )
            .unwrap();
        connection
            .execute(
                "INSERT INTO utterances (audio_segment_id,text) VALUES (1,'interloper')",
                [],
            )
            .unwrap();
        assert_eq!(
            execute_error(&mut connection, plan),
            WalIdempotencyError::Precondition
        );
        assert_eq!(
            count_of(&connection, "SELECT COUNT(*) FROM audio_segments"),
            1
        );
        assert_eq!(count_of(&connection, "SELECT COUNT(*) FROM utterances"), 1);
        assert_eq!(
            count_of(&connection, "SELECT COUNT(*) FROM speaker_observations"),
            0
        );
    }

    // T14 — in-transaction id interference (the only way a collision can
    // survive the pin equality check) is a derived-id mismatch: Corrupt,
    // full rollback.
    #[test]
    fn t14_derived_id_mismatch_is_corrupt_and_rolls_back() {
        let mut connection = connection();
        seed_reserved_audio_work(&connection, WORK_ONE, 1, 1);
        let receipt = terminal_receipt(&mut connection, WORK_ONE, 1);
        let plan = transcript_plan(
            &connection,
            WORK_ONE,
            &receipt,
            1,
            vec![fact("turn-1", 0, 900, "speaker_0", "collision")],
        );
        connection
            .execute_batch(
                "CREATE TRIGGER interfere AFTER INSERT ON audio_segments
                 BEGIN
                   INSERT INTO speaker_clusters (work_unit_id,speaker_local_id,attribution_state)
                   VALUES ('zzzz','intruder','request_local');
                 END;",
            )
            .unwrap();
        assert_eq!(
            execute_error(&mut connection, plan),
            WalIdempotencyError::Corrupt
        );
        connection.execute_batch("DROP TRIGGER interfere;").unwrap();
        nothing_written(&connection);
        assert_eq!(
            count_of(
                &connection,
                "SELECT COUNT(*) FROM media_work_units WHERE state='processing'"
            ),
            1
        );
    }

    // T15 — the speaker_observations UNIQUE(event_id,turn_id) trap fails
    // closed BEFORE any write when another work unit already consumed the
    // pair.
    #[test]
    fn t15_duplicate_event_turn_pair_fails_closed_pre_write() {
        let mut connection = connection();
        seed_reserved_audio_work(&connection, WORK_ONE, 1, 1);
        // A prior window over the same capture event already recorded this
        // model-supplied turn id.
        connection
            .execute(
                "INSERT INTO speaker_observations
                 (event_id,turn_id,speaker_local_id,started_at,ended_at,transcript_text)
                 VALUES ('audio-event-1','turn-1','older_speaker',?1,?1,'previous window')",
                [STARTED_AT],
            )
            .unwrap();
        let receipt = terminal_receipt(&mut connection, WORK_ONE, 1);
        let plan = transcript_plan(
            &connection,
            WORK_ONE,
            &receipt,
            1,
            vec![fact("turn-1", 0, 900, "speaker_0", "colliding turn id")],
        );
        assert_eq!(
            execute_error(&mut connection, plan),
            WalIdempotencyError::Precondition
        );
        assert_eq!(
            count_of(&connection, "SELECT COUNT(*) FROM audio_segments"),
            0
        );
        assert_eq!(count_of(&connection, "SELECT COUNT(*) FROM utterances"), 0);
    }

    // T16 — replay is exact; a rebuilt plan with different pins after the
    // apply is a fingerprint conflict on the same operation id.
    #[test]
    fn t16_replay_is_exact_and_moved_pins_conflict() {
        let mut connection = connection();
        seed_reserved_audio_work(&connection, WORK_ONE, 1, 1);
        let receipt = terminal_receipt(&mut connection, WORK_ONE, 1);
        let turns = || vec![fact("turn-1", 0, 900, "speaker_0", "replayed")];
        let replay = transcript_plan(&connection, WORK_ONE, &receipt, 1, turns());
        let first = transcript_plan(&connection, WORK_ONE, &receipt, 1, turns());
        assert_eq!(
            execute(&mut connection, first).unwrap().disposition(),
            LogicalMutationDisposition::Applied
        );
        connection
            .execute_batch(
                "CREATE TRIGGER reject_rewrite BEFORE UPDATE ON utterances
                 BEGIN SELECT RAISE(ABORT,'no rewrite'); END;",
            )
            .unwrap();
        assert_eq!(
            execute(&mut connection, replay).unwrap().disposition(),
            LogicalMutationDisposition::Replayed
        );
        assert_eq!(count_of(&connection, "SELECT COUNT(*) FROM utterances"), 1);
        // Rebuild from the post-apply state: same operation id, new pins.
        let rebuilt = AudioWindowTranscriptPlan::new(
            ACCOUNT.to_owned(),
            receipt.event_id().to_owned(),
            current_audio_vertex_attempt_commitment(&connection, receipt.event_id(), MODEL)
                .unwrap(),
            receipt.binding_commitment(),
            WORK_ONE.to_owned(),
            [9_u8; 32],
            MODEL.to_owned(),
            committed_at(1),
            read_audio_sequence_pins(&connection).unwrap(),
            turns(),
        )
        .unwrap();
        assert_eq!(
            execute_error(&mut connection, rebuilt),
            WalIdempotencyError::FingerprintConflict
        );
    }

    // T17 — R7: applying the identical plan at two wall clocks writes
    // byte-identical domain rows (no clock executes inside apply).
    #[test]
    fn t17_two_wall_clocks_write_byte_identical_rows() {
        let dump = |connection: &Connection| -> Vec<String> {
            let mut rows = Vec::new();
            for sql in [
                "SELECT id,started_at,ended_at,duration_seconds,source_type,audio_format,
                        transcription_status,created_at FROM audio_segments ORDER BY id",
                "SELECT id,work_unit_id,speaker_local_id,attribution_state,created_at,updated_at
                 FROM speaker_clusters ORDER BY id",
                "SELECT id,person_id,event_id,turn_id,speaker_local_id,started_at,ended_at,
                        transcript_text,language,overlap,cluster_id
                 FROM speaker_observations ORDER BY id",
                "SELECT id,audio_segment_id,start_offset_seconds,end_offset_seconds,text,language,
                        confidence,speaker_label,source_key,speaker_observation_id,created_at
                 FROM utterances ORDER BY id",
                "SELECT id,state,model_id,prompt_version,schema_version,updated_at
                 FROM media_processing_jobs ORDER BY id",
                "SELECT id,state,error_code,updated_at FROM media_work_units ORDER BY id",
            ] {
                let mut statement = connection.prepare(sql).unwrap();
                let columns = statement.column_count();
                let mut query = statement.query([]).unwrap();
                while let Some(row) = query.next().unwrap() {
                    let mut line = String::new();
                    for index in 0..columns {
                        line.push_str(&format!("{:?}|", row.get_ref(index).unwrap()));
                    }
                    rows.push(line);
                }
            }
            rows
        };
        let run = || {
            let mut connection = connection();
            seed_reserved_audio_work(&connection, WORK_ONE, 1, 2);
            let receipt = terminal_receipt(&mut connection, WORK_ONE, 2);
            let plan = transcript_plan(
                &connection,
                WORK_ONE,
                &receipt,
                2,
                vec![
                    fact("turn-1", 0, 900, "speaker_0", "first turn"),
                    fact("turn-2", 1_000, 1_900, "speaker_1", "second turn"),
                ],
            );
            execute(&mut connection, plan).unwrap();
            dump(&connection)
        };
        let first = run();
        std::thread::sleep(std::time::Duration::from_millis(15));
        let second = run();
        assert_eq!(first, second);
        assert!(!first.is_empty());
    }

    // T18 — the utterances FTS trigger indexes the transcript text on the
    // deterministic rowid, in-transaction.
    #[test]
    fn t18_fts_match_finds_transcript_text_after_apply() {
        let mut connection = identity_connection();
        seed_reserved_audio_work(&connection, WORK_ONE, 1, 1);
        let receipt = terminal_receipt(&mut connection, WORK_ONE, 1);
        let plan = transcript_plan(
            &connection,
            WORK_ONE,
            &receipt,
            1,
            vec![fact(
                "turn-1",
                0,
                900,
                "speaker_0",
                "quixotic zeppelin plan",
            )],
        );
        execute(&mut connection, plan).unwrap();
        let rowid: i64 = connection
            .query_row(
                "SELECT rowid FROM utterances_fts WHERE utterances_fts MATCH 'zeppelin'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(rowid, 1);
    }

    // T19 — the closed-form attribution/label/source-type projection.
    #[test]
    fn t19_attribution_states_labels_and_source_type_project_exactly() {
        // (a) local_transmit + single distinct speaker → owner_transmit + "Me".
        let mut owner = connection();
        seed_reserved_audio_work_shaped(&owner, WORK_ONE, 1, 1, "mic", Some("local_transmit"));
        let receipt = terminal_receipt(&mut owner, WORK_ONE, 1);
        let plan = transcript_plan(
            &owner,
            WORK_ONE,
            &receipt,
            1,
            vec![
                fact("turn-1", 0, 400, "speaker_0", "owner speaking"),
                fact("turn-2", 500, 900, "speaker_0", "still the owner"),
            ],
        );
        execute(&mut owner, plan).unwrap();
        assert_eq!(
            owner
                .query_row(
                    "SELECT attribution_state FROM speaker_clusters",
                    [],
                    |row| row.get::<_, String>(0),
                )
                .unwrap(),
            "owner_transmit"
        );
        assert_eq!(
            count_of(
                &owner,
                "SELECT COUNT(*) FROM utterances WHERE speaker_label='Me'"
            ),
            2
        );

        // (b) local_transmit + two speakers → request_local + "Unidentified voice".
        let mut pair = connection();
        seed_reserved_audio_work_shaped(&pair, WORK_ONE, 1, 1, "mic", Some("local_transmit"));
        let receipt = terminal_receipt(&mut pair, WORK_ONE, 1);
        let plan = transcript_plan(
            &pair,
            WORK_ONE,
            &receipt,
            1,
            vec![
                fact("turn-1", 0, 400, "speaker_0", "one voice"),
                fact("turn-2", 500, 900, "speaker_1", "another voice"),
            ],
        );
        execute(&mut pair, plan).unwrap();
        assert_eq!(
            count_of(
                &pair,
                "SELECT COUNT(*) FROM speaker_clusters WHERE attribution_state='request_local'"
            ),
            2
        );
        assert_eq!(
            count_of(
                &pair,
                "SELECT COUNT(*) FROM utterances WHERE speaker_label='Unidentified voice'"
            ),
            2
        );

        // (c) system audio → segment source_type 'system'.
        let mut system = connection();
        seed_reserved_audio_work_shaped(&system, WORK_ONE, 1, 1, "system_audio", None);
        let receipt = terminal_receipt(&mut system, WORK_ONE, 1);
        let plan = transcript_plan(
            &system,
            WORK_ONE,
            &receipt,
            1,
            vec![fact("turn-1", 0, 900, "speaker_0", "system capture")],
        );
        execute(&mut system, plan).unwrap();
        assert_eq!(
            system
                .query_row("SELECT source_type FROM audio_segments", [], |row| row
                    .get::<_, String>(
                    0
                ))
                .unwrap(),
            "system"
        );
    }

    // T20 — terminal-usage gates on the Vertex row and the settled usage.
    #[test]
    fn t20_nonterminal_vertex_or_usage_outcome_is_refused() {
        for mutation in ["vertex-started", "vertex-ambiguous", "usage-outcome"] {
            let mut connection = connection();
            seed_reserved_audio_work(&connection, WORK_ONE, 1, 1);
            let receipt = terminal_receipt(&mut connection, WORK_ONE, 1);
            let plan = transcript_plan(
                &connection,
                WORK_ONE,
                &receipt,
                1,
                vec![fact("turn-1", 0, 900, "speaker_0", "gated")],
            );
            match mutation {
                "vertex-started" => {
                    connection
                        .execute(
                            "UPDATE vertex_usage_events SET outcome='started',http_status=NULL",
                            [],
                        )
                        .unwrap();
                }
                "vertex-ambiguous" => {
                    connection
                        .execute("UPDATE vertex_usage_events SET outcome='ambiguous'", [])
                        .unwrap();
                }
                "usage-outcome" => {
                    connection
                        .execute(
                            "UPDATE media_work_units
                             SET usage_json=json_set(usage_json,'$.outcome','provider_error')",
                            [],
                        )
                        .unwrap();
                    connection
                        .execute(
                            "UPDATE media_processing_jobs
                             SET usage_json=json_set(usage_json,'$.outcome','provider_error')",
                            [],
                        )
                        .unwrap();
                }
                _ => unreachable!(),
            }
            assert_eq!(
                execute_error(&mut connection, plan),
                WalIdempotencyError::Precondition,
                "mutation {mutation}"
            );
            nothing_written(&connection);
        }
    }

    // T21 — binding gates: a tampered binding commitment refuses, and a
    // stale plan after a re-claim cannot poison the successor's coordinate.
    #[test]
    fn t21_tampered_binding_and_stale_topology_are_refused() {
        let mut connection = connection();
        seed_reserved_audio_work(&connection, WORK_ONE, 1, 1);
        let receipt = terminal_receipt(&mut connection, WORK_ONE, 1);
        let mut tampered_binding = receipt.binding_commitment();
        tampered_binding[0] ^= 0x01;
        let tampered = AudioWindowTranscriptPlan::new(
            ACCOUNT.to_owned(),
            receipt.event_id().to_owned(),
            current_audio_vertex_attempt_commitment(&connection, receipt.event_id(), MODEL)
                .unwrap(),
            tampered_binding,
            WORK_ONE.to_owned(),
            load_audio_work(&connection, WORK_ONE).unwrap().commitment(),
            MODEL.to_owned(),
            committed_at(1),
            read_audio_sequence_pins(&connection).unwrap(),
            vec![fact("turn-1", 0, 900, "speaker_0", "tampered")],
        )
        .unwrap();
        assert_eq!(
            execute_error(&mut connection, tampered),
            WalIdempotencyError::Precondition
        );

        // Stale plan: a re-claim advances the counters after this plan was
        // constructed; the moved topology refuses before any write.
        let stale = transcript_plan(
            &connection,
            WORK_ONE,
            &receipt,
            1,
            vec![fact("turn-1", 0, 900, "speaker_0", "stale")],
        );
        connection
            .execute(
                "UPDATE media_work_units SET attempt_count=attempt_count+1",
                [],
            )
            .unwrap();
        connection
            .execute(
                "UPDATE media_processing_jobs SET attempt_count=attempt_count+1",
                [],
            )
            .unwrap();
        assert_eq!(
            execute_error(&mut connection, stale),
            WalIdempotencyError::Precondition
        );
        nothing_written(&connection);
    }

    // T22 — projection refusals and constructor rejections.
    #[test]
    fn t22_projection_and_constructor_refuse_invalid_turn_topology() {
        // Turn past the window duration: the owner check is Malformed and a
        // forced apply refuses without writing.
        let mut short_window = connection();
        seed_reserved_audio_work(&short_window, WORK_ONE, 1, 1);
        let receipt = terminal_receipt(&mut short_window, WORK_ONE, 1);
        let authenticated = load_audio_work(&short_window, WORK_ONE).unwrap();
        let past_end = vec![fact("turn-1", 0, 2_000, "speaker_0", "past the end")];
        assert_eq!(
            project_audio_window_for_owner(&authenticated, &past_end).unwrap_err(),
            WalIdempotencyError::Malformed
        );
        let plan = transcript_plan(&short_window, WORK_ONE, &receipt, 1, past_end);
        assert_eq!(
            execute_error(&mut short_window, plan),
            WalIdempotencyError::Corrupt
        );
        nothing_written(&short_window);

        // A turn inside a member gap projects onto no source interval.
        let mut gapped = connection();
        seed_reserved_audio_work(&gapped, WORK_ONE, 1, 3);
        gapped
            .execute(
                "DELETE FROM media_work_members WHERE work_unit_id=?1 AND ordinal=1",
                [WORK_ONE],
            )
            .unwrap();
        gapped
            .execute(
                "UPDATE media_work_members SET ordinal=1 WHERE work_unit_id=?1 AND ordinal=2",
                [WORK_ONE],
            )
            .unwrap();
        gapped
            .execute(
                "UPDATE media_work_units SET usage_json=?1 WHERE id=?2",
                params![reserved_usage(WORK_ONE, 2), WORK_ONE],
            )
            .unwrap();
        gapped
            .execute(
                "UPDATE media_processing_jobs SET usage_json=?1
                 WHERE id IN (SELECT job_id FROM media_work_members WHERE work_unit_id=?2)",
                params![reserved_usage(WORK_ONE, 2), WORK_ONE],
            )
            .unwrap();
        let receipt = terminal_receipt(&mut gapped, WORK_ONE, 2);
        let authenticated = load_audio_work(&gapped, WORK_ONE).unwrap();
        let in_gap = vec![fact("turn-1", 1_200, 1_800, "speaker_0", "in the gap")];
        assert_eq!(
            project_audio_window_for_owner(&authenticated, &in_gap).unwrap_err(),
            WalIdempotencyError::Malformed
        );
        let plan = transcript_plan(&gapped, WORK_ONE, &receipt, 2, in_gap);
        assert_eq!(
            execute_error(&mut gapped, plan),
            WalIdempotencyError::Corrupt
        );
        nothing_written(&gapped);

        // Constructor rejections: duplicate ids, negative start, and
        // non-monotone starts.
        let build = |turns: Vec<AudioTurnFact>| {
            AudioWindowTranscriptPlan::new(
                ACCOUNT.to_owned(),
                format!("vtx_{}", "a".repeat(64)),
                [1; 32],
                [2; 32],
                WORK_ONE.to_owned(),
                [3; 32],
                MODEL.to_owned(),
                committed_at(1),
                AudioSequencePins::new(0, 0, 0, 0),
                turns,
            )
        };
        assert_eq!(
            build(vec![
                fact("turn-1", 0, 400, "speaker_0", "a"),
                fact("turn-1", 500, 900, "speaker_0", "b"),
            ])
            .unwrap_err(),
            WalIdempotencyError::Malformed
        );
        assert_eq!(
            build(vec![fact("turn-1", -1, 400, "speaker_0", "negative")]).unwrap_err(),
            WalIdempotencyError::Malformed
        );
        assert_eq!(
            build(vec![
                fact("turn-1", 500, 900, "speaker_0", "later"),
                fact("turn-2", 0, 400, "speaker_0", "earlier"),
            ])
            .unwrap_err(),
            WalIdempotencyError::Malformed
        );
    }

    // T23 — the commit-time gate.
    #[test]
    fn t23_commit_time_outside_the_attempt_window_is_refused() {
        for committed in ["2026-08-15T15:00:01.000Z", "2026-08-15T15:05:01.000Z"] {
            let mut connection = connection();
            seed_reserved_audio_work(&connection, WORK_ONE, 1, 1);
            let receipt = terminal_receipt(&mut connection, WORK_ONE, 1);
            let plan = AudioWindowTranscriptPlan::new(
                ACCOUNT.to_owned(),
                receipt.event_id().to_owned(),
                current_audio_vertex_attempt_commitment(&connection, receipt.event_id(), MODEL)
                    .unwrap(),
                receipt.binding_commitment(),
                WORK_ONE.to_owned(),
                load_audio_work(&connection, WORK_ONE).unwrap().commitment(),
                MODEL.to_owned(),
                committed.to_owned(),
                read_audio_sequence_pins(&connection).unwrap(),
                vec![fact("turn-1", 0, 900, "speaker_0", "timed")],
            )
            .unwrap();
            assert_eq!(
                execute_error(&mut connection, plan),
                WalIdempotencyError::Precondition,
                "committed {committed}"
            );
            nothing_written(&connection);
        }
    }

    // E1 — EQUIVALENCE: the omitted legacy tail passes are proven no-ops
    // over the plan's writes.
    #[test]
    fn e1_legacy_reconcile_and_recalculate_change_zero_rows_after_apply() {
        let mut connection = identity_connection();
        seed_reserved_audio_work(&connection, WORK_ONE, 1, 2);
        let receipt = terminal_receipt(&mut connection, WORK_ONE, 2);
        let plan = transcript_plan(
            &connection,
            WORK_ONE,
            &receipt,
            2,
            vec![
                fact("turn-1", 0, 900, "speaker_0", "first voice"),
                fact("turn-2", 1_000, 1_900, "speaker_1", "second voice"),
            ],
        );
        execute(&mut connection, plan).unwrap();
        let relabeled =
            crate::cp::media::reconcile_request_local_speaker_labels(&connection, Some(WORK_ONE))
                .unwrap();
        assert_eq!(relabeled, 0, "per-unit relabel must be a no-op");
        let recalculated =
            crate::cp::voice_memory::recalculate_all_episode_speaker_processing_status(&connection)
                .unwrap();
        assert_eq!(recalculated, 0, "episode recalculation must be a no-op");
    }

    // E2 — the identity-exclusion red line (also the F8-coupling guard:
    // any future change enqueueing voice jobs on this lane must re-open
    // F8's review).
    #[test]
    fn e2_identity_exclusion_red_line_holds_after_apply() {
        let mut connection = identity_connection();
        seed_reserved_audio_work_shaped(&connection, WORK_ONE, 1, 1, "mic", Some("local_transmit"));
        let receipt = terminal_receipt(&mut connection, WORK_ONE, 1);
        let plan = transcript_plan(
            &connection,
            WORK_ONE,
            &receipt,
            1,
            vec![
                fact("turn-1", 0, 400, "speaker_0", "I am definitely someone"),
                fact("turn-2", 500, 900, "speaker_1", "and so are you, Frankie"),
            ],
        );
        execute(&mut connection, plan).unwrap();
        for table in [
            "people",
            "person_name_claims",
            "identity_evidence",
            "person_facts",
            "voice_samples",
            "voice_profiles",
            "voice_sample_profile_assignments",
            "voice_profile_revisions",
            "voice_profile_representatives",
            "profile_identity_bindings",
            "voice_embedding_jobs",
        ] {
            assert_eq!(
                count_of(&connection, &format!("SELECT COUNT(*) FROM {table}")),
                0,
                "identity red line crossed: {table}"
            );
        }
        assert_eq!(
            count_of(
                &connection,
                "SELECT COUNT(*) FROM speaker_observations WHERE person_id IS NOT NULL"
            ),
            0
        );
        assert_eq!(count_of(&connection, "SELECT COUNT(*) FROM episodes"), 0);
    }

    // T24 — the sqlite_sequence gate over the REAL archive baseline
    // (store.rs SCHEMA_SQL + run_migrations), save/reload, shadow parity,
    // and fingerprint re-validation.
    //
    // VERDICT (original): the gate FAILED the family. The frozen epoch-0
    // baseline created `audio_segments` and `utterances` WITHOUT
    // AUTOINCREMENT (media.rs's AUTOINCREMENT DDL is a no-op `IF NOT EXISTS`
    // behind it), so those two tables never allocated `sqlite_sequence` rows,
    // the carried pins were the constant 0, and the first transcript apply on
    // a real archive failed closed at the post-state pin re-validation.
    //
    // VERDICT (now): the sealed re-baseline gave both tables explicit
    // sequences, so the blocking facts are inverted rather than deleted —
    // deleting the test that found the defect would delete the only record of
    // what "fixed" means here. Blocking fact 1 and blocking fact 2 below now
    // assert the opposite of what they used to, on the same real baseline.
    //
    // The remaining §5.6.1 work — the full apply/replay window, the second
    // window's pre-state pins, and killing the divergent `install_schema`
    // fixture — belongs to the transcripts lane, which owns this file.
    #[test]
    fn t24_sequence_gate_admits_the_family_on_the_production_baseline() {
        crate::store::init_vec_extension();
        let directory = tempdir().unwrap();
        let path = directory.path().join("t24-production.sqlite");
        let connection = Connection::open(&path).unwrap();
        connection.execute_batch(crate::store::SCHEMA_SQL).unwrap();
        crate::store::run_migrations(&connection).unwrap();
        // The probes below stand alone; parent capture rows are irrelevant
        // to the sequence facts this gate pins.
        connection
            .execute_batch("PRAGMA foreign_keys=OFF;")
            .unwrap();

        // Blocking fact 1, INVERTED: the baseline DDL now declares all four
        // pinned tables AUTOINCREMENT. It used to declare only two, and that
        // split is what blocked the family.
        let ddl = |table: &str| -> String {
            connection
                .query_row(
                    "SELECT sql FROM sqlite_master WHERE type='table' AND name=?1",
                    [table],
                    |row| row.get(0),
                )
                .unwrap()
        };
        assert!(ddl("audio_segments").contains("AUTOINCREMENT"));
        assert!(ddl("utterances").contains("AUTOINCREMENT"));
        assert!(ddl("speaker_clusters").contains("AUTOINCREMENT"));
        assert!(ddl("speaker_observations").contains("AUTOINCREMENT"));

        // Blocking fact 2, INVERTED: inserts into all four tables now move
        // sqlite_sequence, so the pin discipline observes them — and, the
        // point of the whole change, DELETING every row leaves the high-water
        // standing so an id can never be reissued.
        connection
            .execute(
                "INSERT INTO audio_segments
                 (started_at,ended_at,duration_seconds,source_type)
                 VALUES (?1,?1,1.0,'mic')",
                [STARTED_AT],
            )
            .unwrap();
        connection
            .execute(
                "INSERT INTO utterances
                 (audio_segment_id,start_offset_seconds,end_offset_seconds,text,speaker_label)
                 VALUES (1,0.0,1.0,'probe','Unidentified voice')",
                [],
            )
            .unwrap();
        let pins = read_audio_sequence_pins(&connection).unwrap();
        assert_eq!(
            pins,
            AudioSequencePins::new(1, 0, 0, 1),
            "AUTOINCREMENT tables must appear in sqlite_sequence after one insert"
        );
        connection.execute("DELETE FROM utterances", []).unwrap();
        connection
            .execute("DELETE FROM audio_segments", [])
            .unwrap();
        // The id-reuse proof, and the most important assertion in this file:
        // the pins do NOT rewind. On the pre-re-baseline plain-PK tables the
        // next insert reissued id 1 — the killed MAX(id)+1 allocator with its
        // guardrail removed.
        assert_eq!(
            read_audio_sequence_pins(&connection).unwrap(),
            AudioSequencePins::new(1, 0, 0, 1),
            "DELETE must not rewind the high-water; ids are never reissued"
        );

        // Explicit sequences that DO exist survive an archive save/reload.
        connection
            .execute(
                "INSERT INTO speaker_observations
                 (event_id,turn_id,speaker_local_id,started_at,ended_at,transcript_text)
                 VALUES ('seq-probe','turn-probe','speaker_probe',?1,?1,'probe')",
                [STARTED_AT],
            )
            .unwrap();
        connection
            .execute("DELETE FROM speaker_observations", [])
            .unwrap();
        let before: Vec<(String, i64)> = {
            let mut statement = connection
                .prepare("SELECT name,seq FROM sqlite_sequence ORDER BY name")
                .unwrap();
            let rows = statement
                .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
                .unwrap()
                .collect::<rusqlite::Result<Vec<_>>>()
                .unwrap();
            rows
        };
        assert!(before
            .iter()
            .any(|(name, seq)| name == "speaker_observations" && *seq >= 1));
        drop(connection);
        let connection = Connection::open(&path).unwrap();
        let after: Vec<(String, i64)> = {
            let mut statement = connection
                .prepare("SELECT name,seq FROM sqlite_sequence ORDER BY name")
                .unwrap();
            let rows = statement
                .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
                .unwrap()
                .collect::<rusqlite::Result<Vec<_>>>()
                .unwrap();
            rows
        };
        assert_eq!(before, after, "sqlite_sequence must survive save/reload");
        drop(connection);

        // Shadow parity retains and compares sqlite_sequence: byte-equal
        // copies match, and a copy whose sequence row was tampered with
        // mismatches.
        use std::os::unix::fs::PermissionsExt;
        let copy_a = directory.path().join("t24-copy-a.sqlite");
        let copy_b = directory.path().join("t24-copy-b.sqlite");
        std::fs::copy(&path, &copy_a).unwrap();
        std::fs::copy(&path, &copy_b).unwrap();
        for copy in [&copy_a, &copy_b] {
            std::fs::set_permissions(copy, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        let staged_a =
            crate::archive_v3_shadow_parity::PrivateStagedSqliteCopy::new(copy_a.clone()).unwrap();
        let staged_b =
            crate::archive_v3_shadow_parity::PrivateStagedSqliteCopy::new(copy_b.clone()).unwrap();
        let cancelled = std::sync::atomic::AtomicBool::new(false);
        let control = crate::archive_v3_shadow_parity::ShadowParityRunControl::new(
            std::time::Instant::now() + std::time::Duration::from_secs(60),
            &cancelled,
        );
        assert!(matches!(
            crate::archive_v3_shadow_parity::ShadowParityVerifier::compare_staged_copies(
                &staged_a, &staged_b, &control,
            )
            .unwrap(),
            crate::archive_v3_shadow_parity::ShadowParityResult::Match(_)
        ));
        {
            let tamper = Connection::open(&copy_b).unwrap();
            tamper
                .execute(
                    "UPDATE sqlite_sequence SET seq=seq+7 WHERE name='speaker_observations'",
                    [],
                )
                .unwrap();
        }
        let staged_a =
            crate::archive_v3_shadow_parity::PrivateStagedSqliteCopy::new(copy_a).unwrap();
        let staged_b =
            crate::archive_v3_shadow_parity::PrivateStagedSqliteCopy::new(copy_b).unwrap();
        assert!(matches!(
            crate::archive_v3_shadow_parity::ShadowParityVerifier::compare_staged_copies(
                &staged_a, &staged_b, &control,
            )
            .unwrap(),
            crate::archive_v3_shadow_parity::ShadowParityResult::Mismatch(_)
        ));

        // Blocking fact 3, INVERTED: the FIRST transcript apply on the
        // production baseline now SUCCEEDS. It used to fail closed (Corrupt at
        // the post-state pin re-validation) because the carried pins were the
        // constant 0 while the tables allocated real ids, so the re-validation
        // could never be satisfied. Nothing in the family changed to fix that;
        // the baseline did.
        let mut connection = Connection::open(&path).unwrap();
        connection
            .execute_batch(
                "PRAGMA foreign_keys=OFF;
                 DELETE FROM speaker_observations;",
            )
            .unwrap();
        seed_reserved_audio_work(&connection, WORK_ONE, 1, 1);
        let receipt = terminal_receipt(&mut connection, WORK_ONE, 1);
        let replay = transcript_plan(
            &connection,
            WORK_ONE,
            &receipt,
            1,
            vec![fact("turn-1", 0, 900, "speaker_0", "admitted family")],
        );
        let before = read_audio_sequence_pins(&connection).unwrap();
        let plan = transcript_plan(
            &connection,
            WORK_ONE,
            &receipt,
            1,
            vec![fact("turn-1", 0, 900, "speaker_0", "admitted family")],
        );
        assert_eq!(
            execute(&mut connection, plan).unwrap().disposition(),
            LogicalMutationDisposition::Applied,
            "the re-baselined production baseline must admit the family"
        );
        // The pins advanced by exactly 1 / cluster_count / turn_count /
        // turn_count. One turn, one cluster. Never "advanced by at least".
        let after = read_audio_sequence_pins(&connection).unwrap();
        assert_eq!(
            after,
            AudioSequencePins::new(
                before.audio_segments + 1,
                before.speaker_clusters + 1,
                before.speaker_observations + 1,
                before.utterances + 1,
            ),
            "pins must advance by the exact per-table deltas"
        );
        assert_eq!(count_of(&connection, "SELECT COUNT(*) FROM utterances"), 1);
        assert_eq!(
            count_of(
                &connection,
                "SELECT COUNT(*) FROM media_work_units WHERE state='succeeded'"
            ),
            1
        );
        // The identical plan replays from the ledger without re-advancing
        // anything: the operation is settled, not re-applied.
        assert_eq!(
            execute(&mut connection, replay).unwrap().disposition(),
            LogicalMutationDisposition::Replayed
        );
        assert_eq!(
            read_audio_sequence_pins(&connection).unwrap(),
            after,
            "a replay must not move the sequences"
        );
        assert_eq!(count_of(&connection, "SELECT COUNT(*) FROM utterances"), 1);
    }
}
