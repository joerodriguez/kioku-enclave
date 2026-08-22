#![allow(
    dead_code,
    reason = "inactive ADR-0022 screen-result codec is reviewed before its B attempt boundary, launcher, or worker ownership"
)]

//! Inactive deterministic screen-storyboard result WAL subtype.
//!
//! The production-facing v2 contract consumes the sibling B boundary that
//! durably fixes the Vertex attempt before provider I/O. The exact historical
//! v1 request encoding remains test-covered but has no production constructor.
//! The subtype accepts only a fully leased screen work unit whose
//! provider usage has already reached a terminal result, caller-fixed row IDs,
//! one fixed commit time, and results with no person evidence. It authenticates
//! every work/member/job/capture/media predecessor before atomically inserting
//! the screenshots and observations, settling the exact jobs and work unit, and
//! retaining permanent replay. Audio, person/identity/voice mutation, Store,
//! media reads, provider calls, clocks, automatic IDs, retries, launching, and
//! acknowledgement are deliberately absent.

use rusqlite::{params, types::ValueRef, Connection, OptionalExtension, Row, Transaction};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::archive_v3_wal_idempotency::{
    DomainLedgerBounds, LogicalMutationResult, PreparedLogicalMutation, WalIdempotencyError,
    WalLogicalDomainLedger, WalLogicalDomainPlan, WalLogicalOperationId, WalOperationKind,
    WalReplayResult,
};

const REQUEST_V1: u16 = 1;
const REQUEST_V2: u16 = 2;
const SUBTYPE_V1: &[u8] = b"screen-storyboard-no-people-v1";
const SUBTYPE_V2: &[u8] = b"screen-storyboard-no-people-v2-bound-attempt";
const BOUND_OPERATION_SOURCE_DOMAIN: &[u8] = b"screen-storyboard-result-bound-v2\0";
const PROCESSOR_VERSION: i64 = 1;
const PROMPT_VERSION: i64 = 2;
const RESULT_SCHEMA_VERSION: i64 = 2;
const OBSERVATION_VERSION: i64 = 2;
const MAX_FRAMES: usize = 12;
const MAX_ID_BYTES: usize = 128;
const MAX_MODEL_BYTES: usize = 128;
const MAX_TIMESTAMP_BYTES: usize = 64;
const MAX_CONTEXT_BYTES: usize = 256 * 1024;
const MAX_LITERAL_BYTES: usize = 20_000;
const MAX_VISIBLE_BYTES: usize = 100_000;
const MAX_SALIENT_BYTES: usize = 20_000;
const MIN_PROVIDER_ATTEMPT_WINDOW_MILLIS: i64 = 120_000;
const ENCODED_UNIT_RESULT_BYTES: usize = 9;
const SCHEMA_TABLE: &str = "archive_v3_wal_screen_storyboard_result_schema";
const LEDGER_TABLE: &str = "archive_v3_wal_screen_storyboard_result_operations";
const STATE_TABLE: &str = "archive_v3_wal_screen_storyboard_result_state";
const MAX_ROWS: u32 = 1_048_576;
const MAX_RESULT_BYTES: u64 = 32 * 1024 * 1024;
const BOUNDS: DomainLedgerBounds = DomainLedgerBounds::new(MAX_ROWS, MAX_RESULT_BYTES);

type Result<T> = std::result::Result<T, WalIdempotencyError>;

#[derive(Clone, PartialEq, Eq)]
pub(in crate::cp::media_worker) struct ScreenStoryboardFrameResult {
    event_id: String,
    screenshot_id: i64,
    literal_description: String,
    screen_state: String,
    content_type: String,
    visible_text: String,
    salient_text: String,
}

impl ScreenStoryboardFrameResult {
    #[allow(clippy::too_many_arguments)]
    pub(in crate::cp::media_worker) fn new(
        event_id: String,
        screenshot_id: i64,
        literal_description: String,
        screen_state: String,
        content_type: String,
        visible_text: String,
        salient_text: String,
    ) -> Result<Self> {
        const STATES: &[&str] = &[
            "content",
            "blank",
            "loading",
            "error",
            "transition",
            "locked_or_private",
            "unknown",
        ];
        const TYPES: &[&str] = &[
            "document",
            "presentation",
            "web_page",
            "code",
            "terminal",
            "chat",
            "meeting",
            "media",
            "system_ui",
            "application_ui",
            "unknown",
        ];
        validate_id(&event_id)?;
        if screenshot_id <= 0
            || !STATES.contains(&screen_state.as_str())
            || !TYPES.contains(&content_type.as_str())
        {
            return Err(WalIdempotencyError::Malformed);
        }
        validate_text(&literal_description, MAX_LITERAL_BYTES, true)?;
        validate_text(&visible_text, MAX_VISIBLE_BYTES, false)?;
        validate_text(&salient_text, MAX_SALIENT_BYTES, false)?;
        Ok(Self {
            event_id,
            screenshot_id,
            literal_description,
            screen_state,
            content_type,
            visible_text,
            salient_text,
        })
    }
}

pub(crate) struct ScreenStoryboardResultPlan {
    operation_id: WalLogicalOperationId,
    request_contract: ScreenStoryboardResultRequestContract,
    account_id: String,
    vertex_event_id: String,
    vertex_attempt_commitment: [u8; 32],
    work_unit_id: String,
    predecessor_commitment: [u8; 32],
    requested_model: String,
    committed_at: String,
    frames: Vec<ScreenStoryboardFrameResult>,
}

#[derive(Clone, Copy)]
enum ScreenStoryboardResultRequestContract {
    UnboundV1,
    BoundV2 {
        attempt_binding_commitment: [u8; 32],
    },
}

impl ScreenStoryboardResultPlan {
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
        frames: Vec<ScreenStoryboardFrameResult>,
    ) -> Result<Self> {
        if attempt_binding_commitment == [0; 32] {
            return Err(WalIdempotencyError::Malformed);
        }
        Self::build(
            ScreenStoryboardResultRequestContract::BoundV2 {
                attempt_binding_commitment,
            },
            account_id,
            vertex_event_id,
            vertex_attempt_commitment,
            work_unit_id,
            predecessor_commitment,
            requested_model,
            committed_at,
            frames,
        )
    }

    #[cfg(test)]
    #[allow(clippy::too_many_arguments)]
    fn new_unbound_v1(
        account_id: String,
        vertex_event_id: String,
        vertex_attempt_commitment: [u8; 32],
        work_unit_id: String,
        predecessor_commitment: [u8; 32],
        requested_model: String,
        committed_at: String,
        frames: Vec<ScreenStoryboardFrameResult>,
    ) -> Result<Self> {
        Self::build(
            ScreenStoryboardResultRequestContract::UnboundV1,
            account_id,
            vertex_event_id,
            vertex_attempt_commitment,
            work_unit_id,
            predecessor_commitment,
            requested_model,
            committed_at,
            frames,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn build(
        request_contract: ScreenStoryboardResultRequestContract,
        account_id: String,
        vertex_event_id: String,
        vertex_attempt_commitment: [u8; 32],
        work_unit_id: String,
        predecessor_commitment: [u8; 32],
        requested_model: String,
        committed_at: String,
        frames: Vec<ScreenStoryboardFrameResult>,
    ) -> Result<Self> {
        crate::store::validate_user_id(&account_id).map_err(|_| WalIdempotencyError::Malformed)?;
        validate_prefixed_hex(&vertex_event_id, "vtx_")?;
        if !valid_lower_hex(&work_unit_id, 64)
            || vertex_attempt_commitment == [0; 32]
            || predecessor_commitment == [0; 32]
            || requested_model.is_empty()
            || requested_model.len() > MAX_MODEL_BYTES
            || !super::super::super::vertex_model_name_is_billing_safe(&requested_model)
        {
            return Err(WalIdempotencyError::Malformed);
        }
        validate_canonical_timestamp(&committed_at)?;
        if frames.is_empty() || frames.len() > MAX_FRAMES {
            return Err(if frames.is_empty() {
                WalIdempotencyError::Malformed
            } else {
                WalIdempotencyError::Limit
            });
        }
        if frames
            .windows(2)
            .any(|pair| pair[0].event_id == pair[1].event_id)
            || has_duplicate(frames.iter().map(|frame| frame.event_id.as_str()))
            || has_duplicate(frames.iter().map(|frame| frame.screenshot_id))
        {
            return Err(WalIdempotencyError::Malformed);
        }
        let operation_id = match request_contract {
            ScreenStoryboardResultRequestContract::UnboundV1 => {
                WalLogicalOperationId::from_stable_source(
                    WalOperationKind::DeterministicMediaWorkResult,
                    vertex_event_id.as_bytes(),
                )?
            }
            ScreenStoryboardResultRequestContract::BoundV2 { .. } => {
                let mut source = Vec::with_capacity(
                    BOUND_OPERATION_SOURCE_DOMAIN
                        .len()
                        .saturating_add(vertex_event_id.len()),
                );
                source.extend_from_slice(BOUND_OPERATION_SOURCE_DOMAIN);
                source.extend_from_slice(vertex_event_id.as_bytes());
                WalLogicalOperationId::from_stable_source(
                    WalOperationKind::DeterministicMediaWorkResult,
                    &source,
                )?
            }
        };
        Ok(Self {
            operation_id,
            request_contract,
            account_id,
            vertex_event_id,
            vertex_attempt_commitment,
            work_unit_id,
            predecessor_commitment,
            requested_model,
            committed_at,
            frames,
        })
    }
}

pub(crate) struct ScreenStoryboardResultLedger;

impl WalLogicalDomainPlan for ScreenStoryboardResultPlan {
    type Ledger = ScreenStoryboardResultLedger;
    type Output = ();

    fn kind(&self) -> WalOperationKind {
        WalOperationKind::DeterministicMediaWorkResult
    }

    fn operation_id(&self) -> WalLogicalOperationId {
        self.operation_id
    }

    fn canonical_request(&self) -> Result<Zeroizing<Vec<u8>>> {
        let mut request = Zeroizing::new(Vec::with_capacity(64 * 1024));
        match self.request_contract {
            ScreenStoryboardResultRequestContract::UnboundV1 => {
                request.extend_from_slice(&REQUEST_V1.to_be_bytes());
                encode_bytes(&mut request, SUBTYPE_V1)?;
            }
            ScreenStoryboardResultRequestContract::BoundV2 {
                attempt_binding_commitment,
            } => {
                request.extend_from_slice(&REQUEST_V2.to_be_bytes());
                encode_bytes(&mut request, SUBTYPE_V2)?;
                request.extend_from_slice(&attempt_binding_commitment);
            }
        }
        encode_string(&mut request, &self.account_id)?;
        encode_string(&mut request, &self.vertex_event_id)?;
        request.extend_from_slice(&self.vertex_attempt_commitment);
        encode_string(&mut request, &self.work_unit_id)?;
        request.extend_from_slice(&self.predecessor_commitment);
        encode_string(&mut request, &self.requested_model)?;
        encode_string(&mut request, &self.committed_at)?;
        encode_len(&mut request, self.frames.len())?;
        for frame in &self.frames {
            encode_string(&mut request, &frame.event_id)?;
            request.extend_from_slice(&frame.screenshot_id.to_be_bytes());
            encode_string(&mut request, &frame.literal_description)?;
            encode_string(&mut request, &frame.screen_state)?;
            encode_string(&mut request, &frame.content_type)?;
            encode_string(&mut request, &frame.visible_text)?;
            encode_string(&mut request, &frame.salient_text)?;
        }
        Ok(request)
    }

    fn apply(&self, transaction: &Transaction<'_>) -> Result<WalReplayResult> {
        if current_screen_vertex_attempt_commitment(
            transaction,
            &self.vertex_event_id,
            &self.requested_model,
        )? != self.vertex_attempt_commitment
        {
            return Err(WalIdempotencyError::Precondition);
        }
        let authenticated = load_screen_work(transaction, &self.work_unit_id)?;
        if authenticated.commitment != self.predecessor_commitment
            || authenticated
                .members
                .iter()
                .map(|member| member.event_id.as_str())
                .ne(self.frames.iter().map(|frame| frame.event_id.as_str()))
        {
            return Err(WalIdempotencyError::Precondition);
        }
        if let Some(bound_attempt) = self.authenticate_attempt_binding(transaction)? {
            if hash_screen_work_attempt(transaction, &self.work_unit_id)? != bound_attempt {
                return Err(WalIdempotencyError::Precondition);
            }
        }
        validate_commit_time(transaction, self, &authenticated)?;
        let browser_snapshot_source_keys =
            resolve_browser_snapshot_source_keys(transaction, &authenticated.members)?;
        ensure_targets_absent(transaction, &self.frames)?;
        for ((member, frame), browser_snapshot_source_key) in authenticated
            .members
            .iter()
            .zip(&self.frames)
            .zip(&browser_snapshot_source_keys)
        {
            write_frame(
                transaction,
                self,
                member,
                frame,
                browser_snapshot_source_key.as_deref(),
            )?;
            settle_job(transaction, self, member)?;
            settle_media(transaction, member)?;
        }
        settle_work(transaction, self, &authenticated.work)?;
        verify_final_state(
            transaction,
            self,
            &authenticated,
            &browser_snapshot_source_keys,
        )?;
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

impl ScreenStoryboardResultPlan {
    fn authenticate_attempt_binding(&self, connection: &Connection) -> Result<Option<[u8; 32]>> {
        match self.request_contract {
            ScreenStoryboardResultRequestContract::UnboundV1 => Ok(None),
            ScreenStoryboardResultRequestContract::BoundV2 {
                attempt_binding_commitment,
            } => super::attempt::authenticate_screen_storyboard_attempt_binding(
                connection,
                &self.account_id,
                &self.vertex_event_id,
                &self.work_unit_id,
                &self.requested_model,
                &attempt_binding_commitment,
            )
            .map(Some),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum LedgerSchemaState {
    Absent,
    Present,
}

impl WalLogicalDomainLedger<ScreenStoryboardResultPlan> for ScreenStoryboardResultLedger {
    fn lookup(
        connection: &Connection,
        prepared: &PreparedLogicalMutation<ScreenStoryboardResultPlan>,
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
                 FROM archive_v3_wal_screen_storyboard_result_operations
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
        let _ = prepared
            .plan_for_domain_ledger()
            .authenticate_attempt_binding(connection)?;
        Ok(Some(result))
    }

    fn resolve_or_apply(
        transaction: &Transaction<'_>,
        prepared: &PreparedLogicalMutation<ScreenStoryboardResultPlan>,
    ) -> Result<LogicalMutationResult> {
        require_kind(prepared)?;
        ensure_schema(transaction)?;
        if let Some(result) = Self::lookup(transaction, prepared)? {
            return Ok(LogicalMutationResult::Replayed(result));
        }
        let (row_count, result_bytes) = load_ledger_state(transaction)?;
        BOUNDS.admit(row_count, result_bytes, ENCODED_UNIT_RESULT_BYTES)?;
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
                "INSERT INTO archive_v3_wal_screen_storyboard_result_operations
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
                "UPDATE archive_v3_wal_screen_storyboard_result_state
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
    job: StoredJob,
    media: StoredMedia,
}

struct AuthenticatedScreenWork {
    commitment: [u8; 32],
    work: StoredWork,
    members: Vec<StoredMember>,
}

#[derive(Clone, PartialEq, Eq)]
struct ScreenContext {
    active_app: Option<String>,
    window_title: Option<String>,
    active_url: Option<String>,
    display_id: Option<i64>,
    capture_status: Option<String>,
    primary_bundle_id: Option<String>,
    primary_window_id: Option<i64>,
    browser_state_key: Option<String>,
    visible_windows_json: Option<String>,
    visible_windows_truncated: i64,
}

struct StoredBrowserV2Evidence {
    device_id: String,
    source_wall_at: String,
    observation_id: String,
    observed_at: String,
    state_key: Option<String>,
    context_status: String,
    active_url: Option<String>,
    active_title: Option<String>,
    browser_bundle_id: String,
    browser_name: String,
    permission_status: String,
    content_hash: String,
    tabs_json: String,
}

#[derive(PartialEq, Eq)]
struct StoredScreenshot {
    captured_at: String,
    active_app: Option<String>,
    window_title: Option<String>,
    ocr_text: Option<String>,
    salient_ocr_text: Option<String>,
    url: Option<String>,
    image_hash: Option<String>,
    source_key: Option<String>,
    created_at: String,
    display_id: Option<i64>,
    capture_context_version: Option<i64>,
    capture_status: Option<String>,
    primary_bundle_id: Option<String>,
    primary_window_id: Option<i64>,
    visible_windows_json: Option<String>,
    visible_windows_truncated: i64,
    ocr_status: String,
    is_duplicate: i64,
    capture_group_id: Option<String>,
    visual_signals_json: Option<String>,
    semantic_context_hash: Option<String>,
    browser_snapshot_source_key: Option<String>,
    duplicate_of_id: Option<i64>,
    visible_until: Option<String>,
    dedupe_version: i64,
}

pub(in crate::cp::media_worker) fn current_screen_vertex_attempt_commitment(
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
    if operation != "screen_understanding"
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
    hasher.update(b"archive-v3-screen-storyboard-vertex-attempt-v1\0");
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

pub(in crate::cp::media_worker) fn current_screen_work_predecessor_commitment(
    connection: &Connection,
    work_unit_id: &str,
) -> Result<[u8; 32]> {
    Ok(load_screen_work(connection, work_unit_id)?.commitment)
}

/// Exact pre-provider state plus its stable attempt identity. The predecessor
/// covers every authenticated field. The attempt identity excludes only the
/// usage fields and work timestamp that the already-reviewed post-provider
/// usage settlement is expected to replace; lease, counters, membership,
/// inputs, and media provenance remain covered.
pub(in crate::cp::media_worker) struct ScreenWorkAttemptCommitments {
    predecessor: [u8; 32],
    attempt: [u8; 32],
}

impl ScreenWorkAttemptCommitments {
    pub(in crate::cp::media_worker) const fn predecessor(&self) -> [u8; 32] {
        self.predecessor
    }

    pub(in crate::cp::media_worker) const fn attempt(&self) -> [u8; 32] {
        self.attempt
    }
}

pub(in crate::cp::media_worker) fn current_screen_work_attempt_commitments(
    connection: &Connection,
    work_unit_id: &str,
    attempted_at: &str,
) -> Result<ScreenWorkAttemptCommitments> {
    validate_canonical_timestamp(attempted_at)?;
    let (work, members) = load_screen_work_rows(connection, work_unit_id)?;
    validate_screen_work_for_stage(work_unit_id, &work, &members, ScreenWorkStage::Reserved)?;
    validate_attempt_time(attempted_at, &work, &members)?;
    Ok(ScreenWorkAttemptCommitments {
        predecessor: hash_screen_work(connection, work_unit_id)?,
        attempt: hash_screen_work_attempt(connection, work_unit_id)?,
    })
}

fn load_screen_work(
    connection: &Connection,
    work_unit_id: &str,
) -> Result<AuthenticatedScreenWork> {
    let (work, members) = load_screen_work_rows(connection, work_unit_id)?;
    validate_screen_work(work_unit_id, &work, &members)?;
    let commitment = hash_screen_work(connection, work_unit_id)?;
    Ok(AuthenticatedScreenWork {
        commitment,
        work,
        members,
    })
}

fn load_screen_work_rows(
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
                    e.canonical_media_sha256,
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
        job: StoredJob {
            id: row.get(14)?,
            event_id: row.get(15)?,
            job_kind: row.get(16)?,
            input_revision: row.get(17)?,
            processor_version: row.get(18)?,
            state: row.get(19)?,
            attempt_count: row.get(20)?,
            lease_until: row.get(21)?,
            error_code: row.get(22)?,
            model_id: row.get(23)?,
            prompt_version: row.get(24)?,
            schema_version: row.get(25)?,
            usage_json: row.get(26)?,
            updated_at: row.get(27)?,
        },
        media: StoredMedia {
            asset_id: row.get(28)?,
            event_id: row.get(29)?,
            object_key: row.get(30)?,
            object_generation: row.get(31)?,
            object_backend: row.get(32)?,
            mime_type: row.get(33)?,
            codec: row.get(34)?,
            byte_length: row.get(35)?,
            sha256: row.get(36)?,
            sample_rate: row.get(37)?,
            channels: row.get(38)?,
            frame_count: row.get(39)?,
            width: row.get(40)?,
            height: row.get(41)?,
            scale: row.get(42)?,
            orientation: row.get(43)?,
            processing_state: row.get(44)?,
            retain_until: row.get(45)?,
            deleted_at: row.get(46)?,
            created_at: row.get(47)?,
        },
    })
}

fn validate_screen_work(
    work_unit_id: &str,
    work: &StoredWork,
    members: &[StoredMember],
) -> Result<()> {
    validate_screen_work_for_stage(work_unit_id, work, members, ScreenWorkStage::Terminal)
}

#[derive(Clone, Copy)]
enum ScreenWorkStage {
    Reserved,
    Terminal,
}

fn validate_screen_work_for_stage(
    work_unit_id: &str,
    work: &StoredWork,
    members: &[StoredMember],
    stage: ScreenWorkStage,
) -> Result<()> {
    if work.work_class != "screen"
        || work.processor_version != PROCESSOR_VERSION
        || work.state != "processing"
        || work.reserved_output_tokens
            != i64::from(super::super::super::vertex::MAX_SCREEN_OUTPUT_TOKENS)
        || work.reservation_retained != 1
        || work.attempt_count <= 0
        || work.error_code.is_some()
        || members.is_empty()
        || members.len() > MAX_FRAMES
        || !valid_timestamp(&work.started_at)
        || !valid_timestamp(&work.ended_at)
        || !valid_timestamp(&work.created_at)
        || !valid_timestamp(&work.updated_at)
        || timestamp_millis(&work.started_at)? > timestamp_millis(&work.ended_at)?
    {
        return Err(WalIdempotencyError::Precondition);
    }
    let usage = work
        .usage_json
        .as_deref()
        .ok_or(WalIdempotencyError::Precondition)?;
    match stage {
        ScreenWorkStage::Reserved => validate_reserved_usage(usage, work_unit_id, members.len())?,
        ScreenWorkStage::Terminal => validate_terminal_usage(usage, work_unit_id, members.len())?,
    }
    let work_start = timestamp_millis(&work.started_at)?;
    let work_end = timestamp_millis(&work.ended_at)?;
    for (index, member) in members.iter().enumerate() {
        let ordinal = i64::try_from(index).map_err(|_| WalIdempotencyError::Limit)?;
        if member.ordinal != ordinal
            || member.job_id != member.job.id
            || member.event_id != member.job.event_id
            || member.event_id != member.media.event_id
            || member.job.job_kind != "gemini_screen"
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
            || !member.media.mime_type.starts_with("image/")
            || member.media.width.is_none_or(|value| value <= 0)
            || member.media.height.is_none_or(|value| value <= 0)
            || member.media.sample_rate.is_some()
            || member.media.channels.is_some()
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
            || parse_screen_context(member.context_json.as_deref()).is_err()
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
    plan: &ScreenStoryboardResultPlan,
    authenticated: &AuthenticatedScreenWork,
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
        || value.get("work_class").and_then(serde_json::Value::as_str) != Some("screen")
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
                super::super::super::vertex::MAX_SCREEN_OUTPUT_TOKENS,
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
        || value.get("work_class").and_then(serde_json::Value::as_str) != Some("screen")
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

fn hash_screen_work(connection: &Connection, work_unit_id: &str) -> Result<[u8; 32]> {
    let mut hasher = Sha256::new();
    hasher.update(b"archive-v3-screen-storyboard-predecessor-v1\0");
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
                    e.context_fingerprint,e.dedupe_version,e.received_at
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
        (
            b"browser-v2".as_slice(),
            "SELECT m.event_id,o.observation_id,o.observed_at,o.state_key,o.context_status,
                    o.active_url,o.active_title,o.created_at,s.state_key,s.browser_bundle_id,
                    s.browser_name,s.permission_status,s.content_hash,s.tabs_json,s.created_at
             FROM media_work_members m
             LEFT JOIN browser_observations_v2 o ON o.event_id=m.event_id
             LEFT JOIN browser_states_v2 s ON s.state_key=o.state_key
             WHERE m.work_unit_id=?1 ORDER BY m.ordinal",
        ),
    ] {
        hash_query(connection, &mut hasher, marker, query, work_unit_id)?;
    }
    Ok(hasher.finalize().into())
}

fn hash_screen_work_attempt(connection: &Connection, work_unit_id: &str) -> Result<[u8; 32]> {
    let mut hasher = Sha256::new();
    hasher.update(b"archive-v3-screen-storyboard-work-attempt-v1\0");
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
                    e.context_fingerprint,e.dedupe_version,e.received_at
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

fn ensure_targets_absent(
    transaction: &Transaction<'_>,
    frames: &[ScreenStoryboardFrameResult],
) -> Result<()> {
    for frame in frames {
        let source_key = format!("cloud-v2:{}", frame.event_id);
        let screenshot_count = transaction
            .query_row(
                "SELECT COUNT(*) FROM screenshots WHERE id=?1 OR source_key=?2",
                params![frame.screenshot_id, source_key],
                |row| row.get::<_, i64>(0),
            )
            .map_err(|_| WalIdempotencyError::Unavailable)?;
        let observation_count = transaction
            .query_row(
                "SELECT COUNT(*) FROM screen_observations WHERE screenshot_id=?1",
                [frame.screenshot_id],
                |row| row.get::<_, i64>(0),
            )
            .map_err(|_| WalIdempotencyError::Unavailable)?;
        let evidence_count = transaction
            .query_row(
                "SELECT
                   (SELECT COUNT(*) FROM identity_evidence WHERE source_event_id=?1) +
                   (SELECT COUNT(*) FROM person_name_claims WHERE source_event_id=?1)",
                [&frame.event_id],
                |row| row.get::<_, i64>(0),
            )
            .map_err(|_| WalIdempotencyError::Unavailable)?;
        if screenshot_count != 0 || observation_count != 0 || evidence_count != 0 {
            return Err(WalIdempotencyError::Precondition);
        }
    }
    Ok(())
}

fn parse_screen_context(raw: Option<&str>) -> Result<ScreenContext> {
    let value = match raw {
        None => serde_json::json!({}),
        Some(raw) => {
            if raw.len() > MAX_CONTEXT_BYTES || raw.contains('\0') {
                return Err(WalIdempotencyError::Precondition);
            }
            serde_json::from_str(raw).map_err(|_| WalIdempotencyError::Precondition)?
        }
    };
    if !value.is_object() {
        return Err(WalIdempotencyError::Precondition);
    }
    let string = |key: &str| -> Result<Option<String>> {
        let value = value.get(key).and_then(serde_json::Value::as_str);
        if value.is_some_and(|value| value.len() > MAX_CONTEXT_BYTES || value.contains('\0')) {
            return Err(WalIdempotencyError::Precondition);
        }
        Ok(value.map(str::to_owned))
    };
    let visible_windows_json = value
        .get("visible_windows")
        .map(serde_json::Value::to_string);
    if visible_windows_json
        .as_deref()
        .is_some_and(|value| value.len() > MAX_CONTEXT_BYTES || value.contains('\0'))
    {
        return Err(WalIdempotencyError::Precondition);
    }
    Ok(ScreenContext {
        active_app: string("active_app")?,
        window_title: string("window_title")?,
        active_url: string("active_url")?,
        display_id: value.get("display_id").and_then(serde_json::Value::as_i64),
        capture_status: string("capture_status")?,
        primary_bundle_id: string("primary_bundle_id")?,
        primary_window_id: value
            .get("primary_window_id")
            .and_then(serde_json::Value::as_i64),
        browser_state_key: string("browser_state_key")?,
        visible_windows_json,
        visible_windows_truncated: i64::from(
            value
                .get("visible_windows_truncated")
                .and_then(serde_json::Value::as_bool)
                .unwrap_or(false),
        ),
    })
}

fn resolve_browser_snapshot_source_keys(
    transaction: &Transaction<'_>,
    members: &[StoredMember],
) -> Result<Vec<Option<String>>> {
    let mut source_keys = Vec::with_capacity(members.len());
    for member in members {
        let observed_state_key = transaction
            .query_row(
                "SELECT state_key FROM browser_observations_v2 WHERE event_id=?1",
                [&member.event_id],
                |row| row.get::<_, Option<String>>(0),
            )
            .optional()
            .map_err(|_| WalIdempotencyError::Unavailable)?
            .flatten();
        let observation_carries_browser_v2 = observed_state_key
            .as_deref()
            .is_some_and(|key| key.contains(":browser-v2:"));
        let Some(raw_context) = member.context_json.as_deref() else {
            if observation_carries_browser_v2 {
                return Err(WalIdempotencyError::Precondition);
            }
            source_keys.push(None);
            continue;
        };
        let legacy_context = parse_screen_context(Some(raw_context))?;
        let raw_value: serde_json::Value =
            serde_json::from_str(raw_context).map_err(|_| WalIdempotencyError::Precondition)?;
        let context_carries_browser_v2 = legacy_context
            .browser_state_key
            .as_deref()
            .is_some_and(|key| key.contains(":browser-v2:"))
            || raw_value
                .get("browser_snapshot")
                .and_then(|snapshot| snapshot.get("state_key"))
                .and_then(serde_json::Value::as_str)
                .is_some_and(|key| key.contains(":browser-v2:"));
        if !context_carries_browser_v2 && !observation_carries_browser_v2 {
            source_keys.push(None);
            continue;
        }
        let full_context: crate::cp::media::CaptureContext =
            serde_json::from_value(raw_value).map_err(|_| WalIdempotencyError::Precondition)?;
        let evidence = transaction
            .query_row(
                "SELECT e.device_id,e.source_wall_at,o.observation_id,o.observed_at,o.state_key,
                        o.context_status,o.active_url,o.active_title,s.browser_bundle_id,
                        s.browser_name,s.permission_status,s.content_hash,s.tabs_json
                 FROM capture_events e
                 JOIN browser_observations_v2 o ON o.event_id=e.event_id
                 JOIN browser_states_v2 s ON s.state_key=o.state_key
                 WHERE e.event_id=?1",
                [&member.event_id],
                |row| {
                    Ok(StoredBrowserV2Evidence {
                        device_id: row.get(0)?,
                        source_wall_at: row.get(1)?,
                        observation_id: row.get(2)?,
                        observed_at: row.get(3)?,
                        state_key: row.get(4)?,
                        context_status: row.get(5)?,
                        active_url: row.get(6)?,
                        active_title: row.get(7)?,
                        browser_bundle_id: row.get(8)?,
                        browser_name: row.get(9)?,
                        permission_status: row.get(10)?,
                        content_hash: row.get(11)?,
                        tabs_json: row.get(12)?,
                    })
                },
            )
            .optional()
            .map_err(|_| WalIdempotencyError::Unavailable)?
            .ok_or(WalIdempotencyError::Precondition)?;
        crate::cp::media::validate_browser_v2_persisted_evidence(
            &full_context,
            crate::cp::media::BrowserV2PersistedEvidence {
                event_id: &member.event_id,
                device_id: &evidence.device_id,
                source_wall_at: &evidence.source_wall_at,
                observation_id: &evidence.observation_id,
                observed_at: &evidence.observed_at,
                state_key: evidence.state_key.as_deref(),
                context_status: &evidence.context_status,
                active_url: evidence.active_url.as_deref(),
                active_title: evidence.active_title.as_deref(),
                browser_bundle_id: &evidence.browser_bundle_id,
                browser_name: &evidence.browser_name,
                permission_status: &evidence.permission_status,
                content_hash: &evidence.content_hash,
                tabs_json: &evidence.tabs_json,
            },
        )
        .map_err(|_| WalIdempotencyError::Precondition)?;
        source_keys.push(Some(format!("capture-v2-browser:{}", member.event_id)));
    }
    Ok(source_keys)
}

fn write_frame(
    transaction: &Transaction<'_>,
    plan: &ScreenStoryboardResultPlan,
    member: &StoredMember,
    frame: &ScreenStoryboardFrameResult,
    browser_snapshot_source_key: Option<&str>,
) -> Result<()> {
    let context = parse_screen_context(member.context_json.as_deref())?;
    let changed = transaction
        .execute(
            "INSERT INTO screenshots
             (id,captured_at,active_app,window_title,ocr_text,salient_ocr_text,url,ocr_status,
              image_hash,is_duplicate,source_key,created_at,display_id,capture_context_version,
              capture_status,primary_bundle_id,primary_window_id,visible_windows_json,
              visible_windows_truncated,capture_group_id,visual_signals_json,
              semantic_context_hash,browser_snapshot_source_key,duplicate_of_id,
              visible_until,dedupe_version)
             VALUES (?1,?2,?3,?4,?5,?6,?7,'done',?8,0,?9,?10,?11,2,?12,?13,?14,
                     ?15,?16,NULL,NULL,NULL,?17,NULL,NULL,1)",
            params![
                frame.screenshot_id,
                member.capture_started_at,
                context.active_app,
                context.window_title,
                frame.visible_text,
                frame.salient_text,
                context.active_url,
                member.media.sha256,
                format!("cloud-v2:{}", member.event_id),
                plan.committed_at,
                context.display_id,
                context.capture_status,
                context.primary_bundle_id,
                context.primary_window_id,
                context.visible_windows_json,
                context.visible_windows_truncated,
                browser_snapshot_source_key,
            ],
        )
        .map_err(|_| WalIdempotencyError::Unavailable)?;
    if changed != 1 {
        return Err(WalIdempotencyError::Corrupt);
    }
    let changed = transaction
        .execute(
            "INSERT INTO screen_observations
             (screenshot_id,input_revision,observation_version,status,generation_method,
              literal_description,screen_state,content_type,visible_text_summary,
              notable_items_json,model_name,prompt_version,completed_at)
             VALUES (?1,?2,?3,'ready','gemini_pixels',?4,?5,?6,?7,'[]',?8,?9,?10)",
            params![
                frame.screenshot_id,
                member.media.sha256,
                OBSERVATION_VERSION,
                frame.literal_description,
                frame.screen_state,
                frame.content_type,
                frame.salient_text,
                plan.requested_model,
                PROMPT_VERSION,
                plan.committed_at,
            ],
        )
        .map_err(|_| WalIdempotencyError::Unavailable)?;
    if changed != 1 {
        return Err(WalIdempotencyError::Corrupt);
    }
    Ok(())
}

fn settle_job(
    transaction: &Transaction<'_>,
    plan: &ScreenStoryboardResultPlan,
    member: &StoredMember,
) -> Result<()> {
    let job = &member.job;
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
                PROMPT_VERSION,
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
    plan: &ScreenStoryboardResultPlan,
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

fn verify_final_state(
    transaction: &Transaction<'_>,
    plan: &ScreenStoryboardResultPlan,
    authenticated: &AuthenticatedScreenWork,
    browser_snapshot_source_keys: &[Option<String>],
) -> Result<()> {
    if browser_snapshot_source_keys.len() != authenticated.members.len() {
        return Err(WalIdempotencyError::Corrupt);
    }
    for ((member, frame), browser_snapshot_source_key) in authenticated
        .members
        .iter()
        .zip(&plan.frames)
        .zip(browser_snapshot_source_keys)
    {
        let context = parse_screen_context(member.context_json.as_deref())?;
        let screenshot = transaction
            .query_row(
                "SELECT captured_at,active_app,window_title,ocr_text,salient_ocr_text,url,
                        image_hash,source_key,created_at,display_id,capture_context_version,
                        capture_status,primary_bundle_id,primary_window_id,visible_windows_json,
                        visible_windows_truncated,ocr_status,is_duplicate,capture_group_id,
                        visual_signals_json,semantic_context_hash,browser_snapshot_source_key,
                        duplicate_of_id,visible_until,dedupe_version
                 FROM screenshots WHERE id=?1",
                [frame.screenshot_id],
                |row| {
                    Ok(StoredScreenshot {
                        captured_at: row.get(0)?,
                        active_app: row.get(1)?,
                        window_title: row.get(2)?,
                        ocr_text: row.get(3)?,
                        salient_ocr_text: row.get(4)?,
                        url: row.get(5)?,
                        image_hash: row.get(6)?,
                        source_key: row.get(7)?,
                        created_at: row.get(8)?,
                        display_id: row.get(9)?,
                        capture_context_version: row.get(10)?,
                        capture_status: row.get(11)?,
                        primary_bundle_id: row.get(12)?,
                        primary_window_id: row.get(13)?,
                        visible_windows_json: row.get(14)?,
                        visible_windows_truncated: row.get(15)?,
                        ocr_status: row.get(16)?,
                        is_duplicate: row.get(17)?,
                        capture_group_id: row.get(18)?,
                        visual_signals_json: row.get(19)?,
                        semantic_context_hash: row.get(20)?,
                        browser_snapshot_source_key: row.get(21)?,
                        duplicate_of_id: row.get(22)?,
                        visible_until: row.get(23)?,
                        dedupe_version: row.get(24)?,
                    })
                },
            )
            .map_err(|_| WalIdempotencyError::Corrupt)?;
        if screenshot
            != (StoredScreenshot {
                captured_at: member.capture_started_at.clone(),
                active_app: context.active_app,
                window_title: context.window_title,
                ocr_text: Some(frame.visible_text.clone()),
                salient_ocr_text: Some(frame.salient_text.clone()),
                url: context.active_url,
                image_hash: Some(member.media.sha256.clone()),
                source_key: Some(format!("cloud-v2:{}", member.event_id)),
                created_at: plan.committed_at.clone(),
                display_id: context.display_id,
                capture_context_version: Some(2),
                capture_status: context.capture_status,
                primary_bundle_id: context.primary_bundle_id,
                primary_window_id: context.primary_window_id,
                visible_windows_json: context.visible_windows_json,
                visible_windows_truncated: context.visible_windows_truncated,
                ocr_status: "done".into(),
                is_duplicate: 0,
                capture_group_id: None,
                visual_signals_json: None,
                semantic_context_hash: None,
                browser_snapshot_source_key: browser_snapshot_source_key.clone(),
                duplicate_of_id: None,
                visible_until: None,
                dedupe_version: 1,
            })
        {
            return Err(WalIdempotencyError::Corrupt);
        }
        let observation = transaction
            .query_row(
                "SELECT input_revision,observation_version,status,generation_method,
                        literal_description,screen_state,content_type,visible_text_summary,
                        notable_items_json,model_name,prompt_version,completed_at
                 FROM screen_observations WHERE screenshot_id=?1",
                [frame.screenshot_id],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, String>(4)?,
                        row.get::<_, String>(5)?,
                        row.get::<_, String>(6)?,
                        row.get::<_, Option<String>>(7)?,
                        row.get::<_, String>(8)?,
                        row.get::<_, Option<String>>(9)?,
                        row.get::<_, i64>(10)?,
                        row.get::<_, String>(11)?,
                    ))
                },
            )
            .map_err(|_| WalIdempotencyError::Corrupt)?;
        if observation
            != (
                member.media.sha256.clone(),
                OBSERVATION_VERSION,
                "ready".into(),
                "gemini_pixels".into(),
                frame.literal_description.clone(),
                frame.screen_state.clone(),
                frame.content_type.clone(),
                Some(frame.salient_text.clone()),
                "[]".into(),
                Some(plan.requested_model.clone()),
                PROMPT_VERSION,
                plan.committed_at.clone(),
            )
        {
            return Err(WalIdempotencyError::Corrupt);
        }
        let job = load_job(transaction, member.job.id)?;
        let mut expected_job = member.job.clone();
        expected_job.state = "succeeded".into();
        expected_job.lease_until = None;
        expected_job.error_code = None;
        expected_job.model_id = Some(plan.requested_model.clone());
        expected_job.prompt_version = Some(PROMPT_VERSION);
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
    for frame in &plan.frames {
        let evidence_count = transaction
            .query_row(
                "SELECT
                   (SELECT COUNT(*) FROM identity_evidence WHERE source_event_id=?1) +
                   (SELECT COUNT(*) FROM person_name_claims WHERE source_event_id=?1)",
                [&frame.event_id],
                |row| row.get::<_, i64>(0),
            )
            .map_err(|_| WalIdempotencyError::Corrupt)?;
        if evidence_count != 0 {
            return Err(WalIdempotencyError::Corrupt);
        }
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

fn require_kind(prepared: &PreparedLogicalMutation<ScreenStoryboardResultPlan>) -> Result<()> {
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
                    "CREATE TABLE archive_v3_wal_screen_storyboard_result_schema (
                        singleton INTEGER PRIMARY KEY CHECK(singleton=1),
                        format_version INTEGER NOT NULL CHECK(format_version=1),
                        codec_version INTEGER NOT NULL CHECK(codec_version=1)
                     ) STRICT;
                     CREATE TABLE archive_v3_wal_screen_storyboard_result_operations (
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
                     CREATE TABLE archive_v3_wal_screen_storyboard_result_state (
                        singleton INTEGER PRIMARY KEY CHECK(singleton=1),
                        row_count INTEGER NOT NULL CHECK(row_count BETWEEN 0 AND 1048576),
                        result_bytes INTEGER NOT NULL CHECK(result_bytes BETWEEN 0 AND 33554432)
                     ) STRICT;
                     INSERT INTO archive_v3_wal_screen_storyboard_result_schema
                        (singleton,format_version,codec_version) VALUES (1,1,1);
                     INSERT INTO archive_v3_wal_screen_storyboard_result_state
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
             FROM archive_v3_wal_screen_storyboard_result_schema WHERE singleton=1",
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
             FROM archive_v3_wal_screen_storyboard_result_state WHERE singleton=1",
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

fn validate_id(value: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > MAX_ID_BYTES
        || value.contains('\0')
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
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

fn validate_text(value: &str, max_bytes: usize, nonempty: bool) -> Result<()> {
    if value.len() > max_bytes || value.contains('\0') || (nonempty && value.trim().is_empty()) {
        return Err(WalIdempotencyError::Malformed);
    }
    Ok(())
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
        execute_prepared_for_owner, LogicalMutationDisposition,
    };
    use tempfile::tempdir;

    pub(in crate::cp::media_worker::wal) const ACCOUNT: &str =
        "11111111-1111-4111-8111-111111111111";
    const VERTEX_ONE: &str = "vtx_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const VERTEX_TWO: &str = "vtx_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    pub(in crate::cp::media_worker::wal) const WORK_ONE: &str =
        "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
    pub(in crate::cp::media_worker::wal) const WORK_TWO: &str =
        "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";
    pub(in crate::cp::media_worker::wal) const MODEL: &str = "gemini-3.5-flash";
    const COMMITTED_AT: &str = "2026-08-15T15:00:03.000Z";
    const STARTED_AT: &str = "2026-08-15T15:00:00.000Z";
    const ENDED_AT: &str = "2026-08-15T15:00:01.000Z";
    pub(in crate::cp::media_worker::wal) const LEASE_UNTIL: &str = "2026-08-15T15:05:00.000Z";
    const CREATED_AT: &str = "2026-08-15T14:59:59.000Z";
    pub(in crate::cp::media_worker::wal) const UPDATED_AT: &str = "2026-08-15T15:00:02.000Z";
    const SHA_ONE: &str = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";
    const SHA_TWO: &str = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";

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
                    received_at TEXT NOT NULL
                 ) STRICT;
                 CREATE TABLE browser_states_v2 (
                    state_key TEXT PRIMARY KEY,browser_bundle_id TEXT NOT NULL,
                    browser_name TEXT NOT NULL,permission_status TEXT NOT NULL,
                    content_hash TEXT NOT NULL,tabs_json TEXT NOT NULL,created_at TEXT NOT NULL
                 ) STRICT;
                 CREATE TABLE browser_observations_v2 (
                    observation_id TEXT PRIMARY KEY,event_id TEXT NOT NULL UNIQUE,
                    observed_at TEXT NOT NULL,state_key TEXT,context_status TEXT NOT NULL,
                    active_url TEXT,active_title TEXT,created_at TEXT NOT NULL,
                    FOREIGN KEY(state_key) REFERENCES browser_states_v2(state_key)
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
                 CREATE TABLE screenshots (
                    id INTEGER PRIMARY KEY,captured_at TEXT NOT NULL,active_app TEXT,window_title TEXT,
                    ocr_text TEXT,salient_ocr_text TEXT,url TEXT,ocr_status TEXT NOT NULL DEFAULT 'done',
                    image_hash TEXT,is_duplicate INTEGER NOT NULL DEFAULT 0,source_key TEXT UNIQUE,
                    created_at TEXT NOT NULL,display_id INTEGER,capture_context_version INTEGER,
                    capture_status TEXT,primary_bundle_id TEXT,primary_window_id INTEGER,
                    capture_group_id TEXT,visible_windows_json TEXT,
                    visible_windows_truncated INTEGER NOT NULL DEFAULT 0,visual_signals_json TEXT,
                    semantic_context_hash TEXT,browser_snapshot_source_key TEXT,
                    duplicate_of_id INTEGER,visible_until TEXT,dedupe_version INTEGER NOT NULL DEFAULT 1
                 ) STRICT;
                 CREATE TABLE screen_observations (
                    screenshot_id INTEGER PRIMARY KEY,input_revision TEXT NOT NULL,
                    observation_version INTEGER NOT NULL,status TEXT NOT NULL,generation_method TEXT NOT NULL,
                    literal_description TEXT NOT NULL,screen_state TEXT NOT NULL,content_type TEXT NOT NULL,
                    visible_text_summary TEXT,notable_items_json TEXT NOT NULL,model_name TEXT,
                    prompt_version INTEGER NOT NULL,completed_at TEXT NOT NULL
                 ) STRICT;
                 CREATE TABLE identity_evidence (id INTEGER PRIMARY KEY,source_event_id TEXT);
                 CREATE TABLE person_name_claims (id INTEGER PRIMARY KEY,source_event_id TEXT);",
            )
            .unwrap();
    }

    pub(super) fn connection() -> Connection {
        let connection = Connection::open_in_memory().unwrap();
        install_schema(&connection);
        connection
    }

    fn usage(work: &str, count: usize) -> String {
        serde_json::json!({
            "work_unit_id": work,
            "work_class": "screen",
            "member_count": count,
            "reservation_state": "reserved",
            "reserved_output_tokens": 1024,
            "processor_version": 1,
            "outcome": "model_returned"
        })
        .to_string()
    }

    pub(in crate::cp::media_worker::wal) fn seed_work(
        connection: &Connection,
        work: &str,
        vertex: &str,
        base: i64,
        count: usize,
    ) {
        connection
            .execute(
                "INSERT INTO vertex_usage_events
                 (event_id,operation,requested_model,returned_model,location,traffic_type,http_status,
                  prompt_tokens,input_text_tokens,input_audio_tokens,input_image_tokens,cached_input_tokens,
                  cached_input_text_tokens,cached_input_audio_tokens,cached_input_image_tokens,
                  output_text_tokens,thought_tokens,total_tokens,outcome,delivery_state,
                  delivery_attempt_count,observed_at,updated_at)
                 VALUES (?1,'screen_understanding',?2,?2,'us-central1','on_demand',200,
                         100,0,0,100,0,0,0,0,50,0,150,'metered','pending',0,?3,?3)",
                params![vertex, MODEL, UPDATED_AT],
            )
            .unwrap();
        let usage = usage(work, count);
        connection
            .execute(
                "INSERT INTO media_work_units
                 (id,work_class,processor_version,state,started_at,ended_at,reserved_output_tokens,
                  reservation_retained,attempt_count,error_code,usage_json,created_at,updated_at)
                 VALUES (?1,'screen',1,'processing',?2,?3,1024,1,1,NULL,?4,?5,?6)",
                params![work, STARTED_AT, ENDED_AT, usage, CREATED_AT, UPDATED_AT],
            )
            .unwrap();
        for index in 0..count {
            let number = base + i64::try_from(index).unwrap();
            let event = format!("screen-event-{number}");
            let asset = format!("screen-asset-{number}");
            let sha = if index % 2 == 0 { SHA_ONE } else { SHA_TWO };
            connection
                .execute(
                    "INSERT INTO capture_events
                     (event_id,device_id,install_id,capture_session_id,stream_id,stream_kind,sequence,
                      source_wall_at,source_monotonic_ns,started_at,ended_at,timezone_id,
                      utc_offset_minutes,clock_uncertainty_ms,asset_id,manifest_digest,context_json,
                      media_disposition,canonical_event_id,canonical_asset_id,canonical_media_sha256,
                      perceptual_hash,hamming_distance,pixel_change_ratio,context_fingerprint,
                      dedupe_version,received_at)
                     VALUES (?1,'device','install','session','stream','screen',?2,?3,'1',?3,?4,
                             'America/New_York',-240,1,?5,?6,?7,'canonical',NULL,NULL,NULL,
                             NULL,NULL,NULL,NULL,NULL,?8)",
                    params![
                        event,
                        number,
                        STARTED_AT,
                        ENDED_AT,
                        asset,
                        sha,
                        serde_json::json!({
                            "active_app":"Safari",
                            "window_title":"Review",
                            "active_url":"https://example.com",
                            "display_id":1,
                            "capture_status":"complete",
                            "primary_bundle_id":"com.apple.Safari",
                            "primary_window_id":7,
                            "visible_windows":[],
                            "visible_windows_truncated":false
                        }).to_string(),
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
                     VALUES (?1,?2,?3,7,'current','image/jpeg','jpeg',1000,?4,NULL,NULL,1,
                             1440,900,1.0,'up','processing',?5,NULL,?6)",
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
            let job_id = number;
            connection
                .execute(
                    "INSERT INTO media_processing_jobs
                     (id,event_id,job_kind,input_revision,processor_version,state,attempt_count,
                      lease_until,error_code,model_id,prompt_version,schema_version,usage_json,updated_at)
                     VALUES (?1,?2,'gemini_screen',?3,1,'processing',1,?4,NULL,NULL,NULL,NULL,?5,?6)",
                    params![job_id, event, sha, LEASE_UNTIL, usage, UPDATED_AT],
                )
                .unwrap();
            connection
                .execute(
                    "INSERT INTO media_work_members
                     (work_unit_id,event_id,job_id,ordinal,window_start_ms,window_end_ms)
                     VALUES (?1,?2,?3,?4,0,1000)",
                    params![work, event, job_id, i64::try_from(index).unwrap()],
                )
                .unwrap();
        }
    }

    fn frames(base: i64, count: usize, suffix: &str) -> Vec<ScreenStoryboardFrameResult> {
        (0..count)
            .map(|index| {
                let number = base + i64::try_from(index).unwrap();
                ScreenStoryboardFrameResult::new(
                    format!("screen-event-{number}"),
                    10_000 + number,
                    format!("A reviewed screen {suffix}."),
                    "content".into(),
                    "web_page".into(),
                    format!("Visible screen text {suffix}"),
                    format!("Salient text {suffix}"),
                )
                .unwrap()
            })
            .collect()
    }

    fn plan(
        connection: &Connection,
        work: &str,
        vertex: &str,
        base: i64,
        count: usize,
        suffix: &str,
    ) -> ScreenStoryboardResultPlan {
        ScreenStoryboardResultPlan::new_unbound_v1(
            ACCOUNT.into(),
            vertex.into(),
            current_screen_vertex_attempt_commitment(connection, vertex, MODEL).unwrap(),
            work.into(),
            current_screen_work_predecessor_commitment(connection, work).unwrap(),
            MODEL.into(),
            COMMITTED_AT.into(),
            frames(base, count, suffix),
        )
        .unwrap()
    }

    fn execute(
        connection: &mut Connection,
        plan: ScreenStoryboardResultPlan,
    ) -> std::result::Result<
        crate::archive_v3_wal_idempotency::ExecutedLogicalMutation<ScreenStoryboardResultPlan>,
        WalIdempotencyError,
    > {
        let prepared = PreparedLogicalMutation::prepare(plan)?;
        execute_prepared_for_owner(connection, prepared)
    }

    fn execute_error(
        connection: &mut Connection,
        plan: ScreenStoryboardResultPlan,
    ) -> WalIdempotencyError {
        match execute(connection, plan) {
            Ok(_) => panic!("mutation unexpectedly succeeded"),
            Err(error) => error,
        }
    }

    #[test]
    fn exact_screen_storyboard_applies_once_and_replays_without_rewrite() {
        let mut connection = connection();
        seed_work(&connection, WORK_ONE, VERTEX_ONE, 1, 2);
        let replay = plan(&connection, WORK_ONE, VERTEX_ONE, 1, 2, "once");
        let first = plan(&connection, WORK_ONE, VERTEX_ONE, 1, 2, "once");
        connection
            .execute(
                "UPDATE vertex_usage_events SET delivery_state='delivered',updated_at=?1
                 WHERE event_id=?2",
                params![COMMITTED_AT, VERTEX_ONE],
            )
            .unwrap();
        assert_eq!(
            execute(&mut connection, first).unwrap().disposition(),
            LogicalMutationDisposition::Applied
        );
        assert_eq!(
            connection
                .query_row("SELECT COUNT(*) FROM screenshots", [], |row| row
                    .get::<_, i64>(0))
                .unwrap(),
            2
        );
        assert_eq!(
            connection
                .query_row(
                    "SELECT COUNT(*) FROM media_processing_jobs WHERE state='succeeded'",
                    [],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            2
        );
        connection
            .execute_batch(
                "CREATE TRIGGER reject_rewrite BEFORE UPDATE ON screenshots
                 BEGIN SELECT RAISE(ABORT,'no rewrite'); END;",
            )
            .unwrap();
        assert_eq!(
            execute(&mut connection, replay).unwrap().disposition(),
            LogicalMutationDisposition::Replayed
        );
        assert_eq!(load_ledger_state(&connection).unwrap(), (1, 9));
    }

    #[test]
    fn screen_result_binds_only_the_exact_event_scoped_browser_v2_observation() {
        let event_id = "screen-event-1";
        let hash = "43206e42c20fd24a9372605a13b6792245ed53e50edf6c1735cfba4053be30f3";
        let state_key = format!("device:browser-v2:{hash}");
        let seed_browser = |connection: &Connection| {
            seed_work(connection, WORK_ONE, VERTEX_ONE, 1, 1);
            let tabs = serde_json::json!([
                {
                    "window_index":1,"tab_index":1,"title":"Meeting",
                    "url":"https://meet.google.com/abc?authuser=0#frag",
                    "url_scheme":"https","is_active":true,"is_loading":null
                },
                {
                    "window_index":1,"tab_index":2,"title":"Document",
                    "url":"https://docs.google.com/document/d/exact/edit?tab=t.0",
                    "url_scheme":"https","is_active":false,"is_loading":null
                }
            ]);
            let context = serde_json::json!({
                "capture_status":"stable",
                "active_app":"Safari",
                "primary_bundle_id":"com.apple.Safari",
                "primary_window_id":7,
                "window_title":"Meeting",
                "display_id":1,
                "active_url":"https://meet.google.com/abc?authuser=0#frag",
                "active_url_title":"Meeting",
                "browser_permission_status":"granted",
                "browser_state_key":state_key.clone(),
                "browser_snapshot":{
                    "state_key":state_key.clone(),
                    "browser_bundle_id":"com.apple.Safari",
                    "browser_name":"Safari",
                    "permission_status":"granted",
                    "active_window_index":1,
                    "active_tab_index":1,
                    "reported_tab_count":2,
                    "truncated":false,
                    "ambient_tab_collection_enabled":true,
                    "content_hash":hash,
                    "tabs":tabs.clone()
                },
                "visible_windows":[],
                "visible_windows_truncated":false
            });
            let envelope = serde_json::json!({
                "schema_version":2,
                "active_window_index":1,
                "active_tab_index":1,
                "reported_tab_count":2,
                "truncated":false,
                "ambient_tab_collection_enabled":true,
                "tabs":tabs
            });
            connection
                .execute(
                    "UPDATE capture_events SET context_json=?1 WHERE event_id=?2",
                    params![context.to_string(), event_id],
                )
                .unwrap();
            connection
                .execute(
                    "INSERT INTO browser_states_v2
                     (state_key,browser_bundle_id,browser_name,permission_status,content_hash,
                      tabs_json,created_at)
                     VALUES (?1,'com.apple.Safari','Safari','granted',?2,?3,?4)",
                    params![state_key, hash, envelope.to_string(), CREATED_AT],
                )
                .unwrap();
            connection
                .execute(
                    "INSERT INTO browser_observations_v2
                     (observation_id,event_id,observed_at,state_key,context_status,active_url,
                      active_title,created_at)
                     VALUES (?1,?1,?2,?3,'stable',
                             'https://meet.google.com/abc?authuser=0#frag','Meeting',?4)",
                    params![event_id, STARTED_AT, state_key, CREATED_AT],
                )
                .unwrap();
        };

        let mut primary = connection();
        seed_browser(&primary);

        let result = plan(&primary, WORK_ONE, VERTEX_ONE, 1, 1, "browser-v2");
        execute(&mut primary, result).unwrap();
        assert_eq!(
            primary
                .query_row(
                    "SELECT browser_snapshot_source_key FROM screenshots WHERE source_key=?1",
                    [format!("cloud-v2:{event_id}")],
                    |row| row.get::<_, Option<String>>(0),
                )
                .unwrap()
                .as_deref(),
            Some("capture-v2-browser:screen-event-1")
        );

        let mut corrupt = connection();
        seed_browser(&corrupt);
        corrupt
            .execute(
                "UPDATE browser_observations_v2 SET context_status='unstable'",
                [],
            )
            .unwrap();
        let result = plan(&corrupt, WORK_ONE, VERTEX_ONE, 1, 1, "browser-v2-corrupt");
        assert_eq!(
            execute_error(&mut corrupt, result),
            WalIdempotencyError::Precondition
        );
        assert_eq!(
            corrupt
                .query_row("SELECT COUNT(*) FROM screenshots", [], |row| row
                    .get::<_, i64>(0))
                .unwrap(),
            0,
            "mismatched browser observation evidence must fail before screenshot writes"
        );

        for removed_fields in [
            &["browser_state_key"][..],
            &["browser_state_key", "browser_snapshot"][..],
        ] {
            let mut downgraded = connection();
            seed_browser(&downgraded);
            let raw: String = downgraded
                .query_row(
                    "SELECT context_json FROM capture_events WHERE event_id=?1",
                    [event_id],
                    |row| row.get(0),
                )
                .unwrap();
            let mut context: serde_json::Value = serde_json::from_str(&raw).unwrap();
            for field in removed_fields {
                context.as_object_mut().unwrap().remove(*field);
            }
            downgraded
                .execute(
                    "UPDATE capture_events SET context_json=?1 WHERE event_id=?2",
                    params![context.to_string(), event_id],
                )
                .unwrap();
            let result = plan(
                &downgraded,
                WORK_ONE,
                VERTEX_ONE,
                1,
                1,
                "browser-v2-downgrade",
            );
            assert_eq!(
                execute_error(&mut downgraded, result),
                WalIdempotencyError::Precondition
            );
            assert_eq!(
                downgraded
                    .query_row("SELECT COUNT(*) FROM screenshots", [], |row| row
                        .get::<_, i64>(0))
                    .unwrap(),
                0,
                "persisted browser-v2 observations cannot be downgraded to no-lineage writes"
            );
        }

        let mut context_free = connection();
        seed_work(&context_free, WORK_ONE, VERTEX_ONE, 1, 1);
        context_free
            .execute(
                "UPDATE capture_events SET context_json=NULL WHERE event_id=?1",
                [event_id],
            )
            .unwrap();
        let result = plan(&context_free, WORK_ONE, VERTEX_ONE, 1, 1, "context-free");
        execute(&mut context_free, result).unwrap();
        assert_eq!(
            context_free
                .query_row(
                    "SELECT browser_snapshot_source_key FROM screenshots WHERE source_key=?1",
                    [format!("cloud-v2:{event_id}")],
                    |row| row.get::<_, Option<String>>(0),
                )
                .unwrap(),
            None,
            "a context-free pre-v2 screen remains a valid no-browser storyboard member"
        );

        let mut partial_legacy = connection();
        seed_work(&partial_legacy, WORK_ONE, VERTEX_ONE, 1, 1);
        partial_legacy
            .execute(
                "UPDATE capture_events SET context_json='{}' WHERE event_id=?1",
                [event_id],
            )
            .unwrap();
        let result = plan(
            &partial_legacy,
            WORK_ONE,
            VERTEX_ONE,
            1,
            1,
            "partial-legacy-context",
        );
        execute(&mut partial_legacy, result).unwrap();
        assert_eq!(
            partial_legacy
                .query_row(
                    "SELECT browser_snapshot_source_key FROM screenshots WHERE source_key=?1",
                    [format!("cloud-v2:{event_id}")],
                    |row| row.get::<_, Option<String>>(0),
                )
                .unwrap(),
            None,
            "a partial pre-v2 context remains on the established no-browser path"
        );

        let mut forged = connection();
        seed_browser(&forged);
        forged
            .execute(
                "UPDATE capture_events SET context_json=NULL WHERE event_id=?1",
                [event_id],
            )
            .unwrap();
        let result = plan(
            &forged,
            WORK_ONE,
            VERTEX_ONE,
            1,
            1,
            "context-free-forged-v2",
        );
        assert_eq!(
            execute_error(&mut forged, result),
            WalIdempotencyError::Precondition
        );
        assert_eq!(
            forged
                .query_row("SELECT COUNT(*) FROM screenshots", [], |row| row
                    .get::<_, i64>(0))
                .unwrap(),
            0,
            "a v2 observation cannot be attached to a context-free event"
        );
    }

    #[test]
    fn stable_attempt_identity_conflicts_for_changed_result() {
        let mut connection = connection();
        seed_work(&connection, WORK_ONE, VERTEX_ONE, 1, 1);
        let changed = plan(&connection, WORK_ONE, VERTEX_ONE, 1, 1, "changed");
        let first = plan(&connection, WORK_ONE, VERTEX_ONE, 1, 1, "first");
        assert_eq!(first.operation_id(), changed.operation_id());
        execute(&mut connection, first).unwrap();
        assert_eq!(
            execute_error(&mut connection, changed),
            WalIdempotencyError::FingerprintConflict
        );
    }

    #[test]
    fn bound_v2_identity_is_distinct_while_historical_v1_stays_exact() {
        let connection = connection();
        seed_work(&connection, WORK_ONE, VERTEX_ONE, 1, 1);
        let v1 = plan(&connection, WORK_ONE, VERTEX_ONE, 1, 1, "versioned");
        let v2 = ScreenStoryboardResultPlan::new(
            ACCOUNT.to_owned(),
            VERTEX_ONE.to_owned(),
            current_screen_vertex_attempt_commitment(&connection, VERTEX_ONE, MODEL).unwrap(),
            [3_u8; 32],
            WORK_ONE.to_owned(),
            current_screen_work_predecessor_commitment(&connection, WORK_ONE).unwrap(),
            MODEL.to_owned(),
            COMMITTED_AT.to_owned(),
            frames(1, 1, "versioned"),
        )
        .unwrap();
        assert_eq!(
            v1.operation_id(),
            WalLogicalOperationId::from_stable_source(
                WalOperationKind::DeterministicMediaWorkResult,
                VERTEX_ONE.as_bytes(),
            )
            .unwrap()
        );
        assert_ne!(v1.operation_id(), v2.operation_id());
        assert_eq!(
            &v1.canonical_request().unwrap()[..2],
            &REQUEST_V1.to_be_bytes()
        );
        assert_eq!(
            &v2.canonical_request().unwrap()[..2],
            &REQUEST_V2.to_be_bytes()
        );
    }

    #[test]
    fn every_predecessor_family_is_authenticated_before_writes() {
        for mutation in [
            "vertex", "work", "member", "job", "capture", "media", "target",
        ] {
            let mut connection = connection();
            seed_work(&connection, WORK_ONE, VERTEX_ONE, 1, 1);
            let plan = plan(&connection, WORK_ONE, VERTEX_ONE, 1, 1, "exact");
            match mutation {
                "vertex" => {
                    connection
                        .execute(
                            "UPDATE vertex_usage_events SET outcome='ambiguous' WHERE event_id=?1",
                            [VERTEX_ONE],
                        )
                        .unwrap();
                }
                "work" => {
                    connection
                        .execute(
                            "UPDATE media_work_units SET attempt_count=2 WHERE id=?1",
                            [WORK_ONE],
                        )
                        .unwrap();
                }
                "member" => {
                    connection
                        .execute(
                            "UPDATE media_work_members SET window_end_ms=999 WHERE work_unit_id=?1",
                            [WORK_ONE],
                        )
                        .unwrap();
                }
                "job" => {
                    connection
                        .execute("UPDATE media_processing_jobs SET attempt_count=2", [])
                        .unwrap();
                }
                "capture" => {
                    connection
                        .execute("UPDATE capture_events SET context_json='{}'", [])
                        .unwrap();
                }
                "media" => {
                    connection
                        .execute("UPDATE media_objects SET byte_length=999", [])
                        .unwrap();
                }
                "target" => {
                    connection
                        .execute(
                            "INSERT INTO screenshots
                             (id,captured_at,created_at,source_key,visible_windows_truncated)
                             VALUES (10001,?1,?1,'foreign',0)",
                            [CREATED_AT],
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
            assert_eq!(
                connection
                    .query_row("SELECT COUNT(*) FROM screen_observations", [], |row| row
                        .get::<_, i64>(0),)
                    .unwrap(),
                0
            );
            assert_eq!(
                schema_state(&connection).unwrap(),
                LedgerSchemaState::Absent
            );
        }
    }

    #[test]
    fn auto_ids_audio_and_nonterminal_work_are_rejected() {
        let connection = connection();
        seed_work(&connection, WORK_ONE, VERTEX_ONE, 1, 1);
        assert!(ScreenStoryboardFrameResult::new(
            "screen-event-1".into(),
            0,
            "literal".into(),
            "content".into(),
            "web_page".into(),
            "visible".into(),
            "salient".into(),
        )
        .is_err());
        connection
            .execute("UPDATE media_work_units SET work_class='audio'", [])
            .unwrap();
        assert_eq!(
            current_screen_work_predecessor_commitment(&connection, WORK_ONE).unwrap_err(),
            WalIdempotencyError::Precondition
        );
    }

    #[test]
    fn incomplete_or_incoherent_member_topology_cannot_mint_a_predecessor() {
        let missing_media = connection();
        seed_work(&missing_media, WORK_ONE, VERTEX_ONE, 1, 2);
        missing_media
            .execute(
                "DELETE FROM media_objects WHERE event_id='screen-event-2'",
                [],
            )
            .unwrap();
        assert_eq!(
            current_screen_work_predecessor_commitment(&missing_media, WORK_ONE).unwrap_err(),
            WalIdempotencyError::Precondition
        );

        let incoherent_window = connection();
        seed_work(&incoherent_window, WORK_ONE, VERTEX_ONE, 1, 1);
        incoherent_window
            .execute(
                "UPDATE media_work_members SET window_end_ms=999 WHERE work_unit_id=?1",
                [WORK_ONE],
            )
            .unwrap();
        assert_eq!(
            current_screen_work_predecessor_commitment(&incoherent_window, WORK_ONE).unwrap_err(),
            WalIdempotencyError::Precondition
        );
    }

    #[test]
    fn commit_time_cannot_precede_the_authenticated_attempt_or_inputs() {
        let mut connection = connection();
        seed_work(&connection, WORK_ONE, VERTEX_ONE, 1, 1);
        let mut early_plan = plan(&connection, WORK_ONE, VERTEX_ONE, 1, 1, "exact");
        early_plan.committed_at = "2026-08-15T14:59:58.000Z".into();
        assert_eq!(
            execute_error(&mut connection, early_plan),
            WalIdempotencyError::Precondition
        );
        assert_eq!(
            schema_state(&connection).unwrap(),
            LedgerSchemaState::Absent
        );

        let mut expired_lease_plan = plan(&connection, WORK_ONE, VERTEX_ONE, 1, 1, "expired");
        expired_lease_plan.committed_at = "2026-08-15T15:05:01.000Z".into();
        assert_eq!(
            execute_error(&mut connection, expired_lease_plan),
            WalIdempotencyError::Precondition
        );
        assert_eq!(
            schema_state(&connection).unwrap(),
            LedgerSchemaState::Absent
        );
    }

    #[test]
    fn aggregate_request_over_shared_cap_is_rejected() {
        let connection = connection();
        seed_work(&connection, WORK_ONE, VERTEX_ONE, 1, MAX_FRAMES);
        let mut plan = plan(&connection, WORK_ONE, VERTEX_ONE, 1, MAX_FRAMES, "large");
        for frame in &mut plan.frames {
            frame.visible_text = "x".repeat(MAX_VISIBLE_BYTES);
        }
        assert!(matches!(
            PreparedLogicalMutation::prepare(plan),
            Err(WalIdempotencyError::Limit)
        ));
    }

    #[test]
    fn capacity_is_reserved_before_domain_rows_but_replay_survives() {
        let mut connection = connection();
        seed_work(&connection, WORK_ONE, VERTEX_ONE, 1, 1);
        let replay = plan(&connection, WORK_ONE, VERTEX_ONE, 1, 1, "exact");
        let first = plan(&connection, WORK_ONE, VERTEX_ONE, 1, 1, "exact");
        execute(&mut connection, first).unwrap();
        connection
            .execute(
                "UPDATE archive_v3_wal_screen_storyboard_result_state
                 SET row_count=1048576,result_bytes=33554432",
                [],
            )
            .unwrap();
        assert_eq!(
            execute(&mut connection, replay).unwrap().disposition(),
            LogicalMutationDisposition::Replayed
        );
        seed_work(&connection, WORK_TWO, VERTEX_TWO, 20, 1);
        let blocked = plan(&connection, WORK_TWO, VERTEX_TWO, 20, 1, "blocked");
        assert_eq!(
            execute_error(&mut connection, blocked),
            WalIdempotencyError::Limit
        );
        assert_eq!(
            connection
                .query_row(
                    "SELECT COUNT(*) FROM screenshots WHERE source_key='cloud-v2:screen-event-20'",
                    [],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            0
        );
    }

    #[test]
    fn late_ledger_failure_rolls_back_every_result_row_and_transition() {
        let mut connection = connection();
        seed_work(&connection, WORK_ONE, VERTEX_ONE, 1, 1);
        let plan = plan(&connection, WORK_ONE, VERTEX_ONE, 1, 1, "exact");
        connection
            .execute_batch(
                "CREATE TABLE archive_v3_wal_screen_storyboard_result_schema (
                    singleton INTEGER PRIMARY KEY,format_version INTEGER NOT NULL,codec_version INTEGER NOT NULL
                 ) STRICT;
                 CREATE TABLE archive_v3_wal_screen_storyboard_result_operations (
                    operation_id BLOB PRIMARY KEY,format_version INTEGER NOT NULL,codec_version INTEGER NOT NULL,
                    request_fingerprint BLOB NOT NULL,result_bytes BLOB NOT NULL,result_commitment BLOB NOT NULL
                 ) STRICT, WITHOUT ROWID;
                 CREATE TABLE archive_v3_wal_screen_storyboard_result_state (
                    singleton INTEGER PRIMARY KEY,row_count INTEGER NOT NULL,result_bytes INTEGER NOT NULL
                 ) STRICT;
                 INSERT INTO archive_v3_wal_screen_storyboard_result_schema VALUES (1,1,1);
                 INSERT INTO archive_v3_wal_screen_storyboard_result_state VALUES (1,0,0);
                 CREATE TRIGGER fail_state BEFORE UPDATE ON archive_v3_wal_screen_storyboard_result_state
                 BEGIN SELECT RAISE(ABORT,'late failure'); END;",
            )
            .unwrap();
        assert_eq!(
            execute_error(&mut connection, plan),
            WalIdempotencyError::Unavailable
        );
        assert_eq!(
            connection
                .query_row("SELECT COUNT(*) FROM screenshots", [], |row| row
                    .get::<_, i64>(0))
                .unwrap(),
            0
        );
        assert_eq!(
            connection
                .query_row(
                    "SELECT state FROM media_work_units WHERE id=?1",
                    [WORK_ONE],
                    |row| row.get::<_, String>(0),
                )
                .unwrap(),
            "processing"
        );
    }

    #[test]
    fn post_insert_ledger_rewrite_rolls_back_every_result_row() {
        let mut connection = connection();
        seed_work(&connection, WORK_ONE, VERTEX_ONE, 1, 1);
        let plan = plan(&connection, WORK_ONE, VERTEX_ONE, 1, 1, "exact-readback");
        connection
            .execute_batch(
                "CREATE TABLE archive_v3_wal_screen_storyboard_result_schema (
                    singleton INTEGER PRIMARY KEY,format_version INTEGER NOT NULL,codec_version INTEGER NOT NULL
                 ) STRICT;
                 CREATE TABLE archive_v3_wal_screen_storyboard_result_operations (
                    operation_id BLOB PRIMARY KEY,format_version INTEGER NOT NULL,codec_version INTEGER NOT NULL,
                    request_fingerprint BLOB NOT NULL,result_bytes BLOB NOT NULL,result_commitment BLOB NOT NULL
                 ) STRICT, WITHOUT ROWID;
                 CREATE TABLE archive_v3_wal_screen_storyboard_result_state (
                    singleton INTEGER PRIMARY KEY,row_count INTEGER NOT NULL,result_bytes INTEGER NOT NULL
                 ) STRICT;
                 INSERT INTO archive_v3_wal_screen_storyboard_result_schema VALUES (1,1,1);
                 INSERT INTO archive_v3_wal_screen_storyboard_result_state VALUES (1,0,0);
                 CREATE TRIGGER rewrite_result_ledger AFTER INSERT
                 ON archive_v3_wal_screen_storyboard_result_operations
                 BEGIN
                   UPDATE archive_v3_wal_screen_storyboard_result_operations
                   SET request_fingerprint=zeroblob(32)
                   WHERE operation_id=NEW.operation_id;
                 END;",
            )
            .unwrap();
        assert_eq!(
            execute_error(&mut connection, plan),
            WalIdempotencyError::FingerprintConflict
        );
        assert_eq!(
            connection
                .query_row("SELECT COUNT(*) FROM screenshots", [], |row| row
                    .get::<_, i64>(0))
                .unwrap(),
            0
        );
        assert_eq!(load_ledger_state(&connection).unwrap(), (0, 0));
    }

    #[test]
    fn partial_schema_and_result_tamper_fail_closed() {
        let mut partial = connection();
        seed_work(&partial, WORK_ONE, VERTEX_ONE, 1, 1);
        let partial_plan = plan(&partial, WORK_ONE, VERTEX_ONE, 1, 1, "exact");
        partial
            .execute_batch(
                "CREATE TABLE archive_v3_wal_screen_storyboard_result_schema (
                    singleton INTEGER PRIMARY KEY
                 ) STRICT;",
            )
            .unwrap();
        assert_eq!(
            execute_error(&mut partial, partial_plan),
            WalIdempotencyError::Corrupt
        );

        let mut tampered = connection();
        seed_work(&tampered, WORK_ONE, VERTEX_ONE, 1, 1);
        let replay = plan(&tampered, WORK_ONE, VERTEX_ONE, 1, 1, "exact");
        let first = plan(&tampered, WORK_ONE, VERTEX_ONE, 1, 1, "exact");
        execute(&mut tampered, first).unwrap();
        tampered
            .execute(
                "UPDATE archive_v3_wal_screen_storyboard_result_operations
                 SET result_commitment=?1",
                [[7u8; 32].as_slice()],
            )
            .unwrap();
        assert_eq!(
            execute_error(&mut tampered, replay),
            WalIdempotencyError::Corrupt
        );
    }

    #[test]
    fn close_reopen_replays_then_accepts_an_independent_storyboard() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("screen.sqlite");
        {
            let mut connection = Connection::open(&path).unwrap();
            install_schema(&connection);
            seed_work(&connection, WORK_ONE, VERTEX_ONE, 1, 1);
            let plan = plan(&connection, WORK_ONE, VERTEX_ONE, 1, 1, "exact");
            execute(&mut connection, plan).unwrap();
        }
        let fixture = connection();
        seed_work(&fixture, WORK_ONE, VERTEX_ONE, 1, 1);
        let replay = plan(&fixture, WORK_ONE, VERTEX_ONE, 1, 1, "exact");
        let mut reopened = Connection::open(&path).unwrap();
        assert_eq!(
            execute(&mut reopened, replay).unwrap().disposition(),
            LogicalMutationDisposition::Replayed
        );
        seed_work(&reopened, WORK_TWO, VERTEX_TWO, 20, 1);
        let next = plan(&reopened, WORK_TWO, VERTEX_TWO, 20, 1, "next");
        assert_eq!(
            execute(&mut reopened, next).unwrap().disposition(),
            LogicalMutationDisposition::Applied
        );
        assert_eq!(load_ledger_state(&reopened).unwrap(), (2, 18));
    }
}
