//! Vertex invocation-begin as a sealed WAL plan (ADR-0022 F2).
//!
//! Every paid model call in the product routes through `begin_invocation`,
//! which today mints `format!("vtx_{}", random_token_hex())` — a fresh random
//! billed intent on every retry. This plan derives the event id from durable
//! state instead, so a crash-retry recovers the **same** event id and the
//! already-sealed `VertexUsageOutcomePlan` (keyed on the bare event id) still
//! resolves.
//!
//! The identity's attempt discriminant is a per-lane sequence this plan's own
//! `apply()` CAS-advances in the same transaction (R3 case 1). Each lane is
//! single-threaded in production, so intra-lane contention resolves as one
//! `Precondition` plus a re-read; the caller-carried anchor separates
//! logically distinct requests that could otherwise race one sequence slot.
//!
//! This is the **pre-provider** boundary and must stay one: the content-free
//! intent must be durable before the paid request leaves the enclave. Under
//! WAL, witness settlement substitutes for the legacy `save_user` flush, and
//! the legacy compensating DELETE disappears — a failed settle means no
//! intent **and** no call.

use rusqlite::{params, Connection, OptionalExtension, Transaction};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::archive_v3_wal_idempotency::{
    stable_operation_source, DomainLedgerBounds, LogicalMutationResult, PreparedLogicalMutation,
    WalIdempotencyError, WalLogicalDomainLedger, WalLogicalDomainPlan, WalLogicalOperationId,
    WalOperationKind, WalReplayResult,
};

const REQUEST_V1: u16 = 1;
const SUBTYPE: &[u8] = b"adr-0022-vertex-invocation-begin-v1";
const EVENT_ID_DOMAIN: &[u8] = b"kioku.adr-0022.vertex-invocation-event-id.v1\0";
const MAX_ID_BYTES: usize = 128;
const MAX_MODEL_BYTES: usize = 256;
const MAX_LOCATION_BYTES: usize = 128;
const MAX_TIMESTAMP_BYTES: usize = 64;
const MAX_ANCHOR_BYTES: usize = 4 * 1024;
const EVENT_ID_BYTES: usize = 68;
const SCHEMA_TABLE: &str = "archive_v3_wal_vertex_invocation_schema";
const LEDGER_TABLE: &str = "archive_v3_wal_vertex_invocation_operations";
const STATE_TABLE: &str = "archive_v3_wal_vertex_invocation_state";
const PROGRESS_TABLE: &str = "archive_v3_wal_vertex_invocation_progress";
const MAX_ROWS: u32 = 1_048_576;
const MAX_RESULT_BYTES: u64 = 128 * 1024 * 1024;
const BOUNDS: DomainLedgerBounds = DomainLedgerBounds::new(MAX_ROWS, MAX_RESULT_BYTES);
const LANE_COUNT: u8 = 6;

type Result<T> = std::result::Result<T, WalIdempotencyError>;

/// The six production Vertex lanes. Derived from the operation, never chosen
/// by a caller, so a lane cannot be spoofed into another lane's sequence.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum VertexInvocationLane {
    Summarizer = 1,
    Finalizer = 2,
    MediaAudio = 3,
    MediaScreen = 4,
    SubstanceBackfill = 5,
    VisualEvidenceBackfill = 6,
}

impl VertexInvocationLane {
    pub(crate) fn for_operation(operation: crate::cp::vertex::VertexOperation) -> Self {
        use crate::cp::vertex::VertexOperation;
        match operation {
            VertexOperation::EpisodeSummary | VertexOperation::EpisodeSummaryRepair => {
                Self::Summarizer
            }
            VertexOperation::FinalEpisodeAnalysis => Self::Finalizer,
            VertexOperation::AudioWindow => Self::MediaAudio,
            VertexOperation::ScreenStoryboard => Self::MediaScreen,
            VertexOperation::SubstanceBackfill => Self::SubstanceBackfill,
            VertexOperation::VisualEvidenceBackfill => Self::VisualEvidenceBackfill,
        }
    }

    /// The `VertexOperation` discriminant that separates `EpisodeSummary`
    /// from `EpisodeSummaryRepair` in the identity: `as_str` maps both to
    /// `"episode_summarization"`, which is exactly the collision the design
    /// calls out.
    pub(crate) fn variant_tag(operation: crate::cp::vertex::VertexOperation) -> u8 {
        use crate::cp::vertex::VertexOperation;
        match operation {
            VertexOperation::EpisodeSummary => 1,
            VertexOperation::EpisodeSummaryRepair => 2,
            VertexOperation::SubstanceBackfill => 3,
            VertexOperation::VisualEvidenceBackfill => 4,
            VertexOperation::FinalEpisodeAnalysis => 5,
            VertexOperation::AudioWindow => 6,
            VertexOperation::ScreenStoryboard => 7,
        }
    }

    const fn as_u8(self) -> u8 {
        self as u8
    }
}

/// Read the lane's current sequence through any read-capable connection.
/// Absent tables mean sequence 0 — the plan's `ensure_schema` seeds them.
pub(crate) fn read_lane_sequence(
    connection: &Connection,
    lane: VertexInvocationLane,
) -> std::result::Result<i64, rusqlite::Error> {
    let present: i64 = connection.query_row(
        "SELECT COUNT(*) FROM sqlite_schema WHERE type='table' AND name=?1",
        [PROGRESS_TABLE],
        |row| row.get(0),
    )?;
    if present == 0 {
        return Ok(0);
    }
    connection.query_row(
        "SELECT seq FROM archive_v3_wal_vertex_invocation_progress WHERE lane=?1",
        [i64::from(lane.as_u8())],
        |row| row.get(0),
    )
}

/// The identity commitment over the caller-visible request facts. No clock:
/// a crash-retry must be able to re-derive it exactly.
pub(in crate::cp) fn request_commitment(
    operation: crate::cp::vertex::VertexOperation,
    requested_model: &str,
    location: &str,
    caller_anchor: &[u8],
) -> Result<[u8; 32]> {
    let mut commitment = Sha256::new();
    hash_field(&mut commitment, operation.as_str().as_bytes())?;
    hash_field(
        &mut commitment,
        &[VertexInvocationLane::variant_tag(operation)],
    )?;
    hash_field(&mut commitment, requested_model.as_bytes())?;
    hash_field(&mut commitment, location.as_bytes())?;
    hash_field(&mut commitment, caller_anchor)?;
    let commitment: [u8; 32] = commitment.finalize().into();
    if commitment == [0; 32] {
        return Err(WalIdempotencyError::Corrupt);
    }
    Ok(commitment)
}

/// Derive the event id for `(user, lane, seq, request_commitment)`. Public to
/// the owning module so the caller can probe the **previous** slot for a
/// settled-but-unacknowledged intent before minting a new one.
pub(crate) fn derive_event_id(
    account_id: &str,
    lane: VertexInvocationLane,
    lane_sequence: i64,
    request_commitment: &[u8; 32],
) -> Result<String> {
    let mut hasher = Sha256::new();
    hasher.update(EVENT_ID_DOMAIN);
    hash_field(&mut hasher, account_id.as_bytes())?;
    hash_field(&mut hasher, &[lane.as_u8()])?;
    hash_field(&mut hasher, &lane_sequence.to_be_bytes())?;
    hash_field(&mut hasher, request_commitment)?;
    let event_id = format!("vtx_{:x}", hasher.finalize());
    if event_id.len() != EVENT_ID_BYTES {
        return Err(WalIdempotencyError::Corrupt);
    }
    Ok(event_id)
}

pub(crate) struct VertexInvocationBeginPlan {
    operation_id: WalLogicalOperationId,
    account_id: String,
    lane: VertexInvocationLane,
    lane_sequence: i64,
    operation_str: String,
    variant_tag: u8,
    requested_model: String,
    location: String,
    observed_at: String,
    request_commitment: [u8; 32],
    event_id: String,
}

impl VertexInvocationBeginPlan {
    /// `lane_sequence` is the value a routed read observed. The plan is
    /// constructed once per attempt (R5); `caller_anchor` separates logically
    /// distinct requests (window bounds, episode + predecessor, work unit +
    /// attempt) so a genuinely new call never adopts an old intent.
    #[allow(clippy::too_many_arguments)]
    pub(in crate::cp) fn new(
        account_id: String,
        operation: crate::cp::vertex::VertexOperation,
        lane_sequence: i64,
        requested_model: String,
        location: String,
        observed_at: String,
        caller_anchor: &[u8],
    ) -> Result<Self> {
        crate::store::validate_user_id(&account_id).map_err(|_| WalIdempotencyError::Malformed)?;
        let lane = VertexInvocationLane::for_operation(operation);
        let variant_tag = VertexInvocationLane::variant_tag(operation);
        let operation_str = operation.as_str().to_owned();
        if lane_sequence < 0
            || requested_model.is_empty()
            || requested_model.len() > MAX_MODEL_BYTES
            || location.is_empty()
            || location.len() > MAX_LOCATION_BYTES
            || observed_at.is_empty()
            || observed_at.len() > MAX_TIMESTAMP_BYTES
            || observed_at.contains('\0')
            || caller_anchor.is_empty()
            || caller_anchor.len() > MAX_ANCHOR_BYTES
        {
            return Err(WalIdempotencyError::Malformed);
        }
        let request_commitment =
            request_commitment(operation, &requested_model, &location, caller_anchor)?;
        let event_id = derive_event_id(&account_id, lane, lane_sequence, &request_commitment)?;
        let source = stable_operation_source(
            SUBTYPE,
            &[
                account_id.as_bytes(),
                &[lane.as_u8()],
                &lane_sequence.to_be_bytes(),
                &request_commitment,
            ],
        )?;
        let operation_id =
            WalLogicalOperationId::from_stable_source(WalOperationKind::VertexUsage, &source)?;
        Ok(Self {
            operation_id,
            account_id,
            lane,
            lane_sequence,
            operation_str,
            variant_tag,
            requested_model,
            location,
            observed_at,
            request_commitment,
            event_id,
        })
    }

    pub(in crate::cp) fn event_id(&self) -> &str {
        &self.event_id
    }
}

pub(crate) struct VertexInvocationBeginLedger;

impl WalLogicalDomainPlan for VertexInvocationBeginPlan {
    type Ledger = VertexInvocationBeginLedger;
    type Output = String;

    fn kind(&self) -> WalOperationKind {
        WalOperationKind::VertexUsage
    }

    fn operation_id(&self) -> WalLogicalOperationId {
        self.operation_id
    }

    fn canonical_request(&self) -> Result<Zeroizing<Vec<u8>>> {
        let mut request = Zeroizing::new(Vec::with_capacity(1024));
        request.extend_from_slice(&REQUEST_V1.to_be_bytes());
        encode_bytes(&mut request, SUBTYPE)?;
        encode_string(&mut request, &self.account_id)?;
        request.push(self.lane.as_u8());
        request.extend_from_slice(&self.lane_sequence.to_be_bytes());
        encode_string(&mut request, &self.operation_str)?;
        request.push(self.variant_tag);
        encode_string(&mut request, &self.requested_model)?;
        encode_string(&mut request, &self.location)?;
        // observed_at is deliberately NOT here (nor in the identity): it is a
        // clock, and a crash-retry cannot re-mint the original value. In the
        // identity it would break settled-lost-ack recovery (the probe could
        // never re-derive the id); in the fingerprint it would turn that
        // recovery into a FingerprintConflict that poisons the lane slot. It
        // is carried unfingerprinted and written once by the first apply --
        // a replay returns the stored result and writes nothing. This is a
        // reviewed correction to the family design, which listed observed_at
        // inside the commitment.
        request.extend_from_slice(&self.request_commitment);
        encode_string(&mut request, &self.event_id)?;
        Ok(request)
    }

    fn apply(&self, transaction: &Transaction<'_>) -> Result<WalReplayResult> {
        ensure_progress_schema(transaction)?;
        // The plan's own attempt discriminant: CAS the pinned pre-state
        // sequence forward. A lost race (another intent on this lane settled
        // first) is a Precondition; the caller re-reads and re-derives as a
        // NEW operation.
        let changed = transaction
            .execute(
                "UPDATE archive_v3_wal_vertex_invocation_progress
                 SET seq=seq+1 WHERE lane=?1 AND seq=?2",
                params![i64::from(self.lane.as_u8()), self.lane_sequence],
            )
            .map_err(|_| WalIdempotencyError::Unavailable)?;
        if changed != 1 {
            return Err(WalIdempotencyError::Precondition);
        }
        let existing: i64 = transaction
            .query_row(
                "SELECT COUNT(*) FROM vertex_usage_events WHERE event_id=?1",
                [&self.event_id],
                |row| row.get(0),
            )
            .map_err(|_| WalIdempotencyError::Unavailable)?;
        if existing != 0 {
            return Err(WalIdempotencyError::Precondition);
        }
        let inserted = transaction
            .execute(
                "INSERT INTO vertex_usage_events
                 (event_id,operation,requested_model,location,outcome,
                  delivery_state,delivery_attempt_count,observed_at,updated_at)
                 VALUES (?1,?2,?3,?4,'started','pending',0,?5,?5)",
                params![
                    self.event_id,
                    self.operation_str,
                    self.requested_model,
                    self.location,
                    self.observed_at,
                ],
            )
            .map_err(|_| WalIdempotencyError::Unavailable)?;
        if inserted != 1 {
            return Err(WalIdempotencyError::Corrupt);
        }
        // Clock-free coverage refresh: the period and stamps come from the
        // carried observed_at, and the pending count is a pure function of
        // this transaction's pre-state.
        let period = &self.observed_at[..7.min(self.observed_at.len())];
        transaction
            .execute(
                "INSERT INTO vertex_usage_coverage
                 (period,sequence,pending_events,lost_events,delivery_state,updated_at)
                 VALUES (
                    ?1,1,
                    (SELECT count(*) FROM vertex_usage_events
                     WHERE delivery_state='pending' AND substr(observed_at,1,7)=?1),
                    0,'pending',?2)
                 ON CONFLICT(period) DO UPDATE SET
                    sequence=vertex_usage_coverage.sequence+1,
                    pending_events=excluded.pending_events,
                    lost_events=vertex_usage_coverage.lost_events,
                    delivery_state='pending',
                    updated_at=?2",
                params![period, self.observed_at],
            )
            .map_err(|_| WalIdempotencyError::Unavailable)?;
        WalReplayResult::canonical_response(
            WalOperationKind::VertexUsage,
            self.event_id.as_bytes().to_vec(),
        )
    }

    fn validate_replay(&self, result: &WalReplayResult) -> Result<()> {
        match result {
            WalReplayResult::CanonicalResponse(bytes)
                if bytes.as_slice() == self.event_id.as_bytes() =>
            {
                Ok(())
            }
            _ => Err(WalIdempotencyError::Corrupt),
        }
    }

    fn decode_output(&self, result: &WalReplayResult) -> Result<Self::Output> {
        self.validate_replay(result)?;
        Ok(self.event_id.clone())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum LedgerSchemaState {
    Absent,
    Present,
}

impl WalLogicalDomainLedger<VertexInvocationBeginPlan> for VertexInvocationBeginLedger {
    fn lookup(
        connection: &Connection,
        prepared: &PreparedLogicalMutation<VertexInvocationBeginPlan>,
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
                 FROM archive_v3_wal_vertex_invocation_operations
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
        let kind = WalOperationKind::VertexUsage;
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
        prepared: &PreparedLogicalMutation<VertexInvocationBeginPlan>,
    ) -> Result<LogicalMutationResult> {
        require_kind(prepared)?;
        ensure_schema(transaction)?;
        if let Some(result) = Self::lookup(transaction, prepared)? {
            return Ok(LogicalMutationResult::Replayed(result));
        }
        let (row_count, result_bytes) = load_ledger_state(transaction)?;
        let kind = WalOperationKind::VertexUsage;
        let result = prepared.plan_for_domain_ledger().apply(transaction)?;
        prepared.plan_for_domain_ledger().validate_replay(&result)?;
        let encoded = result.encode(kind)?;
        BOUNDS.admit(row_count, result_bytes, encoded.len())?;
        let commitment = result.commitment(kind)?;
        transaction
            .execute(
                "INSERT INTO archive_v3_wal_vertex_invocation_operations
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
                "UPDATE archive_v3_wal_vertex_invocation_state
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

fn require_kind(prepared: &PreparedLogicalMutation<VertexInvocationBeginPlan>) -> Result<()> {
    if prepared.kind_for_owner() != WalOperationKind::VertexUsage {
        return Err(WalIdempotencyError::Corrupt);
    }
    Ok(())
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

fn ensure_progress_schema(transaction: &Transaction<'_>) -> Result<()> {
    let present: i64 = transaction
        .query_row(
            "SELECT COUNT(*) FROM sqlite_schema WHERE type='table' AND name=?1",
            [PROGRESS_TABLE],
            |row| row.get(0),
        )
        .map_err(|_| WalIdempotencyError::Unavailable)?;
    if present == 1 {
        return Ok(());
    }
    transaction
        .execute_batch(
            "CREATE TABLE archive_v3_wal_vertex_invocation_progress (
                lane INTEGER PRIMARY KEY CHECK(lane BETWEEN 1 AND 6),
                seq INTEGER NOT NULL CHECK(seq >= 0)
             ) STRICT;
             INSERT INTO archive_v3_wal_vertex_invocation_progress (lane,seq)
             VALUES (1,0),(2,0),(3,0),(4,0),(5,0),(6,0);",
        )
        .map_err(|_| WalIdempotencyError::Unavailable)?;
    let seeded: i64 = transaction
        .query_row(
            "SELECT COUNT(*) FROM archive_v3_wal_vertex_invocation_progress",
            [],
            |row| row.get(0),
        )
        .map_err(|_| WalIdempotencyError::Unavailable)?;
    if seeded != i64::from(LANE_COUNT) {
        return Err(WalIdempotencyError::Corrupt);
    }
    Ok(())
}

fn ensure_schema(transaction: &Transaction<'_>) -> Result<()> {
    match schema_state(transaction)? {
        LedgerSchemaState::Present => validate_schema_marker(transaction),
        LedgerSchemaState::Absent => {
            transaction
                .execute_batch(
                    "CREATE TABLE archive_v3_wal_vertex_invocation_schema (
                        singleton INTEGER PRIMARY KEY CHECK(singleton=1),
                        format_version INTEGER NOT NULL CHECK(format_version=1),
                        codec_version INTEGER NOT NULL CHECK(codec_version=1)
                     ) STRICT;
                     CREATE TABLE archive_v3_wal_vertex_invocation_operations (
                        operation_id BLOB PRIMARY KEY NOT NULL,
                        format_version INTEGER NOT NULL CHECK(format_version=1),
                        codec_version INTEGER NOT NULL CHECK(codec_version=1),
                        request_fingerprint BLOB NOT NULL,
                        result_bytes BLOB NOT NULL,
                        result_commitment BLOB NOT NULL,
                        CHECK(length(operation_id)=16 AND operation_id<>zeroblob(16)),
                        CHECK(length(request_fingerprint)=32 AND request_fingerprint<>zeroblob(32)),
                        CHECK(length(result_bytes) BETWEEN 10 AND 4096),
                        CHECK(length(result_commitment)=32 AND result_commitment<>zeroblob(32))
                     ) STRICT, WITHOUT ROWID;
                     CREATE TABLE archive_v3_wal_vertex_invocation_state (
                        singleton INTEGER PRIMARY KEY CHECK(singleton=1),
                        row_count INTEGER NOT NULL CHECK(row_count BETWEEN 0 AND 1048576),
                        result_bytes INTEGER NOT NULL CHECK(result_bytes BETWEEN 0 AND 134217728)
                     ) STRICT;
                     INSERT INTO archive_v3_wal_vertex_invocation_schema
                        (singleton,format_version,codec_version) VALUES (1,1,1);
                     INSERT INTO archive_v3_wal_vertex_invocation_state
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
             FROM archive_v3_wal_vertex_invocation_schema WHERE singleton=1",
            [],
            |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)),
        )
        .optional()
        .map_err(|_| WalIdempotencyError::Corrupt)?;
    if marker
        != Some((
            i64::from(WalOperationKind::format_version()),
            i64::from(WalOperationKind::VertexUsage.codec_version()),
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
             FROM archive_v3_wal_vertex_invocation_state WHERE singleton=1",
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

fn hash_field(hasher: &mut Sha256, value: &[u8]) -> Result<()> {
    hasher.update(
        u32::try_from(value.len())
            .map_err(|_| WalIdempotencyError::Limit)?
            .to_be_bytes(),
    );
    hasher.update(value);
    Ok(())
}

fn encode_len(request: &mut Vec<u8>, value: usize) -> Result<()> {
    let value = u32::try_from(value).map_err(|_| WalIdempotencyError::Limit)?;
    request.extend_from_slice(&value.to_be_bytes());
    Ok(())
}

fn encode_bytes(request: &mut Vec<u8>, value: &[u8]) -> Result<()> {
    encode_len(request, value.len())?;
    request.extend_from_slice(value);
    Ok(())
}

fn encode_string(request: &mut Vec<u8>, value: &str) -> Result<()> {
    encode_bytes(request, value.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::archive_v3_wal_idempotency::{
        execute_prepared_for_owner, LogicalMutationDisposition,
    };
    use crate::cp::vertex::VertexOperation;

    const ACCOUNT: &str = "11111111-1111-4111-8111-111111111111";
    const OBSERVED_AT: &str = "2026-08-20T14:00:00.000Z";

    fn install_schema(connection: &Connection) {
        connection
            .execute_batch(
                "CREATE TABLE vertex_usage_events (
                    event_id TEXT PRIMARY KEY,
                    operation TEXT NOT NULL,
                    requested_model TEXT NOT NULL,
                    location TEXT NOT NULL,
                    outcome TEXT NOT NULL,
                    delivery_state TEXT NOT NULL DEFAULT 'pending',
                    delivery_attempt_count INTEGER NOT NULL DEFAULT 0,
                    observed_at TEXT NOT NULL DEFAULT '',
                    updated_at TEXT NOT NULL DEFAULT ''
                 );
                 CREATE TABLE vertex_usage_coverage (
                    period TEXT PRIMARY KEY,
                    sequence INTEGER NOT NULL,
                    pending_events INTEGER NOT NULL,
                    lost_events INTEGER NOT NULL,
                    delivery_state TEXT NOT NULL,
                    updated_at TEXT NOT NULL DEFAULT ''
                 );",
            )
            .unwrap();
    }

    fn plan(seq: i64, operation: VertexOperation, anchor: &[u8]) -> VertexInvocationBeginPlan {
        VertexInvocationBeginPlan::new(
            ACCOUNT.into(),
            operation,
            seq,
            "gemini-3.5-flash".into(),
            "us-central1".into(),
            OBSERVED_AT.into(),
            anchor,
        )
        .unwrap()
    }

    fn settle(
        connection: &mut Connection,
        plan: VertexInvocationBeginPlan,
    ) -> Result<(LogicalMutationDisposition, String)> {
        let prepared = PreparedLogicalMutation::prepare(plan)?;
        let outcome = execute_prepared_for_owner(connection, prepared)?;
        let disposition = outcome.disposition();
        let event_id = outcome.into_validated_result().release()?;
        Ok((disposition, event_id))
    }

    #[test]
    fn begin_settles_derives_a_stable_id_and_replays_the_same_id() {
        let mut connection = Connection::open_in_memory().unwrap();
        install_schema(&connection);
        let first = plan(0, VertexOperation::EpisodeSummary, b"window:a..b");
        let replay = plan(0, VertexOperation::EpisodeSummary, b"window:a..b");
        let expected = first.event_id().to_owned();
        let (disposition, event_id) = settle(&mut connection, first).unwrap();
        assert!(matches!(disposition, LogicalMutationDisposition::Applied));
        assert_eq!(event_id, expected);
        let started: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM vertex_usage_events
                 WHERE event_id=?1 AND outcome='started' AND delivery_state='pending'",
                [&event_id],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(started, 1);
        let seq: i64 = read_lane_sequence(&connection, VertexInvocationLane::Summarizer).unwrap();
        assert_eq!(seq, 1);
        // A crash-retry resubmits the identical plan and recovers the SAME
        // event id from the ledger: one billed intent, not two. This is the
        // exact defect the random token minted on every retry.
        let (disposition, replayed_id) = settle(&mut connection, replay).unwrap();
        assert!(matches!(disposition, LogicalMutationDisposition::Replayed));
        assert_eq!(replayed_id, expected);
        let events: i64 = connection
            .query_row("SELECT COUNT(*) FROM vertex_usage_events", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(events, 1);
    }

    #[test]
    fn distinct_requests_and_lanes_derive_distinct_ids_and_sequences() {
        let mut connection = Connection::open_in_memory().unwrap();
        install_schema(&connection);
        let summary = plan(0, VertexOperation::EpisodeSummary, b"window:a..b");
        let summary_id = summary.event_id().to_owned();
        settle(&mut connection, summary).unwrap();
        // Same lane, next request: reads the advanced sequence.
        let repair = plan(1, VertexOperation::EpisodeSummaryRepair, b"window:a..b");
        assert_ne!(repair.event_id(), summary_id);
        settle(&mut connection, repair).unwrap();
        // Same as_str, different variant: the discriminant separates them
        // even at the same lane and sequence.
        let a = plan(7, VertexOperation::EpisodeSummary, b"x");
        let b = plan(7, VertexOperation::EpisodeSummaryRepair, b"x");
        assert_ne!(a.event_id(), b.event_id());
        // Different lane, independent sequence.
        let finalizer = plan(0, VertexOperation::FinalEpisodeAnalysis, b"episode:9");
        settle(&mut connection, finalizer).unwrap();
        assert_eq!(
            read_lane_sequence(&connection, VertexInvocationLane::Summarizer).unwrap(),
            2
        );
        assert_eq!(
            read_lane_sequence(&connection, VertexInvocationLane::Finalizer).unwrap(),
            1
        );
    }

    #[test]
    fn a_stale_sequence_fails_closed_and_never_double_bills() {
        let mut connection = Connection::open_in_memory().unwrap();
        install_schema(&connection);
        let racer = plan(0, VertexOperation::EpisodeSummary, b"window:a..b");
        let stale = plan(0, VertexOperation::EpisodeSummary, b"window:c..d");
        settle(&mut connection, racer).unwrap();
        // The slot is consumed: a different request pinned to the same
        // sequence must fail closed, not mint over it.
        assert!(matches!(
            settle(&mut connection, stale),
            Err(WalIdempotencyError::Precondition)
        ));
        let events: i64 = connection
            .query_row("SELECT COUNT(*) FROM vertex_usage_events", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(events, 1);
    }

    #[test]
    fn a_crash_retry_with_a_fresh_clock_replays_instead_of_conflicting() {
        // The retry that matters: the process died after settle, the ack was
        // lost, and the new run re-mints observed_at. Same identity, same
        // fingerprint (neither contains the clock), so the ledger REPLAYS the
        // original event id. If observed_at ever re-enters the identity or
        // the fingerprint, this becomes a FingerprintConflict that poisons
        // the lane slot -- which is why this test exists.
        let mut connection = Connection::open_in_memory().unwrap();
        install_schema(&connection);
        let first = plan(0, VertexOperation::EpisodeSummary, b"window:a..b");
        let expected = first.event_id().to_owned();
        settle(&mut connection, first).unwrap();
        let retry = VertexInvocationBeginPlan::new(
            ACCOUNT.into(),
            VertexOperation::EpisodeSummary,
            0,
            "gemini-3.5-flash".into(),
            "us-central1".into(),
            "2026-08-20T15:59:59.000Z".into(),
            b"window:a..b",
        )
        .unwrap();
        let (disposition, event_id) = settle(&mut connection, retry).unwrap();
        assert!(matches!(disposition, LogicalMutationDisposition::Replayed));
        assert_eq!(event_id, expected);
        // The stored row keeps the ORIGINAL timestamps.
        let observed: String = connection
            .query_row(
                "SELECT observed_at FROM vertex_usage_events WHERE event_id=?1",
                [&event_id],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(observed, OBSERVED_AT);
    }

    #[test]
    fn malformed_inputs_are_rejected() {
        for (seq, model, location, observed, anchor) in [
            (-1i64, "m", "l", OBSERVED_AT, b"a".as_slice()),
            (0, "", "l", OBSERVED_AT, b"a"),
            (0, "m", "", OBSERVED_AT, b"a"),
            (0, "m", "l", "", b"a"),
            (0, "m", "l", OBSERVED_AT, b""),
        ] {
            assert!(VertexInvocationBeginPlan::new(
                ACCOUNT.into(),
                VertexOperation::EpisodeSummary,
                seq,
                model.into(),
                location.into(),
                observed.into(),
                anchor,
            )
            .is_err());
        }
    }

    #[test]
    fn coverage_row_is_refreshed_clock_free_from_the_carried_timestamp() {
        let mut connection = Connection::open_in_memory().unwrap();
        install_schema(&connection);
        settle(
            &mut connection,
            plan(0, VertexOperation::EpisodeSummary, b"w"),
        )
        .unwrap();
        let (period, pending, updated): (String, i64, String) = connection
            .query_row(
                "SELECT period,pending_events,updated_at FROM vertex_usage_coverage",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();
        assert_eq!(period, &OBSERVED_AT[..7]);
        assert_eq!(pending, 1);
        assert_eq!(updated, OBSERVED_AT);
    }
}
