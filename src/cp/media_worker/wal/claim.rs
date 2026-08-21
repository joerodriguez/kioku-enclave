//! The media work claim boundary as a sealed WAL plan (ADR-0022 slice 10i).
//!
//! `lease_work_unit` is the one media-worker mutation with no sealed family:
//! every settle family downstream (`reservation`, `result`, `audio_result`,
//! `usage`) anchors on the `media_work_units` row and the `attempt_count` the
//! claim advanced durably *before* the plan is constructed, and on a
//! WAL-authoritative user nothing ever wrote that row. This family is that
//! missing boundary.
//!
//! The claim must be durable for two reasons, neither of them contention:
//!
//! * `attempt_count` is the ONLY bound on repeated payment. `process_work_unit`
//!   issues a billed Vertex call and `mark_failed` terminalizes at
//!   `attempts >= MAX_ATTEMPTS`. A crash loop between "select work" and "pay"
//!   bills without bound unless the attempt is recorded first.
//! * `span_has_recoverable_media` treats `processing` as "still recoverable"
//!   and holds the summarizer's forward-only cursor. A claim that leaves no
//!   durable trace lets the cursor advance past media that is being processed.
//!
//! **`lease_until` survives, but collapses in meaning.** It is NOT a mutual
//! exclusion token — cross-process safety is delivered by the owner's fencing
//! CAS plus the per-row predecessor CAS below. It is a *deterministic derived
//! recovery deadline*, `add_seconds(committed_at, lease_seconds)`: never
//! renewed, no holder id, no fencing token. It still does two jobs that
//! nothing else can: `(state='processing' AND lease_until<=now)` is the only
//! path by which a work unit abandoned by a dead owner returns to work, and
//! the already-sealed `result`/`audio_result` settles read and validate it as
//! a first-class predecessor fact (`lease_until - attempted_at >=
//! MIN_PROVIDER_ATTEMPT_WINDOW_MILLIS`, `lease_until >= committed_at`, and a
//! byte-exact `lease_until IS ?` CAS clause).
//!
//! The identity is the **resolved member set** — the ordered observed
//! predecessor tuples plus the observed `media_work_units` row — never the
//! clock: `claimed_at`, `scan_limit`, `lease_seconds` and `committed_at` enter
//! only the fingerprinted canonical request. `apply()` re-runs the identical
//! bounded eligibility query (shared with the owner by construction, not by
//! convention), re-derives the member set through the same pure planner, and
//! requires exact equality before writing, so a stale enumeration fails closed
//! instead of claiming rows it never admitted.
//!
//! Kind 6 (`DeterministicMediaWorkResult`) is reused: this is the media
//! job/work bookkeeping family that ordinal 6 already owns. The subtype keeps
//! the ledgers disjoint.

use rusqlite::{params, Connection, OptionalExtension, Row, Transaction};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::archive_v3_wal_idempotency::{
    hash_field, stable_operation_source, DomainLedgerBounds, LogicalMutationResult,
    PreparedLogicalMutation, WalIdempotencyError, WalLogicalDomainLedger, WalLogicalDomainPlan,
    WalLogicalOperationId, WalOperationKind, WalReplayResult,
};
use crate::cp::isotime;
use crate::cp::media_planner::{self, PlanningEvent, WorkClass};

const REQUEST_V1: u16 = 1;
const SUBTYPE: &[u8] = b"adr-0022-media-work-claim-v1";
const SCHEMA_TABLE: &str = "archive_v3_wal_media_work_claim_schema";
const LEDGER_TABLE: &str = "archive_v3_wal_media_work_claim_operations";
const STATE_TABLE: &str = "archive_v3_wal_media_work_claim_state";
const ENCODED_UNIT_RESULT_BYTES: usize = 9;
const MAX_ROWS: u32 = 65_536;
const MAX_RESULT_BYTES: u64 = 65_536 * 9;
const BOUNDS: DomainLedgerBounds = DomainLedgerBounds::new(MAX_ROWS, MAX_RESULT_BYTES);
const MAX_ID_BYTES: usize = 128;
const MAX_TIMESTAMP_BYTES: usize = 64;
const MAX_JSON_BYTES: usize = 8 * 1024;
/// The legacy scan LIMIT ceiling. A resolved set larger than this refuses with
/// `Limit`; it is NEVER truncated — an observed predecessor fact that the plan
/// silently dropped is a claim written against a set the identity never
/// admitted.
const MAX_MEMBERS: usize = 128;
const MAX_SCAN_LIMIT: i64 = 1_024;
const CLAIMABLE_ROW_COMMITMENT_DOMAIN: &[u8] = b"adr-0022-media-claimable-row-v1\0";
/// The two `media_processing_jobs.state` values that a claim may leave, and
/// the three it may consume, are pinned as literals here so a widened
/// eligibility predicate cannot smuggle in a state the CAS never observed.
const CLAIMABLE_STATES: [&str; 3] = ["pending", "retry_wait", "processing"];
const CLAIMED_STATE: &str = "processing";
/// `media_objects.processing_state` after the claim.
const CLAIMED_MEDIA_STATE: &str = "processing";

type Result<T> = std::result::Result<T, WalIdempotencyError>;

/// The identical bounded eligibility query the owner enumerates with and
/// `apply()` revalidates with. One definition — the "same query" requirement
/// holds by construction. This is `lease_work_unit`'s scan plus the
/// predecessor columns the legacy `MediaJob` never selected but the plan must
/// pin, and the legacy literal `LIMIT 128` becomes a carried bound so replay
/// stays deterministic across binary revisions.
///
/// `as_of` is the CARRIED `claimed_at`, never a live clock read inside
/// `apply()`. That is the single most important determinism decision in this
/// family: the predicate's `retry_wait`/`processing` arms are both time
/// comparisons, so a live clock would silently re-derive a different eligible
/// set on every replay.
pub(in crate::cp::media_worker) fn enumerate_claimable(
    connection: &Connection,
    processor_version: i64,
    job_kind: &str,
    as_of: &str,
    scan_limit: i64,
) -> rusqlite::Result<Vec<ClaimableRow>> {
    let mut statement = connection.prepare(
        "SELECT j.id,j.event_id,j.job_kind,j.input_revision,j.processor_version,\
                j.state,j.attempt_count,j.lease_until,j.error_code,j.usage_json,j.updated_at,\
                m.object_key,m.mime_type,m.codec,m.byte_length,m.sample_rate,m.channels,\
                m.width,m.height,m.sha256,m.processing_state,\
                e.started_at,e.ended_at,e.stream_kind,e.capture_session_id,e.stream_id,\
                e.sequence,e.context_json,e.audio_role,e.audio_route,e.route_epoch \
         FROM media_processing_jobs j \
         JOIN capture_events e ON e.event_id=j.event_id \
         JOIN media_objects m ON m.event_id=j.event_id \
         WHERE j.processor_version=?1 AND j.job_kind=?2 AND ( \
             j.state='pending' OR \
             (j.state='retry_wait' AND j.updated_at<=?3) OR \
             (j.state='processing' AND j.lease_until<=?3)) \
         ORDER BY e.started_at,e.sequence,j.id LIMIT ?4",
    )?;
    let rows = statement.query_map(
        params![processor_version, job_kind, as_of, scan_limit],
        ClaimableRow::from_row,
    )?;
    rows.collect()
}

/// T24 is now a residual defence. The sealed epoch-0 re-baseline declares
/// `audio_segments` and `utterances` `AUTOINCREMENT`, so this gate opens on a
/// current production archive. It still refuses a legacy archive materialized
/// before that re-baseline, where either table is a plain `INTEGER PRIMARY
/// KEY`: those tables never advance `sqlite_sequence`, so a non-empty archive
/// can collide at a derived id and even an empty one fails the transcript
/// settle's post-state pin re-validation.
///
/// On such a legacy shape, opening the claim boundary without this probe means
/// audio work units are claimed, **PAID** Vertex audio calls are made, and
/// every settle fails — burning `MAX_ATTEMPTS` paid calls per window, forever,
/// for every selected user with audio. The probe runs BEFORE the claim, so a
/// blocked lane makes no claim, no reservation and no paid call.
///
/// The probe asks whether the two tables ARE `AUTOINCREMENT`, by reading their
/// DDL — never whether they currently HAVE `sqlite_sequence` rows.
///
/// That distinction is the whole correctness of this gate. SQLite creates a
/// table's `sqlite_sequence` row on its FIRST INSERT, not at `CREATE TABLE`.
/// Counting rows would therefore be shut on a freshly created archive even
/// once the tables are AUTOINCREMENT, and because a shut gate makes no claim,
/// nothing would ever insert the row that opens it — a permanent deadlock of
/// the audio lane on every genesis archive, which under genesis-first is
/// every archive. Reading the DDL is true from `CREATE TABLE` onward and is
/// the same fact the sequence gate test pins.
///
/// A missing table, or DDL that cannot be read, is itself the blocked
/// condition, so any query error fails closed.
pub(in crate::cp::media_worker) fn audio_sequence_gate_open(connection: &Connection) -> bool {
    ["audio_segments", "utterances"].iter().all(|table| {
        connection
            .query_row(
                "SELECT sql FROM sqlite_master WHERE type='table' AND name=?1",
                [table],
                |row| row.get::<_, String>(0),
            )
            .map(|ddl| ddl.to_ascii_uppercase().contains("AUTOINCREMENT"))
            .unwrap_or(false)
    })
}

/// The work-unit id digest, extracted verbatim from `lease_work_unit` so the
/// legacy path and the routed path mint byte-identical ids.
///
/// Two hazards are deliberate and must not be "cleaned up":
///
/// * `{class:?}` is the DERIVED `Debug` of `WorkClass` ("Audio"/"Screen").
///   Renaming or reordering that enum silently re-keys every work unit ever
///   minted, orphaning in-flight units and every `media_work_members` row.
/// * The digest is NOT length-framed (`event_id ‖ 0x00 ‖ sha256 ‖ 0x00`). It
///   is collision-safe here because `sha256` is a fixed 64 hex chars and an
///   `event_id` cannot contain NUL. Reframing it through `hash_field` would
///   change every id.
pub(in crate::cp::media_worker) fn work_unit_id<'a, I>(class: WorkClass, selected: I) -> String
where
    I: IntoIterator<Item = (&'a str, &'a str)>,
{
    let mut digest = Sha256::new();
    digest.update(format!("media-work-v1:{class:?}:"));
    for (event_id, sha256) in selected {
        digest.update(event_id.as_bytes());
        digest.update([0]);
        digest.update(sha256.as_bytes());
        digest.update([0]);
    }
    format!("{:x}", digest.finalize())
}

pub(in crate::cp::media_worker) const fn class_name(class: WorkClass) -> &'static str {
    match class {
        WorkClass::Audio => "audio",
        WorkClass::Screen => "screen",
    }
}

pub(in crate::cp::media_worker) const fn job_kind_for(class: WorkClass) -> &'static str {
    match class {
        WorkClass::Audio => "gemini_audio",
        WorkClass::Screen => "gemini_screen",
    }
}

/// One enumerated claimable job: the full observed `media_processing_jobs`
/// predecessor, the `media_objects` predecessor the claim also advances, and
/// the immutable capture metadata the owner needs to build its local work unit
/// without a second read.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(in crate::cp::media_worker) struct ClaimableRow {
    pub(in crate::cp::media_worker) job_id: i64,
    pub(in crate::cp::media_worker) event_id: String,
    pub(in crate::cp::media_worker) job_kind: String,
    pub(in crate::cp::media_worker) input_revision: String,
    pub(in crate::cp::media_worker) processor_version: i64,
    pub(in crate::cp::media_worker) state: String,
    pub(in crate::cp::media_worker) attempt_count: i64,
    pub(in crate::cp::media_worker) lease_until: Option<String>,
    pub(in crate::cp::media_worker) error_code: Option<String>,
    pub(in crate::cp::media_worker) usage_json: Option<String>,
    pub(in crate::cp::media_worker) updated_at: String,
    pub(in crate::cp::media_worker) object_key: String,
    pub(in crate::cp::media_worker) mime_type: String,
    pub(in crate::cp::media_worker) codec: String,
    pub(in crate::cp::media_worker) byte_length: i64,
    pub(in crate::cp::media_worker) sample_rate: Option<i64>,
    pub(in crate::cp::media_worker) channels: Option<i64>,
    pub(in crate::cp::media_worker) width: Option<i64>,
    pub(in crate::cp::media_worker) height: Option<i64>,
    pub(in crate::cp::media_worker) media_sha256: String,
    pub(in crate::cp::media_worker) media_processing_state: String,
    pub(in crate::cp::media_worker) started_at: String,
    pub(in crate::cp::media_worker) ended_at: String,
    pub(in crate::cp::media_worker) stream_kind: String,
    pub(in crate::cp::media_worker) capture_session_id: String,
    pub(in crate::cp::media_worker) stream_id: String,
    pub(in crate::cp::media_worker) sequence: i64,
    pub(in crate::cp::media_worker) context_json: Option<String>,
    pub(in crate::cp::media_worker) audio_role: Option<String>,
    pub(in crate::cp::media_worker) audio_route: Option<String>,
    pub(in crate::cp::media_worker) route_epoch: Option<i64>,
}

impl ClaimableRow {
    pub(in crate::cp::media_worker) fn attempt_count_refuses(
        &self,
        total_attempt_cap: i64,
    ) -> bool {
        self.attempt_count < 0 || self.attempt_count >= total_attempt_cap
    }

    fn from_row(row: &Row<'_>) -> rusqlite::Result<Self> {
        Ok(Self {
            job_id: row.get(0)?,
            event_id: row.get(1)?,
            job_kind: row.get(2)?,
            input_revision: row.get(3)?,
            processor_version: row.get(4)?,
            state: row.get(5)?,
            attempt_count: row.get(6)?,
            lease_until: row.get(7)?,
            error_code: row.get(8)?,
            usage_json: row.get(9)?,
            updated_at: row.get(10)?,
            object_key: row.get(11)?,
            mime_type: row.get(12)?,
            codec: row.get(13)?,
            byte_length: row.get(14)?,
            sample_rate: row.get(15)?,
            channels: row.get(16)?,
            width: row.get(17)?,
            height: row.get(18)?,
            media_sha256: row.get(19)?,
            media_processing_state: row.get(20)?,
            started_at: row.get(21)?,
            ended_at: row.get(22)?,
            stream_kind: row.get(23)?,
            capture_session_id: row.get(24)?,
            stream_id: row.get(25)?,
            sequence: row.get(26)?,
            context_json: row.get(27)?,
            audio_role: row.get(28)?,
            audio_route: row.get(29)?,
            route_epoch: row.get(30)?,
        })
    }

    pub(in crate::cp::media_worker) fn class(&self) -> WorkClass {
        if self.job_kind == "gemini_audio" {
            WorkClass::Audio
        } else {
            WorkClass::Screen
        }
    }

    /// Why the claim family cannot resolve THIS row, or `None` when it can.
    ///
    /// Every bound the family refuses a single enumerated row on lives here
    /// exactly once. `planning_event` and `ClaimMember::resolve` both call it
    /// before they do anything else, so a row this accepts is a row both of
    /// them accept — by construction, not by convention — and a row this names
    /// is one the owner may quarantine knowing the plan could never have been
    /// built over it.
    ///
    /// It is a PURE function of the row plus the carried total-attempt cap: no
    /// clock, no eligibility horizon, no sibling rows. That is what makes its
    /// verdict stable across sweeps, and a stable verdict is the whole
    /// justification for spending an attempt on it instead of retrying forever.
    ///
    /// `started_at`/`ended_at` are bounded HERE, and they are the reason this
    /// function is not just a refactor. They are DEVICE-supplied and were
    /// previously only parsed, never measured, on the claim path — while
    /// `wal::failure`'s `FailureMember` and `wal::result`'s `valid_timestamp`
    /// both refuse a `capture_started_at` over `MAX_TIMESTAMP_BYTES`. An
    /// over-long stamp was therefore claimed and PAID FOR, and then refused by
    /// every settle. `cp::media`'s `MAX_DEVICE_TIMESTAMP_BYTES` closes that at
    /// ingest for new events; this closes it for rows already at rest, BEFORE
    /// the claim, which is the only side of the paid call where closing it
    /// costs nothing.
    pub(in crate::cp::media_worker) fn refusal_reason(
        &self,
        total_attempt_cap: i64,
    ) -> Option<WalIdempotencyError> {
        if isotime::parse_epoch_millis(&self.started_at).is_none()
            || isotime::parse_epoch_millis(&self.ended_at).is_none()
            || self.job_id <= 0
            || self.attempt_count_refuses(total_attempt_cap)
            || self.processor_version <= 0
            || self.event_id.is_empty()
            || self.event_id.len() > MAX_ID_BYTES
            || self.job_kind.is_empty()
            || self.job_kind.len() > MAX_ID_BYTES
            || self.input_revision.is_empty()
            || self.input_revision.len() > MAX_ID_BYTES
            || self.media_sha256.is_empty()
            || self.media_sha256.len() > MAX_ID_BYTES
            || self.updated_at.is_empty()
            || self.updated_at.len() > MAX_TIMESTAMP_BYTES
            || self.started_at.is_empty()
            || self.started_at.len() > MAX_TIMESTAMP_BYTES
            || self.ended_at.is_empty()
            || self.ended_at.len() > MAX_TIMESTAMP_BYTES
            || self.media_processing_state.is_empty()
            || self.media_processing_state.len() > MAX_ID_BYTES
            || !CLAIMABLE_STATES.contains(&self.state.as_str())
            || opt_len_exceeds(self.lease_until.as_deref(), MAX_TIMESTAMP_BYTES)
            || opt_len_exceeds(self.error_code.as_deref(), MAX_ID_BYTES)
            || opt_len_exceeds(self.usage_json.as_deref(), MAX_JSON_BYTES)
        {
            return Some(WalIdempotencyError::Malformed);
        }
        None
    }

    /// Read the exact joined predecessor by job id. The quarantine family uses
    /// this inside its mutation transaction to prove that the row which made a
    /// claim impossible is still byte-for-byte the row the owner observed.
    pub(in crate::cp::media_worker) fn read_exact(
        connection: &Connection,
        job_id: i64,
    ) -> rusqlite::Result<Option<Self>> {
        connection
            .query_row(
                "SELECT j.id,j.event_id,j.job_kind,j.input_revision,j.processor_version,\
                        j.state,j.attempt_count,j.lease_until,j.error_code,j.usage_json,j.updated_at,\
                        m.object_key,m.mime_type,m.codec,m.byte_length,m.sample_rate,m.channels,\
                        m.width,m.height,m.sha256,m.processing_state,\
                        e.started_at,e.ended_at,e.stream_kind,e.capture_session_id,e.stream_id,\
                        e.sequence,e.context_json,e.audio_role,e.audio_route,e.route_epoch \
                 FROM media_processing_jobs j \
                 JOIN capture_events e ON e.event_id=j.event_id \
                 JOIN media_objects m ON m.event_id=j.event_id \
                 WHERE j.id=?1",
                [job_id],
                Self::from_row,
            )
            .optional()
    }

    /// A stable commitment to every column the claim scan observed. The
    /// quarantine request fingerprints this value rather than embedding up to
    /// 128 complete joined rows in the one-MiB canonical-request envelope.
    /// `apply()` separately exact-compares the live row to this retained row.
    pub(in crate::cp::media_worker) fn commitment(&self) -> Result<[u8; 32]> {
        let mut hasher = Sha256::new();
        hasher.update(CLAIMABLE_ROW_COMMITMENT_DOMAIN);
        hash_field(&mut hasher, &self.job_id.to_be_bytes())?;
        hash_field(&mut hasher, self.event_id.as_bytes())?;
        hash_field(&mut hasher, self.job_kind.as_bytes())?;
        hash_field(&mut hasher, self.input_revision.as_bytes())?;
        hash_field(&mut hasher, &self.processor_version.to_be_bytes())?;
        hash_field(&mut hasher, self.state.as_bytes())?;
        hash_field(&mut hasher, &self.attempt_count.to_be_bytes())?;
        hash_opt(&mut hasher, self.lease_until.as_deref())?;
        hash_opt(&mut hasher, self.error_code.as_deref())?;
        hash_opt(&mut hasher, self.usage_json.as_deref())?;
        hash_field(&mut hasher, self.updated_at.as_bytes())?;
        hash_field(&mut hasher, self.object_key.as_bytes())?;
        hash_field(&mut hasher, self.mime_type.as_bytes())?;
        hash_field(&mut hasher, self.codec.as_bytes())?;
        hash_field(&mut hasher, &self.byte_length.to_be_bytes())?;
        hash_opt_i64(&mut hasher, self.sample_rate)?;
        hash_opt_i64(&mut hasher, self.channels)?;
        hash_opt_i64(&mut hasher, self.width)?;
        hash_opt_i64(&mut hasher, self.height)?;
        hash_field(&mut hasher, self.media_sha256.as_bytes())?;
        hash_field(&mut hasher, self.media_processing_state.as_bytes())?;
        hash_field(&mut hasher, self.started_at.as_bytes())?;
        hash_field(&mut hasher, self.ended_at.as_bytes())?;
        hash_field(&mut hasher, self.stream_kind.as_bytes())?;
        hash_field(&mut hasher, self.capture_session_id.as_bytes())?;
        hash_field(&mut hasher, self.stream_id.as_bytes())?;
        hash_field(&mut hasher, &self.sequence.to_be_bytes())?;
        hash_opt(&mut hasher, self.context_json.as_deref())?;
        hash_opt(&mut hasher, self.audio_role.as_deref())?;
        hash_opt(&mut hasher, self.audio_route.as_deref())?;
        hash_opt_i64(&mut hasher, self.route_epoch)?;
        Ok(hasher.finalize().into())
    }

    /// Whether this row can never enter even a one-member planner window.
    pub(in crate::cp::media_worker) fn is_unwindowable(
        &self,
        total_attempt_cap: i64,
    ) -> Result<bool> {
        let candidate = self.planning_event(total_attempt_cap)?;
        Ok(media_planner::plan_first(&[candidate])
            .member_job_ids
            .is_empty())
    }

    /// The member-attributable half of the claim constructor's commit-order
    /// guard, evaluated directly over the observed joined row.
    pub(in crate::cp::media_worker) fn construction_refuses_at(
        &self,
        job_kind: &str,
        processor_version: i64,
        committed_at: &str,
    ) -> bool {
        let latest = match self.lease_until.as_deref() {
            Some(lease) if lease > self.updated_at.as_str() => lease,
            _ => self.updated_at.as_str(),
        };
        self.job_kind != job_kind
            || self.processor_version != processor_version
            || latest > committed_at
    }

    /// The planner input, derived identically for the owner and for `apply()`.
    /// `plan_first` is a pure function of this vector — it re-sorts by
    /// `(started_ms, sequence, job_id)` and folds with saturating arithmetic
    /// over compile-time constants only — so the re-derivation inside `apply()`
    /// is exact.
    pub(in crate::cp::media_worker) fn planning_event(
        &self,
        total_attempt_cap: i64,
    ) -> Result<PlanningEvent> {
        if let Some(error) = self.refusal_reason(total_attempt_cap) {
            return Err(error);
        }
        let started_ms =
            isotime::parse_epoch_millis(&self.started_at).ok_or(WalIdempotencyError::Malformed)?;
        let ended_ms =
            isotime::parse_epoch_millis(&self.ended_at).ok_or(WalIdempotencyError::Malformed)?;
        Ok(PlanningEvent {
            job_id: self.job_id,
            event_id: self.event_id.clone(),
            class: self.class(),
            capture_session_id: self.capture_session_id.clone(),
            stream_id: self.stream_id.clone(),
            sequence: self.sequence,
            started_ms,
            ended_ms,
            byte_length: self.byte_length,
            pixel_count: self
                .width
                .unwrap_or(0)
                .saturating_mul(self.height.unwrap_or(0)),
            route_key: format!(
                "{}:{}:{}:{}:{}:{}:{}:{}",
                self.stream_kind,
                self.mime_type,
                self.codec,
                self.sample_rate.unwrap_or(0),
                self.channels.unwrap_or(0),
                self.audio_role.as_deref().unwrap_or(""),
                self.audio_route.as_deref().unwrap_or(""),
                self.route_epoch.unwrap_or(0)
            ),
        })
    }
}

/// One resolved member of the claim with every predecessor field the CAS pins.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(in crate::cp::media_worker) struct ClaimMember {
    job_id: i64,
    event_id: String,
    job_kind: String,
    input_revision: String,
    processor_version: i64,
    state: String,
    attempt_count: i64,
    lease_until: Option<String>,
    error_code: Option<String>,
    usage_json: Option<String>,
    updated_at: String,
    media_processing_state: String,
    media_sha256: String,
    window_start_ms: i64,
    window_end_ms: i64,
    ordinal: i64,
}

impl ClaimMember {
    fn resolve(
        row: &ClaimableRow,
        ordinal: i64,
        plan_started_ms: i64,
        total_attempt_cap: i64,
    ) -> Result<Self> {
        // The row's own bounds live in ONE place (`ClaimableRow::refusal_reason`)
        // so the set the owner can attribute a refusal to is exactly the set
        // this constructor rejects. `ordinal` is the only non-row fact here.
        if let Some(error) = row.refusal_reason(total_attempt_cap) {
            return Err(error);
        }
        let started_ms =
            isotime::parse_epoch_millis(&row.started_at).ok_or(WalIdempotencyError::Malformed)?;
        let ended_ms =
            isotime::parse_epoch_millis(&row.ended_at).ok_or(WalIdempotencyError::Malformed)?;
        if ordinal < 0 {
            return Err(WalIdempotencyError::Malformed);
        }
        Ok(Self {
            job_id: row.job_id,
            event_id: row.event_id.clone(),
            job_kind: row.job_kind.clone(),
            input_revision: row.input_revision.clone(),
            processor_version: row.processor_version,
            state: row.state.clone(),
            attempt_count: row.attempt_count,
            lease_until: row.lease_until.clone(),
            error_code: row.error_code.clone(),
            usage_json: row.usage_json.clone(),
            updated_at: row.updated_at.clone(),
            media_processing_state: row.media_processing_state.clone(),
            media_sha256: row.media_sha256.clone(),
            window_start_ms: started_ms - plan_started_ms,
            window_end_ms: ended_ms - plan_started_ms,
            ordinal,
        })
    }

    fn latest_observed_timestamp(&self) -> &str {
        match self.lease_until.as_deref() {
            Some(lease) if lease > self.updated_at.as_str() => lease,
            _ => self.updated_at.as_str(),
        }
    }

    /// The per-member half of `MediaWorkClaimPlan::new`'s construction guard:
    /// every refusal there that can be ATTRIBUTED to one member rather than to
    /// the plan as a whole.
    ///
    /// `new` refuses on the first member this names; the structured refusal
    /// classifier walks every member with the same function after first
    /// excluding plan-wide clock/account/code failures. The set the owner may
    /// charge is therefore exactly the stored member evidence the guard
    /// refuses on, without blaming a healthy member for a global inversion.
    ///
    /// The `latest_observed_timestamp` comparison is #331's own trigger, and
    /// it is NOT relaxed by being attributable: it still refuses, still
    /// compares raw strings, still folds `lease_until`. All that changes is
    /// that the refusal now has a name, so the response to it can be bounded.
    fn construction_refusal(&self, committed_at: &str) -> Option<WalIdempotencyError> {
        if self.latest_observed_timestamp() > committed_at {
            return Some(WalIdempotencyError::Malformed);
        }
        None
    }
}

/// A durable claim-construction refusal that may be charged to exact stored
/// evidence. Global account/code invariants and `claimed_at > committed_at`
/// never produce one of these.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::cp::media_worker) enum AttributableClaimRefusalKind {
    MemberCommitOrder,
    DuplicateEventTopology,
    WorkUnitMalformed,
    WorkUnitCommitOrder,
    WorkUnitDerivedMismatch,
    WorkUnitAttemptCount,
}

/// The complete stored evidence for one attributable plan refusal.
pub(in crate::cp::media_worker) struct AttributableClaimRefusal {
    pub(in crate::cp::media_worker) kind: AttributableClaimRefusalKind,
    pub(in crate::cp::media_worker) rows: Vec<ClaimableRow>,
    pub(in crate::cp::media_worker) work_unit_id: Option<String>,
    pub(in crate::cp::media_worker) unit: Option<ClaimedUnitPredecessor>,
    pub(in crate::cp::media_worker) unit_expectation: Option<ClaimedUnitExpectation>,
    pub(in crate::cp::media_worker) claimed_at: String,
    pub(in crate::cp::media_worker) committed_at: String,
}

/// The member jobs a claim over `observation` could not be constructed for,
/// with the observed predecessor tuple each quarantine CAS needs.
///
/// An EMPTY result does not mean the plan builds. This helper covers only the
/// member commit-order guard; the owner's structured classifier separately
/// names duplicate-event and stored-work-unit evidence, while account/code and
/// `claimed_at`/`committed_at` failures remain deliberately non-charging.
///
/// Cheap enough to run unconditionally (at most `MAX_MEMBERS` members, three
/// comparisons each) and pure, so the owner can derive it BEFORE handing the
/// observation to `new` and use it only if `new` refuses.
pub(in crate::cp::media_worker) fn unplannable_members(
    observation: &ClaimObservation,
    processor_version: i64,
    committed_at: &str,
) -> Vec<ClaimableRow> {
    let job_kind = job_kind_for(observation.class);
    if observation
        .members
        .iter()
        .any(|member| member.job_kind != job_kind || member.processor_version != processor_version)
    {
        return Vec::new();
    }
    observation
        .members
        .iter()
        .filter(|member| member.construction_refusal(committed_at).is_some())
        .filter_map(|member| {
            observation
                .rows
                .iter()
                .find(|row| row.job_id == member.job_id)
                .cloned()
        })
        .collect()
}

/// The observed `media_work_units` row. A claim after a failure or a lease
/// expiry finds one; the first claim of a window does not.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(in crate::cp::media_worker) struct ClaimedUnitPredecessor {
    pub(in crate::cp::media_worker) work_class: String,
    pub(in crate::cp::media_worker) processor_version: i64,
    pub(in crate::cp::media_worker) state: String,
    pub(in crate::cp::media_worker) started_at: String,
    pub(in crate::cp::media_worker) ended_at: String,
    pub(in crate::cp::media_worker) reserved_output_tokens: i64,
    pub(in crate::cp::media_worker) attempt_count: i64,
    pub(in crate::cp::media_worker) reservation_retained: i64,
    pub(in crate::cp::media_worker) error_code: Option<String>,
    pub(in crate::cp::media_worker) usage_json: Option<String>,
    pub(in crate::cp::media_worker) created_at: String,
    pub(in crate::cp::media_worker) updated_at: String,
}

impl ClaimedUnitPredecessor {
    pub(in crate::cp::media_worker) fn attempt_count_refuses(
        &self,
        total_attempt_cap: i64,
    ) -> bool {
        self.attempt_count < 0 || self.attempt_count >= total_attempt_cap
    }

    pub(in crate::cp::media_worker) fn read(
        connection: &Connection,
        work_unit_id: &str,
    ) -> rusqlite::Result<Option<Self>> {
        connection
            .query_row(
                "SELECT work_class,processor_version,state,started_at,ended_at,\
                        reserved_output_tokens,attempt_count,reservation_retained,error_code,\
                        usage_json,created_at,updated_at \
                 FROM media_work_units WHERE id=?1",
                [work_unit_id],
                |row| {
                    Ok(Self {
                        work_class: row.get(0)?,
                        processor_version: row.get(1)?,
                        state: row.get(2)?,
                        started_at: row.get(3)?,
                        ended_at: row.get(4)?,
                        reserved_output_tokens: row.get(5)?,
                        attempt_count: row.get(6)?,
                        reservation_retained: row.get(7)?,
                        error_code: row.get(8)?,
                        usage_json: row.get(9)?,
                        created_at: row.get(10)?,
                        updated_at: row.get(11)?,
                    })
                },
            )
            .optional()
    }

    pub(in crate::cp::media_worker) fn refusal_reason(
        &self,
        total_attempt_cap: i64,
    ) -> Option<WalIdempotencyError> {
        if self.work_class.is_empty()
            || self.work_class.len() > MAX_ID_BYTES
            || self.processor_version <= 0
            || self.state.is_empty()
            || self.state.len() > MAX_ID_BYTES
            || isotime::parse_epoch_millis(&self.started_at).is_none()
            || isotime::parse_epoch_millis(&self.ended_at).is_none()
            || self.started_at.len() > MAX_TIMESTAMP_BYTES
            || self.ended_at.len() > MAX_TIMESTAMP_BYTES
            || self.reserved_output_tokens <= 0
            || self.attempt_count_refuses(total_attempt_cap)
            || self.reservation_retained < 0
            || self.created_at.is_empty()
            || self.created_at.len() > MAX_TIMESTAMP_BYTES
            || self.updated_at.is_empty()
            || self.updated_at.len() > MAX_TIMESTAMP_BYTES
            || opt_len_exceeds(self.error_code.as_deref(), MAX_ID_BYTES)
            || opt_len_exceeds(self.usage_json.as_deref(), MAX_JSON_BYTES)
        {
            return Some(WalIdempotencyError::Malformed);
        }
        None
    }

    fn validate(&self, total_attempt_cap: i64) -> Result<()> {
        match self.refusal_reason(total_attempt_cap) {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }

    pub(in crate::cp::media_worker) fn commitment(&self) -> Result<[u8; 32]> {
        let mut hasher = Sha256::new();
        hash_field(&mut hasher, self.work_class.as_bytes())?;
        hash_field(&mut hasher, &self.processor_version.to_be_bytes())?;
        hash_field(&mut hasher, self.state.as_bytes())?;
        hash_field(&mut hasher, self.started_at.as_bytes())?;
        hash_field(&mut hasher, self.ended_at.as_bytes())?;
        hash_field(&mut hasher, &self.reserved_output_tokens.to_be_bytes())?;
        hash_field(&mut hasher, &self.attempt_count.to_be_bytes())?;
        hash_field(&mut hasher, &self.reservation_retained.to_be_bytes())?;
        hash_opt(&mut hasher, self.error_code.as_deref())?;
        hash_opt(&mut hasher, self.usage_json.as_deref())?;
        hash_field(&mut hasher, self.created_at.as_bytes())?;
        hash_field(&mut hasher, self.updated_at.as_bytes())?;
        Ok(hasher.finalize().into())
    }
}

/// The immutable work-unit topology the carried claim would insert on a first
/// attempt. SQLite's conflict arm does not rewrite these columns, so an
/// existing row must already equal them byte-for-byte.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(in crate::cp::media_worker) struct ClaimedUnitExpectation {
    pub(in crate::cp::media_worker) work_class: String,
    pub(in crate::cp::media_worker) processor_version: i64,
    pub(in crate::cp::media_worker) started_at: String,
    pub(in crate::cp::media_worker) ended_at: String,
    pub(in crate::cp::media_worker) reserved_output_tokens: i64,
}

impl ClaimedUnitExpectation {
    fn new(
        class: WorkClass,
        processor_version: i64,
        started_ms: i64,
        ended_ms: i64,
        reserved_output_tokens: i64,
    ) -> Self {
        Self {
            work_class: class_name(class).to_owned(),
            processor_version,
            started_at: isotime::format_epoch_millis(started_ms),
            ended_at: isotime::format_epoch_millis(ended_ms),
            reserved_output_tokens,
        }
    }

    pub(in crate::cp::media_worker) fn commitment(&self) -> Result<[u8; 32]> {
        let mut hasher = Sha256::new();
        hash_field(&mut hasher, self.work_class.as_bytes())?;
        hash_field(&mut hasher, &self.processor_version.to_be_bytes())?;
        hash_field(&mut hasher, self.started_at.as_bytes())?;
        hash_field(&mut hasher, self.ended_at.as_bytes())?;
        hash_field(&mut hasher, &self.reserved_output_tokens.to_be_bytes())?;
        Ok(hasher.finalize().into())
    }
}

impl ClaimedUnitPredecessor {
    pub(in crate::cp::media_worker) fn derived_mismatch(
        &self,
        expected: &ClaimedUnitExpectation,
    ) -> bool {
        self.work_class != expected.work_class
            || self.processor_version != expected.processor_version
            || self.started_at != expected.started_at
            || self.ended_at != expected.ended_at
            || self.reserved_output_tokens != expected.reserved_output_tokens
    }
}

/// The deterministic member resolution: `plan_first` over the enumerated
/// candidates, then the member subset in ordinal order. Shared by the owner
/// and by `apply()` so "the same planner ran" holds by construction.
struct ResolvedClaim {
    members: Vec<ClaimMember>,
    started_ms: i64,
    ended_ms: i64,
}

/// What one enumeration resolves to. The third arm is the whole point: before
/// it existed, an enumeration that produced no plan was indistinguishable from
/// an empty queue, and "indistinguishable from an empty queue" is how a
/// deterministic refusal became a silent permanent wedge.
enum ClaimResolution {
    /// Nothing claimable at this horizon.
    Empty,
    Resolved(Box<ResolvedClaim>),
    /// Rows that cannot be planned, and will not be plannable on any later
    /// sweep because nothing about them or about `plan_first` depends on time.
    /// Named so the owner can bound its response to them.
    Unplannable(Vec<ClaimableRow>),
}

fn resolve_claim(rows: &[ClaimableRow], total_attempt_cap: i64) -> Result<ClaimResolution> {
    if rows.is_empty() {
        return Ok(ClaimResolution::Empty);
    }
    // A row the family cannot resolve is reported rather than collapsed into a
    // whole-enumeration refusal: the offending rows are named, the rest of the
    // lane is untouched, and the next sweep plans what is left once these are
    // quarantined out of the eligible set.
    let unresolvable = rows
        .iter()
        .filter(|row| row.refusal_reason(total_attempt_cap).is_some())
        .cloned()
        .collect::<Vec<_>>();
    if !unresolvable.is_empty() {
        return Ok(ClaimResolution::Unplannable(unresolvable));
    }
    let candidates = rows
        .iter()
        .map(|row| row.planning_event(total_attempt_cap))
        .collect::<Result<Vec<_>>>()?;
    let plan = media_planner::plan_first(&candidates);
    if plan.member_job_ids.is_empty() {
        // The head could not enter a window of its own — an audio event longer
        // than `MAX_AUDIO_WINDOW_MS`, a frame over the byte or pixel cap. The
        // planner is pure, so the identical head is re-selected by every
        // sweep; reporting `Empty` here is what let one such event hold its
        // whole class `pending` forever.
        let head = rows
            .iter()
            .find(|row| row.job_id == plan.head_job_id)
            .ok_or(WalIdempotencyError::Corrupt)?;
        return Ok(ClaimResolution::Unplannable(vec![head.clone()]));
    }
    let mut members = Vec::with_capacity(plan.member_job_ids.len());
    for (ordinal, job_id) in plan.member_job_ids.iter().enumerate() {
        let row = rows
            .iter()
            .find(|row| row.job_id == *job_id)
            .ok_or(WalIdempotencyError::Corrupt)?;
        members.push(ClaimMember::resolve(
            row,
            i64::try_from(ordinal).map_err(|_| WalIdempotencyError::Limit)?,
            plan.started_ms,
            total_attempt_cap,
        )?);
    }
    Ok(ClaimResolution::Resolved(Box::new(ResolvedClaim {
        members,
        started_ms: plan.started_ms,
        ended_ms: plan.ended_ms,
    })))
}

/// Everything the owner reads in ONE routed snapshot, so no carried fact can
/// straddle two reads.
pub(in crate::cp::media_worker) struct ClaimObservation {
    pub(in crate::cp::media_worker) members: Vec<ClaimMember>,
    pub(in crate::cp::media_worker) rows: Vec<ClaimableRow>,
    pub(in crate::cp::media_worker) work_unit_id: String,
    pub(in crate::cp::media_worker) class: WorkClass,
    pub(in crate::cp::media_worker) started_ms: i64,
    pub(in crate::cp::media_worker) ended_ms: i64,
    pub(in crate::cp::media_worker) unit: Option<ClaimedUnitPredecessor>,
    pub(in crate::cp::media_worker) reservation_retained: bool,
    pub(in crate::cp::media_worker) usage_json: String,
}

/// Carried plan-wide inputs shared by refusal attribution and construction.
///
/// Keeping these inputs together makes the two callers feed the same guard
/// without widening that guard's method signature every time a new immutable
/// construction fact is added.
struct ClaimConstructionContext<'a> {
    account_id: &'a str,
    processor_version: i64,
    scan_limit: i64,
    total_attempt_cap: i64,
    lease_seconds: i64,
    reserved_output_tokens: i64,
    claimed_at: &'a str,
    committed_at: &'a str,
}

impl ClaimObservation {
    /// The member rows in ordinal order, for the owner's local work unit.
    pub(in crate::cp::media_worker) fn member_rows(&self) -> Vec<&ClaimableRow> {
        self.members
            .iter()
            .filter_map(|member| self.rows.iter().find(|row| row.job_id == member.job_id))
            .collect()
    }

    fn global_construction_refuses(&self, context: &ClaimConstructionContext<'_>) -> bool {
        let job_kind = job_kind_for(self.class);
        crate::store::validate_user_id(context.account_id).is_err()
            || self.members.is_empty()
            || self.members.len() > MAX_MEMBERS
            || context.processor_version <= 0
            || context.total_attempt_cap <= 0
            || context.reserved_output_tokens <= 0
            || context.lease_seconds <= 0
            || !(1..=MAX_SCAN_LIMIT).contains(&context.scan_limit)
            || usize::try_from(context.scan_limit)
                .map_or(true, |limit| self.members.len() > limit)
            || self.work_unit_id.is_empty()
            || self.work_unit_id.len() > MAX_ID_BYTES
            || self.usage_json.is_empty()
            || self.usage_json.len() > MAX_JSON_BYTES
            || context.claimed_at.is_empty()
            || context.claimed_at.len() > MAX_TIMESTAMP_BYTES
            || context.committed_at.is_empty()
            || context.committed_at.len() > MAX_TIMESTAMP_BYTES
            // This PLAN-wide clock inversion has priority over every member
            // timestamp. Otherwise a healthy `updated_at` between the two
            // clock samples would be blamed on the job for the enclave clock
            // moving backwards.
            || context.claimed_at > context.committed_at
            || self.members.iter().any(|member| {
                member.job_kind != job_kind
                    || member.processor_version != context.processor_version
            })
            || self.members.iter().enumerate().any(|(index, member)| {
                member.ordinal != i64::try_from(index).unwrap_or(i64::MIN)
                    || self
                        .members
                        .iter()
                        .skip(index + 1)
                        .any(|other| other.job_id == member.job_id)
            })
    }

    fn duplicate_event_rows(&self) -> Vec<ClaimableRow> {
        self.members
            .iter()
            .filter(|member| {
                self.members
                    .iter()
                    .filter(|other| other.event_id == member.event_id)
                    .count()
                    > 1
            })
            .filter_map(|member| {
                self.rows
                    .iter()
                    .find(|row| row.job_id == member.job_id)
                    .cloned()
            })
            .collect()
    }

    /// Classify only refusals proved by durable stored evidence. The owner
    /// calls this before consuming the observation. A `None` result is
    /// deliberately non-charging: either the plan constructs, or the refusal
    /// belongs to account/code/clock state rather than to a job.
    #[allow(clippy::too_many_arguments)]
    pub(in crate::cp::media_worker) fn attributable_refusal(
        &self,
        account_id: &str,
        processor_version: i64,
        scan_limit: i64,
        total_attempt_cap: i64,
        lease_seconds: i64,
        reserved_output_tokens: i64,
        claimed_at: &str,
        committed_at: &str,
    ) -> Option<AttributableClaimRefusal> {
        let context = ClaimConstructionContext {
            account_id,
            processor_version,
            scan_limit,
            total_attempt_cap,
            lease_seconds,
            reserved_output_tokens,
            claimed_at,
            committed_at,
        };
        if self.global_construction_refuses(&context) {
            return None;
        }
        let member_rows = unplannable_members(self, processor_version, committed_at);
        if !member_rows.is_empty() {
            return Some(AttributableClaimRefusal {
                kind: AttributableClaimRefusalKind::MemberCommitOrder,
                rows: member_rows,
                work_unit_id: None,
                unit: None,
                unit_expectation: None,
                claimed_at: claimed_at.to_owned(),
                committed_at: committed_at.to_owned(),
            });
        }
        let duplicates = self.duplicate_event_rows();
        if !duplicates.is_empty() {
            return Some(AttributableClaimRefusal {
                kind: AttributableClaimRefusalKind::DuplicateEventTopology,
                rows: duplicates,
                work_unit_id: None,
                unit: None,
                unit_expectation: None,
                claimed_at: claimed_at.to_owned(),
                committed_at: committed_at.to_owned(),
            });
        }
        let unit = self.unit.as_ref()?;
        let expected = ClaimedUnitExpectation::new(
            self.class,
            processor_version,
            self.started_ms,
            self.ended_ms,
            reserved_output_tokens,
        );
        let kind = if unit.attempt_count_refuses(total_attempt_cap) {
            AttributableClaimRefusalKind::WorkUnitAttemptCount
        } else if unit.refusal_reason(total_attempt_cap).is_some() {
            AttributableClaimRefusalKind::WorkUnitMalformed
        } else if unit.created_at.as_str() > committed_at || unit.updated_at.as_str() > committed_at
        {
            AttributableClaimRefusalKind::WorkUnitCommitOrder
        } else if unit.derived_mismatch(&expected) {
            AttributableClaimRefusalKind::WorkUnitDerivedMismatch
        } else {
            return None;
        };
        Some(AttributableClaimRefusal {
            kind,
            rows: self.member_rows().into_iter().cloned().collect(),
            work_unit_id: Some(self.work_unit_id.clone()),
            unit: Some(unit.clone()),
            unit_expectation: Some(expected),
            claimed_at: claimed_at.to_owned(),
            committed_at: committed_at.to_owned(),
        })
    }
}

/// The outcome of the owner's one routed pre-claim read.
pub(in crate::cp::media_worker) enum ClaimScan {
    /// T24: the epoch-0 `sqlite_sequence` gate is closed, so the audio class is
    /// skipped entirely — no claim, no reservation, no PAID call.
    AudioLaneBlocked,
    /// Nothing claimable in this class at this horizon.
    Idle,
    /// Enumerated rows the family cannot plan, and will not be able to plan on
    /// any later sweep. Carries the observed predecessor of each so the owner
    /// can quarantine them without a second read — and, decisively, BEFORE any
    /// reservation or PAID provider call, which is the only side of the call
    /// where refusing is free.
    Unplannable(Vec<ClaimableRow>),
    Observed(Box<ClaimObservation>),
}

/// The single entry point the owner uses. The T24 probe lives HERE, ahead of
/// every enumeration, so no caller can open the claim boundary for audio
/// without passing it.
pub(in crate::cp::media_worker) fn scan_for_claim(
    connection: &Connection,
    class: WorkClass,
    processor_version: i64,
    as_of: &str,
    scan_limit: i64,
    total_attempt_cap: i64,
) -> Result<ClaimScan> {
    if total_attempt_cap <= 0 {
        // A carried code/policy invariant is global and cannot be charged to a
        // stored row. Reject it before enumeration rather than making every
        // non-negative attempt look like attributable poison.
        return Err(WalIdempotencyError::Malformed);
    }
    if matches!(class, WorkClass::Audio) && !audio_sequence_gate_open(connection) {
        return Ok(ClaimScan::AudioLaneBlocked);
    }
    observe_claim(
        connection,
        class,
        processor_version,
        as_of,
        scan_limit,
        total_attempt_cap,
    )
}

/// What one sweep of the claim lane did, for a caller that only needs to know
/// whether the lane still moves. Test-only; see
/// [`probe_claim_lane_for_ingest_regression`].
#[cfg(test)]
#[derive(Debug)]
pub(crate) enum ClaimLaneProbe {
    /// `scan_for_claim` observed work AND `MediaWorkClaimPlan::new` accepted
    /// it. This is the only outcome that means the lane is not wedged.
    Constructed,
    /// Nothing claimable at this horizon.
    Idle,
    /// T24's `sqlite_sequence` gate held the audio class shut.
    AudioLaneBlocked,
    /// Work was observed and the plan REFUSED to construct. Carries the member
    /// jobs the refusal is attributable to, which is exactly the set
    /// `claim_media_work_unit` quarantines; an EMPTY set is a refusal no job
    /// may be charged for.
    Refused(WalIdempotencyError, Vec<i64>),
    /// The enumeration itself could not be planned — an unresolvable row, or a
    /// head that fits no window. Carries the named job ids.
    Unplannable(Vec<i64>),
}

/// Test-only bridge for the ingest -> claim regression tests, which have to
/// live beside the ingest writer in `cp::media::wal::capture_event` (that is
/// the only module that can construct its plan) while the guard they regress
/// lives here.
///
/// It composes the EXACT two production calls `media_worker::claim_media_work_unit`
/// makes, in order and with the same arguments — `scan_for_claim` followed by
/// `MediaWorkClaimPlan::new` — rather than reimplementing either. Anything it
/// accepts, the production sweep accepts; anything it attributes, the
/// production sweep sends to the bounded quarantine instead of collapsing the
/// refusal into `Idle` and re-deriving it forever.
#[cfg(test)]
#[allow(clippy::too_many_arguments)]
pub(crate) fn probe_claim_lane_for_ingest_regression(
    connection: &Connection,
    account_id: &str,
    class: WorkClass,
    processor_version: i64,
    scan_limit: i64,
    total_attempt_cap: i64,
    lease_seconds: i64,
    reserved_output_tokens: i64,
    claimed_at: &str,
    committed_at: &str,
) -> ClaimLaneProbe {
    // The scan's own refusal is propagated verbatim, never collapsed: a
    // member row the enumeration itself cannot resolve (an over-long
    // `updated_at`, say) wedges the lane exactly as a guard refusal does, and
    // a caller has to be able to tell the two apart.
    let scan = match scan_for_claim(
        connection,
        class,
        processor_version,
        claimed_at,
        scan_limit,
        total_attempt_cap,
    ) {
        Ok(scan) => scan,
        Err(error) => return ClaimLaneProbe::Refused(error, Vec::new()),
    };
    let observation = match scan {
        ClaimScan::Observed(observation) => *observation,
        ClaimScan::Idle => return ClaimLaneProbe::Idle,
        ClaimScan::AudioLaneBlocked => return ClaimLaneProbe::AudioLaneBlocked,
        ClaimScan::Unplannable(rows) => {
            return ClaimLaneProbe::Unplannable(rows.iter().map(|row| row.job_id).collect())
        }
    };
    // Derived from the observation BEFORE it is consumed, exactly as the owner
    // does, so the probe cannot report an attribution the production sweep
    // would not have made.
    let attributed = observation
        .attributable_refusal(
            account_id,
            processor_version,
            scan_limit,
            total_attempt_cap,
            lease_seconds,
            reserved_output_tokens,
            claimed_at,
            committed_at,
        )
        .map_or_else(Vec::new, |refusal| {
            refusal.rows.iter().map(|row| row.job_id).collect()
        });
    match MediaWorkClaimPlan::new(
        account_id.to_owned(),
        observation,
        processor_version,
        scan_limit,
        total_attempt_cap,
        lease_seconds,
        reserved_output_tokens,
        claimed_at.to_owned(),
        committed_at.to_owned(),
    ) {
        Ok(_) => ClaimLaneProbe::Constructed,
        Err(error) => ClaimLaneProbe::Refused(error, attributed),
    }
}

pub(in crate::cp::media_worker) fn observe_claim(
    connection: &Connection,
    class: WorkClass,
    processor_version: i64,
    as_of: &str,
    scan_limit: i64,
    total_attempt_cap: i64,
) -> Result<ClaimScan> {
    let rows = enumerate_claimable(
        connection,
        processor_version,
        job_kind_for(class),
        as_of,
        scan_limit,
    )
    .map_err(|_| WalIdempotencyError::Unavailable)?;
    let resolved = match resolve_claim(&rows, total_attempt_cap)? {
        ClaimResolution::Resolved(resolved) => *resolved,
        ClaimResolution::Empty => return Ok(ClaimScan::Idle),
        ClaimResolution::Unplannable(rows) => return Ok(ClaimScan::Unplannable(rows)),
    };
    let work_unit_id = work_unit_id(
        class,
        resolved
            .members
            .iter()
            .map(|member| (member.event_id.as_str(), member.media_sha256.as_str())),
    );
    let unit = ClaimedUnitPredecessor::read(connection, &work_unit_id)
        .map_err(|_| WalIdempotencyError::Unavailable)?;
    let reservation_retained = derive_reservation_retained(&resolved.members, &work_unit_id);
    let usage_json = derive_usage_json(
        &work_unit_id,
        class_name(class),
        resolved.members.len(),
        reservation_retained,
        processor_version,
    );
    Ok(ClaimScan::Observed(Box::new(ClaimObservation {
        members: resolved.members,
        rows,
        work_unit_id,
        class,
        started_ms: resolved.started_ms,
        ended_ms: resolved.ended_ms,
        unit,
        reservation_retained,
        usage_json,
    })))
}

/// The exact legacy predicate (`lease_work_unit`): a retained reservation is
/// one where EVERY member already carries this work unit's `reserved` usage
/// marker, so a retry does not re-reserve tokens it already holds.
fn derive_reservation_retained(members: &[ClaimMember], work_unit_id: &str) -> bool {
    members.iter().all(|member| {
        member
            .usage_json
            .as_deref()
            .and_then(|raw| serde_json::from_str::<Value>(raw).ok())
            .is_some_and(|usage| {
                usage.get("work_unit_id").and_then(Value::as_str) == Some(work_unit_id)
                    && usage.get("reservation_state").and_then(Value::as_str) == Some("reserved")
            })
    })
}

/// The exact legacy `json!` shape. `serde_json` is declared without
/// `preserve_order`, so `Map` is a `BTreeMap` and the key order is sorted and
/// deterministic; enabling that feature would change every stored byte string
/// here. Pinned by test.
fn derive_usage_json(
    work_unit_id: &str,
    class_name: &str,
    member_count: usize,
    reservation_retained: bool,
    processor_version: i64,
) -> String {
    json!({
        "work_unit_id": work_unit_id,
        "work_class": class_name,
        "member_count": member_count,
        "reservation_state": if reservation_retained { "reserved" } else { "planned" },
        "processor_version": processor_version,
    })
    .to_string()
}

pub(crate) struct MediaWorkClaimPlan {
    operation_id: WalLogicalOperationId,
    account_id: String,
    work_unit_id: String,
    class_name: String,
    job_kind: String,
    processor_version: i64,
    scan_limit: i64,
    total_attempt_cap: i64,
    lease_seconds: i64,
    reserved_output_tokens: i64,
    claimed_at: String,
    committed_at: String,
    usage_json: String,
    reservation_retained: bool,
    unit: Option<ClaimedUnitPredecessor>,
    members: Vec<ClaimMember>,
    started_ms: i64,
    ended_ms: i64,
}

impl MediaWorkClaimPlan {
    /// Construct from ONE routed observation. Every deterministic refusal here
    /// is `Malformed`/`Limit` and happens before the claim moves anything. The
    /// owner attributes only the guard's member-local half and sends those
    /// exact rows to the bounded quarantine; plan-level defects remain a
    /// counted no-op, because charging a job for an unattributable refusal
    /// would convert a code defect into permanent data loss.
    #[allow(clippy::too_many_arguments)]
    pub(in crate::cp::media_worker) fn new(
        account_id: String,
        observation: ClaimObservation,
        processor_version: i64,
        scan_limit: i64,
        total_attempt_cap: i64,
        lease_seconds: i64,
        reserved_output_tokens: i64,
        claimed_at: String,
        committed_at: String,
    ) -> Result<Self> {
        if observation.members.len() > MAX_MEMBERS {
            return Err(WalIdempotencyError::Limit);
        }
        let context = ClaimConstructionContext {
            account_id: &account_id,
            processor_version,
            scan_limit,
            total_attempt_cap,
            lease_seconds,
            reserved_output_tokens,
            claimed_at: &claimed_at,
            committed_at: &committed_at,
        };
        if observation.global_construction_refuses(&context) {
            return Err(WalIdempotencyError::Malformed);
        }
        let ClaimObservation {
            members,
            rows: _,
            work_unit_id,
            class,
            started_ms,
            ended_ms,
            unit,
            reservation_retained,
            usage_json,
        } = observation;
        let class_name = class_name(class).to_owned();
        let job_kind = job_kind_for(class).to_owned();
        let unit_expectation = ClaimedUnitExpectation::new(
            class,
            processor_version,
            started_ms,
            ended_ms,
            reserved_output_tokens,
        );
        // The attributable per-member guards, including #331's own
        // `latest_observed_timestamp` comparison, run through the SAME
        // `construction_refusal` the owner's structured classifier walks. The
        // guard is unchanged in strength; only its refusal is now nameable.
        if let Some(error) = members
            .iter()
            .find_map(|member| member.construction_refusal(&committed_at))
        {
            return Err(error);
        }
        // Ordinal order is `plan_first`'s, keyed on (started_ms, sequence,
        // job_id) — NOT ascending job_id. Strict uniqueness is what the CAS
        // needs; a repeated job or event would double-apply one increment.
        for (index, member) in members.iter().enumerate() {
            if member.ordinal != i64::try_from(index).map_err(|_| WalIdempotencyError::Limit)?
                || members
                    .iter()
                    .skip(index + 1)
                    .any(|other| other.job_id == member.job_id || other.event_id == member.event_id)
            {
                return Err(WalIdempotencyError::Malformed);
            }
        }
        if let Some(unit) = unit.as_ref() {
            unit.validate(total_attempt_cap)?;
        }
        // A plan whose commit stamp precedes an observed fact is refused at
        // construction, not at apply. The MEMBER half of this comparison moved
        // into `construction_refusal` above so it can be attributed; the two
        // facts left here belong to the plan as a whole and to the observed
        // work-unit row. The latter is exact durable evidence and is classified
        // by `attributable_refusal`; a global inversion was already rejected
        // before member or unit attribution.
        if unit
            .as_ref()
            .is_some_and(|unit| unit.created_at > committed_at || unit.updated_at > committed_at)
        {
            return Err(WalIdempotencyError::Malformed);
        }
        if unit
            .as_ref()
            .is_some_and(|unit| unit.derived_mismatch(&unit_expectation))
        {
            return Err(WalIdempotencyError::Malformed);
        }
        if usage_json
            != derive_usage_json(
                &work_unit_id,
                &class_name,
                members.len(),
                reservation_retained,
                processor_version,
            )
            || reservation_retained != derive_reservation_retained(&members, &work_unit_id)
            || work_unit_id
                != self::work_unit_id(
                    class,
                    members
                        .iter()
                        .map(|member| (member.event_id.as_str(), member.media_sha256.as_str())),
                )
        {
            return Err(WalIdempotencyError::Malformed);
        }
        let mut payload = Sha256::new();
        hash_field(&mut payload, work_unit_id.as_bytes())?;
        hash_field(&mut payload, class_name.as_bytes())?;
        hash_field(&mut payload, &processor_version.to_be_bytes())?;
        hash_field(&mut payload, &total_attempt_cap.to_be_bytes())?;
        hash_field(&mut payload, &[u8::from(unit.is_some())])?;
        if let Some(unit) = unit.as_ref() {
            hash_field(&mut payload, unit.work_class.as_bytes())?;
            hash_field(&mut payload, &unit.processor_version.to_be_bytes())?;
            hash_field(&mut payload, unit.state.as_bytes())?;
            hash_field(&mut payload, unit.started_at.as_bytes())?;
            hash_field(&mut payload, unit.ended_at.as_bytes())?;
            hash_field(&mut payload, &unit.reserved_output_tokens.to_be_bytes())?;
            hash_field(&mut payload, &unit.attempt_count.to_be_bytes())?;
            hash_field(&mut payload, &unit.reservation_retained.to_be_bytes())?;
            hash_opt(&mut payload, unit.error_code.as_deref())?;
            hash_opt(&mut payload, unit.usage_json.as_deref())?;
            hash_field(&mut payload, unit.created_at.as_bytes())?;
            hash_field(&mut payload, unit.updated_at.as_bytes())?;
        }
        hash_field(
            &mut payload,
            &u32::try_from(members.len())
                .map_err(|_| WalIdempotencyError::Limit)?
                .to_be_bytes(),
        )?;
        for member in &members {
            hash_field(&mut payload, &member.job_id.to_be_bytes())?;
            hash_field(&mut payload, member.event_id.as_bytes())?;
            hash_field(&mut payload, member.job_kind.as_bytes())?;
            hash_field(&mut payload, member.input_revision.as_bytes())?;
            hash_field(&mut payload, member.state.as_bytes())?;
            hash_field(&mut payload, &member.attempt_count.to_be_bytes())?;
            hash_opt(&mut payload, member.lease_until.as_deref())?;
            hash_opt(&mut payload, member.error_code.as_deref())?;
            hash_opt(&mut payload, member.usage_json.as_deref())?;
            hash_field(&mut payload, member.updated_at.as_bytes())?;
            hash_field(&mut payload, member.media_processing_state.as_bytes())?;
            // Commits the media content by digest; the bytes never enter the plan.
            hash_field(&mut payload, member.media_sha256.as_bytes())?;
        }
        let payload: [u8; 32] = payload.finalize().into();
        let source = stable_operation_source(SUBTYPE, &[account_id.as_bytes(), &payload])?;
        let operation_id = WalLogicalOperationId::from_stable_source(
            WalOperationKind::DeterministicMediaWorkResult,
            &source,
        )?;
        Ok(Self {
            operation_id,
            account_id,
            work_unit_id,
            class_name,
            job_kind,
            processor_version,
            scan_limit,
            total_attempt_cap,
            lease_seconds,
            reserved_output_tokens,
            claimed_at,
            committed_at,
            usage_json,
            reservation_retained,
            unit,
            members,
            started_ms,
            ended_ms,
        })
    }

    fn derived_lease_until(&self) -> String {
        // NEVER `now`, NEVER `claimed_at`: the sealed settles CAS on this exact
        // byte value and require it to stay ahead of both the attempt and the
        // commit.
        #[allow(clippy::cast_precision_loss, reason = "bounded lease seconds")]
        isotime::add_seconds(&self.committed_at, self.lease_seconds as f64)
    }
}

pub(crate) struct MediaWorkClaimLedger;

impl WalLogicalDomainPlan for MediaWorkClaimPlan {
    type Ledger = MediaWorkClaimLedger;
    type Output = ();

    fn kind(&self) -> WalOperationKind {
        WalOperationKind::DeterministicMediaWorkResult
    }

    fn operation_id(&self) -> WalLogicalOperationId {
        self.operation_id
    }

    fn canonical_request(&self) -> Result<Zeroizing<Vec<u8>>> {
        let mut request = Zeroizing::new(Vec::with_capacity(8 * 1024));
        request.extend_from_slice(&REQUEST_V1.to_be_bytes());
        encode_bytes(&mut request, SUBTYPE)?;
        encode_string(&mut request, &self.account_id)?;
        encode_string(&mut request, &self.work_unit_id)?;
        encode_string(&mut request, &self.class_name)?;
        encode_string(&mut request, &self.job_kind)?;
        request.extend_from_slice(&self.processor_version.to_be_bytes());
        request.extend_from_slice(&self.scan_limit.to_be_bytes());
        request.extend_from_slice(&self.total_attempt_cap.to_be_bytes());
        request.extend_from_slice(&self.lease_seconds.to_be_bytes());
        encode_string(&mut request, &self.claimed_at)?;
        encode_string(&mut request, &self.committed_at)?;
        encode_string(&mut request, &self.usage_json)?;
        request.push(u8::from(self.unit.is_some()));
        if let Some(unit) = self.unit.as_ref() {
            encode_string(&mut request, &unit.work_class)?;
            request.extend_from_slice(&unit.processor_version.to_be_bytes());
            encode_string(&mut request, &unit.state)?;
            encode_string(&mut request, &unit.started_at)?;
            encode_string(&mut request, &unit.ended_at)?;
            request.extend_from_slice(&unit.reserved_output_tokens.to_be_bytes());
            request.extend_from_slice(&unit.attempt_count.to_be_bytes());
            request.extend_from_slice(&unit.reservation_retained.to_be_bytes());
            encode_opt(&mut request, unit.error_code.as_deref())?;
            encode_opt(&mut request, unit.usage_json.as_deref())?;
            encode_string(&mut request, &unit.created_at)?;
            encode_string(&mut request, &unit.updated_at)?;
        }
        encode_len(&mut request, self.members.len())?;
        for member in &self.members {
            request.extend_from_slice(&member.job_id.to_be_bytes());
            encode_string(&mut request, &member.event_id)?;
            encode_string(&mut request, &member.job_kind)?;
            encode_string(&mut request, &member.input_revision)?;
            request.extend_from_slice(&member.processor_version.to_be_bytes());
            encode_string(&mut request, &member.state)?;
            request.extend_from_slice(&member.attempt_count.to_be_bytes());
            encode_opt(&mut request, member.lease_until.as_deref())?;
            encode_opt(&mut request, member.error_code.as_deref())?;
            encode_opt(&mut request, member.usage_json.as_deref())?;
            encode_string(&mut request, &member.updated_at)?;
            encode_string(&mut request, &member.media_processing_state)?;
            encode_string(&mut request, &member.media_sha256)?;
            request.extend_from_slice(&member.window_start_ms.to_be_bytes());
            request.extend_from_slice(&member.window_end_ms.to_be_bytes());
            request.extend_from_slice(&member.ordinal.to_be_bytes());
        }
        request.extend_from_slice(&self.started_ms.to_be_bytes());
        request.extend_from_slice(&self.ended_ms.to_be_bytes());
        request.extend_from_slice(&self.reserved_output_tokens.to_be_bytes());
        request.push(u8::from(self.reservation_retained));
        Ok(request)
    }

    fn apply(&self, transaction: &Transaction<'_>) -> Result<WalReplayResult> {
        // `Precondition` is legal only before the FIRST write. After it, any
        // inconsistency is `Corrupt`: the row was observed in this very
        // transaction, so a CAS miss is not a race.
        let observed = enumerate_claimable(
            transaction,
            self.processor_version,
            &self.job_kind,
            &self.claimed_at,
            self.scan_limit,
        )
        .map_err(|_| WalIdempotencyError::Unavailable)?;
        // Inside `apply()` an unplannable enumeration is NOT an owner-level
        // quarantine signal — nothing here may soften into a skip. The plan
        // was built over an exactly-resolved set, so anything else is a moved
        // world (`Precondition`) or a row this transaction cannot resolve, and
        // the latter keeps the exact refusal `resolve_claim` produced for it
        // before this arm existed.
        let resolved = match resolve_claim(&observed, self.total_attempt_cap)? {
            ClaimResolution::Resolved(resolved) => *resolved,
            ClaimResolution::Empty => return Err(WalIdempotencyError::Precondition),
            ClaimResolution::Unplannable(rows) => {
                return Err(rows
                    .first()
                    .and_then(|row| row.refusal_reason(self.total_attempt_cap))
                    .unwrap_or(WalIdempotencyError::Precondition))
            }
        };
        if resolved.members != self.members
            || resolved.started_ms != self.started_ms
            || resolved.ended_ms != self.ended_ms
        {
            return Err(WalIdempotencyError::Precondition);
        }
        let class = if self.class_name == "audio" {
            WorkClass::Audio
        } else {
            WorkClass::Screen
        };
        if work_unit_id(
            class,
            self.members
                .iter()
                .map(|member| (member.event_id.as_str(), member.media_sha256.as_str())),
        ) != self.work_unit_id
        {
            // A pure function of carried data: a mismatch is an internally
            // inconsistent plan, not a moved world.
            return Err(WalIdempotencyError::Corrupt);
        }
        let unit = ClaimedUnitPredecessor::read(transaction, &self.work_unit_id)
            .map_err(|_| WalIdempotencyError::Unavailable)?;
        if unit != self.unit {
            return Err(WalIdempotencyError::Precondition);
        }
        if derive_reservation_retained(&self.members, &self.work_unit_id)
            != self.reservation_retained
            || derive_usage_json(
                &self.work_unit_id,
                &self.class_name,
                self.members.len(),
                self.reservation_retained,
                self.processor_version,
            ) != self.usage_json
        {
            return Err(WalIdempotencyError::Corrupt);
        }
        let derived_lease_until = self.derived_lease_until();
        // Compute every increment before the first write. Construction and the
        // transactional re-resolution already enforce `< total_attempt_cap`;
        // checked arithmetic is the final defence if either classifier ever
        // drifts. No Rust overflow and no SQLite INTEGER-to-REAL promotion is
        // permitted on the claim boundary.
        let prior_unit_attempt = self.unit.as_ref().map_or(-1, |unit| unit.attempt_count);
        let next_unit_attempt = match self.unit.as_ref() {
            None => 1,
            Some(unit) => unit
                .attempt_count
                .checked_add(1)
                .filter(|next| *next <= self.total_attempt_cap)
                .ok_or(WalIdempotencyError::Corrupt)?,
        };
        let next_member_attempts = self
            .members
            .iter()
            .map(|member| {
                member
                    .attempt_count
                    .checked_add(1)
                    .filter(|next| *next <= self.total_attempt_cap)
                    .ok_or(WalIdempotencyError::Corrupt)
            })
            .collect::<Result<Vec<_>>>()?;

        // FIRST WRITE. `created_at` and `updated_at` are bound EXPLICITLY:
        // both are declared `DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))`
        // and the legacy INSERT omits both, so porting it unchanged would fire
        // a live clock inside `apply()` — breaking byte-exact replay and
        // permanently wedging `audio_result::validate_attempt_time`, which
        // requires `work.created_at <= attempted_at`.
        let changed = transaction
            .execute(
                "INSERT INTO media_work_units \
                 (id,work_class,processor_version,state,started_at,ended_at,\
                  reserved_output_tokens,reservation_retained,attempt_count,usage_json,\
                  created_at,updated_at) \
                 VALUES (?1,?2,?3,'processing',?4,?5,?6,?7,?10,?8,?9,?9) \
                 ON CONFLICT(id) DO UPDATE SET state='processing',error_code=NULL,\
                  reservation_retained=?7,\
                  attempt_count=?10,usage_json=?8,updated_at=?9 \
                 WHERE typeof(media_work_units.attempt_count)='integer' \
                   AND media_work_units.attempt_count=?11 \
                   AND media_work_units.attempt_count<?12",
                params![
                    self.work_unit_id,
                    self.class_name,
                    self.processor_version,
                    isotime::format_epoch_millis(self.started_ms),
                    isotime::format_epoch_millis(self.ended_ms),
                    self.reserved_output_tokens,
                    i64::from(self.reservation_retained),
                    self.usage_json,
                    self.committed_at,
                    next_unit_attempt,
                    prior_unit_attempt,
                    self.total_attempt_cap,
                ],
            )
            .map_err(|_| WalIdempotencyError::Unavailable)?;
        if changed != 1 {
            return Err(WalIdempotencyError::Corrupt);
        }
        for (member, next_attempt) in self.members.iter().zip(&next_member_attempts) {
            transaction
                .execute(
                    "INSERT OR IGNORE INTO media_work_members \
                     (work_unit_id,event_id,job_id,ordinal,window_start_ms,window_end_ms) \
                     VALUES (?1,?2,?3,?4,?5,?6)",
                    params![
                        self.work_unit_id,
                        member.event_id,
                        member.job_id,
                        member.ordinal,
                        member.window_start_ms,
                        member.window_end_ms,
                    ],
                )
                .map_err(|_| WalIdempotencyError::Corrupt)?;
            // `IS` — never `=` — for the three nullable columns: a NULL
            // comparison is never true, so `=` would silently match zero rows.
            let changed = transaction
                .execute(
                    "UPDATE media_processing_jobs \
                     SET state='processing',attempt_count=?1,lease_until=?2,\
                         error_code=NULL,usage_json=?3,updated_at=?4 \
                     WHERE id=?5 AND event_id=?6 AND job_kind=?7 AND input_revision=?8 \
                       AND processor_version=?9 AND state=?10 AND attempt_count=?11 \
                       AND lease_until IS ?12 AND error_code IS ?13 AND usage_json IS ?14 \
                       AND updated_at=?15 AND typeof(attempt_count)='integer' \
                       AND attempt_count<?16",
                    params![
                        next_attempt,
                        derived_lease_until,
                        self.usage_json,
                        self.committed_at,
                        member.job_id,
                        member.event_id,
                        member.job_kind,
                        member.input_revision,
                        member.processor_version,
                        member.state,
                        member.attempt_count,
                        member.lease_until,
                        member.error_code,
                        member.usage_json,
                        member.updated_at,
                        self.total_attempt_cap,
                    ],
                )
                .map_err(|_| WalIdempotencyError::Unavailable)?;
            if changed != 1 {
                return Err(WalIdempotencyError::Corrupt);
            }
            let changed = transaction
                .execute(
                    "UPDATE media_objects SET processing_state=?1 \
                     WHERE event_id=?2 AND processing_state=?3",
                    params![
                        CLAIMED_MEDIA_STATE,
                        member.event_id,
                        member.media_processing_state,
                    ],
                )
                .map_err(|_| WalIdempotencyError::Unavailable)?;
            if changed != 1 {
                return Err(WalIdempotencyError::Corrupt);
            }
        }
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

impl WalLogicalDomainLedger<MediaWorkClaimPlan> for MediaWorkClaimLedger {
    fn lookup(
        connection: &Connection,
        prepared: &PreparedLogicalMutation<MediaWorkClaimPlan>,
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
                 FROM archive_v3_wal_media_work_claim_operations
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
        Ok(Some(result))
    }

    fn resolve_or_apply(
        transaction: &Transaction<'_>,
        prepared: &PreparedLogicalMutation<MediaWorkClaimPlan>,
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
                "INSERT INTO archive_v3_wal_media_work_claim_operations
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
                "UPDATE archive_v3_wal_media_work_claim_state
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

fn require_kind(prepared: &PreparedLogicalMutation<MediaWorkClaimPlan>) -> Result<()> {
    if prepared.kind_for_owner() != WalOperationKind::DeterministicMediaWorkResult {
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

fn ensure_schema(transaction: &Transaction<'_>) -> Result<()> {
    match schema_state(transaction)? {
        LedgerSchemaState::Present => validate_schema_marker(transaction),
        LedgerSchemaState::Absent => {
            transaction
                .execute_batch(
                    "CREATE TABLE archive_v3_wal_media_work_claim_schema (
                        singleton INTEGER PRIMARY KEY CHECK(singleton=1),
                        format_version INTEGER NOT NULL CHECK(format_version=1),
                        codec_version INTEGER NOT NULL CHECK(codec_version=1)
                     ) STRICT;
                     CREATE TABLE archive_v3_wal_media_work_claim_operations (
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
                     CREATE TABLE archive_v3_wal_media_work_claim_state (
                        singleton INTEGER PRIMARY KEY CHECK(singleton=1),
                        row_count INTEGER NOT NULL CHECK(row_count BETWEEN 0 AND 65536),
                        result_bytes INTEGER NOT NULL CHECK(result_bytes BETWEEN 0 AND 589824)
                     ) STRICT;
                     INSERT INTO archive_v3_wal_media_work_claim_schema
                        (singleton,format_version,codec_version) VALUES (1,1,1);
                     INSERT INTO archive_v3_wal_media_work_claim_state
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
             FROM archive_v3_wal_media_work_claim_schema WHERE singleton=1",
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
             FROM archive_v3_wal_media_work_claim_state WHERE singleton=1",
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

const fn opt_len_exceeds(value: Option<&str>, limit: usize) -> bool {
    match value {
        Some(value) => value.len() > limit,
        None => false,
    }
}

/// Presence-tagged option framing. A bare "empty string for None" encoding lets
/// `Some("")` alias `None` in the identity.
fn hash_opt(hasher: &mut Sha256, value: Option<&str>) -> Result<()> {
    match value {
        None => hash_field(hasher, &[0]),
        Some(value) => {
            hash_field(hasher, &[1])?;
            hash_field(hasher, value.as_bytes())
        }
    }
}

fn hash_opt_i64(hasher: &mut Sha256, value: Option<i64>) -> Result<()> {
    match value {
        None => hash_field(hasher, &[0]),
        Some(value) => {
            hash_field(hasher, &[1])?;
            hash_field(hasher, &value.to_be_bytes())
        }
    }
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

fn encode_opt(request: &mut Vec<u8>, value: Option<&str>) -> Result<()> {
    match value {
        None => {
            request.push(0);
            Ok(())
        }
        Some(value) => {
            request.push(1);
            encode_string(request, value)
        }
    }
}

#[cfg(test)]
// Visible to the sibling `quarantine` family's tests: the quarantine is the
// bounded RESPONSE to a claim refusal, so its regressions must run against
// the claim boundary's own schema and seed rather than a second copy that
// could drift away from them.
pub(in crate::cp::media_worker) mod tests {
    use super::*;
    use crate::archive_v3_wal_idempotency::{
        execute_prepared_for_owner, LogicalMutationDisposition,
    };

    pub(in crate::cp::media_worker) const ACCOUNT: &str = "11111111-1111-4111-8111-111111111111";
    pub(in crate::cp::media_worker) const AS_OF: &str = "2026-08-21T12:00:00.000Z";
    pub(in crate::cp::media_worker) const COMMITTED_AT: &str = "2026-08-21T12:00:01.000Z";
    pub(in crate::cp::media_worker) const RESERVED_TOKENS: i64 = 2_048;
    pub(in crate::cp::media_worker) const TOTAL_ATTEMPT_CAP: i64 = 9;

    /// The four tables this family writes are declared ONLY in
    /// `cp::media::init_schema` (never in `SCHEMA_SQL`), and the two
    /// `strftime` DEFAULTs on `media_work_units` are the whole point of
    /// `apply_binds_created_at_and_updated_at_instead_of_the_clock_default`.
    /// Copied verbatim; `media_work_units_still_declares_the_clock_defaults`
    /// fails if the source drifts away from this fixture.
    pub(in crate::cp::media_worker) fn install_schema(connection: &Connection) {
        connection
            .execute_batch(
                "CREATE TABLE media_processing_jobs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_id TEXT NOT NULL,
                    job_kind TEXT NOT NULL,
                    input_revision TEXT NOT NULL,
                    processor_version INTEGER NOT NULL,
                    state TEXT NOT NULL DEFAULT 'pending'
                        CHECK (state IN ('pending','processing','retry_wait','succeeded','failed_terminal','canceled')),
                    attempt_count INTEGER NOT NULL DEFAULT 0,
                    lease_until TEXT,
                    error_code TEXT,
                    model_id TEXT,
                    prompt_version INTEGER,
                    schema_version INTEGER,
                    usage_json TEXT,
                    updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
                    UNIQUE(job_kind, input_revision, processor_version)
                 );
                 CREATE TABLE capture_events (
                    event_id TEXT PRIMARY KEY,
                    stream_kind TEXT NOT NULL,
                    capture_session_id TEXT NOT NULL,
                    stream_id TEXT NOT NULL,
                    sequence INTEGER NOT NULL,
                    started_at TEXT NOT NULL,
                    ended_at TEXT NOT NULL,
                    context_json TEXT,
                    audio_role TEXT,
                    audio_route TEXT,
                    route_epoch INTEGER
                 );
                 CREATE TABLE media_objects (
                    asset_id TEXT PRIMARY KEY,
                    event_id TEXT NOT NULL UNIQUE,
                    object_key TEXT NOT NULL UNIQUE,
                    mime_type TEXT NOT NULL,
                    codec TEXT NOT NULL,
                    byte_length INTEGER NOT NULL,
                    sha256 TEXT NOT NULL,
                    sample_rate INTEGER,
                    channels INTEGER,
                    width INTEGER,
                    height INTEGER,
                    processing_state TEXT NOT NULL DEFAULT 'queued'
                        CHECK (processing_state IN ('queued','processing','ready','retry_wait','failed','pruned'))
                 );
                 CREATE TABLE media_work_units (
                    id TEXT PRIMARY KEY,
                    work_class TEXT NOT NULL CHECK (work_class IN ('audio','screen')),
                    processor_version INTEGER NOT NULL,
                    state TEXT NOT NULL CHECK (state IN ('planned','processing','retry_wait','succeeded','failed_terminal')),
                    started_at TEXT NOT NULL,
                    ended_at TEXT NOT NULL,
                    reserved_output_tokens INTEGER NOT NULL,
                    reservation_retained INTEGER NOT NULL DEFAULT 0,
                    attempt_count INTEGER NOT NULL DEFAULT 0,
                    error_code TEXT,
                    usage_json TEXT,
                    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
                    updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
                 );
                 CREATE TABLE media_work_members (
                    work_unit_id TEXT NOT NULL,
                    event_id TEXT NOT NULL,
                    job_id INTEGER NOT NULL,
                    ordinal INTEGER NOT NULL,
                    window_start_ms INTEGER NOT NULL,
                    window_end_ms INTEGER NOT NULL,
                    PRIMARY KEY (work_unit_id,event_id),
                    UNIQUE (work_unit_id,ordinal)
                 );",
            )
            .unwrap();
    }

    pub(in crate::cp::media_worker) fn seed(connection: &Connection, count: i64) {
        for index in 0..count {
            let event_id = format!("ev-{index}");
            connection
                .execute(
                    "INSERT INTO capture_events
                     (event_id,stream_kind,capture_session_id,stream_id,sequence,started_at,ended_at)
                     VALUES (?1,'screen','sess-1','stream-1',?2,?3,?4)",
                    params![
                        event_id,
                        index,
                        isotime::format_epoch_millis(1_787_000_000_000 + index * 5_000),
                        isotime::format_epoch_millis(1_787_000_002_000 + index * 5_000),
                    ],
                )
                .unwrap();
            connection
                .execute(
                    "INSERT INTO media_objects
                     (asset_id,event_id,object_key,mime_type,codec,byte_length,sha256,width,height)
                     VALUES (?1,?2,?3,'image/png','png',1024,?4,100,100)",
                    params![
                        format!("asset-{index}"),
                        event_id,
                        format!("raw/{index}"),
                        format!("{:064x}", index + 1),
                    ],
                )
                .unwrap();
            connection
                .execute(
                    "INSERT INTO media_processing_jobs
                     (id,event_id,job_kind,input_revision,processor_version,state,attempt_count,updated_at)
                     VALUES (?1,?2,'gemini_screen',?3,1,'pending',0,'2026-08-21T10:00:00.000Z')",
                    params![index + 1, event_id, format!("rev-{index}")],
                )
                .unwrap();
        }
    }

    pub(in crate::cp::media_worker) fn fixture(count: i64) -> Connection {
        let connection = Connection::open_in_memory().unwrap();
        install_schema(&connection);
        seed(&connection, count);
        connection
    }

    fn observe(connection: &Connection) -> ClaimObservation {
        match scan_for_claim(
            connection,
            WorkClass::Screen,
            1,
            AS_OF,
            128,
            TOTAL_ATTEMPT_CAP,
        )
        .unwrap()
        {
            ClaimScan::Observed(observation) => *observation,
            ClaimScan::Idle => panic!("expected claimable work"),
            ClaimScan::AudioLaneBlocked => panic!("screen is never gated"),
            ClaimScan::Unplannable(rows) => panic!(
                "expected a plannable enumeration, got {:?} unplannable",
                rows.iter().map(|row| row.job_id).collect::<Vec<_>>()
            ),
        }
    }

    fn build(observation: ClaimObservation, committed_at: &str) -> MediaWorkClaimPlan {
        MediaWorkClaimPlan::new(
            ACCOUNT.into(),
            observation,
            1,
            128,
            TOTAL_ATTEMPT_CAP,
            300,
            RESERVED_TOKENS,
            AS_OF.into(),
            committed_at.into(),
        )
        .unwrap()
    }

    fn settle(
        connection: &mut Connection,
        plan: MediaWorkClaimPlan,
    ) -> Result<LogicalMutationDisposition> {
        let prepared = PreparedLogicalMutation::prepare(plan)?;
        execute_prepared_for_owner(connection, prepared).map(|outcome| outcome.disposition())
    }

    fn dump(connection: &Connection) -> Vec<String> {
        let mut rows = Vec::new();
        for sql in [
            "SELECT id,event_id,job_kind,input_revision,processor_version,state,attempt_count,\
                    lease_until,error_code,usage_json,updated_at \
             FROM media_processing_jobs ORDER BY id",
            "SELECT event_id,processing_state FROM media_objects ORDER BY event_id",
            "SELECT id,work_class,processor_version,state,started_at,ended_at,\
                    reserved_output_tokens,reservation_retained,attempt_count,error_code,\
                    usage_json,created_at,updated_at FROM media_work_units ORDER BY id",
            "SELECT work_unit_id,event_id,job_id,ordinal,window_start_ms,window_end_ms \
             FROM media_work_members ORDER BY work_unit_id,ordinal",
        ] {
            let mut statement = connection.prepare(sql).unwrap();
            let columns = statement.column_count();
            let mapped = statement
                .query_map([], |row| {
                    let mut cells = Vec::with_capacity(columns);
                    for index in 0..columns {
                        cells.push(format!(
                            "{:?}",
                            row.get::<_, rusqlite::types::Value>(index)?
                        ));
                    }
                    Ok(cells.join("|"))
                })
                .unwrap()
                .collect::<std::result::Result<Vec<_>, _>>()
                .unwrap();
            rows.extend(mapped);
        }
        rows
    }

    #[test]
    fn the_claim_applies_the_resolved_set_once_and_then_replays() {
        let mut connection = fixture(3);
        let observation = observe(&connection);
        let replay_observation = observe(&connection);
        assert_eq!(observation.members.len(), 3);
        assert!(matches!(
            settle(&mut connection, build(observation, COMMITTED_AT)).unwrap(),
            LogicalMutationDisposition::Applied
        ));
        let applied = dump(&connection);
        assert!(matches!(
            settle(&mut connection, build(replay_observation, COMMITTED_AT)).unwrap(),
            LogicalMutationDisposition::Replayed
        ));
        assert_eq!(
            applied,
            dump(&connection),
            "a replay must not touch a single durable byte"
        );
        let states: Vec<(String, i64, Option<String>, Option<String>)> = connection
            .prepare(
                "SELECT state,attempt_count,lease_until,error_code \
                 FROM media_processing_jobs ORDER BY id",
            )
            .unwrap()
            .query_map([], |row| {
                Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
            })
            .unwrap()
            .collect::<std::result::Result<Vec<_>, _>>()
            .unwrap();
        for (state, attempts, lease, error) in &states {
            assert_eq!(state, "processing");
            assert_eq!(*attempts, 1);
            assert_eq!(lease.as_deref(), Some("2026-08-21T12:05:01.000Z"));
            assert_eq!(error.as_deref(), None);
        }
        let objects: Vec<String> = connection
            .prepare("SELECT processing_state FROM media_objects ORDER BY event_id")
            .unwrap()
            .query_map([], |row| row.get(0))
            .unwrap()
            .collect::<std::result::Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(objects, ["processing", "processing", "processing"]);
        let members: i64 = connection
            .query_row("SELECT COUNT(*) FROM media_work_members", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(members, 3);
    }

    #[test]
    fn apply_binds_created_at_and_updated_at_instead_of_the_clock_default() {
        // The legacy INSERT omits BOTH columns and both are declared
        // `DEFAULT (strftime(...,'now'))`, so porting it unchanged fires a
        // live clock inside apply(): byte-exact replay breaks, and
        // audio_result::validate_attempt_time (which requires
        // `work.created_at <= attempted_at`) wedges the lane forever.
        let mut connection = fixture(2);
        let observation = observe(&connection);
        settle(&mut connection, build(observation, COMMITTED_AT)).unwrap();
        let (created, updated): (String, String) = connection
            .query_row(
                "SELECT created_at,updated_at FROM media_work_units",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(created, COMMITTED_AT, "created_at must be the commit stamp");
        assert_eq!(updated, COMMITTED_AT, "updated_at must be the commit stamp");
        let job_updates: Vec<String> = connection
            .prepare("SELECT updated_at FROM media_processing_jobs ORDER BY id")
            .unwrap()
            .query_map([], |row| row.get(0))
            .unwrap()
            .collect::<std::result::Result<Vec<_>, _>>()
            .unwrap();
        assert!(job_updates.iter().all(|value| value == COMMITTED_AT));
    }

    #[test]
    fn media_work_units_still_declares_the_clock_defaults_the_fixture_copies() {
        let source = include_str!("../../media.rs");
        let start = source
            .find("CREATE TABLE IF NOT EXISTS media_work_units")
            .unwrap();
        let ddl = &source[start..start + source[start..].find(");").unwrap()];
        assert_eq!(
            ddl.matches("DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))")
                .count(),
            2,
            "created_at and updated_at both carry a live-clock DEFAULT"
        );
        // ... and the table is declared ONLY there, never in SCHEMA_SQL.
        let store = include_str!("../../../store.rs");
        assert!(!store.contains("CREATE TABLE IF NOT EXISTS media_work_units"));
        assert!(!store.contains("CREATE TABLE media_work_units"));
    }

    #[test]
    fn the_commit_stamp_stays_out_of_the_identity_and_conflicts_on_the_fingerprint() {
        let mut connection = fixture(2);
        let first = build(observe(&connection), COMMITTED_AT);
        let reminted = build(observe(&connection), "2026-08-21T12:00:09.000Z");
        assert_eq!(
            first.operation_id(),
            reminted.operation_id(),
            "the clock never enters the identity"
        );
        assert!(matches!(
            settle(&mut connection, first).unwrap(),
            LogicalMutationDisposition::Applied
        ));
        let applied = dump(&connection);
        assert!(matches!(
            settle(&mut connection, reminted),
            Err(WalIdempotencyError::FingerprintConflict)
        ));
        assert_eq!(
            applied,
            dump(&connection),
            "a fingerprint conflict is never a silent adoption"
        );
    }

    #[test]
    fn a_moved_predecessor_or_a_different_digest_is_a_different_operation() {
        let connection = fixture(2);
        let baseline = build(observe(&connection), COMMITTED_AT).operation_id();
        // The media content is committed by digest, never embedded.
        let rekeyed = Connection::open_in_memory().unwrap();
        install_schema(&rekeyed);
        seed(&rekeyed, 2);
        rekeyed
            .execute(
                "UPDATE media_objects SET sha256=?1 WHERE event_id='ev-1'",
                [format!("{:064x}", 99)],
            )
            .unwrap();
        assert_ne!(
            baseline,
            build(observe(&rekeyed), COMMITTED_AT).operation_id()
        );
        // A retry after a failure moved attempt_count/updated_at/error_code.
        let advanced = Connection::open_in_memory().unwrap();
        install_schema(&advanced);
        seed(&advanced, 2);
        advanced
            .execute(
                "UPDATE media_processing_jobs \
                 SET state='retry_wait',attempt_count=1,error_code='processing_error' \
                 WHERE id=1",
                [],
            )
            .unwrap();
        assert_ne!(
            baseline,
            build(observe(&advanced), COMMITTED_AT).operation_id()
        );
    }

    #[test]
    fn cap_minus_one_claim_assigns_checked_integers_for_job_and_unit() {
        let mut connection = fixture(1);
        let initial = observe(&connection);
        let work_unit_id = initial.work_unit_id.clone();
        connection
            .execute(
                "INSERT INTO media_work_units \
                 (id,work_class,processor_version,state,started_at,ended_at,\
                  reserved_output_tokens,reservation_retained,attempt_count,created_at,updated_at) \
                 VALUES (?1,'screen',1,'processing',?2,?3,?4,0,?5,?6,?6)",
                params![
                    work_unit_id,
                    isotime::format_epoch_millis(initial.started_ms),
                    isotime::format_epoch_millis(initial.ended_ms),
                    RESERVED_TOKENS,
                    TOTAL_ATTEMPT_CAP - 1,
                    "2026-08-21T11:00:00.000Z",
                ],
            )
            .unwrap();
        connection
            .execute(
                "UPDATE media_processing_jobs SET attempt_count=?1 WHERE id=1",
                [TOTAL_ATTEMPT_CAP - 1],
            )
            .unwrap();

        let plan = build(observe(&connection), COMMITTED_AT);
        settle(&mut connection, plan).unwrap();
        let (job_attempts, job_type): (i64, String) = connection
            .query_row(
                "SELECT attempt_count,typeof(attempt_count) \
                 FROM media_processing_jobs WHERE id=1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        let (unit_attempts, unit_type): (i64, String) = connection
            .query_row(
                "SELECT attempt_count,typeof(attempt_count) FROM media_work_units WHERE id=?1",
                [work_unit_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(job_attempts, TOTAL_ATTEMPT_CAP);
        assert_eq!(unit_attempts, TOTAL_ATTEMPT_CAP);
        assert_eq!(job_type, "integer");
        assert_eq!(unit_type, "integer");

        let source = include_str!("claim.rs");
        let start = source.find("fn apply(&self").unwrap();
        let end = source[start..]
            .find("fn validate_replay")
            .map(|offset| start + offset)
            .unwrap();
        let apply = &source[start..end];
        assert!(!apply.contains("attempt_count+1"));
        assert_eq!(apply.matches(".checked_add(1)").count(), 2);
        assert_eq!(apply.matches("typeof(attempt_count)='integer'").count(), 1);
        assert_eq!(
            apply
                .matches("typeof(media_work_units.attempt_count)='integer'")
                .count(),
            1
        );
    }

    #[test]
    fn a_stale_enumeration_fails_closed_before_any_write() {
        let mut connection = fixture(2);
        let observation = observe(&connection);
        let before = dump(&connection);
        // An interleaved sweep advanced a carried member's predecessor.
        connection
            .execute(
                "UPDATE media_processing_jobs SET attempt_count=2 WHERE id=1",
                [],
            )
            .unwrap();
        let expected = dump(&connection);
        assert_ne!(before, expected);
        assert!(matches!(
            settle(&mut connection, build(observation, COMMITTED_AT)),
            Err(WalIdempotencyError::Precondition)
        ));
        assert_eq!(expected, dump(&connection), "a refusal writes nothing");
    }

    #[test]
    fn a_carried_nullable_predecessor_mismatch_refuses_instead_of_matching_null() {
        let mut connection = fixture(2);
        let observation = observe(&connection);
        // `error_code` is NULL in the carried tuple; a NULL/NULL comparison is
        // never true under `=`, which is why the CAS uses `IS`. Moving it
        // proves the carried value is genuinely pinned.
        connection
            .execute(
                "UPDATE media_processing_jobs SET error_code='vertex_quota' WHERE id=2",
                [],
            )
            .unwrap();
        let expected = dump(&connection);
        assert!(matches!(
            settle(&mut connection, build(observation, COMMITTED_AT)),
            Err(WalIdempotencyError::Precondition)
        ));
        assert_eq!(expected, dump(&connection));
        // And the CAS itself never uses `=` on a nullable column.
        let source = include_str!("claim.rs");
        let start = source.find("UPDATE media_processing_jobs \\").unwrap();
        let end = start + source[start..].find("AND updated_at=?15").unwrap();
        let cas = &source[start..end];
        for column in ["lease_until", "error_code", "usage_json"] {
            assert!(
                cas.contains(&format!("AND {column} IS ?")),
                "{column} must be compared with IS"
            );
        }
    }

    #[test]
    fn the_work_unit_id_digest_is_byte_stable() {
        // Renaming or reordering WorkClass silently re-keys every work unit
        // ever minted; the derived Debug is load-bearing.
        assert_eq!(format!("{:?}", WorkClass::Audio), "Audio");
        assert_eq!(format!("{:?}", WorkClass::Screen), "Screen");
        let first = "a".repeat(64);
        let second = "b".repeat(64);
        let members = [("ev-0", first.as_str()), ("ev-1", second.as_str())];
        assert_eq!(
            work_unit_id(WorkClass::Screen, members.iter().copied()),
            "9af83f08a39510b70b27511b4c10315126953ad2de48f970dc07ba2d16cb22aa"
        );
        assert_eq!(
            work_unit_id(WorkClass::Audio, members.iter().copied()),
            "9e27419c93fd666191f56e2fbc264f75c61279faf74aaf4b955b4fad96efd39e"
        );
    }

    #[test]
    fn the_usage_json_shape_is_byte_stable() {
        // serde_json is declared WITHOUT `preserve_order`, so Map is a
        // BTreeMap and the key order is sorted. Enabling that feature would
        // rewrite every stored usage_json byte string.
        assert_eq!(
            derive_usage_json("wu-1", "screen", 3, false, 1),
            "{\"member_count\":3,\"processor_version\":1,\"reservation_state\":\"planned\",\
             \"work_class\":\"screen\",\"work_unit_id\":\"wu-1\"}"
        );
        assert_eq!(
            derive_usage_json("wu-1", "audio", 1, true, 1),
            "{\"member_count\":1,\"processor_version\":1,\"reservation_state\":\"reserved\",\
             \"work_class\":\"audio\",\"work_unit_id\":\"wu-1\"}"
        );
    }

    #[test]
    fn the_derived_lease_satisfies_the_sealed_settles_provider_window() {
        let mut connection = fixture(2);
        let plan = build(observe(&connection), COMMITTED_AT);
        settle(&mut connection, plan).unwrap();
        let lease: String = connection
            .query_row(
                "SELECT lease_until FROM media_processing_jobs WHERE id=1",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let lease_ms = isotime::parse_epoch_millis(&lease).unwrap();
        let commit_ms = isotime::parse_epoch_millis(COMMITTED_AT).unwrap();
        assert_eq!(lease_ms - commit_ms, 300_000);
        // audio_result::MIN_PROVIDER_ATTEMPT_WINDOW_MILLIS
        assert!(lease_ms - commit_ms >= 120_000);
    }

    #[test]
    fn an_oversized_resolved_set_refuses_instead_of_truncating() {
        let connection = fixture(1);
        let rows = enumerate_claimable(&connection, 1, "gemini_screen", AS_OF, 128).unwrap();
        let template = rows.first().unwrap().clone();
        let mut members = Vec::new();
        for index in 0..=MAX_MEMBERS {
            let mut row = template.clone();
            row.job_id = i64::try_from(index).unwrap() + 1;
            row.event_id = format!("ev-{index}");
            members.push(
                ClaimMember::resolve(&row, i64::try_from(index).unwrap(), 0, TOTAL_ATTEMPT_CAP)
                    .unwrap(),
            );
        }
        assert_eq!(members.len(), MAX_MEMBERS + 1);
        let observation = ClaimObservation {
            members,
            rows,
            work_unit_id: "wu-1".into(),
            class: WorkClass::Screen,
            started_ms: 0,
            ended_ms: 1,
            unit: None,
            reservation_retained: false,
            usage_json: derive_usage_json("wu-1", "screen", MAX_MEMBERS + 1, false, 1),
        };
        // An observed predecessor set is never silently capped.
        assert!(matches!(
            MediaWorkClaimPlan::new(
                ACCOUNT.into(),
                observation,
                1,
                1_024,
                TOTAL_ATTEMPT_CAP,
                300,
                RESERVED_TOKENS,
                AS_OF.into(),
                COMMITTED_AT.into(),
            ),
            Err(WalIdempotencyError::Limit)
        ));
    }

    #[test]
    fn a_commit_stamp_behind_an_observed_fact_is_refused_at_construction() {
        let connection = fixture(2);
        assert!(matches!(
            MediaWorkClaimPlan::new(
                ACCOUNT.into(),
                observe(&connection),
                1,
                128,
                TOTAL_ATTEMPT_CAP,
                300,
                RESERVED_TOKENS,
                AS_OF.into(),
                "2026-08-21T09:00:00.000Z".into(),
            ),
            Err(WalIdempotencyError::Malformed)
        ));
    }

    #[test]
    fn the_audio_lane_is_gated_on_autoincrement_not_on_existing_rows() {
        // T24 / R1. Without AUTOINCREMENT on audio_segments and utterances the
        // sealed transcript family's four sqlite_sequence pins read 0 forever
        // and every settle fails closed -- after a PAID Vertex call.
        //
        // The gate must key on whether the tables ARE AUTOINCREMENT, never on
        // whether they HAVE sqlite_sequence rows. SQLite writes a table's
        // sqlite_sequence row on its first INSERT, not at CREATE TABLE, so a
        // row-counting gate is shut on a freshly created archive -- and since
        // a shut gate makes no claim, nothing ever inserts the row that would
        // open it. That is a permanent deadlock of the audio lane on every
        // genesis archive, which under genesis-first is every archive.
        let connection = Connection::open_in_memory().unwrap();
        install_schema(&connection);
        assert!(
            !audio_sequence_gate_open(&connection),
            "tables absent entirely is the blocked condition"
        );

        // Plain INTEGER PRIMARY KEY: blocked, however many rows exist.
        connection
            .execute_batch(
                "CREATE TABLE audio_segments(id INTEGER PRIMARY KEY,x TEXT);
                 CREATE TABLE utterances(id INTEGER PRIMARY KEY,x TEXT);
                 INSERT INTO audio_segments(x) VALUES ('a');
                 INSERT INTO utterances(x) VALUES ('u');",
            )
            .unwrap();
        assert!(
            !audio_sequence_gate_open(&connection),
            "plain INTEGER PRIMARY KEY stays blocked even with rows present"
        );

        // One of the two converted is not enough.
        let connection = Connection::open_in_memory().unwrap();
        install_schema(&connection);
        connection
            .execute_batch(
                "CREATE TABLE audio_segments(id INTEGER PRIMARY KEY AUTOINCREMENT,x TEXT);
                 CREATE TABLE utterances(id INTEGER PRIMARY KEY,x TEXT);",
            )
            .unwrap();
        assert!(
            !audio_sequence_gate_open(&connection),
            "one of the two tables is not enough"
        );

        // THE DEADLOCK CASE: both AUTOINCREMENT, and EMPTY. sqlite_sequence
        // holds no row for either table yet, and the gate must still open.
        let connection = Connection::open_in_memory().unwrap();
        install_schema(&connection);
        connection
            .execute_batch(
                "CREATE TABLE audio_segments(id INTEGER PRIMARY KEY AUTOINCREMENT,x TEXT);
                 CREATE TABLE utterances(id INTEGER PRIMARY KEY AUTOINCREMENT,x TEXT);",
            )
            .unwrap();
        let sequence_rows: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM sqlite_sequence \
                 WHERE name IN ('audio_segments','utterances')",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(
            sequence_rows, 0,
            "precondition: an unwritten AUTOINCREMENT table has no sequence row"
        );
        assert!(
            audio_sequence_gate_open(&connection),
            "a fresh AUTOINCREMENT archive must open the lane; gating on row \
             presence here deadlocks audio forever"
        );
    }

    #[test]
    fn scan_for_claim_gates_audio_before_it_enumerates_anything() {
        let connection = fixture(1);
        connection
            .execute(
                "UPDATE media_processing_jobs SET job_kind='gemini_audio'",
                [],
            )
            .unwrap();
        assert!(
            matches!(
                scan_for_claim(
                    &connection,
                    WorkClass::Audio,
                    1,
                    AS_OF,
                    128,
                    TOTAL_ATTEMPT_CAP,
                )
                .unwrap(),
                ClaimScan::AudioLaneBlocked
            ),
            "claimable audio work must still be refused while T24 stands"
        );
    }

    fn unplannable_job_ids(scan: &ClaimScan) -> Vec<i64> {
        match scan {
            ClaimScan::Unplannable(rows) => rows.iter().map(|row| row.job_id).collect(),
            ClaimScan::Idle => panic!("the scan reported Idle, which is the wedge shape"),
            ClaimScan::AudioLaneBlocked => panic!("screen is never gated"),
            ClaimScan::Observed(_) => panic!("the scan planned work it should have refused"),
        }
    }

    /// **The amplifier, at the boundary that produced it.**
    ///
    /// A row the family cannot resolve is NAMED, not collapsed into a
    /// whole-enumeration refusal and not reported as an empty queue. Before
    /// this, `resolve_claim` propagated one row's `Malformed` out of
    /// `observe_claim`, the owner logged a `warn!` and returned
    /// `ClaimOutcome::Idle`, and — because `enumerate_claimable`'s `pending`
    /// arm carries no `attempt_count` term and `plan_first` is pure — the next
    /// sweep re-derived the identical refusal, forever, with no attempt cap and
    /// no terminalization path.
    ///
    /// Both triggers below are DEVICE-supplied capture stamps that
    /// `parse_epoch_millis` accepts and that denote a perfectly ordinary
    /// instant. The over-long one is the live sibling of #331:
    /// `capture_events.started_at` had no ingest length bound while
    /// `wal::failure` and `wal::result` both refuse a `capture_started_at` over
    /// 64 bytes, so it was claimed, PAID FOR, and then could never settle
    /// either way.
    ///
    /// Falsifiability, checked by sabotage: dropping the `started_at` length
    /// bound from `ClaimableRow::refusal_reason` makes the first case reach
    /// `ClaimScan::Observed` and `unplannable_job_ids` panics on it.
    #[test]
    fn an_unresolvable_row_is_named_rather_than_wedging_the_enumeration() {
        for (case, column, poison) in [
            (
                "over-long started_at",
                "started_at",
                "2026-08-21T11:00:00.000000000000000000000000000000000000000000000Z".to_owned(),
            ),
            (
                "unparseable ended_at",
                "ended_at",
                "not-a-timestamp".to_owned(),
            ),
        ] {
            let connection = fixture(3);
            // Every trigger must still BE a trigger, or the fixture has
            // silently stopped covering anything.
            match column {
                "started_at" => assert!(
                    poison.len() > MAX_TIMESTAMP_BYTES
                        && isotime::parse_epoch_millis(&poison).is_some(),
                    "{case}: must parse AND exceed the settle families' bound"
                ),
                _ => assert!(
                    isotime::parse_epoch_millis(&poison).is_none(),
                    "{case}: must be the unparseable shape"
                ),
            }
            connection
                .execute(
                    &format!("UPDATE capture_events SET {column}=?1 WHERE event_id='ev-1'"),
                    params![poison],
                )
                .unwrap();

            let scan = scan_for_claim(
                &connection,
                WorkClass::Screen,
                1,
                AS_OF,
                128,
                TOTAL_ATTEMPT_CAP,
            )
            .unwrap();
            assert_eq!(
                unplannable_job_ids(&scan),
                vec![2],
                "{case}: only the offending job may be named"
            );
            // ...and nothing durable moved: naming is not settling.
            let pending: i64 = connection
                .query_row(
                    "SELECT COUNT(*) FROM media_processing_jobs WHERE state='pending'",
                    [],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(pending, 3, "{case}: the scan itself writes nothing");
        }
    }

    /// The third door into the same wedge, and it is live on `main` with no
    /// poisoning at all: `CaptureEventManifest::validate` admits an audio event
    /// up to EIGHT HOURS long and `validate_media` bounds only its bytes, so a
    /// single event longer than `MAX_AUDIO_WINDOW_MS` is ingested normally and
    /// then fits no window `plan_first` can build.
    ///
    /// `plan_first` returned an empty member set, `resolve_claim` turned that
    /// into `Ok(None)`, the scan reported `Idle`, and `process_user` RETURNED —
    /// so the event stayed `pending` forever, `pending_work_classes` kept
    /// reporting audio pending forever, and because audio is scheduled first
    /// the SCREEN lane never ran either.
    ///
    /// Falsifiability, checked by sabotage: restoring `Ok(ClaimResolution::Empty)`
    /// for an empty plan over non-empty rows makes this reach `ClaimScan::Idle`
    /// and `unplannable_job_ids` panics with "the wedge shape".
    #[test]
    fn a_head_that_fits_no_window_is_named_rather_than_reported_idle() {
        let connection = fixture(1);
        connection
            .execute_batch(
                "UPDATE media_processing_jobs SET job_kind='gemini_audio';
                 UPDATE capture_events SET stream_kind='audio';
                 CREATE TABLE audio_segments(id INTEGER PRIMARY KEY AUTOINCREMENT,x TEXT);
                 CREATE TABLE utterances(id INTEGER PRIMARY KEY AUTOINCREMENT,x TEXT);",
            )
            .unwrap();
        let (started, ended): (String, String) = connection
            .query_row(
                "SELECT started_at,ended_at FROM capture_events WHERE event_id='ev-0'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        let started_ms = isotime::parse_epoch_millis(&started).unwrap();
        // Six minutes: over `MAX_AUDIO_WINDOW_MS`, well under the eight-hour
        // duration ingest enforces, and under `MAX_AUDIO_BYTES`.
        let over_window = isotime::format_epoch_millis(started_ms + 6 * 60 * 1_000);
        assert!(
            over_window > ended,
            "precondition: the fixture event must be widened, not narrowed"
        );
        connection
            .execute(
                "UPDATE capture_events SET ended_at=?1 WHERE event_id='ev-0'",
                params![over_window],
            )
            .unwrap();

        let scan = scan_for_claim(
            &connection,
            WorkClass::Audio,
            1,
            AS_OF,
            128,
            TOTAL_ATTEMPT_CAP,
        )
        .unwrap();
        assert_eq!(
            unplannable_job_ids(&scan),
            vec![1],
            "the head that fits no window is the job to name"
        );
    }

    /// The construction guard and the owner's attribution are the SAME
    /// predicate, and the distinction that keeps a job from being charged for
    /// somebody else's defect actually holds.
    ///
    /// Case 1 is #331's own trigger — a member whose `latest_observed_timestamp`
    /// string-sorts above the enclave commit stamp. The guard still refuses;
    /// what is new is that the refusal has a name, so the owner can bound it.
    ///
    /// Case 2 is a refusal belonging to the PLAN — `claimed_at > committed_at`,
    /// a clock inversion. Attribution must come back EMPTY: quarantining a job
    /// for that would burn its attempt budget for a defect it did not cause,
    /// which is precisely the data loss a skip-ladder is supposed to prevent.
    ///
    /// Falsifiability, checked by sabotage: moving the `claimed_at >
    /// committed_at` test into `ClaimMember::construction_refusal` makes case 2
    /// attribute both jobs and the empty assertion fails; deleting the
    /// `latest_observed_timestamp` comparison from `construction_refusal` makes
    /// case 1 construct and both of its assertions fail.
    #[test]
    fn attribution_names_exactly_what_the_construction_guard_refuses() {
        // A healthy observation attributes nothing and constructs.
        let connection = fixture(2);
        let healthy = observe(&connection);
        assert!(unplannable_members(&healthy, 1, COMMITTED_AT).is_empty());
        assert!(MediaWorkClaimPlan::new(
            ACCOUNT.into(),
            healthy,
            1,
            128,
            TOTAL_ATTEMPT_CAP,
            300,
            RESERVED_TOKENS,
            AS_OF.into(),
            COMMITTED_AT.into(),
        )
        .is_ok());

        // Case 1: #331's shape, on ONE of two members.
        let connection = fixture(2);
        let poisoned = "2026-08-21T23:00:00.000+09:00";
        assert!(
            poisoned > COMMITTED_AT && isotime::parse_epoch_millis(poisoned).is_some(),
            "the trigger must string-sort above the commit stamp while parsing fine"
        );
        connection
            .execute(
                "UPDATE media_processing_jobs SET updated_at=?1 WHERE id=2",
                params![poisoned],
            )
            .unwrap();
        let observation = observe(&connection);
        assert_eq!(
            unplannable_members(&observation, 1, COMMITTED_AT)
                .iter()
                .map(|row| row.job_id)
                .collect::<Vec<_>>(),
            vec![2],
            "only the member the guard refuses on may be charged"
        );
        assert_eq!(
            MediaWorkClaimPlan::new(
                ACCOUNT.into(),
                observation,
                1,
                128,
                TOTAL_ATTEMPT_CAP,
                300,
                RESERVED_TOKENS,
                AS_OF.into(),
                COMMITTED_AT.into(),
            )
            .err(),
            Some(WalIdempotencyError::Malformed),
            "the guard itself is unchanged in strength"
        );

        // Case 2: a plan-level refusal charges nobody, even when a healthy
        // member timestamp falls BETWEEN the two backwards clock samples.
        let connection = fixture(2);
        let inverted_commit = "2026-08-21T11:59:59.000Z";
        let between = "2026-08-21T11:59:59.500Z";
        assert!(
            inverted_commit < between && between < AS_OF,
            "the member stamp must sit between commit and claim horizons"
        );
        connection
            .execute(
                "UPDATE media_processing_jobs SET updated_at=?1 WHERE id=1",
                [between],
            )
            .unwrap();
        let observation = observe(&connection);
        assert!(
            !unplannable_members(&observation, 1, inverted_commit).is_empty(),
            "the member-only predicate demonstrates the old misattribution"
        );
        assert!(
            observation
                .attributable_refusal(
                    ACCOUNT,
                    1,
                    128,
                    TOTAL_ATTEMPT_CAP,
                    300,
                    RESERVED_TOKENS,
                    AS_OF,
                    inverted_commit,
                )
                .is_none(),
            "global clock inversion must take priority and charge nobody"
        );
        assert_eq!(
            MediaWorkClaimPlan::new(
                ACCOUNT.into(),
                observation,
                1,
                128,
                TOTAL_ATTEMPT_CAP,
                300,
                RESERVED_TOKENS,
                AS_OF.into(),
                inverted_commit.into(),
            )
            .err(),
            Some(WalIdempotencyError::Malformed)
        );
    }
}
