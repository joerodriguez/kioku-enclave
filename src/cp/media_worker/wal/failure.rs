//! The media work failure tail as a sealed WAL plan (ADR-0022 slice 10i).
//!
//! One plan, one transaction, covering the whole legacy tail: per-job
//! `mark_failed` **or** `defer_for_budget`, plus the `media_work_units`
//! state/error update.
//!
//! ## The trap
//!
//! In BOTH arms the non-terminal branch writes the **future retry time** into
//! `updated_at`, not the commit stamp. `updated_at` doubles as
//! "next-attempt-at" and is read as such by every eligibility predicate on
//! this lane — `claim::enumerate_claimable`, `lease_work_unit`,
//! `pending_work_classes`, `resurrect_failed_jobs` all test
//! `(state='retry_wait' AND updated_at <= now)`.
//!
//! A reviewer told "bind timestamps to the plan's `committed_at`" will
//! "fix" this to `updated_at = committed_at`. That makes every failed job
//! immediately re-eligible, destroys the exponential backoff, and turns a
//! transient Vertex outage into a paid retry storm bounded only by
//! `MAX_ATTEMPTS`. **`committed_at` is the BASE for the arithmetic, not the
//! value written.** Pinned by
//! `non_terminal_failure_writes_the_retry_time_not_the_commit_stamp`.
//!
//! The three policy constants (`attempt_limit`, `resurrection_window_seconds`,
//! `budget_retry_seconds`) are CARRIED in the plan, never read from code
//! constants inside `apply()`, so replay stays stable across binary revisions.
//! `error_code` is in the identity: the same predecessors failing with a
//! different code is a genuinely different mutation.
//!
//! Kind 6 (`DeterministicMediaWorkResult`) is reused; the subtype keeps the
//! ledgers disjoint.

use rusqlite::{params, Connection, OptionalExtension, Transaction};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::archive_v3_wal_idempotency::{
    hash_field, stable_operation_source, DomainLedgerBounds, LogicalMutationResult,
    PreparedLogicalMutation, WalIdempotencyError, WalLogicalDomainLedger, WalLogicalDomainPlan,
    WalLogicalOperationId, WalOperationKind, WalReplayResult,
};
use crate::cp::isotime;

const REQUEST_V1: u16 = 1;
const SUBTYPE: &[u8] = b"adr-0022-media-work-failure-v1";
const SCHEMA_TABLE: &str = "archive_v3_wal_media_work_failure_schema";
const LEDGER_TABLE: &str = "archive_v3_wal_media_work_failure_operations";
const STATE_TABLE: &str = "archive_v3_wal_media_work_failure_state";
const ENCODED_UNIT_RESULT_BYTES: usize = 9;
const MAX_ROWS: u32 = 65_536;
const MAX_RESULT_BYTES: u64 = 65_536 * 9;
const BOUNDS: DomainLedgerBounds = DomainLedgerBounds::new(MAX_ROWS, MAX_RESULT_BYTES);
const MAX_ID_BYTES: usize = 128;
const MAX_TIMESTAMP_BYTES: usize = 64;
const MAX_JSON_BYTES: usize = 8 * 1024;
const MAX_MEMBERS: usize = 128;
const MAX_ATTEMPT_LIMIT: i64 = 64;
/// The `defer_for_budget` sentinel. Its arm terminalizes only on staleness and
/// DECREMENTS the attempt count, so a budget stop never burns the ladder.
pub(in crate::cp::media_worker) const BUDGET_ERROR_CODE: &str = "vertex_daily_budget";
const TERMINAL_STATE: &str = "failed_terminal";
const RETRY_STATE: &str = "retry_wait";

type Result<T> = std::result::Result<T, WalIdempotencyError>;

/// One work-unit member with the full observed predecessor tuple every CAS
/// pins, plus `capture_started_at` — `defer_for_budget` decides staleness from
/// `capture_events.started_at`, so the plan must carry it rather than re-read
/// a fact it never admitted.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(in crate::cp::media_worker) struct FailureMember {
    job_id: i64,
    event_id: String,
    job_kind: String,
    input_revision: String,
    state: String,
    attempt_count: i64,
    lease_until: Option<String>,
    error_code: Option<String>,
    usage_json: Option<String>,
    updated_at: String,
    media_processing_state: String,
    capture_started_at: String,
}

impl FailureMember {
    fn validate(&self) -> Result<()> {
        if self.job_id <= 0
            || self.attempt_count < 0
            || self.event_id.is_empty()
            || self.event_id.len() > MAX_ID_BYTES
            || self.job_kind.is_empty()
            || self.job_kind.len() > MAX_ID_BYTES
            || self.input_revision.is_empty()
            || self.input_revision.len() > MAX_ID_BYTES
            || self.state.is_empty()
            || self.state.len() > MAX_ID_BYTES
            || self.updated_at.is_empty()
            || self.updated_at.len() > MAX_TIMESTAMP_BYTES
            || self.media_processing_state.is_empty()
            || self.media_processing_state.len() > MAX_ID_BYTES
            || self.capture_started_at.is_empty()
            || self.capture_started_at.len() > MAX_TIMESTAMP_BYTES
            || opt_len_exceeds(self.lease_until.as_deref(), MAX_TIMESTAMP_BYTES)
            || opt_len_exceeds(self.error_code.as_deref(), MAX_ID_BYTES)
            || opt_len_exceeds(self.usage_json.as_deref(), MAX_JSON_BYTES)
        {
            return Err(WalIdempotencyError::Malformed);
        }
        Ok(())
    }

    /// ENCLAVE-WRITTEN stamps only. `capture_started_at` is DEVICE-supplied and
    /// must never be folded in here.
    ///
    /// This guard exists to bound stamps the enclave itself wrote, so a commit
    /// stamp cannot precede a fact it recorded. `capture_events.started_at`
    /// comes verbatim from the client manifest, is never compared to the
    /// enclave clock on ingest, and is compared here as a raw STRING — so an
    /// offset-bearing form like `...T20:00:00+09:00` (a PAST instant) or a
    /// millisecond-less `...:04Z` sorts above every `now_iso()` stamp. Folding
    /// it in refused the settle for a work unit the claim family had already
    /// admitted, and the refusal leaves the members in `processing` for the
    /// lease to reclaim. Because `enumerate_claimable` has no `attempt_count`
    /// term — the ONLY attempt cap on this lane lives further down THIS tail —
    /// that became an uncapped loop re-issuing a PAID Vertex call every
    /// `CLAIM_LEASE_SECONDS`, bounded only by the daily budget it would starve.
    ///
    /// Nothing is weakened by excluding it: `capture_started_at` still binds
    /// the operation id, still binds the canonical request, still drives the
    /// budget-staleness test, and is still compared for exact equality by
    /// `apply`'s whole-row precondition. The sibling families agree — the
    /// claim's own `latest_observed_timestamp` folds only enclave stamps, and
    /// the success family bounds `capture_started_at` inside the work window,
    /// never against `committed_at`.
    fn latest_observed_timestamp(&self) -> &str {
        self.updated_at.as_str()
    }

    fn read(connection: &Connection, job_id: i64) -> rusqlite::Result<Option<Self>> {
        connection
            .query_row(
                "SELECT j.id,j.event_id,j.job_kind,j.input_revision,j.state,j.attempt_count,\
                        j.lease_until,j.error_code,j.usage_json,j.updated_at,\
                        m.processing_state,e.started_at \
                 FROM media_processing_jobs j \
                 JOIN capture_events e ON e.event_id=j.event_id \
                 JOIN media_objects m ON m.event_id=j.event_id \
                 WHERE j.id=?1",
                [job_id],
                |row| {
                    Ok(Self {
                        job_id: row.get(0)?,
                        event_id: row.get(1)?,
                        job_kind: row.get(2)?,
                        input_revision: row.get(3)?,
                        state: row.get(4)?,
                        attempt_count: row.get(5)?,
                        lease_until: row.get(6)?,
                        error_code: row.get(7)?,
                        usage_json: row.get(8)?,
                        updated_at: row.get(9)?,
                        media_processing_state: row.get(10)?,
                        capture_started_at: row.get(11)?,
                    })
                },
            )
            .optional()
    }
}

/// The observed `media_work_units` row. The claim created it, so the failure
/// tail always finds one; an absent row is a `Precondition`, never an insert.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(in crate::cp::media_worker) struct FailureUnitPredecessor {
    state: String,
    attempt_count: i64,
    reservation_retained: i64,
    error_code: Option<String>,
    usage_json: Option<String>,
    created_at: String,
    updated_at: String,
}

impl FailureUnitPredecessor {
    fn read(connection: &Connection, work_unit_id: &str) -> rusqlite::Result<Option<Self>> {
        connection
            .query_row(
                "SELECT state,attempt_count,reservation_retained,error_code,usage_json,\
                        created_at,updated_at \
                 FROM media_work_units WHERE id=?1",
                [work_unit_id],
                |row| {
                    Ok(Self {
                        state: row.get(0)?,
                        attempt_count: row.get(1)?,
                        reservation_retained: row.get(2)?,
                        error_code: row.get(3)?,
                        usage_json: row.get(4)?,
                        created_at: row.get(5)?,
                        updated_at: row.get(6)?,
                    })
                },
            )
            .optional()
    }

    fn validate(&self) -> Result<()> {
        if self.state.is_empty()
            || self.state.len() > MAX_ID_BYTES
            || self.attempt_count < 0
            || self.reservation_retained < 0
            || self.created_at.is_empty()
            || self.created_at.len() > MAX_TIMESTAMP_BYTES
            || self.updated_at.is_empty()
            || self.updated_at.len() > MAX_TIMESTAMP_BYTES
            || opt_len_exceeds(self.error_code.as_deref(), MAX_ID_BYTES)
            || opt_len_exceeds(self.usage_json.as_deref(), MAX_JSON_BYTES)
        {
            return Err(WalIdempotencyError::Malformed);
        }
        Ok(())
    }
}

pub(in crate::cp::media_worker) struct FailureObservation {
    pub(in crate::cp::media_worker) members: Vec<FailureMember>,
    pub(in crate::cp::media_worker) unit: FailureUnitPredecessor,
}

/// The owner's single pre-submit read. Members come back ordered by `job_id`
/// so the identity is canonical regardless of the caller's ordering; every
/// write below is an independent per-row CAS, so order never affects the
/// outcome.
pub(in crate::cp::media_worker) fn observe_failure(
    connection: &Connection,
    work_unit_id: &str,
    job_ids: &[i64],
) -> Result<Option<FailureObservation>> {
    let mut ordered = job_ids.to_vec();
    ordered.sort_unstable();
    ordered.dedup();
    let mut members = Vec::with_capacity(ordered.len());
    for job_id in ordered {
        let Some(member) = FailureMember::read(connection, job_id)
            .map_err(|_| WalIdempotencyError::Unavailable)?
        else {
            return Ok(None);
        };
        members.push(member);
    }
    let Some(unit) = FailureUnitPredecessor::read(connection, work_unit_id)
        .map_err(|_| WalIdempotencyError::Unavailable)?
    else {
        return Ok(None);
    };
    Ok(Some(FailureObservation { members, unit }))
}

pub(crate) struct MediaWorkFailurePlan {
    operation_id: WalLogicalOperationId,
    account_id: String,
    work_unit_id: String,
    class_name: String,
    error_code: String,
    processor_version: i64,
    attempt_limit: i64,
    resurrection_window_seconds: i64,
    budget_retry_seconds: i64,
    committed_at: String,
    unit: FailureUnitPredecessor,
    members: Vec<FailureMember>,
}

impl MediaWorkFailurePlan {
    #[allow(clippy::too_many_arguments)]
    pub(in crate::cp::media_worker) fn new(
        account_id: String,
        work_unit_id: String,
        class_name: String,
        error_code: String,
        processor_version: i64,
        attempt_limit: i64,
        resurrection_window_seconds: i64,
        budget_retry_seconds: i64,
        committed_at: String,
        observation: FailureObservation,
    ) -> Result<Self> {
        crate::store::validate_user_id(&account_id).map_err(|_| WalIdempotencyError::Malformed)?;
        let FailureObservation { members, unit } = observation;
        if members.len() > MAX_MEMBERS {
            return Err(WalIdempotencyError::Limit);
        }
        if members.is_empty()
            || processor_version <= 0
            || !(1..=MAX_ATTEMPT_LIMIT).contains(&attempt_limit)
            || resurrection_window_seconds <= 0
            || budget_retry_seconds <= 0
            || work_unit_id.is_empty()
            || work_unit_id.len() > MAX_ID_BYTES
            || error_code.is_empty()
            || error_code.len() > MAX_ID_BYTES
            || !matches!(class_name.as_str(), "audio" | "screen")
            || committed_at.is_empty()
            || committed_at.len() > MAX_TIMESTAMP_BYTES
        {
            return Err(WalIdempotencyError::Malformed);
        }
        for member in &members {
            member.validate()?;
        }
        unit.validate()?;
        if !members
            .windows(2)
            .all(|pair| pair[0].job_id < pair[1].job_id && pair[0].event_id != pair[1].event_id)
        {
            return Err(WalIdempotencyError::Malformed);
        }
        if members
            .iter()
            .any(|member| member.latest_observed_timestamp() > committed_at.as_str())
            || unit.created_at > committed_at
            || unit.updated_at > committed_at
        {
            return Err(WalIdempotencyError::Malformed);
        }
        let mut payload = Sha256::new();
        hash_field(&mut payload, work_unit_id.as_bytes())?;
        hash_field(&mut payload, class_name.as_bytes())?;
        hash_field(&mut payload, error_code.as_bytes())?;
        hash_field(&mut payload, &processor_version.to_be_bytes())?;
        hash_field(&mut payload, unit.state.as_bytes())?;
        hash_field(&mut payload, &unit.attempt_count.to_be_bytes())?;
        hash_field(&mut payload, &unit.reservation_retained.to_be_bytes())?;
        hash_opt(&mut payload, unit.error_code.as_deref())?;
        hash_opt(&mut payload, unit.usage_json.as_deref())?;
        hash_field(&mut payload, unit.created_at.as_bytes())?;
        hash_field(&mut payload, unit.updated_at.as_bytes())?;
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
            hash_field(&mut payload, member.capture_started_at.as_bytes())?;
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
            error_code,
            processor_version,
            attempt_limit,
            resurrection_window_seconds,
            budget_retry_seconds,
            committed_at,
            unit,
            members,
        })
    }

    fn is_budget(&self) -> bool {
        self.error_code == BUDGET_ERROR_CODE
    }

    /// `defer_for_budget`'s staleness horizon, reproduced exactly:
    /// `add_seconds(now, -RESURRECTION_WINDOW_SECONDS)` compared
    /// lexicographically against `capture_events.started_at`, matching the
    /// legacy SQL `e.started_at < ?2`.
    fn budget_window_start(&self) -> String {
        #[allow(clippy::cast_precision_loss, reason = "bounded window seconds")]
        isotime::add_seconds(
            &self.committed_at,
            -(self.resurrection_window_seconds as f64),
        )
    }

    /// The resolved per-member outcome. `updated_at` deliberately carries the
    /// FUTURE retry time on every non-terminal branch — see the module doc.
    fn resolve(&self, member: &FailureMember, budget_window_start: &str) -> MemberOutcome {
        if self.is_budget() {
            if member.capture_started_at.as_str() < budget_window_start {
                return MemberOutcome {
                    terminal: true,
                    state: TERMINAL_STATE,
                    attempt_count: member.attempt_count,
                    updated_at: self.committed_at.clone(),
                    media_processing_state: "failed",
                };
            }
            #[allow(clippy::cast_precision_loss, reason = "bounded retry seconds")]
            let retry_at =
                isotime::add_seconds(&self.committed_at, self.budget_retry_seconds as f64);
            return MemberOutcome {
                terminal: false,
                state: RETRY_STATE,
                attempt_count: member.attempt_count.saturating_sub(1).max(0),
                updated_at: retry_at,
                media_processing_state: RETRY_STATE,
            };
        }
        let terminal = member.attempt_count >= self.attempt_limit;
        #[allow(
            clippy::cast_precision_loss,
            reason = "the shift is capped at 6, so the product is at most 1920"
        )]
        let retry_at = isotime::add_seconds(
            &self.committed_at,
            (30_i64 * (1_i64 << member.attempt_count.min(6))) as f64,
        );
        MemberOutcome {
            terminal,
            state: if terminal {
                TERMINAL_STATE
            } else {
                RETRY_STATE
            },
            attempt_count: member.attempt_count,
            updated_at: if terminal {
                self.committed_at.clone()
            } else {
                retry_at
            },
            media_processing_state: if terminal { "failed" } else { RETRY_STATE },
        }
    }
}

struct MemberOutcome {
    terminal: bool,
    state: &'static str,
    attempt_count: i64,
    updated_at: String,
    media_processing_state: &'static str,
}

pub(crate) struct MediaWorkFailureLedger;

impl WalLogicalDomainPlan for MediaWorkFailurePlan {
    type Ledger = MediaWorkFailureLedger;
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
        encode_string(&mut request, &self.error_code)?;
        request.extend_from_slice(&self.processor_version.to_be_bytes());
        request.extend_from_slice(&self.attempt_limit.to_be_bytes());
        request.extend_from_slice(&self.resurrection_window_seconds.to_be_bytes());
        request.extend_from_slice(&self.budget_retry_seconds.to_be_bytes());
        encode_string(&mut request, &self.committed_at)?;
        encode_string(&mut request, &self.unit.state)?;
        request.extend_from_slice(&self.unit.attempt_count.to_be_bytes());
        request.extend_from_slice(&self.unit.reservation_retained.to_be_bytes());
        encode_opt(&mut request, self.unit.error_code.as_deref())?;
        encode_opt(&mut request, self.unit.usage_json.as_deref())?;
        encode_string(&mut request, &self.unit.created_at)?;
        encode_string(&mut request, &self.unit.updated_at)?;
        encode_len(&mut request, self.members.len())?;
        for member in &self.members {
            request.extend_from_slice(&member.job_id.to_be_bytes());
            encode_string(&mut request, &member.event_id)?;
            encode_string(&mut request, &member.job_kind)?;
            encode_string(&mut request, &member.input_revision)?;
            encode_string(&mut request, &member.state)?;
            request.extend_from_slice(&member.attempt_count.to_be_bytes());
            encode_opt(&mut request, member.lease_until.as_deref())?;
            encode_opt(&mut request, member.error_code.as_deref())?;
            encode_opt(&mut request, member.usage_json.as_deref())?;
            encode_string(&mut request, &member.updated_at)?;
            encode_string(&mut request, &member.media_processing_state)?;
            encode_string(&mut request, &member.capture_started_at)?;
        }
        Ok(request)
    }

    fn apply(&self, transaction: &Transaction<'_>) -> Result<WalReplayResult> {
        for member in &self.members {
            let observed = FailureMember::read(transaction, member.job_id)
                .map_err(|_| WalIdempotencyError::Unavailable)?;
            if observed.as_ref() != Some(member) {
                return Err(WalIdempotencyError::Precondition);
            }
        }
        let observed_unit = FailureUnitPredecessor::read(transaction, &self.work_unit_id)
            .map_err(|_| WalIdempotencyError::Unavailable)?;
        if observed_unit.as_ref() != Some(&self.unit) {
            return Err(WalIdempotencyError::Precondition);
        }
        let budget_window_start = self.budget_window_start();
        let mut any_terminal = false;
        for member in &self.members {
            let outcome = self.resolve(member, &budget_window_start);
            any_terminal |= outcome.terminal;
            let changed = transaction
                .execute(
                    "UPDATE media_processing_jobs \
                     SET state=?1,attempt_count=?2,lease_until=NULL,error_code=?3,updated_at=?4 \
                     WHERE id=?5 AND event_id=?6 AND job_kind=?7 AND input_revision=?8 \
                       AND state=?9 AND attempt_count=?10 AND lease_until IS ?11 \
                       AND error_code IS ?12 AND usage_json IS ?13 AND updated_at=?14",
                    params![
                        outcome.state,
                        outcome.attempt_count,
                        self.error_code,
                        outcome.updated_at,
                        member.job_id,
                        member.event_id,
                        member.job_kind,
                        member.input_revision,
                        member.state,
                        member.attempt_count,
                        member.lease_until,
                        member.error_code,
                        member.usage_json,
                        member.updated_at,
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
                        outcome.media_processing_state,
                        member.event_id,
                        member.media_processing_state,
                    ],
                )
                .map_err(|_| WalIdempotencyError::Unavailable)?;
            if changed != 1 {
                return Err(WalIdempotencyError::Corrupt);
            }
        }
        // A budget stop is never a unit failure: the members go back on the
        // retry ladder with a decremented attempt, so the unit does too.
        let unit_state = if self.is_budget() {
            RETRY_STATE
        } else {
            // Defense in depth: the legacy tail derived this from a COUNT over
            // the durable member rows. Re-run it and require it agrees with the
            // carried derivation.
            let terminal: i64 = transaction
                .query_row(
                    "SELECT COUNT(*) FROM media_processing_jobs \
                     WHERE id IN (SELECT job_id FROM media_work_members WHERE work_unit_id=?1) \
                     AND state='failed_terminal'",
                    [&self.work_unit_id],
                    |row| row.get(0),
                )
                .map_err(|_| WalIdempotencyError::Unavailable)?;
            if (terminal > 0) != any_terminal {
                return Err(WalIdempotencyError::Corrupt);
            }
            if any_terminal {
                TERMINAL_STATE
            } else {
                RETRY_STATE
            }
        };
        let changed = transaction
            .execute(
                "UPDATE media_work_units SET state=?1,error_code=?2,updated_at=?3 \
                 WHERE id=?4 AND state=?5 AND attempt_count=?6 AND reservation_retained=?7 \
                   AND error_code IS ?8 AND usage_json IS ?9 \
                   AND created_at=?10 AND updated_at=?11",
                params![
                    unit_state,
                    self.error_code,
                    self.committed_at,
                    self.work_unit_id,
                    self.unit.state,
                    self.unit.attempt_count,
                    self.unit.reservation_retained,
                    self.unit.error_code,
                    self.unit.usage_json,
                    self.unit.created_at,
                    self.unit.updated_at,
                ],
            )
            .map_err(|_| WalIdempotencyError::Unavailable)?;
        if changed != 1 {
            return Err(WalIdempotencyError::Corrupt);
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

impl WalLogicalDomainLedger<MediaWorkFailurePlan> for MediaWorkFailureLedger {
    fn lookup(
        connection: &Connection,
        prepared: &PreparedLogicalMutation<MediaWorkFailurePlan>,
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
                 FROM archive_v3_wal_media_work_failure_operations
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
        prepared: &PreparedLogicalMutation<MediaWorkFailurePlan>,
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
                "INSERT INTO archive_v3_wal_media_work_failure_operations
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
                "UPDATE archive_v3_wal_media_work_failure_state
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

fn require_kind(prepared: &PreparedLogicalMutation<MediaWorkFailurePlan>) -> Result<()> {
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
                    "CREATE TABLE archive_v3_wal_media_work_failure_schema (
                        singleton INTEGER PRIMARY KEY CHECK(singleton=1),
                        format_version INTEGER NOT NULL CHECK(format_version=1),
                        codec_version INTEGER NOT NULL CHECK(codec_version=1)
                     ) STRICT;
                     CREATE TABLE archive_v3_wal_media_work_failure_operations (
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
                     CREATE TABLE archive_v3_wal_media_work_failure_state (
                        singleton INTEGER PRIMARY KEY CHECK(singleton=1),
                        row_count INTEGER NOT NULL CHECK(row_count BETWEEN 0 AND 65536),
                        result_bytes INTEGER NOT NULL CHECK(result_bytes BETWEEN 0 AND 589824)
                     ) STRICT;
                     INSERT INTO archive_v3_wal_media_work_failure_schema
                        (singleton,format_version,codec_version) VALUES (1,1,1);
                     INSERT INTO archive_v3_wal_media_work_failure_state
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
             FROM archive_v3_wal_media_work_failure_schema WHERE singleton=1",
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
             FROM archive_v3_wal_media_work_failure_state WHERE singleton=1",
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

fn hash_opt(hasher: &mut Sha256, value: Option<&str>) -> Result<()> {
    match value {
        None => hash_field(hasher, &[0]),
        Some(value) => {
            hash_field(hasher, &[1])?;
            hash_field(hasher, value.as_bytes())
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
mod tests {
    use super::*;
    use crate::archive_v3_wal_idempotency::{
        execute_prepared_for_owner, LogicalMutationDisposition,
    };

    const ACCOUNT: &str = "11111111-1111-4111-8111-111111111111";
    const WORK_UNIT: &str = "wu-1";
    /// The claim's commit stamp: every seeded predecessor carries it.
    const CLAIMED_AT: &str = "2026-08-21T12:00:01.000Z";
    const LEASE_UNTIL: &str = "2026-08-21T12:05:01.000Z";
    /// The failure's commit stamp, inside the lease.
    const COMMITTED_AT: &str = "2026-08-21T12:01:00.000Z";
    const CAPTURE_STARTED_AT: &str = "2026-08-21T11:00:00.000Z";
    const STALE_CAPTURE_STARTED_AT: &str = "2026-07-01T11:00:00.000Z";
    const ATTEMPT_LIMIT: i64 = 3;
    const WINDOW_SECONDS: i64 = 7 * 24 * 3_600;
    const BUDGET_SECONDS: i64 = 6 * 60 * 60;

    fn install_schema(connection: &Connection) {
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
                    usage_json TEXT,
                    updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
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

    /// One claimed work unit: `attempts` per member, both `processing`,
    /// exactly as the claim boundary leaves them.
    fn fixture(attempts: &[i64], capture_started_at: &str) -> Connection {
        let connection = Connection::open_in_memory().unwrap();
        install_schema(&connection);
        connection
            .execute(
                "INSERT INTO media_work_units
                 (id,work_class,processor_version,state,started_at,ended_at,
                  reserved_output_tokens,reservation_retained,attempt_count,usage_json,
                  created_at,updated_at)
                 VALUES (?1,'screen',1,'processing','2026-08-21T11:00:00.000Z',
                         '2026-08-21T11:00:02.000Z',2048,0,1,'{}',?2,?2)",
                params![WORK_UNIT, CLAIMED_AT],
            )
            .unwrap();
        for (index, attempt) in attempts.iter().enumerate() {
            let job_id = i64::try_from(index).unwrap() + 1;
            let event_id = format!("ev-{index}");
            connection
                .execute(
                    "INSERT INTO capture_events
                     (event_id,stream_kind,capture_session_id,stream_id,sequence,started_at,ended_at)
                     VALUES (?1,'screen','sess-1','stream-1',?2,?3,?3)",
                    params![event_id, job_id, capture_started_at],
                )
                .unwrap();
            connection
                .execute(
                    "INSERT INTO media_objects
                     (asset_id,event_id,object_key,mime_type,codec,byte_length,sha256,processing_state)
                     VALUES (?1,?2,?3,'image/png','png',1024,?4,'processing')",
                    params![
                        format!("asset-{index}"),
                        event_id,
                        format!("raw/{index}"),
                        format!("{:064x}", job_id),
                    ],
                )
                .unwrap();
            connection
                .execute(
                    "INSERT INTO media_processing_jobs
                     (id,event_id,job_kind,input_revision,processor_version,state,attempt_count,
                      lease_until,error_code,usage_json,updated_at)
                     VALUES (?1,?2,'gemini_screen',?3,1,'processing',?4,?5,NULL,'{}',?6)",
                    params![
                        job_id,
                        event_id,
                        format!("rev-{index}"),
                        attempt,
                        LEASE_UNTIL,
                        CLAIMED_AT,
                    ],
                )
                .unwrap();
            connection
                .execute(
                    "INSERT INTO media_work_members
                     (work_unit_id,event_id,job_id,ordinal,window_start_ms,window_end_ms)
                     VALUES (?1,?2,?3,?4,0,2000)",
                    params![WORK_UNIT, event_id, job_id, i64::try_from(index).unwrap()],
                )
                .unwrap();
        }
        connection
    }

    fn job_ids(attempts: &[i64]) -> Vec<i64> {
        (1..=i64::try_from(attempts.len()).unwrap()).collect()
    }

    fn build(
        connection: &Connection,
        error_code: &str,
        attempt_limit: i64,
        ids: &[i64],
    ) -> MediaWorkFailurePlan {
        let observation = observe_failure(connection, WORK_UNIT, ids)
            .unwrap()
            .unwrap();
        MediaWorkFailurePlan::new(
            ACCOUNT.into(),
            WORK_UNIT.into(),
            "screen".into(),
            error_code.into(),
            1,
            attempt_limit,
            WINDOW_SECONDS,
            BUDGET_SECONDS,
            COMMITTED_AT.into(),
            observation,
        )
        .unwrap()
    }

    fn settle(
        connection: &mut Connection,
        plan: MediaWorkFailurePlan,
    ) -> Result<LogicalMutationDisposition> {
        let prepared = PreparedLogicalMutation::prepare(plan)?;
        execute_prepared_for_owner(connection, prepared).map(|outcome| outcome.disposition())
    }

    fn dump(connection: &Connection) -> Vec<String> {
        let mut rows = Vec::new();
        for sql in [
            "SELECT id,state,attempt_count,lease_until,error_code,updated_at \
             FROM media_processing_jobs ORDER BY id",
            "SELECT event_id,processing_state FROM media_objects ORDER BY event_id",
            "SELECT id,state,error_code,attempt_count,created_at,updated_at \
             FROM media_work_units ORDER BY id",
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

    fn job_row(connection: &Connection, job_id: i64) -> (String, i64, Option<String>, String) {
        connection
            .query_row(
                "SELECT state,attempt_count,lease_until,updated_at \
                 FROM media_processing_jobs WHERE id=?1",
                [job_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .unwrap()
    }

    #[test]
    fn the_failure_tail_applies_once_and_then_replays() {
        let attempts = [1_i64, 1];
        let mut connection = fixture(&attempts, CAPTURE_STARTED_AT);
        let plan = build(
            &connection,
            "processing_error",
            ATTEMPT_LIMIT,
            &job_ids(&attempts),
        );
        let replay = build(
            &connection,
            "processing_error",
            ATTEMPT_LIMIT,
            &job_ids(&attempts),
        );
        assert!(matches!(
            settle(&mut connection, plan).unwrap(),
            LogicalMutationDisposition::Applied
        ));
        let applied = dump(&connection);
        assert!(matches!(
            settle(&mut connection, replay).unwrap(),
            LogicalMutationDisposition::Replayed
        ));
        assert_eq!(applied, dump(&connection));
    }

    /// A device-supplied `capture_started_at` that STRING-sorts above the
    /// commit stamp must still settle. It is not an enclave-written fact, so
    /// it must not reach the commit-stamp ordering guard.
    ///
    /// If it does, the settle returns `Malformed`, the owner warns and returns
    /// leaving the members in `processing`, and `enumerate_claimable` re-admits
    /// them on lease expiry with NO `attempt_count` term — because the only
    /// attempt cap on this lane is further down this very tail. That is an
    /// uncapped loop paying for a Vertex call every `CLAIM_LEASE_SECONDS`.
    ///
    /// Both spellings below are reachable from a real client: an offset-bearing
    /// form is a PAST instant that sorts high, and a millisecond-less form
    /// sorts high because `Z` (0x5A) exceeds `.` (0x2E).
    #[test]
    fn a_high_sorting_device_capture_stamp_still_settles() {
        for stamp in [
            "2026-08-21T21:00:00+09:00", // == 12:00Z, a PAST instant that sorts high
            "2026-08-21T12:01:00Z",      // no milliseconds: 'Z' 0x5A > '.' 0x2E
            "2026-08-21T12:10:00.000Z",  // a genuinely skewed device clock
        ] {
            assert!(
                stamp > COMMITTED_AT,
                "precondition: {stamp} must sort above the commit stamp"
            );
            let attempts = [1_i64];
            let mut connection = fixture(&attempts, stamp);
            let plan = build(
                &connection,
                "processing_error",
                ATTEMPT_LIMIT,
                &job_ids(&attempts),
            );
            settle(&mut connection, plan).unwrap_or_else(|error| {
                panic!(
                    "a device stamp sorting above the commit stamp must settle, \
                     not wedge the unit in `processing` for an uncapped paid \
                     retry loop: {stamp} -> {error:?}"
                )
            });
            let (state, _attempt_count, lease, _updated) = job_row(&connection, 1);
            assert_eq!(state, "retry_wait", "{stamp} must leave `processing`");
            assert_eq!(lease, None);
        }
    }

    #[test]
    fn non_terminal_failure_writes_the_retry_time_not_the_commit_stamp() {
        // THE TRAP. `updated_at` doubles as next-attempt-at; binding it to
        // `committed_at` makes every failed job immediately re-eligible,
        // destroys the exponential backoff, and turns a transient Vertex
        // outage into a paid retry storm bounded only by MAX_ATTEMPTS.
        let attempts = [2_i64];
        let mut connection = fixture(&attempts, CAPTURE_STARTED_AT);
        let plan = build(
            &connection,
            "processing_error",
            ATTEMPT_LIMIT,
            &job_ids(&attempts),
        );
        settle(&mut connection, plan).unwrap();
        let (state, attempt_count, lease, updated) = job_row(&connection, 1);
        assert_eq!(state, "retry_wait");
        assert_eq!(attempt_count, 2, "the failure arm never moves the counter");
        assert_eq!(lease, None);
        // 30 * (1 << 2) == 120 seconds after the commit stamp.
        assert_eq!(updated, isotime::add_seconds(COMMITTED_AT, 120.0));
        assert_ne!(updated, COMMITTED_AT);
        // ...and the eligibility predicate really does read it that way.
        let eligible = crate::cp::media_worker::wal::claim::enumerate_claimable(
            &connection,
            1,
            "gemini_screen",
            COMMITTED_AT,
            128,
        )
        .unwrap();
        assert!(
            eligible.is_empty(),
            "a backed-off job must not be re-claimable at the commit stamp"
        );
        let eligible = crate::cp::media_worker::wal::claim::enumerate_claimable(
            &connection,
            1,
            "gemini_screen",
            &isotime::add_seconds(COMMITTED_AT, 121.0),
            128,
        )
        .unwrap();
        assert_eq!(eligible.len(), 1, "and it returns once the backoff elapses");
    }

    #[test]
    fn the_failure_arm_terminalizes_exactly_at_the_carried_limit() {
        for (attempt, expected) in [(2_i64, "retry_wait"), (3, "failed_terminal")] {
            let attempts = [attempt];
            let mut connection = fixture(&attempts, CAPTURE_STARTED_AT);
            let plan = build(
                &connection,
                "processing_error",
                ATTEMPT_LIMIT,
                &job_ids(&attempts),
            );
            settle(&mut connection, plan).unwrap();
            let (state, _, _, updated) = job_row(&connection, 1);
            assert_eq!(state, expected, "attempt_count={attempt}");
            if expected == "failed_terminal" {
                assert_eq!(
                    updated, COMMITTED_AT,
                    "a terminal row carries no retry time"
                );
            }
            let media: String = connection
                .query_row(
                    "SELECT processing_state FROM media_objects WHERE event_id='ev-0'",
                    [],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(
                media,
                if expected == "failed_terminal" {
                    "failed"
                } else {
                    "retry_wait"
                }
            );
        }
    }

    #[test]
    fn terminalization_follows_the_carried_limit_not_the_code_constant() {
        // Reading MAX_ATTEMPTS inside apply() would terminalize here and make
        // replay drift the moment the constant changes.
        let attempts = [3_i64];
        let mut connection = fixture(&attempts, CAPTURE_STARTED_AT);
        let plan = build(&connection, "processing_error", 5, &job_ids(&attempts));
        settle(&mut connection, plan).unwrap();
        assert_eq!(job_row(&connection, 1).0, "retry_wait");
    }

    #[test]
    fn the_budget_arm_parks_fresh_capture_and_terminalizes_stale_capture() {
        let attempts = [2_i64];
        let mut connection = fixture(&attempts, CAPTURE_STARTED_AT);
        let plan = build(
            &connection,
            BUDGET_ERROR_CODE,
            ATTEMPT_LIMIT,
            &job_ids(&attempts),
        );
        settle(&mut connection, plan).unwrap();
        let (state, attempt_count, lease, updated) = job_row(&connection, 1);
        assert_eq!(state, "retry_wait");
        assert_eq!(attempt_count, 1, "a budget stop refunds the attempt");
        assert_eq!(lease, None);
        assert_eq!(
            updated,
            isotime::add_seconds(COMMITTED_AT, 21_600.0),
            "parked six hours out, not at the commit stamp"
        );
        let unit: (String, String) = connection
            .query_row(
                "SELECT state,error_code FROM media_work_units WHERE id=?1",
                [WORK_UNIT],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(unit, ("retry_wait".into(), BUDGET_ERROR_CODE.into()));

        let mut stale = fixture(&attempts, STALE_CAPTURE_STARTED_AT);
        let plan = build(
            &stale,
            BUDGET_ERROR_CODE,
            ATTEMPT_LIMIT,
            &job_ids(&attempts),
        );
        settle(&mut stale, plan).unwrap();
        let (state, attempt_count, _, updated) = job_row(&stale, 1);
        assert_eq!(state, "failed_terminal");
        assert_eq!(attempt_count, 2);
        assert_eq!(updated, COMMITTED_AT);
        let unit_state: String = stale
            .query_row(
                "SELECT state FROM media_work_units WHERE id=?1",
                [WORK_UNIT],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(
            unit_state, "retry_wait",
            "a budget stop is never a unit failure, however stale a member is"
        );
    }

    #[test]
    fn the_unit_state_follows_the_members() {
        // One terminal member is enough to terminalize the unit.
        let attempts = [3_i64, 1];
        let mut connection = fixture(&attempts, CAPTURE_STARTED_AT);
        let plan = build(
            &connection,
            "processing_error",
            ATTEMPT_LIMIT,
            &job_ids(&attempts),
        );
        settle(&mut connection, plan).unwrap();
        let unit: String = connection
            .query_row(
                "SELECT state FROM media_work_units WHERE id=?1",
                [WORK_UNIT],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(unit, "failed_terminal");
        assert_eq!(job_row(&connection, 1).0, "failed_terminal");
        assert_eq!(job_row(&connection, 2).0, "retry_wait");

        let attempts = [1_i64, 1];
        let mut connection = fixture(&attempts, CAPTURE_STARTED_AT);
        let plan = build(
            &connection,
            "processing_error",
            ATTEMPT_LIMIT,
            &job_ids(&attempts),
        );
        settle(&mut connection, plan).unwrap();
        let unit: String = connection
            .query_row(
                "SELECT state FROM media_work_units WHERE id=?1",
                [WORK_UNIT],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(unit, "retry_wait");
    }

    #[test]
    fn a_moved_predecessor_fails_closed_without_writing() {
        let attempts = [1_i64, 1];
        let mut connection = fixture(&attempts, CAPTURE_STARTED_AT);
        let plan = build(
            &connection,
            "processing_error",
            ATTEMPT_LIMIT,
            &job_ids(&attempts),
        );
        connection
            .execute(
                "UPDATE media_processing_jobs SET attempt_count=2 WHERE id=2",
                [],
            )
            .unwrap();
        let expected = dump(&connection);
        assert!(matches!(
            settle(&mut connection, plan),
            Err(WalIdempotencyError::Precondition)
        ));
        assert_eq!(expected, dump(&connection));
    }

    #[test]
    fn the_error_code_is_part_of_the_identity() {
        let attempts = [1_i64];
        let connection = fixture(&attempts, CAPTURE_STARTED_AT);
        let first = build(
            &connection,
            "processing_error",
            ATTEMPT_LIMIT,
            &job_ids(&attempts),
        );
        let second = build(
            &connection,
            "invalid_model_output",
            ATTEMPT_LIMIT,
            &job_ids(&attempts),
        );
        assert_ne!(first.operation_id(), second.operation_id());
        let reminted = MediaWorkFailurePlan::new(
            ACCOUNT.into(),
            WORK_UNIT.into(),
            "screen".into(),
            "processing_error".into(),
            1,
            ATTEMPT_LIMIT,
            WINDOW_SECONDS,
            BUDGET_SECONDS,
            "2026-08-21T12:02:00.000Z".into(),
            observe_failure(&connection, WORK_UNIT, &job_ids(&attempts))
                .unwrap()
                .unwrap(),
        )
        .unwrap();
        assert_eq!(
            first.operation_id(),
            reminted.operation_id(),
            "the commit stamp never enters the identity"
        );
    }
}
