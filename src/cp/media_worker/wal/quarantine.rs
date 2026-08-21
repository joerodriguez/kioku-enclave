//! The claim-lane quarantine as a sealed WAL plan (ADR-0022 slice 10i).
//!
//! ## What this family is for
//!
//! `MediaWorkClaimPlan::new` refuses deterministically on a bad predecessor,
//! and its refusal is correct — the unit must not be admitted. What was wrong
//! was the RESPONSE to the refusal, and the response is what this family
//! bounds.
//!
//! Before it existed, a deterministic refusal on the claim path wedged an
//! account's whole media lane silently and permanently:
//!
//! * `claim::enumerate_claimable`'s `state='pending'` arm carries no
//!   `attempt_count` term (unlike its `retry_wait` arm, which bounds on
//!   `updated_at`), so a `pending` job is re-enumerated by every sweep;
//! * `plan_first` is pure, so the identical candidate is re-selected;
//! * there is no terminalization path for a `pending` job — `mark_failed` and
//!   `defer_for_budget` and every other `media_processing_jobs` UPDATE need a
//!   SUCCESSFUL claim first, which is exactly what is failing;
//! * `claim_media_work_unit` logged a `warn!` and returned `ClaimOutcome::Idle`,
//!   which by documented design writes nothing and burns no attempt.
//!
//! So the sweep re-derived the identical refusal every 30 seconds forever, with
//! no attempt cap, no user-visible error, and — because
//! `media_objects.processing_state` stayed `'queued'` —
//! `span_has_recoverable_media` pinning the summarizer's forward-only cursor.
//! One poisoned audio job also starved the SCREEN lane, because audio is
//! scheduled first and `process_user` returned on `Idle`.
//!
//! ## What it does
//!
//! One plan, one transaction, over the named jobs (and an exact stored work
//! unit when that predecessor caused the refusal): `attempt_count+1`, and then
//! the SAME two-armed ladder `mark_failed` walks —
//!
//! * `attempt_count+1 >= attempt_limit` → `state='failed_terminal'`,
//!   `media_objects.processing_state='failed'`, `updated_at=committed_at`;
//! * otherwise → `state='retry_wait'`,
//!   `media_objects.processing_state='retry_wait'`, and `updated_at` bound to
//!   the FUTURE next-attempt time, `committed_at + retry_base * 2^min(n,6)`.
//!
//! That last point is `wal::failure`'s documented trap and it applies here
//! verbatim: `updated_at` doubles as next-attempt-at for every eligibility
//! predicate on this lane, so binding it to the commit stamp would leave the
//! job instantly re-eligible and change nothing at all. The future stamp IS the
//! mechanism by which the lane starts moving again.
//!
//! `error_code` is `claim_unplannable`, deliberately NOT one of the two codes
//! (`media_integrity`, `transcript_target_conflict`) that
//! `resurrect_failed_jobs` and `span_has_recoverable_media` treat as never
//! recoverable. A quarantined job therefore keeps the full bounded
//! second-chance ladder: `MAX_ATTEMPTS` fast rounds here, then up to
//! `RESURRECTION_TOTAL_ATTEMPT_CAP` hourly resurrections while the source event
//! is inside the seven-day window. Negative or already-oversized attempt counts
//! terminalize at a saturating carried cap and cannot resurrect. Global clock
//! inversions are never attributed here; they remain non-charging and recover
//! when the clock samples regain order.
//!
//! The claim family carries that same total-attempt cap through its scan,
//! constructor, request identity, and transactional re-resolution. A job or
//! exact existing work unit already at/above it is a named durable refusal,
//! never an increment: checked Rust arithmetic plus guarded integer SQL are the
//! final defence against overflow or SQLite INTEGER-to-REAL promotion.
//!
//! ## The refusal is evidence, not authority
//!
//! A quarantine is justified only while the exact joined row which made the
//! claim impossible is still present. The plan commits every column returned
//! by the claim scan and, when applicable, the complete existing work-unit
//! predecessor. `apply()` rereads all of that evidence transactionally and
//! re-derives the named refusal before the first write. Repairing an over-long
//! capture stamp, planner input, poisoned job stamp, or work-unit predecessor
//! therefore wins the race and fails the stale quarantine closed.
//!
//! The structured cases prove a malformed row, unwindowable planner head,
//! member commit-order violation, duplicate-event topology, or malformed/future
//! stored work unit. Duplicate jobs sharing one event are verified first and
//! then update their shared media row exactly once from the aggregate member
//! disposition. All carried strings are hashed with the WAL framework's
//! unambiguous length framing, while the canonical request contains fixed-size
//! predecessor commitments so its one-MiB envelope remains independent of
//! large fields.
//!
//! No provider call, no media read, no clock, no Store, no launcher, no retry
//! loop. It cannot create a `media_work_units` row, cannot reserve tokens and
//! cannot admit a work unit the claim guard refused — a quarantine is the
//! opposite of a claim.
//!
//! Kind 6 (`DeterministicMediaWorkResult`) is reused: this is the media
//! job/work bookkeeping family that ordinal 6 already owns. The subtype keeps
//! the ledgers disjoint.

use std::collections::BTreeMap;

use rusqlite::{params, Connection, OptionalExtension, Transaction};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::archive_v3_wal_idempotency::{
    hash_field, stable_operation_source, DomainLedgerBounds, LogicalMutationResult,
    PreparedLogicalMutation, WalIdempotencyError, WalLogicalDomainLedger, WalLogicalDomainPlan,
    WalLogicalOperationId, WalOperationKind, WalReplayResult,
};
use crate::cp::isotime;

use super::claim::{
    self, AttributableClaimRefusal, AttributableClaimRefusalKind, ClaimableRow,
    ClaimedUnitExpectation, ClaimedUnitPredecessor,
};

const REQUEST_V1: u16 = 1;
const SUBTYPE: &[u8] = b"adr-0022-media-claim-quarantine-v1";
const SCHEMA_TABLE: &str = "archive_v3_wal_media_claim_quarantine_schema";
const LEDGER_TABLE: &str = "archive_v3_wal_media_claim_quarantine_operations";
const STATE_TABLE: &str = "archive_v3_wal_media_claim_quarantine_state";
const ENCODED_UNIT_RESULT_BYTES: usize = 9;
const MAX_ROWS: u32 = 65_536;
const MAX_RESULT_BYTES: u64 = 65_536 * 9;
const BOUNDS: DomainLedgerBounds = DomainLedgerBounds::new(MAX_ROWS, MAX_RESULT_BYTES);
/// A size bound for the quarantine plan's own scalar inputs. Complete joined
/// rows use `hash_field`'s framework bound and fixed-size commitments.
const MAX_PLAN_FIELD_BYTES: usize = 8 * 1024;
/// The claim scan's LIMIT: the largest set one enumeration can name.
const MAX_MEMBERS: usize = 128;
const MAX_ATTEMPT_LIMIT: i64 = 64;
const MAX_RETRY_BASE_SECONDS: i64 = 24 * 60 * 60;
/// `mark_failed`'s exponent clamp, carried so a replay on a later binary
/// re-derives the identical stamp.
const MAX_BACKOFF_SHIFT: i64 = 6;
const TERMINAL_STATE: &str = "failed_terminal";
const RETRY_STATE: &str = "retry_wait";
const TERMINAL_MEDIA_STATE: &str = "failed";
const RETRY_MEDIA_STATE: &str = "retry_wait";
/// The three `media_processing_jobs.state` values a normal quarantine may
/// CONSUME:
/// exactly the ones `claim::enumerate_claimable` admits. Pinned as literals so
/// a widened eligibility predicate cannot smuggle in a state this family never
/// observed — a quarantine must never be able to reach `succeeded`.
const QUARANTINABLE_STATES: [&str; 3] = ["pending", "retry_wait", "processing"];
/// Deliberately not `media_integrity` and not `transcript_target_conflict`:
/// those two are the codes the resurrection ladder and the summarizer's
/// cursor-hold treat as permanently unrecoverable. A claim refusal is not
/// known to be permanent, so it keeps the full bounded second chance.
pub(in crate::cp::media_worker) const QUARANTINE_ERROR_CODE: &str = "claim_unplannable";

type Result<T> = std::result::Result<T, WalIdempotencyError>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum QuarantineReason {
    MalformedRow,
    AttemptCountOutsideBounds,
    UnwindowableHead,
    CommitStampPrecedesMember,
    DuplicateEventTopology,
    WorkUnitMalformed,
    WorkUnitCommitOrder,
    WorkUnitDerivedMismatch,
    WorkUnitAttemptCount,
}

impl QuarantineReason {
    const fn discriminator(self) -> u8 {
        match self {
            Self::MalformedRow => 1,
            Self::UnwindowableHead => 2,
            Self::CommitStampPrecedesMember => 3,
            Self::DuplicateEventTopology => 4,
            Self::WorkUnitMalformed => 5,
            Self::WorkUnitCommitOrder => 6,
            Self::WorkUnitDerivedMismatch => 7,
            Self::AttemptCountOutsideBounds => 8,
            Self::WorkUnitAttemptCount => 9,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct QuarantineUnit {
    work_unit_id: String,
    predecessor: ClaimedUnitPredecessor,
    expectation: ClaimedUnitExpectation,
}

/// One quarantined job with the full observed predecessor tuple the CAS pins.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(in crate::cp::media_worker) struct QuarantineMember {
    row: ClaimableRow,
    reason: QuarantineReason,
}

impl QuarantineMember {
    /// Built from the SAME complete joined row the claim boundary enumerated.
    /// The reason is derived here rather than accepted from the owner, and is
    /// re-derived inside `apply()` after an exact transactional reread.
    pub(in crate::cp::media_worker) fn from_claimable(
        row: &ClaimableRow,
        job_kind: &str,
        processor_version: i64,
        resurrection_attempt_cap: i64,
        committed_at: &str,
    ) -> Result<Self> {
        let reason = if row.attempt_count_refuses(resurrection_attempt_cap) {
            QuarantineReason::AttemptCountOutsideBounds
        } else if row.refusal_reason(resurrection_attempt_cap).is_some() {
            QuarantineReason::MalformedRow
        } else if row.is_unwindowable(resurrection_attempt_cap)? {
            QuarantineReason::UnwindowableHead
        } else if row.construction_refuses_at(job_kind, processor_version, committed_at) {
            QuarantineReason::CommitStampPrecedesMember
        } else {
            // The refusal disappeared between the claim attempt and the
            // quarantine stamp (for example a sub-second clock inversion).
            // Retrying is correct; charging the job is not.
            return Err(WalIdempotencyError::Precondition);
        };
        Ok(Self {
            row: row.clone(),
            reason,
        })
    }

    fn for_reason(row: ClaimableRow, reason: QuarantineReason) -> Self {
        Self { row, reason }
    }

    fn validate(
        &self,
        job_kind: &str,
        processor_version: i64,
        resurrection_attempt_cap: i64,
        committed_at: &str,
    ) -> Result<()> {
        let row = &self.row;
        // Do not re-reject the very malformed fields `refusal_reason` names.
        // The only production caller obtains these rows from the literal claim
        // eligibility query before classification; every predecessor byte is
        // exact evidence and remains safe to bind in a CAS. In particular this
        // lets an invalid state/kind/version be settled as the poison it is,
        // while non-malformed reasons retain the explicit scope check below.
        if self.reason != QuarantineReason::MalformedRow
            && (row.job_kind != job_kind
                || row.processor_version != processor_version
                || !QUARANTINABLE_STATES.contains(&row.state.as_str()))
        {
            return Err(WalIdempotencyError::Malformed);
        }
        let reason_still_holds = match self.reason {
            QuarantineReason::MalformedRow => {
                row.refusal_reason(resurrection_attempt_cap).is_some()
                    && !row.attempt_count_refuses(resurrection_attempt_cap)
            }
            QuarantineReason::AttemptCountOutsideBounds => {
                row.attempt_count_refuses(resurrection_attempt_cap)
            }
            QuarantineReason::UnwindowableHead => {
                row.refusal_reason(resurrection_attempt_cap).is_none()
                    && row.is_unwindowable(resurrection_attempt_cap)?
            }
            QuarantineReason::CommitStampPrecedesMember => {
                row.refusal_reason(resurrection_attempt_cap).is_none()
                    && !row.is_unwindowable(resurrection_attempt_cap)?
                    && row.construction_refuses_at(job_kind, processor_version, committed_at)
            }
            QuarantineReason::DuplicateEventTopology
            | QuarantineReason::WorkUnitMalformed
            | QuarantineReason::WorkUnitCommitOrder
            | QuarantineReason::WorkUnitDerivedMismatch => true,
            QuarantineReason::WorkUnitAttemptCount => true,
        };
        if !reason_still_holds {
            return Err(WalIdempotencyError::Precondition);
        }
        Ok(())
    }

    /// The disposition this member settles to, derived from carried facts
    /// only. `attempt_count` is advanced HERE because no claim ran: the claim
    /// is the only other writer that advances it, and skipping the increment
    fn disposition(
        &self,
        attempt_limit: i64,
        resurrection_attempt_cap: i64,
        retry_base_seconds: i64,
        committed_at: &str,
    ) -> Settle {
        // A corrupt negative attempt is not allowed to walk hundreds of retry
        // rounds back toward zero. It terminalizes at the carried resurrection
        // cap, which also makes it ineligible for resurrection. An already
        // oversized value is preserved/saturated and is likewise ineligible.
        if self.row.attempt_count < 0 || self.row.attempt_count >= resurrection_attempt_cap {
            return Settle {
                next_attempt: if self.row.attempt_count < 0 {
                    resurrection_attempt_cap
                } else {
                    self.row.attempt_count
                },
                job_state: TERMINAL_STATE,
                updated_at: committed_at.to_owned(),
            };
        }
        let next_attempt = self.row.attempt_count.saturating_add(1);
        if next_attempt >= attempt_limit {
            return Settle {
                next_attempt,
                job_state: TERMINAL_STATE,
                updated_at: committed_at.to_owned(),
            };
        }
        // `mark_failed`'s exact ladder: base * 2^min(attempts, 6), where
        // `attempts` is the count AFTER the advance, because on the paid path
        // the claim advances it before `mark_failed` reads it.
        #[allow(clippy::cast_precision_loss, reason = "bounded backoff seconds")]
        let backoff =
            retry_base_seconds.saturating_mul(1_i64 << next_attempt.min(MAX_BACKOFF_SHIFT)) as f64;
        Settle {
            next_attempt,
            job_state: RETRY_STATE,
            // The FUTURE next-attempt time, never the commit stamp: this value
            // IS the eligibility horizon `enumerate_claimable`,
            // `pending_work_classes` and `lease_work_unit` all read for a
            // `retry_wait` job. Binding it to `committed_at` would re-admit the
            // job on the very next sweep and reproduce the wedge exactly.
            updated_at: isotime::add_seconds(committed_at, backoff),
        }
    }
}

struct Settle {
    next_attempt: i64,
    job_state: &'static str,
    updated_at: String,
}

pub(crate) struct MediaClaimQuarantinePlan {
    operation_id: WalLogicalOperationId,
    account_id: String,
    job_kind: String,
    processor_version: i64,
    error_code: String,
    attempt_limit: i64,
    resurrection_attempt_cap: i64,
    retry_base_seconds: i64,
    eligibility_horizon: String,
    committed_at: String,
    reason: QuarantineReason,
    members: Vec<QuarantineMember>,
    unit: Option<QuarantineUnit>,
}

impl MediaClaimQuarantinePlan {
    /// `members` must be the jobs a claim refusal was ATTRIBUTED to — never a
    /// whole enumeration, and never a job the refusal cannot be charged to.
    /// The owner derives them from `ClaimScan::Unplannable` or from the claim
    /// observation's structured refusal classifier, both of which are the
    /// attribution halves of guards that already exist.
    #[allow(clippy::too_many_arguments)]
    pub(in crate::cp::media_worker) fn new(
        account_id: String,
        job_kind: String,
        processor_version: i64,
        error_code: String,
        attempt_limit: i64,
        resurrection_attempt_cap: i64,
        retry_base_seconds: i64,
        eligibility_horizon: String,
        committed_at: String,
        members: Vec<QuarantineMember>,
    ) -> Result<Self> {
        Self::build(
            account_id,
            job_kind,
            processor_version,
            error_code,
            attempt_limit,
            resurrection_attempt_cap,
            retry_base_seconds,
            eligibility_horizon,
            committed_at,
            members,
            None,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub(in crate::cp::media_worker) fn from_attributable_refusal(
        account_id: String,
        job_kind: String,
        processor_version: i64,
        error_code: String,
        attempt_limit: i64,
        resurrection_attempt_cap: i64,
        retry_base_seconds: i64,
        refusal: AttributableClaimRefusal,
    ) -> Result<Self> {
        let reason = match refusal.kind {
            AttributableClaimRefusalKind::MemberCommitOrder => {
                QuarantineReason::CommitStampPrecedesMember
            }
            AttributableClaimRefusalKind::DuplicateEventTopology => {
                QuarantineReason::DuplicateEventTopology
            }
            AttributableClaimRefusalKind::WorkUnitMalformed => QuarantineReason::WorkUnitMalformed,
            AttributableClaimRefusalKind::WorkUnitCommitOrder => {
                QuarantineReason::WorkUnitCommitOrder
            }
            AttributableClaimRefusalKind::WorkUnitDerivedMismatch => {
                QuarantineReason::WorkUnitDerivedMismatch
            }
            AttributableClaimRefusalKind::WorkUnitAttemptCount => {
                QuarantineReason::WorkUnitAttemptCount
            }
        };
        if matches!(
            refusal.kind,
            AttributableClaimRefusalKind::WorkUnitMalformed
                | AttributableClaimRefusalKind::WorkUnitCommitOrder
                | AttributableClaimRefusalKind::WorkUnitDerivedMismatch
                | AttributableClaimRefusalKind::WorkUnitAttemptCount
        ) {
            let class = match job_kind.as_str() {
                "gemini_audio" => crate::cp::media_planner::WorkClass::Audio,
                "gemini_screen" => crate::cp::media_planner::WorkClass::Screen,
                _ => return Err(WalIdempotencyError::Malformed),
            };
            let derived = claim::work_unit_id(
                class,
                refusal
                    .rows
                    .iter()
                    .map(|row| (row.event_id.as_str(), row.media_sha256.as_str())),
            );
            if refusal.work_unit_id.as_deref() != Some(derived.as_str()) {
                return Err(WalIdempotencyError::Precondition);
            }
        }
        let unit = match (refusal.work_unit_id, refusal.unit, refusal.unit_expectation) {
            (Some(work_unit_id), Some(predecessor), Some(expectation)) => Some(QuarantineUnit {
                work_unit_id,
                predecessor,
                expectation,
            }),
            (None, None, None) => None,
            _ => return Err(WalIdempotencyError::Malformed),
        };
        let members = refusal
            .rows
            .into_iter()
            .map(|row| QuarantineMember::for_reason(row, reason))
            .collect();
        Self::build(
            account_id,
            job_kind,
            processor_version,
            error_code,
            attempt_limit,
            resurrection_attempt_cap,
            retry_base_seconds,
            refusal.claimed_at,
            refusal.committed_at,
            members,
            unit,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn build(
        account_id: String,
        job_kind: String,
        processor_version: i64,
        error_code: String,
        attempt_limit: i64,
        resurrection_attempt_cap: i64,
        retry_base_seconds: i64,
        eligibility_horizon: String,
        committed_at: String,
        mut members: Vec<QuarantineMember>,
        unit: Option<QuarantineUnit>,
    ) -> Result<Self> {
        crate::store::validate_user_id(&account_id).map_err(|_| WalIdempotencyError::Malformed)?;
        if members.len() > MAX_MEMBERS {
            // Never truncate an attributed set: a job dropped here is a job
            // that stays `pending` and keeps the lane wedged.
            return Err(WalIdempotencyError::Limit);
        }
        if members.is_empty()
            || processor_version <= 0
            || !(1..=MAX_ATTEMPT_LIMIT).contains(&attempt_limit)
            || !(attempt_limit..=MAX_ATTEMPT_LIMIT).contains(&resurrection_attempt_cap)
            || !(1..=MAX_RETRY_BASE_SECONDS).contains(&retry_base_seconds)
            || job_kind.is_empty()
            || plan_field_exceeds(Some(job_kind.as_str()))
            || error_code.is_empty()
            || plan_field_exceeds(Some(error_code.as_str()))
            || committed_at.is_empty()
            || plan_field_exceeds(Some(committed_at.as_str()))
            || eligibility_horizon.is_empty()
            || plan_field_exceeds(Some(eligibility_horizon.as_str()))
        {
            return Err(WalIdempotencyError::Malformed);
        }
        let reason = members[0].reason;
        if members.iter().any(|member| member.reason != reason) {
            return Err(WalIdempotencyError::Malformed);
        }
        if matches!(
            reason,
            QuarantineReason::CommitStampPrecedesMember
                | QuarantineReason::DuplicateEventTopology
                | QuarantineReason::WorkUnitMalformed
                | QuarantineReason::WorkUnitCommitOrder
                | QuarantineReason::WorkUnitDerivedMismatch
                | QuarantineReason::WorkUnitAttemptCount
        ) && eligibility_horizon > committed_at
        {
            // This is the proof that a backwards enclave clock was NOT blamed
            // on a member or stored work-unit predecessor.
            return Err(WalIdempotencyError::Precondition);
        }
        Self::validate_group_reason(
            reason,
            &members,
            unit.as_ref(),
            &job_kind,
            processor_version,
            resurrection_attempt_cap,
            &committed_at,
        )?;
        // Enumeration order is event time, not job id. Canonicalize here so a
        // set of multiple malformed rows cannot make its own quarantine
        // unbuildable merely because ids and capture times order differently.
        members.sort_unstable_by_key(|member| member.row.job_id);
        if !members
            .windows(2)
            .all(|pair| pair[0].row.job_id < pair[1].row.job_id)
        {
            return Err(WalIdempotencyError::Malformed);
        }
        for member in &members {
            member.validate(
                &job_kind,
                processor_version,
                resurrection_attempt_cap,
                &committed_at,
            )?;
        }
        let mut payload = Sha256::new();
        hash_field(&mut payload, job_kind.as_bytes())?;
        hash_field(&mut payload, &processor_version.to_be_bytes())?;
        hash_field(&mut payload, error_code.as_bytes())?;
        hash_field(&mut payload, &attempt_limit.to_be_bytes())?;
        hash_field(&mut payload, &resurrection_attempt_cap.to_be_bytes())?;
        hash_field(&mut payload, &retry_base_seconds.to_be_bytes())?;
        hash_field(&mut payload, eligibility_horizon.as_bytes())?;
        hash_field(&mut payload, &[reason.discriminator()])?;
        hash_field(&mut payload, &[u8::from(unit.is_some())])?;
        if let Some(unit) = unit.as_ref() {
            hash_field(&mut payload, unit.work_unit_id.as_bytes())?;
            hash_field(&mut payload, &unit.predecessor.commitment()?)?;
            hash_field(&mut payload, &unit.expectation.commitment()?)?;
        }
        hash_field(
            &mut payload,
            &u32::try_from(members.len())
                .map_err(|_| WalIdempotencyError::Limit)?
                .to_be_bytes(),
        )?;
        for member in &members {
            hash_field(&mut payload, &member.row.commitment()?)?;
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
            job_kind,
            processor_version,
            error_code,
            attempt_limit,
            resurrection_attempt_cap,
            retry_base_seconds,
            eligibility_horizon,
            committed_at,
            reason,
            members,
            unit,
        })
    }

    fn validate_group_reason(
        reason: QuarantineReason,
        members: &[QuarantineMember],
        unit: Option<&QuarantineUnit>,
        job_kind: &str,
        processor_version: i64,
        resurrection_attempt_cap: i64,
        committed_at: &str,
    ) -> Result<()> {
        match reason {
            QuarantineReason::MalformedRow
            | QuarantineReason::AttemptCountOutsideBounds
            | QuarantineReason::UnwindowableHead
            | QuarantineReason::CommitStampPrecedesMember => {
                if unit.is_some() {
                    return Err(WalIdempotencyError::Malformed);
                }
            }
            QuarantineReason::DuplicateEventTopology => {
                if unit.is_some()
                    || members.iter().any(|member| {
                        members
                            .iter()
                            .filter(|other| other.row.event_id == member.row.event_id)
                            .count()
                            < 2
                    })
                {
                    return Err(WalIdempotencyError::Precondition);
                }
            }
            QuarantineReason::WorkUnitMalformed
            | QuarantineReason::WorkUnitCommitOrder
            | QuarantineReason::WorkUnitDerivedMismatch
            | QuarantineReason::WorkUnitAttemptCount => {
                let unit = unit.ok_or(WalIdempotencyError::Malformed)?;
                let still_refused = match reason {
                    QuarantineReason::WorkUnitAttemptCount => unit
                        .predecessor
                        .attempt_count_refuses(resurrection_attempt_cap),
                    QuarantineReason::WorkUnitMalformed => {
                        unit.predecessor
                            .refusal_reason(resurrection_attempt_cap)
                            .is_some()
                            && !unit
                                .predecessor
                                .attempt_count_refuses(resurrection_attempt_cap)
                    }
                    QuarantineReason::WorkUnitCommitOrder => {
                        unit.predecessor
                            .refusal_reason(resurrection_attempt_cap)
                            .is_none()
                            && (unit.predecessor.created_at.as_str() > committed_at
                                || unit.predecessor.updated_at.as_str() > committed_at)
                    }
                    QuarantineReason::WorkUnitDerivedMismatch => {
                        unit.predecessor
                            .refusal_reason(resurrection_attempt_cap)
                            .is_none()
                            && unit.predecessor.created_at.as_str() <= committed_at
                            && unit.predecessor.updated_at.as_str() <= committed_at
                            && unit.predecessor.derived_mismatch(&unit.expectation)
                    }
                    _ => unreachable!(),
                };
                if !still_refused {
                    return Err(WalIdempotencyError::Precondition);
                }
            }
        }
        for member in members {
            member.validate(
                job_kind,
                processor_version,
                resurrection_attempt_cap,
                committed_at,
            )?;
        }
        Ok(())
    }

    /// Whether this plan terminalizes any member — the fact the owner reports
    /// so an operator can tell a backoff from an exhausted ladder without
    /// re-deriving the arithmetic.
    pub(in crate::cp::media_worker) fn terminalizes(&self) -> bool {
        self.members.iter().any(|member| {
            member
                .disposition(
                    self.attempt_limit,
                    self.resurrection_attempt_cap,
                    self.retry_base_seconds,
                    &self.committed_at,
                )
                .job_state
                == TERMINAL_STATE
        })
    }
}

pub(crate) struct MediaClaimQuarantineLedger;

impl WalLogicalDomainPlan for MediaClaimQuarantinePlan {
    type Ledger = MediaClaimQuarantineLedger;
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
        encode_string(&mut request, &self.job_kind)?;
        request.extend_from_slice(&self.processor_version.to_be_bytes());
        encode_string(&mut request, &self.error_code)?;
        request.extend_from_slice(&self.attempt_limit.to_be_bytes());
        request.extend_from_slice(&self.resurrection_attempt_cap.to_be_bytes());
        request.extend_from_slice(&self.retry_base_seconds.to_be_bytes());
        encode_string(&mut request, &self.eligibility_horizon)?;
        encode_string(&mut request, &self.committed_at)?;
        request.push(self.reason.discriminator());
        request.push(u8::from(self.unit.is_some()));
        if let Some(unit) = self.unit.as_ref() {
            encode_string(&mut request, &unit.work_unit_id)?;
            request.extend_from_slice(&unit.predecessor.commitment()?);
            request.extend_from_slice(&unit.expectation.commitment()?);
        }
        encode_len(&mut request, self.members.len())?;
        for member in &self.members {
            request.extend_from_slice(&member.row.commitment()?);
        }
        Ok(request)
    }

    fn apply(&self, transaction: &Transaction<'_>) -> Result<WalReplayResult> {
        // Phase 1: validate EVERY exact predecessor and the refusal itself
        // before the first write. A stale later member is a Precondition, never
        // a partially applied quarantine hidden by rollback.
        for member in &self.members {
            let current = ClaimableRow::read_exact(transaction, member.row.job_id)
                .map_err(|_| WalIdempotencyError::Unavailable)?
                .ok_or(WalIdempotencyError::Precondition)?;
            if current != member.row {
                return Err(WalIdempotencyError::Precondition);
            }
        }
        if let Some(unit) = self.unit.as_ref() {
            let current = ClaimedUnitPredecessor::read(transaction, &unit.work_unit_id)
                .map_err(|_| WalIdempotencyError::Unavailable)?
                .ok_or(WalIdempotencyError::Precondition)?;
            if current != unit.predecessor {
                return Err(WalIdempotencyError::Precondition);
            }
        }
        Self::validate_group_reason(
            self.reason,
            &self.members,
            self.unit.as_ref(),
            &self.job_kind,
            self.processor_version,
            self.resurrection_attempt_cap,
            &self.committed_at,
        )?;

        let outcomes = self
            .members
            .iter()
            .map(|member| self.settle_for(member))
            .collect::<Vec<_>>();
        let mut media = BTreeMap::<&str, (&str, bool)>::new();
        for (member, settle) in self.members.iter().zip(&outcomes) {
            let entry = media
                .entry(member.row.event_id.as_str())
                .or_insert((member.row.media_processing_state.as_str(), true));
            if entry.0 != member.row.media_processing_state {
                return Err(WalIdempotencyError::Corrupt);
            }
            entry.1 &= settle.job_state == TERMINAL_STATE;
        }

        // Phase 2: all evidence is stable. Update every job first, then each
        // shared media row ONCE so duplicate-event jobs cannot invalidate one
        // another inside their own transaction.
        for (member, settle) in self.members.iter().zip(&outcomes) {
            // `IS` — never `=` — for the three nullable columns: a NULL
            // comparison is never true, so `=` would silently match zero rows
            // and this family would report a quarantine it never wrote.
            let changed = transaction
                .execute(
                    "UPDATE media_processing_jobs \
                     SET state=?1,attempt_count=?2,lease_until=NULL,error_code=?3,updated_at=?4 \
                     WHERE id=?5 AND event_id=?6 AND job_kind=?7 AND input_revision=?8 \
                       AND processor_version=?9 AND state=?10 AND attempt_count=?11 \
                       AND lease_until IS ?12 AND error_code IS ?13 AND usage_json IS ?14 \
                       AND updated_at=?15",
                    params![
                        settle.job_state,
                        settle.next_attempt,
                        self.error_code,
                        settle.updated_at,
                        member.row.job_id,
                        member.row.event_id,
                        member.row.job_kind,
                        member.row.input_revision,
                        member.row.processor_version,
                        member.row.state,
                        member.row.attempt_count,
                        member.row.lease_until,
                        member.row.error_code,
                        member.row.usage_json,
                        member.row.updated_at,
                    ],
                )
                .map_err(|_| WalIdempotencyError::Unavailable)?;
            if changed != 1 {
                return Err(WalIdempotencyError::Corrupt);
            }
        }
        for (event_id, (observed_state, all_terminal)) in media {
            let changed = transaction
                .execute(
                    "UPDATE media_objects SET processing_state=?1 \
                     WHERE event_id=?2 AND processing_state=?3",
                    params![
                        if all_terminal {
                            TERMINAL_MEDIA_STATE
                        } else {
                            RETRY_MEDIA_STATE
                        },
                        event_id,
                        observed_state,
                    ],
                )
                .map_err(|_| WalIdempotencyError::Unavailable)?;
            if changed != 1 {
                return Err(WalIdempotencyError::Corrupt);
            }
        }
        if let Some(unit) = self.unit.as_ref() {
            let any_terminal = outcomes
                .iter()
                .any(|outcome| outcome.job_state == TERMINAL_STATE);
            let changed = transaction
                .execute(
                    "UPDATE media_work_units SET state=?1,error_code=?2,updated_at=?3 \
                     WHERE id=?4 AND work_class=?5 AND processor_version=?6 AND state=?7 \
                       AND started_at=?8 AND ended_at=?9 AND reserved_output_tokens=?10 \
                       AND attempt_count=?11 AND reservation_retained=?12 \
                       AND error_code IS ?13 AND usage_json IS ?14 \
                       AND created_at=?15 AND updated_at=?16",
                    params![
                        if any_terminal {
                            TERMINAL_STATE
                        } else {
                            RETRY_STATE
                        },
                        self.error_code,
                        self.committed_at,
                        unit.work_unit_id,
                        unit.predecessor.work_class,
                        unit.predecessor.processor_version,
                        unit.predecessor.state,
                        unit.predecessor.started_at,
                        unit.predecessor.ended_at,
                        unit.predecessor.reserved_output_tokens,
                        unit.predecessor.attempt_count,
                        unit.predecessor.reservation_retained,
                        unit.predecessor.error_code,
                        unit.predecessor.usage_json,
                        unit.predecessor.created_at,
                        unit.predecessor.updated_at,
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

impl MediaClaimQuarantinePlan {
    fn unit_attempt_requires_terminal(&self) -> bool {
        self.unit.as_ref().is_some_and(|unit| {
            unit.predecessor.attempt_count < 0
                || unit.predecessor.attempt_count >= self.resurrection_attempt_cap
        })
    }

    fn settle_for(&self, member: &QuarantineMember) -> Settle {
        if self.unit_attempt_requires_terminal() {
            return Settle {
                next_attempt: if member.row.attempt_count < 0 {
                    self.resurrection_attempt_cap
                } else {
                    member.row.attempt_count.max(self.resurrection_attempt_cap)
                },
                job_state: TERMINAL_STATE,
                updated_at: self.committed_at.clone(),
            };
        }
        member.disposition(
            self.attempt_limit,
            self.resurrection_attempt_cap,
            self.retry_base_seconds,
            &self.committed_at,
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum LedgerSchemaState {
    Absent,
    Present,
}

impl WalLogicalDomainLedger<MediaClaimQuarantinePlan> for MediaClaimQuarantineLedger {
    fn lookup(
        connection: &Connection,
        prepared: &PreparedLogicalMutation<MediaClaimQuarantinePlan>,
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
                 FROM archive_v3_wal_media_claim_quarantine_operations
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
        prepared: &PreparedLogicalMutation<MediaClaimQuarantinePlan>,
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
                "INSERT INTO archive_v3_wal_media_claim_quarantine_operations
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
                "UPDATE archive_v3_wal_media_claim_quarantine_state
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

fn require_kind(prepared: &PreparedLogicalMutation<MediaClaimQuarantinePlan>) -> Result<()> {
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
                    "CREATE TABLE archive_v3_wal_media_claim_quarantine_schema (
                        singleton INTEGER PRIMARY KEY CHECK(singleton=1),
                        format_version INTEGER NOT NULL CHECK(format_version=1),
                        codec_version INTEGER NOT NULL CHECK(codec_version=1)
                     ) STRICT;
                     CREATE TABLE archive_v3_wal_media_claim_quarantine_operations (
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
                     CREATE TABLE archive_v3_wal_media_claim_quarantine_state (
                        singleton INTEGER PRIMARY KEY CHECK(singleton=1),
                        row_count INTEGER NOT NULL CHECK(row_count BETWEEN 0 AND 65536),
                        result_bytes INTEGER NOT NULL CHECK(result_bytes BETWEEN 0 AND 589824)
                     ) STRICT;
                     INSERT INTO archive_v3_wal_media_claim_quarantine_schema
                        (singleton,format_version,codec_version) VALUES (1,1,1);
                     INSERT INTO archive_v3_wal_media_claim_quarantine_state
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
             FROM archive_v3_wal_media_claim_quarantine_schema WHERE singleton=1",
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
             FROM archive_v3_wal_media_claim_quarantine_state WHERE singleton=1",
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

const fn plan_field_exceeds(value: Option<&str>) -> bool {
    match value {
        Some(value) => value.len() > MAX_PLAN_FIELD_BYTES,
        None => false,
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::archive_v3_wal_idempotency::{
        execute_prepared_for_owner, LogicalMutationDisposition,
    };
    use crate::cp::media_planner::WorkClass;
    use crate::cp::media_worker::wal::claim::{
        self, enumerate_claimable, scan_for_claim, unplannable_members, ClaimScan,
        MediaWorkClaimPlan,
    };
    // The claim boundary's OWN schema and seed. A second copy here could drift
    // away from the rows this family is asked to settle, which is the one thing
    // it must never do.
    use crate::cp::media_worker::wal::claim::tests::{fixture, ACCOUNT, AS_OF, COMMITTED_AT};

    const ATTEMPT_LIMIT: i64 = 3;
    const RESURRECTION_ATTEMPT_CAP: i64 = 9;
    const RETRY_BASE_SECONDS: i64 = 30;

    fn rows(connection: &Connection) -> Vec<ClaimableRow> {
        enumerate_claimable(connection, 1, "gemini_screen", AS_OF, 128).unwrap()
    }

    fn plan_for(
        connection: &Connection,
        job_ids: &[i64],
        committed_at: &str,
    ) -> MediaClaimQuarantinePlan {
        let members = rows(connection)
            .iter()
            .filter(|row| job_ids.contains(&row.job_id))
            .map(|row| {
                QuarantineMember::from_claimable(
                    row,
                    "gemini_screen",
                    1,
                    RESURRECTION_ATTEMPT_CAP,
                    committed_at,
                )
            })
            .collect::<Result<Vec<_>>>()
            .unwrap();
        assert_eq!(
            members.len(),
            job_ids.len(),
            "the fixture must expose every named refused job"
        );
        MediaClaimQuarantinePlan::new(
            ACCOUNT.into(),
            "gemini_screen".into(),
            1,
            QUARANTINE_ERROR_CODE.into(),
            ATTEMPT_LIMIT,
            RESURRECTION_ATTEMPT_CAP,
            RETRY_BASE_SECONDS,
            AS_OF.into(),
            committed_at.into(),
            members,
        )
        .unwrap()
    }

    fn plan_for_refusal(refusal: AttributableClaimRefusal) -> MediaClaimQuarantinePlan {
        MediaClaimQuarantinePlan::from_attributable_refusal(
            ACCOUNT.into(),
            "gemini_screen".into(),
            1,
            QUARANTINE_ERROR_CODE.into(),
            ATTEMPT_LIMIT,
            RESURRECTION_ATTEMPT_CAP,
            RETRY_BASE_SECONDS,
            refusal,
        )
        .unwrap()
    }

    fn poison_commit_order(connection: &Connection, job_id: i64) {
        connection
            .execute(
                "UPDATE media_processing_jobs SET updated_at=?1 WHERE id=?2",
                params!["2026-08-21T23:00:00.000+09:00", job_id],
            )
            .unwrap();
    }

    fn settle(
        connection: &mut Connection,
        plan: MediaClaimQuarantinePlan,
    ) -> Result<LogicalMutationDisposition> {
        let prepared = PreparedLogicalMutation::prepare(plan)?;
        execute_prepared_for_owner(connection, prepared).map(|outcome| outcome.disposition())
    }

    fn job(connection: &Connection, id: i64) -> (String, i64, Option<String>, String, String) {
        connection
            .query_row(
                "SELECT j.state,j.attempt_count,j.error_code,j.updated_at,m.processing_state \
                 FROM media_processing_jobs j JOIN media_objects m ON m.event_id=j.event_id \
                 WHERE j.id=?1",
                [id],
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
            .unwrap()
    }

    /// The non-terminal arm writes the FUTURE next-attempt time into
    /// `updated_at`, never the commit stamp.
    ///
    /// This is `wal::failure`'s documented trap and it is the whole mechanism
    /// here: `updated_at` doubles as next-attempt-at for
    /// `enumerate_claimable`, `pending_work_classes`, `lease_work_unit` and
    /// `resurrect_failed_jobs` alike. Bound to `committed_at`, a quarantined
    /// job would be re-admitted by the very next sweep and this family would
    /// change nothing at all — the wedge would survive inside its own remedy.
    ///
    /// Falsifiability, checked by sabotage: returning `committed_at.to_owned()`
    /// from the `retry_wait` arm of `QuarantineMember::disposition` makes the
    /// `> COMMITTED_AT` assertion fail AND makes the re-enumeration assertion
    /// find the job still eligible.
    #[test]
    fn a_deferred_quarantine_parks_the_job_behind_a_future_next_attempt_time() {
        let mut connection = fixture(2);
        poison_commit_order(&connection, 1);
        let plan = plan_for(&connection, &[1], COMMITTED_AT);
        let replay = plan_for(&connection, &[1], COMMITTED_AT);
        assert_eq!(
            settle(&mut connection, plan).unwrap(),
            LogicalMutationDisposition::Applied
        );
        let (state, attempts, error_code, updated_at, media_state) = job(&connection, 1);
        assert_eq!(state, "retry_wait");
        assert_eq!(
            attempts, 1,
            "the attempt ladder advances; no claim did it for us"
        );
        assert_eq!(error_code.as_deref(), Some("claim_unplannable"));
        assert_eq!(media_state, "retry_wait");
        assert!(
            updated_at.as_str() > COMMITTED_AT,
            "updated_at is next-attempt-at, not the commit stamp: {updated_at}"
        );
        let commit_ms = isotime::parse_epoch_millis(COMMITTED_AT).unwrap();
        let next_ms = isotime::parse_epoch_millis(&updated_at).unwrap();
        // `mark_failed`'s exact ladder at attempt 1: 30 * 2^1.
        assert_eq!(next_ms - commit_ms, 60_000);

        // The job has left the eligible set at the horizon it was parked past,
        // and its untouched sibling has not.
        let observed = enumerate_claimable(&connection, 1, "gemini_screen", COMMITTED_AT, 128)
            .unwrap()
            .iter()
            .map(|row| row.job_id)
            .collect::<Vec<_>>();
        assert_eq!(observed, vec![2]);
        assert_eq!(
            job(&connection, 2).0,
            "pending",
            "a quarantine touches only what it names"
        );

        // The identical plan replays and writes nothing at all.
        let before = connection.total_changes();
        assert_eq!(
            settle(&mut connection, replay).unwrap(),
            LogicalMutationDisposition::Replayed
        );
        assert_eq!(
            connection.total_changes(),
            before,
            "a replay writes nothing"
        );
    }

    /// The ladder terminalizes at the CARRIED limit and lands in the shape the
    /// existing recovery machinery already understands: `failed_terminal` with
    /// an `error_code` that is neither of the two codes
    /// `resurrect_failed_jobs` and `span_has_recoverable_media` treat as
    /// permanently unrecoverable.
    ///
    /// That is the reversibility answer. A quarantine is not a verdict that
    /// the media is bad; it is a verdict that the CLAIM could not be built,
    /// and a transient cause (a clock inversion that clears, a defect fixed by
    /// the next deploy) is picked back up by the bounded second-chance ladder
    /// while the source event is inside the seven-day window.
    ///
    /// Falsifiability, checked by sabotage: changing `QUARANTINE_ERROR_CODE` to
    /// `"media_integrity"` fails the resurrection-eligibility assertion;
    /// changing `>=` to `>` in `disposition` leaves the job in `retry_wait` and
    /// the terminal assertions fail.
    #[test]
    fn the_ladder_terminalizes_at_the_carried_limit_and_stays_resurrectable() {
        let mut connection = fixture(1);
        poison_commit_order(&connection, 1);
        connection
            .execute(
                "UPDATE media_processing_jobs SET attempt_count=?1 WHERE id=1",
                params![ATTEMPT_LIMIT - 1],
            )
            .unwrap();
        let plan = plan_for(&connection, &[1], COMMITTED_AT);
        assert!(
            plan.terminalizes(),
            "the owner reports this arm as terminal"
        );
        settle(&mut connection, plan).unwrap();
        let (state, attempts, error_code, updated_at, media_state) = job(&connection, 1);
        assert_eq!(state, "failed_terminal");
        assert_eq!(attempts, ATTEMPT_LIMIT);
        assert_eq!(media_state, "failed");
        assert_eq!(
            updated_at, COMMITTED_AT,
            "a terminal settle stamps the commit time, not a retry time"
        );

        // The exact predicates `resurrect_failed_jobs` and
        // `span_has_recoverable_media` apply, spelled out so a future rename of
        // the code cannot silently move this job into the never-recover set.
        let code = error_code.unwrap();
        assert_ne!(code, "media_integrity");
        assert_ne!(code, "transcript_target_conflict");
        // RESURRECTION_TOTAL_ATTEMPT_CAP is 9; the memory-hold bound is
        // MAX_ATTEMPTS + 2 = 5. Both still hold this job.
        assert!(attempts < 9, "the second-chance ladder is not exhausted");
        assert!(attempts < 5, "the summarizer cursor is still held for it");
    }

    /// **The remedy must survive the poison.**
    ///
    /// Every row this family is handed is, by definition, a row some guard
    /// refused. #331's trigger was a stamp that string-sorts above the enclave
    /// commit stamp; the live sibling is one that is simply too long. If this
    /// family imported either bound — a `committed_at` ordering guard, or a
    /// `MAX_TIMESTAMP_BYTES` measurement — it would refuse to settle exactly
    /// the rows it exists for and the wedge would survive inside its own cure.
    ///
    /// Falsifiability, checked by sabotage: adding `member.updated_at >
    /// committed_at` to `MediaClaimQuarantinePlan::new` makes case (a) refuse;
    /// applying the plan-scalar 8 KiB limit to committed row fields makes case
    /// (b) refuse. Both make the settle assertion fail.
    #[test]
    fn the_quarantine_settles_the_very_stamps_the_claim_guard_refuses() {
        for (case, poison) in [
            // (a) #331: an offset-bearing device stamp denoting a PAST instant
            //     whose text sorts above every `now_iso()` until 23:00Z.
            (
                "sorts above the commit stamp",
                "2026-08-21T23:00:00.000+09:00".to_owned(),
            ),
            // (b) The live sibling: longer than every settle family's bound.
            (
                "over the old quarantine plan-scalar bound",
                format!(
                    "2026-08-21T11:00:00.{}Z",
                    "0".repeat(MAX_PLAN_FIELD_BYTES + 1)
                ),
            ),
            // (c) Not a timestamp at all.
            ("unparseable", "not-a-timestamp".to_owned()),
        ] {
            let mut connection = fixture(1);
            connection
                .execute(
                    "UPDATE media_processing_jobs SET updated_at=?1 WHERE id=1",
                    params![poison],
                )
                .unwrap();
            let stored = enumerate_claimable(&connection, 1, "gemini_screen", AS_OF, 128).unwrap();
            assert_eq!(
                stored.len(),
                1,
                "{case}: a pending job is enumerated whatever its stamp"
            );
            assert_eq!(
                stored[0].updated_at, poison,
                "{case}: the fixture must actually bite"
            );

            let plan = plan_for(&connection, &[1], COMMITTED_AT);
            settle(&mut connection, plan)
                .unwrap_or_else(|error| panic!("{case}: the quarantine must settle it: {error:?}"));
            let (state, attempts, _, updated_at, _) = job(&connection, 1);
            assert_eq!(state, "retry_wait", "{case}");
            assert_eq!(attempts, 1, "{case}");
            assert!(
                updated_at.as_str() > COMMITTED_AT,
                "{case}: the parked stamp is derived from the COMMIT stamp, never from the poison"
            );
        }
    }

    #[test]
    fn a_legacy_overlong_capture_stamp_is_quarantined_before_any_claim() {
        let mut connection = fixture(2);
        let original: String = connection
            .query_row(
                "SELECT started_at FROM capture_events WHERE event_id='ev-0'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let poison = format!("{}{}Z", original.trim_end_matches('Z'), "0".repeat(64));
        assert!(
            poison.len() > 64 && isotime::parse_epoch_millis(&poison).is_some(),
            "the regression value must still denote the original instant"
        );
        connection
            .execute(
                "UPDATE capture_events SET started_at=?1 WHERE event_id='ev-0'",
                params![poison],
            )
            .unwrap();

        let ClaimScan::Unplannable(refused) = scan_for_claim(
            &connection,
            WorkClass::Screen,
            1,
            AS_OF,
            128,
            RESURRECTION_ATTEMPT_CAP,
        )
        .unwrap() else {
            panic!("the legacy row must be refused before claim construction")
        };
        assert_eq!(
            refused.iter().map(|row| row.job_id).collect::<Vec<_>>(),
            vec![1]
        );
        assert_eq!(
            connection
                .query_row("SELECT COUNT(*) FROM media_work_units", [], |row| row
                    .get::<_, i64>(0))
                .unwrap(),
            0,
            "no work unit means no reservation and no paid provider call"
        );

        let plan = plan_for(&connection, &[1], COMMITTED_AT);
        settle(&mut connection, plan).unwrap();
        assert_eq!(job(&connection, 1).0, "retry_wait");
        let ClaimScan::Observed(observation) = scan_for_claim(
            &connection,
            WorkClass::Screen,
            1,
            COMMITTED_AT,
            128,
            RESURRECTION_ATTEMPT_CAP,
        )
        .unwrap() else {
            panic!("the untouched sibling must proceed after quarantine")
        };
        assert_eq!(
            observation
                .member_rows()
                .iter()
                .map(|row| row.job_id)
                .collect::<Vec<_>>(),
            vec![2]
        );
    }

    #[test]
    fn repairing_the_refusal_evidence_invalidates_a_stale_quarantine() {
        let mut connection = fixture(1);
        let original: String = connection
            .query_row(
                "SELECT started_at FROM capture_events WHERE event_id='ev-0'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let poison = format!("{}{}Z", original.trim_end_matches('Z'), "0".repeat(64));
        connection
            .execute(
                "UPDATE capture_events SET started_at=?1 WHERE event_id='ev-0'",
                params![poison],
            )
            .unwrap();
        let stale = plan_for(&connection, &[1], COMMITTED_AT);

        connection
            .execute(
                "UPDATE capture_events SET started_at=?1 WHERE event_id='ev-0'",
                params![original],
            )
            .unwrap();
        assert_eq!(
            settle(&mut connection, stale).err(),
            Some(WalIdempotencyError::Precondition),
            "a repaired capture fact must win the race"
        );
        assert_eq!(job(&connection, 1).0, "pending");
        assert_eq!(job(&connection, 1).1, 0);
        assert_eq!(job(&connection, 1).4, "queued");
    }

    #[test]
    fn multiple_refusals_are_canonicalized_by_job_id_before_settle() {
        let mut connection = fixture(2);
        for (event_id, seconds) in [("ev-0", 10), ("ev-1", 0)] {
            let poison = format!("2026-08-21T11:00:{seconds:02}.{}Z", "0".repeat(64));
            connection
                .execute(
                    "UPDATE capture_events SET started_at=?1 WHERE event_id=?2",
                    params![poison, event_id],
                )
                .unwrap();
        }
        assert_eq!(
            rows(&connection)
                .iter()
                .map(|row| row.job_id)
                .collect::<Vec<_>>(),
            vec![2, 1],
            "claim enumeration is capture order, not job-id order"
        );
        let plan = plan_for(&connection, &[1, 2], COMMITTED_AT);
        let same = plan_for(&connection, &[2, 1], COMMITTED_AT);
        assert_eq!(plan.operation_id(), same.operation_id());
        assert_eq!(
            plan.canonical_request().unwrap(),
            same.canonical_request().unwrap()
        );
        settle(&mut connection, plan).unwrap();
        assert_eq!(job(&connection, 1).0, "retry_wait");
        assert_eq!(job(&connection, 2).0, "retry_wait");
    }

    /// A predecessor that moved between the claim scan and this settle fails
    /// closed, and the nullable columns are compared with `IS` so a NULL
    /// cannot silently match zero rows and be reported as a quarantine.
    ///
    /// Falsifiability, checked by sabotage: replacing `usage_json IS ?14` with
    /// `usage_json = ?14` makes the untouched case write nothing and its
    /// `Applied` assertion fails.
    #[test]
    fn a_moved_predecessor_fails_closed_and_nulls_are_compared_with_is() {
        let mut connection = fixture(1);
        poison_commit_order(&connection, 1);
        // NULL `lease_until`/`error_code`/`usage_json` on a pending job: the
        // ordinary case, and the one `=` would silently miss.
        let plan = plan_for(&connection, &[1], COMMITTED_AT);
        assert_eq!(
            settle(&mut connection, plan).unwrap(),
            LogicalMutationDisposition::Applied
        );

        // A plan built over a stale predecessor cannot re-apply.
        let mut connection = fixture(1);
        poison_commit_order(&connection, 1);
        let stale = plan_for(&connection, &[1], COMMITTED_AT);
        connection
            .execute(
                "UPDATE media_processing_jobs SET attempt_count=7 WHERE id=1",
                [],
            )
            .unwrap();
        assert_eq!(
            settle(&mut connection, stale).err(),
            Some(WalIdempotencyError::Precondition)
        );
        assert_eq!(job(&connection, 1).0, "pending", "nothing was written");
    }

    #[test]
    fn a_stale_later_member_rolls_back_the_whole_quarantine() {
        let mut connection = fixture(2);
        poison_commit_order(&connection, 1);
        poison_commit_order(&connection, 2);
        let stale = plan_for(&connection, &[1, 2], COMMITTED_AT);
        connection
            .execute(
                "UPDATE capture_events SET context_json='repaired' WHERE event_id='ev-1'",
                [],
            )
            .unwrap();

        assert_eq!(
            settle(&mut connection, stale).err(),
            Some(WalIdempotencyError::Precondition)
        );
        for job_id in [1, 2] {
            let (state, attempts, _, _, media_state) = job(&connection, job_id);
            assert_eq!(state, "pending");
            assert_eq!(attempts, 0);
            assert_eq!(media_state, "queued");
        }
    }

    /// **The amplifier regression, end to end on the claim lane.**
    ///
    /// One job carries #331's exact poison. Before this change the sweep did:
    /// scan -> observe -> `MediaWorkClaimPlan::new` refuses -> `warn!` ->
    /// `ClaimOutcome::Idle` -> `process_user` returns; and because
    /// `enumerate_claimable`'s `pending` arm has no `attempt_count` term and
    /// `plan_first` is pure, the next sweep did exactly the same thing, forever,
    /// with no attempt cap, no terminalization path and no user-visible error.
    ///
    /// Now: the refusal is attributed, the named job is quarantined onto the
    /// bounded ladder, and the very next enumeration plans the REST of the lane.
    ///
    /// Falsifiability, checked by sabotage: making `unplannable_members` return
    /// an empty vector leaves nothing to quarantine and the post-quarantine
    /// `Observed` assertion fails on the identical refusal.
    #[test]
    fn a_deterministically_unplannable_job_no_longer_stops_the_lane() {
        let mut connection = fixture(3);
        let poison = "2026-08-21T23:00:00.000+09:00";
        assert!(
            poison > COMMITTED_AT && crate::cp::isotime::parse_epoch_millis(poison).is_some(),
            "the trigger must string-sort above the commit stamp while parsing fine"
        );
        connection
            .execute(
                "UPDATE media_processing_jobs SET updated_at=?1 WHERE id=2",
                params![poison],
            )
            .unwrap();

        // Sweep 1: the whole lane is refused, and the refusal names job 2.
        let ClaimScan::Observed(observation) = scan_for_claim(
            &connection,
            WorkClass::Screen,
            1,
            AS_OF,
            128,
            RESURRECTION_ATTEMPT_CAP,
        )
        .unwrap() else {
            panic!("the enumeration itself resolves; the refusal is at construction");
        };
        let attributed = unplannable_members(&observation, 1, COMMITTED_AT);
        assert_eq!(
            attributed.iter().map(|row| row.job_id).collect::<Vec<_>>(),
            vec![2]
        );
        assert_eq!(
            MediaWorkClaimPlan::new(
                ACCOUNT.into(),
                *observation,
                1,
                128,
                RESURRECTION_ATTEMPT_CAP,
                300,
                2_048,
                AS_OF.into(),
                COMMITTED_AT.into(),
            )
            .err(),
            Some(WalIdempotencyError::Malformed),
            "the guard is untouched: the unit is still not admitted"
        );
        assert!(
            connection
                .query_row("SELECT COUNT(*) FROM media_work_units", [], |row| row
                    .get::<_, i64>(0))
                .unwrap()
                == 0,
            "no work unit, no reservation, no paid call"
        );

        // The bounded, observable response.
        let members = attributed
            .iter()
            .map(|row| {
                QuarantineMember::from_claimable(
                    row,
                    "gemini_screen",
                    1,
                    RESURRECTION_ATTEMPT_CAP,
                    COMMITTED_AT,
                )
            })
            .collect::<Result<Vec<_>>>()
            .unwrap();
        settle(
            &mut connection,
            MediaClaimQuarantinePlan::new(
                ACCOUNT.into(),
                "gemini_screen".into(),
                1,
                QUARANTINE_ERROR_CODE.into(),
                ATTEMPT_LIMIT,
                RESURRECTION_ATTEMPT_CAP,
                RETRY_BASE_SECONDS,
                AS_OF.into(),
                COMMITTED_AT.into(),
                members,
            )
            .unwrap(),
        )
        .unwrap();

        // Observable: the two facts the existing reads already report.
        let (state, attempts, error_code, _, media_state) = job(&connection, 2);
        assert_eq!(state, "retry_wait");
        assert_eq!(attempts, 1);
        assert_eq!(error_code.as_deref(), Some("claim_unplannable"));
        assert_eq!(
            media_state, "retry_wait",
            "capture status and the session's processing counts read this"
        );

        // Sweep 2: the lane MOVES. The remaining jobs plan and construct.
        let later = "2026-08-21T12:00:02.000Z";
        let ClaimScan::Observed(observation) = scan_for_claim(
            &connection,
            WorkClass::Screen,
            1,
            later,
            128,
            RESURRECTION_ATTEMPT_CAP,
        )
        .unwrap() else {
            panic!("the lane is still wedged: the surviving jobs must be claimable");
        };
        assert_eq!(
            observation
                .member_rows()
                .iter()
                .map(|row| row.job_id)
                .collect::<Vec<_>>(),
            vec![1, 3],
            "the untouched jobs are exactly the ones that proceed"
        );
        assert!(unplannable_members(&observation, 1, later).is_empty());
        assert!(MediaWorkClaimPlan::new(
            ACCOUNT.into(),
            *observation,
            1,
            128,
            RESURRECTION_ATTEMPT_CAP,
            300,
            2_048,
            later.into(),
            later.into(),
        )
        .is_ok());
        let _ = claim::class_name(WorkClass::Screen);
    }

    /// Malformed inputs are refused, and an attributed set is never silently
    /// truncated: a dropped job is a job that stays `pending` and keeps the
    /// lane wedged, which is the failure this whole family exists to end.
    #[test]
    fn construction_refuses_malformed_input_and_never_truncates() {
        let connection = fixture(1);
        poison_commit_order(&connection, 1);
        let member = QuarantineMember::from_claimable(
            &rows(&connection)[0],
            "gemini_screen",
            1,
            RESURRECTION_ATTEMPT_CAP,
            COMMITTED_AT,
        )
        .unwrap();
        let build = |members: Vec<QuarantineMember>, attempt_limit: i64, retry: i64| {
            MediaClaimQuarantinePlan::new(
                ACCOUNT.into(),
                "gemini_screen".into(),
                1,
                QUARANTINE_ERROR_CODE.into(),
                attempt_limit,
                RESURRECTION_ATTEMPT_CAP,
                retry,
                AS_OF.into(),
                COMMITTED_AT.into(),
                members,
            )
        };
        assert_eq!(
            build(Vec::new(), ATTEMPT_LIMIT, RETRY_BASE_SECONDS).err(),
            Some(WalIdempotencyError::Malformed)
        );
        assert_eq!(
            build(vec![member.clone()], 0, RETRY_BASE_SECONDS).err(),
            Some(WalIdempotencyError::Malformed)
        );
        assert_eq!(
            build(vec![member.clone()], ATTEMPT_LIMIT, 0).err(),
            Some(WalIdempotencyError::Malformed)
        );
        // Repeated ids would double-apply one attempt advance.
        assert_eq!(
            build(
                vec![member.clone(), member.clone()],
                ATTEMPT_LIMIT,
                RETRY_BASE_SECONDS
            )
            .err(),
            Some(WalIdempotencyError::Malformed)
        );
        // A job in a state the claim scan can never enumerate is never
        // quarantinable: `succeeded` must be unreachable from here.
        let mut settled = member.clone();
        settled.row.state = "succeeded".into();
        assert_eq!(
            build(vec![settled], ATTEMPT_LIMIT, RETRY_BASE_SECONDS).err(),
            Some(WalIdempotencyError::Malformed)
        );
        let mut oversized = Vec::new();
        for index in 0..=MAX_MEMBERS {
            let mut row = member.clone();
            row.row.job_id = i64::try_from(index).unwrap() + 1;
            oversized.push(row);
        }
        assert_eq!(
            build(oversized, ATTEMPT_LIMIT, RETRY_BASE_SECONDS).err(),
            Some(WalIdempotencyError::Limit)
        );
    }

    #[test]
    fn every_member_shape_the_classifier_names_is_accepted_as_malformed_evidence() {
        let base = rows(&fixture(1))[0].clone();
        for case in [
            "job_id",
            "attempt_count",
            "processor_version",
            "event_id",
            "event_id_length",
            "job_kind",
            "job_kind_length",
            "input_revision",
            "input_revision_length",
            "media_sha256",
            "media_sha256_length",
            "updated_at",
            "updated_at_length",
            "started_at",
            "started_at_length",
            "ended_at",
            "ended_at_length",
            "media_state",
            "media_state_length",
            "job_state",
            "lease_until",
            "error_code",
            "usage_json",
        ] {
            let mut row = base.clone();
            match case {
                "job_id" => row.job_id = 0,
                "attempt_count" => row.attempt_count = -1,
                "processor_version" => row.processor_version = 0,
                "event_id" => row.event_id.clear(),
                "event_id_length" => row.event_id = "x".repeat(129),
                "job_kind" => row.job_kind.clear(),
                "job_kind_length" => row.job_kind = "x".repeat(129),
                "input_revision" => row.input_revision.clear(),
                "input_revision_length" => row.input_revision = "x".repeat(129),
                "media_sha256" => row.media_sha256.clear(),
                "media_sha256_length" => row.media_sha256 = "x".repeat(129),
                "updated_at" => row.updated_at.clear(),
                "updated_at_length" => row.updated_at = "x".repeat(65),
                "started_at" => row.started_at.clear(),
                "started_at_length" => {
                    row.started_at = format!("2026-08-21T11:00:00.{}Z", "0".repeat(65))
                }
                "ended_at" => row.ended_at.clear(),
                "ended_at_length" => {
                    row.ended_at = format!("2026-08-21T11:00:01.{}Z", "0".repeat(65))
                }
                "media_state" => row.media_processing_state.clear(),
                "media_state_length" => row.media_processing_state = "x".repeat(129),
                "job_state" => row.state.clear(),
                "lease_until" => row.lease_until = Some("x".repeat(65)),
                "error_code" => row.error_code = Some("x".repeat(129)),
                "usage_json" => row.usage_json = Some("x".repeat(8 * 1024 + 1)),
                _ => unreachable!(),
            }
            assert!(
                row.refusal_reason(RESURRECTION_ATTEMPT_CAP).is_some(),
                "{case}: the case must remain classified"
            );
            let member = QuarantineMember::from_claimable(
                &row,
                "gemini_screen",
                1,
                RESURRECTION_ATTEMPT_CAP,
                COMMITTED_AT,
            )
            .unwrap_or_else(|error| panic!("{case}: classification failed: {error:?}"));
            MediaClaimQuarantinePlan::new(
                ACCOUNT.into(),
                "gemini_screen".into(),
                1,
                QUARANTINE_ERROR_CODE.into(),
                ATTEMPT_LIMIT,
                RESURRECTION_ATTEMPT_CAP,
                RETRY_BASE_SECONDS,
                AS_OF.into(),
                COMMITTED_AT.into(),
                vec![member],
            )
            .unwrap_or_else(|error| {
                panic!("{case}: quarantine rejected already-classified evidence: {error:?}")
            });
        }
    }

    #[test]
    fn malformed_attempts_terminalize_without_overflow_or_resurrection() {
        for (case, poisoned, expected) in [
            ("negative", -1_i64, RESURRECTION_ATTEMPT_CAP),
            ("at_cap", RESURRECTION_ATTEMPT_CAP, RESURRECTION_ATTEMPT_CAP),
            (
                "above_cap",
                RESURRECTION_ATTEMPT_CAP + 1,
                RESURRECTION_ATTEMPT_CAP + 1,
            ),
            ("oversized", i64::MAX, i64::MAX),
        ] {
            let mut connection = fixture(2);
            connection
                .execute(
                    "UPDATE media_processing_jobs SET attempt_count=?1 WHERE id=1",
                    [poisoned],
                )
                .unwrap();
            let ClaimScan::Unplannable(refused) = scan_for_claim(
                &connection,
                WorkClass::Screen,
                1,
                AS_OF,
                128,
                RESURRECTION_ATTEMPT_CAP,
            )
            .unwrap() else {
                panic!("{case}: the otherwise-valid poison must be named before a claim")
            };
            assert_eq!(
                refused.iter().map(|row| row.job_id).collect::<Vec<_>>(),
                vec![1],
                "{case}: no secondary malformed field may be needed"
            );
            assert_eq!(
                connection
                    .query_row("SELECT COUNT(*) FROM media_work_units", [], |row| row
                        .get::<_, i64>(0))
                    .unwrap(),
                0,
                "{case}: classification is before work-unit creation or payment"
            );
            let plan = plan_for(&connection, &[1], COMMITTED_AT);
            settle(&mut connection, plan)
                .unwrap_or_else(|error| panic!("{case}: settle failed: {error:?}"));
            let (state, attempts, error, _, media_state) = job(&connection, 1);
            assert_eq!(state, "failed_terminal", "{case}");
            assert_eq!(attempts, expected, "{case}");
            assert_eq!(error.as_deref(), Some(QUARANTINE_ERROR_CODE), "{case}");
            assert_eq!(media_state, "failed", "{case}");
            assert!(
                attempts >= RESURRECTION_ATTEMPT_CAP,
                "{case}: corrupt attempts must not re-enter resurrection"
            );
            let storage_type: String = connection
                .query_row(
                    "SELECT typeof(attempt_count) FROM media_processing_jobs WHERE id=1",
                    [],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(storage_type, "integer", "{case}: SQLite type drift");

            let ClaimScan::Observed(healthy) = scan_for_claim(
                &connection,
                WorkClass::Screen,
                1,
                COMMITTED_AT,
                128,
                RESURRECTION_ATTEMPT_CAP,
            )
            .unwrap() else {
                panic!("{case}: the healthy same-class sibling must progress")
            };
            assert_eq!(
                healthy
                    .member_rows()
                    .iter()
                    .map(|row| row.job_id)
                    .collect::<Vec<_>>(),
                vec![2],
                "{case}: the poisoned head must no longer pin the class"
            );
            assert!(
                !crate::cp::media_worker::span_has_recoverable_media(
                    &connection,
                    "2026-08-17T20:53:19.000Z",
                    "2026-08-17T20:53:23.000Z",
                    "2026-08-16T00:00:00.000Z",
                )
                .unwrap(),
                "{case}: the cap-terminal poison must release its cursor span"
            );
        }

        let mut connection = fixture(1);
        connection
            .execute("UPDATE media_processing_jobs SET id=0 WHERE id=1", [])
            .unwrap();
        let plan = plan_for(&connection, &[0], COMMITTED_AT);
        settle(&mut connection, plan).unwrap();
        assert_eq!(job(&connection, 0).0, "retry_wait");
        assert_eq!(job(&connection, 0).1, 1);
    }

    #[test]
    fn exact_unit_attempt_cap_is_attributed_and_terminal_without_integer_promotion() {
        for (case, poisoned) in [
            ("at_cap", RESURRECTION_ATTEMPT_CAP),
            ("oversized", i64::MAX),
        ] {
            let mut connection = fixture(1);
            let ClaimScan::Observed(initial) = scan_for_claim(
                &connection,
                WorkClass::Screen,
                1,
                AS_OF,
                128,
                RESURRECTION_ATTEMPT_CAP,
            )
            .unwrap() else {
                panic!("{case}: expected initial observation")
            };
            let work_unit_id = initial.work_unit_id.clone();
            connection
                .execute(
                    "INSERT INTO media_work_units \
                     (id,work_class,processor_version,state,started_at,ended_at,\
                      reserved_output_tokens,reservation_retained,attempt_count,created_at,updated_at) \
                     VALUES (?1,'screen',1,'processing',?2,?3,2048,0,?4,?5,?5)",
                    params![
                        work_unit_id,
                        isotime::format_epoch_millis(initial.started_ms),
                        isotime::format_epoch_millis(initial.ended_ms),
                        poisoned,
                        "2026-08-21T11:00:00.000Z",
                    ],
                )
                .unwrap();

            let ClaimScan::Observed(observation) = scan_for_claim(
                &connection,
                WorkClass::Screen,
                1,
                AS_OF,
                128,
                RESURRECTION_ATTEMPT_CAP,
            )
            .unwrap() else {
                panic!("{case}: the valid member row must still resolve")
            };
            let refusal = observation
                .attributable_refusal(
                    ACCOUNT,
                    1,
                    128,
                    RESURRECTION_ATTEMPT_CAP,
                    300,
                    2_048,
                    AS_OF,
                    COMMITTED_AT,
                )
                .expect("the exact unit attempt poison must be attributable");
            assert_eq!(
                refusal.kind,
                AttributableClaimRefusalKind::WorkUnitAttemptCount,
                "{case}"
            );
            assert_eq!(
                refusal
                    .rows
                    .iter()
                    .map(|row| row.job_id)
                    .collect::<Vec<_>>(),
                vec![1],
                "{case}: the otherwise-valid member is exact settle evidence"
            );
            assert_eq!(
                MediaWorkClaimPlan::new(
                    ACCOUNT.into(),
                    *observation,
                    1,
                    128,
                    RESURRECTION_ATTEMPT_CAP,
                    300,
                    2_048,
                    AS_OF.into(),
                    COMMITTED_AT.into(),
                )
                .err(),
                Some(WalIdempotencyError::Malformed),
                "{case}: construction must reject before any claim increment"
            );
            assert_eq!(
                connection
                    .query_row("SELECT COUNT(*) FROM media_work_members", [], |row| row
                        .get::<_, i64>(0))
                    .unwrap(),
                0,
                "{case}: no claim topology may be written"
            );

            settle(&mut connection, plan_for_refusal(refusal)).unwrap();
            let (job_state, job_attempts, _, _, media_state) = job(&connection, 1);
            assert_eq!(job_state, "failed_terminal", "{case}");
            assert_eq!(job_attempts, RESURRECTION_ATTEMPT_CAP, "{case}");
            assert_eq!(media_state, "failed", "{case}");
            let (unit_state, unit_attempts, storage_type): (String, i64, String) = connection
                .query_row(
                    "SELECT state,attempt_count,typeof(attempt_count) \
                     FROM media_work_units WHERE id=?1",
                    [work_unit_id],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                )
                .unwrap();
            assert_eq!(unit_state, "failed_terminal", "{case}");
            assert_eq!(unit_attempts, poisoned, "{case}");
            assert_eq!(storage_type, "integer", "{case}: SQLite type drift");
            assert!(
                !crate::cp::media_worker::span_has_recoverable_media(
                    &connection,
                    "2026-08-17T20:53:19.000Z",
                    "2026-08-17T20:53:23.000Z",
                    "2026-08-16T00:00:00.000Z",
                )
                .unwrap(),
                "{case}: unit poison must release the cursor at the carried cap"
            );
        }
    }

    fn attributable_at(
        connection: &Connection,
        claimed_at: &str,
        committed_at: &str,
    ) -> AttributableClaimRefusal {
        let ClaimScan::Observed(observation) = scan_for_claim(
            connection,
            WorkClass::Screen,
            1,
            claimed_at,
            128,
            RESURRECTION_ATTEMPT_CAP,
        )
        .unwrap() else {
            panic!("expected an observed claim")
        };
        observation
            .attributable_refusal(
                ACCOUNT,
                1,
                128,
                RESURRECTION_ATTEMPT_CAP,
                300,
                2_048,
                claimed_at,
                committed_at,
            )
            .expect("the stored refusal must be attributable")
    }

    #[test]
    fn duplicate_event_topology_is_grouped_and_cannot_self_invalidate() {
        let mut connection = fixture(3);
        connection
            .execute(
                "INSERT INTO media_processing_jobs \
                 (event_id,job_kind,input_revision,processor_version,state,updated_at) \
                 VALUES ('ev-0','gemini_screen','duplicate-revision',1,'pending',?1)",
                ["2026-08-21T11:00:00.000Z"],
            )
            .unwrap();

        let first = attributable_at(&connection, AS_OF, COMMITTED_AT);
        assert_eq!(
            first.kind,
            AttributableClaimRefusalKind::DuplicateEventTopology
        );
        assert_eq!(
            first.rows.iter().map(|row| row.job_id).collect::<Vec<_>>(),
            vec![1, 4]
        );
        settle(&mut connection, plan_for_refusal(first)).unwrap();
        assert_eq!(job(&connection, 1).0, "retry_wait");
        assert_eq!(job(&connection, 4).0, "retry_wait");
        assert_eq!(job(&connection, 1).4, "retry_wait");

        let ClaimScan::Observed(healthy) = scan_for_claim(
            &connection,
            WorkClass::Screen,
            1,
            COMMITTED_AT,
            128,
            RESURRECTION_ATTEMPT_CAP,
        )
        .unwrap() else {
            panic!("the rest of the same class must progress")
        };
        assert_eq!(
            healthy
                .member_rows()
                .iter()
                .map(|row| row.job_id)
                .collect::<Vec<_>>(),
            vec![2, 3]
        );

        for (claimed_at, committed_at) in [
            ("2026-08-21T12:01:01.000Z", "2026-08-21T12:01:02.000Z"),
            ("2026-08-21T12:03:02.000Z", "2026-08-21T12:03:03.000Z"),
        ] {
            let refusal = attributable_at(&connection, claimed_at, committed_at);
            settle(&mut connection, plan_for_refusal(refusal)).unwrap();
        }
        for id in [1, 4] {
            assert_eq!(job(&connection, id).0, "failed_terminal");
            assert_eq!(job(&connection, id).1, ATTEMPT_LIMIT);
        }
        assert_eq!(job(&connection, 1).4, "failed");

        let held = crate::cp::media_worker::span_has_recoverable_media(
            &connection,
            "2026-08-17T20:53:19.000Z",
            "2026-08-17T20:53:23.000Z",
            "2026-08-16T00:00:00.000Z",
        )
        .unwrap();
        assert!(
            held,
            "the documented early recovery rounds still hold the cursor"
        );
        connection
            .execute(
                "UPDATE media_processing_jobs SET attempt_count=?1 WHERE event_id='ev-0'",
                [RESURRECTION_ATTEMPT_CAP],
            )
            .unwrap();
        assert!(
            !crate::cp::media_worker::span_has_recoverable_media(
                &connection,
                "2026-08-17T20:53:19.000Z",
                "2026-08-17T20:53:23.000Z",
                "2026-08-16T00:00:00.000Z",
            )
            .unwrap(),
            "the carried cap makes the cursor hold finite"
        );
    }

    #[test]
    fn stored_work_unit_refusals_are_exact_bounded_evidence() {
        for (case, expected) in [
            ("malformed", AttributableClaimRefusalKind::WorkUnitMalformed),
            ("future", AttributableClaimRefusalKind::WorkUnitCommitOrder),
            (
                "derived",
                AttributableClaimRefusalKind::WorkUnitDerivedMismatch,
            ),
        ] {
            let mut connection = fixture(2);
            let ClaimScan::Observed(initial) = scan_for_claim(
                &connection,
                WorkClass::Screen,
                1,
                AS_OF,
                128,
                RESURRECTION_ATTEMPT_CAP,
            )
            .unwrap() else {
                panic!("expected initial observation")
            };
            let work_unit_id = initial.work_unit_id.clone();
            connection
                .execute(
                    "INSERT INTO media_work_units \
                     (id,work_class,processor_version,state,started_at,ended_at,\
                      reserved_output_tokens,reservation_retained,attempt_count,error_code,\
                      usage_json,created_at,updated_at) \
                     VALUES (?1,'screen',1,'processing',?2,?3,?4,0,1,NULL,?5,?6,?7)",
                    params![
                        work_unit_id,
                        "2026-08-21T11:00:00.000Z",
                        "2026-08-21T11:00:02.000Z",
                        if case == "derived" { 1024 } else { 2048 },
                        if case == "malformed" {
                            Some("x".repeat(8 * 1024 + 1))
                        } else {
                            None
                        },
                        "2026-08-21T11:00:00.000Z",
                        if case == "future" {
                            "2026-08-21T23:00:00.000+09:00"
                        } else {
                            "2026-08-21T11:00:00.000Z"
                        },
                    ],
                )
                .unwrap();
            let refusal = attributable_at(&connection, AS_OF, COMMITTED_AT);
            assert_eq!(refusal.kind, expected, "{case}");
            let stale = plan_for_refusal(refusal);

            connection
                .execute(
                    "UPDATE media_work_units SET usage_json=NULL,updated_at=?1,\
                     reserved_output_tokens=2048 WHERE id=?2",
                    params!["2026-08-21T11:00:00.000Z", work_unit_id],
                )
                .unwrap();
            assert_eq!(
                settle(&mut connection, stale).err(),
                Some(WalIdempotencyError::Precondition),
                "{case}: repaired unit evidence must win"
            );
            assert_eq!(job(&connection, 1).0, "pending", "{case}");
        }

        for (case, expected) in [
            ("malformed", AttributableClaimRefusalKind::WorkUnitMalformed),
            ("future", AttributableClaimRefusalKind::WorkUnitCommitOrder),
            (
                "derived",
                AttributableClaimRefusalKind::WorkUnitDerivedMismatch,
            ),
        ] {
            let mut connection = fixture(1);
            let ClaimScan::Observed(initial) = scan_for_claim(
                &connection,
                WorkClass::Screen,
                1,
                AS_OF,
                128,
                RESURRECTION_ATTEMPT_CAP,
            )
            .unwrap() else {
                panic!("expected initial observation")
            };
            let work_unit_id = initial.work_unit_id.clone();
            connection
                .execute(
                    "INSERT INTO media_work_units \
                     (id,work_class,processor_version,state,started_at,ended_at,\
                      reserved_output_tokens,reservation_retained,attempt_count,usage_json,\
                      created_at,updated_at) \
                     VALUES (?1,'screen',1,'processing',?2,?3,?4,0,1,?5,?6,?7)",
                    params![
                        work_unit_id,
                        "2026-08-21T11:00:00.000Z",
                        "2026-08-21T11:00:01.000Z",
                        if case == "derived" { 1024 } else { 2048 },
                        if case == "malformed" {
                            Some("x".repeat(8 * 1024 + 1))
                        } else {
                            None
                        },
                        "2026-08-21T11:00:00.000Z",
                        if case == "future" {
                            "2026-08-21T23:00:00.000+09:00"
                        } else {
                            "2026-08-21T11:00:00.000Z"
                        },
                    ],
                )
                .unwrap();
            let refusal = attributable_at(&connection, AS_OF, COMMITTED_AT);
            assert_eq!(refusal.kind, expected, "{case}");
            settle(&mut connection, plan_for_refusal(refusal)).unwrap();
            assert_eq!(job(&connection, 1).0, "retry_wait", "{case}");
            let (unit_state, unit_error): (String, Option<String>) = connection
                .query_row(
                    "SELECT state,error_code FROM media_work_units WHERE id=?1",
                    [work_unit_id],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .unwrap();
            assert_eq!(unit_state, "retry_wait", "{case}");
            assert_eq!(unit_error.as_deref(), Some(QUARANTINE_ERROR_CODE), "{case}");
        }
    }
}
