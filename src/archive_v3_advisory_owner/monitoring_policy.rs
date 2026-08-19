//! Canonical Phase-1 monitoring/rollback policy byte formats and the
//! automatic stop-condition evaluator for the advisory canary.
//!
//! The signed runtime-admission assertion (`canary_trust.rs`) binds a
//! `monitoring_policy_commitment` and a `rollback_policy_commitment` but did
//! not previously define the bytes those commitments hash. This module fixes
//! them: [`Phase1MonitoringPolicy`] and [`Phase1RollbackPolicy`] each parse
//! exactly one fixed-length, big-endian, format-tagged `v1` layout, reject
//! zero and out-of-range values field by field, encode back byte-exactly, and
//! produce the domain-separated SHA-256 commitment over the exact encoded
//! bytes. Owners, stop commands, and evidence locations appear only as
//! 32-byte commitments; no raw name, command text, or location ever enters
//! this module. [`Phase1StopConditionEvaluator`] is the runbook's automatic
//! stop-condition machine: a pure, deterministic, allocation-free state
//! machine consuming abstract caller-ticked observations (comparison
//! outcomes, advisory errors/successes, latency buckets, resident memory) and
//! deciding STOP. It owns no task, channel, clock, or I/O; callers supply
//! monotonic `u64` ticks.
//!
//! Threshold and stop semantics (tested on both sides of every boundary):
//! - Every `max_*` bound is the maximum allowed value: a running value that
//!   strictly exceeds its bound (`>`) latches a permanent stop; a value
//!   exactly at the bound continues. `max_comparison_mismatches` is
//!   hard-required to be zero at parse: the Phase-1 advisory comparison must
//!   agree exactly with the pinned legacy result, so the first mismatch stops
//!   the canary for manual investigation. The field stays explicit in the
//!   wire format so the signed, hash-committed policy states the
//!   zero-tolerance bound rather than implying it; any different tolerance
//!   requires a new reviewed format version.
//! - `now_ticks - start_ticks >= observation_window_ticks` (`>=`, a duration,
//!   not a maximum) yields [`StopReason::ObservationWindowElapsed`]: the
//!   SUCCESSFUL scheduled end of the observation window, represented as a
//!   stop so the controller halts deterministically. The controller
//!   distinguishes this reason as scheduled completion, not failure.
//! - Missing telemetry is a stop signal: a gap strictly longer than
//!   `telemetry_freshness_limit_ticks` since the last accepted observation
//!   (the constructor seeds the anchor with `start_ticks`) yields
//!   [`StopReason::TelemetryStale`]. A `now_ticks` lower than the last
//!   accepted observation tick also latches [`StopReason::TelemetryStale`]:
//!   non-monotonic time means the telemetry stream's clock cannot be trusted,
//!   and clock inconsistency is itself a stop condition.
//! - Stops are sticky and the earliest condition in tick-time wins: once a
//!   reason latches, every later observation is dropped and `verdict` reports
//!   that first reason forever. When staleness and window elapse are due
//!   simultaneously, the conservative [`StopReason::TelemetryStale`] wins,
//!   because a window whose final stretch was unobserved cannot be claimed
//!   complete. When one advisory error exceeds both error bounds at once,
//!   [`StopReason::ConsecutiveAdvisoryErrors`] wins (checked first).
//! - `verdict` is a pure function of the evaluator state and the supplied
//!   tick and cannot latch through `&self`; it reports time-derived stops
//!   (staleness, window elapse, regressed tick) computed at the supplied
//!   tick, and any subsequent `&mut` observation latches them permanently.
//!
//! This module defines only the canonical policy bytes and the automatic
//! evaluator. DEPLOYING alerts/monitoring and naming the on-call and rollback
//! owners are operator work (C6), and no production caller exists in this
//! slice: nothing outside tests constructs these policies or the evaluator,
//! and the pinned admission roots remain deliberately invalid.

use sha2::{Digest, Sha256};

use super::{telemetry::DurationBucket, AdvisoryOwnerError, Result};

const PHASE1_MONITORING_POLICY_DOMAIN: &[u8] = b"kioku/archive-v3/phase1-monitoring-policy/v1\0";
const PHASE1_ROLLBACK_POLICY_DOMAIN: &[u8] = b"kioku/archive-v3/phase1-rollback-policy/v1\0";

const PHASE1_MONITORING_POLICY_FORMAT_V1: u16 = 1;
const PHASE1_ROLLBACK_POLICY_FORMAT_V1: u16 = 1;

const PHASE1_MONITORING_POLICY_BYTES: usize = 2 + 32 + 8 + 4 + 4 + 4 + 1 + 4 + 8;
const PHASE1_ROLLBACK_POLICY_BYTES: usize = 2 + 32 + 32 + 32 + 8 + 8;

/// Phase-1 allows zero comparison mismatches: the advisory result must agree
/// byte-for-byte with the pinned legacy result, so the only safe bound is 0
/// and parse rejects any other value. The field remains explicit in the wire
/// format so the signed policy commits to the zero-tolerance bound.
const REQUIRED_MAX_COMPARISON_MISMATCHES: u32 = 0;
const MIN_CONSECUTIVE_ADVISORY_ERRORS: u32 = 1;
const MAX_CONSECUTIVE_ADVISORY_ERRORS: u32 = 1_000;
const MAX_ADVISORY_ERROR_TOTAL_BOUND: u32 = 100_000;
/// Resident-memory bounds in MiB. The controller's fixed `Phase1TmpfsPolicyV1`
/// preflight already caps the canary under the 4-GiB tmpfs, so a valid policy
/// bound must leave headroom below it: at most 3584 MiB (3.5 GiB), and at
/// least 64 MiB so a nonsensical near-zero bound cannot be committed.
const MIN_RESIDENT_MEMORY_MIB: u32 = 64;
const MAX_RESIDENT_MEMORY_MIB: u32 = 3_584;

/// Highest valid [`DurationBucket`] wire ordinal (`Over30S`).
const MAX_DURATION_BUCKET_ORDINAL: u8 = 8;

/// Canonical wire ordinal of a [`DurationBucket`]. The match is exhaustive so
/// a new telemetry bucket variant fails compilation here instead of silently
/// widening the policy format.
const fn duration_bucket_ordinal(bucket: DurationBucket) -> u8 {
    match bucket {
        DurationBucket::Under10Ms => 0,
        DurationBucket::Under50Ms => 1,
        DurationBucket::Under100Ms => 2,
        DurationBucket::Under500Ms => 3,
        DurationBucket::Under1S => 4,
        DurationBucket::Under5S => 5,
        DurationBucket::Under10S => 6,
        DurationBucket::Under30S => 7,
        DurationBucket::Over30S => 8,
    }
}

fn duration_bucket_from_ordinal(ordinal: u8) -> Result<DurationBucket> {
    match ordinal {
        0 => Ok(DurationBucket::Under10Ms),
        1 => Ok(DurationBucket::Under50Ms),
        2 => Ok(DurationBucket::Under100Ms),
        3 => Ok(DurationBucket::Under500Ms),
        4 => Ok(DurationBucket::Under1S),
        5 => Ok(DurationBucket::Under5S),
        6 => Ok(DurationBucket::Under10S),
        7 => Ok(DurationBucket::Under30S),
        8 => Ok(DurationBucket::Over30S),
        _ => Err(AdvisoryOwnerError::Corrupt),
    }
}

fn fixed<const N: usize>(value: &[u8]) -> Result<[u8; N]> {
    value.try_into().map_err(|_| AdvisoryOwnerError::Corrupt)
}

/// Parsed canonical Phase-1 monitoring policy. Every instance came from (or
/// round-trips to) exactly one valid `v1` byte encoding, and
/// [`Phase1MonitoringPolicy::commitment`] hashes exactly those bytes under
/// the policy domain, so equal commitments imply equal policies.
#[derive(Clone, PartialEq, Eq)]
pub(super) struct Phase1MonitoringPolicy {
    /// Commitment to the named on-call owner; never a raw name.
    on_call_owner_commitment: [u8; 32],
    /// Maximum allowed ticks between accepted telemetry observations.
    telemetry_freshness_limit_ticks: u64,
    /// Hard-required to be [`REQUIRED_MAX_COMPARISON_MISMATCHES`] (zero).
    max_comparison_mismatches: u32,
    /// Maximum allowed consecutive advisory errors (1..=1000).
    max_consecutive_advisory_errors: u32,
    /// Maximum allowed total advisory errors (>= consecutive bound,
    /// <= 100_000).
    max_advisory_error_total: u32,
    /// Slowest allowed latency bucket, stored as the telemetry enum.
    max_latency_bucket: DurationBucket,
    /// Maximum allowed resident memory in MiB (64..=3584 under the 4-GiB
    /// tmpfs policy).
    max_resident_memory_mib: u32,
    /// Length of the observation window in ticks (nonzero).
    observation_window_ticks: u64,
}

impl Phase1MonitoringPolicy {
    /// Parse the exact `v1` monitoring-policy bytes, rejecting any length,
    /// format-tag, zero-value, or range violation as content-free `Corrupt`.
    pub(super) fn parse(bytes: &[u8]) -> Result<Self> {
        let bytes: &[u8; PHASE1_MONITORING_POLICY_BYTES] =
            bytes.try_into().map_err(|_| AdvisoryOwnerError::Corrupt)?;
        if u16::from_be_bytes([bytes[0], bytes[1]]) != PHASE1_MONITORING_POLICY_FORMAT_V1 {
            return Err(AdvisoryOwnerError::Corrupt);
        }
        let on_call_owner_commitment = fixed::<32>(&bytes[2..34])?;
        let telemetry_freshness_limit_ticks = u64::from_be_bytes(fixed::<8>(&bytes[34..42])?);
        let max_comparison_mismatches = u32::from_be_bytes(fixed::<4>(&bytes[42..46])?);
        let max_consecutive_advisory_errors = u32::from_be_bytes(fixed::<4>(&bytes[46..50])?);
        let max_advisory_error_total = u32::from_be_bytes(fixed::<4>(&bytes[50..54])?);
        let max_latency_bucket = duration_bucket_from_ordinal(bytes[54])?;
        let max_resident_memory_mib = u32::from_be_bytes(fixed::<4>(&bytes[55..59])?);
        let observation_window_ticks = u64::from_be_bytes(fixed::<8>(&bytes[59..67])?);
        if on_call_owner_commitment == [0; 32]
            || telemetry_freshness_limit_ticks == 0
            || max_comparison_mismatches != REQUIRED_MAX_COMPARISON_MISMATCHES
            || !(MIN_CONSECUTIVE_ADVISORY_ERRORS..=MAX_CONSECUTIVE_ADVISORY_ERRORS)
                .contains(&max_consecutive_advisory_errors)
            || !(max_consecutive_advisory_errors..=MAX_ADVISORY_ERROR_TOTAL_BOUND)
                .contains(&max_advisory_error_total)
            || !(MIN_RESIDENT_MEMORY_MIB..=MAX_RESIDENT_MEMORY_MIB)
                .contains(&max_resident_memory_mib)
            || observation_window_ticks == 0
        {
            return Err(AdvisoryOwnerError::Corrupt);
        }
        Ok(Self {
            on_call_owner_commitment,
            telemetry_freshness_limit_ticks,
            max_comparison_mismatches,
            max_consecutive_advisory_errors,
            max_advisory_error_total,
            max_latency_bucket,
            max_resident_memory_mib,
            observation_window_ticks,
        })
    }

    /// Encode back to the exact canonical bytes `parse` accepted.
    pub(super) fn encode(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(PHASE1_MONITORING_POLICY_BYTES);
        bytes.extend_from_slice(&PHASE1_MONITORING_POLICY_FORMAT_V1.to_be_bytes());
        bytes.extend_from_slice(&self.on_call_owner_commitment);
        bytes.extend_from_slice(&self.telemetry_freshness_limit_ticks.to_be_bytes());
        bytes.extend_from_slice(&self.max_comparison_mismatches.to_be_bytes());
        bytes.extend_from_slice(&self.max_consecutive_advisory_errors.to_be_bytes());
        bytes.extend_from_slice(&self.max_advisory_error_total.to_be_bytes());
        bytes.push(duration_bucket_ordinal(self.max_latency_bucket));
        bytes.extend_from_slice(&self.max_resident_memory_mib.to_be_bytes());
        bytes.extend_from_slice(&self.observation_window_ticks.to_be_bytes());
        bytes
    }

    /// Domain-separated SHA-256 commitment over the exact encoded bytes; the
    /// value the runtime admission binds as `monitoring_policy_commitment`.
    pub(super) fn commitment(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(PHASE1_MONITORING_POLICY_DOMAIN);
        hasher.update(self.encode());
        hasher.finalize().into()
    }
}

impl std::fmt::Debug for Phase1MonitoringPolicy {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("Phase1MonitoringPolicy(<opaque>)")
    }
}

/// Parsed canonical Phase-1 rollback policy: content-free commitments to the
/// rollback owner, the exact documented stop command, and the evidence
/// location, plus the rollback window and the maximum allowed stop latency
/// inside it.
#[derive(Clone, PartialEq, Eq)]
pub(super) struct Phase1RollbackPolicy {
    /// Commitment to the named rollback owner; never a raw name.
    rollback_owner_commitment: [u8; 32],
    /// Commitment to the exact documented stop command.
    stop_command_commitment: [u8; 32],
    /// Commitment to the evidence location.
    evidence_location_commitment: [u8; 32],
    /// Length of the rollback window in ticks (nonzero).
    rollback_window_ticks: u64,
    /// Maximum allowed ticks from stop decision to executed stop (nonzero,
    /// <= `rollback_window_ticks`).
    max_stop_latency_ticks: u64,
}

impl Phase1RollbackPolicy {
    /// Parse the exact `v1` rollback-policy bytes, rejecting any length,
    /// format-tag, zero-value, or range violation as content-free `Corrupt`.
    pub(super) fn parse(bytes: &[u8]) -> Result<Self> {
        let bytes: &[u8; PHASE1_ROLLBACK_POLICY_BYTES] =
            bytes.try_into().map_err(|_| AdvisoryOwnerError::Corrupt)?;
        if u16::from_be_bytes([bytes[0], bytes[1]]) != PHASE1_ROLLBACK_POLICY_FORMAT_V1 {
            return Err(AdvisoryOwnerError::Corrupt);
        }
        let rollback_owner_commitment = fixed::<32>(&bytes[2..34])?;
        let stop_command_commitment = fixed::<32>(&bytes[34..66])?;
        let evidence_location_commitment = fixed::<32>(&bytes[66..98])?;
        let rollback_window_ticks = u64::from_be_bytes(fixed::<8>(&bytes[98..106])?);
        let max_stop_latency_ticks = u64::from_be_bytes(fixed::<8>(&bytes[106..114])?);
        if rollback_owner_commitment == [0; 32]
            || stop_command_commitment == [0; 32]
            || evidence_location_commitment == [0; 32]
            || rollback_window_ticks == 0
            || !(1..=rollback_window_ticks).contains(&max_stop_latency_ticks)
        {
            return Err(AdvisoryOwnerError::Corrupt);
        }
        Ok(Self {
            rollback_owner_commitment,
            stop_command_commitment,
            evidence_location_commitment,
            rollback_window_ticks,
            max_stop_latency_ticks,
        })
    }

    /// Encode back to the exact canonical bytes `parse` accepted.
    pub(super) fn encode(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(PHASE1_ROLLBACK_POLICY_BYTES);
        bytes.extend_from_slice(&PHASE1_ROLLBACK_POLICY_FORMAT_V1.to_be_bytes());
        bytes.extend_from_slice(&self.rollback_owner_commitment);
        bytes.extend_from_slice(&self.stop_command_commitment);
        bytes.extend_from_slice(&self.evidence_location_commitment);
        bytes.extend_from_slice(&self.rollback_window_ticks.to_be_bytes());
        bytes.extend_from_slice(&self.max_stop_latency_ticks.to_be_bytes());
        bytes
    }

    /// Domain-separated SHA-256 commitment over the exact encoded bytes; the
    /// value the runtime admission binds as `rollback_policy_commitment`.
    pub(super) fn commitment(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(PHASE1_ROLLBACK_POLICY_DOMAIN);
        hasher.update(self.encode());
        hasher.finalize().into()
    }
}

impl std::fmt::Debug for Phase1RollbackPolicy {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("Phase1RollbackPolicy(<opaque>)")
    }
}

/// Content-free reason the evaluator decided STOP. Exactly one latches, and
/// it is permanent.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum StopReason {
    /// A comparison observation did not match (zero mismatches are allowed).
    ComparisonMismatch,
    /// Consecutive advisory errors strictly exceeded the policy bound.
    ConsecutiveAdvisoryErrors,
    /// Total advisory errors strictly exceeded the policy bound.
    AdvisoryErrorTotal,
    /// A latency observation landed in a bucket slower than the policy bound.
    LatencyExceeded,
    /// A resident-memory observation strictly exceeded the policy bound.
    ResidentMemoryExceeded,
    /// The telemetry gap strictly exceeded the freshness limit, or a
    /// non-monotonic tick showed the telemetry clock cannot be trusted.
    TelemetryStale,
    /// The observation window fully elapsed: the SUCCESSFUL scheduled end of
    /// the canary observation period, not a failure. The controller
    /// distinguishes this reason as scheduled completion.
    ObservationWindowElapsed,
}

/// The evaluator's decision at a supplied tick.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum StopVerdict {
    Continue,
    Stop(StopReason),
}

/// Pure-state automatic stop-condition evaluator for one Phase-1 advisory
/// canary run. It holds only fixed-size counters and ticks (allocation-free
/// in steady state), owns no task, channel, clock, or I/O, and is fully
/// deterministic: the same observation sequence always yields the same
/// verdicts. The first threshold crossed in tick-time latches permanently;
/// see the module docs for the exact boundary semantics.
pub(super) struct Phase1StopConditionEvaluator {
    policy: Phase1MonitoringPolicy,
    start_ticks: u64,
    /// Tick of the most recent accepted observation; seeded with
    /// `start_ticks` so freshness is enforced from the start of the window
    /// and any observation before it is non-monotonic.
    last_observation_ticks: u64,
    comparison_mismatches: u32,
    consecutive_advisory_errors: u32,
    total_advisory_errors: u32,
    latched: Option<StopReason>,
}

impl Phase1StopConditionEvaluator {
    pub(super) fn new(policy: Phase1MonitoringPolicy, start_ticks: u64) -> Self {
        Self {
            policy,
            start_ticks,
            last_observation_ticks: start_ticks,
            comparison_mismatches: 0,
            consecutive_advisory_errors: 0,
            total_advisory_errors: 0,
            latched: None,
        }
    }

    /// Record one advisory-versus-legacy comparison outcome. Any mismatch
    /// beyond the policy's (required-zero) bound latches
    /// [`StopReason::ComparisonMismatch`].
    pub(super) fn observe_comparison(&mut self, now_ticks: u64, matched: bool) {
        if !self.admit_observation(now_ticks) || matched {
            return;
        }
        self.comparison_mismatches = self.comparison_mismatches.saturating_add(1);
        if self.comparison_mismatches > self.policy.max_comparison_mismatches {
            self.latched = Some(StopReason::ComparisonMismatch);
        }
    }

    /// Record one advisory error. The consecutive bound is checked before
    /// the total bound, so when a single error exceeds both,
    /// [`StopReason::ConsecutiveAdvisoryErrors`] latches.
    pub(super) fn observe_advisory_error(&mut self, now_ticks: u64) {
        if !self.admit_observation(now_ticks) {
            return;
        }
        self.consecutive_advisory_errors = self.consecutive_advisory_errors.saturating_add(1);
        self.total_advisory_errors = self.total_advisory_errors.saturating_add(1);
        if self.consecutive_advisory_errors > self.policy.max_consecutive_advisory_errors {
            self.latched = Some(StopReason::ConsecutiveAdvisoryErrors);
        } else if self.total_advisory_errors > self.policy.max_advisory_error_total {
            self.latched = Some(StopReason::AdvisoryErrorTotal);
        }
    }

    /// Record one advisory success, resetting the consecutive-error counter.
    /// The total-error counter is never reset.
    pub(super) fn observe_advisory_success(&mut self, now_ticks: u64) {
        if !self.admit_observation(now_ticks) {
            return;
        }
        self.consecutive_advisory_errors = 0;
    }

    /// Record one latency observation. A bucket strictly slower than the
    /// policy's `max_latency_bucket` latches [`StopReason::LatencyExceeded`].
    pub(super) fn observe_latency(&mut self, now_ticks: u64, bucket: DurationBucket) {
        if !self.admit_observation(now_ticks) {
            return;
        }
        if duration_bucket_ordinal(bucket) > duration_bucket_ordinal(self.policy.max_latency_bucket)
        {
            self.latched = Some(StopReason::LatencyExceeded);
        }
    }

    /// Record one resident-memory observation in MiB. A value strictly above
    /// the policy bound latches [`StopReason::ResidentMemoryExceeded`].
    pub(super) fn observe_resident_memory(&mut self, now_ticks: u64, mib: u32) {
        if !self.admit_observation(now_ticks) {
            return;
        }
        if mib > self.policy.max_resident_memory_mib {
            self.latched = Some(StopReason::ResidentMemoryExceeded);
        }
    }

    /// The decision at `now_ticks`: the first latched reason if any,
    /// otherwise the time-derived condition due at this tick (regressed tick,
    /// staleness, or window elapse), otherwise `Continue`. Pure: it never
    /// mutates state, so time-derived stops it reports latch only when a
    /// subsequent `&mut` observation arrives.
    pub(super) fn verdict(&self, now_ticks: u64) -> StopVerdict {
        if let Some(reason) = self.latched {
            return StopVerdict::Stop(reason);
        }
        if now_ticks < self.last_observation_ticks {
            return StopVerdict::Stop(StopReason::TelemetryStale);
        }
        match self.due_time_trigger(now_ticks) {
            Some(reason) => StopVerdict::Stop(reason),
            None => StopVerdict::Continue,
        }
    }

    /// Gate every observation: drop it once latched (stickiness), latch
    /// [`StopReason::TelemetryStale`] on a regressed tick, latch whichever
    /// time-derived condition became due first before this observation's
    /// content is even considered, and otherwise advance the freshness
    /// anchor and admit the content.
    fn admit_observation(&mut self, now_ticks: u64) -> bool {
        if self.latched.is_some() {
            return false;
        }
        if now_ticks < self.last_observation_ticks {
            self.latched = Some(StopReason::TelemetryStale);
            return false;
        }
        if let Some(reason) = self.due_time_trigger(now_ticks) {
            self.latched = Some(reason);
            return false;
        }
        self.last_observation_ticks = now_ticks;
        true
    }

    /// The time-derived condition due at `now_ticks`, if any: staleness
    /// becomes due one tick after the freshness limit is exhausted, window
    /// elapse exactly at `start + window`. The condition with the earlier due
    /// tick wins; a tie prefers the conservative `TelemetryStale`, because a
    /// window whose final stretch was unobserved cannot be claimed complete.
    /// A `checked_add` overflow means the condition is never due.
    fn due_time_trigger(&self, now_ticks: u64) -> Option<StopReason> {
        let stale_due_at = self
            .last_observation_ticks
            .checked_add(self.policy.telemetry_freshness_limit_ticks)
            .and_then(|tick| tick.checked_add(1))
            .filter(|due| *due <= now_ticks);
        let elapsed_due_at = self
            .start_ticks
            .checked_add(self.policy.observation_window_ticks)
            .filter(|due| *due <= now_ticks);
        match (stale_due_at, elapsed_due_at) {
            (Some(stale), Some(elapsed)) if elapsed < stale => {
                Some(StopReason::ObservationWindowElapsed)
            }
            (Some(_), _) => Some(StopReason::TelemetryStale),
            (None, Some(_)) => Some(StopReason::ObservationWindowElapsed),
            (None, None) => None,
        }
    }
}

impl std::fmt::Debug for Phase1StopConditionEvaluator {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("Phase1StopConditionEvaluator(<opaque>)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MonitoringPolicyFields {
        owner: [u8; 32],
        freshness: u64,
        mismatches: u32,
        consecutive: u32,
        total: u32,
        bucket: u8,
        memory_mib: u32,
        window: u64,
    }

    fn canonical_monitoring_fields() -> MonitoringPolicyFields {
        MonitoringPolicyFields {
            owner: [0x51; 32],
            freshness: 60,
            mismatches: 0,
            consecutive: 3,
            total: 20,
            bucket: 5,
            memory_mib: 512,
            window: 600,
        }
    }

    fn encode_monitoring_fields(fields: &MonitoringPolicyFields) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(PHASE1_MONITORING_POLICY_BYTES);
        bytes.extend_from_slice(&PHASE1_MONITORING_POLICY_FORMAT_V1.to_be_bytes());
        bytes.extend_from_slice(&fields.owner);
        bytes.extend_from_slice(&fields.freshness.to_be_bytes());
        bytes.extend_from_slice(&fields.mismatches.to_be_bytes());
        bytes.extend_from_slice(&fields.consecutive.to_be_bytes());
        bytes.extend_from_slice(&fields.total.to_be_bytes());
        bytes.push(fields.bucket);
        bytes.extend_from_slice(&fields.memory_mib.to_be_bytes());
        bytes.extend_from_slice(&fields.window.to_be_bytes());
        assert_eq!(bytes.len(), PHASE1_MONITORING_POLICY_BYTES);
        bytes
    }

    fn assert_monitoring_rejects(mutate: impl FnOnce(&mut MonitoringPolicyFields)) {
        let mut fields = canonical_monitoring_fields();
        mutate(&mut fields);
        assert_eq!(
            Phase1MonitoringPolicy::parse(&encode_monitoring_fields(&fields)),
            Err(AdvisoryOwnerError::Corrupt)
        );
    }

    fn assert_monitoring_accepts(mutate: impl FnOnce(&mut MonitoringPolicyFields)) {
        let mut fields = canonical_monitoring_fields();
        mutate(&mut fields);
        Phase1MonitoringPolicy::parse(&encode_monitoring_fields(&fields)).unwrap();
    }

    struct RollbackPolicyFields {
        owner: [u8; 32],
        stop_command: [u8; 32],
        evidence_location: [u8; 32],
        window: u64,
        stop_latency: u64,
    }

    fn canonical_rollback_fields() -> RollbackPolicyFields {
        RollbackPolicyFields {
            owner: [0x61; 32],
            stop_command: [0x62; 32],
            evidence_location: [0x63; 32],
            window: 900,
            stop_latency: 120,
        }
    }

    fn encode_rollback_fields(fields: &RollbackPolicyFields) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(PHASE1_ROLLBACK_POLICY_BYTES);
        bytes.extend_from_slice(&PHASE1_ROLLBACK_POLICY_FORMAT_V1.to_be_bytes());
        bytes.extend_from_slice(&fields.owner);
        bytes.extend_from_slice(&fields.stop_command);
        bytes.extend_from_slice(&fields.evidence_location);
        bytes.extend_from_slice(&fields.window.to_be_bytes());
        bytes.extend_from_slice(&fields.stop_latency.to_be_bytes());
        assert_eq!(bytes.len(), PHASE1_ROLLBACK_POLICY_BYTES);
        bytes
    }

    fn assert_rollback_rejects(mutate: impl FnOnce(&mut RollbackPolicyFields)) {
        let mut fields = canonical_rollback_fields();
        mutate(&mut fields);
        assert_eq!(
            Phase1RollbackPolicy::parse(&encode_rollback_fields(&fields)),
            Err(AdvisoryOwnerError::Corrupt)
        );
    }

    fn assert_rollback_accepts(mutate: impl FnOnce(&mut RollbackPolicyFields)) {
        let mut fields = canonical_rollback_fields();
        mutate(&mut fields);
        Phase1RollbackPolicy::parse(&encode_rollback_fields(&fields)).unwrap();
    }

    const START: u64 = 100;

    /// freshness 50, zero mismatches, 2 consecutive / 4 total errors,
    /// Under5S latency, 512 MiB, 1000-tick window.
    fn evaluator_policy() -> Phase1MonitoringPolicy {
        let fields = MonitoringPolicyFields {
            owner: [0x51; 32],
            freshness: 50,
            mismatches: 0,
            consecutive: 2,
            total: 4,
            bucket: 5,
            memory_mib: 512,
            window: 1_000,
        };
        Phase1MonitoringPolicy::parse(&encode_monitoring_fields(&fields)).unwrap()
    }

    fn evaluator() -> Phase1StopConditionEvaluator {
        Phase1StopConditionEvaluator::new(evaluator_policy(), START)
    }

    #[test]
    fn monitoring_policy_round_trips_byte_exactly() {
        let bytes = encode_monitoring_fields(&canonical_monitoring_fields());
        let policy = Phase1MonitoringPolicy::parse(&bytes).unwrap();
        assert_eq!(policy.encode(), bytes);
        let reparsed = Phase1MonitoringPolicy::parse(&policy.encode()).unwrap();
        assert_eq!(reparsed, policy);
        assert_eq!(policy.max_latency_bucket, DurationBucket::Under5S);
    }

    #[test]
    fn monitoring_policy_rejects_malformed_and_out_of_range_fields() {
        let canonical = encode_monitoring_fields(&canonical_monitoring_fields());
        // Exact-length violations.
        assert!(Phase1MonitoringPolicy::parse(&[]).is_err());
        assert!(Phase1MonitoringPolicy::parse(&canonical[..canonical.len() - 1]).is_err());
        let mut long = canonical.clone();
        long.push(0);
        assert!(Phase1MonitoringPolicy::parse(&long).is_err());
        // Wrong format tag.
        let mut wrong_tag = canonical;
        wrong_tag[0..2].copy_from_slice(&2_u16.to_be_bytes());
        assert!(Phase1MonitoringPolicy::parse(&wrong_tag).is_err());
        // Zero / out-of-range fields, with the accepted side of each boundary.
        assert_monitoring_rejects(|fields| fields.owner = [0; 32]);
        assert_monitoring_rejects(|fields| fields.freshness = 0);
        assert_monitoring_accepts(|fields| fields.freshness = 1);
        assert_monitoring_rejects(|fields| fields.consecutive = 0);
        assert_monitoring_accepts(|fields| fields.consecutive = 1);
        assert_monitoring_accepts(|fields| {
            fields.consecutive = 1_000;
            fields.total = 1_000;
        });
        assert_monitoring_rejects(|fields| {
            fields.consecutive = 1_001;
            fields.total = 1_001;
        });
        assert_monitoring_rejects(|fields| fields.total = 2);
        assert_monitoring_accepts(|fields| fields.total = 3);
        assert_monitoring_accepts(|fields| fields.total = 100_000);
        assert_monitoring_rejects(|fields| fields.total = 100_001);
        assert_monitoring_accepts(|fields| fields.bucket = 0);
        assert_monitoring_accepts(|fields| fields.bucket = 8);
        assert_monitoring_rejects(|fields| fields.bucket = 9);
        assert_monitoring_rejects(|fields| fields.bucket = 0xFF);
        assert_monitoring_rejects(|fields| fields.memory_mib = 63);
        assert_monitoring_accepts(|fields| fields.memory_mib = 64);
        assert_monitoring_accepts(|fields| fields.memory_mib = 3_584);
        assert_monitoring_rejects(|fields| fields.memory_mib = 3_585);
        assert_monitoring_rejects(|fields| fields.window = 0);
        assert_monitoring_accepts(|fields| fields.window = 1);
    }

    #[test]
    fn monitoring_policy_requires_zero_comparison_mismatches() {
        // Zero mismatches is the only safe Phase-1 value: the advisory
        // comparison must agree exactly, and the explicit wire field commits
        // the signed policy to that bound.
        assert_monitoring_accepts(|fields| fields.mismatches = 0);
        assert_monitoring_rejects(|fields| fields.mismatches = 1);
        assert_monitoring_rejects(|fields| fields.mismatches = u32::MAX);
    }

    #[test]
    fn monitoring_policy_commitment_is_deterministic_and_byte_sensitive() {
        let bytes = encode_monitoring_fields(&canonical_monitoring_fields());
        let base = Phase1MonitoringPolicy::parse(&bytes).unwrap().commitment();
        assert_eq!(
            base,
            Phase1MonitoringPolicy::parse(&bytes).unwrap().commitment()
        );
        let mut parsed_variants = 0;
        for (index, _) in bytes.iter().enumerate() {
            let mut changed = bytes.clone();
            changed[index] ^= 0x01;
            if let Ok(policy) = Phase1MonitoringPolicy::parse(&changed) {
                assert_eq!(policy.encode(), changed);
                assert_ne!(policy.commitment(), base);
                parsed_variants += 1;
            }
        }
        assert!(parsed_variants > 0);
    }

    #[test]
    fn rollback_policy_round_trips_byte_exactly() {
        let bytes = encode_rollback_fields(&canonical_rollback_fields());
        let policy = Phase1RollbackPolicy::parse(&bytes).unwrap();
        assert_eq!(policy.encode(), bytes);
        let reparsed = Phase1RollbackPolicy::parse(&policy.encode()).unwrap();
        assert_eq!(reparsed, policy);
    }

    #[test]
    fn rollback_policy_rejects_malformed_and_out_of_range_fields() {
        let canonical = encode_rollback_fields(&canonical_rollback_fields());
        assert!(Phase1RollbackPolicy::parse(&[]).is_err());
        assert!(Phase1RollbackPolicy::parse(&canonical[..canonical.len() - 1]).is_err());
        let mut long = canonical.clone();
        long.push(0);
        assert!(Phase1RollbackPolicy::parse(&long).is_err());
        let mut wrong_tag = canonical;
        wrong_tag[0..2].copy_from_slice(&2_u16.to_be_bytes());
        assert!(Phase1RollbackPolicy::parse(&wrong_tag).is_err());
        assert_rollback_rejects(|fields| fields.owner = [0; 32]);
        assert_rollback_rejects(|fields| fields.stop_command = [0; 32]);
        assert_rollback_rejects(|fields| fields.evidence_location = [0; 32]);
        assert_rollback_rejects(|fields| fields.window = 0);
        assert_rollback_rejects(|fields| fields.stop_latency = 0);
        assert_rollback_accepts(|fields| fields.stop_latency = 1);
        // Stop latency exactly at the window is allowed; beyond it is not.
        assert_rollback_accepts(|fields| fields.stop_latency = fields.window);
        assert_rollback_rejects(|fields| fields.stop_latency = fields.window + 1);
    }

    #[test]
    fn rollback_policy_commitment_is_deterministic_and_byte_sensitive() {
        let bytes = encode_rollback_fields(&canonical_rollback_fields());
        let base = Phase1RollbackPolicy::parse(&bytes).unwrap().commitment();
        assert_eq!(
            base,
            Phase1RollbackPolicy::parse(&bytes).unwrap().commitment()
        );
        let mut parsed_variants = 0;
        for (index, _) in bytes.iter().enumerate() {
            let mut changed = bytes.clone();
            changed[index] ^= 0x01;
            if let Ok(policy) = Phase1RollbackPolicy::parse(&changed) {
                assert_eq!(policy.encode(), changed);
                assert_ne!(policy.commitment(), base);
                parsed_variants += 1;
            }
        }
        assert!(parsed_variants > 0);
    }

    #[test]
    fn evaluator_continues_at_every_exact_threshold() {
        let mut evaluator = evaluator();
        evaluator.observe_comparison(110, true);
        // Exactly max consecutive errors (2) continues.
        evaluator.observe_advisory_error(120);
        evaluator.observe_advisory_error(121);
        assert_eq!(evaluator.verdict(121), StopVerdict::Continue);
        evaluator.observe_advisory_success(122);
        // Exactly max total errors (4) continues.
        evaluator.observe_advisory_error(123);
        evaluator.observe_advisory_error(124);
        assert_eq!(evaluator.verdict(124), StopVerdict::Continue);
        evaluator.observe_advisory_success(125);
        // Exactly the max latency bucket continues.
        evaluator.observe_latency(130, DurationBucket::Under5S);
        evaluator.observe_latency(131, DurationBucket::Under10Ms);
        // Exactly the max resident memory continues.
        evaluator.observe_resident_memory(140, 512);
        // A telemetry gap exactly at the freshness limit continues.
        assert_eq!(evaluator.verdict(190), StopVerdict::Continue);
        // An observation arriving exactly at the freshness limit is accepted.
        evaluator.observe_comparison(190, true);
        assert_eq!(evaluator.verdict(190), StopVerdict::Continue);
    }

    #[test]
    fn first_comparison_mismatch_latches_stop() {
        let mut evaluator = evaluator();
        evaluator.observe_comparison(110, true);
        assert_eq!(evaluator.verdict(110), StopVerdict::Continue);
        evaluator.observe_comparison(111, false);
        assert_eq!(
            evaluator.verdict(111),
            StopVerdict::Stop(StopReason::ComparisonMismatch)
        );
        // Sticky: much later, staleness would otherwise be due, but the
        // first latched reason still wins.
        assert_eq!(
            evaluator.verdict(500),
            StopVerdict::Stop(StopReason::ComparisonMismatch)
        );
    }

    #[test]
    fn consecutive_advisory_errors_latch_beyond_max_and_success_resets() {
        // One past the consecutive bound latches.
        let mut evaluator = evaluator();
        evaluator.observe_advisory_error(110);
        evaluator.observe_advisory_error(111);
        assert_eq!(evaluator.verdict(111), StopVerdict::Continue);
        evaluator.observe_advisory_error(112);
        assert_eq!(
            evaluator.verdict(112),
            StopVerdict::Stop(StopReason::ConsecutiveAdvisoryErrors)
        );
        // A success between error runs resets the consecutive counter.
        let mut reset = Phase1StopConditionEvaluator::new(evaluator_policy(), START);
        reset.observe_advisory_error(110);
        reset.observe_advisory_error(111);
        reset.observe_advisory_success(112);
        reset.observe_advisory_error(113);
        reset.observe_advisory_error(114);
        assert_eq!(reset.verdict(114), StopVerdict::Continue);
    }

    #[test]
    fn advisory_error_total_latches_beyond_max_across_resets() {
        let mut evaluator = evaluator();
        // Four total errors (the bound), never more than two consecutive.
        evaluator.observe_advisory_error(110);
        evaluator.observe_advisory_error(111);
        evaluator.observe_advisory_success(112);
        evaluator.observe_advisory_error(113);
        evaluator.observe_advisory_error(114);
        evaluator.observe_advisory_success(115);
        assert_eq!(evaluator.verdict(115), StopVerdict::Continue);
        // The fifth total error exceeds the total bound while consecutive
        // stays within its own bound.
        evaluator.observe_advisory_error(116);
        assert_eq!(
            evaluator.verdict(116),
            StopVerdict::Stop(StopReason::AdvisoryErrorTotal)
        );
    }

    #[test]
    fn consecutive_priority_when_consecutive_and_total_exceed_together() {
        // consecutive == total == 2: the third straight error exceeds both
        // bounds in one observation; the consecutive reason wins by the
        // documented check order.
        let fields = MonitoringPolicyFields {
            owner: [0x51; 32],
            freshness: 50,
            mismatches: 0,
            consecutive: 2,
            total: 2,
            bucket: 5,
            memory_mib: 512,
            window: 1_000,
        };
        let policy = Phase1MonitoringPolicy::parse(&encode_monitoring_fields(&fields)).unwrap();
        let mut evaluator = Phase1StopConditionEvaluator::new(policy, START);
        evaluator.observe_advisory_error(110);
        evaluator.observe_advisory_error(111);
        assert_eq!(evaluator.verdict(111), StopVerdict::Continue);
        evaluator.observe_advisory_error(112);
        assert_eq!(
            evaluator.verdict(112),
            StopVerdict::Stop(StopReason::ConsecutiveAdvisoryErrors)
        );
    }

    #[test]
    fn latency_bucket_beyond_max_latches() {
        let mut evaluator = evaluator();
        evaluator.observe_latency(110, DurationBucket::Under5S);
        assert_eq!(evaluator.verdict(110), StopVerdict::Continue);
        evaluator.observe_latency(111, DurationBucket::Under10S);
        assert_eq!(
            evaluator.verdict(111),
            StopVerdict::Stop(StopReason::LatencyExceeded)
        );
        // The slowest bucket also stops a fresh evaluator.
        let mut worst = Phase1StopConditionEvaluator::new(evaluator_policy(), START);
        worst.observe_latency(110, DurationBucket::Over30S);
        assert_eq!(
            worst.verdict(110),
            StopVerdict::Stop(StopReason::LatencyExceeded)
        );
    }

    #[test]
    fn resident_memory_beyond_max_latches() {
        let mut evaluator = evaluator();
        evaluator.observe_resident_memory(110, 512);
        assert_eq!(evaluator.verdict(110), StopVerdict::Continue);
        evaluator.observe_resident_memory(111, 513);
        assert_eq!(
            evaluator.verdict(111),
            StopVerdict::Stop(StopReason::ResidentMemoryExceeded)
        );
    }

    #[test]
    fn telemetry_staleness_reported_in_verdict_and_latched_by_late_observation() {
        // With no observations after construction, the anchor is start_ticks:
        // a gap of exactly the limit continues, one past it is stale.
        let evaluator = evaluator();
        assert_eq!(evaluator.verdict(150), StopVerdict::Continue);
        assert_eq!(
            evaluator.verdict(151),
            StopVerdict::Stop(StopReason::TelemetryStale)
        );
        // verdict is pure: it did not latch, so an earlier tick still
        // continues.
        assert_eq!(evaluator.verdict(150), StopVerdict::Continue);
        // A fresh observation advances the anchor.
        let mut refreshed = Phase1StopConditionEvaluator::new(evaluator_policy(), START);
        refreshed.observe_comparison(149, true);
        assert_eq!(refreshed.verdict(199), StopVerdict::Continue);
        assert_eq!(
            refreshed.verdict(200),
            StopVerdict::Stop(StopReason::TelemetryStale)
        );
        // An observation arriving after a stale gap latches permanently, so
        // the stop decision does not depend on when verdict was polled.
        refreshed.observe_comparison(200, true);
        assert_eq!(
            refreshed.verdict(200),
            StopVerdict::Stop(StopReason::TelemetryStale)
        );
        assert_eq!(
            refreshed.verdict(5_000),
            StopVerdict::Stop(StopReason::TelemetryStale)
        );
    }

    #[test]
    fn observation_window_elapse_is_scheduled_completion_stop() {
        let mut evaluator = evaluator();
        // Healthy, fresh observations across the whole window.
        for tick in (START..START + 1_000).step_by(40) {
            evaluator.observe_comparison(tick, true);
        }
        assert_eq!(evaluator.verdict(1_099), StopVerdict::Continue);
        // now - start >= window: the scheduled, successful end of the
        // observation window, represented as a stop.
        assert_eq!(
            evaluator.verdict(1_100),
            StopVerdict::Stop(StopReason::ObservationWindowElapsed)
        );
        // An observation at/after the window end latches the completion, so
        // no later event can replace it.
        evaluator.observe_comparison(1_100, false);
        assert_eq!(
            evaluator.verdict(1_100),
            StopVerdict::Stop(StopReason::ObservationWindowElapsed)
        );
    }

    #[test]
    fn earliest_time_trigger_wins_between_staleness_and_window_elapse() {
        // Staleness due at 151 precedes window elapse due at 1100.
        let stale_first = evaluator();
        assert_eq!(
            stale_first.verdict(2_000),
            StopVerdict::Stop(StopReason::TelemetryStale)
        );
        // A freshness limit outlasting the window leaves only window elapse.
        let fields = MonitoringPolicyFields {
            owner: [0x51; 32],
            freshness: 5_000,
            mismatches: 0,
            consecutive: 2,
            total: 4,
            bucket: 5,
            memory_mib: 512,
            window: 1_000,
        };
        let policy = Phase1MonitoringPolicy::parse(&encode_monitoring_fields(&fields)).unwrap();
        let window_first = Phase1StopConditionEvaluator::new(policy, START);
        assert_eq!(
            window_first.verdict(2_000),
            StopVerdict::Stop(StopReason::ObservationWindowElapsed)
        );
        // Tie (both due at 1100): the conservative staleness reason wins,
        // because the window's final stretch was unobserved.
        let tie_fields = MonitoringPolicyFields {
            owner: [0x51; 32],
            freshness: 999,
            mismatches: 0,
            consecutive: 2,
            total: 4,
            bucket: 5,
            memory_mib: 512,
            window: 1_000,
        };
        let tie_policy =
            Phase1MonitoringPolicy::parse(&encode_monitoring_fields(&tie_fields)).unwrap();
        let tie = Phase1StopConditionEvaluator::new(tie_policy, START);
        assert_eq!(
            tie.verdict(1_100),
            StopVerdict::Stop(StopReason::TelemetryStale)
        );
    }

    #[test]
    fn non_monotonic_ticks_latch_telemetry_stale() {
        let mut evaluator = evaluator();
        evaluator.observe_comparison(140, true);
        // A regressed verdict tick is reported (purely) as stale.
        assert_eq!(
            evaluator.verdict(139),
            StopVerdict::Stop(StopReason::TelemetryStale)
        );
        assert_eq!(evaluator.verdict(190), StopVerdict::Continue);
        // An equal tick is monotonic and accepted.
        evaluator.observe_comparison(140, true);
        assert_eq!(evaluator.verdict(140), StopVerdict::Continue);
        // A regressed observation tick latches permanently: clock
        // inconsistency is a stop signal.
        evaluator.observe_comparison(139, true);
        assert_eq!(
            evaluator.verdict(300),
            StopVerdict::Stop(StopReason::TelemetryStale)
        );
        // Observations before start_ticks are non-monotonic from birth.
        let mut before_start = Phase1StopConditionEvaluator::new(evaluator_policy(), START);
        before_start.observe_advisory_success(START - 1);
        assert_eq!(
            before_start.verdict(START),
            StopVerdict::Stop(StopReason::TelemetryStale)
        );
    }

    #[test]
    fn first_latched_reason_is_sticky_across_later_violations() {
        let mut evaluator = evaluator();
        evaluator.observe_comparison(110, false);
        assert_eq!(
            evaluator.verdict(110),
            StopVerdict::Stop(StopReason::ComparisonMismatch)
        );
        // Later worse events of every other kind are dropped.
        evaluator.observe_resident_memory(120, 4_000);
        evaluator.observe_latency(121, DurationBucket::Over30S);
        for tick in 122..130 {
            evaluator.observe_advisory_error(tick);
        }
        evaluator.observe_comparison(50, false);
        assert_eq!(
            evaluator.verdict(130),
            StopVerdict::Stop(StopReason::ComparisonMismatch)
        );
        // Even when staleness and window elapse are both long overdue.
        assert_eq!(
            evaluator.verdict(10_000),
            StopVerdict::Stop(StopReason::ComparisonMismatch)
        );
    }

    #[test]
    fn duration_bucket_ordinals_cover_exactly_the_telemetry_enum() {
        for ordinal in 0..=MAX_DURATION_BUCKET_ORDINAL {
            let bucket = duration_bucket_from_ordinal(ordinal).unwrap();
            assert_eq!(duration_bucket_ordinal(bucket), ordinal);
        }
        assert_eq!(
            duration_bucket_from_ordinal(MAX_DURATION_BUCKET_ORDINAL + 1),
            Err(AdvisoryOwnerError::Corrupt)
        );
    }
}
