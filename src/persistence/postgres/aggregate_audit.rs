use serde::{Deserialize, Serialize};
use sqlx::Row;

use super::PostgresPersistence;

pub(crate) const POSTGRES_AGGREGATE_AUDIT_CONTRACT: &str = "kioku.postdeploy.aggregate-audit.v1";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum AggregateAuditFailure {
    InvalidArguments,
    MissingConfiguration,
    InvalidSince,
    SinceOutOfRange,
    PostgresUnavailable,
    AuditFailed,
}

impl AggregateAuditFailure {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::InvalidArguments => "invalid_arguments",
            Self::MissingConfiguration => "missing_configuration",
            Self::InvalidSince => "invalid_since",
            Self::SinceOutOfRange => "since_out_of_range",
            Self::PostgresUnavailable => "postgres_unavailable",
            Self::AuditFailed => "audit_failed",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct PostgresAggregateAuditReport {
    pub(crate) contract: String,
    pub(crate) schema_version: i64,
    pub(crate) observed_at: String,
    pub(crate) since: String,
    pub(crate) usage_day: String,
    pub(crate) transaction_read_only: bool,
    pub(crate) activation: ActivationAudit,
    pub(crate) capture_events: CaptureEventsAudit,
    pub(crate) media: MediaAudit,
    pub(crate) formation: FormationAudit,
    pub(crate) reconciliation: ReconciliationAudit,
    pub(crate) topology: TopologyAudit,
    pub(crate) vertex_usage: VertexUsageAudit,
    pub(crate) usage_daily: UsageDailyAudit,
    pub(crate) finalization: FinalizationAudit,
    pub(crate) capacity: CapacityAudit,
    pub(crate) gates: GateAudit,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct ActivationAudit {
    pub(crate) present: bool,
    pub(crate) phase: Option<String>,
    pub(crate) generation: Option<i64>,
    pub(crate) rollout_basis_points: Option<i64>,
    pub(crate) explicit_canary_count: Option<i64>,
    pub(crate) applied_at_ms: Option<i64>,
    pub(crate) active_accounts: i64,
    pub(crate) assignments: i64,
    pub(crate) unassigned_active_accounts: i64,
    pub(crate) backfill_present: bool,
    pub(crate) backfill_refresh_generation: Option<i64>,
    pub(crate) backfill_complete: Option<bool>,
    pub(crate) backfill_rows_scanned: Option<i64>,
    pub(crate) backfill_rows_inserted: Option<i64>,
    pub(crate) backfill_rows_reopened: Option<i64>,
    pub(crate) backfill_updated_at_ms: Option<i64>,
    pub(crate) backfill_completed_at_ms: Option<i64>,
    pub(crate) drain_present: bool,
    pub(crate) drain_complete: Option<bool>,
    pub(crate) drain_claims_scanned: Option<i64>,
    pub(crate) drain_claims_revoked: Option<i64>,
    pub(crate) drain_updated_at_ms: Option<i64>,
    pub(crate) drain_completed_at_ms: Option<i64>,
    pub(crate) pending_episode_deletions: i64,
    pub(crate) episode_deletion_coherence_violations: i64,
    pub(crate) scoped_draft_finalization_claims: i64,
    pub(crate) domain_violation_count: i64,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct CaptureEventsAudit {
    pub(crate) groups: Vec<CaptureEventGroup>,
    pub(crate) domain_violation_count: i64,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct CaptureEventGroup {
    pub(crate) stream_kind: String,
    pub(crate) media_disposition: String,
    pub(crate) count: i64,
    pub(crate) first_started_at_ms: Option<i64>,
    pub(crate) last_ended_at_ms: Option<i64>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct MediaAudit {
    pub(crate) work_units_since: Vec<MediaWorkGroup>,
    pub(crate) work_units_unfinished: Vec<MediaWorkGroup>,
    pub(crate) jobs_since: Vec<MediaJobGroup>,
    pub(crate) jobs_unfinished: Vec<MediaJobGroup>,
    pub(crate) work_domain_violation_count: i64,
    pub(crate) job_domain_violation_count: i64,
    pub(crate) current_budget_jobs: i64,
    pub(crate) current_budget_work_units: i64,
    pub(crate) current_budget_distinct_work_units: i64,
    pub(crate) budget_retry_due_jobs: i64,
    pub(crate) budget_retry_future_jobs: i64,
    pub(crate) budget_retry_past_due_jobs: i64,
    pub(crate) budget_retry_earliest_next_attempt_at_ms: Option<i64>,
    pub(crate) budget_retry_latest_next_attempt_at_ms: Option<i64>,
    pub(crate) budget_retry_max_jobs_per_account: i64,
    pub(crate) expired_processing_jobs: i64,
    pub(crate) expired_processing_work_units: i64,
    pub(crate) inconsistent_processing_jobs: i64,
    pub(crate) inconsistent_processing_work_units: i64,
    pub(crate) unfinished_work_without_members: i64,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct MediaWorkGroup {
    pub(crate) work_class: String,
    pub(crate) state: String,
    pub(crate) reservation_retained: bool,
    pub(crate) count: i64,
    pub(crate) attempt_count: i64,
    pub(crate) reserved_output_tokens: i64,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct MediaJobGroup {
    pub(crate) job_kind: String,
    pub(crate) state: String,
    pub(crate) count: i64,
    pub(crate) attempt_count: i64,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct FormationAudit {
    pub(crate) receipts_since: Vec<FormationReceiptGroup>,
    pub(crate) receipts_unfinished: Vec<FormationReceiptGroup>,
    pub(crate) pages_since: Vec<FormationPageGroup>,
    pub(crate) pages_unfinished: Vec<FormationPageGroup>,
    pub(crate) receipt_domain_violation_count: i64,
    pub(crate) page_domain_violation_count: i64,
    pub(crate) finished_dirty_receipts: i64,
    pub(crate) ended_without_finish_receipts: i64,
    pub(crate) seal_pending_receipts: i64,
    pub(crate) unresolved_source_accounts: i64,
    pub(crate) retry_due_receipts: i64,
    pub(crate) retry_future_receipts: i64,
    pub(crate) expired_processing_receipts: i64,
    pub(crate) nonterminal_pages_for_finished_receipts: i64,
    pub(crate) staged_response_pages: i64,
    pub(crate) legacy_processing_claims: i64,
    pub(crate) legacy_expired_claims: i64,
    pub(crate) legacy_retry_due_claims: i64,
    pub(crate) legacy_retry_future_claims: i64,
    pub(crate) legacy_budget_error_claims: i64,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct FormationReceiptGroup {
    pub(crate) state: String,
    pub(crate) count: i64,
    pub(crate) attempt_count: i64,
    pub(crate) outstanding_revisions: i64,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct FormationPageGroup {
    pub(crate) state: String,
    pub(crate) count: i64,
    pub(crate) provider_attempts: i64,
    pub(crate) covered_utterances: i64,
    pub(crate) covered_screenshots: i64,
    pub(crate) staged_responses: i64,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct ReconciliationAudit {
    pub(crate) jobs_since: Vec<ReconciliationJobGroup>,
    pub(crate) jobs_unfinished: Vec<ReconciliationJobGroup>,
    pub(crate) job_domain_violation_count: i64,
    pub(crate) retry_due_jobs: i64,
    pub(crate) retry_future_jobs: i64,
    pub(crate) expired_processing_jobs: i64,
    pub(crate) staged_rows: i64,
    pub(crate) stage_without_authoritative_job: i64,
    pub(crate) candidate_drafts: i64,
    pub(crate) candidate_components: i64,
    pub(crate) max_drafts_per_component: i64,
    pub(crate) components_over_32: i64,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct ReconciliationJobGroup {
    pub(crate) state: String,
    pub(crate) count: i64,
    pub(crate) attempt_count: i64,
    pub(crate) model_attempt_count: i64,
    pub(crate) predecessor_count: i64,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct TopologyAudit {
    pub(crate) groups: Vec<TopologyGroup>,
    pub(crate) domain_violation_count: i64,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct TopologyGroup {
    pub(crate) relation: String,
    pub(crate) count: i64,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct VertexUsageAudit {
    pub(crate) groups: Vec<VertexUsageGroup>,
    pub(crate) domain_violation_count: i64,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct VertexUsageGroup {
    pub(crate) operation: String,
    pub(crate) outcome: String,
    pub(crate) count: i64,
    pub(crate) output_text_tokens: i64,
    pub(crate) thought_tokens: i64,
    pub(crate) total_tokens: i64,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct UsageDailyAudit {
    pub(crate) active_accounts: i64,
    pub(crate) usage_rows: i64,
    pub(crate) vertex_requests: i64,
    pub(crate) vertex_output_tokens: i64,
    pub(crate) class_output_tokens: i64,
    pub(crate) total_mismatch_rows: i64,
    pub(crate) request_slot_mismatch_rows: i64,
    pub(crate) classes: Vec<UsageClassAudit>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct UsageClassAudit {
    pub(crate) class: String,
    pub(crate) token_limit: i64,
    pub(crate) quantum: i64,
    pub(crate) slot_limit: i64,
    pub(crate) used_tokens: i64,
    pub(crate) reservation_slots: i64,
    pub(crate) max_used_tokens_per_active_account: i64,
    pub(crate) minimum_remaining_tokens_per_active_account: i64,
    pub(crate) minimum_remaining_slots_per_active_account: i64,
    pub(crate) accounts_at_or_over_limit: i64,
    pub(crate) nondivisible_rows: i64,
    pub(crate) admitted_event_rows: i64,
    pub(crate) terminal_event_rows: i64,
    pub(crate) pending_started_rows: i64,
    pub(crate) possible_billed_rows: i64,
    pub(crate) unmatched_reservations: i64,
    pub(crate) event_overhang: i64,
    pub(crate) accounts_with_unmatched_reservations: i64,
    pub(crate) max_unmatched_reservations_per_account: i64,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct FinalizationAudit {
    pub(crate) active_handle_episodes: i64,
    pub(crate) draft_episodes: i64,
    pub(crate) reconciled_episodes: i64,
    pub(crate) needs_finalization: i64,
    pub(crate) reconciled_needs_finalization: i64,
    pub(crate) processing_claims: i64,
    pub(crate) expired_processing_claims: i64,
    pub(crate) due_waits: i64,
    pub(crate) future_waits: i64,
    pub(crate) budget_waits: i64,
    pub(crate) failed_terminal: i64,
    pub(crate) oldest_wait_at_ms: Option<i64>,
    pub(crate) latest_wait_at_ms: Option<i64>,
    pub(crate) domain_violation_count: i64,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct CapacityAudit {
    pub(crate) projected_components: i64,
    pub(crate) projected_successor_finalizers: i64,
    pub(crate) max_required_derived_slots: i64,
    pub(crate) accounts_insufficient_derived: i64,
    pub(crate) minimum_derived_headroom_slots: i64,
    pub(crate) accounts_below_audio_96_slots: i64,
    pub(crate) minimum_audio_remaining_slots: i64,
    pub(crate) accounts_at_screen_cap: i64,
    pub(crate) audio_remaining_at_least_96: bool,
    pub(crate) derived_remaining_covers_backlog: bool,
    pub(crate) screen_remaining_nonzero: bool,
    pub(crate) no_oversized_components: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct GateAudit {
    pub(crate) domain_clean: bool,
    pub(crate) quota_invariants_hold: bool,
    pub(crate) provider_quiescent: bool,
    pub(crate) media_budget_drained: bool,
    pub(crate) leases_unexpired: bool,
    pub(crate) formation_quiescent: bool,
    pub(crate) reconciliation_quiescent: bool,
    pub(crate) finalization_claims_quiescent: bool,
    pub(crate) activation_ready_for_drain: bool,
    pub(crate) activation_ready_for_active: bool,
    pub(crate) capacity_sufficient: bool,
    pub(crate) ready_for_drain: bool,
    pub(crate) ready_for_active: bool,
}

impl GateAudit {
    fn shared_transition_gates_hold(&self) -> bool {
        self.domain_clean
            && self.quota_invariants_hold
            && self.provider_quiescent
            && self.media_budget_drained
            && self.leases_unexpired
            && self.reconciliation_quiescent
            && self.finalization_claims_quiescent
            && self.capacity_sufficient
    }

    fn expected_ready_for_drain(&self) -> bool {
        // Formation's historical-finish import and first immutable seal become
        // legal only after signed Draining. They remain observable here and are
        // mandatory for Active, but cannot be a precondition of their own phase.
        self.shared_transition_gates_hold() && self.activation_ready_for_drain
    }

    fn expected_ready_for_active(&self) -> bool {
        self.shared_transition_gates_hold()
            && self.formation_quiescent
            && self.activation_ready_for_active
    }

    fn readiness_is_exact(&self) -> bool {
        self.ready_for_drain == self.expected_ready_for_drain()
            && self.ready_for_active == self.expected_ready_for_active()
    }
}

pub(crate) fn parse_postgres_audit_since(raw: &str) -> Result<(), AggregateAuditFailure> {
    let bytes = raw.as_bytes();
    if bytes.len() != 20
        || bytes[4] != b'-'
        || bytes[7] != b'-'
        || bytes[10] != b'T'
        || bytes[13] != b':'
        || bytes[16] != b':'
        || bytes[19] != b'Z'
        || bytes.iter().enumerate().any(|(index, byte)| {
            !matches!(index, 4 | 7 | 10 | 13 | 16 | 19) && !byte.is_ascii_digit()
        })
    {
        return Err(AggregateAuditFailure::InvalidSince);
    }
    let number = |start: usize, end: usize| -> u32 {
        bytes[start..end]
            .iter()
            .fold(0, |value, byte| value * 10 + u32::from(byte - b'0'))
    };
    let year = number(0, 4);
    let month = number(5, 7);
    let day = number(8, 10);
    let hour = number(11, 13);
    let minute = number(14, 16);
    let second = number(17, 19);
    let leap = year.is_multiple_of(4) && (!year.is_multiple_of(100) || year.is_multiple_of(400));
    let maximum_day = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if leap => 29,
        2 => 28,
        _ => 0,
    };
    if year == 0 || day == 0 || day > maximum_day || hour > 23 || minute > 59 || second > 59 {
        return Err(AggregateAuditFailure::InvalidSince);
    }
    Ok(())
}

impl PostgresAggregateAuditReport {
    fn validate(&self, expected_since: &str) -> Result<(), AggregateAuditFailure> {
        if self.contract != POSTGRES_AGGREGATE_AUDIT_CONTRACT
            || self.schema_version != 1
            || self.since != expected_since
            || self.usage_day != expected_since[..10]
            || !self.transaction_read_only
            || !valid_observed_at(&self.observed_at)
            || !valid_usage_day(&self.usage_day)
            || !exact_capture_groups(&self.capture_events.groups)
            || !exact_media_work_groups(&self.media.work_units_since)
            || !exact_media_work_groups(&self.media.work_units_unfinished)
            || !exact_media_job_groups(&self.media.jobs_since)
            || !exact_media_job_groups(&self.media.jobs_unfinished)
            || !exact_state_groups(
                self.formation
                    .receipts_since
                    .iter()
                    .map(|group| group.state.as_str()),
                &FORMATION_RECEIPT_STATES,
            )
            || !exact_state_groups(
                self.formation
                    .receipts_unfinished
                    .iter()
                    .map(|group| group.state.as_str()),
                &FORMATION_RECEIPT_STATES,
            )
            || !exact_state_groups(
                self.formation
                    .pages_since
                    .iter()
                    .map(|group| group.state.as_str()),
                &FORMATION_PAGE_STATES,
            )
            || !exact_state_groups(
                self.formation
                    .pages_unfinished
                    .iter()
                    .map(|group| group.state.as_str()),
                &FORMATION_PAGE_STATES,
            )
            || !exact_state_groups(
                self.reconciliation
                    .jobs_since
                    .iter()
                    .map(|group| group.state.as_str()),
                &RECONCILIATION_STATES,
            )
            || !exact_state_groups(
                self.reconciliation
                    .jobs_unfinished
                    .iter()
                    .map(|group| group.state.as_str()),
                &RECONCILIATION_STATES,
            )
            || !exact_state_groups(
                self.topology
                    .groups
                    .iter()
                    .map(|group| group.relation.as_str()),
                &TOPOLOGY_RELATIONS,
            )
            || !exact_vertex_groups(&self.vertex_usage.groups)
            || !exact_state_groups(
                self.usage_daily
                    .classes
                    .iter()
                    .map(|group| group.class.as_str()),
                &USAGE_CLASSES,
            )
            || !self.gates.readiness_is_exact()
        {
            return Err(AggregateAuditFailure::AuditFailed);
        }
        let value = serde_json::to_value(self).map_err(|_| AggregateAuditFailure::AuditFailed)?;
        if contains_unexpected_negative_integer(&value, None) {
            return Err(AggregateAuditFailure::AuditFailed);
        }
        Ok(())
    }
}

fn valid_observed_at(value: &str) -> bool {
    if !value.is_ascii()
        || value.len() != 24
        || !value.ends_with('Z')
        || value.as_bytes().get(19) != Some(&b'.')
    {
        return false;
    }
    let seconds = format!("{}Z", &value[..19]);
    parse_postgres_audit_since(&seconds).is_ok()
        && value.as_bytes()[20..23].iter().all(u8::is_ascii_digit)
}

fn valid_usage_day(value: &str) -> bool {
    parse_postgres_audit_since(&format!("{value}T00:00:00Z")).is_ok()
}

fn contains_unexpected_negative_integer(value: &serde_json::Value, key: Option<&str>) -> bool {
    match value {
        serde_json::Value::Number(number) => {
            key != Some("minimum_derived_headroom_slots")
                && number.as_i64().is_some_and(|number| number < 0)
        }
        serde_json::Value::Array(values) => values
            .iter()
            .any(|value| contains_unexpected_negative_integer(value, None)),
        serde_json::Value::Object(values) => values
            .iter()
            .any(|(key, value)| contains_unexpected_negative_integer(value, Some(key.as_str()))),
        _ => false,
    }
}

const STREAM_KINDS: [&str; 6] = [
    "mic",
    "system_audio",
    "mac_screen",
    "ios_mic",
    "ios_imported_screenshot",
    "ios_shared_page",
];
const MEDIA_DISPOSITIONS: [&str; 2] = ["canonical", "reference"];
const MEDIA_WORK_CLASSES: [&str; 2] = ["audio", "screen"];
const MEDIA_WORK_STATES: [&str; 5] = [
    "planned",
    "processing",
    "retry_wait",
    "succeeded",
    "failed_terminal",
];
const MEDIA_JOB_KINDS: [&str; 2] = ["gemini_audio", "gemini_screen"];
const MEDIA_JOB_STATES: [&str; 6] = [
    "pending",
    "processing",
    "retry_wait",
    "succeeded",
    "failed_terminal",
    "canceled",
];
const FORMATION_RECEIPT_STATES: [&str; 4] = ["pending", "processing", "retry_wait", "complete"];
const FORMATION_PAGE_STATES: [&str; 4] = ["processing", "retry_wait", "complete", "invalidated"];
const RECONCILIATION_STATES: [&str; 5] = [
    "pending",
    "processing",
    "retry_wait",
    "complete",
    "failed_terminal",
];
const TOPOLOGY_RELATIONS: [&str; 3] = ["merge", "split", "repartition"];
const VERTEX_OPERATIONS: [&str; 5] = [
    "audio_understanding",
    "screen_understanding",
    "episode_summarization",
    "episode_finalization",
    "episode_reconciliation",
];
const VERTEX_OUTCOMES: [&str; 5] = [
    "started",
    "metered",
    "usage_missing",
    "ambiguous",
    "not_billed",
];
const USAGE_CLASSES: [&str; 3] = ["audio", "screen", "derived"];

fn exact_capture_groups(groups: &[CaptureEventGroup]) -> bool {
    groups.len() == STREAM_KINDS.len() * MEDIA_DISPOSITIONS.len()
        && groups
            .iter()
            .zip(STREAM_KINDS.iter().flat_map(|stream| {
                MEDIA_DISPOSITIONS
                    .iter()
                    .map(move |disposition| (*stream, *disposition))
            }))
            .all(|(group, expected)| {
                (group.stream_kind.as_str(), group.media_disposition.as_str()) == expected
            })
}

fn exact_media_work_groups(groups: &[MediaWorkGroup]) -> bool {
    groups.len() == MEDIA_WORK_CLASSES.len() * MEDIA_WORK_STATES.len() * 2
        && groups
            .iter()
            .zip(MEDIA_WORK_CLASSES.iter().flat_map(|class| {
                MEDIA_WORK_STATES.iter().flat_map(move |state| {
                    [false, true]
                        .into_iter()
                        .map(move |retained| (*class, *state, retained))
                })
            }))
            .all(|(group, expected)| {
                (
                    group.work_class.as_str(),
                    group.state.as_str(),
                    group.reservation_retained,
                ) == expected
            })
}

fn exact_media_job_groups(groups: &[MediaJobGroup]) -> bool {
    groups.len() == MEDIA_JOB_KINDS.len() * MEDIA_JOB_STATES.len()
        && groups
            .iter()
            .zip(
                MEDIA_JOB_KINDS
                    .iter()
                    .flat_map(|kind| MEDIA_JOB_STATES.iter().map(move |state| (*kind, *state))),
            )
            .all(|(group, expected)| (group.job_kind.as_str(), group.state.as_str()) == expected)
}

fn exact_vertex_groups(groups: &[VertexUsageGroup]) -> bool {
    groups.len() == VERTEX_OPERATIONS.len() * VERTEX_OUTCOMES.len()
        && groups
            .iter()
            .zip(VERTEX_OPERATIONS.iter().flat_map(|operation| {
                VERTEX_OUTCOMES
                    .iter()
                    .map(move |outcome| (*operation, *outcome))
            }))
            .all(|(group, expected)| (group.operation.as_str(), group.outcome.as_str()) == expected)
}

fn exact_state_groups<'a>(actual: impl Iterator<Item = &'a str>, expected: &[&str]) -> bool {
    actual.eq(expected.iter().copied())
}

impl PostgresPersistence {
    async fn begin_aggregate_audit_transaction(
        &self,
    ) -> Result<sqlx::Transaction<'_, sqlx::Postgres>, AggregateAuditFailure> {
        let mut transaction = self
            .pool()
            .begin()
            .await
            .map_err(|_| AggregateAuditFailure::PostgresUnavailable)?;
        if sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
            .execute(&mut *transaction)
            .await
            .is_err()
            || sqlx::query(
                "SELECT set_config('TimeZone','UTC',true), \
                        set_config('statement_timeout','15000',true), \
                        set_config('lock_timeout','2000',true), \
                        set_config('idle_in_transaction_session_timeout','30000',true)",
            )
            .execute(&mut *transaction)
            .await
            .is_err()
        {
            let _ = transaction.rollback().await;
            return Err(AggregateAuditFailure::AuditFailed);
        }
        Ok(transaction)
    }

    pub(crate) async fn aggregate_audit(
        &self,
        since: &str,
    ) -> Result<PostgresAggregateAuditReport, AggregateAuditFailure> {
        parse_postgres_audit_since(since)?;
        let mut transaction = self.begin_aggregate_audit_transaction().await?;
        let queried = sqlx::query(AGGREGATE_AUDIT_SQL)
            .bind(since)
            .fetch_all(&mut *transaction)
            .await;
        let rollback = transaction.rollback().await;
        if rollback.is_err() {
            return Err(AggregateAuditFailure::AuditFailed);
        }
        let rows = queried.map_err(|_| AggregateAuditFailure::AuditFailed)?;
        let row = match rows.as_slice() {
            [] => return Err(AggregateAuditFailure::SinceOutOfRange),
            [row] => row,
            _ => return Err(AggregateAuditFailure::AuditFailed),
        };
        let payload: String = row
            .try_get("payload")
            .map_err(|_| AggregateAuditFailure::AuditFailed)?;
        let report: PostgresAggregateAuditReport =
            serde_json::from_str(&payload).map_err(|_| AggregateAuditFailure::AuditFailed)?;
        report.validate(since)?;
        Ok(report)
    }
}

const AGGREGATE_AUDIT_SQL: &str = include_str!("aggregate_audit.sql");

#[cfg(test)]
async fn test_real_pg_aggregate_audit_isolated(base: &PostgresPersistence) {
    use std::{str::FromStr as _, time::Duration};

    use sqlx::postgres::{PgConnectOptions, PgPoolOptions};

    let _release_contract_guard = super::POSTGRES_RELEASE_CONTRACT_MUTEX.lock().await;
    let unique = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("test clock must follow the Unix epoch")
        .as_nanos();
    // Reuse the schema-release contract's reviewed isolated-test namespace.
    let schema = format!("kioku_activation_audit_{}_{}", std::process::id(), unique);
    assert!(schema
        .bytes()
        .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_'));
    sqlx::query(sqlx::AssertSqlSafe(format!("CREATE SCHEMA {schema}")))
        .execute(base.pool())
        .await
        .expect("create isolated aggregate-audit schema");
    let database_url = std::env::var("KIOKU_TEST_POSTGRES_URL")
        .expect("real PostgreSQL aggregate-audit contract requires its configured URL");
    let migration_options = PgConnectOptions::from_str(&database_url)
        .expect("parse real PostgreSQL aggregate-audit URL")
        .options([("search_path", format!("{schema},public"))]);
    let migration_pool = PgPoolOptions::new()
        .max_connections(2)
        .acquire_timeout(Duration::from_secs(5))
        .connect_with(migration_options)
        .await
        .expect("connect isolated aggregate-audit schema");
    let migration_persistence = PostgresPersistence {
        pool: migration_pool,
    };
    migration_persistence.migrate().await.unwrap();
    migration_persistence.pool.close().await;

    // Once migrations have resolved extension types, remove `public` from the
    // lookup path so a populated reusable contract database cannot shadow the
    // isolated activation and audit relations.
    let audit_options = PgConnectOptions::from_str(&database_url)
        .expect("parse real PostgreSQL aggregate-audit URL")
        .options([("search_path", schema.clone())]);
    let audit_pool = PgPoolOptions::new()
        .max_connections(2)
        .acquire_timeout(Duration::from_secs(5))
        .connect_with(audit_options)
        .await
        .expect("connect strict isolated aggregate-audit schema");
    let persistence = PostgresPersistence { pool: audit_pool };
    Box::pin(test_real_pg_aggregate_audit_inner(&persistence, true)).await;
    persistence.pool.close().await;
    sqlx::query(sqlx::AssertSqlSafe(format!("DROP SCHEMA {schema} CASCADE")))
        .execute(base.pool())
        .await
        .expect("drop isolated aggregate-audit schema");
}

#[cfg(test)]
pub(super) async fn test_real_pg_aggregate_audit(persistence: &PostgresPersistence) {
    // This contract is also nested inside the exhaustive control-plane test.
    // Keep its intentionally broad fixture future off that test thread's stack.
    Box::pin(test_real_pg_aggregate_audit_inner(persistence, false)).await;
}

#[cfg(test)]
async fn test_real_pg_aggregate_audit_inner(
    persistence: &PostgresPersistence,
    isolated_gate_edges: bool,
) {
    let schema_installed = sqlx::query_scalar::<_, bool>(
        "SELECT to_regclass(format('%I.%I',current_schema(), \
                                   'persistence_schema')) IS NOT NULL",
    )
    .fetch_one(persistence.pool())
    .await
    .unwrap();
    if !schema_installed {
        persistence.migrate().await.unwrap();
    }
    let activation_installed = sqlx::query_scalar::<_, bool>(
        "SELECT to_regclass(format('%I.%I',current_schema(), \
                                   'persistence_feature_activation_events')) IS NOT NULL",
    )
    .fetch_one(persistence.pool())
    .await
    .unwrap();
    if !activation_installed {
        persistence
            .install_memory_reconciliation_activation_schema()
            .await
            .unwrap();
    }
    let before = sqlx::query_scalar::<_, i64>("SELECT count(*) FROM accounts")
        .fetch_one(persistence.pool())
        .await
        .unwrap();
    let since = sqlx::query_scalar::<_, String>(
        "SELECT to_char(clock_timestamp()-interval '1 hour', \
                        'YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"')",
    )
    .fetch_one(persistence.pool())
    .await
    .unwrap();
    let report = persistence.aggregate_audit(&since).await.unwrap();
    assert_eq!(report.contract, POSTGRES_AGGREGATE_AUDIT_CONTRACT);
    assert_eq!(report.schema_version, 1);
    assert!(report.transaction_read_only);
    assert_eq!(report.capture_events.groups.len(), 12);
    assert_eq!(report.media.work_units_since.len(), 20);
    assert_eq!(report.media.work_units_unfinished.len(), 20);
    assert_eq!(report.media.jobs_since.len(), 12);
    assert_eq!(report.media.jobs_unfinished.len(), 12);
    assert_eq!(report.vertex_usage.groups.len(), 25);
    assert_eq!(report.usage_daily.classes.len(), 3);
    let after = sqlx::query_scalar::<_, i64>("SELECT count(*) FROM accounts")
        .fetch_one(persistence.pool())
        .await
        .unwrap();
    assert_eq!(
        before, after,
        "the aggregate audit must not mutate PostgreSQL"
    );

    if isolated_gate_edges {
        sqlx::raw_sql(
            "INSERT INTO accounts(id,email,primary_provider,primary_subject) \
         VALUES('aggregate-audit-gate-contract','aggregate-audit-gate@example.com', \
                'google','aggregate-audit-gate'); \
         INSERT INTO capture_sessions( \
             account_id,id,device_id,install_id,started_at,last_event_at,ended_at,schema_version) \
         VALUES('aggregate-audit-gate-contract','unsealed-session','gate-device','gate-install', \
                clock_timestamp()-interval '2 seconds',clock_timestamp(),clock_timestamp(),2); \
         INSERT INTO capture_streams( \
             account_id,id,capture_session_id,device_id,stream_kind, \
             committed_through_sequence,sealed_sequence) \
         VALUES('aggregate-audit-gate-contract','unsealed-stream','unsealed-session', \
                'gate-device','mac_screen',0,0); \
         INSERT INTO capture_events( \
             account_id,event_id,device_id,install_id,capture_session_id,stream_id,stream_kind, \
             sequence,source_wall_at,source_monotonic_ns,started_at,ended_at,timezone_id, \
             utc_offset_minutes,clock_uncertainty_ms,asset_id,manifest_digest,media_disposition) \
         VALUES('aggregate-audit-gate-contract','unsealed-event','gate-device','gate-install', \
                'unsealed-session','unsealed-stream','mac_screen',0, \
                clock_timestamp()-interval '1 second','0', \
                clock_timestamp()-interval '1 second',clock_timestamp(),'UTC',0,0, \
                'unsealed-asset',repeat('b',64),'canonical'); \
         INSERT INTO capture_formation_receipts( \
             account_id,capture_session_id,source_revision,completed_revision,state, \
             completed_outcome,completed_claim_token,completed_source_fingerprint,completed_at, \
             finish_requested_at,finish_request_provenance) \
         VALUES('aggregate-audit-gate-contract','unsealed-session',1,1,'complete','no_memory', \
                'gate-completed-claim',decode(repeat('ab',32),'hex'),clock_timestamp(), \
                clock_timestamp(),'finish_endpoint_v1');",
        )
        .execute(persistence.pool())
        .await
        .unwrap();
        let unsealed = persistence.aggregate_audit(&since).await.unwrap();
        assert_eq!(unsealed.formation.finished_dirty_receipts, 0);
        assert_eq!(unsealed.formation.ended_without_finish_receipts, 0);
        assert_eq!(unsealed.formation.seal_pending_receipts, 1);
        assert_eq!(unsealed.formation.unresolved_source_accounts, 1);
        assert!(!unsealed.gates.formation_quiescent);
        sqlx::query(
            "UPDATE capture_formation_receipts \
            SET seal_generation=1,seal_finalized_at=clock_timestamp(), \
                seal_finalization_provenance='quiet_contiguous_v1' \
          WHERE account_id='aggregate-audit-gate-contract' \
            AND capture_session_id='unsealed-session'",
        )
        .execute(persistence.pool())
        .await
        .unwrap();
        let missing_seal_proof = persistence.aggregate_audit(&since).await.unwrap();
        assert_eq!(missing_seal_proof.formation.seal_pending_receipts, 0);
        assert_eq!(missing_seal_proof.formation.unresolved_source_accounts, 1);
        assert!(!missing_seal_proof.gates.formation_quiescent);
        sqlx::query(
            "DELETE FROM capture_sessions \
          WHERE account_id='aggregate-audit-gate-contract' AND id='unsealed-session'",
        )
        .execute(persistence.pool())
        .await
        .unwrap();

        sqlx::query(
            "INSERT INTO capture_sessions( \
             account_id,id,device_id,install_id,started_at,last_event_at,ended_at,schema_version) \
         VALUES('aggregate-audit-gate-contract','missing-receipt-session', \
                'gate-device','gate-install',clock_timestamp()-interval '2 seconds', \
                clock_timestamp(),clock_timestamp(),2)",
        )
        .execute(persistence.pool())
        .await
        .unwrap();
        let missing_receipt = persistence.aggregate_audit(&since).await.unwrap();
        assert_eq!(missing_receipt.formation.unresolved_source_accounts, 1);
        assert!(!missing_receipt.gates.formation_quiescent);
        sqlx::query(
            "DELETE FROM capture_sessions \
          WHERE account_id='aggregate-audit-gate-contract' AND id='missing-receipt-session'",
        )
        .execute(persistence.pool())
        .await
        .unwrap();

        sqlx::query(
            "UPDATE persistence_feature_activation_backfills \
            SET complete=true,completed_at=clock_timestamp(),updated_at=clock_timestamp() \
          WHERE feature='episode_topology_reconciliation' \
            AND backfill_name='capture_formation_receipts' AND refresh_generation=0",
        )
        .execute(persistence.pool())
        .await
        .unwrap();
        let deletion_clear = persistence.aggregate_audit(&since).await.unwrap();
        assert_eq!(deletion_clear.activation.pending_episode_deletions, 0);
        assert_eq!(
            deletion_clear
                .activation
                .episode_deletion_coherence_violations,
            0
        );
        assert!(deletion_clear.gates.activation_ready_for_drain);
        assert!(deletion_clear.gates.ready_for_drain);

        sqlx::query(
            "INSERT INTO episode_deletions( \
             account_id,episode_id,state,purge,media_object_keys,utterance_ids, \
             screenshot_ids,segment_ids,orphan_event_ids) \
         VALUES('aggregate-audit-gate-contract',9100,'pending','{}'::jsonb,'[]'::jsonb, \
                '[]'::jsonb,'[]'::jsonb,'[]'::jsonb,'[]'::jsonb)",
        )
        .execute(persistence.pool())
        .await
        .unwrap();
        let pending_deletion = persistence.aggregate_audit(&since).await.unwrap();
        assert_eq!(pending_deletion.activation.pending_episode_deletions, 1);
        assert_eq!(
            pending_deletion
                .activation
                .episode_deletion_coherence_violations,
            1
        );
        assert!(!pending_deletion.gates.activation_ready_for_drain);
        assert!(!pending_deletion.gates.ready_for_drain);
        sqlx::query(
            "DELETE FROM episode_deletions \
          WHERE account_id='aggregate-audit-gate-contract' AND episode_id=9100",
        )
        .execute(persistence.pool())
        .await
        .unwrap();
        let deletion_cleared = persistence.aggregate_audit(&since).await.unwrap();
        assert!(deletion_cleared.gates.activation_ready_for_drain);
        assert!(deletion_cleared.gates.ready_for_drain);

        sqlx::raw_sql(
            "INSERT INTO capture_sessions( \
                 account_id,id,device_id,install_id,started_at,last_event_at,ended_at,schema_version) \
             VALUES \
                 ('aggregate-audit-gate-contract','historical-ended','gate-device','gate-install', \
                  clock_timestamp()-interval '6 hours',clock_timestamp()-interval '5 hours', \
                  clock_timestamp()-interval '5 hours',2), \
                 ('aggregate-audit-gate-contract','historical-seal','gate-device','gate-install', \
                  clock_timestamp()-interval '6 hours',clock_timestamp()-interval '5 hours', \
                  clock_timestamp()-interval '5 hours',2); \
             INSERT INTO capture_streams( \
                 account_id,id,capture_session_id,device_id,stream_kind,committed_through_sequence) \
             VALUES \
                 ('aggregate-audit-gate-contract','historical-ended-stream','historical-ended', \
                  'gate-device','mac_screen',0), \
                 ('aggregate-audit-gate-contract','historical-seal-stream','historical-seal', \
                  'gate-device','mac_screen',0); \
             INSERT INTO capture_events( \
                 account_id,event_id,device_id,install_id,capture_session_id,stream_id,stream_kind, \
                 sequence,source_wall_at,source_monotonic_ns,started_at,ended_at,timezone_id, \
                 utc_offset_minutes,clock_uncertainty_ms,asset_id,manifest_digest,media_disposition) \
             VALUES \
                 ('aggregate-audit-gate-contract','historical-ended-event','gate-device', \
                  'gate-install','historical-ended','historical-ended-stream','mac_screen',0, \
                  clock_timestamp()-interval '5 hours','0',clock_timestamp()-interval '5 hours', \
                  clock_timestamp()-interval '5 hours','UTC',0,0,'historical-ended-asset', \
                  repeat('c',64),'canonical'), \
                 ('aggregate-audit-gate-contract','historical-seal-event','gate-device', \
                  'gate-install','historical-seal','historical-seal-stream','mac_screen',0, \
                  clock_timestamp()-interval '5 hours','0',clock_timestamp()-interval '5 hours', \
                  clock_timestamp()-interval '5 hours','UTC',0,0,'historical-seal-asset', \
                  repeat('d',64),'canonical'); \
             INSERT INTO capture_formation_receipts( \
                 account_id,capture_session_id,source_revision) \
             VALUES('aggregate-audit-gate-contract','historical-ended',1); \
             INSERT INTO capture_formation_receipts( \
                 account_id,capture_session_id,source_revision,completed_revision,state, \
                 completed_outcome,completed_claim_token,completed_source_fingerprint,completed_at, \
                 finish_requested_at,finish_request_provenance) \
             VALUES('aggregate-audit-gate-contract','historical-seal',1,1,'complete','no_memory', \
                    'historical-seal-claim',decode(repeat('cd',32),'hex'), \
                    clock_timestamp()-interval '5 hours',clock_timestamp()-interval '5 hours', \
                    'finish_endpoint_v1');",
        )
        .execute(persistence.pool())
        .await
        .unwrap();
        let installed_formation_debt = persistence.aggregate_audit(&since).await.unwrap();
        assert_eq!(
            installed_formation_debt
                .formation
                .ended_without_finish_receipts,
            1
        );
        assert_eq!(installed_formation_debt.formation.seal_pending_receipts, 1);
        assert!(!installed_formation_debt.gates.formation_quiescent);
        assert!(installed_formation_debt.gates.activation_ready_for_drain);
        assert!(installed_formation_debt.gates.ready_for_drain);
        assert!(!installed_formation_debt.gates.ready_for_active);

        let budget_job_id = sqlx::query_scalar::<_, i64>(
            "INSERT INTO media_processing_jobs( \
                 account_id,event_id,job_kind,input_revision,processor_version,state,error_code, \
                 updated_at) \
             VALUES('aggregate-audit-gate-contract','historical-ended-event','gemini_screen', \
                    'aggregate-audit-budget-input',1,'retry_wait','vertex_daily_budget', \
                    clock_timestamp()-interval '1 minute') RETURNING id",
        )
        .fetch_one(persistence.pool())
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO media_work_units( \
                 account_id,id,work_class,processor_version,state,started_at,ended_at, \
                 reserved_output_tokens,error_code,updated_at) \
             VALUES('aggregate-audit-gate-contract','budget-work','screen',1,'retry_wait', \
                    clock_timestamp()-interval '5 hours',clock_timestamp()-interval '5 hours', \
                    1024,'vertex_daily_budget',clock_timestamp()-interval '1 minute')",
        )
        .execute(persistence.pool())
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO media_work_members( \
                 account_id,work_unit_id,event_id,job_id,ordinal,window_start_ms,window_end_ms) \
             VALUES('aggregate-audit-gate-contract','budget-work','historical-ended-event', \
                    $1,0,0,1000)",
        )
        .bind(budget_job_id)
        .execute(persistence.pool())
        .await
        .unwrap();
        let budget_blocked = persistence.aggregate_audit(&since).await.unwrap();
        assert_eq!(budget_blocked.media.current_budget_jobs, 1);
        assert_eq!(budget_blocked.media.current_budget_work_units, 1);
        assert!(!budget_blocked.gates.media_budget_drained);
        assert!(!budget_blocked.gates.ready_for_drain);
        sqlx::raw_sql(
            "DELETE FROM media_work_units \
               WHERE account_id='aggregate-audit-gate-contract' AND id='budget-work'; \
             DELETE FROM media_processing_jobs \
               WHERE account_id='aggregate-audit-gate-contract' \
                 AND input_revision='aggregate-audit-budget-input';",
        )
        .execute(persistence.pool())
        .await
        .unwrap();

        sqlx::query(
            "UPDATE capture_events SET stream_kind='gate_invalid' \
              WHERE account_id='aggregate-audit-gate-contract' \
                AND event_id='historical-ended-event'",
        )
        .execute(persistence.pool())
        .await
        .unwrap();
        let domain_blocked = persistence.aggregate_audit(&since).await.unwrap();
        assert!(!domain_blocked.gates.domain_clean);
        assert!(!domain_blocked.gates.ready_for_drain);
        sqlx::query(
            "UPDATE capture_events SET stream_kind='mac_screen' \
              WHERE account_id='aggregate-audit-gate-contract' \
                AND event_id='historical-ended-event'",
        )
        .execute(persistence.pool())
        .await
        .unwrap();

        sqlx::query(
            "INSERT INTO usage_daily( \
                 account_id,day,vertex_requests,vertex_output_tokens, \
                 vertex_audio_output_tokens,vertex_screen_output_tokens, \
                 vertex_derived_output_tokens) \
             VALUES('aggregate-audit-gate-contract', \
                    ($1::timestamptz AT TIME ZONE 'UTC')::date,0,1,0,0,0)",
        )
        .bind(&since)
        .execute(persistence.pool())
        .await
        .unwrap();
        let quota_blocked = persistence.aggregate_audit(&since).await.unwrap();
        assert!(!quota_blocked.gates.quota_invariants_hold);
        assert!(quota_blocked.gates.provider_quiescent);
        assert!(!quota_blocked.gates.ready_for_drain);
        sqlx::query("DELETE FROM usage_daily WHERE account_id='aggregate-audit-gate-contract'")
            .execute(persistence.pool())
            .await
            .unwrap();

        sqlx::query(
            "INSERT INTO vertex_usage_events( \
                 account_id,event_id,request_fingerprint,operation,requested_model,location, \
                 outcome,observed_at) \
             VALUES('aggregate-audit-gate-contract','gate-provider-started', \
                    decode(repeat('ef',32),'hex'),'episode_reconciliation','gate-model', \
                    'us-central1','started',$1::timestamptz+interval '1 second')",
        )
        .bind(&since)
        .execute(persistence.pool())
        .await
        .unwrap();
        let provider_blocked = persistence.aggregate_audit(&since).await.unwrap();
        assert!(provider_blocked.gates.quota_invariants_hold);
        assert!(!provider_blocked.gates.provider_quiescent);
        assert!(!provider_blocked.gates.ready_for_drain);
        sqlx::query(
            "DELETE FROM vertex_usage_events \
              WHERE account_id='aggregate-audit-gate-contract' \
                AND event_id='gate-provider-started'",
        )
        .execute(persistence.pool())
        .await
        .unwrap();

        sqlx::raw_sql(
            "INSERT INTO media_processing_jobs( \
                 account_id,event_id,job_kind,input_revision,processor_version,state) \
             VALUES('aggregate-audit-gate-contract','historical-ended-event','gemini_screen', \
                    'aggregate-audit-lease-input',1,'processing'); \
             INSERT INTO media_work_units( \
                 account_id,id,work_class,processor_version,state,started_at,ended_at, \
                 reserved_output_tokens) \
             VALUES('aggregate-audit-gate-contract','lease-work','screen',1,'processing', \
                    clock_timestamp()-interval '5 hours',clock_timestamp()-interval '5 hours', \
                    1024);",
        )
        .execute(persistence.pool())
        .await
        .unwrap();
        let lease_blocked = persistence.aggregate_audit(&since).await.unwrap();
        assert!(!lease_blocked.gates.leases_unexpired);
        assert!(!lease_blocked.gates.ready_for_drain);
        sqlx::raw_sql(
            "DELETE FROM media_work_units \
               WHERE account_id='aggregate-audit-gate-contract' AND id='lease-work'; \
             DELETE FROM media_processing_jobs \
               WHERE account_id='aggregate-audit-gate-contract' \
                 AND input_revision='aggregate-audit-lease-input';",
        )
        .execute(persistence.pool())
        .await
        .unwrap();

        sqlx::query(
            "INSERT INTO memory_reconciliation_jobs( \
                 account_id,source_fingerprint,topology_fingerprint,predecessor_episode_ids, \
                 cohort_started_at,cohort_ended_at,state) \
             VALUES('aggregate-audit-gate-contract',decode(repeat('12',32),'hex'), \
                    decode(repeat('34',32),'hex'),ARRAY[1]::bigint[], \
                    clock_timestamp()-interval '6 hours', \
                    clock_timestamp()-interval '5 hours','pending')",
        )
        .execute(persistence.pool())
        .await
        .unwrap();
        let reconciliation_blocked = persistence.aggregate_audit(&since).await.unwrap();
        assert!(!reconciliation_blocked.gates.reconciliation_quiescent);
        assert!(!reconciliation_blocked.gates.ready_for_drain);
        sqlx::query(
            "DELETE FROM memory_reconciliation_jobs \
              WHERE account_id='aggregate-audit-gate-contract'",
        )
        .execute(persistence.pool())
        .await
        .unwrap();

        sqlx::query(
            "INSERT INTO episodes( \
                 account_id,id,started_at,ended_at,type,title,summary,structure_state, \
                 finalization_status,updated_at) \
             VALUES('aggregate-audit-gate-contract',9200,clock_timestamp()-interval '6 hours', \
                    clock_timestamp()-interval '5 hours','work','Finalization gate fixture', \
                    'Finalization gate fixture','reconciled','processing',clock_timestamp())",
        )
        .execute(persistence.pool())
        .await
        .unwrap();
        let finalization_blocked = persistence.aggregate_audit(&since).await.unwrap();
        assert!(!finalization_blocked.gates.finalization_claims_quiescent);
        assert!(!finalization_blocked.gates.ready_for_drain);
        sqlx::raw_sql(
            "DELETE FROM memory_handles \
               WHERE account_id='aggregate-audit-gate-contract' AND episode_id=9200; \
             DELETE FROM episodes \
               WHERE account_id='aggregate-audit-gate-contract' AND id=9200;",
        )
        .execute(persistence.pool())
        .await
        .unwrap();

        sqlx::query(
            "INSERT INTO episodes( \
                 account_id,id,started_at,ended_at,type,title,summary,structure_state, \
                 finalization_status,updated_at) \
             SELECT 'aggregate-audit-gate-contract',9300+value, \
                    clock_timestamp()-interval '6 hours',clock_timestamp()-interval '5 hours', \
                    'work','Capacity gate fixture','Capacity gate fixture','draft', \
                    'pending_horizon',clock_timestamp() \
               FROM generate_series(0,32) value",
        )
        .execute(persistence.pool())
        .await
        .unwrap();
        let capacity_blocked = persistence.aggregate_audit(&since).await.unwrap();
        assert!(!capacity_blocked.capacity.no_oversized_components);
        assert!(!capacity_blocked.gates.capacity_sufficient);
        assert!(!capacity_blocked.gates.ready_for_drain);
        sqlx::raw_sql(
            "DELETE FROM memory_handles \
               WHERE account_id='aggregate-audit-gate-contract' \
                 AND episode_id BETWEEN 9300 AND 9332; \
             DELETE FROM episodes \
               WHERE account_id='aggregate-audit-gate-contract' \
                 AND id BETWEEN 9300 AND 9332;",
        )
        .execute(persistence.pool())
        .await
        .unwrap();

        let predrain_clean = persistence.aggregate_audit(&since).await.unwrap();
        assert!(!predrain_clean.gates.formation_quiescent);
        assert!(predrain_clean.gates.ready_for_drain);

        sqlx::raw_sql(
            "INSERT INTO persistence_feature_activation_events( \
             feature,generation,previous_phase,phase,rollout_basis_points,rollout_seed, \
             explicit_canary_account_ids,candidate_fleet_image_digest, \
             reconciliation_producer_contract_sha256,reconciliation_model,vertex_location, \
             receipt,receipt_sha256,receipt_signature,receipt_key_sha256) \
         VALUES( \
             'episode_topology_reconciliation',1,'installed','draining',10000, \
             'sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', \
             ARRAY[]::text[], \
             'sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb', \
             'sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc', \
             'gate-model','us-central1', \
             jsonb_build_object( \
                 'generation',1,'previous_phase','installed','requested_phase','draining', \
                 'rollout_basis_points',10000, \
                 'rollout_seed', \
                    'sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', \
                 'explicit_canary_account_ids','[]'::jsonb, \
                 'candidate_fleet_image_digest', \
                    'sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb', \
                 'reconciliation_producer_contract_sha256', \
                    'sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc', \
                 'reconciliation_model','gate-model','vertex_location','us-central1'), \
             decode(repeat('11',32),'hex'),decode(repeat('22',64),'hex'), \
             decode(repeat('33',32),'hex')); \
         UPDATE persistence_feature_activation_backfills \
            SET refresh_generation=1,complete=true,completed_at=clock_timestamp(), \
                updated_at=clock_timestamp() \
          WHERE feature='episode_topology_reconciliation' \
            AND backfill_name='capture_formation_receipts'; \
         INSERT INTO persistence_feature_activation_drains( \
             feature,activation_generation,complete,completed_at) \
         VALUES('episode_topology_reconciliation',1,true,clock_timestamp()); \
         INSERT INTO persistence_feature_activation_assignments( \
             feature,account_id,activation_generation) \
         VALUES('episode_topology_reconciliation','aggregate-audit-gate-contract',1);",
        )
        .execute(persistence.pool())
        .await
        .unwrap();
        let draining_formation_debt = persistence.aggregate_audit(&since).await.unwrap();
        assert_eq!(
            draining_formation_debt
                .activation
                .scoped_draft_finalization_claims,
            0
        );
        assert!(draining_formation_debt.gates.activation_ready_for_active);
        assert!(!draining_formation_debt.gates.formation_quiescent);
        assert!(!draining_formation_debt.gates.ready_for_active);
        sqlx::query(
            "DELETE FROM capture_sessions \
              WHERE account_id='aggregate-audit-gate-contract' \
                AND id IN ('historical-ended','historical-seal')",
        )
        .execute(persistence.pool())
        .await
        .unwrap();
        let draining_clean = persistence.aggregate_audit(&since).await.unwrap();
        assert!(draining_clean.gates.formation_quiescent);
        assert!(draining_clean.gates.activation_ready_for_active);
        assert!(draining_clean.gates.ready_for_active);

        sqlx::raw_sql(
            "INSERT INTO episodes( \
             account_id,id,started_at,ended_at,type,title,summary,structure_state, \
             finalization_status,finalization_claim_token,finalization_claim_until,updated_at) \
         VALUES('aggregate-audit-gate-contract',9000,clock_timestamp()-interval '6 hours', \
                clock_timestamp()-interval '5 hours','work','Scoped draft fixture', \
                'Scoped draft fixture','draft','processing','scoped-draft-claim', \
                clock_timestamp()+interval '15 minutes',clock_timestamp()); \
         UPDATE memory_handles SET state='retired',origin_relation='non_memory', \
                retired_at=clock_timestamp() \
          WHERE account_id='aggregate-audit-gate-contract' AND episode_id=9000;",
        )
        .execute(persistence.pool())
        .await
        .unwrap();
        let scoped_draft_claim = persistence.aggregate_audit(&since).await.unwrap();
        assert_eq!(scoped_draft_claim.finalization.processing_claims, 0);
        assert_eq!(
            scoped_draft_claim
                .activation
                .scoped_draft_finalization_claims,
            1
        );
        assert!(!scoped_draft_claim.gates.activation_ready_for_active);
        sqlx::raw_sql(
            "DELETE FROM memory_handles \
          WHERE account_id='aggregate-audit-gate-contract' AND episode_id=9000; \
         DELETE FROM episodes \
          WHERE account_id='aggregate-audit-gate-contract' AND id=9000;",
        )
        .execute(persistence.pool())
        .await
        .unwrap();
        let claim_cleared = persistence.aggregate_audit(&since).await.unwrap();
        assert!(claim_cleared.gates.activation_ready_for_active);
        assert!(claim_cleared.gates.ready_for_active);
    }

    let mut value = serde_json::to_value(&report).unwrap();
    value
        .as_object_mut()
        .unwrap()
        .insert("unexpected".into(), serde_json::json!(0));
    assert!(serde_json::from_value::<PostgresAggregateAuditReport>(value).is_err());

    let too_old = sqlx::query_scalar::<_, String>(
        "SELECT to_char(clock_timestamp()-interval '49 hours', \
                        'YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"')",
    )
    .fetch_one(persistence.pool())
    .await
    .unwrap();
    assert_eq!(
        persistence.aggregate_audit(&too_old).await,
        Err(AggregateAuditFailure::SinceOutOfRange)
    );

    let mut transaction = persistence
        .begin_aggregate_audit_transaction()
        .await
        .unwrap();
    let settings = sqlx::query_as::<_, (String, String, String, String, String, String)>(
        "SELECT current_setting('transaction_isolation'), \
                current_setting('transaction_read_only'), \
                current_setting('statement_timeout'), \
                current_setting('lock_timeout'), \
                current_setting('idle_in_transaction_session_timeout'), \
                current_setting('TimeZone')",
    )
    .fetch_one(&mut *transaction)
    .await
    .unwrap();
    assert_eq!(
        settings,
        (
            "repeatable read".into(),
            "on".into(),
            "15s".into(),
            "2s".into(),
            "30s".into(),
            "UTC".into(),
        )
    );
    let mutation = sqlx::query(
        "INSERT INTO accounts(id,email,primary_provider,primary_subject) \
         VALUES('aggregate-audit-mutation-refused','refused@example.com','google','refused')",
    )
    .execute(&mut *transaction)
    .await
    .unwrap_err();
    assert_eq!(
        mutation
            .as_database_error()
            .and_then(|error| error.code())
            .as_deref(),
        Some("25006")
    );
    transaction.rollback().await.unwrap();
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT count(*) FROM accounts WHERE id='aggregate-audit-mutation-refused'",
        )
        .fetch_one(persistence.pool())
        .await
        .unwrap(),
        0
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    fn installed_gate_fixture() -> GateAudit {
        GateAudit {
            domain_clean: true,
            quota_invariants_hold: true,
            provider_quiescent: true,
            media_budget_drained: true,
            leases_unexpired: true,
            formation_quiescent: false,
            reconciliation_quiescent: true,
            finalization_claims_quiescent: true,
            activation_ready_for_drain: true,
            activation_ready_for_active: false,
            capacity_sufficient: true,
            ready_for_drain: true,
            ready_for_active: false,
        }
    }

    #[test]
    fn composite_readiness_stages_formation_after_drain_and_retains_other_gates() {
        let installed = installed_gate_fixture();
        assert!(installed.readiness_is_exact());
        assert!(installed.expected_ready_for_drain());
        assert!(!installed.expected_ready_for_active());

        type BlockGate = (&'static str, fn(&mut GateAudit));
        let shared_blockers: [BlockGate; 8] = [
            ("domain", |gate| gate.domain_clean = false),
            ("quota", |gate| gate.quota_invariants_hold = false),
            ("provider", |gate| gate.provider_quiescent = false),
            ("media budget", |gate| gate.media_budget_drained = false),
            ("lease", |gate| gate.leases_unexpired = false),
            ("reconciliation", |gate| {
                gate.reconciliation_quiescent = false;
            }),
            ("finalization claim", |gate| {
                gate.finalization_claims_quiescent = false;
            }),
            ("capacity", |gate| gate.capacity_sufficient = false),
        ];
        for (name, block) in shared_blockers {
            let mut blocked = installed_gate_fixture();
            block(&mut blocked);
            assert!(!blocked.expected_ready_for_drain(), "{name}");
            assert!(!blocked.readiness_is_exact(), "{name}");
            blocked.ready_for_drain = false;
            assert!(blocked.readiness_is_exact(), "{name}");
        }

        let mut stale_activation = installed_gate_fixture();
        stale_activation.activation_ready_for_drain = false;
        assert!(!stale_activation.expected_ready_for_drain());
        assert!(!stale_activation.readiness_is_exact());

        let mut draining = installed_gate_fixture();
        draining.activation_ready_for_drain = false;
        draining.activation_ready_for_active = true;
        draining.ready_for_drain = false;
        assert!(draining.readiness_is_exact());
        assert!(!draining.expected_ready_for_active());
        draining.formation_quiescent = true;
        assert!(!draining.readiness_is_exact());
        draining.ready_for_active = true;
        assert!(draining.readiness_is_exact());

        for (name, block) in shared_blockers {
            let mut blocked = draining.clone();
            block(&mut blocked);
            assert!(!blocked.expected_ready_for_active(), "{name}");
            assert!(!blocked.readiness_is_exact(), "{name}");
            blocked.ready_for_active = false;
            assert!(blocked.readiness_is_exact(), "{name}");
        }
    }

    #[test]
    fn since_is_exact_utc_seconds_with_real_calendar_validation() {
        for valid in [
            "2026-09-01T00:00:00Z",
            "2024-02-29T23:59:59Z",
            "2000-02-29T12:30:45Z",
        ] {
            assert_eq!(parse_postgres_audit_since(valid), Ok(()));
        }
        for invalid in [
            "",
            "2026-09-01t00:00:00Z",
            "2026-09-01T00:00:00+00:00",
            "2026-09-01T00:00:00.000Z",
            "2026-02-29T00:00:00Z",
            "2100-02-29T00:00:00Z",
            "2026-13-01T00:00:00Z",
            "2026-09-31T00:00:00Z",
            "2026-09-01T24:00:00Z",
            "2026-09-01T00:60:00Z",
            "2026-09-01T00:00:60Z",
        ] {
            assert_eq!(
                parse_postgres_audit_since(invalid),
                Err(AggregateAuditFailure::InvalidSince),
                "{invalid}"
            );
        }
    }

    #[test]
    fn failure_classes_are_fixed_and_content_free() {
        assert_eq!(
            [
                AggregateAuditFailure::InvalidArguments,
                AggregateAuditFailure::MissingConfiguration,
                AggregateAuditFailure::InvalidSince,
                AggregateAuditFailure::SinceOutOfRange,
                AggregateAuditFailure::PostgresUnavailable,
                AggregateAuditFailure::AuditFailed,
            ]
            .map(AggregateAuditFailure::as_str),
            [
                "invalid_arguments",
                "missing_configuration",
                "invalid_since",
                "since_out_of_range",
                "postgres_unavailable",
                "audit_failed",
            ]
        );
    }

    #[test]
    fn checked_in_fixture_is_the_exact_strict_contract() {
        let fixture = include_str!("aggregate_audit_fixture.json");
        let report: PostgresAggregateAuditReport = serde_json::from_str(fixture).unwrap();
        report.validate(&report.since).unwrap();
        let mut extra = serde_json::to_value(report).unwrap();
        extra
            .as_object_mut()
            .unwrap()
            .insert("unexpected".into(), serde_json::json!(0));
        assert!(serde_json::from_value::<PostgresAggregateAuditReport>(extra).is_err());
    }

    #[test]
    fn aggregate_query_has_one_parameter_and_no_arbitrary_surface() {
        assert!(AGGREGATE_AUDIT_SQL.contains("$1::timestamptz"));
        assert!(!AGGREGATE_AUDIT_SQL.contains("$2"));
        assert!(!AGGREGATE_AUDIT_SQL
            .to_ascii_lowercase()
            .contains("select *"));
        for prohibited_projection in [
            "'title'",
            "'summary'",
            "'minutes_text'",
            "'transcript'",
            "'payload'",
            "'requested_model'",
            "'returned_model'",
            "'last_error_code'",
            "'finalization_error'",
            "'account_id'",
            "'event_id'",
            "'claim_token'",
        ] {
            assert!(
                !AGGREGATE_AUDIT_SQL.contains(prohibited_projection),
                "query exposes prohibited projection: {prohibited_projection}"
            );
        }
    }

    #[test]
    fn aggregate_drain_projection_tracks_the_latest_draining_event() {
        assert!(AGGREGATE_AUDIT_SQL.contains("latest_draining_activation AS MATERIALIZED"));
        assert!(AGGREGATE_AUDIT_SQL.contains("AND event.phase='draining'"));
        assert!(AGGREGATE_AUDIT_SQL.contains("JOIN latest_draining_activation activation"));
        assert!(!AGGREGATE_AUDIT_SQL.contains("JOIN latest_activation activation\n"));
    }

    #[tokio::test]
    async fn postgres_aggregate_audit_contract() {
        let required = std::env::var("KIOKU_REQUIRE_POSTGRES_CONTRACT").as_deref() == Ok("1");
        let database_url = match std::env::var("KIOKU_TEST_POSTGRES_URL") {
            Ok(value) => value,
            Err(_) => {
                assert!(!required, "KIOKU_TEST_POSTGRES_URL is required");
                return;
            }
        };
        let base = PostgresPersistence::connect(super::super::PostgresPoolConfig {
            database_url,
            root_ca_pem: None,
            max_connections: 2,
            acquire_timeout: std::time::Duration::from_secs(5),
            statement_timeout: std::time::Duration::from_secs(15),
        })
        .await
        .unwrap();
        super::test_real_pg_aggregate_audit_isolated(&base).await;
        base.pool.close().await;
    }
}
