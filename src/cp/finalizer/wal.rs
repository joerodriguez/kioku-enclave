#![allow(
    dead_code,
    reason = "inactive ADR-0022 finalization-commit codec is reviewed before its B attempt boundary, launcher, or worker ownership"
)]

//! Inactive exact finalization-commit WAL domain.
//!
//! A future B boundary must first durably fix the Vertex attempt and every
//! outbound delivery identity. This child then authenticates one complete
//! episode predecessor, exact membership, and a commitment to the prior
//! generated product before replacing the brief and screen product, inserting
//! the already-fixed initial outbox rows, and completing the episode in the
//! same transaction as permanent replay. It allocates no identity or clock,
//! calls no Store, provider, worker, launcher, or acknowledgement path, and
//! cannot schedule or send a delivery.

use rusqlite::{params, types::ValueRef, Connection, OptionalExtension, Row, Transaction};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::archive_v3_wal_idempotency::{
    DomainLedgerBounds, LogicalMutationResult, PreparedLogicalMutation, WalIdempotencyError,
    WalLogicalDomainLedger, WalLogicalDomainPlan, WalLogicalOperationId, WalOperationKind,
    WalReplayResult,
};

const REQUEST_V1: u16 = 1;
const SUBTYPE: &[u8] = b"finalization-commit-v1";
// Codec v1 is permanently tied to the reviewed v5 finalization/screen product.
const TARGET_FINALIZATION_VERSION: i32 = 5;
const TARGET_OBSERVATION_VERSION: i32 = 3;
const TARGET_OBSERVATION_PROMPT_VERSION: i32 = 3;
const TARGET_INTERPRETATION_VERSION: i32 = 2;
const TARGET_INTERPRETATION_PROMPT_VERSION: i32 = 2;
const ENCODED_UNIT_RESULT_BYTES: usize = 9;
const MAX_TIMESTAMP_BYTES: usize = 64;
const MAX_MODEL_BYTES: usize = 256;
const MAX_BRIEF_FIELD_BYTES: usize = 256 * 1024;
const MAX_MEMBERS: usize = 4_096;
const MAX_SCREENS: usize = 512;
const MAX_DELIVERIES: usize = 512;
const MAX_ID_BYTES: usize = 128;
const SCHEMA_TABLE: &str = "archive_v3_wal_finalization_commit_schema";
const LEDGER_TABLE: &str = "archive_v3_wal_finalization_commit_operations";
const STATE_TABLE: &str = "archive_v3_wal_finalization_commit_state";
const MAX_ROWS: u32 = 1_048_576;
const MAX_RESULT_BYTES: u64 = 32 * 1024 * 1024;
const BOUNDS: DomainLedgerBounds = DomainLedgerBounds::new(MAX_ROWS, MAX_RESULT_BYTES);

type Result<T> = std::result::Result<T, WalIdempotencyError>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CommitMode {
    Initial,
    Regeneration,
}

#[derive(Clone, PartialEq, Eq)]
pub(super) struct FinalizationCommitPredecessor {
    finalized_at: Option<String>,
    finalization_version: Option<i32>,
    status: String,
    error: Option<String>,
    attempted_at: Option<String>,
    attempt_count: i64,
    next_attempt_at: Option<String>,
    updated_at: Option<String>,
    product_commitment: [u8; 32],
}

impl FinalizationCommitPredecessor {
    #[allow(clippy::too_many_arguments)]
    pub(super) fn new(
        finalized_at: Option<String>,
        finalization_version: Option<i32>,
        status: String,
        error: Option<String>,
        attempted_at: Option<String>,
        attempt_count: i64,
        next_attempt_at: Option<String>,
        updated_at: Option<String>,
        product_commitment: [u8; 32],
    ) -> Result<Self> {
        if status != "processing"
            || finalization_version.is_some_and(|version| version <= 0)
            || attempt_count < 0
        {
            return Err(WalIdempotencyError::Precondition);
        }
        if finalized_at.is_some()
            && finalization_version.unwrap_or(1) >= TARGET_FINALIZATION_VERSION
        {
            return Err(WalIdempotencyError::Precondition);
        }
        if error.as_deref().is_some_and(|value| {
            value.len() > 4_000 || value.chars().count() > 1_000 || value.contains('\0')
        }) {
            return Err(WalIdempotencyError::Malformed);
        }
        for value in [
            finalized_at.as_deref(),
            attempted_at.as_deref(),
            next_attempt_at.as_deref(),
            updated_at.as_deref(),
        ]
        .into_iter()
        .flatten()
        {
            validate_timestamp(value)?;
        }
        if attempted_at.is_none() || updated_at.is_none() {
            return Err(WalIdempotencyError::Precondition);
        }
        Ok(Self {
            finalized_at,
            finalization_version,
            status,
            error,
            attempted_at,
            attempt_count,
            next_attempt_at,
            updated_at,
            product_commitment,
        })
    }

    const fn mode(&self) -> CommitMode {
        if self.finalized_at.is_none() {
            CommitMode::Initial
        } else {
            CommitMode::Regeneration
        }
    }
}

#[derive(Clone, PartialEq, Eq)]
pub(super) struct FinalizationBrief {
    overview: String,
    decisions: String,
    action_items: String,
    important_links: String,
    open_questions: String,
}

impl FinalizationBrief {
    pub(super) fn new(
        overview: String,
        decisions: String,
        action_items: String,
        important_links: String,
        open_questions: String,
    ) -> Result<Self> {
        validate_text(&overview, MAX_BRIEF_FIELD_BYTES, true)?;
        for value in [&decisions, &action_items, &important_links, &open_questions] {
            validate_canonical_json_array(value, MAX_BRIEF_FIELD_BYTES)?;
        }
        Ok(Self {
            overview,
            decisions,
            action_items,
            important_links,
            open_questions,
        })
    }
}

#[derive(Clone, PartialEq, Eq)]
pub(super) struct FinalizationScreenResult {
    screenshot_id: i64,
    observation_revision: String,
    literal_description: String,
    screen_state: String,
    content_type: String,
    visible_text_summary: Option<String>,
    notable_items_json: String,
    activity_summary: Option<String>,
    relevance_level: i64,
    relevance_reason: String,
    milestone_type: String,
    base_score: i64,
    key_rank: Option<i64>,
    is_key_screen: bool,
    semantic_group: String,
}

impl FinalizationScreenResult {
    #[allow(clippy::too_many_arguments)]
    pub(super) fn new(
        screenshot_id: i64,
        observation_revision: String,
        literal_description: String,
        screen_state: String,
        content_type: String,
        visible_text_summary: Option<String>,
        notable_items_json: String,
        activity_summary: Option<String>,
        relevance_level: i64,
        relevance_reason: String,
        milestone_type: String,
        base_score: i64,
        key_rank: Option<i64>,
        is_key_screen: bool,
        semantic_group: String,
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
        const MILESTONES: &[&str] = &[
            "none",
            "topic_start",
            "decision",
            "action",
            "result",
            "resource",
            "demonstration",
            "problem",
            "resolution",
        ];
        if screenshot_id <= 0
            || !valid_lower_hex(&observation_revision, 64)
            || !valid_lower_hex(&semantic_group, 64)
            || !STATES.contains(&screen_state.as_str())
            || !TYPES.contains(&content_type.as_str())
            || !MILESTONES.contains(&milestone_type.as_str())
            || !(0..=3).contains(&relevance_level)
            || !(0..=100).contains(&base_score)
            || relevance_reason.trim().is_empty()
            || relevance_reason.chars().count() > 200
            || key_rank.is_some_and(|rank| rank <= 0)
            || key_rank.is_some() != is_key_screen
        {
            return Err(WalIdempotencyError::Malformed);
        }
        validate_chars(&literal_description, 280, true)?;
        validate_optional_chars(visible_text_summary.as_deref(), 200)?;
        validate_optional_chars(activity_summary.as_deref(), 280)?;
        let notable: serde_json::Value = validate_canonical_json_array(&notable_items_json, 4_000)?;
        let notable = notable.as_array().ok_or(WalIdempotencyError::Malformed)?;
        if notable.len() > 5
            || notable.iter().any(|value| {
                value
                    .as_str()
                    .is_none_or(|item| item.chars().count() > 120 || item.contains('\0'))
            })
        {
            return Err(WalIdempotencyError::Malformed);
        }
        Ok(Self {
            screenshot_id,
            observation_revision,
            literal_description,
            screen_state,
            content_type,
            visible_text_summary,
            notable_items_json,
            activity_summary,
            relevance_level,
            relevance_reason,
            milestone_type,
            base_score,
            key_rank,
            is_key_screen,
            semantic_group,
        })
    }
}

#[derive(Clone, PartialEq, Eq)]
pub(super) struct FinalizationWebhookDelivery {
    subscription_id: String,
    event_id: String,
}

impl FinalizationWebhookDelivery {
    pub(super) fn new(subscription_id: String, event_id: String) -> Result<Self> {
        validate_uuid(&subscription_id)?;
        validate_prefixed_hex(&event_id, "evt_")?;
        Ok(Self {
            subscription_id,
            event_id,
        })
    }
}

#[derive(Clone, PartialEq, Eq)]
pub(super) struct FinalizationEmailDelivery {
    delivery_id: String,
    include_content: bool,
}

impl FinalizationEmailDelivery {
    pub(super) fn new(delivery_id: String, include_content: bool) -> Result<Self> {
        validate_prefixed_hex(&delivery_id, "deliv_")?;
        Ok(Self {
            delivery_id,
            include_content,
        })
    }
}

#[derive(Clone, PartialEq, Eq)]
pub(super) struct FinalizationPushDelivery {
    installation_id: String,
    delivery_id: String,
    handoff_handle: String,
    collapse_id: String,
}

impl FinalizationPushDelivery {
    pub(super) fn new(
        installation_id: String,
        delivery_id: String,
        handoff_handle: String,
        collapse_id: String,
    ) -> Result<Self> {
        validate_uuid(&installation_id)?;
        validate_uuid(&delivery_id)?;
        validate_uuid(&collapse_id)?;
        if handoff_handle.len() != 43
            || !handoff_handle
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        {
            return Err(WalIdempotencyError::Malformed);
        }
        Ok(Self {
            installation_id,
            delivery_id,
            handoff_handle,
            collapse_id,
        })
    }
}

pub(crate) struct FinalizationCommitPlan {
    operation_id: WalLogicalOperationId,
    account_id: String,
    vertex_event_id: String,
    vertex_attempt_commitment: [u8; 32],
    episode_id: i64,
    committed_at: String,
    predecessor: FinalizationCommitPredecessor,
    utterance_members: Vec<i64>,
    screenshot_members: Vec<i64>,
    model_name: String,
    analysis_revision: String,
    brief: FinalizationBrief,
    screens: Vec<FinalizationScreenResult>,
    webhooks: Vec<FinalizationWebhookDelivery>,
    email: Option<FinalizationEmailDelivery>,
    pushes: Vec<FinalizationPushDelivery>,
}

impl FinalizationCommitPlan {
    #[allow(clippy::too_many_arguments)]
    pub(super) fn new(
        account_id: String,
        vertex_event_id: String,
        vertex_attempt_commitment: [u8; 32],
        episode_id: i64,
        committed_at: String,
        predecessor: FinalizationCommitPredecessor,
        utterance_members: Vec<i64>,
        screenshot_members: Vec<i64>,
        model_name: String,
        analysis_revision: String,
        brief: FinalizationBrief,
        screens: Vec<FinalizationScreenResult>,
        webhooks: Vec<FinalizationWebhookDelivery>,
        email: Option<FinalizationEmailDelivery>,
        pushes: Vec<FinalizationPushDelivery>,
    ) -> Result<Self> {
        validate_uuid(&account_id)?;
        validate_prefixed_hex(&vertex_event_id, "vtx_")?;
        validate_canonical_timestamp(&committed_at)?;
        if episode_id <= 0
            || !valid_lower_hex(&analysis_revision, 64)
            || model_name.is_empty()
            || model_name.len() > MAX_MODEL_BYTES
            || !super::super::vertex_model_name_is_billing_safe(&model_name)
        {
            return Err(WalIdempotencyError::Malformed);
        }
        validate_sorted_ids(&utterance_members, MAX_MEMBERS)?;
        validate_sorted_ids(&screenshot_members, MAX_MEMBERS)?;
        if screens.len() > MAX_SCREENS
            || webhooks.len() > MAX_DELIVERIES
            || pushes.len() > MAX_DELIVERIES
        {
            return Err(WalIdempotencyError::Limit);
        }
        let screen_ids = screens
            .iter()
            .map(|screen| screen.screenshot_id)
            .collect::<Vec<_>>();
        validate_sorted_ids(&screen_ids, MAX_SCREENS)?;
        if screen_ids
            .iter()
            .any(|id| screenshot_members.binary_search(id).is_err())
        {
            return Err(WalIdempotencyError::Precondition);
        }
        validate_key_ranks(&screens)?;
        validate_webhooks(&webhooks)?;
        validate_pushes(&pushes)?;
        if predecessor.mode() == CommitMode::Regeneration
            && (!webhooks.is_empty() || email.is_some() || !pushes.is_empty())
        {
            return Err(WalIdempotencyError::Precondition);
        }
        let committed_millis = timestamp_millis(&committed_at)?;
        for value in [
            predecessor.finalized_at.as_deref(),
            predecessor.attempted_at.as_deref(),
            predecessor.updated_at.as_deref(),
        ]
        .into_iter()
        .flatten()
        {
            if timestamp_millis(value)? > committed_millis {
                return Err(WalIdempotencyError::Precondition);
            }
        }
        let operation_id = WalLogicalOperationId::from_stable_source(
            WalOperationKind::FinalizationCommit,
            vertex_event_id.as_bytes(),
        )?;
        Ok(Self {
            operation_id,
            account_id,
            vertex_event_id,
            vertex_attempt_commitment,
            episode_id,
            committed_at,
            predecessor,
            utterance_members,
            screenshot_members,
            model_name,
            analysis_revision,
            brief,
            screens,
            webhooks,
            email,
            pushes,
        })
    }
}

pub(crate) struct FinalizationCommitLedger;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum LedgerSchemaState {
    Absent,
    Present,
}

impl WalLogicalDomainPlan for FinalizationCommitPlan {
    type Ledger = FinalizationCommitLedger;
    type Output = ();

    fn kind(&self) -> WalOperationKind {
        WalOperationKind::FinalizationCommit
    }

    fn operation_id(&self) -> WalLogicalOperationId {
        self.operation_id
    }

    fn canonical_request(&self) -> Result<Zeroizing<Vec<u8>>> {
        let mut request = Zeroizing::new(Vec::with_capacity(64 * 1024));
        request.extend_from_slice(&REQUEST_V1.to_be_bytes());
        encode_bytes(&mut request, SUBTYPE)?;
        encode_string(&mut request, &self.account_id)?;
        encode_string(&mut request, &self.vertex_event_id)?;
        request.extend_from_slice(&self.vertex_attempt_commitment);
        request.extend_from_slice(&self.episode_id.to_be_bytes());
        request.extend_from_slice(&TARGET_FINALIZATION_VERSION.to_be_bytes());
        request.extend_from_slice(&TARGET_OBSERVATION_VERSION.to_be_bytes());
        request.extend_from_slice(&TARGET_OBSERVATION_PROMPT_VERSION.to_be_bytes());
        request.extend_from_slice(&TARGET_INTERPRETATION_VERSION.to_be_bytes());
        request.extend_from_slice(&TARGET_INTERPRETATION_PROMPT_VERSION.to_be_bytes());
        encode_string(&mut request, &self.committed_at)?;
        encode_predecessor(&mut request, &self.predecessor)?;
        encode_i64_vec(&mut request, &self.utterance_members)?;
        encode_i64_vec(&mut request, &self.screenshot_members)?;
        encode_string(&mut request, &self.model_name)?;
        encode_string(&mut request, &self.analysis_revision)?;
        encode_brief(&mut request, &self.brief)?;
        encode_len(&mut request, self.screens.len())?;
        for screen in &self.screens {
            encode_screen(&mut request, screen)?;
        }
        encode_len(&mut request, self.webhooks.len())?;
        for delivery in &self.webhooks {
            encode_string(&mut request, &delivery.subscription_id)?;
            encode_string(&mut request, &delivery.event_id)?;
        }
        match &self.email {
            None => request.push(0),
            Some(delivery) => {
                request.push(1);
                encode_string(&mut request, &delivery.delivery_id)?;
                request.push(u8::from(delivery.include_content));
            }
        }
        encode_len(&mut request, self.pushes.len())?;
        for delivery in &self.pushes {
            encode_string(&mut request, &delivery.installation_id)?;
            encode_string(&mut request, &delivery.delivery_id)?;
            encode_string(&mut request, &delivery.handoff_handle)?;
            encode_string(&mut request, &delivery.collapse_id)?;
        }
        Ok(request)
    }

    fn apply(&self, transaction: &Transaction<'_>) -> Result<WalReplayResult> {
        if current_vertex_attempt_commitment(transaction, &self.vertex_event_id, &self.model_name)?
            != self.vertex_attempt_commitment
        {
            return Err(WalIdempotencyError::Precondition);
        }
        let stored =
            load_episode(transaction, self.episode_id)?.ok_or(WalIdempotencyError::Precondition)?;
        if !stored.matches_predecessor(&self.predecessor) {
            return Err(WalIdempotencyError::Precondition);
        }
        let utterances = load_members(transaction, self.episode_id, "utterance")?;
        let screenshots = load_members(transaction, self.episode_id, "screenshot")?;
        if utterances != self.utterance_members || screenshots != self.screenshot_members {
            return Err(WalIdempotencyError::Precondition);
        }
        let canonical_screens = load_canonical_screen_members(transaction, self.episode_id)?;
        if canonical_screens
            != self
                .screens
                .iter()
                .map(|screen| screen.screenshot_id)
                .collect::<Vec<_>>()
        {
            return Err(WalIdempotencyError::Precondition);
        }
        if current_product_commitment(transaction, self.episode_id)?
            != self.predecessor.product_commitment
        {
            return Err(WalIdempotencyError::Precondition);
        }
        ensure_delivery_preconditions(transaction, self)?;

        transaction
            .execute(
                "DELETE FROM episode_screen_interpretations WHERE episode_id=?1",
                [self.episode_id],
            )
            .map_err(|_| WalIdempotencyError::Unavailable)?;
        for screen in &self.screens {
            write_screen_product(transaction, self, screen)?;
        }
        write_interpretation_job(transaction, self)?;
        write_brief(transaction, self)?;
        write_deliveries(transaction, self)?;
        let changed = transaction
            .execute(
                "UPDATE episodes
                 SET finalized_at=COALESCE(finalized_at,?1),
                     finalization_version=?2,finalization_status='complete',
                     finalization_error=NULL,finalization_attempt_count=0,
                     finalization_next_attempt_at=NULL,updated_at=?1
                 WHERE id=?3 AND finalized_at IS ?4 AND finalization_version IS ?5
                   AND finalization_status=?6 AND finalization_error IS ?7
                   AND finalization_attempted_at IS ?8
                   AND finalization_attempt_count=?9
                   AND finalization_next_attempt_at IS ?10 AND updated_at IS ?11",
                params![
                    self.committed_at,
                    TARGET_FINALIZATION_VERSION,
                    self.episode_id,
                    self.predecessor.finalized_at,
                    self.predecessor.finalization_version,
                    self.predecessor.status,
                    self.predecessor.error,
                    self.predecessor.attempted_at,
                    self.predecessor.attempt_count,
                    self.predecessor.next_attempt_at,
                    self.predecessor.updated_at,
                ],
            )
            .map_err(|_| WalIdempotencyError::Unavailable)?;
        if changed != 1 {
            return Err(WalIdempotencyError::Corrupt);
        }
        verify_final_state(transaction, self)?;
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

impl WalLogicalDomainLedger<FinalizationCommitPlan> for FinalizationCommitLedger {
    fn lookup(
        connection: &Connection,
        prepared: &PreparedLogicalMutation<FinalizationCommitPlan>,
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
                 FROM archive_v3_wal_finalization_commit_operations
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
        let kind = WalOperationKind::FinalizationCommit;
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
        prepared: &PreparedLogicalMutation<FinalizationCommitPlan>,
    ) -> Result<LogicalMutationResult> {
        require_kind(prepared)?;
        ensure_schema(transaction)?;
        if let Some(result) = Self::lookup(transaction, prepared)? {
            return Ok(LogicalMutationResult::Replayed(result));
        }
        let (row_count, result_bytes) = load_ledger_state(transaction)?;
        BOUNDS.admit(row_count, result_bytes, ENCODED_UNIT_RESULT_BYTES)?;
        let kind = WalOperationKind::FinalizationCommit;
        let result = prepared.plan_for_domain_ledger().apply(transaction)?;
        prepared.plan_for_domain_ledger().validate_replay(&result)?;
        let encoded = result.encode(kind)?;
        if encoded.len() != ENCODED_UNIT_RESULT_BYTES {
            return Err(WalIdempotencyError::Corrupt);
        }
        let commitment = result.commitment(kind)?;
        transaction
            .execute(
                "INSERT INTO archive_v3_wal_finalization_commit_operations
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
                "UPDATE archive_v3_wal_finalization_commit_state
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
        Ok(LogicalMutationResult::Applied(result))
    }
}

#[derive(PartialEq, Eq)]
struct StoredEpisode {
    finalized_at: Option<String>,
    finalization_version: Option<i32>,
    status: String,
    error: Option<String>,
    attempted_at: Option<String>,
    attempt_count: i64,
    next_attempt_at: Option<String>,
    updated_at: Option<String>,
}

#[derive(PartialEq, Eq)]
struct StoredInterpretation {
    episode_revision: String,
    interpretation_version: i32,
    status: String,
    activity_summary: Option<String>,
    relevance_level: i64,
    relevance_reason: Option<String>,
    milestone_type: String,
    base_score: i64,
    key_rank: Option<i64>,
    is_key_screen: i64,
    semantic_group: Option<String>,
    model_name: Option<String>,
    prompt_version: i32,
    completed_at: String,
    updated_at: String,
}

impl StoredEpisode {
    fn from_row(row: &Row<'_>) -> rusqlite::Result<Self> {
        Ok(Self {
            finalized_at: row.get(0)?,
            finalization_version: row.get(1)?,
            status: row.get(2)?,
            error: row.get(3)?,
            attempted_at: row.get(4)?,
            attempt_count: row.get(5)?,
            next_attempt_at: row.get(6)?,
            updated_at: row.get(7)?,
        })
    }

    fn matches_predecessor(&self, predecessor: &FinalizationCommitPredecessor) -> bool {
        self.finalized_at == predecessor.finalized_at
            && self.finalization_version == predecessor.finalization_version
            && self.status == predecessor.status
            && self.error == predecessor.error
            && self.attempted_at == predecessor.attempted_at
            && self.attempt_count == predecessor.attempt_count
            && self.next_attempt_at == predecessor.next_attempt_at
            && self.updated_at == predecessor.updated_at
    }
}

fn load_episode(connection: &Connection, episode_id: i64) -> Result<Option<StoredEpisode>> {
    connection
        .query_row(
            "SELECT finalized_at,finalization_version,finalization_status,
                    finalization_error,finalization_attempted_at,
                    finalization_attempt_count,finalization_next_attempt_at,updated_at
             FROM episodes WHERE id=?1",
            [episode_id],
            StoredEpisode::from_row,
        )
        .optional()
        .map_err(|_| WalIdempotencyError::Unavailable)
}

fn load_members(connection: &Connection, episode_id: i64, kind: &str) -> Result<Vec<i64>> {
    let mut statement = connection
        .prepare(
            "SELECT record_id FROM episode_members
             WHERE episode_id=?1 AND record_type=?2 ORDER BY record_id",
        )
        .map_err(|_| WalIdempotencyError::Unavailable)?;
    let rows = statement
        .query_map(params![episode_id, kind], |row| row.get::<_, i64>(0))
        .map_err(|_| WalIdempotencyError::Unavailable)?;
    rows.collect::<rusqlite::Result<Vec<_>>>()
        .map_err(|_| WalIdempotencyError::Unavailable)
}

fn load_canonical_screen_members(connection: &Connection, episode_id: i64) -> Result<Vec<i64>> {
    let mut statement = connection
        .prepare(
            "SELECT s.id FROM screenshots s
             JOIN episode_members m ON m.record_type='screenshot' AND m.record_id=s.id
             WHERE m.episode_id=?1 AND s.is_duplicate=0 ORDER BY s.id",
        )
        .map_err(|_| WalIdempotencyError::Unavailable)?;
    let rows = statement
        .query_map([episode_id], |row| row.get::<_, i64>(0))
        .map_err(|_| WalIdempotencyError::Unavailable)?;
    rows.collect::<rusqlite::Result<Vec<_>>>()
        .map_err(|_| WalIdempotencyError::Unavailable)
}

pub(super) fn current_vertex_attempt_commitment(
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
    let operation = row
        .get::<_, String>(1)
        .map_err(|_| WalIdempotencyError::Unavailable)?;
    let requested_model = row
        .get::<_, String>(2)
        .map_err(|_| WalIdempotencyError::Unavailable)?;
    let returned_model = row
        .get::<_, Option<String>>(3)
        .map_err(|_| WalIdempotencyError::Unavailable)?;
    let location = row
        .get::<_, String>(4)
        .map_err(|_| WalIdempotencyError::Unavailable)?;
    let traffic_type = row
        .get::<_, String>(5)
        .map_err(|_| WalIdempotencyError::Unavailable)?;
    let http_status = row
        .get::<_, Option<i64>>(6)
        .map_err(|_| WalIdempotencyError::Unavailable)?;
    let outcome = row
        .get::<_, String>(18)
        .map_err(|_| WalIdempotencyError::Unavailable)?;
    let observed_at = row
        .get::<_, String>(19)
        .map_err(|_| WalIdempotencyError::Unavailable)?;
    if operation != "episode_finalization"
        || requested_model != expected_model
        || !matches!(outcome.as_str(), "metered" | "usage_missing")
        || http_status != Some(200)
        || location.is_empty()
        || location.len() > 128
        || !matches!(
            traffic_type.as_str(),
            "on_demand" | "batch" | "provisioned_throughput"
        )
        || returned_model.as_deref().is_some_and(|model| {
            model.len() > MAX_MODEL_BYTES || !super::super::vertex_model_name_is_billing_safe(model)
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
    hasher.update(b"archive-v3-finalization-vertex-attempt-v1\0");
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

pub(super) fn current_product_commitment(
    connection: &Connection,
    episode_id: i64,
) -> Result<[u8; 32]> {
    let mut hasher = Sha256::new();
    hasher.update(b"archive-v3-finalization-product-predecessor-v1\0");
    for (marker, query) in [
        (
            b"brief".as_slice(),
            "SELECT overview,decisions,action_items,important_links,open_questions,created_at
             FROM episode_final_briefs WHERE episode_id=?1 ORDER BY episode_id",
        ),
        (
            b"observations".as_slice(),
            "SELECT o.screenshot_id,o.input_revision,o.observation_version,o.status,
                    o.generation_method,o.literal_description,o.screen_state,o.content_type,
                    o.visible_text_summary,o.notable_items_json,o.model_name,o.prompt_version,
                    o.completed_at
             FROM screen_observations o JOIN episode_members m
               ON m.record_type='screenshot' AND m.record_id=o.screenshot_id
             WHERE m.episode_id=?1 ORDER BY o.screenshot_id",
        ),
        (
            b"observation-jobs".as_slice(),
            "SELECT j.screenshot_id,j.input_revision,j.observation_version,j.state,
                    j.attempt_count,j.error_code,j.updated_at
             FROM screen_observation_jobs j JOIN episode_members m
               ON m.record_type='screenshot' AND m.record_id=j.screenshot_id
             WHERE m.episode_id=?1 ORDER BY j.screenshot_id",
        ),
        (
            b"interpretations".as_slice(),
            "SELECT episode_id,screenshot_id,episode_revision,interpretation_version,status,
                    activity_summary,relevance_level,relevance_reason,milestone_type,base_score,
                    key_rank,is_key_screen,semantic_group,model_name,prompt_version,
                    completed_at,updated_at
             FROM episode_screen_interpretations WHERE episode_id=?1 ORDER BY screenshot_id",
        ),
        (
            b"interpretation-job".as_slice(),
            "SELECT episode_id,episode_revision,interpretation_version,state,attempt_count,
                    error_code,updated_at
             FROM episode_screen_interpretation_jobs WHERE episode_id=?1 ORDER BY episode_id",
        ),
    ] {
        hash_query(connection, &mut hasher, marker, query, episode_id)?;
    }
    Ok(hasher.finalize().into())
}

fn hash_query(
    connection: &Connection,
    hasher: &mut Sha256,
    marker: &[u8],
    query: &str,
    episode_id: i64,
) -> Result<()> {
    hasher.update((marker.len() as u64).to_be_bytes());
    hasher.update(marker);
    let mut statement = connection
        .prepare(query)
        .map_err(|_| WalIdempotencyError::Unavailable)?;
    let column_count = statement.column_count();
    let mut rows = statement
        .query([episode_id])
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

fn ensure_delivery_preconditions(
    transaction: &Transaction<'_>,
    plan: &FinalizationCommitPlan,
) -> Result<()> {
    if plan.predecessor.mode() == CommitMode::Regeneration {
        return Ok(());
    }
    for table in ["webhook_deliveries", "email_deliveries", "push_deliveries"] {
        let sql =
            format!("SELECT COUNT(*) FROM {table} WHERE episode_id=?1 AND delivery_version=?2");
        let count = transaction
            .query_row(
                &sql,
                params![plan.episode_id, TARGET_FINALIZATION_VERSION],
                |row| row.get::<_, i64>(0),
            )
            .map_err(|_| WalIdempotencyError::Unavailable)?;
        if count != 0 {
            return Err(WalIdempotencyError::Precondition);
        }
    }
    for delivery in &plan.webhooks {
        require_unique_absent(
            transaction,
            "webhook_deliveries",
            "event_id",
            &delivery.event_id,
        )?;
    }
    if let Some(delivery) = &plan.email {
        require_unique_absent(
            transaction,
            "email_deliveries",
            "delivery_id",
            &delivery.delivery_id,
        )?;
    }
    for delivery in &plan.pushes {
        require_unique_absent(
            transaction,
            "push_deliveries",
            "delivery_id",
            &delivery.delivery_id,
        )?;
        require_unique_absent(
            transaction,
            "push_deliveries",
            "handoff_handle",
            &delivery.handoff_handle,
        )?;
    }
    Ok(())
}

fn require_unique_absent(
    transaction: &Transaction<'_>,
    table: &str,
    column: &str,
    value: &str,
) -> Result<()> {
    let sql = format!("SELECT COUNT(*) FROM {table} WHERE {column}=?1");
    let count = transaction
        .query_row(&sql, [value], |row| row.get::<_, i64>(0))
        .map_err(|_| WalIdempotencyError::Unavailable)?;
    if count != 0 {
        return Err(WalIdempotencyError::Precondition);
    }
    Ok(())
}

fn write_screen_product(
    transaction: &Transaction<'_>,
    plan: &FinalizationCommitPlan,
    screen: &FinalizationScreenResult,
) -> Result<()> {
    transaction
        .execute(
            "INSERT INTO screen_observations
             (screenshot_id,input_revision,observation_version,status,generation_method,
              literal_description,screen_state,content_type,visible_text_summary,
              notable_items_json,model_name,prompt_version,completed_at)
             VALUES (?1,?2,?3,'ready','episode_model',?4,?5,?6,?7,?8,?9,?10,?11)
             ON CONFLICT(screenshot_id) DO UPDATE SET
               input_revision=excluded.input_revision,
               observation_version=excluded.observation_version,status='ready',
               generation_method='episode_model',literal_description=excluded.literal_description,
               screen_state=excluded.screen_state,content_type=excluded.content_type,
               visible_text_summary=excluded.visible_text_summary,
               notable_items_json=excluded.notable_items_json,model_name=excluded.model_name,
               prompt_version=excluded.prompt_version,completed_at=excluded.completed_at",
            params![
                screen.screenshot_id,
                screen.observation_revision,
                TARGET_OBSERVATION_VERSION,
                screen.literal_description,
                screen.screen_state,
                screen.content_type,
                screen.visible_text_summary,
                screen.notable_items_json,
                plan.model_name,
                TARGET_OBSERVATION_PROMPT_VERSION,
                plan.committed_at,
            ],
        )
        .map_err(|_| WalIdempotencyError::Unavailable)?;
    transaction
        .execute(
            "INSERT INTO screen_observation_jobs
             (screenshot_id,input_revision,observation_version,state,attempt_count,error_code,updated_at)
             VALUES (?1,?2,?3,'ready',0,NULL,?4)
             ON CONFLICT(screenshot_id) DO UPDATE SET
               input_revision=excluded.input_revision,
               observation_version=excluded.observation_version,state='ready',
               attempt_count=0,error_code=NULL,updated_at=excluded.updated_at",
            params![
                screen.screenshot_id,
                screen.observation_revision,
                TARGET_OBSERVATION_VERSION,
                plan.committed_at,
            ],
        )
        .map_err(|_| WalIdempotencyError::Unavailable)?;
    transaction
        .execute(
            "INSERT INTO episode_screen_interpretations
             (episode_id,screenshot_id,episode_revision,interpretation_version,status,
              activity_summary,relevance_level,relevance_reason,milestone_type,base_score,
              key_rank,is_key_screen,semantic_group,model_name,prompt_version,
              completed_at,updated_at)
             VALUES (?1,?2,?3,?4,'ready',?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?15)",
            params![
                plan.episode_id,
                screen.screenshot_id,
                plan.analysis_revision,
                TARGET_INTERPRETATION_VERSION,
                screen.activity_summary,
                screen.relevance_level,
                screen.relevance_reason,
                screen.milestone_type,
                screen.base_score,
                screen.key_rank,
                i64::from(screen.is_key_screen),
                screen.semantic_group,
                plan.model_name,
                TARGET_INTERPRETATION_PROMPT_VERSION,
                plan.committed_at,
            ],
        )
        .map_err(|_| WalIdempotencyError::Unavailable)?;
    Ok(())
}

fn write_interpretation_job(
    transaction: &Transaction<'_>,
    plan: &FinalizationCommitPlan,
) -> Result<()> {
    transaction
        .execute(
            "INSERT INTO episode_screen_interpretation_jobs
             (episode_id,episode_revision,interpretation_version,state,attempt_count,error_code,updated_at)
             VALUES (?1,?2,?3,'ready',0,NULL,?4)
             ON CONFLICT(episode_id) DO UPDATE SET
               episode_revision=excluded.episode_revision,
               interpretation_version=excluded.interpretation_version,state='ready',
               attempt_count=0,error_code=NULL,updated_at=excluded.updated_at",
            params![
                plan.episode_id,
                plan.analysis_revision,
                TARGET_INTERPRETATION_VERSION,
                plan.committed_at,
            ],
        )
        .map_err(|_| WalIdempotencyError::Unavailable)?;
    Ok(())
}

fn write_brief(transaction: &Transaction<'_>, plan: &FinalizationCommitPlan) -> Result<()> {
    transaction
        .execute(
            "INSERT INTO episode_final_briefs
             (episode_id,overview,decisions,action_items,important_links,open_questions,created_at)
             VALUES (?1,?2,?3,?4,?5,?6,?7)
             ON CONFLICT(episode_id) DO UPDATE SET
               overview=excluded.overview,decisions=excluded.decisions,
               action_items=excluded.action_items,important_links=excluded.important_links,
               open_questions=excluded.open_questions,created_at=excluded.created_at",
            params![
                plan.episode_id,
                plan.brief.overview,
                plan.brief.decisions,
                plan.brief.action_items,
                plan.brief.important_links,
                plan.brief.open_questions,
                plan.committed_at,
            ],
        )
        .map_err(|_| WalIdempotencyError::Unavailable)?;
    Ok(())
}

fn write_deliveries(transaction: &Transaction<'_>, plan: &FinalizationCommitPlan) -> Result<()> {
    if plan.predecessor.mode() == CommitMode::Regeneration {
        return Ok(());
    }
    for delivery in &plan.webhooks {
        transaction
            .execute(
                "INSERT INTO webhook_deliveries
                 (episode_id,subscription_id,delivery_version,event_id,state,attempt_count,
                  next_attempt_at,response_status,error_code,created_at,updated_at)
                 VALUES (?1,?2,?3,?4,'pending',0,NULL,NULL,NULL,?5,?5)",
                params![
                    plan.episode_id,
                    delivery.subscription_id,
                    TARGET_FINALIZATION_VERSION,
                    delivery.event_id,
                    plan.committed_at,
                ],
            )
            .map_err(|_| WalIdempotencyError::Unavailable)?;
    }
    if let Some(delivery) = &plan.email {
        transaction
            .execute(
                "INSERT INTO email_deliveries
                 (episode_id,delivery_version,delivery_id,include_content,state,attempt_count,
                  next_attempt_at,provider_message_id,response_status,error_code,created_at,updated_at)
                 VALUES (?1,?2,?3,?4,'pending',0,?5,NULL,NULL,NULL,?5,?5)",
                params![
                    plan.episode_id,
                    TARGET_FINALIZATION_VERSION,
                    delivery.delivery_id,
                    i64::from(delivery.include_content),
                    plan.committed_at,
                ],
            )
            .map_err(|_| WalIdempotencyError::Unavailable)?;
    }
    for delivery in &plan.pushes {
        transaction
            .execute(
                "INSERT INTO push_deliveries
                 (episode_id,installation_id,delivery_version,delivery_id,handoff_handle,
                  collapse_id,state,attempt_count,next_attempt_at,response_status,error_code,
                  created_at,updated_at)
                 VALUES (?1,?2,?3,?4,?5,?6,'pending',0,?7,NULL,NULL,?7,?7)",
                params![
                    plan.episode_id,
                    delivery.installation_id,
                    TARGET_FINALIZATION_VERSION,
                    delivery.delivery_id,
                    delivery.handoff_handle,
                    delivery.collapse_id,
                    plan.committed_at,
                ],
            )
            .map_err(|_| WalIdempotencyError::Unavailable)?;
    }
    Ok(())
}

fn verify_final_state(transaction: &Transaction<'_>, plan: &FinalizationCommitPlan) -> Result<()> {
    let episode =
        load_episode(transaction, plan.episode_id)?.ok_or(WalIdempotencyError::Corrupt)?;
    let expected_finalized_at = plan
        .predecessor
        .finalized_at
        .as_deref()
        .unwrap_or(&plan.committed_at);
    if episode.finalized_at.as_deref() != Some(expected_finalized_at)
        || episode.finalization_version != Some(TARGET_FINALIZATION_VERSION)
        || episode.status != "complete"
        || episode.error.is_some()
        || episode.attempted_at != plan.predecessor.attempted_at
        || episode.attempt_count != 0
        || episode.next_attempt_at.is_some()
        || episode.updated_at.as_deref() != Some(&plan.committed_at)
    {
        return Err(WalIdempotencyError::Corrupt);
    }
    let brief = transaction
        .query_row(
            "SELECT overview,decisions,action_items,important_links,open_questions,created_at
             FROM episode_final_briefs WHERE episode_id=?1",
            [plan.episode_id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, String>(5)?,
                ))
            },
        )
        .map_err(|_| WalIdempotencyError::Corrupt)?;
    if brief
        != (
            plan.brief.overview.clone(),
            plan.brief.decisions.clone(),
            plan.brief.action_items.clone(),
            plan.brief.important_links.clone(),
            plan.brief.open_questions.clone(),
            plan.committed_at.clone(),
        )
    {
        return Err(WalIdempotencyError::Corrupt);
    }
    let interpretation_count = transaction
        .query_row(
            "SELECT COUNT(*) FROM episode_screen_interpretations WHERE episode_id=?1",
            [plan.episode_id],
            |row| row.get::<_, i64>(0),
        )
        .map_err(|_| WalIdempotencyError::Corrupt)?;
    if usize::try_from(interpretation_count).ok() != Some(plan.screens.len()) {
        return Err(WalIdempotencyError::Corrupt);
    }
    for screen in &plan.screens {
        verify_screen(transaction, plan, screen)?;
    }
    verify_interpretation_job(transaction, plan)?;
    verify_deliveries(transaction, plan)?;
    Ok(())
}

fn verify_screen(
    transaction: &Transaction<'_>,
    plan: &FinalizationCommitPlan,
    screen: &FinalizationScreenResult,
) -> Result<()> {
    let observation = transaction
        .query_row(
            "SELECT input_revision,observation_version,status,generation_method,
                    literal_description,screen_state,content_type,visible_text_summary,
                    notable_items_json,model_name,prompt_version,completed_at
             FROM screen_observations WHERE screenshot_id=?1",
            [screen.screenshot_id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, i32>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, String>(6)?,
                    row.get::<_, Option<String>>(7)?,
                    row.get::<_, String>(8)?,
                    row.get::<_, Option<String>>(9)?,
                    row.get::<_, i32>(10)?,
                    row.get::<_, String>(11)?,
                ))
            },
        )
        .map_err(|_| WalIdempotencyError::Corrupt)?;
    if observation
        != (
            screen.observation_revision.clone(),
            TARGET_OBSERVATION_VERSION,
            "ready".into(),
            "episode_model".into(),
            screen.literal_description.clone(),
            screen.screen_state.clone(),
            screen.content_type.clone(),
            screen.visible_text_summary.clone(),
            screen.notable_items_json.clone(),
            Some(plan.model_name.clone()),
            TARGET_OBSERVATION_PROMPT_VERSION,
            plan.committed_at.clone(),
        )
    {
        return Err(WalIdempotencyError::Corrupt);
    }
    let job = transaction
        .query_row(
            "SELECT input_revision,observation_version,state,attempt_count,error_code,updated_at
             FROM screen_observation_jobs WHERE screenshot_id=?1",
            [screen.screenshot_id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, i32>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, Option<String>>(4)?,
                    row.get::<_, String>(5)?,
                ))
            },
        )
        .map_err(|_| WalIdempotencyError::Corrupt)?;
    if job
        != (
            screen.observation_revision.clone(),
            TARGET_OBSERVATION_VERSION,
            "ready".into(),
            0,
            None,
            plan.committed_at.clone(),
        )
    {
        return Err(WalIdempotencyError::Corrupt);
    }
    let interpretation = transaction
        .query_row(
            "SELECT episode_revision,interpretation_version,status,activity_summary,
                    relevance_level,relevance_reason,milestone_type,base_score,key_rank,
                    is_key_screen,semantic_group,model_name,prompt_version,completed_at,updated_at
             FROM episode_screen_interpretations
             WHERE episode_id=?1 AND screenshot_id=?2",
            params![plan.episode_id, screen.screenshot_id],
            |row| {
                Ok(StoredInterpretation {
                    episode_revision: row.get(0)?,
                    interpretation_version: row.get(1)?,
                    status: row.get(2)?,
                    activity_summary: row.get(3)?,
                    relevance_level: row.get(4)?,
                    relevance_reason: row.get(5)?,
                    milestone_type: row.get(6)?,
                    base_score: row.get(7)?,
                    key_rank: row.get(8)?,
                    is_key_screen: row.get(9)?,
                    semantic_group: row.get(10)?,
                    model_name: row.get(11)?,
                    prompt_version: row.get(12)?,
                    completed_at: row.get(13)?,
                    updated_at: row.get(14)?,
                })
            },
        )
        .map_err(|_| WalIdempotencyError::Corrupt)?;
    if interpretation
        != (StoredInterpretation {
            episode_revision: plan.analysis_revision.clone(),
            interpretation_version: TARGET_INTERPRETATION_VERSION,
            status: "ready".into(),
            activity_summary: screen.activity_summary.clone(),
            relevance_level: screen.relevance_level,
            relevance_reason: Some(screen.relevance_reason.clone()),
            milestone_type: screen.milestone_type.clone(),
            base_score: screen.base_score,
            key_rank: screen.key_rank,
            is_key_screen: i64::from(screen.is_key_screen),
            semantic_group: Some(screen.semantic_group.clone()),
            model_name: Some(plan.model_name.clone()),
            prompt_version: TARGET_INTERPRETATION_PROMPT_VERSION,
            completed_at: plan.committed_at.clone(),
            updated_at: plan.committed_at.clone(),
        })
    {
        return Err(WalIdempotencyError::Corrupt);
    }
    Ok(())
}

fn verify_interpretation_job(
    transaction: &Transaction<'_>,
    plan: &FinalizationCommitPlan,
) -> Result<()> {
    let job = transaction
        .query_row(
            "SELECT episode_revision,interpretation_version,state,attempt_count,error_code,updated_at
             FROM episode_screen_interpretation_jobs WHERE episode_id=?1",
            [plan.episode_id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, i32>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, Option<String>>(4)?,
                    row.get::<_, String>(5)?,
                ))
            },
        )
        .map_err(|_| WalIdempotencyError::Corrupt)?;
    if job
        != (
            plan.analysis_revision.clone(),
            TARGET_INTERPRETATION_VERSION,
            "ready".into(),
            0,
            None,
            plan.committed_at.clone(),
        )
    {
        return Err(WalIdempotencyError::Corrupt);
    }
    Ok(())
}

fn verify_deliveries(transaction: &Transaction<'_>, plan: &FinalizationCommitPlan) -> Result<()> {
    if plan.predecessor.mode() == CommitMode::Regeneration {
        return Ok(());
    }
    let counts = (
        delivery_count(transaction, "webhook_deliveries", plan.episode_id)?,
        delivery_count(transaction, "email_deliveries", plan.episode_id)?,
        delivery_count(transaction, "push_deliveries", plan.episode_id)?,
    );
    if counts
        != (
            i64::try_from(plan.webhooks.len()).map_err(|_| WalIdempotencyError::Limit)?,
            i64::from(plan.email.is_some()),
            i64::try_from(plan.pushes.len()).map_err(|_| WalIdempotencyError::Limit)?,
        )
    {
        return Err(WalIdempotencyError::Corrupt);
    }
    for delivery in &plan.webhooks {
        let row = transaction
            .query_row(
                "SELECT event_id,state,attempt_count,next_attempt_at,response_status,error_code,
                        created_at,updated_at
                 FROM webhook_deliveries
                 WHERE episode_id=?1 AND subscription_id=?2 AND delivery_version=?3",
                params![
                    plan.episode_id,
                    delivery.subscription_id,
                    TARGET_FINALIZATION_VERSION,
                ],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, i64>(2)?,
                        row.get::<_, Option<String>>(3)?,
                        row.get::<_, Option<i64>>(4)?,
                        row.get::<_, Option<String>>(5)?,
                        row.get::<_, String>(6)?,
                        row.get::<_, String>(7)?,
                    ))
                },
            )
            .map_err(|_| WalIdempotencyError::Corrupt)?;
        if row
            != (
                delivery.event_id.clone(),
                "pending".into(),
                0,
                None,
                None,
                None,
                plan.committed_at.clone(),
                plan.committed_at.clone(),
            )
        {
            return Err(WalIdempotencyError::Corrupt);
        }
    }
    if let Some(delivery) = &plan.email {
        let row = transaction
            .query_row(
                "SELECT delivery_id,include_content,state,attempt_count,next_attempt_at,
                        provider_message_id,response_status,error_code,created_at,updated_at
                 FROM email_deliveries WHERE episode_id=?1 AND delivery_version=?2",
                params![plan.episode_id, TARGET_FINALIZATION_VERSION],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, i64>(3)?,
                        row.get::<_, String>(4)?,
                        row.get::<_, Option<String>>(5)?,
                        row.get::<_, Option<i64>>(6)?,
                        row.get::<_, Option<String>>(7)?,
                        row.get::<_, String>(8)?,
                        row.get::<_, String>(9)?,
                    ))
                },
            )
            .map_err(|_| WalIdempotencyError::Corrupt)?;
        if row
            != (
                delivery.delivery_id.clone(),
                i64::from(delivery.include_content),
                "pending".into(),
                0,
                plan.committed_at.clone(),
                None,
                None,
                None,
                plan.committed_at.clone(),
                plan.committed_at.clone(),
            )
        {
            return Err(WalIdempotencyError::Corrupt);
        }
    }
    for delivery in &plan.pushes {
        let row = transaction
            .query_row(
                "SELECT delivery_id,handoff_handle,collapse_id,state,attempt_count,next_attempt_at,
                        response_status,error_code,created_at,updated_at
                 FROM push_deliveries
                 WHERE episode_id=?1 AND installation_id=?2 AND delivery_version=?3",
                params![
                    plan.episode_id,
                    delivery.installation_id,
                    TARGET_FINALIZATION_VERSION,
                ],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, i64>(4)?,
                        row.get::<_, String>(5)?,
                        row.get::<_, Option<i64>>(6)?,
                        row.get::<_, Option<String>>(7)?,
                        row.get::<_, String>(8)?,
                        row.get::<_, String>(9)?,
                    ))
                },
            )
            .map_err(|_| WalIdempotencyError::Corrupt)?;
        if row
            != (
                delivery.delivery_id.clone(),
                delivery.handoff_handle.clone(),
                delivery.collapse_id.clone(),
                "pending".into(),
                0,
                plan.committed_at.clone(),
                None,
                None,
                plan.committed_at.clone(),
                plan.committed_at.clone(),
            )
        {
            return Err(WalIdempotencyError::Corrupt);
        }
    }
    Ok(())
}

fn delivery_count(transaction: &Transaction<'_>, table: &str, episode_id: i64) -> Result<i64> {
    let sql = format!("SELECT COUNT(*) FROM {table} WHERE episode_id=?1 AND delivery_version=?2");
    transaction
        .query_row(
            &sql,
            params![episode_id, TARGET_FINALIZATION_VERSION],
            |row| row.get(0),
        )
        .map_err(|_| WalIdempotencyError::Corrupt)
}

fn require_kind(prepared: &PreparedLogicalMutation<FinalizationCommitPlan>) -> Result<()> {
    (prepared.kind_for_owner() == WalOperationKind::FinalizationCommit)
        .then_some(())
        .ok_or(WalIdempotencyError::ResultUnsupported)
}

fn validate_uuid(value: &str) -> Result<()> {
    if value.len() != 36
        || !value.bytes().enumerate().all(|(index, byte)| match index {
            8 | 13 | 18 | 23 => byte == b'-',
            _ => byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte),
        })
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

fn validate_chars(value: &str, max_chars: usize, nonempty: bool) -> Result<()> {
    if value.chars().count() > max_chars
        || value.contains('\0')
        || (nonempty && value.trim().is_empty())
    {
        return Err(WalIdempotencyError::Malformed);
    }
    Ok(())
}

fn validate_optional_chars(value: Option<&str>, max_chars: usize) -> Result<()> {
    if let Some(value) = value {
        validate_chars(value, max_chars, false)?;
    }
    Ok(())
}

fn validate_canonical_json_array(value: &str, max_bytes: usize) -> Result<serde_json::Value> {
    validate_text(value, max_bytes, false)?;
    let parsed: serde_json::Value =
        serde_json::from_str(value).map_err(|_| WalIdempotencyError::Malformed)?;
    if !parsed.is_array()
        || serde_json::to_string(&parsed).map_err(|_| WalIdempotencyError::Malformed)? != value
    {
        return Err(WalIdempotencyError::Malformed);
    }
    Ok(parsed)
}

fn validate_sorted_ids(values: &[i64], max: usize) -> Result<()> {
    if values.len() > max
        || values.iter().any(|value| *value <= 0)
        || values.windows(2).any(|pair| pair[0] >= pair[1])
    {
        return Err(WalIdempotencyError::Malformed);
    }
    Ok(())
}

fn validate_key_ranks(screens: &[FinalizationScreenResult]) -> Result<()> {
    let mut ranks = screens
        .iter()
        .filter_map(|screen| screen.key_rank)
        .collect::<Vec<_>>();
    ranks.sort_unstable();
    if ranks
        != (1..=i64::try_from(ranks.len()).map_err(|_| WalIdempotencyError::Limit)?)
            .collect::<Vec<_>>()
    {
        return Err(WalIdempotencyError::Malformed);
    }
    Ok(())
}

fn validate_webhooks(values: &[FinalizationWebhookDelivery]) -> Result<()> {
    if values
        .windows(2)
        .any(|pair| pair[0].subscription_id >= pair[1].subscription_id)
    {
        return Err(WalIdempotencyError::Malformed);
    }
    let mut event_ids = values
        .iter()
        .map(|value| value.event_id.as_str())
        .collect::<Vec<_>>();
    event_ids.sort_unstable();
    if event_ids.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(WalIdempotencyError::Malformed);
    }
    Ok(())
}

fn validate_pushes(values: &[FinalizationPushDelivery]) -> Result<()> {
    if values
        .windows(2)
        .any(|pair| pair[0].installation_id >= pair[1].installation_id)
    {
        return Err(WalIdempotencyError::Malformed);
    }
    for projection in [
        values
            .iter()
            .map(|value| value.delivery_id.as_str())
            .collect::<Vec<_>>(),
        values
            .iter()
            .map(|value| value.handoff_handle.as_str())
            .collect::<Vec<_>>(),
    ] {
        let mut projection = projection;
        projection.sort_unstable();
        if projection.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(WalIdempotencyError::Malformed);
        }
    }
    Ok(())
}

fn valid_timestamp(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_TIMESTAMP_BYTES
        && !value.contains('\0')
        && super::super::isotime::parse_epoch_millis(value).is_some()
}

fn validate_timestamp(value: &str) -> Result<()> {
    valid_timestamp(value)
        .then_some(())
        .ok_or(WalIdempotencyError::Malformed)
}

fn timestamp_millis(value: &str) -> Result<i64> {
    super::super::isotime::parse_epoch_millis(value).ok_or(WalIdempotencyError::Malformed)
}

fn validate_canonical_timestamp(value: &str) -> Result<()> {
    validate_timestamp(value)?;
    if super::super::isotime::format_epoch_millis(timestamp_millis(value)?) != value {
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

fn encode_optional_string(output: &mut Vec<u8>, value: Option<&str>) -> Result<()> {
    match value {
        None => output.push(0),
        Some(value) => {
            output.push(1);
            encode_len(output, value.len())?;
            output.extend_from_slice(value.as_bytes());
        }
    }
    Ok(())
}

fn encode_optional_i32(output: &mut Vec<u8>, value: Option<i32>) {
    match value {
        None => output.push(0),
        Some(value) => {
            output.push(1);
            output.extend_from_slice(&value.to_be_bytes());
        }
    }
}

fn encode_predecessor(
    output: &mut Vec<u8>,
    predecessor: &FinalizationCommitPredecessor,
) -> Result<()> {
    encode_optional_string(output, predecessor.finalized_at.as_deref())?;
    encode_optional_i32(output, predecessor.finalization_version);
    encode_string(output, &predecessor.status)?;
    encode_optional_string(output, predecessor.error.as_deref())?;
    encode_optional_string(output, predecessor.attempted_at.as_deref())?;
    output.extend_from_slice(&predecessor.attempt_count.to_be_bytes());
    encode_optional_string(output, predecessor.next_attempt_at.as_deref())?;
    encode_optional_string(output, predecessor.updated_at.as_deref())?;
    output.extend_from_slice(&predecessor.product_commitment);
    Ok(())
}

fn encode_i64_vec(output: &mut Vec<u8>, values: &[i64]) -> Result<()> {
    encode_len(output, values.len())?;
    for value in values {
        output.extend_from_slice(&value.to_be_bytes());
    }
    Ok(())
}

fn encode_brief(output: &mut Vec<u8>, brief: &FinalizationBrief) -> Result<()> {
    encode_string(output, &brief.overview)?;
    encode_string(output, &brief.decisions)?;
    encode_string(output, &brief.action_items)?;
    encode_string(output, &brief.important_links)?;
    encode_string(output, &brief.open_questions)?;
    Ok(())
}

fn encode_screen(output: &mut Vec<u8>, screen: &FinalizationScreenResult) -> Result<()> {
    output.extend_from_slice(&screen.screenshot_id.to_be_bytes());
    encode_string(output, &screen.observation_revision)?;
    encode_string(output, &screen.literal_description)?;
    encode_string(output, &screen.screen_state)?;
    encode_string(output, &screen.content_type)?;
    encode_optional_string(output, screen.visible_text_summary.as_deref())?;
    encode_string(output, &screen.notable_items_json)?;
    encode_optional_string(output, screen.activity_summary.as_deref())?;
    output.extend_from_slice(&screen.relevance_level.to_be_bytes());
    encode_string(output, &screen.relevance_reason)?;
    encode_string(output, &screen.milestone_type)?;
    output.extend_from_slice(&screen.base_score.to_be_bytes());
    match screen.key_rank {
        None => output.push(0),
        Some(rank) => {
            output.push(1);
            output.extend_from_slice(&rank.to_be_bytes());
        }
    }
    output.push(u8::from(screen.is_key_screen));
    encode_string(output, &screen.semantic_group)?;
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
                    "CREATE TABLE archive_v3_wal_finalization_commit_schema (
                        singleton INTEGER PRIMARY KEY CHECK(singleton=1),
                        format_version INTEGER NOT NULL CHECK(format_version=1),
                        codec_version INTEGER NOT NULL CHECK(codec_version=1)
                     ) STRICT;
                     CREATE TABLE archive_v3_wal_finalization_commit_operations (
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
                     CREATE TABLE archive_v3_wal_finalization_commit_state (
                        singleton INTEGER PRIMARY KEY CHECK(singleton=1),
                        row_count INTEGER NOT NULL CHECK(row_count BETWEEN 0 AND 1048576),
                        result_bytes INTEGER NOT NULL CHECK(result_bytes BETWEEN 0 AND 33554432)
                     ) STRICT;
                     INSERT INTO archive_v3_wal_finalization_commit_schema
                        (singleton,format_version,codec_version) VALUES (1,1,1);
                     INSERT INTO archive_v3_wal_finalization_commit_state
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
             FROM archive_v3_wal_finalization_commit_schema WHERE singleton=1",
            [],
            |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)),
        )
        .optional()
        .map_err(|_| WalIdempotencyError::Corrupt)?;
    if marker
        != Some((
            i64::from(WalOperationKind::format_version()),
            i64::from(WalOperationKind::FinalizationCommit.codec_version()),
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
             FROM archive_v3_wal_finalization_commit_state WHERE singleton=1",
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
    use tempfile::tempdir;

    const ACCOUNT: &str = "11111111-1111-4111-8111-111111111111";
    const SUBSCRIPTION: &str = "22222222-2222-4222-8222-222222222222";
    const INSTALLATION: &str = "33333333-3333-4333-8333-333333333333";
    const PUSH_DELIVERY: &str = "44444444-4444-4444-8444-444444444444";
    const COLLAPSE: &str = "55555555-5555-4555-8555-555555555555";
    const EVENT_ONE: &str = "vtx_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const EVENT_TWO: &str = "vtx_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    const WEBHOOK_EVENT: &str =
        "evt_cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
    const EMAIL_DELIVERY: &str =
        "deliv_dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";
    const HANDOFF: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    const ATTEMPTED_AT: &str = "2026-08-15T14:00:00.000Z";
    const UPDATED_AT: &str = "2026-08-15T14:00:01.000Z";
    const COMMITTED_AT: &str = "2026-08-15T14:00:02.000Z";
    const OLD_FINALIZED_AT: &str = "2026-08-14T12:00:00.000Z";
    const ANALYSIS_REVISION: &str =
        "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";
    const OBSERVATION_REVISION: &str =
        "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
    const SEMANTIC_GROUP: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    fn install_domain_schema(connection: &Connection) {
        connection
            .execute_batch(
                "PRAGMA foreign_keys=ON;
                 CREATE TABLE episodes (
                    id INTEGER PRIMARY KEY,
                    finalized_at TEXT,
                    finalization_version INTEGER,
                    finalization_status TEXT NOT NULL,
                    finalization_error TEXT,
                    finalization_attempted_at TEXT,
                    finalization_attempt_count INTEGER NOT NULL,
                    finalization_next_attempt_at TEXT,
                    updated_at TEXT
                 ) STRICT;
                 CREATE TABLE vertex_usage_events (
                    event_id TEXT PRIMARY KEY,
                    operation TEXT NOT NULL,
                    requested_model TEXT NOT NULL,
                    returned_model TEXT,
                    location TEXT NOT NULL,
                    traffic_type TEXT NOT NULL,
                    http_status INTEGER,
                    prompt_tokens INTEGER,
                    input_text_tokens INTEGER,
                    input_audio_tokens INTEGER,
                    input_image_tokens INTEGER,
                    cached_input_tokens INTEGER,
                    cached_input_text_tokens INTEGER,
                    cached_input_audio_tokens INTEGER,
                    cached_input_image_tokens INTEGER,
                    output_text_tokens INTEGER,
                    thought_tokens INTEGER,
                    total_tokens INTEGER,
                    outcome TEXT NOT NULL,
                    delivery_state TEXT NOT NULL,
                    delivery_attempt_count INTEGER NOT NULL,
                    observed_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                 ) STRICT;
                 CREATE TABLE screenshots (
                    id INTEGER PRIMARY KEY,
                    is_duplicate INTEGER NOT NULL
                 ) STRICT;
                 CREATE TABLE episode_members (
                    episode_id INTEGER NOT NULL,
                    record_type TEXT NOT NULL,
                    record_id INTEGER NOT NULL,
                    PRIMARY KEY (episode_id,record_type,record_id)
                 ) STRICT;
                 CREATE TABLE screen_observations (
                    screenshot_id INTEGER PRIMARY KEY,
                    input_revision TEXT NOT NULL,
                    observation_version INTEGER NOT NULL,
                    status TEXT NOT NULL,
                    generation_method TEXT NOT NULL,
                    literal_description TEXT NOT NULL,
                    screen_state TEXT NOT NULL,
                    content_type TEXT NOT NULL,
                    visible_text_summary TEXT,
                    notable_items_json TEXT NOT NULL,
                    model_name TEXT,
                    prompt_version INTEGER NOT NULL,
                    completed_at TEXT NOT NULL
                 ) STRICT;
                 CREATE TABLE screen_observation_jobs (
                    screenshot_id INTEGER PRIMARY KEY,
                    input_revision TEXT NOT NULL,
                    observation_version INTEGER NOT NULL,
                    state TEXT NOT NULL,
                    attempt_count INTEGER NOT NULL,
                    error_code TEXT,
                    updated_at TEXT NOT NULL
                 ) STRICT;
                 CREATE TABLE episode_screen_interpretations (
                    episode_id INTEGER NOT NULL,
                    screenshot_id INTEGER NOT NULL,
                    episode_revision TEXT NOT NULL,
                    interpretation_version INTEGER NOT NULL,
                    status TEXT NOT NULL,
                    activity_summary TEXT,
                    relevance_level INTEGER NOT NULL,
                    relevance_reason TEXT,
                    milestone_type TEXT NOT NULL,
                    base_score INTEGER NOT NULL,
                    key_rank INTEGER,
                    is_key_screen INTEGER NOT NULL,
                    semantic_group TEXT,
                    model_name TEXT,
                    prompt_version INTEGER NOT NULL,
                    completed_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    PRIMARY KEY (episode_id,screenshot_id)
                 ) STRICT;
                 CREATE TABLE episode_screen_interpretation_jobs (
                    episode_id INTEGER PRIMARY KEY,
                    episode_revision TEXT NOT NULL,
                    interpretation_version INTEGER NOT NULL,
                    state TEXT NOT NULL,
                    attempt_count INTEGER NOT NULL,
                    error_code TEXT,
                    updated_at TEXT NOT NULL
                 ) STRICT;
                 CREATE TABLE episode_final_briefs (
                    episode_id INTEGER PRIMARY KEY,
                    overview TEXT NOT NULL,
                    decisions TEXT NOT NULL,
                    action_items TEXT NOT NULL,
                    important_links TEXT NOT NULL,
                    open_questions TEXT NOT NULL,
                    created_at TEXT NOT NULL
                 ) STRICT;
                 CREATE TABLE webhook_deliveries (
                    episode_id INTEGER NOT NULL,
                    subscription_id TEXT NOT NULL,
                    delivery_version INTEGER NOT NULL,
                    event_id TEXT NOT NULL UNIQUE,
                    state TEXT NOT NULL,
                    attempt_count INTEGER NOT NULL,
                    next_attempt_at TEXT,
                    response_status INTEGER,
                    error_code TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    PRIMARY KEY (episode_id,subscription_id,delivery_version)
                 ) STRICT;
                 CREATE TABLE email_deliveries (
                    episode_id INTEGER NOT NULL,
                    delivery_version INTEGER NOT NULL,
                    delivery_id TEXT NOT NULL UNIQUE,
                    include_content INTEGER NOT NULL,
                    state TEXT NOT NULL,
                    attempt_count INTEGER NOT NULL,
                    next_attempt_at TEXT NOT NULL,
                    provider_message_id TEXT,
                    response_status INTEGER,
                    error_code TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    PRIMARY KEY (episode_id,delivery_version)
                 ) STRICT;
                 CREATE TABLE push_deliveries (
                    episode_id INTEGER NOT NULL,
                    installation_id TEXT NOT NULL,
                    delivery_version INTEGER NOT NULL,
                    delivery_id TEXT NOT NULL UNIQUE,
                    handoff_handle TEXT NOT NULL UNIQUE,
                    collapse_id TEXT NOT NULL,
                    state TEXT NOT NULL,
                    attempt_count INTEGER NOT NULL,
                    next_attempt_at TEXT NOT NULL,
                    response_status INTEGER,
                    error_code TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    PRIMARY KEY (episode_id,installation_id,delivery_version)
                 ) STRICT;",
            )
            .unwrap();
    }

    fn connection() -> Connection {
        let connection = Connection::open_in_memory().unwrap();
        install_domain_schema(&connection);
        connection
    }

    fn seed_episode(
        connection: &Connection,
        episode_id: i64,
        finalized_at: Option<&str>,
        version: Option<i32>,
    ) {
        for event_id in [EVENT_ONE, EVENT_TWO] {
            connection
                .execute(
                    "INSERT OR IGNORE INTO vertex_usage_events
                     (event_id,operation,requested_model,returned_model,location,traffic_type,
                      http_status,prompt_tokens,input_text_tokens,input_audio_tokens,
                      input_image_tokens,cached_input_tokens,cached_input_text_tokens,
                      cached_input_audio_tokens,cached_input_image_tokens,output_text_tokens,
                      thought_tokens,total_tokens,outcome,delivery_state,delivery_attempt_count,
                      observed_at,updated_at)
                     VALUES (?1,'episode_finalization','gemini-2.5-flash','gemini-2.5-flash',
                             'us-central1','on_demand',200,100,100,0,0,0,0,0,0,50,0,150,
                             'metered','pending',0,?2,?2)",
                    params![event_id, ATTEMPTED_AT],
                )
                .unwrap();
        }
        connection
            .execute(
                "INSERT INTO episodes
                 (id,finalized_at,finalization_version,finalization_status,
                  finalization_error,finalization_attempted_at,finalization_attempt_count,
                  finalization_next_attempt_at,updated_at)
                 VALUES (?1,?2,?3,'processing',NULL,?4,2,NULL,?5)",
                params![episode_id, finalized_at, version, ATTEMPTED_AT, UPDATED_AT],
            )
            .unwrap();
        connection
            .execute(
                "INSERT INTO screenshots (id,is_duplicate) VALUES (?1,0),(?2,1)",
                params![episode_id * 10, episode_id * 10 + 1],
            )
            .unwrap();
        connection
            .execute(
                "INSERT INTO episode_members (episode_id,record_type,record_id)
                 VALUES (?1,'utterance',?2),
                        (?1,'screenshot',?3),
                        (?1,'screenshot',?4)",
                params![
                    episode_id,
                    episode_id * 100,
                    episode_id * 10,
                    episode_id * 10 + 1,
                ],
            )
            .unwrap();
    }

    fn predecessor(
        connection: &Connection,
        episode_id: i64,
        finalized_at: Option<&str>,
        version: Option<i32>,
    ) -> FinalizationCommitPredecessor {
        FinalizationCommitPredecessor::new(
            finalized_at.map(str::to_owned),
            version,
            "processing".into(),
            None,
            Some(ATTEMPTED_AT.into()),
            2,
            None,
            Some(UPDATED_AT.into()),
            current_product_commitment(connection, episode_id).unwrap(),
        )
        .unwrap()
    }

    fn brief(overview: &str) -> FinalizationBrief {
        FinalizationBrief::new(
            overview.into(),
            "[]".into(),
            "[]".into(),
            "[]".into(),
            "[]".into(),
        )
        .unwrap()
    }

    fn screen(screenshot_id: i64) -> FinalizationScreenResult {
        FinalizationScreenResult::new(
            screenshot_id,
            OBSERVATION_REVISION.into(),
            "Safari displays the reviewed episode.".into(),
            "content".into(),
            "web_page".into(),
            Some("Episode details".into()),
            "[\"Episode 323\"]".into(),
            Some("Reviewing episode evidence".into()),
            3,
            "This screen shows the completed review.".into(),
            "result".into(),
            85,
            Some(1),
            true,
            SEMANTIC_GROUP.into(),
        )
        .unwrap()
    }

    fn initial_plan(
        connection: &Connection,
        event: &str,
        episode_id: i64,
        overview: &str,
    ) -> FinalizationCommitPlan {
        FinalizationCommitPlan::new(
            ACCOUNT.into(),
            event.into(),
            current_vertex_attempt_commitment(connection, event, "gemini-2.5-flash").unwrap(),
            episode_id,
            COMMITTED_AT.into(),
            predecessor(connection, episode_id, None, None),
            vec![episode_id * 100],
            vec![episode_id * 10, episode_id * 10 + 1],
            "gemini-2.5-flash".into(),
            ANALYSIS_REVISION.into(),
            brief(overview),
            vec![screen(episode_id * 10)],
            vec![
                FinalizationWebhookDelivery::new(SUBSCRIPTION.into(), WEBHOOK_EVENT.into())
                    .unwrap(),
            ],
            Some(FinalizationEmailDelivery::new(EMAIL_DELIVERY.into(), true).unwrap()),
            vec![FinalizationPushDelivery::new(
                INSTALLATION.into(),
                PUSH_DELIVERY.into(),
                HANDOFF.into(),
                COLLAPSE.into(),
            )
            .unwrap()],
        )
        .unwrap()
    }

    fn regeneration_plan(connection: &Connection, episode_id: i64) -> FinalizationCommitPlan {
        FinalizationCommitPlan::new(
            ACCOUNT.into(),
            EVENT_TWO.into(),
            current_vertex_attempt_commitment(connection, EVENT_TWO, "gemini-2.5-flash").unwrap(),
            episode_id,
            COMMITTED_AT.into(),
            predecessor(connection, episode_id, Some(OLD_FINALIZED_AT), Some(4)),
            vec![episode_id * 100],
            vec![episode_id * 10, episode_id * 10 + 1],
            "gemini-2.5-flash".into(),
            ANALYSIS_REVISION.into(),
            brief("Regenerated exact episode brief."),
            vec![screen(episode_id * 10)],
            vec![],
            None,
            vec![],
        )
        .unwrap()
    }

    fn initial_plan_without_deliveries(
        connection: &Connection,
        event: &str,
        episode_id: i64,
        overview: &str,
    ) -> FinalizationCommitPlan {
        FinalizationCommitPlan::new(
            ACCOUNT.into(),
            event.into(),
            current_vertex_attempt_commitment(connection, event, "gemini-2.5-flash").unwrap(),
            episode_id,
            COMMITTED_AT.into(),
            predecessor(connection, episode_id, None, None),
            vec![episode_id * 100],
            vec![episode_id * 10, episode_id * 10 + 1],
            "gemini-2.5-flash".into(),
            ANALYSIS_REVISION.into(),
            brief(overview),
            vec![screen(episode_id * 10)],
            vec![],
            None,
            vec![],
        )
        .unwrap()
    }

    fn execute(
        connection: &mut Connection,
        plan: FinalizationCommitPlan,
    ) -> std::result::Result<
        crate::archive_v3_wal_idempotency::ExecutedLogicalMutation<FinalizationCommitPlan>,
        WalIdempotencyError,
    > {
        execute_prepared_for_owner(connection, PreparedLogicalMutation::prepare(plan).unwrap())
    }

    fn execute_error(
        connection: &mut Connection,
        plan: FinalizationCommitPlan,
    ) -> WalIdempotencyError {
        match execute(connection, plan) {
            Ok(_) => panic!("logical mutation unexpectedly succeeded"),
            Err(error) => error,
        }
    }

    #[test]
    fn codec_versions_are_pinned_to_the_reviewed_product() {
        assert_eq!(
            TARGET_FINALIZATION_VERSION,
            crate::store::EPISODE_FINALIZATION_VERSION
        );
        assert_eq!(
            TARGET_OBSERVATION_VERSION,
            crate::cp::screen_understanding::OBSERVATION_VERSION
        );
        assert_eq!(
            TARGET_OBSERVATION_PROMPT_VERSION,
            crate::cp::screen_understanding::OBSERVATION_PROMPT_VERSION
        );
        assert_eq!(
            TARGET_INTERPRETATION_VERSION,
            crate::cp::screen_understanding::INTERPRETATION_VERSION
        );
        assert_eq!(
            TARGET_INTERPRETATION_PROMPT_VERSION,
            crate::cp::screen_understanding::INTERPRETATION_PROMPT_VERSION
        );
    }

    #[test]
    fn stable_identity_is_the_preexisting_vertex_attempt() {
        let connection = connection();
        seed_episode(&connection, 1, None, None);
        let first = initial_plan(&connection, EVENT_ONE, 1, "Exact episode brief.");
        let changed = initial_plan(&connection, EVENT_ONE, 1, "Changed episode brief.");
        assert_eq!(first.operation_id(), changed.operation_id());
        assert_ne!(
            first.canonical_request().unwrap(),
            changed.canonical_request().unwrap()
        );
        assert_ne!(
            first.operation_id(),
            initial_plan(&connection, EVENT_TWO, 1, "Exact episode brief.").operation_id()
        );
    }

    #[test]
    fn aggregate_request_over_shared_cap_is_rejected() {
        let connection = connection();
        seed_episode(&connection, 1, None, None);
        let mut plan = initial_plan(&connection, EVENT_ONE, 1, "Exact episode brief.");
        let large_array = serde_json::to_string(&vec!["x".repeat(240_000)]).unwrap();
        plan.brief = FinalizationBrief::new(
            "x".repeat(240_000),
            large_array.clone(),
            large_array.clone(),
            large_array.clone(),
            large_array,
        )
        .unwrap();
        assert!(matches!(
            PreparedLogicalMutation::prepare(plan),
            Err(WalIdempotencyError::Limit)
        ));
    }

    #[test]
    fn exact_initial_commit_applies_once_and_replays_without_rewrite() {
        let mut connection = connection();
        seed_episode(&connection, 1, None, None);
        let replay = initial_plan(&connection, EVENT_ONE, 1, "Exact episode brief.");
        let first = initial_plan(&connection, EVENT_ONE, 1, "Exact episode brief.");
        connection
            .execute(
                "UPDATE vertex_usage_events
                 SET delivery_state='delivered',updated_at='2026-08-15T14:00:01.500Z'
                 WHERE event_id=?1",
                [EVENT_ONE],
            )
            .unwrap();
        assert_eq!(
            execute(&mut connection, first).unwrap().disposition(),
            LogicalMutationDisposition::Applied
        );
        assert_eq!(
            connection
                .query_row(
                    "SELECT finalized_at,finalization_version,finalization_status,
                            finalization_attempted_at,updated_at FROM episodes WHERE id=1",
                    [],
                    |row| Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, i32>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, String>(4)?,
                    )),
                )
                .unwrap(),
            (
                COMMITTED_AT.into(),
                TARGET_FINALIZATION_VERSION,
                "complete".into(),
                ATTEMPTED_AT.into(),
                COMMITTED_AT.into(),
            )
        );
        assert_eq!(load_ledger_state(&connection).unwrap(), (1, 9));
        assert_eq!(
            execute(&mut connection, replay).unwrap().disposition(),
            LogicalMutationDisposition::Replayed
        );
        assert_eq!(load_ledger_state(&connection).unwrap(), (1, 9));
        assert_eq!(delivery_count_direct(&connection, "webhook_deliveries"), 1);
        assert_eq!(delivery_count_direct(&connection, "email_deliveries"), 1);
        assert_eq!(delivery_count_direct(&connection, "push_deliveries"), 1);
    }

    #[test]
    fn every_authenticated_predecessor_family_fails_closed_when_changed() {
        for mutation in [
            "UPDATE vertex_usage_events SET outcome='ambiguous' WHERE event_id='vtx_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'",
            "UPDATE episodes SET finalization_attempt_count=3 WHERE id=1",
            "INSERT INTO episode_members VALUES (1,'utterance',999)",
            "UPDATE screenshots SET is_duplicate=1 WHERE id=10",
            "INSERT INTO episode_final_briefs VALUES (1,'old','[]','[]','[]','[]','2026-08-15T13:00:00.000Z')",
            "INSERT INTO webhook_deliveries VALUES (1,'99999999-9999-4999-8999-999999999999',5,'evt_9999999999999999999999999999999999999999999999999999999999999999','pending',0,NULL,NULL,NULL,'2026-08-15T13:00:00.000Z','2026-08-15T13:00:00.000Z')",
        ] {
            let mut connection = connection();
            seed_episode(&connection, 1, None, None);
            let plan = initial_plan(&connection, EVENT_ONE, 1, "Exact episode brief.");
            connection.execute_batch(mutation).unwrap();
            assert_eq!(
                execute_error(&mut connection, plan),
                WalIdempotencyError::Precondition,
                "mutation unexpectedly admitted: {mutation}"
            );
            assert_eq!(
                connection
                    .query_row(
                        "SELECT finalization_status FROM episodes WHERE id=1",
                        [],
                        |row| row.get::<_, String>(0),
                    )
                    .unwrap(),
                "processing"
            );
            assert_eq!(schema_state(&connection).unwrap(), LedgerSchemaState::Absent);
        }
    }

    #[test]
    fn regeneration_preserves_original_time_and_never_enqueues_deliveries() {
        let mut connection = connection();
        seed_episode(&connection, 2, Some(OLD_FINALIZED_AT), Some(4));
        let plan = regeneration_plan(&connection, 2);
        assert_eq!(
            execute(&mut connection, plan).unwrap().disposition(),
            LogicalMutationDisposition::Applied
        );
        assert_eq!(
            connection
                .query_row(
                    "SELECT finalized_at,finalization_version FROM episodes WHERE id=2",
                    [],
                    |row| Ok((row.get::<_, String>(0)?, row.get::<_, i32>(1)?)),
                )
                .unwrap(),
            (OLD_FINALIZED_AT.into(), TARGET_FINALIZATION_VERSION)
        );
        assert_eq!(delivery_count_direct(&connection, "webhook_deliveries"), 0);
        assert_eq!(delivery_count_direct(&connection, "email_deliveries"), 0);
        assert_eq!(delivery_count_direct(&connection, "push_deliveries"), 0);
    }

    #[test]
    fn changed_same_attempt_conflicts_before_touching_the_completed_product() {
        let mut connection = connection();
        seed_episode(&connection, 1, None, None);
        let changed = initial_plan(&connection, EVENT_ONE, 1, "Changed episode brief.");
        let first = initial_plan(&connection, EVENT_ONE, 1, "Exact episode brief.");
        execute(&mut connection, first).unwrap();
        assert_eq!(
            execute_error(&mut connection, changed),
            WalIdempotencyError::FingerprintConflict
        );
        assert_eq!(
            connection
                .query_row(
                    "SELECT overview FROM episode_final_briefs WHERE episode_id=1",
                    [],
                    |row| row.get::<_, String>(0),
                )
                .unwrap(),
            "Exact episode brief."
        );
    }

    #[test]
    fn capacity_is_reserved_before_product_mutation_but_replay_survives() {
        let mut connection = connection();
        seed_episode(&connection, 1, None, None);
        let replay = initial_plan(&connection, EVENT_ONE, 1, "Exact episode brief.");
        let first = initial_plan(&connection, EVENT_ONE, 1, "Exact episode brief.");
        execute(&mut connection, first).unwrap();
        connection
            .execute(
                "UPDATE archive_v3_wal_finalization_commit_state SET row_count=?1",
                [i64::from(MAX_ROWS)],
            )
            .unwrap();
        assert_eq!(
            execute(&mut connection, replay).unwrap().disposition(),
            LogicalMutationDisposition::Replayed
        );

        seed_episode(&connection, 2, None, None);
        let before = current_product_commitment(&connection, 2).unwrap();
        let second = initial_plan(&connection, EVENT_TWO, 2, "Second exact brief.");
        assert_eq!(
            execute_error(&mut connection, second),
            WalIdempotencyError::Limit
        );
        assert_eq!(current_product_commitment(&connection, 2).unwrap(), before);
        assert_eq!(
            load_episode(&connection, 2).unwrap().unwrap().status,
            "processing"
        );
    }

    #[test]
    fn late_ledger_failure_rolls_back_the_complete_product_and_outboxes() {
        let mut connection = connection();
        seed_episode(&connection, 1, None, None);
        let before = current_product_commitment(&connection, 1).unwrap();
        let plan = initial_plan(&connection, EVENT_ONE, 1, "Exact episode brief.");
        let transaction = connection.transaction().unwrap();
        ensure_schema(&transaction).unwrap();
        transaction.commit().unwrap();
        connection
            .execute_batch(
                "CREATE TRIGGER reject_finalization_commit_ledger
                 BEFORE INSERT ON archive_v3_wal_finalization_commit_operations
                 BEGIN SELECT RAISE(ABORT,'late ledger failure'); END;",
            )
            .unwrap();
        assert_eq!(
            execute_error(&mut connection, plan),
            WalIdempotencyError::Unavailable
        );
        assert_eq!(current_product_commitment(&connection, 1).unwrap(), before);
        assert_eq!(
            load_episode(&connection, 1).unwrap().unwrap().status,
            "processing"
        );
        assert_eq!(delivery_count_direct(&connection, "webhook_deliveries"), 0);
        assert_eq!(load_ledger_state(&connection).unwrap(), (0, 0));
    }

    #[test]
    fn missing_precondition_rolls_back_lazy_schema_and_same_attempt_can_retry() {
        let mut connection = connection();
        seed_episode(&connection, 1, None, None);
        let plan = initial_plan(&connection, EVENT_ONE, 1, "Exact episode brief.");
        connection
            .execute("DELETE FROM episodes WHERE id=1", [])
            .unwrap();
        assert_eq!(
            execute_error(&mut connection, plan),
            WalIdempotencyError::Precondition
        );
        assert_eq!(
            schema_state(&connection).unwrap(),
            LedgerSchemaState::Absent
        );
        seed_episode(&connection, 2, None, None);
        let retry = initial_plan(&connection, EVENT_ONE, 2, "Exact episode brief.");
        assert_eq!(
            execute(&mut connection, retry).unwrap().disposition(),
            LogicalMutationDisposition::Applied
        );
    }

    #[test]
    fn partial_schema_and_result_tamper_fail_closed() {
        let mut partial = connection();
        seed_episode(&partial, 1, None, None);
        partial
            .execute_batch(
                "CREATE TABLE archive_v3_wal_finalization_commit_schema(
                    singleton INTEGER PRIMARY KEY,
                    format_version INTEGER NOT NULL,
                    codec_version INTEGER NOT NULL
                 ) STRICT;",
            )
            .unwrap();
        assert_eq!(
            {
                let plan = initial_plan(&partial, EVENT_ONE, 1, "Exact episode brief.");
                execute_error(&mut partial, plan)
            },
            WalIdempotencyError::Corrupt
        );

        let mut tampered = connection();
        seed_episode(&tampered, 1, None, None);
        let replay = initial_plan(&tampered, EVENT_ONE, 1, "Exact episode brief.");
        let first = initial_plan(&tampered, EVENT_ONE, 1, "Exact episode brief.");
        execute(&mut tampered, first).unwrap();
        tampered
            .execute(
                "UPDATE archive_v3_wal_finalization_commit_operations
                 SET result_bytes=zeroblob(9)",
                [],
            )
            .unwrap();
        assert_eq!(
            execute_error(&mut tampered, replay),
            WalIdempotencyError::Corrupt
        );
    }

    #[test]
    fn close_reopen_replays_then_accepts_an_independent_commit() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("user.sqlite");
        {
            let mut connection = Connection::open(&path).unwrap();
            install_domain_schema(&connection);
            seed_episode(&connection, 1, None, None);
            let plan = initial_plan(&connection, EVENT_ONE, 1, "Exact episode brief.");
            execute(&mut connection, plan).unwrap();
        }
        let mut reopened = Connection::open(&path).unwrap();
        // The predecessor commitment is part of the fingerprint; rebuild the
        // original request from a fresh equivalent fixture rather than trust
        // the now-completed database to reconstruct it.
        let fixture = connection();
        seed_episode(&fixture, 1, None, None);
        let replay = initial_plan(&fixture, EVENT_ONE, 1, "Exact episode brief.");
        assert_eq!(
            execute(&mut reopened, replay).unwrap().disposition(),
            LogicalMutationDisposition::Replayed
        );

        seed_episode(&reopened, 2, None, None);
        let second =
            initial_plan_without_deliveries(&reopened, EVENT_TWO, 2, "Second exact brief.");
        assert_eq!(
            execute(&mut reopened, second).unwrap().disposition(),
            LogicalMutationDisposition::Applied
        );
    }

    #[test]
    fn constructors_reject_unstable_or_incomplete_facts() {
        assert!(FinalizationCommitPredecessor::new(
            None,
            None,
            "queued".into(),
            None,
            Some(ATTEMPTED_AT.into()),
            0,
            None,
            Some(UPDATED_AT.into()),
            [1; 32],
        )
        .is_err());
        assert!(FinalizationBrief::new(
            "brief".into(),
            "[ ]".into(),
            "[]".into(),
            "[]".into(),
            "[]".into(),
        )
        .is_err());
        assert!(FinalizationPushDelivery::new(
            INSTALLATION.into(),
            PUSH_DELIVERY.into(),
            "short".into(),
            COLLAPSE.into(),
        )
        .is_err());
        let mut later_id_first_rank = screen(20);
        let mut earlier_id_second_rank = screen(10);
        later_id_first_rank.key_rank = Some(1);
        earlier_id_second_rank.key_rank = Some(2);
        assert!(validate_key_ranks(
            &[earlier_id_second_rank.clone(), later_id_first_rank.clone(),]
        )
        .is_ok());
        later_id_first_rank.key_rank = Some(2);
        assert!(validate_key_ranks(&[earlier_id_second_rank, later_id_first_rank]).is_err());

        let connection = connection();
        seed_episode(&connection, 2, Some(OLD_FINALIZED_AT), Some(4));
        let predecessor = predecessor(&connection, 2, Some(OLD_FINALIZED_AT), Some(4));
        assert!(FinalizationCommitPlan::new(
            ACCOUNT.into(),
            EVENT_TWO.into(),
            current_vertex_attempt_commitment(&connection, EVENT_TWO, "gemini-2.5-flash").unwrap(),
            2,
            COMMITTED_AT.into(),
            predecessor,
            vec![200],
            vec![20, 21],
            "gemini-2.5-flash".into(),
            ANALYSIS_REVISION.into(),
            brief("Regenerated exact episode brief."),
            vec![screen(20)],
            vec![
                FinalizationWebhookDelivery::new(SUBSCRIPTION.into(), WEBHOOK_EVENT.into(),)
                    .unwrap()
            ],
            None,
            vec![],
        )
        .is_err());
    }

    fn delivery_count_direct(connection: &Connection, table: &str) -> i64 {
        connection
            .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
                row.get(0)
            })
            .unwrap()
    }
}
