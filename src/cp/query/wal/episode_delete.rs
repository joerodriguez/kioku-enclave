//! Exact selected-archive episode deletion and browser-state garbage collection.
//!
//! The preparation plan re-reads the complete logical predecessor inside the
//! owner transaction, purges plaintext rows, and atomically reserves every
//! permanent receipt byte before provider I/O. It retains only exact encrypted
//! object identities and content-free response keys. The route can therefore
//! resume physical deletion after any crash without reconstructing deleted
//! plaintext. A distinct completion plan records that all frozen provider
//! objects are absent; only then is the public deletion receipt replayable.

use std::collections::BTreeSet;

use rusqlite::{params, types::ValueRef, Connection, OptionalExtension, ToSql, Transaction};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::archive_v3_wal_idempotency::{
    hash_field, stable_operation_source, DomainLedgerBounds, LogicalMutationResult,
    PreparedLogicalMutation, WalIdempotencyError, WalLogicalDomainLedger, WalLogicalDomainPlan,
    WalLogicalOperationId, WalOperationKind, WalReplayResult, WalRequestFingerprint,
};
use crate::episodes::{purge_episode_transaction_at_deferred_voice, EpisodePurge};

const PREPARE_REQUEST_V1: u16 = 1;
const COMPLETE_REQUEST_V1: u16 = 1;
const PREPARE_SUBTYPE: &[u8] = b"adr-0022-exact-episode-delete-prepare-v1";
const COMPLETE_SUBTYPE: &[u8] = b"adr-0022-exact-episode-delete-complete-v1";
const CLEANUP_SUBTYPE: &[u8] = b"adr-0022-exact-episode-delete-cleanup-v1";
const RECEIPT_DOMAIN: &[u8] = b"kioku:adr-0022:episode-delete:receipt:v1";
const CLEANUP_DOMAIN: &[u8] = b"kioku:adr-0022:episode-delete:cleanup:v1";
const SELECTOR_ITEMS_DOMAIN: &[u8] = b"kioku:adr-0022:episode-delete:selector-items:v1";
const FINAL_CLEANUP_DOMAIN: &[u8] = b"kioku:adr-0022:episode-delete:final-cleanup:v1";
const SCHEMA_TABLE: &str = "archive_v3_wal_episode_delete_schema";
const LEDGER_TABLE: &str = "archive_v3_wal_episode_delete_operations";
const SOURCE_TABLE: &str = "archive_v3_wal_episode_delete_sources";
const CLEANUP_TABLE: &str = "archive_v3_wal_episode_delete_cleanup";
const SELECTOR_TABLE: &str = "archive_v3_wal_episode_delete_selectors";
const VOICE_PROGRESS_TABLE: &str = "archive_v3_wal_episode_delete_voice_progress";
const STATE_TABLE: &str = "archive_v3_wal_episode_delete_state";
const PROGRESS_TABLE: &str = "archive_v3_wal_episode_delete_progress";
const MAX_ROWS: u32 = 1_048_576;
const MAX_RESULT_BYTES: u64 = 32 * 1024 * 1024;
const MAX_SOURCE_ROWS: u64 = 1_048_576;
const MAX_SOURCE_BYTES: u64 = 512 * 1024 * 1024;
const MAX_MEMBERS_PER_CLASS: usize = crate::cp::summarizer::wal::window::MAX_MEMBERS_PER_ITEM;
const MAX_SOURCES_PER_EPISODE: usize = MAX_MEMBERS_PER_CLASS * 2;
const MAX_CLEANUP_ROWS: usize = MAX_SOURCES_PER_EPISODE * 2;
const MAX_EVENTS_PER_SELECTOR: usize = 128 * 128;
const MAX_VOICE_EPISODES_PER_PAGE: usize = 128;
const MAX_EVIDENCE_QUERIES: u64 = 1_048_576;
const MAX_EVIDENCE_ROWS: u64 = 1_048_576;
const MAX_EVIDENCE_BYTES: u64 = 512 * 1024 * 1024;
const MAX_EVIDENCE_FIELD_BYTES: u64 = 8 * 1024 * 1024;
const MAX_SOURCE_KEY_BYTES: usize = 1_024;
const MAX_WORK_UNIT_ID_BYTES: usize = 128;
const VOICE_RESERVED_CLEANUP_ROWS: u64 = MAX_EVENTS_PER_SELECTOR as u64;
const VOICE_RESERVED_CLEANUP_BYTES: u64 =
    VOICE_RESERVED_CLEANUP_ROWS * (MAX_SOURCE_KEY_BYTES as u64 + 64 + "current".len() as u64);
const VOICE_PROGRESS_ROW_BYTES: u64 = 16 + (5 * 8) + (2 * 32);
const UNIT_RESULT_BYTES: usize = 9;
const BOUNDS: DomainLedgerBounds = DomainLedgerBounds::new(MAX_ROWS, MAX_RESULT_BYTES);

type Result<T> = std::result::Result<T, WalIdempotencyError>;

#[derive(Default)]
struct EvidenceBudget {
    queries: u64,
    rows: u64,
    bytes: u64,
}

impl EvidenceBudget {
    fn begin_query(&mut self) -> Result<()> {
        self.queries = self
            .queries
            .checked_add(1)
            .ok_or(WalIdempotencyError::Limit)?;
        (self.queries <= MAX_EVIDENCE_QUERIES)
            .then_some(())
            .ok_or(WalIdempotencyError::Limit)
    }

    fn observe_row(&mut self) -> Result<()> {
        self.rows = self.rows.checked_add(1).ok_or(WalIdempotencyError::Limit)?;
        (self.rows <= MAX_EVIDENCE_ROWS)
            .then_some(())
            .ok_or(WalIdempotencyError::Limit)
    }

    fn observe_bytes(&mut self, count: usize) -> Result<()> {
        self.bytes = self
            .bytes
            .checked_add(u64::try_from(count).map_err(|_| WalIdempotencyError::Limit)?)
            .ok_or(WalIdempotencyError::Limit)?;
        (self.bytes <= MAX_EVIDENCE_BYTES)
            .then_some(())
            .ok_or(WalIdempotencyError::Limit)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(in crate::cp) struct EpisodeDeleteMedia {
    pub(in crate::cp) object_key: String,
    pub(in crate::cp) object_generation: Option<i64>,
    pub(in crate::cp) object_backend: Option<String>,
    pub(in crate::cp) sha256: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(in crate::cp) struct EpisodeDeleteEvidence {
    episode_id: i64,
    predecessor_commitment: [u8; 32],
    mutation_stamp: String,
    event_ids: Vec<String>,
    work_unit_ids: Vec<String>,
    stream_ids: Vec<String>,
    session_ids: Vec<String>,
    browser_state_keys: Vec<String>,
    legacy_browser_snapshot_ids: Vec<i64>,
    media: Vec<EpisodeDeleteMedia>,
    legacy_media_keys: Vec<String>,
    selectors: Vec<EpisodeDeleteSelector>,
    purge: EpisodePurge,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct EpisodeDeleteSelector {
    selector_kind: String,
    selector_ref: String,
}

impl EpisodeDeleteEvidence {
    pub(in crate::cp) fn media(&self) -> &[EpisodeDeleteMedia] {
        &self.media
    }

    pub(in crate::cp) fn legacy_media_keys(&self) -> &[String] {
        &self.legacy_media_keys
    }

    pub(in crate::cp) fn episode_id(&self) -> i64 {
        self.episode_id
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct EpisodeDeleteReceipt {
    pub(in crate::cp) episode_id: i64,
    pub(in crate::cp) purge: EpisodePurge,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct EpisodeDeletePreparation {
    account_id: String,
    preparation_operation_id: WalLogicalOperationId,
    completion_operation_id: WalLogicalOperationId,
    predecessor_commitment: [u8; 32],
    mutation_stamp: String,
    receipt_commitment: [u8; 32],
    cleanup_commitment: [u8; 32],
    receipt: EpisodeDeleteReceipt,
    media: Vec<EpisodeDeleteMedia>,
    legacy_media_keys: Vec<String>,
    selectors: Vec<EpisodeDeleteSelector>,
}

impl EpisodeDeletePreparation {
    pub(in crate::cp) fn episode_id(&self) -> i64 {
        self.receipt.episode_id
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(in crate::cp) enum EpisodeDeleteCleanupTarget {
    Retained(EpisodeDeleteMedia),
    Legacy(String),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(in crate::cp) struct EpisodeDeleteCleanupItem {
    preparation: EpisodeDeletePreparation,
    selector_ordinal: i64,
    cleanup_kind: String,
    ordinal: i64,
    target: EpisodeDeleteCleanupTarget,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct EpisodeDeleteSelectorExpansion {
    preparation: EpisodeDeletePreparation,
    selector_ordinal: i64,
    selector: EpisodeDeleteSelector,
    predecessor_commitment: [u8; 32],
    event_ids: Vec<String>,
    work_unit_ids: Vec<String>,
    stream_ids: Vec<String>,
    session_ids: Vec<String>,
    browser_state_keys: Vec<String>,
    observation_ids: Vec<i64>,
    voice_page_sequence: i64,
    voice_scan_cursor: i64,
    voice_progress_commitment: Option<[u8; 32]>,
    voice_progress_rows: u64,
    reserved_cleanup_rows: u64,
    reserved_cleanup_bytes: u64,
    media: Vec<EpisodeDeleteMedia>,
    legacy_media_keys: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct VoiceEpisodePredecessor {
    episode_id: i64,
    identity_revision: i64,
    prior_progress: Option<VoiceEpisodeProgress>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct VoiceEpisodeProgress {
    page_sequence: i64,
    predecessor_revision: i64,
    resulting_revision: i64,
    page_predecessor_commitment: [u8; 32],
    progress_commitment: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct EpisodeDeleteVoicePage {
    preparation: EpisodeDeletePreparation,
    selector_ordinal: i64,
    selector: EpisodeDeleteSelector,
    expected_page_sequence: i64,
    expected_scan_cursor: i64,
    expected_progress_rows: u64,
    predecessor_commitment: [u8; 32],
    episodes: Vec<VoiceEpisodePredecessor>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct EpisodeDeleteVoiceReservation {
    preparation: EpisodeDeletePreparation,
    selector_ordinal: i64,
    selector: EpisodeDeleteSelector,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct EpisodeDeleteSelectorCompletion {
    preparation: EpisodeDeletePreparation,
    selector_ordinal: i64,
    selector: EpisodeDeleteSelector,
    expansion_predecessor_commitment: [u8; 32],
    cleanup_items_commitment: [u8; 32],
    cleanup_count: u64,
    cleanup_rows: u64,
    cleanup_bytes: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum EpisodeDeleteCleanupAction {
    ReserveVoiceCapacity(EpisodeDeleteVoiceReservation),
    Expand(Box<EpisodeDeleteSelectorExpansion>),
    AdvanceVoiceEpisodes(EpisodeDeleteVoicePage),
    Settle(EpisodeDeleteCleanupItem),
    FinishSelector(EpisodeDeleteSelectorCompletion),
    AdvanceResumeCursor {
        preparation: EpisodeDeletePreparation,
        expected_cursor: i64,
        expected_sequence: i64,
        episode_ids: Vec<i64>,
        next_cursor: i64,
    },
}

pub(in crate::cp) struct EpisodeDeleteResumeBatch {
    pub(in crate::cp) episode_ids: Vec<i64>,
    pub(in crate::cp) plan: EpisodeDeleteCleanupPlan,
}

pub(in crate::cp) enum EpisodeDeleteWork {
    Expand(EpisodeDeleteCleanupPlan),
    Provider(EpisodeDeleteCleanupItem),
    FinishSelector(EpisodeDeleteCleanupPlan),
    Complete(EpisodeDeletePlan),
}

impl EpisodeDeleteCleanupItem {
    pub(in crate::cp) fn target(&self) -> &EpisodeDeleteCleanupTarget {
        &self.target
    }

    pub(in crate::cp) fn episode_id(&self) -> i64 {
        self.preparation.receipt.episode_id
    }
}

pub(in crate::cp) enum EpisodeDeleteStart {
    Absent,
    Evidence(EpisodeDeleteEvidence),
    Prepared(EpisodeDeletePreparation),
    Complete(EpisodeDeleteReceipt),
}

pub(crate) struct EpisodeDeletePreparePlan {
    operation_id: WalLogicalOperationId,
    completion_operation_id: WalLogicalOperationId,
    account_id: String,
    evidence: EpisodeDeleteEvidence,
}

impl EpisodeDeletePreparePlan {
    pub(in crate::cp) fn new(account_id: String, evidence: EpisodeDeleteEvidence) -> Result<Self> {
        crate::store::validate_user_id(&account_id).map_err(|_| WalIdempotencyError::Malformed)?;
        validate_evidence(&account_id, &evidence)?;
        let episode = evidence.episode_id.to_be_bytes();
        let source = stable_operation_source(PREPARE_SUBTYPE, &[account_id.as_bytes(), &episode])?;
        let operation_id = WalLogicalOperationId::from_stable_source(
            WalOperationKind::EpisodeDeletePrepare,
            &source,
        )?;
        let completion_operation_id = completion_operation_id(&account_id, evidence.episode_id)?;
        Ok(Self {
            operation_id,
            completion_operation_id,
            account_id,
            evidence,
        })
    }

    fn apply_exact(&self, transaction: &Transaction<'_>) -> Result<()> {
        let current =
            load_episode_delete_evidence(transaction, &self.account_id, self.evidence.episode_id)?
                .ok_or(WalIdempotencyError::Precondition)?;
        if current != self.evidence {
            return Err(WalIdempotencyError::Precondition);
        }
        let purge = purge_episode_transaction_at_deferred_voice(
            transaction,
            self.evidence.episode_id,
            &self.evidence.mutation_stamp,
        )
        .map_err(|_| WalIdempotencyError::Unavailable)?
        .ok_or(WalIdempotencyError::Precondition)?;
        if purge != self.evidence.purge {
            return Err(WalIdempotencyError::Corrupt);
        }

        for event_id in &self.evidence.event_ids {
            transaction
                .execute("DELETE FROM capture_events WHERE event_id=?1", [event_id])
                .map_err(|_| WalIdempotencyError::Unavailable)?;
        }
        for stream_id in &self.evidence.stream_ids {
            transaction
                .execute(
                    "DELETE FROM capture_streams
                     WHERE id=?1 AND NOT EXISTS (
                        SELECT 1 FROM capture_events event WHERE event.stream_id=capture_streams.id
                     )",
                    [stream_id],
                )
                .map_err(|_| WalIdempotencyError::Unavailable)?;
        }
        for session_id in &self.evidence.session_ids {
            transaction
                .execute(
                    "DELETE FROM capture_sessions
                     WHERE id=?1 AND NOT EXISTS (
                        SELECT 1 FROM capture_events event
                        WHERE event.capture_session_id=capture_sessions.id
                     ) AND NOT EXISTS (
                        SELECT 1 FROM capture_streams stream
                        WHERE stream.capture_session_id=capture_sessions.id
                     )",
                    [session_id],
                )
                .map_err(|_| WalIdempotencyError::Unavailable)?;
        }
        for work_unit_id in &self.evidence.work_unit_ids {
            transaction
                .execute(
                    "DELETE FROM media_work_units
                     WHERE id=?1 AND NOT EXISTS (
                        SELECT 1 FROM media_work_members m
                        WHERE m.work_unit_id=media_work_units.id
                     )",
                    [work_unit_id],
                )
                .map_err(|_| WalIdempotencyError::Unavailable)?;
        }
        for snapshot_id in &self.evidence.legacy_browser_snapshot_ids {
            transaction
                .execute(
                    "DELETE FROM browser_snapshots
                     WHERE id=?1 AND NOT EXISTS (
                        SELECT 1 FROM screenshots screenshot
                        WHERE screenshot.browser_snapshot_source_key=browser_snapshots.source_key
                     )",
                    [snapshot_id],
                )
                .map_err(|_| WalIdempotencyError::Unavailable)?;
        }
        for state_key in &self.evidence.browser_state_keys {
            transaction
                .execute(
                    "DELETE FROM browser_states_v2
                     WHERE state_key=?1 AND NOT EXISTS (
                        SELECT 1 FROM browser_observations_v2 o
                        WHERE o.state_key=browser_states_v2.state_key
                     )",
                    [state_key],
                )
                .map_err(|_| WalIdempotencyError::Unavailable)?;
        }
        if transaction
            .query_row(
                "SELECT COUNT(*) FROM episodes WHERE id=?1",
                [self.evidence.episode_id],
                |row| row.get::<_, i64>(0),
            )
            .map_err(|_| WalIdempotencyError::Unavailable)?
            != 0
        {
            return Err(WalIdempotencyError::Corrupt);
        }
        for event_id in &self.evidence.event_ids {
            if transaction
                .query_row(
                    "SELECT COUNT(*) FROM capture_events WHERE event_id=?1",
                    [event_id],
                    |row| row.get::<_, i64>(0),
                )
                .map_err(|_| WalIdempotencyError::Unavailable)?
                != 0
            {
                return Err(WalIdempotencyError::Corrupt);
            }
        }
        Ok(())
    }
}

pub(crate) struct EpisodeDeletePrepareLedger;

impl WalLogicalDomainPlan for EpisodeDeletePreparePlan {
    type Ledger = EpisodeDeletePrepareLedger;
    type Output = EpisodeDeletePreparation;

    fn kind(&self) -> WalOperationKind {
        WalOperationKind::EpisodeDeletePrepare
    }

    fn operation_id(&self) -> WalLogicalOperationId {
        self.operation_id
    }

    fn canonical_request(&self) -> Result<Zeroizing<Vec<u8>>> {
        prepare_request(
            &self.account_id,
            self.evidence.episode_id,
            self.evidence.predecessor_commitment,
        )
    }

    fn apply(&self, transaction: &Transaction<'_>) -> Result<WalReplayResult> {
        self.apply_exact(transaction)?;
        Ok(WalReplayResult::unit())
    }

    fn validate_replay(&self, result: &WalReplayResult) -> Result<()> {
        match result {
            WalReplayResult::UnitApplied => Ok(()),
            WalReplayResult::CanonicalResponse(_) => Err(WalIdempotencyError::ResultUnsupported),
        }
    }

    fn decode_output(&self, result: &WalReplayResult) -> Result<Self::Output> {
        self.validate_replay(result)?;
        preparation_from_evidence(
            self.account_id.clone(),
            self.operation_id,
            self.completion_operation_id,
            &self.evidence,
        )
    }
}

pub(crate) struct EpisodeDeletePlan {
    operation_id: WalLogicalOperationId,
    preparation: EpisodeDeletePreparation,
    final_cleanup_commitment: [u8; 32],
}

impl EpisodeDeletePlan {
    fn new(
        preparation: EpisodeDeletePreparation,
        final_cleanup_commitment: [u8; 32],
    ) -> Result<Self> {
        validate_preparation(&preparation)?;
        if final_cleanup_commitment == [0; 32] {
            return Err(WalIdempotencyError::Malformed);
        }
        Ok(Self {
            operation_id: preparation.completion_operation_id,
            preparation,
            final_cleanup_commitment,
        })
    }
}

pub(crate) struct EpisodeDeleteLedger;

pub(crate) struct EpisodeDeleteCleanupPlan {
    operation_id: WalLogicalOperationId,
    action: EpisodeDeleteCleanupAction,
    request_fingerprint: WalRequestFingerprint,
}

impl EpisodeDeleteCleanupPlan {
    pub(in crate::cp) fn new(item: EpisodeDeleteCleanupItem) -> Result<Self> {
        validate_preparation(&item.preparation)?;
        if item.selector_ordinal < 0
            || item.ordinal < 0
            || !matches!(item.cleanup_kind.as_str(), "retained" | "legacy")
        {
            return Err(WalIdempotencyError::Malformed);
        }
        match (&item.cleanup_kind[..], &item.target) {
            ("retained", EpisodeDeleteCleanupTarget::Retained(row)) => {
                validate_media_for_account(
                    &item.preparation.account_id,
                    std::slice::from_ref(row),
                )?;
            }
            ("legacy", EpisodeDeleteCleanupTarget::Legacy(key))
                if !key.is_empty() && key.len() <= MAX_SOURCE_KEY_BYTES => {}
            _ => return Err(WalIdempotencyError::Malformed),
        }
        let ordinal = item.ordinal.to_be_bytes();
        let selector_ordinal = item.selector_ordinal.to_be_bytes();
        let source = stable_operation_source(
            CLEANUP_SUBTYPE,
            &[
                item.preparation.account_id.as_bytes(),
                item.preparation.preparation_operation_id.as_bytes(),
                item.cleanup_kind.as_bytes(),
                &selector_ordinal,
                &ordinal,
            ],
        )?;
        let action = EpisodeDeleteCleanupAction::Settle(item);
        let request_fingerprint = WalRequestFingerprint::derive(
            WalOperationKind::EpisodeDeleteCleanup,
            &cleanup_action_request(&action)?,
        )?;
        Ok(Self {
            operation_id: WalLogicalOperationId::from_stable_source(
                WalOperationKind::EpisodeDeleteCleanup,
                &source,
            )?,
            action,
            request_fingerprint,
        })
    }

    fn expand(expansion: EpisodeDeleteSelectorExpansion) -> Result<Self> {
        validate_preparation(&expansion.preparation)?;
        validate_selector_expansion(&expansion)?;
        let ordinal = expansion.selector_ordinal.to_be_bytes();
        let source = stable_operation_source(
            CLEANUP_SUBTYPE,
            &[
                expansion.preparation.account_id.as_bytes(),
                expansion.preparation.preparation_operation_id.as_bytes(),
                b"expand",
                &ordinal,
            ],
        )?;
        let action = EpisodeDeleteCleanupAction::Expand(Box::new(expansion));
        let request_fingerprint = WalRequestFingerprint::derive(
            WalOperationKind::EpisodeDeleteCleanup,
            &cleanup_action_request(&action)?,
        )?;
        Ok(Self {
            operation_id: WalLogicalOperationId::from_stable_source(
                WalOperationKind::EpisodeDeleteCleanup,
                &source,
            )?,
            action,
            request_fingerprint,
        })
    }

    fn reserve_voice_capacity(reservation: EpisodeDeleteVoiceReservation) -> Result<Self> {
        validate_preparation(&reservation.preparation)?;
        validate_selectors(std::slice::from_ref(&reservation.selector))?;
        if reservation.selector_ordinal < 0 || reservation.selector.selector_kind != "voice" {
            return Err(WalIdempotencyError::Malformed);
        }
        let ordinal = reservation.selector_ordinal.to_be_bytes();
        let source = stable_operation_source(
            CLEANUP_SUBTYPE,
            &[
                reservation.preparation.account_id.as_bytes(),
                reservation.preparation.preparation_operation_id.as_bytes(),
                b"voice-reserve",
                &ordinal,
            ],
        )?;
        let action = EpisodeDeleteCleanupAction::ReserveVoiceCapacity(reservation);
        let request_fingerprint = WalRequestFingerprint::derive(
            WalOperationKind::EpisodeDeleteCleanup,
            &cleanup_action_request(&action)?,
        )?;
        Ok(Self {
            operation_id: WalLogicalOperationId::from_stable_source(
                WalOperationKind::EpisodeDeleteCleanup,
                &source,
            )?,
            action,
            request_fingerprint,
        })
    }

    fn advance_voice_episodes(page: EpisodeDeleteVoicePage) -> Result<Self> {
        validate_preparation(&page.preparation)?;
        validate_voice_page(&page)?;
        let ordinal = page.selector_ordinal.to_be_bytes();
        let sequence = page
            .expected_page_sequence
            .checked_add(1)
            .ok_or(WalIdempotencyError::Limit)?
            .to_be_bytes();
        let source = stable_operation_source(
            CLEANUP_SUBTYPE,
            &[
                page.preparation.account_id.as_bytes(),
                page.preparation.preparation_operation_id.as_bytes(),
                b"voice-page",
                &ordinal,
                &sequence,
            ],
        )?;
        let action = EpisodeDeleteCleanupAction::AdvanceVoiceEpisodes(page);
        let request_fingerprint = WalRequestFingerprint::derive(
            WalOperationKind::EpisodeDeleteCleanup,
            &cleanup_action_request(&action)?,
        )?;
        Ok(Self {
            operation_id: WalLogicalOperationId::from_stable_source(
                WalOperationKind::EpisodeDeleteCleanup,
                &source,
            )?,
            action,
            request_fingerprint,
        })
    }

    fn finish_selector(completion: EpisodeDeleteSelectorCompletion) -> Result<Self> {
        validate_preparation(&completion.preparation)?;
        if completion.selector_ordinal < 0
            || completion.expansion_predecessor_commitment == [0; 32]
            || completion.cleanup_items_commitment == [0; 32]
        {
            return Err(WalIdempotencyError::Malformed);
        }
        validate_selectors(std::slice::from_ref(&completion.selector))?;
        let ordinal = completion.selector_ordinal.to_be_bytes();
        let source = stable_operation_source(
            CLEANUP_SUBTYPE,
            &[
                completion.preparation.account_id.as_bytes(),
                completion.preparation.preparation_operation_id.as_bytes(),
                b"finish",
                &ordinal,
            ],
        )?;
        let action = EpisodeDeleteCleanupAction::FinishSelector(completion);
        let request_fingerprint = WalRequestFingerprint::derive(
            WalOperationKind::EpisodeDeleteCleanup,
            &cleanup_action_request(&action)?,
        )?;
        Ok(Self {
            operation_id: WalLogicalOperationId::from_stable_source(
                WalOperationKind::EpisodeDeleteCleanup,
                &source,
            )?,
            action,
            request_fingerprint,
        })
    }

    fn advance_resume_cursor(
        preparation: EpisodeDeletePreparation,
        expected_cursor: i64,
        expected_sequence: i64,
        episode_ids: Vec<i64>,
        next_cursor: i64,
    ) -> Result<Self> {
        validate_preparation(&preparation)?;
        if expected_cursor < 0
            || expected_sequence < 0
            || next_cursor <= 0
            || episode_ids.is_empty()
            || episode_ids.len() > 4
            || episode_ids.iter().any(|id| *id <= 0)
        {
            return Err(WalIdempotencyError::Malformed);
        }
        let next_sequence = expected_sequence
            .checked_add(1)
            .ok_or(WalIdempotencyError::Limit)?;
        let source = stable_operation_source(
            CLEANUP_SUBTYPE,
            &[
                preparation.account_id.as_bytes(),
                b"resume-cursor",
                &next_sequence.to_be_bytes(),
            ],
        )?;
        let action = EpisodeDeleteCleanupAction::AdvanceResumeCursor {
            preparation,
            expected_cursor,
            expected_sequence,
            episode_ids,
            next_cursor,
        };
        let request_fingerprint = WalRequestFingerprint::derive(
            WalOperationKind::EpisodeDeleteCleanup,
            &cleanup_action_request(&action)?,
        )?;
        Ok(Self {
            operation_id: WalLogicalOperationId::from_stable_source(
                WalOperationKind::EpisodeDeleteCleanup,
                &source,
            )?,
            action,
            request_fingerprint,
        })
    }

    fn preparation(&self) -> &EpisodeDeletePreparation {
        match &self.action {
            EpisodeDeleteCleanupAction::ReserveVoiceCapacity(reservation) => {
                &reservation.preparation
            }
            EpisodeDeleteCleanupAction::Expand(expansion) => &expansion.preparation,
            EpisodeDeleteCleanupAction::AdvanceVoiceEpisodes(page) => &page.preparation,
            EpisodeDeleteCleanupAction::Settle(item) => &item.preparation,
            EpisodeDeleteCleanupAction::FinishSelector(completion) => &completion.preparation,
            EpisodeDeleteCleanupAction::AdvanceResumeCursor { preparation, .. } => preparation,
        }
    }
}

pub(crate) struct EpisodeDeleteCleanupLedger;

impl WalLogicalDomainPlan for EpisodeDeleteCleanupPlan {
    type Ledger = EpisodeDeleteCleanupLedger;
    type Output = ();

    fn kind(&self) -> WalOperationKind {
        WalOperationKind::EpisodeDeleteCleanup
    }

    fn operation_id(&self) -> WalLogicalOperationId {
        self.operation_id
    }

    fn canonical_request(&self) -> Result<Zeroizing<Vec<u8>>> {
        cleanup_action_request(&self.action)
    }

    fn apply(&self, transaction: &Transaction<'_>) -> Result<WalReplayResult> {
        match &self.action {
            EpisodeDeleteCleanupAction::ReserveVoiceCapacity(reservation) => {
                apply_voice_capacity_reservation(transaction, reservation)?;
            }
            EpisodeDeleteCleanupAction::Settle(item) => {
                let changed = transaction
                    .execute(
                        "UPDATE archive_v3_wal_episode_delete_cleanup
                 SET cleanup_state='complete'
                 WHERE preparation_operation_id=?1 AND selector_ordinal=?2
                   AND cleanup_kind=?3 AND ordinal=?4
                   AND object_key=?5 AND object_generation IS ?6 AND object_backend IS ?7
                   AND sha256 IS ?8 AND cleanup_state='pending'",
                        params![
                            item.preparation
                                .preparation_operation_id
                                .as_bytes()
                                .as_slice(),
                            item.selector_ordinal,
                            item.cleanup_kind,
                            item.ordinal,
                            cleanup_object_key(&item.target),
                            cleanup_generation(&item.target),
                            cleanup_backend(&item.target),
                            cleanup_sha256(&item.target),
                        ],
                    )
                    .map_err(|_| WalIdempotencyError::Unavailable)?;
                if changed != 1 {
                    return Err(WalIdempotencyError::Precondition);
                }
                if transaction
                    .execute(
                        "UPDATE archive_v3_wal_episode_delete_selectors
                         SET settled_count=settled_count+1
                         WHERE preparation_operation_id=?1 AND ordinal=?2
                           AND selector_state='cleaning'
                           AND settled_count<cleanup_count",
                        params![
                            item.preparation
                                .preparation_operation_id
                                .as_bytes()
                                .as_slice(),
                            item.selector_ordinal,
                        ],
                    )
                    .map_err(|_| WalIdempotencyError::Unavailable)?
                    != 1
                {
                    return Err(WalIdempotencyError::Precondition);
                }
            }
            EpisodeDeleteCleanupAction::Expand(expansion) => {
                apply_selector_expansion(transaction, expansion, self.request_fingerprint)?;
            }
            EpisodeDeleteCleanupAction::AdvanceVoiceEpisodes(page) => {
                apply_voice_episode_page(transaction, page, self.request_fingerprint)?;
            }
            EpisodeDeleteCleanupAction::FinishSelector(completion) => {
                let exact = load_selector_completion(
                    transaction,
                    completion.preparation.clone(),
                    completion.selector_ordinal,
                )?;
                if exact != *completion {
                    return Err(WalIdempotencyError::Precondition);
                }
                let state = load_ledger_state(transaction)?;
                if state.source_count < completion.cleanup_rows
                    || state.source_bytes < completion.cleanup_bytes
                {
                    return Err(WalIdempotencyError::Corrupt);
                }
                transaction
                    .execute(
                        "DELETE FROM archive_v3_wal_episode_delete_cleanup
                         WHERE preparation_operation_id=?1 AND selector_ordinal=?2",
                        params![
                            completion
                                .preparation
                                .preparation_operation_id
                                .as_bytes()
                                .as_slice(),
                            completion.selector_ordinal,
                        ],
                    )
                    .map_err(|_| WalIdempotencyError::Unavailable)?;
                if transaction
                    .execute(
                        "UPDATE archive_v3_wal_episode_delete_selectors
                         SET selector_state='complete',
                             finish_request_fingerprint=?10
                         WHERE preparation_operation_id=?1 AND ordinal=?2
                           AND selector_kind=?3 AND selector_ref=?4
                           AND selector_state='cleaning'
                           AND expansion_predecessor_commitment=?5
                           AND cleanup_items_commitment=?6
                           AND cleanup_count=?7 AND settled_count=?7
                           AND cleanup_rows=?8 AND cleanup_bytes=?9
                           AND expansion_request_fingerprint IS NOT NULL
                           AND finish_request_fingerprint IS NULL",
                        params![
                            completion
                                .preparation
                                .preparation_operation_id
                                .as_bytes()
                                .as_slice(),
                            completion.selector_ordinal,
                            completion.selector.selector_kind,
                            completion.selector.selector_ref,
                            completion.expansion_predecessor_commitment.as_slice(),
                            completion.cleanup_items_commitment.as_slice(),
                            i64::try_from(completion.cleanup_count)
                                .map_err(|_| WalIdempotencyError::Limit)?,
                            i64::try_from(completion.cleanup_rows)
                                .map_err(|_| WalIdempotencyError::Limit)?,
                            i64::try_from(completion.cleanup_bytes)
                                .map_err(|_| WalIdempotencyError::Limit)?,
                            self.request_fingerprint.as_bytes().as_slice(),
                        ],
                    )
                    .map_err(|_| WalIdempotencyError::Unavailable)?
                    != 1
                {
                    return Err(WalIdempotencyError::Precondition);
                }
                if transaction
                    .execute(
                        "UPDATE archive_v3_wal_episode_delete_state
                         SET source_count=source_count-?1,source_bytes=source_bytes-?2
                         WHERE singleton=1 AND source_count=?3 AND source_bytes=?4",
                        params![
                            i64::try_from(completion.cleanup_rows)
                                .map_err(|_| WalIdempotencyError::Limit)?,
                            i64::try_from(completion.cleanup_bytes)
                                .map_err(|_| WalIdempotencyError::Limit)?,
                            i64::try_from(state.source_count)
                                .map_err(|_| WalIdempotencyError::Corrupt)?,
                            i64::try_from(state.source_bytes)
                                .map_err(|_| WalIdempotencyError::Corrupt)?,
                        ],
                    )
                    .map_err(|_| WalIdempotencyError::Unavailable)?
                    != 1
                {
                    return Err(WalIdempotencyError::Corrupt);
                }
            }
            EpisodeDeleteCleanupAction::AdvanceResumeCursor {
                preparation,
                expected_cursor,
                expected_sequence,
                episode_ids,
                next_cursor,
            } => {
                if pending_episode_ids_after_cursor(
                    transaction,
                    *expected_cursor,
                    episode_ids.len(),
                )? != *episode_ids
                    || preparation.receipt.episode_id != episode_ids[0]
                {
                    return Err(WalIdempotencyError::Precondition);
                }
                if transaction
                    .execute(
                        "UPDATE archive_v3_wal_episode_delete_state
                         SET resume_cursor=?1,resume_sequence=resume_sequence+1
                         WHERE singleton=1 AND resume_cursor=?2 AND resume_sequence=?3",
                        params![next_cursor, expected_cursor, expected_sequence],
                    )
                    .map_err(|_| WalIdempotencyError::Unavailable)?
                    != 1
                {
                    return Err(WalIdempotencyError::Precondition);
                }
            }
        }
        Ok(WalReplayResult::unit())
    }

    fn validate_replay(&self, result: &WalReplayResult) -> Result<()> {
        matches!(result, WalReplayResult::UnitApplied)
            .then_some(())
            .ok_or(WalIdempotencyError::ResultUnsupported)
    }

    fn decode_output(&self, result: &WalReplayResult) -> Result<Self::Output> {
        self.validate_replay(result)
    }
}

impl WalLogicalDomainPlan for EpisodeDeletePlan {
    type Ledger = EpisodeDeleteLedger;
    type Output = EpisodeDeleteReceipt;

    fn kind(&self) -> WalOperationKind {
        WalOperationKind::EpisodeDelete
    }

    fn operation_id(&self) -> WalLogicalOperationId {
        self.operation_id
    }

    fn canonical_request(&self) -> Result<Zeroizing<Vec<u8>>> {
        completion_request(&self.preparation, self.final_cleanup_commitment)
    }

    fn apply(&self, _transaction: &Transaction<'_>) -> Result<WalReplayResult> {
        Ok(WalReplayResult::unit())
    }

    fn validate_replay(&self, result: &WalReplayResult) -> Result<()> {
        match result {
            WalReplayResult::UnitApplied => Ok(()),
            WalReplayResult::CanonicalResponse(_) => Err(WalIdempotencyError::ResultUnsupported),
        }
    }

    fn decode_output(&self, result: &WalReplayResult) -> Result<Self::Output> {
        self.validate_replay(result)?;
        Ok(self.preparation.receipt.clone())
    }
}

impl WalLogicalDomainLedger<EpisodeDeletePreparePlan> for EpisodeDeletePrepareLedger {
    fn lookup(
        connection: &Connection,
        prepared: &PreparedLogicalMutation<EpisodeDeletePreparePlan>,
    ) -> Result<Option<WalReplayResult>> {
        require_prepare_kind(prepared)?;
        if schema_state(connection)? == LedgerSchemaState::Absent {
            return Ok(None);
        }
        validate_schema_marker(connection)?;
        let row = connection
            .query_row(
                "SELECT prepare_format_version,prepare_codec_version,prepare_request_fingerprint,
                        prepare_result_bytes,prepare_result_commitment
                 FROM archive_v3_wal_episode_delete_operations
                 WHERE preparation_operation_id=?1",
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
        let kind = WalOperationKind::EpisodeDeletePrepare;
        if format != i64::from(WalOperationKind::format_version())
            || codec != i64::from(kind.codec_version())
            || fingerprint.as_slice()
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
        prepared: &PreparedLogicalMutation<EpisodeDeletePreparePlan>,
    ) -> Result<LogicalMutationResult> {
        require_prepare_kind(prepared)?;
        ensure_schema(transaction)?;
        if let Some(result) = Self::lookup(transaction, prepared)? {
            return Ok(LogicalMutationResult::Replayed(result));
        }
        let state = load_ledger_state(transaction)?;
        BOUNDS.admit(
            state.row_count,
            state.result_bytes,
            UNIT_RESULT_BYTES
                .checked_mul(2)
                .ok_or(WalIdempotencyError::Limit)?,
        )?;
        let plan = prepared.plan_for_domain_ledger();
        let (source_rows, source_bytes) = stored_variable_usage(&plan.evidence)?;
        if state
            .source_count
            .checked_add(u64::try_from(source_rows).map_err(|_| WalIdempotencyError::Limit)?)
            .is_none_or(|value| value > MAX_SOURCE_ROWS)
            || state
                .source_bytes
                .checked_add(source_bytes)
                .is_none_or(|value| value > MAX_SOURCE_BYTES)
        {
            return Err(WalIdempotencyError::Limit);
        }

        let result = plan.apply(transaction)?;
        plan.validate_replay(&result)?;
        let kind = WalOperationKind::EpisodeDeletePrepare;
        let encoded = result.encode(kind)?;
        let commitment = result.commitment(kind)?;
        let receipt_commitment =
            receipt_commitment(plan.evidence.episode_id, &plan.evidence.purge)?;
        let cleanup_commitment = cleanup_commitment(
            &plan.evidence.media,
            &plan.evidence.legacy_media_keys,
            &plan.evidence.selectors,
        )?;
        transaction
            .execute(
                "INSERT INTO archive_v3_wal_episode_delete_operations
                 (preparation_operation_id,completion_operation_id,episode_id,
                  prepare_format_version,prepare_codec_version,prepare_request_fingerprint,
                  prepare_result_bytes,prepare_result_commitment,deleted_utterances,
                  deleted_screenshots,deleted_segments,predecessor_commitment,
                  receipt_commitment,cleanup_commitment,mutation_stamp)
                 VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15)",
                params![
                    prepared.operation_id_for_owner().as_bytes().as_slice(),
                    plan.completion_operation_id.as_bytes().as_slice(),
                    plan.evidence.episode_id,
                    i64::from(WalOperationKind::format_version()),
                    i64::from(kind.codec_version()),
                    prepared
                        .request_fingerprint_for_owner()
                        .as_bytes()
                        .as_slice(),
                    encoded.as_slice(),
                    commitment.as_slice(),
                    i64::try_from(plan.evidence.purge.deleted_utterances)
                        .map_err(|_| WalIdempotencyError::Limit)?,
                    i64::try_from(plan.evidence.purge.deleted_screenshots)
                        .map_err(|_| WalIdempotencyError::Limit)?,
                    i64::try_from(plan.evidence.purge.deleted_segments)
                        .map_err(|_| WalIdempotencyError::Limit)?,
                    plan.evidence.predecessor_commitment.as_slice(),
                    receipt_commitment.as_slice(),
                    cleanup_commitment.as_slice(),
                    plan.evidence.mutation_stamp,
                ],
            )
            .map_err(|_| WalIdempotencyError::Unavailable)?;
        insert_sources(
            transaction,
            prepared.operation_id_for_owner(),
            &plan.evidence.purge,
        )?;
        insert_cleanup(
            transaction,
            prepared.operation_id_for_owner(),
            &plan.evidence.media,
            &plan.evidence.legacy_media_keys,
        )?;
        insert_selectors(
            transaction,
            prepared.operation_id_for_owner(),
            &plan.evidence.selectors,
        )?;
        if transaction
            .execute(
                "UPDATE archive_v3_wal_episode_delete_state
                 SET row_count=row_count+1,result_bytes=result_bytes+?1,
                     source_count=source_count+?2,source_bytes=source_bytes+?3
                 WHERE singleton=1 AND row_count=?4 AND result_bytes=?5
                   AND source_count=?6 AND source_bytes=?7",
                params![
                    i64::try_from(UNIT_RESULT_BYTES * 2).map_err(|_| WalIdempotencyError::Limit)?,
                    i64::try_from(source_rows).map_err(|_| WalIdempotencyError::Limit)?,
                    i64::try_from(source_bytes).map_err(|_| WalIdempotencyError::Limit)?,
                    i64::from(state.row_count),
                    i64::try_from(state.result_bytes).map_err(|_| WalIdempotencyError::Corrupt)?,
                    i64::try_from(state.source_count).map_err(|_| WalIdempotencyError::Corrupt)?,
                    i64::try_from(state.source_bytes).map_err(|_| WalIdempotencyError::Corrupt)?,
                ],
            )
            .map_err(|_| WalIdempotencyError::Unavailable)?
            != 1
        {
            return Err(WalIdempotencyError::Corrupt);
        }
        Ok(LogicalMutationResult::Applied(result))
    }
}

impl WalLogicalDomainLedger<EpisodeDeletePlan> for EpisodeDeleteLedger {
    fn lookup(
        connection: &Connection,
        prepared: &PreparedLogicalMutation<EpisodeDeletePlan>,
    ) -> Result<Option<WalReplayResult>> {
        require_complete_kind(prepared)?;
        if schema_state(connection)? == LedgerSchemaState::Absent {
            return Ok(None);
        }
        validate_schema_marker(connection)?;
        let stored = load_preparation_by_id(
            connection,
            &prepared.plan_for_domain_ledger().preparation.account_id,
            prepared
                .plan_for_domain_ledger()
                .preparation
                .receipt
                .episode_id,
        )?
        .ok_or(WalIdempotencyError::Precondition)?;
        if stored.preparation != prepared.plan_for_domain_ledger().preparation {
            return Err(WalIdempotencyError::FingerprintConflict);
        }
        let Some(completion) = stored.completion else {
            return Ok(None);
        };
        if completion.operation_id != prepared.operation_id_for_owner()
            || completion.request_fingerprint != prepared.request_fingerprint_for_owner()
        {
            return Err(WalIdempotencyError::FingerprintConflict);
        }
        prepared
            .plan_for_domain_ledger()
            .validate_replay(&completion.result)?;
        Ok(Some(completion.result))
    }

    fn resolve_or_apply(
        transaction: &Transaction<'_>,
        prepared: &PreparedLogicalMutation<EpisodeDeletePlan>,
    ) -> Result<LogicalMutationResult> {
        require_complete_kind(prepared)?;
        ensure_schema(transaction)?;
        if let Some(result) = Self::lookup(transaction, prepared)? {
            return Ok(LogicalMutationResult::Replayed(result));
        }
        let plan = prepared.plan_for_domain_ledger();
        let stored = load_preparation_by_id(
            transaction,
            &plan.preparation.account_id,
            plan.preparation.receipt.episode_id,
        )?
        .ok_or(WalIdempotencyError::Precondition)?;
        if stored.preparation != plan.preparation || stored.completion.is_some() {
            return Err(WalIdempotencyError::Precondition);
        }
        if final_selector_cleanup_commitment(transaction, &plan.preparation)?
            != plan.final_cleanup_commitment
        {
            return Err(WalIdempotencyError::Precondition);
        }
        let pending = transaction
            .query_row(
                "SELECT COUNT(*) FROM archive_v3_wal_episode_delete_cleanup
                 WHERE preparation_operation_id=?1",
                [plan
                    .preparation
                    .preparation_operation_id
                    .as_bytes()
                    .as_slice()],
                |row| row.get::<_, i64>(0),
            )
            .map_err(|_| WalIdempotencyError::Unavailable)?;
        if pending != 0 {
            return Err(WalIdempotencyError::Precondition);
        }
        let pending_selectors = transaction
            .query_row(
                "SELECT COUNT(*) FROM archive_v3_wal_episode_delete_selectors
                 WHERE preparation_operation_id=?1 AND selector_state<>'complete'",
                [plan
                    .preparation
                    .preparation_operation_id
                    .as_bytes()
                    .as_slice()],
                |row| row.get::<_, i64>(0),
            )
            .map_err(|_| WalIdempotencyError::Unavailable)?;
        if pending_selectors != 0 {
            return Err(WalIdempotencyError::Precondition);
        }
        let result = plan.apply(transaction)?;
        plan.validate_replay(&result)?;
        let kind = WalOperationKind::EpisodeDelete;
        let encoded = result.encode(kind)?;
        let commitment = result.commitment(kind)?;
        if transaction
            .execute(
                "UPDATE archive_v3_wal_episode_delete_operations
                 SET completion_format_version=?1,completion_codec_version=?2,
                     completion_request_fingerprint=?3,completion_result_bytes=?4,
                     completion_result_commitment=?5
                 WHERE preparation_operation_id=?6 AND completion_operation_id=?7
                   AND predecessor_commitment=?8 AND receipt_commitment=?9
                   AND cleanup_commitment=?10
                   AND completion_format_version IS NULL
                   AND completion_codec_version IS NULL
                   AND completion_request_fingerprint IS NULL
                   AND completion_result_bytes IS NULL
                   AND completion_result_commitment IS NULL",
                params![
                    i64::from(WalOperationKind::format_version()),
                    i64::from(kind.codec_version()),
                    prepared
                        .request_fingerprint_for_owner()
                        .as_bytes()
                        .as_slice(),
                    encoded.as_slice(),
                    commitment.as_slice(),
                    plan.preparation
                        .preparation_operation_id
                        .as_bytes()
                        .as_slice(),
                    prepared.operation_id_for_owner().as_bytes().as_slice(),
                    plan.preparation.predecessor_commitment.as_slice(),
                    plan.preparation.receipt_commitment.as_slice(),
                    plan.preparation.cleanup_commitment.as_slice(),
                ],
            )
            .map_err(|_| WalIdempotencyError::Unavailable)?
            != 1
        {
            return Err(WalIdempotencyError::Precondition);
        }
        transaction
            .execute(
                "DELETE FROM archive_v3_wal_episode_delete_progress
                 WHERE preparation_operation_id=?1",
                [plan
                    .preparation
                    .preparation_operation_id
                    .as_bytes()
                    .as_slice()],
            )
            .map_err(|_| WalIdempotencyError::Unavailable)?;
        Ok(LogicalMutationResult::Applied(result))
    }
}

impl WalLogicalDomainLedger<EpisodeDeleteCleanupPlan> for EpisodeDeleteCleanupLedger {
    fn lookup(
        connection: &Connection,
        prepared: &PreparedLogicalMutation<EpisodeDeleteCleanupPlan>,
    ) -> Result<Option<WalReplayResult>> {
        require_cleanup_kind(prepared)?;
        if schema_state(connection)? == LedgerSchemaState::Absent {
            return Ok(None);
        }
        validate_schema_marker(connection)?;
        let row = connection
            .query_row(
                "SELECT request_fingerprint,result_bytes,result_commitment
                 FROM archive_v3_wal_episode_delete_progress WHERE operation_id=?1",
                [prepared.operation_id_for_owner().as_bytes().as_slice()],
                |row| {
                    Ok((
                        row.get::<_, Vec<u8>>(0)?,
                        row.get::<_, Vec<u8>>(1)?,
                        row.get::<_, Vec<u8>>(2)?,
                    ))
                },
            )
            .optional()
            .map_err(|_| WalIdempotencyError::Unavailable)?;
        let Some((fingerprint, encoded, commitment)) = row else {
            return Ok(None);
        };
        if fingerprint.as_slice()
            != prepared
                .request_fingerprint_for_owner()
                .as_bytes()
                .as_slice()
        {
            return Err(WalIdempotencyError::FingerprintConflict);
        }
        let result = WalReplayResult::decode(WalOperationKind::EpisodeDeleteCleanup, &encoded)?;
        if commitment.as_slice()
            != result
                .commitment(WalOperationKind::EpisodeDeleteCleanup)?
                .as_slice()
        {
            return Err(WalIdempotencyError::Corrupt);
        }
        prepared.plan_for_domain_ledger().validate_replay(&result)?;
        Ok(Some(result))
    }

    fn resolve_or_apply(
        transaction: &Transaction<'_>,
        prepared: &PreparedLogicalMutation<EpisodeDeleteCleanupPlan>,
    ) -> Result<LogicalMutationResult> {
        require_cleanup_kind(prepared)?;
        ensure_schema(transaction)?;
        if let Some(result) = Self::lookup(transaction, prepared)? {
            return Ok(LogicalMutationResult::Replayed(result));
        }
        let result = prepared.plan_for_domain_ledger().apply(transaction)?;
        prepared.plan_for_domain_ledger().validate_replay(&result)?;
        let encoded = result.encode(WalOperationKind::EpisodeDeleteCleanup)?;
        let commitment = result.commitment(WalOperationKind::EpisodeDeleteCleanup)?;
        // Cleanup actions are internal and strictly serialized by the exact
        // selector/item state machine. Retain the immediately preceding
        // response for the only lost-ack window, then replace it as forward
        // progress becomes durable. This bounds the sidecar to one row per
        // pending episode instead of one permanent row per provider object.
        transaction
            .execute(
                "DELETE FROM archive_v3_wal_episode_delete_progress
                 WHERE preparation_operation_id=?1",
                [prepared
                    .plan_for_domain_ledger()
                    .preparation()
                    .preparation_operation_id
                    .as_bytes()
                    .as_slice()],
            )
            .map_err(|_| WalIdempotencyError::Unavailable)?;
        transaction
            .execute(
                "INSERT INTO archive_v3_wal_episode_delete_progress
                 (operation_id,preparation_operation_id,request_fingerprint,
                  result_bytes,result_commitment)
                 VALUES (?1,?2,?3,?4,?5)",
                params![
                    prepared.operation_id_for_owner().as_bytes().as_slice(),
                    prepared
                        .plan_for_domain_ledger()
                        .preparation()
                        .preparation_operation_id
                        .as_bytes()
                        .as_slice(),
                    prepared
                        .request_fingerprint_for_owner()
                        .as_bytes()
                        .as_slice(),
                    encoded.as_slice(),
                    commitment.as_slice(),
                ],
            )
            .map_err(|_| WalIdempotencyError::Unavailable)?;
        Ok(LogicalMutationResult::Applied(result))
    }
}

pub(in crate::cp) fn load_episode_delete_evidence(
    connection: &Connection,
    account_id: &str,
    episode_id: i64,
) -> Result<Option<EpisodeDeleteEvidence>> {
    crate::store::validate_user_id(account_id).map_err(|_| WalIdempotencyError::Malformed)?;
    if episode_id <= 0 {
        return Err(WalIdempotencyError::Malformed);
    }
    if connection
        .query_row(
            "SELECT COUNT(*) FROM episodes WHERE id=?1",
            [episode_id],
            |row| row.get::<_, i64>(0),
        )
        .map_err(|_| WalIdempotencyError::Unavailable)?
        == 0
    {
        return Ok(None);
    }

    let mut hasher = Sha256::new();
    let mut budget = EvidenceBudget::default();
    hash_query(
        connection,
        "SELECT * FROM episodes WHERE id=?1",
        &[&episode_id],
        &mut hasher,
        &mut budget,
    )?;
    hash_query(
        connection,
        "SELECT * FROM episode_members WHERE episode_id=?1 ORDER BY record_type,record_id",
        &[&episode_id],
        &mut hasher,
        &mut budget,
    )?;
    let utterances = member_rows(connection, episode_id, "utterance", "utterances")?;
    let screenshots = member_rows(connection, episode_id, "screenshot", "screenshots")?;
    if utterances.len() > MAX_MEMBERS_PER_CLASS || screenshots.len() > MAX_MEMBERS_PER_CLASS {
        return Err(WalIdempotencyError::Limit);
    }
    hash_query(
        connection,
        "SELECT membership.* FROM episode_members membership
         WHERE membership.record_type='utterance' AND membership.record_id IN (
            SELECT target.record_id FROM episode_members target
            WHERE target.episode_id=?1 AND target.record_type='utterance'
         ) ORDER BY membership.episode_id,membership.record_type,membership.record_id",
        &[&episode_id],
        &mut hasher,
        &mut budget,
    )?;
    hash_query(
        connection,
        "SELECT membership.* FROM episode_members membership
         WHERE membership.record_type='screenshot' AND membership.record_id IN (
            SELECT target.record_id FROM episode_members target
            WHERE target.episode_id=?1 AND target.record_type='screenshot'
         ) ORDER BY membership.episode_id,membership.record_type,membership.record_id",
        &[&episode_id],
        &mut hasher,
        &mut budget,
    )?;
    hash_episode_purge_subtree(connection, episode_id, &mut hasher, &mut budget)?;
    let mutation_stamp = deletion_mutation_stamp(connection, episode_id)?;
    let purge = EpisodePurge {
        deleted_utterances: utterances.len(),
        deleted_screenshots: screenshots.len(),
        deleted_segments: count_distinct_segments(connection, episode_id)?,
        utterance_source_keys: utterances.iter().filter_map(|row| row.1.clone()).collect(),
        screenshot_source_keys: screenshots.iter().filter_map(|row| row.1.clone()).collect(),
    };
    validate_source_keys(&purge)?;

    let target_screenshot_ids = screenshots
        .iter()
        .map(|(id, _)| *id)
        .collect::<BTreeSet<_>>();
    let target_utterance_ids = utterances
        .iter()
        .map(|(id, _)| *id)
        .collect::<BTreeSet<_>>();
    let legacy_browser_snapshot_ids = legacy_browser_snapshot_ids(connection, episode_id)?;
    hash_query(
        connection,
        "SELECT DISTINCT snapshot.* FROM browser_snapshots snapshot
         JOIN screenshots screenshot ON screenshot.browser_snapshot_source_key=snapshot.source_key
         JOIN episode_members member ON member.record_id=screenshot.id
         WHERE member.episode_id=?1 AND member.record_type='screenshot'
           AND snapshot.id IN (
             SELECT candidate.id FROM browser_snapshots candidate
             WHERE NOT EXISTS (
               SELECT 1 FROM screenshots survivor
               WHERE survivor.browser_snapshot_source_key=candidate.source_key
                 AND NOT EXISTS (
                   SELECT 1 FROM episode_members target
                   WHERE target.episode_id=?1 AND target.record_type='screenshot'
                     AND target.record_id=survivor.id
                 )
             )
           ) ORDER BY snapshot.id",
        &[&episode_id],
        &mut hasher,
        &mut budget,
    )?;
    hash_query(
        connection,
        "SELECT tab.* FROM browser_tabs tab
         WHERE tab.browser_snapshot_id IN (
           SELECT DISTINCT snapshot.id FROM browser_snapshots snapshot
           JOIN screenshots screenshot ON screenshot.browser_snapshot_source_key=snapshot.source_key
           JOIN episode_members member ON member.record_id=screenshot.id
           WHERE member.episode_id=?1 AND member.record_type='screenshot'
             AND NOT EXISTS (
               SELECT 1 FROM screenshots survivor
               WHERE survivor.browser_snapshot_source_key=snapshot.source_key
                 AND NOT EXISTS (
                   SELECT 1 FROM episode_members target
                   WHERE target.episode_id=?1 AND target.record_type='screenshot'
                     AND target.record_id=survivor.id
                 )
             )
         ) ORDER BY tab.browser_snapshot_id,tab.window_index,tab.tab_index",
        &[&episode_id],
        &mut hasher,
        &mut budget,
    )?;

    let selectors = load_episode_delete_selectors(
        connection,
        episode_id,
        &target_screenshot_ids,
        &target_utterance_ids,
    )?;
    hash_optional_table_rows(
        connection,
        "screenshot_images",
        "SELECT image.* FROM screenshot_images image
         JOIN episode_members member ON member.record_id=image.screenshot_id
         WHERE member.episode_id=?1 AND member.record_type='screenshot'
         ORDER BY image.screenshot_id,image.object_key",
        &[&episode_id],
        &mut hasher,
        &mut budget,
    )?;
    for selector in &selectors {
        hash_field(&mut hasher, selector.selector_kind.as_bytes())?;
        hash_field(&mut hasher, selector.selector_ref.as_bytes())?;
    }
    let predecessor_commitment: [u8; 32] = hasher.finalize().into();
    let evidence = EpisodeDeleteEvidence {
        episode_id,
        predecessor_commitment,
        mutation_stamp,
        event_ids: Vec::new(),
        work_unit_ids: Vec::new(),
        stream_ids: Vec::new(),
        session_ids: Vec::new(),
        browser_state_keys: Vec::new(),
        legacy_browser_snapshot_ids,
        media: Vec::new(),
        legacy_media_keys: Vec::new(),
        selectors,
        purge,
    };
    validate_evidence(account_id, &evidence)?;
    Ok(Some(evidence))
}

pub(in crate::cp) fn load_episode_delete_start(
    connection: &Connection,
    account_id: &str,
    episode_id: i64,
) -> Result<EpisodeDeleteStart> {
    crate::store::validate_user_id(account_id).map_err(|_| WalIdempotencyError::Malformed)?;
    if episode_id <= 0 {
        return Err(WalIdempotencyError::Malformed);
    }
    match schema_state(connection)? {
        LedgerSchemaState::Absent => {}
        LedgerSchemaState::Present => {
            validate_schema_marker(connection)?;
            if let Some(stored) = load_preparation_by_id(connection, account_id, episode_id)? {
                return Ok(match stored.completion {
                    Some(_) => EpisodeDeleteStart::Complete(stored.preparation.receipt),
                    None => EpisodeDeleteStart::Prepared(stored.preparation),
                });
            }
        }
    }
    Ok(
        match load_episode_delete_evidence(connection, account_id, episode_id)? {
            Some(evidence) => EpisodeDeleteStart::Evidence(evidence),
            None => EpisodeDeleteStart::Absent,
        },
    )
}

pub(in crate::cp) fn load_episode_delete_receipt(
    connection: &Connection,
    account_id: &str,
    episode_id: i64,
) -> Result<Option<EpisodeDeleteReceipt>> {
    Ok(
        match load_episode_delete_start(connection, account_id, episode_id)? {
            EpisodeDeleteStart::Complete(receipt) => Some(receipt),
            EpisodeDeleteStart::Absent
            | EpisodeDeleteStart::Evidence(_)
            | EpisodeDeleteStart::Prepared(_) => None,
        },
    )
}

pub(in crate::cp) fn load_episode_delete_cleanup_item(
    connection: &Connection,
    account_id: &str,
    episode_id: i64,
) -> Result<Option<EpisodeDeleteCleanupItem>> {
    let Some(stored) = load_preparation_by_id(connection, account_id, episode_id)? else {
        return Ok(None);
    };
    if stored.completion.is_some() {
        return Ok(None);
    }
    let active_selector = connection
        .query_row(
            "SELECT ordinal,cleanup_items_commitment,cleanup_count,cleanup_rows,cleanup_bytes
             FROM archive_v3_wal_episode_delete_selectors
             WHERE preparation_operation_id=?1 AND selector_state='cleaning'
             ORDER BY ordinal LIMIT 2",
            [stored
                .preparation
                .preparation_operation_id
                .as_bytes()
                .as_slice()],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, Option<Vec<u8>>>(1)?,
                    row.get::<_, Option<i64>>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, i64>(4)?,
                ))
            },
        )
        .optional()
        .map_err(|_| WalIdempotencyError::Unavailable)?;
    if let Some((ordinal, commitment, count, rows, bytes)) = active_selector {
        let (targets, actual_bytes) = load_selector_cleanup_targets(
            connection,
            stored.preparation.preparation_operation_id,
            ordinal,
            false,
        )?;
        if count.is_none()
            || count != Some(i64::try_from(targets.len()).map_err(|_| WalIdempotencyError::Limit)?)
            || rows != count.unwrap()
            || bytes < 0
            || actual_bytes != u64::try_from(bytes).map_err(|_| WalIdempotencyError::Corrupt)?
            || selector_cleanup_targets_commitment(&targets)?
                != exact_digest(commitment.as_deref().ok_or(WalIdempotencyError::Corrupt)?)?
        {
            return Err(WalIdempotencyError::Precondition);
        }
    }
    let row = connection
        .query_row(
            "SELECT selector_ordinal,cleanup_kind,ordinal,object_key,object_generation,object_backend,sha256
             FROM archive_v3_wal_episode_delete_cleanup
             WHERE preparation_operation_id=?1 AND cleanup_state='pending'
             ORDER BY CASE cleanup_kind WHEN 'retained' THEN 0 ELSE 1 END,ordinal
             LIMIT 1",
            [stored
                .preparation
                .preparation_operation_id
                .as_bytes()
                .as_slice()],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, Option<i64>>(4)?,
                    row.get::<_, Option<String>>(5)?,
                    row.get::<_, Option<String>>(6)?,
                ))
            },
        )
        .optional()
        .map_err(|_| WalIdempotencyError::Unavailable)?;
    let Some((selector_ordinal, kind, ordinal, object_key, generation, backend, sha256)) = row
    else {
        return Ok(None);
    };
    let target = match kind.as_str() {
        "retained" => EpisodeDeleteCleanupTarget::Retained(EpisodeDeleteMedia {
            object_key,
            object_generation: generation,
            object_backend: backend,
            sha256: sha256.ok_or(WalIdempotencyError::Corrupt)?,
        }),
        "legacy" if generation.is_none() && backend.is_none() && sha256.is_none() => {
            EpisodeDeleteCleanupTarget::Legacy(object_key)
        }
        _ => return Err(WalIdempotencyError::Corrupt),
    };
    let item = EpisodeDeleteCleanupItem {
        preparation: stored.preparation,
        selector_ordinal,
        cleanup_kind: kind,
        ordinal,
        target,
    };
    // Construction revalidates the exact retained identity and the carried
    // preparation before any provider method can observe the item.
    let _ = EpisodeDeleteCleanupPlan::new(item.clone())?;
    Ok(Some(item))
}

fn pending_episode_ids_after_cursor(
    connection: &Connection,
    cursor: i64,
    limit: usize,
) -> Result<Vec<i64>> {
    if cursor < 0 || limit == 0 || limit > 4 {
        return Err(WalIdempotencyError::Limit);
    }
    let collect = |predicate: &str, bound: i64, take: usize| -> Result<Vec<i64>> {
        if take == 0 {
            return Ok(Vec::new());
        }
        let mut statement = connection
            .prepare(&format!(
                "SELECT episode_id FROM archive_v3_wal_episode_delete_operations
                 WHERE completion_format_version IS NULL AND episode_id {predicate} ?1
                 ORDER BY episode_id LIMIT ?2"
            ))
            .map_err(|_| WalIdempotencyError::Unavailable)?;
        let values = statement
            .query_map(
                params![
                    bound,
                    i64::try_from(take).map_err(|_| WalIdempotencyError::Limit)?
                ],
                |row| row.get::<_, i64>(0),
            )
            .map_err(|_| WalIdempotencyError::Unavailable)?
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|_| WalIdempotencyError::Unavailable)?;
        Ok(values)
    };
    let mut ids = collect(">", cursor, limit)?;
    if ids.len() < limit {
        ids.extend(collect("<=", cursor, limit - ids.len())?);
    }
    if ids.iter().any(|id| *id <= 0) {
        return Err(WalIdempotencyError::Corrupt);
    }
    Ok(ids)
}

pub(in crate::cp) fn load_pending_episode_delete_batch(
    connection: &Connection,
    account_id: &str,
) -> Result<Option<EpisodeDeleteResumeBatch>> {
    crate::store::validate_user_id(account_id).map_err(|_| WalIdempotencyError::Malformed)?;
    if schema_state(connection)? == LedgerSchemaState::Absent {
        return Ok(None);
    }
    validate_schema_marker(connection)?;
    let state = load_ledger_state(connection)?;
    let episode_ids = pending_episode_ids_after_cursor(connection, state.resume_cursor, 4)?;
    let Some(first_episode_id) = episode_ids.first().copied() else {
        return Ok(None);
    };
    let preparation = load_preparation_by_id(connection, account_id, first_episode_id)?
        .filter(|stored| stored.completion.is_none())
        .ok_or(WalIdempotencyError::Corrupt)?
        .preparation;
    let next_cursor = *episode_ids.last().ok_or(WalIdempotencyError::Corrupt)?;
    let plan = EpisodeDeleteCleanupPlan::advance_resume_cursor(
        preparation,
        state.resume_cursor,
        state.resume_sequence,
        episode_ids.clone(),
        next_cursor,
    )?;
    Ok(Some(EpisodeDeleteResumeBatch { episode_ids, plan }))
}

pub(in crate::cp) fn load_episode_delete_work(
    connection: &Connection,
    account_id: &str,
    episode_id: i64,
) -> Result<Option<EpisodeDeleteWork>> {
    let Some(stored) = load_preparation_by_id(connection, account_id, episode_id)? else {
        return Ok(None);
    };
    if stored.completion.is_some() {
        return Ok(None);
    }
    let mut active_statement = connection
        .prepare(
            "SELECT ordinal,selector_kind,selector_ref
             FROM archive_v3_wal_episode_delete_selectors
             WHERE preparation_operation_id=?1 AND selector_state='cleaning'
             ORDER BY ordinal LIMIT 2",
        )
        .map_err(|_| WalIdempotencyError::Unavailable)?;
    let active = active_statement
        .query_map(
            [stored
                .preparation
                .preparation_operation_id
                .as_bytes()
                .as_slice()],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    EpisodeDeleteSelector {
                        selector_kind: row.get(1)?,
                        selector_ref: row.get(2)?,
                    },
                ))
            },
        )
        .map_err(|_| WalIdempotencyError::Unavailable)?
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|_| WalIdempotencyError::Unavailable)?;
    let active = match active.as_slice() {
        [] => None,
        [only] => Some(only.clone()),
        _ => return Err(WalIdempotencyError::Corrupt),
    };
    if let Some((selector_ordinal, selector)) = active {
        if let Some(item) = load_episode_delete_cleanup_item(connection, account_id, episode_id)? {
            if item.selector_ordinal != selector_ordinal {
                return Err(WalIdempotencyError::Corrupt);
            }
            return Ok(Some(EpisodeDeleteWork::Provider(item)));
        }
        let completion =
            load_selector_completion(connection, stored.preparation.clone(), selector_ordinal)?;
        if completion.preparation != stored.preparation || completion.selector != selector {
            return Err(WalIdempotencyError::Corrupt);
        }
        return Ok(Some(EpisodeDeleteWork::FinishSelector(
            EpisodeDeleteCleanupPlan::finish_selector(completion)?,
        )));
    }
    let pending = connection
        .query_row(
            "SELECT ordinal,selector_kind,selector_ref
             FROM archive_v3_wal_episode_delete_selectors
             WHERE preparation_operation_id=?1 AND selector_state='pending'
             ORDER BY ordinal LIMIT 1",
            [stored
                .preparation
                .preparation_operation_id
                .as_bytes()
                .as_slice()],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    EpisodeDeleteSelector {
                        selector_kind: row.get(1)?,
                        selector_ref: row.get(2)?,
                    },
                ))
            },
        )
        .optional()
        .map_err(|_| WalIdempotencyError::Unavailable)?;
    if let Some((selector_ordinal, selector)) = pending {
        if selector.selector_kind == "voice" {
            if let Some(reservation) = load_voice_capacity_reservation(
                connection,
                stored.preparation.clone(),
                selector_ordinal,
                selector.clone(),
            )? {
                return Ok(Some(EpisodeDeleteWork::Expand(
                    EpisodeDeleteCleanupPlan::reserve_voice_capacity(reservation)?,
                )));
            }
            if let Some(page) = load_voice_episode_page(
                connection,
                stored.preparation.clone(),
                selector_ordinal,
                selector.clone(),
            )? {
                return Ok(Some(EpisodeDeleteWork::Expand(
                    EpisodeDeleteCleanupPlan::advance_voice_episodes(page)?,
                )));
            }
        }
        let expansion =
            load_selector_expansion(connection, stored.preparation, selector_ordinal, selector)?;
        return Ok(Some(EpisodeDeleteWork::Expand(
            EpisodeDeleteCleanupPlan::expand(expansion)?,
        )));
    }
    let final_cleanup_commitment =
        final_selector_cleanup_commitment(connection, &stored.preparation)?;
    Ok(Some(EpisodeDeleteWork::Complete(EpisodeDeletePlan::new(
        stored.preparation,
        final_cleanup_commitment,
    )?)))
}

fn load_selector_completion(
    connection: &Connection,
    preparation: EpisodeDeletePreparation,
    selector_ordinal: i64,
) -> Result<EpisodeDeleteSelectorCompletion> {
    let preparation_operation_id = preparation.preparation_operation_id;
    let selector_row = connection
        .query_row(
            "SELECT selector_kind,selector_ref,selector_state,
                    expansion_predecessor_commitment,cleanup_items_commitment,
                    cleanup_count,settled_count,cleanup_rows,cleanup_bytes
             FROM archive_v3_wal_episode_delete_selectors
             WHERE preparation_operation_id=?1 AND ordinal=?2",
            params![
                preparation_operation_id.as_bytes().as_slice(),
                selector_ordinal
            ],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, Option<Vec<u8>>>(3)?,
                    row.get::<_, Option<Vec<u8>>>(4)?,
                    row.get::<_, Option<i64>>(5)?,
                    row.get::<_, i64>(6)?,
                    row.get::<_, i64>(7)?,
                    row.get::<_, i64>(8)?,
                ))
            },
        )
        .optional()
        .map_err(|_| WalIdempotencyError::Unavailable)?
        .ok_or(WalIdempotencyError::Precondition)?;
    let (
        kind,
        reference,
        state,
        expansion_commitment,
        cleanup_commitment,
        count,
        settled,
        rows,
        bytes,
    ) = selector_row;
    if state != "cleaning" || count.is_none() || settled < 0 || rows < 0 || bytes < 0 {
        return Err(WalIdempotencyError::Precondition);
    }
    let cleanup_count = u64::try_from(count.unwrap()).map_err(|_| WalIdempotencyError::Corrupt)?;
    let cleanup_rows = u64::try_from(rows).map_err(|_| WalIdempotencyError::Corrupt)?;
    let cleanup_bytes = u64::try_from(bytes).map_err(|_| WalIdempotencyError::Corrupt)?;
    if u64::try_from(settled).map_err(|_| WalIdempotencyError::Corrupt)? != cleanup_count
        || cleanup_rows != cleanup_count
    {
        return Err(WalIdempotencyError::Precondition);
    }
    let (items, actual_bytes) = load_selector_cleanup_targets(
        connection,
        preparation_operation_id,
        selector_ordinal,
        true,
    )?;
    if u64::try_from(items.len()).map_err(|_| WalIdempotencyError::Limit)? != cleanup_count
        || actual_bytes != cleanup_bytes
        || selector_cleanup_targets_commitment(&items)?
            != exact_digest(
                cleanup_commitment
                    .as_deref()
                    .ok_or(WalIdempotencyError::Corrupt)?,
            )?
    {
        return Err(WalIdempotencyError::Precondition);
    }
    Ok(EpisodeDeleteSelectorCompletion {
        preparation,
        selector_ordinal,
        selector: EpisodeDeleteSelector {
            selector_kind: kind,
            selector_ref: reference,
        },
        expansion_predecessor_commitment: exact_digest(
            &expansion_commitment.ok_or(WalIdempotencyError::Corrupt)?,
        )?,
        cleanup_items_commitment: exact_digest(
            cleanup_commitment
                .as_deref()
                .ok_or(WalIdempotencyError::Corrupt)?,
        )?,
        cleanup_count,
        cleanup_rows,
        cleanup_bytes,
    })
}

fn validate_voice_page(page: &EpisodeDeleteVoicePage) -> Result<()> {
    validate_selectors(std::slice::from_ref(&page.selector))?;
    if page.selector.selector_kind != "voice"
        || page.selector_ordinal < 0
        || page.expected_page_sequence < 0
        || page.expected_scan_cursor < 0
        || page.expected_progress_rows > MAX_SOURCE_ROWS
        || page.predecessor_commitment == [0; 32]
        || page.episodes.is_empty()
        || page.episodes.len() > MAX_VOICE_EPISODES_PER_PAGE
        || page
            .episodes
            .windows(2)
            .any(|pair| pair[0].episode_id >= pair[1].episode_id)
        || page.episodes.iter().any(|row| {
            row.episode_id <= 0
                || row.identity_revision < 0
                || row.identity_revision == i64::MAX
                || row.prior_progress.as_ref().is_some_and(|progress| {
                    progress.page_sequence <= 0
                        || progress.page_sequence > page.expected_page_sequence
                        || progress.predecessor_revision < 0
                        || progress.resulting_revision
                            != progress
                                .predecessor_revision
                                .checked_add(1)
                                .unwrap_or_default()
                        || progress.page_predecessor_commitment == [0; 32]
                        || progress.progress_commitment == [0; 32]
                        || voice_episode_progress_commitment(
                            &page.preparation,
                            page.selector_ordinal,
                            row.episode_id,
                            progress,
                        ) != Ok(progress.progress_commitment)
                })
        })
    {
        return Err(WalIdempotencyError::Malformed);
    }
    let new_rows = u64::try_from(
        page.episodes
            .iter()
            .filter(|episode| episode.prior_progress.is_none())
            .count(),
    )
    .map_err(|_| WalIdempotencyError::Limit)?;
    if page
        .expected_progress_rows
        .checked_add(new_rows)
        .is_none_or(|rows| rows > MAX_SOURCE_ROWS)
    {
        return Err(WalIdempotencyError::Limit);
    }
    Ok(())
}

fn voice_episode_progress_commitment(
    preparation: &EpisodeDeletePreparation,
    selector_ordinal: i64,
    episode_id: i64,
    progress: &VoiceEpisodeProgress,
) -> Result<[u8; 32]> {
    let mut hasher = Sha256::new();
    hash_field(&mut hasher, b"kioku:episode-delete:voice-progress-row:v1")?;
    hash_field(&mut hasher, preparation.preparation_operation_id.as_bytes())?;
    hash_field(&mut hasher, &selector_ordinal.to_be_bytes())?;
    hash_field(&mut hasher, &episode_id.to_be_bytes())?;
    hash_field(&mut hasher, &progress.page_sequence.to_be_bytes())?;
    hash_field(&mut hasher, &progress.predecessor_revision.to_be_bytes())?;
    hash_field(&mut hasher, &progress.resulting_revision.to_be_bytes())?;
    hash_field(&mut hasher, &progress.page_predecessor_commitment)?;
    Ok(hasher.finalize().into())
}

fn validate_voice_progress(
    connection: &Connection,
    preparation: &EpisodeDeletePreparation,
    selector_ordinal: i64,
    expected_sequence: i64,
) -> Result<([u8; 32], u64)> {
    if expected_sequence < 0 {
        return Err(WalIdempotencyError::Corrupt);
    }
    let mut statement = connection
        .prepare(
            "SELECT episode_id,page_sequence,predecessor_revision,resulting_revision,
                    page_predecessor_commitment,progress_commitment
             FROM archive_v3_wal_episode_delete_voice_progress
             WHERE preparation_operation_id=?1 AND selector_ordinal=?2
             ORDER BY episode_id",
        )
        .map_err(|_| WalIdempotencyError::Unavailable)?;
    let mut rows = statement
        .query(params![
            preparation.preparation_operation_id.as_bytes().as_slice(),
            selector_ordinal,
        ])
        .map_err(|_| WalIdempotencyError::Unavailable)?;
    let mut hasher = Sha256::new();
    let mut budget = EvidenceBudget::default();
    hash_field(&mut hasher, b"kioku:episode-delete:voice-progress:v2")?;
    hash_field(&mut hasher, preparation.preparation_operation_id.as_bytes())?;
    hash_field(&mut hasher, &selector_ordinal.to_be_bytes())?;
    hash_field(&mut hasher, &expected_sequence.to_be_bytes())?;
    let mut previous_episode_id = 0;
    let mut progress_rows = 0u64;
    while let Some(row) = rows.next().map_err(|_| WalIdempotencyError::Unavailable)? {
        budget.observe_row()?;
        progress_rows = progress_rows
            .checked_add(1)
            .ok_or(WalIdempotencyError::Limit)?;
        let episode_id = row
            .get::<_, i64>(0)
            .map_err(|_| WalIdempotencyError::Corrupt)?;
        let progress = VoiceEpisodeProgress {
            page_sequence: row
                .get::<_, i64>(1)
                .map_err(|_| WalIdempotencyError::Corrupt)?,
            predecessor_revision: row
                .get::<_, i64>(2)
                .map_err(|_| WalIdempotencyError::Corrupt)?,
            resulting_revision: row
                .get::<_, i64>(3)
                .map_err(|_| WalIdempotencyError::Corrupt)?,
            page_predecessor_commitment: exact_digest(
                &row.get::<_, Vec<u8>>(4)
                    .map_err(|_| WalIdempotencyError::Corrupt)?,
            )?,
            progress_commitment: exact_digest(
                &row.get::<_, Vec<u8>>(5)
                    .map_err(|_| WalIdempotencyError::Corrupt)?,
            )?,
        };
        if episode_id <= previous_episode_id
            || progress.page_sequence <= 0
            || progress.page_sequence > expected_sequence
            || progress.predecessor_revision < 0
            || progress.resulting_revision
                != progress
                    .predecessor_revision
                    .checked_add(1)
                    .ok_or(WalIdempotencyError::Corrupt)?
            || voice_episode_progress_commitment(
                preparation,
                selector_ordinal,
                episode_id,
                &progress,
            )? != progress.progress_commitment
        {
            return Err(WalIdempotencyError::Corrupt);
        }
        hash_field(&mut hasher, &episode_id.to_be_bytes())?;
        hash_field(&mut hasher, &progress.page_sequence.to_be_bytes())?;
        hash_field(&mut hasher, &progress.predecessor_revision.to_be_bytes())?;
        hash_field(&mut hasher, &progress.resulting_revision.to_be_bytes())?;
        hash_field(&mut hasher, &progress.page_predecessor_commitment)?;
        hash_field(&mut hasher, &progress.progress_commitment)?;
        previous_episode_id = episode_id;
    }
    Ok((hasher.finalize().into(), progress_rows))
}

fn load_voice_capacity_reservation(
    connection: &Connection,
    preparation: EpisodeDeletePreparation,
    selector_ordinal: i64,
    selector: EpisodeDeleteSelector,
) -> Result<Option<EpisodeDeleteVoiceReservation>> {
    if selector.selector_kind != "voice" || selector_ordinal < 0 {
        return Err(WalIdempotencyError::Malformed);
    }
    let (rows, bytes) = connection
        .query_row(
            "SELECT reserved_cleanup_rows,reserved_cleanup_bytes
             FROM archive_v3_wal_episode_delete_selectors
             WHERE preparation_operation_id=?1 AND ordinal=?2
               AND selector_kind='voice' AND selector_ref=?3 AND selector_state='pending'",
            params![
                preparation.preparation_operation_id.as_bytes().as_slice(),
                selector_ordinal,
                selector.selector_ref,
            ],
            |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)),
        )
        .optional()
        .map_err(|_| WalIdempotencyError::Unavailable)?
        .ok_or(WalIdempotencyError::Precondition)?;
    match (u64::try_from(rows), u64::try_from(bytes)) {
        (Ok(0), Ok(0)) => Ok(Some(EpisodeDeleteVoiceReservation {
            preparation,
            selector_ordinal,
            selector,
        })),
        (Ok(VOICE_RESERVED_CLEANUP_ROWS), Ok(VOICE_RESERVED_CLEANUP_BYTES)) => Ok(None),
        _ => Err(WalIdempotencyError::Corrupt),
    }
}

fn load_voice_episode_page(
    connection: &Connection,
    preparation: EpisodeDeletePreparation,
    selector_ordinal: i64,
    selector: EpisodeDeleteSelector,
) -> Result<Option<EpisodeDeleteVoicePage>> {
    if selector.selector_kind != "voice" || selector_ordinal < 0 {
        return Err(WalIdempotencyError::Malformed);
    }
    let (
        expected_page_sequence,
        expected_scan_cursor,
        expected_progress_rows,
        reserved_rows,
        reserved_bytes,
    ) = connection
        .query_row(
            "SELECT voice_page_sequence,voice_scan_cursor,
                    voice_progress_rows,reserved_cleanup_rows,reserved_cleanup_bytes
             FROM archive_v3_wal_episode_delete_selectors
             WHERE preparation_operation_id=?1 AND ordinal=?2
               AND selector_kind='voice' AND selector_ref=?3 AND selector_state='pending'",
            params![
                preparation.preparation_operation_id.as_bytes().as_slice(),
                selector_ordinal,
                selector.selector_ref,
            ],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, i64>(4)?,
                ))
            },
        )
        .optional()
        .map_err(|_| WalIdempotencyError::Unavailable)?
        .ok_or(WalIdempotencyError::Precondition)?;
    if expected_page_sequence < 0
        || expected_scan_cursor < 0
        || expected_progress_rows < 0
        || u64::try_from(reserved_rows).ok() != Some(VOICE_RESERVED_CLEANUP_ROWS)
        || u64::try_from(reserved_bytes).ok() != Some(VOICE_RESERVED_CLEANUP_BYTES)
    {
        return Err(WalIdempotencyError::Corrupt);
    }
    let expected_progress_rows =
        u64::try_from(expected_progress_rows).map_err(|_| WalIdempotencyError::Corrupt)?;
    let observation_id = selector
        .selector_ref
        .parse::<i64>()
        .map_err(|_| WalIdempotencyError::Malformed)?;
    if observation_id <= 0 || observation_has_surviving_utterances(connection, observation_id)? {
        return Err(WalIdempotencyError::Precondition);
    }
    let profile_ids = affected_voice_profile_ids(connection, &[observation_id])?;
    if profile_ids.is_empty() {
        return Ok(None);
    }
    let profiles = profile_ids
        .iter()
        .map(i64::to_string)
        .collect::<Vec<_>>()
        .join(",");
    let sql = format!(
        "SELECT DISTINCT episode.id,CAST(episode.identity_revision AS TEXT),
                typeof(episode.identity_revision),episode.identity_refresh_status,
                progress.page_sequence,progress.predecessor_revision,
                progress.resulting_revision,progress.page_predecessor_commitment,
                progress.progress_commitment
         FROM episode_members member
         JOIN utterances utterance ON utterance.id=member.record_id
         JOIN voice_samples sample ON sample.speaker_observation_id=utterance.speaker_observation_id
         JOIN episodes episode ON episode.id=member.episode_id
         LEFT JOIN archive_v3_wal_episode_delete_voice_progress progress
           ON progress.preparation_operation_id=?1 AND progress.selector_ordinal=?2
          AND progress.episode_id=episode.id
         WHERE member.record_type='utterance'
           AND (EXISTS (
                 SELECT 1 FROM voice_sample_profile_assignments assignment
                 WHERE assignment.sample_id=sample.id AND assignment.active=1
                   AND assignment.profile_id IN ({profiles})
               ) OR (sample.voice_profile_id IN ({profiles}) AND NOT EXISTS (
                 SELECT 1 FROM voice_sample_profile_assignments assignment
                 WHERE assignment.sample_id=sample.id
               )))
           AND (progress.episode_id IS NULL
                OR typeof(episode.identity_revision)<>'integer'
                OR CAST(episode.identity_revision AS TEXT)<>CAST(progress.resulting_revision AS TEXT)
                OR COALESCE(episode.identity_refresh_status,'')<>'queued')
           AND (?3=0 OR episode.id>?3)
         ORDER BY episode.id LIMIT {MAX_VOICE_EPISODES_PER_PAGE}",
    );
    let load_rows = |cursor: i64| {
        let mut statement = connection
            .prepare(&sql)
            .map_err(|_| WalIdempotencyError::Unavailable)?;
        let mapped = statement
            .query_map(
                params![
                    preparation.preparation_operation_id.as_bytes().as_slice(),
                    selector_ordinal,
                    cursor,
                ],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, Option<String>>(3)?,
                        row.get::<_, Option<i64>>(4)?,
                        row.get::<_, Option<i64>>(5)?,
                        row.get::<_, Option<i64>>(6)?,
                        row.get::<_, Option<Vec<u8>>>(7)?,
                        row.get::<_, Option<Vec<u8>>>(8)?,
                    ))
                },
            )
            .map_err(|_| WalIdempotencyError::Unavailable)?;
        mapped
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|_| WalIdempotencyError::Unavailable)
    };
    let mut rows = load_rows(expected_scan_cursor)?;
    if rows.is_empty() && expected_scan_cursor > 0 {
        rows = load_rows(0)?;
    }
    if rows.is_empty() {
        return Ok(None);
    }
    let mut episodes = Vec::with_capacity(rows.len());
    for (
        episode_id,
        revision,
        storage_class,
        _,
        progress_sequence,
        progress_predecessor,
        progress_resulting,
        progress_page_commitment,
        progress_commitment,
    ) in rows
    {
        if episode_id <= 0 || storage_class != "integer" {
            return Err(WalIdempotencyError::Malformed);
        }
        let identity_revision = revision
            .parse::<i64>()
            .map_err(|_| WalIdempotencyError::Malformed)?;
        if identity_revision < 0 || identity_revision == i64::MAX {
            return Err(WalIdempotencyError::Malformed);
        }
        let prior_progress = match (
            progress_sequence,
            progress_predecessor,
            progress_resulting,
            progress_page_commitment,
            progress_commitment,
        ) {
            (None, None, None, None, None) => None,
            (
                Some(page_sequence),
                Some(predecessor_revision),
                Some(resulting_revision),
                Some(page_predecessor_commitment),
                Some(progress_commitment),
            ) => Some(VoiceEpisodeProgress {
                page_sequence,
                predecessor_revision,
                resulting_revision,
                page_predecessor_commitment: exact_digest(&page_predecessor_commitment)?,
                progress_commitment: exact_digest(&progress_commitment)?,
            }),
            _ => return Err(WalIdempotencyError::Corrupt),
        };
        episodes.push(VoiceEpisodePredecessor {
            episode_id,
            identity_revision,
            prior_progress,
        });
    }
    let mut page = EpisodeDeleteVoicePage {
        preparation,
        selector_ordinal,
        selector,
        expected_page_sequence,
        expected_scan_cursor,
        expected_progress_rows,
        predecessor_commitment: [0; 32],
        episodes,
    };
    page.predecessor_commitment = voice_episode_page_predecessor_commitment(connection, &page)?;
    validate_voice_page(&page)?;
    Ok(Some(page))
}

fn final_selector_cleanup_commitment(
    connection: &Connection,
    preparation: &EpisodeDeletePreparation,
) -> Result<[u8; 32]> {
    let preparation_operation_id = preparation.preparation_operation_id;
    let expected_selectors = &preparation.selectors;
    let mut statement = connection
        .prepare(
            "SELECT ordinal,selector_kind,selector_ref,selector_state,
                    expansion_predecessor_commitment,cleanup_items_commitment,
                    cleanup_count,settled_count,cleanup_rows,cleanup_bytes,
                    voice_page_sequence,voice_scan_cursor,
                    reserved_cleanup_rows,reserved_cleanup_bytes,
                    voice_progress_rows,
                    expansion_request_fingerprint,finish_request_fingerprint
             FROM archive_v3_wal_episode_delete_selectors
             WHERE preparation_operation_id=?1 ORDER BY ordinal",
        )
        .map_err(|_| WalIdempotencyError::Unavailable)?;
    let mut rows = statement
        .query([preparation_operation_id.as_bytes().as_slice()])
        .map_err(|_| WalIdempotencyError::Unavailable)?;
    let mut hasher = Sha256::new();
    hash_field(&mut hasher, FINAL_CLEANUP_DOMAIN)?;
    hash_field(
        &mut hasher,
        &u64::try_from(expected_selectors.len())
            .map_err(|_| WalIdempotencyError::Limit)?
            .to_be_bytes(),
    )?;
    for (expected_ordinal, expected_selector) in expected_selectors.iter().enumerate() {
        let row = rows
            .next()
            .map_err(|_| WalIdempotencyError::Unavailable)?
            .ok_or(WalIdempotencyError::Corrupt)?;
        let ordinal = row
            .get::<_, i64>(0)
            .map_err(|_| WalIdempotencyError::Corrupt)?;
        let selector = EpisodeDeleteSelector {
            selector_kind: row.get(1).map_err(|_| WalIdempotencyError::Corrupt)?,
            selector_ref: row.get(2).map_err(|_| WalIdempotencyError::Corrupt)?,
        };
        let state = row
            .get::<_, String>(3)
            .map_err(|_| WalIdempotencyError::Corrupt)?;
        let expansion_predecessor_commitment = exact_digest(
            &row.get::<_, Option<Vec<u8>>>(4)
                .map_err(|_| WalIdempotencyError::Corrupt)?
                .ok_or(WalIdempotencyError::Corrupt)?,
        )?;
        let cleanup_items_commitment = exact_digest(
            &row.get::<_, Option<Vec<u8>>>(5)
                .map_err(|_| WalIdempotencyError::Corrupt)?
                .ok_or(WalIdempotencyError::Corrupt)?,
        )?;
        let cleanup_count = u64::try_from(
            row.get::<_, Option<i64>>(6)
                .map_err(|_| WalIdempotencyError::Corrupt)?
                .ok_or(WalIdempotencyError::Corrupt)?,
        )
        .map_err(|_| WalIdempotencyError::Corrupt)?;
        let settled_count = u64::try_from(
            row.get::<_, i64>(7)
                .map_err(|_| WalIdempotencyError::Corrupt)?,
        )
        .map_err(|_| WalIdempotencyError::Corrupt)?;
        let cleanup_rows = u64::try_from(
            row.get::<_, i64>(8)
                .map_err(|_| WalIdempotencyError::Corrupt)?,
        )
        .map_err(|_| WalIdempotencyError::Corrupt)?;
        let cleanup_bytes = u64::try_from(
            row.get::<_, i64>(9)
                .map_err(|_| WalIdempotencyError::Corrupt)?,
        )
        .map_err(|_| WalIdempotencyError::Corrupt)?;
        let voice_page_sequence = row
            .get::<_, i64>(10)
            .map_err(|_| WalIdempotencyError::Corrupt)?;
        let voice_scan_cursor = row
            .get::<_, i64>(11)
            .map_err(|_| WalIdempotencyError::Corrupt)?;
        let reserved_cleanup_rows = u64::try_from(
            row.get::<_, i64>(12)
                .map_err(|_| WalIdempotencyError::Corrupt)?,
        )
        .map_err(|_| WalIdempotencyError::Corrupt)?;
        let reserved_cleanup_bytes = u64::try_from(
            row.get::<_, i64>(13)
                .map_err(|_| WalIdempotencyError::Corrupt)?,
        )
        .map_err(|_| WalIdempotencyError::Corrupt)?;
        let voice_progress_rows = u64::try_from(
            row.get::<_, i64>(14)
                .map_err(|_| WalIdempotencyError::Corrupt)?,
        )
        .map_err(|_| WalIdempotencyError::Corrupt)?;
        let expansion_fingerprint = exact_digest(
            &row.get::<_, Option<Vec<u8>>>(15)
                .map_err(|_| WalIdempotencyError::Corrupt)?
                .ok_or(WalIdempotencyError::Corrupt)?,
        )?;
        let finish_fingerprint = row
            .get::<_, Option<Vec<u8>>>(16)
            .map_err(|_| WalIdempotencyError::Corrupt)?;
        if ordinal != i64::try_from(expected_ordinal).map_err(|_| WalIdempotencyError::Limit)?
            || &selector != expected_selector
            || state != "complete"
            || voice_page_sequence < 0
            || voice_scan_cursor < 0
            || voice_progress_rows != 0
            || (selector.selector_kind == "voice"
                && (reserved_cleanup_rows != VOICE_RESERVED_CLEANUP_ROWS
                    || reserved_cleanup_bytes != VOICE_RESERVED_CLEANUP_BYTES))
            || (selector.selector_kind != "voice"
                && (voice_page_sequence != 0
                    || voice_scan_cursor != 0
                    || reserved_cleanup_rows != 0
                    || reserved_cleanup_bytes != 0))
            || cleanup_count != settled_count
            || cleanup_rows != cleanup_count
        {
            return Err(WalIdempotencyError::Corrupt);
        }
        let expected_expansion_fingerprint = WalRequestFingerprint::derive(
            WalOperationKind::EpisodeDeleteCleanup,
            &selector_expansion_request(SelectorExpansionRequest {
                preparation,
                selector_ordinal: ordinal,
                selector: &selector,
                expansion_predecessor_commitment,
                cleanup_items_commitment,
                cleanup_rows,
                cleanup_bytes,
                voice_page_sequence,
                voice_scan_cursor,
                reserved_cleanup_rows,
                reserved_cleanup_bytes,
            })?,
        )?;
        if expansion_fingerprint.as_slice() != expected_expansion_fingerprint.as_bytes().as_slice()
        {
            return Err(WalIdempotencyError::FingerprintConflict);
        }
        if cleanup_count == 0 {
            if finish_fingerprint.is_some() {
                return Err(WalIdempotencyError::Corrupt);
            }
        } else {
            let completion = EpisodeDeleteSelectorCompletion {
                preparation: preparation.clone(),
                selector_ordinal: ordinal,
                selector: selector.clone(),
                expansion_predecessor_commitment,
                cleanup_items_commitment,
                cleanup_count,
                cleanup_rows,
                cleanup_bytes,
            };
            let expected_finish = WalRequestFingerprint::derive(
                WalOperationKind::EpisodeDeleteCleanup,
                &selector_finish_request(&completion)?,
            )?;
            if finish_fingerprint
                .as_deref()
                .is_none_or(|value| value != expected_finish.as_bytes().as_slice())
            {
                return Err(WalIdempotencyError::FingerprintConflict);
            }
        }
        hash_field(&mut hasher, &ordinal.to_be_bytes())?;
        hash_field(&mut hasher, selector.selector_kind.as_bytes())?;
        hash_field(&mut hasher, selector.selector_ref.as_bytes())?;
        hash_field(&mut hasher, &expansion_predecessor_commitment)?;
        hash_field(&mut hasher, &cleanup_items_commitment)?;
        hash_field(&mut hasher, &cleanup_count.to_be_bytes())?;
        hash_field(&mut hasher, &cleanup_bytes.to_be_bytes())?;
        hash_field(&mut hasher, &voice_page_sequence.to_be_bytes())?;
        hash_field(&mut hasher, &voice_scan_cursor.to_be_bytes())?;
        hash_field(&mut hasher, &reserved_cleanup_rows.to_be_bytes())?;
        hash_field(&mut hasher, &reserved_cleanup_bytes.to_be_bytes())?;
        hash_field(&mut hasher, &voice_progress_rows.to_be_bytes())?;
        hash_field(&mut hasher, &expansion_fingerprint)?;
        if let Some(fingerprint) = finish_fingerprint {
            hash_field(&mut hasher, &fingerprint)?;
        } else {
            hash_field(&mut hasher, &[])?;
        }
    }
    if rows
        .next()
        .map_err(|_| WalIdempotencyError::Unavailable)?
        .is_some()
    {
        return Err(WalIdempotencyError::Corrupt);
    }
    let commitment: [u8; 32] = hasher.finalize().into();
    (commitment != [0; 32])
        .then_some(commitment)
        .ok_or(WalIdempotencyError::Corrupt)
}

fn load_selector_expansion(
    connection: &Connection,
    preparation: EpisodeDeletePreparation,
    selector_ordinal: i64,
    selector: EpisodeDeleteSelector,
) -> Result<EpisodeDeleteSelectorExpansion> {
    if selector_ordinal < 0 {
        return Err(WalIdempotencyError::Malformed);
    }
    let exact = connection
        .query_row(
            "SELECT selector_kind,selector_ref,selector_state
             FROM archive_v3_wal_episode_delete_selectors
             WHERE preparation_operation_id=?1 AND ordinal=?2",
            params![
                preparation.preparation_operation_id.as_bytes().as_slice(),
                selector_ordinal,
            ],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                ))
            },
        )
        .optional()
        .map_err(|_| WalIdempotencyError::Unavailable)?
        .ok_or(WalIdempotencyError::Precondition)?;
    if exact.0 != selector.selector_kind || exact.1 != selector.selector_ref || exact.2 != "pending"
    {
        return Err(WalIdempotencyError::Precondition);
    }

    let mut roots = BTreeSet::new();
    let mut observation_ids = BTreeSet::new();
    let mut legacy_media_keys = Vec::new();
    match selector.selector_kind.as_str() {
        "event" => {
            if capture_event_exists(connection, &selector.selector_ref)? {
                roots.insert(selector.selector_ref.clone());
            }
        }
        "voice" => {
            let observation_id = selector
                .selector_ref
                .parse::<i64>()
                .map_err(|_| WalIdempotencyError::Malformed)?;
            if observation_has_surviving_utterances(connection, observation_id)? {
                return Err(WalIdempotencyError::Precondition);
            }
            if connection
                .query_row(
                    "SELECT COUNT(*) FROM speaker_observations WHERE id=?1",
                    [observation_id],
                    |row| row.get::<_, i64>(0),
                )
                .map_err(|_| WalIdempotencyError::Unavailable)?
                == 1
            {
                observation_ids.insert(observation_id);
                roots.extend(observation_event_roots(connection, observation_id)?);
            }
        }
        "legacy" => legacy_media_keys.push(selector.selector_ref.clone()),
        _ => return Err(WalIdempotencyError::Corrupt),
    }

    let mut event_ids = BTreeSet::new();
    let mut work_unit_ids = BTreeSet::new();
    for root in roots {
        let subtree = capture_event_subtree_bounded(connection, &root)?;
        // `capture_events.canonical_event_id` is ON DELETE CASCADE.  A
        // surviving descendant therefore protects the whole ancestor chain;
        // filtering individual rows would delete the very child we chose to
        // preserve when its parent is removed.
        let mut protected = false;
        for event_id in &subtree {
            if event_has_surviving_evidence(connection, event_id)?
                || event_has_other_observations(connection, event_id, &observation_ids)?
            {
                protected = true;
                break;
            }
        }
        if protected {
            continue;
        }
        for event_id in subtree {
            let work_units = event_work_units(connection, &event_id)?;
            if work_units.len() > 1 {
                return Err(WalIdempotencyError::Corrupt);
            }
            work_unit_ids.extend(work_units);
            event_ids.insert(event_id);
        }
        if event_ids.len() > MAX_EVENTS_PER_SELECTOR {
            return Err(WalIdempotencyError::Limit);
        }
    }

    let event_ids = event_ids.into_iter().collect::<Vec<_>>();
    let work_unit_ids = work_unit_ids.into_iter().collect::<Vec<_>>();
    let observation_ids = observation_ids.into_iter().collect::<Vec<_>>();
    let (
        voice_page_sequence,
        voice_scan_cursor,
        voice_progress_commitment,
        voice_progress_rows,
        reserved_cleanup_rows,
        reserved_cleanup_bytes,
    ) = if observation_ids.is_empty() {
        (0, 0, None, 0, 0, 0)
    } else {
        if load_voice_episode_page(
            connection,
            preparation.clone(),
            selector_ordinal,
            selector.clone(),
        )?
        .is_some()
        {
            return Err(WalIdempotencyError::Precondition);
        }
        let (page_sequence, scan_cursor, stored_progress_rows, reserved_rows, reserved_bytes) =
            connection
                .query_row(
                    "SELECT voice_page_sequence,voice_scan_cursor,
                        voice_progress_rows,reserved_cleanup_rows,reserved_cleanup_bytes
                 FROM archive_v3_wal_episode_delete_selectors
                 WHERE preparation_operation_id=?1 AND ordinal=?2",
                    params![
                        preparation.preparation_operation_id.as_bytes().as_slice(),
                        selector_ordinal
                    ],
                    |row| {
                        Ok((
                            row.get::<_, i64>(0)?,
                            row.get::<_, i64>(1)?,
                            row.get::<_, i64>(2)?,
                            row.get::<_, i64>(3)?,
                            row.get::<_, i64>(4)?,
                        ))
                    },
                )
                .map_err(|_| WalIdempotencyError::Unavailable)?;
        let reserved_rows =
            u64::try_from(reserved_rows).map_err(|_| WalIdempotencyError::Corrupt)?;
        let reserved_bytes =
            u64::try_from(reserved_bytes).map_err(|_| WalIdempotencyError::Corrupt)?;
        let stored_progress_rows =
            u64::try_from(stored_progress_rows).map_err(|_| WalIdempotencyError::Corrupt)?;
        if page_sequence < 0
            || scan_cursor < 0
            || reserved_rows != VOICE_RESERVED_CLEANUP_ROWS
            || reserved_bytes != VOICE_RESERVED_CLEANUP_BYTES
        {
            return Err(WalIdempotencyError::Corrupt);
        }
        let (progress_commitment, progress_rows) =
            validate_voice_progress(connection, &preparation, selector_ordinal, page_sequence)?;
        if progress_rows != stored_progress_rows {
            return Err(WalIdempotencyError::Corrupt);
        }
        (
            page_sequence,
            scan_cursor,
            Some(progress_commitment),
            progress_rows,
            reserved_rows,
            reserved_bytes,
        )
    };
    let mut stream_ids = BTreeSet::new();
    let mut session_ids = BTreeSet::new();
    let mut browser_state_keys = BTreeSet::new();
    let mut media = Vec::new();
    for event_id in &event_ids {
        if let Some((stream_id, session_id)) = connection
            .query_row(
                "SELECT stream_id,capture_session_id FROM capture_events WHERE event_id=?1",
                [event_id],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
            )
            .optional()
            .map_err(|_| WalIdempotencyError::Unavailable)?
        {
            stream_ids.insert(stream_id);
            session_ids.insert(session_id);
        }
        if let Some(row) = connection
            .query_row(
                "SELECT object_key,object_generation,object_backend,sha256
                 FROM media_objects WHERE event_id=?1",
                [event_id],
                |row| {
                    Ok(EpisodeDeleteMedia {
                        object_key: row.get(0)?,
                        object_generation: row.get(1)?,
                        object_backend: row.get(2)?,
                        sha256: row.get(3)?,
                    })
                },
            )
            .optional()
            .map_err(|_| WalIdempotencyError::Unavailable)?
        {
            media.push(row);
        }
        if let Some(key) = connection
            .query_row(
                "SELECT state_key FROM browser_observations_v2 WHERE event_id=?1",
                [event_id],
                |row| row.get::<_, Option<String>>(0),
            )
            .optional()
            .map_err(|_| WalIdempotencyError::Unavailable)?
            .flatten()
        {
            browser_state_keys.insert(key);
        }
    }
    media.sort_by(|left, right| left.object_key.cmp(&right.object_key));
    validate_media_for_account(&preparation.account_id, &media)?;
    let stream_ids = stream_ids.into_iter().collect::<Vec<_>>();
    let session_ids = session_ids.into_iter().collect::<Vec<_>>();
    let browser_state_keys = browser_state_keys.into_iter().collect::<Vec<_>>();

    let predecessor_commitment = selector_expansion_commitment(
        connection,
        &preparation,
        selector_ordinal,
        &selector,
        &event_ids,
        &work_unit_ids,
        &stream_ids,
        &session_ids,
        &browser_state_keys,
        &observation_ids,
        voice_page_sequence,
        voice_scan_cursor,
        voice_progress_commitment,
        voice_progress_rows,
        reserved_cleanup_rows,
        reserved_cleanup_bytes,
        &media,
        &legacy_media_keys,
    )?;
    let expansion = EpisodeDeleteSelectorExpansion {
        preparation,
        selector_ordinal,
        selector,
        predecessor_commitment,
        event_ids,
        work_unit_ids,
        stream_ids,
        session_ids,
        browser_state_keys,
        observation_ids,
        voice_page_sequence,
        voice_scan_cursor,
        voice_progress_commitment,
        voice_progress_rows,
        reserved_cleanup_rows,
        reserved_cleanup_bytes,
        media,
        legacy_media_keys,
    };
    validate_selector_expansion(&expansion)?;
    Ok(expansion)
}

fn apply_selector_expansion(
    transaction: &Transaction<'_>,
    expansion: &EpisodeDeleteSelectorExpansion,
    request_fingerprint: WalRequestFingerprint,
) -> Result<()> {
    let current = load_selector_expansion(
        transaction,
        expansion.preparation.clone(),
        expansion.selector_ordinal,
        expansion.selector.clone(),
    )?;
    if current != *expansion {
        return Err(WalIdempotencyError::Precondition);
    }
    let cleanup_items_commitment =
        selector_cleanup_items_commitment(&expansion.media, &expansion.legacy_media_keys)?;
    let (cleanup_rows, cleanup_bytes) =
        cleanup_variable_usage(&expansion.media, &expansion.legacy_media_keys)?;
    let progress_bytes = expansion
        .voice_progress_rows
        .checked_mul(VOICE_PROGRESS_ROW_BYTES)
        .ok_or(WalIdempotencyError::Limit)?;
    let state = load_ledger_state(transaction)?;
    let released_rows = expansion
        .reserved_cleanup_rows
        .checked_add(expansion.voice_progress_rows)
        .ok_or(WalIdempotencyError::Limit)?;
    let released_bytes = expansion
        .reserved_cleanup_bytes
        .checked_add(progress_bytes)
        .ok_or(WalIdempotencyError::Limit)?;
    if state.source_count < released_rows
        || state.source_bytes < released_bytes
        || (expansion.selector.selector_kind == "voice"
            && (cleanup_rows > expansion.reserved_cleanup_rows
                || cleanup_bytes > expansion.reserved_cleanup_bytes))
    {
        return Err(WalIdempotencyError::Corrupt);
    }
    let next_source_count = state
        .source_count
        .checked_sub(released_rows)
        .ok_or(WalIdempotencyError::Corrupt)?
        .checked_add(cleanup_rows)
        .ok_or(WalIdempotencyError::Limit)?;
    let next_source_bytes = state
        .source_bytes
        .checked_sub(released_bytes)
        .ok_or(WalIdempotencyError::Corrupt)?
        .checked_add(cleanup_bytes)
        .ok_or(WalIdempotencyError::Limit)?;
    if next_source_count > MAX_SOURCE_ROWS || next_source_bytes > MAX_SOURCE_BYTES {
        return Err(WalIdempotencyError::Limit);
    }
    if transaction
        .execute(
            "UPDATE archive_v3_wal_episode_delete_state
             SET source_count=?1,source_bytes=?2
             WHERE singleton=1 AND source_count=?3 AND source_bytes=?4",
            params![
                i64::try_from(next_source_count).map_err(|_| WalIdempotencyError::Limit)?,
                i64::try_from(next_source_bytes).map_err(|_| WalIdempotencyError::Limit)?,
                i64::try_from(state.source_count).map_err(|_| WalIdempotencyError::Corrupt)?,
                i64::try_from(state.source_bytes).map_err(|_| WalIdempotencyError::Corrupt)?,
            ],
        )
        .map_err(|_| WalIdempotencyError::Unavailable)?
        != 1
    {
        return Err(WalIdempotencyError::Corrupt);
    }
    crate::episodes::purge_speaker_observations_after_invalidation_transaction_at(
        transaction,
        &expansion.observation_ids,
        &expansion.preparation.mutation_stamp,
    )
    .map_err(|_| WalIdempotencyError::Unavailable)?;
    insert_cleanup_for_selector(transaction, expansion)?;
    for event_id in &expansion.event_ids {
        transaction
            .execute("DELETE FROM capture_events WHERE event_id=?1", [event_id])
            .map_err(|_| WalIdempotencyError::Unavailable)?;
    }
    for work_unit_id in &expansion.work_unit_ids {
        transaction
            .execute(
                "DELETE FROM media_work_units WHERE id=?1 AND NOT EXISTS (
                   SELECT 1 FROM media_work_members member
                   WHERE member.work_unit_id=media_work_units.id
                 )",
                [work_unit_id],
            )
            .map_err(|_| WalIdempotencyError::Unavailable)?;
    }
    for stream_id in &expansion.stream_ids {
        transaction
            .execute(
                "DELETE FROM capture_streams WHERE id=?1 AND NOT EXISTS (
                   SELECT 1 FROM capture_events event WHERE event.stream_id=capture_streams.id
                 )",
                [stream_id],
            )
            .map_err(|_| WalIdempotencyError::Unavailable)?;
    }
    for session_id in &expansion.session_ids {
        transaction
            .execute(
                "DELETE FROM capture_sessions WHERE id=?1 AND NOT EXISTS (
                   SELECT 1 FROM capture_events event
                   WHERE event.capture_session_id=capture_sessions.id
                 ) AND NOT EXISTS (
                   SELECT 1 FROM capture_streams stream
                   WHERE stream.capture_session_id=capture_sessions.id
                 )",
                [session_id],
            )
            .map_err(|_| WalIdempotencyError::Unavailable)?;
    }
    for state_key in &expansion.browser_state_keys {
        transaction
            .execute(
                "DELETE FROM browser_states_v2 WHERE state_key=?1 AND NOT EXISTS (
                   SELECT 1 FROM browser_observations_v2 observation
                   WHERE observation.state_key=browser_states_v2.state_key
                 )",
                [state_key],
            )
            .map_err(|_| WalIdempotencyError::Unavailable)?;
    }
    if expansion.selector.selector_kind == "voice" {
        let deleted = transaction
            .execute(
                "DELETE FROM archive_v3_wal_episode_delete_voice_progress
                 WHERE preparation_operation_id=?1 AND selector_ordinal=?2",
                params![
                    expansion
                        .preparation
                        .preparation_operation_id
                        .as_bytes()
                        .as_slice(),
                    expansion.selector_ordinal,
                ],
            )
            .map_err(|_| WalIdempotencyError::Unavailable)?;
        if u64::try_from(deleted).map_err(|_| WalIdempotencyError::Corrupt)?
            != expansion.voice_progress_rows
        {
            return Err(WalIdempotencyError::Precondition);
        }
    }
    let cleanup_count = cleanup_rows;
    let next_state = if cleanup_count == 0 {
        "complete"
    } else {
        "cleaning"
    };
    if transaction
        .execute(
            "UPDATE archive_v3_wal_episode_delete_selectors
             SET selector_state=?1,expansion_predecessor_commitment=?2,
                 cleanup_items_commitment=?3,cleanup_count=?4,settled_count=0,
                 cleanup_rows=?5,cleanup_bytes=?6,expansion_request_fingerprint=?7,
                 voice_progress_rows=0
             WHERE preparation_operation_id=?8 AND ordinal=?9
               AND selector_kind=?10 AND selector_ref=?11 AND selector_state='pending'
               AND expansion_predecessor_commitment IS NULL
               AND cleanup_items_commitment IS NULL AND cleanup_count IS NULL
               AND settled_count=0 AND cleanup_rows=0 AND cleanup_bytes=0
               AND voice_progress_rows=?12
               AND reserved_cleanup_rows=?13 AND reserved_cleanup_bytes=?14",
            params![
                next_state,
                expansion.predecessor_commitment.as_slice(),
                cleanup_items_commitment.as_slice(),
                i64::try_from(cleanup_count).map_err(|_| WalIdempotencyError::Limit)?,
                i64::try_from(cleanup_rows).map_err(|_| WalIdempotencyError::Limit)?,
                i64::try_from(cleanup_bytes).map_err(|_| WalIdempotencyError::Limit)?,
                request_fingerprint.as_bytes().as_slice(),
                expansion
                    .preparation
                    .preparation_operation_id
                    .as_bytes()
                    .as_slice(),
                expansion.selector_ordinal,
                expansion.selector.selector_kind,
                expansion.selector.selector_ref,
                i64::try_from(expansion.voice_progress_rows)
                    .map_err(|_| WalIdempotencyError::Limit)?,
                i64::try_from(expansion.reserved_cleanup_rows)
                    .map_err(|_| WalIdempotencyError::Limit)?,
                i64::try_from(expansion.reserved_cleanup_bytes)
                    .map_err(|_| WalIdempotencyError::Limit)?,
            ],
        )
        .map_err(|_| WalIdempotencyError::Unavailable)?
        != 1
    {
        return Err(WalIdempotencyError::Precondition);
    }
    Ok(())
}

fn apply_voice_capacity_reservation(
    transaction: &Transaction<'_>,
    reservation: &EpisodeDeleteVoiceReservation,
) -> Result<()> {
    let current = load_voice_capacity_reservation(
        transaction,
        reservation.preparation.clone(),
        reservation.selector_ordinal,
        reservation.selector.clone(),
    )?
    .ok_or(WalIdempotencyError::Precondition)?;
    if current != *reservation {
        return Err(WalIdempotencyError::Precondition);
    }
    let state = load_ledger_state(transaction)?;
    let next_count = state
        .source_count
        .checked_add(VOICE_RESERVED_CLEANUP_ROWS)
        .ok_or(WalIdempotencyError::Limit)?;
    let next_bytes = state
        .source_bytes
        .checked_add(VOICE_RESERVED_CLEANUP_BYTES)
        .ok_or(WalIdempotencyError::Limit)?;
    if next_count > MAX_SOURCE_ROWS || next_bytes > MAX_SOURCE_BYTES {
        return Err(WalIdempotencyError::Limit);
    }
    if transaction
        .execute(
            "UPDATE archive_v3_wal_episode_delete_state
             SET source_count=?1,source_bytes=?2
             WHERE singleton=1 AND source_count=?3 AND source_bytes=?4",
            params![
                i64::try_from(next_count).map_err(|_| WalIdempotencyError::Limit)?,
                i64::try_from(next_bytes).map_err(|_| WalIdempotencyError::Limit)?,
                i64::try_from(state.source_count).map_err(|_| WalIdempotencyError::Corrupt)?,
                i64::try_from(state.source_bytes).map_err(|_| WalIdempotencyError::Corrupt)?,
            ],
        )
        .map_err(|_| WalIdempotencyError::Unavailable)?
        != 1
    {
        return Err(WalIdempotencyError::Corrupt);
    }
    if transaction
        .execute(
            "UPDATE archive_v3_wal_episode_delete_selectors
             SET reserved_cleanup_rows=?1,reserved_cleanup_bytes=?2
             WHERE preparation_operation_id=?3 AND ordinal=?4
               AND selector_kind='voice' AND selector_ref=?5
               AND selector_state='pending'
               AND reserved_cleanup_rows=0 AND reserved_cleanup_bytes=0
               AND voice_page_sequence=0 AND voice_scan_cursor=0 AND voice_progress_rows=0
               AND expansion_predecessor_commitment IS NULL
               AND cleanup_items_commitment IS NULL AND cleanup_count IS NULL",
            params![
                i64::try_from(VOICE_RESERVED_CLEANUP_ROWS)
                    .map_err(|_| WalIdempotencyError::Limit)?,
                i64::try_from(VOICE_RESERVED_CLEANUP_BYTES)
                    .map_err(|_| WalIdempotencyError::Limit)?,
                reservation
                    .preparation
                    .preparation_operation_id
                    .as_bytes()
                    .as_slice(),
                reservation.selector_ordinal,
                reservation.selector.selector_ref,
            ],
        )
        .map_err(|_| WalIdempotencyError::Unavailable)?
        != 1
    {
        return Err(WalIdempotencyError::Precondition);
    }
    Ok(())
}

fn voice_episode_page_predecessor_commitment(
    connection: &Connection,
    page: &EpisodeDeleteVoicePage,
) -> Result<[u8; 32]> {
    let mut hasher = Sha256::new();
    let mut budget = EvidenceBudget::default();
    hash_field(
        &mut hasher,
        b"kioku:episode-delete:voice-page-predecessor:v1",
    )?;
    hash_field(
        &mut hasher,
        page.preparation.preparation_operation_id.as_bytes(),
    )?;
    hash_field(&mut hasher, &page.selector_ordinal.to_be_bytes())?;
    hash_field(&mut hasher, page.selector.selector_ref.as_bytes())?;
    hash_field(&mut hasher, &page.expected_page_sequence.to_be_bytes())?;
    hash_field(&mut hasher, &page.expected_scan_cursor.to_be_bytes())?;
    hash_field(&mut hasher, &page.expected_progress_rows.to_be_bytes())?;
    hash_query(
        connection,
        "SELECT * FROM archive_v3_wal_episode_delete_selectors
         WHERE preparation_operation_id=?1 AND ordinal=?2",
        &[
            &page
                .preparation
                .preparation_operation_id
                .as_bytes()
                .as_slice(),
            &page.selector_ordinal,
        ],
        &mut hasher,
        &mut budget,
    )?;
    let observation_id = page
        .selector
        .selector_ref
        .parse::<i64>()
        .map_err(|_| WalIdempotencyError::Malformed)?;
    hash_voice_observation_closure(connection, &[observation_id], &mut hasher, &mut budget)?;
    for episode in &page.episodes {
        if let Some(progress) = &episode.prior_progress {
            hash_field(&mut hasher, &progress.page_sequence.to_be_bytes())?;
            hash_field(&mut hasher, &progress.predecessor_revision.to_be_bytes())?;
            hash_field(&mut hasher, &progress.resulting_revision.to_be_bytes())?;
            hash_field(&mut hasher, &progress.page_predecessor_commitment)?;
            hash_field(&mut hasher, &progress.progress_commitment)?;
        } else {
            hash_field(&mut hasher, &[])?;
        }
        hash_query(
            connection,
            "SELECT * FROM episodes WHERE id=?1",
            &[&episode.episode_id],
            &mut hasher,
            &mut budget,
        )?;
        hash_query(
            connection,
            "SELECT member.* FROM episode_members member
             WHERE member.episode_id=?1 ORDER BY member.record_type,member.record_id",
            &[&episode.episode_id],
            &mut hasher,
            &mut budget,
        )?;
        hash_query(
            connection,
            "SELECT utterance.* FROM utterances utterance
             JOIN episode_members member ON member.record_id=utterance.id
             WHERE member.episode_id=?1 AND member.record_type='utterance'
             ORDER BY utterance.id",
            &[&episode.episode_id],
            &mut hasher,
            &mut budget,
        )?;
    }
    Ok(hasher.finalize().into())
}

fn apply_voice_episode_page(
    transaction: &Transaction<'_>,
    page: &EpisodeDeleteVoicePage,
    _request_fingerprint: WalRequestFingerprint,
) -> Result<()> {
    let current = load_voice_episode_page(
        transaction,
        page.preparation.clone(),
        page.selector_ordinal,
        page.selector.clone(),
    )?
    .ok_or(WalIdempotencyError::Precondition)?;
    if current != *page {
        return Err(WalIdempotencyError::Precondition);
    }
    let new_progress_rows = u64::try_from(
        page.episodes
            .iter()
            .filter(|episode| episode.prior_progress.is_none())
            .count(),
    )
    .map_err(|_| WalIdempotencyError::Limit)?;
    let new_progress_bytes = new_progress_rows
        .checked_mul(VOICE_PROGRESS_ROW_BYTES)
        .ok_or(WalIdempotencyError::Limit)?;
    let next_progress_rows = page
        .expected_progress_rows
        .checked_add(new_progress_rows)
        .ok_or(WalIdempotencyError::Limit)?;
    if next_progress_rows > MAX_SOURCE_ROWS {
        return Err(WalIdempotencyError::Limit);
    }
    if new_progress_rows > 0 {
        let state = load_ledger_state(transaction)?;
        let next_source_count = state
            .source_count
            .checked_add(new_progress_rows)
            .ok_or(WalIdempotencyError::Limit)?;
        let next_source_bytes = state
            .source_bytes
            .checked_add(new_progress_bytes)
            .ok_or(WalIdempotencyError::Limit)?;
        if next_source_count > MAX_SOURCE_ROWS || next_source_bytes > MAX_SOURCE_BYTES {
            return Err(WalIdempotencyError::Limit);
        }
        if transaction
            .execute(
                "UPDATE archive_v3_wal_episode_delete_state
                 SET source_count=?1,source_bytes=?2
                 WHERE singleton=1 AND source_count=?3 AND source_bytes=?4",
                params![
                    i64::try_from(next_source_count).map_err(|_| WalIdempotencyError::Limit)?,
                    i64::try_from(next_source_bytes).map_err(|_| WalIdempotencyError::Limit)?,
                    i64::try_from(state.source_count).map_err(|_| WalIdempotencyError::Corrupt)?,
                    i64::try_from(state.source_bytes).map_err(|_| WalIdempotencyError::Corrupt)?,
                ],
            )
            .map_err(|_| WalIdempotencyError::Unavailable)?
            != 1
        {
            return Err(WalIdempotencyError::Corrupt);
        }
    }
    let page_sequence = page
        .expected_page_sequence
        .checked_add(1)
        .ok_or(WalIdempotencyError::Limit)?;
    let next_scan_cursor = page
        .episodes
        .last()
        .map(|episode| episode.episode_id)
        .ok_or(WalIdempotencyError::Malformed)?;
    for episode in &page.episodes {
        let resulting_revision = episode
            .identity_revision
            .checked_add(1)
            .ok_or(WalIdempotencyError::Limit)?;
        if transaction
            .execute(
                "UPDATE episodes
                 SET identity_revision=?1,identity_refresh_status='queued',
                     updated_at=CASE WHEN COALESCE(updated_at,'')<?2 THEN ?2 ELSE updated_at END
                 WHERE id=?3 AND typeof(identity_revision)='integer'
                   AND identity_revision=?4",
                params![
                    resulting_revision,
                    page.preparation.mutation_stamp,
                    episode.episode_id,
                    episode.identity_revision,
                ],
            )
            .map_err(|_| WalIdempotencyError::Unavailable)?
            != 1
        {
            return Err(WalIdempotencyError::Precondition);
        }
        let mut progress = VoiceEpisodeProgress {
            page_sequence,
            predecessor_revision: episode.identity_revision,
            resulting_revision,
            page_predecessor_commitment: page.predecessor_commitment,
            progress_commitment: [0; 32],
        };
        progress.progress_commitment = voice_episode_progress_commitment(
            &page.preparation,
            page.selector_ordinal,
            episode.episode_id,
            &progress,
        )?;
        let changed = if let Some(prior) = &episode.prior_progress {
            transaction
                .execute(
                    "UPDATE archive_v3_wal_episode_delete_voice_progress
                     SET page_sequence=?1,predecessor_revision=?2,resulting_revision=?3,
                         page_predecessor_commitment=?4,progress_commitment=?5
                     WHERE preparation_operation_id=?6 AND selector_ordinal=?7
                       AND episode_id=?8 AND page_sequence=?9
                       AND predecessor_revision=?10 AND resulting_revision=?11
                       AND page_predecessor_commitment=?12 AND progress_commitment=?13",
                    params![
                        progress.page_sequence,
                        progress.predecessor_revision,
                        progress.resulting_revision,
                        progress.page_predecessor_commitment.as_slice(),
                        progress.progress_commitment.as_slice(),
                        page.preparation
                            .preparation_operation_id
                            .as_bytes()
                            .as_slice(),
                        page.selector_ordinal,
                        episode.episode_id,
                        prior.page_sequence,
                        prior.predecessor_revision,
                        prior.resulting_revision,
                        prior.page_predecessor_commitment.as_slice(),
                        prior.progress_commitment.as_slice(),
                    ],
                )
                .map_err(|_| WalIdempotencyError::Unavailable)?
        } else {
            transaction
                .execute(
                    "INSERT INTO archive_v3_wal_episode_delete_voice_progress
                       (preparation_operation_id,selector_ordinal,episode_id,page_sequence,
                        predecessor_revision,resulting_revision,
                        page_predecessor_commitment,progress_commitment)
                     VALUES (?1,?2,?3,?4,?5,?6,?7,?8)",
                    params![
                        page.preparation
                            .preparation_operation_id
                            .as_bytes()
                            .as_slice(),
                        page.selector_ordinal,
                        episode.episode_id,
                        progress.page_sequence,
                        progress.predecessor_revision,
                        progress.resulting_revision,
                        progress.page_predecessor_commitment.as_slice(),
                        progress.progress_commitment.as_slice(),
                    ],
                )
                .map_err(|_| WalIdempotencyError::Unavailable)?
        };
        if changed != 1 {
            return Err(WalIdempotencyError::Precondition);
        }
    }
    if transaction
        .execute(
            "UPDATE archive_v3_wal_episode_delete_selectors
             SET voice_page_sequence=?1,voice_scan_cursor=?2,voice_progress_rows=?3
             WHERE preparation_operation_id=?4 AND ordinal=?5
               AND selector_kind='voice' AND selector_ref=?6
               AND selector_state='pending' AND voice_page_sequence=?7
               AND voice_scan_cursor=?8 AND voice_progress_rows=?9
               AND reserved_cleanup_rows=?10 AND reserved_cleanup_bytes=?11
               AND expansion_predecessor_commitment IS NULL
               AND cleanup_items_commitment IS NULL AND cleanup_count IS NULL",
            params![
                page_sequence,
                next_scan_cursor,
                i64::try_from(next_progress_rows).map_err(|_| WalIdempotencyError::Limit)?,
                page.preparation
                    .preparation_operation_id
                    .as_bytes()
                    .as_slice(),
                page.selector_ordinal,
                page.selector.selector_ref,
                page.expected_page_sequence,
                page.expected_scan_cursor,
                i64::try_from(page.expected_progress_rows)
                    .map_err(|_| WalIdempotencyError::Limit)?,
                i64::try_from(VOICE_RESERVED_CLEANUP_ROWS)
                    .map_err(|_| WalIdempotencyError::Limit)?,
                i64::try_from(VOICE_RESERVED_CLEANUP_BYTES)
                    .map_err(|_| WalIdempotencyError::Limit)?,
            ],
        )
        .map_err(|_| WalIdempotencyError::Unavailable)?
        != 1
    {
        return Err(WalIdempotencyError::Precondition);
    }
    Ok(())
}

#[derive(Clone)]
struct StoredCompletion {
    operation_id: WalLogicalOperationId,
    request_fingerprint: WalRequestFingerprint,
    result: WalReplayResult,
}

struct StoredPreparation {
    preparation: EpisodeDeletePreparation,
    completion: Option<StoredCompletion>,
}

fn load_preparation_by_id(
    connection: &Connection,
    account_id: &str,
    episode_id: i64,
) -> Result<Option<StoredPreparation>> {
    let expected_preparation_id = preparation_operation_id(account_id, episode_id)?;
    let expected_completion_id = completion_operation_id(account_id, episode_id)?;
    let row = connection
        .query_row(
            "SELECT preparation_operation_id,completion_operation_id,episode_id,
                    prepare_format_version,prepare_codec_version,prepare_request_fingerprint,
                    prepare_result_bytes,prepare_result_commitment,
                    completion_format_version,completion_codec_version,
                    completion_request_fingerprint,completion_result_bytes,
                    completion_result_commitment,deleted_utterances,deleted_screenshots,
                    deleted_segments,predecessor_commitment,receipt_commitment,cleanup_commitment,
                    mutation_stamp
             FROM archive_v3_wal_episode_delete_operations
             WHERE preparation_operation_id=?1",
            [expected_preparation_id.as_bytes().as_slice()],
            |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, i64>(4)?,
                    row.get::<_, Vec<u8>>(5)?,
                    row.get::<_, Vec<u8>>(6)?,
                    row.get::<_, Vec<u8>>(7)?,
                    row.get::<_, Option<i64>>(8)?,
                    row.get::<_, Option<i64>>(9)?,
                    row.get::<_, Option<Vec<u8>>>(10)?,
                    row.get::<_, Option<Vec<u8>>>(11)?,
                    row.get::<_, Option<Vec<u8>>>(12)?,
                    row.get::<_, i64>(13)?,
                    row.get::<_, i64>(14)?,
                    row.get::<_, i64>(15)?,
                    row.get::<_, Vec<u8>>(16)?,
                    row.get::<_, Vec<u8>>(17)?,
                    row.get::<_, Vec<u8>>(18)?,
                    row.get::<_, String>(19)?,
                ))
            },
        )
        .optional()
        .map_err(|_| WalIdempotencyError::Unavailable)?;
    let Some(row) = row else {
        let conflicting = connection
            .query_row(
                "SELECT COUNT(*) FROM archive_v3_wal_episode_delete_operations
                 WHERE episode_id=?1 OR completion_operation_id=?2",
                params![episode_id, expected_completion_id.as_bytes().as_slice()],
                |row| row.get::<_, i64>(0),
            )
            .map_err(|_| WalIdempotencyError::Unavailable)?;
        if conflicting != 0 {
            return Err(WalIdempotencyError::Corrupt);
        }
        return Ok(None);
    };
    let (
        preparation_id,
        completion_id,
        stored_episode_id,
        prepare_format,
        prepare_codec,
        prepare_fingerprint,
        prepare_result,
        prepare_result_commitment,
        completion_format,
        completion_codec,
        completion_fingerprint,
        completion_result,
        completion_result_commitment,
        utterances,
        screenshots,
        segments,
        predecessor_commitment,
        stored_receipt_commitment,
        stored_cleanup_commitment,
        mutation_stamp,
    ) = row;
    if preparation_id.as_slice() != expected_preparation_id.as_bytes().as_slice()
        || completion_id.as_slice() != expected_completion_id.as_bytes().as_slice()
        || stored_episode_id != episode_id
        || prepare_format != i64::from(WalOperationKind::format_version())
        || prepare_codec != i64::from(WalOperationKind::EpisodeDeletePrepare.codec_version())
        || utterances < 0
        || screenshots < 0
        || segments < 0
    {
        return Err(WalIdempotencyError::Corrupt);
    }
    let predecessor_commitment = exact_digest(&predecessor_commitment)?;
    let stored_receipt_commitment = exact_digest(&stored_receipt_commitment)?;
    let stored_cleanup_commitment = exact_digest(&stored_cleanup_commitment)?;
    let expected_prepare_fingerprint = WalRequestFingerprint::derive(
        WalOperationKind::EpisodeDeletePrepare,
        &prepare_request(account_id, episode_id, predecessor_commitment)?,
    )?;
    if prepare_fingerprint.as_slice() != expected_prepare_fingerprint.as_bytes().as_slice() {
        return Err(WalIdempotencyError::FingerprintConflict);
    }
    let prepare_result =
        WalReplayResult::decode(WalOperationKind::EpisodeDeletePrepare, &prepare_result)?;
    if prepare_result_commitment.as_slice()
        != prepare_result
            .commitment(WalOperationKind::EpisodeDeletePrepare)?
            .as_slice()
        || !matches!(prepare_result, WalReplayResult::UnitApplied)
    {
        return Err(WalIdempotencyError::Corrupt);
    }

    let mut purge = EpisodePurge {
        deleted_utterances: usize::try_from(utterances)
            .map_err(|_| WalIdempotencyError::Corrupt)?,
        deleted_screenshots: usize::try_from(screenshots)
            .map_err(|_| WalIdempotencyError::Corrupt)?,
        deleted_segments: usize::try_from(segments).map_err(|_| WalIdempotencyError::Corrupt)?,
        ..EpisodePurge::default()
    };
    let mut statement = connection
        .prepare(
            "SELECT source_kind,ordinal,source_key FROM archive_v3_wal_episode_delete_sources
             WHERE preparation_operation_id=?1 ORDER BY source_kind,ordinal",
        )
        .map_err(|_| WalIdempotencyError::Unavailable)?;
    let mut rows = statement
        .query([expected_preparation_id.as_bytes().as_slice()])
        .map_err(|_| WalIdempotencyError::Unavailable)?;
    let mut source_count = 0usize;
    let mut next_utterance_ordinal = 0i64;
    let mut next_screenshot_ordinal = 0i64;
    while let Some(row) = rows.next().map_err(|_| WalIdempotencyError::Unavailable)? {
        source_count = source_count
            .checked_add(1)
            .ok_or(WalIdempotencyError::Limit)?;
        if source_count > MAX_SOURCES_PER_EPISODE {
            return Err(WalIdempotencyError::Corrupt);
        }
        let kind = row
            .get::<_, String>(0)
            .map_err(|_| WalIdempotencyError::Corrupt)?;
        let ordinal = row
            .get::<_, i64>(1)
            .map_err(|_| WalIdempotencyError::Corrupt)?;
        let key = row
            .get::<_, String>(2)
            .map_err(|_| WalIdempotencyError::Corrupt)?;
        match kind.as_str() {
            "utterance" if ordinal == next_utterance_ordinal => {
                next_utterance_ordinal += 1;
                purge.utterance_source_keys.push(key);
            }
            "screenshot" if ordinal == next_screenshot_ordinal => {
                next_screenshot_ordinal += 1;
                purge.screenshot_source_keys.push(key);
            }
            _ => return Err(WalIdempotencyError::Corrupt),
        }
    }
    if purge.utterance_source_keys.len() > purge.deleted_utterances
        || purge.screenshot_source_keys.len() > purge.deleted_screenshots
    {
        return Err(WalIdempotencyError::Corrupt);
    }
    validate_source_keys(&purge)?;
    if receipt_commitment(episode_id, &purge)? != stored_receipt_commitment {
        return Err(WalIdempotencyError::Corrupt);
    }

    let media = Vec::new();
    let legacy_media_keys = Vec::new();
    let selectors = load_selectors(connection, expected_preparation_id)?;
    if cleanup_commitment(&media, &legacy_media_keys, &selectors)? != stored_cleanup_commitment {
        return Err(WalIdempotencyError::Corrupt);
    }
    let receipt = EpisodeDeleteReceipt { episode_id, purge };
    let preparation = EpisodeDeletePreparation {
        account_id: account_id.to_owned(),
        preparation_operation_id: expected_preparation_id,
        completion_operation_id: expected_completion_id,
        predecessor_commitment,
        mutation_stamp,
        receipt_commitment: stored_receipt_commitment,
        cleanup_commitment: stored_cleanup_commitment,
        receipt,
        media,
        legacy_media_keys,
        selectors,
    };
    validate_preparation(&preparation)?;
    if connection
        .query_row(
            "SELECT COUNT(*) FROM episodes WHERE id=?1",
            [episode_id],
            |row| row.get::<_, i64>(0),
        )
        .map_err(|_| WalIdempotencyError::Unavailable)?
        != 0
    {
        return Err(WalIdempotencyError::Corrupt);
    }

    let completion_values = (
        completion_format,
        completion_codec,
        completion_fingerprint,
        completion_result,
        completion_result_commitment,
    );
    let completion = match completion_values {
        (None, None, None, None, None) => None,
        (Some(format), Some(codec), Some(fingerprint), Some(encoded), Some(commitment)) => {
            if format != i64::from(WalOperationKind::format_version())
                || codec != i64::from(WalOperationKind::EpisodeDelete.codec_version())
            {
                return Err(WalIdempotencyError::Corrupt);
            }
            let expected_fingerprint = WalRequestFingerprint::derive(
                WalOperationKind::EpisodeDelete,
                &completion_request(
                    &preparation,
                    final_selector_cleanup_commitment(connection, &preparation)?,
                )?,
            )?;
            if fingerprint.as_slice() != expected_fingerprint.as_bytes().as_slice() {
                return Err(WalIdempotencyError::FingerprintConflict);
            }
            let result = WalReplayResult::decode(WalOperationKind::EpisodeDelete, &encoded)?;
            if commitment.as_slice()
                != result
                    .commitment(WalOperationKind::EpisodeDelete)?
                    .as_slice()
                || !matches!(result, WalReplayResult::UnitApplied)
            {
                return Err(WalIdempotencyError::Corrupt);
            }
            Some(StoredCompletion {
                operation_id: expected_completion_id,
                request_fingerprint: expected_fingerprint,
                result,
            })
        }
        _ => return Err(WalIdempotencyError::Corrupt),
    };
    Ok(Some(StoredPreparation {
        preparation,
        completion,
    }))
}

fn member_rows(
    connection: &Connection,
    episode_id: i64,
    record_type: &str,
    table: &str,
) -> Result<Vec<(i64, Option<String>)>> {
    let bounds_sql = format!(
        "SELECT COUNT(*),COALESCE(MAX(length(CAST(row.source_key AS BLOB))),0),
                COALESCE(SUM(length(CAST(row.source_key AS BLOB))),0)
         FROM episode_members member
         JOIN {table} row ON row.id=member.record_id
         WHERE member.episode_id=?1 AND member.record_type=?2"
    );
    let (count, max_source_bytes, total_source_bytes) = connection
        .query_row(&bounds_sql, params![episode_id, record_type], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, i64>(2)?,
            ))
        })
        .map_err(|_| WalIdempotencyError::Unavailable)?;
    if count < 0
        || usize::try_from(count).map_err(|_| WalIdempotencyError::Limit)? > MAX_MEMBERS_PER_CLASS
        || max_source_bytes < 0
        || usize::try_from(max_source_bytes).map_err(|_| WalIdempotencyError::Limit)?
            > MAX_SOURCE_KEY_BYTES
        || total_source_bytes < 0
        || u64::try_from(total_source_bytes).map_err(|_| WalIdempotencyError::Limit)?
            > MAX_SOURCE_BYTES
    {
        return Err(WalIdempotencyError::Limit);
    }
    let sql = format!(
        "SELECT row.id,row.source_key FROM episode_members member
         JOIN {table} row ON row.id=member.record_id
         WHERE member.episode_id=?1 AND member.record_type=?2 ORDER BY row.id",
    );
    let mut statement = connection
        .prepare(&sql)
        .map_err(|_| WalIdempotencyError::Unavailable)?;
    let rows = statement
        .query_map(params![episode_id, record_type], |row| {
            Ok((row.get::<_, i64>(0)?, row.get::<_, Option<String>>(1)?))
        })
        .map_err(|_| WalIdempotencyError::Unavailable)?
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|_| WalIdempotencyError::Unavailable)?;
    if rows.len() != usize::try_from(count).map_err(|_| WalIdempotencyError::Limit)? {
        return Err(WalIdempotencyError::Precondition);
    }
    Ok(rows)
}

fn exact_screenshot_event(connection: &Connection, screenshot_id: i64) -> Result<Option<String>> {
    let row = connection
        .query_row(
            "SELECT source_key,browser_snapshot_source_key FROM screenshots WHERE id=?1",
            [screenshot_id],
            |row| {
                Ok((
                    row.get::<_, Option<String>>(0)?,
                    row.get::<_, Option<String>>(1)?,
                ))
            },
        )
        .optional()
        .map_err(|_| WalIdempotencyError::Unavailable)?
        .ok_or(WalIdempotencyError::Precondition)?;
    let source_event = match row.0.as_deref() {
        Some(source) if source.starts_with("cloud-v2:") => {
            let event_id = source
                .strip_prefix("cloud-v2:")
                .filter(|value| !value.is_empty() && value.len() <= MAX_SOURCE_KEY_BYTES)
                .ok_or(WalIdempotencyError::Malformed)?;
            require_capture_event(connection, event_id)?;
            Some(event_id.to_owned())
        }
        Some(source) => {
            let mut statement = connection
                .prepare(
                    "SELECT event_id FROM capture_events
                     WHERE device_id||':'||stream_id||':'||sequence=?1
                     ORDER BY event_id LIMIT 2",
                )
                .map_err(|_| WalIdempotencyError::Unavailable)?;
            let found = statement
                .query_map([source], |row| row.get::<_, String>(0))
                .map_err(|_| WalIdempotencyError::Unavailable)?
                .collect::<std::result::Result<Vec<_>, _>>()
                .map_err(|_| WalIdempotencyError::Unavailable)?;
            match found.as_slice() {
                [] => None,
                [event_id] => Some(event_id.clone()),
                _ => return Err(WalIdempotencyError::Corrupt),
            }
        }
        None => None,
    };
    let browser_event = match row.1.as_deref() {
        Some(source) if source.starts_with("capture-v2-browser:") => {
            let event_id = source
                .strip_prefix("capture-v2-browser:")
                .filter(|value| !value.is_empty() && value.len() <= MAX_SOURCE_KEY_BYTES)
                .ok_or(WalIdempotencyError::Malformed)?;
            require_capture_event(connection, event_id)?;
            Some(event_id.to_owned())
        }
        _ => None,
    };
    match (source_event, browser_event) {
        (Some(source), Some(browser)) if source != browser => Err(WalIdempotencyError::Corrupt),
        (None, Some(_)) => Err(WalIdempotencyError::Corrupt),
        (Some(source), _) => Ok(Some(source)),
        (None, None) => Ok(None),
    }
}

fn load_episode_delete_selectors(
    connection: &Connection,
    episode_id: i64,
    target_screenshot_ids: &BTreeSet<i64>,
    target_utterance_ids: &BTreeSet<i64>,
) -> Result<Vec<EpisodeDeleteSelector>> {
    let mut selectors = BTreeSet::new();
    for screenshot_id in target_screenshot_ids {
        if let Some(event_id) = exact_screenshot_event(connection, *screenshot_id)? {
            selectors.insert(EpisodeDeleteSelector {
                selector_kind: "event".into(),
                selector_ref: event_id,
            });
        }
    }

    for utterance_id in target_utterance_ids {
        let (observation_id, source_key) = connection
            .query_row(
                "SELECT speaker_observation_id,source_key FROM utterances WHERE id=?1",
                [utterance_id],
                |row| {
                    Ok((
                        row.get::<_, Option<i64>>(0)?,
                        row.get::<_, Option<String>>(1)?,
                    ))
                },
            )
            .map_err(|_| WalIdempotencyError::Unavailable)?;
        if let Some(observation_id) = observation_id {
            if observation_id <= 0 {
                return Err(WalIdempotencyError::Malformed);
            }
            let survivors = connection
                .query_row(
                    "SELECT COUNT(*) FROM utterances survivor
                     JOIN speaker_observations observation ON observation.id=?1
                     WHERE (survivor.speaker_observation_id=?1
                            OR (survivor.speaker_observation_id IS NULL
                                AND survivor.source_key='cloud-v2:'||observation.event_id||':'||observation.turn_id))
                       AND NOT EXISTS (
                         SELECT 1 FROM episode_members target
                         WHERE target.episode_id=?2 AND target.record_type='utterance'
                           AND target.record_id=survivor.id
                       )",
                    params![observation_id, episode_id],
                    |row| row.get::<_, i64>(0),
                )
                .map_err(|_| WalIdempotencyError::Unavailable)?;
            if survivors == 0 {
                selectors.insert(EpisodeDeleteSelector {
                    selector_kind: "voice".into(),
                    selector_ref: observation_id.to_string(),
                });
            }
            continue;
        }

        // Historical cloud-v2 utterances predate the explicit observation FK
        // but retain an unambiguous `cloud-v2:<event>:<turn>` source key.  The
        // deletion selector repairs that lineage without making a legacy row
        // permanently undeletable. Older non-cloud source keys have no
        // provider-backed capture graph; the logical purge and returned local
        // source-key list are their complete deletion contract.
        let Some(source_key) = source_key else {
            continue;
        };
        let Some(rest) = source_key.strip_prefix("cloud-v2:") else {
            continue;
        };
        let (event_id, turn_id) = rest
            .rsplit_once(':')
            .ok_or(WalIdempotencyError::Precondition)?;
        if event_id.is_empty()
            || event_id.len() > MAX_SOURCE_KEY_BYTES
            || turn_id.is_empty()
            || turn_id.len() > MAX_SOURCE_KEY_BYTES
        {
            return Err(WalIdempotencyError::Malformed);
        }
        require_capture_event(connection, event_id)?;
        let mut repaired_statement = connection
            .prepare(
                "SELECT id FROM speaker_observations
                 WHERE event_id=?1 AND turn_id=?2 ORDER BY id LIMIT 2",
            )
            .map_err(|_| WalIdempotencyError::Unavailable)?;
        let repaired = repaired_statement
            .query_map(params![event_id, turn_id], |row| row.get::<_, i64>(0))
            .map_err(|_| WalIdempotencyError::Unavailable)?
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|_| WalIdempotencyError::Unavailable)?;
        if repaired.len() > 1 {
            return Err(WalIdempotencyError::Corrupt);
        }
        if let Some(observation_id) = repaired.first().copied() {
            let survivors = connection
                .query_row(
                    "SELECT COUNT(*) FROM utterances survivor
                     JOIN speaker_observations observation ON observation.id=?1
                     WHERE (survivor.speaker_observation_id=?1
                            OR (survivor.speaker_observation_id IS NULL
                                AND survivor.source_key='cloud-v2:'||observation.event_id||':'||observation.turn_id))
                       AND NOT EXISTS (
                         SELECT 1 FROM episode_members target
                         WHERE target.episode_id=?2 AND target.record_type='utterance'
                           AND target.record_id=survivor.id
                       )",
                    params![observation_id, episode_id],
                    |row| row.get::<_, i64>(0),
                )
                .map_err(|_| WalIdempotencyError::Unavailable)?;
            if survivors == 0 {
                selectors.insert(EpisodeDeleteSelector {
                    selector_kind: "voice".into(),
                    selector_ref: observation_id.to_string(),
                });
            }
        } else {
            selectors.insert(EpisodeDeleteSelector {
                selector_kind: "event".into(),
                selector_ref: event_id.to_owned(),
            });
        }
    }

    for object_key in legacy_media_keys(connection, episode_id)? {
        selectors.insert(EpisodeDeleteSelector {
            selector_kind: "legacy".into(),
            selector_ref: object_key,
        });
    }
    if selectors.len() > MAX_SOURCE_ROWS as usize {
        return Err(WalIdempotencyError::Limit);
    }
    Ok(selectors.into_iter().collect())
}

fn require_capture_event(connection: &Connection, event_id: &str) -> Result<()> {
    let count = connection
        .query_row(
            "SELECT COUNT(*) FROM capture_events WHERE event_id=?1",
            [event_id],
            |row| row.get::<_, i64>(0),
        )
        .map_err(|_| WalIdempotencyError::Unavailable)?;
    (count == 1)
        .then_some(())
        .ok_or(WalIdempotencyError::Corrupt)
}

fn capture_event_exists(connection: &Connection, event_id: &str) -> Result<bool> {
    let count = connection
        .query_row(
            "SELECT COUNT(*) FROM capture_events WHERE event_id=?1",
            [event_id],
            |row| row.get::<_, i64>(0),
        )
        .map_err(|_| WalIdempotencyError::Unavailable)?;
    match count {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(WalIdempotencyError::Corrupt),
    }
}

fn observation_event_roots(
    connection: &Connection,
    observation_id: i64,
) -> Result<BTreeSet<String>> {
    let mut roots = BTreeSet::new();
    if let Some(event_id) = connection
        .query_row(
            "SELECT event_id FROM speaker_observations WHERE id=?1",
            [observation_id],
            |row| row.get::<_, String>(0),
        )
        .optional()
        .map_err(|_| WalIdempotencyError::Unavailable)?
    {
        if capture_event_exists(connection, &event_id)? {
            roots.insert(event_id);
        }
    }
    let mut statement = connection
        .prepare(
            "SELECT event_id FROM speaker_observation_sources
             WHERE speaker_observation_id=?1 ORDER BY event_id,window_start_ms LIMIT 129",
        )
        .map_err(|_| WalIdempotencyError::Unavailable)?;
    let rows = statement
        .query_map([observation_id], |row| row.get::<_, String>(0))
        .map_err(|_| WalIdempotencyError::Unavailable)?
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|_| WalIdempotencyError::Unavailable)?;
    if rows.len() > 128 {
        return Err(WalIdempotencyError::Limit);
    }
    for event_id in rows {
        if capture_event_exists(connection, &event_id)? {
            roots.insert(event_id);
        }
    }
    Ok(roots)
}

fn affected_voice_profile_ids(
    connection: &Connection,
    observation_ids: &[i64],
) -> Result<Vec<i64>> {
    if observation_ids.is_empty() {
        return Ok(Vec::new());
    }
    if observation_ids.len() > 128 || observation_ids.iter().any(|id| *id <= 0) {
        return Err(WalIdempotencyError::Limit);
    }
    let ids = observation_ids
        .iter()
        .map(i64::to_string)
        .collect::<Vec<_>>()
        .join(",");
    let mut statement = connection
        .prepare(&format!(
            "SELECT profile_id FROM (
               SELECT DISTINCT assignment.profile_id AS profile_id
               FROM voice_sample_profile_assignments assignment
               JOIN voice_samples sample ON sample.id=assignment.sample_id
               WHERE sample.speaker_observation_id IN ({ids})
                 AND assignment.active=1
               UNION
               SELECT DISTINCT sample.voice_profile_id AS profile_id
               FROM voice_samples sample
               WHERE sample.speaker_observation_id IN ({ids})
                 AND sample.voice_profile_id IS NOT NULL
                 AND NOT EXISTS (
                   SELECT 1 FROM voice_sample_profile_assignments assignment
                   WHERE assignment.sample_id=sample.id
                 )
             ) WHERE profile_id IS NOT NULL ORDER BY profile_id LIMIT 129"
        ))
        .map_err(|_| WalIdempotencyError::Unavailable)?;
    let values = statement
        .query_map([], |row| row.get::<_, i64>(0))
        .map_err(|_| WalIdempotencyError::Unavailable)?
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|_| WalIdempotencyError::Unavailable)?;
    if values.len() > 128 || values.iter().any(|id| *id <= 0) {
        return Err(WalIdempotencyError::Limit);
    }
    Ok(values)
}

fn event_work_units(connection: &Connection, event_id: &str) -> Result<Vec<String>> {
    let mut statement = connection
        .prepare(
            "SELECT DISTINCT work_unit_id FROM media_work_members
             WHERE event_id=?1 ORDER BY work_unit_id LIMIT 3",
        )
        .map_err(|_| WalIdempotencyError::Unavailable)?;
    let values = statement
        .query_map([event_id], |row| row.get::<_, String>(0))
        .map_err(|_| WalIdempotencyError::Unavailable)?
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|_| WalIdempotencyError::Unavailable)?;
    if values
        .iter()
        .any(|value| value.is_empty() || value.len() > MAX_WORK_UNIT_ID_BYTES)
    {
        return Err(WalIdempotencyError::Malformed);
    }
    Ok(values)
}

fn capture_event_subtree_bounded(connection: &Connection, root: &str) -> Result<BTreeSet<String>> {
    let mut events = BTreeSet::from([root.to_owned()]);
    let mut queue = vec![root.to_owned()];
    let mut cursor = 0usize;
    while let Some(parent) = queue.get(cursor).cloned() {
        cursor = cursor.checked_add(1).ok_or(WalIdempotencyError::Limit)?;
        let mut statement = connection
            .prepare(
                "SELECT event_id FROM capture_events
                 WHERE canonical_event_id=?1 ORDER BY event_id LIMIT 129",
            )
            .map_err(|_| WalIdempotencyError::Unavailable)?;
        let children = statement
            .query_map([parent], |row| row.get::<_, String>(0))
            .map_err(|_| WalIdempotencyError::Unavailable)?
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|_| WalIdempotencyError::Unavailable)?;
        if children.len() > 128 {
            return Err(WalIdempotencyError::Limit);
        }
        for child in children {
            if child.is_empty() || child.len() > MAX_SOURCE_KEY_BYTES {
                return Err(WalIdempotencyError::Malformed);
            }
            if events.insert(child.clone()) {
                queue.push(child);
                if events.len() > 128 {
                    return Err(WalIdempotencyError::Limit);
                }
            }
        }
    }
    Ok(events)
}

fn event_has_other_observations(
    connection: &Connection,
    event_id: &str,
    owned_observation_ids: &BTreeSet<i64>,
) -> Result<bool> {
    let mut statement = connection
        .prepare(
            "SELECT DISTINCT observation.id
             FROM speaker_observations observation
             LEFT JOIN speaker_observation_sources source
               ON source.speaker_observation_id=observation.id
             WHERE observation.event_id=?1 OR source.event_id=?1
             ORDER BY observation.id LIMIT 129",
        )
        .map_err(|_| WalIdempotencyError::Unavailable)?;
    let values = statement
        .query_map([event_id], |row| row.get::<_, i64>(0))
        .map_err(|_| WalIdempotencyError::Unavailable)?
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|_| WalIdempotencyError::Unavailable)?;
    if values.len() > 128 {
        return Err(WalIdempotencyError::Limit);
    }
    Ok(values
        .iter()
        .any(|observation_id| !owned_observation_ids.contains(observation_id)))
}

fn event_has_surviving_evidence(connection: &Connection, event_id: &str) -> Result<bool> {
    let survivors = connection
        .query_row(
            "SELECT
               EXISTS(
                 SELECT 1 FROM screenshots screenshot
                 JOIN capture_events event ON event.event_id=?1
                 WHERE screenshot.source_key='cloud-v2:'||event.event_id
                    OR screenshot.source_key=(event.device_id||':'||event.stream_id||':'||event.sequence)
                    OR screenshot.browser_snapshot_source_key='capture-v2-browser:'||event.event_id
                 LIMIT 1
               ) OR EXISTS(
                 SELECT 1 FROM utterances utterance
                 JOIN speaker_observations observation
                   ON observation.id=utterance.speaker_observation_id
                 LEFT JOIN speaker_observation_sources source
                   ON source.speaker_observation_id=observation.id
                 WHERE observation.event_id=?1 OR source.event_id=?1
                 LIMIT 1
               ) OR EXISTS(
                 SELECT 1 FROM utterances utterance
                 WHERE utterance.speaker_observation_id IS NULL
                   AND substr(utterance.source_key,1,length('cloud-v2:'||?1||':'))
                       ='cloud-v2:'||?1||':'
                 LIMIT 1
               )",
            [event_id],
            |row| row.get::<_, i64>(0),
        )
        .map_err(|_| WalIdempotencyError::Unavailable)?;
    Ok(survivors != 0)
}

fn observation_has_surviving_utterances(
    connection: &Connection,
    observation_id: i64,
) -> Result<bool> {
    let count = connection
        .query_row(
            "SELECT COUNT(*) FROM utterances utterance
             JOIN speaker_observations observation ON observation.id=?1
             WHERE utterance.speaker_observation_id=?1
                OR (utterance.speaker_observation_id IS NULL
                    AND utterance.source_key='cloud-v2:'||observation.event_id||':'||observation.turn_id)",
            [observation_id],
            |row| row.get::<_, i64>(0),
        )
        .map_err(|_| WalIdempotencyError::Unavailable)?;
    Ok(count != 0)
}

fn legacy_browser_snapshot_ids(connection: &Connection, episode_id: i64) -> Result<Vec<i64>> {
    let mut statement = connection
        .prepare(
            "SELECT DISTINCT snapshot.id
             FROM browser_snapshots snapshot
             JOIN screenshots target ON target.browser_snapshot_source_key=snapshot.source_key
             JOIN episode_members member ON member.record_id=target.id
             WHERE member.episode_id=?1 AND member.record_type='screenshot'
               AND snapshot.source_key NOT LIKE 'capture-v2-browser:%'
               AND NOT EXISTS (
                 SELECT 1 FROM screenshots survivor
                 WHERE survivor.browser_snapshot_source_key=snapshot.source_key
                   AND NOT EXISTS (
                     SELECT 1 FROM episode_members owned
                     WHERE owned.episode_id=?1 AND owned.record_type='screenshot'
                       AND owned.record_id=survivor.id
                   )
               )
             ORDER BY snapshot.id LIMIT ?2",
        )
        .map_err(|_| WalIdempotencyError::Unavailable)?;
    let ids = statement
        .query_map(
            params![
                episode_id,
                i64::try_from(MAX_MEMBERS_PER_CLASS + 1).map_err(|_| WalIdempotencyError::Limit)?
            ],
            |row| row.get::<_, i64>(0),
        )
        .map_err(|_| WalIdempotencyError::Unavailable)?
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|_| WalIdempotencyError::Unavailable)?;
    if ids.len() > MAX_MEMBERS_PER_CLASS || ids.iter().any(|id| *id <= 0) {
        return Err(WalIdempotencyError::Limit);
    }
    Ok(ids)
}

fn deletion_mutation_stamp(connection: &Connection, episode_id: i64) -> Result<String> {
    let mut statement = connection
        .prepare(
            "WITH target_samples(sample_id) AS (
               SELECT DISTINCT sample.id
               FROM voice_samples sample
               JOIN utterances utterance
                 ON utterance.speaker_observation_id=sample.speaker_observation_id
               JOIN episode_members member ON member.record_id=utterance.id
               WHERE member.episode_id=?1 AND member.record_type='utterance'
             ), target_profiles(profile_id) AS (
               SELECT DISTINCT assignment.profile_id
               FROM voice_sample_profile_assignments assignment
               WHERE assignment.sample_id IN (SELECT sample_id FROM target_samples)
                 AND assignment.active=1
               UNION
               SELECT DISTINCT sample.voice_profile_id
               FROM voice_samples sample
               WHERE sample.id IN (SELECT sample_id FROM target_samples)
                 AND sample.voice_profile_id IS NOT NULL
                 AND NOT EXISTS (
                   SELECT 1 FROM voice_sample_profile_assignments assignment
                   WHERE assignment.sample_id=sample.id
                 )
             ), profile_samples(sample_id) AS (
               SELECT DISTINCT assignment.sample_id
               FROM voice_sample_profile_assignments assignment
               WHERE assignment.profile_id IN (SELECT profile_id FROM target_profiles)
                 AND assignment.active=1
               UNION
               SELECT DISTINCT sample.id
               FROM voice_samples sample
               WHERE sample.voice_profile_id IN (SELECT profile_id FROM target_profiles)
                 AND NOT EXISTS (
                   SELECT 1 FROM voice_sample_profile_assignments assignment
                   WHERE assignment.sample_id=sample.id
                 )
             )
             SELECT stamp FROM (
               SELECT COALESCE(updated_at,created_at,started_at) AS stamp
               FROM episodes WHERE id=?1
               UNION ALL SELECT updated_at FROM episode_speaker_slots WHERE episode_id=?1
               UNION ALL SELECT profile.updated_at FROM voice_profiles profile
               WHERE profile.id IN (SELECT profile_id FROM target_profiles)
               UNION ALL SELECT sample.created_at FROM voice_samples sample
               WHERE sample.id IN (SELECT sample_id FROM profile_samples)
               UNION ALL SELECT assignment.created_at
               FROM voice_sample_profile_assignments assignment
               WHERE assignment.profile_id IN (SELECT profile_id FROM target_profiles)
               UNION ALL SELECT representative.updated_at
               FROM voice_profile_representatives representative
               WHERE representative.profile_id IN (SELECT profile_id FROM target_profiles)
               UNION ALL SELECT revision.created_at FROM voice_profile_revisions revision
               WHERE revision.active=1
                 AND revision.profile_id IN (SELECT profile_id FROM target_profiles)
               UNION ALL SELECT binding.updated_at FROM profile_identity_bindings binding
               WHERE binding.voice_profile_id IN (SELECT profile_id FROM target_profiles)
               UNION ALL SELECT COALESCE(other.updated_at,other.created_at,other.started_at)
               FROM episodes other
               JOIN episode_members other_member ON other_member.episode_id=other.id
               JOIN utterances other_utterance ON other_utterance.id=other_member.record_id
               JOIN voice_samples other_sample
                 ON other_sample.speaker_observation_id=other_utterance.speaker_observation_id
               WHERE other.id<>?1
                 AND other_member.record_type='utterance'
                 AND other_sample.id IN (SELECT sample_id FROM profile_samples)
             ) WHERE stamp IS NOT NULL",
        )
        .map_err(|_| WalIdempotencyError::Unavailable)?;
    let mut rows = statement
        .query([episode_id])
        .map_err(|_| WalIdempotencyError::Unavailable)?;
    let mut max_millis = None;
    while let Some(row) = rows.next().map_err(|_| WalIdempotencyError::Unavailable)? {
        let value = row
            .get::<_, String>(0)
            .map_err(|_| WalIdempotencyError::Corrupt)?;
        if value.is_empty() || value.len() > 64 {
            return Err(WalIdempotencyError::Malformed);
        }
        let millis =
            crate::cp::isotime::parse_epoch_millis(&value).ok_or(WalIdempotencyError::Malformed)?;
        max_millis = Some(max_millis.map_or(millis, |current: i64| current.max(millis)));
    }
    max_millis
        .map(crate::cp::isotime::format_epoch_millis)
        .ok_or(WalIdempotencyError::Precondition)
}

fn count_distinct_segments(connection: &Connection, episode_id: i64) -> Result<usize> {
    let count = connection
        .query_row(
            "SELECT COUNT(DISTINCT u.audio_segment_id)
             FROM episode_members m JOIN utterances u ON u.id=m.record_id
             WHERE m.episode_id=?1 AND m.record_type='utterance'
               AND NOT EXISTS (
                 SELECT 1 FROM utterances other
                 WHERE other.audio_segment_id=u.audio_segment_id AND other.id<>u.id
                   AND NOT EXISTS (
                     SELECT 1 FROM episode_members own
                     WHERE own.episode_id=?1 AND own.record_type='utterance'
                       AND own.record_id=other.id
                   )
               )",
            [episode_id],
            |row| row.get::<_, i64>(0),
        )
        .map_err(|_| WalIdempotencyError::Unavailable)?;
    usize::try_from(count).map_err(|_| WalIdempotencyError::Corrupt)
}

fn legacy_media_keys(connection: &Connection, episode_id: i64) -> Result<Vec<String>> {
    let present = connection
        .query_row(
            "SELECT COUNT(*) FROM sqlite_schema
             WHERE type='table' AND name='screenshot_images'",
            [],
            |row| row.get::<_, i64>(0),
        )
        .map_err(|_| WalIdempotencyError::Unavailable)?;
    if present == 0 {
        return Ok(Vec::new());
    }
    let (count, maximum, total) = connection
        .query_row(
            "SELECT COUNT(*),COALESCE(MAX(length(CAST(image.object_key AS BLOB))),0),
                    COALESCE(SUM(length(CAST(image.object_key AS BLOB))),0)
             FROM screenshot_images image
             JOIN episode_members member ON member.record_id=image.screenshot_id
             WHERE member.episode_id=?1 AND member.record_type='screenshot'",
            [episode_id],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, i64>(2)?,
                ))
            },
        )
        .map_err(|_| WalIdempotencyError::Unavailable)?;
    if count < 0
        || usize::try_from(count).map_err(|_| WalIdempotencyError::Limit)? > MAX_MEMBERS_PER_CLASS
        || maximum <= 0
        || usize::try_from(maximum).map_err(|_| WalIdempotencyError::Limit)? > MAX_SOURCE_KEY_BYTES
        || total < 0
        || u64::try_from(total).map_err(|_| WalIdempotencyError::Limit)? > MAX_SOURCE_BYTES
    {
        if count == 0 && maximum == 0 && total == 0 {
            return Ok(Vec::new());
        }
        return Err(WalIdempotencyError::Limit);
    }
    let mut statement = connection
        .prepare(
            "SELECT image.object_key FROM screenshot_images image
             JOIN episode_members member ON member.record_id=image.screenshot_id
             WHERE member.episode_id=?1 AND member.record_type='screenshot'
             ORDER BY image.object_key",
        )
        .map_err(|_| WalIdempotencyError::Unavailable)?;
    let keys = statement
        .query_map([episode_id], |row| row.get::<_, String>(0))
        .map_err(|_| WalIdempotencyError::Unavailable)?
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|_| WalIdempotencyError::Unavailable)?;
    if keys.len() != usize::try_from(count).map_err(|_| WalIdempotencyError::Limit)?
        || !is_sorted_unique(&keys)
    {
        return Err(WalIdempotencyError::Corrupt);
    }
    Ok(keys)
}

fn hash_episode_purge_subtree(
    connection: &Connection,
    episode_id: i64,
    hasher: &mut Sha256,
    budget: &mut EvidenceBudget,
) -> Result<()> {
    // This is the exact closure mutated by the initial tombstone transaction.
    // Voice observations and capture media are intentionally absent: bounded
    // selectors authenticate and remove those subtrees later, one unit at a
    // time. Keeping this phase to the immediate FK/explicit-delete closure
    // prevents a legal 65,536-member episode from expanding into an unbounded
    // voice/media graph before the deletion receipt is durable.
    for (table, sql) in [
        (
            "episode_participants",
            "SELECT * FROM episode_participants WHERE episode_id=?1 ORDER BY id",
        ),
        (
            "episode_speaker_slots",
            "SELECT * FROM episode_speaker_slots WHERE episode_id=?1 ORDER BY id",
        ),
        (
            "vec_episodes",
            "SELECT * FROM vec_episodes WHERE episode_id=?1 ORDER BY episode_id",
        ),
        (
            "vec_utterances",
            "SELECT v.* FROM vec_utterances v
             JOIN episode_members m ON m.record_id=v.utterance_id
             WHERE m.episode_id=?1 AND m.record_type='utterance'
             ORDER BY v.utterance_id",
        ),
        (
            "vec_screenshots",
            "SELECT v.* FROM vec_screenshots v
             JOIN episode_members m ON m.record_id=v.screenshot_id
             WHERE m.episode_id=?1 AND m.record_type='screenshot'
             ORDER BY v.screenshot_id",
        ),
        (
            "audio_segments",
            "SELECT DISTINCT segment.* FROM audio_segments segment
             JOIN utterances utterance ON utterance.audio_segment_id=segment.id
             JOIN episode_members member ON member.record_id=utterance.id
             WHERE member.episode_id=?1 AND member.record_type='utterance'
             ORDER BY segment.id",
        ),
        (
            "utterances",
            "SELECT DISTINCT sibling.* FROM utterances sibling
             WHERE sibling.audio_segment_id IN (
                SELECT utterance.audio_segment_id FROM utterances utterance
                JOIN episode_members member ON member.record_id=utterance.id
                WHERE member.episode_id=?1 AND member.record_type='utterance'
             ) ORDER BY sibling.id",
        ),
        (
            "screenshots",
            "SELECT screenshot.* FROM screenshots screenshot
             JOIN episode_members member ON member.record_id=screenshot.id
             WHERE member.episode_id=?1 AND member.record_type='screenshot'
             ORDER BY screenshot.id",
        ),
        (
            "screenshots",
            "SELECT survivor.* FROM screenshots survivor
             WHERE survivor.duplicate_of_id IN (
               SELECT target.record_id FROM episode_members target
               WHERE target.episode_id=?1 AND target.record_type='screenshot'
             ) ORDER BY survivor.id",
        ),
        (
            "screen_observation_jobs",
            "SELECT job.* FROM screen_observation_jobs job
             WHERE job.screenshot_id IN (
               SELECT target.record_id FROM episode_members target
               WHERE target.episode_id=?1 AND target.record_type='screenshot'
             ) ORDER BY job.screenshot_id",
        ),
        (
            "screen_observations",
            "SELECT observation.* FROM screen_observations observation
             WHERE observation.screenshot_id IN (
               SELECT target.record_id FROM episode_members target
               WHERE target.episode_id=?1 AND target.record_type='screenshot'
             ) ORDER BY observation.screenshot_id",
        ),
        (
            "visual_speaker_observations",
            "SELECT observation.* FROM visual_speaker_observations observation
             WHERE observation.screenshot_id IN (
               SELECT target.record_id FROM episode_members target
               WHERE target.episode_id=?1 AND target.record_type='screenshot'
             ) ORDER BY observation.id",
        ),
        (
            "episode_screen_interpretations",
            "SELECT interpretation.* FROM episode_screen_interpretations interpretation
             WHERE interpretation.episode_id=?1 OR interpretation.screenshot_id IN (
               SELECT target.record_id FROM episode_members target
               WHERE target.episode_id=?1 AND target.record_type='screenshot'
             ) ORDER BY interpretation.episode_id,interpretation.screenshot_id",
        ),
        (
            "episode_screen_interpretation_jobs",
            "SELECT * FROM episode_screen_interpretation_jobs WHERE episode_id=?1",
        ),
        (
            "episode_final_briefs",
            "SELECT * FROM episode_final_briefs WHERE episode_id=?1",
        ),
        (
            "webhook_deliveries",
            "SELECT * FROM webhook_deliveries WHERE episode_id=?1
             ORDER BY subscription_id,delivery_version",
        ),
        (
            "email_deliveries",
            "SELECT * FROM email_deliveries WHERE episode_id=?1 ORDER BY delivery_version",
        ),
        (
            "push_deliveries",
            "SELECT * FROM push_deliveries WHERE episode_id=?1
             ORDER BY installation_id,delivery_version",
        ),
        (
            "archive_v3_wal_webhook_frozen_requests",
            "SELECT frozen.* FROM archive_v3_wal_webhook_frozen_requests frozen
             JOIN webhook_deliveries delivery ON delivery.event_id=frozen.event_id
             WHERE delivery.episode_id=?1 ORDER BY frozen.event_id",
        ),
        (
            "archive_v3_wal_webhook_send_claims",
            "SELECT claim.* FROM archive_v3_wal_webhook_send_claims claim
             JOIN webhook_deliveries delivery ON delivery.event_id=claim.event_id
             WHERE delivery.episode_id=?1 ORDER BY claim.claim_id",
        ),
        (
            "archive_v3_wal_email_frozen_requests",
            "SELECT frozen.* FROM archive_v3_wal_email_frozen_requests frozen
             JOIN email_deliveries delivery ON delivery.delivery_id=frozen.delivery_id
             WHERE delivery.episode_id=?1 ORDER BY frozen.delivery_id",
        ),
        (
            "archive_v3_wal_email_send_claims",
            "SELECT claim.* FROM archive_v3_wal_email_send_claims claim
             JOIN email_deliveries delivery ON delivery.delivery_id=claim.delivery_id
             WHERE delivery.episode_id=?1 ORDER BY claim.claim_id",
        ),
        (
            "archive_v3_wal_push_send_claims",
            "SELECT claim.* FROM archive_v3_wal_push_send_claims claim
             JOIN push_deliveries delivery ON delivery.delivery_id=claim.delivery_id
             WHERE delivery.episode_id=?1 ORDER BY claim.claim_id",
        ),
    ] {
        hash_optional_table_rows(connection, table, sql, &[&episode_id], hasher, budget)?;
    }
    Ok(())
}

fn hash_optional_table_rows(
    connection: &Connection,
    table: &str,
    sql: &str,
    query_params: &[&dyn ToSql],
    hasher: &mut Sha256,
    budget: &mut EvidenceBudget,
) -> Result<()> {
    let present = connection
        .query_row(
            "SELECT COUNT(*) FROM sqlite_schema WHERE type='table' AND name=?1",
            [table],
            |row| row.get::<_, i64>(0),
        )
        .map_err(|_| WalIdempotencyError::Unavailable)?;
    hash_field(hasher, table.as_bytes())?;
    hash_field(hasher, &present.to_be_bytes())?;
    if present == 0 {
        return Ok(());
    }
    if present != 1 {
        return Err(WalIdempotencyError::Corrupt);
    }
    hash_query(connection, sql, query_params, hasher, budget)
}

fn hash_query(
    connection: &Connection,
    sql: &str,
    query_params: &[&dyn ToSql],
    hasher: &mut Sha256,
    budget: &mut EvidenceBudget,
) -> Result<()> {
    budget.begin_query()?;
    hash_field(hasher, sql.as_bytes())?;
    let statement = connection
        .prepare(sql)
        .map_err(|_| WalIdempotencyError::Unavailable)?;
    let column_count = statement.column_count();
    let length_terms = statement
        .column_names()
        .iter()
        .map(|name| {
            let quoted = name.replace('"', "\"\"");
            format!("COALESCE(length(CAST(bounded.\"{quoted}\" AS BLOB)),0)")
        })
        .collect::<Vec<_>>();
    drop(statement);
    if length_terms.is_empty() {
        return Err(WalIdempotencyError::Corrupt);
    }
    let row_length = length_terms.join("+");
    let maximum_field = if length_terms.len() == 1 {
        length_terms[0].clone()
    } else {
        format!("max({})", length_terms.join(","))
    };
    let probe_sql = format!(
        "SELECT COUNT(*),COALESCE(MAX({maximum_field}),0),COALESCE(SUM({row_length}),0)
         FROM ({sql}) AS bounded"
    );
    let (prospective_rows, maximum_field, prospective_bytes) = connection
        .query_row(&probe_sql, query_params, |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, i64>(2)?,
            ))
        })
        .map_err(|_| WalIdempotencyError::Limit)?;
    if prospective_rows < 0
        || maximum_field < 0
        || prospective_bytes < 0
        || u64::try_from(maximum_field).map_err(|_| WalIdempotencyError::Limit)?
            > MAX_EVIDENCE_FIELD_BYTES
        || budget
            .rows
            .checked_add(u64::try_from(prospective_rows).map_err(|_| WalIdempotencyError::Limit)?)
            .is_none_or(|value| value > MAX_EVIDENCE_ROWS)
        || budget
            .bytes
            .checked_add(u64::try_from(prospective_bytes).map_err(|_| WalIdempotencyError::Limit)?)
            .is_none_or(|value| value > MAX_EVIDENCE_BYTES)
    {
        return Err(WalIdempotencyError::Limit);
    }
    let mut statement = connection
        .prepare(sql)
        .map_err(|_| WalIdempotencyError::Unavailable)?;
    let mut rows = statement
        .query(query_params)
        .map_err(|_| WalIdempotencyError::Unavailable)?;
    let mut row_count = 0u64;
    while let Some(row) = rows.next().map_err(|_| WalIdempotencyError::Unavailable)? {
        budget.observe_row()?;
        row_count = row_count.checked_add(1).ok_or(WalIdempotencyError::Limit)?;
        if row_count > MAX_SOURCE_ROWS {
            return Err(WalIdempotencyError::Limit);
        }
        for index in 0..column_count {
            match row
                .get_ref(index)
                .map_err(|_| WalIdempotencyError::Unavailable)?
            {
                ValueRef::Null => hash_field(hasher, &[0])?,
                ValueRef::Integer(value) => {
                    hash_field(hasher, &[1])?;
                    hash_field(hasher, &value.to_be_bytes())?;
                }
                ValueRef::Real(value) => {
                    hash_field(hasher, &[2])?;
                    hash_field(hasher, &value.to_bits().to_be_bytes())?;
                }
                ValueRef::Text(value) => {
                    budget.observe_bytes(value.len())?;
                    hash_field(hasher, &[3])?;
                    hash_field(hasher, value)?;
                }
                ValueRef::Blob(value) => {
                    budget.observe_bytes(value.len())?;
                    hash_field(hasher, &[4])?;
                    hash_field(hasher, value)?;
                }
            }
        }
    }
    hash_field(hasher, &row_count.to_be_bytes())
}

fn validate_evidence(account_id: &str, evidence: &EpisodeDeleteEvidence) -> Result<()> {
    if evidence.episode_id <= 0
        || evidence.predecessor_commitment == [0; 32]
        || evidence.mutation_stamp.is_empty()
        || evidence.mutation_stamp.len() > 64
        || evidence.purge.deleted_utterances < evidence.purge.utterance_source_keys.len()
        || evidence.purge.deleted_screenshots < evidence.purge.screenshot_source_keys.len()
    {
        return Err(WalIdempotencyError::Malformed);
    }
    validate_source_keys(&evidence.purge)?;
    if [
        &evidence.event_ids,
        &evidence.work_unit_ids,
        &evidence.stream_ids,
        &evidence.session_ids,
        &evidence.browser_state_keys,
        &evidence.legacy_media_keys,
    ]
    .into_iter()
    .any(|values| {
        values.len() > MAX_SOURCES_PER_EPISODE
            || values
                .iter()
                .any(|value| value.is_empty() || value.len() > MAX_SOURCE_KEY_BYTES)
    }) || !is_sorted_unique(&evidence.event_ids)
        || !is_sorted_unique(&evidence.work_unit_ids)
        || !is_sorted_unique(&evidence.stream_ids)
        || !is_sorted_unique(&evidence.session_ids)
        || !is_sorted_unique(&evidence.browser_state_keys)
        || !is_sorted_unique(&evidence.legacy_media_keys)
        || evidence.legacy_browser_snapshot_ids.len() > MAX_SOURCES_PER_EPISODE
        || evidence
            .legacy_browser_snapshot_ids
            .iter()
            .any(|value| *value <= 0)
        || !evidence
            .legacy_browser_snapshot_ids
            .windows(2)
            .all(|pair| pair[0] < pair[1])
    {
        return Err(WalIdempotencyError::Malformed);
    }
    validate_media_for_account(account_id, &evidence.media)?;
    let raw_prefix = format!("raw/{account_id}/");
    let legacy_prefix = format!("media/{account_id}/");
    for key in &evidence.legacy_media_keys {
        if key.is_empty()
            || key.len() > MAX_SOURCE_KEY_BYTES
            || (!key.starts_with(&raw_prefix) && !key.starts_with(&legacy_prefix))
        {
            return Err(WalIdempotencyError::Malformed);
        }
    }
    validate_selectors(&evidence.selectors)?;
    Ok(())
}

fn validate_selectors(selectors: &[EpisodeDeleteSelector]) -> Result<()> {
    if selectors.len() > MAX_SOURCE_ROWS as usize
        || selectors.iter().any(|selector| {
            !matches!(
                selector.selector_kind.as_str(),
                "event" | "voice" | "legacy"
            ) || selector.selector_ref.is_empty()
                || selector.selector_ref.len() > MAX_SOURCE_KEY_BYTES
        })
        || !selectors.windows(2).all(|pair| pair[0] < pair[1])
    {
        return Err(WalIdempotencyError::Malformed);
    }
    for selector in selectors {
        if selector.selector_kind == "voice"
            && selector
                .selector_ref
                .parse::<i64>()
                .ok()
                .is_none_or(|value| value <= 0)
        {
            return Err(WalIdempotencyError::Malformed);
        }
    }
    Ok(())
}

fn validate_media_for_account(account_id: &str, media: &[EpisodeDeleteMedia]) -> Result<()> {
    let raw_prefix = format!("raw/{account_id}/");
    for row in media {
        if row.object_key.is_empty()
            || row.object_key.len() > MAX_SOURCE_KEY_BYTES
            || !row.object_key.starts_with(&raw_prefix)
            || row.object_generation.is_some_and(|value| value <= 0)
            || !matches!(row.object_backend.as_deref(), None | Some("current"))
            || (row.object_backend.as_deref() == Some("current") && row.object_generation.is_none())
            || row.sha256.len() != 64
            || !row.sha256.bytes().all(|byte| byte.is_ascii_hexdigit())
        {
            return Err(WalIdempotencyError::Malformed);
        }
    }
    if !media
        .windows(2)
        .all(|pair| pair[0].object_key < pair[1].object_key)
    {
        return Err(WalIdempotencyError::Malformed);
    }
    Ok(())
}

fn validate_selector_expansion(expansion: &EpisodeDeleteSelectorExpansion) -> Result<()> {
    validate_preparation(&expansion.preparation)?;
    validate_selectors(std::slice::from_ref(&expansion.selector))?;
    if expansion.selector_ordinal < 0
        || expansion.predecessor_commitment == [0; 32]
        || expansion.event_ids.len() > MAX_EVENTS_PER_SELECTOR
        || expansion.work_unit_ids.len() > MAX_EVENTS_PER_SELECTOR
        || expansion.stream_ids.len() > MAX_EVENTS_PER_SELECTOR
        || expansion.session_ids.len() > MAX_EVENTS_PER_SELECTOR
        || expansion.browser_state_keys.len() > MAX_EVENTS_PER_SELECTOR
        || expansion.observation_ids.len() > 128
        || expansion.voice_page_sequence < 0
        || expansion.voice_scan_cursor < 0
        || expansion.media.len() > MAX_EVENTS_PER_SELECTOR
        || expansion.legacy_media_keys.len() > 1
        || !is_sorted_unique(&expansion.event_ids)
        || !is_sorted_unique(&expansion.work_unit_ids)
        || !is_sorted_unique(&expansion.stream_ids)
        || !is_sorted_unique(&expansion.session_ids)
        || !is_sorted_unique(&expansion.browser_state_keys)
        || !is_sorted_unique(&expansion.legacy_media_keys)
        || !expansion
            .observation_ids
            .windows(2)
            .all(|pair| pair[0] < pair[1])
        || expansion.observation_ids.iter().any(|id| *id <= 0)
    {
        return Err(WalIdempotencyError::Malformed);
    }
    validate_media_for_account(&expansion.preparation.account_id, &expansion.media)?;
    if expansion.selector.selector_kind == "legacy"
        && expansion.legacy_media_keys.as_slice() != [expansion.selector.selector_ref.as_str()]
    {
        return Err(WalIdempotencyError::Malformed);
    }
    if (expansion.observation_ids.is_empty()
        && (expansion.voice_page_sequence != 0
            || expansion.voice_scan_cursor != 0
            || expansion.voice_progress_commitment.is_some()
            || expansion.voice_progress_rows != 0
            || expansion.reserved_cleanup_rows != 0
            || expansion.reserved_cleanup_bytes != 0))
        || (!expansion.observation_ids.is_empty()
            && (expansion.voice_progress_commitment.is_none()
                || expansion.reserved_cleanup_rows != VOICE_RESERVED_CLEANUP_ROWS
                || expansion.reserved_cleanup_bytes != VOICE_RESERVED_CLEANUP_BYTES))
    {
        return Err(WalIdempotencyError::Malformed);
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn selector_expansion_commitment(
    connection: &Connection,
    preparation: &EpisodeDeletePreparation,
    selector_ordinal: i64,
    selector: &EpisodeDeleteSelector,
    event_ids: &[String],
    work_unit_ids: &[String],
    stream_ids: &[String],
    session_ids: &[String],
    browser_state_keys: &[String],
    observation_ids: &[i64],
    voice_page_sequence: i64,
    voice_scan_cursor: i64,
    voice_progress_commitment: Option<[u8; 32]>,
    voice_progress_rows: u64,
    reserved_cleanup_rows: u64,
    reserved_cleanup_bytes: u64,
    media: &[EpisodeDeleteMedia],
    legacy_media_keys: &[String],
) -> Result<[u8; 32]> {
    let mut hasher = Sha256::new();
    let mut budget = EvidenceBudget::default();
    hash_field(&mut hasher, b"kioku:episode-delete:selector-expansion:v1")?;
    hash_field(&mut hasher, preparation.preparation_operation_id.as_bytes())?;
    hash_field(&mut hasher, &selector_ordinal.to_be_bytes())?;
    hash_field(&mut hasher, selector.selector_kind.as_bytes())?;
    hash_field(&mut hasher, selector.selector_ref.as_bytes())?;
    hash_query(
        connection,
        "SELECT * FROM archive_v3_wal_episode_delete_selectors
         WHERE preparation_operation_id=?1 AND ordinal=?2",
        &[
            &preparation.preparation_operation_id.as_bytes().as_slice(),
            &selector_ordinal,
        ],
        &mut hasher,
        &mut budget,
    )?;
    for work_unit_id in work_unit_ids {
        hash_query(
            connection,
            "SELECT * FROM media_work_units WHERE id=?1",
            &[work_unit_id],
            &mut hasher,
            &mut budget,
        )?;
        hash_query(
            connection,
            "SELECT * FROM media_work_members WHERE work_unit_id=?1 ORDER BY ordinal,event_id",
            &[work_unit_id],
            &mut hasher,
            &mut budget,
        )?;
        hash_optional_table_rows(
            connection,
            "speaker_clusters",
            "SELECT * FROM speaker_clusters WHERE work_unit_id=?1 ORDER BY id",
            &[work_unit_id],
            &mut hasher,
            &mut budget,
        )?;
    }
    for event_id in event_ids {
        for (table, sql) in [
            (
                "capture_events",
                "SELECT * FROM capture_events WHERE event_id=?1",
            ),
            (
                "media_objects",
                "SELECT * FROM media_objects WHERE event_id=?1",
            ),
            (
                "media_processing_jobs",
                "SELECT * FROM media_processing_jobs WHERE event_id=?1 ORDER BY id",
            ),
            (
                "media_work_members",
                "SELECT * FROM media_work_members WHERE event_id=?1 ORDER BY work_unit_id,ordinal",
            ),
            (
                "browser_observations_v2",
                "SELECT * FROM browser_observations_v2 WHERE event_id=?1 ORDER BY observation_id",
            ),
            (
                "speaker_observations",
                "SELECT * FROM speaker_observations WHERE event_id=?1 ORDER BY id",
            ),
            (
                "speaker_observation_sources",
                "SELECT * FROM speaker_observation_sources WHERE event_id=?1
                 ORDER BY speaker_observation_id,window_start_ms",
            ),
            (
                "identity_evidence",
                "SELECT * FROM identity_evidence WHERE source_event_id=?1 ORDER BY id",
            ),
            (
                "person_name_claims",
                "SELECT * FROM person_name_claims WHERE source_event_id=?1 ORDER BY id",
            ),
            (
                "person_name_claims",
                "SELECT survivor.* FROM person_name_claims survivor
                 WHERE survivor.supersedes_id IN (
                   SELECT target.id FROM person_name_claims target
                   WHERE target.source_event_id=?1
                 ) ORDER BY survivor.id",
            ),
            (
                "person_facts",
                "SELECT * FROM person_facts WHERE source_event_id=?1 ORDER BY id",
            ),
            (
                "person_facts",
                "SELECT survivor.* FROM person_facts survivor
                 WHERE survivor.supersedes_id IN (
                         SELECT target.id FROM person_facts target WHERE target.source_event_id=?1
                       )
                    OR survivor.conflicts_with_id IN (
                         SELECT target.id FROM person_facts target WHERE target.source_event_id=?1
                       ) ORDER BY survivor.id",
            ),
            (
                "visual_speaker_observations",
                "SELECT * FROM visual_speaker_observations WHERE event_id=?1 ORDER BY id",
            ),
        ] {
            hash_optional_table_rows(
                connection,
                table,
                sql,
                &[event_id],
                &mut hasher,
                &mut budget,
            )?;
        }
    }
    for stream_id in stream_ids {
        hash_query(
            connection,
            "SELECT * FROM capture_streams WHERE id=?1",
            &[stream_id],
            &mut hasher,
            &mut budget,
        )?;
    }
    for session_id in session_ids {
        hash_query(
            connection,
            "SELECT * FROM capture_sessions WHERE id=?1",
            &[session_id],
            &mut hasher,
            &mut budget,
        )?;
    }
    for state_key in browser_state_keys {
        hash_query(
            connection,
            "SELECT * FROM browser_states_v2 WHERE state_key=?1",
            &[state_key],
            &mut hasher,
            &mut budget,
        )?;
        hash_query(
            connection,
            "SELECT * FROM browser_observations_v2 WHERE state_key=?1 ORDER BY observation_id",
            &[state_key],
            &mut hasher,
            &mut budget,
        )?;
    }
    hash_voice_observation_closure(connection, observation_ids, &mut hasher, &mut budget)?;
    hash_field(&mut hasher, &voice_page_sequence.to_be_bytes())?;
    hash_field(&mut hasher, &voice_scan_cursor.to_be_bytes())?;
    if let Some(commitment) = voice_progress_commitment {
        hash_field(&mut hasher, &commitment)?;
    } else {
        hash_field(&mut hasher, &[])?;
    }
    hash_field(&mut hasher, &voice_progress_rows.to_be_bytes())?;
    hash_field(&mut hasher, &reserved_cleanup_rows.to_be_bytes())?;
    hash_field(&mut hasher, &reserved_cleanup_bytes.to_be_bytes())?;
    for row in media {
        hash_field(&mut hasher, row.object_key.as_bytes())?;
        hash_field(
            &mut hasher,
            &row.object_generation.unwrap_or_default().to_be_bytes(),
        )?;
        hash_field(
            &mut hasher,
            row.object_backend.as_deref().unwrap_or_default().as_bytes(),
        )?;
        hash_field(&mut hasher, row.sha256.as_bytes())?;
    }
    for key in legacy_media_keys {
        hash_field(&mut hasher, key.as_bytes())?;
    }
    Ok(hasher.finalize().into())
}

fn hash_voice_observation_closure(
    connection: &Connection,
    observation_ids: &[i64],
    hasher: &mut Sha256,
    budget: &mut EvidenceBudget,
) -> Result<()> {
    let profiles = affected_voice_profile_ids(connection, observation_ids)?;
    for observation_id in observation_ids {
        for (table, sql) in [
            (
                "speaker_observations",
                "SELECT * FROM speaker_observations WHERE id=?1",
            ),
            (
                "speaker_observation_sources",
                "SELECT * FROM speaker_observation_sources WHERE speaker_observation_id=?1
                 ORDER BY event_id,window_start_ms",
            ),
            (
                "voice_embedding_jobs",
                "SELECT * FROM voice_embedding_jobs WHERE speaker_observation_id=?1 ORDER BY id",
            ),
            (
                "voice_samples",
                "SELECT * FROM voice_samples WHERE speaker_observation_id=?1 ORDER BY id",
            ),
            (
                "voice_sample_profile_assignments",
                "SELECT assignment.* FROM voice_sample_profile_assignments assignment
                 JOIN voice_samples sample ON sample.id=assignment.sample_id
                 WHERE sample.speaker_observation_id=?1 ORDER BY assignment.id",
            ),
            (
                "voice_profile_proposal_samples",
                "SELECT proposal_sample.* FROM voice_profile_proposal_samples proposal_sample
                 JOIN voice_samples sample ON sample.id=proposal_sample.sample_id
                 WHERE sample.speaker_observation_id=?1
                 ORDER BY proposal_sample.proposal_id,proposal_sample.sample_id",
            ),
            (
                "identity_evidence",
                "SELECT * FROM identity_evidence WHERE speaker_observation_id=?1 ORDER BY id",
            ),
            (
                "person_name_claims",
                "SELECT * FROM person_name_claims WHERE speaker_observation_id=?1 ORDER BY id",
            ),
            (
                "person_name_claims",
                "SELECT survivor.* FROM person_name_claims survivor
                 WHERE survivor.supersedes_id IN (
                   SELECT target.id FROM person_name_claims target
                   WHERE target.speaker_observation_id=?1
                 ) ORDER BY survivor.id",
            ),
            (
                "person_facts",
                "SELECT * FROM person_facts WHERE speaker_observation_id=?1 ORDER BY id",
            ),
            (
                "person_facts",
                "SELECT survivor.* FROM person_facts survivor
                 WHERE survivor.supersedes_id IN (
                         SELECT target.id FROM person_facts target
                         WHERE target.speaker_observation_id=?1
                       )
                    OR survivor.conflicts_with_id IN (
                         SELECT target.id FROM person_facts target
                         WHERE target.speaker_observation_id=?1
                       ) ORDER BY survivor.id",
            ),
        ] {
            hash_optional_table_rows(connection, table, sql, &[observation_id], hasher, budget)?;
        }
    }
    for profile_id in profiles {
        if connection
            .query_row(
                "SELECT COUNT(*) FROM voice_profiles WHERE id=?1",
                [profile_id],
                |row| row.get::<_, i64>(0),
            )
            .map_err(|_| WalIdempotencyError::Unavailable)?
            != 1
        {
            return Err(WalIdempotencyError::Corrupt);
        }
        for (table, sql) in [
            ("voice_profiles", "SELECT * FROM voice_profiles WHERE id=?1"),
            (
                "voice_profile_representatives",
                "SELECT * FROM voice_profile_representatives WHERE profile_id=?1 ORDER BY id",
            ),
            (
                "voice_profile_revisions",
                "SELECT * FROM voice_profile_revisions WHERE profile_id=?1 ORDER BY id",
            ),
            (
                "profile_identity_bindings",
                "SELECT * FROM profile_identity_bindings WHERE voice_profile_id=?1 ORDER BY id",
            ),
            (
                "voice_sample_profile_assignments",
                "SELECT * FROM voice_sample_profile_assignments WHERE profile_id=?1 ORDER BY id",
            ),
            (
                "voice_samples",
                "SELECT sample.* FROM voice_samples sample
                 WHERE EXISTS (
                         SELECT 1 FROM voice_sample_profile_assignments assignment
                         WHERE assignment.sample_id=sample.id AND assignment.profile_id=?1
                           AND assignment.active=1
                       )
                    OR (sample.voice_profile_id=?1 AND NOT EXISTS (
                         SELECT 1 FROM voice_sample_profile_assignments assignment
                         WHERE assignment.sample_id=sample.id
                       ))
                 ORDER BY sample.id",
            ),
        ] {
            hash_optional_table_rows(connection, table, sql, &[&profile_id], hasher, budget)?;
        }
    }
    hash_query(
        connection,
        "SELECT name,seq FROM sqlite_sequence
         WHERE name IN ('voice_profile_representatives','voice_profile_revisions',
                        'voice_sample_profile_assignments') ORDER BY name",
        &[],
        hasher,
        budget,
    )?;
    Ok(())
}

fn validate_source_keys(purge: &EpisodePurge) -> Result<()> {
    if purge
        .utterance_source_keys
        .iter()
        .chain(&purge.screenshot_source_keys)
        .any(|key| key.is_empty() || key.len() > MAX_SOURCE_KEY_BYTES)
        || purge.utterance_source_keys.len() > MAX_MEMBERS_PER_CLASS
        || purge.screenshot_source_keys.len() > MAX_MEMBERS_PER_CLASS
    {
        return Err(WalIdempotencyError::Limit);
    }
    Ok(())
}

fn is_sorted_unique(values: &[String]) -> bool {
    values.windows(2).all(|pair| pair[0] < pair[1])
}

fn encode_string(output: &mut Vec<u8>, value: &str) -> Result<()> {
    let length = u16::try_from(value.len()).map_err(|_| WalIdempotencyError::Limit)?;
    if length == 0 {
        return Err(WalIdempotencyError::Malformed);
    }
    output.extend_from_slice(&length.to_be_bytes());
    output.extend_from_slice(value.as_bytes());
    Ok(())
}

fn preparation_operation_id(account_id: &str, episode_id: i64) -> Result<WalLogicalOperationId> {
    let episode = episode_id.to_be_bytes();
    let source = stable_operation_source(PREPARE_SUBTYPE, &[account_id.as_bytes(), &episode])?;
    WalLogicalOperationId::from_stable_source(WalOperationKind::EpisodeDeletePrepare, &source)
}

fn completion_operation_id(account_id: &str, episode_id: i64) -> Result<WalLogicalOperationId> {
    let episode = episode_id.to_be_bytes();
    let source = stable_operation_source(COMPLETE_SUBTYPE, &[account_id.as_bytes(), &episode])?;
    WalLogicalOperationId::from_stable_source(WalOperationKind::EpisodeDelete, &source)
}

fn prepare_request(
    account_id: &str,
    episode_id: i64,
    predecessor_commitment: [u8; 32],
) -> Result<Zeroizing<Vec<u8>>> {
    let mut request = Zeroizing::new(Vec::with_capacity(128));
    request.extend_from_slice(&PREPARE_REQUEST_V1.to_be_bytes());
    encode_string(&mut request, account_id)?;
    request.extend_from_slice(&episode_id.to_be_bytes());
    request.extend_from_slice(&predecessor_commitment);
    Ok(request)
}

fn completion_request(
    preparation: &EpisodeDeletePreparation,
    final_cleanup_commitment: [u8; 32],
) -> Result<Zeroizing<Vec<u8>>> {
    let mut request = Zeroizing::new(Vec::with_capacity(160));
    request.extend_from_slice(&COMPLETE_REQUEST_V1.to_be_bytes());
    encode_string(&mut request, &preparation.account_id)?;
    request.extend_from_slice(&preparation.receipt.episode_id.to_be_bytes());
    request.extend_from_slice(preparation.preparation_operation_id.as_bytes());
    request.extend_from_slice(&preparation.predecessor_commitment);
    request.extend_from_slice(&preparation.receipt_commitment);
    request.extend_from_slice(&preparation.cleanup_commitment);
    request.extend_from_slice(&final_cleanup_commitment);
    Ok(request)
}

fn cleanup_action_request(action: &EpisodeDeleteCleanupAction) -> Result<Zeroizing<Vec<u8>>> {
    match action {
        EpisodeDeleteCleanupAction::Settle(item) => cleanup_settlement_request(item),
        EpisodeDeleteCleanupAction::Expand(expansion) => {
            let cleanup_items_commitment =
                selector_cleanup_items_commitment(&expansion.media, &expansion.legacy_media_keys)?;
            let (cleanup_rows, cleanup_bytes) =
                cleanup_variable_usage(&expansion.media, &expansion.legacy_media_keys)?;
            selector_expansion_request(SelectorExpansionRequest {
                preparation: &expansion.preparation,
                selector_ordinal: expansion.selector_ordinal,
                selector: &expansion.selector,
                expansion_predecessor_commitment: expansion.predecessor_commitment,
                cleanup_items_commitment,
                cleanup_rows,
                cleanup_bytes,
                voice_page_sequence: expansion.voice_page_sequence,
                voice_scan_cursor: expansion.voice_scan_cursor,
                reserved_cleanup_rows: expansion.reserved_cleanup_rows,
                reserved_cleanup_bytes: expansion.reserved_cleanup_bytes,
            })
        }
        EpisodeDeleteCleanupAction::ReserveVoiceCapacity(reservation) => {
            let mut request = Zeroizing::new(Vec::with_capacity(192));
            request.extend_from_slice(&COMPLETE_REQUEST_V1.to_be_bytes());
            encode_string(&mut request, &reservation.preparation.account_id)?;
            request.extend_from_slice(reservation.preparation.preparation_operation_id.as_bytes());
            request.push(5);
            request.extend_from_slice(&reservation.selector_ordinal.to_be_bytes());
            encode_string(&mut request, &reservation.selector.selector_ref)?;
            request.extend_from_slice(&VOICE_RESERVED_CLEANUP_ROWS.to_be_bytes());
            request.extend_from_slice(&VOICE_RESERVED_CLEANUP_BYTES.to_be_bytes());
            Ok(request)
        }
        EpisodeDeleteCleanupAction::AdvanceVoiceEpisodes(page) => {
            let mut request = Zeroizing::new(Vec::with_capacity(4096));
            request.extend_from_slice(&COMPLETE_REQUEST_V1.to_be_bytes());
            encode_string(&mut request, &page.preparation.account_id)?;
            request.extend_from_slice(page.preparation.preparation_operation_id.as_bytes());
            request.push(4);
            request.extend_from_slice(&page.selector_ordinal.to_be_bytes());
            encode_string(&mut request, &page.selector.selector_ref)?;
            request.extend_from_slice(&page.expected_page_sequence.to_be_bytes());
            request.extend_from_slice(&page.expected_scan_cursor.to_be_bytes());
            request.extend_from_slice(&page.expected_progress_rows.to_be_bytes());
            request.extend_from_slice(&page.predecessor_commitment);
            request.extend_from_slice(
                &u64::try_from(page.episodes.len())
                    .map_err(|_| WalIdempotencyError::Limit)?
                    .to_be_bytes(),
            );
            for episode in &page.episodes {
                request.extend_from_slice(&episode.episode_id.to_be_bytes());
                request.extend_from_slice(&episode.identity_revision.to_be_bytes());
                if let Some(progress) = &episode.prior_progress {
                    request.push(1);
                    request.extend_from_slice(&progress.page_sequence.to_be_bytes());
                    request.extend_from_slice(&progress.predecessor_revision.to_be_bytes());
                    request.extend_from_slice(&progress.resulting_revision.to_be_bytes());
                    request.extend_from_slice(&progress.page_predecessor_commitment);
                    request.extend_from_slice(&progress.progress_commitment);
                } else {
                    request.push(0);
                }
            }
            Ok(request)
        }
        EpisodeDeleteCleanupAction::FinishSelector(completion) => {
            selector_finish_request(completion)
        }
        EpisodeDeleteCleanupAction::AdvanceResumeCursor {
            preparation,
            expected_cursor,
            expected_sequence,
            episode_ids,
            next_cursor,
        } => {
            let mut request = Zeroizing::new(Vec::with_capacity(160));
            request.extend_from_slice(&COMPLETE_REQUEST_V1.to_be_bytes());
            encode_string(&mut request, &preparation.account_id)?;
            request.extend_from_slice(preparation.preparation_operation_id.as_bytes());
            request.push(3);
            request.extend_from_slice(&expected_cursor.to_be_bytes());
            request.extend_from_slice(&expected_sequence.to_be_bytes());
            request.extend_from_slice(
                &u64::try_from(episode_ids.len())
                    .map_err(|_| WalIdempotencyError::Limit)?
                    .to_be_bytes(),
            );
            for episode_id in episode_ids {
                request.extend_from_slice(&episode_id.to_be_bytes());
            }
            request.extend_from_slice(&next_cursor.to_be_bytes());
            Ok(request)
        }
    }
}

fn selector_finish_request(
    completion: &EpisodeDeleteSelectorCompletion,
) -> Result<Zeroizing<Vec<u8>>> {
    let mut request = Zeroizing::new(Vec::with_capacity(192));
    request.extend_from_slice(&COMPLETE_REQUEST_V1.to_be_bytes());
    encode_string(&mut request, &completion.preparation.account_id)?;
    request.extend_from_slice(completion.preparation.preparation_operation_id.as_bytes());
    request.push(2);
    request.extend_from_slice(&completion.selector_ordinal.to_be_bytes());
    encode_string(&mut request, &completion.selector.selector_kind)?;
    encode_string(&mut request, &completion.selector.selector_ref)?;
    request.extend_from_slice(&completion.expansion_predecessor_commitment);
    request.extend_from_slice(&completion.cleanup_items_commitment);
    request.extend_from_slice(&completion.cleanup_count.to_be_bytes());
    request.extend_from_slice(&completion.cleanup_rows.to_be_bytes());
    request.extend_from_slice(&completion.cleanup_bytes.to_be_bytes());
    Ok(request)
}

struct SelectorExpansionRequest<'a> {
    preparation: &'a EpisodeDeletePreparation,
    selector_ordinal: i64,
    selector: &'a EpisodeDeleteSelector,
    expansion_predecessor_commitment: [u8; 32],
    cleanup_items_commitment: [u8; 32],
    cleanup_rows: u64,
    cleanup_bytes: u64,
    voice_page_sequence: i64,
    voice_scan_cursor: i64,
    reserved_cleanup_rows: u64,
    reserved_cleanup_bytes: u64,
}

fn selector_expansion_request(
    evidence: SelectorExpansionRequest<'_>,
) -> Result<Zeroizing<Vec<u8>>> {
    let mut request = Zeroizing::new(Vec::with_capacity(224));
    request.extend_from_slice(&COMPLETE_REQUEST_V1.to_be_bytes());
    encode_string(&mut request, &evidence.preparation.account_id)?;
    request.extend_from_slice(evidence.preparation.preparation_operation_id.as_bytes());
    request.push(1);
    request.extend_from_slice(&evidence.selector_ordinal.to_be_bytes());
    encode_string(&mut request, &evidence.selector.selector_kind)?;
    encode_string(&mut request, &evidence.selector.selector_ref)?;
    request.extend_from_slice(&evidence.expansion_predecessor_commitment);
    request.extend_from_slice(&evidence.cleanup_items_commitment);
    request.extend_from_slice(&evidence.cleanup_rows.to_be_bytes());
    request.extend_from_slice(&evidence.cleanup_bytes.to_be_bytes());
    request.extend_from_slice(&evidence.voice_page_sequence.to_be_bytes());
    request.extend_from_slice(&evidence.voice_scan_cursor.to_be_bytes());
    request.extend_from_slice(&evidence.reserved_cleanup_rows.to_be_bytes());
    request.extend_from_slice(&evidence.reserved_cleanup_bytes.to_be_bytes());
    Ok(request)
}

fn cleanup_settlement_request(item: &EpisodeDeleteCleanupItem) -> Result<Zeroizing<Vec<u8>>> {
    let mut request = Zeroizing::new(Vec::with_capacity(1400));
    request.extend_from_slice(&COMPLETE_REQUEST_V1.to_be_bytes());
    encode_string(&mut request, &item.preparation.account_id)?;
    request.extend_from_slice(item.preparation.preparation_operation_id.as_bytes());
    encode_string(&mut request, &item.cleanup_kind)?;
    request.extend_from_slice(&item.selector_ordinal.to_be_bytes());
    request.extend_from_slice(&item.ordinal.to_be_bytes());
    encode_string(&mut request, cleanup_object_key(&item.target))?;
    match &item.target {
        EpisodeDeleteCleanupTarget::Retained(row) => {
            request.push(1);
            request.extend_from_slice(&row.object_generation.unwrap_or_default().to_be_bytes());
            encode_string(
                &mut request,
                row.object_backend.as_deref().unwrap_or("legacy-compatible"),
            )?;
            encode_string(&mut request, &row.sha256)?;
        }
        EpisodeDeleteCleanupTarget::Legacy(_) => request.push(2),
    }
    Ok(request)
}

fn cleanup_object_key(target: &EpisodeDeleteCleanupTarget) -> &str {
    match target {
        EpisodeDeleteCleanupTarget::Retained(row) => &row.object_key,
        EpisodeDeleteCleanupTarget::Legacy(key) => key,
    }
}

fn cleanup_generation(target: &EpisodeDeleteCleanupTarget) -> Option<i64> {
    match target {
        EpisodeDeleteCleanupTarget::Retained(row) => row.object_generation,
        EpisodeDeleteCleanupTarget::Legacy(_) => None,
    }
}

fn cleanup_backend(target: &EpisodeDeleteCleanupTarget) -> Option<&str> {
    match target {
        EpisodeDeleteCleanupTarget::Retained(row) => row.object_backend.as_deref(),
        EpisodeDeleteCleanupTarget::Legacy(_) => None,
    }
}

fn cleanup_sha256(target: &EpisodeDeleteCleanupTarget) -> Option<&str> {
    match target {
        EpisodeDeleteCleanupTarget::Retained(row) => Some(&row.sha256),
        EpisodeDeleteCleanupTarget::Legacy(_) => None,
    }
}

fn exact_digest(value: &[u8]) -> Result<[u8; 32]> {
    value.try_into().map_err(|_| WalIdempotencyError::Corrupt)
}

fn receipt_commitment(episode_id: i64, purge: &EpisodePurge) -> Result<[u8; 32]> {
    let mut hasher = Sha256::new();
    hash_field(&mut hasher, RECEIPT_DOMAIN)?;
    hash_field(&mut hasher, &episode_id.to_be_bytes())?;
    hash_field(
        &mut hasher,
        &u64::try_from(purge.deleted_utterances)
            .map_err(|_| WalIdempotencyError::Limit)?
            .to_be_bytes(),
    )?;
    hash_field(
        &mut hasher,
        &u64::try_from(purge.deleted_screenshots)
            .map_err(|_| WalIdempotencyError::Limit)?
            .to_be_bytes(),
    )?;
    hash_field(
        &mut hasher,
        &u64::try_from(purge.deleted_segments)
            .map_err(|_| WalIdempotencyError::Limit)?
            .to_be_bytes(),
    )?;
    for (kind, keys) in [
        (b"utterance".as_slice(), &purge.utterance_source_keys),
        (b"screenshot".as_slice(), &purge.screenshot_source_keys),
    ] {
        hash_field(&mut hasher, kind)?;
        hash_field(
            &mut hasher,
            &u64::try_from(keys.len())
                .map_err(|_| WalIdempotencyError::Limit)?
                .to_be_bytes(),
        )?;
        for key in keys {
            hash_field(&mut hasher, key.as_bytes())?;
        }
    }
    Ok(hasher.finalize().into())
}

fn cleanup_commitment(
    media: &[EpisodeDeleteMedia],
    legacy_media_keys: &[String],
    selectors: &[EpisodeDeleteSelector],
) -> Result<[u8; 32]> {
    let mut hasher = Sha256::new();
    hash_field(&mut hasher, CLEANUP_DOMAIN)?;
    hash_field(
        &mut hasher,
        &u64::try_from(media.len())
            .map_err(|_| WalIdempotencyError::Limit)?
            .to_be_bytes(),
    )?;
    for row in media {
        hash_field(&mut hasher, row.object_key.as_bytes())?;
        hash_field(
            &mut hasher,
            &row.object_generation.unwrap_or_default().to_be_bytes(),
        )?;
        hash_field(
            &mut hasher,
            row.object_backend.as_deref().unwrap_or_default().as_bytes(),
        )?;
        hash_field(&mut hasher, row.sha256.as_bytes())?;
    }
    hash_field(
        &mut hasher,
        &u64::try_from(legacy_media_keys.len())
            .map_err(|_| WalIdempotencyError::Limit)?
            .to_be_bytes(),
    )?;
    for key in legacy_media_keys {
        hash_field(&mut hasher, key.as_bytes())?;
    }
    hash_field(
        &mut hasher,
        &u64::try_from(selectors.len())
            .map_err(|_| WalIdempotencyError::Limit)?
            .to_be_bytes(),
    )?;
    for selector in selectors {
        hash_field(&mut hasher, selector.selector_kind.as_bytes())?;
        hash_field(&mut hasher, selector.selector_ref.as_bytes())?;
    }
    Ok(hasher.finalize().into())
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct StoredCleanupTarget {
    cleanup_kind: String,
    ordinal: i64,
    target: EpisodeDeleteCleanupTarget,
}

fn cleanup_variable_usage(
    media: &[EpisodeDeleteMedia],
    legacy_media_keys: &[String],
) -> Result<(u64, u64)> {
    let rows = u64::try_from(
        media
            .len()
            .checked_add(legacy_media_keys.len())
            .ok_or(WalIdempotencyError::Limit)?,
    )
    .map_err(|_| WalIdempotencyError::Limit)?;
    let retained_bytes = media.iter().try_fold(0u64, |total, row| {
        total
            .checked_add(
                u64::try_from(
                    row.object_key.len()
                        + row.object_backend.as_deref().unwrap_or_default().len()
                        + row.sha256.len(),
                )
                .map_err(|_| WalIdempotencyError::Limit)?,
            )
            .ok_or(WalIdempotencyError::Limit)
    })?;
    let bytes = legacy_media_keys
        .iter()
        .try_fold(retained_bytes, |total, key| {
            total
                .checked_add(u64::try_from(key.len()).map_err(|_| WalIdempotencyError::Limit)?)
                .ok_or(WalIdempotencyError::Limit)
        })?;
    Ok((rows, bytes))
}

fn selector_cleanup_items_commitment(
    media: &[EpisodeDeleteMedia],
    legacy_media_keys: &[String],
) -> Result<[u8; 32]> {
    let mut items = Vec::with_capacity(
        media
            .len()
            .checked_add(legacy_media_keys.len())
            .ok_or(WalIdempotencyError::Limit)?,
    );
    for (ordinal, row) in media.iter().enumerate() {
        items.push(StoredCleanupTarget {
            cleanup_kind: "retained".into(),
            ordinal: i64::try_from(ordinal).map_err(|_| WalIdempotencyError::Limit)?,
            target: EpisodeDeleteCleanupTarget::Retained(row.clone()),
        });
    }
    for (ordinal, key) in legacy_media_keys.iter().enumerate() {
        items.push(StoredCleanupTarget {
            cleanup_kind: "legacy".into(),
            ordinal: i64::try_from(ordinal).map_err(|_| WalIdempotencyError::Limit)?,
            target: EpisodeDeleteCleanupTarget::Legacy(key.clone()),
        });
    }
    selector_cleanup_targets_commitment(&items)
}

fn selector_cleanup_targets_commitment(items: &[StoredCleanupTarget]) -> Result<[u8; 32]> {
    let mut hasher = Sha256::new();
    hash_field(&mut hasher, SELECTOR_ITEMS_DOMAIN)?;
    hash_field(
        &mut hasher,
        &u64::try_from(items.len())
            .map_err(|_| WalIdempotencyError::Limit)?
            .to_be_bytes(),
    )?;
    for item in items {
        hash_field(&mut hasher, item.cleanup_kind.as_bytes())?;
        hash_field(&mut hasher, &item.ordinal.to_be_bytes())?;
        hash_field(&mut hasher, cleanup_object_key(&item.target).as_bytes())?;
        hash_field(
            &mut hasher,
            &cleanup_generation(&item.target)
                .unwrap_or_default()
                .to_be_bytes(),
        )?;
        hash_field(
            &mut hasher,
            cleanup_backend(&item.target).unwrap_or_default().as_bytes(),
        )?;
        hash_field(
            &mut hasher,
            cleanup_sha256(&item.target).unwrap_or_default().as_bytes(),
        )?;
    }
    Ok(hasher.finalize().into())
}

fn load_selector_cleanup_targets(
    connection: &Connection,
    preparation_operation_id: WalLogicalOperationId,
    selector_ordinal: i64,
    require_complete: bool,
) -> Result<(Vec<StoredCleanupTarget>, u64)> {
    let mut statement = connection
        .prepare(
            "SELECT cleanup_kind,ordinal,object_key,object_generation,object_backend,sha256,
                    cleanup_state
             FROM archive_v3_wal_episode_delete_cleanup
             WHERE preparation_operation_id=?1 AND selector_ordinal=?2
             ORDER BY CASE cleanup_kind WHEN 'retained' THEN 0 ELSE 1 END,ordinal",
        )
        .map_err(|_| WalIdempotencyError::Unavailable)?;
    let mut rows = statement
        .query(params![
            preparation_operation_id.as_bytes().as_slice(),
            selector_ordinal
        ])
        .map_err(|_| WalIdempotencyError::Unavailable)?;
    let mut items = Vec::new();
    let mut retained_ordinal = 0i64;
    let mut legacy_ordinal = 0i64;
    while let Some(row) = rows.next().map_err(|_| WalIdempotencyError::Unavailable)? {
        if items.len() >= MAX_CLEANUP_ROWS {
            return Err(WalIdempotencyError::Limit);
        }
        let kind = row
            .get::<_, String>(0)
            .map_err(|_| WalIdempotencyError::Corrupt)?;
        let ordinal = row
            .get::<_, i64>(1)
            .map_err(|_| WalIdempotencyError::Corrupt)?;
        let object_key = row
            .get::<_, String>(2)
            .map_err(|_| WalIdempotencyError::Corrupt)?;
        let generation = row
            .get::<_, Option<i64>>(3)
            .map_err(|_| WalIdempotencyError::Corrupt)?;
        let backend = row
            .get::<_, Option<String>>(4)
            .map_err(|_| WalIdempotencyError::Corrupt)?;
        let sha256 = row
            .get::<_, Option<String>>(5)
            .map_err(|_| WalIdempotencyError::Corrupt)?;
        let state = row
            .get::<_, String>(6)
            .map_err(|_| WalIdempotencyError::Corrupt)?;
        if require_complete && state != "complete" {
            return Err(WalIdempotencyError::Precondition);
        }
        let target = match kind.as_str() {
            "retained" if ordinal == retained_ordinal => {
                retained_ordinal = retained_ordinal
                    .checked_add(1)
                    .ok_or(WalIdempotencyError::Limit)?;
                EpisodeDeleteCleanupTarget::Retained(EpisodeDeleteMedia {
                    object_key,
                    object_generation: generation,
                    object_backend: backend,
                    sha256: sha256.ok_or(WalIdempotencyError::Corrupt)?,
                })
            }
            "legacy"
                if ordinal == legacy_ordinal
                    && generation.is_none()
                    && backend.is_none()
                    && sha256.is_none() =>
            {
                legacy_ordinal = legacy_ordinal
                    .checked_add(1)
                    .ok_or(WalIdempotencyError::Limit)?;
                EpisodeDeleteCleanupTarget::Legacy(object_key)
            }
            _ => return Err(WalIdempotencyError::Corrupt),
        };
        items.push(StoredCleanupTarget {
            cleanup_kind: kind,
            ordinal,
            target,
        });
    }
    let media = items
        .iter()
        .filter_map(|item| match &item.target {
            EpisodeDeleteCleanupTarget::Retained(row) => Some(row.clone()),
            EpisodeDeleteCleanupTarget::Legacy(_) => None,
        })
        .collect::<Vec<_>>();
    let legacy = items
        .iter()
        .filter_map(|item| match &item.target {
            EpisodeDeleteCleanupTarget::Legacy(key) => Some(key.clone()),
            EpisodeDeleteCleanupTarget::Retained(_) => None,
        })
        .collect::<Vec<_>>();
    let (_, bytes) = cleanup_variable_usage(&media, &legacy)?;
    Ok((items, bytes))
}

fn preparation_from_evidence(
    account_id: String,
    preparation_operation_id: WalLogicalOperationId,
    completion_operation_id: WalLogicalOperationId,
    evidence: &EpisodeDeleteEvidence,
) -> Result<EpisodeDeletePreparation> {
    let preparation = EpisodeDeletePreparation {
        account_id,
        preparation_operation_id,
        completion_operation_id,
        predecessor_commitment: evidence.predecessor_commitment,
        mutation_stamp: evidence.mutation_stamp.clone(),
        receipt_commitment: receipt_commitment(evidence.episode_id, &evidence.purge)?,
        cleanup_commitment: cleanup_commitment(
            &evidence.media,
            &evidence.legacy_media_keys,
            &evidence.selectors,
        )?,
        receipt: EpisodeDeleteReceipt {
            episode_id: evidence.episode_id,
            purge: evidence.purge.clone(),
        },
        media: evidence.media.clone(),
        legacy_media_keys: evidence.legacy_media_keys.clone(),
        selectors: evidence.selectors.clone(),
    };
    validate_preparation(&preparation)?;
    Ok(preparation)
}

fn validate_preparation(preparation: &EpisodeDeletePreparation) -> Result<()> {
    crate::store::validate_user_id(&preparation.account_id)
        .map_err(|_| WalIdempotencyError::Malformed)?;
    if preparation.receipt.episode_id <= 0
        || preparation.predecessor_commitment == [0; 32]
        || preparation.mutation_stamp.is_empty()
        || preparation.mutation_stamp.len() > 64
        || preparation.receipt_commitment == [0; 32]
        || preparation.cleanup_commitment == [0; 32]
        || preparation.preparation_operation_id
            != preparation_operation_id(&preparation.account_id, preparation.receipt.episode_id)?
        || preparation.completion_operation_id
            != completion_operation_id(&preparation.account_id, preparation.receipt.episode_id)?
        || receipt_commitment(preparation.receipt.episode_id, &preparation.receipt.purge)?
            != preparation.receipt_commitment
        || cleanup_commitment(
            &preparation.media,
            &preparation.legacy_media_keys,
            &preparation.selectors,
        )? != preparation.cleanup_commitment
    {
        return Err(WalIdempotencyError::Malformed);
    }
    validate_source_keys(&preparation.receipt.purge)?;
    let evidence = EpisodeDeleteEvidence {
        episode_id: preparation.receipt.episode_id,
        predecessor_commitment: preparation.predecessor_commitment,
        mutation_stamp: "1970-01-01T00:00:00.000Z".into(),
        event_ids: Vec::new(),
        work_unit_ids: Vec::new(),
        stream_ids: Vec::new(),
        session_ids: Vec::new(),
        browser_state_keys: Vec::new(),
        legacy_browser_snapshot_ids: Vec::new(),
        media: preparation.media.clone(),
        legacy_media_keys: preparation.legacy_media_keys.clone(),
        selectors: preparation.selectors.clone(),
        purge: preparation.receipt.purge.clone(),
    };
    validate_evidence(&preparation.account_id, &evidence)
}

fn stored_variable_usage(evidence: &EpisodeDeleteEvidence) -> Result<(usize, u64)> {
    let rows = evidence
        .purge
        .utterance_source_keys
        .len()
        .checked_add(evidence.purge.screenshot_source_keys.len())
        .and_then(|value| value.checked_add(evidence.media.len()))
        .and_then(|value| value.checked_add(evidence.legacy_media_keys.len()))
        .and_then(|value| value.checked_add(evidence.selectors.len()))
        .ok_or(WalIdempotencyError::Limit)?;
    let bytes = evidence
        .purge
        .utterance_source_keys
        .iter()
        .chain(&evidence.purge.screenshot_source_keys)
        .chain(evidence.legacy_media_keys.iter())
        .try_fold(0u64, |total, value| {
            total
                .checked_add(u64::try_from(value.len()).map_err(|_| WalIdempotencyError::Limit)?)
                .ok_or(WalIdempotencyError::Limit)
        })?;
    let bytes = evidence.media.iter().try_fold(bytes, |total, row| {
        total
            .checked_add(
                u64::try_from(
                    row.object_key.len()
                        + row.object_backend.as_deref().unwrap_or_default().len()
                        + row.sha256.len(),
                )
                .map_err(|_| WalIdempotencyError::Limit)?,
            )
            .ok_or(WalIdempotencyError::Limit)
    })?;
    let bytes = evidence
        .selectors
        .iter()
        .try_fold(bytes, |total, selector| {
            total
                .checked_add(
                    u64::try_from(selector.selector_kind.len() + selector.selector_ref.len())
                        .map_err(|_| WalIdempotencyError::Limit)?,
                )
                .ok_or(WalIdempotencyError::Limit)
        })?;
    Ok((rows, bytes))
}

fn insert_cleanup(
    transaction: &Transaction<'_>,
    operation_id: WalLogicalOperationId,
    media: &[EpisodeDeleteMedia],
    legacy_media_keys: &[String],
) -> Result<()> {
    for (ordinal, row) in media.iter().enumerate() {
        transaction
            .execute(
                "INSERT INTO archive_v3_wal_episode_delete_cleanup
                 (preparation_operation_id,cleanup_kind,ordinal,object_key,
                  object_generation,object_backend,sha256,selector_ordinal)
                 VALUES (?1,'retained',?2,?3,?4,?5,?6,0)",
                params![
                    operation_id.as_bytes().as_slice(),
                    i64::try_from(ordinal).map_err(|_| WalIdempotencyError::Limit)?,
                    row.object_key,
                    row.object_generation,
                    row.object_backend,
                    row.sha256,
                ],
            )
            .map_err(|_| WalIdempotencyError::Unavailable)?;
    }
    for (ordinal, key) in legacy_media_keys.iter().enumerate() {
        transaction
            .execute(
                "INSERT INTO archive_v3_wal_episode_delete_cleanup
                 (preparation_operation_id,cleanup_kind,ordinal,object_key,
                  object_generation,object_backend,sha256,selector_ordinal)
                 VALUES (?1,'legacy',?2,?3,NULL,NULL,NULL,0)",
                params![
                    operation_id.as_bytes().as_slice(),
                    i64::try_from(ordinal).map_err(|_| WalIdempotencyError::Limit)?,
                    key,
                ],
            )
            .map_err(|_| WalIdempotencyError::Unavailable)?;
    }
    Ok(())
}

fn insert_cleanup_for_selector(
    transaction: &Transaction<'_>,
    expansion: &EpisodeDeleteSelectorExpansion,
) -> Result<()> {
    for (ordinal, row) in expansion.media.iter().enumerate() {
        transaction
            .execute(
                "INSERT INTO archive_v3_wal_episode_delete_cleanup
                 (preparation_operation_id,selector_ordinal,cleanup_kind,ordinal,object_key,
                  object_generation,object_backend,sha256,cleanup_state)
                 VALUES (?1,?2,'retained',?3,?4,?5,?6,?7,'pending')",
                params![
                    expansion
                        .preparation
                        .preparation_operation_id
                        .as_bytes()
                        .as_slice(),
                    expansion.selector_ordinal,
                    i64::try_from(ordinal).map_err(|_| WalIdempotencyError::Limit)?,
                    row.object_key,
                    row.object_generation,
                    row.object_backend,
                    row.sha256,
                ],
            )
            .map_err(|_| WalIdempotencyError::Unavailable)?;
    }
    for (ordinal, key) in expansion.legacy_media_keys.iter().enumerate() {
        transaction
            .execute(
                "INSERT INTO archive_v3_wal_episode_delete_cleanup
                 (preparation_operation_id,selector_ordinal,cleanup_kind,ordinal,object_key,
                  object_generation,object_backend,sha256,cleanup_state)
                 VALUES (?1,?2,'legacy',?3,?4,NULL,NULL,NULL,'pending')",
                params![
                    expansion
                        .preparation
                        .preparation_operation_id
                        .as_bytes()
                        .as_slice(),
                    expansion.selector_ordinal,
                    i64::try_from(ordinal).map_err(|_| WalIdempotencyError::Limit)?,
                    key,
                ],
            )
            .map_err(|_| WalIdempotencyError::Unavailable)?;
    }
    Ok(())
}

fn insert_selectors(
    transaction: &Transaction<'_>,
    operation_id: WalLogicalOperationId,
    selectors: &[EpisodeDeleteSelector],
) -> Result<()> {
    for (ordinal, selector) in selectors.iter().enumerate() {
        transaction
            .execute(
                "INSERT INTO archive_v3_wal_episode_delete_selectors
                 (preparation_operation_id,ordinal,selector_kind,selector_ref,selector_state)
                 VALUES (?1,?2,?3,?4,'pending')",
                params![
                    operation_id.as_bytes().as_slice(),
                    i64::try_from(ordinal).map_err(|_| WalIdempotencyError::Limit)?,
                    selector.selector_kind,
                    selector.selector_ref,
                ],
            )
            .map_err(|_| WalIdempotencyError::Unavailable)?;
    }
    Ok(())
}

fn load_selectors(
    connection: &Connection,
    operation_id: WalLogicalOperationId,
) -> Result<Vec<EpisodeDeleteSelector>> {
    let mut statement = connection
        .prepare(
            "SELECT ordinal,selector_kind,selector_ref
             FROM archive_v3_wal_episode_delete_selectors
             WHERE preparation_operation_id=?1 ORDER BY ordinal",
        )
        .map_err(|_| WalIdempotencyError::Unavailable)?;
    let mut rows = statement
        .query([operation_id.as_bytes().as_slice()])
        .map_err(|_| WalIdempotencyError::Unavailable)?;
    let mut selectors = Vec::new();
    while let Some(row) = rows.next().map_err(|_| WalIdempotencyError::Unavailable)? {
        let ordinal = row
            .get::<_, i64>(0)
            .map_err(|_| WalIdempotencyError::Corrupt)?;
        if ordinal != i64::try_from(selectors.len()).map_err(|_| WalIdempotencyError::Limit)? {
            return Err(WalIdempotencyError::Corrupt);
        }
        selectors.push(EpisodeDeleteSelector {
            selector_kind: row.get(1).map_err(|_| WalIdempotencyError::Corrupt)?,
            selector_ref: row.get(2).map_err(|_| WalIdempotencyError::Corrupt)?,
        });
        if selectors.len() > MAX_SOURCE_ROWS as usize {
            return Err(WalIdempotencyError::Corrupt);
        }
    }
    validate_selectors(&selectors)?;
    Ok(selectors)
}

fn load_cleanup_rows(
    connection: &Connection,
    operation_id: WalLogicalOperationId,
) -> Result<(Vec<EpisodeDeleteMedia>, Vec<String>)> {
    let mut statement = connection
        .prepare(
            "SELECT cleanup_kind,ordinal,object_key,object_generation,object_backend,sha256
             FROM archive_v3_wal_episode_delete_cleanup
             WHERE preparation_operation_id=?1 ORDER BY selector_ordinal,cleanup_kind,ordinal",
        )
        .map_err(|_| WalIdempotencyError::Unavailable)?;
    let mut rows = statement
        .query([operation_id.as_bytes().as_slice()])
        .map_err(|_| WalIdempotencyError::Unavailable)?;
    let mut media = Vec::new();
    let mut legacy = Vec::new();
    let mut next_retained = 0i64;
    let mut next_legacy = 0i64;
    while let Some(row) = rows.next().map_err(|_| WalIdempotencyError::Unavailable)? {
        if media.len().saturating_add(legacy.len()) >= MAX_CLEANUP_ROWS {
            return Err(WalIdempotencyError::Corrupt);
        }
        let kind = row
            .get::<_, String>(0)
            .map_err(|_| WalIdempotencyError::Corrupt)?;
        let ordinal = row
            .get::<_, i64>(1)
            .map_err(|_| WalIdempotencyError::Corrupt)?;
        let key = row
            .get::<_, String>(2)
            .map_err(|_| WalIdempotencyError::Corrupt)?;
        match kind.as_str() {
            "retained" if ordinal == next_retained => {
                next_retained += 1;
                media.push(EpisodeDeleteMedia {
                    object_key: key,
                    object_generation: row.get(3).map_err(|_| WalIdempotencyError::Corrupt)?,
                    object_backend: row.get(4).map_err(|_| WalIdempotencyError::Corrupt)?,
                    sha256: row.get(5).map_err(|_| WalIdempotencyError::Corrupt)?,
                });
            }
            "legacy" if ordinal == next_legacy => {
                next_legacy += 1;
                if row
                    .get::<_, Option<i64>>(3)
                    .map_err(|_| WalIdempotencyError::Corrupt)?
                    .is_some()
                    || row
                        .get::<_, Option<String>>(4)
                        .map_err(|_| WalIdempotencyError::Corrupt)?
                        .is_some()
                    || row
                        .get::<_, Option<String>>(5)
                        .map_err(|_| WalIdempotencyError::Corrupt)?
                        .is_some()
                {
                    return Err(WalIdempotencyError::Corrupt);
                }
                legacy.push(key);
            }
            _ => return Err(WalIdempotencyError::Corrupt),
        }
    }
    Ok((media, legacy))
}

fn insert_sources(
    transaction: &Transaction<'_>,
    operation_id: WalLogicalOperationId,
    purge: &EpisodePurge,
) -> Result<()> {
    for (kind, keys) in [
        ("utterance", &purge.utterance_source_keys),
        ("screenshot", &purge.screenshot_source_keys),
    ] {
        for (ordinal, key) in keys.iter().enumerate() {
            transaction
                .execute(
                    "INSERT INTO archive_v3_wal_episode_delete_sources
                     (preparation_operation_id,source_kind,ordinal,source_key)
                     VALUES (?1,?2,?3,?4)",
                    params![
                        operation_id.as_bytes().as_slice(),
                        kind,
                        i64::try_from(ordinal).map_err(|_| WalIdempotencyError::Limit)?,
                        key,
                    ],
                )
                .map_err(|_| WalIdempotencyError::Unavailable)?;
        }
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum LedgerSchemaState {
    Absent,
    Present,
}

#[derive(Clone, Copy)]
struct LedgerState {
    row_count: u32,
    result_bytes: u64,
    source_count: u64,
    source_bytes: u64,
    resume_cursor: i64,
    resume_sequence: i64,
}

fn require_prepare_kind(
    prepared: &PreparedLogicalMutation<EpisodeDeletePreparePlan>,
) -> Result<()> {
    (prepared.kind_for_owner() == WalOperationKind::EpisodeDeletePrepare)
        .then_some(())
        .ok_or(WalIdempotencyError::ResultUnsupported)
}

fn require_complete_kind(prepared: &PreparedLogicalMutation<EpisodeDeletePlan>) -> Result<()> {
    (prepared.kind_for_owner() == WalOperationKind::EpisodeDelete)
        .then_some(())
        .ok_or(WalIdempotencyError::ResultUnsupported)
}

fn require_cleanup_kind(
    prepared: &PreparedLogicalMutation<EpisodeDeleteCleanupPlan>,
) -> Result<()> {
    (prepared.kind_for_owner() == WalOperationKind::EpisodeDeleteCleanup)
        .then_some(())
        .ok_or(WalIdempotencyError::ResultUnsupported)
}

fn schema_state(connection: &Connection) -> Result<LedgerSchemaState> {
    let present = connection
        .query_row(
            "SELECT COUNT(*) FROM sqlite_schema
             WHERE type='table' AND name IN (?1,?2,?3,?4,?5,?6,?7,?8)",
            params![
                SCHEMA_TABLE,
                LEDGER_TABLE,
                SOURCE_TABLE,
                CLEANUP_TABLE,
                STATE_TABLE,
                PROGRESS_TABLE,
                SELECTOR_TABLE,
                VOICE_PROGRESS_TABLE,
            ],
            |row| row.get::<_, i64>(0),
        )
        .map_err(|_| WalIdempotencyError::Unavailable)?;
    match present {
        0 => Ok(LedgerSchemaState::Absent),
        8 => Ok(LedgerSchemaState::Present),
        _ => Err(WalIdempotencyError::Corrupt),
    }
}

fn ensure_schema(transaction: &Transaction<'_>) -> Result<()> {
    match schema_state(transaction)? {
        LedgerSchemaState::Present => validate_schema_marker(transaction),
        LedgerSchemaState::Absent => {
            transaction
                .execute_batch(
                    "CREATE TABLE archive_v3_wal_episode_delete_schema (
                        singleton INTEGER PRIMARY KEY CHECK(singleton=1),
                        format_version INTEGER NOT NULL CHECK(format_version=1),
                        codec_version INTEGER NOT NULL CHECK(codec_version=1)
                     ) STRICT;
                     CREATE TABLE archive_v3_wal_episode_delete_operations (
                        preparation_operation_id BLOB PRIMARY KEY NOT NULL,
                        completion_operation_id BLOB NOT NULL UNIQUE,
                        episode_id INTEGER NOT NULL UNIQUE CHECK(episode_id>0),
                        prepare_format_version INTEGER NOT NULL CHECK(prepare_format_version=1),
                        prepare_codec_version INTEGER NOT NULL CHECK(prepare_codec_version=1),
                        prepare_request_fingerprint BLOB NOT NULL,
                        prepare_result_bytes BLOB NOT NULL,
                        prepare_result_commitment BLOB NOT NULL,
                        completion_format_version INTEGER CHECK(completion_format_version=1),
                        completion_codec_version INTEGER CHECK(completion_codec_version=1),
                        completion_request_fingerprint BLOB,
                        completion_result_bytes BLOB,
                        completion_result_commitment BLOB,
                        deleted_utterances INTEGER NOT NULL CHECK(deleted_utterances>=0),
                        deleted_screenshots INTEGER NOT NULL CHECK(deleted_screenshots>=0),
                        deleted_segments INTEGER NOT NULL CHECK(deleted_segments>=0),
                        predecessor_commitment BLOB NOT NULL,
                        receipt_commitment BLOB NOT NULL,
                        cleanup_commitment BLOB NOT NULL,
                        mutation_stamp TEXT NOT NULL CHECK(length(mutation_stamp) BETWEEN 1 AND 64),
                        CHECK(length(preparation_operation_id)=16 AND preparation_operation_id<>zeroblob(16)),
                        CHECK(length(completion_operation_id)=16 AND completion_operation_id<>zeroblob(16)),
                        CHECK(length(prepare_request_fingerprint)=32 AND prepare_request_fingerprint<>zeroblob(32)),
                        CHECK(length(prepare_result_bytes)=9),
                        CHECK(length(prepare_result_commitment)=32 AND prepare_result_commitment<>zeroblob(32)),
                        CHECK(length(predecessor_commitment)=32 AND predecessor_commitment<>zeroblob(32)),
                        CHECK(length(receipt_commitment)=32 AND receipt_commitment<>zeroblob(32)),
                        CHECK(length(cleanup_commitment)=32 AND cleanup_commitment<>zeroblob(32)),
                        CHECK((completion_format_version IS NULL AND completion_codec_version IS NULL
                               AND completion_request_fingerprint IS NULL
                               AND completion_result_bytes IS NULL
                               AND completion_result_commitment IS NULL)
                           OR (completion_format_version IS NOT NULL AND completion_codec_version IS NOT NULL
                               AND length(completion_request_fingerprint)=32
                               AND completion_request_fingerprint<>zeroblob(32)
                               AND length(completion_result_bytes)=9
                               AND length(completion_result_commitment)=32
                               AND completion_result_commitment<>zeroblob(32)))
                     ) STRICT, WITHOUT ROWID;
                     CREATE TABLE archive_v3_wal_episode_delete_sources (
                        preparation_operation_id BLOB NOT NULL,
                        source_kind TEXT NOT NULL CHECK(source_kind IN ('utterance','screenshot')),
                        ordinal INTEGER NOT NULL CHECK(ordinal>=0),
                        source_key TEXT NOT NULL CHECK(length(source_key) BETWEEN 1 AND 1024),
                        PRIMARY KEY(preparation_operation_id,source_kind,ordinal),
                        FOREIGN KEY(preparation_operation_id) REFERENCES archive_v3_wal_episode_delete_operations(preparation_operation_id)
                     ) STRICT, WITHOUT ROWID;
                     CREATE TABLE archive_v3_wal_episode_delete_cleanup (
                        preparation_operation_id BLOB NOT NULL,
                        selector_ordinal INTEGER NOT NULL CHECK(selector_ordinal>=0),
                        cleanup_kind TEXT NOT NULL CHECK(cleanup_kind IN ('retained','legacy')),
                        ordinal INTEGER NOT NULL CHECK(ordinal>=0),
                        object_key TEXT NOT NULL CHECK(length(object_key) BETWEEN 1 AND 1024),
                        object_generation INTEGER,
                        object_backend TEXT,
                        sha256 TEXT,
                        cleanup_state TEXT NOT NULL DEFAULT 'pending'
                            CHECK(cleanup_state IN ('pending','complete')),
                        PRIMARY KEY(preparation_operation_id,selector_ordinal,cleanup_kind,ordinal),
                        FOREIGN KEY(preparation_operation_id) REFERENCES archive_v3_wal_episode_delete_operations(preparation_operation_id),
                        CHECK((cleanup_kind='retained' AND length(sha256)=64
                               AND (object_generation IS NULL OR object_generation>0)
                               AND (object_backend IS NULL OR object_backend='current'))
                           OR (cleanup_kind='legacy' AND object_generation IS NULL
                               AND object_backend IS NULL AND sha256 IS NULL))
                     ) STRICT, WITHOUT ROWID;
                     CREATE TABLE archive_v3_wal_episode_delete_selectors (
                        preparation_operation_id BLOB NOT NULL,
                        ordinal INTEGER NOT NULL CHECK(ordinal>=0),
                        selector_kind TEXT NOT NULL
                          CHECK(selector_kind IN ('event','voice','legacy')),
                        selector_ref TEXT NOT NULL CHECK(length(selector_ref) BETWEEN 1 AND 1024),
                        selector_state TEXT NOT NULL
                          CHECK(selector_state IN ('pending','cleaning','complete')),
                        expansion_predecessor_commitment BLOB,
                        cleanup_items_commitment BLOB,
                        cleanup_count INTEGER CHECK(cleanup_count>=0),
                        settled_count INTEGER NOT NULL DEFAULT 0 CHECK(settled_count>=0),
                        cleanup_rows INTEGER NOT NULL DEFAULT 0 CHECK(cleanup_rows>=0),
                        cleanup_bytes INTEGER NOT NULL DEFAULT 0 CHECK(cleanup_bytes>=0),
                        voice_page_sequence INTEGER NOT NULL DEFAULT 0
                          CHECK(voice_page_sequence>=0),
                        voice_scan_cursor INTEGER NOT NULL DEFAULT 0
                          CHECK(voice_scan_cursor>=0),
                        voice_progress_rows INTEGER NOT NULL DEFAULT 0
                          CHECK(voice_progress_rows BETWEEN 0 AND 1048576),
                        reserved_cleanup_rows INTEGER NOT NULL DEFAULT 0
                          CHECK(reserved_cleanup_rows>=0),
                        reserved_cleanup_bytes INTEGER NOT NULL DEFAULT 0
                          CHECK(reserved_cleanup_bytes>=0),
                        expansion_request_fingerprint BLOB,
                        finish_request_fingerprint BLOB,
                        PRIMARY KEY(preparation_operation_id,ordinal),
                        UNIQUE(preparation_operation_id,selector_kind,selector_ref),
                        FOREIGN KEY(preparation_operation_id)
                          REFERENCES archive_v3_wal_episode_delete_operations(preparation_operation_id),
                        CHECK((selector_state='pending'
                               AND expansion_predecessor_commitment IS NULL
                               AND cleanup_items_commitment IS NULL AND cleanup_count IS NULL
                               AND settled_count=0 AND cleanup_rows=0 AND cleanup_bytes=0
                               AND expansion_request_fingerprint IS NULL
                               AND finish_request_fingerprint IS NULL)
                           OR (selector_state='cleaning'
                               AND length(expansion_predecessor_commitment)=32
                               AND expansion_predecessor_commitment<>zeroblob(32)
                               AND length(cleanup_items_commitment)=32
                               AND cleanup_items_commitment<>zeroblob(32)
                               AND cleanup_count>0 AND settled_count<=cleanup_count
                               AND cleanup_rows=cleanup_count AND cleanup_bytes>=0
                               AND length(expansion_request_fingerprint)=32
                               AND expansion_request_fingerprint<>zeroblob(32)
                               AND voice_progress_rows=0
                               AND finish_request_fingerprint IS NULL)
                           OR (selector_state='complete'
                               AND length(expansion_predecessor_commitment)=32
                               AND expansion_predecessor_commitment<>zeroblob(32)
                               AND length(cleanup_items_commitment)=32
                               AND cleanup_items_commitment<>zeroblob(32)
                               AND cleanup_count>=0 AND settled_count=cleanup_count
                               AND cleanup_rows=cleanup_count AND cleanup_bytes>=0
                               AND length(expansion_request_fingerprint)=32
                               AND expansion_request_fingerprint<>zeroblob(32)
                               AND voice_progress_rows=0
                               AND (cleanup_count=0 OR (
                                   length(finish_request_fingerprint)=32
                                   AND finish_request_fingerprint<>zeroblob(32)))) ),
                        CHECK(selector_kind='voice' OR (
                          voice_page_sequence=0 AND voice_scan_cursor=0
                          AND voice_progress_rows=0
                          AND reserved_cleanup_rows=0 AND reserved_cleanup_bytes=0
                        )),
                        CHECK(selector_kind<>'voice' OR (
                          (reserved_cleanup_rows=0 AND reserved_cleanup_bytes=0
                           AND voice_page_sequence=0 AND voice_scan_cursor=0
                           AND voice_progress_rows=0)
                          OR (reserved_cleanup_rows=16384
                              AND reserved_cleanup_bytes=17940480)
                        ))
                     ) STRICT, WITHOUT ROWID;
                     CREATE TABLE archive_v3_wal_episode_delete_voice_progress (
                        preparation_operation_id BLOB NOT NULL,
                        selector_ordinal INTEGER NOT NULL CHECK(selector_ordinal>=0),
                        episode_id INTEGER NOT NULL CHECK(episode_id>0),
                        page_sequence INTEGER NOT NULL CHECK(page_sequence>0),
                        predecessor_revision INTEGER NOT NULL CHECK(predecessor_revision>=0),
                        resulting_revision INTEGER NOT NULL CHECK(resulting_revision>0),
                        page_predecessor_commitment BLOB NOT NULL,
                        progress_commitment BLOB NOT NULL,
                        PRIMARY KEY(preparation_operation_id,selector_ordinal,episode_id),
                        FOREIGN KEY(preparation_operation_id,selector_ordinal)
                          REFERENCES archive_v3_wal_episode_delete_selectors(
                            preparation_operation_id,ordinal
                          ) ON DELETE CASCADE,
                        CHECK(resulting_revision=predecessor_revision+1),
                        CHECK(length(page_predecessor_commitment)=32
                              AND page_predecessor_commitment<>zeroblob(32)),
                        CHECK(length(progress_commitment)=32
                              AND progress_commitment<>zeroblob(32))
                     ) STRICT, WITHOUT ROWID;
                     CREATE TABLE archive_v3_wal_episode_delete_progress (
                        operation_id BLOB PRIMARY KEY NOT NULL,
                        preparation_operation_id BLOB NOT NULL UNIQUE,
                        request_fingerprint BLOB NOT NULL,
                        result_bytes BLOB NOT NULL,
                        result_commitment BLOB NOT NULL,
                        CHECK(length(operation_id)=16 AND operation_id<>zeroblob(16)),
                        CHECK(length(request_fingerprint)=32 AND request_fingerprint<>zeroblob(32)),
                        CHECK(length(result_bytes)=9),
                        CHECK(length(result_commitment)=32 AND result_commitment<>zeroblob(32)),
                        FOREIGN KEY(preparation_operation_id)
                          REFERENCES archive_v3_wal_episode_delete_operations(preparation_operation_id)
                     ) STRICT, WITHOUT ROWID;
                     CREATE TABLE archive_v3_wal_episode_delete_state (
                        singleton INTEGER PRIMARY KEY CHECK(singleton=1),
                        row_count INTEGER NOT NULL CHECK(row_count BETWEEN 0 AND 1048576),
                        result_bytes INTEGER NOT NULL CHECK(result_bytes BETWEEN 0 AND 33554432),
                        source_count INTEGER NOT NULL CHECK(source_count BETWEEN 0 AND 1048576),
                        source_bytes INTEGER NOT NULL CHECK(source_bytes BETWEEN 0 AND 536870912),
                        resume_cursor INTEGER NOT NULL CHECK(resume_cursor>=0),
                        resume_sequence INTEGER NOT NULL CHECK(resume_sequence>=0)
                     ) STRICT;
                     INSERT INTO archive_v3_wal_episode_delete_schema
                        (singleton,format_version,codec_version) VALUES (1,1,1);
                     INSERT INTO archive_v3_wal_episode_delete_state
                        (singleton,row_count,result_bytes,source_count,source_bytes,
                         resume_cursor,resume_sequence)
                        VALUES (1,0,0,0,0,0,0);",
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
             FROM archive_v3_wal_episode_delete_schema WHERE singleton=1",
            [],
            |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)),
        )
        .optional()
        .map_err(|_| WalIdempotencyError::Corrupt)?;
    if marker
        != Some((
            i64::from(WalOperationKind::format_version()),
            i64::from(WalOperationKind::EpisodeDelete.codec_version()),
        ))
    {
        return Err(WalIdempotencyError::Corrupt);
    }
    let _ = load_ledger_state(connection)?;
    Ok(())
}

fn load_ledger_state(connection: &Connection) -> Result<LedgerState> {
    let row = connection
        .query_row(
            "SELECT row_count,result_bytes,source_count,source_bytes,resume_cursor,resume_sequence
             FROM archive_v3_wal_episode_delete_state WHERE singleton=1",
            [],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, i64>(4)?,
                    row.get::<_, i64>(5)?,
                ))
            },
        )
        .optional()
        .map_err(|_| WalIdempotencyError::Corrupt)?
        .ok_or(WalIdempotencyError::Corrupt)?;
    let state = LedgerState {
        row_count: u32::try_from(row.0).map_err(|_| WalIdempotencyError::Corrupt)?,
        result_bytes: u64::try_from(row.1).map_err(|_| WalIdempotencyError::Corrupt)?,
        source_count: u64::try_from(row.2).map_err(|_| WalIdempotencyError::Corrupt)?,
        source_bytes: u64::try_from(row.3).map_err(|_| WalIdempotencyError::Corrupt)?,
        resume_cursor: row.4,
        resume_sequence: row.5,
    };
    if state.row_count > MAX_ROWS
        || state.result_bytes > MAX_RESULT_BYTES
        || state.source_count > MAX_SOURCE_ROWS
        || state.source_bytes > MAX_SOURCE_BYTES
        || state.resume_cursor < 0
        || state.resume_sequence < 0
    {
        return Err(WalIdempotencyError::Corrupt);
    }
    Ok(state)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::archive_v3_wal_idempotency::{
        execute_prepared_for_owner, LogicalMutationDisposition, PreparedLogicalMutation,
    };

    const ACCOUNT: &str = "episode-delete-user";
    const STAMP: &str = "2026-08-22T12:00:00.000Z";

    fn connection() -> (tempfile::TempDir, Connection) {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("archive.sqlite");
        crate::store::initialize_wal_owner_store_for_test(&path).unwrap();
        let connection = Connection::open(path).unwrap();
        connection.execute_batch("PRAGMA foreign_keys=ON;").unwrap();
        (directory, connection)
    }

    #[test]
    fn voice_cleanup_and_progress_charges_match_their_exact_bounds() {
        let maximum_retained_row_bytes =
            MAX_SOURCE_KEY_BYTES as u64 + 64 + u64::try_from("current".len()).unwrap();
        assert_eq!(VOICE_RESERVED_CLEANUP_ROWS, MAX_EVENTS_PER_SELECTOR as u64);
        assert_eq!(VOICE_RESERVED_CLEANUP_BYTES, 17_940_480);
        assert_eq!(
            VOICE_RESERVED_CLEANUP_BYTES,
            VOICE_RESERVED_CLEANUP_ROWS * maximum_retained_row_bytes
        );
        assert!(
            u64::try_from(MAX_EVENTS_PER_SELECTOR)
                .unwrap()
                .checked_add(1)
                .unwrap()
                > VOICE_RESERVED_CLEANUP_ROWS
        );
        assert_eq!(VOICE_PROGRESS_ROW_BYTES, 120);
    }

    fn insert_episode(connection: &Connection, episode_id: i64) {
        connection
            .execute(
                "INSERT INTO episodes (id,started_at,ended_at,title)
                 VALUES (?1,?2,?2,'episode')",
                params![episode_id, STAMP],
            )
            .unwrap();
    }

    fn insert_capture(connection: &Connection, event_id: &str, sequence: i64, state_key: &str) {
        connection
            .execute(
                "INSERT OR IGNORE INTO capture_sessions
                 (id,device_id,install_id,started_at,last_event_at,schema_version)
                 VALUES ('session','device','install',?1,?1,2)",
                [STAMP],
            )
            .unwrap();
        connection
            .execute(
                "INSERT OR IGNORE INTO capture_streams
                 (id,capture_session_id,device_id,stream_kind)
                 VALUES ('stream','session','device','screen')",
                [],
            )
            .unwrap();
        connection
            .execute(
                "INSERT INTO capture_events
                 (event_id,device_id,install_id,capture_session_id,stream_id,stream_kind,
                  sequence,source_wall_at,source_monotonic_ns,started_at,ended_at,
                  timezone_id,utc_offset_minutes,clock_uncertainty_ms,asset_id,manifest_digest)
                 VALUES (?1,'device','install','session','stream','screen',?2,?3,'1',?3,?3,
                         'UTC',0,0,?4,?5)",
                params![
                    event_id,
                    sequence,
                    STAMP,
                    format!("asset-{sequence}"),
                    "a".repeat(64)
                ],
            )
            .unwrap();
        connection
            .execute(
                "INSERT INTO media_objects
                 (asset_id,event_id,object_key,object_generation,object_backend,mime_type,codec,
                  byte_length,sha256,width,height,processing_state)
                 VALUES (?1,?2,?3,?4,'current','image/jpeg','jpeg',10,?5,10,10,'ready')",
                params![
                    format!("asset-{sequence}"),
                    event_id,
                    format!("raw/{ACCOUNT}/asset-{sequence}.enc"),
                    sequence + 1,
                    format!("{:064x}", sequence + 1),
                ],
            )
            .unwrap();
        connection
            .execute(
                "INSERT OR IGNORE INTO browser_states_v2
                 (state_key,browser_bundle_id,browser_name,permission_status,content_hash,tabs_json)
                 VALUES (?1,'com.apple.Safari','Safari','granted',?2,'[]')",
                params![state_key, format!("{:064x}", sequence + 20)],
            )
            .unwrap();
        connection
            .execute(
                "INSERT INTO browser_observations_v2
                 (observation_id,event_id,observed_at,state_key,context_status)
                 VALUES (?1,?2,?3,?4,'stable')",
                params![
                    format!("observation-{sequence}"),
                    event_id,
                    STAMP,
                    state_key
                ],
            )
            .unwrap();
    }

    fn insert_screen_member(
        connection: &Connection,
        episode_id: i64,
        screenshot_id: i64,
        event_id: &str,
    ) {
        connection
            .execute(
                "INSERT INTO screenshots
                 (id,captured_at,ocr_text,source_key,browser_snapshot_source_key)
                 VALUES (?1,?2,'screen',?3,?4)",
                params![
                    screenshot_id,
                    STAMP,
                    format!("cloud-v2:{event_id}"),
                    format!("capture-v2-browser:{event_id}"),
                ],
            )
            .unwrap();
        connection
            .execute(
                "INSERT INTO episode_members (episode_id,record_type,record_id)
                 VALUES (?1,'screenshot',?2)",
                params![episode_id, screenshot_id],
            )
            .unwrap();
    }

    fn insert_audio_utterance(
        connection: &Connection,
        episode_id: i64,
        utterance_id: i64,
        event_id: &str,
        sequence: i64,
    ) {
        if connection
            .query_row(
                "SELECT COUNT(*) FROM capture_events WHERE event_id=?1",
                [event_id],
                |row| row.get::<_, i64>(0),
            )
            .unwrap()
            == 0
        {
            insert_capture(
                connection,
                event_id,
                sequence,
                &format!("audio-state-{sequence}"),
            );
        }
        let observation_id = 10_000 + utterance_id;
        connection
            .execute(
                "INSERT INTO speaker_observations
                 (id,event_id,turn_id,speaker_local_id,started_at,ended_at,transcript_text)
                 VALUES (?1,?2,?3,'speaker',?4,?4,'audio words')",
                params![
                    observation_id,
                    event_id,
                    format!("turn-{utterance_id}"),
                    STAMP
                ],
            )
            .unwrap();
        connection
            .execute(
                "INSERT INTO speaker_observation_sources
                 (speaker_observation_id,event_id,window_start_ms,window_end_ms,
                  event_start_ms,event_end_ms) VALUES (?1,?2,0,1000,0,1000)",
                params![observation_id, event_id],
            )
            .unwrap();
        connection
            .execute(
                "INSERT INTO audio_segments
                 (id,started_at,ended_at,duration_seconds,source_type,
                  audio_format,transcription_status)
                 VALUES (?1,?2,?2,1.0,'mic','m4a','ready')",
                params![20_000 + utterance_id, STAMP],
            )
            .unwrap();
        connection
            .execute(
                "INSERT INTO utterances
                 (id,audio_segment_id,start_offset_seconds,end_offset_seconds,text,
                  speaker_label,source_key,speaker_observation_id)
                 VALUES (?1,?2,0.0,1.0,'audio words','speaker',?3,?4)",
                params![
                    utterance_id,
                    20_000 + utterance_id,
                    format!("audio:{event_id}:{utterance_id}"),
                    observation_id
                ],
            )
            .unwrap();
        connection
            .execute(
                "INSERT INTO episode_members (episode_id,record_type,record_id)
                 VALUES (?1,'utterance',?2)",
                params![episode_id, utterance_id],
            )
            .unwrap();
    }

    fn insert_legacy_browser_snapshot(
        connection: &Connection,
        source_key: &str,
        screenshot_ids: &[i64],
    ) -> i64 {
        connection
            .execute(
                "INSERT INTO browser_snapshots
                 (source_key,captured_at,browser_bundle_id,browser_name,permission_status,
                  reported_tab_count,truncated,content_hash,created_at)
                 VALUES (?1,?2,'com.apple.Safari','Safari','granted',1,0,?3,?2)",
                params![source_key, STAMP, "b".repeat(64)],
            )
            .unwrap();
        let snapshot_id = connection.last_insert_rowid();
        connection
            .execute(
                "INSERT INTO browser_tabs
                 (browser_snapshot_id,window_index,tab_index,title,url,url_scheme,is_active)
                 VALUES (?1,0,0,'Sensitive title','https://example.com/private','https',1)",
                [snapshot_id],
            )
            .unwrap();
        for screenshot_id in screenshot_ids {
            connection
                .execute(
                    "UPDATE screenshots SET browser_snapshot_source_key=?1 WHERE id=?2",
                    params![source_key, screenshot_id],
                )
                .unwrap();
        }
        snapshot_id
    }

    fn insert_screenshot_range(connection: &Connection, episode_id: i64, from: i64, to: i64) {
        connection
            .execute(
                "WITH RECURSIVE sequence(value) AS (
                   SELECT ?1 UNION ALL SELECT value+1 FROM sequence WHERE value<?2
                 )
                 INSERT INTO screenshots (id,captured_at,source_key)
                 SELECT value,?3,NULL FROM sequence",
                params![from, to, STAMP],
            )
            .unwrap();
        connection
            .execute(
                "WITH RECURSIVE sequence(value) AS (
                   SELECT ?2 UNION ALL SELECT value+1 FROM sequence WHERE value<?3
                 )
                 INSERT INTO episode_members (episode_id,record_type,record_id)
                 SELECT ?1,'screenshot',value FROM sequence",
                params![episode_id, from, to],
            )
            .unwrap();
    }

    fn unit_embedding(index: usize) -> Vec<u8> {
        let mut values = vec![0.0f32; 256];
        values[index] = 1.0;
        values.into_iter().flat_map(f32::to_le_bytes).collect()
    }

    fn seed(connection: &Connection) {
        insert_episode(connection, 1);
        insert_episode(connection, 2);
        insert_capture(connection, "event-unique", 1, "state-unique");
        insert_capture(connection, "event-shared", 2, "state-shared");
        insert_capture(connection, "event-survivor", 3, "state-shared");
        insert_screen_member(connection, 1, 11, "event-unique");
        insert_screen_member(connection, 1, 12, "event-shared");
        insert_screen_member(connection, 2, 21, "event-survivor");
        connection
            .execute(
                "INSERT INTO media_work_units
                 (id,work_class,processor_version,state,started_at,ended_at,reserved_output_tokens)
                 VALUES ('shared-unit','screen',1,'succeeded',?1,?1,1024)",
                [STAMP],
            )
            .unwrap();
        for (ordinal, event_id) in ["event-shared", "event-survivor"].into_iter().enumerate() {
            connection
                .execute(
                    "INSERT INTO media_processing_jobs
                     (event_id,job_kind,input_revision,processor_version,state)
                     VALUES (?1,'storyboard',?2,1,'succeeded')",
                    params![event_id, format!("revision-{ordinal}")],
                )
                .unwrap();
            let job_id = connection.last_insert_rowid();
            connection
                .execute(
                    "INSERT INTO media_work_members
                     (work_unit_id,event_id,job_id,ordinal,window_start_ms,window_end_ms)
                     VALUES ('shared-unit',?1,?2,?3,0,1)",
                    params![event_id, job_id, ordinal as i64],
                )
                .unwrap();
        }
    }

    fn apply_preparation(
        connection: &mut Connection,
        evidence: EpisodeDeleteEvidence,
    ) -> (EpisodeDeletePreparation, LogicalMutationDisposition) {
        let applied = execute_prepared_for_owner(
            connection,
            PreparedLogicalMutation::prepare(
                EpisodeDeletePreparePlan::new(ACCOUNT.into(), evidence).unwrap(),
            )
            .unwrap(),
        )
        .unwrap();
        let disposition = applied.disposition();
        let preparation = applied.into_validated_result().release().unwrap();
        (preparation, disposition)
    }

    fn apply_completion(
        connection: &mut Connection,
        preparation: EpisodeDeletePreparation,
    ) -> (EpisodeDeleteReceipt, LogicalMutationDisposition) {
        let completion_plan = loop {
            let work = load_episode_delete_work(
                connection,
                &preparation.account_id,
                preparation.receipt.episode_id,
            )
            .unwrap();
            let Some(work) = work else {
                break EpisodeDeletePlan::new(
                    preparation.clone(),
                    final_selector_cleanup_commitment(connection, &preparation).unwrap(),
                )
                .unwrap();
            };
            match work {
                EpisodeDeleteWork::Expand(plan) | EpisodeDeleteWork::FinishSelector(plan) => {
                    execute_prepared_for_owner(
                        connection,
                        PreparedLogicalMutation::prepare(plan).unwrap(),
                    )
                    .unwrap();
                }
                EpisodeDeleteWork::Provider(item) => {
                    execute_prepared_for_owner(
                        connection,
                        PreparedLogicalMutation::prepare(
                            EpisodeDeleteCleanupPlan::new(item).unwrap(),
                        )
                        .unwrap(),
                    )
                    .unwrap();
                }
                EpisodeDeleteWork::Complete(plan) => break plan,
            }
        };
        let applied = execute_prepared_for_owner(
            connection,
            PreparedLogicalMutation::prepare(completion_plan).unwrap(),
        )
        .unwrap();
        let disposition = applied.disposition();
        let receipt = applied.into_validated_result().release().unwrap();
        (receipt, disposition)
    }

    #[test]
    fn exact_delete_purges_capture_lineage_and_only_unreferenced_browser_state() {
        let (_directory, mut connection) = connection();
        seed(&connection);
        let evidence = load_episode_delete_evidence(&connection, ACCOUNT, 1)
            .unwrap()
            .unwrap();
        assert_eq!(
            evidence
                .selectors
                .iter()
                .filter(|selector| selector.selector_kind == "event")
                .count(),
            2
        );
        let (preparation, preparation_disposition) =
            apply_preparation(&mut connection, evidence.clone());
        assert_eq!(preparation_disposition, LogicalMutationDisposition::Applied);
        assert!(load_episode_delete_receipt(&connection, ACCOUNT, 1)
            .unwrap()
            .is_none());
        let (receipt, completion_disposition) =
            apply_completion(&mut connection, preparation.clone());
        assert_eq!(completion_disposition, LogicalMutationDisposition::Applied);
        assert_eq!(receipt.purge.deleted_screenshots, 2);
        assert_eq!(
            connection
                .query_row("SELECT COUNT(*) FROM episodes WHERE id=1", [], |row| row
                    .get::<_, i64>(0))
                .unwrap(),
            0
        );
        assert_eq!(
            connection
                .query_row(
                    "SELECT COUNT(*) FROM capture_events WHERE event_id='event-survivor'",
                    [],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            1
        );
        assert_eq!(
            connection
                .query_row(
                    "SELECT COUNT(*) FROM media_work_members
                     WHERE work_unit_id='shared-unit' AND event_id='event-survivor'",
                    [],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            1
        );
        assert_eq!(
            connection
                .query_row(
                    "SELECT COUNT(*) FROM capture_events WHERE event_id IN ('event-unique','event-shared')",
                    [],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            0
        );
        assert_eq!(
            connection
                .query_row(
                    "SELECT COUNT(*) FROM browser_states_v2 WHERE state_key='state-unique'",
                    [],
                    |row| row.get::<_, i64>(0)
                )
                .unwrap(),
            0
        );
        assert_eq!(
            connection
                .query_row(
                    "SELECT COUNT(*) FROM browser_states_v2 WHERE state_key='state-shared'",
                    [],
                    |row| row.get::<_, i64>(0)
                )
                .unwrap(),
            1
        );
        assert_eq!(
            load_episode_delete_receipt(&connection, ACCOUNT, 1)
                .unwrap()
                .unwrap()
                .purge
                .screenshot_source_keys,
            evidence.purge.screenshot_source_keys
        );

        let (replay_receipt, replay_disposition) = apply_completion(&mut connection, preparation);
        assert_eq!(replay_disposition, LogicalMutationDisposition::Replayed);
        assert_eq!(replay_receipt, receipt);
    }

    #[test]
    fn stale_predecessor_rolls_back_without_partial_purge() {
        let (_directory, mut connection) = connection();
        seed(&connection);
        let evidence = load_episode_delete_evidence(&connection, ACCOUNT, 1)
            .unwrap()
            .unwrap();
        connection
            .execute(
                "UPDATE screenshots SET ocr_text='changed after freeze' WHERE id=11",
                [],
            )
            .unwrap();
        let error = match execute_prepared_for_owner(
            &mut connection,
            PreparedLogicalMutation::prepare(
                EpisodeDeletePreparePlan::new(ACCOUNT.into(), evidence).unwrap(),
            )
            .unwrap(),
        ) {
            Ok(_) => panic!("stale deletion unexpectedly applied"),
            Err(error) => error,
        };
        assert_eq!(error, WalIdempotencyError::Precondition);
        assert_eq!(
            connection
                .query_row("SELECT COUNT(*) FROM episodes WHERE id=1", [], |row| row
                    .get::<_, i64>(0))
                .unwrap(),
            1
        );
        assert_eq!(
            connection
                .query_row(
                    "SELECT COUNT(*) FROM capture_events WHERE event_id='event-unique'",
                    [],
                    |row| row.get::<_, i64>(0)
                )
                .unwrap(),
            1
        );
        assert!(load_episode_delete_receipt(&connection, ACCOUNT, 1)
            .unwrap()
            .is_none());
    }

    #[test]
    fn missing_legacy_source_key_does_not_wedge_hard_delete_or_replay() {
        let (_directory, mut connection) = connection();
        insert_episode(&connection, 9);
        connection
            .execute(
                "INSERT INTO screenshots (id,captured_at,ocr_text,source_key)
                 VALUES (90,?1,'legacy',NULL)",
                [STAMP],
            )
            .unwrap();
        connection
            .execute(
                "INSERT INTO episode_members (episode_id,record_type,record_id)
                 VALUES (9,'screenshot',90)",
                [],
            )
            .unwrap();
        let evidence = load_episode_delete_evidence(&connection, ACCOUNT, 9)
            .unwrap()
            .unwrap();
        assert_eq!(evidence.purge.deleted_screenshots, 1);
        assert!(evidence.purge.screenshot_source_keys.is_empty());
        let (preparation, _) = apply_preparation(&mut connection, evidence);
        let (receipt, _) = apply_completion(&mut connection, preparation);
        assert_eq!(receipt.purge.deleted_screenshots, 1);
        assert!(receipt.purge.screenshot_source_keys.is_empty());
        assert_eq!(
            load_episode_delete_receipt(&connection, ACCOUNT, 9)
                .unwrap()
                .unwrap(),
            receipt
        );
    }

    #[test]
    fn pre_cloud_audio_without_provider_lineage_remains_deletable() {
        let (_directory, mut connection) = connection();
        insert_episode(&connection, 9);
        insert_audio_utterance(&connection, 9, 901, "event-pre-cloud", 91);
        connection
            .execute(
                "UPDATE utterances SET source_key=NULL,speaker_observation_id=NULL WHERE id=901",
                [],
            )
            .unwrap();
        connection
            .execute("DELETE FROM speaker_observations WHERE id=10901", [])
            .unwrap();
        connection
            .execute(
                "DELETE FROM capture_events WHERE event_id='event-pre-cloud'",
                [],
            )
            .unwrap();

        let evidence = load_episode_delete_evidence(&connection, ACCOUNT, 9)
            .unwrap()
            .unwrap();
        assert!(evidence.selectors.is_empty());
        let (preparation, _) = apply_preparation(&mut connection, evidence);
        let (receipt, _) = apply_completion(&mut connection, preparation);
        assert_eq!(receipt.purge.deleted_utterances, 1);
        assert!(receipt.purge.utterance_source_keys.is_empty());
        assert_eq!(
            connection
                .query_row("SELECT COUNT(*) FROM episodes WHERE id=9", [], |row| {
                    row.get::<_, i64>(0)
                })
                .unwrap(),
            0
        );
    }

    #[test]
    fn capacity_is_reserved_before_logical_or_provider_cleanup_can_begin() {
        fn case(column: &str, value: u64) {
            let (_directory, mut connection) = connection();
            seed(&connection);
            let evidence = load_episode_delete_evidence(&connection, ACCOUNT, 1)
                .unwrap()
                .unwrap();
            let transaction = connection.transaction().unwrap();
            ensure_schema(&transaction).unwrap();
            transaction.commit().unwrap();
            connection
                .execute(
                    &format!(
                        "UPDATE archive_v3_wal_episode_delete_state SET {column}=?1 WHERE singleton=1"
                    ),
                    [i64::try_from(value).unwrap()],
                )
                .unwrap();
            let error = match execute_prepared_for_owner(
                &mut connection,
                PreparedLogicalMutation::prepare(
                    EpisodeDeletePreparePlan::new(ACCOUNT.into(), evidence).unwrap(),
                )
                .unwrap(),
            ) {
                Ok(_) => panic!("capacity-exhausted preparation unexpectedly applied"),
                Err(error) => error,
            };
            assert_eq!(error, WalIdempotencyError::Limit);
            assert_eq!(
                connection
                    .query_row("SELECT COUNT(*) FROM episodes WHERE id=1", [], |row| {
                        row.get::<_, i64>(0)
                    })
                    .unwrap(),
                1
            );
            assert_eq!(
                connection
                    .query_row(
                        "SELECT COUNT(*) FROM archive_v3_wal_episode_delete_operations",
                        [],
                        |row| row.get::<_, i64>(0),
                    )
                    .unwrap(),
                0
            );
        }

        case("row_count", u64::from(MAX_ROWS));
        case(
            "result_bytes",
            MAX_RESULT_BYTES - (UNIT_RESULT_BYTES as u64 * 2) + 1,
        );
        case("source_count", MAX_SOURCE_ROWS);
        case("source_bytes", MAX_SOURCE_BYTES);

        let (_directory, mut connection) = connection();
        seed(&connection);
        let evidence = load_episode_delete_evidence(&connection, ACCOUNT, 1)
            .unwrap()
            .unwrap();
        let (variable_rows, variable_bytes) = stored_variable_usage(&evidence).unwrap();
        let transaction = connection.transaction().unwrap();
        ensure_schema(&transaction).unwrap();
        transaction.commit().unwrap();
        connection
            .execute(
                "UPDATE archive_v3_wal_episode_delete_state
                 SET row_count=?1,result_bytes=?2,source_count=?3,source_bytes=?4
                 WHERE singleton=1",
                params![
                    i64::from(MAX_ROWS - 1),
                    i64::try_from(MAX_RESULT_BYTES - UNIT_RESULT_BYTES as u64 * 2).unwrap(),
                    i64::try_from(MAX_SOURCE_ROWS - variable_rows as u64).unwrap(),
                    i64::try_from(MAX_SOURCE_BYTES - variable_bytes).unwrap(),
                ],
            )
            .unwrap();
        let (_, disposition) = apply_preparation(&mut connection, evidence);
        assert_eq!(disposition, LogicalMutationDisposition::Applied);
        assert_eq!(
            connection
                .query_row(
                    "SELECT row_count FROM archive_v3_wal_episode_delete_state",
                    [],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            i64::from(MAX_ROWS)
        );
    }

    #[test]
    fn mismatched_or_missing_browser_event_evidence_refuses_before_any_purge() {
        for pointer in [
            "capture-v2-browser:event-unique",
            "capture-v2-browser:event-missing",
        ] {
            let (_directory, connection) = connection();
            seed(&connection);
            connection
                .execute(
                    "UPDATE screenshots SET browser_snapshot_source_key=?1 WHERE id=12",
                    [pointer],
                )
                .unwrap();
            assert!(matches!(
                load_episode_delete_evidence(&connection, ACCOUNT, 1),
                Err(WalIdempotencyError::Corrupt)
            ));
            assert_eq!(
                connection
                    .query_row("SELECT COUNT(*) FROM episodes WHERE id=1", [], |row| {
                        row.get::<_, i64>(0)
                    })
                    .unwrap(),
                1
            );
        }
    }

    #[test]
    fn audio_event_media_is_deleted_only_after_its_last_utterance_reference() {
        let (_directory, mut connection) = connection();
        insert_episode(&connection, 1);
        insert_episode(&connection, 2);
        insert_audio_utterance(&connection, 1, 101, "event-audio", 10);
        insert_audio_utterance(&connection, 2, 201, "event-audio", 10);

        let first = load_episode_delete_evidence(&connection, ACCOUNT, 1)
            .unwrap()
            .unwrap();
        assert!(first.media.is_empty(), "shared raw audio must be preserved");
        assert!(first.event_ids.is_empty());
        assert_eq!(
            first.selectors,
            vec![EpisodeDeleteSelector {
                selector_kind: "voice".into(),
                selector_ref: "10101".into(),
            }]
        );
        let (first_preparation, _) = apply_preparation(&mut connection, first);
        apply_completion(&mut connection, first_preparation);
        assert_eq!(
            connection
                .query_row(
                    "SELECT COUNT(*) FROM capture_events WHERE event_id='event-audio'",
                    [],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            1
        );

        let last = load_episode_delete_evidence(&connection, ACCOUNT, 2)
            .unwrap()
            .unwrap();
        assert_eq!(
            last.selectors,
            vec![EpisodeDeleteSelector {
                selector_kind: "voice".into(),
                selector_ref: "10201".into(),
            }]
        );
        let (last_preparation, _) = apply_preparation(&mut connection, last);
        assert_eq!(last_preparation.selectors.len(), 1);
        apply_completion(&mut connection, last_preparation);
        assert_eq!(
            connection
                .query_row(
                    "SELECT COUNT(*) FROM capture_events WHERE event_id='event-audio'",
                    [],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            0
        );
    }

    #[test]
    fn selected_pre_v2_audio_lineage_is_derived_exactly_before_purge() {
        let (_directory, mut connection) = connection();
        insert_episode(&connection, 1);
        insert_audio_utterance(&connection, 1, 101, "event-audio", 10);
        connection
            .execute(
                "UPDATE utterances
                 SET speaker_observation_id=NULL,
                     source_key='cloud-v2:event-audio:turn-101'
                 WHERE id=101",
                [],
            )
            .unwrap();
        let evidence = load_episode_delete_evidence(&connection, ACCOUNT, 1)
            .unwrap()
            .unwrap();
        assert_eq!(
            evidence.selectors,
            vec![EpisodeDeleteSelector {
                selector_kind: "voice".into(),
                selector_ref: "10101".into(),
            }]
        );
        let (preparation, _) = apply_preparation(&mut connection, evidence);
        apply_completion(&mut connection, preparation);
        assert_eq!(
            connection
                .query_row("SELECT COUNT(*) FROM episodes WHERE id=1", [], |row| {
                    row.get::<_, i64>(0)
                })
                .unwrap(),
            0
        );
        assert_eq!(
            connection
                .query_row(
                    "SELECT COUNT(*) FROM capture_events WHERE event_id='event-audio'",
                    [],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            0
        );
    }

    #[test]
    fn legacy_browser_rows_are_purged_only_after_the_last_screenshot_reference() {
        let (_directory, mut connection) = connection();
        seed(&connection);
        let unique = insert_legacy_browser_snapshot(&connection, "legacy-unique", &[11]);
        let shared = insert_legacy_browser_snapshot(&connection, "legacy-shared", &[12, 21]);
        let evidence = load_episode_delete_evidence(&connection, ACCOUNT, 1)
            .unwrap()
            .unwrap();
        assert_eq!(evidence.legacy_browser_snapshot_ids, vec![unique]);
        let (preparation, _) = apply_preparation(&mut connection, evidence);
        apply_completion(&mut connection, preparation);
        assert_eq!(
            connection
                .query_row(
                    "SELECT COUNT(*) FROM browser_snapshots WHERE id=?1",
                    [unique],
                    |row| { row.get::<_, i64>(0) }
                )
                .unwrap(),
            0
        );
        assert_eq!(
            connection
                .query_row(
                    "SELECT COUNT(*) FROM browser_tabs WHERE browser_snapshot_id=?1",
                    [unique],
                    |row| { row.get::<_, i64>(0) }
                )
                .unwrap(),
            0
        );
        assert_eq!(
            connection
                .query_row(
                    "SELECT COUNT(*) FROM browser_snapshots WHERE id=?1",
                    [shared],
                    |row| { row.get::<_, i64>(0) }
                )
                .unwrap(),
            1
        );
    }

    #[test]
    fn cross_episode_membership_and_allocator_changes_are_exact_preconditions() {
        {
            let (_directory, mut connection) = connection();
            seed(&connection);
            let evidence = load_episode_delete_evidence(&connection, ACCOUNT, 1)
                .unwrap()
                .unwrap();
            connection
                .execute(
                    "INSERT INTO episode_members (episode_id,record_type,record_id)
                     VALUES (2,'screenshot',11)",
                    [],
                )
                .unwrap();
            let error = match execute_prepared_for_owner(
                &mut connection,
                PreparedLogicalMutation::prepare(
                    EpisodeDeletePreparePlan::new(ACCOUNT.into(), evidence).unwrap(),
                )
                .unwrap(),
            ) {
                Ok(_) => panic!("stale membership unexpectedly applied"),
                Err(error) => error,
            };
            assert_eq!(error, WalIdempotencyError::Precondition);
            assert_eq!(
                connection
                    .query_row("SELECT COUNT(*) FROM episodes WHERE id=1", [], |row| {
                        row.get::<_, i64>(0)
                    })
                    .unwrap(),
                1
            );
        }

        let (_directory, mut connection) = connection();
        seed(&connection);
        let evidence = load_episode_delete_evidence(&connection, ACCOUNT, 1)
            .unwrap()
            .unwrap();
        let (preparation, _) = apply_preparation(&mut connection, evidence);
        let expansion = match load_episode_delete_work(&connection, ACCOUNT, 1)
            .unwrap()
            .unwrap()
        {
            EpisodeDeleteWork::Expand(plan) => plan,
            _ => panic!("selector expansion was not available"),
        };
        connection
            .execute(
                "INSERT INTO sqlite_sequence(name,seq)
                 VALUES ('voice_profile_revisions',7)",
                [],
            )
            .unwrap();
        let error = match execute_prepared_for_owner(
            &mut connection,
            PreparedLogicalMutation::prepare(expansion).unwrap(),
        ) {
            Ok(_) => panic!("stale allocator unexpectedly applied"),
            Err(error) => error,
        };
        assert_eq!(error, WalIdempotencyError::Precondition);
        assert!(matches!(
            load_episode_delete_work(&connection, ACCOUNT, 1).unwrap(),
            Some(EpisodeDeleteWork::Expand(_))
        ));
        assert_eq!(preparation.receipt.episode_id, 1);
    }

    #[test]
    fn unrelated_incomplete_voice_lineage_does_not_block_screen_only_delete() {
        let (_directory, connection) = connection();
        seed(&connection);
        connection
            .execute(
                "INSERT INTO voice_profiles
                 (label,embedding_space,channel_domain,centroid,updated_at)
                 VALUES ('unrelated','voice-v1','mic',zeroblob(1024),?1)",
                [STAMP],
            )
            .unwrap();
        assert!(load_episode_delete_evidence(&connection, ACCOUNT, 1)
            .unwrap()
            .is_some());
    }

    #[test]
    fn fully_authenticated_receipt_rejects_operation_result_source_and_cleanup_tampering() {
        for mutation in [
            "account",
            "episode",
            "operation",
            "fingerprint",
            "result",
            "source-gap",
            "source-missing",
            "source-extra",
            "cleanup-missing",
            "cleanup-change",
            "partial-schema",
        ] {
            let (_directory, mut connection) = connection();
            seed(&connection);
            let evidence = load_episode_delete_evidence(&connection, ACCOUNT, 1)
                .unwrap()
                .unwrap();
            let (preparation, _) = apply_preparation(&mut connection, evidence);
            apply_completion(&mut connection, preparation);
            match mutation {
                "account" => {}
                "episode" => {
                    connection
                        .execute(
                            "UPDATE archive_v3_wal_episode_delete_operations SET episode_id=99",
                            [],
                        )
                        .unwrap();
                }
                "operation" => {
                    connection
                        .execute(
                            "UPDATE archive_v3_wal_episode_delete_operations
                             SET completion_operation_id=?1",
                            [[9u8; 16].as_slice()],
                        )
                        .unwrap();
                }
                "fingerprint" => {
                    connection
                        .execute(
                            "UPDATE archive_v3_wal_episode_delete_operations
                             SET completion_request_fingerprint=?1",
                            [[8u8; 32].as_slice()],
                        )
                        .unwrap();
                }
                "result" => {
                    connection
                        .execute(
                            "UPDATE archive_v3_wal_episode_delete_operations
                             SET completion_result_commitment=?1",
                            [[7u8; 32].as_slice()],
                        )
                        .unwrap();
                }
                "source-gap" => {
                    connection
                        .execute(
                            "UPDATE archive_v3_wal_episode_delete_sources
                             SET ordinal=ordinal+10 WHERE source_kind='screenshot'",
                            [],
                        )
                        .unwrap();
                }
                "source-missing" => {
                    connection
                        .execute(
                            "DELETE FROM archive_v3_wal_episode_delete_sources
                             WHERE source_kind='screenshot' AND ordinal=0",
                            [],
                        )
                        .unwrap();
                }
                "source-extra" => {
                    let operation_id: Vec<u8> = connection
                        .query_row(
                            "SELECT preparation_operation_id
                             FROM archive_v3_wal_episode_delete_operations",
                            [],
                            |row| row.get(0),
                        )
                        .unwrap();
                    connection
                        .execute(
                            "INSERT INTO archive_v3_wal_episode_delete_sources
                             (preparation_operation_id,source_kind,ordinal,source_key)
                             VALUES (?1,'screenshot',99,'extra-source')",
                            [operation_id],
                        )
                        .unwrap();
                }
                "cleanup-missing" => {
                    connection
                        .execute(
                            "DELETE FROM archive_v3_wal_episode_delete_selectors
                             WHERE ordinal=0",
                            [],
                        )
                        .unwrap();
                }
                "cleanup-change" => {
                    connection
                        .execute(
                            "UPDATE archive_v3_wal_episode_delete_selectors
                             SET selector_ref='changed-selector' WHERE ordinal=0",
                            [],
                        )
                        .unwrap();
                }
                "partial-schema" => {
                    connection
                        .execute("DROP TABLE archive_v3_wal_episode_delete_sources", [])
                        .unwrap();
                }
                _ => unreachable!(),
            }
            let account = if mutation == "account" {
                "other-episode-delete-user"
            } else {
                ACCOUNT
            };
            assert!(load_episode_delete_start(&connection, account, 1).is_err());
        }
    }

    #[test]
    fn prepared_cleanup_survives_reopen_and_completion_replays_without_plaintext() {
        let (directory, mut connection) = connection();
        let path = directory.path().join("archive.sqlite");
        seed(&connection);
        let evidence = load_episode_delete_evidence(&connection, ACCOUNT, 1)
            .unwrap()
            .unwrap();
        let (expected, disposition) = apply_preparation(&mut connection, evidence);
        assert_eq!(disposition, LogicalMutationDisposition::Applied);
        drop(connection);

        let mut reopened = Connection::open(path).unwrap();
        reopened.execute_batch("PRAGMA foreign_keys=ON;").unwrap();
        let recovered = match load_episode_delete_start(&reopened, ACCOUNT, 1).unwrap() {
            EpisodeDeleteStart::Prepared(preparation) => preparation,
            _ => panic!("prepared provider cleanup was not recoverable"),
        };
        assert_eq!(recovered, expected);
        let (receipt, disposition) = apply_completion(&mut reopened, recovered);
        assert_eq!(disposition, LogicalMutationDisposition::Applied);
        assert_eq!(
            load_episode_delete_receipt(&reopened, ACCOUNT, 1)
                .unwrap()
                .unwrap(),
            receipt
        );
    }

    #[test]
    fn delete_bound_matches_the_legal_writer_member_bound() {
        assert_eq!(
            MAX_MEMBERS_PER_CLASS,
            crate::cp::summarizer::wal::window::MAX_MEMBERS_PER_ITEM
        );
        let (_directory, connection) = connection();
        insert_episode(&connection, 1);
        insert_screenshot_range(&connection, 1, 1, 8_193);
        assert_eq!(
            load_episode_delete_evidence(&connection, ACCOUNT, 1)
                .unwrap()
                .unwrap()
                .purge
                .deleted_screenshots,
            8_193
        );
        insert_screenshot_range(
            &connection,
            1,
            8_194,
            i64::try_from(MAX_MEMBERS_PER_CLASS).unwrap(),
        );
        assert_eq!(
            member_rows(&connection, 1, "screenshot", "screenshots")
                .unwrap()
                .len(),
            MAX_MEMBERS_PER_CLASS
        );
        insert_screenshot_range(
            &connection,
            1,
            i64::try_from(MAX_MEMBERS_PER_CLASS + 1).unwrap(),
            i64::try_from(MAX_MEMBERS_PER_CLASS + 1).unwrap(),
        );
        assert_eq!(
            load_episode_delete_evidence(&connection, ACCOUNT, 1).unwrap_err(),
            WalIdempotencyError::Limit
        );
    }

    #[test]
    fn shared_voice_profile_recompute_is_monotone_and_replay_exact() {
        let (_directory, mut connection) = connection();
        insert_episode(&connection, 1);
        insert_episode(&connection, 2);
        insert_audio_utterance(&connection, 1, 101, "event-audio-1", 31);
        insert_audio_utterance(&connection, 2, 201, "event-audio-2", 32);
        let newer = "2026-08-23T12:00:00.000Z";
        connection
            .execute(
                "INSERT INTO voice_profiles
                 (id,label,embedding_space,channel_domain,centroid,sample_count,
                  scorer_version,representative_kind,status,created_at,updated_at)
                 VALUES (1,'shared-profile','voice-v1','mic',?1,2,2,
                         'medoid_trimmed_centroid','tentative',?2,?2)",
                params![unit_embedding(0), newer],
            )
            .unwrap();
        for (sample_id, observation_id, embedding) in [
            (1i64, 10_101i64, unit_embedding(0)),
            (2i64, 10_201i64, unit_embedding(1)),
        ] {
            connection
                .execute(
                    "INSERT INTO voice_samples
                     (id,speaker_observation_id,voice_profile_id,embedding_space,
                      channel_domain,embedding,quality_score,accepted,eligibility,
                      outlier,created_at)
                     VALUES (?1,?2,1,'voice-v1','mic',?3,1.0,1,'enroll',0,?4)",
                    params![sample_id, observation_id, embedding, newer],
                )
                .unwrap();
            connection
                .execute(
                    "INSERT INTO voice_sample_profile_assignments
                     (sample_id,profile_id,active,created_at) VALUES (?1,1,1,?2)",
                    params![sample_id, newer],
                )
                .unwrap();
        }
        connection
            .execute(
                "UPDATE voice_profiles SET medoid_sample_id=1 WHERE id=1",
                [],
            )
            .unwrap();
        connection
            .execute(
                "INSERT INTO voice_profile_representatives
                 (profile_id,channel_domain,centroid,sample_count,medoid_sample_id,
                  scorer_version,created_at,updated_at)
                 VALUES (1,'mic',?1,2,1,2,?2,?2)",
                params![unit_embedding(0), newer],
            )
            .unwrap();
        connection
            .execute(
                "INSERT INTO voice_profile_revisions
                 (profile_id,status,derivation_version,scorer_version,representative_kind,
                  centroid,sample_count,medoid_sample_id,reason_code,active,created_at)
                 VALUES (1,'tentative',1,2,'medoid_trimmed_centroid',?1,2,1,
                         'initial',1,?2)",
                params![unit_embedding(0), newer],
            )
            .unwrap();

        let evidence = load_episode_delete_evidence(&connection, ACCOUNT, 1)
            .unwrap()
            .unwrap();
        assert!(evidence.mutation_stamp.as_str() >= newer);
        let mutation_stamp = evidence.mutation_stamp.clone();
        let (preparation, _) = apply_preparation(&mut connection, evidence);
        let (receipt, disposition) = apply_completion(&mut connection, preparation.clone());
        assert_eq!(disposition, LogicalMutationDisposition::Applied);
        let profile = connection
            .query_row(
                "SELECT sample_count,medoid_sample_id,updated_at FROM voice_profiles WHERE id=1",
                [],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, Option<i64>>(1)?,
                        row.get::<_, String>(2)?,
                    ))
                },
            )
            .unwrap();
        assert_eq!(profile, (1, Some(2), mutation_stamp.clone()));
        let active_revision = connection
            .query_row(
                "SELECT sample_count,medoid_sample_id,created_at
                 FROM voice_profile_revisions WHERE profile_id=1 AND active=1",
                [],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, Option<i64>>(1)?,
                        row.get::<_, String>(2)?,
                    ))
                },
            )
            .unwrap();
        assert_eq!(active_revision, (1, Some(2), mutation_stamp));
        let (replay, disposition) = apply_completion(&mut connection, preparation);
        assert_eq!(disposition, LogicalMutationDisposition::Replayed);
        assert_eq!(receipt, replay);
    }

    #[test]
    fn selected_imported_voice_lineage_backfills_exactly_and_replays_after_reopen() {
        let (directory, mut connection) = connection();
        let path = directory.path().join("archive.sqlite");
        insert_episode(&connection, 1);
        insert_episode(&connection, 2);
        insert_episode(&connection, 3);
        insert_audio_utterance(&connection, 1, 101, "event-imported-target", 61);
        insert_audio_utterance(&connection, 2, 201, "event-imported-survivor", 62);
        // A screenshot membership with the same numeric record id as the
        // surviving utterance is not part of the voice dependency closure.
        connection
            .execute(
                "INSERT INTO screenshots (id,captured_at,source_key) VALUES (201,?1,NULL)",
                [STAMP],
            )
            .unwrap();
        connection
            .execute(
                "INSERT INTO episode_members (episode_id,record_type,record_id)
                 VALUES (3,'screenshot',201)",
                [],
            )
            .unwrap();
        connection
            .execute(
                "INSERT INTO voice_profiles
                 (id,label,embedding_space,channel_domain,centroid,sample_count,
                  scorer_version,representative_kind,medoid_sample_id,status,created_at,updated_at)
                 VALUES (1,'imported-profile','voice-v1','mic',?1,2,2,
                         'medoid_trimmed_centroid',1,'tentative',?2,?2)",
                params![unit_embedding(0), STAMP],
            )
            .unwrap();
        for (sample_id, observation_id, embedding) in [
            (1i64, 10_101i64, unit_embedding(0)),
            (2i64, 10_201i64, unit_embedding(1)),
        ] {
            connection
                .execute(
                    "INSERT INTO voice_samples
                     (id,speaker_observation_id,voice_profile_id,embedding_space,
                      channel_domain,embedding,quality_score,accepted,eligibility,
                      outlier,created_at)
                     VALUES (?1,?2,1,'voice-v1','mic',?3,1.0,1,'enroll',0,?4)",
                    params![sample_id, observation_id, embedding, STAMP],
                )
                .unwrap();
        }
        assert_eq!(
            connection
                .query_row("SELECT COUNT(*) FROM voice_profile_revisions", [], |row| {
                    row.get::<_, i64>(0)
                },)
                .unwrap(),
            0
        );
        assert_eq!(
            connection
                .query_row(
                    "SELECT COUNT(*) FROM voice_sample_profile_assignments",
                    [],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            0
        );

        let evidence = load_episode_delete_evidence(&connection, ACCOUNT, 1)
            .unwrap()
            .unwrap();
        let mutation_stamp = evidence.mutation_stamp.clone();
        let (preparation, disposition) = apply_preparation(&mut connection, evidence);
        assert_eq!(disposition, LogicalMutationDisposition::Applied);
        drop(connection);

        let mut reopened = Connection::open(&path).unwrap();
        reopened.execute_batch("PRAGMA foreign_keys=ON;").unwrap();
        let recovered = match load_episode_delete_start(&reopened, ACCOUNT, 1).unwrap() {
            EpisodeDeleteStart::Prepared(preparation) => preparation,
            _ => panic!("selected imported voice deletion did not recover after reopen"),
        };
        assert_eq!(recovered, preparation);
        let (receipt, disposition) = apply_completion(&mut reopened, recovered.clone());
        assert_eq!(disposition, LogicalMutationDisposition::Applied);
        assert_eq!(
            reopened
                .query_row(
                    "SELECT sample_count,medoid_sample_id,typeof(sample_count)
                     FROM voice_profiles WHERE id=1",
                    [],
                    |row| {
                        Ok((
                            row.get::<_, i64>(0)?,
                            row.get::<_, Option<i64>>(1)?,
                            row.get::<_, String>(2)?,
                        ))
                    },
                )
                .unwrap(),
            (1, Some(2), "integer".to_owned())
        );
        assert_eq!(
            reopened
                .query_row("SELECT COUNT(*) FROM voice_samples WHERE id=1", [], |row| {
                    row.get::<_, i64>(0)
                },)
                .unwrap(),
            0
        );
        assert_eq!(
            reopened
                .query_row(
                    "SELECT profile_id,active,created_at
                     FROM voice_sample_profile_assignments WHERE sample_id=2",
                    [],
                    |row| {
                        Ok((
                            row.get::<_, i64>(0)?,
                            row.get::<_, i64>(1)?,
                            row.get::<_, String>(2)?,
                        ))
                    },
                )
                .unwrap(),
            (1, 1, mutation_stamp.clone())
        );
        assert!(
            reopened
                .query_row(
                    "SELECT COUNT(*) FROM voice_profile_revisions
                     WHERE profile_id=1 AND reason_code='schema_backfill' AND created_at=?1",
                    [&mutation_stamp],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap()
                >= 1
        );
        assert_eq!(
            reopened
                .query_row(
                    "SELECT identity_revision FROM episodes WHERE id=2",
                    [],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            1
        );
        assert_eq!(
            reopened
                .query_row(
                    "SELECT identity_revision FROM episodes WHERE id=3",
                    [],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            0
        );

        drop(reopened);
        let mut replayed = Connection::open(path).unwrap();
        replayed.execute_batch("PRAGMA foreign_keys=ON;").unwrap();
        let (replay_receipt, replay_disposition) = apply_completion(&mut replayed, recovered);
        assert_eq!(replay_disposition, LogicalMutationDisposition::Replayed);
        assert_eq!(replay_receipt, receipt);
        assert_eq!(
            replayed
                .query_row(
                    "SELECT sample_count,medoid_sample_id FROM voice_profiles WHERE id=1",
                    [],
                    |row| Ok((row.get::<_, i64>(0)?, row.get::<_, Option<i64>>(1)?)),
                )
                .unwrap(),
            (1, Some(2))
        );
    }

    #[test]
    fn voice_invalidation_pages_across_more_than_128_surviving_episodes() {
        let (directory, mut connection) = connection();
        let path = directory.path().join("archive.sqlite");
        insert_episode(&connection, 1);
        insert_audio_utterance(&connection, 1, 101, "event-paged-target", 401);
        for episode_id in 2..=130i64 {
            insert_episode(&connection, episode_id);
            let utterance_id = 1_000 + episode_id;
            insert_audio_utterance(
                &connection,
                episode_id,
                utterance_id,
                &format!("event-paged-{episode_id}"),
                500 + episode_id,
            );
        }
        connection
            .execute(
                "INSERT INTO voice_profiles
                 (id,label,embedding_space,channel_domain,centroid,sample_count,
                  scorer_version,representative_kind,medoid_sample_id,status,created_at,updated_at)
                 VALUES (1,'paged-profile','voice-v1','mic',?1,130,2,
                         'medoid_trimmed_centroid',1,'tentative',?2,?2)",
                params![unit_embedding(0), STAMP],
            )
            .unwrap();
        let mut observations = vec![10_101i64];
        observations.extend((2..=130i64).map(|episode_id| 10_000 + 1_000 + episode_id));
        for (index, observation_id) in observations.into_iter().enumerate() {
            let sample_id = i64::try_from(index + 1).unwrap();
            connection
                .execute(
                    "INSERT INTO voice_samples
                     (id,speaker_observation_id,voice_profile_id,embedding_space,
                      channel_domain,embedding,quality_score,accepted,eligibility,
                      outlier,created_at)
                     VALUES (?1,?2,1,'voice-v1','mic',?3,1.0,1,'enroll',0,?4)",
                    params![
                        sample_id,
                        observation_id,
                        unit_embedding(index % 256),
                        STAMP
                    ],
                )
                .unwrap();
            connection
                .execute(
                    "INSERT INTO voice_sample_profile_assignments
                     (sample_id,profile_id,active,created_at) VALUES (?1,1,1,?2)",
                    params![sample_id, STAMP],
                )
                .unwrap();
        }
        let evidence = load_episode_delete_evidence(&connection, ACCOUNT, 1)
            .unwrap()
            .unwrap();
        let (preparation, _) = apply_preparation(&mut connection, evidence);
        let reservation = match load_episode_delete_work(&connection, ACCOUNT, 1)
            .unwrap()
            .unwrap()
        {
            EpisodeDeleteWork::Expand(plan) => plan,
            _ => panic!("voice cleanup capacity reservation was not available"),
        };
        assert!(matches!(
            &reservation.action,
            EpisodeDeleteCleanupAction::ReserveVoiceCapacity(_)
        ));
        execute_prepared_for_owner(
            &mut connection,
            PreparedLogicalMutation::prepare(reservation).unwrap(),
        )
        .unwrap();
        let first = match load_episode_delete_work(&connection, ACCOUNT, 1)
            .unwrap()
            .unwrap()
        {
            EpisodeDeleteWork::Expand(plan) => plan,
            _ => panic!("first voice invalidation page was not available"),
        };
        assert!(matches!(
            &first.action,
            EpisodeDeleteCleanupAction::AdvanceVoiceEpisodes(page)
                if page.episodes.len() == 128 && page.expected_page_sequence == 0
        ));
        execute_prepared_for_owner(
            &mut connection,
            PreparedLogicalMutation::prepare(first).unwrap(),
        )
        .unwrap();
        // A finalizer may complete every row in the first page between
        // bounded deletion turns. The rotating cursor must still reach the
        // higher episode before wrapping to requeue that stale first page.
        connection
            .execute(
                "UPDATE episodes SET identity_refresh_status='ready' WHERE id BETWEEN 2 AND 129",
                [],
            )
            .unwrap();
        drop(connection);

        let mut reopened = Connection::open(&path).unwrap();
        reopened.execute_batch("PRAGMA foreign_keys=ON;").unwrap();
        let second = match load_episode_delete_work(&reopened, ACCOUNT, 1)
            .unwrap()
            .unwrap()
        {
            EpisodeDeleteWork::Expand(plan) => plan,
            _ => panic!("second voice invalidation page was not available after reopen"),
        };
        assert!(matches!(
            &second.action,
            EpisodeDeleteCleanupAction::AdvanceVoiceEpisodes(page)
                if page.episodes.iter().map(|row| row.episode_id).collect::<Vec<_>>() == [130]
                    && page.expected_page_sequence == 1
                    && page.expected_scan_cursor == 129
        ));
        execute_prepared_for_owner(
            &mut reopened,
            PreparedLogicalMutation::prepare(second).unwrap(),
        )
        .unwrap();
        let wrapped = match load_episode_delete_work(&reopened, ACCOUNT, 1)
            .unwrap()
            .unwrap()
        {
            EpisodeDeleteWork::Expand(plan) => plan,
            _ => panic!("stale first page was not revisited after the cursor wrapped"),
        };
        assert!(matches!(
            &wrapped.action,
            EpisodeDeleteCleanupAction::AdvanceVoiceEpisodes(page)
                if page.episodes.len() == 128
                    && page.episodes.first().map(|row| row.episode_id) == Some(2)
                    && page.episodes.last().map(|row| row.episode_id) == Some(129)
                    && page.expected_page_sequence == 2
                    && page.expected_scan_cursor == 130
        ));
        execute_prepared_for_owner(
            &mut reopened,
            PreparedLogicalMutation::prepare(wrapped).unwrap(),
        )
        .unwrap();
        let expansion = match load_episode_delete_work(&reopened, ACCOUNT, 1)
            .unwrap()
            .unwrap()
        {
            EpisodeDeleteWork::Expand(plan) => plan,
            _ => panic!("voice selector did not advance after the clean wrapped page"),
        };
        assert!(matches!(
            &expansion.action,
            EpisodeDeleteCleanupAction::Expand(expansion)
                if expansion.voice_page_sequence == 3
                    && expansion.voice_scan_cursor == 129
                    && expansion.reserved_cleanup_rows == VOICE_RESERVED_CLEANUP_ROWS
                    && expansion.reserved_cleanup_bytes == VOICE_RESERVED_CLEANUP_BYTES
        ));
        assert_eq!(
            reopened
                .query_row(
                    "SELECT COUNT(*) FROM archive_v3_wal_episode_delete_voice_progress",
                    [],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            129,
            "paging retains at most one current row per affected episode"
        );
        execute_prepared_for_owner(
            &mut reopened,
            PreparedLogicalMutation::prepare(expansion).unwrap(),
        )
        .unwrap();
        assert_eq!(
            reopened
                .query_row(
                    "SELECT COUNT(*) FROM archive_v3_wal_episode_delete_voice_progress",
                    [],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            0,
            "temporary voice progress is removed with local selector expansion"
        );
        for episode_id in 2..=130i64 {
            assert_eq!(
                reopened
                    .query_row(
                        "SELECT identity_revision,identity_refresh_status FROM episodes WHERE id=?1",
                        [episode_id],
                        |row| Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?)),
                    )
                    .unwrap(),
                (
                    if episode_id <= 129 { 2 } else { 1 },
                    "queued".to_owned()
                )
            );
        }
        apply_completion(&mut reopened, preparation);
        assert!(
            reopened
                .query_row(
                    "SELECT sample_count FROM voice_profiles WHERE id=1",
                    [],
                    |row| { row.get::<_, i64>(0) }
                )
                .unwrap()
                >= 1
        );
    }

    #[test]
    fn inactive_assignment_history_does_not_expand_the_effective_profile_closure() {
        let (_directory, mut connection) = connection();
        insert_episode(&connection, 1);
        insert_episode(&connection, 2);
        insert_audio_utterance(&connection, 1, 101, "event-history-target", 701);
        insert_audio_utterance(&connection, 2, 201, "event-history-survivor", 702);
        for profile_id in 1..=130i64 {
            connection
                .execute(
                    "INSERT INTO voice_profiles
                     (id,label,embedding_space,channel_domain,centroid,sample_count,
                      scorer_version,representative_kind,medoid_sample_id,status,created_at,updated_at)
                     VALUES (?1,?2,'voice-v1','mic',?3,?4,2,
                             'medoid_trimmed_centroid',NULL,'tentative',?5,?5)",
                    params![
                        profile_id,
                        format!("history-{profile_id}"),
                        unit_embedding((profile_id as usize) % 256),
                        if profile_id == 130 { 2 } else { 0 },
                        STAMP,
                    ],
                )
                .unwrap();
        }
        for (sample_id, observation_id) in [(1i64, 10_101i64), (2i64, 10_201i64)] {
            connection
                .execute(
                    "INSERT INTO voice_samples
                     (id,speaker_observation_id,voice_profile_id,embedding_space,
                      channel_domain,embedding,quality_score,accepted,eligibility,
                      outlier,created_at)
                     VALUES (?1,?2,130,'voice-v1','mic',?3,1.0,1,'enroll',0,?4)",
                    params![
                        sample_id,
                        observation_id,
                        unit_embedding(sample_id as usize),
                        STAMP
                    ],
                )
                .unwrap();
        }
        for profile_id in 1..=129i64 {
            connection
                .execute(
                    "INSERT INTO voice_sample_profile_assignments
                     (sample_id,profile_id,active,created_at) VALUES (1,?1,0,?2)",
                    params![profile_id, STAMP],
                )
                .unwrap();
        }
        for sample_id in [1i64, 2i64] {
            connection
                .execute(
                    "INSERT INTO voice_sample_profile_assignments
                     (sample_id,profile_id,active,created_at) VALUES (?1,130,1,?2)",
                    params![sample_id, STAMP],
                )
                .unwrap();
        }
        let evidence = load_episode_delete_evidence(&connection, ACCOUNT, 1)
            .unwrap()
            .unwrap();
        let (preparation, _) = apply_preparation(&mut connection, evidence);
        apply_completion(&mut connection, preparation);
        assert_eq!(
            connection
                .query_row(
                    "SELECT identity_revision FROM episodes WHERE id=2",
                    [],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            1
        );
        assert_eq!(
            connection
                .query_row(
                    "SELECT sample_count FROM voice_profiles WHERE id=130",
                    [],
                    |row| { row.get::<_, i64>(0) }
                )
                .unwrap(),
            1
        );
        assert_eq!(
            connection
                .query_row(
                    "SELECT COUNT(*) FROM voice_profile_revisions WHERE profile_id<130",
                    [],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            0,
            "inactive history must not be recomputed or backfilled"
        );
    }

    #[test]
    fn stale_voice_episode_is_requeued_after_cursor_wrap_without_history() {
        let (_directory, mut connection) = connection();
        insert_episode(&connection, 1);
        insert_episode(&connection, 2);
        insert_audio_utterance(&connection, 1, 101, "event-page-proof-target", 801);
        insert_audio_utterance(&connection, 2, 201, "event-page-proof-survivor", 802);
        connection
            .execute(
                "INSERT INTO voice_profiles
                 (id,label,embedding_space,channel_domain,centroid,sample_count,
                  scorer_version,representative_kind,status,created_at,updated_at)
                 VALUES (1,'page-proof','voice-v1','mic',?1,2,2,
                         'medoid_trimmed_centroid','tentative',?2,?2)",
                params![unit_embedding(0), STAMP],
            )
            .unwrap();
        for (sample_id, observation_id) in [(1i64, 10_101i64), (2i64, 10_201i64)] {
            connection
                .execute(
                    "INSERT INTO voice_samples
                     (id,speaker_observation_id,voice_profile_id,embedding_space,
                      channel_domain,embedding,quality_score,accepted,eligibility,
                      outlier,created_at)
                     VALUES (?1,?2,1,'voice-v1','mic',?3,1.0,1,'enroll',0,?4)",
                    params![
                        sample_id,
                        observation_id,
                        unit_embedding(sample_id as usize),
                        STAMP
                    ],
                )
                .unwrap();
            connection
                .execute(
                    "INSERT INTO voice_sample_profile_assignments
                     (sample_id,profile_id,active,created_at) VALUES (?1,1,1,?2)",
                    params![sample_id, STAMP],
                )
                .unwrap();
        }
        let evidence = load_episode_delete_evidence(&connection, ACCOUNT, 1)
            .unwrap()
            .unwrap();
        let (preparation, _) = apply_preparation(&mut connection, evidence);
        let reservation = match load_episode_delete_work(&connection, ACCOUNT, 1)
            .unwrap()
            .unwrap()
        {
            EpisodeDeleteWork::Expand(plan) => plan,
            _ => panic!("voice reservation was not available"),
        };
        execute_prepared_for_owner(
            &mut connection,
            PreparedLogicalMutation::prepare(reservation).unwrap(),
        )
        .unwrap();
        let page = match load_episode_delete_work(&connection, ACCOUNT, 1)
            .unwrap()
            .unwrap()
        {
            EpisodeDeleteWork::Expand(plan) => plan,
            _ => panic!("voice page was not available"),
        };
        execute_prepared_for_owner(
            &mut connection,
            PreparedLogicalMutation::prepare(page).unwrap(),
        )
        .unwrap();
        connection
            .execute(
                "UPDATE episodes SET identity_refresh_status='ready' WHERE id=2",
                [],
            )
            .unwrap();
        connection
            .execute(
                "UPDATE archive_v3_wal_episode_delete_selectors
                 SET voice_scan_cursor=999999 WHERE selector_kind='voice'",
                [],
            )
            .unwrap();
        let wrapped = match load_episode_delete_work(&connection, ACCOUNT, 1)
            .unwrap()
            .unwrap()
        {
            EpisodeDeleteWork::Expand(plan) => plan,
            _ => panic!("stale voice episode was skipped by the wrapped cursor"),
        };
        assert!(matches!(
            &wrapped.action,
            EpisodeDeleteCleanupAction::AdvanceVoiceEpisodes(page)
                if page.episodes.len() == 1
                    && page.episodes[0].episode_id == 2
                    && page.episodes[0].identity_revision == 1
                    && page.episodes[0].prior_progress.is_some()
                    && page.expected_scan_cursor == 999999
        ));
        execute_prepared_for_owner(
            &mut connection,
            PreparedLogicalMutation::prepare(wrapped).unwrap(),
        )
        .unwrap();
        for expected_sequence in 2..18i64 {
            connection
                .execute(
                    "UPDATE episodes SET identity_refresh_status='ready' WHERE id=2",
                    [],
                )
                .unwrap();
            let next = match load_episode_delete_work(&connection, ACCOUNT, 1)
                .unwrap()
                .unwrap()
            {
                EpisodeDeleteWork::Expand(plan) => plan,
                _ => panic!("repeated stale voice episode was not requeued"),
            };
            assert!(matches!(
                &next.action,
                EpisodeDeleteCleanupAction::AdvanceVoiceEpisodes(page)
                    if page.expected_page_sequence == expected_sequence
                        && page.episodes.len() == 1
                        && page.episodes[0].episode_id == 2
                        && page.episodes[0].prior_progress.is_some()
            ));
            execute_prepared_for_owner(
                &mut connection,
                PreparedLogicalMutation::prepare(next).unwrap(),
            )
            .unwrap();
            assert_eq!(
                connection
                    .query_row(
                        "SELECT COUNT(*) FROM archive_v3_wal_episode_delete_progress",
                        [],
                        |row| row.get::<_, i64>(0),
                    )
                    .unwrap(),
                1,
                "lost-ack evidence must stay bounded to the current cleanup action"
            );
        }
        assert_eq!(
            connection
                .query_row(
                    "SELECT COUNT(*) FROM sqlite_schema
                     WHERE name='archive_v3_wal_episode_delete_voice_pages'",
                    [],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            0,
            "voice paging must not retain append-only page history"
        );
        assert_eq!(
            connection
                .query_row(
                    "SELECT COUNT(*) FROM archive_v3_wal_episode_delete_voice_progress",
                    [],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            1,
            "repeated requeues must overwrite one current row per affected episode"
        );
        apply_completion(&mut connection, preparation);
        assert_eq!(
            connection
                .query_row(
                    "SELECT COUNT(*) FROM speaker_observations WHERE id=10101",
                    [],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            0
        );
        assert!(load_episode_delete_receipt(&connection, ACCOUNT, 1)
            .unwrap()
            .is_some());
    }

    #[test]
    fn changed_affected_episode_refuses_voice_cleanup_before_mutation() {
        let (_directory, mut connection) = connection();
        insert_episode(&connection, 1);
        insert_episode(&connection, 2);
        insert_audio_utterance(&connection, 1, 101, "event-voice-stale-1", 81);
        insert_audio_utterance(&connection, 2, 201, "event-voice-stale-2", 82);
        let newer = "2026-08-23T12:00:00.000Z";
        connection
            .execute(
                "INSERT INTO voice_profiles
                 (id,label,embedding_space,channel_domain,centroid,sample_count,
                  scorer_version,representative_kind,status,created_at,updated_at)
                 VALUES (1,'shared-profile','voice-v1','mic',?1,2,2,
                         'medoid_trimmed_centroid','tentative',?2,?2)",
                params![unit_embedding(0), newer],
            )
            .unwrap();
        for (sample_id, observation_id, embedding) in [
            (1i64, 10_101i64, unit_embedding(0)),
            (2i64, 10_201i64, unit_embedding(1)),
        ] {
            connection
                .execute(
                    "INSERT INTO voice_samples
                     (id,speaker_observation_id,voice_profile_id,embedding_space,
                      channel_domain,embedding,quality_score,accepted,eligibility,
                      outlier,created_at)
                     VALUES (?1,?2,1,'voice-v1','mic',?3,1.0,1,'enroll',0,?4)",
                    params![sample_id, observation_id, embedding, newer],
                )
                .unwrap();
            connection
                .execute(
                    "INSERT INTO voice_sample_profile_assignments
                     (sample_id,profile_id,active,created_at) VALUES (?1,1,1,?2)",
                    params![sample_id, newer],
                )
                .unwrap();
        }
        connection
            .execute(
                "UPDATE voice_profiles SET medoid_sample_id=1 WHERE id=1",
                [],
            )
            .unwrap();
        connection
            .execute(
                "INSERT INTO voice_profile_representatives
                 (profile_id,channel_domain,centroid,sample_count,medoid_sample_id,
                  scorer_version,created_at,updated_at)
                 VALUES (1,'mic',?1,2,1,2,?2,?2)",
                params![unit_embedding(0), newer],
            )
            .unwrap();
        connection
            .execute(
                "INSERT INTO voice_profile_revisions
                 (profile_id,status,derivation_version,scorer_version,representative_kind,
                  centroid,sample_count,medoid_sample_id,reason_code,active,created_at)
                 VALUES (1,'tentative',1,2,'medoid_trimmed_centroid',?1,2,1,
                         'initial',1,?2)",
                params![unit_embedding(0), newer],
            )
            .unwrap();

        let evidence = load_episode_delete_evidence(&connection, ACCOUNT, 1)
            .unwrap()
            .unwrap();
        apply_preparation(&mut connection, evidence);
        let reservation = match load_episode_delete_work(&connection, ACCOUNT, 1)
            .unwrap()
            .unwrap()
        {
            EpisodeDeleteWork::Expand(plan) => plan,
            _ => panic!("voice capacity reservation was not available"),
        };
        execute_prepared_for_owner(
            &mut connection,
            PreparedLogicalMutation::prepare(reservation).unwrap(),
        )
        .unwrap();
        let expand = match load_episode_delete_work(&connection, ACCOUNT, 1)
            .unwrap()
            .unwrap()
        {
            EpisodeDeleteWork::Expand(plan) => plan,
            _ => panic!("voice selector did not expand first"),
        };
        connection
            .execute("UPDATE episodes SET title='changed' WHERE id=2", [])
            .unwrap();
        let error = match execute_prepared_for_owner(
            &mut connection,
            PreparedLogicalMutation::prepare(expand).unwrap(),
        ) {
            Ok(_) => panic!("stale affected episode unexpectedly applied"),
            Err(error) => error,
        };
        assert_eq!(error, WalIdempotencyError::Precondition);
        assert_eq!(
            connection
                .query_row(
                    "SELECT COUNT(*) FROM speaker_observations WHERE id=10101",
                    [],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            1
        );
        assert_eq!(
            connection
                .query_row(
                    "SELECT sample_count FROM voice_profiles WHERE id=1",
                    [],
                    |row| { row.get::<_, i64>(0) }
                )
                .unwrap(),
            2
        );

        connection
            .execute(
                "UPDATE episodes SET identity_revision=?1 WHERE id=2",
                [i64::MAX],
            )
            .unwrap();
        let exhausted = match load_episode_delete_work(&connection, ACCOUNT, 1) {
            Ok(_) => panic!("an exhausted affected-episode counter produced a purge plan"),
            Err(error) => error,
        };
        assert_eq!(exhausted, WalIdempotencyError::Malformed);
        let transaction = connection.transaction().unwrap();
        assert!(crate::episodes::purge_speaker_observations_transaction_at(
            &transaction,
            &[10_101],
            &[2],
            newer,
        )
        .is_err());
        transaction.rollback().unwrap();
        assert_eq!(
            connection
                .query_row(
                    "SELECT identity_revision,typeof(identity_revision) FROM episodes WHERE id=2",
                    [],
                    |row| Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?)),
                )
                .unwrap(),
            (i64::MAX, "integer".to_owned())
        );
        assert_eq!(
            connection
                .query_row(
                    "SELECT COUNT(*) FROM speaker_observations WHERE id=10101",
                    [],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            1
        );
    }

    #[test]
    fn legacy_purge_backfills_voice_lineage_before_choosing_its_mutation_stamp() {
        let (_directory, mut connection) = connection();
        insert_episode(&connection, 1);
        insert_audio_utterance(&connection, 1, 101, "event-legacy-voice", 51);
        connection
            .execute(
                "INSERT INTO voice_profiles
                 (id,label,embedding_space,channel_domain,centroid,sample_count,
                  scorer_version,representative_kind,status,created_at,updated_at)
                 VALUES (1,'legacy-profile','voice-v1','mic',?1,1,2,
                         'medoid_trimmed_centroid','tentative',?2,?2)",
                params![unit_embedding(0), STAMP],
            )
            .unwrap();
        connection
            .execute(
                "INSERT INTO voice_samples
                 (id,speaker_observation_id,voice_profile_id,embedding_space,
                  channel_domain,embedding,quality_score,accepted,eligibility,
                  outlier,created_at)
                 VALUES (1,10101,1,'voice-v1','mic',?1,1.0,1,'enroll',0,?2)",
                params![unit_embedding(0), STAMP],
            )
            .unwrap();

        let transaction = connection.transaction().unwrap();
        crate::episodes::purge_episode_transaction(&transaction, 1)
            .unwrap()
            .unwrap();
        transaction.commit().unwrap();

        let revisions = connection
            .prepare(
                "SELECT reason_code,created_at FROM voice_profile_revisions
                 WHERE profile_id=1 ORDER BY id",
            )
            .unwrap()
            .query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })
            .unwrap()
            .collect::<std::result::Result<Vec<_>, _>>()
            .unwrap();
        assert!(revisions.len() >= 2);
        assert_eq!(revisions[0].0, "schema_backfill");
        assert!(
            revisions.windows(2).all(|pair| pair[0].1 <= pair[1].1),
            "a post-delete revision must never predate its backfilled predecessor"
        );
    }

    #[test]
    fn shared_speaker_observation_remains_bound_to_the_surviving_utterance() {
        let (_directory, mut connection) = connection();
        insert_episode(&connection, 1);
        insert_episode(&connection, 2);
        insert_audio_utterance(&connection, 1, 101, "event-shared-observation", 41);
        insert_audio_utterance(&connection, 2, 201, "event-other", 42);
        connection
            .execute(
                "UPDATE utterances SET speaker_observation_id=10101 WHERE id=201",
                [],
            )
            .unwrap();

        let evidence = load_episode_delete_evidence(&connection, ACCOUNT, 1)
            .unwrap()
            .unwrap();
        assert!(evidence.selectors.is_empty());
        let (preparation, _) = apply_preparation(&mut connection, evidence);
        apply_completion(&mut connection, preparation);

        assert_eq!(
            connection
                .query_row(
                    "SELECT speaker_observation_id FROM utterances WHERE id=201",
                    [],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            10101
        );
        assert_eq!(
            connection
                .query_row(
                    "SELECT COUNT(*) FROM speaker_observations WHERE id=10101",
                    [],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            1
        );
        assert_eq!(
            connection
                .query_row(
                    "SELECT COUNT(*) FROM capture_events WHERE event_id='event-shared-observation'",
                    [],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            1
        );
    }

    #[test]
    fn provider_cleanup_progress_replays_once_and_reopens_after_the_exact_prefix() {
        let (directory, mut connection) = connection();
        let path = directory.path().join("archive.sqlite");
        seed(&connection);
        let evidence = load_episode_delete_evidence(&connection, ACCOUNT, 1)
            .unwrap()
            .unwrap();
        let (preparation, _) = apply_preparation(&mut connection, evidence);

        let expand = match load_episode_delete_work(&connection, ACCOUNT, 1)
            .unwrap()
            .unwrap()
        {
            EpisodeDeleteWork::Expand(plan) => plan,
            _ => panic!("first bounded unit was not selector expansion"),
        };
        execute_prepared_for_owner(
            &mut connection,
            PreparedLogicalMutation::prepare(expand).unwrap(),
        )
        .unwrap();
        let item = match load_episode_delete_work(&connection, ACCOUNT, 1)
            .unwrap()
            .unwrap()
        {
            EpisodeDeleteWork::Provider(item) => item,
            _ => panic!("expanded retained object was not provider work"),
        };
        let first_key = cleanup_object_key(item.target()).to_owned();
        let first = execute_prepared_for_owner(
            &mut connection,
            PreparedLogicalMutation::prepare(EpisodeDeleteCleanupPlan::new(item.clone()).unwrap())
                .unwrap(),
        )
        .unwrap();
        assert_eq!(first.disposition(), LogicalMutationDisposition::Applied);
        let replay = execute_prepared_for_owner(
            &mut connection,
            PreparedLogicalMutation::prepare(EpisodeDeleteCleanupPlan::new(item).unwrap()).unwrap(),
        )
        .unwrap();
        assert_eq!(replay.disposition(), LogicalMutationDisposition::Replayed);

        drop(connection);
        let mut reopened = Connection::open(path).unwrap();
        reopened.execute_batch("PRAGMA foreign_keys=ON;").unwrap();
        let next = load_episode_delete_work(&reopened, ACCOUNT, 1)
            .unwrap()
            .unwrap();
        assert!(
            !matches!(
                &next,
                EpisodeDeleteWork::Provider(next_item)
                    if cleanup_object_key(next_item.target()) == first_key
            ),
            "a durable cleanup prefix must not reissue provider work after reopen"
        );
        apply_completion(&mut reopened, preparation);
    }

    #[test]
    fn one_legal_audio_window_expands_in_one_bounded_unit() {
        let (_directory, mut connection) = connection();
        insert_episode(&connection, 1);
        insert_audio_utterance(&connection, 1, 101, "event-audio-0", 100);
        for index in 1..128i64 {
            let event_id = format!("event-audio-{index}");
            insert_capture(
                &connection,
                &event_id,
                100 + index,
                &format!("state-{index}"),
            );
            connection
                .execute(
                    "INSERT INTO speaker_observation_sources
                     (speaker_observation_id,event_id,window_start_ms,window_end_ms,
                      event_start_ms,event_end_ms) VALUES (10101,?1,0,1000,0,1000)",
                    [event_id],
                )
                .unwrap();
        }
        let evidence = load_episode_delete_evidence(&connection, ACCOUNT, 1)
            .unwrap()
            .unwrap();
        assert_eq!(evidence.selectors.len(), 1);
        let (preparation, _) = apply_preparation(&mut connection, evidence);
        let reservation = match load_episode_delete_work(&connection, ACCOUNT, 1)
            .unwrap()
            .unwrap()
        {
            EpisodeDeleteWork::Expand(plan) => plan,
            _ => panic!("legal audio window did not reserve cleanup capacity"),
        };
        execute_prepared_for_owner(
            &mut connection,
            PreparedLogicalMutation::prepare(reservation).unwrap(),
        )
        .unwrap();
        let expand = match load_episode_delete_work(&connection, ACCOUNT, 1)
            .unwrap()
            .unwrap()
        {
            EpisodeDeleteWork::Expand(plan) => plan,
            _ => panic!("legal audio window was not deferred to a selector"),
        };
        match &expand.action {
            EpisodeDeleteCleanupAction::Expand(expansion) => {
                assert_eq!(expansion.event_ids.len(), 128);
                assert_eq!(expansion.media.len(), 128);
            }
            _ => unreachable!(),
        }
        execute_prepared_for_owner(
            &mut connection,
            PreparedLogicalMutation::prepare(expand).unwrap(),
        )
        .unwrap();
        apply_completion(&mut connection, preparation);
        assert_eq!(
            connection
                .query_row("SELECT COUNT(*) FROM capture_events", [], |row| {
                    row.get::<_, i64>(0)
                })
                .unwrap(),
            0
        );
    }

    #[test]
    fn every_initial_cascade_family_is_an_exact_precondition() {
        for mutation in ["screen-job", "brief", "delivery", "duplicate-survivor"] {
            let (_directory, mut connection) = connection();
            seed(&connection);
            connection
                .execute(
                    "INSERT INTO screen_observation_jobs
                     (screenshot_id,input_revision,observation_version,state,updated_at)
                     VALUES (11,'revision',1,'ready',?1)",
                    [STAMP],
                )
                .unwrap();
            connection
                .execute(
                    "INSERT INTO episode_final_briefs
                     (episode_id,overview,decisions,action_items,important_links,open_questions)
                     VALUES (1,'overview','[]','[]','[]','[]')",
                    [],
                )
                .unwrap();
            connection
                .execute(
                    "INSERT INTO webhook_deliveries
                     (episode_id,subscription_id,delivery_version,event_id,state,created_at,updated_at)
                     VALUES (1,'subscription',1,'delivery-event','failed',?1,?1)",
                    [STAMP],
                )
                .unwrap();
            connection
                .execute(
                    "INSERT INTO screenshots (id,captured_at,ocr_text,duplicate_of_id)
                     VALUES (31,?1,'survivor',11)",
                    [STAMP],
                )
                .unwrap();
            let evidence = load_episode_delete_evidence(&connection, ACCOUNT, 1)
                .unwrap()
                .unwrap();
            match mutation {
                "screen-job" => {
                    connection
                        .execute(
                            "UPDATE screen_observation_jobs SET error_code='changed' WHERE screenshot_id=11",
                            [],
                        )
                        .unwrap();
                }
                "brief" => {
                    connection
                        .execute(
                            "UPDATE episode_final_briefs SET overview='changed' WHERE episode_id=1",
                            [],
                        )
                        .unwrap();
                }
                "delivery" => {
                    connection
                        .execute(
                            "UPDATE webhook_deliveries SET error_code='changed' WHERE event_id='delivery-event'",
                            [],
                        )
                        .unwrap();
                }
                "duplicate-survivor" => {
                    connection
                        .execute("UPDATE screenshots SET ocr_text='changed' WHERE id=31", [])
                        .unwrap();
                }
                _ => unreachable!(),
            }
            let error = match execute_prepared_for_owner(
                &mut connection,
                PreparedLogicalMutation::prepare(
                    EpisodeDeletePreparePlan::new(ACCOUNT.into(), evidence).unwrap(),
                )
                .unwrap(),
            ) {
                Ok(_) => panic!("{mutation} mutation unexpectedly applied"),
                Err(error) => error,
            };
            assert_eq!(error, WalIdempotencyError::Precondition, "{mutation}");
            assert_eq!(
                connection
                    .query_row("SELECT COUNT(*) FROM episodes WHERE id=1", [], |row| {
                        row.get::<_, i64>(0)
                    })
                    .unwrap(),
                1
            );
        }
    }

    #[test]
    fn retained_ledger_never_contains_legacy_browser_title_url_or_tabs() {
        let (_directory, mut connection) = connection();
        seed(&connection);
        insert_legacy_browser_snapshot(&connection, "legacy-sensitive", &[11]);
        let evidence = load_episode_delete_evidence(&connection, ACCOUNT, 1)
            .unwrap()
            .unwrap();
        let (preparation, _) = apply_preparation(&mut connection, evidence);
        apply_completion(&mut connection, preparation);
        let mut statement = connection
            .prepare(
                "SELECT CAST(preparation_operation_id AS TEXT),
                        CAST(completion_operation_id AS TEXT),CAST(episode_id AS TEXT),
                        CAST(prepare_result_bytes AS TEXT),
                        CAST(completion_result_bytes AS TEXT),
                        CAST(predecessor_commitment AS TEXT),CAST(receipt_commitment AS TEXT),
                        CAST(cleanup_commitment AS TEXT)
                 FROM archive_v3_wal_episode_delete_operations",
            )
            .unwrap();
        let row = statement
            .query_row([], |row| {
                Ok((0..8)
                    .map(|index| row.get::<_, String>(index).unwrap_or_default())
                    .collect::<Vec<_>>()
                    .join("|"))
            })
            .unwrap();
        let sources = connection
            .prepare(
                "SELECT group_concat(source_key,'|')
                 FROM archive_v3_wal_episode_delete_sources",
            )
            .unwrap()
            .query_row([], |row| row.get::<_, Option<String>>(0))
            .unwrap()
            .unwrap_or_default();
        let cleanup = connection
            .prepare(
                "SELECT group_concat(object_key||COALESCE(sha256,''),'|')
                 FROM archive_v3_wal_episode_delete_cleanup",
            )
            .unwrap()
            .query_row([], |row| row.get::<_, Option<String>>(0))
            .unwrap()
            .unwrap_or_default();
        let retained = format!("{row}|{sources}|{cleanup}");
        for forbidden in [
            "Sensitive title",
            "https://example.com/private",
            "example.com",
        ] {
            assert!(!retained.contains(forbidden));
        }
    }

    #[test]
    fn selector_expansion_reserves_and_releases_exact_global_capacity() {
        for exhausted_column in ["source_count", "source_bytes"] {
            let (_directory, mut connection) = connection();
            insert_episode(&connection, 1);
            insert_capture(&connection, "capacity-event", 71, "capacity-state");
            insert_screen_member(&connection, 1, 711, "capacity-event");
            let evidence = load_episode_delete_evidence(&connection, ACCOUNT, 1)
                .unwrap()
                .unwrap();
            let (preparation, _) = apply_preparation(&mut connection, evidence);
            let baseline = load_ledger_state(&connection).unwrap();
            connection
                .execute(
                    &format!(
                        "UPDATE archive_v3_wal_episode_delete_state SET {exhausted_column}=?1"
                    ),
                    [i64::try_from(if exhausted_column == "source_count" {
                        MAX_SOURCE_ROWS
                    } else {
                        MAX_SOURCE_BYTES
                    })
                    .unwrap()],
                )
                .unwrap();
            let expand = match load_episode_delete_work(&connection, ACCOUNT, 1)
                .unwrap()
                .unwrap()
            {
                EpisodeDeleteWork::Expand(plan) => plan,
                _ => panic!("first work was not expansion"),
            };
            let error = match execute_prepared_for_owner(
                &mut connection,
                PreparedLogicalMutation::prepare(expand).unwrap(),
            ) {
                Ok(_) => panic!("capacity-exhausted expansion unexpectedly applied"),
                Err(error) => error,
            };
            assert_eq!(error, WalIdempotencyError::Limit);
            assert_eq!(
                connection
                    .query_row(
                        "SELECT COUNT(*) FROM capture_events WHERE event_id='capacity-event'",
                        [],
                        |row| row.get::<_, i64>(0),
                    )
                    .unwrap(),
                1,
                "capacity refusal must precede local purge"
            );
            connection
                .execute(
                    "UPDATE archive_v3_wal_episode_delete_state
                     SET source_count=?1,source_bytes=?2",
                    params![
                        i64::try_from(baseline.source_count).unwrap(),
                        i64::try_from(baseline.source_bytes).unwrap(),
                    ],
                )
                .unwrap();
            apply_completion(&mut connection, preparation);
            let final_state = load_ledger_state(&connection).unwrap();
            assert_eq!(final_state.source_count, baseline.source_count);
            assert_eq!(final_state.source_bytes, baseline.source_bytes);
        }
    }

    #[test]
    fn voice_capacity_is_reserved_before_identity_or_provider_mutation() {
        for exhausted_column in ["source_count", "source_bytes"] {
            let (_directory, mut connection) = connection();
            insert_episode(&connection, 1);
            insert_episode(&connection, 2);
            insert_audio_utterance(&connection, 1, 101, "voice-capacity-target", 901);
            insert_audio_utterance(&connection, 2, 201, "voice-capacity-survivor", 902);
            connection
                .execute(
                    "INSERT INTO voice_profiles
                     (id,label,embedding_space,channel_domain,centroid,sample_count,
                      scorer_version,representative_kind,medoid_sample_id,status,created_at,updated_at)
                     VALUES (1,'capacity-profile','voice-v1','mic',?1,2,2,
                             'medoid_trimmed_centroid',1,'tentative',?2,?2)",
                    params![unit_embedding(0), STAMP],
                )
                .unwrap();
            for (sample_id, observation_id) in [(1i64, 10_101i64), (2i64, 10_201i64)] {
                connection
                    .execute(
                        "INSERT INTO voice_samples
                         (id,speaker_observation_id,voice_profile_id,embedding_space,
                          channel_domain,embedding,quality_score,accepted,eligibility,
                          outlier,created_at)
                         VALUES (?1,?2,1,'voice-v1','mic',?3,1.0,1,'enroll',0,?4)",
                        params![
                            sample_id,
                            observation_id,
                            unit_embedding(sample_id as usize),
                            STAMP
                        ],
                    )
                    .unwrap();
            }
            let evidence = load_episode_delete_evidence(&connection, ACCOUNT, 1)
                .unwrap()
                .unwrap();
            let (preparation, _) = apply_preparation(&mut connection, evidence);
            let baseline = load_ledger_state(&connection).unwrap();
            let exhausted = if exhausted_column == "source_count" {
                MAX_SOURCE_ROWS - VOICE_RESERVED_CLEANUP_ROWS + 1
            } else {
                MAX_SOURCE_BYTES - VOICE_RESERVED_CLEANUP_BYTES + 1
            };
            connection
                .execute(
                    &format!(
                        "UPDATE archive_v3_wal_episode_delete_state SET {exhausted_column}=?1"
                    ),
                    [i64::try_from(exhausted).unwrap()],
                )
                .unwrap();
            let reservation = match load_episode_delete_work(&connection, ACCOUNT, 1)
                .unwrap()
                .unwrap()
            {
                EpisodeDeleteWork::Expand(plan) => plan,
                _ => panic!("voice capacity reservation was not first"),
            };
            assert!(matches!(
                &reservation.action,
                EpisodeDeleteCleanupAction::ReserveVoiceCapacity(_)
            ));
            let error = match execute_prepared_for_owner(
                &mut connection,
                PreparedLogicalMutation::prepare(reservation).unwrap(),
            ) {
                Ok(_) => panic!("capacity-exhausted voice reservation unexpectedly applied"),
                Err(error) => error,
            };
            assert_eq!(error, WalIdempotencyError::Limit);
            assert_eq!(
                connection
                    .query_row(
                        "SELECT identity_revision,identity_refresh_status FROM episodes WHERE id=2",
                        [],
                        |row| Ok((row.get::<_, i64>(0)?, row.get::<_, Option<String>>(1)?)),
                    )
                    .unwrap(),
                (0, None),
                "capacity refusal must precede identity invalidation"
            );
            assert_eq!(
                connection
                    .query_row(
                        "SELECT reserved_cleanup_rows,reserved_cleanup_bytes,voice_page_sequence
                         FROM archive_v3_wal_episode_delete_selectors WHERE selector_kind='voice'",
                        [],
                        |row| {
                            Ok((
                                row.get::<_, i64>(0)?,
                                row.get::<_, i64>(1)?,
                                row.get::<_, i64>(2)?,
                            ))
                        },
                    )
                    .unwrap(),
                (0, 0, 0),
                "failed reservation must not leave partial selector state"
            );
            assert_eq!(
                connection
                    .query_row(
                        "SELECT COUNT(*) FROM capture_events WHERE event_id='voice-capacity-target'",
                        [],
                        |row| row.get::<_, i64>(0),
                    )
                    .unwrap(),
                1,
                "capacity refusal must precede provider-backed local purge"
            );
            connection
                .execute(
                    "UPDATE archive_v3_wal_episode_delete_state
                     SET source_count=?1,source_bytes=?2",
                    params![
                        i64::try_from(baseline.source_count).unwrap(),
                        i64::try_from(baseline.source_bytes).unwrap(),
                    ],
                )
                .unwrap();
            apply_completion(&mut connection, preparation);
            let final_state = load_ledger_state(&connection).unwrap();
            assert_eq!(final_state.source_count, baseline.source_count);
            assert_eq!(final_state.source_bytes, baseline.source_bytes);
        }
    }

    #[test]
    fn voice_progress_is_globally_charged_before_page_mutation() {
        let (_directory, mut connection) = connection();
        insert_episode(&connection, 1);
        insert_episode(&connection, 2);
        insert_audio_utterance(&connection, 1, 101, "voice-progress-target", 911);
        insert_audio_utterance(&connection, 2, 201, "voice-progress-survivor", 912);
        connection
            .execute(
                "INSERT INTO voice_profiles
                 (id,label,embedding_space,channel_domain,centroid,sample_count,
                  scorer_version,representative_kind,medoid_sample_id,status,created_at,updated_at)
                 VALUES (1,'progress-profile','voice-v1','mic',?1,2,2,
                         'medoid_trimmed_centroid',1,'tentative',?2,?2)",
                params![unit_embedding(0), STAMP],
            )
            .unwrap();
        for (sample_id, observation_id) in [(1i64, 10_101i64), (2i64, 10_201i64)] {
            connection
                .execute(
                    "INSERT INTO voice_samples
                     (id,speaker_observation_id,voice_profile_id,embedding_space,
                      channel_domain,embedding,quality_score,accepted,eligibility,
                      outlier,created_at)
                     VALUES (?1,?2,1,'voice-v1','mic',?3,1.0,1,'enroll',0,?4)",
                    params![
                        sample_id,
                        observation_id,
                        unit_embedding(sample_id as usize),
                        STAMP
                    ],
                )
                .unwrap();
            connection
                .execute(
                    "INSERT INTO voice_sample_profile_assignments
                     (sample_id,profile_id,active,created_at) VALUES (?1,1,1,?2)",
                    params![sample_id, STAMP],
                )
                .unwrap();
        }
        let evidence = load_episode_delete_evidence(&connection, ACCOUNT, 1)
            .unwrap()
            .unwrap();
        let (preparation, _) = apply_preparation(&mut connection, evidence);
        let reservation = match load_episode_delete_work(&connection, ACCOUNT, 1)
            .unwrap()
            .unwrap()
        {
            EpisodeDeleteWork::Expand(plan) => plan,
            _ => panic!("voice capacity reservation was not available"),
        };
        execute_prepared_for_owner(
            &mut connection,
            PreparedLogicalMutation::prepare(reservation).unwrap(),
        )
        .unwrap();
        let reserved_state = load_ledger_state(&connection).unwrap();
        let page = match load_episode_delete_work(&connection, ACCOUNT, 1)
            .unwrap()
            .unwrap()
        {
            EpisodeDeleteWork::Expand(plan) => plan,
            _ => panic!("voice invalidation page was not available"),
        };
        assert!(matches!(
            &page.action,
            EpisodeDeleteCleanupAction::AdvanceVoiceEpisodes(page)
                if page.expected_progress_rows == 0 && page.episodes.len() == 1
        ));
        for exhausted_column in ["source_count", "source_bytes"] {
            connection
                .execute(
                    &format!(
                        "UPDATE archive_v3_wal_episode_delete_state SET {exhausted_column}=?1"
                    ),
                    [i64::try_from(if exhausted_column == "source_count" {
                        MAX_SOURCE_ROWS
                    } else {
                        MAX_SOURCE_BYTES
                    })
                    .unwrap()],
                )
                .unwrap();
            let page = match load_episode_delete_work(&connection, ACCOUNT, 1)
                .unwrap()
                .unwrap()
            {
                EpisodeDeleteWork::Expand(plan) => plan,
                _ => panic!("voice invalidation page disappeared"),
            };
            let error = match execute_prepared_for_owner(
                &mut connection,
                PreparedLogicalMutation::prepare(page).unwrap(),
            ) {
                Ok(_) => panic!("progress-capacity-exhausted page unexpectedly applied"),
                Err(error) => error,
            };
            assert_eq!(error, WalIdempotencyError::Limit);
            assert_eq!(
                connection
                    .query_row(
                        "SELECT identity_revision,identity_refresh_status FROM episodes WHERE id=2",
                        [],
                        |row| Ok((row.get::<_, i64>(0)?, row.get::<_, Option<String>>(1)?)),
                    )
                    .unwrap(),
                (0, None),
                "global progress-capacity refusal must precede identity mutation"
            );
            assert_eq!(
                connection
                    .query_row(
                        "SELECT voice_progress_rows FROM archive_v3_wal_episode_delete_selectors
                         WHERE selector_kind='voice'",
                        [],
                        |row| row.get::<_, i64>(0),
                    )
                    .unwrap(),
                0
            );
            assert_eq!(
                connection
                    .query_row(
                        "SELECT COUNT(*) FROM archive_v3_wal_episode_delete_voice_progress",
                        [],
                        |row| row.get::<_, i64>(0),
                    )
                    .unwrap(),
                0
            );
            connection
                .execute(
                    "UPDATE archive_v3_wal_episode_delete_state
                     SET source_count=?1,source_bytes=?2",
                    params![
                        i64::try_from(reserved_state.source_count).unwrap(),
                        i64::try_from(reserved_state.source_bytes).unwrap(),
                    ],
                )
                .unwrap();
        }
        let page = match load_episode_delete_work(&connection, ACCOUNT, 1)
            .unwrap()
            .unwrap()
        {
            EpisodeDeleteWork::Expand(plan) => plan,
            _ => panic!("voice invalidation page disappeared after restoring capacity"),
        };
        execute_prepared_for_owner(
            &mut connection,
            PreparedLogicalMutation::prepare(page).unwrap(),
        )
        .unwrap();
        let charged_state = load_ledger_state(&connection).unwrap();
        assert_eq!(charged_state.source_count, reserved_state.source_count + 1);
        assert_eq!(
            charged_state.source_bytes,
            reserved_state.source_bytes + VOICE_PROGRESS_ROW_BYTES
        );
        assert_eq!(
            connection
                .query_row(
                    "SELECT voice_progress_rows FROM archive_v3_wal_episode_delete_selectors
                     WHERE selector_kind='voice'",
                    [],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            1
        );
        apply_completion(&mut connection, preparation);
        let released_state = load_ledger_state(&connection).unwrap();
        assert_eq!(
            released_state.source_count,
            reserved_state.source_count - VOICE_RESERVED_CLEANUP_ROWS
        );
        assert_eq!(
            released_state.source_bytes,
            reserved_state.source_bytes - VOICE_RESERVED_CLEANUP_BYTES
        );
    }

    #[test]
    fn cleanup_inventory_and_selector_state_cannot_be_forged_complete() {
        for mutation in ["missing", "reordered", "state-flip"] {
            let (_directory, mut connection) = connection();
            insert_episode(&connection, 1);
            insert_capture(&connection, "commit-event", 72, "commit-state");
            insert_screen_member(&connection, 1, 721, "commit-event");
            let evidence = load_episode_delete_evidence(&connection, ACCOUNT, 1)
                .unwrap()
                .unwrap();
            let (preparation, _) = apply_preparation(&mut connection, evidence);
            let expand = match load_episode_delete_work(&connection, ACCOUNT, 1)
                .unwrap()
                .unwrap()
            {
                EpisodeDeleteWork::Expand(plan) => plan,
                _ => panic!("first work was not expansion"),
            };
            execute_prepared_for_owner(
                &mut connection,
                PreparedLogicalMutation::prepare(expand).unwrap(),
            )
            .unwrap();
            match mutation {
                "missing" => {
                    connection
                        .execute("DELETE FROM archive_v3_wal_episode_delete_cleanup", [])
                        .unwrap();
                }
                "reordered" => {
                    connection
                        .execute(
                            "UPDATE archive_v3_wal_episode_delete_cleanup SET ordinal=1",
                            [],
                        )
                        .unwrap();
                }
                "state-flip" => {
                    connection
                        .execute("DELETE FROM archive_v3_wal_episode_delete_cleanup", [])
                        .unwrap();
                    connection
                        .execute(
                            "UPDATE archive_v3_wal_episode_delete_selectors
                             SET selector_state='complete',cleanup_count=0,settled_count=0,
                                 cleanup_rows=0,cleanup_bytes=0,finish_request_fingerprint=NULL",
                            [],
                        )
                        .unwrap();
                }
                _ => unreachable!(),
            }
            assert!(
                load_episode_delete_work(&connection, ACCOUNT, 1).is_err(),
                "{mutation}"
            );
            assert!(load_episode_delete_receipt(&connection, ACCOUNT, 1)
                .unwrap()
                .is_none());
            assert_eq!(preparation.receipt.episode_id, 1);
        }
    }

    #[test]
    fn a_surviving_canonical_child_preserves_its_parent_and_provider_object() {
        let (_directory, mut connection) = connection();
        insert_episode(&connection, 1);
        insert_episode(&connection, 2);
        insert_capture(&connection, "canonical-parent", 73, "parent-state");
        insert_capture(&connection, "canonical-child", 74, "child-state");
        connection
            .execute(
                "UPDATE capture_events SET canonical_event_id='canonical-parent'
                 WHERE event_id='canonical-child'",
                [],
            )
            .unwrap();
        insert_screen_member(&connection, 1, 731, "canonical-parent");
        insert_screen_member(&connection, 2, 741, "canonical-child");
        let evidence = load_episode_delete_evidence(&connection, ACCOUNT, 1)
            .unwrap()
            .unwrap();
        let (preparation, _) = apply_preparation(&mut connection, evidence);
        apply_completion(&mut connection, preparation);
        assert_eq!(
            connection
                .query_row(
                    "SELECT COUNT(*) FROM capture_events
                     WHERE event_id IN ('canonical-parent','canonical-child')",
                    [],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            2
        );
        assert_eq!(
            connection
                .query_row(
                    "SELECT COUNT(*) FROM media_objects
                     WHERE event_id IN ('canonical-parent','canonical-child')",
                    [],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            2
        );
    }

    #[test]
    fn null_cloud_voice_references_obey_the_same_sharing_boundary() {
        {
            let (_directory, connection) = connection();
            insert_episode(&connection, 1);
            insert_episode(&connection, 2);
            insert_audio_utterance(&connection, 1, 101, "same-turn-event", 76);
            connection
                .execute(
                    "UPDATE utterances SET speaker_observation_id=NULL,
                     source_key='cloud-v2:same-turn-event:turn-101' WHERE id=101",
                    [],
                )
                .unwrap();
            connection
                .execute(
                    "INSERT INTO audio_segments
                     (id,started_at,ended_at,duration_seconds,source_type,audio_format,transcription_status)
                     VALUES (20201,?1,?1,1.0,'mic','m4a','ready')",
                    [STAMP],
                )
                .unwrap();
            assert!(
                connection
                    .execute(
                        "INSERT INTO utterances
                     (id,audio_segment_id,start_offset_seconds,end_offset_seconds,text,
                      speaker_label,source_key,speaker_observation_id)
                     VALUES (201,20201,0.0,1.0,'survivor','speaker',
                             'cloud-v2:same-turn-event:turn-101',NULL)",
                        [],
                    )
                    .is_err(),
                "the UNIQUE source-key contract forbids two NULL rows for one turn"
            );
        }
        for survivor_kind in ["explicit", "different-null", "none"] {
            let (_directory, mut connection) = connection();
            insert_episode(&connection, 1);
            insert_episode(&connection, 2);
            insert_audio_utterance(&connection, 1, 101, "null-event", 75);
            connection
                .execute(
                    "UPDATE utterances SET speaker_observation_id=NULL,
                     source_key='cloud-v2:null-event:turn-101' WHERE id=101",
                    [],
                )
                .unwrap();
            if survivor_kind != "none" {
                connection
                    .execute(
                        "INSERT INTO audio_segments
                         (id,started_at,ended_at,duration_seconds,source_type,audio_format,transcription_status)
                         VALUES (20201,?1,?1,1.0,'mic','m4a','ready')",
                        [STAMP],
                    )
                    .unwrap();
                let (source, observation) = match survivor_kind {
                    "explicit" => ("audio:explicit-survivor", Some(10101i64)),
                    "different-null" => ("cloud-v2:null-event:other-turn", None),
                    _ => unreachable!(),
                };
                connection
                    .execute(
                        "INSERT INTO utterances
                         (id,audio_segment_id,start_offset_seconds,end_offset_seconds,text,
                          speaker_label,source_key,speaker_observation_id)
                         VALUES (201,20201,0.0,1.0,'survivor','speaker',?1,?2)",
                        params![source, observation],
                    )
                    .unwrap();
                connection
                    .execute(
                        "INSERT INTO episode_members (episode_id,record_type,record_id)
                         VALUES (2,'utterance',201)",
                        [],
                    )
                    .unwrap();
            }
            let evidence = load_episode_delete_evidence(&connection, ACCOUNT, 1)
                .unwrap()
                .unwrap();
            let (preparation, _) = apply_preparation(&mut connection, evidence);
            apply_completion(&mut connection, preparation);
            let retained = connection
                .query_row(
                    "SELECT COUNT(*) FROM capture_events WHERE event_id='null-event'",
                    [],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap();
            assert_eq!(
                retained,
                i64::from(survivor_kind != "none"),
                "{survivor_kind}"
            );
        }
    }

    #[test]
    fn durable_resume_cursor_rotates_past_oldest_jobs_after_reopen() {
        let (directory, mut connection) = connection();
        let path = directory.path().join("archive.sqlite");
        for episode_id in 1..=6 {
            insert_episode(&connection, episode_id);
            let evidence = load_episode_delete_evidence(&connection, ACCOUNT, episode_id)
                .unwrap()
                .unwrap();
            apply_preparation(&mut connection, evidence);
        }
        let first = load_pending_episode_delete_batch(&connection, ACCOUNT)
            .unwrap()
            .unwrap();
        assert_eq!(first.episode_ids, vec![1, 2, 3, 4]);
        execute_prepared_for_owner(
            &mut connection,
            PreparedLogicalMutation::prepare(first.plan).unwrap(),
        )
        .unwrap();
        drop(connection);
        let reopened = Connection::open(path).unwrap();
        reopened.execute_batch("PRAGMA foreign_keys=ON;").unwrap();
        let second = load_pending_episode_delete_batch(&reopened, ACCOUNT)
            .unwrap()
            .unwrap();
        assert_eq!(second.episode_ids, vec![5, 6, 1, 2]);
    }
}
