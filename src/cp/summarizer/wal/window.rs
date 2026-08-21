//! Episode window upsert as a sealed WAL plan (ADR-0022 F8) — the product
//! core: the summarizer's episode writes for a WAL-authoritative user.
//!
//! **Identity** is the full window commitment: `SUBTYPE ‖ user ‖ window_seq`
//! over a hash of the window bounds, the effective cutoff, the ordered
//! normalized episode vector (final post-merge target values plus each
//! UPDATE arm's full predecessor tuple), the commit stamp, and the
//! `sqlite_sequence` pin. `window_seq` is the **pre-state** value that this
//! plan's own `apply()` CAS-advances, so one application is admitted per
//! window and a `Precondition` leaves the sequence unchanged — the next run
//! re-derives with a fresh batch commitment, a new operation, never a wedge.
//!
//! **Episode id allocation** keeps `AUTOINCREMENT`: `apply()` asserts the
//! carried `sqlite_sequence` pin, INSERTs plainly, and records each
//! `(window_seq, ordinal) → id` in the assignment table inside the same
//! transaction. The pin cannot be invalidated concurrently — this plan's
//! owner is the sole production episode inserter, the summarizer is
//! serialized, and `AUTOINCREMENT` never decreases, so deletes are harmless.
//! If the pin *is* stale, a second summarizer run landed and the window is
//! genuinely stale: `Precondition` is the correct answer. With the pin
//! asserted, each new id is exactly `pin + inserts_so_far + 1`; `apply()`
//! verifies that equality and treats a miss as `Corrupt`.
//!
//! **The Control/archive cursor split** is closed by the progress row's
//! `effective_cutoff`, recorded here inside `apply()`: the owner starts the
//! next window from `max(control.summarized_until, archive cutoff)`, so an
//! archive commit whose Control write was lost moves the cursor forward
//! instead of re-summarizing the range into duplicate episodes. A
//! member-exclusivity precondition is deliberately NOT used — it would
//! convert exactly that duplicate case into a permanent wedge.
//!
//! **Excluded from `apply()`** (WAL path only; verified free of cost for a
//! migrated user): `reconcile_episode_speaker_slots` (mints uuids in-txn)
//! and `recalculate_all_episode_speaker_processing_status` (unbounded
//! whole-table UPDATE whose guard matches zero rows when no voice jobs
//! exist). The legacy path for unselected users keeps both.

use rusqlite::{params, Connection, OptionalExtension, Transaction};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::archive_v3_wal_idempotency::{
    stable_operation_source, DomainLedgerBounds, LogicalMutationResult, PreparedLogicalMutation,
    WalIdempotencyError, WalLogicalDomainLedger, WalLogicalDomainPlan, WalLogicalOperationId,
    WalOperationKind, WalReplayResult,
};

const REQUEST_V1: u16 = 1;
const SUBTYPE: &[u8] = b"adr-0022-episode-window-upsert-v1";
const MAX_BATCH_ITEMS: usize = 64;
const MAX_TIMESTAMP_BYTES: usize = 64;
const MAX_MEMBERS_PER_ITEM: usize = 65_536;
const ENCODED_UNIT_RESULT_BYTES: usize = 9;
const SCHEMA_TABLE: &str = "archive_v3_wal_episode_window_schema";
const LEDGER_TABLE: &str = "archive_v3_wal_episode_window_operations";
const STATE_TABLE: &str = "archive_v3_wal_episode_window_state";
const PROGRESS_TABLE: &str = "archive_v3_wal_episode_window_progress";
const ASSIGNMENT_TABLE: &str = "archive_v3_wal_episode_window_assignments";
const MAX_ROWS: u32 = 1_048_576;
const MAX_RESULT_BYTES: u64 = 1_048_576 * 9;
const BOUNDS: DomainLedgerBounds = DomainLedgerBounds::new(MAX_ROWS, MAX_RESULT_BYTES);

type Result<T> = std::result::Result<T, WalIdempotencyError>;

/// Window progress as the owner reads it: the next window's pre-state
/// sequence and the archive-recorded cutoff (`None` before the first apply
/// or when the tables do not exist yet).
pub(in crate::cp) fn read_window_progress(
    connection: &Connection,
) -> rusqlite::Result<(i64, Option<String>)> {
    let present: i64 = connection.query_row(
        "SELECT COUNT(*) FROM sqlite_schema WHERE type='table' AND name=?1",
        [PROGRESS_TABLE],
        |row| row.get(0),
    )?;
    if present == 0 {
        return Ok((0, None));
    }
    let row: Option<(i64, String)> = connection
        .query_row(
            "SELECT window_seq,effective_cutoff
             FROM archive_v3_wal_episode_window_progress WHERE singleton=1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?;
    Ok(match row {
        Some((seq, cutoff)) if !cutoff.is_empty() => (seq, Some(cutoff)),
        Some((seq, _)) => (seq, None),
        None => (0, None),
    })
}

/// The `sqlite_sequence` pre-state for `episodes` — the id-allocation pin.
pub(in crate::cp) fn read_sequence_pin(connection: &Connection) -> rusqlite::Result<i64> {
    connection.query_row(
        "SELECT COALESCE((SELECT seq FROM sqlite_sequence WHERE name='episodes'),0)",
        [],
        |row| row.get(0),
    )
}

/// The settled ordinal → episode-id map for one window, in ordinal order.
pub(in crate::cp) fn read_window_assignments(
    connection: &Connection,
    window_seq: i64,
) -> rusqlite::Result<Vec<i64>> {
    let mut statement = connection.prepare(
        "SELECT episode_id FROM archive_v3_wal_episode_window_assignments
         WHERE window_seq=?1 ORDER BY ordinal",
    )?;
    let rows = statement.query_map([window_seq], |row| row.get(0))?;
    rows.collect()
}

/// One existing row's full written-set predecessor, as observed by the
/// routed pre-submit read and pinned by the UPDATE arm's CAS.
#[derive(Clone, PartialEq, Eq)]
pub(in crate::cp) struct EpisodePredecessor {
    started_at: String,
    ended_at: String,
    episode_type: Option<String>,
    title: Option<String>,
    summary: Option<String>,
    participants: Option<String>,
    languages: Option<String>,
    action_items: Option<String>,
    model: Option<String>,
    minute_summaries: Option<String>,
    minutes_text: Option<String>,
    substance: String,
    visual_evidence: String,
    updated_at: Option<String>,
}

impl EpisodePredecessor {
    pub(in crate::cp) fn minute_summaries(&self) -> Option<&str> {
        self.minute_summaries.as_deref()
    }

    pub(in crate::cp) fn substance(&self) -> &str {
        &self.substance
    }

    pub(in crate::cp) fn visual_evidence(&self) -> &str {
        &self.visual_evidence
    }
}

/// Routed read of one episode's predecessor tuple; `None` when the row does
/// not exist (the item becomes an INSERT arm, matching the legacy probe).
pub(in crate::cp) fn read_episode_predecessor(
    connection: &Connection,
    episode_id: i64,
) -> rusqlite::Result<Option<EpisodePredecessor>> {
    connection
        .query_row(
            "SELECT started_at,ended_at,type,title,summary,participants,languages,
                    action_items,model,minute_summaries,minutes_text,substance,
                    visual_evidence,updated_at
             FROM episodes WHERE id=?1",
            [episode_id],
            |row| {
                Ok(EpisodePredecessor {
                    started_at: row.get(0)?,
                    ended_at: row.get(1)?,
                    episode_type: row.get(2)?,
                    title: row.get(3)?,
                    summary: row.get(4)?,
                    participants: row.get(5)?,
                    languages: row.get(6)?,
                    action_items: row.get(7)?,
                    model: row.get(8)?,
                    minute_summaries: row.get(9)?,
                    minutes_text: row.get(10)?,
                    substance: row.get(11)?,
                    visual_evidence: row.get(12)?,
                    updated_at: row.get(13)?,
                })
            },
        )
        .optional()
}

#[derive(Clone)]
enum EpisodeArm {
    Insert,
    Update {
        episode_id: i64,
        predecessor: Box<EpisodePredecessor>,
    },
}

/// One normalized episode: final post-merge target values plus the arm.
#[derive(Clone)]
pub(in crate::cp) struct WindowEpisode {
    arm: EpisodeArm,
    started_at: String,
    ended_at: String,
    episode_type: Option<String>,
    title: String,
    summary: Option<String>,
    participants_json: Option<String>,
    languages_json: Option<String>,
    action_items_json: Option<String>,
    model: Option<String>,
    minutes_json: Option<String>,
    minutes_text: Option<String>,
    substance: String,
    visual_evidence: String,
    member_utterance_ids: Vec<i64>,
    member_screenshot_ids: Vec<i64>,
}

/// The final target values for one episode, all merges already computed.
pub(in crate::cp) struct WindowEpisodeTarget {
    pub(in crate::cp) started_at: String,
    pub(in crate::cp) ended_at: String,
    pub(in crate::cp) episode_type: Option<String>,
    pub(in crate::cp) title: String,
    pub(in crate::cp) summary: Option<String>,
    pub(in crate::cp) participants_json: Option<String>,
    pub(in crate::cp) languages_json: Option<String>,
    pub(in crate::cp) action_items_json: Option<String>,
    pub(in crate::cp) model: Option<String>,
    pub(in crate::cp) minutes_json: Option<String>,
    pub(in crate::cp) minutes_text: Option<String>,
    pub(in crate::cp) substance: String,
    pub(in crate::cp) visual_evidence: String,
    pub(in crate::cp) member_utterance_ids: Vec<i64>,
    pub(in crate::cp) member_screenshot_ids: Vec<i64>,
}

impl WindowEpisode {
    pub(in crate::cp) fn insert(target: WindowEpisodeTarget) -> Result<Self> {
        Self::build(EpisodeArm::Insert, target)
    }

    pub(in crate::cp) fn update(
        episode_id: i64,
        predecessor: EpisodePredecessor,
        target: WindowEpisodeTarget,
    ) -> Result<Self> {
        if episode_id <= 0 {
            return Err(WalIdempotencyError::Malformed);
        }
        validate_predecessor(&predecessor)?;
        Self::build(
            EpisodeArm::Update {
                episode_id,
                predecessor: Box::new(predecessor),
            },
            target,
        )
    }

    fn build(arm: EpisodeArm, target: WindowEpisodeTarget) -> Result<Self> {
        validate_timestamp(&target.started_at)?;
        validate_timestamp(&target.ended_at)?;
        // No per-field byte caps: content values are either observed facts
        // from our own rows or model output the legacy path accepts
        // unbounded — refusing them here was the RC1 cursor wedge. The
        // plan's boundedness is structural (item and member counts) and the
        // canonical request commits content by hash, so size cannot breach
        // the kit's request cap. An empty title is accepted exactly as
        // legacy inserts it.
        if !valid_substance(&target.substance)
            || !valid_visual_evidence(&target.visual_evidence)
            || target.member_utterance_ids.len() > MAX_MEMBERS_PER_ITEM
            || target.member_screenshot_ids.len() > MAX_MEMBERS_PER_ITEM
        {
            return Err(WalIdempotencyError::Malformed);
        }
        Ok(Self {
            arm,
            started_at: target.started_at,
            ended_at: target.ended_at,
            episode_type: target.episode_type,
            title: target.title,
            summary: target.summary,
            participants_json: target.participants_json,
            languages_json: target.languages_json,
            action_items_json: target.action_items_json,
            model: target.model,
            minutes_json: target.minutes_json,
            minutes_text: target.minutes_text,
            substance: target.substance,
            visual_evidence: target.visual_evidence,
            member_utterance_ids: target.member_utterance_ids,
            member_screenshot_ids: target.member_screenshot_ids,
        })
    }
}

pub(crate) struct EpisodeWindowUpsertPlan {
    operation_id: WalLogicalOperationId,
    account_id: String,
    window_seq: i64,
    from_iso: String,
    to_iso: String,
    effective_cutoff: String,
    sequence_pin: i64,
    committed_at: String,
    episodes: Vec<WindowEpisode>,
}

impl EpisodeWindowUpsertPlan {
    #[allow(clippy::too_many_arguments)]
    pub(in crate::cp) fn new(
        account_id: String,
        window_seq: i64,
        from_iso: String,
        to_iso: String,
        effective_cutoff: String,
        sequence_pin: i64,
        committed_at: String,
        episodes: Vec<WindowEpisode>,
    ) -> Result<Self> {
        crate::store::validate_user_id(&account_id).map_err(|_| WalIdempotencyError::Malformed)?;
        if window_seq < 0
            || sequence_pin < 0
            || episodes.is_empty()
            || episodes.len() > MAX_BATCH_ITEMS
        {
            return Err(WalIdempotencyError::Malformed);
        }
        validate_timestamp(&from_iso)?;
        validate_timestamp(&to_iso)?;
        validate_timestamp(&effective_cutoff)?;
        validate_timestamp(&committed_at)?;
        if from_iso >= to_iso {
            return Err(WalIdempotencyError::Malformed);
        }
        // Duplicate UPDATE targets are the caller's to coalesce (sequential
        // legacy semantics); two arms racing one row inside a single CAS'd
        // batch cannot be expressed and are refused outright.
        let mut update_ids: Vec<i64> = episodes
            .iter()
            .filter_map(|episode| match &episode.arm {
                EpisodeArm::Update { episode_id, .. } => Some(*episode_id),
                EpisodeArm::Insert => None,
            })
            .collect();
        update_ids.sort_unstable();
        if update_ids.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(WalIdempotencyError::Malformed);
        }
        let mut payload = Sha256::new();
        hash_field(&mut payload, from_iso.as_bytes())?;
        hash_field(&mut payload, to_iso.as_bytes())?;
        hash_field(&mut payload, effective_cutoff.as_bytes())?;
        hash_field(&mut payload, committed_at.as_bytes())?;
        hash_field(&mut payload, &sequence_pin.to_be_bytes())?;
        hash_field(&mut payload, &(episodes.len() as u64).to_be_bytes())?;
        for episode in &episodes {
            hash_episode(&mut payload, episode)?;
        }
        let payload: [u8; 32] = payload.finalize().into();
        let source = stable_operation_source(
            SUBTYPE,
            &[account_id.as_bytes(), &window_seq.to_be_bytes(), &payload],
        )?;
        let operation_id =
            WalLogicalOperationId::from_stable_source(WalOperationKind::ReviewerBackfill, &source)?;
        Ok(Self {
            operation_id,
            account_id,
            window_seq,
            from_iso,
            to_iso,
            effective_cutoff,
            sequence_pin,
            committed_at,
            episodes,
        })
    }
}

pub(crate) struct EpisodeWindowUpsertLedger;

impl WalLogicalDomainPlan for EpisodeWindowUpsertPlan {
    type Ledger = EpisodeWindowUpsertLedger;
    type Output = ();

    fn kind(&self) -> WalOperationKind {
        WalOperationKind::ReviewerBackfill
    }

    fn operation_id(&self) -> WalLogicalOperationId {
        self.operation_id
    }

    fn canonical_request(&self) -> Result<Zeroizing<Vec<u8>>> {
        let mut request = Zeroizing::new(Vec::with_capacity(
            1024 + self.episodes.len() * 768
                + self
                    .episodes
                    .iter()
                    .map(|episode| {
                        8 * (episode.member_utterance_ids.len()
                            + episode.member_screenshot_ids.len())
                    })
                    .sum::<usize>(),
        ));
        request.extend_from_slice(&REQUEST_V1.to_be_bytes());
        encode_bytes(&mut request, SUBTYPE)?;
        encode_string(&mut request, &self.account_id)?;
        request.extend_from_slice(&self.window_seq.to_be_bytes());
        encode_string(&mut request, &self.from_iso)?;
        encode_string(&mut request, &self.to_iso)?;
        encode_string(&mut request, &self.effective_cutoff)?;
        request.extend_from_slice(&self.sequence_pin.to_be_bytes());
        encode_string(&mut request, &self.committed_at)?;
        encode_len(&mut request, self.episodes.len())?;
        for episode in &self.episodes {
            encode_episode(&mut request, episode)?;
        }
        Ok(request)
    }

    fn apply(&self, transaction: &Transaction<'_>) -> Result<WalReplayResult> {
        let current_seq: i64 = transaction
            .query_row(
                "SELECT window_seq FROM archive_v3_wal_episode_window_progress
                 WHERE singleton=1",
                [],
                |row| row.get(0),
            )
            .optional()
            .map_err(|_| WalIdempotencyError::Unavailable)?
            .ok_or(WalIdempotencyError::Corrupt)?;
        if current_seq != self.window_seq {
            return Err(WalIdempotencyError::Precondition);
        }
        let observed_pin =
            read_sequence_pin(transaction).map_err(|_| WalIdempotencyError::Unavailable)?;
        if observed_pin != self.sequence_pin {
            // A second summarizer run allocated ids since this window was
            // derived: the window is genuinely stale. The next run
            // re-derives with a fresh commitment — a new operation, so this
            // refusal has no fixed point.
            return Err(WalIdempotencyError::Precondition);
        }
        let mut inserted: i64 = 0;
        for (ordinal, episode) in self.episodes.iter().enumerate() {
            let episode_id = match &episode.arm {
                EpisodeArm::Update {
                    episode_id,
                    predecessor,
                } => {
                    let changed = transaction
                        .execute(
                            "UPDATE episodes SET
                                 started_at=?2, ended_at=?3, type=?4, title=?5,
                                 summary=?6, participants=?7, languages=?8,
                                 action_items=?9, model=?10,
                                 minute_summaries=?11, minutes_text=?12,
                                 substance=?13, visual_evidence=?14,
                                 updated_at=?15
                             WHERE id=?1
                               AND started_at=?16 AND ended_at=?17
                               AND type IS ?18 AND title IS ?19 AND summary IS ?20
                               AND participants IS ?21 AND languages IS ?22
                               AND action_items IS ?23 AND model IS ?24
                               AND minute_summaries IS ?25 AND minutes_text IS ?26
                               AND substance=?27 AND visual_evidence=?28
                               AND updated_at IS ?29",
                            params![
                                episode_id,
                                episode.started_at,
                                episode.ended_at,
                                episode.episode_type,
                                episode.title,
                                episode.summary,
                                episode.participants_json,
                                episode.languages_json,
                                episode.action_items_json,
                                episode.model,
                                episode.minutes_json,
                                episode.minutes_text,
                                episode.substance,
                                episode.visual_evidence,
                                self.committed_at,
                                predecessor.started_at,
                                predecessor.ended_at,
                                predecessor.episode_type,
                                predecessor.title,
                                predecessor.summary,
                                predecessor.participants,
                                predecessor.languages,
                                predecessor.action_items,
                                predecessor.model,
                                predecessor.minute_summaries,
                                predecessor.minutes_text,
                                predecessor.substance,
                                predecessor.visual_evidence,
                                predecessor.updated_at,
                            ],
                        )
                        .map_err(|_| WalIdempotencyError::Unavailable)?;
                    if changed != 1 {
                        // The row moved (finalizer rewrite, deletion, or an
                        // interleaved run) since the routed read. Refuse; the
                        // next run re-reads fresh predecessors and converges.
                        return Err(WalIdempotencyError::Precondition);
                    }
                    *episode_id
                }
                EpisodeArm::Insert => {
                    transaction
                        .execute(
                            // created_at is explicit because the frozen
                            // baseline declares it with a strftime DEFAULT
                            // (store.rs), and a clock inside apply would
                            // break byte-exact replay. Same value as
                            // updated_at, as this row is being created now.
                            "INSERT INTO episodes
                                 (started_at, ended_at, type, title, summary,
                                  participants, languages, action_items, model,
                                  minute_summaries, minutes_text, substance,
                                  visual_evidence, updated_at, created_at)
                             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?14)",
                            params![
                                episode.started_at,
                                episode.ended_at,
                                episode.episode_type,
                                episode.title,
                                episode.summary,
                                episode.participants_json,
                                episode.languages_json,
                                episode.action_items_json,
                                episode.model,
                                episode.minutes_json,
                                episode.minutes_text,
                                episode.substance,
                                episode.visual_evidence,
                                self.committed_at,
                            ],
                        )
                        .map_err(|_| WalIdempotencyError::Unavailable)?;
                    inserted += 1;
                    let id = transaction.last_insert_rowid();
                    // With the pin asserted and this plan the only inserter
                    // in the transaction, ids are a pure function of the
                    // pre-state. A divergence is corruption, not a race.
                    if id != self.sequence_pin + inserted {
                        return Err(WalIdempotencyError::Corrupt);
                    }
                    id
                }
            };
            for utterance_id in &episode.member_utterance_ids {
                transaction
                    .execute(
                        "INSERT OR IGNORE INTO episode_members
                             (episode_id, record_type, record_id)
                         VALUES (?1,'utterance',?2)",
                        params![episode_id, utterance_id],
                    )
                    .map_err(|_| WalIdempotencyError::Unavailable)?;
            }
            for screenshot_id in &episode.member_screenshot_ids {
                transaction
                    .execute(
                        "INSERT OR IGNORE INTO episode_members
                             (episode_id, record_type, record_id)
                         VALUES (?1,'screenshot',?2)",
                        params![episode_id, screenshot_id],
                    )
                    .map_err(|_| WalIdempotencyError::Unavailable)?;
            }
            let ordinal = i64::try_from(ordinal).map_err(|_| WalIdempotencyError::Limit)?;
            transaction
                .execute(
                    "INSERT INTO archive_v3_wal_episode_window_assignments
                         (window_seq, ordinal, episode_id)
                     VALUES (?1,?2,?3)",
                    params![self.window_seq, ordinal, episode_id],
                )
                .map_err(|_| WalIdempotencyError::Unavailable)?;
        }
        let advanced = transaction
            .execute(
                "UPDATE archive_v3_wal_episode_window_progress
                 SET window_seq=window_seq+1, from_iso=?1, to_iso=?2,
                     effective_cutoff=?3
                 WHERE singleton=1 AND window_seq=?4",
                params![
                    self.from_iso,
                    self.to_iso,
                    self.effective_cutoff,
                    self.window_seq,
                ],
            )
            .map_err(|_| WalIdempotencyError::Unavailable)?;
        if advanced != 1 {
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

fn validate_predecessor(predecessor: &EpisodePredecessor) -> Result<()> {
    // Predecessor values are observed facts read from our own row; a size
    // refusal here would wedge exactly the episode it observed (RC1).
    if predecessor.started_at.is_empty()
        || predecessor.ended_at.is_empty()
        || !valid_substance(&predecessor.substance)
        || !valid_visual_evidence(&predecessor.visual_evidence)
    {
        return Err(WalIdempotencyError::Malformed);
    }
    Ok(())
}

fn valid_substance(value: &str) -> bool {
    matches!(value, "none" | "low" | "normal")
}

fn valid_visual_evidence(value: &str) -> bool {
    matches!(value, "none" | "useful")
}

fn validate_timestamp(value: &str) -> Result<()> {
    if value.is_empty() || value.len() > MAX_TIMESTAMP_BYTES {
        return Err(WalIdempotencyError::Malformed);
    }
    Ok(())
}

fn hash_optional(hasher: &mut Sha256, value: Option<&str>) -> Result<()> {
    match value {
        None => hash_field(hasher, b"\x00"),
        Some(value) => {
            hash_field(hasher, b"\x01")?;
            hash_field(hasher, value.as_bytes())
        }
    }
}

fn hash_episode(hasher: &mut Sha256, episode: &WindowEpisode) -> Result<()> {
    match &episode.arm {
        EpisodeArm::Insert => hash_field(hasher, b"insert")?,
        EpisodeArm::Update {
            episode_id,
            predecessor,
        } => {
            hash_field(hasher, b"update")?;
            hash_field(hasher, &episode_id.to_be_bytes())?;
            hash_field(hasher, predecessor.started_at.as_bytes())?;
            hash_field(hasher, predecessor.ended_at.as_bytes())?;
            hash_optional(hasher, predecessor.episode_type.as_deref())?;
            hash_optional(hasher, predecessor.title.as_deref())?;
            hash_optional(hasher, predecessor.summary.as_deref())?;
            hash_optional(hasher, predecessor.participants.as_deref())?;
            hash_optional(hasher, predecessor.languages.as_deref())?;
            hash_optional(hasher, predecessor.action_items.as_deref())?;
            hash_optional(hasher, predecessor.model.as_deref())?;
            hash_optional(hasher, predecessor.minute_summaries.as_deref())?;
            hash_optional(hasher, predecessor.minutes_text.as_deref())?;
            hash_field(hasher, predecessor.substance.as_bytes())?;
            hash_field(hasher, predecessor.visual_evidence.as_bytes())?;
            hash_optional(hasher, predecessor.updated_at.as_deref())?;
        }
    }
    hash_field(hasher, episode.started_at.as_bytes())?;
    hash_field(hasher, episode.ended_at.as_bytes())?;
    hash_optional(hasher, episode.episode_type.as_deref())?;
    hash_field(hasher, episode.title.as_bytes())?;
    hash_optional(hasher, episode.summary.as_deref())?;
    hash_optional(hasher, episode.participants_json.as_deref())?;
    hash_optional(hasher, episode.languages_json.as_deref())?;
    hash_optional(hasher, episode.action_items_json.as_deref())?;
    hash_optional(hasher, episode.model.as_deref())?;
    hash_optional(hasher, episode.minutes_json.as_deref())?;
    hash_optional(hasher, episode.minutes_text.as_deref())?;
    hash_field(hasher, episode.substance.as_bytes())?;
    hash_field(hasher, episode.visual_evidence.as_bytes())?;
    hash_field(
        hasher,
        &(episode.member_utterance_ids.len() as u64).to_be_bytes(),
    )?;
    for id in &episode.member_utterance_ids {
        hash_field(hasher, &id.to_be_bytes())?;
    }
    hash_field(
        hasher,
        &(episode.member_screenshot_ids.len() as u64).to_be_bytes(),
    )?;
    for id in &episode.member_screenshot_ids {
        hash_field(hasher, &id.to_be_bytes())?;
    }
    Ok(())
}

/// Commit a content field into the canonical request by hash: the
/// fingerprint binds the exact bytes with the same strength as verbatim
/// encoding, the request stays structurally bounded regardless of how large
/// the stored timeline grows (the RC1 wedge), and no episode plaintext is
/// ever materialized into the request buffer.
fn encode_committed(request: &mut Vec<u8>, value: &str) -> Result<()> {
    let digest: [u8; 32] = Sha256::digest(value.as_bytes()).into();
    encode_bytes(request, &digest)
}

fn encode_committed_optional(request: &mut Vec<u8>, value: Option<&str>) -> Result<()> {
    match value {
        None => {
            request.push(0);
            Ok(())
        }
        Some(value) => {
            request.push(1);
            encode_committed(request, value)
        }
    }
}

fn encode_episode(request: &mut Vec<u8>, episode: &WindowEpisode) -> Result<()> {
    match &episode.arm {
        EpisodeArm::Insert => request.push(0),
        EpisodeArm::Update {
            episode_id,
            predecessor,
        } => {
            request.push(1);
            request.extend_from_slice(&episode_id.to_be_bytes());
            encode_string(request, &predecessor.started_at)?;
            encode_string(request, &predecessor.ended_at)?;
            encode_committed_optional(request, predecessor.episode_type.as_deref())?;
            encode_committed_optional(request, predecessor.title.as_deref())?;
            encode_committed_optional(request, predecessor.summary.as_deref())?;
            encode_committed_optional(request, predecessor.participants.as_deref())?;
            encode_committed_optional(request, predecessor.languages.as_deref())?;
            encode_committed_optional(request, predecessor.action_items.as_deref())?;
            encode_committed_optional(request, predecessor.model.as_deref())?;
            encode_committed_optional(request, predecessor.minute_summaries.as_deref())?;
            encode_committed_optional(request, predecessor.minutes_text.as_deref())?;
            encode_string(request, &predecessor.substance)?;
            encode_string(request, &predecessor.visual_evidence)?;
            encode_committed_optional(request, predecessor.updated_at.as_deref())?;
        }
    }
    encode_string(request, &episode.started_at)?;
    encode_string(request, &episode.ended_at)?;
    encode_committed_optional(request, episode.episode_type.as_deref())?;
    encode_committed(request, &episode.title)?;
    encode_committed_optional(request, episode.summary.as_deref())?;
    encode_committed_optional(request, episode.participants_json.as_deref())?;
    encode_committed_optional(request, episode.languages_json.as_deref())?;
    encode_committed_optional(request, episode.action_items_json.as_deref())?;
    encode_committed_optional(request, episode.model.as_deref())?;
    encode_committed_optional(request, episode.minutes_json.as_deref())?;
    encode_committed_optional(request, episode.minutes_text.as_deref())?;
    encode_string(request, &episode.substance)?;
    encode_string(request, &episode.visual_evidence)?;
    encode_len(request, episode.member_utterance_ids.len())?;
    for id in &episode.member_utterance_ids {
        request.extend_from_slice(&id.to_be_bytes());
    }
    encode_len(request, episode.member_screenshot_ids.len())?;
    for id in &episode.member_screenshot_ids {
        request.extend_from_slice(&id.to_be_bytes());
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum LedgerSchemaState {
    Absent,
    Present,
}

impl WalLogicalDomainLedger<EpisodeWindowUpsertPlan> for EpisodeWindowUpsertLedger {
    fn lookup(
        connection: &Connection,
        prepared: &PreparedLogicalMutation<EpisodeWindowUpsertPlan>,
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
                 FROM archive_v3_wal_episode_window_operations
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
        let kind = WalOperationKind::ReviewerBackfill;
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
        prepared: &PreparedLogicalMutation<EpisodeWindowUpsertPlan>,
    ) -> Result<LogicalMutationResult> {
        require_kind(prepared)?;
        ensure_schema(transaction)?;
        if let Some(result) = Self::lookup(transaction, prepared)? {
            return Ok(LogicalMutationResult::Replayed(result));
        }
        let (row_count, result_bytes) = load_ledger_state(transaction)?;
        BOUNDS.admit(row_count, result_bytes, ENCODED_UNIT_RESULT_BYTES)?;
        let kind = WalOperationKind::ReviewerBackfill;
        let result = prepared.plan_for_domain_ledger().apply(transaction)?;
        prepared.plan_for_domain_ledger().validate_replay(&result)?;
        let encoded = result.encode(kind)?;
        if encoded.len() != ENCODED_UNIT_RESULT_BYTES {
            return Err(WalIdempotencyError::Corrupt);
        }
        let commitment = result.commitment(kind)?;
        transaction
            .execute(
                "INSERT INTO archive_v3_wal_episode_window_operations
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
                "UPDATE archive_v3_wal_episode_window_state
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

fn require_kind(prepared: &PreparedLogicalMutation<EpisodeWindowUpsertPlan>) -> Result<()> {
    if prepared.kind_for_owner() != WalOperationKind::ReviewerBackfill {
        return Err(WalIdempotencyError::Corrupt);
    }
    Ok(())
}

fn schema_state(connection: &Connection) -> Result<LedgerSchemaState> {
    let present = connection
        .query_row(
            "SELECT COUNT(*) FROM sqlite_schema
             WHERE type='table' AND name IN (?1,?2,?3,?4,?5)",
            params![
                SCHEMA_TABLE,
                LEDGER_TABLE,
                STATE_TABLE,
                PROGRESS_TABLE,
                ASSIGNMENT_TABLE
            ],
            |row| row.get::<_, i64>(0),
        )
        .map_err(|_| WalIdempotencyError::Unavailable)?;
    match present {
        0 => Ok(LedgerSchemaState::Absent),
        5 => Ok(LedgerSchemaState::Present),
        _ => Err(WalIdempotencyError::Corrupt),
    }
}

fn ensure_schema(transaction: &Transaction<'_>) -> Result<()> {
    match schema_state(transaction)? {
        LedgerSchemaState::Present => validate_schema_marker(transaction),
        LedgerSchemaState::Absent => {
            transaction
                .execute_batch(
                    "CREATE TABLE archive_v3_wal_episode_window_schema (
                        singleton INTEGER PRIMARY KEY CHECK(singleton=1),
                        format_version INTEGER NOT NULL CHECK(format_version=1),
                        codec_version INTEGER NOT NULL CHECK(codec_version=1)
                     ) STRICT;
                     CREATE TABLE archive_v3_wal_episode_window_operations (
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
                     CREATE TABLE archive_v3_wal_episode_window_state (
                        singleton INTEGER PRIMARY KEY CHECK(singleton=1),
                        row_count INTEGER NOT NULL CHECK(row_count BETWEEN 0 AND 1048576),
                        result_bytes INTEGER NOT NULL CHECK(result_bytes BETWEEN 0 AND 9437184)
                     ) STRICT;
                     CREATE TABLE archive_v3_wal_episode_window_progress (
                        singleton INTEGER PRIMARY KEY CHECK(singleton=1),
                        window_seq INTEGER NOT NULL CHECK(window_seq>=0),
                        from_iso TEXT NOT NULL,
                        to_iso TEXT NOT NULL,
                        effective_cutoff TEXT NOT NULL
                     ) STRICT;
                     CREATE TABLE archive_v3_wal_episode_window_assignments (
                        window_seq INTEGER NOT NULL CHECK(window_seq>=0),
                        ordinal INTEGER NOT NULL CHECK(ordinal>=0),
                        episode_id INTEGER NOT NULL CHECK(episode_id>0),
                        PRIMARY KEY(window_seq, ordinal)
                     ) STRICT, WITHOUT ROWID;
                     INSERT INTO archive_v3_wal_episode_window_schema
                        (singleton,format_version,codec_version) VALUES (1,1,1);
                     INSERT INTO archive_v3_wal_episode_window_state
                        (singleton,row_count,result_bytes) VALUES (1,0,0);
                     INSERT INTO archive_v3_wal_episode_window_progress
                        (singleton,window_seq,from_iso,to_iso,effective_cutoff)
                        VALUES (1,0,'','','');",
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
             FROM archive_v3_wal_episode_window_schema WHERE singleton=1",
            [],
            |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)),
        )
        .optional()
        .map_err(|_| WalIdempotencyError::Corrupt)?;
    if marker
        != Some((
            i64::from(WalOperationKind::format_version()),
            i64::from(WalOperationKind::ReviewerBackfill.codec_version()),
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
             FROM archive_v3_wal_episode_window_state WHERE singleton=1",
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

    const ACCOUNT: &str = "11111111-1111-4111-8111-111111111111";
    const FROM: &str = "2026-08-20T10:00:00.000Z";
    const TO: &str = "2026-08-20T16:00:00.000Z";
    const CUTOFF: &str = "2026-08-20T15:45:00.000Z";
    const COMMITTED_AT: &str = "2026-08-20T16:01:00.000Z";

    fn install_schema(connection: &Connection) {
        connection
            .execute_batch(
                "CREATE TABLE episodes (
                    id            INTEGER PRIMARY KEY AUTOINCREMENT,
                    started_at    TEXT NOT NULL,
                    ended_at      TEXT NOT NULL,
                    type          TEXT,
                    title         TEXT,
                    summary       TEXT,
                    participants  TEXT,
                    languages     TEXT,
                    action_items  TEXT,
                    model         TEXT,
                    minute_summaries TEXT,
                    minutes_text  TEXT,
                    substance     TEXT NOT NULL DEFAULT 'normal'
                                  CHECK (substance IN ('none','low','normal')),
                    visual_evidence TEXT NOT NULL DEFAULT 'none'
                                  CHECK (visual_evidence IN ('none','useful')),
                    -- Declared exactly as the frozen baseline does, clock
                    -- DEFAULT included, so an apply that fails to bind it is
                    -- observable here instead of silently absent.
                    created_at    TEXT NOT NULL
                                  DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
                    updated_at    TEXT
                 );
                 CREATE TABLE episode_members (
                    episode_id INTEGER NOT NULL,
                    record_type TEXT NOT NULL,
                    record_id INTEGER NOT NULL,
                    PRIMARY KEY (episode_id, record_type, record_id)
                 );",
            )
            .unwrap();
    }

    fn target(title: &str) -> WindowEpisodeTarget {
        WindowEpisodeTarget {
            started_at: "2026-08-20T10:05:00.000Z".into(),
            ended_at: "2026-08-20T11:00:00.000Z".into(),
            episode_type: Some("work".into()),
            title: title.into(),
            summary: Some("a summary".into()),
            participants_json: None,
            languages_json: Some("[\"en\"]".into()),
            action_items_json: None,
            model: Some("gemini".into()),
            minutes_json: Some("[{\"start\":\"2026-08-20T10:05:00Z\",\"gist\":\"g\"}]".into()),
            minutes_text: Some("g".into()),
            substance: "normal".into(),
            visual_evidence: "none".into(),
            member_utterance_ids: vec![7, 9],
            member_screenshot_ids: vec![3],
        }
    }

    fn build(
        window_seq: i64,
        sequence_pin: i64,
        committed_at: &str,
        episodes: Vec<WindowEpisode>,
    ) -> EpisodeWindowUpsertPlan {
        EpisodeWindowUpsertPlan::new(
            ACCOUNT.into(),
            window_seq,
            FROM.into(),
            TO.into(),
            CUTOFF.into(),
            sequence_pin,
            committed_at.into(),
            episodes,
        )
        .unwrap()
    }

    fn settle(
        connection: &mut Connection,
        plan: EpisodeWindowUpsertPlan,
    ) -> Result<LogicalMutationDisposition> {
        let prepared = PreparedLogicalMutation::prepare(plan)?;
        execute_prepared_for_owner(connection, prepared).map(|outcome| outcome.disposition())
    }

    #[test]
    fn a_fresh_window_inserts_deterministic_ids_and_advances_progress() {
        let mut connection = Connection::open_in_memory().unwrap();
        install_schema(&connection);
        let episodes = vec![
            WindowEpisode::insert(target("first")).unwrap(),
            WindowEpisode::insert(target("second")).unwrap(),
        ];
        let plan = build(0, 0, COMMITTED_AT, episodes.clone());
        assert!(matches!(
            settle(&mut connection, plan).unwrap(),
            LogicalMutationDisposition::Applied
        ));
        let ids = read_window_assignments(&connection, 0).unwrap();
        assert_eq!(ids, vec![1, 2], "ids are a pure function of the pin");
        let (title, updated, created): (String, String, String) = connection
            .query_row(
                "SELECT title,updated_at,created_at FROM episodes WHERE id=2",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();
        assert_eq!(title, "second");
        assert_eq!(updated, COMMITTED_AT, "the carried stamp replaces strftime");
        // created_at carries its own strftime DEFAULT in the baseline, so it
        // needs its own binding and its own assertion. Checking updated_at
        // alone left the clock running in this very row.
        assert_eq!(
            created, COMMITTED_AT,
            "the carried stamp replaces strftime for created_at too"
        );
        let members: i64 = connection
            .query_row("SELECT COUNT(*) FROM episode_members", [], |row| row.get(0))
            .unwrap();
        assert_eq!(members, 6);
        let (seq, cutoff) = read_window_progress(&connection).unwrap();
        assert_eq!(seq, 1);
        assert_eq!(cutoff.as_deref(), Some(CUTOFF));
        // Exact replay resolves from the ledger without re-applying.
        assert!(matches!(
            settle(&mut connection, build(0, 0, COMMITTED_AT, episodes)).unwrap(),
            LogicalMutationDisposition::Replayed
        ));
        let episodes_count: i64 = connection
            .query_row("SELECT COUNT(*) FROM episodes", [], |row| row.get(0))
            .unwrap();
        assert_eq!(episodes_count, 2);
    }

    #[test]
    fn an_extension_updates_under_the_full_predecessor_cas() {
        let mut connection = Connection::open_in_memory().unwrap();
        install_schema(&connection);
        let first = vec![WindowEpisode::insert(target("first")).unwrap()];
        assert!(matches!(
            settle(&mut connection, build(0, 0, COMMITTED_AT, first)).unwrap(),
            LogicalMutationDisposition::Applied
        ));
        let predecessor = read_episode_predecessor(&connection, 1).unwrap().unwrap();
        let mut extended = target("first, extended");
        extended.ended_at = "2026-08-20T12:00:00.000Z".into();
        extended.member_utterance_ids = vec![9, 11];
        let episodes = vec![WindowEpisode::update(1, predecessor, extended).unwrap()];
        assert!(matches!(
            settle(
                &mut connection,
                build(1, 1, "2026-08-20T17:00:00.000Z", episodes)
            )
            .unwrap(),
            LogicalMutationDisposition::Applied
        ));
        let (title, ended, updated): (String, String, String) = connection
            .query_row(
                "SELECT title,ended_at,updated_at FROM episodes WHERE id=1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();
        assert_eq!(title, "first, extended");
        assert_eq!(ended, "2026-08-20T12:00:00.000Z");
        assert_eq!(updated, "2026-08-20T17:00:00.000Z");
        // Members are additive across runs.
        let members: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM episode_members WHERE record_type='utterance'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(members, 3, "7 and 9 from the insert, 11 from the extension");
        assert_eq!(read_window_assignments(&connection, 1).unwrap(), vec![1]);
    }

    #[test]
    fn a_moved_predecessor_fails_closed() {
        let mut connection = Connection::open_in_memory().unwrap();
        install_schema(&connection);
        let first = vec![WindowEpisode::insert(target("first")).unwrap()];
        assert!(matches!(
            settle(&mut connection, build(0, 0, COMMITTED_AT, first)).unwrap(),
            LogicalMutationDisposition::Applied
        ));
        let predecessor = read_episode_predecessor(&connection, 1).unwrap().unwrap();
        // A finalizer rewrite lands between the routed read and the settle.
        connection
            .execute("UPDATE episodes SET title='finalized title' WHERE id=1", [])
            .unwrap();
        let episodes = vec![WindowEpisode::update(1, predecessor, target("stale")).unwrap()];
        assert!(matches!(
            settle(
                &mut connection,
                build(1, 1, "2026-08-20T17:00:00.000Z", episodes)
            ),
            Err(WalIdempotencyError::Precondition)
        ));
    }

    #[test]
    fn a_stale_window_seq_or_sequence_pin_fails_closed() {
        let mut connection = Connection::open_in_memory().unwrap();
        install_schema(&connection);
        let first = vec![WindowEpisode::insert(target("first")).unwrap()];
        assert!(matches!(
            settle(&mut connection, build(0, 0, COMMITTED_AT, first)).unwrap(),
            LogicalMutationDisposition::Applied
        ));
        // A second plan derived against the already-settled window_seq.
        let stale_seq = vec![WindowEpisode::insert(target("stale-seq")).unwrap()];
        assert!(matches!(
            settle(
                &mut connection,
                build(0, 1, "2026-08-20T17:00:00.000Z", stale_seq)
            ),
            Err(WalIdempotencyError::Precondition)
        ));
        // A pin captured before an id was allocated elsewhere.
        let stale_pin = vec![WindowEpisode::insert(target("stale-pin")).unwrap()];
        assert!(matches!(
            settle(
                &mut connection,
                build(1, 0, "2026-08-20T17:00:00.000Z", stale_pin)
            ),
            Err(WalIdempotencyError::Precondition)
        ));
        // Neither refusal advanced the window or wrote an episode.
        assert_eq!(read_window_progress(&connection).unwrap().0, 1);
        let count: i64 = connection
            .query_row("SELECT COUNT(*) FROM episodes", [], |row| row.get(0))
            .unwrap();
        assert_eq!(count, 1);
    }

    #[test]
    fn the_identity_binds_the_window_commitment() {
        let episodes = || vec![WindowEpisode::insert(target("first")).unwrap()];
        let base = build(0, 0, COMMITTED_AT, episodes());
        // A different window sequence is a different operation.
        assert_ne!(
            base.operation_id(),
            build(1, 0, COMMITTED_AT, episodes()).operation_id()
        );
        // A re-derived batch (fresh commit stamp) is a new operation; the
        // window_seq CAS is what prevents double-apply, not id reuse.
        assert_ne!(
            base.operation_id(),
            build(0, 0, "2026-08-20T17:00:00.000Z", episodes()).operation_id()
        );
        // The pin is part of the commitment.
        assert_ne!(
            base.operation_id(),
            build(0, 5, COMMITTED_AT, episodes()).operation_id()
        );
    }

    #[test]
    fn an_accumulated_minute_timeline_beyond_the_kit_request_cap_still_settles() {
        // The RC1 wedge from the adversarial review: a long-lived episode's
        // stored minute timeline grows without bound, and a canonical
        // request that embedded it verbatim (predecessor AND merged target)
        // breached the kit's 1 MiB whole-request cap — a deterministic
        // refusal that froze the user's cursor forever. Content fields are
        // committed (hashed) into the request instead, so size cannot wedge.
        let mut connection = Connection::open_in_memory().unwrap();
        install_schema(&connection);
        let first = vec![WindowEpisode::insert(target("first")).unwrap()];
        assert!(matches!(
            settle(&mut connection, build(0, 0, COMMITTED_AT, first)).unwrap(),
            LogicalMutationDisposition::Applied
        ));
        let huge = format!(
            "[{}]",
            (0..40_000)
                .map(|i| format!(
                    "{{\"start\":\"2026-08-{:02}T{:02}:{:02}:00Z\",\"gist\":\"minute\"}}",
                    1 + (i / 1440) % 28,
                    (i / 60) % 24,
                    i % 60
                ))
                .collect::<Vec<_>>()
                .join(",")
        );
        assert!(huge.len() > 1_600_000, "fixture must exceed the 1 MiB cap");
        connection
            .execute(
                "UPDATE episodes SET minute_summaries=?1, minutes_text=?2 WHERE id=1",
                params![huge, "m\n".repeat(40_000)],
            )
            .unwrap();
        let predecessor = read_episode_predecessor(&connection, 1).unwrap().unwrap();
        let mut extended = target("first, extended");
        extended.minutes_json = Some(huge);
        extended.minutes_text = Some("m\n".repeat(40_001));
        let episodes = vec![WindowEpisode::update(1, predecessor, extended).unwrap()];
        assert!(matches!(
            settle(
                &mut connection,
                build(1, 1, "2026-08-20T17:00:00.000Z", episodes)
            )
            .unwrap(),
            LogicalMutationDisposition::Applied
        ));
    }

    #[test]
    fn an_empty_title_is_accepted_exactly_as_legacy_accepts_it() {
        // Legacy upsert_episodes inserts an LLM-produced empty title
        // verbatim; refusing it here was a divergent deterministic refusal.
        let mut connection = Connection::open_in_memory().unwrap();
        install_schema(&connection);
        let episodes = vec![WindowEpisode::insert(target("")).unwrap()];
        assert!(matches!(
            settle(&mut connection, build(0, 0, COMMITTED_AT, episodes)).unwrap(),
            LogicalMutationDisposition::Applied
        ));
    }

    #[test]
    fn malformed_windows_are_rejected() {
        assert!(
            EpisodeWindowUpsertPlan::new(
                ACCOUNT.into(),
                0,
                FROM.into(),
                TO.into(),
                CUTOFF.into(),
                0,
                COMMITTED_AT.into(),
                vec![],
            )
            .is_err(),
            "empty windows are never submitted"
        );
        let connection = Connection::open_in_memory().unwrap();
        install_schema(&connection);
        connection
            .execute(
                "INSERT INTO episodes (started_at,ended_at,title) VALUES ('a','b','t')",
                [],
            )
            .unwrap();
        let predecessor = read_episode_predecessor(&connection, 1).unwrap().unwrap();
        let duplicate = vec![
            WindowEpisode::update(1, predecessor.clone(), target("one")).unwrap(),
            WindowEpisode::update(1, predecessor, target("two")).unwrap(),
        ];
        assert!(EpisodeWindowUpsertPlan::new(
            ACCOUNT.into(),
            0,
            FROM.into(),
            TO.into(),
            CUTOFF.into(),
            1,
            COMMITTED_AT.into(),
            duplicate,
        )
        .is_err());
        let mut bad = target("bad");
        bad.substance = "loud".into();
        assert!(WindowEpisode::insert(bad).is_err());
    }
}
