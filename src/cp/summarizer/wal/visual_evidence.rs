//! Inactive exact ADR-0010 visual-evidence backfill WAL domain.
//!
//! A future owner supplies one already-classified, cursor-bound batch. This
//! child reconstructs the same bounded text-only episode and screenshot input,
//! updates only the exact eligible prefix, and advances its private cursor in
//! the same transaction as permanent replay. It cannot load pixels, reserve or
//! invoke a model, call Store, launch work, or acknowledge a request.

use rusqlite::{params, Connection, OptionalExtension, Transaction};
use zeroize::Zeroizing;

use crate::archive_v3_wal_idempotency::{
    DomainLedgerBounds, LogicalMutationResult, PreparedLogicalMutation, WalIdempotencyError,
    WalLogicalDomainLedger, WalLogicalDomainPlan, WalLogicalOperationId, WalOperationKind,
    WalReplayResult,
};

const REQUEST_V1: u16 = 1;
const SUBTYPE: &[u8] = b"adr-0010-visual-evidence-backfill-v1";
const MARKER_KEY: &str = "adr_0010_visual_evidence_backfill_v1";
const MARKER_VALUE: &str = "complete";
const MARKER_TIME: &str = "2026-08-15T00:00:00.000Z";
const EPISODE_EXCERPT_CHARS: usize = 6_000;
const SCREEN_FIELD_READ_CHARS: usize = 10_000;
const SCREEN_OCR_CHARS: usize = 500;
const SCREEN_EXCERPT_CHARS: usize = 10_000;
const MAX_SCREEN_ROWS: usize = 120;
const MAX_EVIDENCE_CHARS: usize = EPISODE_EXCERPT_CHARS + SCREEN_EXCERPT_CHARS + 128;
const MAX_EVIDENCE_BYTES: usize = MAX_EVIDENCE_CHARS * 4;
// Sixteen worst-case UTF-8 evidence values plus framing remain below the
// shared one-MiB canonical WAL request cap; seventeen cannot be admitted.
const MAX_BATCH_ITEMS: usize = 16;
const ENCODED_UNIT_RESULT_BYTES: usize = 9;
const MAX_ROWS: u32 = 65_536;
const MAX_RESULT_BYTES: u64 = MAX_ROWS as u64 * ENCODED_UNIT_RESULT_BYTES as u64;
const SCHEMA_TABLE: &str = "archive_v3_wal_visual_evidence_backfill_schema";
const LEDGER_TABLE: &str = "archive_v3_wal_visual_evidence_backfill_operations";
const BOUNDS_TABLE: &str = "archive_v3_wal_visual_evidence_backfill_bounds";
const PROGRESS_TABLE: &str = "archive_v3_wal_visual_evidence_backfill_progress";
const BOUNDS: DomainLedgerBounds = DomainLedgerBounds::new(MAX_ROWS, MAX_RESULT_BYTES);

type Result<T> = std::result::Result<T, WalIdempotencyError>;

#[derive(Clone, PartialEq, Eq)]
pub(super) struct VisualEvidenceBackfillItem {
    episode_id: i64,
    evidence: String,
    predecessor_substance: String,
    predecessor_visual_evidence: String,
    visual_evidence: String,
}

impl VisualEvidenceBackfillItem {
    pub(super) fn new(
        episode_id: i64,
        evidence: String,
        predecessor_substance: String,
        predecessor_visual_evidence: String,
        visual_evidence: String,
    ) -> Result<Self> {
        if episode_id <= 0
            || predecessor_substance != "normal"
            || predecessor_visual_evidence != "none"
            || !valid_visual_evidence(&visual_evidence)
        {
            return Err(WalIdempotencyError::Malformed);
        }
        validate_evidence(&evidence)?;
        Ok(Self {
            episode_id,
            evidence,
            predecessor_substance,
            predecessor_visual_evidence,
            visual_evidence,
        })
    }
}

/// One exact next visual-evidence batch, or an empty exact-tail completion,
/// for one already authenticated stable account.
pub(crate) struct VisualEvidenceBackfillBatchPlan {
    operation_id: WalLogicalOperationId,
    user_id: String,
    cursor: i64,
    items: Vec<VisualEvidenceBackfillItem>,
}

impl VisualEvidenceBackfillBatchPlan {
    pub(super) fn new(
        user_id: String,
        cursor: i64,
        items: Vec<VisualEvidenceBackfillItem>,
    ) -> Result<Self> {
        Self::build(None, user_id, cursor, items)
    }

    fn build(
        operation_id: Option<WalLogicalOperationId>,
        user_id: String,
        cursor: i64,
        items: Vec<VisualEvidenceBackfillItem>,
    ) -> Result<Self> {
        super::validate_uuid(&user_id)?;
        if cursor < 0 || items.len() > MAX_BATCH_ITEMS {
            return Err(WalIdempotencyError::Malformed);
        }
        let mut prior = cursor;
        for item in &items {
            if item.episode_id <= prior {
                return Err(WalIdempotencyError::Malformed);
            }
            prior = item.episode_id;
        }
        let operation_id = match operation_id {
            Some(value) => value,
            None => {
                let mut source = Vec::with_capacity(SUBTYPE.len() + 1 + user_id.len() + 9);
                source.extend_from_slice(SUBTYPE);
                source.push(0);
                source.extend_from_slice(user_id.as_bytes());
                source.extend_from_slice(&cursor.to_be_bytes());
                source.push(u8::from(items.is_empty()));
                WalLogicalOperationId::from_stable_source(
                    WalOperationKind::ReviewerBackfill,
                    &source,
                )?
            }
        };
        Ok(Self {
            operation_id,
            user_id,
            cursor,
            items,
        })
    }

    #[cfg(test)]
    fn with_operation_id(
        operation_id: WalLogicalOperationId,
        user_id: &str,
        cursor: i64,
        items: Vec<VisualEvidenceBackfillItem>,
    ) -> Result<Self> {
        Self::build(Some(operation_id), user_id.to_owned(), cursor, items)
    }
}

pub(crate) struct VisualEvidenceBackfillBatchLedger;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum LedgerSchemaState {
    Absent,
    Present,
}

impl WalLogicalDomainPlan for VisualEvidenceBackfillBatchPlan {
    type Ledger = VisualEvidenceBackfillBatchLedger;
    type Output = ();

    fn kind(&self) -> WalOperationKind {
        WalOperationKind::ReviewerBackfill
    }

    fn operation_id(&self) -> WalLogicalOperationId {
        self.operation_id
    }

    fn canonical_request(&self) -> Result<Zeroizing<Vec<u8>>> {
        let mut request = Zeroizing::new(Vec::with_capacity(
            128usize.saturating_add(
                self.items
                    .iter()
                    .map(|item| item.evidence.len().saturating_add(64))
                    .sum::<usize>(),
            ),
        ));
        request.extend_from_slice(&REQUEST_V1.to_be_bytes());
        super::encode_bytes(&mut request, SUBTYPE)?;
        super::encode_bytes(&mut request, self.user_id.as_bytes())?;
        request.extend_from_slice(&self.cursor.to_be_bytes());
        request.extend_from_slice(
            &u16::try_from(self.items.len())
                .map_err(|_| WalIdempotencyError::Limit)?
                .to_be_bytes(),
        );
        for item in &self.items {
            request.extend_from_slice(&item.episode_id.to_be_bytes());
            super::encode_bytes(&mut request, item.evidence.as_bytes())?;
            super::encode_bytes(&mut request, item.predecessor_substance.as_bytes())?;
            super::encode_bytes(&mut request, item.predecessor_visual_evidence.as_bytes())?;
            super::encode_bytes(&mut request, item.visual_evidence.as_bytes())?;
        }
        Ok(request)
    }

    fn apply(&self, transaction: &Transaction<'_>) -> Result<WalReplayResult> {
        let marker = load_marker(transaction)?;
        if marker.as_deref().is_some_and(|value| value != MARKER_VALUE) {
            return Err(WalIdempotencyError::Precondition);
        }
        let progress = load_progress(transaction)?;
        if progress.completed {
            return Err(WalIdempotencyError::Corrupt);
        }
        if progress.cursor != self.cursor {
            return Err(WalIdempotencyError::Precondition);
        }

        if marker.as_deref() == Some(MARKER_VALUE) {
            if !self.items.is_empty() || self.cursor != 0 {
                return Err(WalIdempotencyError::Precondition);
            }
            cas_progress(transaction, progress, progress.cursor, true)?;
            return Ok(WalReplayResult::unit());
        }

        let observed = load_next_rows(transaction, self.cursor)?;
        if self.items.is_empty() {
            if !observed.is_empty() {
                return Err(WalIdempotencyError::Precondition);
            }
            transaction
                .execute(
                    "INSERT INTO app_metadata(key,value,updated_at) VALUES (?1,?2,?3)",
                    params![MARKER_KEY, MARKER_VALUE, MARKER_TIME],
                )
                .map_err(|_| WalIdempotencyError::Unavailable)?;
            if load_marker(transaction)?.as_deref() != Some(MARKER_VALUE) {
                return Err(WalIdempotencyError::Corrupt);
            }
            cas_progress(transaction, progress, progress.cursor, true)?;
            return Ok(WalReplayResult::unit());
        }

        if observed.len() < self.items.len()
            || (self.items.len() < MAX_BATCH_ITEMS && observed.len() != self.items.len())
        {
            return Err(WalIdempotencyError::Precondition);
        }
        for (expected, actual) in self.items.iter().zip(&observed) {
            if expected.episode_id != actual.episode_id
                || expected.evidence != actual.evidence
                || expected.predecessor_substance != actual.substance
                || expected.predecessor_visual_evidence != actual.visual_evidence
            {
                return Err(WalIdempotencyError::Precondition);
            }
        }
        for item in &self.items {
            let changed = transaction
                .execute(
                    "UPDATE episodes SET visual_evidence=?4
                     WHERE id=?1 AND substance=?2 AND visual_evidence=?3",
                    params![
                        item.episode_id,
                        item.predecessor_substance,
                        item.predecessor_visual_evidence,
                        item.visual_evidence,
                    ],
                )
                .map_err(|_| WalIdempotencyError::Unavailable)?;
            if changed != 1 {
                return Err(WalIdempotencyError::Precondition);
            }
        }
        let next_cursor = self
            .items
            .last()
            .map(|item| item.episode_id)
            .ok_or(WalIdempotencyError::Corrupt)?;
        cas_progress(transaction, progress, next_cursor, false)?;
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

impl WalLogicalDomainLedger<VisualEvidenceBackfillBatchPlan> for VisualEvidenceBackfillBatchLedger {
    fn lookup(
        connection: &Connection,
        prepared: &PreparedLogicalMutation<VisualEvidenceBackfillBatchPlan>,
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
                 FROM archive_v3_wal_visual_evidence_backfill_operations
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
        prepared: &PreparedLogicalMutation<VisualEvidenceBackfillBatchPlan>,
    ) -> Result<LogicalMutationResult> {
        require_kind(prepared)?;
        ensure_schema(transaction)?;
        if let Some(result) = Self::lookup(transaction, prepared)? {
            return Ok(LogicalMutationResult::Replayed(result));
        }
        let (row_count, result_bytes) = load_bounds(transaction)?;
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
                "INSERT INTO archive_v3_wal_visual_evidence_backfill_operations
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
                "UPDATE archive_v3_wal_visual_evidence_backfill_bounds
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Progress {
    cursor: i64,
    completed: bool,
}

struct ObservedItem {
    episode_id: i64,
    evidence: String,
    substance: String,
    visual_evidence: String,
}

fn load_marker(connection: &Connection) -> Result<Option<String>> {
    connection
        .query_row(
            "SELECT value FROM app_metadata WHERE key=?1",
            [MARKER_KEY],
            |row| row.get(0),
        )
        .optional()
        .map_err(|_| WalIdempotencyError::Unavailable)
}

fn load_next_rows(connection: &Connection, cursor: i64) -> Result<Vec<ObservedItem>> {
    type EpisodeSourceRow = (
        i64,
        Option<String>,
        Option<String>,
        Option<String>,
        Option<String>,
        String,
        String,
    );

    let episodes = {
        let mut statement = connection
            .prepare(
                "SELECT e.id,
                        substr(e.title,1,?3),substr(e.summary,1,?3),
                        substr(e.minutes_text,1,?3),substr(e.action_items,1,?3),
                        e.substance,e.visual_evidence
                 FROM episodes e
                 WHERE e.id>?1 AND e.substance='normal' AND e.visual_evidence='none'
                   AND EXISTS (
                       SELECT 1 FROM episode_members m
                       JOIN screenshots s ON s.id=m.record_id
                       WHERE m.episode_id=e.id AND m.record_type='screenshot'
                         AND s.is_duplicate=0
                   )
                 ORDER BY e.id ASC LIMIT ?2",
            )
            .map_err(|_| WalIdempotencyError::Unavailable)?;
        let rows = statement
            .query_map(
                params![
                    cursor,
                    i64::try_from(MAX_BATCH_ITEMS + 1).map_err(|_| WalIdempotencyError::Limit)?,
                    i64::try_from(EPISODE_EXCERPT_CHARS).map_err(|_| WalIdempotencyError::Limit)?,
                ],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                        row.get(5)?,
                        row.get(6)?,
                    ))
                },
            )
            .map_err(|_| WalIdempotencyError::Unavailable)?
            .collect::<std::result::Result<Vec<EpisodeSourceRow>, _>>()
            .map_err(|_| WalIdempotencyError::Unavailable)?;
        rows
    };

    let mut screens = connection
        .prepare(
            "SELECT substr(s.captured_at,1,?2),substr(s.active_app,1,?2),
                    substr(s.window_title,1,?2),substr(s.url,1,?2),
                    substr(s.ocr_text,1,?3)
             FROM episode_members m
             JOIN screenshots s ON s.id=m.record_id
             WHERE m.episode_id=?1 AND m.record_type='screenshot'
               AND s.is_duplicate=0
             ORDER BY s.captured_at ASC,s.id ASC LIMIT ?4",
        )
        .map_err(|_| WalIdempotencyError::Unavailable)?;
    let mut observed = Vec::with_capacity(episodes.len());
    for (episode_id, title, summary, minutes, actions, substance, visual_evidence) in episodes {
        let screen_lines = screens
            .query_map(
                params![
                    episode_id,
                    i64::try_from(SCREEN_FIELD_READ_CHARS)
                        .map_err(|_| WalIdempotencyError::Limit)?,
                    i64::try_from(SCREEN_OCR_CHARS).map_err(|_| WalIdempotencyError::Limit)?,
                    i64::try_from(MAX_SCREEN_ROWS).map_err(|_| WalIdempotencyError::Limit)?,
                ],
                |row| {
                    let captured_at: String = row.get(0)?;
                    let app: Option<String> = row.get(1)?;
                    let window_title: Option<String> = row.get(2)?;
                    let url: Option<String> = row.get(3)?;
                    let ocr: Option<String> = row.get(4)?;
                    Ok(format!(
                        "{captured_at} | app={} | title={} | url={} | text={}",
                        app.as_deref().unwrap_or(""),
                        window_title.as_deref().unwrap_or(""),
                        url.as_deref().unwrap_or(""),
                        ocr.as_deref().unwrap_or("")
                    ))
                },
            )
            .map_err(|_| WalIdempotencyError::Unavailable)?
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|_| WalIdempotencyError::Unavailable)?;
        if screen_lines.is_empty() {
            return Err(WalIdempotencyError::Corrupt);
        }
        let episode_text = [title, summary, minutes, actions]
            .into_iter()
            .flatten()
            .collect::<Vec<_>>()
            .join("\n");
        let episode_excerpt = episode_text
            .chars()
            .take(EPISODE_EXCERPT_CHARS)
            .collect::<String>();
        let screen_excerpt = screen_lines
            .join("\n")
            .chars()
            .take(SCREEN_EXCERPT_CHARS)
            .collect::<String>();
        let evidence = format!(
            "EPISODE TEXT:\n{episode_excerpt}\n\nSCREEN METADATA (TEXT ONLY; NO PIXELS):\n{screen_excerpt}"
        );
        validate_evidence(&evidence)?;
        observed.push(ObservedItem {
            episode_id,
            evidence,
            substance,
            visual_evidence,
        });
    }
    Ok(observed)
}

fn load_progress(connection: &Connection) -> Result<Progress> {
    let row = connection
        .query_row(
            "SELECT cursor,completed
             FROM archive_v3_wal_visual_evidence_backfill_progress WHERE singleton=1",
            [],
            |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)),
        )
        .optional()
        .map_err(|_| WalIdempotencyError::Corrupt)?
        .ok_or(WalIdempotencyError::Corrupt)?;
    if row.0 < 0 || !matches!(row.1, 0 | 1) {
        return Err(WalIdempotencyError::Corrupt);
    }
    Ok(Progress {
        cursor: row.0,
        completed: row.1 == 1,
    })
}

fn cas_progress(
    transaction: &Transaction<'_>,
    expected: Progress,
    next_cursor: i64,
    completed: bool,
) -> Result<()> {
    if next_cursor < expected.cursor || (expected.completed && !completed) {
        return Err(WalIdempotencyError::Corrupt);
    }
    let changed = transaction
        .execute(
            "UPDATE archive_v3_wal_visual_evidence_backfill_progress
             SET cursor=?1,completed=?2
             WHERE singleton=1 AND cursor=?3 AND completed=?4",
            params![
                next_cursor,
                i64::from(completed),
                expected.cursor,
                i64::from(expected.completed),
            ],
        )
        .map_err(|_| WalIdempotencyError::Unavailable)?;
    if changed != 1 {
        return Err(WalIdempotencyError::Corrupt);
    }
    Ok(())
}

fn require_kind(prepared: &PreparedLogicalMutation<VisualEvidenceBackfillBatchPlan>) -> Result<()> {
    (prepared.kind_for_owner() == WalOperationKind::ReviewerBackfill)
        .then_some(())
        .ok_or(WalIdempotencyError::ResultUnsupported)
}

fn valid_visual_evidence(value: &str) -> bool {
    matches!(value, "none" | "useful")
}

fn validate_evidence(value: &str) -> Result<()> {
    if value.is_empty()
        || value.chars().count() > MAX_EVIDENCE_CHARS
        || value.len() > MAX_EVIDENCE_BYTES
        || value.bytes().any(|byte| byte == 0)
    {
        return Err(WalIdempotencyError::Malformed);
    }
    Ok(())
}

fn schema_state(connection: &Connection) -> Result<LedgerSchemaState> {
    let present = connection
        .query_row(
            "SELECT COUNT(*) FROM sqlite_schema
             WHERE type='table' AND name IN (?1,?2,?3,?4)",
            params![SCHEMA_TABLE, LEDGER_TABLE, BOUNDS_TABLE, PROGRESS_TABLE],
            |row| row.get::<_, i64>(0),
        )
        .map_err(|_| WalIdempotencyError::Unavailable)?;
    match present {
        0 => Ok(LedgerSchemaState::Absent),
        4 => Ok(LedgerSchemaState::Present),
        _ => Err(WalIdempotencyError::Corrupt),
    }
}

fn ensure_schema(transaction: &Transaction<'_>) -> Result<()> {
    match schema_state(transaction)? {
        LedgerSchemaState::Present => validate_schema_marker(transaction),
        LedgerSchemaState::Absent => {
            transaction
                .execute_batch(
                    "CREATE TABLE archive_v3_wal_visual_evidence_backfill_schema (
                        singleton INTEGER PRIMARY KEY CHECK(singleton=1),
                        format_version INTEGER NOT NULL CHECK(format_version=1),
                        codec_version INTEGER NOT NULL CHECK(codec_version=1)
                     ) STRICT;
                     CREATE TABLE archive_v3_wal_visual_evidence_backfill_operations (
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
                     CREATE TABLE archive_v3_wal_visual_evidence_backfill_bounds (
                        singleton INTEGER PRIMARY KEY CHECK(singleton=1),
                        row_count INTEGER NOT NULL CHECK(row_count BETWEEN 0 AND 65536),
                        result_bytes INTEGER NOT NULL CHECK(result_bytes BETWEEN 0 AND 589824)
                     ) STRICT;
                     CREATE TABLE archive_v3_wal_visual_evidence_backfill_progress (
                        singleton INTEGER PRIMARY KEY CHECK(singleton=1),
                        cursor INTEGER NOT NULL CHECK(cursor>=0),
                        completed INTEGER NOT NULL CHECK(completed IN (0,1))
                     ) STRICT;
                     INSERT INTO archive_v3_wal_visual_evidence_backfill_schema
                        (singleton,format_version,codec_version) VALUES (1,1,1);
                     INSERT INTO archive_v3_wal_visual_evidence_backfill_bounds
                        (singleton,row_count,result_bytes) VALUES (1,0,0);
                     INSERT INTO archive_v3_wal_visual_evidence_backfill_progress
                        (singleton,cursor,completed) VALUES (1,0,0);",
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
             FROM archive_v3_wal_visual_evidence_backfill_schema WHERE singleton=1",
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
    let _ = load_bounds(connection)?;
    let _ = load_progress(connection)?;
    Ok(())
}

fn load_bounds(connection: &Connection) -> Result<(u32, u64)> {
    let state = connection
        .query_row(
            "SELECT row_count,result_bytes
             FROM archive_v3_wal_visual_evidence_backfill_bounds WHERE singleton=1",
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
        execute_prepared_for_owner, ExecutedLogicalMutation, LogicalMutationDisposition,
    };
    use tempfile::tempdir;

    const USER: &str = "11111111-1111-4111-8111-111111111111";
    const USER_TWO: &str = "22222222-2222-4222-8222-222222222222";

    fn install_domain_schema(connection: &Connection) {
        connection
            .execute_batch(
                "CREATE TABLE episodes(
                    id INTEGER PRIMARY KEY,title TEXT,summary TEXT,minutes_text TEXT,
                    action_items TEXT,substance TEXT NOT NULL,visual_evidence TEXT NOT NULL
                 ) STRICT;
                 CREATE TABLE screenshots(
                    id INTEGER PRIMARY KEY,captured_at TEXT NOT NULL,active_app TEXT,
                    window_title TEXT,url TEXT,ocr_text TEXT,is_duplicate INTEGER NOT NULL
                 ) STRICT;
                 CREATE TABLE episode_members(
                    episode_id INTEGER NOT NULL,record_type TEXT NOT NULL,record_id INTEGER NOT NULL,
                    PRIMARY KEY(episode_id,record_type,record_id)
                 ) STRICT;
                 CREATE TABLE app_metadata(
                    key TEXT PRIMARY KEY,value TEXT NOT NULL,
                    updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
                 ) STRICT;",
            )
            .unwrap();
    }

    fn connection() -> Connection {
        let connection = Connection::open_in_memory().unwrap();
        install_domain_schema(&connection);
        connection
    }

    fn captured_at(id: i64) -> String {
        format!("2026-08-15T00:00:{id:02}Z")
    }

    fn screen_line(id: i64) -> String {
        format!(
            "{} | app=App {id} | title=window {id} | url=https://example.com/{id} | text=ocr {id}",
            captured_at(id)
        )
    }

    fn evidence(id: i64) -> String {
        format!(
            "EPISODE TEXT:\ntitle {id}\nsummary {id}\nminutes {id}\naction {id}\n\nSCREEN METADATA (TEXT ONLY; NO PIXELS):\n{}",
            screen_line(id)
        )
    }

    fn seed(connection: &Connection, start: i64, end: i64) {
        for id in start..=end {
            connection
                .execute(
                    "INSERT INTO episodes
                     (id,title,summary,minutes_text,action_items,substance,visual_evidence)
                     VALUES (?1,?2,?3,?4,?5,'normal','none')",
                    params![
                        id,
                        format!("title {id}"),
                        format!("summary {id}"),
                        format!("minutes {id}"),
                        format!("action {id}"),
                    ],
                )
                .unwrap();
            connection
                .execute(
                    "INSERT INTO screenshots
                     (id,captured_at,active_app,window_title,url,ocr_text,is_duplicate)
                     VALUES (?1,?2,?3,?4,?5,?6,0)",
                    params![
                        id,
                        captured_at(id),
                        format!("App {id}"),
                        format!("window {id}"),
                        format!("https://example.com/{id}"),
                        format!("ocr {id}"),
                    ],
                )
                .unwrap();
            connection
                .execute(
                    "INSERT INTO episode_members(episode_id,record_type,record_id)
                     VALUES (?1,'screenshot',?1)",
                    [id],
                )
                .unwrap();
        }
    }

    fn item(id: i64, result: &str) -> VisualEvidenceBackfillItem {
        VisualEvidenceBackfillItem::new(
            id,
            evidence(id),
            "normal".into(),
            "none".into(),
            result.into(),
        )
        .unwrap()
    }

    fn plan(
        cursor: i64,
        items: Vec<VisualEvidenceBackfillItem>,
    ) -> VisualEvidenceBackfillBatchPlan {
        VisualEvidenceBackfillBatchPlan::new(USER.into(), cursor, items).unwrap()
    }

    fn execute(
        connection: &mut Connection,
        plan: VisualEvidenceBackfillBatchPlan,
    ) -> std::result::Result<
        ExecutedLogicalMutation<VisualEvidenceBackfillBatchPlan>,
        WalIdempotencyError,
    > {
        execute_prepared_for_owner(connection, PreparedLogicalMutation::prepare(plan).unwrap())
    }

    fn explicit_id(value: u8) -> WalLogicalOperationId {
        WalLogicalOperationId::from_bytes([value; 16]).unwrap()
    }

    #[test]
    fn stable_identity_is_subtype_user_cursor_and_phase_bound() {
        let first = plan(0, vec![item(1, "useful")]);
        let replay = plan(0, vec![item(1, "useful")]);
        assert_eq!(first.operation_id(), replay.operation_id());
        assert_eq!(
            first.canonical_request().unwrap(),
            replay.canonical_request().unwrap()
        );
        assert_ne!(first.operation_id(), plan(1, Vec::new()).operation_id());
        assert_ne!(first.operation_id(), plan(0, Vec::new()).operation_id());
        assert_ne!(
            first.operation_id(),
            VisualEvidenceBackfillBatchPlan::new(USER_TWO.into(), 0, vec![item(1, "useful")],)
                .unwrap()
                .operation_id()
        );
    }

    #[test]
    fn ordered_batches_complete_once_and_replay_without_rewrite() {
        let mut connection = connection();
        seed(&connection, 1, 3);
        let first = execute(
            &mut connection,
            plan(
                0,
                vec![item(1, "useful"), item(2, "none"), item(3, "useful")],
            ),
        )
        .unwrap();
        assert_eq!(first.disposition(), LogicalMutationDisposition::Applied);
        assert_eq!(
            load_progress(&connection).unwrap(),
            Progress {
                cursor: 3,
                completed: false
            }
        );
        assert_eq!(
            execute(&mut connection, plan(3, Vec::new()))
                .unwrap()
                .disposition(),
            LogicalMutationDisposition::Applied
        );
        assert_eq!(
            load_marker(&connection).unwrap().as_deref(),
            Some(MARKER_VALUE)
        );
        assert_eq!(
            execute(
                &mut connection,
                plan(
                    0,
                    vec![item(1, "useful"), item(2, "none"), item(3, "useful")],
                ),
            )
            .unwrap()
            .disposition(),
            LogicalMutationDisposition::Replayed
        );
        assert_eq!(load_bounds(&connection).unwrap(), (2, 18));
    }

    #[test]
    fn exact_source_eligibility_and_membership_are_required_before_update() {
        for mutation in [
            "UPDATE episodes SET title='changed' WHERE id=1",
            "UPDATE episodes SET substance='low' WHERE id=1",
            "UPDATE episodes SET visual_evidence='useful' WHERE id=1",
            "UPDATE screenshots SET window_title='changed' WHERE id=1",
            "DELETE FROM episode_members WHERE episode_id=1",
        ] {
            let mut connection = connection();
            seed(&connection, 1, 1);
            connection.execute(mutation, []).unwrap();
            assert_eq!(
                execute(&mut connection, plan(0, vec![item(1, "useful")]))
                    .err()
                    .unwrap(),
                WalIdempotencyError::Precondition
            );
            assert_eq!(
                connection
                    .query_row(
                        "SELECT COUNT(*) FROM sqlite_schema
                         WHERE name LIKE 'archive_v3_wal_visual_evidence_backfill_%'",
                        [],
                        |row| row.get::<_, i64>(0),
                    )
                    .unwrap(),
                0
            );
        }
    }

    #[test]
    fn a_short_batch_cannot_skip_a_later_row_and_empty_cannot_finish_early() {
        let mut connection = connection();
        seed(&connection, 1, 2);
        assert_eq!(
            execute(&mut connection, plan(0, vec![item(1, "useful")]))
                .err()
                .unwrap(),
            WalIdempotencyError::Precondition
        );
        assert_eq!(
            execute(&mut connection, plan(0, Vec::new())).err().unwrap(),
            WalIdempotencyError::Precondition
        );
    }

    #[test]
    fn duplicate_only_episode_does_not_hide_the_next_eligible_episode() {
        let mut connection = connection();
        seed(&connection, 1, 2);
        connection
            .execute("UPDATE screenshots SET is_duplicate=1 WHERE id=1", [])
            .unwrap();

        execute(&mut connection, plan(0, vec![item(2, "useful")])).unwrap();

        assert_eq!(
            load_progress(&connection).unwrap(),
            Progress {
                cursor: 2,
                completed: false
            }
        );
        assert_eq!(
            connection
                .query_row(
                    "SELECT visual_evidence FROM episodes WHERE id=1",
                    [],
                    |row| row.get::<_, String>(0),
                )
                .unwrap(),
            "none"
        );
    }

    #[test]
    fn maximum_batch_advances_exactly_one_prefix() {
        let mut connection = connection();
        let retained_id = MAX_BATCH_ITEMS as i64 + 1;
        seed(&connection, 1, retained_id);
        let items = (1..=MAX_BATCH_ITEMS as i64)
            .map(|id| item(id, "useful"))
            .collect();
        execute(&mut connection, plan(0, items)).unwrap();
        assert_eq!(
            load_progress(&connection).unwrap().cursor,
            MAX_BATCH_ITEMS as i64
        );
        assert_eq!(
            connection
                .query_row(
                    "SELECT visual_evidence FROM episodes WHERE id=?1",
                    [retained_id],
                    |row| row.get::<_, String>(0),
                )
                .unwrap(),
            "none"
        );
    }

    #[test]
    fn maximum_request_geometry_fits_the_shared_wal_cap() {
        let evidence = "🦀".repeat(MAX_EVIDENCE_CHARS);
        let items = (1..=MAX_BATCH_ITEMS as i64)
            .map(|episode_id| {
                VisualEvidenceBackfillItem::new(
                    episode_id,
                    evidence.clone(),
                    "normal".into(),
                    "none".into(),
                    "useful".into(),
                )
                .unwrap()
            })
            .collect();
        PreparedLogicalMutation::prepare(plan(0, items)).unwrap();
    }

    #[test]
    fn equal_timestamp_screens_are_rendered_in_id_order() {
        let mut connection = connection();
        seed(&connection, 1, 1);
        for (screen_id, app) in [(0, "First"), (2, "Last")] {
            connection
                .execute(
                    "INSERT INTO screenshots
                     (id,captured_at,active_app,window_title,url,ocr_text,is_duplicate)
                     VALUES (?1,?2,?3,'','','',0)",
                    params![screen_id, captured_at(1), app],
                )
                .unwrap();
            connection
                .execute(
                    "INSERT INTO episode_members(episode_id,record_type,record_id)
                     VALUES (1,'screenshot',?1)",
                    [screen_id],
                )
                .unwrap();
        }
        let expected = format!(
            "EPISODE TEXT:\ntitle 1\nsummary 1\nminutes 1\naction 1\n\nSCREEN METADATA (TEXT ONLY; NO PIXELS):\n{} | app=First | title= | url= | text=\n{}\n{} | app=Last | title= | url= | text=",
            captured_at(1),
            screen_line(1),
            captured_at(1),
        );
        let exact = VisualEvidenceBackfillItem::new(
            1,
            expected,
            "normal".into(),
            "none".into(),
            "useful".into(),
        )
        .unwrap();
        execute(&mut connection, plan(0, vec![exact])).unwrap();
    }

    #[test]
    fn cursor_order_and_changed_same_operation_fail_closed() {
        let mut connection = connection();
        seed(&connection, 1, 1);
        assert_eq!(
            execute(&mut connection, plan(1, Vec::new())).err().unwrap(),
            WalIdempotencyError::Precondition
        );
        let fixed = || {
            VisualEvidenceBackfillBatchPlan::with_operation_id(
                explicit_id(8),
                USER,
                0,
                vec![item(1, "useful")],
            )
            .unwrap()
        };
        execute(&mut connection, fixed()).unwrap();
        let changed = VisualEvidenceBackfillBatchPlan::with_operation_id(
            explicit_id(8),
            USER,
            0,
            vec![item(1, "none")],
        )
        .unwrap();
        assert_eq!(
            execute(&mut connection, changed).err().unwrap(),
            WalIdempotencyError::FingerprintConflict
        );
    }

    #[test]
    fn capacity_is_reserved_before_domain_mutation_but_replay_survives() {
        let mut connection = connection();
        seed(&connection, 1, 2);
        execute(
            &mut connection,
            plan(0, vec![item(1, "useful"), item(2, "none")]),
        )
        .unwrap();
        connection
            .execute(
                "UPDATE archive_v3_wal_visual_evidence_backfill_bounds SET row_count=?1",
                [i64::from(MAX_ROWS)],
            )
            .unwrap();
        assert_eq!(
            execute(
                &mut connection,
                plan(0, vec![item(1, "useful"), item(2, "none")]),
            )
            .unwrap()
            .disposition(),
            LogicalMutationDisposition::Replayed
        );
        seed(&connection, 3, 3);
        assert_eq!(
            execute(&mut connection, plan(2, vec![item(3, "useful")]))
                .err()
                .unwrap(),
            WalIdempotencyError::Limit
        );
        assert_eq!(
            connection
                .query_row(
                    "SELECT visual_evidence FROM episodes WHERE id=3",
                    [],
                    |row| row.get::<_, String>(0),
                )
                .unwrap(),
            "none"
        );
    }

    #[test]
    fn late_ledger_failure_rolls_back_row_and_progress() {
        let mut connection = connection();
        seed(&connection, 1, 1);
        {
            let transaction = connection.transaction().unwrap();
            ensure_schema(&transaction).unwrap();
            transaction.commit().unwrap();
        }
        connection
            .execute_batch(
                "CREATE TRIGGER reject_visual_ledger_insert
                 BEFORE INSERT ON archive_v3_wal_visual_evidence_backfill_operations
                 BEGIN SELECT RAISE(ABORT, 'injected'); END;",
            )
            .unwrap();
        assert_eq!(
            execute(&mut connection, plan(0, vec![item(1, "useful")]))
                .err()
                .unwrap(),
            WalIdempotencyError::Unavailable
        );
        assert_eq!(
            load_progress(&connection).unwrap(),
            Progress {
                cursor: 0,
                completed: false
            }
        );
        assert_eq!(
            connection
                .query_row(
                    "SELECT visual_evidence FROM episodes WHERE id=1",
                    [],
                    |row| row.get::<_, String>(0),
                )
                .unwrap(),
            "none"
        );
    }

    #[test]
    fn late_ledger_failure_rolls_back_completion_marker_and_progress() {
        let mut connection = connection();
        {
            let transaction = connection.transaction().unwrap();
            ensure_schema(&transaction).unwrap();
            transaction.commit().unwrap();
        }
        connection
            .execute_batch(
                "CREATE TRIGGER reject_visual_completion_ledger_insert
                 BEFORE INSERT ON archive_v3_wal_visual_evidence_backfill_operations
                 BEGIN SELECT RAISE(ABORT, 'injected'); END;",
            )
            .unwrap();
        assert_eq!(
            execute(&mut connection, plan(0, Vec::new())).err().unwrap(),
            WalIdempotencyError::Unavailable
        );
        assert_eq!(load_marker(&connection).unwrap(), None);
        assert_eq!(
            load_progress(&connection).unwrap(),
            Progress {
                cursor: 0,
                completed: false
            }
        );
    }

    #[test]
    fn partial_schema_and_result_tamper_fail_closed() {
        let mut partial = connection();
        partial
            .execute_batch(
                "CREATE TABLE archive_v3_wal_visual_evidence_backfill_schema(
                    singleton INTEGER PRIMARY KEY,format_version INTEGER,codec_version INTEGER
                 ) STRICT;",
            )
            .unwrap();
        assert_eq!(
            execute(&mut partial, plan(0, Vec::new())).err().unwrap(),
            WalIdempotencyError::Corrupt
        );

        let mut tampered = connection();
        execute(&mut tampered, plan(0, Vec::new())).unwrap();
        tampered
            .execute(
                "UPDATE archive_v3_wal_visual_evidence_backfill_operations
                 SET result_commitment=?1",
                [[9u8; 32].as_slice()],
            )
            .unwrap();
        assert_eq!(
            execute(&mut tampered, plan(0, Vec::new())).err().unwrap(),
            WalIdempotencyError::Corrupt
        );
    }

    #[test]
    fn close_reopen_replays_exact_batch_and_continues() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("archive.sqlite");
        {
            let mut connection = Connection::open(&path).unwrap();
            install_domain_schema(&connection);
            seed(&connection, 1, 2);
            execute(
                &mut connection,
                plan(0, vec![item(1, "useful"), item(2, "none")]),
            )
            .unwrap();
        }
        let mut connection = Connection::open(&path).unwrap();
        assert_eq!(
            execute(
                &mut connection,
                plan(0, vec![item(1, "useful"), item(2, "none")]),
            )
            .unwrap()
            .disposition(),
            LogicalMutationDisposition::Replayed
        );
        execute(&mut connection, plan(2, Vec::new())).unwrap();
        assert_eq!(
            load_progress(&connection).unwrap(),
            Progress {
                cursor: 2,
                completed: true
            }
        );
    }

    #[test]
    fn exact_legacy_marker_is_adopted_but_conflict_is_rejected() {
        let mut adopted = connection();
        seed(&adopted, 1, 2);
        adopted
            .execute(
                "INSERT INTO app_metadata(key,value) VALUES (?1,?2)",
                params![MARKER_KEY, MARKER_VALUE],
            )
            .unwrap();
        execute(&mut adopted, plan(0, Vec::new())).unwrap();
        assert_eq!(
            load_progress(&adopted).unwrap(),
            Progress {
                cursor: 0,
                completed: true
            }
        );

        let mut conflicting = connection();
        conflicting
            .execute(
                "INSERT INTO app_metadata(key,value) VALUES (?1,'other')",
                [MARKER_KEY],
            )
            .unwrap();
        assert_eq!(
            execute(&mut conflicting, plan(0, Vec::new()))
                .err()
                .unwrap(),
            WalIdempotencyError::Precondition
        );
    }

    #[test]
    fn constructors_reject_unbounded_or_noncanonical_inputs() {
        assert!(VisualEvidenceBackfillBatchPlan::new("bad".into(), 0, Vec::new()).is_err());
        assert!(VisualEvidenceBackfillBatchPlan::new(USER.into(), -1, Vec::new()).is_err());
        assert!(VisualEvidenceBackfillItem::new(
            0,
            String::new(),
            "normal".into(),
            "none".into(),
            "useful".into(),
        )
        .is_err());
        assert!(VisualEvidenceBackfillItem::new(
            1,
            String::new(),
            "low".into(),
            "none".into(),
            "useful".into(),
        )
        .is_err());
        assert!(VisualEvidenceBackfillItem::new(
            1,
            String::new(),
            "normal".into(),
            "none".into(),
            "invalid".into(),
        )
        .is_err());
        assert!(VisualEvidenceBackfillItem::new(
            1,
            "x".repeat(MAX_EVIDENCE_CHARS + 1),
            "normal".into(),
            "none".into(),
            "useful".into(),
        )
        .is_err());
        let too_many = (1..=MAX_BATCH_ITEMS as i64 + 1)
            .map(|id| item(id, "useful"))
            .collect();
        assert!(VisualEvidenceBackfillBatchPlan::new(USER.into(), 0, too_many).is_err());
        assert!(VisualEvidenceBackfillBatchPlan::new(
            USER.into(),
            0,
            vec![item(2, "useful"), item(1, "useful")],
        )
        .is_err());
    }
}
