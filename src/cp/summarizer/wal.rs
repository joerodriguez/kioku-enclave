#![allow(
    dead_code,
    reason = "inactive ADR-0022 backfills are reviewed before B-attempt or launcher ownership"
)]

//! Inactive exact ADR-0009 substance and private ADR-0010 visual-evidence
//! backfill WAL domains.
//!
//! A future owner supplies one ordered, cursor-bound batch after classification.
//! This child re-reads the exact bounded model input, updates only that prefix,
//! and advances its private cursor in the same transaction as permanent replay.
//! An empty exact tail alone may write the completion marker. It cannot reserve
//! Vertex capacity, invoke a model, call Store, launch work, or acknowledge a
//! request.

pub(super) mod embedding;
mod visual_evidence;
pub(in crate::cp) mod window;
pub(in crate::cp) use embedding::EpisodeEmbedding;
pub(crate) use embedding::{EpisodeEmbeddingBatchLedger, EpisodeEmbeddingBatchPlan};
pub(crate) use visual_evidence::{
    VisualEvidenceBackfillBatchLedger, VisualEvidenceBackfillBatchPlan,
};
pub(crate) use window::{EpisodeWindowUpsertLedger, EpisodeWindowUpsertPlan};

use rusqlite::{params, Connection, OptionalExtension, Transaction};
use zeroize::Zeroizing;

use crate::archive_v3_wal_idempotency::{
    DomainLedgerBounds, LogicalMutationResult, PreparedLogicalMutation, WalIdempotencyError,
    WalLogicalDomainLedger, WalLogicalDomainPlan, WalLogicalOperationId, WalOperationKind,
    WalReplayResult,
};

const REQUEST_V1: u16 = 1;
const SUBTYPE: &[u8] = b"adr-0009-substance-backfill-v1";
const MARKER_KEY: &str = "adr_0009_substance_backfill_v1";
const MARKER_VALUE: &str = "complete";
const MARKER_TIME: &str = "2026-08-14T00:00:00.000Z";
const MAX_UUID_BYTES: usize = 36;
const MAX_INPUT_CHARS: usize = 6_000;
const MAX_INPUT_BYTES: usize = MAX_INPUT_CHARS * 4;
const MAX_BATCH_ITEMS: usize = 32;
const ENCODED_UNIT_RESULT_BYTES: usize = 9;
const MAX_ROWS: u32 = 65_536;
const MAX_RESULT_BYTES: u64 = MAX_ROWS as u64 * ENCODED_UNIT_RESULT_BYTES as u64;
const SCHEMA_TABLE: &str = "archive_v3_wal_substance_backfill_schema";
const LEDGER_TABLE: &str = "archive_v3_wal_substance_backfill_operations";
const BOUNDS_TABLE: &str = "archive_v3_wal_substance_backfill_bounds";
const PROGRESS_TABLE: &str = "archive_v3_wal_substance_backfill_progress";
const BOUNDS: DomainLedgerBounds = DomainLedgerBounds::new(MAX_ROWS, MAX_RESULT_BYTES);

type Result<T> = std::result::Result<T, WalIdempotencyError>;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct SubstanceBackfillItem {
    episode_id: i64,
    input: String,
    predecessor: String,
    substance: String,
}

impl SubstanceBackfillItem {
    pub(super) fn new(
        episode_id: i64,
        input: String,
        predecessor: String,
        substance: String,
    ) -> Result<Self> {
        if episode_id <= 0
            || input.chars().count() > MAX_INPUT_CHARS
            || input.len() > MAX_INPUT_BYTES
            || !valid_substance(&predecessor)
            || !valid_substance(&substance)
        {
            return Err(WalIdempotencyError::Malformed);
        }
        Ok(Self {
            episode_id,
            input,
            predecessor,
            substance,
        })
    }
}

/// One exact next batch, or an empty exact-tail completion, for one already
/// authenticated stable account.
pub(crate) struct SubstanceBackfillBatchPlan {
    operation_id: WalLogicalOperationId,
    user_id: String,
    cursor: i64,
    items: Vec<SubstanceBackfillItem>,
}

impl SubstanceBackfillBatchPlan {
    pub(super) fn new(
        user_id: String,
        cursor: i64,
        items: Vec<SubstanceBackfillItem>,
    ) -> Result<Self> {
        Self::build(None, user_id, cursor, items)
    }

    fn build(
        operation_id: Option<WalLogicalOperationId>,
        user_id: String,
        cursor: i64,
        items: Vec<SubstanceBackfillItem>,
    ) -> Result<Self> {
        validate_uuid(&user_id)?;
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
        items: Vec<SubstanceBackfillItem>,
    ) -> Result<Self> {
        Self::build(Some(operation_id), user_id.to_owned(), cursor, items)
    }
}

pub(crate) struct SubstanceBackfillBatchLedger;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum LedgerSchemaState {
    Absent,
    Present,
}

impl WalLogicalDomainPlan for SubstanceBackfillBatchPlan {
    type Ledger = SubstanceBackfillBatchLedger;
    type Output = ();

    fn kind(&self) -> WalOperationKind {
        WalOperationKind::ReviewerBackfill
    }

    fn operation_id(&self) -> WalLogicalOperationId {
        self.operation_id
    }

    fn canonical_request(&self) -> Result<Zeroizing<Vec<u8>>> {
        let mut request = Zeroizing::new(Vec::with_capacity(
            96usize.saturating_add(
                self.items
                    .iter()
                    .map(|item| item.input.len().saturating_add(40))
                    .sum::<usize>(),
            ),
        ));
        request.extend_from_slice(&REQUEST_V1.to_be_bytes());
        encode_bytes(&mut request, SUBTYPE)?;
        encode_bytes(&mut request, self.user_id.as_bytes())?;
        request.extend_from_slice(&self.cursor.to_be_bytes());
        request.extend_from_slice(
            &u16::try_from(self.items.len())
                .map_err(|_| WalIdempotencyError::Limit)?
                .to_be_bytes(),
        );
        for item in &self.items {
            request.extend_from_slice(&item.episode_id.to_be_bytes());
            encode_bytes(&mut request, item.input.as_bytes())?;
            encode_bytes(&mut request, item.predecessor.as_bytes())?;
            encode_bytes(&mut request, item.substance.as_bytes())?;
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
                || expected.input != actual.input
                || expected.predecessor != actual.substance
            {
                return Err(WalIdempotencyError::Precondition);
            }
        }
        for item in &self.items {
            let changed = transaction
                .execute(
                    "UPDATE episodes SET substance=?3 WHERE id=?1 AND substance=?2",
                    params![item.episode_id, item.predecessor, item.substance],
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

impl WalLogicalDomainLedger<SubstanceBackfillBatchPlan> for SubstanceBackfillBatchLedger {
    fn lookup(
        connection: &Connection,
        prepared: &PreparedLogicalMutation<SubstanceBackfillBatchPlan>,
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
                 FROM archive_v3_wal_substance_backfill_operations
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
        prepared: &PreparedLogicalMutation<SubstanceBackfillBatchPlan>,
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
                "INSERT INTO archive_v3_wal_substance_backfill_operations
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
                "UPDATE archive_v3_wal_substance_backfill_bounds
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

#[derive(Debug, PartialEq, Eq)]
struct ObservedItem {
    episode_id: i64,
    input: String,
    substance: String,
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
    let mut statement = connection
        .prepare(
            "SELECT id,title,summary,minutes_text,substance
             FROM episodes WHERE id>?1 ORDER BY id ASC LIMIT ?2",
        )
        .map_err(|_| WalIdempotencyError::Unavailable)?;
    let rows = statement
        .query_map(
            params![
                cursor,
                i64::try_from(MAX_BATCH_ITEMS + 1).map_err(|_| WalIdempotencyError::Limit)?
            ],
            |row| {
                let parts = [
                    row.get::<_, Option<String>>(1)?,
                    row.get::<_, Option<String>>(2)?,
                    row.get::<_, Option<String>>(3)?,
                ];
                let joined = parts.into_iter().flatten().collect::<Vec<_>>().join("\n");
                Ok(ObservedItem {
                    episode_id: row.get(0)?,
                    input: joined.chars().take(MAX_INPUT_CHARS).collect(),
                    substance: row.get(4)?,
                })
            },
        )
        .map_err(|_| WalIdempotencyError::Unavailable)?
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|_| WalIdempotencyError::Unavailable)?;
    Ok(rows)
}

fn load_progress(connection: &Connection) -> Result<Progress> {
    let row = connection
        .query_row(
            "SELECT cursor,completed
             FROM archive_v3_wal_substance_backfill_progress WHERE singleton=1",
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
            "UPDATE archive_v3_wal_substance_backfill_progress
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

fn require_kind(prepared: &PreparedLogicalMutation<SubstanceBackfillBatchPlan>) -> Result<()> {
    (prepared.kind_for_owner() == WalOperationKind::ReviewerBackfill)
        .then_some(())
        .ok_or(WalIdempotencyError::ResultUnsupported)
}

fn valid_substance(value: &str) -> bool {
    matches!(value, "none" | "low" | "normal")
}

fn validate_uuid(value: &str) -> Result<()> {
    if value.len() != MAX_UUID_BYTES
        || !value.bytes().enumerate().all(|(index, byte)| match index {
            8 | 13 | 18 | 23 => byte == b'-',
            _ => byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte),
        })
    {
        return Err(WalIdempotencyError::Malformed);
    }
    Ok(())
}

fn encode_bytes(output: &mut Vec<u8>, value: &[u8]) -> Result<()> {
    let length = u32::try_from(value.len()).map_err(|_| WalIdempotencyError::Limit)?;
    output.extend_from_slice(&length.to_be_bytes());
    output.extend_from_slice(value);
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
                    "CREATE TABLE archive_v3_wal_substance_backfill_schema (
                        singleton INTEGER PRIMARY KEY CHECK(singleton=1),
                        format_version INTEGER NOT NULL CHECK(format_version=1),
                        codec_version INTEGER NOT NULL CHECK(codec_version=1)
                     ) STRICT;
                     CREATE TABLE archive_v3_wal_substance_backfill_operations (
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
                     CREATE TABLE archive_v3_wal_substance_backfill_bounds (
                        singleton INTEGER PRIMARY KEY CHECK(singleton=1),
                        row_count INTEGER NOT NULL CHECK(row_count BETWEEN 0 AND 65536),
                        result_bytes INTEGER NOT NULL CHECK(result_bytes BETWEEN 0 AND 589824)
                     ) STRICT;
                     CREATE TABLE archive_v3_wal_substance_backfill_progress (
                        singleton INTEGER PRIMARY KEY CHECK(singleton=1),
                        cursor INTEGER NOT NULL CHECK(cursor>=0),
                        completed INTEGER NOT NULL CHECK(completed IN (0,1))
                     ) STRICT;
                     INSERT INTO archive_v3_wal_substance_backfill_schema
                        (singleton,format_version,codec_version) VALUES (1,1,1);
                     INSERT INTO archive_v3_wal_substance_backfill_bounds
                        (singleton,row_count,result_bytes) VALUES (1,0,0);
                     INSERT INTO archive_v3_wal_substance_backfill_progress
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
             FROM archive_v3_wal_substance_backfill_schema WHERE singleton=1",
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
             FROM archive_v3_wal_substance_backfill_bounds WHERE singleton=1",
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
                    substance TEXT NOT NULL
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

    fn seed(connection: &Connection, start: i64, end: i64) {
        for id in start..=end {
            connection
                .execute(
                    "INSERT INTO episodes(id,title,summary,minutes_text,substance)
                     VALUES (?1,?2,?3,?4,'normal')",
                    params![
                        id,
                        format!("title {id}"),
                        format!("summary {id}"),
                        format!("minutes {id}"),
                    ],
                )
                .unwrap();
        }
    }

    fn item(id: i64, substance: &str) -> SubstanceBackfillItem {
        SubstanceBackfillItem::new(
            id,
            format!("title {id}\nsummary {id}\nminutes {id}"),
            "normal".into(),
            substance.into(),
        )
        .unwrap()
    }

    fn plan(cursor: i64, items: Vec<SubstanceBackfillItem>) -> SubstanceBackfillBatchPlan {
        SubstanceBackfillBatchPlan::new(USER.into(), cursor, items).unwrap()
    }

    fn execute(
        connection: &mut Connection,
        plan: SubstanceBackfillBatchPlan,
    ) -> std::result::Result<ExecutedLogicalMutation<SubstanceBackfillBatchPlan>, WalIdempotencyError>
    {
        execute_prepared_for_owner(connection, PreparedLogicalMutation::prepare(plan).unwrap())
    }

    fn explicit_id(value: u8) -> WalLogicalOperationId {
        WalLogicalOperationId::from_bytes([value; 16]).unwrap()
    }

    #[test]
    fn stable_identity_is_subtype_user_cursor_and_phase_bound() {
        let first = plan(0, vec![item(1, "low")]);
        let replay = plan(0, vec![item(1, "low")]);
        assert_eq!(first.operation_id(), replay.operation_id());
        assert_eq!(
            first.canonical_request().unwrap(),
            replay.canonical_request().unwrap()
        );
        assert_ne!(first.operation_id(), plan(1, Vec::new()).operation_id());
        assert_ne!(first.operation_id(), plan(0, Vec::new()).operation_id());
        assert_ne!(
            first.operation_id(),
            SubstanceBackfillBatchPlan::new(USER_TWO.into(), 0, vec![item(1, "low")])
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
            plan(0, vec![item(1, "low"), item(2, "none"), item(3, "normal")]),
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
            load_progress(&connection).unwrap(),
            Progress {
                cursor: 3,
                completed: true
            }
        );
        assert_eq!(
            execute(
                &mut connection,
                plan(0, vec![item(1, "low"), item(2, "none"), item(3, "normal")],),
            )
            .unwrap()
            .disposition(),
            LogicalMutationDisposition::Replayed
        );
        assert_eq!(load_bounds(&connection).unwrap(), (2, 18));
    }

    #[test]
    fn exact_next_source_and_predecessor_are_required_before_any_update() {
        for mutation in [
            "UPDATE episodes SET title='changed' WHERE id=1",
            "UPDATE episodes SET substance='low' WHERE id=1",
            "DELETE FROM episodes WHERE id=1",
        ] {
            let mut connection = connection();
            seed(&connection, 1, 2);
            connection.execute(mutation, []).unwrap();
            assert_eq!(
                execute(
                    &mut connection,
                    plan(0, vec![item(1, "low"), item(2, "none")]),
                )
                .err()
                .unwrap(),
                WalIdempotencyError::Precondition
            );
            assert_eq!(
                connection
                    .query_row(
                        "SELECT COUNT(*) FROM sqlite_schema
                         WHERE name LIKE 'archive_v3_wal_substance_backfill_%'",
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
            execute(&mut connection, plan(0, vec![item(1, "low")]))
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
    fn maximum_batch_advances_exactly_one_prefix() {
        let mut connection = connection();
        seed(&connection, 1, 33);
        let items = (1..=MAX_BATCH_ITEMS as i64)
            .map(|id| item(id, "low"))
            .collect();
        execute(&mut connection, plan(0, items)).unwrap();
        assert_eq!(load_progress(&connection).unwrap().cursor, 32);
        assert_eq!(
            connection
                .query_row("SELECT substance FROM episodes WHERE id=33", [], |row| {
                    row.get::<_, String>(0)
                })
                .unwrap(),
            "normal"
        );
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
            SubstanceBackfillBatchPlan::with_operation_id(
                explicit_id(7),
                USER,
                0,
                vec![item(1, "low")],
            )
            .unwrap()
        };
        execute(&mut connection, fixed()).unwrap();
        let changed = SubstanceBackfillBatchPlan::with_operation_id(
            explicit_id(7),
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
            plan(0, vec![item(1, "low"), item(2, "none")]),
        )
        .unwrap();
        connection
            .execute(
                "UPDATE archive_v3_wal_substance_backfill_bounds SET row_count=?1",
                [i64::from(MAX_ROWS)],
            )
            .unwrap();
        assert_eq!(
            execute(
                &mut connection,
                plan(0, vec![item(1, "low"), item(2, "none")]),
            )
            .unwrap()
            .disposition(),
            LogicalMutationDisposition::Replayed
        );
        seed(&connection, 3, 3);
        assert_eq!(
            execute(&mut connection, plan(2, vec![item(3, "low")]))
                .err()
                .unwrap(),
            WalIdempotencyError::Limit
        );
        assert_eq!(
            connection
                .query_row("SELECT substance FROM episodes WHERE id=3", [], |row| {
                    row.get::<_, String>(0)
                })
                .unwrap(),
            "normal"
        );
    }

    #[test]
    fn late_ledger_failure_rolls_back_rows_and_progress() {
        let mut connection = connection();
        seed(&connection, 1, 1);
        {
            let transaction = connection.transaction().unwrap();
            ensure_schema(&transaction).unwrap();
            transaction.commit().unwrap();
        }
        connection
            .execute_batch(
                "CREATE TRIGGER reject_substance_ledger_insert
                 BEFORE INSERT ON archive_v3_wal_substance_backfill_operations
                 BEGIN SELECT RAISE(ABORT, 'injected'); END;",
            )
            .unwrap();
        assert_eq!(
            execute(&mut connection, plan(0, vec![item(1, "low")]))
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
                .query_row("SELECT substance FROM episodes WHERE id=1", [], |row| {
                    row.get::<_, String>(0)
                })
                .unwrap(),
            "normal"
        );
        assert_eq!(load_marker(&connection).unwrap(), None);
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
                "CREATE TRIGGER reject_substance_completion_ledger_insert
                 BEFORE INSERT ON archive_v3_wal_substance_backfill_operations
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
                "CREATE TABLE archive_v3_wal_substance_backfill_schema(
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
                "UPDATE archive_v3_wal_substance_backfill_operations
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
                plan(0, vec![item(1, "low"), item(2, "none")]),
            )
            .unwrap();
        }
        let mut connection = Connection::open(&path).unwrap();
        assert_eq!(
            execute(
                &mut connection,
                plan(0, vec![item(1, "low"), item(2, "none")]),
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
        assert!(SubstanceBackfillBatchPlan::new("bad".into(), 0, Vec::new()).is_err());
        assert!(SubstanceBackfillBatchPlan::new(USER.into(), -1, Vec::new()).is_err());
        assert!(
            SubstanceBackfillItem::new(0, String::new(), "normal".into(), "low".into()).is_err()
        );
        assert!(
            SubstanceBackfillItem::new(1, String::new(), "invalid".into(), "low".into()).is_err()
        );
        assert!(SubstanceBackfillItem::new(
            1,
            "x".repeat(MAX_INPUT_BYTES + 1),
            "normal".into(),
            "low".into(),
        )
        .is_err());
        let too_many = (1..=MAX_BATCH_ITEMS as i64 + 1)
            .map(|id| item(id, "low"))
            .collect();
        assert!(SubstanceBackfillBatchPlan::new(USER.into(), 0, too_many).is_err());
        assert!(SubstanceBackfillBatchPlan::new(
            USER.into(),
            0,
            vec![item(2, "low"), item(1, "low")],
        )
        .is_err());
    }
}
