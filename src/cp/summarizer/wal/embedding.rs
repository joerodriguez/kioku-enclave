//! Episode embedding batch as a sealed WAL plan (ADR-0022 F9).
//!
//! The cheapest real plan — one table, no provider, durable input ids, a
//! convergent write — and it repairs the already-sealed finalization path,
//! which today leaves every finalized episode's search vector stale.
//!
//! The per-id **content** commitment is load-bearing: the finalizer re-embeds
//! the same ids after finalization rewrites `title`/`summary`, and that must
//! be a **new** operation, not a false replay. The encoder is the in-TEE
//! candle engine — no network, KMS, or GCS — so no provider facts are
//! carried. `vec0` does not honour ON CONFLICT, so the write is spelled
//! DELETE + INSERT, verbatim the legacy helper; `apply()` re-reads each blob
//! and requires byte equality, making the plan self-verifying.

use rusqlite::{params, Connection, OptionalExtension, Transaction};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::archive_v3_wal_idempotency::{
    stable_operation_source, DomainLedgerBounds, LogicalMutationResult, PreparedLogicalMutation,
    WalIdempotencyError, WalLogicalDomainLedger, WalLogicalDomainPlan, WalLogicalOperationId,
    WalOperationKind, WalReplayResult,
};

const REQUEST_V1: u16 = 1;
const SUBTYPE: &[u8] = b"adr-0022-episode-embedding-batch-v1";
const EMBEDDING_DIMENSION: usize = 384;
const EMBEDDING_BYTES: usize = EMBEDDING_DIMENSION * 4;
const MAX_BATCH: usize = 64;
const ENCODED_UNIT_RESULT_BYTES: usize = 9;
const SCHEMA_TABLE: &str = "archive_v3_wal_episode_embedding_schema";
const LEDGER_TABLE: &str = "archive_v3_wal_episode_embedding_operations";
const STATE_TABLE: &str = "archive_v3_wal_episode_embedding_state";
const MAX_ROWS: u32 = 65_536;
const MAX_RESULT_BYTES: u64 = 65_536 * 9;
const BOUNDS: DomainLedgerBounds = DomainLedgerBounds::new(MAX_ROWS, MAX_RESULT_BYTES);

type Result<T> = std::result::Result<T, WalIdempotencyError>;

/// One episode's embedding with the commitment to the exact text it encodes.
#[derive(Clone)]
pub(in crate::cp) struct EpisodeEmbedding {
    episode_id: i64,
    text_commitment: [u8; 32],
    vector_bytes: Vec<u8>,
}

impl EpisodeEmbedding {
    pub(in crate::cp) fn new(
        episode_id: i64,
        text_commitment: [u8; 32],
        vector_bytes: Vec<u8>,
    ) -> Result<Self> {
        if episode_id <= 0 || text_commitment == [0; 32] || vector_bytes.len() != EMBEDDING_BYTES {
            return Err(WalIdempotencyError::Malformed);
        }
        Ok(Self {
            episode_id,
            text_commitment,
            vector_bytes,
        })
    }
}

pub(crate) struct EpisodeEmbeddingBatchPlan {
    operation_id: WalLogicalOperationId,
    account_id: String,
    entries: Vec<EpisodeEmbedding>,
}

impl EpisodeEmbeddingBatchPlan {
    pub(in crate::cp) fn new(account_id: String, entries: Vec<EpisodeEmbedding>) -> Result<Self> {
        crate::store::validate_user_id(&account_id).map_err(|_| WalIdempotencyError::Malformed)?;
        if entries.is_empty() || entries.len() > MAX_BATCH {
            return Err(WalIdempotencyError::Malformed);
        }
        if !entries
            .windows(2)
            .all(|pair| pair[0].episode_id < pair[1].episode_id)
        {
            return Err(WalIdempotencyError::Malformed);
        }
        let mut payload = Sha256::new();
        hash_field(&mut payload, &(entries.len() as u32).to_be_bytes())?;
        for entry in &entries {
            hash_field(&mut payload, &entry.episode_id.to_be_bytes())?;
            hash_field(&mut payload, &entry.text_commitment)?;
            let vector_commitment: [u8; 32] = Sha256::digest(&entry.vector_bytes).into();
            hash_field(&mut payload, &vector_commitment)?;
        }
        let payload: [u8; 32] = payload.finalize().into();
        let source = stable_operation_source(SUBTYPE, &[account_id.as_bytes(), &payload])?;
        let operation_id =
            WalLogicalOperationId::from_stable_source(WalOperationKind::ReviewerBackfill, &source)?;
        Ok(Self {
            operation_id,
            account_id,
            entries,
        })
    }
}

pub(crate) struct EpisodeEmbeddingBatchLedger;

impl WalLogicalDomainPlan for EpisodeEmbeddingBatchPlan {
    type Ledger = EpisodeEmbeddingBatchLedger;
    type Output = ();

    fn kind(&self) -> WalOperationKind {
        WalOperationKind::ReviewerBackfill
    }

    fn operation_id(&self) -> WalLogicalOperationId {
        self.operation_id
    }

    fn canonical_request(&self) -> Result<Zeroizing<Vec<u8>>> {
        let mut request = Zeroizing::new(Vec::with_capacity(
            64 + self.entries.len() * (EMBEDDING_BYTES + 48),
        ));
        request.extend_from_slice(&REQUEST_V1.to_be_bytes());
        encode_bytes(&mut request, SUBTYPE)?;
        encode_string(&mut request, &self.account_id)?;
        encode_len(&mut request, self.entries.len())?;
        for entry in &self.entries {
            request.extend_from_slice(&entry.episode_id.to_be_bytes());
            request.extend_from_slice(&entry.text_commitment);
            encode_bytes(&mut request, &entry.vector_bytes)?;
        }
        Ok(request)
    }

    fn apply(&self, transaction: &Transaction<'_>) -> Result<WalReplayResult> {
        for entry in &self.entries {
            // The episode must exist: a vector for a deleted episode would be
            // an orphan the search path can join against.
            let exists: i64 = transaction
                .query_row(
                    "SELECT COUNT(*) FROM episodes WHERE id=?1",
                    [entry.episode_id],
                    |row| row.get(0),
                )
                .map_err(|_| WalIdempotencyError::Unavailable)?;
            if exists != 1 {
                return Err(WalIdempotencyError::Precondition);
            }
            // vec0 has no ON CONFLICT: DELETE + INSERT, verbatim the legacy
            // helper. Identical bytes make the pair convergent.
            transaction
                .execute(
                    "DELETE FROM vec_episodes WHERE episode_id = ?1",
                    [entry.episode_id],
                )
                .map_err(|_| WalIdempotencyError::Unavailable)?;
            transaction
                .execute(
                    "INSERT INTO vec_episodes (episode_id, embedding) VALUES (?1, ?2)",
                    params![entry.episode_id, entry.vector_bytes.as_slice()],
                )
                .map_err(|_| WalIdempotencyError::Unavailable)?;
            // Self-verifying: the stored blob must be byte-identical.
            let stored: Vec<u8> = transaction
                .query_row(
                    "SELECT embedding FROM vec_episodes WHERE episode_id = ?1",
                    [entry.episode_id],
                    |row| row.get(0),
                )
                .map_err(|_| WalIdempotencyError::Unavailable)?;
            if stored != entry.vector_bytes {
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

impl WalLogicalDomainLedger<EpisodeEmbeddingBatchPlan> for EpisodeEmbeddingBatchLedger {
    fn lookup(
        connection: &Connection,
        prepared: &PreparedLogicalMutation<EpisodeEmbeddingBatchPlan>,
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
                 FROM archive_v3_wal_episode_embedding_operations
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
        prepared: &PreparedLogicalMutation<EpisodeEmbeddingBatchPlan>,
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
                "INSERT INTO archive_v3_wal_episode_embedding_operations
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
                "UPDATE archive_v3_wal_episode_embedding_state
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

fn require_kind(prepared: &PreparedLogicalMutation<EpisodeEmbeddingBatchPlan>) -> Result<()> {
    if prepared.kind_for_owner() != WalOperationKind::ReviewerBackfill {
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
                    "CREATE TABLE archive_v3_wal_episode_embedding_schema (
                        singleton INTEGER PRIMARY KEY CHECK(singleton=1),
                        format_version INTEGER NOT NULL CHECK(format_version=1),
                        codec_version INTEGER NOT NULL CHECK(codec_version=1)
                     ) STRICT;
                     CREATE TABLE archive_v3_wal_episode_embedding_operations (
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
                     CREATE TABLE archive_v3_wal_episode_embedding_state (
                        singleton INTEGER PRIMARY KEY CHECK(singleton=1),
                        row_count INTEGER NOT NULL CHECK(row_count BETWEEN 0 AND 65536),
                        result_bytes INTEGER NOT NULL CHECK(result_bytes BETWEEN 0 AND 589824)
                     ) STRICT;
                     INSERT INTO archive_v3_wal_episode_embedding_schema
                        (singleton,format_version,codec_version) VALUES (1,1,1);
                     INSERT INTO archive_v3_wal_episode_embedding_state
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
             FROM archive_v3_wal_episode_embedding_schema WHERE singleton=1",
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
             FROM archive_v3_wal_episode_embedding_state WHERE singleton=1",
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

    fn connection() -> Connection {
        // The extension registers for FUTURE connections; it must precede
        // the open.
        crate::store::init_vec_extension();
        Connection::open_in_memory().unwrap()
    }

    fn install_schema(connection: &Connection) {
        connection
            .execute_batch(
                "CREATE TABLE episodes (id INTEGER PRIMARY KEY AUTOINCREMENT, title TEXT);
                 CREATE VIRTUAL TABLE vec_episodes USING vec0(
                    episode_id INTEGER PRIMARY KEY,
                    embedding float[384] distance_metric=cosine
                 );",
            )
            .unwrap();
        connection
            .execute("INSERT INTO episodes (id,title) VALUES (1,'a'),(2,'b')", [])
            .unwrap();
    }

    fn vector(seed: u8) -> Vec<u8> {
        (0..EMBEDDING_DIMENSION)
            .flat_map(|index| ((index as f32 + f32::from(seed)) / 1000.0).to_le_bytes())
            .collect()
    }

    fn entry(episode_id: i64, text: &str, seed: u8) -> EpisodeEmbedding {
        EpisodeEmbedding::new(
            episode_id,
            Sha256::digest(text.as_bytes()).into(),
            vector(seed),
        )
        .unwrap()
    }

    fn settle(
        connection: &mut Connection,
        plan: EpisodeEmbeddingBatchPlan,
    ) -> Result<LogicalMutationDisposition> {
        let prepared = PreparedLogicalMutation::prepare(plan)?;
        execute_prepared_for_owner(connection, prepared).map(|outcome| outcome.disposition())
    }

    #[test]
    fn batch_settles_verifies_bytes_and_replays_without_rewrite() {
        let mut connection = connection();
        install_schema(&connection);
        let build = || {
            EpisodeEmbeddingBatchPlan::new(
                ACCOUNT.into(),
                vec![entry(1, "text-one", 1), entry(2, "text-two", 2)],
            )
            .unwrap()
        };
        assert!(matches!(
            settle(&mut connection, build()).unwrap(),
            LogicalMutationDisposition::Applied
        ));
        let stored: Vec<u8> = connection
            .query_row(
                "SELECT embedding FROM vec_episodes WHERE episode_id=1",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(stored, vector(1));
        assert!(matches!(
            settle(&mut connection, build()).unwrap(),
            LogicalMutationDisposition::Replayed
        ));
    }

    #[test]
    fn re_embedding_after_content_change_is_a_new_operation_not_a_false_replay() {
        // The finalizer re-embeds the same ids after rewriting title/summary.
        // The content commitment separates the two operations, and the second
        // write wins — this is the stale-search-vector repair.
        let mut connection = connection();
        install_schema(&connection);
        let before =
            EpisodeEmbeddingBatchPlan::new(ACCOUNT.into(), vec![entry(1, "draft text", 1)])
                .unwrap();
        let after =
            EpisodeEmbeddingBatchPlan::new(ACCOUNT.into(), vec![entry(1, "finalized text", 9)])
                .unwrap();
        assert_ne!(
            before.operation_id().as_bytes(),
            after.operation_id().as_bytes()
        );
        settle(&mut connection, before).unwrap();
        assert!(matches!(
            settle(&mut connection, after).unwrap(),
            LogicalMutationDisposition::Applied
        ));
        let stored: Vec<u8> = connection
            .query_row(
                "SELECT embedding FROM vec_episodes WHERE episode_id=1",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(stored, vector(9), "the re-embed replaces the stale vector");
    }

    #[test]
    fn missing_episode_and_malformed_entries_fail_closed() {
        let mut connection = connection();
        install_schema(&connection);
        let orphan =
            EpisodeEmbeddingBatchPlan::new(ACCOUNT.into(), vec![entry(99, "text", 1)]).unwrap();
        assert!(matches!(
            settle(&mut connection, orphan),
            Err(WalIdempotencyError::Precondition)
        ));
        assert!(EpisodeEmbedding::new(0, [1; 32], vector(1)).is_err());
        assert!(EpisodeEmbedding::new(1, [0; 32], vector(1)).is_err());
        assert!(EpisodeEmbedding::new(1, [1; 32], vec![0; 10]).is_err());
        // Unordered ids.
        assert!(EpisodeEmbeddingBatchPlan::new(
            ACCOUNT.into(),
            vec![entry(2, "b", 2), entry(1, "a", 1)],
        )
        .is_err());
        assert!(EpisodeEmbeddingBatchPlan::new(ACCOUNT.into(), vec![]).is_err());
    }
}
