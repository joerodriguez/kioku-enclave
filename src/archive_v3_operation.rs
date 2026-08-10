#![allow(
    dead_code,
    reason = "inactive ADR-0022 mutation-ledger primitives are compiled and tested before route or authority wiring"
)]

//! Transactional idempotency ledger primitives for ADR-0022.
//!
//! This module is deliberately inactive. It defines the encrypted SQLite data
//! that a future WAL/extent root will carry, but it is not connected to Store,
//! mutation routes, a witness acknowledgement, retention GC, or production
//! authority.

use std::{collections::HashSet, fmt};

use rand::{rngs::OsRng, RngCore};
use rusqlite::{params, Connection, OptionalExtension, Transaction};
use sha2::{Digest, Sha256};
use thiserror::Error;
use zeroize::Zeroizing;

const FINGERPRINT_DOMAIN: &[u8] = b"kioku:archive:v3:operation-request\0";
const INLINE_RESULT_DOMAIN: &[u8] = b"kioku:archive:v3:operation-inline-result\0";
const ENTITY_RESULT_DOMAIN: &[u8] = b"kioku:archive:v3:operation-entity-result\0";
const LEDGER_SCHEMA_VERSION: u8 = 1;
pub const MAX_INLINE_RESULT_BYTES: usize = 16 * 1024;
pub const MAX_CANONICAL_MUTATION_BYTES: usize = 1024 * 1024;
pub const MAX_OWNER_BATCH_OPERATIONS: usize = 64;
pub const MAX_OWNER_BATCH_LOGICAL_BYTES: u64 = 1_048_576;

#[derive(Debug, Error)]
pub enum OperationLedgerError {
    #[error("archive-v3 operation ledger input is malformed: {0}")]
    Malformed(&'static str),
    #[error("archive-v3 operation ledger input exceeds a fixed bound: {0}")]
    TooLarge(&'static str),
    #[error("operation ID was reused with a different request fingerprint")]
    FingerprintConflict,
    #[error("operation ID and request match but the committed result differs")]
    ResultConflict,
    #[error("archive-v3 operation ledger row is corrupt")]
    Corrupt,
    #[error("archive-v3 operation ledger SQLite operation failed")]
    Sqlite(#[source] rusqlite::Error),
}

impl From<rusqlite::Error> for OperationLedgerError {
    fn from(error: rusqlite::Error) -> Self {
        Self::Sqlite(error)
    }
}

type Result<T> = std::result::Result<T, OperationLedgerError>;

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct OperationId([u8; 16]);

impl OperationId {
    pub fn random() -> Self {
        let mut value = [0u8; 16];
        OsRng.fill_bytes(&mut value);
        Self(value)
    }

    pub const fn from_bytes(value: [u8; 16]) -> Self {
        Self(value)
    }

    pub const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

impl fmt::Debug for OperationId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("OperationId(<opaque>)")
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct RequestFingerprint([u8; 32]);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u16)]
pub enum OperationRoute {
    IngestCommit = 1,
    EpisodeUpdate = 2,
    EpisodeDelete = 3,
    CaptureAppend = 4,
    AccountDelete = 5,
}

impl OperationRoute {
    const fn codec_version(self) -> u16 {
        match self {
            Self::IngestCommit
            | Self::EpisodeUpdate
            | Self::EpisodeDelete
            | Self::CaptureAppend
            | Self::AccountDelete => 1,
        }
    }
}

impl RequestFingerprint {
    /// Hash exact, bounded canonical mutation bytes under a centrally allocated
    /// route and codec version. Only the digest is persisted in the ledger.
    fn derive(route: OperationRoute, canonical_mutation: &[u8]) -> Result<Self> {
        if canonical_mutation.is_empty() {
            return Err(OperationLedgerError::Malformed("empty canonical mutation"));
        }
        if canonical_mutation.len() > MAX_CANONICAL_MUTATION_BYTES {
            return Err(OperationLedgerError::TooLarge("canonical mutation"));
        }
        let mut hash = Sha256::new();
        hash.update(FINGERPRINT_DOMAIN);
        hash.update([LEDGER_SCHEMA_VERSION]);
        hash.update((route as u16).to_be_bytes());
        hash.update(route.codec_version().to_be_bytes());
        hash.update((canonical_mutation.len() as u32).to_be_bytes());
        hash.update(canonical_mutation);
        Ok(Self(hash.finalize().into()))
    }

    const fn from_bytes(value: [u8; 32]) -> Self {
        Self(value)
    }

    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for RequestFingerprint {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RequestFingerprint(<redacted>)")
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum OperationResultStatus {
    Succeeded = 1,
    Accepted = 2,
    Noop = 3,
}

impl OperationResultStatus {
    fn decode(value: i64) -> Result<Self> {
        match value {
            1 => Ok(Self::Succeeded),
            2 => Ok(Self::Accepted),
            3 => Ok(Self::Noop),
            _ => Err(OperationLedgerError::Corrupt),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum RetentionClass {
    SourceEntity = 1,
    RetryWindow = 2,
}

impl RetentionClass {
    fn decode(value: i64) -> Result<Self> {
        match value {
            1 => Ok(Self::SourceEntity),
            2 => Ok(Self::RetryWindow),
            _ => Err(OperationLedgerError::Corrupt),
        }
    }
}

#[derive(Clone, PartialEq, Eq)]
enum BoundedOperationResultKind {
    Inline {
        bytes: Zeroizing<Vec<u8>>,
        digest: [u8; 32],
    },
    EntityReference {
        entity_kind: u16,
        entity_id: [u8; 16],
        entity_version: u64,
        result_digest: [u8; 32],
    },
}

#[derive(Clone, PartialEq, Eq)]
pub struct BoundedOperationResult {
    kind: BoundedOperationResultKind,
}

impl BoundedOperationResult {
    pub fn inline(status: OperationResultStatus, bytes: Vec<u8>) -> Result<Self> {
        if bytes.len() > MAX_INLINE_RESULT_BYTES {
            return Err(OperationLedgerError::TooLarge("inline result"));
        }
        let mut hash = Sha256::new();
        hash.update(INLINE_RESULT_DOMAIN);
        hash.update([LEDGER_SCHEMA_VERSION, status as u8]);
        hash.update((bytes.len() as u32).to_be_bytes());
        hash.update(&bytes);
        Ok(Self {
            kind: BoundedOperationResultKind::Inline {
                bytes: Zeroizing::new(bytes),
                digest: hash.finalize().into(),
            },
        })
    }

    pub fn entity_reference(
        status: OperationResultStatus,
        entity_kind: u16,
        entity_id: [u8; 16],
        entity_version: u64,
    ) -> Result<Self> {
        if entity_kind == 0 || entity_version == 0 || entity_version > i64::MAX as u64 {
            return Err(OperationLedgerError::Malformed("entity reference"));
        }
        let mut hash = Sha256::new();
        hash.update(ENTITY_RESULT_DOMAIN);
        hash.update([LEDGER_SCHEMA_VERSION, status as u8]);
        hash.update(entity_kind.to_be_bytes());
        hash.update(entity_id);
        hash.update(entity_version.to_be_bytes());
        Ok(Self {
            kind: BoundedOperationResultKind::EntityReference {
                entity_kind,
                entity_id,
                entity_version,
                result_digest: hash.finalize().into(),
            },
        })
    }

    pub const fn digest(&self) -> &[u8; 32] {
        match &self.kind {
            BoundedOperationResultKind::Inline { digest, .. } => digest,
            BoundedOperationResultKind::EntityReference { result_digest, .. } => result_digest,
        }
    }

    fn validate(&self, status: OperationResultStatus) -> Result<()> {
        match &self.kind {
            BoundedOperationResultKind::Inline { bytes, digest } => {
                let rebuilt = Self::inline(status, bytes.to_vec())?;
                if rebuilt.digest() != digest {
                    return Err(OperationLedgerError::Malformed("inline result digest"));
                }
            }
            BoundedOperationResultKind::EntityReference {
                entity_kind,
                entity_id,
                entity_version,
                result_digest,
            } => {
                let rebuilt =
                    Self::entity_reference(status, *entity_kind, *entity_id, *entity_version)?;
                if rebuilt.digest() != result_digest {
                    return Err(OperationLedgerError::Malformed("entity result digest"));
                }
            }
        }
        Ok(())
    }
}

impl fmt::Debug for BoundedOperationResult {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.kind {
            BoundedOperationResultKind::Inline { bytes, .. } => formatter
                .debug_struct("Inline")
                .field("bytes", &format_args!("<redacted:{} bytes>", bytes.len()))
                .field("digest", &"<redacted>")
                .finish(),
            BoundedOperationResultKind::EntityReference { entity_kind, .. } => formatter
                .debug_struct("EntityReference")
                .field("entity_kind", entity_kind)
                .field("entity_id", &"<opaque>")
                .field("entity_version", &"<redacted>")
                .field("result_digest", &"<redacted>")
                .finish(),
        }
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct OperationRecord {
    operation_id: OperationId,
    request_fingerprint: RequestFingerprint,
    committed_root_seq: u64,
    status: OperationResultStatus,
    result: BoundedOperationResult,
    retention_class: RetentionClass,
    retain_through_root_seq: u64,
}

impl OperationRecord {
    pub fn new(
        operation_id: OperationId,
        request_fingerprint: RequestFingerprint,
        committed_root_seq: u64,
        status: OperationResultStatus,
        result: BoundedOperationResult,
        retention_class: RetentionClass,
        retain_through_root_seq: u64,
    ) -> Result<Self> {
        let record = Self {
            operation_id,
            request_fingerprint,
            committed_root_seq,
            status,
            result,
            retention_class,
            retain_through_root_seq,
        };
        record.validate()?;
        Ok(record)
    }

    fn validate(&self) -> Result<()> {
        if self.committed_root_seq == 0
            || self.committed_root_seq > i64::MAX as u64
            || self.retain_through_root_seq < self.committed_root_seq
            || self.retain_through_root_seq > i64::MAX as u64
        {
            return Err(OperationLedgerError::Malformed("root sequence"));
        }
        self.result.validate(self.status)
    }

    pub const fn operation_id(&self) -> OperationId {
        self.operation_id
    }

    pub const fn request_fingerprint(&self) -> RequestFingerprint {
        self.request_fingerprint
    }
}

impl fmt::Debug for OperationRecord {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OperationRecord")
            .field("operation_id", &self.operation_id)
            .field("request_fingerprint", &self.request_fingerprint)
            .field("committed_root_seq", &self.committed_root_seq)
            .field("status", &self.status)
            .field("result", &self.result)
            .field("retention_class", &self.retention_class)
            .field("retain_through_root_seq", &"<redacted>")
            .finish()
    }
}

#[derive(Clone)]
pub struct CanonicalMutation {
    operation_id: OperationId,
    request_fingerprint: RequestFingerprint,
    bytes: Zeroizing<Vec<u8>>,
}

impl CanonicalMutation {
    pub fn new(
        operation_id: OperationId,
        route: OperationRoute,
        canonical_bytes: Vec<u8>,
    ) -> Result<Self> {
        let request_fingerprint = RequestFingerprint::derive(route, &canonical_bytes)?;
        Ok(Self {
            operation_id,
            request_fingerprint,
            bytes: Zeroizing::new(canonical_bytes),
        })
    }

    pub fn canonical_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

pub struct OwnerBatch {
    operations: Vec<CanonicalMutation>,
    logical_bytes: u64,
}

impl OwnerBatch {
    pub fn new(operations: Vec<CanonicalMutation>) -> Result<Self> {
        if operations.is_empty() {
            return Err(OperationLedgerError::Malformed("empty operation batch"));
        }
        if operations.len() > MAX_OWNER_BATCH_OPERATIONS {
            return Err(OperationLedgerError::TooLarge("operation batch count"));
        }
        let mut logical_bytes = 0u64;
        let mut seen = HashSet::with_capacity(operations.len());
        for operation in &operations {
            if !seen.insert(operation.operation_id) {
                return Err(OperationLedgerError::Malformed("duplicate operation ID"));
            }
            logical_bytes = logical_bytes
                .checked_add(operation.bytes.len() as u64)
                .ok_or(OperationLedgerError::TooLarge("operation batch bytes"))?;
            if logical_bytes > MAX_OWNER_BATCH_LOGICAL_BYTES {
                return Err(OperationLedgerError::TooLarge("operation batch bytes"));
            }
        }
        Ok(Self {
            operations,
            logical_bytes,
        })
    }

    pub const fn logical_bytes(&self) -> u64 {
        self.logical_bytes
    }

    pub fn operations(&self) -> &[CanonicalMutation] {
        &self.operations
    }
}

pub struct OperationCompletion {
    status: OperationResultStatus,
    result: BoundedOperationResult,
    retention_class: RetentionClass,
    retain_through_root_seq: u64,
}

impl OperationCompletion {
    pub fn new(
        status: OperationResultStatus,
        result: BoundedOperationResult,
        retention_class: RetentionClass,
        retain_through_root_seq: u64,
    ) -> Self {
        Self {
            status,
            result,
            retention_class,
            retain_through_root_seq,
        }
    }
}

pub enum ExecutionOutcome {
    Replay(OperationRecord),
    Applied(OperationRecord),
}

pub enum LookupOutcome {
    Absent,
    Replay(OperationRecord),
    FingerprintConflict,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RecordOutcome {
    Recorded,
    AlreadyRecorded,
}

pub struct OperationLedger;

impl OperationLedger {
    pub fn initialize(connection: &Connection) -> Result<()> {
        connection.execute_batch(
            "CREATE TABLE IF NOT EXISTS archive_v3_operation_ledger (
                operation_id BLOB PRIMARY KEY NOT NULL CHECK(length(operation_id) = 16),
                request_fingerprint BLOB NOT NULL CHECK(length(request_fingerprint) = 32),
                committed_root_seq INTEGER NOT NULL CHECK(committed_root_seq > 0),
                result_status INTEGER NOT NULL CHECK(result_status BETWEEN 1 AND 3),
                result_digest BLOB NOT NULL CHECK(length(result_digest) = 32),
                result_kind INTEGER NOT NULL CHECK(result_kind IN (1, 2)),
                inline_result BLOB,
                entity_kind INTEGER,
                entity_id BLOB,
                entity_version INTEGER,
                retention_class INTEGER NOT NULL CHECK(retention_class IN (1, 2)),
                retain_through_root_seq INTEGER NOT NULL
                    CHECK(retain_through_root_seq >= committed_root_seq),
                CHECK(
                    (result_kind = 1
                        AND inline_result IS NOT NULL
                        AND length(inline_result) <= 16384
                        AND entity_kind IS NULL
                        AND entity_id IS NULL
                        AND entity_version IS NULL)
                    OR
                    (result_kind = 2
                        AND inline_result IS NULL
                        AND entity_kind > 0
                        AND length(entity_id) = 16
                        AND entity_version > 0)
                )
            ) STRICT;",
        )?;
        Ok(())
    }

    pub fn lookup(
        connection: &Connection,
        operation_id: OperationId,
        expected_fingerprint: RequestFingerprint,
    ) -> Result<LookupOutcome> {
        let record = Self::read_record(connection, operation_id)?;
        Ok(match record {
            None => LookupOutcome::Absent,
            Some(record) if record.request_fingerprint != expected_fingerprint => {
                LookupOutcome::FingerprintConflict
            }
            Some(record) => LookupOutcome::Replay(record),
        })
    }

    /// Execute every absent mutation and its ledger insert in one SQLite
    /// transaction. Any fingerprint conflict, mutation error, validation error,
    /// or ledger error drops the transaction without committing domain SQL.
    pub fn execute_batch<F>(
        connection: &mut Connection,
        proposed_root_seq: u64,
        batch: OwnerBatch,
        mut apply: F,
    ) -> Result<Vec<ExecutionOutcome>>
    where
        F: FnMut(&Transaction<'_>, &CanonicalMutation) -> Result<OperationCompletion>,
    {
        if proposed_root_seq == 0 || proposed_root_seq > i64::MAX as u64 {
            return Err(OperationLedgerError::Malformed("root sequence"));
        }
        let transaction = connection.transaction()?;
        let mut outcomes = Vec::with_capacity(batch.operations.len());
        for mutation in &batch.operations {
            if let Some(existing) = Self::read_record(&transaction, mutation.operation_id)? {
                if existing.request_fingerprint != mutation.request_fingerprint {
                    return Err(OperationLedgerError::FingerprintConflict);
                }
                outcomes.push(ExecutionOutcome::Replay(existing));
                continue;
            }
            let completion = apply(&transaction, mutation)?;
            let record = OperationRecord::new(
                mutation.operation_id,
                mutation.request_fingerprint,
                proposed_root_seq,
                completion.status,
                completion.result,
                completion.retention_class,
                completion.retain_through_root_seq,
            )?;
            if Self::record(&transaction, &record)? != RecordOutcome::Recorded {
                return Err(OperationLedgerError::Corrupt);
            }
            outcomes.push(ExecutionOutcome::Applied(record));
        }
        transaction.commit()?;
        Ok(outcomes)
    }

    fn record(transaction: &Transaction<'_>, record: &OperationRecord) -> Result<RecordOutcome> {
        record.validate()?;
        if let Some(existing) = Self::read_record(transaction, record.operation_id)? {
            if existing.request_fingerprint != record.request_fingerprint {
                return Err(OperationLedgerError::FingerprintConflict);
            }
            if &existing != record {
                return Err(OperationLedgerError::ResultConflict);
            }
            return Ok(RecordOutcome::AlreadyRecorded);
        }
        let (result_kind, inline_result, entity_kind, entity_id, entity_version) =
            match &record.result.kind {
                BoundedOperationResultKind::Inline { bytes, .. } => {
                    (1i64, Some(bytes.as_slice()), None, None, None)
                }
                BoundedOperationResultKind::EntityReference {
                    entity_kind,
                    entity_id,
                    entity_version,
                    ..
                } => (
                    2i64,
                    None,
                    Some(i64::from(*entity_kind)),
                    Some(entity_id.as_slice()),
                    Some(
                        i64::try_from(*entity_version)
                            .map_err(|_| OperationLedgerError::Malformed("entity version"))?,
                    ),
                ),
            };
        let inserted = transaction.execute(
            "INSERT INTO archive_v3_operation_ledger (
                operation_id, request_fingerprint, committed_root_seq,
                result_status, result_digest, result_kind, inline_result,
                entity_kind, entity_id, entity_version, retention_class,
                retain_through_root_seq
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            params![
                record.operation_id.as_bytes().as_slice(),
                record.request_fingerprint.as_bytes().as_slice(),
                record.committed_root_seq as i64,
                record.status as i64,
                record.result.digest().as_slice(),
                result_kind,
                inline_result,
                entity_kind,
                entity_id,
                entity_version,
                record.retention_class as i64,
                record.retain_through_root_seq as i64,
            ],
        )?;
        if inserted != 1 {
            return Err(OperationLedgerError::Corrupt);
        }
        Ok(RecordOutcome::Recorded)
    }

    fn read_record(
        connection: &Connection,
        operation_id: OperationId,
    ) -> Result<Option<OperationRecord>> {
        type LedgerRow = (
            Vec<u8>,
            i64,
            i64,
            Vec<u8>,
            i64,
            Option<Vec<u8>>,
            Option<i64>,
            Option<Vec<u8>>,
            Option<i64>,
            i64,
            i64,
        );
        let row: Option<LedgerRow> = connection
            .query_row(
                "SELECT request_fingerprint, committed_root_seq, result_status,
                        result_digest, result_kind, inline_result, entity_kind,
                        entity_id, entity_version, retention_class,
                        retain_through_root_seq
                 FROM archive_v3_operation_ledger WHERE operation_id = ?",
                params![operation_id.as_bytes().as_slice()],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                        row.get(5)?,
                        row.get(6)?,
                        row.get(7)?,
                        row.get(8)?,
                        row.get(9)?,
                        row.get(10)?,
                    ))
                },
            )
            .optional()?;
        let Some((
            fingerprint,
            committed_root_seq,
            status,
            result_digest,
            result_kind,
            inline_result,
            entity_kind,
            entity_id,
            entity_version,
            retention_class,
            retain_through_root_seq,
        )) = row
        else {
            return Ok(None);
        };
        let fingerprint: [u8; 32] = fingerprint
            .try_into()
            .map_err(|_| OperationLedgerError::Corrupt)?;
        let result_digest: [u8; 32] = result_digest
            .try_into()
            .map_err(|_| OperationLedgerError::Corrupt)?;
        let committed_root_seq = positive_u64(committed_root_seq)?;
        let status = OperationResultStatus::decode(status)?;
        let result = match result_kind {
            1 => {
                if entity_kind.is_some() || entity_id.is_some() || entity_version.is_some() {
                    return Err(OperationLedgerError::Corrupt);
                }
                let bytes = inline_result.ok_or(OperationLedgerError::Corrupt)?;
                if bytes.len() > MAX_INLINE_RESULT_BYTES {
                    return Err(OperationLedgerError::Corrupt);
                }
                let rebuilt = BoundedOperationResult::inline(status, bytes)?;
                if rebuilt.digest() != &result_digest {
                    return Err(OperationLedgerError::Corrupt);
                }
                rebuilt
            }
            2 => {
                if inline_result.is_some() {
                    return Err(OperationLedgerError::Corrupt);
                }
                let entity_kind = u16::try_from(entity_kind.ok_or(OperationLedgerError::Corrupt)?)
                    .map_err(|_| OperationLedgerError::Corrupt)?;
                let entity_id: [u8; 16] = entity_id
                    .ok_or(OperationLedgerError::Corrupt)?
                    .try_into()
                    .map_err(|_| OperationLedgerError::Corrupt)?;
                let entity_version =
                    positive_u64(entity_version.ok_or(OperationLedgerError::Corrupt)?)?;
                let rebuilt = BoundedOperationResult::entity_reference(
                    status,
                    entity_kind,
                    entity_id,
                    entity_version,
                )?;
                if rebuilt.digest() != &result_digest {
                    return Err(OperationLedgerError::Corrupt);
                }
                rebuilt
            }
            _ => return Err(OperationLedgerError::Corrupt),
        };
        OperationRecord::new(
            operation_id,
            RequestFingerprint::from_bytes(fingerprint),
            committed_root_seq,
            status,
            result,
            RetentionClass::decode(retention_class)?,
            nonnegative_u64(retain_through_root_seq)?,
        )
        .map(Some)
        .map_err(|_| OperationLedgerError::Corrupt)
    }
}

fn positive_u64(value: i64) -> Result<u64> {
    if value <= 0 {
        return Err(OperationLedgerError::Corrupt);
    }
    Ok(value as u64)
}

fn nonnegative_u64(value: i64) -> Result<u64> {
    if value < 0 {
        return Err(OperationLedgerError::Corrupt);
    }
    Ok(value as u64)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn setup() -> Connection {
        let connection = Connection::open_in_memory().unwrap();
        OperationLedger::initialize(&connection).unwrap();
        connection
    }

    fn fingerprint(value: u8) -> RequestFingerprint {
        RequestFingerprint::derive(OperationRoute::IngestCommit, &[value]).unwrap()
    }

    fn mutation(id: u8, bytes: usize) -> CanonicalMutation {
        CanonicalMutation::new(
            OperationId::from_bytes([id; 16]),
            OperationRoute::IngestCommit,
            vec![id; bytes],
        )
        .unwrap()
    }

    fn record(id: u8, fingerprint: RequestFingerprint, result: &[u8]) -> OperationRecord {
        OperationRecord::new(
            OperationId::from_bytes([id; 16]),
            fingerprint,
            9,
            OperationResultStatus::Succeeded,
            BoundedOperationResult::inline(OperationResultStatus::Succeeded, result.to_vec())
                .unwrap(),
            RetentionClass::RetryWindow,
            109,
        )
        .unwrap()
    }

    #[test]
    fn transactional_record_replays_exact_result_and_is_idempotent() {
        let mut connection = setup();
        let expected = record(1, fingerprint(2), b"stable-result");
        let transaction = connection.transaction().unwrap();
        assert_eq!(
            OperationLedger::record(&transaction, &expected).unwrap(),
            RecordOutcome::Recorded
        );
        assert_eq!(
            OperationLedger::record(&transaction, &expected).unwrap(),
            RecordOutcome::AlreadyRecorded
        );
        transaction.commit().unwrap();
        match OperationLedger::lookup(
            &connection,
            expected.operation_id,
            expected.request_fingerprint,
        )
        .unwrap()
        {
            LookupOutcome::Replay(actual) => assert_eq!(actual, expected),
            _ => panic!("expected an exact replay"),
        }
    }

    #[test]
    fn owned_batch_transaction_commits_domain_sql_and_ledger_together() {
        let mut connection = setup();
        connection
            .execute_batch("CREATE TABLE domain_effect(value BLOB NOT NULL) STRICT;")
            .unwrap();
        let batch = OwnerBatch::new(vec![mutation(1, 13)]).unwrap();
        let outcomes = OperationLedger::execute_batch(&mut connection, 9, batch, |tx, mutation| {
            tx.execute(
                "INSERT INTO domain_effect(value) VALUES (?)",
                params![mutation.canonical_bytes()],
            )?;
            Ok(OperationCompletion::new(
                OperationResultStatus::Succeeded,
                BoundedOperationResult::inline(
                    OperationResultStatus::Succeeded,
                    b"stable-result".to_vec(),
                )?,
                RetentionClass::RetryWindow,
                109,
            ))
        })
        .unwrap();
        assert!(matches!(
            outcomes.as_slice(),
            [ExecutionOutcome::Applied(_)]
        ));
        assert_eq!(
            connection
                .query_row("SELECT count(*) FROM domain_effect", [], |row| row
                    .get::<_, i64>(0))
                .unwrap(),
            1
        );
        assert_eq!(
            connection
                .query_row(
                    "SELECT count(*) FROM archive_v3_operation_ledger",
                    [],
                    |row| row.get::<_, i64>(0)
                )
                .unwrap(),
            1
        );
    }

    #[test]
    fn owned_batch_transaction_rolls_back_all_domain_sql_on_late_error() {
        let mut connection = setup();
        connection
            .execute_batch("CREATE TABLE domain_effect(value BLOB NOT NULL) STRICT;")
            .unwrap();
        let batch = OwnerBatch::new(vec![mutation(1, 4), mutation(2, 4)]).unwrap();
        let error = OperationLedger::execute_batch(&mut connection, 9, batch, |tx, mutation| {
            tx.execute(
                "INSERT INTO domain_effect(value) VALUES (?)",
                params![mutation.canonical_bytes()],
            )?;
            if mutation.operation_id == OperationId::from_bytes([2; 16]) {
                return Err(OperationLedgerError::Malformed("injected late failure"));
            }
            Ok(OperationCompletion::new(
                OperationResultStatus::Succeeded,
                BoundedOperationResult::inline(
                    OperationResultStatus::Succeeded,
                    b"stable-result".to_vec(),
                )?,
                RetentionClass::RetryWindow,
                109,
            ))
        });
        assert!(matches!(
            error,
            Err(OperationLedgerError::Malformed("injected late failure"))
        ));
        for table in ["domain_effect", "archive_v3_operation_ledger"] {
            let sql = format!("SELECT count(*) FROM {table}");
            assert_eq!(
                connection
                    .query_row(&sql, [], |row| row.get::<_, i64>(0))
                    .unwrap(),
                0
            );
        }
    }

    #[test]
    fn rollback_leaves_no_operation_and_reuse_conflicts_fail_closed() {
        let mut connection = setup();
        let expected = record(1, fingerprint(2), b"stable-result");
        let transaction = connection.transaction().unwrap();
        OperationLedger::record(&transaction, &expected).unwrap();
        transaction.rollback().unwrap();
        assert!(matches!(
            OperationLedger::lookup(
                &connection,
                expected.operation_id,
                expected.request_fingerprint
            )
            .unwrap(),
            LookupOutcome::Absent
        ));

        let transaction = connection.transaction().unwrap();
        OperationLedger::record(&transaction, &expected).unwrap();
        transaction.commit().unwrap();
        assert!(matches!(
            OperationLedger::lookup(&connection, expected.operation_id, fingerprint(3)).unwrap(),
            LookupOutcome::FingerprintConflict
        ));

        let different_result = record(1, expected.request_fingerprint, b"changed-result");
        let transaction = connection.transaction().unwrap();
        assert!(matches!(
            OperationLedger::record(&transaction, &different_result),
            Err(OperationLedgerError::ResultConflict)
        ));
    }

    #[test]
    fn result_shapes_and_corrupt_rows_fail_closed() {
        assert!(matches!(
            BoundedOperationResult::inline(
                OperationResultStatus::Succeeded,
                vec![0; MAX_INLINE_RESULT_BYTES + 1]
            ),
            Err(OperationLedgerError::TooLarge("inline result"))
        ));
        assert!(matches!(
            BoundedOperationResult::entity_reference(
                OperationResultStatus::Succeeded,
                0,
                [1; 16],
                1
            ),
            Err(OperationLedgerError::Malformed("entity reference"))
        ));

        let connection = setup();
        connection
            .execute_batch("PRAGMA ignore_check_constraints = ON;")
            .unwrap();
        connection
            .execute(
                "INSERT INTO archive_v3_operation_ledger VALUES (?, ?, 9, 1, ?, 1, ?, NULL, NULL, NULL, 2, 109)",
                params![&[1u8; 16], &[2u8; 31], &[3u8; 32], b"result"],
            )
            .unwrap();
        assert!(matches!(
            OperationLedger::lookup(
                &connection,
                OperationId::from_bytes([1; 16]),
                fingerprint(2)
            ),
            Err(OperationLedgerError::Corrupt)
        ));

        connection
            .execute(
                "INSERT INTO archive_v3_operation_ledger VALUES (?, ?, 9, 1, ?, 2, NULL, 7, ?, 99, 2, 109)",
                params![
                    &[2u8; 16],
                    fingerprint(2).as_bytes().as_slice(),
                    &[9u8; 32],
                    &[3u8; 16]
                ],
            )
            .unwrap();
        assert!(matches!(
            OperationLedger::lookup(
                &connection,
                OperationId::from_bytes([2; 16]),
                fingerprint(2)
            ),
            Err(OperationLedgerError::Corrupt)
        ));
    }

    #[test]
    fn record_revalidates_private_result_digest_before_sql() {
        let mut connection = setup();
        let mut tampered = record(1, fingerprint(2), b"stable-result");
        match &mut tampered.result.kind {
            BoundedOperationResultKind::Inline { digest, .. } => *digest = [0x55; 32],
            BoundedOperationResultKind::EntityReference { .. } => unreachable!(),
        }
        let transaction = connection.transaction().unwrap();
        assert!(matches!(
            OperationLedger::record(&transaction, &tampered),
            Err(OperationLedgerError::Malformed("inline result digest"))
        ));
        transaction.rollback().unwrap();
        assert!(matches!(
            OperationLedger::lookup(
                &connection,
                tampered.operation_id,
                tampered.request_fingerprint
            )
            .unwrap(),
            LookupOutcome::Absent
        ));
    }

    #[test]
    fn owner_batch_bounds_count_bytes_and_duplicate_ids() {
        assert_eq!(
            OwnerBatch::new(vec![mutation(1, MAX_OWNER_BATCH_LOGICAL_BYTES as usize)])
                .unwrap()
                .logical_bytes(),
            MAX_OWNER_BATCH_LOGICAL_BYTES
        );
        assert!(matches!(
            OwnerBatch::new(vec![mutation(1, 1), mutation(1, 1)]),
            Err(OperationLedgerError::Malformed("duplicate operation ID"))
        ));
        assert!(matches!(
            CanonicalMutation::new(
                OperationId::from_bytes([1; 16]),
                OperationRoute::IngestCommit,
                vec![1; MAX_CANONICAL_MUTATION_BYTES + 1]
            ),
            Err(OperationLedgerError::TooLarge("canonical mutation"))
        ));
        let too_many: Vec<_> = (0..=MAX_OWNER_BATCH_OPERATIONS)
            .map(|id| mutation(id as u8, 1))
            .collect();
        assert!(matches!(
            OwnerBatch::new(too_many),
            Err(OperationLedgerError::TooLarge("operation batch count"))
        ));
    }

    #[test]
    fn debug_output_redacts_operation_request_result_and_entity_identity() {
        let inline = record(0x11, fingerprint(0x22), b"plaintext-result");
        let debug = format!("{inline:?}");
        for forbidden in ["111111", "222222", "plaintext-result"] {
            assert!(!debug.contains(forbidden));
        }
        let entity = BoundedOperationResult::entity_reference(
            OperationResultStatus::Succeeded,
            7,
            [0x33; 16],
            99,
        )
        .unwrap();
        let debug = format!("{entity:?}");
        assert!(!debug.contains("333333"));
        assert!(!debug.contains("444444"));
        assert!(!debug.contains("99"));
    }

    #[test]
    fn canonical_request_fingerprint_binds_route_codec_and_digest() {
        let base = RequestFingerprint::derive(OperationRoute::IngestCommit, b"canonical").unwrap();
        assert_ne!(
            base,
            RequestFingerprint::derive(OperationRoute::EpisodeUpdate, b"canonical").unwrap()
        );
        assert_ne!(
            base,
            RequestFingerprint::derive(OperationRoute::IngestCommit, b"canonical-2").unwrap()
        );
    }
}
