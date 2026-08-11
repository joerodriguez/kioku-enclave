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

use crate::archive_v3::{CiphertextEnvelope, LogicalLocation, ObjectContext, ObjectId, ObjectRole};
use crate::archive_v3_shadow_session::{
    ShadowAttemptId, ShadowCandidate, ShadowSessionBinding, ShadowSessionError, ShadowSessionId,
    ShadowSessionRecord, ShadowSessionState, SHADOW_SESSION_RECORD_BYTES,
};

const FINGERPRINT_DOMAIN: &[u8] = b"kioku:archive:v3:operation-request\0";
const INLINE_RESULT_DOMAIN: &[u8] = b"kioku:archive:v3:operation-inline-result\0";
const ENTITY_RESULT_DOMAIN: &[u8] = b"kioku:archive:v3:operation-entity-result\0";
const LEDGER_SCHEMA_VERSION: u8 = 1;
pub const MAX_INLINE_RESULT_BYTES: usize = 16 * 1024;
pub const MAX_CANONICAL_MUTATION_BYTES: usize = 1024 * 1024;
pub const MAX_OWNER_BATCH_OPERATIONS: usize = 64;
pub const MAX_OWNER_BATCH_LOGICAL_BYTES: u64 = 1_048_576;
pub const MAX_SHADOW_SESSION_ATTEMPTS: i64 = 16;
/// One 32 GiB checkpoint contains at most 32,768 1 MiB chunks, 129
/// fixed-fanout manifests, and one root candidate.  This bound is deliberately
/// per durable attempt, rather than a process-local upload budget.
pub const MAX_SHADOW_OBJECTS_PER_ATTEMPT: usize = 32_768 + 129 + 1;
const MAX_SHADOW_OBJECT_CONTEXT_BYTES: usize = 512;

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
    #[error(transparent)]
    ShadowSession(#[from] ShadowSessionError),
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

    pub(crate) const fn from_bytes(value: [u8; 32]) -> Self {
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

    pub const fn committed_root_seq(&self) -> u64 {
        self.committed_root_seq
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

/// Lifecycle of one exact immutable object created by an inactive shadow
/// attempt.  Rows contain only opaque archive context/AAD bytes and ciphertext
/// commitments; they never contain a provider URL, cursor, user identity,
/// timestamp, plaintext, or diagnostic string.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub(crate) enum ShadowObjectState {
    Reserved = 1,
    Materialized = 2,
    RetainedByWitness = 3,
    OrphanPendingGrace = 4,
}

impl ShadowObjectState {
    fn decode(value: i64) -> Result<Self> {
        match value {
            1 => Ok(Self::Reserved),
            2 => Ok(Self::Materialized),
            3 => Ok(Self::RetainedByWitness),
            4 => Ok(Self::OrphanPendingGrace),
            _ => Err(OperationLedgerError::Corrupt),
        }
    }
}

/// Exact, ciphertext-safe identity of one immutable object.  `context_aad` is
/// the canonical authenticated context, not a provider name; persisting it
/// makes context substitution detectable after a process crash.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct ShadowObjectFacts {
    object_id: ObjectId,
    object_role: ObjectRole,
    root_seq: Option<u64>,
    context_aad: Zeroizing<Vec<u8>>,
    ciphertext_hash: [u8; 32],
}

impl ShadowObjectFacts {
    pub(crate) fn from_sealed(
        context: &ObjectContext,
        envelope: &CiphertextEnvelope,
    ) -> Result<Self> {
        let context_aad = context.canonical_aad();
        if context_aad.is_empty() || context_aad.len() > MAX_SHADOW_OBJECT_CONTEXT_BYTES {
            return Err(OperationLedgerError::TooLarge("shadow object context"));
        }
        let root_seq = match context.location() {
            LogicalLocation::Root { root_seq } if *root_seq <= i64::MAX as u64 => Some(*root_seq),
            LogicalLocation::Root { .. } => {
                return Err(OperationLedgerError::Malformed("shadow root sequence"));
            }
            _ => None,
        };
        Ok(Self {
            object_id: context.object_id(),
            object_role: context.role(),
            root_seq,
            context_aad: Zeroizing::new(context_aad),
            ciphertext_hash: envelope.hash(),
        })
    }

    pub(crate) const fn object_id(&self) -> ObjectId {
        self.object_id
    }

    pub(crate) const fn ciphertext_hash(&self) -> [u8; 32] {
        self.ciphertext_hash
    }

    fn is_root_candidate(&self, candidate: ShadowCandidate) -> bool {
        self.object_role == ObjectRole::RootV3
            && self.root_seq == Some(candidate.root_seq())
            && self.object_id.as_bytes() == &candidate.object_id()
            && self.ciphertext_hash == candidate.ciphertext_hash()
    }
}

impl fmt::Debug for ShadowObjectFacts {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ShadowObjectFacts(<opaque>)")
    }
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
            ) STRICT;
            CREATE TABLE IF NOT EXISTS archive_v3_shadow_sessions (
                session_id BLOB NOT NULL CHECK(length(session_id) = 16),
                attempt_id BLOB UNIQUE NOT NULL CHECK(length(attempt_id) = 16),
                archive_id BLOB NOT NULL CHECK(length(archive_id) = 16),
                database_epoch BLOB NOT NULL CHECK(length(database_epoch) = 16),
                operation_id BLOB NOT NULL CHECK(length(operation_id) = 16),
                request_fingerprint BLOB NOT NULL CHECK(length(request_fingerprint) = 32),
                state INTEGER NOT NULL CHECK(state BETWEEN 1 AND 6),
                record BLOB NOT NULL CHECK(length(record) = 344),
                PRIMARY KEY(session_id, attempt_id)
            ) STRICT;
            CREATE UNIQUE INDEX IF NOT EXISTS archive_v3_shadow_sessions_one_active
                ON archive_v3_shadow_sessions(session_id)
                WHERE state IN (1, 2, 3);
            CREATE UNIQUE INDEX IF NOT EXISTS archive_v3_shadow_sessions_one_witnessed
                ON archive_v3_shadow_sessions(session_id)
                WHERE state = 4;
            CREATE TABLE IF NOT EXISTS archive_v3_shadow_objects (
                session_id BLOB NOT NULL CHECK(length(session_id) = 16),
                attempt_id BLOB NOT NULL CHECK(length(attempt_id) = 16),
                object_id BLOB NOT NULL CHECK(length(object_id) = 16),
                object_role INTEGER NOT NULL CHECK(object_role BETWEEN 1 AND 8),
                root_seq INTEGER,
                context_aad BLOB NOT NULL
                    CHECK(length(context_aad) > 0 AND length(context_aad) <= 512),
                ciphertext_hash BLOB NOT NULL CHECK(length(ciphertext_hash) = 32),
                state INTEGER NOT NULL CHECK(state BETWEEN 1 AND 4),
                PRIMARY KEY(session_id, attempt_id, object_id),
                CHECK(root_seq IS NULL OR root_seq > 0),
                CHECK((object_role = 5 AND root_seq IS NOT NULL)
                    OR (object_role != 5 AND root_seq IS NULL))
            ) STRICT;
            CREATE INDEX IF NOT EXISTS archive_v3_shadow_objects_exact_attempt
                ON archive_v3_shadow_objects(session_id, attempt_id, state);",
        )?;
        Ok(())
    }

    /// Persist one exact prepared shadow session before any candidate object is
    /// created. Exact retries are idempotent; either reuse of the stable session
    /// ID or reuse of the archive/epoch/operation tuple with different bytes
    /// fails closed.
    pub fn prepare_shadow_session(
        connection: &Connection,
        record: &ShadowSessionRecord,
    ) -> Result<RecordOutcome> {
        if record.state() != ShadowSessionState::Prepared || record.candidate().is_some() {
            return Err(OperationLedgerError::ShadowSession(
                ShadowSessionError::InvalidTransition,
            ));
        }
        if let Some(existing) =
            Self::read_shadow_session(connection, record.session_id(), record.attempt_id())?
        {
            return if &existing == record {
                Ok(RecordOutcome::AlreadyRecorded)
            } else if existing.binding().request_fingerprint()
                != record.binding().request_fingerprint()
            {
                Err(OperationLedgerError::FingerprintConflict)
            } else {
                Err(OperationLedgerError::ResultConflict)
            };
        }
        let binding = record.binding();
        let existing = Self::read_shadow_session_family(connection, record.session_id())?;
        if let Some(first) = existing.first() {
            let first_binding = first.binding();
            if first_binding.archive_id() != binding.archive_id()
                || first_binding.database_epoch() != binding.database_epoch()
                || first_binding.operation_id() != binding.operation_id()
            {
                return Err(OperationLedgerError::ResultConflict);
            }
            if first_binding.request_fingerprint() != binding.request_fingerprint() {
                return Err(OperationLedgerError::FingerprintConflict);
            }
            if existing.iter().any(|value| {
                matches!(
                    value.state(),
                    ShadowSessionState::Prepared
                        | ShadowSessionState::CandidatePersisted
                        | ShadowSessionState::ReconcileRequired
                        | ShadowSessionState::Witnessed
                )
            }) {
                return Err(OperationLedgerError::ResultConflict);
            }
            if i64::try_from(existing.len()).unwrap_or(i64::MAX) >= MAX_SHADOW_SESSION_ATTEMPTS {
                return Err(OperationLedgerError::TooLarge("shadow session attempts"));
            }
        }
        let encoded = record.encode()?;
        let inserted = connection.execute(
            "INSERT INTO archive_v3_shadow_sessions (
                session_id, attempt_id, archive_id, database_epoch,
                operation_id, request_fingerprint, state, record
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            params![
                record.session_id().as_bytes().as_slice(),
                record.attempt_id().as_bytes().as_slice(),
                binding.archive_id().as_slice(),
                binding.database_epoch().as_slice(),
                binding.operation_id().as_slice(),
                binding.request_fingerprint().as_slice(),
                record.state() as i64,
                encoded.as_slice(),
            ],
        )?;
        if inserted != 1 {
            return Err(OperationLedgerError::Corrupt);
        }
        Ok(RecordOutcome::Recorded)
    }

    pub fn load_shadow_session(
        connection: &Connection,
        session_id: ShadowSessionId,
        attempt_id: ShadowAttemptId,
    ) -> Result<Option<ShadowSessionRecord>> {
        Self::read_shadow_session(connection, session_id, attempt_id)
    }

    /// Reserve the exact object/context/ciphertext tuple before the caller is
    /// allowed to send an immutable-create request.  Repeating the *identical*
    /// reservation is idempotent; an object ID, AAD, role, root sequence, or
    /// ciphertext commitment substitution fails closed.
    pub(crate) fn reserve_shadow_object(
        connection: &mut Connection,
        session_id: ShadowSessionId,
        attempt_id: ShadowAttemptId,
        expected_binding: ShadowSessionBinding,
        facts: &ShadowObjectFacts,
    ) -> Result<RecordOutcome> {
        let transaction = connection.transaction()?;
        let session = Self::read_shadow_session(&transaction, session_id, attempt_id)?
            .ok_or(OperationLedgerError::Corrupt)?;
        session.require_binding(expected_binding)?;
        if session.state() != ShadowSessionState::Prepared {
            return Err(OperationLedgerError::ShadowSession(
                ShadowSessionError::InvalidTransition,
            ));
        }
        if let Some(existing) =
            Self::read_shadow_object(&transaction, session_id, attempt_id, facts.object_id)?
        {
            if existing == *facts {
                transaction.commit()?;
                return Ok(RecordOutcome::AlreadyRecorded);
            }
            return Err(OperationLedgerError::ResultConflict);
        }
        let count: i64 = transaction.query_row(
            "SELECT COUNT(*) FROM archive_v3_shadow_objects
             WHERE session_id = ? AND attempt_id = ?",
            params![
                session_id.as_bytes().as_slice(),
                attempt_id.as_bytes().as_slice()
            ],
            |row| row.get(0),
        )?;
        if count < 0
            || usize::try_from(count)
                .ok()
                .is_none_or(|value| value >= MAX_SHADOW_OBJECTS_PER_ATTEMPT)
        {
            return Err(OperationLedgerError::TooLarge("shadow objects per attempt"));
        }
        let inserted = transaction.execute(
            "INSERT INTO archive_v3_shadow_objects (
                session_id, attempt_id, object_id, object_role, root_seq,
                context_aad, ciphertext_hash, state
             ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            params![
                session_id.as_bytes().as_slice(),
                attempt_id.as_bytes().as_slice(),
                facts.object_id.as_bytes().as_slice(),
                facts.object_role as i64,
                facts.root_seq.map(|value| value as i64),
                facts.context_aad.as_slice(),
                facts.ciphertext_hash.as_slice(),
                ShadowObjectState::Reserved as i64,
            ],
        )?;
        if inserted != 1 {
            return Err(OperationLedgerError::Corrupt);
        }
        transaction.commit()?;
        Ok(RecordOutcome::Recorded)
    }

    /// Persist post-create exact readback.  The inventory never upgrades a
    /// reservation based only on a create response: the caller must have read
    /// the exact key and compared the complete immutable envelope first.
    pub(crate) fn mark_shadow_object_materialized(
        connection: &mut Connection,
        session_id: ShadowSessionId,
        attempt_id: ShadowAttemptId,
        expected_binding: ShadowSessionBinding,
        facts: &ShadowObjectFacts,
    ) -> Result<RecordOutcome> {
        let transaction = connection.transaction()?;
        let session = Self::read_shadow_session(&transaction, session_id, attempt_id)?
            .ok_or(OperationLedgerError::Corrupt)?;
        session.require_binding(expected_binding)?;
        let state =
            Self::read_shadow_object(&transaction, session_id, attempt_id, facts.object_id)?
                .filter(|existing| existing == facts)
                .ok_or(OperationLedgerError::ResultConflict)?;
        let current =
            Self::read_shadow_object_state(&transaction, session_id, attempt_id, facts.object_id)?
                .ok_or(OperationLedgerError::Corrupt)?;
        let _ = state;
        match current {
            ShadowObjectState::Reserved => {
                let changed = transaction.execute(
                    "UPDATE archive_v3_shadow_objects SET state = ?
                     WHERE session_id = ? AND attempt_id = ? AND object_id = ? AND state = ?",
                    params![
                        ShadowObjectState::Materialized as i64,
                        session_id.as_bytes().as_slice(),
                        attempt_id.as_bytes().as_slice(),
                        facts.object_id.as_bytes().as_slice(),
                        ShadowObjectState::Reserved as i64,
                    ],
                )?;
                if changed != 1 {
                    return Err(OperationLedgerError::Corrupt);
                }
                transaction.commit()?;
                Ok(RecordOutcome::Recorded)
            }
            ShadowObjectState::Materialized => {
                transaction.commit()?;
                Ok(RecordOutcome::AlreadyRecorded)
            }
            _ => Err(OperationLedgerError::ResultConflict),
        }
    }

    pub(crate) fn shadow_object_state(
        connection: &Connection,
        session_id: ShadowSessionId,
        attempt_id: ShadowAttemptId,
        expected_binding: ShadowSessionBinding,
        facts: &ShadowObjectFacts,
    ) -> Result<Option<ShadowObjectState>> {
        let session = Self::read_shadow_session(connection, session_id, attempt_id)?
            .ok_or(OperationLedgerError::Corrupt)?;
        session.require_binding(expected_binding)?;
        let exact = Self::read_shadow_object(connection, session_id, attempt_id, facts.object_id)?;
        match exact {
            Some(existing) if existing == *facts => {
                Self::read_shadow_object_state(connection, session_id, attempt_id, facts.object_id)
            }
            Some(_) => Err(OperationLedgerError::ResultConflict),
            None => Ok(None),
        }
    }

    /// Durably bind the one immutable root candidate before a witness CAS may
    /// be sent. Repeating the exact update is idempotent; replacing a candidate
    /// is forbidden.
    pub fn persist_shadow_candidate(
        connection: &mut Connection,
        session_id: ShadowSessionId,
        attempt_id: ShadowAttemptId,
        expected_binding: ShadowSessionBinding,
        candidate: ShadowCandidate,
        root_facts: &ShadowObjectFacts,
    ) -> Result<ShadowSessionRecord> {
        let transaction = connection.transaction()?;
        let mut record = Self::read_shadow_session(&transaction, session_id, attempt_id)?
            .ok_or(OperationLedgerError::Corrupt)?;
        record.require_binding(expected_binding)?;
        if !root_facts.is_root_candidate(candidate)
            || Self::read_shadow_object(&transaction, session_id, attempt_id, root_facts.object_id)?
                .filter(|existing| existing == root_facts)
                .is_none()
            || Self::read_shadow_object_state(
                &transaction,
                session_id,
                attempt_id,
                root_facts.object_id,
            )? != Some(ShadowObjectState::Materialized)
        {
            return Err(OperationLedgerError::ResultConflict);
        }
        let before = record.encode()?;
        record.persist_candidate(candidate)?;
        Self::replace_shadow_session(&transaction, &before, &record)?;
        transaction.commit()?;
        Ok(record)
    }

    /// Persist a non-acknowledging state transition. Witnessed completion is
    /// deliberately excluded because it must be atomic with the operation
    /// result ledger through `record_shadow_completion`.
    pub fn transition_shadow_session(
        connection: &mut Connection,
        session_id: ShadowSessionId,
        attempt_id: ShadowAttemptId,
        expected_binding: ShadowSessionBinding,
        next: ShadowSessionState,
    ) -> Result<ShadowSessionRecord> {
        if next == ShadowSessionState::Witnessed {
            return Err(OperationLedgerError::ShadowSession(
                ShadowSessionError::InvalidTransition,
            ));
        }
        let transaction = connection.transaction()?;
        let mut record = Self::read_shadow_session(&transaction, session_id, attempt_id)?
            .ok_or(OperationLedgerError::Corrupt)?;
        record.require_binding(expected_binding)?;
        if record.state() == next {
            transaction.commit()?;
            return Ok(record);
        }
        let before = record.encode()?;
        record.transition(next)?;
        match next {
            ShadowSessionState::ReconcileRequired => Self::terminalize_shadow_objects(
                &transaction,
                session_id,
                attempt_id,
                ShadowObjectState::RetainedByWitness,
            )?,
            ShadowSessionState::Superseded | ShadowSessionState::Aborted => {
                Self::terminalize_shadow_objects(
                    &transaction,
                    session_id,
                    attempt_id,
                    ShadowObjectState::OrphanPendingGrace,
                )?
            }
            _ => {}
        }
        Self::replace_shadow_session(&transaction, &before, &record)?;
        transaction.commit()?;
        Ok(record)
    }

    /// Atomically mark the exact candidate witnessed and record the bounded
    /// operation replay result. No durable state can claim one without the
    /// other, including across process termination.
    pub fn record_shadow_completion(
        connection: &mut Connection,
        session_id: ShadowSessionId,
        attempt_id: ShadowAttemptId,
        expected_binding: ShadowSessionBinding,
        completion: &OperationRecord,
    ) -> Result<RecordOutcome> {
        let transaction = connection.transaction()?;
        let mut session = Self::read_shadow_session(&transaction, session_id, attempt_id)?
            .ok_or(OperationLedgerError::Corrupt)?;
        session.require_binding(expected_binding)?;
        if session.binding().operation_id() != *completion.operation_id().as_bytes()
            || session.binding().request_fingerprint()
                != *completion.request_fingerprint().as_bytes()
        {
            return Err(OperationLedgerError::FingerprintConflict);
        }
        if session.candidate().map(ShadowCandidate::root_seq) != Some(completion.committed_root_seq)
        {
            return Err(OperationLedgerError::ResultConflict);
        }
        if session.state() == ShadowSessionState::Witnessed {
            let existing = Self::read_record(&transaction, completion.operation_id())?
                .ok_or(OperationLedgerError::Corrupt)?;
            if &existing != completion {
                return Err(OperationLedgerError::ResultConflict);
            }
            transaction.commit()?;
            return Ok(RecordOutcome::AlreadyRecorded);
        }
        if Self::read_record(&transaction, completion.operation_id())?.is_some() {
            return Err(OperationLedgerError::Corrupt);
        }
        let before = session.encode()?;
        session.transition(ShadowSessionState::Witnessed)?;
        if Self::record(&transaction, completion)? != RecordOutcome::Recorded {
            return Err(OperationLedgerError::Corrupt);
        }
        Self::terminalize_shadow_objects(
            &transaction,
            session_id,
            attempt_id,
            ShadowObjectState::RetainedByWitness,
        )?;
        Self::replace_shadow_session(&transaction, &before, &session)?;
        transaction.commit()?;
        Ok(RecordOutcome::Recorded)
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

    fn read_shadow_session(
        connection: &Connection,
        session_id: ShadowSessionId,
        attempt_id: ShadowAttemptId,
    ) -> Result<Option<ShadowSessionRecord>> {
        let row: Option<ShadowSessionRow> = connection
            .query_row(
                "SELECT session_id, attempt_id, archive_id, database_epoch,
                        operation_id, request_fingerprint, state, record
                 FROM archive_v3_shadow_sessions
                 WHERE session_id = ? AND attempt_id = ?",
                params![
                    session_id.as_bytes().as_slice(),
                    attempt_id.as_bytes().as_slice(),
                ],
                read_shadow_session_row,
            )
            .optional()?;
        let record = row.map(decode_shadow_session_row).transpose()?;
        if record.as_ref().is_some_and(|record| {
            record.session_id() != session_id || record.attempt_id() != attempt_id
        }) {
            return Err(OperationLedgerError::Corrupt);
        }
        Ok(record)
    }

    fn read_shadow_session_family(
        connection: &Connection,
        session_id: ShadowSessionId,
    ) -> Result<Vec<ShadowSessionRecord>> {
        let mut statement = connection.prepare(
            "SELECT session_id, attempt_id, archive_id, database_epoch,
                        operation_id, request_fingerprint, state, record
                 FROM archive_v3_shadow_sessions
                 WHERE session_id = ? ORDER BY rowid LIMIT 17",
        )?;
        let rows = statement.query_map(
            params![session_id.as_bytes().as_slice()],
            read_shadow_session_row,
        )?;
        let mut records = Vec::new();
        for row in rows {
            let record = decode_shadow_session_row(row?)?;
            if record.session_id() != session_id {
                return Err(OperationLedgerError::Corrupt);
            }
            records.push(record);
        }
        Ok(records)
    }

    fn read_shadow_object(
        connection: &Connection,
        session_id: ShadowSessionId,
        attempt_id: ShadowAttemptId,
        object_id: ObjectId,
    ) -> Result<Option<ShadowObjectFacts>> {
        type ObjectRow = (i64, Option<i64>, Vec<u8>, Vec<u8>);
        let row: Option<ObjectRow> = connection
            .query_row(
                "SELECT object_role, root_seq, context_aad, ciphertext_hash
                 FROM archive_v3_shadow_objects
                 WHERE session_id = ? AND attempt_id = ? AND object_id = ?",
                params![
                    session_id.as_bytes().as_slice(),
                    attempt_id.as_bytes().as_slice(),
                    object_id.as_bytes().as_slice(),
                ],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .optional()?;
        row.map(|(role, root_seq, context_aad, ciphertext_hash)| {
            let object_role = match role {
                1 => ObjectRole::CheckpointChunkV3,
                2 => ObjectRole::WalSegmentV3,
                3 => ObjectRole::ExtentV3,
                4 => ObjectRole::MerkleNodeV3,
                5 => ObjectRole::RootV3,
                6 => ObjectRole::KeyRegistryV3,
                7 => ObjectRole::StagingV3,
                8 => ObjectRole::CheckpointManifestV3,
                _ => return Err(OperationLedgerError::Corrupt),
            };
            if context_aad.is_empty() || context_aad.len() > MAX_SHADOW_OBJECT_CONTEXT_BYTES {
                return Err(OperationLedgerError::Corrupt);
            }
            let root_seq = root_seq.map(positive_u64).transpose()?;
            if (object_role == ObjectRole::RootV3) != root_seq.is_some() {
                return Err(OperationLedgerError::Corrupt);
            }
            Ok(ShadowObjectFacts {
                object_id,
                object_role,
                root_seq,
                context_aad: Zeroizing::new(context_aad),
                ciphertext_hash: ciphertext_hash
                    .try_into()
                    .map_err(|_| OperationLedgerError::Corrupt)?,
            })
        })
        .transpose()
    }

    fn read_shadow_object_state(
        connection: &Connection,
        session_id: ShadowSessionId,
        attempt_id: ShadowAttemptId,
        object_id: ObjectId,
    ) -> Result<Option<ShadowObjectState>> {
        connection
            .query_row(
                "SELECT state FROM archive_v3_shadow_objects
                 WHERE session_id = ? AND attempt_id = ? AND object_id = ?",
                params![
                    session_id.as_bytes().as_slice(),
                    attempt_id.as_bytes().as_slice(),
                    object_id.as_bytes().as_slice(),
                ],
                |row| row.get::<_, i64>(0),
            )
            .optional()?
            .map(ShadowObjectState::decode)
            .transpose()
    }

    fn terminalize_shadow_objects(
        transaction: &Transaction<'_>,
        session_id: ShadowSessionId,
        attempt_id: ShadowAttemptId,
        terminal: ShadowObjectState,
    ) -> Result<()> {
        let changed = match terminal {
            ShadowObjectState::RetainedByWitness => transaction.execute(
                "UPDATE archive_v3_shadow_objects SET state = ?
                 WHERE session_id = ? AND attempt_id = ?
                   AND state IN (?, ?)",
                params![
                    terminal as i64,
                    session_id.as_bytes().as_slice(),
                    attempt_id.as_bytes().as_slice(),
                    ShadowObjectState::Reserved as i64,
                    ShadowObjectState::Materialized as i64,
                ],
            )?,
            ShadowObjectState::OrphanPendingGrace => transaction.execute(
                "UPDATE archive_v3_shadow_objects SET state = ?
                 WHERE session_id = ? AND attempt_id = ?
                   AND state IN (?, ?)",
                params![
                    terminal as i64,
                    session_id.as_bytes().as_slice(),
                    attempt_id.as_bytes().as_slice(),
                    ShadowObjectState::Reserved as i64,
                    ShadowObjectState::Materialized as i64,
                ],
            )?,
            _ => return Err(OperationLedgerError::Corrupt),
        };
        let _ = changed;
        Ok(())
    }

    fn replace_shadow_session(
        transaction: &Transaction<'_>,
        previous: &[u8; SHADOW_SESSION_RECORD_BYTES],
        next: &ShadowSessionRecord,
    ) -> Result<()> {
        let encoded = next.encode()?;
        let updated = transaction.execute(
            "UPDATE archive_v3_shadow_sessions SET state = ?, record = ?
             WHERE session_id = ? AND attempt_id = ? AND record = ?",
            params![
                next.state() as i64,
                encoded.as_slice(),
                next.session_id().as_bytes().as_slice(),
                next.attempt_id().as_bytes().as_slice(),
                previous.as_slice(),
            ],
        )?;
        if updated != 1 {
            return Err(OperationLedgerError::Corrupt);
        }
        Ok(())
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

type ShadowSessionRow = (
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    i64,
    Vec<u8>,
);

fn read_shadow_session_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<ShadowSessionRow> {
    Ok((
        row.get(0)?,
        row.get(1)?,
        row.get(2)?,
        row.get(3)?,
        row.get(4)?,
        row.get(5)?,
        row.get(6)?,
        row.get(7)?,
    ))
}

fn decode_shadow_session_row(row: ShadowSessionRow) -> Result<ShadowSessionRecord> {
    let (
        session_id,
        attempt_id,
        archive_id,
        database_epoch,
        operation_id,
        request_fingerprint,
        state,
        encoded,
    ) = row;
    let record =
        ShadowSessionRecord::decode(&encoded).map_err(|_| OperationLedgerError::Corrupt)?;
    let binding = record.binding();
    if session_id.as_slice() != record.session_id().as_bytes()
        || attempt_id.as_slice() != record.attempt_id().as_bytes()
        || archive_id.as_slice() != binding.archive_id()
        || database_epoch.as_slice() != binding.database_epoch()
        || operation_id.as_slice() != binding.operation_id()
        || request_fingerprint.as_slice() != binding.request_fingerprint()
        || state != record.state() as i64
    {
        return Err(OperationLedgerError::Corrupt);
    }
    Ok(record)
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
    use crate::archive_v3_shadow_session::ShadowAttemptId;

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

    fn shadow_binding(
        operation_id: OperationId,
        request_fingerprint: RequestFingerprint,
        owner_fence: u64,
    ) -> ShadowSessionBinding {
        ShadowSessionBinding::new(
            [0xa1; 16],
            [0xb2; 16],
            0,
            [0xc3; 16],
            1,
            [0xd4; 16],
            [0xe5; 32],
            11,
            [0xf6; 16],
            [0x17; 32],
            owner_fence,
            *operation_id.as_bytes(),
            *request_fingerprint.as_bytes(),
            1,
            3,
            1,
            4,
        )
        .unwrap()
    }

    fn shadow_session(id: u8, request_byte: u8) -> ShadowSessionRecord {
        let operation_id = OperationId::from_bytes([id; 16]);
        let request_fingerprint = fingerprint(request_byte);
        ShadowSessionRecord::prepared(
            ShadowSessionId::for_operation(*operation_id.as_bytes()).unwrap(),
            ShadowAttemptId::from_bytes([id.wrapping_add(1); 16]),
            shadow_binding(operation_id, request_fingerprint, 13),
        )
        .unwrap()
    }

    fn shadow_candidate() -> ShadowCandidate {
        ShadowCandidate::new(12, [0x28; 16], [0x39; 32]).unwrap()
    }

    fn materialized_root(
        connection: &mut Connection,
        session: &ShadowSessionRecord,
    ) -> ShadowObjectFacts {
        let candidate = shadow_candidate();
        let facts = shadow_root_facts(candidate);
        assert_eq!(
            OperationLedger::reserve_shadow_object(
                connection,
                session.session_id(),
                session.attempt_id(),
                session.binding(),
                &facts,
            )
            .unwrap(),
            RecordOutcome::Recorded
        );
        assert_eq!(
            OperationLedger::mark_shadow_object_materialized(
                connection,
                session.session_id(),
                session.attempt_id(),
                session.binding(),
                &facts,
            )
            .unwrap(),
            RecordOutcome::Recorded
        );
        facts
    }

    fn shadow_root_facts(candidate: ShadowCandidate) -> ShadowObjectFacts {
        ShadowObjectFacts {
            object_id: ObjectId::from_bytes(candidate.object_id()),
            object_role: ObjectRole::RootV3,
            root_seq: Some(candidate.root_seq()),
            context_aad: Zeroizing::new(b"test-opaque-root-context".to_vec()),
            ciphertext_hash: candidate.ciphertext_hash(),
        }
    }

    fn shadow_completion(id: u8, request_byte: u8) -> OperationRecord {
        OperationRecord::new(
            OperationId::from_bytes([id; 16]),
            fingerprint(request_byte),
            12,
            OperationResultStatus::Succeeded,
            BoundedOperationResult::inline(
                OperationResultStatus::Succeeded,
                b"shadow-result".to_vec(),
            )
            .unwrap(),
            RetentionClass::RetryWindow,
            112,
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
    fn prepared_shadow_session_is_durable_idempotent_and_operation_bound() {
        let temporary = tempfile::NamedTempFile::new().unwrap();
        let session = shadow_session(0x41, 0x51);
        {
            let connection = Connection::open(temporary.path()).unwrap();
            OperationLedger::initialize(&connection).unwrap();
            assert_eq!(
                OperationLedger::prepare_shadow_session(&connection, &session).unwrap(),
                RecordOutcome::Recorded
            );
        }
        let connection = Connection::open(temporary.path()).unwrap();
        OperationLedger::initialize(&connection).unwrap();
        assert_eq!(
            OperationLedger::prepare_shadow_session(&connection, &session).unwrap(),
            RecordOutcome::AlreadyRecorded
        );
        assert_eq!(
            OperationLedger::load_shadow_session(
                &connection,
                session.session_id(),
                session.attempt_id(),
            )
            .unwrap(),
            Some(session.clone())
        );

        let conflicting_fingerprint = shadow_session(0x41, 0x52);
        assert!(matches!(
            OperationLedger::prepare_shadow_session(&connection, &conflicting_fingerprint),
            Err(OperationLedgerError::FingerprintConflict)
        ));

        let conflicting_binding = ShadowSessionRecord::prepared(
            session.session_id(),
            session.attempt_id(),
            shadow_binding(OperationId::from_bytes([0x41; 16]), fingerprint(0x51), 99),
        )
        .unwrap();
        assert!(matches!(
            OperationLedger::prepare_shadow_session(&connection, &conflicting_binding),
            Err(OperationLedgerError::ResultConflict)
        ));
    }

    #[test]
    fn exact_candidate_survives_restart_and_cannot_be_replaced() {
        let temporary = tempfile::NamedTempFile::new().unwrap();
        let session = shadow_session(0x42, 0x53);
        {
            let mut connection = Connection::open(temporary.path()).unwrap();
            OperationLedger::initialize(&connection).unwrap();
            OperationLedger::prepare_shadow_session(&connection, &session).unwrap();
            let root_facts = materialized_root(&mut connection, &session);
            let persisted = OperationLedger::persist_shadow_candidate(
                &mut connection,
                session.session_id(),
                session.attempt_id(),
                session.binding(),
                shadow_candidate(),
                &root_facts,
            )
            .unwrap();
            assert_eq!(persisted.state(), ShadowSessionState::CandidatePersisted);
        }
        let mut connection = Connection::open(temporary.path()).unwrap();
        OperationLedger::initialize(&connection).unwrap();
        let loaded = OperationLedger::load_shadow_session(
            &connection,
            session.session_id(),
            session.attempt_id(),
        )
        .unwrap()
        .unwrap();
        assert_eq!(loaded.candidate(), Some(shadow_candidate()));
        let root_facts = shadow_root_facts(shadow_candidate());
        OperationLedger::persist_shadow_candidate(
            &mut connection,
            session.session_id(),
            session.attempt_id(),
            session.binding(),
            shadow_candidate(),
            &root_facts,
        )
        .unwrap();
        assert!(matches!(
            OperationLedger::persist_shadow_candidate(
                &mut connection,
                session.session_id(),
                session.attempt_id(),
                session.binding(),
                ShadowCandidate::new(12, [0x48; 16], [0x59; 32]).unwrap(),
                &root_facts,
            ),
            Err(OperationLedgerError::ResultConflict)
        ));
        let reconciled = OperationLedger::transition_shadow_session(
            &mut connection,
            session.session_id(),
            session.attempt_id(),
            session.binding(),
            ShadowSessionState::ReconcileRequired,
        )
        .unwrap();
        assert_eq!(reconciled.state(), ShadowSessionState::ReconcileRequired);
        assert!(OperationLedger::transition_shadow_session(
            &mut connection,
            session.session_id(),
            session.attempt_id(),
            session.binding(),
            ShadowSessionState::Witnessed,
        )
        .is_err());
    }

    #[test]
    fn shadow_object_inventory_is_exact_bound_and_redacted() {
        let mut connection = setup();
        let session = shadow_session(0x46, 0x57);
        OperationLedger::prepare_shadow_session(&connection, &session).unwrap();
        let facts = shadow_root_facts(shadow_candidate());
        assert_eq!(
            OperationLedger::reserve_shadow_object(
                &mut connection,
                session.session_id(),
                session.attempt_id(),
                session.binding(),
                &facts,
            )
            .unwrap(),
            RecordOutcome::Recorded
        );
        assert_eq!(
            OperationLedger::reserve_shadow_object(
                &mut connection,
                session.session_id(),
                session.attempt_id(),
                session.binding(),
                &facts,
            )
            .unwrap(),
            RecordOutcome::AlreadyRecorded
        );
        let mut substituted = facts.clone();
        substituted.ciphertext_hash[0] ^= 1;
        assert!(matches!(
            OperationLedger::reserve_shadow_object(
                &mut connection,
                session.session_id(),
                session.attempt_id(),
                session.binding(),
                &substituted,
            ),
            Err(OperationLedgerError::ResultConflict)
        ));
        let other_binding =
            shadow_binding(OperationId::from_bytes([0x46; 16]), fingerprint(0x57), 99);
        assert!(matches!(
            OperationLedger::shadow_object_state(
                &connection,
                session.session_id(),
                session.attempt_id(),
                other_binding,
                &facts,
            ),
            Err(OperationLedgerError::ShadowSession(
                ShadowSessionError::BindingConflict
            ))
        ));
        assert!(!format!("{facts:?}").contains("test-opaque-root-context"));
    }

    #[test]
    fn root_candidate_requires_prior_materialized_exact_object() {
        let mut connection = setup();
        let session = shadow_session(0x47, 0x58);
        OperationLedger::prepare_shadow_session(&connection, &session).unwrap();
        let facts = shadow_root_facts(shadow_candidate());
        assert!(matches!(
            OperationLedger::persist_shadow_candidate(
                &mut connection,
                session.session_id(),
                session.attempt_id(),
                session.binding(),
                shadow_candidate(),
                &facts,
            ),
            Err(OperationLedgerError::ResultConflict)
        ));
        let facts = materialized_root(&mut connection, &session);
        OperationLedger::persist_shadow_candidate(
            &mut connection,
            session.session_id(),
            session.attempt_id(),
            session.binding(),
            shadow_candidate(),
            &facts,
        )
        .unwrap();
    }

    #[test]
    fn terminal_session_transitions_atomically_retain_or_orphan_inventory() {
        let mut connection = setup();
        let retained = shadow_session(0x48, 0x59);
        OperationLedger::prepare_shadow_session(&connection, &retained).unwrap();
        let retained_facts = materialized_root(&mut connection, &retained);
        OperationLedger::persist_shadow_candidate(
            &mut connection,
            retained.session_id(),
            retained.attempt_id(),
            retained.binding(),
            shadow_candidate(),
            &retained_facts,
        )
        .unwrap();
        OperationLedger::transition_shadow_session(
            &mut connection,
            retained.session_id(),
            retained.attempt_id(),
            retained.binding(),
            ShadowSessionState::ReconcileRequired,
        )
        .unwrap();
        assert_eq!(
            OperationLedger::shadow_object_state(
                &connection,
                retained.session_id(),
                retained.attempt_id(),
                retained.binding(),
                &retained_facts,
            )
            .unwrap(),
            Some(ShadowObjectState::RetainedByWitness)
        );

        let orphan = shadow_session(0x49, 0x5a);
        OperationLedger::prepare_shadow_session(&connection, &orphan).unwrap();
        let orphan_facts = materialized_root(&mut connection, &orphan);
        OperationLedger::transition_shadow_session(
            &mut connection,
            orphan.session_id(),
            orphan.attempt_id(),
            orphan.binding(),
            ShadowSessionState::Aborted,
        )
        .unwrap();
        assert_eq!(
            OperationLedger::shadow_object_state(
                &connection,
                orphan.session_id(),
                orphan.attempt_id(),
                orphan.binding(),
                &orphan_facts,
            )
            .unwrap(),
            Some(ShadowObjectState::OrphanPendingGrace)
        );
    }

    #[test]
    fn inventory_cap_rejects_another_reservation_before_provider_io() {
        let mut connection = setup();
        let session = shadow_session(0x4a, 0x5b);
        OperationLedger::prepare_shadow_session(&connection, &session).unwrap();
        let transaction = connection.transaction().unwrap();
        for value in 0..MAX_SHADOW_OBJECTS_PER_ATTEMPT {
            let mut object_id = [0u8; 16];
            object_id[..8].copy_from_slice(&(value as u64).to_be_bytes());
            transaction
                .execute(
                    "INSERT INTO archive_v3_shadow_objects (
                        session_id, attempt_id, object_id, object_role, root_seq,
                        context_aad, ciphertext_hash, state
                     ) VALUES (?, ?, ?, ?, NULL, ?, ?, ?)",
                    params![
                        session.session_id().as_bytes().as_slice(),
                        session.attempt_id().as_bytes().as_slice(),
                        object_id.as_slice(),
                        ObjectRole::CheckpointManifestV3 as i64,
                        b"opaque".as_slice(),
                        [0x61u8; 32].as_slice(),
                        ShadowObjectState::Reserved as i64,
                    ],
                )
                .unwrap();
        }
        transaction.commit().unwrap();
        let facts = ShadowObjectFacts {
            object_id: ObjectId::from_bytes([0xff; 16]),
            object_role: ObjectRole::CheckpointManifestV3,
            root_seq: None,
            context_aad: Zeroizing::new(b"one-too-many".to_vec()),
            ciphertext_hash: [0x62; 32],
        };
        assert!(matches!(
            OperationLedger::reserve_shadow_object(
                &mut connection,
                session.session_id(),
                session.attempt_id(),
                session.binding(),
                &facts,
            ),
            Err(OperationLedgerError::TooLarge("shadow objects per attempt"))
        ));
    }

    #[test]
    fn terminal_attempt_is_retained_before_a_new_attempt_for_the_same_operation() {
        let mut connection = setup();
        let first = shadow_session(0x45, 0x56);
        OperationLedger::prepare_shadow_session(&connection, &first).unwrap();
        let second = ShadowSessionRecord::prepared(
            first.session_id(),
            ShadowAttemptId::from_bytes([0x77; 16]),
            first.binding(),
        )
        .unwrap();
        assert!(matches!(
            OperationLedger::prepare_shadow_session(&connection, &second),
            Err(OperationLedgerError::ResultConflict)
        ));
        OperationLedger::transition_shadow_session(
            &mut connection,
            first.session_id(),
            first.attempt_id(),
            first.binding(),
            ShadowSessionState::Aborted,
        )
        .unwrap();
        assert_eq!(
            OperationLedger::prepare_shadow_session(&connection, &second).unwrap(),
            RecordOutcome::Recorded
        );
        assert_eq!(
            OperationLedger::load_shadow_session(
                &connection,
                first.session_id(),
                first.attempt_id(),
            )
            .unwrap()
            .unwrap()
            .state(),
            ShadowSessionState::Aborted
        );
        assert_eq!(
            OperationLedger::load_shadow_session(
                &connection,
                second.session_id(),
                second.attempt_id(),
            )
            .unwrap(),
            Some(second)
        );
    }

    #[test]
    fn witnessed_session_and_operation_result_commit_atomically() {
        let mut connection = setup();
        let session = shadow_session(0x43, 0x54);
        let completion = shadow_completion(0x43, 0x54);
        OperationLedger::prepare_shadow_session(&connection, &session).unwrap();
        let root_facts = materialized_root(&mut connection, &session);
        OperationLedger::persist_shadow_candidate(
            &mut connection,
            session.session_id(),
            session.attempt_id(),
            session.binding(),
            shadow_candidate(),
            &root_facts,
        )
        .unwrap();
        let wrong_root = OperationRecord::new(
            completion.operation_id(),
            completion.request_fingerprint(),
            13,
            OperationResultStatus::Succeeded,
            BoundedOperationResult::inline(
                OperationResultStatus::Succeeded,
                b"shadow-result".to_vec(),
            )
            .unwrap(),
            RetentionClass::RetryWindow,
            113,
        )
        .unwrap();
        assert!(matches!(
            OperationLedger::record_shadow_completion(
                &mut connection,
                session.session_id(),
                session.attempt_id(),
                session.binding(),
                &wrong_root,
            ),
            Err(OperationLedgerError::ResultConflict)
        ));
        connection
            .execute_batch(
                "CREATE TRIGGER fail_shadow_session_update
                 BEFORE UPDATE ON archive_v3_shadow_sessions
                 BEGIN SELECT RAISE(ABORT, 'injected'); END;",
            )
            .unwrap();
        assert!(OperationLedger::record_shadow_completion(
            &mut connection,
            session.session_id(),
            session.attempt_id(),
            session.binding(),
            &completion,
        )
        .is_err());
        assert!(matches!(
            OperationLedger::lookup(
                &connection,
                completion.operation_id(),
                completion.request_fingerprint()
            )
            .unwrap(),
            LookupOutcome::Absent
        ));
        assert_eq!(
            OperationLedger::load_shadow_session(
                &connection,
                session.session_id(),
                session.attempt_id(),
            )
            .unwrap()
            .unwrap()
            .state(),
            ShadowSessionState::CandidatePersisted
        );

        connection
            .execute_batch("DROP TRIGGER fail_shadow_session_update;")
            .unwrap();
        assert_eq!(
            OperationLedger::record_shadow_completion(
                &mut connection,
                session.session_id(),
                session.attempt_id(),
                session.binding(),
                &completion,
            )
            .unwrap(),
            RecordOutcome::Recorded
        );
        assert_eq!(
            OperationLedger::record_shadow_completion(
                &mut connection,
                session.session_id(),
                session.attempt_id(),
                session.binding(),
                &completion,
            )
            .unwrap(),
            RecordOutcome::AlreadyRecorded
        );
        assert_eq!(
            OperationLedger::load_shadow_session(
                &connection,
                session.session_id(),
                session.attempt_id(),
            )
            .unwrap()
            .unwrap()
            .state(),
            ShadowSessionState::Witnessed
        );
    }

    #[test]
    fn shadow_session_index_corruption_fails_closed() {
        let connection = setup();
        let session = shadow_session(0x44, 0x55);
        OperationLedger::prepare_shadow_session(&connection, &session).unwrap();
        connection
            .execute_batch("PRAGMA ignore_check_constraints = ON;")
            .unwrap();
        connection
            .execute(
                "UPDATE archive_v3_shadow_sessions SET state = 3 WHERE session_id = ?",
                params![session.session_id().as_bytes().as_slice()],
            )
            .unwrap();
        assert!(matches!(
            OperationLedger::load_shadow_session(
                &connection,
                session.session_id(),
                session.attempt_id(),
            ),
            Err(OperationLedgerError::Corrupt)
        ));
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
