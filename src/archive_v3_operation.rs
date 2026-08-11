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
use rusqlite::{params, Connection, OptionalExtension, Transaction, TransactionBehavior};
use sha2::{Digest, Sha256};
use thiserror::Error;
use zeroize::Zeroizing;

use crate::archive_v3::{
    CiphertextEnvelope, LogicalLocation, ObjectContext, ObjectId, ObjectKey, ObjectRole,
};
use crate::archive_v3_legacy_extent_session::{
    LegacyExtentAttemptId, LegacyExtentCandidate, LegacyExtentRootAdmission,
    LegacyExtentSessionBinding, LegacyExtentSessionError, LegacyExtentSessionId,
    LegacyExtentSessionRecord, LegacyExtentSessionState, LEGACY_EXTENT_SESSION_RECORD_BYTES,
};
use crate::archive_v3_shadow_session::{
    ShadowAttemptId, ShadowCandidate, ShadowSessionBinding, ShadowSessionError, ShadowSessionId,
    ShadowSessionRecord, ShadowSessionState, SHADOW_SESSION_RECORD_BYTES,
};

const FINGERPRINT_DOMAIN: &[u8] = b"kioku:archive:v3:operation-request\0";
const LEGACY_EXTENT_CURSOR_DOMAIN: &[u8] = b"kioku:archive:v3:legacy-extent-cursor\0";
const LEGACY_EXTENT_INVENTORY_DOMAIN: &[u8] = b"kioku:archive:v3:legacy-extent-inventory\0";
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
pub const MAX_SHADOW_OBJECTS_PAGE: usize = 256;
const MAX_SHADOW_OBJECT_CONTEXT_BYTES: usize = 512;
pub(crate) const MAX_LEGACY_EXTENT_SESSION_ATTEMPTS: i64 = 16;
pub(crate) const MAX_LEGACY_EXTENT_OBJECTS_PER_ATTEMPT: usize = 32_898;
pub(crate) const MAX_LEGACY_EXTENT_OBJECTS_PAGE: usize = 256;
const LEGACY_EXTENT_SCHEMA_TABLE_SQL: &str = "CREATE TABLE archive_v3_legacy_extent_schema (singleton INTEGER PRIMARY KEY CHECK(singleton = 1), version INTEGER NOT NULL CHECK(version = 2)) STRICT";
const LEGACY_EXTENT_SESSIONS_TABLE_SQL: &str = "CREATE TABLE archive_v3_legacy_extent_sessions (session_id BLOB NOT NULL CHECK(length(session_id) = 16), attempt_id BLOB UNIQUE NOT NULL CHECK(length(attempt_id) = 16), archive_id BLOB NOT NULL CHECK(length(archive_id) = 16), database_epoch BLOB NOT NULL CHECK(length(database_epoch) = 16), operation_id BLOB NOT NULL CHECK(length(operation_id) = 16), request_fingerprint BLOB NOT NULL CHECK(length(request_fingerprint) = 32), state INTEGER NOT NULL CHECK(state BETWEEN 1 AND 3), record BLOB NOT NULL CHECK(length(record) = 436), PRIMARY KEY(session_id, attempt_id)) STRICT";
const LEGACY_EXTENT_OBJECTS_TABLE_SQL: &str = "CREATE TABLE archive_v3_legacy_extent_objects (session_id BLOB NOT NULL CHECK(length(session_id) = 16), attempt_id BLOB NOT NULL CHECK(length(attempt_id) = 16), ordinal INTEGER NOT NULL CHECK(ordinal >= 0 AND ordinal < 32898), object_id BLOB NOT NULL CHECK(length(object_id) = 16), object_role INTEGER NOT NULL CHECK(object_role IN (3, 4, 5)), root_seq INTEGER, context_aad BLOB NOT NULL CHECK(length(context_aad) > 0 AND length(context_aad) <= 512), object_key TEXT NOT NULL CHECK(length(object_key) > 0 AND length(object_key) <= 512), ciphertext_hash BLOB NOT NULL CHECK(length(ciphertext_hash) = 32), state INTEGER NOT NULL CHECK(state BETWEEN 1 AND 3), PRIMARY KEY(session_id, attempt_id, ordinal), UNIQUE(session_id, attempt_id, object_id), CHECK(root_seq IS NULL OR root_seq > 0), CHECK((object_role = 5 AND root_seq IS NOT NULL) OR (object_role != 5 AND root_seq IS NULL))) STRICT";
const LEGACY_EXTENT_OBJECTS_INDEX_SQL: &str = "CREATE INDEX archive_v3_legacy_extent_objects_exact_attempt ON archive_v3_legacy_extent_objects(session_id, attempt_id, state, ordinal)";
const SHADOW_OBJECT_SCHEMA_TABLE_SQL: &str = "CREATE TABLE archive_v3_shadow_object_schema (singleton INTEGER PRIMARY KEY CHECK(singleton = 1), version INTEGER NOT NULL CHECK(version BETWEEN 1 AND 2)) STRICT";
const SHADOW_OBJECT_INDEX_SQL: &str = "CREATE INDEX archive_v3_shadow_objects_exact_attempt ON archive_v3_shadow_objects(session_id, attempt_id, state)";
const SHADOW_OBJECT_TABLE_V1_SQL: &str = "CREATE TABLE archive_v3_shadow_objects (session_id BLOB NOT NULL CHECK(length(session_id) = 16), attempt_id BLOB NOT NULL CHECK(length(attempt_id) = 16), object_id BLOB NOT NULL CHECK(length(object_id) = 16), object_role INTEGER NOT NULL CHECK(object_role BETWEEN 1 AND 8), root_seq INTEGER, context_aad BLOB NOT NULL CHECK(length(context_aad) > 0 AND length(context_aad) <= 512), ciphertext_hash BLOB NOT NULL CHECK(length(ciphertext_hash) = 32), state INTEGER NOT NULL CHECK(state BETWEEN 1 AND 4), PRIMARY KEY(session_id, attempt_id, object_id), CHECK(root_seq IS NULL OR root_seq > 0), CHECK((object_role = 5 AND root_seq IS NOT NULL) OR (object_role != 5 AND root_seq IS NULL))) STRICT";
const SHADOW_OBJECT_TABLE_V2_SQL: &str = "CREATE TABLE archive_v3_shadow_objects (session_id BLOB NOT NULL CHECK(length(session_id) = 16), attempt_id BLOB NOT NULL CHECK(length(attempt_id) = 16), ordinal INTEGER NOT NULL CHECK(ordinal >= 0 AND ordinal < 32898), object_id BLOB NOT NULL CHECK(length(object_id) = 16), object_role INTEGER NOT NULL CHECK(object_role BETWEEN 1 AND 8), root_seq INTEGER, context_aad BLOB NOT NULL CHECK(length(context_aad) > 0 AND length(context_aad) <= 512), object_key TEXT NOT NULL CHECK(length(object_key) > 0 AND length(object_key) <= 512), ciphertext_hash BLOB NOT NULL CHECK(length(ciphertext_hash) = 32), state INTEGER NOT NULL CHECK(state BETWEEN 1 AND 4), PRIMARY KEY(session_id, attempt_id, ordinal), UNIQUE(session_id, attempt_id, object_id), CHECK(root_seq IS NULL OR root_seq > 0), CHECK((object_role = 5 AND root_seq IS NOT NULL) OR (object_role != 5 AND root_seq IS NULL))) STRICT";

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
    #[error(transparent)]
    LegacyExtentSession(#[from] LegacyExtentSessionError),
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
    ordinal: u32,
    object_id: ObjectId,
    object_role: ObjectRole,
    root_seq: Option<u64>,
    context_aad: Zeroizing<Vec<u8>>,
    object_key: String,
    ciphertext_hash: [u8; 32],
}

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct ShadowObjectInventoryEntry {
    facts: ShadowObjectFacts,
    state: ShadowObjectState,
}

impl ShadowObjectInventoryEntry {
    pub(crate) const fn state(&self) -> ShadowObjectState {
        self.state
    }

    pub(crate) fn facts(&self) -> &ShadowObjectFacts {
        &self.facts
    }
}

impl fmt::Debug for ShadowObjectInventoryEntry {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ShadowObjectInventoryEntry(<opaque>)")
    }
}

pub(crate) struct ShadowObjectInventoryPage {
    entries: Vec<ShadowObjectInventoryEntry>,
    next_ordinal: Option<u32>,
}

impl ShadowObjectInventoryPage {
    pub(crate) fn empty() -> Self {
        Self {
            entries: Vec::new(),
            next_ordinal: None,
        }
    }
    pub(crate) fn entries(&self) -> &[ShadowObjectInventoryEntry] {
        &self.entries
    }
    pub(crate) const fn next_ordinal(&self) -> Option<u32> {
        self.next_ordinal
    }
}

impl ShadowObjectFacts {
    pub(crate) fn from_sealed(
        context: &ObjectContext,
        envelope: &CiphertextEnvelope,
        ordinal: u32,
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
        if usize::try_from(ordinal)
            .ok()
            .is_none_or(|value| value >= MAX_SHADOW_OBJECTS_PER_ATTEMPT)
        {
            return Err(OperationLedgerError::TooLarge("shadow object ordinal"));
        }
        Ok(Self {
            ordinal,
            object_id: context.object_id(),
            object_role: context.role(),
            root_seq,
            context_aad: Zeroizing::new(context_aad),
            object_key: context.object_key().as_str().to_owned(),
            ciphertext_hash: envelope.hash(),
        })
    }

    pub(crate) const fn object_id(&self) -> ObjectId {
        self.object_id
    }

    pub(crate) const fn ciphertext_hash(&self) -> [u8; 32] {
        self.ciphertext_hash
    }

    pub(crate) fn object_key(&self) -> Result<ObjectKey> {
        self.validate_canonical()?;
        Ok(ObjectKey::from_validated_canonical(
            self.object_key.clone(),
            self.object_id,
        ))
    }

    fn is_root_candidate(&self, candidate: ShadowCandidate) -> bool {
        self.object_role == ObjectRole::RootV3
            && self.root_seq == Some(candidate.root_seq())
            && self.object_id.as_bytes() == &candidate.object_id()
            && self.ciphertext_hash == candidate.ciphertext_hash()
    }

    fn matches_binding(&self, binding: ShadowSessionBinding) -> bool {
        let Ok(context) = self.decode_and_validate_canonical() else {
            return false;
        };
        let root_is_bound = match context.location() {
            LogicalLocation::Root { root_seq } => {
                binding.base_root_seq().checked_add(1) == Some(*root_seq)
                    && context.parent().is_some_and(|parent| {
                        parent.object_id.as_bytes() == &binding.base_root_object_id()
                            && parent.envelope_hash == binding.base_root_ciphertext_hash()
                    })
            }
            _ => true,
        };
        root_is_bound
            && context.archive_id().as_bytes() == &binding.archive_id()
            && context.database_epoch().as_bytes() == &binding.database_epoch()
            && context.key_epoch().as_bytes() == &binding.registry_epoch()
    }

    fn validate_canonical(&self) -> Result<()> {
        self.decode_and_validate_canonical().map(|_| ())
    }

    fn decode_and_validate_canonical(&self) -> Result<ObjectContext> {
        if !valid_shadow_object_key(&self.object_key, self.object_role, self.object_id) {
            return Err(OperationLedgerError::Corrupt);
        }
        let context = ObjectContext::decode_canonical_aad(self.context_aad.as_slice())
            .map_err(|_| OperationLedgerError::Corrupt)?;
        let expected_root_seq = match context.location() {
            LogicalLocation::Root { root_seq } => Some(*root_seq),
            _ => None,
        };
        if context.object_id() != self.object_id
            || context.role() != self.object_role
            || expected_root_seq != self.root_seq
            || context.object_key().as_str() != self.object_key
        {
            return Err(OperationLedgerError::Corrupt);
        }
        Ok(context)
    }
}

fn valid_shadow_object_key(value: &str, role: ObjectRole, object_id: ObjectId) -> bool {
    if crate::archive_v3_gcs::canonical_object_id(value) != Some(object_id) {
        return false;
    }
    let lexical = !value.is_empty()
        && value.len() <= MAX_SHADOW_OBJECT_CONTEXT_BYTES
        && value.starts_with("archive/v3/")
        && value.as_bytes().iter().all(|byte| {
            byte.is_ascii_lowercase()
                || byte.is_ascii_digit()
                || matches!(byte, b'/' | b'-' | b'_' | b'.')
        })
        && !value.contains("//")
        && !value.contains("..");
    if !lexical {
        return false;
    }
    let role_component = value.split('/').nth(3);
    matches!(
        (role, role_component),
        (
            ObjectRole::CheckpointChunkV3 | ObjectRole::CheckpointManifestV3,
            Some("checkpoints")
        ) | (ObjectRole::RootV3, Some("root-candidates"))
            | (ObjectRole::WalSegmentV3, Some("wal"))
            | (ObjectRole::ExtentV3, Some("extents"))
            | (ObjectRole::MerkleNodeV3, Some("nodes"))
            | (ObjectRole::KeyRegistryV3, Some("keys"))
            | (ObjectRole::StagingV3, Some("staging"))
    )
}

fn decode_object_role(value: i64) -> Result<ObjectRole> {
    match value {
        1 => Ok(ObjectRole::CheckpointChunkV3),
        2 => Ok(ObjectRole::WalSegmentV3),
        3 => Ok(ObjectRole::ExtentV3),
        4 => Ok(ObjectRole::MerkleNodeV3),
        5 => Ok(ObjectRole::RootV3),
        6 => Ok(ObjectRole::KeyRegistryV3),
        7 => Ok(ObjectRole::StagingV3),
        8 => Ok(ObjectRole::CheckpointManifestV3),
        _ => Err(OperationLedgerError::Corrupt),
    }
}

fn shadow_object_columns_v1() -> HashSet<String> {
    [
        "session_id",
        "attempt_id",
        "object_id",
        "object_role",
        "root_seq",
        "context_aad",
        "ciphertext_hash",
        "state",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect()
}

fn shadow_object_columns_v2() -> HashSet<String> {
    [
        "session_id",
        "attempt_id",
        "ordinal",
        "object_id",
        "object_role",
        "root_seq",
        "context_aad",
        "object_key",
        "ciphertext_hash",
        "state",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect()
}

fn normalized_schema_sql(input: &str) -> String {
    input
        .bytes()
        .filter(|byte| !byte.is_ascii_whitespace())
        .map(char::from)
        .collect::<String>()
        .to_ascii_lowercase()
        .replace("ifnotexists", "")
        .trim_end_matches(';')
        .to_owned()
}

impl fmt::Debug for ShadowObjectFacts {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ShadowObjectFacts(<opaque>)")
    }
}

/// Exact object lifecycle for an inactive legacy-to-extent conversion attempt.
/// `CandidateReady` is deliberately not a retained-by-witness state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub(crate) enum LegacyExtentObjectState {
    Reserved = 1,
    Materialized = 2,
    OrphanPendingGrace = 3,
}

impl LegacyExtentObjectState {
    fn decode(value: i64) -> Result<Self> {
        match value {
            1 => Ok(Self::Reserved),
            2 => Ok(Self::Materialized),
            3 => Ok(Self::OrphanPendingGrace),
            _ => Err(OperationLedgerError::Corrupt),
        }
    }
}

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct LegacyExtentObjectFacts {
    ordinal: u32,
    object_id: ObjectId,
    object_role: ObjectRole,
    root_seq: Option<u64>,
    context_aad: Zeroizing<Vec<u8>>,
    object_key: String,
    ciphertext_hash: [u8; 32],
}

impl LegacyExtentObjectFacts {
    pub(crate) fn from_sealed(
        context: &ObjectContext,
        envelope: &CiphertextEnvelope,
        ordinal: u32,
    ) -> Result<Self> {
        let context_aad = context.canonical_aad();
        let root_seq = match context.location() {
            LogicalLocation::Root { root_seq } => Some(*root_seq),
            _ => None,
        };
        let value = Self {
            ordinal,
            object_id: context.object_id(),
            object_role: context.role(),
            root_seq,
            context_aad: Zeroizing::new(context_aad),
            object_key: context.object_key().as_str().to_owned(),
            ciphertext_hash: envelope.hash(),
        };
        value.validate_canonical()?;
        Ok(value)
    }

    pub(crate) const fn ordinal(&self) -> u32 {
        self.ordinal
    }
    pub(crate) const fn object_id(&self) -> ObjectId {
        self.object_id
    }
    pub(crate) const fn object_role(&self) -> ObjectRole {
        self.object_role
    }
    pub(crate) const fn root_seq(&self) -> Option<u64> {
        self.root_seq
    }
    pub(crate) const fn ciphertext_hash(&self) -> [u8; 32] {
        self.ciphertext_hash
    }

    fn validate_canonical(&self) -> Result<()> {
        if usize::try_from(self.ordinal)
            .ok()
            .is_none_or(|x| x >= MAX_LEGACY_EXTENT_OBJECTS_PER_ATTEMPT)
            || self.context_aad.is_empty()
            || self.context_aad.len() > MAX_SHADOW_OBJECT_CONTEXT_BYTES
            || self.object_key.is_empty()
            || self.object_key.len() > MAX_SHADOW_OBJECT_CONTEXT_BYTES
            || self.ciphertext_hash.iter().all(|x| *x == 0)
            || !matches!(
                self.object_role,
                ObjectRole::ExtentV3 | ObjectRole::MerkleNodeV3 | ObjectRole::RootV3
            )
        {
            return Err(OperationLedgerError::Corrupt);
        }
        let context = ObjectContext::decode_canonical_aad(self.context_aad.as_slice())
            .map_err(|_| OperationLedgerError::Corrupt)?;
        let root_seq = match context.location() {
            LogicalLocation::Root { root_seq } => Some(*root_seq),
            _ => None,
        };
        if context.object_id() != self.object_id
            || context.role() != self.object_role
            || root_seq != self.root_seq
            || context.object_key().as_str() != self.object_key
            || !valid_shadow_object_key(&self.object_key, self.object_role, self.object_id)
        {
            return Err(OperationLedgerError::Corrupt);
        }
        Ok(())
    }

    fn matches_binding(&self, binding: LegacyExtentSessionBinding) -> bool {
        let Ok(context) = ObjectContext::decode_canonical_aad(self.context_aad.as_slice()) else {
            return false;
        };
        context.archive_id().as_bytes() == &binding.archive_id()
            && context.database_epoch().as_bytes() == &binding.database_epoch()
            && context.key_epoch().as_bytes() == &binding.key_epoch()
            && match (self.object_role, context.location()) {
                (ObjectRole::RootV3, LogicalLocation::Root { root_seq }) => {
                    binding.base_root_seq().checked_add(1) == Some(*root_seq)
                        && context.parent().is_some_and(|parent| {
                            parent.object_id.as_bytes() == &binding.base_root_object_id()
                                && parent.envelope_hash == binding.base_root_ciphertext_hash()
                        })
                }
                (ObjectRole::ExtentV3 | ObjectRole::MerkleNodeV3, _) => context.parent().is_none(),
                _ => false,
            }
    }

    fn is_candidate_root(&self, candidate: LegacyExtentCandidate) -> bool {
        self.object_role == ObjectRole::RootV3
            && self.root_seq == Some(candidate.root_seq())
            && self.object_id.as_bytes() == &candidate.object_id()
            && self.ciphertext_hash == candidate.ciphertext_hash()
    }
}
impl fmt::Debug for LegacyExtentObjectFacts {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("LegacyExtentObjectFacts(<opaque>)")
    }
}

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct LegacyExtentObjectInventoryEntry {
    facts: LegacyExtentObjectFacts,
    state: LegacyExtentObjectState,
}
impl LegacyExtentObjectInventoryEntry {
    pub(crate) const fn state(&self) -> LegacyExtentObjectState {
        self.state
    }
    pub(crate) fn facts(&self) -> &LegacyExtentObjectFacts {
        &self.facts
    }
}
impl fmt::Debug for LegacyExtentObjectInventoryEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("LegacyExtentObjectInventoryEntry(<opaque>)")
    }
}
pub(crate) struct LegacyExtentObjectInventoryPage {
    entries: Vec<LegacyExtentObjectInventoryEntry>,
    next_cursor: Option<LegacyExtentObjectCursor>,
}
impl LegacyExtentObjectInventoryPage {
    pub(crate) fn entries(&self) -> &[LegacyExtentObjectInventoryEntry] {
        &self.entries
    }
    pub(crate) const fn next_cursor(&self) -> Option<LegacyExtentObjectCursor> {
        self.next_cursor
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct LegacyExtentObjectCursor {
    session_id: LegacyExtentSessionId,
    attempt_id: LegacyExtentAttemptId,
    next_ordinal: u32,
    integrity: [u8; 32],
}
impl LegacyExtentObjectCursor {
    fn new(
        session_id: LegacyExtentSessionId,
        attempt_id: LegacyExtentAttemptId,
        next_ordinal: u32,
    ) -> Self {
        let mut hash = Sha256::new();
        hash.update(LEGACY_EXTENT_CURSOR_DOMAIN);
        hash.update(session_id.as_bytes());
        hash.update(attempt_id.as_bytes());
        hash.update(next_ordinal.to_be_bytes());
        Self {
            session_id,
            attempt_id,
            next_ordinal,
            integrity: hash.finalize().into(),
        }
    }
    fn valid(self) -> bool {
        self == Self::new(self.session_id, self.attempt_id, self.next_ordinal)
    }
}
impl fmt::Debug for LegacyExtentObjectCursor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("LegacyExtentObjectCursor(<opaque>)")
    }
}

#[derive(Clone, Copy)]
enum LegacyExtentInventoryRequirement {
    Materialized,
    PreOrphan,
    Orphaned,
}

struct LegacyExtentInventoryScan {
    count: usize,
    root: Option<LegacyExtentObjectFacts>,
    commitment: [u8; 32],
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
            ",
        )?;
        let transaction = Transaction::new_unchecked(connection, TransactionBehavior::Immediate)?;
        Self::initialize_shadow_object_inventory(&transaction)?;
        Self::initialize_legacy_extent_inventory(&transaction)?;
        transaction.commit()?;
        Ok(())
    }

    /// Version and migrate the exact-object inventory under the same SQLite
    /// write lock.  V1 persisted the AAD but not its derived canonical key or
    /// a stable per-attempt cursor ordinal; the migration reconstructs both
    /// only after decoding and re-encoding the authenticated context.
    fn initialize_shadow_object_inventory(transaction: &Transaction<'_>) -> Result<()> {
        let schema_was_present = transaction
            .query_row(
                "SELECT 1 FROM sqlite_master WHERE type = 'table'
                 AND name = 'archive_v3_shadow_object_schema'",
                [],
                |_| Ok(()),
            )
            .optional()?
            .is_some();
        transaction.execute_batch(
            "CREATE TABLE IF NOT EXISTS archive_v3_shadow_object_schema (
                singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
                version INTEGER NOT NULL CHECK(version BETWEEN 1 AND 2)
            ) STRICT;",
        )?;
        let exists = transaction
            .query_row(
                "SELECT 1 FROM sqlite_master WHERE type = 'table'
                 AND name = 'archive_v3_shadow_objects'",
                [],
                |_| Ok(()),
            )
            .optional()?
            .is_some();
        if !Self::has_exact_schema_descriptor(
            transaction,
            "archive_v3_shadow_object_schema",
            SHADOW_OBJECT_SCHEMA_TABLE_SQL,
        )? {
            return Err(OperationLedgerError::Corrupt);
        }
        let version = Self::read_shadow_object_schema_version(transaction)?;
        if !exists {
            if schema_was_present {
                return Err(OperationLedgerError::Corrupt);
            }
            Self::create_shadow_object_table_v2(transaction)?;
            Self::create_shadow_object_index_v2(transaction)?;
            Self::set_shadow_object_schema_version(transaction, 2)?;
            return Ok(());
        }
        let columns = Self::shadow_object_columns(transaction)?;
        let v2 = columns == shadow_object_columns_v2()
            && Self::has_exact_schema_descriptor(
                transaction,
                "archive_v3_shadow_objects",
                SHADOW_OBJECT_TABLE_V2_SQL,
            )?
            && Self::has_exact_index_descriptor(
                transaction,
                "archive_v3_shadow_objects_exact_attempt",
                SHADOW_OBJECT_INDEX_SQL,
            )?;
        let v1 = columns == shadow_object_columns_v1()
            && Self::has_exact_schema_descriptor(
                transaction,
                "archive_v3_shadow_objects",
                SHADOW_OBJECT_TABLE_V1_SQL,
            )?
            && Self::has_exact_index_descriptor(
                transaction,
                "archive_v3_shadow_objects_exact_attempt",
                SHADOW_OBJECT_INDEX_SQL,
            )?;
        if v2 {
            if version != Some(2) {
                return Err(OperationLedgerError::Corrupt);
            }
            Self::create_shadow_object_index_v2(transaction)?;
            Self::set_shadow_object_schema_version(transaction, 2)?;
            return Ok(());
        }
        if !v1 || !matches!(version, None | Some(1)) {
            return Err(OperationLedgerError::Corrupt);
        }
        transaction.execute_batch(
            "ALTER TABLE archive_v3_shadow_objects
                RENAME TO archive_v3_shadow_objects_v1_migration;",
        )?;
        // Do not create the named v2 index yet: SQLite retains index names on
        // the renamed table, and IF NOT EXISTS would otherwise skip it.
        Self::create_shadow_object_table_v2(transaction)?;
        Self::migrate_shadow_objects_v1(transaction)?;
        transaction.execute_batch("DROP TABLE archive_v3_shadow_objects_v1_migration;")?;
        Self::create_shadow_object_index_v2(transaction)?;
        Self::set_shadow_object_schema_version(transaction, 2)?;
        Ok(())
    }

    fn shadow_object_columns(transaction: &Transaction<'_>) -> Result<HashSet<String>> {
        let mut statement = transaction.prepare("PRAGMA table_info(archive_v3_shadow_objects)")?;
        let rows = statement.query_map([], |row| row.get::<_, String>(1))?;
        let mut columns = HashSet::new();
        for row in rows {
            columns.insert(row?);
        }
        Ok(columns)
    }

    fn has_exact_schema_descriptor(
        transaction: &Transaction<'_>,
        name: &str,
        expected: &str,
    ) -> Result<bool> {
        let actual: Option<String> = transaction
            .query_row(
                "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = ?",
                params![name],
                |row| row.get(0),
            )
            .optional()?;
        Ok(actual.is_some_and(|actual| {
            normalized_schema_sql(&actual) == normalized_schema_sql(expected)
        }))
    }

    fn has_exact_index_descriptor(
        transaction: &Transaction<'_>,
        name: &str,
        expected: &str,
    ) -> Result<bool> {
        let actual: Option<String> = transaction
            .query_row(
                "SELECT sql FROM sqlite_master WHERE type = 'index' AND name = ?",
                params![name],
                |row| row.get(0),
            )
            .optional()?;
        Ok(actual.is_some_and(|actual| {
            normalized_schema_sql(&actual) == normalized_schema_sql(expected)
        }))
    }

    fn read_shadow_object_schema_version(transaction: &Transaction<'_>) -> Result<Option<i64>> {
        let mut statement = transaction.prepare(
            "SELECT singleton, version FROM archive_v3_shadow_object_schema ORDER BY singleton LIMIT 3",
        )?;
        let rows =
            statement.query_map([], |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)))?;
        let mut values = Vec::new();
        for row in rows {
            values.push(row?);
        }
        match values.as_slice() {
            [] => Ok(None),
            [(1, version)] => Ok(Some(*version)),
            _ => Err(OperationLedgerError::Corrupt),
        }
    }

    fn create_shadow_object_table_v2(transaction: &Transaction<'_>) -> Result<()> {
        transaction.execute_batch(
            "CREATE TABLE archive_v3_shadow_objects (
                session_id BLOB NOT NULL CHECK(length(session_id) = 16),
                attempt_id BLOB NOT NULL CHECK(length(attempt_id) = 16),
                ordinal INTEGER NOT NULL CHECK(ordinal >= 0 AND ordinal < 32898),
                object_id BLOB NOT NULL CHECK(length(object_id) = 16),
                object_role INTEGER NOT NULL CHECK(object_role BETWEEN 1 AND 8),
                root_seq INTEGER,
                context_aad BLOB NOT NULL
                    CHECK(length(context_aad) > 0 AND length(context_aad) <= 512),
                object_key TEXT NOT NULL
                    CHECK(length(object_key) > 0 AND length(object_key) <= 512),
                ciphertext_hash BLOB NOT NULL CHECK(length(ciphertext_hash) = 32),
                state INTEGER NOT NULL CHECK(state BETWEEN 1 AND 4),
                PRIMARY KEY(session_id, attempt_id, ordinal),
                UNIQUE(session_id, attempt_id, object_id),
                CHECK(root_seq IS NULL OR root_seq > 0),
                CHECK((object_role = 5 AND root_seq IS NOT NULL)
                    OR (object_role != 5 AND root_seq IS NULL))
            ) STRICT;",
        )?;
        Ok(())
    }

    fn create_shadow_object_index_v2(transaction: &Transaction<'_>) -> Result<()> {
        transaction.execute_batch(
            "CREATE INDEX IF NOT EXISTS archive_v3_shadow_objects_exact_attempt
                ON archive_v3_shadow_objects(session_id, attempt_id, state);",
        )?;
        Ok(())
    }

    fn set_shadow_object_schema_version(transaction: &Transaction<'_>, version: i64) -> Result<()> {
        transaction.execute(
            "INSERT INTO archive_v3_shadow_object_schema(singleton, version) VALUES (1, ?)
             ON CONFLICT(singleton) DO UPDATE SET version = excluded.version",
            params![version],
        )?;
        Ok(())
    }

    fn migrate_shadow_objects_v1(transaction: &Transaction<'_>) -> Result<()> {
        let mut statement = transaction.prepare(
            "SELECT session_id, attempt_id, object_id, object_role, root_seq,
                    context_aad, ciphertext_hash, state
             FROM archive_v3_shadow_objects_v1_migration
             ORDER BY session_id, attempt_id, rowid",
        )?;
        let mut rows = statement.query([])?;
        let mut prior_attempt: Option<([u8; 16], [u8; 16])> = None;
        let mut ordinal = 0u32;
        while let Some(row) = rows.next()? {
            let session_id = row.get::<_, Vec<u8>>(0)?;
            let attempt_id = row.get::<_, Vec<u8>>(1)?;
            let object_id = row.get::<_, Vec<u8>>(2)?;
            let role = row.get::<_, i64>(3)?;
            let root_seq = row.get::<_, Option<i64>>(4)?;
            let context_aad = row.get::<_, Vec<u8>>(5)?;
            let ciphertext_hash = row.get::<_, Vec<u8>>(6)?;
            let state = row.get::<_, i64>(7)?;
            let session_id: [u8; 16] = session_id
                .try_into()
                .map_err(|_| OperationLedgerError::Corrupt)?;
            let attempt_id: [u8; 16] = attempt_id
                .try_into()
                .map_err(|_| OperationLedgerError::Corrupt)?;
            let attempt = (session_id, attempt_id);
            if prior_attempt != Some(attempt) {
                prior_attempt = Some(attempt);
                ordinal = 0;
            }
            if (ordinal as usize) >= MAX_SHADOW_OBJECTS_PER_ATTEMPT {
                return Err(OperationLedgerError::TooLarge("shadow objects per attempt"));
            }
            let session_id = ShadowSessionId::from_bytes(session_id);
            let attempt_id = ShadowAttemptId::from_bytes(attempt_id);
            let record = Self::read_shadow_session(transaction, session_id, attempt_id)?
                .ok_or(OperationLedgerError::Corrupt)?;
            let object_id = ObjectId::from_bytes(
                object_id
                    .try_into()
                    .map_err(|_| OperationLedgerError::Corrupt)?,
            );
            let object_role = decode_object_role(role)?;
            let root_seq = root_seq.map(positive_u64).transpose()?;
            let facts = ShadowObjectFacts {
                ordinal,
                object_id,
                object_role,
                root_seq,
                context_aad: Zeroizing::new(context_aad),
                object_key: String::new(),
                ciphertext_hash: ciphertext_hash
                    .try_into()
                    .map_err(|_| OperationLedgerError::Corrupt)?,
            };
            let context = ObjectContext::decode_canonical_aad(facts.context_aad.as_slice())
                .map_err(|_| OperationLedgerError::Corrupt)?;
            let facts = ShadowObjectFacts {
                object_key: context.object_key().as_str().to_owned(),
                ..facts
            };
            facts.validate_canonical()?;
            if !facts.matches_binding(record.binding()) {
                return Err(OperationLedgerError::Corrupt);
            }
            let state = ShadowObjectState::decode(state)?;
            let inserted = transaction.execute(
                "INSERT INTO archive_v3_shadow_objects (
                    session_id, attempt_id, ordinal, object_id, object_role, root_seq,
                    context_aad, object_key, ciphertext_hash, state
                 ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                params![
                    session_id.as_bytes().as_slice(),
                    attempt_id.as_bytes().as_slice(),
                    ordinal as i64,
                    facts.object_id.as_bytes().as_slice(),
                    facts.object_role as i64,
                    facts.root_seq.map(|value| value as i64),
                    facts.context_aad.as_slice(),
                    facts.object_key.as_str(),
                    facts.ciphertext_hash.as_slice(),
                    state as i64,
                ],
            )?;
            if inserted != 1 {
                return Err(OperationLedgerError::Corrupt);
            }
            ordinal = ordinal
                .checked_add(1)
                .ok_or(OperationLedgerError::Corrupt)?;
        }
        Ok(())
    }

    /// Persist one exact prepared shadow session before any candidate object is
    /// created. Exact retries are idempotent; either reuse of the stable session
    /// ID or reuse of the archive/epoch/operation tuple with different bytes
    /// fails closed.
    pub fn prepare_shadow_session(
        connection: &mut Connection,
        record: &ShadowSessionRecord,
    ) -> Result<RecordOutcome> {
        if record.state() != ShadowSessionState::Prepared || record.candidate().is_some() {
            return Err(OperationLedgerError::ShadowSession(
                ShadowSessionError::InvalidTransition,
            ));
        }
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        if let Some(existing) =
            Self::read_shadow_session(&transaction, record.session_id(), record.attempt_id())?
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
        let existing = Self::read_shadow_session_family(&transaction, record.session_id())?;
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
        let inserted = transaction.execute(
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
        transaction.commit()?;
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
        if !facts.matches_binding(expected_binding) {
            return Err(OperationLedgerError::ResultConflict);
        }
        if session.state() != ShadowSessionState::Prepared {
            return Err(OperationLedgerError::ShadowSession(
                ShadowSessionError::InvalidTransition,
            ));
        }
        if let Some(existing) =
            Self::read_shadow_object_ordinal(&transaction, session_id, attempt_id, facts.ordinal)?
        {
            if existing == *facts {
                transaction.commit()?;
                return Ok(RecordOutcome::AlreadyRecorded);
            }
            return Err(OperationLedgerError::ResultConflict);
        }
        if Self::read_shadow_object(&transaction, session_id, attempt_id, facts.object_id)?
            .is_some()
        {
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
                session_id, attempt_id, ordinal, object_id, object_role, root_seq,
                context_aad, object_key, ciphertext_hash, state
             ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            params![
                session_id.as_bytes().as_slice(),
                attempt_id.as_bytes().as_slice(),
                facts.ordinal as i64,
                facts.object_id.as_bytes().as_slice(),
                facts.object_role as i64,
                facts.root_seq.map(|value| value as i64),
                facts.context_aad.as_slice(),
                facts.object_key.as_str(),
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

    /// Read one exact attempt's bounded ordinal inventory.  This is the sole
    /// restart seam: callers receive provider-neutral exact keys only and must
    /// reconcile each row with `get`, never a prefix/list operation.
    pub(crate) fn load_exact_shadow_object_page(
        connection: &Connection,
        session_id: ShadowSessionId,
        attempt_id: ShadowAttemptId,
        expected_binding: ShadowSessionBinding,
        after_ordinal: Option<u32>,
    ) -> Result<ShadowObjectInventoryPage> {
        let session = Self::read_shadow_session(connection, session_id, attempt_id)?
            .ok_or(OperationLedgerError::Corrupt)?;
        session.require_binding(expected_binding)?;
        let mut statement = connection.prepare(
            "SELECT ordinal, object_id, object_role, root_seq, context_aad, object_key, ciphertext_hash, state
             FROM archive_v3_shadow_objects
             WHERE session_id = ? AND attempt_id = ? AND ordinal > ?
             ORDER BY ordinal LIMIT 257",
        )?;
        let rows = statement.query_map(
            params![
                session_id.as_bytes().as_slice(),
                attempt_id.as_bytes().as_slice(),
                after_ordinal.map(i64::from).unwrap_or(-1),
            ],
            |row| Ok((read_shadow_object_row(row)?, row.get::<_, i64>(7)?)),
        )?;
        let mut values = Vec::new();
        let mut previous = after_ordinal;
        for row in rows {
            let (row, state) = row?;
            let facts = Self::read_shadow_object_row(Some(row), None)?
                .ok_or(OperationLedgerError::Corrupt)?;
            if !facts.matches_binding(expected_binding) {
                return Err(OperationLedgerError::Corrupt);
            }
            if previous.is_some_and(|value| facts.ordinal <= value) {
                return Err(OperationLedgerError::Corrupt);
            }
            previous = Some(facts.ordinal);
            values.push(ShadowObjectInventoryEntry {
                facts,
                state: ShadowObjectState::decode(state)?,
            });
        }
        let next_ordinal = if values.len() > MAX_SHADOW_OBJECTS_PAGE {
            values.pop().ok_or(OperationLedgerError::Corrupt)?;
            values.last().map(|entry| entry.facts.ordinal)
        } else {
            None
        };
        Ok(ShadowObjectInventoryPage {
            entries: values,
            next_ordinal,
        })
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
        let reserved: i64 = transaction.query_row(
            "SELECT COUNT(*) FROM archive_v3_shadow_objects
             WHERE session_id = ? AND attempt_id = ? AND state = ?",
            params![
                session_id.as_bytes().as_slice(),
                attempt_id.as_bytes().as_slice(),
                ShadowObjectState::Reserved as i64,
            ],
            |row| row.get(0),
        )?;
        if reserved != 0 {
            return Err(OperationLedgerError::ResultConflict);
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
        Self::read_shadow_object_row(
            connection.query_row(
                "SELECT ordinal, object_id, object_role, root_seq, context_aad, object_key, ciphertext_hash
                 FROM archive_v3_shadow_objects
                 WHERE session_id = ? AND attempt_id = ? AND object_id = ?",
                params![
                    session_id.as_bytes().as_slice(),
                    attempt_id.as_bytes().as_slice(),
                    object_id.as_bytes().as_slice(),
                ],
                read_shadow_object_row,
            ).optional()?,
            Some(object_id),
        )
    }

    fn read_shadow_object_ordinal(
        connection: &Connection,
        session_id: ShadowSessionId,
        attempt_id: ShadowAttemptId,
        ordinal: u32,
    ) -> Result<Option<ShadowObjectFacts>> {
        Self::read_shadow_object_row(
            connection.query_row(
                "SELECT ordinal, object_id, object_role, root_seq, context_aad, object_key, ciphertext_hash
                 FROM archive_v3_shadow_objects
                 WHERE session_id = ? AND attempt_id = ? AND ordinal = ?",
                params![
                    session_id.as_bytes().as_slice(),
                    attempt_id.as_bytes().as_slice(),
                    ordinal as i64,
                ],
                read_shadow_object_row,
            ).optional()?,
            None,
        )
    }

    fn read_shadow_object_row(
        row: Option<ShadowObjectRow>,
        expected_object_id: Option<ObjectId>,
    ) -> Result<Option<ShadowObjectFacts>> {
        row.map(
            |(ordinal, object_id, role, root_seq, context_aad, object_key, ciphertext_hash)| {
                let object_id: [u8; 16] = object_id
                    .try_into()
                    .map_err(|_| OperationLedgerError::Corrupt)?;
                let object_id = ObjectId::from_bytes(object_id);
                if expected_object_id.is_some_and(|expected| expected != object_id) {
                    return Err(OperationLedgerError::Corrupt);
                }
                let ordinal = u32::try_from(ordinal).map_err(|_| OperationLedgerError::Corrupt)?;
                let object_role = decode_object_role(role)?;
                if context_aad.is_empty() || context_aad.len() > MAX_SHADOW_OBJECT_CONTEXT_BYTES {
                    return Err(OperationLedgerError::Corrupt);
                }
                if !valid_shadow_object_key(&object_key, object_role, object_id) {
                    return Err(OperationLedgerError::Corrupt);
                }
                let root_seq = root_seq.map(positive_u64).transpose()?;
                if (object_role == ObjectRole::RootV3) != root_seq.is_some() {
                    return Err(OperationLedgerError::Corrupt);
                }
                let facts = ShadowObjectFacts {
                    object_id,
                    ordinal,
                    object_role,
                    root_seq,
                    context_aad: Zeroizing::new(context_aad),
                    object_key,
                    ciphertext_hash: ciphertext_hash
                        .try_into()
                        .map_err(|_| OperationLedgerError::Corrupt)?,
                };
                facts.validate_canonical()?;
                Ok(facts)
            },
        )
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

type ShadowObjectRow = (i64, Vec<u8>, i64, Option<i64>, Vec<u8>, String, Vec<u8>);

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

fn read_shadow_object_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<ShadowObjectRow> {
    Ok((
        row.get(0)?,
        row.get(1)?,
        row.get(2)?,
        row.get(3)?,
        row.get(4)?,
        row.get(5)?,
        row.get(6)?,
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

type LegacyExtentSessionRow = ShadowSessionRow;

fn read_legacy_extent_session_row(
    row: &rusqlite::Row<'_>,
) -> rusqlite::Result<LegacyExtentSessionRow> {
    read_shadow_session_row(row)
}

fn decode_legacy_extent_session_row(
    row: LegacyExtentSessionRow,
) -> Result<LegacyExtentSessionRecord> {
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
        LegacyExtentSessionRecord::decode(&encoded).map_err(|_| OperationLedgerError::Corrupt)?;
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

impl OperationLedger {
    /// Separate, exact schema for legacy conversion.  It never aliases a
    /// shadow row: a future migration cannot forge WAL-specific facts.
    fn initialize_legacy_extent_inventory(transaction: &Transaction<'_>) -> Result<()> {
        let existing: i64 = transaction.query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name IN (
                'archive_v3_legacy_extent_schema',
                'archive_v3_legacy_extent_sessions',
                'archive_v3_legacy_extent_objects')",
            [],
            |row| row.get(0),
        )?;
        if !matches!(existing, 0 | 3) {
            return Err(OperationLedgerError::Corrupt);
        }
        if existing == 0 {
            transaction.execute_batch(
            "CREATE TABLE IF NOT EXISTS archive_v3_legacy_extent_schema (
                singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
                version INTEGER NOT NULL CHECK(version = 2)
            ) STRICT;
            CREATE TABLE IF NOT EXISTS archive_v3_legacy_extent_sessions (
                session_id BLOB NOT NULL CHECK(length(session_id) = 16),
                attempt_id BLOB UNIQUE NOT NULL CHECK(length(attempt_id) = 16),
                archive_id BLOB NOT NULL CHECK(length(archive_id) = 16),
                database_epoch BLOB NOT NULL CHECK(length(database_epoch) = 16),
                operation_id BLOB NOT NULL CHECK(length(operation_id) = 16),
                request_fingerprint BLOB NOT NULL CHECK(length(request_fingerprint) = 32),
                state INTEGER NOT NULL CHECK(state BETWEEN 1 AND 3),
                record BLOB NOT NULL CHECK(length(record) = 436),
                PRIMARY KEY(session_id, attempt_id)
            ) STRICT;
            CREATE TABLE IF NOT EXISTS archive_v3_legacy_extent_objects (
                session_id BLOB NOT NULL CHECK(length(session_id) = 16),
                attempt_id BLOB NOT NULL CHECK(length(attempt_id) = 16),
                ordinal INTEGER NOT NULL CHECK(ordinal >= 0 AND ordinal < 32898),
                object_id BLOB NOT NULL CHECK(length(object_id) = 16),
                object_role INTEGER NOT NULL CHECK(object_role IN (3, 4, 5)),
                root_seq INTEGER,
                context_aad BLOB NOT NULL CHECK(length(context_aad) > 0 AND length(context_aad) <= 512),
                object_key TEXT NOT NULL CHECK(length(object_key) > 0 AND length(object_key) <= 512),
                ciphertext_hash BLOB NOT NULL CHECK(length(ciphertext_hash) = 32),
                state INTEGER NOT NULL CHECK(state BETWEEN 1 AND 3),
                PRIMARY KEY(session_id, attempt_id, ordinal),
                UNIQUE(session_id, attempt_id, object_id),
                CHECK(root_seq IS NULL OR root_seq > 0),
                CHECK((object_role = 5 AND root_seq IS NOT NULL) OR (object_role != 5 AND root_seq IS NULL))
            ) STRICT;
            CREATE INDEX IF NOT EXISTS archive_v3_legacy_extent_objects_exact_attempt
                ON archive_v3_legacy_extent_objects(session_id, attempt_id, state, ordinal);",
            )?;
            transaction.execute(
                "INSERT INTO archive_v3_legacy_extent_schema(singleton, version) VALUES (1, 2)",
                [],
            )?;
        }
        for (name, expected) in [
            (
                "archive_v3_legacy_extent_schema",
                LEGACY_EXTENT_SCHEMA_TABLE_SQL,
            ),
            (
                "archive_v3_legacy_extent_sessions",
                LEGACY_EXTENT_SESSIONS_TABLE_SQL,
            ),
            (
                "archive_v3_legacy_extent_objects",
                LEGACY_EXTENT_OBJECTS_TABLE_SQL,
            ),
        ] {
            if !Self::has_exact_schema_descriptor(transaction, name, expected)? {
                return Err(OperationLedgerError::Corrupt);
            }
        }
        if !Self::has_exact_index_descriptor(
            transaction,
            "archive_v3_legacy_extent_objects_exact_attempt",
            LEGACY_EXTENT_OBJECTS_INDEX_SQL,
        )? {
            return Err(OperationLedgerError::Corrupt);
        }
        let triggers: i64 = transaction.query_row(
            "SELECT COUNT(*) FROM (
                SELECT type, tbl_name FROM sqlite_master
                UNION ALL
                SELECT type, tbl_name FROM sqlite_temp_master
             ) WHERE type = 'trigger' AND tbl_name IN (
                'archive_v3_legacy_extent_schema',
                'archive_v3_legacy_extent_sessions',
                'archive_v3_legacy_extent_objects')",
            [],
            |row| row.get(0),
        )?;
        if triggers != 0 {
            return Err(OperationLedgerError::Corrupt);
        }
        let rows: Vec<(i64, i64)> = transaction.prepare("SELECT singleton, version FROM archive_v3_legacy_extent_schema ORDER BY singleton LIMIT 2")?
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?.collect::<std::result::Result<_, _>>()?;
        if rows.as_slice() != [(1, 2)] {
            return Err(OperationLedgerError::Corrupt);
        }
        Ok(())
    }

    pub(crate) fn prepare_legacy_extent_session(
        connection: &mut Connection,
        record: &LegacyExtentSessionRecord,
    ) -> Result<RecordOutcome> {
        if record.state() != LegacyExtentSessionState::Prepared || record.candidate().is_some() {
            return Err(OperationLedgerError::LegacyExtentSession(
                LegacyExtentSessionError::InvalidTransition,
            ));
        }
        let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        if let Some(existing) =
            Self::read_legacy_extent_session(&tx, record.session_id(), record.attempt_id())?
        {
            return if existing == *record {
                Ok(RecordOutcome::AlreadyRecorded)
            } else if existing.binding().request_fingerprint()
                != record.binding().request_fingerprint()
            {
                Err(OperationLedgerError::FingerprintConflict)
            } else {
                Err(OperationLedgerError::ResultConflict)
            };
        }
        let mut statement = tx.prepare("SELECT session_id,attempt_id,archive_id,database_epoch,operation_id,request_fingerprint,state,record FROM archive_v3_legacy_extent_sessions WHERE session_id = ? ORDER BY attempt_id LIMIT 17")?;
        let family: Vec<LegacyExtentSessionRecord> = statement
            .query_map(params![record.session_id().as_bytes().as_slice()], |row| {
                read_legacy_extent_session_row(row)
            })?
            .map(|row| {
                row.map_err(OperationLedgerError::from)
                    .and_then(decode_legacy_extent_session_row)
            })
            .collect::<Result<_>>()?;
        drop(statement);
        for existing in &family {
            Self::validate_legacy_extent_session_inventory(&tx, existing)?;
        }
        if family.len() >= usize::try_from(MAX_LEGACY_EXTENT_SESSION_ATTEMPTS).unwrap() {
            return Err(OperationLedgerError::TooLarge(
                "legacy extent session attempts",
            ));
        }
        if let Some(first) = family.first() {
            let a = first.binding();
            let b = record.binding();
            if a.archive_id() != b.archive_id()
                || a.database_epoch() != b.database_epoch()
                || a.operation_id() != b.operation_id()
            {
                return Err(OperationLedgerError::ResultConflict);
            }
            if a.request_fingerprint() != b.request_fingerprint() {
                return Err(OperationLedgerError::FingerprintConflict);
            }
            if family.iter().any(|r| {
                matches!(
                    r.state(),
                    LegacyExtentSessionState::Prepared | LegacyExtentSessionState::CandidateReady
                )
            }) {
                return Err(OperationLedgerError::ResultConflict);
            }
        }
        let b = record.binding();
        let encoded = record.encode()?;
        if tx.execute("INSERT INTO archive_v3_legacy_extent_sessions (session_id, attempt_id, archive_id, database_epoch, operation_id, request_fingerprint, state, record) VALUES (?, ?, ?, ?, ?, ?, ?, ?)", params![record.session_id().as_bytes().as_slice(), record.attempt_id().as_bytes().as_slice(), b.archive_id().as_slice(), b.database_epoch().as_slice(), b.operation_id().as_slice(), b.request_fingerprint().as_slice(), record.state() as i64, encoded.as_slice()])? != 1 { return Err(OperationLedgerError::Corrupt); }
        tx.commit()?;
        Ok(RecordOutcome::Recorded)
    }

    pub(crate) fn load_legacy_extent_session(
        connection: &Connection,
        session_id: LegacyExtentSessionId,
        attempt_id: LegacyExtentAttemptId,
    ) -> Result<Option<LegacyExtentSessionRecord>> {
        Self::read_legacy_extent_session(connection, session_id, attempt_id)
    }

    pub(crate) fn reserve_legacy_extent_object(
        connection: &mut Connection,
        session_id: LegacyExtentSessionId,
        attempt_id: LegacyExtentAttemptId,
        binding: LegacyExtentSessionBinding,
        facts: &LegacyExtentObjectFacts,
    ) -> Result<RecordOutcome> {
        facts.validate_canonical()?;
        if !facts.matches_binding(binding) {
            return Err(OperationLedgerError::ResultConflict);
        }
        let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let record = Self::read_legacy_extent_session(&tx, session_id, attempt_id)?
            .ok_or(OperationLedgerError::Corrupt)?;
        record.require_binding(binding)?;
        if record.state() != LegacyExtentSessionState::Prepared {
            return Err(OperationLedgerError::LegacyExtentSession(
                LegacyExtentSessionError::InvalidTransition,
            ));
        }
        if let Some(existing) =
            Self::read_legacy_extent_object_ordinal(&tx, session_id, attempt_id, facts.ordinal)?
        {
            if existing == *facts {
                tx.commit()?;
                return Ok(RecordOutcome::AlreadyRecorded);
            }
            return Err(OperationLedgerError::ResultConflict);
        }
        if Self::read_legacy_extent_object(&tx, session_id, attempt_id, facts.object_id)?.is_some()
        {
            return Err(OperationLedgerError::ResultConflict);
        }
        let count:i64=tx.query_row("SELECT COUNT(*) FROM archive_v3_legacy_extent_objects WHERE session_id=? AND attempt_id=?",params![session_id.as_bytes().as_slice(),attempt_id.as_bytes().as_slice()],|r|r.get(0))?;
        if count < 0
            || usize::try_from(count)
                .ok()
                .is_none_or(|n| n >= MAX_LEGACY_EXTENT_OBJECTS_PER_ATTEMPT)
        {
            return Err(OperationLedgerError::TooLarge(
                "legacy extent objects per attempt",
            ));
        }
        if facts.ordinal != u32::try_from(count).map_err(|_| OperationLedgerError::Corrupt)? {
            return Err(OperationLedgerError::ResultConflict);
        }
        let roots: i64 = tx.query_row(
            "SELECT COUNT(*) FROM archive_v3_legacy_extent_objects
             WHERE session_id = ? AND attempt_id = ? AND object_role = ?",
            params![
                session_id.as_bytes().as_slice(),
                attempt_id.as_bytes().as_slice(),
                ObjectRole::RootV3 as i64
            ],
            |row| row.get(0),
        )?;
        if roots != 0 {
            return Err(OperationLedgerError::ResultConflict);
        }
        if tx.execute("INSERT INTO archive_v3_legacy_extent_objects (session_id,attempt_id,ordinal,object_id,object_role,root_seq,context_aad,object_key,ciphertext_hash,state) VALUES (?,?,?,?,?,?,?,?,?,?)",params![session_id.as_bytes().as_slice(),attempt_id.as_bytes().as_slice(),i64::from(facts.ordinal),facts.object_id.as_bytes().as_slice(),facts.object_role as i64,facts.root_seq.map(|x|x as i64),facts.context_aad.as_slice(),facts.object_key.as_str(),facts.ciphertext_hash.as_slice(),LegacyExtentObjectState::Reserved as i64])? !=1 {return Err(OperationLedgerError::Corrupt)}
        tx.commit()?;
        Ok(RecordOutcome::Recorded)
    }

    pub(crate) fn mark_legacy_extent_object_materialized(
        connection: &mut Connection,
        session_id: LegacyExtentSessionId,
        attempt_id: LegacyExtentAttemptId,
        binding: LegacyExtentSessionBinding,
        facts: &LegacyExtentObjectFacts,
    ) -> Result<RecordOutcome> {
        let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let record = Self::read_legacy_extent_session(&tx, session_id, attempt_id)?
            .ok_or(OperationLedgerError::Corrupt)?;
        record.require_binding(binding)?;
        if record.state() != LegacyExtentSessionState::Prepared {
            return Err(OperationLedgerError::LegacyExtentSession(
                LegacyExtentSessionError::InvalidTransition,
            ));
        }
        if Self::read_legacy_extent_object(&tx, session_id, attempt_id, facts.object_id)?.as_ref()
            != Some(facts)
        {
            return Err(OperationLedgerError::ResultConflict);
        }
        match Self::read_legacy_extent_object_state(&tx, session_id, attempt_id, facts.object_id)? {
            Some(LegacyExtentObjectState::Reserved) => {
                if tx.execute("UPDATE archive_v3_legacy_extent_objects SET state=? WHERE session_id=? AND attempt_id=? AND object_id=? AND state=?",params![LegacyExtentObjectState::Materialized as i64,session_id.as_bytes().as_slice(),attempt_id.as_bytes().as_slice(),facts.object_id.as_bytes().as_slice(),LegacyExtentObjectState::Reserved as i64])?!=1{return Err(OperationLedgerError::Corrupt)}
                tx.commit()?;
                Ok(RecordOutcome::Recorded)
            }
            Some(LegacyExtentObjectState::Materialized) => {
                tx.commit()?;
                Ok(RecordOutcome::AlreadyRecorded)
            }
            _ => Err(OperationLedgerError::ResultConflict),
        }
    }

    pub(crate) fn load_exact_legacy_extent_object_page(
        connection: &Connection,
        session_id: LegacyExtentSessionId,
        attempt_id: LegacyExtentAttemptId,
        binding: LegacyExtentSessionBinding,
        cursor: Option<LegacyExtentObjectCursor>,
    ) -> Result<LegacyExtentObjectInventoryPage> {
        let transaction = Transaction::new_unchecked(connection, TransactionBehavior::Deferred)?;
        let record = Self::read_legacy_extent_session(&transaction, session_id, attempt_id)?
            .ok_or(OperationLedgerError::Corrupt)?;
        record.require_binding(binding)?;
        let expected = match cursor {
            None => 0,
            Some(cursor)
                if cursor.session_id == session_id
                    && cursor.attempt_id == attempt_id
                    && cursor.valid()
                    && usize::try_from(cursor.next_ordinal)
                        .ok()
                        .is_some_and(|value| value < MAX_LEGACY_EXTENT_OBJECTS_PER_ATTEMPT) =>
            {
                cursor.next_ordinal
            }
            Some(_) => return Err(OperationLedgerError::Corrupt),
        };
        let prefix_count: i64 = transaction.query_row(
            "SELECT COUNT(*) FROM archive_v3_legacy_extent_objects
             WHERE session_id = ? AND attempt_id = ? AND ordinal < ?",
            params![
                session_id.as_bytes().as_slice(),
                attempt_id.as_bytes().as_slice(),
                i64::from(expected)
            ],
            |row| row.get(0),
        )?;
        if prefix_count != i64::from(expected) {
            return Err(OperationLedgerError::Corrupt);
        }
        let mut st=transaction.prepare("SELECT ordinal,object_id,object_role,root_seq,context_aad,object_key,ciphertext_hash,state FROM archive_v3_legacy_extent_objects WHERE session_id=? AND attempt_id=? AND ordinal>=? ORDER BY ordinal LIMIT 257")?;
        let rows = st.query_map(
            params![
                session_id.as_bytes().as_slice(),
                attempt_id.as_bytes().as_slice(),
                i64::from(expected)
            ],
            |r| Ok((read_shadow_object_row(r)?, r.get::<_, i64>(7)?)),
        )?;
        let mut entries = Vec::new();
        let mut next_expected = expected;
        for row in rows {
            let (row, state) = row?;
            let facts = Self::legacy_facts_from_row(row)?;
            if !facts.matches_binding(binding) || facts.ordinal != next_expected {
                return Err(OperationLedgerError::Corrupt);
            }
            next_expected = next_expected
                .checked_add(1)
                .ok_or(OperationLedgerError::Corrupt)?;
            entries.push(LegacyExtentObjectInventoryEntry {
                facts,
                state: LegacyExtentObjectState::decode(state)?,
            });
        }
        let next_cursor = if entries.len() > MAX_LEGACY_EXTENT_OBJECTS_PAGE {
            entries.pop();
            Some(LegacyExtentObjectCursor::new(
                session_id,
                attempt_id,
                expected
                    .checked_add(
                        u32::try_from(entries.len()).map_err(|_| OperationLedgerError::Corrupt)?,
                    )
                    .ok_or(OperationLedgerError::Corrupt)?,
            ))
        } else {
            if cursor.is_some() && entries.is_empty() {
                return Err(OperationLedgerError::Corrupt);
            }
            None
        };
        drop(st);
        transaction.commit()?;
        Ok(LegacyExtentObjectInventoryPage {
            entries,
            next_cursor,
        })
    }

    fn scan_legacy_extent_inventory(
        connection: &Connection,
        session_id: LegacyExtentSessionId,
        attempt_id: LegacyExtentAttemptId,
        binding: LegacyExtentSessionBinding,
        requirement: LegacyExtentInventoryRequirement,
    ) -> Result<LegacyExtentInventoryScan> {
        let mut statement=connection.prepare("SELECT ordinal,object_id,object_role,root_seq,context_aad,object_key,ciphertext_hash,state FROM archive_v3_legacy_extent_objects WHERE session_id=? AND attempt_id=? ORDER BY ordinal LIMIT 32899")?;
        let rows = statement.query_map(
            params![
                session_id.as_bytes().as_slice(),
                attempt_id.as_bytes().as_slice()
            ],
            |row| Ok((read_shadow_object_row(row)?, row.get::<_, i64>(7)?)),
        )?;
        let mut count = 0usize;
        let mut root = None;
        let mut commitment = Sha256::new();
        commitment.update(LEGACY_EXTENT_INVENTORY_DOMAIN);
        commitment.update(session_id.as_bytes());
        commitment.update(attempt_id.as_bytes());
        for row in rows {
            let (row, encoded_state) = row?;
            let facts = Self::legacy_facts_from_row(row)?;
            let state = LegacyExtentObjectState::decode(encoded_state)?;
            if count >= MAX_LEGACY_EXTENT_OBJECTS_PER_ATTEMPT
                || facts.ordinal
                    != u32::try_from(count).map_err(|_| OperationLedgerError::Corrupt)?
                || !facts.matches_binding(binding)
                || root.is_some()
                || !match requirement {
                    LegacyExtentInventoryRequirement::Materialized => {
                        state == LegacyExtentObjectState::Materialized
                    }
                    LegacyExtentInventoryRequirement::PreOrphan => matches!(
                        state,
                        LegacyExtentObjectState::Reserved | LegacyExtentObjectState::Materialized
                    ),
                    LegacyExtentInventoryRequirement::Orphaned => {
                        state == LegacyExtentObjectState::OrphanPendingGrace
                    }
                }
            {
                return Err(OperationLedgerError::Corrupt);
            }
            if facts.object_role == ObjectRole::RootV3 {
                root = Some(facts.clone());
            }
            commitment.update(facts.ordinal.to_be_bytes());
            commitment.update(facts.object_id.as_bytes());
            commitment.update([facts.object_role as u8]);
            match facts.root_seq {
                Some(sequence) => {
                    commitment.update([1]);
                    commitment.update(sequence.to_be_bytes());
                }
                None => commitment.update([0; 9]),
            }
            commitment.update(
                u32::try_from(facts.context_aad.len())
                    .map_err(|_| OperationLedgerError::Corrupt)?
                    .to_be_bytes(),
            );
            commitment.update(facts.context_aad.as_slice());
            commitment.update(
                u32::try_from(facts.object_key.len())
                    .map_err(|_| OperationLedgerError::Corrupt)?
                    .to_be_bytes(),
            );
            commitment.update(facts.object_key.as_bytes());
            commitment.update(facts.ciphertext_hash);
            count += 1;
        }
        commitment.update(
            u32::try_from(count)
                .map_err(|_| OperationLedgerError::Corrupt)?
                .to_be_bytes(),
        );
        Ok(LegacyExtentInventoryScan {
            count,
            root,
            commitment: commitment.finalize().into(),
        })
    }

    /// One IMMEDIATE transaction admits only a complete contiguous materialized graph
    /// and its final root.  It is still not a witness retention or CAS.
    pub(crate) fn persist_legacy_extent_candidate(
        connection: &mut Connection,
        session_id: LegacyExtentSessionId,
        attempt_id: LegacyExtentAttemptId,
        binding: LegacyExtentSessionBinding,
        admission: LegacyExtentRootAdmission,
        root_facts: &LegacyExtentObjectFacts,
    ) -> Result<LegacyExtentSessionRecord> {
        let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let mut record = Self::read_legacy_extent_session(&tx, session_id, attempt_id)?
            .ok_or(OperationLedgerError::Corrupt)?;
        record.require_binding(binding)?;
        let candidate = admission.candidate();
        if !admission.matches(binding)
            || !admission.matches_root_aad(root_facts.context_aad.as_slice())
            || !root_facts.is_candidate_root(candidate)
        {
            return Err(OperationLedgerError::ResultConflict);
        }
        let scan = Self::scan_legacy_extent_inventory(
            &tx,
            session_id,
            attempt_id,
            binding,
            LegacyExtentInventoryRequirement::Materialized,
        )?;
        if scan.count < 2
            || root_facts.ordinal == 0
            || scan.root.as_ref() != Some(root_facts)
            || !scan
                .root
                .as_ref()
                .is_some_and(|facts| facts.is_candidate_root(candidate))
        {
            return Err(OperationLedgerError::ResultConflict);
        }
        let before = record.encode()?;
        record.persist_candidate(candidate)?;
        Self::replace_legacy_extent_session(&tx, &before, &record)?;
        tx.commit()?;
        Ok(record)
    }

    pub(crate) fn orphan_legacy_extent_attempt(
        connection: &mut Connection,
        session_id: LegacyExtentSessionId,
        attempt_id: LegacyExtentAttemptId,
        binding: LegacyExtentSessionBinding,
    ) -> Result<LegacyExtentSessionRecord> {
        let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let mut record = Self::read_legacy_extent_session(&tx, session_id, attempt_id)?
            .ok_or(OperationLedgerError::Corrupt)?;
        record.require_binding(binding)?;
        if record.state() == LegacyExtentSessionState::OrphanPendingGrace {
            let scan = Self::scan_legacy_extent_inventory(
                &tx,
                session_id,
                attempt_id,
                binding,
                LegacyExtentInventoryRequirement::Orphaned,
            )?;
            let proof = record
                .orphan_inventory_proof()
                .ok_or(OperationLedgerError::Corrupt)?;
            if proof
                != (
                    u32::try_from(scan.count).map_err(|_| OperationLedgerError::Corrupt)?,
                    scan.commitment,
                )
            {
                return Err(OperationLedgerError::Corrupt);
            }
            tx.commit()?;
            return Ok(record);
        }
        if record.state() != LegacyExtentSessionState::Prepared {
            return Err(OperationLedgerError::LegacyExtentSession(
                LegacyExtentSessionError::InvalidTransition,
            ));
        }
        let scan = Self::scan_legacy_extent_inventory(
            &tx,
            session_id,
            attempt_id,
            binding,
            LegacyExtentInventoryRequirement::PreOrphan,
        )?;
        let before = record.encode()?;
        record.orphan_with_inventory(
            u32::try_from(scan.count).map_err(|_| OperationLedgerError::Corrupt)?,
            scan.commitment,
        )?;
        let changed=tx.execute("UPDATE archive_v3_legacy_extent_objects SET state=? WHERE session_id=? AND attempt_id=? AND state IN (?,?)",params![LegacyExtentObjectState::OrphanPendingGrace as i64,session_id.as_bytes().as_slice(),attempt_id.as_bytes().as_slice(),LegacyExtentObjectState::Reserved as i64,LegacyExtentObjectState::Materialized as i64])?;
        if changed != scan.count {
            return Err(OperationLedgerError::Corrupt);
        }
        let normalized = Self::scan_legacy_extent_inventory(
            &tx,
            session_id,
            attempt_id,
            binding,
            LegacyExtentInventoryRequirement::Orphaned,
        )?;
        if normalized.count != scan.count || normalized.commitment != scan.commitment {
            return Err(OperationLedgerError::Corrupt);
        }
        Self::replace_legacy_extent_session(&tx, &before, &record)?;
        tx.commit()?;
        Ok(record)
    }

    fn read_legacy_extent_session(
        connection: &Connection,
        session_id: LegacyExtentSessionId,
        attempt_id: LegacyExtentAttemptId,
    ) -> Result<Option<LegacyExtentSessionRecord>> {
        let row: Option<LegacyExtentSessionRow> = connection.query_row("SELECT session_id,attempt_id,archive_id,database_epoch,operation_id,request_fingerprint,state,record FROM archive_v3_legacy_extent_sessions WHERE session_id=? AND attempt_id=?",params![session_id.as_bytes().as_slice(),attempt_id.as_bytes().as_slice()],read_legacy_extent_session_row).optional()?;
        let record = row.map(decode_legacy_extent_session_row).transpose()?;
        if record.as_ref().is_some_and(|record| {
            record.session_id() != session_id || record.attempt_id() != attempt_id
        }) {
            return Err(OperationLedgerError::Corrupt);
        }
        if let Some(record) = record.as_ref() {
            Self::validate_legacy_extent_session_inventory(connection, record)?;
        }
        Ok(record)
    }

    fn validate_legacy_extent_session_inventory(
        connection: &Connection,
        record: &LegacyExtentSessionRecord,
    ) -> Result<()> {
        if record.state() == LegacyExtentSessionState::OrphanPendingGrace {
            let scan = Self::scan_legacy_extent_inventory(
                connection,
                record.session_id(),
                record.attempt_id(),
                record.binding(),
                LegacyExtentInventoryRequirement::Orphaned,
            )?;
            let proof = record
                .orphan_inventory_proof()
                .ok_or(OperationLedgerError::Corrupt)?;
            if proof
                != (
                    u32::try_from(scan.count).map_err(|_| OperationLedgerError::Corrupt)?,
                    scan.commitment,
                )
            {
                return Err(OperationLedgerError::Corrupt);
            }
        }
        if record.state() == LegacyExtentSessionState::CandidateReady {
            let candidate = record.candidate().ok_or(OperationLedgerError::Corrupt)?;
            let scan = Self::scan_legacy_extent_inventory(
                connection,
                record.session_id(),
                record.attempt_id(),
                record.binding(),
                LegacyExtentInventoryRequirement::Materialized,
            )?;
            if scan.count < 2
                || !scan
                    .root
                    .as_ref()
                    .is_some_and(|root| root.is_candidate_root(candidate))
            {
                return Err(OperationLedgerError::Corrupt);
            }
        }
        Ok(())
    }
    fn replace_legacy_extent_session(
        tx: &Transaction<'_>,
        before: &[u8; LEGACY_EXTENT_SESSION_RECORD_BYTES],
        after: &LegacyExtentSessionRecord,
    ) -> Result<()> {
        let encoded = after.encode()?;
        if tx.execute("UPDATE archive_v3_legacy_extent_sessions SET state=?,record=? WHERE session_id=? AND attempt_id=? AND record=?",params![after.state() as i64,encoded.as_slice(),after.session_id().as_bytes().as_slice(),after.attempt_id().as_bytes().as_slice(),before.as_slice()])?!=1{return Err(OperationLedgerError::Corrupt)}
        Ok(())
    }
    fn read_legacy_extent_object(
        connection: &Connection,
        session: LegacyExtentSessionId,
        attempt: LegacyExtentAttemptId,
        object: ObjectId,
    ) -> Result<Option<LegacyExtentObjectFacts>> {
        let row:Option<ShadowObjectRow>=connection.query_row("SELECT ordinal,object_id,object_role,root_seq,context_aad,object_key,ciphertext_hash FROM archive_v3_legacy_extent_objects WHERE session_id=? AND attempt_id=? AND object_id=?",params![session.as_bytes().as_slice(),attempt.as_bytes().as_slice(),object.as_bytes().as_slice()],read_shadow_object_row).optional()?;
        row.map(Self::legacy_facts_from_row).transpose()
    }
    fn read_legacy_extent_object_ordinal(
        connection: &Connection,
        session: LegacyExtentSessionId,
        attempt: LegacyExtentAttemptId,
        ordinal: u32,
    ) -> Result<Option<LegacyExtentObjectFacts>> {
        let row:Option<ShadowObjectRow>=connection.query_row("SELECT ordinal,object_id,object_role,root_seq,context_aad,object_key,ciphertext_hash FROM archive_v3_legacy_extent_objects WHERE session_id=? AND attempt_id=? AND ordinal=?",params![session.as_bytes().as_slice(),attempt.as_bytes().as_slice(),i64::from(ordinal)],read_shadow_object_row).optional()?;
        row.map(Self::legacy_facts_from_row).transpose()
    }
    fn read_legacy_extent_object_state(
        connection: &Connection,
        session: LegacyExtentSessionId,
        attempt: LegacyExtentAttemptId,
        object: ObjectId,
    ) -> Result<Option<LegacyExtentObjectState>> {
        connection.query_row("SELECT state FROM archive_v3_legacy_extent_objects WHERE session_id=? AND attempt_id=? AND object_id=?",params![session.as_bytes().as_slice(),attempt.as_bytes().as_slice(),object.as_bytes().as_slice()],|r|r.get::<_,i64>(0)).optional()?.map(LegacyExtentObjectState::decode).transpose()
    }
    fn legacy_facts_from_row(row: ShadowObjectRow) -> Result<LegacyExtentObjectFacts> {
        let (ordinal, object_id, role, root_seq, aad, key, hash) = row;
        let facts = LegacyExtentObjectFacts {
            ordinal: u32::try_from(ordinal).map_err(|_| OperationLedgerError::Corrupt)?,
            object_id: ObjectId::from_bytes(
                object_id
                    .try_into()
                    .map_err(|_| OperationLedgerError::Corrupt)?,
            ),
            object_role: decode_object_role(role)?,
            root_seq: root_seq.map(positive_u64).transpose()?,
            context_aad: Zeroizing::new(aad),
            object_key: key,
            ciphertext_hash: hash.try_into().map_err(|_| OperationLedgerError::Corrupt)?,
        };
        facts.validate_canonical()?;
        Ok(facts)
    }
}

#[cfg(test)]
mod tests {
    use std::{
        sync::{Arc, Barrier},
        thread,
        time::Duration,
    };

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
        let facts = shadow_root_facts(session, candidate);
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

    fn shadow_root_facts(
        session: &ShadowSessionRecord,
        candidate: ShadowCandidate,
    ) -> ShadowObjectFacts {
        let binding = session.binding();
        let context = ObjectContext::new(
            crate::archive_v3::ArchiveId::from_bytes(binding.archive_id()),
            crate::archive_v3::DatabaseEpoch::from_bytes(binding.database_epoch()),
            crate::archive_v3::KeyEpoch::from_bytes(binding.registry_epoch()),
            ObjectRole::RootV3,
            LogicalLocation::Root {
                root_seq: candidate.root_seq(),
            },
            ObjectId::from_bytes(candidate.object_id()),
            Some(crate::archive_v3::ParentReference {
                object_id: ObjectId::from_bytes(binding.base_root_object_id()),
                envelope_hash: binding.base_root_ciphertext_hash(),
            }),
        )
        .unwrap();
        ShadowObjectFacts {
            ordinal: 0,
            object_id: context.object_id(),
            object_role: context.role(),
            root_seq: Some(candidate.root_seq()),
            context_aad: Zeroizing::new(context.canonical_aad()),
            object_key: context.object_key().as_str().to_owned(),
            ciphertext_hash: candidate.ciphertext_hash(),
        }
    }

    fn shadow_manifest_facts(session: &ShadowSessionRecord, ordinal: u32) -> ShadowObjectFacts {
        let mut object = [0u8; 16];
        object[..8].copy_from_slice(&u64::from(ordinal).to_be_bytes());
        object[15] = 1;
        let binding = session.binding();
        let context = ObjectContext::new(
            crate::archive_v3::ArchiveId::from_bytes(binding.archive_id()),
            crate::archive_v3::DatabaseEpoch::from_bytes(binding.database_epoch()),
            crate::archive_v3::KeyEpoch::from_bytes(binding.registry_epoch()),
            ObjectRole::CheckpointManifestV3,
            LogicalLocation::CheckpointManifest {
                checkpoint_id: ObjectId::from_bytes([0x7a; 16]),
                level: 0,
                range_start: ordinal,
                range_end: ordinal + 1,
            },
            ObjectId::from_bytes(object),
            None,
        )
        .unwrap();
        ShadowObjectFacts {
            ordinal,
            object_id: context.object_id(),
            object_role: context.role(),
            root_seq: None,
            context_aad: Zeroizing::new(context.canonical_aad()),
            object_key: context.object_key().as_str().to_owned(),
            ciphertext_hash: [ordinal as u8; 32],
        }
    }

    fn hex_id(value: [u8; 16]) -> String {
        value.iter().map(|byte| format!("{byte:02x}")).collect()
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

    fn create_v1_shadow_object_fixture(connection: &Connection) {
        connection
            .execute_batch(
                "DROP INDEX archive_v3_shadow_objects_exact_attempt;
                 DROP TABLE archive_v3_shadow_objects;
                 UPDATE archive_v3_shadow_object_schema SET version = 1 WHERE singleton = 1;
                 CREATE TABLE archive_v3_shadow_objects (
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
                 CREATE INDEX archive_v3_shadow_objects_exact_attempt
                    ON archive_v3_shadow_objects(session_id, attempt_id, state);",
            )
            .unwrap();
    }

    #[test]
    fn migrates_v1_shadow_inventory_transactionally_and_recreates_the_index() {
        let temporary = tempfile::NamedTempFile::new().unwrap();
        let session = shadow_session(0x3e, 0x4f);
        let facts;
        {
            let mut connection = Connection::open(temporary.path()).unwrap();
            OperationLedger::initialize(&connection).unwrap();
            OperationLedger::prepare_shadow_session(&mut connection, &session).unwrap();
            create_v1_shadow_object_fixture(&connection);
            facts = shadow_root_facts(&session, shadow_candidate());
            connection
                .execute(
                    "INSERT INTO archive_v3_shadow_objects (
                        session_id, attempt_id, object_id, object_role, root_seq,
                        context_aad, ciphertext_hash, state
                     ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                    params![
                        session.session_id().as_bytes().as_slice(),
                        session.attempt_id().as_bytes().as_slice(),
                        facts.object_id.as_bytes().as_slice(),
                        facts.object_role as i64,
                        facts.root_seq.map(|value| value as i64),
                        facts.context_aad.as_slice(),
                        facts.ciphertext_hash.as_slice(),
                        ShadowObjectState::Materialized as i64,
                    ],
                )
                .unwrap();
            connection
                .execute("DELETE FROM archive_v3_shadow_object_schema", [])
                .unwrap();
            OperationLedger::initialize(&connection).unwrap();
            assert_eq!(
                connection
                    .query_row(
                        "SELECT version FROM archive_v3_shadow_object_schema WHERE singleton = 1",
                        [],
                        |row| row.get::<_, i64>(0),
                    )
                    .unwrap(),
                2
            );
            assert!(connection
                .query_row(
                    "SELECT 1 FROM sqlite_master WHERE type = 'index'
                     AND name = 'archive_v3_shadow_objects_exact_attempt'",
                    [],
                    |_| Ok(()),
                )
                .optional()
                .unwrap()
                .is_some());
        }
        let connection = Connection::open(temporary.path()).unwrap();
        OperationLedger::initialize(&connection).unwrap();
        let page = OperationLedger::load_exact_shadow_object_page(
            &connection,
            session.session_id(),
            session.attempt_id(),
            session.binding(),
            None,
        )
        .unwrap();
        assert_eq!(page.entries().len(), 1);
        assert_eq!(page.entries()[0].facts(), &facts);
        assert_eq!(page.entries()[0].state(), ShadowObjectState::Materialized);
    }

    #[test]
    fn v2_inventory_requires_exact_descriptor_and_exactly_one_version_row() {
        for version_sql in [
            "DELETE FROM archive_v3_shadow_object_schema",
            "UPDATE archive_v3_shadow_object_schema SET version = 1",
        ] {
            let connection = setup();
            connection.execute_batch(version_sql).unwrap();
            assert!(matches!(
                OperationLedger::initialize(&connection),
                Err(OperationLedgerError::Corrupt)
            ));
        }
        let connection = setup();
        connection
            .execute_batch(
                "DROP INDEX archive_v3_shadow_objects_exact_attempt;
                 DROP TABLE archive_v3_shadow_objects;
                 CREATE TABLE archive_v3_shadow_objects (
                    session_id BLOB NOT NULL, attempt_id BLOB NOT NULL, ordinal INTEGER NOT NULL,
                    object_id BLOB NOT NULL, object_role INTEGER NOT NULL, root_seq INTEGER,
                    context_aad BLOB NOT NULL, object_key TEXT NOT NULL,
                    ciphertext_hash BLOB NOT NULL, state INTEGER NOT NULL,
                    PRIMARY KEY(session_id, attempt_id, ordinal),
                    UNIQUE(session_id, attempt_id, object_id)
                 );
                 CREATE INDEX archive_v3_shadow_objects_exact_attempt
                    ON archive_v3_shadow_objects(session_id, attempt_id, state);",
            )
            .unwrap();
        assert!(matches!(
            OperationLedger::initialize(&connection),
            Err(OperationLedgerError::Corrupt)
        ));
        assert_eq!(
            connection
                .query_row(
                    "SELECT COUNT(*) FROM archive_v3_shadow_objects",
                    [],
                    |row| { row.get::<_, i64>(0) }
                )
                .unwrap(),
            0
        );
        let connection = setup();
        connection
            .execute_batch(
                "DROP INDEX archive_v3_shadow_objects_exact_attempt;
                 DROP TABLE archive_v3_shadow_objects;",
            )
            .unwrap();
        assert!(matches!(
            OperationLedger::initialize(&connection),
            Err(OperationLedgerError::Corrupt)
        ));
    }

    #[test]
    fn weakened_v1_inventory_descriptor_fails_before_migration() {
        let connection = setup();
        create_v1_shadow_object_fixture(&connection);
        connection
            .execute_batch(
                "DROP INDEX archive_v3_shadow_objects_exact_attempt;
                 ALTER TABLE archive_v3_shadow_objects RENAME TO weak_shadow_objects;
                 CREATE TABLE archive_v3_shadow_objects (
                    session_id BLOB NOT NULL, attempt_id BLOB NOT NULL, object_id BLOB NOT NULL,
                    object_role INTEGER NOT NULL, root_seq INTEGER, context_aad BLOB NOT NULL,
                    ciphertext_hash BLOB NOT NULL, state INTEGER NOT NULL,
                    PRIMARY KEY(session_id, attempt_id, object_id)
                 );
                 DROP TABLE weak_shadow_objects;
                 CREATE INDEX archive_v3_shadow_objects_exact_attempt
                    ON archive_v3_shadow_objects(session_id, attempt_id, state);",
            )
            .unwrap();
        assert!(matches!(
            OperationLedger::initialize(&connection),
            Err(OperationLedgerError::Corrupt)
        ));
        assert_eq!(
            connection
                .query_row(
                    "SELECT COUNT(*) FROM archive_v3_shadow_objects",
                    [],
                    |row| { row.get::<_, i64>(0) }
                )
                .unwrap(),
            0
        );
    }

    fn assert_v1_migration_rollback(connection: &Connection) {
        assert_eq!(shadow_object_columns_v1(), {
            let mut statement = connection
                .prepare("PRAGMA table_info(archive_v3_shadow_objects)")
                .unwrap();
            statement
                .query_map([], |row| row.get::<_, String>(1))
                .unwrap()
                .map(|row| row.unwrap())
                .collect()
        });
        assert!(connection
            .query_row(
                "SELECT 1 FROM sqlite_master WHERE type = 'index'
                 AND name = 'archive_v3_shadow_objects_exact_attempt'",
                [],
                |_| Ok(()),
            )
            .optional()
            .unwrap()
            .is_some());
        assert_eq!(
            connection
                .query_row(
                    "SELECT COUNT(*) FROM archive_v3_shadow_objects",
                    [],
                    |row| { row.get::<_, i64>(0) }
                )
                .unwrap(),
            1
        );
        assert_eq!(
            connection
                .query_row(
                    "SELECT version FROM archive_v3_shadow_object_schema WHERE singleton = 1",
                    [],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            1
        );
    }

    #[test]
    fn malformed_v1_aad_rolls_back_inventory_migration_without_advancing_version() {
        let mut connection = setup();
        let session = shadow_session(0x3f, 0x50);
        OperationLedger::prepare_shadow_session(&mut connection, &session).unwrap();
        create_v1_shadow_object_fixture(&connection);
        let facts = shadow_root_facts(&session, shadow_candidate());
        connection
            .execute(
                "INSERT INTO archive_v3_shadow_objects (
                    session_id, attempt_id, object_id, object_role, root_seq,
                    context_aad, ciphertext_hash, state
                 ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                params![
                    session.session_id().as_bytes().as_slice(),
                    session.attempt_id().as_bytes().as_slice(),
                    facts.object_id.as_bytes().as_slice(),
                    facts.object_role as i64,
                    facts.root_seq.map(|value| value as i64),
                    b"not canonical aad".as_slice(),
                    facts.ciphertext_hash.as_slice(),
                    ShadowObjectState::Reserved as i64,
                ],
            )
            .unwrap();
        assert!(matches!(
            OperationLedger::initialize(&connection),
            Err(OperationLedgerError::Corrupt)
        ));
        assert_v1_migration_rollback(&connection);
    }

    #[test]
    fn missing_or_mismatched_v1_session_rolls_back_inventory_migration() {
        for prepared in [false, true] {
            let mut connection = setup();
            let session = shadow_session(0x40, 0x51);
            if prepared {
                OperationLedger::prepare_shadow_session(&mut connection, &session).unwrap();
            }
            create_v1_shadow_object_fixture(&connection);
            let facts = if prepared {
                let mismatched = ShadowSessionRecord::prepared(
                    session.session_id(),
                    session.attempt_id(),
                    ShadowSessionBinding::new(
                        [0xa2; 16],
                        [0xb2; 16],
                        0,
                        [0xc3; 16],
                        1,
                        [0xd4; 16],
                        [0xe5; 32],
                        11,
                        [0xf6; 16],
                        [0x17; 32],
                        99,
                        *OperationId::from_bytes([0x40; 16]).as_bytes(),
                        *fingerprint(0x51).as_bytes(),
                        1,
                        3,
                        1,
                        4,
                    )
                    .unwrap(),
                )
                .unwrap();
                shadow_root_facts(&mismatched, shadow_candidate())
            } else {
                shadow_root_facts(&session, shadow_candidate())
            };
            connection
                .execute(
                    "INSERT INTO archive_v3_shadow_objects (
                        session_id, attempt_id, object_id, object_role, root_seq,
                        context_aad, ciphertext_hash, state
                     ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                    params![
                        session.session_id().as_bytes().as_slice(),
                        session.attempt_id().as_bytes().as_slice(),
                        facts.object_id.as_bytes().as_slice(),
                        facts.object_role as i64,
                        facts.root_seq.map(|value| value as i64),
                        facts.context_aad.as_slice(),
                        facts.ciphertext_hash.as_slice(),
                        ShadowObjectState::Reserved as i64,
                    ],
                )
                .unwrap();
            assert!(matches!(
                OperationLedger::initialize(&connection),
                Err(OperationLedgerError::Corrupt)
            ));
            assert_v1_migration_rollback(&connection);
        }
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
            let mut connection = Connection::open(temporary.path()).unwrap();
            OperationLedger::initialize(&connection).unwrap();
            assert_eq!(
                OperationLedger::prepare_shadow_session(&mut connection, &session).unwrap(),
                RecordOutcome::Recorded
            );
        }
        let mut connection = Connection::open(temporary.path()).unwrap();
        OperationLedger::initialize(&connection).unwrap();
        assert_eq!(
            OperationLedger::prepare_shadow_session(&mut connection, &session).unwrap(),
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
            OperationLedger::prepare_shadow_session(&mut connection, &conflicting_fingerprint),
            Err(OperationLedgerError::FingerprintConflict)
        ));

        let conflicting_binding = ShadowSessionRecord::prepared(
            session.session_id(),
            session.attempt_id(),
            shadow_binding(OperationId::from_bytes([0x41; 16]), fingerprint(0x51), 99),
        )
        .unwrap();
        assert!(matches!(
            OperationLedger::prepare_shadow_session(&mut connection, &conflicting_binding),
            Err(OperationLedgerError::ResultConflict)
        ));
    }

    #[test]
    fn concurrent_prepare_uses_an_immediate_transaction_and_rereads_exact_conflicts() {
        let temporary = tempfile::NamedTempFile::new().unwrap();
        let session = shadow_session(0x41, 0x61);
        let competing = ShadowSessionRecord::prepared(
            session.session_id(),
            ShadowAttemptId::from_bytes([0x79; 16]),
            session.binding(),
        )
        .unwrap();
        let connection = Connection::open(temporary.path()).unwrap();
        OperationLedger::initialize(&connection).unwrap();
        drop(connection);
        let barrier = Arc::new(Barrier::new(2));
        let first_path = temporary.path().to_owned();
        let first_barrier = Arc::clone(&barrier);
        let first = thread::spawn(move || {
            let mut connection = Connection::open(first_path).unwrap();
            connection.busy_timeout(Duration::from_secs(2)).unwrap();
            first_barrier.wait();
            OperationLedger::prepare_shadow_session(&mut connection, &session)
        });
        let second_path = temporary.path().to_owned();
        let second = thread::spawn(move || {
            let mut connection = Connection::open(second_path).unwrap();
            connection.busy_timeout(Duration::from_secs(2)).unwrap();
            barrier.wait();
            OperationLedger::prepare_shadow_session(&mut connection, &competing)
        });
        let first = first.join().unwrap();
        let second = second.join().unwrap();
        assert!(matches!(
            (&first, &second),
            (
                Ok(RecordOutcome::Recorded),
                Err(OperationLedgerError::ResultConflict)
            ) | (
                Err(OperationLedgerError::ResultConflict),
                Ok(RecordOutcome::Recorded)
            )
        ));
    }

    #[test]
    fn concurrent_exact_prepare_replays_only_after_the_immediate_transaction_reread() {
        let temporary = tempfile::NamedTempFile::new().unwrap();
        let session = shadow_session(0x42, 0x62);
        let connection = Connection::open(temporary.path()).unwrap();
        OperationLedger::initialize(&connection).unwrap();
        drop(connection);
        let barrier = Arc::new(Barrier::new(2));
        let first_path = temporary.path().to_owned();
        let first_barrier = Arc::clone(&barrier);
        let first_session = session.clone();
        let first = thread::spawn(move || {
            let mut connection = Connection::open(first_path).unwrap();
            connection.busy_timeout(Duration::from_secs(2)).unwrap();
            first_barrier.wait();
            OperationLedger::prepare_shadow_session(&mut connection, &first_session)
        });
        let second_path = temporary.path().to_owned();
        let second = thread::spawn(move || {
            let mut connection = Connection::open(second_path).unwrap();
            connection.busy_timeout(Duration::from_secs(2)).unwrap();
            barrier.wait();
            OperationLedger::prepare_shadow_session(&mut connection, &session)
        });
        let first = first.join().unwrap();
        let second = second.join().unwrap();
        assert!(matches!(
            (&first, &second),
            (
                Ok(RecordOutcome::Recorded),
                Ok(RecordOutcome::AlreadyRecorded)
            ) | (
                Ok(RecordOutcome::AlreadyRecorded),
                Ok(RecordOutcome::Recorded)
            )
        ));
    }

    #[test]
    fn exact_candidate_survives_restart_and_cannot_be_replaced() {
        let temporary = tempfile::NamedTempFile::new().unwrap();
        let session = shadow_session(0x42, 0x53);
        {
            let mut connection = Connection::open(temporary.path()).unwrap();
            OperationLedger::initialize(&connection).unwrap();
            OperationLedger::prepare_shadow_session(&mut connection, &session).unwrap();
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
        let root_facts = shadow_root_facts(&session, shadow_candidate());
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
        OperationLedger::prepare_shadow_session(&mut connection, &session).unwrap();
        let facts = shadow_root_facts(&session, shadow_candidate());
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
        OperationLedger::prepare_shadow_session(&mut connection, &session).unwrap();
        let facts = shadow_root_facts(&session, shadow_candidate());
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
        OperationLedger::prepare_shadow_session(&mut connection, &retained).unwrap();
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
            Some(ShadowObjectState::Materialized)
        );
        OperationLedger::transition_shadow_session(
            &mut connection,
            retained.session_id(),
            retained.attempt_id(),
            retained.binding(),
            ShadowSessionState::Superseded,
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
            Some(ShadowObjectState::OrphanPendingGrace)
        );

        let orphan = shadow_session(0x49, 0x5a);
        OperationLedger::prepare_shadow_session(&mut connection, &orphan).unwrap();
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
        OperationLedger::prepare_shadow_session(&mut connection, &session).unwrap();
        let transaction = connection.transaction().unwrap();
        for value in 0..MAX_SHADOW_OBJECTS_PER_ATTEMPT {
            let facts = shadow_manifest_facts(&session, value as u32);
            transaction
                .execute(
                    "INSERT INTO archive_v3_shadow_objects (
                        session_id, attempt_id, ordinal, object_id, object_role, root_seq,
                        context_aad, object_key, ciphertext_hash, state
                     ) VALUES (?, ?, ?, ?, ?, NULL, ?, ?, ?, ?)",
                    params![
                        session.session_id().as_bytes().as_slice(),
                        session.attempt_id().as_bytes().as_slice(),
                        value as i64,
                        facts.object_id.as_bytes().as_slice(),
                        facts.object_role as i64,
                        facts.context_aad.as_slice(),
                        facts.object_key.as_str(),
                        facts.ciphertext_hash.as_slice(),
                        ShadowObjectState::Reserved as i64,
                    ],
                )
                .unwrap();
        }
        transaction.commit().unwrap();
        let facts = shadow_manifest_facts(&session, MAX_SHADOW_OBJECTS_PER_ATTEMPT as u32);
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
        let mut after = None;
        let mut traversed = 0usize;
        let mut pages = 0usize;
        loop {
            let page = OperationLedger::load_exact_shadow_object_page(
                &connection,
                session.session_id(),
                session.attempt_id(),
                session.binding(),
                after,
            )
            .unwrap();
            traversed += page.entries().len();
            pages += 1;
            match page.next_ordinal() {
                Some(next) => {
                    assert!(after.is_none_or(|previous| next > previous));
                    after = Some(next);
                }
                None => break,
            }
        }
        assert_eq!(traversed, MAX_SHADOW_OBJECTS_PER_ATTEMPT);
        assert_eq!(pages, 129);
    }

    #[test]
    fn exact_inventory_pages_255_256_and_257_without_repeating_a_cursor() {
        for count in [255usize, 256, 257] {
            let mut connection = setup();
            let session = shadow_session(0x5d, 0x6e);
            OperationLedger::prepare_shadow_session(&mut connection, &session).unwrap();
            for ordinal in 0..count {
                let facts = shadow_manifest_facts(&session, ordinal as u32);
                OperationLedger::reserve_shadow_object(
                    &mut connection,
                    session.session_id(),
                    session.attempt_id(),
                    session.binding(),
                    &facts,
                )
                .unwrap();
            }
            let first = OperationLedger::load_exact_shadow_object_page(
                &connection,
                session.session_id(),
                session.attempt_id(),
                session.binding(),
                None,
            )
            .unwrap();
            assert_eq!(first.entries().len(), count.min(MAX_SHADOW_OBJECTS_PAGE));
            if count == 257 {
                assert_eq!(first.next_ordinal(), Some(255));
                let second = OperationLedger::load_exact_shadow_object_page(
                    &connection,
                    session.session_id(),
                    session.attempt_id(),
                    session.binding(),
                    first.next_ordinal(),
                )
                .unwrap();
                assert_eq!(second.entries().len(), 1);
                assert_eq!(second.next_ordinal(), None);
            } else {
                assert_eq!(first.next_ordinal(), None);
            }
        }
    }

    #[test]
    fn exact_inventory_rejects_cross_archive_epoch_object_and_role_keys() {
        let mut connection = setup();
        let session = shadow_session(0x5e, 0x6f);
        OperationLedger::prepare_shadow_session(&mut connection, &session).unwrap();
        let facts = materialized_root(&mut connection, &session);
        let correct = facts.object_key.clone();
        let replacements = [
            "not-a-key".to_owned(),
            correct.replacen(&"a1".repeat(16), &"c3".repeat(16), 1),
            correct.replacen(&"b2".repeat(16), &"d4".repeat(16), 1),
            correct.replacen(&hex_id(*facts.object_id.as_bytes()), &hex_id([0xee; 16]), 1),
            correct.replacen("root-candidates", "checkpoints", 1),
        ];
        for replacement in replacements {
            connection
                .execute(
                    "UPDATE archive_v3_shadow_objects SET object_key = ?
                 WHERE session_id = ? AND attempt_id = ? AND ordinal = 0",
                    params![
                        replacement,
                        session.session_id().as_bytes().as_slice(),
                        session.attempt_id().as_bytes().as_slice(),
                    ],
                )
                .unwrap();
            assert!(matches!(
                OperationLedger::load_exact_shadow_object_page(
                    &connection,
                    session.session_id(),
                    session.attempt_id(),
                    session.binding(),
                    None,
                ),
                Err(OperationLedgerError::Corrupt)
            ));
            connection
                .execute(
                    "UPDATE archive_v3_shadow_objects SET object_key = ?
                 WHERE session_id = ? AND attempt_id = ? AND ordinal = 0",
                    params![
                        correct.as_str(),
                        session.session_id().as_bytes().as_slice(),
                        session.attempt_id().as_bytes().as_slice(),
                    ],
                )
                .unwrap();
        }
    }

    #[test]
    fn exact_inventory_rejects_root_parent_or_sequence_outside_its_binding() {
        let mut connection = setup();
        let session = shadow_session(0x5f, 0x70);
        OperationLedger::prepare_shadow_session(&mut connection, &session).unwrap();
        let facts = materialized_root(&mut connection, &session);
        let binding = session.binding();
        let altered_parent = ObjectContext::new(
            crate::archive_v3::ArchiveId::from_bytes(binding.archive_id()),
            crate::archive_v3::DatabaseEpoch::from_bytes(binding.database_epoch()),
            crate::archive_v3::KeyEpoch::from_bytes(binding.registry_epoch()),
            ObjectRole::RootV3,
            LogicalLocation::Root {
                root_seq: shadow_candidate().root_seq(),
            },
            facts.object_id,
            Some(crate::archive_v3::ParentReference {
                object_id: ObjectId::from_bytes([0xaa; 16]),
                envelope_hash: binding.base_root_ciphertext_hash(),
            }),
        )
        .unwrap();
        connection
            .execute(
                "UPDATE archive_v3_shadow_objects SET context_aad = ?
                 WHERE session_id = ? AND attempt_id = ? AND ordinal = 0",
                params![
                    altered_parent.canonical_aad(),
                    session.session_id().as_bytes().as_slice(),
                    session.attempt_id().as_bytes().as_slice(),
                ],
            )
            .unwrap();
        assert!(matches!(
            OperationLedger::load_exact_shadow_object_page(
                &connection,
                session.session_id(),
                session.attempt_id(),
                binding,
                None,
            ),
            Err(OperationLedgerError::Corrupt)
        ));
        let altered_sequence = ObjectContext::new(
            crate::archive_v3::ArchiveId::from_bytes(binding.archive_id()),
            crate::archive_v3::DatabaseEpoch::from_bytes(binding.database_epoch()),
            crate::archive_v3::KeyEpoch::from_bytes(binding.registry_epoch()),
            ObjectRole::RootV3,
            LogicalLocation::Root { root_seq: 13 },
            facts.object_id,
            Some(crate::archive_v3::ParentReference {
                object_id: ObjectId::from_bytes(binding.base_root_object_id()),
                envelope_hash: binding.base_root_ciphertext_hash(),
            }),
        )
        .unwrap();
        connection
            .execute(
                "UPDATE archive_v3_shadow_objects
                 SET root_seq = ?, context_aad = ?, object_key = ?
                 WHERE session_id = ? AND attempt_id = ? AND ordinal = 0",
                params![
                    13i64,
                    altered_sequence.canonical_aad(),
                    altered_sequence.object_key().as_str(),
                    session.session_id().as_bytes().as_slice(),
                    session.attempt_id().as_bytes().as_slice(),
                ],
            )
            .unwrap();
        assert!(matches!(
            OperationLedger::load_exact_shadow_object_page(
                &connection,
                session.session_id(),
                session.attempt_id(),
                binding,
                None,
            ),
            Err(OperationLedgerError::Corrupt)
        ));
    }

    #[test]
    fn terminal_attempt_is_retained_before_a_new_attempt_for_the_same_operation() {
        let mut connection = setup();
        let first = shadow_session(0x45, 0x56);
        OperationLedger::prepare_shadow_session(&mut connection, &first).unwrap();
        let second = ShadowSessionRecord::prepared(
            first.session_id(),
            ShadowAttemptId::from_bytes([0x77; 16]),
            first.binding(),
        )
        .unwrap();
        assert!(matches!(
            OperationLedger::prepare_shadow_session(&mut connection, &second),
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
            OperationLedger::prepare_shadow_session(&mut connection, &second).unwrap(),
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
        OperationLedger::prepare_shadow_session(&mut connection, &session).unwrap();
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
        let mut connection = setup();
        let session = shadow_session(0x44, 0x55);
        OperationLedger::prepare_shadow_session(&mut connection, &session).unwrap();
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

    fn legacy_binding(id: u8) -> LegacyExtentSessionBinding {
        LegacyExtentSessionBinding::fixture_for_test(
            [id; 16],
            [id.wrapping_add(1); 16],
            [id.wrapping_add(2); 16],
            [id.wrapping_add(7); 16],
            [id.wrapping_add(8); 32],
        )
    }

    fn legacy_session(id: u8) -> LegacyExtentSessionRecord {
        let binding = legacy_binding(id);
        LegacyExtentSessionRecord::prepared(
            LegacyExtentSessionId::for_binding(binding).unwrap(),
            LegacyExtentAttemptId::from_bytes_for_test([id.wrapping_add(11); 16]),
            binding,
        )
        .unwrap()
    }

    fn legacy_facts(
        session: &LegacyExtentSessionRecord,
        ordinal: u32,
        role: ObjectRole,
    ) -> LegacyExtentObjectFacts {
        let binding = session.binding();
        let mut object_bytes = [0x31; 16];
        object_bytes[..4].copy_from_slice(&ordinal.to_be_bytes());
        let object = ObjectId::from_bytes(object_bytes);
        let (location, root_seq) = match role {
            ObjectRole::ExtentV3 => (
                LogicalLocation::Extent {
                    extent_no: u64::from(ordinal),
                    byte_len: crate::archive_v3::SQLITE_PAGE_SIZE,
                },
                None,
            ),
            ObjectRole::MerkleNodeV3 => (
                LogicalLocation::MerkleNode {
                    level: 0,
                    range_start: 0,
                    range_end: 1,
                },
                None,
            ),
            ObjectRole::RootV3 => (
                LogicalLocation::Root {
                    root_seq: binding.base_root_seq() + 1,
                },
                Some(binding.base_root_seq() + 1),
            ),
            _ => unreachable!(),
        };
        let context = ObjectContext::new(
            crate::archive_v3::ArchiveId::from_bytes(binding.archive_id()),
            crate::archive_v3::DatabaseEpoch::from_bytes(binding.database_epoch()),
            crate::archive_v3::KeyEpoch::from_bytes(binding.key_epoch()),
            role,
            location,
            object,
            (role == ObjectRole::RootV3).then_some(crate::archive_v3::ParentReference {
                object_id: ObjectId::from_bytes(binding.base_root_object_id()),
                envelope_hash: binding.base_root_ciphertext_hash(),
            }),
        )
        .unwrap();
        let mut ciphertext_hash = [0x51; 32];
        ciphertext_hash[..4].copy_from_slice(&ordinal.to_be_bytes());
        LegacyExtentObjectFacts {
            ordinal,
            object_id: object,
            object_role: role,
            root_seq,
            context_aad: Zeroizing::new(context.canonical_aad()),
            object_key: context.object_key().as_str().to_owned(),
            ciphertext_hash,
        }
    }

    fn legacy_root_admission(
        session: &LegacyExtentSessionRecord,
        facts: &LegacyExtentObjectFacts,
    ) -> LegacyExtentRootAdmission {
        let binding = session.binding();
        let context = ObjectContext::decode_canonical_aad(facts.context_aad.as_slice()).unwrap();
        let root = crate::archive_v3::ArchiveRoot {
            root_seq: binding.base_root_seq() + 1,
            parent: Some(crate::archive_v3::ParentReference {
                object_id: ObjectId::from_bytes(binding.base_root_object_id()),
                envelope_hash: binding.base_root_ciphertext_hash(),
            }),
            database_epoch: crate::archive_v3::DatabaseEpoch::from_bytes(binding.database_epoch()),
            key_epoch: crate::archive_v3::KeyEpoch::from_bytes(binding.key_epoch()),
            owner_fencing_epoch: binding.owner_fence(),
            sqlite_page_size: crate::archive_v3::SQLITE_PAGE_SIZE,
            logical_file_length: binding.plaintext_len(),
            user_schema_version: 1,
            storage_format_version: crate::archive_v3::ARCHIVE_FORMAT_VERSION,
            wal_generation: 0,
            wal_segment_count: 0,
            checkpoint_root: None,
            extent_tree_root: Some(crate::archive_v3::ImmutableReference {
                object_id: ObjectId::from_bytes([0x71; 16]),
                envelope_hash: [0x72; 32],
            }),
            wal_chain_root: None,
        };
        LegacyExtentRootAdmission::from_validated_root_for_test(
            &root,
            &context,
            facts.ciphertext_hash,
            binding,
        )
        .unwrap()
    }

    fn wrong_parent_root_aad(facts: &LegacyExtentObjectFacts) -> Vec<u8> {
        let context = ObjectContext::decode_canonical_aad(facts.context_aad.as_slice()).unwrap();
        ObjectContext::new(
            context.archive_id(),
            context.database_epoch(),
            context.key_epoch(),
            context.role(),
            context.location().clone(),
            context.object_id(),
            Some(crate::archive_v3::ParentReference {
                object_id: ObjectId::from_bytes([0x73; 16]),
                envelope_hash: [0x74; 32],
            }),
        )
        .unwrap()
        .canonical_aad()
    }

    fn unexpected_parent_aad(facts: &LegacyExtentObjectFacts) -> Vec<u8> {
        let context = ObjectContext::decode_canonical_aad(facts.context_aad.as_slice()).unwrap();
        ObjectContext::new(
            context.archive_id(),
            context.database_epoch(),
            context.key_epoch(),
            context.role(),
            context.location().clone(),
            context.object_id(),
            Some(crate::archive_v3::ParentReference {
                object_id: ObjectId::from_bytes([0x75; 16]),
                envelope_hash: [0x76; 32],
            }),
        )
        .unwrap()
        .canonical_aad()
    }

    #[test]
    fn legacy_extent_ledger_is_idempotent_contiguous_and_root_final() {
        let mut connection = setup();
        let session = legacy_session(21);
        assert_eq!(
            OperationLedger::prepare_legacy_extent_session(&mut connection, &session).unwrap(),
            RecordOutcome::Recorded
        );
        assert_eq!(
            OperationLedger::prepare_legacy_extent_session(&mut connection, &session).unwrap(),
            RecordOutcome::AlreadyRecorded
        );
        let gap = legacy_facts(&session, 1, ObjectRole::ExtentV3);
        assert!(OperationLedger::reserve_legacy_extent_object(
            &mut connection,
            session.session_id(),
            session.attempt_id(),
            session.binding(),
            &gap
        )
        .is_err());
        let extent = legacy_facts(&session, 0, ObjectRole::ExtentV3);
        assert_eq!(
            OperationLedger::reserve_legacy_extent_object(
                &mut connection,
                session.session_id(),
                session.attempt_id(),
                session.binding(),
                &extent
            )
            .unwrap(),
            RecordOutcome::Recorded
        );
        assert_eq!(
            OperationLedger::reserve_legacy_extent_object(
                &mut connection,
                session.session_id(),
                session.attempt_id(),
                session.binding(),
                &extent
            )
            .unwrap(),
            RecordOutcome::AlreadyRecorded
        );
        let root = legacy_facts(&session, 1, ObjectRole::RootV3);
        assert_eq!(
            OperationLedger::reserve_legacy_extent_object(
                &mut connection,
                session.session_id(),
                session.attempt_id(),
                session.binding(),
                &root
            )
            .unwrap(),
            RecordOutcome::Recorded
        );
        assert!(OperationLedger::reserve_legacy_extent_object(
            &mut connection,
            session.session_id(),
            session.attempt_id(),
            session.binding(),
            &legacy_facts(&session, 2, ObjectRole::MerkleNodeV3)
        )
        .is_err());
        assert_eq!(
            OperationLedger::mark_legacy_extent_object_materialized(
                &mut connection,
                session.session_id(),
                session.attempt_id(),
                session.binding(),
                &extent
            )
            .unwrap(),
            RecordOutcome::Recorded
        );
        assert_eq!(
            OperationLedger::mark_legacy_extent_object_materialized(
                &mut connection,
                session.session_id(),
                session.attempt_id(),
                session.binding(),
                &root
            )
            .unwrap(),
            RecordOutcome::Recorded
        );
        let candidate =
            LegacyExtentCandidate::new(1, *root.object_id.as_bytes(), root.ciphertext_hash)
                .unwrap();
        let admission = legacy_root_admission(&session, &root);
        let exact_extent_aad = extent.context_aad.clone();
        connection
            .execute(
                "UPDATE archive_v3_legacy_extent_objects SET context_aad = ?
                 WHERE session_id = ? AND attempt_id = ? AND ordinal = 0",
                params![
                    unexpected_parent_aad(&extent),
                    session.session_id().as_bytes().as_slice(),
                    session.attempt_id().as_bytes().as_slice()
                ],
            )
            .unwrap();
        assert!(OperationLedger::persist_legacy_extent_candidate(
            &mut connection,
            session.session_id(),
            session.attempt_id(),
            session.binding(),
            admission,
            &root,
        )
        .is_err());
        connection
            .execute(
                "UPDATE archive_v3_legacy_extent_objects SET context_aad = ?
                 WHERE session_id = ? AND attempt_id = ? AND ordinal = 0",
                params![
                    exact_extent_aad.as_slice(),
                    session.session_id().as_bytes().as_slice(),
                    session.attempt_id().as_bytes().as_slice()
                ],
            )
            .unwrap();
        let mut substituted_root = root.clone();
        substituted_root.context_aad = Zeroizing::new(wrong_parent_root_aad(&root));
        assert!(OperationLedger::persist_legacy_extent_candidate(
            &mut connection,
            session.session_id(),
            session.attempt_id(),
            session.binding(),
            admission,
            &substituted_root,
        )
        .is_err());
        assert_eq!(
            OperationLedger::persist_legacy_extent_candidate(
                &mut connection,
                session.session_id(),
                session.attempt_id(),
                session.binding(),
                admission,
                &root
            )
            .unwrap()
            .state(),
            LegacyExtentSessionState::CandidateReady
        );
        assert_eq!(
            OperationLedger::load_legacy_extent_session(
                &connection,
                session.session_id(),
                session.attempt_id()
            )
            .unwrap()
            .unwrap()
            .candidate(),
            Some(candidate)
        );
    }

    #[test]
    fn legacy_extent_session_identity_has_one_bounded_attempt_family() {
        let mut connection = setup();
        let binding = legacy_binding(31);
        let session_id = LegacyExtentSessionId::for_binding(binding).unwrap();
        let mut alternate = session_id.as_bytes();
        alternate[0] ^= 1;
        assert!(LegacyExtentSessionRecord::prepared(
            LegacyExtentSessionId::from_bytes_for_test(alternate),
            LegacyExtentAttemptId::from_bytes_for_test([1; 16]),
            binding,
        )
        .is_err());

        let first = LegacyExtentSessionRecord::prepared(
            session_id,
            LegacyExtentAttemptId::from_bytes_for_test([1; 16]),
            binding,
        )
        .unwrap();
        OperationLedger::prepare_legacy_extent_session(&mut connection, &first).unwrap();
        OperationLedger::orphan_legacy_extent_attempt(
            &mut connection,
            first.session_id(),
            first.attempt_id(),
            binding,
        )
        .unwrap();

        let conflicting_binding = LegacyExtentSessionBinding::fixture_for_test(
            binding.archive_id(),
            binding.database_epoch(),
            binding.key_epoch(),
            binding.operation_id(),
            [0xa5; 32],
        );
        assert_eq!(
            LegacyExtentSessionId::for_binding(conflicting_binding).unwrap(),
            session_id
        );
        let conflicting = LegacyExtentSessionRecord::prepared(
            session_id,
            LegacyExtentAttemptId::from_bytes_for_test([18; 16]),
            conflicting_binding,
        )
        .unwrap();
        assert!(matches!(
            OperationLedger::prepare_legacy_extent_session(&mut connection, &conflicting),
            Err(OperationLedgerError::FingerprintConflict)
        ));

        for attempt in 2..=MAX_LEGACY_EXTENT_SESSION_ATTEMPTS {
            let record = LegacyExtentSessionRecord::prepared(
                session_id,
                LegacyExtentAttemptId::from_bytes_for_test([u8::try_from(attempt).unwrap(); 16]),
                binding,
            )
            .unwrap();
            OperationLedger::prepare_legacy_extent_session(&mut connection, &record).unwrap();
            OperationLedger::orphan_legacy_extent_attempt(
                &mut connection,
                record.session_id(),
                record.attempt_id(),
                binding,
            )
            .unwrap();
        }
        let overflow = LegacyExtentSessionRecord::prepared(
            session_id,
            LegacyExtentAttemptId::from_bytes_for_test([17; 16]),
            binding,
        )
        .unwrap();
        assert!(matches!(
            OperationLedger::prepare_legacy_extent_session(&mut connection, &overflow),
            Err(OperationLedgerError::TooLarge(
                "legacy extent session attempts"
            ))
        ));
        let (families, attempts): (i64, i64) = connection
            .query_row(
                "SELECT COUNT(DISTINCT hex(session_id)), COUNT(*)
                 FROM archive_v3_legacy_extent_sessions",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(
            (families, attempts),
            (1, MAX_LEGACY_EXTENT_SESSION_ATTEMPTS)
        );
    }

    #[test]
    fn legacy_extent_candidate_rejects_reserved_root_and_denormalized_tamper() {
        let mut connection = setup();
        let session = legacy_session(41);
        OperationLedger::prepare_legacy_extent_session(&mut connection, &session).unwrap();
        let root = legacy_facts(&session, 0, ObjectRole::RootV3);
        OperationLedger::reserve_legacy_extent_object(
            &mut connection,
            session.session_id(),
            session.attempt_id(),
            session.binding(),
            &root,
        )
        .unwrap();
        let admission = legacy_root_admission(&session, &root);
        assert!(OperationLedger::persist_legacy_extent_candidate(
            &mut connection,
            session.session_id(),
            session.attempt_id(),
            session.binding(),
            admission,
            &root
        )
        .is_err());
        connection
            .execute(
                "UPDATE archive_v3_legacy_extent_sessions SET state = 2 WHERE session_id = ?",
                params![session.session_id().as_bytes().as_slice()],
            )
            .unwrap();
        assert!(OperationLedger::load_legacy_extent_session(
            &connection,
            session.session_id(),
            session.attempt_id()
        )
        .is_err());
    }

    #[test]
    fn legacy_extent_orphaning_scans_exact_rows_and_rejects_tamper() {
        let mut connection = setup();
        let session = legacy_session(61);
        OperationLedger::prepare_legacy_extent_session(&mut connection, &session).unwrap();
        let extent = legacy_facts(&session, 0, ObjectRole::ExtentV3);
        OperationLedger::reserve_legacy_extent_object(
            &mut connection,
            session.session_id(),
            session.attempt_id(),
            session.binding(),
            &extent,
        )
        .unwrap();
        let orphaned = OperationLedger::orphan_legacy_extent_attempt(
            &mut connection,
            session.session_id(),
            session.attempt_id(),
            session.binding(),
        )
        .unwrap();
        assert_eq!(
            orphaned.state(),
            LegacyExtentSessionState::OrphanPendingGrace
        );
        OperationLedger::orphan_legacy_extent_attempt(
            &mut connection,
            session.session_id(),
            session.attempt_id(),
            session.binding(),
        )
        .unwrap();
        connection
            .execute(
                "UPDATE archive_v3_legacy_extent_objects SET ciphertext_hash = zeroblob(32)
             WHERE session_id = ? AND attempt_id = ? AND ordinal = 0",
                params![
                    session.session_id().as_bytes().as_slice(),
                    session.attempt_id().as_bytes().as_slice()
                ],
            )
            .unwrap();
        assert!(OperationLedger::orphan_legacy_extent_attempt(
            &mut connection,
            session.session_id(),
            session.attempt_id(),
            session.binding(),
        )
        .is_err());

        for (id, mutation) in [
            (
                62,
                "UPDATE archive_v3_legacy_extent_objects SET ordinal = 1",
            ),
            (
                63,
                "UPDATE archive_v3_legacy_extent_objects SET context_aad = zeroblob(32)",
            ),
            (
                64,
                "UPDATE archive_v3_legacy_extent_objects SET object_key = 'archive/v3/bad'",
            ),
            (
                65,
                "UPDATE archive_v3_legacy_extent_objects SET ciphertext_hash = zeroblob(32)",
            ),
            (66, "UPDATE archive_v3_legacy_extent_objects SET state = 3"),
        ] {
            let mut connection = setup();
            let session = legacy_session(id);
            OperationLedger::prepare_legacy_extent_session(&mut connection, &session).unwrap();
            let extent = legacy_facts(&session, 0, ObjectRole::ExtentV3);
            OperationLedger::reserve_legacy_extent_object(
                &mut connection,
                session.session_id(),
                session.attempt_id(),
                session.binding(),
                &extent,
            )
            .unwrap();
            connection.execute(mutation, []).unwrap();
            assert!(OperationLedger::orphan_legacy_extent_attempt(
                &mut connection,
                session.session_id(),
                session.attempt_id(),
                session.binding(),
            )
            .is_err());
        }

        let mut connection = setup();
        let session = legacy_session(67);
        OperationLedger::prepare_legacy_extent_session(&mut connection, &session).unwrap();
        let extent = legacy_facts(&session, 0, ObjectRole::ExtentV3);
        OperationLedger::reserve_legacy_extent_object(
            &mut connection,
            session.session_id(),
            session.attempt_id(),
            session.binding(),
            &extent,
        )
        .unwrap();
        connection
            .execute(
                "UPDATE archive_v3_legacy_extent_objects SET context_aad = ?",
                params![unexpected_parent_aad(&extent)],
            )
            .unwrap();
        assert!(OperationLedger::orphan_legacy_extent_attempt(
            &mut connection,
            session.session_id(),
            session.attempt_id(),
            session.binding(),
        )
        .is_err());
    }

    #[test]
    fn legacy_extent_orphan_proof_rejects_deletion_and_accepts_exact_empty_retry() {
        let mut connection = setup();
        let empty = legacy_session(68);
        OperationLedger::prepare_legacy_extent_session(&mut connection, &empty).unwrap();
        OperationLedger::orphan_legacy_extent_attempt(
            &mut connection,
            empty.session_id(),
            empty.attempt_id(),
            empty.binding(),
        )
        .unwrap();
        OperationLedger::orphan_legacy_extent_attempt(
            &mut connection,
            empty.session_id(),
            empty.attempt_id(),
            empty.binding(),
        )
        .unwrap();

        for (id, object_count, deleted_ordinal) in [(69, 1, 0), (70, 2, 1)] {
            let mut connection = setup();
            let session = legacy_session(id);
            OperationLedger::prepare_legacy_extent_session(&mut connection, &session).unwrap();
            for ordinal in 0..object_count {
                let facts = legacy_facts(&session, ordinal, ObjectRole::ExtentV3);
                OperationLedger::reserve_legacy_extent_object(
                    &mut connection,
                    session.session_id(),
                    session.attempt_id(),
                    session.binding(),
                    &facts,
                )
                .unwrap();
            }
            OperationLedger::orphan_legacy_extent_attempt(
                &mut connection,
                session.session_id(),
                session.attempt_id(),
                session.binding(),
            )
            .unwrap();
            connection
                .execute(
                    "DELETE FROM archive_v3_legacy_extent_objects
                     WHERE session_id = ? AND attempt_id = ? AND ordinal = ?",
                    params![
                        session.session_id().as_bytes().as_slice(),
                        session.attempt_id().as_bytes().as_slice(),
                        deleted_ordinal
                    ],
                )
                .unwrap();
            assert!(OperationLedger::load_legacy_extent_session(
                &connection,
                session.session_id(),
                session.attempt_id(),
            )
            .is_err());
            assert!(OperationLedger::orphan_legacy_extent_attempt(
                &mut connection,
                session.session_id(),
                session.attempt_id(),
                session.binding(),
            )
            .is_err());
        }
    }

    #[test]
    fn legacy_extent_cursor_is_bound_contiguous_and_cannot_skip() {
        let mut connection = setup();
        let session = legacy_session(71);
        OperationLedger::prepare_legacy_extent_session(&mut connection, &session).unwrap();
        for ordinal in 0..257 {
            let facts = legacy_facts(&session, ordinal, ObjectRole::ExtentV3);
            OperationLedger::reserve_legacy_extent_object(
                &mut connection,
                session.session_id(),
                session.attempt_id(),
                session.binding(),
                &facts,
            )
            .unwrap();
        }
        let first = OperationLedger::load_exact_legacy_extent_object_page(
            &connection,
            session.session_id(),
            session.attempt_id(),
            session.binding(),
            None,
        )
        .unwrap();
        assert_eq!(first.entries().len(), 256);
        let cursor = first.next_cursor().unwrap();
        let final_page = OperationLedger::load_exact_legacy_extent_object_page(
            &connection,
            session.session_id(),
            session.attempt_id(),
            session.binding(),
            Some(cursor),
        )
        .unwrap();
        assert_eq!(final_page.entries().len(), 1);
        assert_eq!(final_page.entries()[0].facts().ordinal(), 256);
        let replay = OperationLedger::load_exact_legacy_extent_object_page(
            &connection,
            session.session_id(),
            session.attempt_id(),
            session.binding(),
            Some(cursor),
        )
        .unwrap();
        assert_eq!(replay.entries()[0].facts().ordinal(), 256);
        let forged = LegacyExtentObjectCursor {
            next_ordinal: 200,
            ..cursor
        };
        assert!(OperationLedger::load_exact_legacy_extent_object_page(
            &connection,
            session.session_id(),
            session.attempt_id(),
            session.binding(),
            Some(forged),
        )
        .is_err());
        let cross = LegacyExtentObjectCursor {
            session_id: legacy_session(72).session_id(),
            ..cursor
        };
        assert!(OperationLedger::load_exact_legacy_extent_object_page(
            &connection,
            session.session_id(),
            session.attempt_id(),
            session.binding(),
            Some(cross),
        )
        .is_err());
        let out_of_range = LegacyExtentObjectCursor {
            next_ordinal: MAX_LEGACY_EXTENT_OBJECTS_PER_ATTEMPT as u32,
            ..cursor
        };
        assert!(OperationLedger::load_exact_legacy_extent_object_page(
            &connection,
            session.session_id(),
            session.attempt_id(),
            session.binding(),
            Some(out_of_range),
        )
        .is_err());
        let mut over_cap = legacy_facts(&session, 257, ObjectRole::ExtentV3);
        over_cap.ordinal = MAX_LEGACY_EXTENT_OBJECTS_PER_ATTEMPT as u32;
        assert!(OperationLedger::reserve_legacy_extent_object(
            &mut connection,
            session.session_id(),
            session.attempt_id(),
            session.binding(),
            &over_cap,
        )
        .is_err());
        connection
            .execute(
                "DELETE FROM archive_v3_legacy_extent_objects
                 WHERE session_id = ? AND attempt_id = ? AND ordinal = 0",
                params![
                    session.session_id().as_bytes().as_slice(),
                    session.attempt_id().as_bytes().as_slice()
                ],
            )
            .unwrap();
        assert!(OperationLedger::load_exact_legacy_extent_object_page(
            &connection,
            session.session_id(),
            session.attempt_id(),
            session.binding(),
            Some(cursor),
        )
        .is_err());
    }

    #[test]
    fn legacy_extent_candidate_ready_restart_rescans_inventory_and_schema_tamper_fails() {
        let mut connection = setup();
        let session = legacy_session(81);
        OperationLedger::prepare_legacy_extent_session(&mut connection, &session).unwrap();
        let extent = legacy_facts(&session, 0, ObjectRole::ExtentV3);
        let root = legacy_facts(&session, 1, ObjectRole::RootV3);
        for facts in [&extent, &root] {
            OperationLedger::reserve_legacy_extent_object(
                &mut connection,
                session.session_id(),
                session.attempt_id(),
                session.binding(),
                facts,
            )
            .unwrap();
            OperationLedger::mark_legacy_extent_object_materialized(
                &mut connection,
                session.session_id(),
                session.attempt_id(),
                session.binding(),
                facts,
            )
            .unwrap();
        }
        OperationLedger::persist_legacy_extent_candidate(
            &mut connection,
            session.session_id(),
            session.attempt_id(),
            session.binding(),
            legacy_root_admission(&session, &root),
            &root,
        )
        .unwrap();
        let exact_extent_aad = extent.context_aad.clone();
        connection
            .execute(
                "UPDATE archive_v3_legacy_extent_objects SET context_aad = ?
                 WHERE session_id = ? AND attempt_id = ? AND ordinal = 0",
                params![
                    unexpected_parent_aad(&extent),
                    session.session_id().as_bytes().as_slice(),
                    session.attempt_id().as_bytes().as_slice()
                ],
            )
            .unwrap();
        assert!(OperationLedger::load_legacy_extent_session(
            &connection,
            session.session_id(),
            session.attempt_id(),
        )
        .is_err());
        connection
            .execute(
                "UPDATE archive_v3_legacy_extent_objects SET context_aad = ?
                 WHERE session_id = ? AND attempt_id = ? AND ordinal = 0",
                params![
                    exact_extent_aad.as_slice(),
                    session.session_id().as_bytes().as_slice(),
                    session.attempt_id().as_bytes().as_slice()
                ],
            )
            .unwrap();
        let wrong_parent_aad = wrong_parent_root_aad(&root);
        connection
            .execute(
                "UPDATE archive_v3_legacy_extent_objects SET context_aad = ?
             WHERE session_id = ? AND attempt_id = ? AND ordinal = 1",
                params![
                    wrong_parent_aad,
                    session.session_id().as_bytes().as_slice(),
                    session.attempt_id().as_bytes().as_slice()
                ],
            )
            .unwrap();
        assert!(OperationLedger::load_legacy_extent_session(
            &connection,
            session.session_id(),
            session.attempt_id(),
        )
        .is_err());

        let connection = setup();
        connection
            .execute_batch("DROP INDEX archive_v3_legacy_extent_objects_exact_attempt;")
            .unwrap();
        assert!(OperationLedger::initialize(&connection).is_err());
        let connection = setup();
        connection
            .execute("DELETE FROM archive_v3_legacy_extent_schema", [])
            .unwrap();
        assert!(OperationLedger::initialize(&connection).is_err());
        let connection = setup();
        connection
            .execute_batch("DROP TABLE archive_v3_legacy_extent_objects;")
            .unwrap();
        assert!(OperationLedger::initialize(&connection).is_err());
        let connection = setup();
        connection
            .execute_batch(
                "CREATE TRIGGER archive_v3_legacy_extent_objects_delete_tamper
                 AFTER DELETE ON archive_v3_legacy_extent_objects
                 BEGIN
                    UPDATE archive_v3_legacy_extent_sessions SET state = state;
                 END;",
            )
            .unwrap();
        assert!(OperationLedger::initialize(&connection).is_err());
    }
}
