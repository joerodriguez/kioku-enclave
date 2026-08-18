#![allow(
    dead_code,
    reason = "inactive ADR-0022 Extent shadow coordinator is compiled and tested before runtime activation"
)]

//! Inactive ADR-0022 Extent Shadow coordinator and bounded parity verifier.
//!
//! Read-only shadow parity verification between the authoritative engine and the Extent VFS
//! shadow engine, with operation-scoped receipt identity:
//! - The coordinator takes ownership of both connections at construction and configures them
//!   read-only once (`PRAGMA query_only=ON; PRAGMA trusted_schema=OFF`, mirroring the store
//!   snapshot idiom); it owns read-only configuration for its connections and never hands the
//!   connections back out, so the configuration cannot be lifted by later callers.
//! - Caller SQL must prepare to a single statement that reports read-only
//!   (`sqlite3_stmt_readonly`) on BOTH engines; anything else is rejected with a content-free
//!   error before a single row is stepped. Multi-statement SQL is rejected at prepare time.
//! - Read transactions are RAII-managed: every error path rolls back on drop and leaves both
//!   connections transaction-free.
//! - Both read transactions are opened, and each snapshot is materialized immediately after
//!   its `BEGIN DEFERRED`, before either query runs, so the two snapshots are pinned
//!   concurrently. Concurrent pinning bounds skew but does not prove the two engines are at
//!   the same logical state — the caller must pin the shadow engine to the intended root.
//!   Receipts carry both engines' `PRAGMA data_version` values (content-free integers) as
//!   best-effort snapshot markers.
//! - Comparison is multiset-based: per-row SHA-256 digests combine by 256-bit addition modulo
//!   2^256 (order-independent, duplicate-sensitive), so row-order differences (for example
//!   differing scan order or `ORDER BY` plans) do not cause false mismatches, while
//!   duplicated rows still change the digest.
//! - Emits immutable, content-free, operation-scoped receipts ([`ShadowTraceReceipt`],
//!   [`IntegrityReceipt`]) with opaque `Debug`; no row content, SQL text, engine error
//!   detail, or timing information is exposed.
//! - `PRAGMA integrity_check` is a full-database scan (bounded by database size); it is meant
//!   for scheduled verification, not per-query use.
//! - Dual-engine mutation execution is deliberately deferred until a transactional two-phase
//!   commit replay ledger is formally specified.

use std::fmt;

use rusqlite::{Connection, Statement, Transaction};
use sha2::{Digest, Sha256};

use crate::archive_v3::ArchiveId;

const DOMAIN_QUERY_FINGERPRINT: &[u8] = b"kioku/archive-v3/extent-shadow/query/v2\0";
const DOMAIN_RECEIPT_ID: &[u8] = b"kioku/archive-v3/extent-shadow/receipt-id/v2\0";
const DOMAIN_ROW: &[u8] = b"kioku/archive-v3/extent-shadow/row/v2\0";
const DOMAIN_RESULT: &[u8] = b"kioku/archive-v3/extent-shadow/result/v2\0";
const DOMAIN_RECEIPT_CONTENT: &[u8] = b"kioku:extent_shadow_receipt:v2\0";

/// Closed, content-free failure kinds for shadow comparison, assigned by call site.
///
/// Engine error text is never carried: SQLite messages can embed rowids, page numbers,
/// schema names, or query fragments, so each failing call site drops the underlying
/// error and reports only its kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ExtentShadowError {
    /// Preparing caller SQL failed. Multi-statement SQL lands here: rusqlite refuses
    /// SQL with a non-empty tail at prepare time, before anything executes.
    #[error("shadow trace statement preparation failed")]
    Prepare,
    /// Caller SQL prepared to a statement that is not read-only on both engines.
    /// Returned before any row is stepped.
    #[error("shadow trace statement is not read-only")]
    NotReadOnly,
    /// Stepping result rows or reading column values failed.
    #[error("shadow trace row step failed")]
    Step,
    /// Read-only connection configuration, transaction control, or snapshot pinning failed.
    #[error("shadow trace transaction control failed")]
    Transaction,
    /// Executing `PRAGMA integrity_check` failed.
    #[error("shadow integrity check execution failed")]
    Integrity,
}

/// Durable, content-free comparison receipt for an executed shadow trace.
///
/// Operation-scoped identity: `receipt_id` derives deterministically from the operation
/// id, archive id, and the operation-salted query fingerprint. Fields are digests,
/// counters, and flags only — never row content, SQL text, or timing. `Debug` is opaque.
#[derive(Clone, PartialEq, Eq)]
pub struct ShadowTraceReceipt {
    receipt_id: [u8; 16],
    operation_id: [u8; 16],
    archive_id: ArchiveId,
    query_fingerprint: [u8; 32],
    authoritative_rows: usize,
    shadow_rows: usize,
    authoritative_hash: [u8; 32],
    shadow_hash: [u8; 32],
    authoritative_data_version: i64,
    shadow_data_version: i64,
    matched: bool,
}

impl fmt::Debug for ShadowTraceReceipt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ShadowTraceReceipt").finish_non_exhaustive()
    }
}

impl ShadowTraceReceipt {
    pub fn receipt_id(&self) -> [u8; 16] {
        self.receipt_id
    }
    pub fn operation_id(&self) -> [u8; 16] {
        self.operation_id
    }
    pub fn archive_id(&self) -> ArchiveId {
        self.archive_id
    }
    /// Operation-salted SQL fingerprint: `SHA-256(domain || operation_id || sql)`.
    ///
    /// The per-operation salt resists offline dictionary correlation of low-entropy SQL
    /// literals across receipts. Trace SQL should still prefer parameterized/constant
    /// shapes over embedding secret literals, and receipts remain enclave-internal.
    pub fn query_fingerprint(&self) -> [u8; 32] {
        self.query_fingerprint
    }
    pub fn authoritative_rows(&self) -> usize {
        self.authoritative_rows
    }
    pub fn shadow_rows(&self) -> usize {
        self.shadow_rows
    }
    /// Authoritative multiset result digest (see [`ExtentShadowCoordinator::compare_query`]).
    pub fn authoritative_hash(&self) -> [u8; 32] {
        self.authoritative_hash
    }
    /// Shadow multiset result digest (see [`ExtentShadowCoordinator::compare_query`]).
    pub fn shadow_hash(&self) -> [u8; 32] {
        self.shadow_hash
    }
    /// Authoritative engine `PRAGMA data_version` observed inside its pinned read
    /// snapshot. A content-free counter serving as a best-effort snapshot marker; it does
    /// not prove logical equivalence with the shadow engine.
    pub fn authoritative_data_version(&self) -> i64 {
        self.authoritative_data_version
    }
    /// Shadow engine `PRAGMA data_version` observed inside its pinned read snapshot.
    pub fn shadow_data_version(&self) -> i64 {
        self.shadow_data_version
    }
    pub fn matched(&self) -> bool {
        self.matched
    }

    /// Deterministic digest over every receipt field.
    ///
    /// Covers the per-engine multiset result digests (each of which binds the row
    /// multiset accumulator, row count, and first-row column count), both row counts,
    /// both engines' `data_version` snapshot markers, and the match verdict.
    pub fn content_digest(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(DOMAIN_RECEIPT_CONTENT);
        hasher.update(self.receipt_id);
        hasher.update(self.operation_id);
        hasher.update(self.archive_id.as_bytes());
        hasher.update(self.query_fingerprint);
        hasher.update((self.authoritative_rows as u64).to_le_bytes());
        hasher.update((self.shadow_rows as u64).to_le_bytes());
        hasher.update(self.authoritative_hash);
        hasher.update(self.shadow_hash);
        hasher.update(self.authoritative_data_version.to_le_bytes());
        hasher.update(self.shadow_data_version.to_le_bytes());
        hasher.update([if self.matched { 1 } else { 0 }]);
        hasher.finalize().into()
    }
}

/// Content-free receipt for one scheduled dual-engine integrity verification.
///
/// Carries only booleans: `PRAGMA integrity_check` failure messages can embed rowids and
/// page numbers, so they are consumed and discarded at the call site. `Debug` is opaque.
#[derive(Clone, PartialEq, Eq)]
pub struct IntegrityReceipt {
    operation_id: [u8; 16],
    authoritative_ok: bool,
    shadow_ok: bool,
}

impl fmt::Debug for IntegrityReceipt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("IntegrityReceipt").finish_non_exhaustive()
    }
}

impl IntegrityReceipt {
    pub fn operation_id(&self) -> [u8; 16] {
        self.operation_id
    }
    pub fn authoritative_ok(&self) -> bool {
        self.authoritative_ok
    }
    pub fn shadow_ok(&self) -> bool {
        self.shadow_ok
    }
}

/// Dual-engine coordinator executing read-only traces and verifying parity.
///
/// Owns both engine connections. Construction sets `PRAGMA query_only=ON` and
/// `PRAGMA trusted_schema=OFF` on each (the same read-only snapshot idiom as the store's
/// advisory capture path), and the connections are never exposed again, so no later
/// caller can lift the read-only configuration for the coordinator's lifetime.
pub struct ExtentShadowCoordinator {
    archive_id: ArchiveId,
    authoritative: Connection,
    shadow: Connection,
}

impl ExtentShadowCoordinator {
    /// Take ownership of both engine connections and configure them read-only.
    ///
    /// The caller must finish any seeding/setup before construction: from here on both
    /// connections permanently enforce `query_only=ON` and `trusted_schema=OFF`.
    pub fn new(
        archive_id: ArchiveId,
        authoritative: Connection,
        shadow: Connection,
    ) -> Result<Self, ExtentShadowError> {
        for conn in [&authoritative, &shadow] {
            conn.execute_batch("PRAGMA query_only=ON; PRAGMA trusted_schema=OFF;")
                .map_err(|_| ExtentShadowError::Transaction)?;
        }
        Ok(Self {
            archive_id,
            authoritative,
            shadow,
        })
    }

    pub fn archive_id(&self) -> ArchiveId {
        self.archive_id
    }

    /// Execute one read-only statement on both engines under concurrently pinned read
    /// snapshots and compare streaming multiset digests of the result rows.
    ///
    /// Read-only enforcement (defense in depth):
    /// - rusqlite rejects multi-statement SQL at prepare time ([`ExtentShadowError::Prepare`]);
    /// - the prepared statement must report read-only on BOTH engines, checked before any
    ///   row is stepped ([`ExtentShadowError::NotReadOnly`]);
    /// - `PRAGMA query_only=ON`, set at construction, makes the engines themselves refuse
    ///   writes even if a non-read-only statement were ever stepped.
    ///
    /// Snapshot discipline: both `BEGIN DEFERRED` read transactions are opened and each
    /// snapshot is materialized immediately (a cheap `sqlite_master` read) before either
    /// query runs, so the snapshots are pinned concurrently. Transactions are RAII-managed;
    /// every error path rolls back on drop. Concurrent pinning bounds skew but does not
    /// prove the engines share a logical state — the caller must pin the shadow engine to
    /// the intended root. Each engine's `PRAGMA data_version` is recorded in the receipt
    /// as a content-free, best-effort snapshot marker.
    ///
    /// Digest semantics: each row hashes to `SHA-256(row-domain || col_count || framed
    /// values)` using type-tagged, length-prefixed framing; rows combine by 256-bit
    /// addition modulo 2^256, an order-independent but duplicate-sensitive multiset
    /// accumulator. The published per-engine digest is `SHA-256(result-domain ||
    /// accumulator || row_count || first-row col_count (or 0))`. Because comparison is
    /// multiset-based, `ORDER BY` or scan-order differences between engines do not cause
    /// false mismatches; cardinality and duplicated rows are still detected.
    pub fn compare_query(
        &self,
        operation_id: [u8; 16],
        sql: &str,
    ) -> Result<ShadowTraceReceipt, ExtentShadowError> {
        let mut query_hasher = Sha256::new();
        query_hasher.update(DOMAIN_QUERY_FINGERPRINT);
        query_hasher.update(operation_id);
        query_hasher.update(sql.as_bytes());
        let query_fingerprint: [u8; 32] = query_hasher.finalize().into();

        let mut receipt_hasher = Sha256::new();
        receipt_hasher.update(DOMAIN_RECEIPT_ID);
        receipt_hasher.update(operation_id);
        receipt_hasher.update(self.archive_id.as_bytes());
        receipt_hasher.update(query_fingerprint);
        let receipt_digest: [u8; 32] = receipt_hasher.finalize().into();
        let mut receipt_id = [0u8; 16];
        receipt_id.copy_from_slice(&receipt_digest[..16]);

        // Open BOTH read transactions and pin each snapshot immediately, before either
        // query runs, so the snapshots overlap in time. RAII: drop rolls back on every
        // error path below, leaving both connections transaction-free.
        let auth_tx = self
            .authoritative
            .unchecked_transaction()
            .map_err(|_| ExtentShadowError::Transaction)?;
        let authoritative_data_version = pin_snapshot(&auth_tx)?;
        let shadow_tx = self
            .shadow
            .unchecked_transaction()
            .map_err(|_| ExtentShadowError::Transaction)?;
        let shadow_data_version = pin_snapshot(&shadow_tx)?;

        // Prepare on both engines and require read-only on both before any step.
        let mut auth_stmt = auth_tx
            .prepare(sql)
            .map_err(|_| ExtentShadowError::Prepare)?;
        let mut shadow_stmt = shadow_tx
            .prepare(sql)
            .map_err(|_| ExtentShadowError::Prepare)?;
        if !auth_stmt.readonly() || !shadow_stmt.readonly() {
            return Err(ExtentShadowError::NotReadOnly);
        }

        // Run authoritative first, then shadow, both under the already-pinned snapshots.
        let authoritative_result = digest_result_rows(&mut auth_stmt)?;
        let shadow_result = digest_result_rows(&mut shadow_stmt)?;

        drop(auth_stmt);
        drop(shadow_stmt);
        // Pure read transactions: commit and rollback are equivalent; end deterministically.
        shadow_tx
            .commit()
            .map_err(|_| ExtentShadowError::Transaction)?;
        auth_tx
            .commit()
            .map_err(|_| ExtentShadowError::Transaction)?;

        let matched = authoritative_result.row_count == shadow_result.row_count
            && authoritative_result.digest == shadow_result.digest;

        Ok(ShadowTraceReceipt {
            receipt_id,
            operation_id,
            archive_id: self.archive_id,
            query_fingerprint,
            authoritative_rows: authoritative_result.row_count,
            shadow_rows: shadow_result.row_count,
            authoritative_hash: authoritative_result.digest,
            shadow_hash: shadow_result.digest,
            authoritative_data_version,
            shadow_data_version,
            matched,
        })
    }

    /// Run `PRAGMA integrity_check(100)` on both engines, each inside its own RAII read
    /// transaction, consuming every returned row.
    ///
    /// An engine is clean only when the check emits exactly one row equal to `ok`; any
    /// other output (including the up-to-100 corruption messages) marks it not-ok, and
    /// the message text is discarded because it can embed rowids and page numbers.
    ///
    /// `integrity_check` scans the full database — bounded by database size, not by row
    /// output — so this is a scheduled-verification entry point, not a per-query one.
    pub fn verify_integrity(
        &self,
        operation_id: [u8; 16],
    ) -> Result<IntegrityReceipt, ExtentShadowError> {
        let authoritative_ok = integrity_clean(&self.authoritative)?;
        let shadow_ok = integrity_clean(&self.shadow)?;
        Ok(IntegrityReceipt {
            operation_id,
            authoritative_ok,
            shadow_ok,
        })
    }
}

/// Materialize the deferred transaction's read snapshot now (a cheap catalog read) and
/// return the connection's `PRAGMA data_version` marker observed inside that snapshot.
fn pin_snapshot(tx: &Transaction<'_>) -> Result<i64, ExtentShadowError> {
    let _schema_probe: i64 = tx
        .query_row("SELECT count(*) FROM sqlite_master", [], |row| row.get(0))
        .map_err(|_| ExtentShadowError::Transaction)?;
    tx.query_row("PRAGMA data_version", [], |row| row.get(0))
        .map_err(|_| ExtentShadowError::Transaction)
}

struct EngineResultDigest {
    digest: [u8; 32],
    row_count: usize,
}

/// Stream all rows of a prepared read-only statement into an order-independent,
/// duplicate-sensitive multiset digest without buffering row content.
///
/// Per-row digest: `SHA-256(row-domain || col_count || framed values)` with type-tagged,
/// length-prefixed value framing. Rows combine by 256-bit addition modulo 2^256
/// (duplicate rows shift the sum; XOR would let duplicate pairs cancel). The returned
/// digest is `SHA-256(result-domain || accumulator || row_count || first-row col_count
/// (or 0))`, binding the row multiset, cardinality, and result shape.
fn digest_result_rows(stmt: &mut Statement<'_>) -> Result<EngineResultDigest, ExtentShadowError> {
    let mut accumulator = [0u8; 32];
    let mut row_count: usize = 0;
    let mut first_col_count: u32 = 0;
    let mut rows = stmt.query([]).map_err(|_| ExtentShadowError::Step)?;
    while let Some(row) = rows.next().map_err(|_| ExtentShadowError::Step)? {
        let col_count = row.as_ref().column_count();
        if row_count == 0 {
            first_col_count = col_count as u32;
        }
        row_count += 1;
        let mut row_hasher = Sha256::new();
        row_hasher.update(DOMAIN_ROW);
        row_hasher.update((col_count as u32).to_le_bytes());
        for i in 0..col_count {
            let val_ref = row.get_ref(i).map_err(|_| ExtentShadowError::Step)?;
            match val_ref {
                rusqlite::types::ValueRef::Null => row_hasher.update([0x00]),
                rusqlite::types::ValueRef::Integer(v) => {
                    row_hasher.update([0x01]);
                    row_hasher.update(v.to_le_bytes());
                }
                rusqlite::types::ValueRef::Real(v) => {
                    row_hasher.update([0x02]);
                    row_hasher.update(v.to_le_bytes());
                }
                rusqlite::types::ValueRef::Text(v) => {
                    row_hasher.update([0x03]);
                    row_hasher.update((v.len() as u32).to_le_bytes());
                    row_hasher.update(v);
                }
                rusqlite::types::ValueRef::Blob(v) => {
                    row_hasher.update([0x04]);
                    row_hasher.update((v.len() as u32).to_le_bytes());
                    row_hasher.update(v);
                }
            }
        }
        let row_digest: [u8; 32] = row_hasher.finalize().into();
        accumulate_mod_2_256(&mut accumulator, &row_digest);
    }
    let mut result_hasher = Sha256::new();
    result_hasher.update(DOMAIN_RESULT);
    result_hasher.update(accumulator);
    result_hasher.update((row_count as u64).to_le_bytes());
    result_hasher.update(first_col_count.to_le_bytes());
    Ok(EngineResultDigest {
        digest: result_hasher.finalize().into(),
        row_count,
    })
}

/// Multiset accumulator: 256-bit addition modulo 2^256 over little-endian byte arrays.
///
/// Addition (not XOR) keeps the accumulator duplicate-sensitive: a row appearing twice
/// shifts the sum, whereas XOR would cancel duplicate pairs to zero.
fn accumulate_mod_2_256(accumulator: &mut [u8; 32], row_digest: &[u8; 32]) {
    let mut carry: u16 = 0;
    for (acc_byte, digest_byte) in accumulator.iter_mut().zip(row_digest.iter()) {
        let sum = u16::from(*acc_byte) + u16::from(*digest_byte) + carry;
        *acc_byte = (sum & 0xff) as u8;
        carry = sum >> 8;
    }
    // The final carry is discarded: addition is modulo 2^256.
}

/// Run `PRAGMA integrity_check(100)` inside an RAII read transaction, consuming every
/// row and reporting only a boolean (message text can contain rowids and page numbers).
fn integrity_clean(conn: &Connection) -> Result<bool, ExtentShadowError> {
    let tx = conn
        .unchecked_transaction()
        .map_err(|_| ExtentShadowError::Transaction)?;
    let clean = {
        let mut stmt = tx
            .prepare("PRAGMA integrity_check(100)")
            .map_err(|_| ExtentShadowError::Integrity)?;
        let mut rows = stmt.query([]).map_err(|_| ExtentShadowError::Integrity)?;
        let mut row_count: usize = 0;
        let mut all_ok = true;
        while let Some(row) = rows.next().map_err(|_| ExtentShadowError::Integrity)? {
            row_count += 1;
            let is_ok_marker = matches!(
                row.get_ref(0),
                Ok(rusqlite::types::ValueRef::Text(text)) if text == b"ok".as_slice()
            );
            if !is_ok_marker {
                all_ok = false;
            }
        }
        row_count == 1 && all_ok
    };
    tx.commit().map_err(|_| ExtentShadowError::Transaction)?;
    Ok(clean)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::archive_v3::{DatabaseEpoch, InMemoryImmutableBackend, KeyEpoch};
    use crate::archive_v3_extent::tests::TestCipher;
    use crate::archive_v3_extent_vfs::RegisteredExtentVfs;
    use rand::{rngs::OsRng, RngCore};
    use std::sync::Arc;

    fn seeded_pair(schema_and_rows: &str) -> (Connection, Connection) {
        let auth = Connection::open_in_memory().unwrap();
        let shadow = Connection::open_in_memory().unwrap();
        auth.execute_batch(schema_and_rows).unwrap();
        shadow.execute_batch(schema_and_rows).unwrap();
        (auth, shadow)
    }

    const KEEP_ONE_ROW: &str =
        "CREATE TABLE t (id INTEGER PRIMARY KEY, v TEXT); INSERT INTO t (id, v) VALUES (1, 'keep');";

    #[test]
    fn test_extent_shadow_streaming_hash_and_query_parity() {
        let (auth, shadow) = seeded_pair(
            "CREATE TABLE notes (id INTEGER PRIMARY KEY, text TEXT); INSERT INTO notes (id, text) VALUES (1, 'memory');",
        );

        let coordinator = ExtentShadowCoordinator::new(ArchiveId::random(), auth, shadow)
            .expect("configures read-only connections");
        let op_id = [0x42; 16];

        let receipt = coordinator
            .compare_query(op_id, "SELECT id, text FROM notes WHERE id=1")
            .expect("query parity matches");
        assert!(receipt.matched());
        assert_eq!(receipt.authoritative_rows(), 1);
        assert_eq!(receipt.shadow_rows(), 1);
        assert_eq!(receipt.authoritative_hash(), receipt.shadow_hash());
        assert_eq!(receipt.operation_id(), op_id);
        assert_ne!(receipt.content_digest(), [0u8; 32]);
        // Receipts are Debug-opaque.
        assert_eq!(format!("{receipt:?}"), "ShadowTraceReceipt { .. }");

        let integrity = coordinator
            .verify_integrity(op_id)
            .expect("integrity check runs");
        assert!(integrity.authoritative_ok());
        assert!(integrity.shadow_ok());
        assert_eq!(integrity.operation_id(), op_id);
        assert_eq!(format!("{integrity:?}"), "IntegrityReceipt { .. }");
    }

    #[test]
    fn test_dml_rejected_not_read_only_and_rows_survive() {
        let (auth, shadow) = seeded_pair(KEEP_ONE_ROW);
        let coordinator = ExtentShadowCoordinator::new(ArchiveId::random(), auth, shadow).unwrap();

        for (salt, dml) in [
            (0x01u8, "DELETE FROM t"),
            (0x02u8, "UPDATE t SET v='clobbered'"),
            (0x03u8, "INSERT INTO t (id, v) VALUES (2, 'extra')"),
        ] {
            let err = coordinator.compare_query([salt; 16], dml).unwrap_err();
            assert_eq!(err, ExtentShadowError::NotReadOnly);
        }

        // The original row survived with its original value on both engines, and no
        // inserted row appeared.
        let keep = coordinator
            .compare_query([0x04; 16], "SELECT id, v FROM t WHERE v='keep'")
            .expect("connections stay usable after rejected DML");
        assert!(keep.matched());
        assert_eq!(keep.authoritative_rows(), 1);
        assert_eq!(keep.shadow_rows(), 1);

        let all_rows = coordinator
            .compare_query([0x05; 16], "SELECT id, v FROM t")
            .unwrap();
        assert!(all_rows.matched());
        assert_eq!(all_rows.authoritative_rows(), 1);
        assert_eq!(all_rows.shadow_rows(), 1);
    }

    #[test]
    fn test_multi_statement_sql_rejected_at_prepare() {
        let (auth, shadow) = seeded_pair(KEEP_ONE_ROW);
        let coordinator = ExtentShadowCoordinator::new(ArchiveId::random(), auth, shadow).unwrap();

        let err = coordinator
            .compare_query([0x11; 16], "SELECT 1; DELETE FROM t")
            .unwrap_err();
        assert_eq!(err, ExtentShadowError::Prepare);

        // Nothing executed: the row survives on both engines.
        let receipt = coordinator
            .compare_query([0x12; 16], "SELECT id, v FROM t WHERE v='keep'")
            .unwrap();
        assert!(receipt.matched());
        assert_eq!(receipt.authoritative_rows(), 1);
        assert_eq!(receipt.shadow_rows(), 1);
    }

    #[test]
    fn test_genuine_mismatch_detected() {
        let auth = Connection::open_in_memory().unwrap();
        let shadow = Connection::open_in_memory().unwrap();
        auth.execute_batch(
            "CREATE TABLE t (id INTEGER PRIMARY KEY, v TEXT); INSERT INTO t (id, v) VALUES (1, 'alpha');",
        )
        .unwrap();
        shadow
            .execute_batch(
                "CREATE TABLE t (id INTEGER PRIMARY KEY, v TEXT); INSERT INTO t (id, v) VALUES (1, 'beta');",
            )
            .unwrap();
        let coordinator = ExtentShadowCoordinator::new(ArchiveId::random(), auth, shadow).unwrap();

        let receipt = coordinator
            .compare_query([0x21; 16], "SELECT id, v FROM t")
            .unwrap();
        assert!(!receipt.matched());
        assert_ne!(receipt.authoritative_hash(), receipt.shadow_hash());
        assert_eq!(receipt.authoritative_rows(), 1);
        assert_eq!(receipt.shadow_rows(), 1);
    }

    #[test]
    fn test_duplicate_rows_do_not_cancel_in_multiset_digest() {
        // Equal-cardinality result sets whose per-row digests each appear exactly twice:
        // an XOR accumulator would collapse both sides to zero and falsely match; the
        // additive accumulator must not.
        let auth = Connection::open_in_memory().unwrap();
        let shadow = Connection::open_in_memory().unwrap();
        auth.execute_batch(
            "CREATE TABLE t (id INTEGER PRIMARY KEY, v TEXT); INSERT INTO t (id, v) VALUES (1, 'x'), (2, 'x');",
        )
        .unwrap();
        shadow
            .execute_batch(
                "CREATE TABLE t (id INTEGER PRIMARY KEY, v TEXT); INSERT INTO t (id, v) VALUES (1, 'y'), (2, 'y');",
            )
            .unwrap();
        let coordinator = ExtentShadowCoordinator::new(ArchiveId::random(), auth, shadow).unwrap();

        let receipt = coordinator
            .compare_query([0x22; 16], "SELECT v FROM t")
            .unwrap();
        assert_eq!(receipt.authoritative_rows(), receipt.shadow_rows());
        assert!(!receipt.matched());
        assert_ne!(receipt.authoritative_hash(), receipt.shadow_hash());
    }

    #[test]
    fn test_identical_multisets_in_different_orders_match() {
        let (auth, shadow) = seeded_pair(
            "CREATE TABLE t (id INTEGER PRIMARY KEY, v TEXT); INSERT INTO t (id, v) VALUES (1, 'a'), (2, 'b'), (3, 'c');",
        );
        // Reverse unordered scans on the shadow engine only (set before the coordinator
        // takes ownership), then prove the physical row order genuinely differs.
        shadow
            .execute_batch("PRAGMA reverse_unordered_selects=ON;")
            .unwrap();
        let shadow_first: i64 = shadow
            .query_row("SELECT id FROM t", [], |row| row.get(0))
            .unwrap();
        let auth_first: i64 = auth
            .query_row("SELECT id FROM t", [], |row| row.get(0))
            .unwrap();
        assert_ne!(shadow_first, auth_first, "scan orders must differ");

        let coordinator = ExtentShadowCoordinator::new(ArchiveId::random(), auth, shadow).unwrap();
        let receipt = coordinator
            .compare_query([0x23; 16], "SELECT id, v FROM t")
            .unwrap();
        assert!(receipt.matched());
        assert_eq!(receipt.authoritative_hash(), receipt.shadow_hash());
        assert_eq!(receipt.authoritative_rows(), 3);
        assert_eq!(receipt.shadow_rows(), 3);
    }

    #[test]
    fn test_error_paths_leave_connections_usable() {
        let (auth, shadow) = seeded_pair(KEEP_ONE_ROW);
        let coordinator = ExtentShadowCoordinator::new(ArchiveId::random(), auth, shadow).unwrap();

        // Rejected after both read transactions were opened (NotReadOnly path).
        assert_eq!(
            coordinator
                .compare_query([0x31; 16], "DELETE FROM t")
                .unwrap_err(),
            ExtentShadowError::NotReadOnly
        );
        // Rejected at prepare: multi-statement and unknown-column paths.
        assert_eq!(
            coordinator
                .compare_query([0x32; 16], "SELECT 1; SELECT 2")
                .unwrap_err(),
            ExtentShadowError::Prepare
        );
        assert_eq!(
            coordinator
                .compare_query([0x33; 16], "SELECT missing_col FROM t")
                .unwrap_err(),
            ExtentShadowError::Prepare
        );

        // Regression for the historical transaction leak: with hand-rolled BEGIN/COMMIT
        // every error above stranded an open transaction and the next BEGIN failed.
        // RAII rollback must leave both connections immediately usable.
        let receipt = coordinator
            .compare_query([0x34; 16], "SELECT id, v FROM t")
            .unwrap();
        assert!(receipt.matched());
        assert_eq!(receipt.authoritative_rows(), 1);

        let integrity = coordinator.verify_integrity([0x35; 16]).unwrap();
        assert!(integrity.authoritative_ok());
        assert!(integrity.shadow_ok());
    }

    #[test]
    fn test_integrity_receipt_reports_both_engines_ok() {
        let (auth, shadow) = seeded_pair("CREATE TABLE t (id INTEGER PRIMARY KEY);");
        let coordinator = ExtentShadowCoordinator::new(ArchiveId::random(), auth, shadow).unwrap();
        let op_id = [0x77; 16];
        let receipt = coordinator.verify_integrity(op_id).unwrap();
        assert!(receipt.authoritative_ok());
        assert!(receipt.shadow_ok());
        assert_eq!(receipt.operation_id(), op_id);
    }

    #[test]
    fn test_query_fingerprint_is_operation_salted() {
        let (auth, shadow) =
            seeded_pair("CREATE TABLE t (id INTEGER PRIMARY KEY); INSERT INTO t (id) VALUES (1);");
        let coordinator = ExtentShadowCoordinator::new(ArchiveId::random(), auth, shadow).unwrap();
        let first = coordinator
            .compare_query([0x41; 16], "SELECT id FROM t")
            .unwrap();
        let second = coordinator
            .compare_query([0x42; 16], "SELECT id FROM t")
            .unwrap();
        // Same SQL, different operations: fingerprints and receipt ids differ, while
        // the data digests (operation-independent) agree.
        assert_ne!(first.query_fingerprint(), second.query_fingerprint());
        assert_ne!(first.receipt_id(), second.receipt_id());
        assert_eq!(first.authoritative_hash(), second.authoritative_hash());
    }

    #[test]
    fn test_multiset_accumulator_is_commutative_and_wraps() {
        let a = [0x7fu8; 32];
        let mut b = [0u8; 32];
        b[0] = 0x81;
        b[31] = 0xff;

        let mut left = [0u8; 32];
        accumulate_mod_2_256(&mut left, &a);
        accumulate_mod_2_256(&mut left, &b);
        let mut right = [0u8; 32];
        accumulate_mod_2_256(&mut right, &b);
        accumulate_mod_2_256(&mut right, &a);
        assert_eq!(left, right);

        // Wrap-around: (2^256 - 1) + 1 == 0 (mod 2^256).
        let mut acc = [0xffu8; 32];
        let mut one = [0u8; 32];
        one[0] = 1;
        accumulate_mod_2_256(&mut acc, &one);
        assert_eq!(acc, [0u8; 32]);

        // Duplicate sensitivity: x + x != 0, unlike XOR where x ^ x == 0.
        let mut twice = [0u8; 32];
        accumulate_mod_2_256(&mut twice, &a);
        accumulate_mod_2_256(&mut twice, &a);
        assert_ne!(twice, [0u8; 32]);
    }

    #[test]
    fn test_extent_shadow_with_registered_vfs_instance() {
        let backend = InMemoryImmutableBackend::default();
        let archive_id = ArchiveId::random();
        let db_epoch = DatabaseEpoch::random();
        let key_epoch = KeyEpoch::random();
        let cipher = TestCipher::new(archive_id, key_epoch);
        let ledger_conn = Arc::new(std::sync::Mutex::new(Connection::open_in_memory().unwrap()));
        let ledger = Arc::new(
            crate::archive_v3_extent_commit::SqliteExtentAttemptLedger::new(ledger_conn).unwrap(),
        );
        let vfs_name = format!("extent-shadow-{}", uuid_string());
        let vfs = RegisteredExtentVfs::install(
            &vfs_name,
            Arc::new(backend),
            Arc::new(cipher),
            db_epoch,
            ledger,
            None,
        )
        .expect("installs VFS");

        let auth = Connection::open_in_memory().unwrap();
        auth.execute_batch("CREATE TABLE kv (k TEXT PRIMARY KEY, v TEXT); INSERT INTO kv (k, v) VALUES ('user_key', 'encrypted_val');")
            .unwrap();

        // The shadow database name is an absolute path inside a per-test temporary
        // directory: concurrent test runs never collide and nothing lands in the repo.
        let shadow_dir = tempfile::tempdir().expect("creates tempdir");
        let shadow_file = shadow_dir
            .path()
            .join(format!("shadow-{}.db", uuid_string()));
        let db_path = format!("file:{}?vfs={}", shadow_file.display(), vfs_name);
        let shadow = Connection::open_with_flags(
            &db_path,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE
                | rusqlite::OpenFlags::SQLITE_OPEN_CREATE
                | rusqlite::OpenFlags::SQLITE_OPEN_URI,
        )
        .expect("opens shadow db with extent vfs");
        shadow
            .execute_batch("PRAGMA journal_mode=MEMORY; PRAGMA temp_store=MEMORY;")
            .unwrap();

        shadow.execute_batch("CREATE TABLE kv (k TEXT PRIMARY KEY, v TEXT); INSERT INTO kv (k, v) VALUES ('user_key', 'encrypted_val');")
            .unwrap();

        let coordinator = ExtentShadowCoordinator::new(archive_id, auth, shadow)
            .expect("configures read-only connections");
        let op_id = [0x55; 16];

        let receipt = coordinator
            .compare_query(op_id, "SELECT k, v FROM kv ORDER BY k ASC;")
            .unwrap();
        assert!(receipt.matched());
        assert_eq!(receipt.authoritative_rows(), 1);
        assert_eq!(receipt.authoritative_hash(), receipt.shadow_hash());

        let integrity = coordinator.verify_integrity(op_id).unwrap();
        assert!(integrity.authoritative_ok());
        assert!(integrity.shadow_ok());

        drop(coordinator);
        drop(vfs);
    }

    fn uuid_string() -> String {
        let mut rand_bytes = [0u8; 8];
        OsRng.fill_bytes(&mut rand_bytes);
        let mut s = String::with_capacity(16);
        for b in rand_bytes {
            use std::fmt::Write;
            let _ = write!(&mut s, "{:02x}", b);
        }
        s
    }
}
