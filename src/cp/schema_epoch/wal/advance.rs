#![allow(
    dead_code,
    reason = "ADR-0022 Part B: the ladder driver is reviewed before the first shipped step; SCHEMA_LADDER stays empty until the baseline seal flips"
)]

//! One schema-ladder step as a sealed WAL plan (ADR-0022 Part B, §7.3/§7.4).
//!
//! # What this is
//!
//! `WalOperationKind::SchemaEpochAdvance = 13` has existed as a reserved
//! ordinal with no plan behind it. This is the plan: it carries **one** live
//! archive from epoch `N` to epoch `N+1` by executing the single ladder step
//! that spans them, inside the owner's own transaction, and records the new
//! `(epoch, chain_digest)` marker in the same commit.
//!
//! # One plan per STEP, never one per advance-to-target
//!
//! [`advance_one_epoch`] advances by exactly one epoch and returns; the caller
//! loops. That is not a convenience — it is what keeps the ledger row
//! unambiguous about how far the archive actually got. A plan spanning
//! `0 → 3` that died after step 2 would leave a ledger row whose operation id
//! claims a transition the archive never completed. Every intermediate epoch
//! is a complete, servable state precisely because every step is its own
//! commit; that is the structural property a drop-and-recreate rebuild does
//! not have, and the reason the rebuild was rejected.
//!
//! # Why there is no `committed_at`
//!
//! The advance writes no timestamped row: `schema_epoch` is
//! `(singleton, epoch, chain_digest)` and nothing else. Carrying a wall clock
//! anyway would put a value in the request fingerprint that is **not** in the
//! operation-id source, so two presentations of the same logical advance —
//! two owner replicas racing, or a retry after a lost acknowledgement — would
//! derive the same operation id with different fingerprints and collide as
//! `FingerprintConflict` instead of resolving as `Replayed` or as the clean
//! `Precondition` this family promises. A clock in a replayed plan is the
//! defect shape this program has already shipped four times; the correct fix
//! here is not to bind it but to not have one. Every byte this plan commits is
//! a function of the plan, never of the moment it ran.
//!
//! # Deliberately NOT idempotent
//!
//! A step is never written with `IF NOT EXISTS`, and precondition (1) is an
//! exact CAS on the marker, never `>=`. A silently idempotent step would let a
//! second application pass unnoticed, which is the one thing the epoch marker
//! exists to make impossible.

use rusqlite::{params, Connection, OptionalExtension, Transaction};
use zeroize::Zeroizing;

use crate::archive_v3_wal_idempotency::{
    stable_operation_source, DomainLedgerBounds, LogicalMutationResult, PreparedLogicalMutation,
    WalIdempotencyError, WalLogicalDomainLedger, WalLogicalDomainPlan, WalLogicalOperationId,
    WalOperationKind, WalReplayResult,
};
use crate::schema_ladder::{step_digest, ArchiveEpoch, LadderView};

const REQUEST_V1: u16 = 1;
const SUBTYPE: &[u8] = b"adr-0022-schema-epoch-advance-v1";
const MAX_STEP_ID_BYTES: usize = 128;
const ENCODED_UNIT_RESULT_BYTES: usize = 9;
const SCHEMA_TABLE: &str = "archive_v3_wal_schema_epoch_schema";
const LEDGER_TABLE: &str = "archive_v3_wal_schema_epoch_operations";
const STATE_TABLE: &str = "archive_v3_wal_schema_epoch_state";
/// An archive advances at most once per shipped step, and the ladder is
/// append-only from 1. 1024 is orders of magnitude above any plausible ladder
/// length and still bounds the family. Keep the CHECK literals in
/// [`ensure_schema`] in sync with these two.
const MAX_ROWS: u32 = 1024;
const MAX_RESULT_BYTES: u64 = 1024 * 9;
const BOUNDS: DomainLedgerBounds = DomainLedgerBounds::new(MAX_ROWS, MAX_RESULT_BYTES);

/// The bookkeeping namespace every WAL family creates inside its own apply
/// transaction. It is not product schema and a canonical build never contains
/// it, so the epoch comparison below excludes it — and then proves the
/// excluded set contains nothing else.
const WAL_DOMAIN_PREFIX: &str = "archive_v3_wal_";

type Result<T> = std::result::Result<T, WalIdempotencyError>;

/// One sealed advance of one archive by exactly one epoch.
pub(crate) struct SchemaEpochAdvancePlan {
    operation_id: WalLogicalOperationId,
    account_id: String,
    from_epoch: u32,
    to_epoch: u32,
    step_id: &'static str,
    step_digest: [u8; 32],
    from_chain: [u8; 32],
    to_chain: [u8; 32],
    /// The ladder this plan was built against. Deliberately **not** part of
    /// the canonical request: the ladder's *content* is already bound exactly
    /// by `step_digest`, `from_chain` and `to_chain`, which are. This field is
    /// only how `apply` looks the step up, and precondition (3) is what
    /// refuses a binary whose ladder was edited after the step shipped.
    ladder: LadderView,
}

impl Clone for SchemaEpochAdvancePlan {
    fn clone(&self) -> Self {
        Self {
            operation_id: self.operation_id,
            account_id: self.account_id.clone(),
            from_epoch: self.from_epoch,
            to_epoch: self.to_epoch,
            step_id: self.step_id,
            step_digest: self.step_digest,
            from_chain: self.from_chain,
            to_chain: self.to_chain,
            ladder: self.ladder,
        }
    }
}

impl std::fmt::Debug for SchemaEpochAdvancePlan {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("SchemaEpochAdvancePlan(<opaque>)")
    }
}

impl SchemaEpochAdvancePlan {
    /// Build the plan that carries `from_epoch` to `from_epoch + 1` over the
    /// production ladder.
    ///
    /// Everything the plan commits is derived here, once, from the ladder this
    /// binary compiled in — never from the archive, and never from a clock.
    pub(in crate::cp) fn new(account_id: String, from_epoch: u32) -> Result<Self> {
        Self::over_ladder(account_id, from_epoch, LadderView::PRODUCTION)
    }

    /// The same constructor against an explicit ladder view.
    ///
    /// Private in production — [`new`](Self::new) is the only reachable entry
    /// point and it binds [`LadderView::PRODUCTION`] — and visible to tests so
    /// the family can be exercised end to end while `SCHEMA_LADDER` is still
    /// empty. See [`LadderView`] for why it must be.
    fn over_ladder(account_id: String, from_epoch: u32, ladder: LadderView) -> Result<Self> {
        crate::store::validate_user_id(&account_id).map_err(|_| WalIdempotencyError::Malformed)?;
        let to_epoch = from_epoch
            .checked_add(1)
            .ok_or(WalIdempotencyError::Malformed)?;
        if to_epoch > ladder.target() || ladder.target() > ladder.head() {
            return Err(WalIdempotencyError::Precondition);
        }
        let step = ladder
            .step_at(to_epoch)
            .ok_or(WalIdempotencyError::Precondition)?;
        if step.id.is_empty() || step.id.len() > MAX_STEP_ID_BYTES || step.sql.trim().is_empty() {
            return Err(WalIdempotencyError::Malformed);
        }
        let source = stable_operation_source(
            SUBTYPE,
            &[
                account_id.as_bytes(),
                &from_epoch.to_be_bytes(),
                &to_epoch.to_be_bytes(),
                step.id.as_bytes(),
            ],
        )?;
        let operation_id = WalLogicalOperationId::from_stable_source(
            WalOperationKind::SchemaEpochAdvance,
            &source,
        )?;
        Ok(Self {
            operation_id,
            account_id,
            from_epoch,
            to_epoch,
            step_id: step.id,
            step_digest: step_digest(step),
            from_chain: ladder.chain_digest(from_epoch),
            to_chain: ladder.chain_digest(to_epoch),
            ladder,
        })
    }

    pub(in crate::cp) fn advances_from(&self) -> u32 {
        self.from_epoch
    }

    pub(in crate::cp) fn advances_to(&self) -> u32 {
        self.to_epoch
    }
}

pub(crate) struct SchemaEpochAdvanceLedger;

impl WalLogicalDomainPlan for SchemaEpochAdvancePlan {
    type Ledger = SchemaEpochAdvanceLedger;
    type Output = ();

    fn kind(&self) -> WalOperationKind {
        WalOperationKind::SchemaEpochAdvance
    }

    fn operation_id(&self) -> WalLogicalOperationId {
        self.operation_id
    }

    fn canonical_request(&self) -> Result<Zeroizing<Vec<u8>>> {
        let mut request = Zeroizing::new(Vec::with_capacity(256));
        request.extend_from_slice(&REQUEST_V1.to_be_bytes());
        encode_bytes(&mut request, SUBTYPE)?;
        encode_string(&mut request, &self.account_id)?;
        request.extend_from_slice(&self.from_epoch.to_be_bytes());
        request.extend_from_slice(&self.to_epoch.to_be_bytes());
        encode_string(&mut request, self.step_id)?;
        request.extend_from_slice(&self.step_digest);
        request.extend_from_slice(&self.from_chain);
        request.extend_from_slice(&self.to_chain);
        Ok(request)
    }

    /// The ten checks of §7.3, in this exact order, every failure closed.
    ///
    /// The whole body runs inside the owner's single `BEGIN IMMEDIATE`, which
    /// the shared gate supplies by signature. SQLite DDL is transactional, so
    /// the step, the marker upsert and the ledger row commit or roll back as
    /// one — there is no half-applied schema and no wedge.
    fn apply(&self, transaction: &Transaction<'_>) -> Result<WalReplayResult> {
        // (1) Exact CAS on the marker. NEVER `>=`: a second application of a
        // shipped step must be refused, not adopted.
        let marker = crate::schema_ladder::read_archive_epoch(transaction)
            .map_err(|_| WalIdempotencyError::Precondition)?;
        if marker
            != (ArchiveEpoch {
                epoch: self.from_epoch,
                chain: self.from_chain,
            })
        {
            return Err(WalIdempotencyError::Precondition);
        }

        // (2) Exactly one epoch, and never past what this binary will drive to
        // or could build.
        if self.to_epoch != self.from_epoch.saturating_add(1)
            || self.to_epoch > self.ladder.target()
            || self.ladder.target() > self.ladder.head()
        {
            return Err(WalIdempotencyError::Precondition);
        }

        // (3) The running binary's ladder must be the ladder this plan was
        // built against. A step edited after shipping, a renumbered step, or a
        // different baseline all land here rather than being applied on top of
        // a divergent history.
        let step = self
            .ladder
            .step_at(self.to_epoch)
            .ok_or(WalIdempotencyError::Precondition)?;
        if step_digest(step) != self.step_digest
            || self.ladder.chain_digest(self.from_epoch) != self.from_chain
            || self.ladder.chain_digest(self.to_epoch) != self.to_chain
        {
            return Err(WalIdempotencyError::Precondition);
        }

        // (4) ASSERTED, never set. `PRAGMA foreign_keys` is silently ignored
        // inside a transaction, so setting it here would yield exactly nothing
        // while the author believed they were protected.
        let foreign_keys: i64 = transaction
            .query_row("PRAGMA foreign_keys", [], |row| row.get(0))
            .map_err(|_| WalIdempotencyError::Unavailable)?;
        if foreign_keys != 1 {
            return Err(WalIdempotencyError::Precondition);
        }

        // (5) Pre-state pin: the archive must already be verbatim what this
        // binary builds at `from_epoch`, or the step is about to run against a
        // schema nobody described.
        let canonical_from = self
            .ladder
            .build_canonical(self.from_epoch)
            .map_err(|_| WalIdempotencyError::Unavailable)?;
        if product_descriptor(transaction)? != product_descriptor(&canonical_from)? {
            return Err(WalIdempotencyError::Precondition);
        }

        // (6) One `execute_batch`, aborting on the first error.
        //
        // Note precisely what this does and does not buy. It does NOT provide
        // the all-or-nothing guarantee — the enclosing transaction does, and a
        // statement-by-statement loop inside the same transaction would roll
        // back just as completely (measured, by sabotaging it). What it buys is
        // that the step is executed as ONE unit of text, the same call
        // `apply_each` makes on the canonical side, so the two sides cannot
        // diverge by executing the same SQL differently.
        //
        // The thing that would actually break convergence is committing
        // mid-apply. Never do that here: `apply` must leave the transaction
        // exactly as it found it or fail.
        transaction
            .execute_batch(step.sql)
            .map_err(|_| WalIdempotencyError::Unavailable)?;

        // (7) Post-state pin. This single check subsumes every worry about
        // quoting, whitespace, column position and index reproduction: the
        // archive's text must equal the canonical's text, byte for byte.
        let canonical_to = self
            .ladder
            .build_canonical(self.to_epoch)
            .map_err(|_| WalIdempotencyError::Unavailable)?;
        if product_descriptor(transaction)? != product_descriptor(&canonical_to)? {
            return Err(WalIdempotencyError::Corrupt);
        }

        // (8) The step must not have orphaned a reference.
        let violations: i64 = transaction
            .query_row("SELECT COUNT(*) FROM pragma_foreign_key_check", [], |row| {
                row.get(0)
            })
            .map_err(|_| WalIdempotencyError::Unavailable)?;
        if violations != 0 {
            return Err(WalIdempotencyError::Corrupt);
        }

        // (9) Settle the marker in the SAME transaction, from the plan's own
        // recorded `to_chain` rather than a recomputation.
        crate::schema_ladder::write_epoch_marker(transaction, self.to_epoch, self.to_chain)
            .map_err(|_| WalIdempotencyError::Corrupt)?;
        let settled = crate::schema_ladder::read_archive_epoch(transaction)
            .map_err(|_| WalIdempotencyError::Corrupt)?;
        if settled
            != (ArchiveEpoch {
                epoch: self.to_epoch,
                chain: self.to_chain,
            })
        {
            return Err(WalIdempotencyError::Corrupt);
        }

        // (10)
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

/// The product half of [`crate::store::schema_descriptor`].
///
/// This is deliberately **not** a second descriptor query. It calls the one
/// shared descriptor the read path uses and then removes exactly one named
/// namespace from both sides of the comparison: `archive_v3_wal_*`, the
/// bookkeeping tables every WAL family creates inside its own apply
/// transaction — including this family's, which `ensure_schema` has already
/// created by the time `apply` runs.
///
/// Comparing that namespace would make the equality **unsatisfiable** for any
/// archive that has ever run a settled WAL commit, i.e. every archive this
/// plan can possibly be presented with. The exclusion is paid for by the
/// closed-world check below: anything outside the product schema that is not a
/// well-formed WAL-domain name is `Corrupt`, so the excluded set can never
/// become a hiding place.
fn product_descriptor(conn: &Connection) -> Result<Vec<crate::store::SchemaDescriptorRow>> {
    let rows =
        crate::store::schema_descriptor(conn).map_err(|_| WalIdempotencyError::Unavailable)?;
    let mut product = Vec::with_capacity(rows.len());
    for row in rows {
        let (_, name, table, _) = &row;
        let wal_named = is_wal_domain_name(name);
        if wal_named != is_wal_domain_name(table) {
            // A product object attached to a WAL-domain table, or the reverse.
            // Neither side of the comparison can describe that.
            return Err(WalIdempotencyError::Corrupt);
        }
        if wal_named {
            continue;
        }
        product.push(row);
    }
    Ok(product)
}

/// A WAL bookkeeping object name: the prefix plus a strictly lowercase
/// `snake_case` tail. Closed-world on purpose — a name that merely *starts*
/// with the prefix but is otherwise arbitrary is refused rather than excluded.
fn is_wal_domain_name(name: &str) -> bool {
    name.strip_prefix(WAL_DOMAIN_PREFIX).is_some_and(|tail| {
        !tail.is_empty()
            && tail
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
    })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum LedgerSchemaState {
    Absent,
    Present,
}

impl WalLogicalDomainLedger<SchemaEpochAdvancePlan> for SchemaEpochAdvanceLedger {
    fn lookup(
        connection: &Connection,
        prepared: &PreparedLogicalMutation<SchemaEpochAdvancePlan>,
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
                 FROM archive_v3_wal_schema_epoch_operations
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
        let kind = WalOperationKind::SchemaEpochAdvance;
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
        prepared: &PreparedLogicalMutation<SchemaEpochAdvancePlan>,
    ) -> Result<LogicalMutationResult> {
        require_kind(prepared)?;
        ensure_schema(transaction)?;
        if let Some(result) = Self::lookup(transaction, prepared)? {
            return Ok(LogicalMutationResult::Replayed(result));
        }
        let (row_count, result_bytes) = load_ledger_state(transaction)?;
        BOUNDS.admit(row_count, result_bytes, ENCODED_UNIT_RESULT_BYTES)?;
        let kind = WalOperationKind::SchemaEpochAdvance;
        let result = prepared.plan_for_domain_ledger().apply(transaction)?;
        prepared.plan_for_domain_ledger().validate_replay(&result)?;
        let encoded = result.encode(kind)?;
        if encoded.len() != ENCODED_UNIT_RESULT_BYTES {
            return Err(WalIdempotencyError::Corrupt);
        }
        let commitment = result.commitment(kind)?;
        transaction
            .execute(
                "INSERT INTO archive_v3_wal_schema_epoch_operations
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
                "UPDATE archive_v3_wal_schema_epoch_state
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

fn require_kind(prepared: &PreparedLogicalMutation<SchemaEpochAdvancePlan>) -> Result<()> {
    if prepared.kind_for_owner() != WalOperationKind::SchemaEpochAdvance {
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
                    "CREATE TABLE archive_v3_wal_schema_epoch_schema (
                        singleton INTEGER PRIMARY KEY CHECK(singleton=1),
                        format_version INTEGER NOT NULL CHECK(format_version=1),
                        codec_version INTEGER NOT NULL CHECK(codec_version=1)
                     ) STRICT;
                     CREATE TABLE archive_v3_wal_schema_epoch_operations (
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
                     CREATE TABLE archive_v3_wal_schema_epoch_state (
                        singleton INTEGER PRIMARY KEY CHECK(singleton=1),
                        row_count INTEGER NOT NULL CHECK(row_count BETWEEN 0 AND 1024),
                        result_bytes INTEGER NOT NULL CHECK(result_bytes BETWEEN 0 AND 9216)
                     ) STRICT;
                     INSERT INTO archive_v3_wal_schema_epoch_schema
                        (singleton,format_version,codec_version) VALUES (1,1,1);
                     INSERT INTO archive_v3_wal_schema_epoch_state
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
             FROM archive_v3_wal_schema_epoch_schema WHERE singleton=1",
            [],
            |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)),
        )
        .optional()
        .map_err(|_| WalIdempotencyError::Corrupt)?;
    if marker
        != Some((
            i64::from(WalOperationKind::format_version()),
            i64::from(WalOperationKind::SchemaEpochAdvance.codec_version()),
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
             FROM archive_v3_wal_schema_epoch_state WHERE singleton=1",
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

// ── The driver ────────────────────────────────────────────────────────────

/// What one call to [`advance_one_epoch`] did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum AdvanceOutcome {
    /// The archive is already at (or beyond) this binary's target. Nothing was
    /// submitted.
    AlreadyAtTarget(u32),
    /// The archive moved from `from` to `to`. Exactly one epoch.
    Advanced { from: u32, to: u32 },
    /// This binary cannot describe the archive's recorded epoch, so it must
    /// not drive it. Never an advance, never a repair.
    RefusedNotServable(u32),
}

/// The decision the driver takes from the marker alone: `Some(outcome)` when
/// nothing may be submitted, `None` when an advance should be planned.
///
/// Extracted so the decision is testable without a serving authority, and so
/// the two reasons for not submitting stay visibly distinct: "there is nothing
/// to do" and "this binary must not touch this archive" are different facts
/// and must never collapse into one.
fn decide_from_marker(marker: ArchiveEpoch, ladder: LadderView) -> Option<AdvanceOutcome> {
    // Servability first. An archive this binary cannot describe must be
    // refused even when its epoch happens to sit at or above the target —
    // reporting `AlreadyAtTarget` for an archive whose chain is not this
    // binary's baseline would report success for an archive that must not be
    // served at all.
    if ladder.validate_servable(marker).is_err() {
        return Some(AdvanceOutcome::RefusedNotServable(marker.epoch));
    }
    // `>=`, not `==`: an archive a newer binary already advanced past this
    // binary's target must not be driven. This is a refusal to ACT, never a
    // relaxed precondition — `apply`'s check (2) keeps its strict
    // `to_epoch <= target` and is what would refuse the plan if one were built.
    if marker.epoch >= ladder.target() {
        return Some(AdvanceOutcome::AlreadyAtTarget(marker.epoch));
    }
    None
}

/// Advance ONE archive by exactly ONE epoch, or report it is already there.
///
/// The caller loops until [`AdvanceOutcome::AlreadyAtTarget`] or
/// [`AdvanceOutcome::RefusedNotServable`]. Never advances more than one epoch
/// per call — see the module docs for why one plan per step is load-bearing.
///
/// `from_epoch` comes from the marker and from nothing else: never from a
/// `MAX`, a `COUNT`, a file measurement, or a config value. The marker is the
/// only thing that knows where this archive actually is.
pub(crate) async fn advance_one_epoch(
    store: &crate::store::Store,
    user_id: &str,
) -> crate::error::Result<AdvanceOutcome> {
    let ladder = LadderView::PRODUCTION;
    // ONE routed read, reading the marker and nothing else. A second read
    // would open a window in which the epoch this plan is built for is not the
    // epoch the plan is submitted against.
    let marker = store
        .wal_authoritative_read(user_id, move |conn| {
            crate::schema_ladder::read_archive_epoch(conn)
        })
        .await?;

    if let Some(outcome) = decide_from_marker(marker, ladder) {
        return Ok(outcome);
    }

    let from = marker.epoch;
    // Constructed ONCE. The Conflict arm re-prepares this same plan, so the
    // operation id and the request fingerprint are byte-identical and the
    // resubmission is a replay rather than a new operation.
    let plan = SchemaEpochAdvancePlan::new(user_id.to_owned(), from).map_err(|_| {
        crate::error::EnclaveError::Store("schema epoch advance plan construction failed".into())
    })?;
    let to = plan.advances_to();
    let retry = plan.clone();
    let prepared = PreparedLogicalMutation::prepare(plan).map_err(|_| {
        crate::error::EnclaveError::Store("schema epoch advance plan construction failed".into())
    })?;
    match store.wal_authoritative_submit(user_id, prepared).await {
        Err(crate::error::EnclaveError::Conflict(_)) => {
            let prepared = PreparedLogicalMutation::prepare(retry).map_err(|_| {
                crate::error::EnclaveError::Store(
                    "schema epoch advance plan construction failed".into(),
                )
            })?;
            store.wal_authoritative_submit(user_id, prepared).await?;
        }
        other => other?,
    }
    Ok(AdvanceOutcome::Advanced { from, to })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::archive_v3_wal_idempotency::{
        execute_prepared_for_owner, LogicalMutationDisposition,
    };
    use crate::schema_ladder::{
        chain_digest, read_archive_epoch, seed_epoch_marker, SchemaStep, StepClass,
        SCHEMA_EPOCH_TARGET,
    };

    const ACCOUNT: &str = "11111111-1111-4111-8111-111111111111";
    /// A second account id, used ONLY to force a ledger miss so that a
    /// precondition inside `apply` is what refuses, rather than the replay
    /// path short-circuiting before `apply` ever runs.
    const OTHER: &str = "22222222-2222-4222-8222-222222222222";

    /// The reviewed candidate for ladder step 1, verbatim.
    ///
    /// `advance_contiguous_ack` (`src/cp/media.rs`) probes
    /// `capture_events WHERE stream_id=?1 AND sequence=?2` in a loop on every
    /// capture-event ingest. The table's `UNIQUE(device_id, stream_id,
    /// sequence)` cannot serve that predicate — its leading column is
    /// `device_id`, which the query never binds — so each probe is a full
    /// scan of a table that has no production `DELETE` and therefore only
    /// grows. This is a real want, not a placeholder.
    ///
    /// It is NOT `UNIQUE`: nothing in the schema forces `capture_events.
    /// device_id` to agree with its stream's device, so a unique step could
    /// fail at apply time on a live archive. A ladder step must never be able
    /// to do that.
    const STEP_ONE_SQL: &str =
        "CREATE INDEX idx_capture_events_stream_sequence ON capture_events (stream_id, sequence);";

    const LADDER_ONE: &[SchemaStep] = &[SchemaStep {
        epoch: 1,
        id: "0001_capture_events_stream_sequence",
        class: StepClass::Index,
        sql: STEP_ONE_SQL,
    }];

    /// The same step id and epoch, one byte of SQL different. Stands in for a
    /// shipped step that was edited afterwards.
    const LADDER_ONE_EDITED: &[SchemaStep] = &[SchemaStep {
        epoch: 1,
        id: "0001_capture_events_stream_sequence",
        class: StepClass::Index,
        sql: "CREATE INDEX idx_capture_events_stream_sequence ON capture_events (stream_id, sequence) ;",
    }];

    /// A step whose batch fails on its second statement (duplicate index
    /// name). Only a fixture can be this: a shipped step that fails would be
    /// a defect, so the rollback property is untestable without one.
    const LADDER_BROKEN: &[SchemaStep] = &[SchemaStep {
        epoch: 1,
        id: "0001_broken",
        class: StepClass::Index,
        sql: "CREATE INDEX idx_probe_rollback ON capture_events (stream_id);\
              CREATE INDEX idx_probe_rollback ON capture_events (sequence);",
    }];

    fn ladder(steps: &'static [SchemaStep]) -> LadderView {
        LadderView::for_test(steps, 1, 1, 0)
    }

    /// A real archive at epoch 0: the frozen baseline plus the birth witness,
    /// exactly what genesis materializes.
    fn archive_at_epoch_zero() -> Connection {
        let conn = crate::schema_ladder::build_canonical(0).unwrap();
        conn.execute_batch("PRAGMA foreign_keys = ON;").unwrap();
        seed_epoch_marker(&conn, 0).unwrap();
        conn
    }

    fn settle(
        connection: &mut Connection,
        plan: SchemaEpochAdvancePlan,
    ) -> Result<LogicalMutationDisposition> {
        let prepared = PreparedLogicalMutation::prepare(plan)?;
        execute_prepared_for_owner(connection, prepared).map(|outcome| outcome.disposition())
    }

    fn index_exists(conn: &Connection, name: &str) -> bool {
        conn.query_row(
            "SELECT COUNT(*) FROM sqlite_schema WHERE type='index' AND name=?1",
            [name],
            |row| row.get::<_, i64>(0),
        )
        .unwrap()
            == 1
    }

    // ── The whole loop: 0 → 1, canonical match, no-op at 1 ────────────────

    #[test]
    fn an_archive_advances_from_epoch_zero_to_one_and_matches_the_canonical_verbatim() {
        let view = ladder(LADDER_ONE);
        let mut archive = archive_at_epoch_zero();

        // Pre-state. The marker is the birth witness and the step's object
        // does not exist yet.
        assert_eq!(
            read_archive_epoch(&archive).unwrap(),
            ArchiveEpoch {
                epoch: 0,
                chain: view.chain_digest(0)
            }
        );
        assert!(!index_exists(
            &archive,
            "idx_capture_events_stream_sequence"
        ));

        let plan = SchemaEpochAdvancePlan::over_ladder(ACCOUNT.into(), 0, view).unwrap();
        assert_eq!(plan.advances_from(), 0);
        assert_eq!(plan.advances_to(), 1);
        assert_eq!(
            settle(&mut archive, plan).unwrap(),
            LogicalMutationDisposition::Applied
        );

        // The marker AND the chain digest moved, together, in that commit.
        let marker = read_archive_epoch(&archive).unwrap();
        assert_eq!(marker.epoch, 1);
        assert_eq!(marker.chain, view.chain_digest(1));
        assert_ne!(
            view.chain_digest(1),
            view.chain_digest(0),
            "a step that does not move the chain would make the marker \
             unable to distinguish the epochs it certifies"
        );
        assert!(index_exists(&archive, "idx_capture_events_stream_sequence"));

        // A canonical build at epoch 1 matches the live archive VERBATIM.
        // This is the driver's own post-state pin, re-asserted from outside.
        let canonical = view.build_canonical(1).unwrap();
        assert_eq!(
            product_descriptor(&archive).unwrap(),
            product_descriptor(&canonical).unwrap(),
            "a live archive and a canonical build must reach epoch 1 by the \
             identical statement text in the identical order"
        );

        // And the delta versus epoch 0 is EXACTLY the intended object.
        let before = product_descriptor(&view.build_canonical(0).unwrap()).unwrap();
        let after = product_descriptor(&canonical).unwrap();
        let added: Vec<_> = after.iter().filter(|row| !before.contains(row)).collect();
        assert_eq!(added.len(), 1, "the step added more than the one object");
        assert_eq!(added[0].0, "index");
        assert_eq!(added[0].1, "idx_capture_events_stream_sequence");
        assert!(
            before.iter().all(|row| after.contains(row)),
            "a step is additive: nothing may disappear"
        );
    }

    #[test]
    fn an_archive_already_at_the_target_is_a_no_op() {
        let view = ladder(LADDER_ONE);
        let mut archive = archive_at_epoch_zero();
        let build = || SchemaEpochAdvancePlan::over_ladder(ACCOUNT.into(), 0, view).unwrap();
        assert_eq!(
            settle(&mut archive, build()).unwrap(),
            LogicalMutationDisposition::Applied
        );
        let settled = product_descriptor(&archive).unwrap();
        let marker = read_archive_epoch(&archive).unwrap();

        // (a) The driver never even submits: the marker says it is there.
        assert_eq!(
            decide_from_marker(marker, view),
            Some(AdvanceOutcome::AlreadyAtTarget(1))
        );

        // (b) And if the identical plan IS re-presented, the ledger replays it
        // rather than re-running the step. Nothing is rewritten.
        assert_eq!(
            settle(&mut archive, build()).unwrap(),
            LogicalMutationDisposition::Replayed
        );
        assert_eq!(product_descriptor(&archive).unwrap(), settled);
        assert_eq!(read_archive_epoch(&archive).unwrap(), marker);
    }

    // ── The `from_epoch` precondition ────────────────────────────────────

    #[test]
    fn a_second_application_of_a_shipped_step_is_refused() {
        // The exact-CAS half of check (1). The distinct account id exists only
        // to miss the ledger, so `apply` actually runs and its own precondition
        // is what refuses — otherwise this test would silently be a second
        // copy of the replay test above.
        let view = ladder(LADDER_ONE);
        let mut archive = archive_at_epoch_zero();
        settle(
            &mut archive,
            SchemaEpochAdvancePlan::over_ladder(ACCOUNT.into(), 0, view).unwrap(),
        )
        .unwrap();
        let settled = product_descriptor(&archive).unwrap();

        let again = SchemaEpochAdvancePlan::over_ladder(OTHER.into(), 0, view).unwrap();
        assert_eq!(
            settle(&mut archive, again).unwrap_err(),
            WalIdempotencyError::Precondition,
            "a step must never apply twice"
        );
        // Nothing was re-applied.
        assert_eq!(product_descriptor(&archive).unwrap(), settled);
        assert_eq!(read_archive_epoch(&archive).unwrap().epoch, 1);
    }

    #[test]
    fn a_marker_ahead_of_the_schema_is_refused_rather_than_silently_repaired() {
        // This is what ISOLATES check (1). Softening the exact CAS to an
        // epoch-only `>=` is NOT caught by the end-to-end test above: there,
        // check (5)'s pre-state pin refuses second, because an
        // already-advanced archive no longer matches `build_canonical(0)`.
        // Layered refusal is a good property, but it means that test cannot
        // pin check (1) on its own.
        //
        // Here the marker and the schema disagree: the marker says epoch 1,
        // the schema is still epoch 0. The pre-state pin therefore PASSES, and
        // check (1) is the only thing standing between a refusal and silently
        // "repairing" an archive whose recorded history nobody can vouch for.
        let view = ladder(LADDER_ONE);
        let mut archive = archive_at_epoch_zero();
        crate::schema_ladder::write_epoch_marker(&archive, 1, view.chain_digest(1)).unwrap();

        // Precondition for the precondition: the schema really is still at 0,
        // so check (5) has nothing to complain about.
        assert_eq!(
            product_descriptor(&archive).unwrap(),
            product_descriptor(&view.build_canonical(0).unwrap()).unwrap()
        );

        let plan = SchemaEpochAdvancePlan::over_ladder(ACCOUNT.into(), 0, view).unwrap();
        assert_eq!(
            settle(&mut archive, plan).unwrap_err(),
            WalIdempotencyError::Precondition
        );
        assert!(!index_exists(
            &archive,
            "idx_capture_events_stream_sequence"
        ));
        assert_eq!(read_archive_epoch(&archive).unwrap().epoch, 1);
    }

    #[test]
    fn a_marker_whose_chain_is_not_the_plans_from_chain_is_refused() {
        // The other half of check (1): the CAS covers the chain, not only the
        // epoch number. An archive sitting at epoch 0 of some OTHER history
        // must not be advanced onto this one.
        let view = ladder(LADDER_ONE);
        let mut archive = archive_at_epoch_zero();
        archive
            .execute(
                "UPDATE schema_epoch SET chain_digest=?1 WHERE singleton=1",
                [&[0x5a_u8; 32][..]],
            )
            .unwrap();
        let plan = SchemaEpochAdvancePlan::over_ladder(ACCOUNT.into(), 0, view).unwrap();
        assert_eq!(
            settle(&mut archive, plan).unwrap_err(),
            WalIdempotencyError::Precondition
        );
        assert!(!index_exists(
            &archive,
            "idx_capture_events_stream_sequence"
        ));
    }

    #[test]
    fn an_archive_with_no_birth_witness_is_refused() {
        let view = ladder(LADDER_ONE);
        let mut archive = crate::schema_ladder::build_canonical(0).unwrap();
        archive.execute_batch("PRAGMA foreign_keys = ON;").unwrap();
        // No `seed_epoch_marker`: the shape a pre-re-baseline binary leaves.
        let plan = SchemaEpochAdvancePlan::over_ladder(ACCOUNT.into(), 0, view).unwrap();
        assert_eq!(
            settle(&mut archive, plan).unwrap_err(),
            WalIdempotencyError::Precondition,
            "an absent marker must refuse, never be coerced to epoch 0"
        );
    }

    // ── A step edited after shipping ─────────────────────────────────────

    #[test]
    fn a_step_edited_after_shipping_is_refused_and_diverges_from_the_canonical() {
        let original = ladder(LADDER_ONE);
        let edited = ladder(LADDER_ONE_EDITED);

        // The digests and chains actually differ, or the rest proves nothing.
        assert_ne!(original.chain_digest(1), edited.chain_digest(1));

        let mut archive = archive_at_epoch_zero();
        settle(
            &mut archive,
            SchemaEpochAdvancePlan::over_ladder(ACCOUNT.into(), 0, original).unwrap(),
        )
        .unwrap();

        // Same account, same epochs, same step id -> the SAME operation id,
        // but a different request. The ledger refuses it as a fingerprint
        // conflict rather than applying an edited step on top of a history
        // that recorded the original.
        let tampered = SchemaEpochAdvancePlan::over_ladder(ACCOUNT.into(), 0, edited).unwrap();
        assert_eq!(
            tampered.operation_id().as_bytes(),
            SchemaEpochAdvancePlan::over_ladder(ACCOUNT.into(), 0, original)
                .unwrap()
                .operation_id()
                .as_bytes()
        );
        assert_eq!(
            settle(&mut archive, tampered).unwrap_err(),
            WalIdempotencyError::FingerprintConflict
        );

        // And the text-equality property is what makes that mandatory: an
        // archive advanced by the original does NOT match a canonical built
        // from the edited ladder.
        assert_ne!(
            product_descriptor(&archive).unwrap(),
            product_descriptor(&edited.build_canonical(1).unwrap()).unwrap()
        );
        assert_eq!(
            product_descriptor(&archive).unwrap(),
            product_descriptor(&original.build_canonical(1).unwrap()).unwrap()
        );
    }

    // ── Crash convergence ────────────────────────────────────────────────

    #[test]
    fn a_step_that_fails_mid_batch_leaves_the_archive_exactly_where_it_was() {
        // Crash point: mid-apply. One transaction, DDL included, so the step,
        // the marker upsert and the ledger row are all-or-nothing. The archive
        // stays at `from_epoch` and the driver simply retries.
        let view = ladder(LADDER_BROKEN);
        let mut archive = archive_at_epoch_zero();
        let before = product_descriptor(&archive).unwrap();

        let plan = SchemaEpochAdvancePlan::over_ladder(ACCOUNT.into(), 0, view).unwrap();
        assert!(settle(&mut archive, plan).is_err());

        // Exactly at `from_epoch`, with no residue anywhere.
        assert_eq!(read_archive_epoch(&archive).unwrap().epoch, 0);
        assert_eq!(product_descriptor(&archive).unwrap(), before);
        assert!(!index_exists(&archive, "idx_probe_rollback"));
        // Not even the ledger's own bookkeeping tables survived: they are
        // created inside the same transaction.
        assert_eq!(schema_state(&archive).unwrap(), LedgerSchemaState::Absent);
        let integrity: String = archive
            .query_row("PRAGMA integrity_check", [], |row| row.get(0))
            .unwrap();
        assert_eq!(integrity, "ok");

        // Convergence: a good step still advances the same archive afterwards.
        let good = ladder(LADDER_ONE);
        settle(
            &mut archive,
            SchemaEpochAdvancePlan::over_ladder(ACCOUNT.into(), 0, good).unwrap(),
        )
        .unwrap();
        assert_eq!(read_archive_epoch(&archive).unwrap().epoch, 1);
    }

    // ── The driver's decision ────────────────────────────────────────────

    #[test]
    fn the_driver_refuses_an_archive_it_cannot_describe_and_never_calls_it_done() {
        let view = ladder(LADDER_ONE);
        let foreign = ArchiveEpoch {
            epoch: 1,
            chain: [0x77; 32],
        };
        assert_eq!(
            decide_from_marker(foreign, view),
            Some(AdvanceOutcome::RefusedNotServable(1)),
            "an archive whose chain is not this binary's must be refused even \
             when its epoch sits at the target"
        );
        let above = ArchiveEpoch {
            epoch: 2,
            chain: view.chain_digest(2),
        };
        assert_eq!(
            decide_from_marker(above, view),
            Some(AdvanceOutcome::RefusedNotServable(2))
        );
        // The servable epoch below target is the only case that plans.
        assert_eq!(
            decide_from_marker(
                ArchiveEpoch {
                    epoch: 0,
                    chain: view.chain_digest(0)
                },
                view
            ),
            None
        );
    }

    #[test]
    fn the_production_driver_is_a_no_op_while_the_ladder_is_empty() {
        // The shipped configuration, asserted rather than assumed: with
        // SCHEMA_LADDER empty and every epoch constant 0, a genesis-born
        // archive is already at target and nothing is ever submitted.
        let conn = archive_at_epoch_zero();
        let marker = read_archive_epoch(&conn).unwrap();
        assert_eq!(marker.chain, chain_digest(0));
        assert_eq!(
            decide_from_marker(marker, LadderView::PRODUCTION),
            Some(AdvanceOutcome::AlreadyAtTarget(SCHEMA_EPOCH_TARGET))
        );
        // And no plan can be constructed against it, so the family cannot
        // move an archive by accident before a step ships.
        assert!(SchemaEpochAdvancePlan::new(ACCOUNT.into(), 0).is_err());
    }

    // ── The descriptor exclusion ─────────────────────────────────────────

    #[test]
    fn the_wal_namespace_exclusion_is_load_bearing_and_closed_world() {
        // After one settled commit the archive carries this family's three
        // bookkeeping tables. The SHARED descriptor therefore no longer
        // matches a canonical build — which is exactly why the epoch
        // comparison is taken over the product half.
        let view = ladder(LADDER_ONE);
        let mut archive = archive_at_epoch_zero();
        settle(
            &mut archive,
            SchemaEpochAdvancePlan::over_ladder(ACCOUNT.into(), 0, view).unwrap(),
        )
        .unwrap();
        let canonical = view.build_canonical(1).unwrap();
        assert_ne!(
            crate::store::schema_descriptor(&archive).unwrap(),
            crate::store::schema_descriptor(&canonical).unwrap(),
            "if these matched, the exclusion would be dead code"
        );
        assert_eq!(
            product_descriptor(&archive).unwrap(),
            product_descriptor(&canonical).unwrap()
        );

        // Closed world: the excluded set admits only well-formed WAL-domain
        // names, so it can never become a hiding place for product schema.
        assert!(is_wal_domain_name("archive_v3_wal_schema_epoch_state"));
        assert!(!is_wal_domain_name("archive_v3_wal_"));
        assert!(!is_wal_domain_name("archive_v3_walrus_Cache"));
        assert!(!is_wal_domain_name("archive_v3_wal_Mixed"));
        assert!(!is_wal_domain_name("capture_events"));

        // An object whose own name is product but whose table is WAL-domain
        // (or the reverse) is refused, not silently dropped by one side.
        archive
            .execute_batch(
                "CREATE INDEX smuggled ON archive_v3_wal_schema_epoch_state (row_count);",
            )
            .unwrap();
        assert_eq!(
            product_descriptor(&archive).unwrap_err(),
            WalIdempotencyError::Corrupt
        );
    }

    #[test]
    fn the_plan_refuses_to_be_built_for_an_epoch_the_ladder_cannot_reach() {
        let view = ladder(LADDER_ONE);
        // Past the target.
        assert_eq!(
            SchemaEpochAdvancePlan::over_ladder(ACCOUNT.into(), 1, view).unwrap_err(),
            WalIdempotencyError::Precondition
        );
        // And an unusable account id never produces a plan at all.
        // `validate_user_id` admits `[A-Za-z0-9_-]{1,128}`, so the rejected
        // shapes are the empty id and one carrying anything outside that set.
        for bad in ["", "has space", "semi;colon"] {
            assert_eq!(
                SchemaEpochAdvancePlan::over_ladder(bad.into(), 0, view).unwrap_err(),
                WalIdempotencyError::Malformed,
                "account id {bad:?} must not produce a plan"
            );
        }
    }

    #[test]
    fn the_canonical_request_binds_every_committed_field() {
        let view = ladder(LADDER_ONE);
        let plan = SchemaEpochAdvancePlan::over_ladder(ACCOUNT.into(), 0, view).unwrap();
        let request = plan.canonical_request().unwrap();
        for field in [
            &plan.step_digest[..],
            &plan.from_chain[..],
            &plan.to_chain[..],
            SUBTYPE,
            ACCOUNT.as_bytes(),
            plan.step_id.as_bytes(),
        ] {
            assert!(
                request.windows(field.len()).any(|window| window == field),
                "a committed field is missing from the canonical request"
            );
        }
        // Byte-exact replay: the request is a pure function of the plan, so
        // rebuilding the identical plan reproduces it exactly. Nothing here
        // reads a clock.
        let again = SchemaEpochAdvancePlan::over_ladder(ACCOUNT.into(), 0, view).unwrap();
        assert_eq!(&request[..], &again.canonical_request().unwrap()[..]);
    }
}
