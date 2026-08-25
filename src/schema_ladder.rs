#![allow(
    dead_code,
    reason = "ADR-0022 schema epoch ladder: the frozen baseline, phased declarations, and owner-side driver deliberately land before every surface is live"
)]

//! Append-only product schema ladder.
//!
//! # Why this exists
//!
//! Once an archive is WAL-authoritative the owner *pins* its schema: it opens
//! the database, runs the baseline DDL, and refuses if that mutated anything
//! (`migration_dirty`), while parity independently compares the exact
//! plaintext SHA-256. There is no schema-advance path anywhere, so shipping a
//! product `ALTER TABLE` after the first archive exists would make every
//! migrated user's enclave refuse to open their database — permanently, until
//! the change is reverted.
//!
//! The ladder is how product schema evolves without weakening either check:
//! the epoch-0 baseline (`SCHEMA_SQL` + `run_migrations` in [`crate::store`])
//! is **frozen**, and every future DDL statement is appended here as a
//! numbered step which the owner later applies under its own lease, publishing
//! the change as an ordinary settled WAL commit.
//!
//! # The property that makes it safe
//!
//! A canonical database and a live archive both reach epoch `E` by executing
//! **the identical statement text in the identical order**: the baseline, then
//! steps `1..=E`. Schema comparison is verbatim on `sqlite_schema.sql`, so
//! sameness of the *statements* is what guarantees sameness of the *text*.
//!
//! Editing the baseline breaks that in one of two ways, and which one you get
//! is not up to you:
//!
//! - **Edit the baseline alone.** Archives already built carry the old text
//!   and have no way to advance; a canonical rebuild now produces the new
//!   text. Every existing archive fails its schema comparison.
//! - **Edit the baseline *and* append the equivalent step.** The step now runs
//!   against a baseline that already has the column and fails outright —
//!   SQLite raises `duplicate column name`, so `build_canonical` errors and
//!   every archive is refused.
//!
//! Note that these are the hazards, *not* a general claim that an
//! ALTER-produced text differs from a hand-written one. SQLite splices an
//! ALTER-added column in verbatim before the closing paren, so the two texts
//! coincide exactly when the developer happens to write the same column, in
//! the same words, in last position — and diverge as soon as they don't
//! (a different position or different spacing is enough). The freeze is what
//! makes the question moot instead of a coin flip, and the gate enforces it.
//!
//! # Production phase declaration
//!
//! The ladder and its three epoch constants move through the ordered releases
//! in the runbook below. Their declarations live in one explicitly delimited
//! source region; runtime logic, documentation, and tests outside that region
//! are phase-generic. `BASELINE_DIGEST` fixes the epoch-0 text in every phase,
//! and the gate fails the build if anyone edits it.
//!
//! # The one-time non-additive sweep (2026-08-21)
//!
//! The sealed re-baseline is the **last** moment a non-additive baseline
//! defect is fixable: after the seal the only expressible change is an
//! additive ladder step, and `AUTOINCREMENT`, a dropped column, a relaxed
//! CHECK and a changed DEFAULT are all non-additive. So all four frozen DDL
//! sources were swept once, deliberately, while the window was open. What the
//! sweep found and what was decided:
//!
//! - **Allocator ids that are deleted from.** Exactly three:
//!   `audio_segments`, `utterances`, `screenshots`. All three now carry
//!   `AUTOINCREMENT`. Every other plain `INTEGER PRIMARY KEY` in the baseline
//!   is a *borrowed* key (`screenshot_id`/`episode_id` on a cascade child) or
//!   a projection mirror (`mcp_safe_*`, whose id is copied from its source
//!   row); none of them allocates, so `AUTOINCREMENT` would be wrong there,
//!   and the mirrors inherit non-reuse from the source tables above.
//!   `browser_snapshots` and `episodes` already had it — the baseline was
//!   internally inconsistent, and this is what made it consistent.
//! - **Foreign keys with no explicit `ON DELETE`.** None. Every `REFERENCES`
//!   in all four sources already names an action.
//! - **`strftime` DEFAULTs.** 42 tables carry one, and seven sealed-plan
//!   `INSERT`s still omit such a column. Deliberately **not** changed here:
//!   the fix is to bind the column in the plan, which is a plan change
//!   expressible at any time, not a baseline change. Removing a DEFAULT would
//!   be the non-additive act, and nothing wants it removed.
//! - **The duplicate dead declarations** in `cp::media::init_schema` for
//!   `audio_segments` and `utterances` are now **frozen in both directions**:
//!   they sit behind `CREATE TABLE IF NOT EXISTS` for tables `SCHEMA_SQL`
//!   already created, so they execute nothing, and they are inside the
//!   digest, so they can no longer be edited either. They happen to agree
//!   with the live baseline now that it declares `AUTOINCREMENT`. Deleting
//!   them is a separate baseline change and there will be no window for it —
//!   that is the accepted cost of leaving them.
//!
//! # RUNBOOK — adding a new table, column or index
//!
//! **This is the standing answer, and after the seal it is the only
//! procedure.** Follow it rather than reinventing one; every numbered step
//! below exists because skipping it has a specific failure mode, named
//! inline. The mechanism that executes it is
//! [`crate::cp::schema_epoch::wal::advance_one_epoch`].
//!
//! 1. **Confirm the seal.** `python3 scripts/test_schema_ladder_gate.py`
//!    passes and `scripts/schema_baseline_seal.json` reads `"sealed": true`.
//!    If it reads `false` you are inside the zero-archive window — stop and
//!    read `docs/adr/0022/zero-archive-proof.md` instead. The window is not a
//!    convenience: using it requires discharging the full proof obligation.
//!    Gate rule **G4** enforces this and will fail the build if you append a
//!    step over an unsealed baseline, because `chain_digest` anchors on
//!    `BASELINE_DIGEST` and a step over a movable anchor produces a chain that
//!    changes retroactively — every archive that recorded the old chain would
//!    be refused.
//!
//! 2. **Write the DDL as exactly one transaction-safe statement.**
//!    - New table → `CREATE TABLE <name> (...)`, [`StepClass::Table`].
//!    - New column → `ALTER TABLE <t> ADD COLUMN <c> <type>`,
//!      [`StepClass::Column`]. The column lands **last** in declaration order,
//!      and its `DEFAULT` must be a **constant**: SQLite refuses
//!      `ALTER ... ADD COLUMN` with a non-constant default, and a `strftime`
//!      default would inject a clock into a replayed plan. This program has
//!      shipped four defects of exactly that shape.
//!    - New index → `CREATE INDEX` / `CREATE UNIQUE INDEX`,
//!      [`StepClass::Index`].
//!    - Anything else — dropping a column, changing a constraint, adding
//!      `AUTOINCREMENT` to an existing table — is **not expressible**. There is
//!      no rebuild step class and there must not be one: `FORBIDDEN_STEP_SQL`
//!      in the gate rejects `drop table`, `drop index`, `drop column`,
//!      `rename to`, `rename column` and `alter table drop` for every step,
//!      and the re-baseline was chosen over a rebuild precisely so that rule
//!      would never need relaxing.
//!    - **Never write the step with `IF NOT EXISTS`.** A silently idempotent
//!      step would let a second application pass unnoticed, which is exactly
//!      what the `from_epoch` precondition exists to catch.
//!
//! 3. **Bound the step's write cost, in pages, before writing it.** A step's
//!    DDL text is small and its WAL is not: `CREATE INDEX` over a live table
//!    produces frames in proportion to the *table*. One advance commit may
//!    allocate at most `MAX_STEP_ALLOCATED_PAGES` (in
//!    [`crate::cp::schema_epoch::wal::advance`]) —
//!    1018 pages ≈ 4 MiB with today's constants, derived from the shadow
//!    capture's 8 MiB ceiling and the publication ceiling, not chosen. Above
//!    it the advance refuses, cleanly and repeatably, and **the archive never
//!    advances at all**; there is no forcing it, because a commit past the
//!    capture ceiling poisons the owner instead of failing. So estimate first:
//!    for an index, the new b-tree is roughly (rows × indexed bytes) / 4096
//!    pages, and the largest archive in the fleet is the one that decides.
//!    A step that does not fit is a step to **split or narrow** — a partial
//!    index, a narrower key — never one to ship and hope. Note this is a real
//!    ceiling on what the ladder can express, and it is deliberately the
//!    conservative side of a wedge.
//!
//! 4. **Append one [`SchemaStep`]** to [`SCHEMA_LADDER`] with
//!    `epoch: SCHEMA_EPOCH_HEAD + 1`, a fresh never-reused `id` of the form
//!    `"NNNN_snake_name"`, its class, and the SQL as a plain double-quoted Rust
//!    literal. **Never edit, reorder or renumber a shipped step** — its digest
//!    is recorded in the chain every archive carries.
//!
//!    Then **pin it in the gate**: run
//!    `python3 scripts/test_schema_ladder_gate.py --print-ladder-pins` and
//!    paste both `SEALED_STEP_DIGESTS` and `SEALED_LADDER_CHAIN_HEAD` into
//!    `scripts/test_schema_ladder_gate.py`. Gate rules **G5**/**G6** are what
//!    make "never edit a shipped step" enforceable rather than advisory: no
//!    runtime check can catch an edited step, because the plan and the running
//!    binary share one `&'static` ladder by construction, and at `from_epoch`
//!    0 the recorded chain is the bare baseline anchor and carries no step to
//!    disagree with. Recompute the pins, never transcribe them.
//!
//! 5. **Bump [`SCHEMA_EPOCH_HEAD`]** to the new epoch. Leave
//!    [`SCHEMA_EPOCH_TARGET`] and [`SCHEMA_EPOCH_MIN_SERVABLE`] alone. Ship.
//!    This deploys a binary that *knows* the step and applies nothing. The
//!    rollout gap is deliberate: the step is observed in service before
//!    anything acts on it.
//!
//! 6. **Add the four required tests:** `build_canonical(N)` succeeds; an
//!    archive advanced `N-1 → N` by the driver has a product descriptor
//!    byte-identical to `build_canonical(N)`; the descriptor delta versus
//!    `N-1` is exactly the intended object and nothing else, asserted as a
//!    diff; and **the step stays inside the page budget on an archive at the
//!    fleet's largest realistic row count**, asserted from the pager's own
//!    counters rather than from the estimate in step 3. The end-to-end tests
//!    in this module and in `crate::cp::schema_epoch::wal::advance` are
//!    written to be copied — including
//!    `a_step_that_exceeds_the_page_budget_is_refused_before_it_writes`.
//!
//! 7. **Verify the fleet is on the new binary** — every serving replica
//!    reports `SCHEMA_EPOCH_HEAD == N`. Only then, in a **second** PR, bump
//!    [`SCHEMA_EPOCH_TARGET`] to `N`. Ship.
//!
//! 8. **The driver advances each archive by one epoch** at startup, under its
//!    own lease, before request admission. Progress is observable as the
//!    `schema_epoch` row. No manual action, and no batch job: every
//!    intermediate epoch is a complete, servable state, which is the
//!    structural property a drop-and-recreate rebuild does not have.
//!
//!    An archive that does not reach the target keeps serving at the epoch it
//!    recorded and is counted `behind_target` at startup — **not**
//!    `unavailable`, because it is not. That count is the operator signal, and
//!    it is what blocks step 9.
//!
//! 9. **When every archive reports `epoch >= N`** and no binary older than the
//!    step is in service, bump [`SCHEMA_EPOCH_MIN_SERVABLE`] to `N` in a
//!    **third** PR. Only after this may reading code assume the new object
//!    exists. A non-zero `behind_target` means this step has not landed
//!    everywhere; raising the floor over it would refuse those archives.
//!
//! 10. **Until step 9 completes, product code must tolerate `epoch < N`.**
//!     Absence of the new column or table is a legal servable state. Degrade,
//!     never error.
//!
//! **Never, at any point after the seal:** edit `SCHEMA_SQL`, the
//! `run_migrations` body, `cp::media::init_schema`, or
//! `cp::mcp_projection::init_projection_schema`. All four are frozen by
//! [`BASELINE_DIGEST`], and the gate recomputes it on every run.

use rusqlite::{Connection, OptionalExtension};
use sha2::{Digest, Sha256};

use crate::error::{EnclaveError, Result};

fn epoch_marker_error(detail: &str) -> EnclaveError {
    EnclaveError::Store(format!("schema epoch marker: {detail}"))
}

/// Domain separation for every digest in this module. Changing it invalidates
/// the recorded baseline, which is exactly the intended blast radius.
const LADDER_DOMAIN: &[u8] = b"kioku.schema-ladder.v1";

/// The kinds of DDL a step may perform.
///
/// Deliberately additive-only. Dropping a column or rewriting a constraint
/// requires SQLite's twelve-step table rebuild, which rewrites unrelated
/// `sqlite_schema` text and would break the identical-text property above;
/// those changes need the separately reviewed rebuild path, not a step.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum StepClass {
    Table,
    Column,
    Index,
}

/// One append-only schema step.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct SchemaStep {
    /// Contiguous from 1. Never renumbered.
    pub(crate) epoch: u32,
    /// Stable identifier, never reused even if a step is superseded.
    pub(crate) id: &'static str,
    pub(crate) class: StepClass,
    /// Exactly one transaction-safe DDL statement.
    pub(crate) sql: &'static str,
}

/// The production phase declarations. The ladder is **append only** — editing
/// or reordering a shipped step changes its digest, which the gate rejects and
/// which a live archive would refuse. The boundary comments below must each
/// occur exactly once: reviewed release admission treats the bytes strictly
/// between them as the sole phase-mutable declaration fragment.
///
/// # The reviewed first step
///
/// ```ignore
/// SchemaStep {
///     epoch: 1,
///     id: "0001_capture_events_stream_sequence",
///     class: StepClass::Index,
///     sql: "CREATE INDEX idx_capture_events_stream_sequence \
///           ON capture_events (stream_id, sequence);",
/// }
/// ```
///
/// `cp::media::advance_contiguous_ack` probes
/// `capture_events WHERE stream_id=?1 AND sequence=?2` inside a loop, on every
/// capture-event ingest, from both insert paths. The table's
/// `UNIQUE(device_id, stream_id, sequence)` cannot serve that predicate — its
/// leading column is `device_id`, which the query never binds — so every probe
/// is a full scan, and `capture_events` has no production `DELETE`, so the
/// scanned table only grows. Deliberately **not** `UNIQUE`: nothing forces
/// `capture_events.device_id` to agree with its stream's device, so a unique
/// step could fail at apply time on a live archive, and a step must never be
/// able to do that. An index also needs no "tolerate `epoch < N`" branch in
/// product code, which makes it the cheapest possible first rung of the
/// runbook above.
// ADR0022_SCHEMA_PHASE_DECLARATION_BEGIN
pub(crate) const SCHEMA_LADDER: &[SchemaStep] = &[];

pub(crate) const SCHEMA_EPOCH_HEAD: u32 = 0;

pub(crate) const SCHEMA_EPOCH_TARGET: u32 = 0;

pub(crate) const SCHEMA_EPOCH_MIN_SERVABLE: u32 = 0;
// ADR0022_SCHEMA_PHASE_DECLARATION_END

// Enforced at compile time rather than in a test: a binary must never be asked
// to drive an archive past what it knows how to build, and must never refuse to
// serve an epoch it is itself willing to create. These remain load-bearing in
// every release phase, including phases in which one or more values are zero.
#[allow(
    clippy::absurd_extreme_comparisons,
    reason = "the reviewed phase constants may include zero; the ordering assertion remains mandatory"
)]
const _: () = assert!(SCHEMA_EPOCH_TARGET <= SCHEMA_EPOCH_HEAD);
#[allow(
    clippy::absurd_extreme_comparisons,
    reason = "the reviewed phase constants may include zero; the ordering assertion remains mandatory"
)]
const _: () = assert!(SCHEMA_EPOCH_MIN_SERVABLE <= SCHEMA_EPOCH_TARGET);

/// One coherent (ladder, epoch-constants) pair.
///
/// [`LadderView::PRODUCTION`] is the only view any production path ever names,
/// and every free function below is a thin binding to it, so production
/// behaviour is byte-for-byte what it was before this type existed. The type
/// is a strict generalisation, never a relaxation: it adds no way to reach a
/// different ladder from production code.
///
/// # Why the seam exists
///
/// The test-only constructor keeps coverage independent of whichever phase is
/// currently declared. A fixture view carries multiple real steps and its own
/// epoch constants, and the advance plan, the driver, the canonical builder
/// and the descriptor comparison all run over it through **exactly** the
/// production code path — the same `apply_each`, the same `schema_descriptor`,
/// the same marker writes. The only thing a fixture changes is *which* DDL is
/// in the ladder. It also buys coverage a shipped step never could: a step
/// that fails mid-batch, so the whole-transaction rollback is provable.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct LadderView {
    steps: &'static [SchemaStep],
    head: u32,
    target: u32,
    min_servable: u32,
}

impl LadderView {
    /// The one view production uses.
    pub(crate) const PRODUCTION: Self = Self {
        steps: SCHEMA_LADDER,
        head: SCHEMA_EPOCH_HEAD,
        target: SCHEMA_EPOCH_TARGET,
        min_servable: SCHEMA_EPOCH_MIN_SERVABLE,
    };

    /// A fixture view. Test-only on purpose: promoting it would turn "which
    /// ladder is authoritative" from a compile-time fact into a parameter.
    #[cfg(test)]
    pub(crate) fn for_test(
        steps: &'static [SchemaStep],
        head: u32,
        target: u32,
        min_servable: u32,
    ) -> Self {
        assert!(target <= head, "fixture view drives past what it can build");
        assert!(
            min_servable <= target,
            "fixture view refuses an epoch it would create"
        );
        Self {
            steps,
            head,
            target,
            min_servable,
        }
    }

    pub(crate) fn head(self) -> u32 {
        self.head
    }

    pub(crate) fn target(self) -> u32 {
        self.target
    }

    /// The single step that carries `to_epoch - 1` to `to_epoch`, or `None`.
    pub(crate) fn step_at(self, to_epoch: u32) -> Option<&'static SchemaStep> {
        self.steps.iter().find(|step| step.epoch == to_epoch)
    }

    /// Digest of this ladder's prefix through `epoch`, chained from the
    /// baseline. See [`chain_digest`].
    pub(crate) fn chain_digest(self, epoch: u32) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(LADDER_DOMAIN);
        hasher.update(BASELINE_DIGEST);
        let mut digest: [u8; 32] = hasher.finalize().into();
        for step in self.steps.iter().filter(|step| step.epoch <= epoch) {
            let mut hasher = Sha256::new();
            hasher.update(digest);
            hasher.update(step_digest(step));
            digest = hasher.finalize().into();
        }
        digest
    }

    /// The steps that carry an archive from `from` to `to`.
    pub(crate) fn steps_between(
        self,
        from: u32,
        to: u32,
    ) -> impl Iterator<Item = &'static SchemaStep> {
        self.steps
            .iter()
            .filter(move |step| step.epoch > from && step.epoch <= to)
    }

    /// Execute the steps carrying an already-open database from `from` to `to`.
    pub(crate) fn apply_steps(self, conn: &Connection, from: u32, to: u32) -> Result<()> {
        apply_each(conn, self.steps_between(from, to))
    }

    /// Build, in memory, the canonical database for `epoch` over this ladder.
    pub(crate) fn build_canonical(self, epoch: u32) -> Result<Connection> {
        // The baseline declares a vec0 virtual table, so the extension has to
        // be registered before the connection opens. Idempotent (Once guard).
        crate::store::init_vec_extension();
        let conn = Connection::open_in_memory()?;
        conn.execute_batch(crate::store::SCHEMA_SQL)?;
        crate::store::run_migrations(&conn)?;
        self.apply_steps(&conn, 0, epoch)?;
        Ok(conn)
    }

    /// See [`validate_servable_epoch`].
    pub(crate) fn validate_servable(self, marker: ArchiveEpoch) -> Result<()> {
        // Always written as the full range. Simplifying this to only the upper
        // bound during a phase whose floor is zero would make a later floor
        // raise a silent no-op. (No `absurd_extreme_comparisons` allow is
        // needed here, unlike the module-level const assertions: these are
        // runtime fields, so the lint cannot see a constant to fold.)
        if marker.epoch < self.min_servable || marker.epoch > self.head {
            return Err(epoch_marker_error(
                "recorded epoch is outside this binary's servable range",
            ));
        }
        if marker.chain != self.chain_digest(marker.epoch) {
            return Err(epoch_marker_error(
                "recorded chain does not match this binary's baseline and ladder",
            ));
        }
        Ok(())
    }
}

/// Digest of one step, binding its epoch, identity and exact SQL.
pub(crate) fn step_digest(step: &SchemaStep) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(LADDER_DOMAIN);
    hasher.update(step.epoch.to_be_bytes());
    hash_framed(&mut hasher, step.id.as_bytes());
    hash_framed(&mut hasher, step.sql.as_bytes());
    hasher.finalize().into()
}

/// Digest of the ladder prefix through `epoch`, chained from the baseline.
///
/// An archive records the chain digest it reached, so a step whose SQL was
/// edited after shipping produces a different chain and is refused rather than
/// silently applied on top of a divergent history.
pub(crate) fn chain_digest(epoch: u32) -> [u8; 32] {
    LadderView::PRODUCTION.chain_digest(epoch)
}

/// The steps that carry an archive from `from` to `to`.
pub(crate) fn steps_between(from: u32, to: u32) -> impl Iterator<Item = &'static SchemaStep> {
    LadderView::PRODUCTION.steps_between(from, to)
}

/// Execute the steps that carry an already-open database from `from` to `to`.
///
/// One statement per step, in epoch order, exactly as
/// [`build_canonical`] executes them — the identical-text property depends on
/// the order being the same on both sides, not merely the set.
pub(crate) fn apply_steps(conn: &Connection, from: u32, to: u32) -> Result<()> {
    LadderView::PRODUCTION.apply_steps(conn, from, to)
}

/// The executor both [`apply_steps`] and the tests share, so a fixture ladder
/// exercises the same code the production ladder will.
fn apply_each<'a>(conn: &Connection, steps: impl Iterator<Item = &'a SchemaStep>) -> Result<()> {
    for step in steps {
        conn.execute_batch(step.sql)?;
    }
    Ok(())
}

/// Build, in memory, the canonical database for `epoch`.
///
/// This is the reference a live archive is compared against, so it must reach
/// `epoch` the same way an archive does: the frozen baseline first, then the
/// ladder steps in order. Never the baseline "as it would look today".
pub(crate) fn build_canonical(epoch: u32) -> Result<Connection> {
    LadderView::PRODUCTION.build_canonical(epoch)
}

/// The single step that carries `from` to `from + 1`, or `None`.
pub(crate) fn step_at(to_epoch: u32) -> Option<&'static SchemaStep> {
    LadderView::PRODUCTION.step_at(to_epoch)
}

/// The epoch marker a live archive records, plus the ladder chain it reached
/// it by.
///
/// This is a **birth witness**: every path that materializes a servable
/// archive writes it, epoch 0 included. There is no "absent means zero"
/// reading anywhere — see [`read_archive_epoch`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ArchiveEpoch {
    pub(crate) epoch: u32,
    pub(crate) chain: [u8; 32],
}

/// Read the marker.
///
/// An **absent row is a refusal, never a coercion to epoch 0.** Coercing would
/// make "absent" ambiguous between an archive this binary built at epoch 0 and
/// an archive some other binary built without the marker at all — and the
/// second is exactly the plain-primary-key archive a rolled-back or mid-deploy
/// image can still produce. A malformed row (extra rows, out-of-range epoch,
/// wrong digest length) is likewise a refusal.
pub(crate) fn read_archive_epoch(conn: &Connection) -> Result<ArchiveEpoch> {
    let mut statement =
        conn.prepare("SELECT epoch, chain_digest FROM schema_epoch WHERE singleton = 1")?;
    let row = statement
        .query_row([], |row| {
            Ok((row.get::<_, i64>(0)?, row.get::<_, Vec<u8>>(1)?))
        })
        .optional()?;
    let Some((epoch, chain)) = row else {
        return Err(epoch_marker_error(
            "archive carries no epoch marker; it was not born under this baseline",
        ));
    };
    let epoch = u32::try_from(epoch)
        .map_err(|_| epoch_marker_error("recorded epoch is out of range for this binary"))?;
    let chain: [u8; 32] = chain
        .try_into()
        .map_err(|_| epoch_marker_error("recorded chain digest is not 32 bytes"))?;
    Ok(ArchiveEpoch { epoch, chain })
}

/// Write the marker for `epoch`, unconditionally — epoch 0 included.
///
/// Seeding at epoch 0 is what makes the row a birth witness rather than a
/// record that only appears once the ladder has moved. The upsert is asserted
/// (`changes() == 1`) and then re-read and compared, so a CHECK that silently
/// declined the write cannot pass for a success.
pub(crate) fn seed_epoch_marker(conn: &Connection, epoch: u32) -> Result<()> {
    write_epoch_marker(conn, epoch, chain_digest(epoch))
}

/// Write an explicitly supplied `(epoch, chain)` marker.
///
/// The advance plan commits through here rather than through
/// [`seed_epoch_marker`] on purpose. `seed_epoch_marker` *recomputes* the chain
/// from whatever ladder the running binary happens to carry; a sealed plan must
/// write the value it was constructed with and that its own preconditions
/// verified, so that a replay of the identical plan writes identical bytes. A
/// recomputation inside apply is the same class of defect as a clock DEFAULT
/// firing inside apply: it makes the committed bytes a function of the
/// executing binary instead of a function of the plan.
///
/// The upsert is asserted (`changes() == 1`) and then re-read and compared, so
/// a CHECK that silently declined the write cannot pass for a success.
pub(crate) fn write_epoch_marker(conn: &Connection, epoch: u32, chain: [u8; 32]) -> Result<()> {
    let changed = conn.execute(
        "INSERT INTO schema_epoch (singleton, epoch, chain_digest) VALUES (1, ?1, ?2)
         ON CONFLICT(singleton) DO UPDATE SET epoch = excluded.epoch,
                                              chain_digest = excluded.chain_digest",
        rusqlite::params![epoch, &chain[..]],
    )?;
    if changed != 1 {
        return Err(epoch_marker_error("upsert did not write exactly one row"));
    }
    let readback = read_archive_epoch(conn)?;
    if readback != (ArchiveEpoch { epoch, chain }) {
        return Err(epoch_marker_error("marker did not read back as written"));
    }
    Ok(())
}

/// Refuse unless this binary can serve the archive's recorded epoch.
///
/// Two conjuncts:
///   `SCHEMA_EPOCH_MIN_SERVABLE <= marker.epoch <= SCHEMA_EPOCH_HEAD`
/// and `marker.chain == chain_digest(marker.epoch)`.
///
/// The second is what makes the marker non-self-certifying: the chain is
/// recomputed from **this** binary's `BASELINE_DIGEST` + `SCHEMA_LADDER`, so an
/// archive cannot vouch for its own history. At epoch 0 the chain is exactly
/// the baseline anchor, which is what carries the re-baselined digest into
/// every archive at birth.
pub(crate) fn validate_servable_epoch(marker: ArchiveEpoch) -> Result<()> {
    LadderView::PRODUCTION.validate_servable(marker)
}

/// Verbatim product-schema equality against `build_canonical(marker.epoch)`.
///
/// Shares [`crate::store::schema_descriptor`] with the read path on purpose: a
/// second descriptor query here would be a second definition of "the same
/// schema", which is precisely the divergence the ladder exists to prevent.
pub(crate) fn assert_canonical_at(conn: &Connection, marker: ArchiveEpoch) -> Result<()> {
    let canonical = build_canonical(marker.epoch)?;
    if crate::store::schema_descriptor(conn)? != crate::store::schema_descriptor(&canonical)? {
        return Err(epoch_marker_error(
            "archive schema is not what this binary would build at its recorded epoch",
        ));
    }
    Ok(())
}

fn hash_framed(hasher: &mut Sha256, value: &[u8]) {
    // Length-prefixed so ("ab","c") cannot alias ("a","bc").
    hasher.update((value.len() as u64).to_be_bytes());
    hasher.update(value);
}

/// The frozen epoch-0 baseline digest.
///
/// Recorded from the `SCHEMA_SQL` text, the `run_migrations` body, and the
/// bodies of the two functions `run_migrations` delegates to —
/// `cp::mcp_projection::init_projection_schema` and `cp::media::init_schema`.
/// The gate recomputes it and fails if any of them is edited: after the ladder
/// exists, schema changes are steps, never baseline edits.
///
/// The delegated bodies are covered because they are baseline DDL in every
/// sense that matters — between them they create 37 of the epoch-0 tables. The
/// original pin hashed only `store.rs`, so all of that DDL could be edited
/// without tripping the freeze; the digest then described one file rather than
/// the baseline it claims to freeze. Re-pinning to close that is a change of
/// the recorded VALUE under an unchanged, strictly stronger RULE.
///
/// # Re-pin history
///
/// The recorded value has moved three times. The RULE — "the recorded digest
/// must describe the live baseline" — has never moved, and never may.
///
/// 1. `c9f277fa…c551`, 2026-08-19 — genesis (#282/#286), `store.rs` only.
/// 2. `bc90061e…3f66`, 2026-08-20 — #316, extended to the four DDL sources.
/// 3. `d5ff84db…2dfb`, 2026-08-21 — **the sealed re-baseline.** Taken inside
///    the zero-archive window under the proof obligation in
///    `docs/adr/0022/zero-archive-proof.md`. It made `audio_segments.id`,
///    `utterances.id` and `screenshots.id` `AUTOINCREMENT` and added the
///    `schema_epoch` birth witness. This is a **non-additive** baseline change
///    and therefore not expressible as a ladder step — `AUTOINCREMENT` cannot
///    be added to an existing table by any additive DDL, and
///    `CREATE TABLE IF NOT EXISTS` makes the edit a permanent silent no-op on
///    any archive that already exists. It was legitimate only because the set
///    of existing archives was provably empty, and it is the **last** such
///    change: `scripts/schema_baseline_seal.json` records the window and
///    closes it.
///
/// Recompute, never transcribe: `python3 scripts/test_schema_ladder_gate.py
/// --print-digest` emits this literal from the same `baseline_digest` the gate
/// asserts against.
pub(crate) const BASELINE_DIGEST: [u8; 32] = [
    0xd5, 0xff, 0x84, 0xdb, 0x4c, 0x22, 0xac, 0x09, 0x3b, 0x52, 0x64, 0x0a, 0xca, 0x6e, 0xad, 0x6d,
    0x1d, 0xb5, 0xd9, 0x72, 0x6f, 0x27, 0x92, 0x7d, 0xe7, 0x01, 0xd7, 0x91, 0xb1, 0x79, 0x2d, 0xfb,
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn production_phase_declarations_are_coherent() {
        // Exercise the phase relation through runtime values. BOOTSTRAP is
        // intentionally 0/0/0, and comparing those declarations directly
        // makes Clippy constant-fold the assertions instead of checking the
        // same relation future signed phases must satisfy.
        let [head, target, minimum] = std::hint::black_box([
            SCHEMA_EPOCH_HEAD,
            SCHEMA_EPOCH_TARGET,
            SCHEMA_EPOCH_MIN_SERVABLE,
        ]);
        assert_eq!(usize::try_from(head).unwrap(), SCHEMA_LADDER.len());
        assert!(target <= head);
        assert!(minimum <= target);
    }

    #[test]
    fn ladder_epochs_are_contiguous_from_one_with_unique_ids() {
        // A gap or duplicate id would make the chain digest ambiguous in any
        // production phase.
        let mut expected = 1;
        let mut seen = std::collections::HashSet::new();
        for step in SCHEMA_LADDER {
            assert_eq!(step.epoch, expected, "ladder epochs must be contiguous");
            assert!(seen.insert(step.id), "duplicate step id {}", step.id);
            assert!(!step.sql.trim().is_empty());
            expected += 1;
        }
        assert_eq!(SCHEMA_EPOCH_HEAD, expected - 1);
    }

    #[test]
    fn step_digests_bind_epoch_identity_and_sql_exactly() {
        let base = SchemaStep {
            epoch: 1,
            id: "0001_probe",
            class: StepClass::Table,
            sql: "CREATE TABLE a (x INTEGER) STRICT;",
        };
        let edited_sql = SchemaStep {
            sql: "CREATE TABLE a (y INTEGER) STRICT;",
            ..base
        };
        let renamed = SchemaStep {
            id: "0001_probe_v2",
            ..base
        };
        let renumbered = SchemaStep { epoch: 2, ..base };

        // Editing a shipped step must be detectable — that is the whole point
        // of recording the digest.
        assert_ne!(step_digest(&base), step_digest(&edited_sql));
        assert_ne!(step_digest(&base), step_digest(&renamed));
        assert_ne!(step_digest(&base), step_digest(&renumbered));
        assert_eq!(step_digest(&base), step_digest(&base));

        // Framing: the id and sql fields cannot bleed into one another.
        let split_a = SchemaStep {
            id: "ab",
            sql: "c",
            ..base
        };
        let split_b = SchemaStep {
            id: "a",
            sql: "bc",
            ..base
        };
        assert_ne!(step_digest(&split_a), step_digest(&split_b));
    }

    #[test]
    fn chain_digest_is_stable_and_anchored_to_the_baseline() {
        let mut anchor = Sha256::new();
        anchor.update(LADDER_DOMAIN);
        anchor.update(BASELINE_DIGEST);
        let mut expected: [u8; 32] = anchor.finalize().into();
        assert_eq!(chain_digest(0), expected);
        for step in SCHEMA_LADDER {
            let mut link = Sha256::new();
            link.update(expected);
            link.update(step_digest(step));
            expected = link.finalize().into();
        }
        assert_eq!(chain_digest(SCHEMA_EPOCH_HEAD), expected);
    }

    #[test]
    fn steps_between_selects_the_half_open_range() {
        assert_eq!(
            steps_between(0, SCHEMA_EPOCH_HEAD).count(),
            SCHEMA_LADDER.len()
        );
        assert_eq!(steps_between(0, 0).count(), 0);
    }

    /// A fixture ladder keeps the executor coverage independent of the
    /// production phase. These are the three permitted step classes.
    const FIXTURE_LADDER: &[SchemaStep] = &[
        SchemaStep {
            epoch: 1,
            id: "0001_probe_table",
            class: StepClass::Table,
            sql: "CREATE TABLE ladder_probe (id INTEGER PRIMARY KEY, note TEXT) STRICT;",
        },
        SchemaStep {
            epoch: 2,
            id: "0002_probe_column",
            class: StepClass::Column,
            sql: "ALTER TABLE ladder_probe ADD COLUMN weight INTEGER;",
        },
        SchemaStep {
            epoch: 3,
            id: "0003_probe_index",
            class: StepClass::Index,
            sql: "CREATE INDEX ladder_probe_note ON ladder_probe (note);",
        },
    ];

    fn descriptor(conn: &Connection) -> Vec<(String, String)> {
        let mut statement = conn
            .prepare(
                "SELECT name, coalesce(sql, '') FROM sqlite_schema
                 WHERE name NOT LIKE 'sqlite_%' ORDER BY name",
            )
            .unwrap();
        statement
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
            .unwrap()
            .collect::<std::result::Result<Vec<_>, _>>()
            .unwrap()
    }

    #[test]
    fn apply_each_runs_every_step_in_epoch_order() {
        let conn = Connection::open_in_memory().unwrap();
        apply_each(&conn, FIXTURE_LADDER.iter()).unwrap();
        let objects = descriptor(&conn);
        assert_eq!(objects.len(), 2, "one table and one index");
        // The column landed on the table the earlier step created, which only
        // works if the steps ran in order.
        let table = &objects
            .iter()
            .find(|(name, _)| name == "ladder_probe")
            .unwrap()
            .1;
        assert!(table.contains("weight"));

        // Applying the same ladder to a database that skipped step 1 must
        // fail rather than half-apply: steps are not independent.
        let bare = Connection::open_in_memory().unwrap();
        assert!(apply_each(&bare, FIXTURE_LADDER[1..].iter()).is_err());
    }

    /// The two ways a baseline edit bricks archives. Both are what the gate's
    /// frozen `BASELINE_DIGEST` exists to make unreachable.
    #[test]
    fn editing_the_baseline_bricks_archives_either_way() {
        let baseline = "CREATE TABLE ladder_probe (id INTEGER PRIMARY KEY, note TEXT) STRICT;";
        let step = "ALTER TABLE ladder_probe ADD COLUMN weight INTEGER;";

        // (1) Baseline edited, no step. An archive built from the old baseline
        // cannot advance, and a canonical rebuild no longer describes it.
        let existing_archive = Connection::open_in_memory().unwrap();
        existing_archive.execute_batch(baseline).unwrap();
        let edited_canonical = Connection::open_in_memory().unwrap();
        edited_canonical
            .execute_batch(
                "CREATE TABLE ladder_probe (id INTEGER PRIMARY KEY, note TEXT, weight INTEGER) STRICT;",
            )
            .unwrap();
        assert_ne!(descriptor(&existing_archive), descriptor(&edited_canonical));

        // (2) Baseline edited AND the equivalent step appended. The step now
        // runs against a baseline that already has the column, so the
        // canonical build itself fails and every archive is refused.
        let both = Connection::open_in_memory().unwrap();
        both.execute_batch(
            "CREATE TABLE ladder_probe (id INTEGER PRIMARY KEY, note TEXT, weight INTEGER) STRICT;",
        )
        .unwrap();
        let duplicate = both.execute_batch(step).unwrap_err();
        assert!(duplicate.to_string().contains("duplicate column name"));
    }

    /// Guards the *scope* of the claim above, because getting this backwards
    /// would invite someone to "just edit the baseline, the text matches".
    #[test]
    fn an_alter_added_column_matches_a_hand_written_one_only_by_coincidence() {
        let stepped = Connection::open_in_memory().unwrap();
        stepped
            .execute_batch("CREATE TABLE ladder_probe (id INTEGER PRIMARY KEY, note TEXT) STRICT;")
            .unwrap();
        stepped
            .execute_batch("ALTER TABLE ladder_probe ADD COLUMN weight INTEGER;")
            .unwrap();

        // Appended last, spelled identically: SQLite splices the column text
        // in verbatim, so the stored texts DO coincide.
        let appended = Connection::open_in_memory().unwrap();
        appended
            .execute_batch(
                "CREATE TABLE ladder_probe (id INTEGER PRIMARY KEY, note TEXT, weight INTEGER) STRICT;",
            )
            .unwrap();
        assert_eq!(descriptor(&stepped), descriptor(&appended));

        // Same logical schema, column declared in a different position: the
        // texts diverge, and nothing anywhere forces a developer to pick the
        // position that happens to match.
        let reordered = Connection::open_in_memory().unwrap();
        reordered
            .execute_batch(
                "CREATE TABLE ladder_probe (id INTEGER PRIMARY KEY, weight INTEGER, note TEXT) STRICT;",
            )
            .unwrap();
        assert_ne!(descriptor(&stepped), descriptor(&reordered));
    }

    #[test]
    fn build_canonical_reaches_epoch_zero_and_matches_a_bare_baseline() {
        let canonical = build_canonical(0).unwrap();
        let baseline = Connection::open_in_memory().unwrap();
        baseline.execute_batch(crate::store::SCHEMA_SQL).unwrap();
        crate::store::run_migrations(&baseline).unwrap();
        // At epoch 0 the ladder contributes nothing in every phase, so the
        // canonical database is exactly the frozen baseline and is what
        // BASELINE_DIGEST describes.
        assert_eq!(descriptor(&canonical), descriptor(&baseline));
    }

    #[test]
    fn apply_steps_reaches_the_declared_production_head() {
        let conn = build_canonical(0).unwrap();
        apply_steps(&conn, 0, SCHEMA_EPOCH_HEAD).unwrap();
        let canonical = build_canonical(SCHEMA_EPOCH_HEAD).unwrap();
        assert_eq!(descriptor(&conn), descriptor(&canonical));
    }

    // ── The epoch marker: a birth witness, not an absence ──────────────────

    #[test]
    fn seeding_at_epoch_zero_writes_a_row_rather_than_nothing() {
        // The whole amendment. If epoch 0 were encoded as "no row", then
        // "no row" would also be what a pre-marker binary leaves behind, and
        // the two would be indistinguishable at open — which is exactly the
        // plain-primary-key archive the re-baseline exists to refuse.
        let conn = build_canonical(0).unwrap();
        assert_eq!(
            conn.query_row("SELECT count(*) FROM schema_epoch", [], |row| row
                .get::<_, i64>(0))
                .unwrap(),
            0,
            "build_canonical is a schema reference, not an archive: it must \
             NOT seed the marker, or the canonical stops describing a fresh \
             baseline"
        );

        seed_epoch_marker(&conn, 0).unwrap();
        let marker = read_archive_epoch(&conn).unwrap();
        assert_eq!(marker.epoch, 0);
        assert_eq!(marker.chain, chain_digest(0));
    }

    #[test]
    fn an_absent_marker_is_a_refusal_and_never_epoch_zero() {
        let conn = build_canonical(0).unwrap();
        let error = read_archive_epoch(&conn).unwrap_err().to_string();
        assert!(
            error.contains("no epoch marker"),
            "absent marker must refuse, not coerce: {error}"
        );
    }

    #[test]
    fn a_marker_whose_chain_is_not_this_binarys_baseline_is_refused() {
        // Closes D3: the archive supplies the value that would otherwise
        // select its own comparand. The chain is recomputed here, from THIS
        // binary's BASELINE_DIGEST, so an archive cannot certify itself.
        let epoch = SCHEMA_EPOCH_MIN_SERVABLE;
        let conn = build_canonical(epoch).unwrap();
        seed_epoch_marker(&conn, epoch).unwrap();
        conn.execute(
            "UPDATE schema_epoch SET chain_digest = ?1 WHERE singleton = 1",
            [&[7_u8; 32][..]],
        )
        .unwrap();
        let marker = read_archive_epoch(&conn).unwrap();
        assert_ne!(marker.chain, chain_digest(epoch));
        let error = validate_servable_epoch(marker).unwrap_err().to_string();
        assert!(error.contains("chain does not match"), "{error}");
    }

    #[test]
    fn the_declared_servable_floor_is_accepted() {
        let minimum = std::hint::black_box(SCHEMA_EPOCH_MIN_SERVABLE);
        let floor = ArchiveEpoch {
            epoch: minimum,
            chain: chain_digest(minimum),
        };
        validate_servable_epoch(floor).unwrap();
        if minimum > 0 {
            let below = ArchiveEpoch {
                epoch: minimum - 1,
                chain: chain_digest(minimum - 1),
            };
            assert!(validate_servable_epoch(below).is_err());
        }
    }

    #[test]
    fn an_epoch_this_binary_cannot_serve_is_refused() {
        let above = ArchiveEpoch {
            epoch: SCHEMA_EPOCH_HEAD + 1,
            chain: chain_digest(SCHEMA_EPOCH_HEAD + 1),
        };
        assert!(validate_servable_epoch(above).is_err());
    }

    #[test]
    fn a_malformed_marker_row_is_a_refusal() {
        let conn = Connection::open_in_memory().unwrap();
        // Without the baseline CHECKs, so the malformed shapes are reachable.
        conn.execute_batch(
            "CREATE TABLE schema_epoch (singleton INTEGER PRIMARY KEY, \
             epoch INTEGER NOT NULL, chain_digest BLOB NOT NULL);",
        )
        .unwrap();
        conn.execute(
            "INSERT INTO schema_epoch VALUES (1, 0, ?1)",
            [&[0_u8; 8][..]],
        )
        .unwrap();
        assert!(read_archive_epoch(&conn)
            .unwrap_err()
            .to_string()
            .contains("32 bytes"));

        // Restore a well-formed digest first. Leaving the 8-byte one in place
        // made this assertion unfalsifiable on its own axis: the read would
        // have failed on the digest whatever the epoch said.
        conn.execute(
            "UPDATE schema_epoch SET chain_digest = ?1",
            [&chain_digest(0)[..]],
        )
        .unwrap();
        assert!(
            read_archive_epoch(&conn).is_ok(),
            "precondition: with a well-formed row the read must succeed, or \
             the epoch assertion below proves nothing"
        );

        conn.execute("UPDATE schema_epoch SET epoch = -1", [])
            .unwrap();
        let refusal = read_archive_epoch(&conn).unwrap_err().to_string();
        assert!(
            !refusal.contains("32 bytes"),
            "the refusal must be attributable to the epoch, not the digest: {refusal}"
        );
    }

    #[test]
    fn the_baseline_checks_refuse_a_zero_or_short_chain_digest() {
        // The CHECK constraints are the in-database half of the same refusal.
        let conn = build_canonical(0).unwrap();
        for bad in [vec![0_u8; 32], vec![1_u8; 31]] {
            assert!(
                conn.execute("INSERT INTO schema_epoch VALUES (1, 0, ?1)", [&bad[..]])
                    .is_err(),
                "baseline CHECK admitted a malformed chain digest"
            );
        }
        assert!(
            conn.execute(
                "INSERT INTO schema_epoch VALUES (2, 0, ?1)",
                [&[1_u8; 32][..]]
            )
            .is_err(),
            "baseline CHECK admitted a second marker row"
        );
    }

    #[test]
    fn seeding_is_an_upsert_that_reads_back() {
        let conn = build_canonical(0).unwrap();
        seed_epoch_marker(&conn, 0).unwrap();
        seed_epoch_marker(&conn, 0).unwrap();
        assert_eq!(
            conn.query_row("SELECT count(*) FROM schema_epoch", [], |row| row
                .get::<_, i64>(0))
                .unwrap(),
            1,
            "the singleton must stay a singleton across re-seeds"
        );
    }

    #[test]
    fn assert_canonical_at_pins_the_archive_against_its_recorded_epoch() {
        let conn = build_canonical(SCHEMA_EPOCH_TARGET).unwrap();
        seed_epoch_marker(&conn, SCHEMA_EPOCH_TARGET).unwrap();
        let marker = read_archive_epoch(&conn).unwrap();
        // The marker row itself is data, not schema, so a seeded archive is
        // still descriptor-identical to the canonical.
        assert_canonical_at(&conn, marker).unwrap();

        conn.execute_batch("CREATE TABLE interloper (x INTEGER);")
            .unwrap();
        assert!(assert_canonical_at(&conn, marker).is_err());
    }

    #[test]
    fn step_at_selects_the_single_step_that_reaches_an_epoch() {
        assert!(step_at(0).is_none());
        for step in SCHEMA_LADDER {
            assert_eq!(step_at(step.epoch), Some(step));
        }
        assert!(step_at(SCHEMA_EPOCH_HEAD + 1).is_none());
    }
}
