#![allow(
    dead_code,
    reason = "ADR-0022 schema epoch ladder: slice 0 is the frozen baseline pin and its plumbing; the owner-side driver arrives with the reviewed epoch domain"
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
//! # Slice 0
//!
//! The ladder is empty and every epoch constant is 0, so this module changes
//! no behaviour. What it establishes is the pin: `BASELINE_DIGEST` fixes the
//! epoch-0 text, and the gate fails the build if anyone edits it.

use rusqlite::Connection;
use sha2::{Digest, Sha256};

use crate::error::Result;

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

/// The ladder. **Append only** — editing or reordering a shipped step changes
/// its digest, which the gate rejects and which a live archive would refuse.
pub(crate) const SCHEMA_LADDER: &[SchemaStep] = &[];

/// Highest epoch this binary knows how to build.
pub(crate) const SCHEMA_EPOCH_HEAD: u32 = 0;

/// Highest epoch this binary will drive an archive to. Held below
/// `SCHEMA_EPOCH_HEAD` while a step rolls out, so the step ships and is
/// observed before anything applies it.
pub(crate) const SCHEMA_EPOCH_TARGET: u32 = 0;

/// Lowest epoch this binary can still serve. Lets an older binary keep serving
/// an archive a newer binary advanced, instead of refusing it.
pub(crate) const SCHEMA_EPOCH_MIN_SERVABLE: u32 = 0;

// Enforced at compile time rather than in a test: a binary must never be asked
// to drive an archive past what it knows how to build, and must never refuse to
// serve an epoch it is itself willing to create. Both comparisons are trivially
// true while every epoch is 0 — which is precisely why they are pinned now,
// before the first step makes them load-bearing and easy to violate silently.
#[allow(
    clippy::absurd_extreme_comparisons,
    reason = "vacuous at epoch 0 by construction; becomes meaningful with the first ladder step"
)]
const _: () = assert!(SCHEMA_EPOCH_TARGET <= SCHEMA_EPOCH_HEAD);
#[allow(
    clippy::absurd_extreme_comparisons,
    reason = "vacuous at epoch 0 by construction; becomes meaningful with the first ladder step"
)]
const _: () = assert!(SCHEMA_EPOCH_MIN_SERVABLE <= SCHEMA_EPOCH_TARGET);

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
    let mut hasher = Sha256::new();
    hasher.update(LADDER_DOMAIN);
    hasher.update(BASELINE_DIGEST);
    let mut digest: [u8; 32] = hasher.finalize().into();
    for step in SCHEMA_LADDER.iter().filter(|step| step.epoch <= epoch) {
        let mut hasher = Sha256::new();
        hasher.update(digest);
        hasher.update(step_digest(step));
        digest = hasher.finalize().into();
    }
    digest
}

/// The steps that carry an archive from `from` to `to`.
pub(crate) fn steps_between(from: u32, to: u32) -> impl Iterator<Item = &'static SchemaStep> {
    SCHEMA_LADDER
        .iter()
        .filter(move |step| step.epoch > from && step.epoch <= to)
}

/// Execute the steps that carry an already-open database from `from` to `to`.
///
/// One statement per step, in epoch order, exactly as
/// [`build_canonical`] executes them — the identical-text property depends on
/// the order being the same on both sides, not merely the set.
pub(crate) fn apply_steps(conn: &Connection, from: u32, to: u32) -> Result<()> {
    apply_each(conn, steps_between(from, to))
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
    // The baseline declares a vec0 virtual table, so the extension has to be
    // registered before the connection opens. Idempotent (Once guard).
    crate::store::init_vec_extension();
    let conn = Connection::open_in_memory()?;
    conn.execute_batch(crate::store::SCHEMA_SQL)?;
    crate::store::run_migrations(&conn)?;
    apply_steps(&conn, 0, epoch)?;
    Ok(conn)
}

fn hash_framed(hasher: &mut Sha256, value: &[u8]) {
    // Length-prefixed so ("ab","c") cannot alias ("a","bc").
    hasher.update((value.len() as u64).to_be_bytes());
    hasher.update(value);
}

/// The frozen epoch-0 baseline digest.
///
/// Recorded once, from the `SCHEMA_SQL` text and `run_migrations` body that
/// existed when the ladder was introduced. The gate recomputes it and fails if
/// the baseline is edited: after the ladder exists, schema changes are steps,
/// never baseline edits.
pub(crate) const BASELINE_DIGEST: [u8; 32] = [
    0xc9, 0xf2, 0x77, 0xfa, 0xac, 0x14, 0x19, 0x96, 0x4b, 0x3f, 0x8f, 0x3c, 0x6a, 0x3c, 0x25, 0x78,
    0x08, 0xa4, 0x3b, 0x72, 0x10, 0x49, 0x0f, 0x28, 0xfd, 0xcb, 0x3e, 0x42, 0xa2, 0xb9, 0xc5, 0x51,
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slice_zero_ladder_is_empty_and_epochs_are_coherent() {
        assert!(SCHEMA_LADDER.is_empty());
        assert_eq!(SCHEMA_EPOCH_HEAD, 0);
        assert_eq!(SCHEMA_EPOCH_TARGET, 0);
        assert_eq!(SCHEMA_EPOCH_MIN_SERVABLE, 0);
        // The ordering invariants are compile-time assertions above.
    }

    #[test]
    fn ladder_epochs_are_contiguous_from_one_with_unique_ids() {
        // Holds vacuously at slice 0 and is the invariant every future step
        // must preserve: a gap or a duplicate id would make the chain digest
        // ambiguous.
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
        // At slice 0 the chain is exactly the baseline anchor.
        assert_eq!(chain_digest(0), chain_digest(SCHEMA_EPOCH_HEAD));
        let mut anchor = Sha256::new();
        anchor.update(LADDER_DOMAIN);
        anchor.update(BASELINE_DIGEST);
        assert_eq!(chain_digest(0), <[u8; 32]>::from(anchor.finalize()));
    }

    #[test]
    fn steps_between_selects_the_half_open_range() {
        assert_eq!(steps_between(0, SCHEMA_EPOCH_HEAD).count(), 0);
        assert_eq!(steps_between(0, 0).count(), 0);
    }

    /// A fixture ladder, so the executor is exercised before the production
    /// ladder has any steps. These are the three permitted step classes.
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
        // At epoch 0 the ladder contributes nothing, so the canonical database
        // is exactly the frozen baseline. This is what makes slice 0's
        // BASELINE_DIGEST describe `build_canonical(0)` too.
        assert_eq!(descriptor(&canonical), descriptor(&baseline));
    }

    #[test]
    fn apply_steps_is_a_no_op_while_the_production_ladder_is_empty() {
        let conn = build_canonical(0).unwrap();
        let before = descriptor(&conn);
        apply_steps(&conn, 0, SCHEMA_EPOCH_HEAD).unwrap();
        assert_eq!(descriptor(&conn), before);
    }
}
