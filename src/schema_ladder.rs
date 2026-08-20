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
//! steps `1..=E`. This matters because schema comparison is verbatim on
//! `sqlite_schema.sql`, and SQLite *appends* an ALTER-added column to the
//! stored `CREATE TABLE` text rather than rewriting it. A developer who added
//! a column to both `SCHEMA_SQL` and a ladder step would therefore produce two
//! different texts for the same logical schema and brick every migrated
//! archive. Freezing the baseline makes that divergence impossible by
//! construction rather than by convention, and the gate enforces the freeze.
//!
//! # Slice 0
//!
//! The ladder is empty and every epoch constant is 0, so this module changes
//! no behaviour. What it establishes is the pin: `BASELINE_DIGEST` fixes the
//! epoch-0 text, and the gate fails the build if anyone edits it.

use sha2::{Digest, Sha256};

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
}
