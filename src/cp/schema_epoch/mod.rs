//! The owner-side schema-epoch domain (ADR-0022 Part B).
//!
//! `src/schema_ladder.rs` declares *what* the product schema is at each epoch
//! and freezes epoch 0. This module is the other half: the mechanism that
//! carries one live archive from the epoch it recorded at birth to the epoch
//! this binary is willing to drive it to, one step at a time, as an ordinary
//! settled WAL commit under the owner's own lease.
//!
//! The runbook for actually adding a table or a column lives in
//! [`crate::schema_ladder`]'s module docs. Read that first; this module is the
//! engine it describes, not the procedure.

pub(crate) mod wal;
