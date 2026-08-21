//! Sealed WAL plan families for the schema-epoch domain.

pub(crate) mod advance;

pub(crate) use advance::{
    advance_one_epoch, AdvanceOutcome, SchemaEpochAdvanceLedger, SchemaEpochAdvancePlan,
};
