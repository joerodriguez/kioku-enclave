//! Active exact email delivery owner.
//!
//! `claim` freezes one recipient and one request body for the complete
//! delivery lifetime before any provider call. `exact` carries the complete
//! due-row predecessor across that call and settles every provider or
//! provider-free outcome with exact adoption and CAS. Neither child can call
//! Store, Control, the provider, or a runtime launcher.

pub(super) mod claim;
pub(super) mod exact;

pub(in crate::cp) use claim::{
    load_claim_recovery, load_frozen_request, load_open_claim, validate_live_send_authority,
    EmailClaimRecovery, EmailFrozenRequest, EmailSendClaim, EmailSendClaimDisposition,
    MIN_SEND_LEASE_MILLIS,
};
pub(crate) use claim::{EmailSendClaimLedger, EmailSendClaimPlan};
#[cfg(test)]
pub(in crate::cp) use exact::AMBIGUOUS_ERROR_CODE;
pub(in crate::cp) use exact::{EmailDeliverySnapshot, EmailSettlementKind};
pub(crate) use exact::{ExactEmailDeliverySettlementLedger, ExactEmailDeliverySettlementPlan};
