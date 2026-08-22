//! Active exact webhook delivery owner.
//!
//! `claim` freezes one destination, signing-key commitment, and canonical
//! event body for the complete delivery lifetime before any provider call.
//! `exact` carries the complete due-row predecessor across that call and
//! settles every provider or provider-free outcome with exact adoption and
//! CAS. Neither child can call Store, Control, DNS, HTTP, or a runtime
//! launcher.

pub(super) mod claim;
pub(super) mod exact;

#[cfg(test)]
pub(in crate::cp) use claim::CLAIM_LEASE_MILLIS;
pub(in crate::cp) use claim::{
    load_claim_recovery, load_frozen_request, load_open_claim, validate_live_send_authority,
    WebhookClaimRecovery, WebhookFrozenRequest, WebhookSendClaim, WebhookSendClaimDisposition,
    MIN_SEND_LEASE_MILLIS,
};
pub(crate) use claim::{WebhookSendClaimLedger, WebhookSendClaimPlan};
pub(in crate::cp) use exact::{
    load_subscription_purge_candidate, WebhookDeliverySnapshot, WebhookSettlementKind,
    WebhookSubscriptionPurgeCandidate,
};
pub(crate) use exact::{
    ExactWebhookDeliveryPurgeLedger, ExactWebhookDeliveryPurgePlan,
    ExactWebhookDeliverySettlementLedger, ExactWebhookDeliverySettlementPlan,
};
