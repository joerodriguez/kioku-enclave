# ADR-0020: Owner-only account-economics facade

- Status: Accepted
- Date: 2026-08-09
- Revised: 2026-08-13

## Context

The owner dashboard needs a per-account operating view, while the external control plane
intentionally has only random account IDs. Email and the active-user roster must not cross
that boundary. The public enclave must not interpret a merchant ledger or commercial
provider schema.

## Decision

Authorize owners using image-baked stable UUIDs in `ADMIN_USER_IDS`, separate from the
ordinary account allow-list. Authorization happens before identity enumeration or any
external call.

The bounded facade joins an external page to the local `(account pseudonym,email)` mapping
and removes each pseudonym before returning the owner-only response. Commercial fields are
opaque to the enclave and remain owned, versioned, and presented by the closed control
plane/dashboard. The enclave validates only the bounded page envelope, unique account
pseudonyms, timestamps, and the local inference-coverage fields that it must reconcile.

Local current logical storage bytes, accepted email-delivery count, and durable inference
telemetry coverage may be added because those facts exist only inside encrypted enclave
state. Missing, stale, pending, or lost inference telemetry forces dependent modeled cost
and contribution fields to null/unavailable; the facade never fabricates zero.

The owner-only facade may also expose two aggregate account-population counts derived
after authorization from the enclave's current identity roster: all status-active accounts
and the subset of those accounts created during the current UTC month. Here, `active` does
not mean the account recorded, signed in, or generated revenue during the month. Beginning
account deletion changes the status and intentionally removes the account from both
aggregates before physical purge, so the current-month count is not a durable signup or
acquisition cohort. Each cursor page receives a fresh page-independent aggregate and local
read time; it is not a pagination snapshot. The public response exposes only the
aggregates, never an account's stable enclave UUID or account-level creation timestamp.

Responses are `Cache-Control: no-store`. Neither email nor stable enclave UUID is sent to
the external service, and random account IDs are removed from the public response.

## Consequences

- The enclave remains only the privacy-preserving join point; it is not the source of
  commercial truth and has no merchant-specific field names.
- Commercial schema changes are confined to the external service and dashboard as long
  as the bounded page and account pseudonym envelope remains stable.
- Retained-account aggregates can answer a current operating question without creating a
  new identity export. They cannot answer historical signup, churn, or cohort questions;
  those require a separately designed privacy-preserving ledger and deletion contract.
- Changing the owner set requires a new attested image digest.
