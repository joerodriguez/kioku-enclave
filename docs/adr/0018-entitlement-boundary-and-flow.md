# ADR-0018: Entitlement boundary and rejection flow

- Status: Accepted
- Date: 2026-08-09
- Revised: 2026-08-11

## Context

Entitlement state must affect capture without allowing an external outage to corrupt the
private archive. The control plane needs stable accounting identity but must not learn a
login identity, email, device, capture, episode, prompt, model output, or user content.

## Decision

Use bounded JSON over authenticated HTTPS between the enclave and a provider-neutral
external control-plane port. The enclave obtains a Google OIDC identity token from the
metadata service. Its audience exactly equals the image-baked service origin; redirects
are disabled and connect, request, and response sizes are bounded.

The encrypted enclave control database maps each stable user UUID to a random
`acct_<random>` pseudonym. Only that pseudonym crosses the boundary. The control-plane
contract consists of:

- an entitlement snapshot for allowance, usage, reset, and admission presentation;
- an idempotent prospective usage reservation;
- content-free inference-usage and coverage telemetry;
- deletion detach; and
- an owner-only opaque economics page whose commercial fields are interpreted only by
  the closed control plane and dashboard.

The existing public `/api/billing` route names are a compatibility facade for shipped
clients. Their implementation is limited to snapshot/lease forwarding. Account purchase
and management actions are opaque HTTPS URLs from the authenticated external port; the
enclave verifies only generic URL safety and never names or implements a merchant.

`POST /api/billing/recording-lease` accepts exact `{request_id,lease_id}`. UUIDv4 request
identity plus null lease starts or recovers; the returned opaque lease renews while
active. A successful unique request reserves 60 seconds and returns
`{lease_id,expires_at,billing}`. Encrypted intents and receipts recover the same decision
after a process crash. An abandoned pending intent is reconciled with its original
idempotency key before a new request can consume the per-user pending slot.

Every response is `Cache-Control: no-store`. Denial or inactive lease is typed HTTP 402
before persistence; upstream or durable-state unavailability is HTTP 503; early renewal
and idempotency conflict are HTTP 409. `BILLING_ENFORCEMENT_MODE=shadow|enforce` is a
temporary compatibility configuration: enforce fails new capture closed, while shadow
records only bounded operational warnings and never logs upstream detail.

## Consequences

- This repository contains the admission protocol, not a commerce implementation.
- A pending remote outcome is retried with the same deterministic key and cannot be
  replaced by an unrelated reservation.
- The external control plane may replace its commercial provider without changing the
  enclave contract.
- Existing archive reads, search, export, and deletion are independent of entitlement
  availability and remain cloud-only.
