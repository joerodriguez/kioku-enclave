# ADR-0018: Billing boundary and entitlement flow

- Status: Accepted
- Date: 2026-08-09

## Context

Subscription state must affect capture without allowing a billing outage to corrupt the
private archive. The external service needs enough identity for stable accounting, but
must not learn Google identity, email, capture IDs, episode IDs, prompts, or output.

## Decision

Use bounded JSON over HTTPS between the enclave and the monorepo billing service. The
enclave obtains a Google OIDC identity token from the metadata service. Its audience must
exactly equal the image-baked `BILLING_SERVICE_URL` origin; redirects are disabled and
connect/request/response sizes are bounded.

The encrypted enclave control database maps each stable user UUID to a random
`acct_<random>` billing pseudonym. Only that pseudonym crosses the billing boundary. Public
checkout and portal responses are accepted only on Paddle's exact hosted HTTPS domains.

The public authenticated facade is:

- `GET /api/billing`: current plan, allowance, usage, remaining seconds, reset time, and
  recording decision.
- `POST /api/billing/recording-lease`: exact body `{request_id,lease_id}`. `request_id` is
  UUIDv4; null starts and the returned server-issued lease ID renews while active. Every
  accepted unique request prospectively reserves 60 server-timed seconds, extends from
  `max(now,current expiry)`, and returns `{lease_id,expires_at,billing}`. Encrypted lease
  and request receipts recover the same successful response across process crashes.
- `POST /api/billing/checkout`: monthly plan selection.
- `POST /api/billing/portal`: hosted plan-management URL for upgrades, downgrades, and
  cancellation.

Every response is `Cache-Control: no-store`. Enforced denials, expired leases, or lease
mismatches return typed HTTP 402 before new audio is persisted. Billing or durable-receipt
unavailability returns typed HTTP 503. Early renewal and idempotency payload conflict are
HTTP 409. Every new capture upload, including screenshot/reference events, requires an
active lease after duplicate detection but does not consume again.

Rollout is image-baked as `BILLING_ENFORCEMENT_MODE=shadow|enforce`. Shadow mode calls the
same boundary and records bounded operational warnings but permits recording on denial or
outage; it never logs an upstream reason. Enforce mode fails closed. Account deletion
transactionally removes the pseudonym mapping and places only the random account ID in a
durable detach outbox; retry completion removes that outbox row.

Production promotion to `enforce` requires a healthy version-pinned billing secret,
successful catalog reads for every offered price, a successful reconciliation run with
zero failures, an idempotent 60-second authorize/replay/detach canary, and a published
cloud-only native client that renders typed quota denial as an upgrade path. These gates
were satisfied before the 2026-08-11 promotion. The release script binds schema-v3 build
metadata to the repository mode observed before tagging.

Rollback is a new signed release built after setting the repository mode to `shadow`,
followed by the ordinary verified digest roll. Launch metadata cannot override the mode.

## Consequences

- The Mac menu and website can share the same summary contract; presentation remains a
  client responsibility.
- No billing-plane response is trusted as content or a redirect until its schema/host is
  validated.
- A pending intent is durable before remote authorization. Only a pre-existing pending
  intent may recover an upstream duplicate; a new intent receiving `duplicate=true` is
  HTTP 409. This prevents an old pruned receipt from minting a fresh free lease.
- The billing service is an availability dependency only for new recording; existing
  cloud archive reads, search, export, and deletion remain available. None is a local
  fallback.
