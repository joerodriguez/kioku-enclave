# ADR-0017: Subscription catalog, payment provider, and recording meter

- Status: Accepted
- Date: 2026-08-09

## Context

Kioku needs a catalog that is easy to understand, leaves room for inference and support
cost, and measures the product behavior a person recognizes as “recording.” Media segment
duration is unsuitable: voice activity detection omits silence, simultaneous mic/system
tracks overlap, and screenshots can still be processed during silence.

## Decision

Use Paddle Billing as merchant of record for checkout, tax, invoices, subscription state,
and its hosted customer portal. The new monorepo billing service owns Paddle-specific
webhooks, product/price identifiers, catalog pricing, proration, and subscription state.
The enclave contract remains provider-neutral and never receives Paddle customer IDs.

Launch with monthly plans only:

| Public name | Monthly price | Included wall-clock recording |
|---|---:|---:|
| Free | $0 | 30 minutes |
| Plus | $15 | 3 hours |
| Pro | $39 | 8 hours |
| Max | $199 | 40 hours |

Max is hidden from the ordinary upgrade grid and available for high-usage customers.
There is no annual interval at launch. Plan identifiers and amounts are billing-service
catalog data, not enclave constants.

The sole subscription meter is `recording_seconds_v1`. The authenticated client reserves
server-timed wall-clock time using `POST /api/billing/recording-lease`. A UUIDv4
`request_id` plus null lease starts a server-issued lease; a new request ID plus the active
lease renews it. Every grant is exactly 60 prospective seconds, and its encrypted receipt
makes retries and crash recovery idempotent. Every new capture event requires an active
lease so screen inference during silent periods cannot bypass allowance enforcement, but
screenshots and references do not consume a second time. Reads, search, export, and
deletion remain ungated.

## Consequences

- A client must renew only in the final 15 seconds and stop on HTTP 402 or 503. Early
  renewal is HTTP 409, preventing unique-ID loops from reserving far ahead. Sixty-second
  grants bound over-counting after a crash while keeping allowances in whole minutes.
- A monthly allowance is comprehensible but does not perfectly allocate every compute
  cost; Vertex cost is measured independently for margin analysis.
- Catalog changes require no enclave release unless the provider-neutral response shape
  changes.
- Annual discounts, top-ups, and overage billing are deferred until retention and churn
  data justify them.

## Alternatives rejected

- Charging media-manifest duration: not wall-clock accurate and double-counts overlapping
  streams.
- Stripe-only integration in the enclave: exposes provider identifiers to the privacy
  boundary and couples an attested release to billing-vendor changes.
- gRPC from the enclave: it adds schema/tooling complexity without a streaming need; the
  bounded JSON operations fit authenticated HTTPS and durable outboxes.
