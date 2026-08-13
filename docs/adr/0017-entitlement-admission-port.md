# ADR-0017: Provider-neutral entitlement admission port

- Status: Accepted
- Date: 2026-08-09
- Revised: 2026-08-13

## Context

New cloud capture must stop when an account has no remaining allowance, while the
open-source, attested data plane must not embed a merchant, catalog, price, payment,
subscription, or tax implementation. Those commercial policies are independently
deployable and intentionally outside this repository.

## Decision

The enclave owns only a narrow entitlement port. It supplies a cryptographically random
account pseudonym, a deterministic idempotency key, the stable meter name
`recording_seconds_v1`, a bounded quantity, and server-observed time to an authenticated
external control plane. It accepts only a bounded decision, public reason class, duplicate
marker, and usage snapshot. No provider customer, transaction, product, price, invoice,
or subscription identifier may appear as a structured entitlement field. A deprecated
account-action facade may carry an opaque HTTPS URL whose contents the enclave neither
parses nor persists; that compatibility exception is not authorization input.

The authenticated client reserves server-timed wall-clock recording through a durable
60-second lease. Null lease identity starts or reattaches; the returned per-user opaque
lease identity renews. Every grant is prospective and exactly one minute. Durable request
receipts make authorization, process-crash recovery, and client retries idempotent. Every
new capture event requires an active lease; multiple media streams and screenshots do not
consume the meter again.

The external control plane owns all commercial policy and provider adapters. The
enclave's compatibility facade may pass through a bounded entitlement snapshot or an
opaque HTTPS account-action URL, but it does not interpret the commercial implementation.
New clients should use the hosted account surface for purchase and plan management.
Allowance amount and cadence are likewise external policy. The enclave forwards exact
period bounds from the snapshot and never assumes a calendar month, calendar week, or
rolling window.

## Consequences

- Catalog, pricing, payment-provider, refund, tax, and subscription changes require no
  enclave release.
- Reads, search, export, and deletion remain available when new capture is denied.
- A control-plane outage fails new capture closed without exposing provider detail.
- The lease protocol is a Kioku admission contract, not a payment-provider API.

## Alternatives rejected

- Embedding a merchant SDK or catalog in the enclave couples attestation to private
  commercial implementation and leaks that implementation into the public repository.
- Metering media duration double-counts overlapping streams and omits silence/screens.
- OpenFeature provider resolution alone is insufficient because a prospective usage
  reservation needs durable idempotency and atomic consumption, not only flag evaluation.
