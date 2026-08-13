# ADR-0019: Privacy-preserving Vertex cost attribution

- Status: Accepted
- Date: 2026-08-09

## Context

Contribution margin needs direct inference cost per account. Vertex responses expose
usage metadata, model version, and traffic type, but model calls originate inside the TEE
and their prompts, outputs, provider response IDs, and internal capture/episode IDs must
not become billing data. A timeout can lose a billable response, while a received non-2xx
response is not billed.

## Decision

Before each Vertex request, create and durably flush an opaque `vtx_<random>` intent in
the encrypted per-user SQLite database. If intent persistence fails, fail the operation
before paid egress. Every call uses one of four billing operations:
`audio_understanding`, `screen_understanding`, `episode_summarization`, or
`episode_finalization`. The row contains only operation, requested/returned model,
location, normalized traffic class, HTTP status when known, nullable token counters,
outcome, timestamps, and delivery state.

Parse and preserve `usageMetadata`, `promptTokensDetails`, `cacheTokensDetails`,
`modelVersion`, and `trafficType`. Normalize traffic to `on_demand`, `batch`, or
`provisioned_throughput`; omission defaults to `on_demand` because these requests are
known pay-as-you-go calls. An absent modality in a present details array is zero. A
metered event requires coherent primary usage with positive prompt and total tokens.
Missing or inconsistent usage becomes `usage_missing`, and every token field sent for
that event is null—absence is never represented as zero. Cache modality fields are either
all null or all integers whose sum equals cached input and do not exceed corresponding
input modalities.

Outcome rules:

- Valid HTTP 200 plus coherent usage: `metered`, `http_status=200`.
- Valid HTTP 200 without coherent usage: `usage_missing`, `http_status=200`.
- Transport timeout/lost response: `ambiguous`, `http_status=null`.
- Malformed HTTP 200: `ambiguous`, `http_status=200`.
- Received non-2xx: terminal internal `not_billed`; never deliver it.
- A crash-stale intent becomes `ambiguous` after the generation timeout horizon.

An asynchronous per-user outbox sends batches of 1–100 to
`POST /internal/v1/vertex-usage/batch`. Events contain the random billing account ID and
opaque event ID, never Google identity, email, content, response ID, or capture/episode
identifier. The backend deduplicates `event_id`. Delivery completes only when
`accepted + duplicates` equals the batch size; `unpriced` and `ambiguous` are overlapping
quality counters, not delivery acknowledgements. Downstream delivery failure never
retries model generation; only inability to persist the pre-egress intent blocks a call.

Each intent/delivery transition also advances a durable monotonic per-account/month
coverage snapshot. The worker posts exact snapshots to
`POST /internal/v1/vertex-usage/coverage` with `sequence`, unresolved pending count, and
lost count. A current-month zero is sent only after all paid-call intents are durably
delivered; an older sequence cannot overwrite a newer nonzero snapshot. Accepted,
duplicate, and stale acknowledgements are mutually exclusive. `lost_events` is zero by
construction because paid egress is impossible without a durable intent.

The owner facade rereads every active user's current-month local snapshot at report
time and replaces the upstream row's `direct_vertex.producer_coverage`, recomputing
age/freshness against report generation time. Local pending or lost events, stale or
missing coverage, or a read failure makes modeled Vertex totals and sustainable/cash
contribution null. Because observed GCP allocation needs a complete all-account
denominator, any unsafe local snapshot makes `allocated_gcp_observed_costs.vertex`
unallocated. This closes the interval between a newly persisted intent and the next
asynchronous coverage delivery.

## Consequences

- Exact attribution is possible when Vertex supplies coherent counters; missing and
  ambiguous cost remains explicitly visible rather than silently understated.
- Per-user ledgers and pending outbox rows disappear with the encrypted user database on
  account deletion.
- Backend pricing stays model/version/location/traffic aware and can change without an
  enclave release.
