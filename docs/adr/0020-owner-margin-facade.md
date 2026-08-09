# ADR-0020: Owner-only contribution-margin facade

- Status: Accepted
- Date: 2026-08-09

## Context

The owner needs a monthly operating view by customer email, while the billing service
intentionally has only random account IDs. Email and the active-user roster must not cross
the billing boundary. Persistent storage size is not currently measurable without a new
privacy-sensitive inventory path.

## Decision

Authorize owners using image-baked stable UUIDs in `ADMIN_USER_IDS`, separate from
`ALLOWED_EMAILS`. The handler checks this list before reading active identities or calling
the billing service.

- `GET /api/admin/capabilities` reports the estimated-margin view and current logical
  storage-byte measurement.
- `GET /api/admin/margin?limit=1..100&after=<optional cursor>` is current-month only and
  forwards bounded pagination to `/internal/v1/admin/margin`. It lists active
  `(UUID,email)` pairs inside the enclave, obtains their random billing account IDs, then
  replaces account IDs with email for only the returned page. Callers continue until
  `next_cursor` is null and must use a defensive page cap/mark incomplete if exceeded.

Neither email nor UUID is sent upstream. Random account IDs are removed before the public
response. Responses are `Cache-Control: no-store`. Non-admin callers receive HTTP 403
before upstream access or email enumeration.

The report labels `margin_kind=estimated_contribution_margin`. For each returned active
account the enclave measures current logical bytes as SQLite allocated pages plus declared
encrypted media-object bytes. This is a current driver, not byte-month usage or actual
storage cost. It also counts accepted current-month email deliveries from the encrypted
user database; provider invoice cost remains null with
`status=provider_invoice_unavailable`. A failed local measurement is null/unavailable.

For each active user, reread the current-month local Vertex coverage sequence, pending/lost
counts, and observed time while assembling the report. Replace the billing row's
`direct_vertex.producer_coverage` with that local snapshot and recompute its age/freshness
against the upstream report's `generated_at`, retaining the bounded freshness basis and
`population_complete=false`. Pending/lost events, stale or missing coverage, or an unreadable
database force modeled Vertex totals plus sustainable/cash contribution and margin null.
Any such account makes `allocated_gcp_observed_costs.vertex` globally unallocated;
otherwise an asynchronously stale zero could understate cost. `paddle_observed` remains
explicitly webhook-observed evidence and every legacy flat `actual_*` value remains null.
Storage cost and other shared pools remain nullable when not reconciled. The facade never
fabricates zero for unavailable cost.

## Consequences

- The enclave is the only join point between customer email and billing pseudonym.
- Changing the owner set requires a new attested image digest.
- The dashboard can render useful revenue and Vertex data immediately while clearly
  distinguishing unavailable cost pools from zero cost.
