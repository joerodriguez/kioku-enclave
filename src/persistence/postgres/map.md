# PostgreSQL persistence

The production-target implementations of the backend-neutral persistence
ports. They share one bounded SQLx pool and PostgreSQL transaction authority.
Startup selects the complete set once and refuses any fallback to legacy state.

| File | Role |
|---|---|
| `mod.rs` | Pool construction, UTC/timeout policy, explicit migrator, schema verification, and shared transaction helpers. |
| `admission.rs` | Database-clocked fleet token buckets and crash-recoverable concurrency leases. |
| `billing.rs` | Fleet-wide billing pseudonyms, recording lease/credit receipts, coverage anchors, and detach outbox. |
| `entitlement.rs` | Fleet-wide active-account checks and atomic daily quota/Vertex reservations. |
| `episode_deletion.rs` | Durable freeze, exact media inventory, structured purge, and replay receipt for episode deletion. |
| `identity.rs` | PostgreSQL accounts, identities, signup budget, Apple credentials, and coherent session reads. |
| `lifecycle.rs` | PostgreSQL account tombstones, deletion progress, Apple-revocation settlement, cascading purge, and billing-detach creation. |
| `notification.rs` | PostgreSQL webhook destinations, email consent, and bounded push installation registry serialized against send fences. |
| `oauth.rs` | PostgreSQL OAuth client registration, consent/code consumption, and refresh-token rotation. |
| `playback.rs` | Tenant-qualified recording playback datasets and person-memory availability projections. |
| `query.rs` | Tenant-qualified PostgreSQL full-text/vector retrieval, hybrid fusion, stable episode pagination/facets/final briefs, merged feed, and capture status. |
| `recording_retention.rs` | Fleet-wide retention preview/CAS, durable key epochs, exact inventory, and downgrade completion. |
| `work.rs` | PostgreSQL-authoritative fleet account enumeration, summarizer cursor, email, webhook, and push send capabilities, outcome receipts, cancellation, and exact reconciliation. |
