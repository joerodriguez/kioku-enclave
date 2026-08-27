# PostgreSQL persistence

The production-target implementations of the backend-neutral persistence
ports. They share one bounded SQLx pool and PostgreSQL transaction authority.
The module is compiled and contract-tested during extraction, but startup must
not select it until every active domain has moved off the legacy stores.

| File | Role |
|---|---|
| `mod.rs` | Pool construction, UTC/timeout policy, explicit migrator, schema verification, and shared transaction helpers. |
| `billing.rs` | Fleet-wide billing pseudonyms, recording lease/credit receipts, coverage anchors, and detach outbox. |
| `entitlement.rs` | Fleet-wide active-account checks and atomic daily quota/Vertex reservations. |
| `identity.rs` | PostgreSQL accounts, identities, signup budget, Apple credentials, and coherent session reads. |
| `notification.rs` | PostgreSQL webhook destinations, email consent, and bounded push installation registry serialized against send fences. |
| `oauth.rs` | PostgreSQL OAuth client registration, consent/code consumption, and refresh-token rotation. |
| `work.rs` | PostgreSQL-authoritative email, webhook, and push send capabilities, outcome receipts, cancellation, and exact reconciliation. |
