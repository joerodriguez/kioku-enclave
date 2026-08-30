# `src/persistence/postgres/` map

The sole structured-state implementation. Every adapter shares one bounded SQLx PostgreSQL pool,
uses tenant-qualified queries, database time for leases/deadlines, and explicit transactions for
claims and settlement. Serving startup verifies schema version 25; only the explicit release
migrator applies the append-only files under `migrations/`.

| File | Responsibility |
|---|---|
| `mod.rs` | TLS PostgreSQL pool construction, UTC/statement-timeout policy, schema verification, explicit migration ladder/lock, and shared transaction helpers. |
| `admission.rs` | Fleet token buckets and crash-recoverable concurrency leases. |
| `billing.rs` | Billing pseudonyms, recording lease/credit receipts, coverage anchors, retained-account metrics, and detach work. |
| `capture.rs` | Atomic capture/reference admission, media metadata, receipts, event/session status, and replay. |
| `delivery_outbox.rs` | Fleet-owned email, webhook, and push candidate selection, frozen requests, claims, expiry takeover, and exact settlement. |
| `entitlement.rs` | Active-account checks and atomic daily quota/Vertex reservations. |
| `episode_deletion.rs` | Durable logical freeze, exact GCS inventory, provider-cleanup progress, structured purge, and replay receipt. |
| `finalization.rs` | Finalization claims, source projection, and atomic recap/episode/outbox settlement. |
| `identity.rs` | Accounts, provider identities, signup budget, Apple credentials/grants, and coherent session reads. |
| `lifecycle.rs` | Pre-fence account admission tombstones, deletion ownership/progress, transactionally marked reviewer-fixture refusal, revocation settlement, cascading purge, and no-resurrection checks. |
| `media_processing.rs` | Media work claims, attempts, usage, screen/audio projection with stable owner-source classification, voice jobs, bounded retry/resurrection, and retention progress. |
| `memory_formation.rs` | Summarizer windows, turn-timed source projections, episode/member writes, embeddings, and atomic durable cursor settlement. |
| `model_usage.rs` | Paid-model intents/outcomes, usage batch claims/delivery, and coverage reconciliation. |
| `notification.rs` | Webhook destinations, email consent, push installations, and configuration/disclosure-fence serialization. |
| `oauth.rs` | OAuth registration, consent, authorization codes, native sessions, and refresh-token rotation. |
| `playback.rs` | Tenant-qualified recording timelines/segments and person-memory availability. |
| `query.rs` | PostgreSQL full-text/pgvector retrieval, hybrid fusion, turn-timed/person-attributed episode members, feed/people/evidence projections, MCP query shapes, and capture status. |
| `recording_retention.rs` | Retention preview/CAS, key epochs, exact media inventory, and downgrade reconciliation. |
| `work.rs` | Fleet active-account enumeration and PostgreSQL-backed summarizer cursor storage. |

No adapter reads a filesystem or GCS database, and no route can choose a structured-state
implementation. Real PostgreSQL contracts—not alternate-backend parity—are the release authority
for tenant isolation, type/time-zone behavior, search, concurrency, restart, export, and deletion.
