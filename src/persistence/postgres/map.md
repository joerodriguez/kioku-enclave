# `src/persistence/postgres/` map

The sole structured-state implementation. Every adapter shares one bounded SQLx PostgreSQL pool,
uses tenant-qualified queries, database time for leases/deadlines, and explicit transactions for
claims and settlement. Serving startup accepts finalized schema 26 or the exact receipted 25/26
expand during the ADR-0041 mixed-fleet window. Topology publication remains hard-dark even after
finalization until a later release adds a durable fleet-wide activation receipt and mixed-process
finalizer fence. Only the explicit release migrator applies the append-only files under `migrations/`.

| File | Responsibility |
|---|---|
| `mod.rs` | TLS PostgreSQL pool construction, UTC/statement-timeout policy, schema marker primitives, disposable test ladder, and shared transaction helpers. |
| `schema_release.rs` | Session-locked online v26 release: collision-refusing receipted DDL, exact per-step catalog evidence, concurrent guards/indexes, compatibility-trigger barrier, resumable keyset backfill, baked-anchor Ed25519 fleet authorization, and serving/writer re-verification. |
| `admission.rs` | Fleet token buckets and crash-recoverable concurrency leases. |
| `billing.rs` | Creating and lookup-only billing pseudonym resolution, recording lease/credit receipts, coverage anchors, retained-account metrics, and detach work. |
| `capture.rs` | Atomic capture/reference admission, media metadata, receipts, event/session status, and replay. |
| `delivery_outbox.rs` | Fleet-owned email, webhook, and push candidate selection, frozen requests, claims, expiry takeover, and exact settlement. |
| `entitlement.rs` | Active-account checks and atomic daily quota/Vertex reservations. |
| `episode_deletion.rs` | Durable logical freeze, exact GCS inventory, provider-cleanup progress, structured purge, and replay receipt. |
| `finalization.rs` | Finalization claims, source projection, and atomic recap/episode/outbox settlement. |
| `identity.rs` | Accounts, provider identities, signup budget, Apple credentials/grants, and coherent session reads. |
| `lifecycle.rs` | Pre-fence account admission tombstones, deletion-owned recovery of expired outbound claims/global lanes, deletion ownership/progress, transactionally marked reviewer-fixture refusal, revocation settlement, cascading purge, and no-resurrection checks. |
| `media_processing.rs` | Media work claims, attempts, usage, screen/audio projection with stable owner-source classification, voice jobs, bounded retry/resurrection, and retention progress. |
| `memory_formation.rs` | Summarizer windows, turn-timed source projections, episode/member writes, complete memory/final-brief human-text embeddings, and atomic durable cursor settlement. |
| `memory_reconciliation.rs` | PostgreSQL source-closure snapshots and fingerprints, fleet claims, structured staged model results, serializable topology publication, and bounded handle resolution. |
| `model_usage.rs` | Paid-model intents/outcomes, usage batch claims/delivery, and coverage reconciliation. |
| `notification.rs` | Webhook destinations, email consent, push installations, and configuration/disclosure-fence serialization. |
| `oauth.rs` | OAuth registration, consent, authorization codes, native sessions, and refresh-token rotation. |
| `playback.rs` | Tenant-qualified recording timelines/segments, identified-person-only link projections, and exact person-memory availability. |
| `query.rs` | PostgreSQL full-text/pgvector retrieval and hybrid fusion across memories, final briefs, transcripts, and screen evidence; batched stable memory/identified-person navigation; turn-timed episode members; feed/people/evidence projections; MCP query shapes; and capture status. |
| `recording_retention.rs` | Retention preview/CAS, key epochs, exact media inventory, and downgrade reconciliation. |
| `work.rs` | Fleet active-account enumeration and PostgreSQL-backed summarizer cursor storage. |

No adapter reads a filesystem or GCS database, and no route can choose a structured-state
implementation. Real PostgreSQL contracts—not alternate-backend parity—are the release authority
for tenant isolation, type/time-zone behavior, search, concurrency, restart, export, and deletion.
