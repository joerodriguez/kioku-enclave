# `src/persistence/postgres/` map

The sole structured-state implementation. Every adapter shares one bounded SQLx PostgreSQL pool,
uses tenant-qualified queries, database time for leases/deadlines, and explicit transactions for
claims and settlement. Serving startup accepts finalized schema 26 or the exact receipted 24/26
expand during the ADR-0041 mixed-fleet window. The additive v27 activation contract keeps
reconciliation egress dark through install/drain, attaches legacy/deletion guards at signed
Draining, and enables topology publication only from a signed Active generation with exact
fleet-image, source-completeness, and provider-contract fences. Pause is forward-only. Only the explicit
release migrator applies the append-only files under `migrations/`.

| File | Responsibility |
|---|---|
| `mod.rs` | TLS PostgreSQL pool construction, UTC/statement-timeout policy, schema marker primitives, disposable test ladder, and shared transaction helpers. |
| `aggregate_audit.rs` / `aggregate_audit.sql` / `aggregate_audit_fixture.json` | Fixed, content-free post-deploy PostgreSQL aggregate snapshot in a repeatable-read, read-only transaction; strict recent UTC cutoff validation and exact operator JSON contract. Its staged readiness keeps every shared safety gate on both transitions, excludes phase-gated formation repair only from `ready_for_drain`, and requires formation quiescence for `ready_for_active`. |
| `schema_release.rs` | Session-locked online v24-to-v26 release plus phase-aware v27 serving verification: marker-preserving expansion, exact per-step catalog evidence, concurrent indexes, baked-anchor Ed25519 fleet/activation authorization, and immutable model/location/producer readiness binding. |
| `activation.rs` | Append-only v27 install/backfill/drain/activate/pause/resume authority, shared/exclusive release-lock serialization before schema probes, sticky scope, durable candidate-fleet image identity, exact catalog/receipt verification, database guard installation, claim drain, and runtime/repository gates. |
| `admission.rs` | Fleet token buckets and crash-recoverable concurrency leases. |
| `billing.rs` | Creating and lookup-only billing pseudonym resolution, recording lease/credit receipts, coverage anchors, retained-account metrics, and detach work. |
| `capture.rs` | Atomic capture/reference admission, media metadata, provisional finish receipts, append-audited seal-generation reopen for late offline sources, exact deletion-tombstone replay acknowledgement without resurrection, event/session status, and replay. |
| `delivery_outbox.rs` | Fleet-owned email, webhook, and push candidate selection, frozen requests, claims, expiry takeover, and exact settlement. |
| `entitlement.rs` | Active-account checks and atomic daily quota/Vertex reservations. |
| `episode_deletion.rs` | Durable logical freeze plus uncapped keyset-paged member/root/family/session inventory, canonical/reference-family and provider-claim fences, bounded GCS acknowledgement before structured mutation, reference-before-root accepted-sequence tombstone/purge, media aggregate cleanup/replan, formation refresh, exact terminal closure, and replay receipt. |
| `finalization.rs` | Database-time finalization claims, the activation/account/episode provider-egress fence held through terminal usage, source projection, and atomic recap/episode/outbox settlement. |
| `identity.rs` | Accounts, provider identities, signup budget, Apple credentials/grants, and coherent session reads. |
| `lifecycle.rs` | Pre-fence account admission tombstones, deletion-owned recovery of expired outbound claims/global lanes, deletion ownership/progress, transactionally marked reviewer-fixture refusal, revocation settlement, cascading purge, and no-resurrection checks. |
| `media_processing.rs` | Media work claims, attempts, usage, screen/audio projection with stable owner-source classification, voice jobs, database-time bounded retry/resurrection, and retention progress. |
| `memory_formation.rs` | Forward summarizer windows plus exact late-session formation revisions and durable bounded pages, frozen request/attempt recovery, reference-aware unowned source projection, evidence-free deletion tombstones, renewed durable provider/deletion fences, pending-revision topology rebind, bounded legacy-finish import, four-hour quiet seal generations, episode/member writes, complete memory/final-brief human-text embeddings, and atomic durable settlement. |
| `memory_reconciliation.rs` | PostgreSQL formation/seal-complete source closures and fingerprints, active-generation claims, producer-bound provider egress/stages, bounded providerless oversized-neighborhood discovery plus independent commitment verification, serializable topology publication, and bounded handle resolution. |
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
