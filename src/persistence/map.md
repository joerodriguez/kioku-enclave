# `src/persistence/` map

Typed application repository ports and their single production composition. Handlers and workers
depend on these use-case interfaces rather than `sqlx`, SQL callbacks, or object-provider details.
`RepositorySet::postgres` installs one complete PostgreSQL adapter set at startup; there is no
legacy adapter, backend selector, fallback, dual write, or shadow read.

| Path | Responsibility |
|---|---|
| `mod.rs` | Port exports and `RepositorySet`, which composes PostgreSQL repositories—including the durable reconciliation-activation authority—with the live encrypted-media object port. |
| `admission.rs` | Fleet token-bucket and crash-recoverable concurrency-lease contract. |
| `billing.rs` | Billing pseudonym, recording authorization/credit, coverage, retained-account metrics, and detach-outbox contract. |
| `capture.rs` | Atomic capture/reference preflight, commit, replay, deletion-tombstone no-resurrection, session, and event-status contract. |
| `delivery_outbox.rs` | Email, webhook, and push candidate/claim/frozen-request/settlement contract. |
| `entitlement.rs` | Active-account checks and atomic daily quota/Vertex reservations. |
| `episode.rs` | Pure episode merge/substance/visual-evidence domain rules shared by memory formation and deletion. |
| `episode_deletion.rs` | Durable episode freeze, bounded resumable provider/inventory advancement, exact terminal structured purge, and replay receipt. |
| `finalization.rs` | Claim and atomic recap/finalization/outbox settlement contract. |
| `identity.rs` | Account/session and Apple-credential contract. |
| `lifecycle.rs` | Durable pre-fence deletion request, account tombstone/no-resurrection progress, deletion-owned expiry recovery for already-admitted provider disclosures, persistent reviewer-fixture protection, provider revocation, and final cleanup contract. |
| `media_object.rs` | Provider-neutral encrypted-media object operations, exact-generation reads, account/episode purge, and all-generation reconciliation. |
| `gcs_media.rs` | Live GCS media adapter joining PostgreSQL object identity to the provider semantics in `../gcs.rs`. It never stores structured state in GCS. |
| `media_processing.rs` | Media job claim, usage, screen/audio projection, owner-source classification, voice evidence, retry, and settlement contract. |
| `memory_formation.rs` | Forward-window and exact capture-session revision/page claims, frozen bounded provider requests and stable attempt identities, turn-timed/reference-aware source evidence, evidence-free accepted-sequence tombstones, renewed deletion-fenced provider authorization and settlement, open-memory projection, explicit accounted/no-memory outcomes, atomic cursor/episode settlement, and embedding-source contract over memory text plus final-brief human values. |
| `memory_reconciliation.rs` | Source-settled cohort snapshots, fleet leases, durable staged partitions, bounded providerless neighborhood discovery/verification, atomic active-topology publication, and content-free handle resolution contract. |
| `model_usage.rs` | Vertex intent/outcome, billing batch claim, and coverage reconciliation contract. |
| `notification.rs` | Webhook, email-consent, and push-installation configuration with redacted secret-bearing types. |
| `oauth.rs` | OAuth client, consent, authorization-code, native-session, and refresh-token transaction contract. |
| `playback.rs` | Recording playback dataset and exact identified-person memory page/availability projection contract. |
| `query.rs` | Tenant-scoped full-text/vector search over memories, structured final briefs, transcripts, and screen evidence; stable memory navigation and identified-person link projections; MCP query projections; turn-timed episode members; and feed/people/browser/screenshot reads plus capture status. |
| `recording_retention.rs` | Retention preview/CAS, durable recording-key epoch, exact inventory, and downgrade completion. |
| `work.rs` | Fleet active-account enumeration, summarizer cursor storage, and shared outbound-provider outcome validation. |
| [`postgres/`](postgres/map.md) | The only structured-state implementation: bounded SQLx pool plus every repository adapter. |

The media port is intentionally separate from structured repositories so useful domain fakes can
exercise handler/worker behavior without coupling to SQLx or making GCS an alternate database.
