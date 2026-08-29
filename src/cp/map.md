# `src/cp/` map

The in-enclave product layer serves OAuth, capture, query, MCP, export/deletion, retention,
playback, and owner surfaces and runs the restartable background workers. Structured state and
fleet coordination are always PostgreSQL-backed through the typed ports in `../persistence/`.
Encrypted large media is accessed only through that layer's live GCS media port.

There are no per-module WAL children, SQLite control store, archive selector, or legacy worker
lane. Provider workers claim and freeze work durably in PostgreSQL before I/O, settle with exact
claim ownership afterward, and treat an ambiguous outcome as no-resend.

| File | Responsibility |
|---|---|
| `mod.rs` | `CpConfig`, shared `CpState`, provider-neutral composition, bounded HTTP clients, Secret Manager access, and common content-free error behavior. |
| `apple.rs` | Sign in with Apple native/browser verification, grant retention/revocation, and account linking through identity repositories. |
| `auth.rs` | Kioku access-token and Google/Apple/reviewer identity middleware, active/deleting-account rules, route authorization, and bounded provider-auth evidence for destructive operations. |
| `billing.rs` | Provider-neutral entitlement/recording admission, offline usage reconciliation, pseudonymous billing delivery, and coverage reporting. |
| `cors.rs` | Exact public-origin CORS policy. |
| `delivery.rs` | Canonical finalized-memory delivery model and PostgreSQL-backed loader shared by outbound channels. |
| `dlp.rs` | Bounded sensitive-data classification/redaction helpers. |
| `email_renderer.rs` | Pure text/HTML email rendering, escaping, and link safety. |
| `email_worker.rs` | PostgreSQL-claimed Resend delivery with frozen requests, bounded retry, disclosure fences, ambiguity no-resend, and horizontally safe settlement. |
| `finalizer.rs` | Restartable final-memory/recap worker and atomic creation of email, webhook, and APNs outbox rows. |
| `identity.rs` | Identity facade and account/session projections. |
| `isotime.rs` | RFC 3339 UTC parsing, formatting, and arithmetic. |
| `limits.rs` | Volatile request rate limiting plus PostgreSQL fleet admission, quota, concurrency, and Vertex reservation use. |
| `mcp_safety.rs` | MCP query/projection boundary, pagination limits, restricted-data refusal, URL minimization, and recursive response redaction. |
| `media.rs` | Cloud Capture ingestion, reference batching, exact live-media admission, encryption, and transactional receipt/session settlement. |
| `media_planner.rs` | Deterministic bounded audio/screen processing work-unit planning. |
| `media_worker.rs` | PostgreSQL-claimed media processing, KMS/GCS/Vertex work, result projection, voice work, bounded retry/resurrection, and retention cleanup. |
| `model_usage.rs` | Durable Vertex intent/outcome accounting, usage delivery, and coverage reconciliation. |
| `oauth.rs` | OAuth 2.1 discovery, dynamic registration, Google/Apple/reviewer PKCE consent/code flow, durable client-bound refresh rotation for native and local-device web sessions, and the native session facade. |
| `playback.rs` | Owner-authorized recording timeline, JavaScript-exact revision projection, owner-source display, and exact encrypted-segment serving. |
| `push.rs` | APNs installation/handoff routes and PostgreSQL-claimed content-free ready notifications with credential-generation fences and no-resend ambiguity. |
| `query.rs` | REST/MCP search, episodes, feed, people, browser evidence, screenshots, webhooks, and durable episode-deletion initiation/status behavior. |
| `retention.rs` | Recording-retention preview/CAS, key epochs, downgrade reconciliation, and durable-recording policy routes. |
| `screen_understanding.rs` | Bounded screen/storyboard result validation and projection. |
| `summarizer.rs` | PostgreSQL-claimed incremental memory formation, bounded Vertex summarization, in-enclave embedding, and cursor settlement. Recurring and session-settled passes traverse only proven-empty sparse-history windows and stop at the first outcome that may have invoked the model; queued duplicate hints coalesce without suppressing a later media-complete edge. |
| `sync.rs` | Compatibility tombstones plus current account export and restartable account-deletion status/routes. |
| `tokens.rs` | JWT/PKCE/opaque-token primitives and account-, lease-, retention-, and revision-bound capabilities. |
| `vertex.rs` | Bounded Vertex Gemini adapter with strict schemas and content-free usage metadata. |
| `voice_memory.rs` | Pure-Rust audio decoding, fbank, and pinned WeSpeaker inference used by explicit voice-evaluation tooling. |
| `voice_quality.rs` | Versioned enrollment/matching quality policy and robust representative selection. |
| `voice_eval.rs` | Public voice/identity/diarization scoring contract and real-corpus release classification. |
| `voice_eval_assets.rs` | Offline, hash-bound licensed-corpus derivation outside Git. |
| `voice_eval_evidence.rs` | Strict real-run evidence reducer binding model, media, identity, export, and deletion results. |
| `voice_eval_similarity.rs` | Offline similarity calibration over exact private inputs without persisting embeddings or content. |
| `webhook_worker.rs` | PostgreSQL-claimed signed CloudEvent delivery with SSRF controls, per-destination ordering, disclosure fencing, ambiguity no-resend, and horizontal settlement. |

## Worker and API invariants

- Claim acquisition, expiry takeover, cancellation, and settlement use database time and exact
  compare-and-set predecessors; no database lock is held across provider I/O.
- Account/destination deletion prevents new disclosure, conflicts with a currently frozen send,
  and cannot be bypassed by a stale worker.
- Query absence remains distinguishable from PostgreSQL/provider unavailability and malformed
  encrypted evidence; public errors never contain content.
- Export includes selected tenant-qualified PostgreSQL rows and media metadata, not GCS bytes; full
  media-byte export remains an activation blocker. Episode/account deletion remains restartable
  and cannot report completion before PostgreSQL and GCS converge.
- Process-local pacing/circuits are only accelerators; PostgreSQL claims are the service-wide
  correctness boundary for horizontal workers.
