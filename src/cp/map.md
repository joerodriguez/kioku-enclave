# map.md — src/cp/ (in-enclave control plane)

The control plane runs inside the enclave. All
of this runs in the one attested binary; handlers call the data-plane query/storage code
([`../search.rs`](../map.md), `../timeline.rs`, `../episodes.rs`, `../ingest.rs`) in-process
— no HTTP hop. Routes are wired in [`../main.rs`](../map.md).

| File | Role |
|---|---|
| `mod.rs` | `CpConfig` validates image-baked OAuth audiences, allow-list, HTTPS API/browser origins, Vertex, and quotas; production JWT secrets come from the KMS-protected control store and the web OAuth secret comes from Secret Manager. `CpState` holds shared stores, verifiers, limiters, and the embedder |
| `tokens.rs` | HS256 JWTs (access / OAuth state / auth-code), PKCE S256, sha256-hex, opaque tokens, UUIDv4 |
| `control_store.rs` | Identity + accounting in the context-bound encrypted SQLite blob `control/control.db.enc` (users, deletion tombstones, OAuth clients/codes, refresh tokens, usage, redacted query log); migration images rewrite legacy encryption on load |
| `auth.rs` | End-user Google ID-token verifier (audiences = our OAuth client ids) + `require_auth` middleware → attaches `AuthUser` |
| `cors.rs` | Hand-rolled CORS for the single image-baked HTTPS `WEB_ORIGIN`: answers OPTIONS preflights and stamps `Access-Control-Allow-Origin` only for that exact origin. Layered outside `require_auth` so preflights do not 401; bearer tokens still gate requests |
| `oauth.rs` | OAuth 2.1-style facade + bounded DCR: discovery, `/register`, explicit consent at `/authorize`, Google callbacks, persisted single-use authorization codes, PKCE, and atomic client-bound refresh rotation at `/token` |
| `sync.rs` | `/api/sync/batch` (utterance→segment join), `/status`, `/api/export`, `/api/account` |
| `query.rs` | MCP server `/mcp` (JSON-RPC, 6 tools) + REST mirrors `/api/search`, `/api/episodes`, direct `GET /api/episodes/{id}`, `/.../members`, `DELETE /api/episodes/{id}` (purge: episode + member raw records, returns deleted source keys for the Mac's local purge), and `GET /api/feed` (ADR-0008 fused feed). List and direct detail share one row-shaping query, including final briefs and visibility rules; ADR-0009 browse/detail default to hiding `substance=none` and accept `include_low`. ADR-0010 screenshot-image plans expose remaining count/byte budgets and minute-gist boundaries; uploads revalidate eligible nonduplicate membership, decode JPEG bytes, enforce exact hashes/dimensions and the 4-image/600-KiB episode cap transactionally, remain same-hash idempotent, and install one per-user media DEK with first-writer-wins semantics. Search returns `{episodes, results}` — episodes first-class (relevance-ranked, with snippets + minute_summaries; ADR-0004) |
| `summarizer.rs` | v2 incremental episode summarizer + internal tokio cron (replaces Cloud Scheduler). Open-episode context carries type, participants, the current summary and action items, and the recent timeline so the model extends a shared workflow instead of fragmenting it. Single-pass output includes a concrete, actionable summary, attributed minute gists, exact user-directed actions/resources (including full captured URLs), ADR-0009 substance, and ADR-0010 visual-evidence classification. Guarded one-time historical passes backfill substance and, for normal episodes with screenshot members, visual evidence from stored episode text plus screenshot metadata/OCR only (never image pixels); completion markers are written only after a fully valid pass. After upsert it embeds each episode in-enclave (candle, pinned MODEL_ID → `vec_episodes`, §G.2). Live-tail cursor semantics hold short/empty tails as documented in the module |
| `finalizer.rs` | Episode finalization worker that waits for the summarizer cursor and contributing-device watermarks, builds a bounded chronological log with timestamps, speaker/app/window attribution, exact evidence IDs, and mirrored mic/system utterances deduplicated, then extracts an allow-list of captured URLs, validates structured Gemini evidence references, and stores the canonical actionable brief. Finalization version 2 regenerates each older finalized brief once, preserves its original `finalized_at`, and never creates another Gmail outbox entry; first-time finalization may enqueue the configured Gmail delivery |
| `email_worker.rs` | Email outbox delivery worker that polls the pending/retry deliveries queue, refreshes Gmail OAuth credentials, constructs RFC 5322 MIME messages, and sends them via Gmail API |
| `vertex.rs` | Vertex Gemini client (`generateContent`) with caller-supplied constrained schemas: full episode output requires summary, action items, `minutes[]`, substance, and visual evidence; historical repairs use compact id/classification schemas. Sends text outside the TEE — documented caveat |
| `limits.rs` | Token-bucket rate limiter + daily quotas + query-log accounting |
| `isotime.rs` | RFC3339-UTC parse/format/add (no `chrono`; musl-friendly) |

> Identity/accounting writes are low-volume, so the control store persists the whole blob
> per write (fine here, unlike user indexes — see ADR-0002). Keep this `map.md` and the
> public API documentation and downstream clients in sync when routes change.
