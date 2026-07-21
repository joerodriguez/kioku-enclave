# map.md — src/cp/ (in-enclave control plane)

The control plane (ADR-0001), folded into the enclave from the deleted Node `cloud/`. All
of this runs in the one attested binary; handlers call the data-plane query/storage code
([`../search.rs`](../map.md), `../timeline.rs`, `../episodes.rs`, `../ingest.rs`) in-process
— no HTTP hop. Routes are wired in [`../main.rs`](../map.md).

| File | Role |
|---|---|
| `mod.rs` | `CpConfig` (env-baked: JWT secrets, Google client ids, Vertex, quotas) + `CpState` (shared `Arc<Store>`, control store, verifier, limiters) |
| `tokens.rs` | HS256 JWTs (access / OAuth state / auth-code), PKCE S256, sha256-hex, opaque tokens, UUIDv4 |
| `control_store.rs` | Identity + accounting in an encrypted SQLite blob `control/control.db.enc` (users, oauth_clients, refresh_tokens, usage_daily, query_log). **Replaces Cloud SQL Postgres** |
| `auth.rs` | End-user Google ID-token verifier (audiences = our OAuth client ids) + `require_auth` middleware → attaches `AuthUser` |
| `cors.rs` | Hand-rolled CORS for the kiokuu.com web dashboard (ADR-0008): answers OPTIONS preflights and stamps `Access-Control-Allow-Origin` ONLY for the single `WEB_ORIGIN` env origin (default `https://kiokuu.com`). Layered OUTSIDE `require_auth` so preflights don't 401. Not an auth mechanism — bearer tokens still gate every request |
| `oauth.rs` | OAuth 2.1 facade + DCR: discovery, `/register`, `/authorize`, Google `/callback`, `/token` |
| `sync.rs` | `/api/sync/batch` (utterance→segment join), `/status`, `/api/export`, `/api/account` |
| `query.rs` | MCP server `/mcp` (JSON-RPC, 6 tools) + REST mirrors `/api/search`, `/api/episodes`, `/.../members`, `DELETE /api/episodes/{id}` (purge: episode + member raw records, returns deleted source_keys for the Mac's local purge), and `GET /api/feed` (ADR-0008 fused feed). ADR-0009 episode browse defaults to hiding `substance=none`, accepts `include_low`, and returns `hidden_count`; `low` remains visible. Search returns `{episodes, results}` — episodes first-class (relevance-ranked, with snippets + minute_summaries; ADR-0004) |
| `summarizer.rs` | v2 incremental episode summarizer + internal tokio cron (replaces Cloud Scheduler). Single-pass eager generation: title, exec summary, minute-timeline gists, and ADR-0009 substance; guarded one-time batched historical substance backfill stored in per-user metadata. After upsert it embeds each episode in-enclave (candle, pinned MODEL_ID → `vec_episodes`, §G.2). Live-tail cursor semantics hold short/empty tails as documented in the module |
| `finalizer.rs` | Episode finalization worker that sweeps eligible older episodes, extracts page/URL candidates, runs structured Gemini queries to verify referenced evidence, and stores final briefs in user content DB |
| `email_worker.rs` | Email outbox delivery worker that polls the pending/retry deliveries queue, refreshes Gmail OAuth credentials, constructs RFC 5322 MIME messages, and sends them via Gmail API |
| `vertex.rs` | Vertex Gemini client (`generateContent`) with caller-supplied constrained schemas: full episode output includes `minutes[]` + `substance`; historical backfill uses compact id/substance output. Sends text outside the TEE — documented caveat |
| `limits.rs` | Token-bucket rate limiter + daily quotas + query-log accounting |
| `isotime.rs` | RFC3339-UTC parse/format/add (no `chrono`; musl-friendly) |

> Identity/accounting writes are low-volume, so the control store persists the whole blob
> per write (fine here, unlike user indexes — see ADR-0002). Keep this `map.md` and the
> contracts in the monorepo `docs/CLOUD.md` in sync when routes change.
