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
| `oauth.rs` | OAuth 2.1 facade + DCR: discovery, `/register`, `/authorize`, Google `/callback`, `/token` |
| `sync.rs` | `/api/sync/batch` (utterance→segment join), `/status`, `/api/export`, `/api/account` |
| `query.rs` | MCP server `/mcp` (JSON-RPC, 6 tools) + REST mirrors `/api/search`, `/api/episodes`, `/.../members` |
| `summarizer.rs` | v2 incremental episode summarizer + internal tokio cron (replaces Cloud Scheduler) |
| `vertex.rs` | Vertex Gemini client (`generateContent`, constrained schema). Sends text outside the TEE — documented caveat |
| `limits.rs` | Token-bucket rate limiter + daily quotas + query-log accounting |
| `isotime.rs` | RFC3339-UTC parse/format/add (no `chrono`; musl-friendly) |

> Identity/accounting writes are low-volume, so the control store persists the whole blob
> per write (fine here, unlike user indexes — see ADR-0002). Keep this `map.md` and the
> contracts in the monorepo `docs/CLOUD.md` in sync when routes change.
