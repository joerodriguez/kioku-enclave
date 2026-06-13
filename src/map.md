# map.md — src/ (enclave service)

The Rust service. As of **ADR-0001 it is the entire Kioku backend** (not just the data
plane): it terminates TLS and serves OAuth, sync, the MCP server, account, quotas, and the
summarizer — see [`cp/`](cp/map.md) — alongside the original data-plane query/storage code.
Plaintext exists only here (and SEV tmpfs), never on disk.

| File | Role |
|---|---|
| `main.rs` | Entry point; wires the legacy `/v1/*` data-plane routes **and** the `cp` control-plane routes; `serve_tls` accept loop when TLS is on; `dump_user_export` |
| `tls.rs` | **In-enclave TLS termination (ADR-0001).** Loads a deploy-provided cert/key, builds a rustls config (ring), computes the cert SHA-256 fingerprint (RA-TLS channel-binding value). Gated by `ENCLAVE_TLS` |
| [`cp/`](cp/map.md) | **Control plane (ADR-0001):** OAuth/DCR, sync, account, MCP + REST, quotas, summarizer, identity control store. Replaces the deleted Node `cloud/` |
| `attestation.rs` | Confidential Space attestation: VM OIDC token, KMS-gated key release |
| `auth.rs` | Legacy caller auth — verifies the control-plane SA ID token for the `/v1/*` routes |
| `crypto.rs` | AES-256-GCM encrypt/decrypt of per-user (and control) SQLite blobs; key handling |
| `store.rs` | Per-user encrypted SQLite blob storage in GCS (load → decrypt → mutate → encrypt → persist) |
| `ingest.rs` | Ingest transcripts + OCR text; `ingest_batch` is the in-process entry the `cp::sync` path calls |
| `search.rs` | Full-text search (SQLite FTS5); `search_all` is called in-process by `cp::query` |
| `timeline.rs` | Context / time-range queries; `fetch_context` called in-process by MCP `get_context` |
| `episodes.rs` | v2 episode storage; `upsert_episodes` called in-process by `cp::summarizer` |
| `error.rs` | Error types + HTTP mapping |

> Security reminders: don't weaken the attestation/ID-token path; never log decrypted
> content or write plaintext to persistent disk. FTS5 external-content tables MUST use
> the `'delete'` command on update (plain DELETE/UPDATE corrupts the index — see
> PROGRESS.md). Keep this `map.md` and the `/v1/*` contract (monorepo CONTRACTS.md) in
> sync when modules change.
