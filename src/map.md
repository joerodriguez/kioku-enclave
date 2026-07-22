# map.md — src/ (enclave service)

The entire attested Kioku backend: it terminates TLS and serves OAuth, sync, MCP/REST,
account, quotas, and the summarizer—see [`cp/`](cp/map.md)—alongside the legacy `/v1/*`
query/storage API. Plaintext databases exist only here and in SEV tmpfs, never on
persistent disk; selected summarisation text and opted-in final-brief email leave the TEE
through the documented Vertex/Gmail trust boundaries.

| File | Role |
|---|---|
| `main.rs` | Entry point; wires public OAuth, auth-gated control-plane routes, legacy `/v1/*`, and public health/attestation; production serves only through `serve_tls`, while plaintext application HTTP requires a debug build plus `ENCLAVE_TEST_MODE=1`; spawns the isolated ACME :80 listener and renewal loop |
| `tls.rs` | In-enclave rustls termination with a swappable certificate resolver and SHA-256 leaf fingerprint. Production uses ACME; static/generated certificate paths are custom/debug fallback mechanisms, not production launch overrides |
| `acme.rs` | Required production ACME lifecycle: answers HTTP-01 on :80, generates the TLS key in the TEE, persists account/cert/key as context-bound KMS-wrapped state (`acme/tls.json.enc`), blocks boot until a usable cert exists, and hot-swaps renewals |
| [`cp/`](cp/map.md) | **Control plane:** OAuth/DCR, sync, account, MCP + REST, quotas, summarizer, and identity control store |
| `attestation.rs` | Two separated Confidential Space token paths: internal WIF-audience STS exchange for KMS credentials, and public HTTPS-verifier-audience OIDC tokens that can never use the WIF audience |
| `auth.rs` | Legacy caller auth — verifies the control-plane SA ID token for the `/v1/*` routes |
| `crypto.rs` | KMS/DEK handling plus versioned, context-bound AES-256-GCM v2 blobs. Legacy formats fail closed unless a migration image bakes `ENCLAVE_ALLOW_LEGACY_BLOBS=1` |
| `store.rs` | Per-user encrypted SQLite storage in GCS (load → authenticate/decrypt → mutate → context-bound encrypt → generation-checked persist); a migration image rewrites legacy user blobs on first open |
| `ingest.rs` | Ingest transcripts + OCR text (+ their Mac-computed embeddings into vec0 tables, with a `source_key` backfill-upsert path and an embedding-model gate); `ingest_batch` is the in-process entry the `cp::sync` path calls |
| `search.rs` | Search (SQLite FTS5 + hybrid RRF with vec0 KNN over utterances, screenshots, AND episodes when a query embedding is present). Episode hits are the primary result entity (ADR-0004): relevance-ranked, with FTS snippets + minute_summaries; ADR-0009 excludes `substance=none` before FTS/speaker/hybrid ranking while retaining `low`. Speaker filter (ADR-0006 P3): `SearchRequest.speaker` or inline `speaker:Name` token — utterance `speaker_label` match, episode `participants` via json_each, empty-query browse modes. `search_all` / `search_episodes` are called in-process by `cp::query` |
| `embedding.rs` | **In-enclave query embedding (hybrid search).** candle BERT encoder (`paraphrase-multilingual-MiniLM-L12-v2`, 384-dim, pinned `MODEL_ID`) loaded from `EMBED_MODEL_DIR` (baked into the image). Chunked mean-pooling for long text (10k-char cap). Absent/failed engine → FTS-only, never fatal. Any client that precomputes document embeddings MUST use the identical model and configuration |
| `timeline.rs` | Context / time-range queries; `fetch_context` called in-process by MCP `get_context` |
| `episodes.rs` | v2 episode storage; `upsert_episodes` called in-process by `cp::summarizer`. Holds the ADR-0004 minute-timeline merge and ADR-0009 validated `none → low → normal` upgrade-only substance merge; `write_episode_embedding` stores in-enclave vectors in `vec_episodes`; `purge_episode` deletes an episode + member raw records (FTS/vec cleanup, emptied segments, cross-episode refs) for the user-initiated purge |
| `error.rs` | Error types + HTTP mapping |

> Security reminders: don't weaken the attestation/ID-token path; never log decrypted
> content or write plaintext to persistent disk. FTS5 external-content tables MUST use
> the `'delete'` command on update (plain DELETE/UPDATE corrupts the index — see
> PROGRESS.md). Keep this `map.md`, the public API documentation, and downstream `/v1/*`
> clients in sync when modules change.
