# map.md — src/ (enclave service)

The entire attested Kioku backend: it terminates TLS and serves OAuth, sync, MCP/REST,
account, quotas, and the summarizer—see [`cp/`](cp/map.md)—alongside the legacy `/v1/*`
query/storage API. Plaintext databases exist only here and in SEV tmpfs, never on
persistent disk; bounded audio, screenshot pixels, transcript/screen text, and metadata
leave the TEE through the documented Vertex inference boundary, while explicitly
configured webhook events use the separate webhook boundary.

| File | Role |
|---|---|
| `main.rs` | Entry point; wires public OAuth, auth-gated control-plane routes (including Cloud Capture v2), legacy `/v1/*`, public health/attestation, and offline ADR-0016 derivation/similarity/evidence/scoring commands; starts media and summarization workers; production serves only through `serve_tls`, while plaintext application HTTP requires a debug build plus `ENCLAVE_TEST_MODE=1`; spawns the isolated ACME :80 listener and renewal loop |
| `tls.rs` | In-enclave rustls termination with a swappable certificate resolver and SHA-256 leaf fingerprint. Production uses ACME; static/generated certificate paths are custom/debug fallback mechanisms, not production launch overrides |
| `acme.rs` | Required production ACME lifecycle: answers HTTP-01 on :80, generates the TLS key in the TEE, persists account/cert/key as context-bound KMS-wrapped state (`acme/tls.json.enc`), blocks boot until a usable cert exists, and hot-swaps renewals |
| [`cp/`](cp/map.md) | **Control plane:** OAuth/DCR, sync, account, MCP + REST, quotas, summarizer, and identity control store |
| `attestation.rs` | Two separated Confidential Space token paths: internal WIF-audience STS exchange for KMS credentials, and public HTTPS-verifier-audience OIDC tokens that can never use the WIF audience |
| `auth.rs` | Legacy caller auth — verifies the control-plane SA ID token for the `/v1/*` routes |
| `crypto.rs` | KMS/DEK handling plus versioned, context-bound AES-256-GCM v2 blobs. Legacy formats fail closed unless a migration image bakes `ENCLAVE_ALLOW_LEGACY_BLOBS=1` |
| `archive_v3.rs` | **Inactive ADR-0022 foundation:** non-loggable opaque identities; zeroizing, context-verified KMS-wrap framing for the archive/media key registry; canonical HKDF/AES-GCM archive envelopes; bounded leaf/internal Merkle and root codecs; and a cursor-bounded immutable-backend contract with an in-memory test backend. The unsupported monolithic checkpoint role is reserved rather than implying a multi-GiB database fits one envelope; roots can name a future bounded checkpoint-manifest and WAL roots require that base. It has no KMS calls, Store/VFS/witness/route wiring, or write authority until the ADR shadow gates pass. |
| `store.rs` | Per-user encrypted SQLite storage plus encrypted raw-media object access in GCS (load → authenticate/decrypt → mutate → context-bound encrypt → generation-checked persist); owns the validated `raw/{user_id}/evidence/{opaque}.enc` constructor for new selected screenshot evidence while reads/deletion retain legacy-key compatibility; account deletion discovers both legacy evidence and Cloud Capture objects; a migration image rewrites legacy user blobs on first open |
| `ingest.rs` | Transactional ingest for transcripts and canonical screenshot provenance/browser dependencies; every nonduplicate screen immediately gets a deterministic observation fallback, while settled episodes later receive one holistic text/metadata Vertex analysis and Mac-computed embeddings retain their model gate and source-key idempotency |
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
