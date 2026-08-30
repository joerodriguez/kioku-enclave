# kioku-enclave map

This repository is the complete attested Kioku backend: TLS, identity/OAuth, capture, query,
MCP, workers, export, retention, and deletion. Private Cloud SQL PostgreSQL 17 is the only
structured-state authority. GCS stores only live application-encrypted large media/recording
objects; it is not a database authority or fallback. See
[ADR-0042](docs/adr/0042-postgresql-only-structured-state.md).

```text
native/web/MCP clients
          │ authenticated HTTPS
          ▼
Confidential Space regional fleet
  ├─ API and restartable workers
  ├─ private TLS PostgreSQL ── tenant state, jobs, claims, receipts, search
  ├─ encrypted GCS objects ── large media and recordings only
  ├─ attestation-bound KMS ── per-user media-key wrap/unwrap
  ├─ Vertex ── bounded disclosed content processing
  ├─ webhooks ── explicit user-selected content egress
  └─ APNs/billing ── content-free provider egress
```

PostgreSQL migrations are append-only and applied by the digest-pinned dedicated migrator;
serving members verify the required schema unconditionally and expose no schema-mode input. Durable claims, leases, reservations, and
compare-and-set settlement make worker effects safe across replicas. Readiness checks PostgreSQL
schema and shared TLS state, while liveness remains process-local for safe replacement.

Media ciphertext uses per-user KMS-wrapped keys and authenticated context binding its account,
purpose, logical object, and exact GCS generation. Structured export reports PostgreSQL rows and
media inventory metadata but not GCS bytes; deletion uses that authority to remove exact owned
media generations. Never add a database-in-GCS path, backend selector, fallback, shadow read, dual
write, or SQLite reference implementation.

## Directory and document guide

| Path | Responsibility |
|---|---|
| [src/](src/map.md) | Rust service, domain repository ports, PostgreSQL adapters, live encrypted-media adapter, API routes, fleet-safe workers, crypto, TLS, attestation, and provider clients. `src/gcs.rs` owns the provider client and canonical live-media object rules; `src/persistence/gcs_media.rs` composes it with PostgreSQL inventory. |
| [src/persistence/](src/persistence/map.md) | Provider-neutral domain repository interfaces plus the production PostgreSQL implementation and test fakes. Handlers consume these ports rather than `sqlx` directly. |
| [src/cp/](src/cp/map.md) | Cloud-product API, OAuth, capture, query, playback, retention, deletion, summarization, inference, and horizontally coordinated provider workers. |
| [migrations/](migrations/map.md) | Reviewed append-only PostgreSQL schema; serving instances verify it and never run DDL. |
| [scripts/](scripts/map.md) | Fail-closed local verification, source-frozen image build, SBOM/scan, signed evidence, immutable release, and rollout helpers. |
| [config/](config/map.md) | Intentionally minimal checked-in configuration documentation. No backend/archive/witness runtime profile is retained. |
| [docs/](docs/map.md) | Architecture decisions, including the PostgreSQL-only structured-state decision. |
| [eval/](eval/map.md) | Public, content-free voice/identity evaluation contracts and fixtures; restricted media remains outside Git. |
| [README.md](README.md) | Product architecture, public boundaries, verification, configuration, and deployment overview. |
| [API.md](API.md) | Stable authenticated API behavior, retries, privacy, export, deletion, playback, and provider-effect semantics. |
| [SECURITY.md](SECURITY.md) | Trust model, data boundaries, threats, mitigations, release posture, and residual risks. |
| [RELEASING.md](RELEASING.md) | Local signed release and ADR-0041 staged zero-unavailable rollout runbook. |
| [TASKS.md](TASKS.md) | Current cleanup evidence, required gates, and preserved product activation blockers. |
| [Dockerfile](Dockerfile) | Pinned static Linux/amd64 scratch image for Confidential Space; no SQLite extension workaround. |
| `Cargo.toml` / `Cargo.lock` / `rust-toolchain.toml` | Pinned Rust feature, dependency, and toolchain boundary. |

## Cross-cutting invariants

- Structured plaintext exists only in the attested process, private PostgreSQL, and documented
  bounded provider egress. Never write it to VM persistent disk or logs.
- Every account-owned PostgreSQL operation is tenant-qualified. Real PostgreSQL contracts, not an
  alternate backend, prove concurrency, type, search, deletion, and restart behavior.
- Provider calls occur only after durable admission/claim. Stale owners cannot settle; ambiguous
  outcomes are not resent automatically; deletion fences future disclosure.
- Export returns selected current PostgreSQL rows and media metadata, not media bytes; byte-complete
  export remains an activation blocker. Deletion first commits a recoverable local admission
  tombstone, settles usage and the one-way billing fence, then erases PostgreSQL rows plus exact
  current/noncurrent object generations and reports completion only after reconciliation.
- Releases retain signed tags, immutable digest promotion, SBOM, vulnerability scan, independently
  pinned Ed25519 evidence, exact KMS admission, process-immutable shared TLS with fleet-roll
  rotation, schema verification, and ADR-0041's staged predecessor/candidate rollout receipts.
