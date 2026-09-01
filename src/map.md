# `src/` map

The attested Kioku service is one Rust binary rooted at `main.rs`. Private Cloud SQL
PostgreSQL is its only structured-state authority. GCS is reachable only through the live
encrypted-media boundary; no SQLite database, archive/WAL/checkpoint runtime, witness, backend
selector, or fallback module remains in this source tree.

The out-of-line module graph is deliberately small and auditable:

```text
main.rs
├── attestation.rs
├── auth.rs
├── cp/
├── crypto.rs
├── embedding.rs
├── error.rs
├── gcs.rs
├── ocr.rs
├── persistence/
└── tls.rs
```

| Path | Responsibility |
|---|---|
| `main.rs` | PostgreSQL-only composition root, phase-confirmed expand/finalize migrator role, baked configuration, KMS/media construction, shared TLS, REST/MCP/OAuth routing, worker startup, readiness/liveness, and bounded drain. |
| `attestation.rs` | Bounded Confidential Space launcher protocol, internal attestation-derived STS/KMS credential path, and separately audience-bound public attestation tokens. |
| `auth.rs` | Google service-account ID-token verification retained for authenticated `410 Gone` compatibility routes. |
| [`cp/`](cp/map.md) | Product API, OAuth, capture, query, MCP, retention, export/deletion, inference, and horizontally coordinated workers. |
| `crypto.rs` | KMS client plus versioned context-bound AES-256-GCM envelopes and per-user media-key handling. |
| `embedding.rs` | Pinned in-enclave multilingual query embedding; absence degrades search to PostgreSQL full text rather than changing authority. |
| `error.rs` | Content-free application errors and HTTP mappings. |
| `gcs.rs` | Live GCS provider client, strict exact-generation/conditional-write semantics, canonical media/recording object names and authenticated contexts, bounded listing, and all-generation deletion. It contains no structured-state database behavior. |
| `ocr.rs` | Bounded OCR and visual-evidence parsing helpers. |
| [`persistence/`](persistence/map.md) | Typed domain repository ports, the single PostgreSQL adapter set, and the PostgreSQL-inventoried encrypted-media adapter. |
| `tls.rs` | In-enclave rustls termination using one process-immutable shared Secret Manager certificate/key generation; rotation is a staged fleet rollout, not a hot swap. |

## Invariants

- HTTP handlers and workers depend on repository ports, not `sqlx` connections or database-file
  operations.
- Serving members verify finalized PostgreSQL schema or an exact candidate-compatible v24-to-v26 expand;
  only the explicit one-shot migrator runs append-only DDL. Memory-reconciliation publication is
  authorized only by the durable v27 phase; no process-local flag can enable it.
- Fleet-wide claims, leases, reservations, and compare-and-set settlement precede provider effects.
  Stale workers cannot settle and ambiguous provider results are never blindly resent.
- GCS objects are application-encrypted and bound to the owning account, purpose, canonical name,
  and exact generation recorded in PostgreSQL. A bucket is never structured authority.
- Export emits selected tenant-qualified PostgreSQL rows and media metadata, not GCS bytes; full
  media-byte export remains an activation blocker. Deletion first commits a recoverable admission
  tombstone, settles usage and the billing fence, then removes PostgreSQL rows and
  current/noncurrent object generations and reports completion only after durable reconciliation.
- Production readiness requires the exact PostgreSQL schema marker, embedded-contract receipt and
  physical catalog plus the process-immutable shared TLS generation. Reconciliation writing also
  requires the persisted, hash-verified homogeneous-fleet activation receipt and `Active` phase. Liveness remains
  process-local so ADR-0041 can rotate certificates or replace fleet members with zero unavailable
  capacity.
