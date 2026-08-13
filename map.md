# map.md — kioku-enclave (root)

> **What `map.md` files are:** one per directory, describing what it's for and how it
> fits the whole, so agents can orient quickly. **Keep them current** when you add/
> remove/rename files or change a directory's role. See [AGENTS.md](AGENTS.md).

## What this repo is

The **attested Kioku backend** — the only Kioku-operated server process that handles user
plaintext. This Rust service runs inside a GCP Confidential Space VM (AMD SEV) and is
published so a running image can be audited against signed source and build provenance.
It includes TLS, OAuth, sync, MCP/REST queries, account operations, summarisation, and
encrypted persistence; client applications and deployment automation are downstream
consumers.

## Where it sits

```
OAuth clients and legacy service-identity integrations
        │  authenticated HTTPS
        ▼
   THIS SERVICE (Confidential Space VM, SEV)
        ├── context-bound AES-256-GCM blobs ──► GCS (ciphertext only)
        ├── attestation-derived credentials ─► Cloud KMS
        ├── documented plaintext egress ─────► Vertex / Resend transactional email / user-configured webhooks
        ├── generic metadata-only egress ────► Apple Push Notification service
        └── content-free pseudonymous egress ► monorepo billing service
```

The control plane is part of this process. Plaintext databases live only in process memory
and SEV-protected tmpfs (`/tmp`), never on persistent disk. Selected summarisation text
and explicitly configured webhook events cross the TEE boundary as documented in
`SECURITY.md`.

## Layout

| Path | What it is |
|---|---|
| [config/](config/map.md) | Checked-in, non-secret, fail-closed attested-image configuration; the archive-witness probe profile starts exact `off`/empty and has no repository-variable or dispatch override |
| [src/](src/map.md) | The Rust backend: TLS, OAuth/API, crypto, capture-session feedback, APNs ready receipts, separate KMS/public/Firestore-witness/archive-GCS attestation boundaries, per-user synchronized encrypted storage, search, episodes |
| `src/archive_v3.rs` / `src/archive_v3_extent.rs` / `src/archive_v3_journal.rs` / `src/archive_v3_operation.rs` / `src/archive_v3_shadow.rs` / `src/archive_v3_shadow_checkpoint.rs` / `src/archive_v3_shadow_wal.rs` / `src/archive_v3_shadow_coordinator.rs` / `src/archive_v3_sqlite_vfs.rs` / `src/archive_v3_export.rs` | Inactive ADR-0022 immutable archive foundation (format 4), bounded sparse extent-tree and checkpoint/WAL formats, transactional idempotency ledger, synchronized WAL capture, exact-readback checkpoint upload, bounded multi-commit lineage, no-list witnessed composite recovery into cleanup-owned private staging, fail-closed shadow-publication coordination, an opt-in transparent SQLite VFS wrapper with connection-scoped Store retention and exact cancellation-safe attempt drains, and a transactional export seam whose cancellation-aware witness, authenticated walker, deletion-safe publication admission, canonical product-semantic adapter, and guarded nonempty output are sealed compile-time blockers; compiled/tested only, with every live Store constructor capture-disabled and no startup VFS registration, provider handoff, or live persistence authority until shadow gates pass |
| `src/archive_v3_witness.rs` | Inactive ADR-0022 content-free witness/recovery contract with an in-memory linearizable model; it is compiled/tested only and has no concrete provider or live-authority wiring |
| `src/archive_v3_deletion.rs` | Inactive ADR-0022 deletion driver: freshly witness-reauthenticated worker/operation/fence orchestration over a sealed, bounded canonical metadata inventory; only inventory-minted per-entry capabilities reach the concrete GCS adapter, which validates full execution binding and exact membership before I/O. It removes exact content generations and derived permanent claims, reconciles uncertain mutations only by exact absence checks, and binds physical-completion witness evidence to the exact inventory plus a fresh provider drain. It has no route, Store, runtime/provider/credential construction, or authority wiring. Full metadata traversal is a compile-time activation blocker: current immutable references omit descendant locations, the inventory API is module-private, and no non-test full-reachability seal exists. |
| `src/archive_v3_firestore_witness.rs` / `src/archive_v3_firestore_http.rs` | **Inactive ADR-0022 Firestore witness boundary and concrete REST transport:** provider-neutral read-write transaction, one named (never `(default)`) database/document and one fixed bytes field codec, readTime-derived monotonic clock, conditional full-record commit, bounded `ABORTED` retry, and lost-response readback rules. The compiled transport has a fixed rustls-only Firestore origin, disables HTTP retries, and issues only begin, exact one-object-array batch-get, and commit with bounded response/error parsing; it is test-loopback injectable only. The separately compiled bearer source mints only for the exact dedicated `archive-witness-attest` WIF provider. These pieces have no runtime connection or production authority. |
| `src/archive_v3_firestore_auth.rs` | **Inactive ADR-0022 Firestore identity boundary:** type-separated exact dedicated WIF audience, no-nonce Confidential Space launcher token, fixed retry-disabled Google STS exchange, zeroizing request/response/cache ownership, and no metadata/default credentials, service-account impersonation, REST-transport connection, or runtime authority wiring |
| `src/archive_v3_firestore_shadow.rs` | **Inactive ADR-0022 Firestore shadow composition:** one typed deployment config constructs the exact named-database adapter, dedicated attestation bearer, and fixed REST transport without I/O, while preserving uncertain commit outcomes for exact coordinator reconciliation; it has no Store/startup/env/bootstrap or live authority |
| `src/archive_v3_gcs_auth.rs` | **Inactive ADR-0022 archive-GCS identity boundary:** an independently typed `archive-gcs-attest/archive-gcs` WIF audience, no-nonce launcher token, fixed retry-disabled Google STS exchange for only `devstorage.read_write`, zeroizing request/response/cache ownership, and no metadata/default credentials, service-account impersonation, GCS-transport connection, or runtime authority wiring |
| `src/archive_v3_registry_kms.rs` | **Inactive ADR-0022 archive-registry KMS adapter:** derives one numeric version only below the exact legacy production KMS key, verifies the exact enabled symmetric-software version and encrypt response coordinate, binds both wrap and unwrap to one zeroizing canonical registry-plus-version AAD, clears caller destinations before work, and strictly bounds/validates its stored wrapper and Cloud KMS integrity fields. It reuses only the existing attestation-derived KMS bearer source; it has no environment/startup/Store/provider/route/flag/authority wiring and does not change live `KmsClient` behavior or endpoints. |
| `.github/workflows/` | CI, CodeQL/dependency checks, image build/scan, provenance/SBOM attestations, and the signed schema-v6 Phase-0/probe-mode release-manifest subject |
| `Dockerfile` | Digest-pinned builder/model definition for the static `x86_64-unknown-linux-musl` image; Phase-0 bakes distinct current-media and legacy-media buckets, with legacy equal to the index bucket, with remaining rebuild limits documented in `SECURITY.md` |
| `Cargo.toml` / `Cargo.lock` | Crate manifest |
| `README.md` | What the enclave does + the attestation/privacy claim |
| `API.md` | Stable Cloud Capture API v2 contract for pure-Swift macOS/iOS clients, durable session finish, exact-session status, privacy-safe push registration/handoff, retry semantics, browser metadata, processing status, and learned people profiles |
| [eval/](eval/map.md) | Public, content-free voice/identity quality scoring plus archive-capacity contracts, synthetic regression inputs, and real-corpus methodology |
| [scripts/](scripts/map.md) | Offline evaluation-asset and capacity-fixture generation, fail-closed inactive archive-v3 signed-capacity-evidence verification, versioning, build-profile, and signed-release operator tools |
| [TASKS.md](TASKS.md) | Scoped ADR-0022 implementation evidence and intentionally remaining authority gates |
| `SECURITY.md` | **Threat model + residual risks — read before touching crypto/auth/attestation** |
| `CONTRIBUTING.md` | PR rules, lightweight local verification, and required GitHub CI gate |
| `rust-toolchain.toml` | Pinned toolchain |

## Working here

- Required GitHub CI is the exhaustive merge gate. For normal local feedback,
  run `./scripts/agent-verify.sh quick` plus a focused test with
  `./scripts/agent-verify.sh focused -- <test-filter>`; use
  `./scripts/agent-verify.sh full` for broad/security-sensitive changes or CI
  diagnosis. The helper uses locked Cargo compilation/test commands and no
  separate local build is required.
- Retire a finished linked worktree's Rust artifacts with
  `./scripts/retire_rust_worktree_artifacts.py --worktree <absolute-path>`;
  it is dry-run-only unless `--apply` is supplied and fails closed unless the
  worktree is clean and its exact GitHub PR head is merged. Verification and
  retirement share the same crash-safe per-worktree lock, with process and Cargo
  profile-lock checks as additional defenses. Do not race retirement with raw
  Cargo commands outside `agent-verify.sh`. The tool removes generated artifacts,
  never sources or the worktree itself.
- Treat every change as security-sensitive; explain threat-model impact for auth/crypto/
  attestation changes.
- The `/api/v2/capture/*`, `/api/v2/people*`, and `/v1/*` APIs are public compatibility boundaries; keep handler behavior and public
  documentation in sync, and coordinate breaking changes with downstream clients.
- Record the enclave commit SHA + deployed image digest in the operator's deployment
  record.

`src/archive_v3_shadow_checkpoint.rs` uploads a stable SQLite snapshot only through bounded
encrypted chunks and fixed-fanout manifests. Its recovery entrypoint accepts only the exact root
named by the witness and never lists storage; it atomically exposes verified bytes to a `/tmp`
sink only after all object, context, coverage, per-chunk, and full-file checks pass. It is not
wired to Store, the VFS, a provider credential, a runtime flag, routing, or authority transition.

`src/archive_v3_shadow_coordinator.rs` composes an injected async witness transaction with the
checkpoint and immutable-backend contracts. It reads the witness as sole authority, creates and
authenticates a parent-bound root candidate before its first witness CAS, and resolves a lost CAS
response or post-send failure only through an opaque exact handle and witness reread. The owned
task covers caller cancellation only while the runtime lives; process restart begins from the
independent witness, with durable retry identity deferred to operation-ledger wiring. It does not
list, clean up, truncate, mutate the legacy store, or connect to runtime authority.
