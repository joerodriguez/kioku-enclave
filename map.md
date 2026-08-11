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
        └── content-free pseudonymous egress ► monorepo billing service
```

The control plane is part of this process. Plaintext databases live only in process memory
and SEV-protected tmpfs (`/tmp`), never on persistent disk. Selected summarisation text
and explicitly configured webhook events cross the TEE boundary as documented in
`SECURITY.md`.

## Layout

| Path | What it is |
|---|---|
| [src/](src/map.md) | The Rust backend: TLS, OAuth/API, crypto, separate KMS/public/Firestore-witness attestation boundaries, per-user synchronized encrypted storage, search, episodes |
| `src/archive_v3.rs` / `src/archive_v3_journal.rs` / `src/archive_v3_operation.rs` / `src/archive_v3_shadow.rs` / `src/archive_v3_shadow_checkpoint.rs` / `src/archive_v3_shadow_coordinator.rs` / `src/archive_v3_sqlite_vfs.rs` | Inactive ADR-0022 immutable archive foundation, bounded checkpoint/WAL formats, transactional idempotency ledger, synchronized WAL capture, checkpoint upload/recovery, fail-closed shadow-publication coordination, and an opt-in transparent SQLite VFS wrapper; compiled/tested only, with no startup VFS registration or live persistence authority until shadow gates pass |
| `src/archive_v3_witness.rs` | Inactive ADR-0022 content-free witness/recovery contract with an in-memory linearizable model; it is compiled/tested only and has no concrete provider or live-authority wiring |
| `src/archive_v3_firestore_witness.rs` / `src/archive_v3_firestore_http.rs` | **Inactive ADR-0022 Firestore witness boundary and concrete REST transport:** provider-neutral read-write transaction, one named (never `(default)`) database/document and one fixed bytes field codec, readTime-derived monotonic clock, conditional full-record commit, bounded `ABORTED` retry, and lost-response readback rules. The compiled transport has a fixed rustls-only Firestore origin, disables HTTP retries, and issues only begin, exact one-object-array batch-get, and commit with bounded response/error parsing; it is test-loopback injectable only. The separately compiled bearer source mints only for the exact dedicated `archive-witness-attest` WIF provider. These pieces have no runtime connection or production authority. |
| `src/archive_v3_firestore_auth.rs` | **Inactive ADR-0022 Firestore identity boundary:** type-separated exact dedicated WIF audience, no-nonce Confidential Space launcher token, fixed retry-disabled Google STS exchange, zeroizing request/response/cache ownership, and no metadata/default credentials, service-account impersonation, REST-transport connection, or runtime authority wiring |
| `.github/workflows/` | CI, CodeQL/dependency checks, image build/scan, provenance, and SBOM attestations |
| `Dockerfile` | Digest-pinned builder/model definition for the static `x86_64-unknown-linux-musl` image; remaining rebuild limits are documented in `SECURITY.md` |
| `Cargo.toml` / `Cargo.lock` | Crate manifest |
| `README.md` | What the enclave does + the attestation/privacy claim |
| `API.md` | Stable Cloud Capture API v2 contract for pure-Swift macOS/iOS clients, retry semantics, browser metadata, processing status, and learned people profiles |
| [eval/](eval/map.md) | Public, content-free voice/identity quality scoring plus archive-capacity contracts, synthetic regression inputs, and real-corpus methodology |
| [scripts/](scripts/map.md) | Offline evaluation-asset and capacity-fixture generation, versioning, build-profile, and signed-release operator tools |
| [TASKS.md](TASKS.md) | Scoped ADR-0022 implementation evidence and intentionally remaining authority gates |
| `SECURITY.md` | **Threat model + residual risks — read before touching crypto/auth/attestation** |
| `CONTRIBUTING.md` | PR rules; the three pre-commit checks |
| `rust-toolchain.toml` | Pinned toolchain |

## Working here

- Pre-commit, all must pass: `cargo test --locked`,
  `cargo clippy --locked --all-targets -- -D warnings`, `cargo fmt --all -- --check`.
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
