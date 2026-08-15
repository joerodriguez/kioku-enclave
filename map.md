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
| [config/](config/map.md) | Checked-in, non-secret, fail-closed attested-image configuration; the archive-witness probe and sealed single-archive WAL runtime profiles start exact `off`/empty and have no operator, environment, repository-variable, or dispatch override |
| [docs/](docs/map.md) | Proposed and accepted cross-boundary architecture decisions |
| [src/](src/map.md) | The Rust backend: TLS, OAuth/API, crypto, capture-session feedback, APNs ready receipts, separate KMS/public/Firestore-witness/archive-GCS attestation boundaries, per-user synchronized encrypted storage, search, episodes |
| `src/archive_v3.rs` / `src/archive_v3_extent.rs` / `src/archive_v3_journal.rs` / `src/archive_v3_operation.rs` / `src/archive_v3_shadow.rs` / `src/archive_v3_shadow_checkpoint.rs` / `src/archive_v3_shadow_wal.rs` / `src/archive_v3_shadow_coordinator.rs` / `src/archive_v3_sqlite_vfs.rs` / `src/archive_v3_export.rs` | Inactive ADR-0022 immutable archive foundation (format 4), bounded sparse extent-tree and checkpoint/WAL formats, transactional idempotency ledger, synchronized WAL capture, exact-readback checkpoint upload, bounded multi-commit lineage, no-list witnessed composite recovery into cleanup-owned private staging, fail-closed shadow-publication coordination, an opt-in transparent SQLite VFS wrapper with connection-scoped Store retention and exact cancellation-safe attempt drains, and a transactional export seam whose cancellation-aware witness, authenticated walker, deletion-safe publication admission, canonical product-semantic adapter, and guarded nonempty output are sealed compile-time blockers; compiled/tested only, with every live Store constructor capture-disabled and no startup VFS registration, provider handoff, or live persistence authority until shadow gates pass |
| `src/archive_v3_witness.rs` | Inactive ADR-0022 content-free witness/recovery contract with an in-memory linearizable model; it is compiled/tested only and has no concrete provider or live-authority wiring |
| `src/archive_v3_deletion.rs` | Inactive ADR-0022 deletion driver: freshly witness-reauthenticated worker/operation/fence orchestration over the exact authenticated lifecycle-page inventory; only inventory-minted per-entry capabilities reach the concrete GCS adapter, which validates full execution binding and exact membership before I/O. It removes exact content generations and derived permanent claims, reconciles uncertain mutations only by exact absence checks, and binds physical-completion witness evidence to the lifecycle seal's exact commitment plus a fresh provider drain. The obsolete independent builder/commitment is gone. A producer-token-gated private conversion can hand the distinct pre-witness complete inventory only to its separate inactive execution protocol; no normal deletion type accepts it. It has no route, Store, runtime/provider/credential construction, invocation, or authority wiring. |
| `src/archive_v3_lifecycle.rs` / `src/archive_v3_lifecycle_page_store.rs` / `src/archive_v3_inventory_coordinator.rs` / `src/archive_v3_witness_disposition.rs` | Inactive ADR-0022 lifecycle authority/codec, encrypted exact-name inventory pages, authenticated inventory coordination, and capability-only pre-witness disposition. New bootstrap reservations atomically enroll a versioned witness-send protocol; the sealed Genesis creator cannot submit the initial Firestore commit before encrypted control durably marks send-start. Deletion serially closes unstarted versus started dispatch, and only the former plus a private fresh exact-`None` observation can mint a non-serializable absence proof. Any later present/invalid document irreversibly poisons absence to manual; missing/old/unknown protocol state is manual, never inferred unsent. Final KILP-v2 pages contain only canonical key/role/ciphertext-hash facts. The normal coordinator authenticates Tombstoned current/predecessor reachability plus frozen create-ahead; the separate pre-witness branch consumes absence into a create-ahead-only snapshot/seal (including zero objects) and returns only a non-authorizing type with no deletion-driver conversion. There is no startup/Store/runtime/provider construction, deletion invocation/integration, cloud activation, or production authority. |
| `src/archive_v3_pre_witness_deletion.rs` | **Inactive ADR-0022 pre-witness execution protocol:** consumes only the exact authenticated pre-witness inventory through a private producer token, binds it to a random durable operation and distinct commitment domains, and records a strict restartable registry/object/drain evidence chain. It exposes no normal-deletion conversion, entry/provider capability, destructive evidence producer, production cleanup transition, runtime construction, Store/route/config/provider/cloud/deploy wiring, or driver invocation. |
| `src/archive_v3_wal_idempotency.rs` / `src/cp/media/wal.rs` / `src/cp/model_usage/wal.rs` / `src/cp/query/wal.rs` / `src/cp/query/wal/finalization_queue.rs` / `src/cp/finalizer/wal.rs` / `src/cp/media_worker/wal.rs` / `src/cp/media_worker/wal/result.rs` / `src/cp/email_worker/wal.rs` / `src/cp/push/wal.rs` / `src/cp/webhook_worker/wal.rs` / `src/cp/reviewer/wal.rs` / `src/cp/summarizer/wal.rs` / `src/cp/summarizer/wal/visual_evidence.rs` / `src/archive_v3_wal_owner.rs` / `src/archive_v3_wal_owner/publisher.rs` | **Inactive ADR-0022 logical mutation, single-archive owner, and publisher/checkpoint worker:** fixed portable operation domains, opaque stable IDs/fingerprints, bounded retained replay results, and sealed per-domain ledgers feed a private actor whose dedicated blocking lane owns the recovered SQLite copy and reversible exact-one WAL drain. Production A seals currently cover capture-session finish, metadata-only screen-reference batches, selected-screenshot receipts, caller-stable finalization queue, exact finalization commit, screen-storyboard results without person evidence, exact post-provider raw-media retention settlement, provider-accepted email, provider-accepted APNs, definitive-success webhook settlement, the exact synthetic reviewer fixture, cursor-bound substance and text-only visual-evidence backfill batches, and terminal outcome for a pre-existing Vertex event; each derives identity from its validated stable source and owns a closed codec plus distinct bounded exact-replay ledger. The screen-result subtype requires an already durable terminal Vertex attempt, exact complete leased-work predecessor, fixed commit time, and caller-fixed screenshot IDs; it inserts only complete screenshots/observations and full-tuple settles the matching jobs, media, and work unit. Its future B boundary, screen person evidence, and every audio/person/identity/voice result remain unsupported. Other children retain their previously reviewed boundaries: provider handoffs, deletion, delivery, model calls, automatic IDs/clocks, retry, Store, launching, and acknowledgement stay outside the logical codecs. Encrypted control persists archive+kind+operation-scoped publication facts, transition-validates the deterministic WAL plan, and reconciles an exact pending candidate successor before settlement. The private publisher consumes only the maintenance handoff, manages adequate-lifetime/same-fence/higher-fence witness leases, atomically consumes terminal comparison rows before later owner-binding transitions, and performs mandatory checkpoint source retirement on owned blocking workers plus exact deterministic reserve/create/readback recovery before a new mutation crosses fixed caps. Candidate/send source maintenance reads and authenticates exact provider state without renewing/reacquiring; reload recomputes the full chunk/manifest/root topology, lost-success reconciliation precedes the old-head gate, and checkpoint settlement atomically consumes the prior witnessed logical publication. The runtime exposes only exact-name immutable create/get. Fresh witnessed current staging supplies permanent indexed replay without replacing another operation's terminal Control row. No launcher exists; ordinary Store remains legacy, and no runtime/startup/route/config, acknowledgement, list/delete, cloud, or serving wiring exists. |
| `src/archive_v3_reachability.rs` | Inactive ADR-0022 authenticated exact-name reachability visitor. It prevalidates one witness-selected current graph plus its optional predecessor and already exact-registry-bound ciphers before I/O; records sequence-derived historical roots in the correct database namespace without guessing a key epoch; follows bounded checkpoint, extent, and WAL metadata without listing; opens every fetched envelope under its exact cipher; and returns only an opaque content-free non-authorizing report. It does not union create-ahead rows, build lifecycle pages, mint a deletion/reachability seal, or connect to control, Store, startup, providers, credentials, routes, or deployment. |
| `src/archive_v3_firestore_witness.rs` / `src/archive_v3_firestore_http.rs` | **Inactive ADR-0022 Firestore witness boundary and concrete REST transport:** provider-neutral read-write transaction, one named (never `(default)`) database/document and one fixed bytes field codec, readTime-derived monotonic clock, conditional full-record commit, bounded `ABORTED` retry, and lost-response readback rules. The compiled transport has a fixed rustls-only Firestore origin, disables HTTP retries, and issues only begin, exact one-object-array batch-get, and commit with bounded response/error parsing; it is test-loopback injectable only. The separately compiled bearer source mints only for the exact dedicated `archive-witness-attest` WIF provider. These pieces have no runtime connection or production authority. |
| `src/archive_v3_firestore_auth.rs` | **Inactive ADR-0022 Firestore identity boundary:** type-separated exact dedicated WIF audience, no-nonce Confidential Space launcher token, fixed retry-disabled Google STS exchange, zeroizing request/response/cache ownership, and no metadata/default credentials, service-account impersonation, REST-transport connection, or runtime authority wiring |
| `src/archive_v3_firestore_shadow.rs` | **Inactive ADR-0022 Firestore shadow composition:** one typed deployment config constructs the exact named-database adapter, dedicated attestation bearer, and fixed REST transport without I/O, while preserving uncertain commit outcomes for exact coordinator reconciliation; it has no Store/startup/env/bootstrap or live authority |
| `src/archive_v3_gcs_auth.rs` | **Inactive ADR-0022 archive-GCS identity boundary:** an independently typed `archive-gcs-attest/archive-gcs` WIF audience, no-nonce launcher token, fixed retry-disabled Google STS exchange for only `devstorage.read_write`, zeroizing request/response/cache ownership, and no metadata/default credentials, service-account impersonation, GCS-transport connection, or runtime authority wiring |
| `src/archive_v3_registry_kms.rs` | **Inactive ADR-0022 archive-registry KMS adapter:** derives one numeric version only below the exact legacy production KMS key, verifies the exact enabled symmetric-software version and encrypt response coordinate, binds both wrap and unwrap to one zeroizing canonical registry-plus-version AAD, clears caller destinations before work, and strictly bounds/validates its stored wrapper and Cloud KMS integrity fields. It reuses only the existing attestation-derived KMS bearer source; it has no environment/startup/Store/provider/route/flag/authority wiring and does not change live `KmsClient` behavior or endpoints. |
| `src/archive_v3_shadow_runtime.rs` | **Inactive sealed ADR-0022 single-archive WAL runtime:** synchronously derives fixed archive-GCS, exact registry-KMS-version, and named-Firestore providers without I/O, then requires one exact image-commitment match against an opaque durable encrypted-control archive binding. The importer owns the whole non-cloneable provider bundle; narrow maintenance operations stay borrowed except for one importer-token-gated object-handle clone required by owned cancellation-safe recovery, and terminal ownership is moved into the WAL handoff. Archive ID/providers stay private with no general getters, callbacks, tasks, operations, acknowledgement, deletion, or true drain gate. Startup never constructs it and it has no Store/VFS/lifecycle/route/health/admission/WAL-publication or authority connection. |
| `src/archive_v3_maintenance_import.rs` | **Inactive ADR-0022 maintenance-window import:** a sealed-runtime-owned, single-archive offline coordinator durably fences and pins one exact legacy Store generation, authenticates the existing Active+Legacy witness/root/registry, uploads exact-readback checkpoint objects under a distinct domain-separated zero-WAL-only binding and canonical R1, reconciles ShadowWal only by exact witness reread, performs full independent SQLite parity with fresh source/witness validation, then creates/reconciles R2 into offline WalAuthoritative. Terminal and terminal-restart paths reacquire the exact pinned source, reload exact encrypted Control state, freshly authenticate exact R2, revoke the import lease and prove it absent by fresh read, scrub DB/WAL/SHM, and return only a non-cloneable WAL-owner-token-gated handoff retaining the process-local Store admission guards and entire provider bundle. Encrypted control owns bounded restart stages, full-tuple lease renewal/reacquire CAS, reacquire-only partial-attempt supersession, up to 16 retained attempts, and 32,898 exact artifacts per attempt. It has no main/startup/route/worker/config/serving wiring, archive-v3 provider list/delete, legacy-source deletion, policy switch, cloud action, or deployment authority; only the existing bounded legacy-intent prefix scan drains pre-marker writes. |
| `Dockerfile` | Digest-pinned builder/model definition for the static `x86_64-unknown-linux-musl` image; Phase-0 bakes distinct current-media and legacy-media buckets, with legacy equal to the index bucket, with remaining rebuild limits documented in `SECURITY.md` |
| `Cargo.toml` / `Cargo.lock` | Crate manifest |
| `README.md` | What the enclave does + the attestation/privacy claim |
| `API.md` | Stable Cloud Capture API v2 contract for pure-Swift macOS/iOS clients, bounded Mac screenshot-reference batches, durable session finish, exact-session status, privacy-safe push registration/handoff, retry semantics, browser metadata, processing status, and learned people profiles |
| [eval/](eval/map.md) | Public, content-free voice/identity quality scoring plus archive-capacity contracts, synthetic regression inputs, and real-corpus methodology |
| [scripts/](scripts/map.md) | Offline evaluation-asset and capacity-fixture generation, fail-closed inactive archive-v3 signed-capacity-evidence verification, versioning, build-profile, and signed-release operator tools |
| [TASKS.md](TASKS.md) | Scoped ADR-0022 implementation evidence and intentionally remaining authority gates |
| `SECURITY.md` | **Threat model + residual risks — read before touching crypto/auth/attestation** |
| `CONTRIBUTING.md` | PR rules and lightweight/exhaustive local verification gates |
| `rust-toolchain.toml` | Pinned toolchain |

## Working here

- The reviewed local verification pipeline is the exhaustive merge gate; hosted
  GitHub Actions is disabled. For normal local feedback,
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
