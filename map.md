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

ADR-0022's archive-v3 work remains compiled but inactive: no startup, route, Store, or
serving path constructs it, and no image acknowledges a write from it. Its route to
authority changed in August 2026. The **genesis-first replan** drops retention of existing
archive data, so the advisory-canary/Phase-2 migration path was deleted rather than
finished: `#288` (`61ae996`) severed the advisory-owner entry point and `#289` (`9b2f87e`)
deleted the advisory-owner family, the Phase-2 admission, the
`--run-archive-v3-phase1-canary` argv entry, and the eight phase1/phase2 signer/provision
scripts. With the Phase-2 admission went its compile-pinned
`full_reviewed_mutation_set_commitment`, which had made every new `WalOperationKind`
ordinal require an offline re-signing ceremony; `#290` (`6c66842`) added
`SchemaEpochAdvance = 13` with no ceremony, which is the point. The reviewed-plan seal and
the `WalOperationKind` enum are now the whole mutation-admission story.

Two things deliberately survive the deletion, and neither is a dormant advisory path. The
eight advisory/Phase-2 control-store tables keep their DDL and the `migrate_advisory_abort_locus`
migration, both applied on every control-DB open, because dropping a table without its
migration in the same commit bricks every replica on startup — schema removal is its own
atomic PR. **No writer for any of those tables survives outside tests**, so in production
they are permanently empty and the live gates that query them (notably
`ensure_advisory_release_absent`, which the surviving import path still calls) can never
fail: live plumbing over an empty ledger. The witness's advisory-terminal predicates
likewise still compile and are called by the surviving lease functions in the same module,
but nothing outside the witness/Firestore pair calls those lease functions — treat them as
compilation keepers, not as a reachable path.

The five ADR-0022 activation documents under [`docs/adr/`](docs/adr/map.md)
(activation-readiness, production-activation-runbook, solo-operator-activation, and the two
Phase-1 plans) are **superseded historical records**: they describe the deleted two-boundary
ceremony and grant no cloud or deployment permission. A genesis-first activation needs a new
runbook written against the surviving WAL owner, genesis bootstrap, and schema-epoch ladder.

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
| `src/archive_v3.rs` / `src/archive_v3_extent.rs` / `src/archive_v3_extent_vfs.rs` / `src/archive_v3_extent_commit.rs` / `src/archive_v3_extent_shadow.rs` / `src/archive_v3_wal_to_extent.rs` / `src/archive_v3_vector_accelerator.rs` / `src/archive_v3_phase3_gates.rs` / `src/archive_v3_journal.rs` / `src/archive_v3_operation.rs` / `src/archive_v3_shadow.rs` / `src/archive_v3_shadow_checkpoint.rs` / `src/archive_v3_shadow_wal.rs` / `src/archive_v3_shadow_coordinator.rs` / `src/archive_v3_sqlite_vfs.rs` / `src/archive_v3_export.rs` | Inactive ADR-0022 immutable archive foundation (format 4), bounded sparse extent-tree and checkpoint/WAL formats, transactional idempotency ledger, synchronized WAL capture, exact-readback checkpoint upload, bounded multi-commit lineage, no-list witnessed composite recovery into cleanup-owned private staging, fail-closed shadow-publication coordination, an opt-in transparent SQLite VFS wrapper with connection-scoped Store retention and exact cancellation-safe attempt drains, and a transactional export seam whose cancellation-aware witness, authenticated walker, deletion-safe publication admission, canonical product-semantic adapter, and guarded nonempty output are sealed compile-time blockers; compiled/tested only. The exact-user capture selection (`StoreShadowCaptureSelection`) survives as a crate-private test-only injection: `#289` deleted the advisory terminal that was its sole production installer, along with the owner-only prefix/snapshot drain, the exact-R1 replay/full-parity comparison consumer, and the durable comparison-settlement and capture-retirement transitions, so no production path installs a selector or retires a registration. Every live Store constructor remains capture-disabled, with no startup registration, provider mutation handoff, or live persistence authority until shadow gates pass. |
| `src/archive_v3_witness.rs` | Inactive ADR-0022 content-free witness/recovery contract with an in-memory linearizable model; it is compiled/tested only and has no concrete provider or live-authority wiring |
| `src/archive_v3_deletion.rs` | Inactive ADR-0022 deletion driver: freshly witness-reauthenticated worker/operation/fence orchestration over the exact authenticated lifecycle-page inventory; only inventory-minted per-entry capabilities reach the concrete GCS adapter, which validates full execution binding and exact membership before I/O. It removes exact content generations and derived permanent claims, reconciles uncertain mutations only by exact absence checks, and binds physical-completion witness evidence to the lifecycle seal's exact commitment plus a fresh provider drain. The obsolete independent builder/commitment is gone. A producer-token-gated private conversion can hand the distinct pre-witness complete inventory only to its separate inactive execution protocol; no normal deletion type accepts it. It has no route, Store, runtime/provider/credential construction, invocation, or authority wiring. |
| `src/archive_v3_lifecycle.rs` / `src/archive_v3_lifecycle_page_store.rs` / `src/archive_v3_inventory_coordinator.rs` / `src/archive_v3_witness_disposition.rs` | Inactive ADR-0022 lifecycle authority/codec, encrypted exact-name inventory pages, authenticated inventory coordination, and capability-only pre-witness disposition. New bootstrap reservations atomically enroll a versioned witness-send protocol; the sealed Genesis creator cannot submit the initial Firestore commit before encrypted control durably marks send-start. Deletion serially closes unstarted versus started dispatch, and only the former plus a private fresh exact-`None` observation can mint a non-serializable absence proof. Any later present/invalid document irreversibly poisons absence to manual; missing/old/unknown protocol state is manual, never inferred unsent. Final KILP-v2 pages contain only canonical key/role/ciphertext-hash facts. The normal coordinator authenticates Tombstoned current/predecessor reachability plus frozen create-ahead; the separate pre-witness branch consumes absence into a create-ahead-only snapshot/seal (including zero objects) and returns only a non-authorizing type with no deletion-driver conversion. There is no startup/Store/runtime/provider construction, deletion invocation/integration, cloud activation, or production authority. |
| `src/archive_v3_pre_witness_deletion.rs` | **Inactive ADR-0022 pre-witness execution protocol:** consumes only the exact authenticated pre-witness inventory through a private producer token, binds it to a random durable operation and distinct commitment domains, and records a strict restartable registry/object/drain evidence chain. It exposes no normal-deletion conversion, entry/provider capability, destructive evidence producer, production cleanup transition, runtime construction, Store/route/config/provider/cloud/deploy wiring, or driver invocation. |
| `src/archive_v3_wal_idempotency.rs` / `src/cp/*/wal.rs` and private WAL children / `src/archive_v3_wal_owner.rs` / `src/archive_v3_wal_owner/launcher.rs` / `src/archive_v3_wal_owner/publisher.rs` | **Inactive ADR-0022 logical mutation, single-archive launcher/owner, and publisher/checkpoint worker:** the sealed reviewed A/B/C plans retain stable identities, exact bounded replay, provider send markers/proofs, and fail-closed terminal settlement without generic SQL or result access. One private non-cloneable launcher consumes only the parity-certified maintenance handoff, re-reads its exact terminal Control row, and owns a heterogeneous sealed-plan actor whose blocking lane alone holds the recovered writable SQLite copy and exact-one WAL drain. The create/get-only publisher manages witness leases, deterministic immutable WAL/checkpoint topology, lost-success reconciliation, comparison-row consumption, and fresh recovery. Mutation admission is now the reviewed-plan seal plus the `WalOperationKind` enum alone: `#289` deleted the Phase-2 admission and its compile-pinned `full_reviewed_mutation_set_commitment`, so a new ordinal no longer forces an offline re-signing ceremony (`#290` added `SchemaEpochAdvance = 13` under exactly that freedom). Unsupported semantic domains, concrete provider/KMS adapters, Store/startup/route/config/acknowledgement wiring, list/delete authority, cloud mutation, and serving activation remain explicit blockers. The advisory shadow integration is no longer among them — it was deleted, not deferred — and `docs/adr/0022-activation-readiness.md` is a superseded historical record, not a live blocker list. |
| `src/archive_v3_reachability.rs` | Inactive ADR-0022 authenticated exact-name reachability visitor. It prevalidates one witness-selected current graph plus its optional predecessor and already exact-registry-bound ciphers before I/O; records sequence-derived historical roots in the correct database namespace without guessing a key epoch; follows bounded checkpoint, extent, and WAL metadata without listing; opens every fetched envelope under its exact cipher; and returns only an opaque content-free non-authorizing report. It does not union create-ahead rows, build lifecycle pages, mint a deletion/reachability seal, or connect to control, Store, startup, providers, credentials, routes, or deployment. |
| `src/archive_v3_firestore_witness.rs` / `src/archive_v3_firestore_http.rs` | **Inactive ADR-0022 Firestore witness boundary and concrete REST transport:** provider-neutral read-write transaction, one named (never `(default)`) database/document and one fixed bytes field codec, readTime-derived monotonic clock, conditional full-record commit, bounded `ABORTED` retry, and lost-response readback rules. The compiled transport has a fixed rustls-only Firestore origin, disables HTTP retries, and issues only begin, exact one-object-array batch-get, and commit with bounded response/error parsing; it is test-loopback injectable only. The separately compiled bearer source mints only for the exact dedicated `archive-witness-attest` WIF provider. These pieces have no runtime connection or production authority. |
| `src/archive_v3_firestore_auth.rs` | **Inactive ADR-0022 Firestore identity boundary:** type-separated exact dedicated WIF audience, no-nonce Confidential Space launcher token, fixed retry-disabled Google STS exchange, zeroizing request/response/cache ownership, and no metadata/default credentials, service-account impersonation, REST-transport connection, or runtime authority wiring |
| `src/archive_v3_firestore_shadow.rs` | **Inactive ADR-0022 Firestore shadow composition:** one typed deployment config constructs the exact named-database adapter, dedicated attestation bearer, and fixed REST transport without I/O, while preserving uncertain commit outcomes for exact coordinator reconciliation; it has no Store/startup/env/bootstrap or live authority |
| `src/archive_v3_gcs_auth.rs` | **Inactive ADR-0022 archive-GCS identity boundary:** an independently typed `archive-gcs-attest/archive-gcs` WIF audience, no-nonce launcher token, fixed retry-disabled Google STS exchange for only `devstorage.read_write`, zeroizing request/response/cache ownership, and no metadata/default credentials, service-account impersonation, GCS-transport connection, or runtime authority wiring |
| `src/archive_v3_registry_kms.rs` | **Inactive ADR-0022 archive-registry KMS adapter:** derives one numeric version only below the exact legacy production KMS key, verifies the exact enabled symmetric-software version and encrypt response coordinate, binds both wrap and unwrap to one zeroizing canonical registry-plus-version AAD, clears caller destinations before work, and strictly bounds/validates its stored wrapper and Cloud KMS integrity fields. It reuses only the existing attestation-derived KMS bearer source; it has no environment/startup/Store/provider/route/flag/authority wiring and does not change live `KmsClient` behavior or endpoints. |
| `src/archive_v3_shadow_runtime.rs` | **Inactive sealed ADR-0022 single-archive WAL runtime:** synchronously derives fixed archive-GCS, exact registry-KMS-version, and named-Firestore providers without I/O, then requires one exact image-commitment match against an opaque durable encrypted-control archive binding. The importer owns the whole non-cloneable provider bundle; narrow maintenance operations stay borrowed except for one importer-token-gated object-handle clone required by owned cancellation-safe recovery, and terminal ownership is moved into the WAL handoff. Archive ID/providers stay private with no general getters, callbacks, tasks, operations, acknowledgement, deletion, or true drain gate. Startup never constructs it and it has no Store/VFS/lifecycle/route/health/admission/WAL-publication or authority connection. |
| `src/archive_v3_maintenance_import.rs` | **Inactive ADR-0022 maintenance-window import:** a sealed-runtime-owned, single-archive offline coordinator durably fences and pins one exact legacy Store generation, authenticates the existing Active+Legacy witness/root/registry, uploads exact-readback checkpoint objects under a distinct domain-separated zero-WAL-only binding and canonical R1, reconciles ShadowWal only by exact witness reread, and performs full independent SQLite parity with fresh source/witness validation. `#289` deleted the advisory arm: `MaintenanceImportTarget` now has the single variant `WalAuthoritative`, and with the advisory importer went its sealed Store/user/archive/import target, the advisory release ledger and exact-marker executor, the local-resume transition that installed a capture selector, and the private R1-replay/parity comparison child. `abort_pre_owner` still handles import failure before any owner exists, reconciling exact-generation provider-marker deletion to a fresh `NotFound` and durably transitioning the stage to `manual_required` under the exclusive user lifecycle lock before safely unblocking both process-local gates. **The surviving R2/WalAuthoritative door is closed in practice, not merely inactive:** it is gated on `ensure_phase2_acquisition_intact`, which requires a durable `archive_v3_phase2_authority_acquisitions` row resting at `Phase2Acquired`, and `#289` removed every writer of that table — only `from_db`/`load_phase2_authority_acquisition` survive, so existing rows still decode but no new acquisition can ever be minted here. Under the genesis-first replan an archive is created from genesis rather than migrated, so no successor mint is planned. Encrypted control still owns bounded restart stages, full-tuple lease renewal/reacquire CAS, reacquire-only partial-attempt supersession, up to 16 retained attempts, and 32,898 exact artifacts per attempt. It has no main/startup/route/worker/config/serving wiring, archive-v3 provider list/delete, legacy-source deletion, durable capture settlement, policy switch, cloud action, or deployment authority; only the existing bounded legacy-intent prefix scan drains pre-marker writes. |
| `Dockerfile` | Digest-pinned builder/model definition for the static `x86_64-unknown-linux-musl` image. Stable tool/model/dependency layers precede final configuration; explicit committed Cargo/source subset hashes prevent stale BuildKit records while source time stays in signed evidence rather than Docker's global cache inputs. Configuration is assembled from an ephemeral BuildKit secret whose non-secret `CONFIG_SHA256` is declared only in the late image-config stage and verified against the assembled bytes. Native OCI output and the explicitly confirmed fallback are driven by `scripts/local_image_pipeline.py`; remaining rebuild limits are documented in `SECURITY.md` |
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
