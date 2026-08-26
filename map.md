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

ADR-0022's Genesis WAL path is production-wired behind the signed image profile: startup
installs every durable WAL-authoritative selection, reconstructs and launches its serving
authority before request admission, sign-in converges new selected accounts from Genesis,
and routed Store reads/submits serve only settled owner state. The checked source carries the
fixed fresh-production `durable-fleet-wal-v1` provider tuple and accepts archive identities only
as opaque bindings already minted and validated by encrypted Control. An exact signed archive-v3
release tag is still required to select the active path; evaluation and ordinary pretag builds
force the effective profile off. This logical-WAL path is distinct
from the old advisory/extent migration stack.

The route to authority changed in August 2026. The **genesis-first replan** drops retention
of existing archive data, so the advisory-canary/Phase-2 migration path was deleted rather
than finished: `#288` (`61ae996`) severed the advisory-owner entry point and `#289` (`9b2f87e`)
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

The five pre-Genesis ADR-0022 activation documents under [`docs/adr/`](docs/adr/map.md)
(activation-readiness, production-activation-runbook, solo-operator-activation, and the two
Phase-1 plans) are **superseded historical records**: they describe the deleted two-boundary
ceremony and grant no cloud or deployment permission. Current rollout authority comes only
from the signed Genesis-WAL release profile and the fail-closed release/deployment tooling.

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
| [config/](config/map.md) | Checked-in, non-secret, fail-closed attested-image configuration; the archive witness probe stays exact off, while the Archive V3 profile carries the fixed fresh-production durable-fleet provider tuple. Evaluation/main pretag selection still forces it off. The canonical fresh-generation intent and synthetic schema-10 cross-repository fixture pin the original BOOTSTRAP publication tuple and encoding without provider authority. |
| [docs/](docs/map.md) | Proposed and accepted cross-boundary architecture decisions |
| [src/](src/map.md) | The Rust backend: TLS, OAuth/API, crypto, capture-session feedback, APNs ready receipts, separate KMS/public/Firestore-witness/archive-GCS attestation boundaries, per-user synchronized encrypted storage, search, episodes |
| `src/archive_v3_extent.rs` / `src/archive_v3_extent_vfs.rs` / `src/archive_v3_extent_commit.rs` / `src/archive_v3_extent_shadow.rs` / `src/archive_v3_wal_to_extent.rs` / `src/archive_v3_vector_accelerator.rs` / `src/archive_v3_phase3_gates.rs` / `src/archive_v3_shadow_coordinator.rs` / `src/archive_v3_export.rs` | **Inactive ADR-0022 extent/shadow future:** sparse extent storage, extent cutover/parity, vector sidecar, Phase-3 gates, shadow coordinator, and export-publication seams remain compiled/tested only. They have no active Store, route, startup, or deployment authority. This does not include the journal/checkpoint/WAL/VFS primitives used by the active Genesis logical-WAL publisher. |
| `src/archive_v3.rs` / `src/archive_v3_journal.rs` / `src/archive_v3_operation.rs` / `src/archive_v3_shadow.rs` / `src/archive_v3_shadow_checkpoint.rs` / `src/archive_v3_shadow_wal.rs` / `src/archive_v3_shadow_session.rs` / `src/archive_v3_sqlite_vfs.rs` | **Active Genesis-WAL storage core under the signed profile:** authenticated archive types, bounded journal/checkpoint formats, operation inventory, synchronous SQLite WAL capture, exact staging/recovery, and the named VFS used only inside the one-owner serving lane. They expose no route/provider selection or generic mutation authority. The deleted advisory capture installer remains unavailable. |
| `src/archive_v3_witness.rs` | **Active content-free witness/recovery contract under the signed profile:** the WAL publisher and Genesis ladder authenticate exact owner leases, roots, migrations, and lost-response recovery through Firestore; account deletion uses a separate native-async principal-key-authenticated tombstone/recovery/advance surface. In-memory models remain test oracles; extent/advisory transitions remain unreachable. |
| `src/archive_v3_deletion.rs` | **Active deletion-only driver under the signed profile:** freshly reauthenticates worker/operation/fence authority, consumes only the authenticated lifecycle-page inventory, erases registry epochs, removes exact content generations and permanent claims, reconciles uncertainty by exact absence, and binds physical completion to the inventory plus fresh provider drain. No route or caller can choose names, prefixes, credentials, or providers; the type-separated pre-witness execution protocol remains inactive. |
| `src/archive_v3_lifecycle.rs` / `src/archive_v3_lifecycle_page_store.rs` / `src/archive_v3_inventory_coordinator.rs` / `src/archive_v3_witness_disposition.rs` | **Deletion lifecycle family:** the signed runtime actively uses the normal Tombstoned-witness coordinator, exact reachability union, encrypted KILP-v2 pages, durable seal, and exact cleanup path. Bootstrap create admission remains shared with Genesis. The capability-only pre-witness absence branch stays type-separated and inactive because no production destructive producer or conversion reaches it. |
| `src/archive_v3_pre_witness_deletion.rs` | **Inactive ADR-0022 pre-witness execution protocol:** consumes only the exact authenticated pre-witness inventory through a private producer token, binds it to a random durable operation and distinct commitment domains, and records a strict restartable registry/object/drain evidence chain. It exposes no normal-deletion conversion, entry/provider capability, destructive evidence producer, production cleanup transition, runtime construction, Store/route/config/provider/cloud/deploy wiring, or driver invocation. |
| `src/archive_v3_wal_idempotency.rs` / `src/cp/*/wal.rs` and private WAL children / `src/archive_v3_wal_owner.rs` / `src/archive_v3_wal_owner/launcher.rs` / `src/archive_v3_wal_owner/publisher.rs` | **Active Genesis-WAL logical mutation, single-archive launcher/owner, and publisher/checkpoint worker:** sealed domain plans retain stable identities, exact bounded replay, provider send markers/proofs, and fail-closed terminal settlement without generic SQL or result access. The private non-cloneable launcher consumes only a durable serving handoff and owns a heterogeneous sealed-plan actor whose blocking lane alone holds the recovered writable SQLite copy and exact-one WAL drain. The create/get-only publisher manages witness leases, deterministic immutable WAL/checkpoint topology, lost-success reconciliation, and fresh recovery. Startup relaunch and sign-in Genesis convergence are the only production launch paths; Store exposes only routed settled reads and typed sealed submits for selected users. Mutation admission is the reviewed-plan seal plus the `WalOperationKind` enum. Unsupported semantic/provider-attempt domains remain closed, while the deleted advisory/Phase-2 integration grants no authority. |
| `src/archive_v3_reachability.rs` | **Active deletion-only exact-name reachability visitor:** prevalidates the witnessed current/predecessor graphs and exact registry-bound ciphers, follows bounded checkpoint/extent/WAL metadata without listing or prefix inference, and returns a non-authorizing report consumed only by the lifecycle inventory coordinator. |
| `src/archive_v3_firestore_witness.rs` / `src/archive_v3_firestore_http.rs` | **Conditionally active ADR-0022 Firestore witness boundary and concrete transport:** under the signed runtime, Genesis and WAL publication use the fixed named-database, one-record transaction codec, bounded `ABORTED` retry, and lost-response exact readback. The rustls/no-proxy transport and dedicated bearer are image-selected; routes and requests cannot choose them. Off-profile images construct none of it. |
| `src/archive_v3_firestore_auth.rs` | **Conditionally active Firestore witness identity:** the signed runtime alone composes this dedicated WIF/no-nonce/retry-disabled STS boundary for the fixed witness transport. No route or request can select its audience or credentials. |
| `src/archive_v3_firestore_shadow.rs` | **Conditionally active Firestore witness composition:** the signed runtime constructs the exact named-database adapter, dedicated attestation bearer, and fixed transport without I/O for Genesis, WAL publication, and deletion-only native-async recovery. Off-profile images construct none of it. |
| `src/archive_v3_gcs_auth.rs` | **Signed-runtime ADR-0022 archive-GCS identity boundary:** an independently typed `archive-gcs-attest/archive-gcs` WIF audience, no-nonce launcher token, fixed retry-disabled Google STS exchange for only `devstorage.read_write`, zeroizing request/response/cache ownership, and no metadata/default credentials or service-account impersonation; only the signed Genesis runtime connects it to the fixed archive transport |
| `src/archive_v3_registry_kms.rs` | **Conditionally active ADR-0022 archive-registry KMS adapter:** derives one numeric version only below the exact production KMS key, verifies the exact enabled symmetric-software version and encrypt response coordinate, binds wrap and unwrap to canonical registry-plus-version AAD, and strictly validates wrappers and KMS integrity fields. Only the signed runtime can supply the version and provider; Store, routes, and requests cannot select them. |
| `src/archive_v3_shadow_runtime.rs` | **Conditionally active sealed ADR-0022 runtime composer:** the signed Genesis profile binds fixed archive-GCS, registry-KMS, and named-Firestore providers to opaque per-account archive bindings read only from encrypted Control. Each resulting runtime is still single-archive and bind-once; the image profile now authorizes the durable fleet rather than one canary commitment. Startup separately installs an exact deletion-only bundle using the same baked coordinates plus Control-derived deletion/page keys. Off-profile images install no deletion lane and retain the honest pending response. |
| `src/archive_v3_maintenance_import.rs` | **Inactive ADR-0022 maintenance-window import:** a sealed-runtime-owned, single-archive offline coordinator durably fences and pins one exact legacy Store generation, authenticates the existing Active+Legacy witness/root/registry, uploads exact-readback checkpoint objects under a distinct domain-separated zero-WAL-only binding and canonical R1, reconciles ShadowWal only by exact witness reread, and performs full independent SQLite parity with fresh source/witness validation. `#289` deleted the advisory arm: `MaintenanceImportTarget` now has the single variant `WalAuthoritative`, and with the advisory importer went its sealed Store/user/archive/import target, the advisory release ledger and exact-marker executor, the local-resume transition that installed a capture selector, and the private R1-replay/parity comparison child. `abort_pre_owner` still handles import failure before any owner exists, reconciling exact-generation provider-marker deletion to a fresh `NotFound` and durably transitioning the stage to `manual_required` under the exclusive user lifecycle lock before safely unblocking both process-local gates. **The surviving R2/WalAuthoritative door is closed in practice, not merely inactive:** it is gated on `ensure_phase2_acquisition_intact`, which requires a durable `archive_v3_phase2_authority_acquisitions` row resting at `Phase2Acquired`, and `#289` removed every writer of that table — only `from_db`/`load_phase2_authority_acquisition` survive, so existing rows still decode but no new acquisition can ever be minted here. Under the genesis-first replan an archive is created from genesis rather than migrated, so no successor mint is planned. Encrypted control still owns bounded restart stages, full-tuple lease renewal/reacquire CAS, reacquire-only partial-attempt supersession, up to 16 retained attempts, and 32,898 exact artifacts per attempt. It has no main/startup/route/worker/config/serving wiring, archive-v3 provider list/delete, legacy-source deletion, durable capture settlement, policy switch, cloud action, or deployment authority; only the existing bounded legacy-intent prefix scan drains pre-marker writes. |
| `Dockerfile` | Digest-pinned builder/model definition for the static `x86_64-unknown-linux-musl` image. Stable tool/model/dependency layers precede final configuration; explicit committed Cargo/source subset hashes prevent stale BuildKit records while source time stays in signed evidence rather than Docker's global cache inputs. Configuration is assembled from an ephemeral BuildKit secret whose non-secret `CONFIG_SHA256` is declared only in the late image-config stage and verified against the assembled bytes. Native OCI output and the explicitly confirmed fallback are driven by `scripts/local_image_pipeline.py`; remaining rebuild limits are documented in `SECURITY.md` |
| `Cargo.toml` / `Cargo.lock` | Crate manifest |
| `README.md` | What the enclave does + the attestation/privacy claim |
| `API.md` | Stable Cloud Capture API v2 contract for pure-Swift macOS/iOS clients, bounded Mac screenshot-reference batches, durable session finish, exact-session status, privacy-safe push registration/handoff, retry semantics, browser metadata, processing status, and learned people profiles |
| [eval/](eval/map.md) | Public, content-free voice/identity quality scoring plus archive-capacity contracts, synthetic regression inputs, and real-corpus methodology |
| [scripts/](scripts/map.md) | Offline evaluation-asset and capacity-fixture generation, fail-closed inactive archive-v3 signed-capacity-evidence verification, versioning, build-profile, and signed-release operator tools, including the exact provider-free fresh-BOOTSTRAP schema-10 producer/verifier |
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
