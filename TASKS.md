# PostgreSQL-only structured-state cleanup (ADR-0042)

Production has no users or legacy user data to migrate. This cleanup removes the retired
SQLite/GCS authority rather than preserving it as a swappable backend. It must not add backfill,
dual-write, shadow-read, import, or reverse-rollback machinery.

## Runtime and persistence

- [x] Make PostgreSQL the unconditional serving authority across startup, routes, workers,
  exports, episode/account deletion, restart recovery, search, and readiness.
- [x] Delete the SQLite ControlStore/Store implementation, SQLite search/FTS/vector adapters,
  backend selection/fallback branches, archive-v3/WAL/checkpoint/witness runtime, and legacy-only
  tests after PostgreSQL parity is proved.
- [x] Preserve domain repository ports and useful in-memory fakes; do not couple HTTP handlers or
  provider adapters directly to `sqlx`.
- [x] Keep GCS exclusively for live application-encrypted media and recording bytes, including
  exact-generation access, conditional writes, object-bound authenticated context, and complete
  deletion inventory. Do not delete live media buckets or PostgreSQL state.
- [x] Confirm the final serving source has no reachable SQLite authority/fallback, no obsolete
  archive/WAL/witness runtime, and no unjustified `rusqlite` or SQLite extension dependency.

## Configuration, tooling, and infrastructure

- [x] Remove obsolete checked-in archive/witness/genesis configuration, capacity fixtures,
  release-tag sequencing, SQLite image workaround, and legacy-only tooling tests.
- [x] Make `agent-verify.sh full` require an explicit real PostgreSQL URL, export the fail-closed
  contract signal, and refuse to silently assume Docker availability.
- [x] Keep the signed local release path, immutable source/tag/image binding, SBOM, vulnerability
  scan, Ed25519 evidence, canonical release metadata, and incompatible scale-to-zero lane.
- [x] Remove the dead image/runtime PostgreSQL schema-mode key; serving verifies schema
  unconditionally, while release evidence records that fixed source invariant directly.
- [x] Reduce production configuration to PostgreSQL, shared TLS, KMS, live media/recordings,
  authentication, billing, inference, and outbound-provider inputs.
- [x] In the deployment repository, remove retired authority selectors and unreachable infrastructure
  wiring while preserving Cloud SQL, live media/recordings, KMS admission, shared TLS, the regional
  fleet, health checks, and provider identities. Apply the source-only state transition and finish
  it with an independently reviewed refreshed no-change plan.
- [ ] After a homogeneous v0.9.9 rollout is proved, retire the five exact predecessor legacy-IAM
  edges and the separately inventoried protected provider objects through reviewed, staged plans;
  never combine that retirement with the serving rollout.

## Required verification before merge

- [x] Run focused Rust repository/worker/API tests continuously while source slices settle.
- [x] Run every checked-in Python and shell tooling contract.
- [x] Run `./scripts/agent-verify.sh full` against disposable PostgreSQL 17 and prove the harness
  cannot skip contracts when `KIOKU_REQUIRE_POSTGRES_CONTRACT=1`.
- [x] Prove real PostgreSQL tenant isolation, schema readiness, full-text/vector/time-zone queries,
  concurrent claims, expired-lease takeover, stale settlement refusal, provider ambiguity/no
  resend, restart enumeration, export, episode deletion, account deletion, and no resurrection.
- [x] Run clean formatting, locked tests, all-target Clippy, production-feature builds, RustSec,
  SBOM generation, and vulnerability scanning; record the exact commands and results in the PR.
- [x] Rebase onto current `origin/main`, obtain review, and rebase-merge. Do not push directly to
  `main`.

## Release and rollout, if the runtime digest changes

- [ ] Publish from a signed standard `vMAJOR.MINOR.PATCH` tag with schema-11 metadata and exact
  source/image/config/SBOM/scan/evidence bindings.
- [ ] Follow ADR-0041's staged zero-unavailable regional rollout: predecessor/candidate KMS
  admission, canary, PostgreSQL schema and shared-TLS readiness, authenticated API and content-free
  provider-effect probes, member-by-member replacement, predecessor retirement, and final
  no-change Terraform plan.
- [ ] Record the exact source commit, signed tag, image digest, KMS condition, PostgreSQL authority
  and schema, fleet member zones/digests, readiness/liveness, no-op/effect-safety receipts, and
  final infrastructure plan.

# Existing product gates preserved by the cleanup

## ADR-0029 ready-notification delivery

- [x] Persist per-installation APNs registrations with account-switch and credential-generation
  fencing; commit first-finalization deliveries atomically and never replay regeneration.
- [x] Use privacy-safe per-device handoff handles, owner-only resolution, bounded expiry/pacing,
  provider ambiguity as terminal no-resend, and content-free telemetry.
- [x] Use durable PostgreSQL claim/lease/settlement transitions so horizontal workers cannot send
  the same provider effect twice; deletion and credential rotation conflict with an in-flight
  destination before disclosure.
- [x] Keep APNs non-blocking to memory finalization while production startup and release fail closed
  on an incomplete provider configuration.

## ADR-0030 silence compaction

- [ ] Keep speech-time compaction disabled until its versioned real-corpus recall, timestamp
  restoration, provider-token, latency, and net-cost gates pass. The structured-state cleanup does
  not activate or weaken those gates.

## ADR-0036 durable recording audio

- [ ] Keep external durable-recording/playback activation blocked until export includes all media
  bytes and account/episode deletion inventories every exact live and noncurrent recording
  generation. The cleanup preserves the live recordings bucket and its KMS/media boundary.
