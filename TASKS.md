# ADR-0029 ready-notification delivery

- [x] Persist authenticated, per-installation APNs registrations with account-switch and token-generation fencing.
- [x] Commit first-finalization push deliveries atomically with the final memory result; regeneration does not replay them.
- [x] Send privacy-safe per-device handoff handles through separate production and sandbox APNs transports.
- [x] Resolve notification handoffs only for the authenticated owner and canonical browser memory route.
- [x] Treat APNs delivery as non-blocking to finalization while failing production startup/release closed on missing provider configuration.
- [x] Verify the complete Rust suite, lint, formatting, release-selection, and release-preflight contracts.
- [x] Publish signed production release v0.8.14 from source commit
  `181d1131211ee986d8c6897339ebaff62ee8f532` and roll the attested image
  `sha256:f64359c5370e79c3d15b1a1d2dd76e793bd0fbed12906e82e40f5b3f7f891ee7`
  to production. The signed v0.8.13 image remains non-deployable and untouched:
  its attested manifest omitted the selected production profile, and the release
  wrapper correctly rejected it before rollout.

# ADR-0022 task evidence

## Encrypted lifecycle page-store seam

- [x] Added a strict versioned AES-256-GCM envelope with a control-DEK-derived
  independent key, separately domain-derived retry-stable nonce, and AAD
  covering the full exact page name, archive, deletion fence, ordinal, page
  ID, predecessor, hash, and encoded length.
- [x] Added deterministic exact-name immutable create plus authenticated exact
  readback reconciliation; encrypted control durably admits every create as
  outcome-unknown first, and sealing requires the complete exact Created set.
- [x] Added a durable pre-page snapshot commitment that requires every artifact
  and witness create to be settled, advances the exact revision, and rejects
  later artifact reconciliation so cancellation/restart cannot change page bytes.
- [x] Persisted the sole unresolved page's exact bounded bytes and ordered split
  until authenticated readback; restart recovers that exact typed plan and
  conflicting partitions fail before remote I/O.
- [x] Bound exact all-generation and soft-delete absence cleanup to durable
  control physical completion, a frozen/drained prior-create proof, and
  producer-private durable/absence receipts.
- [x] Kept the seam construction-only: no concrete provider, credential,
  runtime/startup/Store/route wiring, reachability walker, pre-witness
  coordinator, cloud mutation, or deployment authority was added.

This compiled seam does not authorize archive-v3 persistence or deletion.

## Authenticated deletion-inventory coordinator

- [x] Replaced final lifecycle-page `PlannedArtifact` payloads with strict
  canonical key/role/ciphertext-hash facts; create attempt, ordinal, state, and
  encoded length remain only in the frozen create-ahead snapshot.
- [x] Introduced a separate KILP-v2 codec, page-hash domain, and inventory-seal
  domain while retaining the independent lifecycle control-anchor format v1;
  the never-live page v1 is rejected rather than migrated.
- [x] Added injected exact Tombstoned witness and encrypted-control boundaries,
  current/predecessor authenticated reachability union, exact object-ID
  dedup/conflict handling, and deterministic greedy paging under combined
  object/key/page/entry/encoded limits.
- [x] Revalidate the complete witness recovery and frozen control snapshot
  immediately before page I/O and before the atomic seal; cancellation/restart
  accepts only the durable Created prefix and sole unresolved exact next page.
- [x] Authenticate exact Tombstoned deletion authority before the snapshot CAS,
  then reauthenticate the unchanged record after freeze and before the graph's
  first exact read, so wrong credentials/Active state cause zero control or
  external I/O.
- [x] Require a producer-private one-shot coordinator proof binding the frozen
  snapshot, canonical plan, exact references, and authenticated readbacks at
  the control seal CAS; removed raw/generic pages-to-seal entry points.
- [x] Added a restart-only sealed loader that validates the full reference set
  before GET, authenticates the exact v2 chain/count/terminal/global object set,
  and mints deletion inventory with exactly the lifecycle seal commitment.
- [x] Removed the deletion driver's obsolete independent inventory builder,
  test-overwritten commitment, and `FullReachabilitySeal`.
- [x] Kept pre-witness absence, Store/startup/runtime/config/routes/health,
  provider construction, deletion-driver invocation, cloud I/O, and deployment
  out of scope and disconnected.

This compiled coordinator does not activate archive-v3 persistence or deletion.

## Pre-witness exact-absence disposition capability

- [x] Atomically enroll each new lifecycle reservation in a versioned,
  domain-committed initial-witness protocol; legacy/missing/unknown enrollment
  is manual and never inferred unsent.
- [x] Persist exact prepared witness hash/length and admitted revision, then
  require a producer-private non-cloneable send-start receipt before the
  Firestore commit boundary.
- [x] Serialize deletion with dispatch so unstarted and started/ambiguous
  creates close into distinct monotonic phases; generic witness reconciliation
  cannot forge absence or unknown-send state.
- [x] Authenticate the tombstoned control binding, lifecycle, protocol, and
  deletion fence before any exact-name witness read; only closed-unsent plus a
  fresh `None` and full-state CAS mints a private absence proof.
- [x] Persist facts rather than proof authority: restart and remint require full
  row validation and another exact absent read, while started `None` remains
  manual and a later exact retained record may resolve present.
- [x] Support reservation/objects-prepared deletion with an exact candidate-free
  closed tuple; permanently poison any later exact, mismatched, malformed, or
  noncanonical present document so confirmed absence cannot resurrect.
- [x] Seal the Genesis witness-create surface to the commit-start-aware
  Firestore creator and recover a crash-after-commit only through the retained
  exact send-start adoption CAS.
- [x] Keep this capability disconnected from deletion-driver invocation,
  Store/startup/runtime/config/routes, provider construction, credentials,
  cloud mutation, deployment, and user-visible behavior.

## Type-separated pre-witness inventory capability

- [x] Consume the fresh absence proof exactly once into a separate versioned
  encrypted-control snapshot binding the complete absence/protocol/bootstrap/
  fence/revision tuple and every settled create-ahead fact.
- [x] Enforce exactly one normal-tombstone or pre-witness inventory branch;
  dual rows, stale revisions, unknown versions, unresolved creates, or tuple
  corruption fail closed before page I/O.
- [x] Reuse only the exact-name page producer under one deterministic plan,
  with fresh durable revalidation before page I/O and seal, exact restart of a
  created prefix/sole unresolved next page, rejection of every zero-plan or
  alternate page before durable admission, and no reachability or metadata GET.
- [x] Represent a reserved zero-object archive as zero pages/artifacts and a
  zero terminal hash under a nonzero, domain-separated branch commitment;
  never create an empty KILP page.
- [x] Load the sealed chain into a separate opaque non-authorizing complete
  inventory with no conversion, entry, provider, or deletion-driver surface.
- [x] Keep startup/Store/runtime/config/routes, provider construction,
  destructive invocation, cloud mutation, deployment, and user-visible
  behavior disconnected.

This compiled capability does not itself authorize provider I/O and does not activate archive-v3
persistence or deletion.

## Durable pre-witness deletion execution protocol

- [x] Added a separate versioned encrypted-control execution row that binds the
  exact pre-witness snapshot/seal revisions, bootstrap attempt, random nonzero
  operation ID, ordered object-set commitment, dimensions, terminal hash, and
  inventory commitment.
- [x] Consume the complete authenticated pre-witness inventory only through a
  producer-private conversion; IDs alone cannot recover execution authority,
  and there is no conversion to normal witnessed deletion types.
- [x] Revalidate the immutable tombstoned/fenced absence branch, deterministic
  Created page set, snapshot, seal, and absence of the normal branch before
  first bind, adoption, recovery, and every evidence CAS.
- [x] Enforce the monotonic inventory-bound -> registry-erased ->
  objects-absent -> physical-complete -> reserved payload-erased matrix with
  full-row exact replay and rejection of alternate, skipped, regressed, zero,
  cross-operation, or structurally invalid evidence.
- [x] Own the sole control SQLite handle outside the shared cache across each
  execution flush, so cancellation/failure forces an authoritative reload and
  lost PUT success is accepted only by exact encrypted-ciphertext readback;
  no local-only stage can mint a recovery capability.
- [x] Preserve the explicit zero-object geometry under nonzero inventory,
  object-set, and execution commitments without creating object/provider
  access, and test close/reopen recovery at every stage.
- [x] Keep all production destructive evidence producers, provider interfaces,
  page cleanup, payload cleanup, driver invocation, Store/startup/runtime/
  config/routes, cloud mutation, deployment, and user-visible behavior out of
  scope and disconnected.

This PR-A protocol persists capability facts only. Destructive execution and cleanup remain
separate activation blockers.

## Firestore transport-probe release boundary

- [x] Made one exact checked-in, non-secret probe profile the sole input to both build
  selection and schema-v7 release verification; it starts `off` with an empty namespace.
- [x] Removed repository-variable and manual-dispatch witness inputs, forced evaluation
  and ordinary `main` images off, and limited `probe-v1` to exact
  `vX.Y.Z-witness-probe.N` prereleases that cannot use `release.sh --roll`.
- [x] Awaited the one-shot probe under a fixed deadline before application Store/KMS/GCS
  construction, emitted only one fixed redacted outcome, and retained no health/startup/
  archive-authority connection.

These release and runtime boundaries do not create a Firestore database, grant provider
IAM, publish a probe release, deploy an image, or activate archive-v3 authority.

## Construction-only shadow-runtime release boundary

- [x] Composed fixed archive-GCS, exact registry-KMS-version, and named-Firestore
  providers synchronously behind one non-cloneable private-field bundle with an
  always-deny hard-delete gate and no callable runtime handle.
- [x] Added one exact checked-in `off`/empty profile as the sole build and schema-v7
  release claim; repository variables, dispatch, tags, and process environment cannot
  select provider fragments or an active mode.
- [x] Kept startup, Store/VFS, lifecycle, routes, health, admission, tasks, provider I/O,
  deployment, and every archive/root/deletion authority path disconnected.

This code-only boundary does not make schema-v7 images deployable. The deployment
repository must first merge an independently reviewed schema-v7 compatibility update;
until then no release from this source may be promoted or rolled.

## Capacity fixture and local gate

- [x] Versioned deterministic, numeric-only 12-month fixtures for 40, 80, and 100
  recording hours per month, with exact derived distributions.
- [x] Declared and validated the 32-GiB SQLite ceiling and a sparse near-ceiling extent
  profile without committing generated data.
- [x] Added a separate, opt-in production-shaped local gate with profile-derived disk
  preflight, bounded streaming batches, exact per-kind distribution checks, SQLite
  DB/WAL/checkpoint observations over materialized content-free payload/vector-shape BLOBs,
  and content-free reports.
- [x] Kept Phase-0a smoke tests fast and permanently non-evidence; the long gate is not
  executed in CI contract tests.
- [x] Defined an inactive, offline, restricted-JCS preauthorization schema and policy
  template, exact workload-by-result/environment/metric/formula verifier, explicit untrusted-wrapper activation
  blockers, and adversarial test contract. The checked-in template has intentionally invalid
  anchors; no current input authenticates time/challenge/provenance or consumes a replay nonce.
- [ ] Populate a separately controlled release policy with real trust anchors, collect
  signed production evidence, and exercise archive-v3 VFS, backend, witness, fault,
  lifecycle, cache, and concurrency paths before any authority transition.

The checked items do not authorize archive-v3 persistence or deployment. See
[`eval/capacity/README.md`](eval/capacity/README.md) for the reproducible operator command
and the local gate's explicit limitations.
