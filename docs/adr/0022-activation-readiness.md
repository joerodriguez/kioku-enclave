# ADR-0022 activation-readiness review

> **SUPERSEDED (2026-08-20) — historical record, do not execute.** The genesis-first
> replan drops retention of existing archive data, so the advisory-canary/Phase-2 route
> to authority this review certified was deleted rather than finished: `#288` (`61ae996`)
> severed the advisory-owner entry point and `#289` (`9b2f87e`) deleted the whole
> advisory-owner family, the Phase-2 admission (including
> `full_reviewed_mutation_set_commitment` and its offline signing ceremony), the
> `--run-archive-v3-phase1-canary` argv entry, and the eight phase1/phase2
> signer/provision scripts. Removing that compile-pinned mutation-set commitment is what
> allowed `#290` (`6c66842`) to add `WalOperationKind::SchemaEpochAdvance = 13` without an
> offline re-signing ceremony. **Every boundary this document reviews below is gone from
> the tree**, and none of its blockers is a live prerequisite. It is retained for the
> decision history only; the current path to authority is genesis-first archive creation
> plus the schema-epoch ladder, not migration of an existing archive.

Status: inactive Phase-1 protocol-boundary review complete; production activation is neither
authorized nor ready to perform. The exact operational decision and rollout gates are recorded in
[`0022-production-activation-runbook.md`](0022-production-activation-runbook.md).

This review covers the enclave implementation of ADR-0022 through the inactive single-archive WAL
launcher/owner, capture/comparison, settlement/retirement, and three-root admission boundaries. It
does not revise the authoritative ADR, enable a runtime path, or claim production evidence.

## Inactive boundary now closed

- The encrypted checkpoint, WAL, root, witness, exact-name recovery, lifecycle, and deletion
  protocols are compiled and locally tested without a serving call path.
- The maintenance importer independently compares the pinned legacy database with the recovered
  archive-v3 database across SQLite integrity, FTS/vector integrity, table counts, logical export,
  full logical contents, and selected queries before it can mint a terminal handoff.
- A type-separated Phase-1 importer can now stop at that verified `ShadowWal` point, release only
  the exact maintenance lease, scrub its scratch family, and drop its owned Store guard values.
  The permanent legacy provider fence and process-local Store/barrier blocks remain fail-closed.
  A reviewed inactive Store-owned executor now consumes the Control advisory-release ledger and
  reconciles deletion of only the exact permanent marker generation. A separate consuming local-
  resume transition freshly reauthenticates the frozen witness and exact terminal Control row
  under the same user lifecycle lock, then reopens both process-local gates together without
  provider or database I/O. It is still private and has no production caller.
  Its opaque handoff cannot request `WalAuthoritative` or change serving acknowledgements. Direct
  use of the existing authority importer after release is fenced; a separately reviewed Phase-2
  acquisition transition is still required.
- The terminal handoff carries a non-cloneable parity-certified Control record. The private WAL
  launcher re-reads that exact record and reauthenticates its terminal witness/root relation before
  publisher ownership can start.
- A separate private Phase-1 launcher now consumes only that advisory handoff. Encrypted Control
  reserves one random advisory owner and durably records `SendStarted` before the exact ShadowWal
  witness acquisition. A lost response is adopted only from the exact owner/fence successor, and
  reopen exact-loads the same bound row without a second provider mutation. The live owner may now
  heartbeat the same exact fence or reacquire only after provider-trusted expiry; every one-step
  successor is exact-adopted and full-tuple-CASed in Control, while a restarted process cannot
  heartbeat the old fence and remains inert until exact post-expiry higher-fence reacquisition.
  This capability still has no capture, root, object, Store, acknowledgement, task, or startup
  operation.
- One private actor serializes the complete reviewed twenty-one-plan A/B/C set. Type erasure occurs
  only after sealed plan preparation, exposes neither generic SQL nor a ledger selector, and returns
  a result only to the matching typed submitter after durable witness settlement.
- The publisher retains only exact-name immutable create/get authority. No object enumeration or
  deletion capability crosses the handoff.
- The launcher, publisher, logical codecs, and test-only Store policy have no caller from main,
  startup, configuration, routes, health, workers, the production Store registry, or an
  acknowledgement surface.
- The inactive advisory release ledger authenticates the exact parity terminal and bound owner,
  then full-tuple-CASes `Prepared -> DeleteStarted -> Released`. Preparation permanently fences
  owner-lease succession. Later stages accept only Store-token-minted exact marker-name/authority/
  metadata/generation and exact-name absence evidence. The retained one-user Store target exact-
  reads and authenticates that marker, deletes only its recorded generation after `DeleteStarted`,
  and reconciles a lost response only through fresh exact-name absence. Release and maintenance
  serialize on the same one-user lifecycle lock; maintenance plan adoption plus a post-lock
  Control check rejects started release before provider I/O, and release freshly matches the
  retained advisory witness before Control prepare. Maintenance now performs that post-lock
  check before closing either local gate, so a stale waiter cannot leave Store reblocked after
  terminal resume. Local resume repeats the exact witness and release reads, rejects partial gate/
  active-handle or writer state, and clears registry plus raw-content admission under both locks.
  It has no list/get/put/delete capability. No capture selector, startup, route, or task invokes
  this path.

## Activation decision

The production decision is **NO-GO until every applicable row below is closed by a separately
reviewed activation change and production evidence**.

| Boundary | Current state | Required before activation |
|---|---|---|
| Phase-1 advisory shadow canary | Verified ShadowWal bootstrap plus inactive exact advisory-owner acquisition/heartbeat/expiry-reacquire exist. Store's inactive capture injection is exact-one-user and production-unconstructible; the parity terminal hands the owner a sealed exact Store/user/archive/import target. The release ledger and Store-owned executor durably freeze succession, authenticate/delete only the exact marker generation, and prove exact-name absence, including lost-response recovery. The separate local transition reopens both process-local legacy gates atomically only after fresh exact witness/Control authentication, installs the exact-user capture selector, and stale maintenance cannot reblock them. The owner can select one bounded cancellation-safe prefix together with a read-only transaction pinned to the same serialized legacy state. Its private worker exact-recovers R1, replays the strict captured prefix, compares independent staging copies, atomically restores the still-live exact drain before evidence, repeats source/release/witness authentication, and emits only opaque evidence. Retirement wins the restore lock and fails evidence closed. Successful evidence can enter one exact one-shot encrypted-Control settlement; late readback rolls back and retained rows load before new work. Only after that durable row, a cancellation-owned exact Store transition clears the matching selector and retires/scrubs the matching registration, with exact already-retired reconciliation. The legacy connection remains open and authoritative; the terminal owner cannot compare twice, acknowledge, or publish. One encrypted exact canary scope plus a separate runtime-precondition row are atomically consumed with and bound to the first owner reservation. A private fixed-size verifier requires pairwise-distinct operator, image-attestation, and deployment-observer Ed25519 roots; the third assertion fixes Phase 1 to an empty authoritative mutation set, legacy-only acknowledgements, one maintenance-window/deployment/challenge tuple, zero serving replicas, and exact monitoring/rollback commitments. Fixed non-configurable `Phase1TmpfsPolicyV1` strictly enforces `total = (database * 2) + worst_case_wal + sqlite_scratch + model_working_set < 4 GiB` and `total * 4 < authenticated_vm_bytes`. A durable encrypted Control controller run ledger with full-tuple CAS (`Prepared -> Eligible -> Imported -> Authorized -> OwnerAdmitted -> Retired / Aborted / ManualRequired`) executes inside an owned task with cancellation safety. Live non-cloneable `HeldPhase1Window` revalidation and commitment-only panic-isolated asynchronous telemetry are verified. All checked-in roots remain intentionally invalid and there is no caller or signing key. | Restrict the canary to an exact database plus worst-case WAL/SQLite/model working set below 4 GiB and below 25% of measured VM memory. Populate three separately controlled public roots; live Confidential Space claim/nonce and fresh deployment-state observers, reviewed archive resources, and deployed monitoring/rollback; hold the window and zero-serving condition across import, handoff, and admission; prove advisory failures cannot affect legacy behavior. |
| Enabled mutation set | Phase 1 is cryptographically fixed to an empty authoritative set; it may only observe and compare legacy-authoritative work. The reviewed twenty-one-plan publisher remains inactive and separate. | Keep the Phase-1 set empty. Before a separately authorized Phase 2, select an exact plan-level canary allowlist. Every enabled path must supply its stable identity and typed plan. Slice 11 records the audio split-domain decision: audio-window transcripts (attempt B + bound transcript A, no identity rows) are now reviewed plan families, while person/identity/voice mutation, screen-person evidence, and generic/finalization Vertex-begin stay disabled or receive their own review first. The sealed epoch-0 re-baseline now creates `audio_segments`/`utterances` with `AUTOINCREMENT`, so the audio family's sqlite-sequence gate opens on a current production archive; it remains a residual fail-closed defence against a legacy pre-re-baseline archive shape. |
| External attempts | Provider-neutral seams only where reviewed | For any enabled provider-writing domain, construct only the reviewed KMS/provider adapter and preserve durable B send identity, one-shot execution, exact readback, C definitive-rejection, and manual handling of ambiguity. |
| Runtime ownership | Private inactive Phase-1 lease-lifecycle owner, restart-safe owned controller task, and a separate inactive authority importer exist; advisory release cannot enter that importer. The owner-only drain binds a complete prefix to the exact pinned legacy transaction, and the private recovery/replay/parity worker returns only a non-settling commitment. The runtime-admission row is exact-bound to the initial owner. The restart-safe controller authenticates and holds one fresh non-cloneable `HeldPhase1Window` observer condition before importer start through owner admission, with no process-clock authority; constructs only the exact scoped importer from `SealedSingleArchiveWalRuntime`; proves durable comparison/retirement/rollback ownership; and keeps a distinct exact Phase-2 authority acquisition with no second Store/runtime. | Add a live observer integration, populated production roots, and signed authorization before activation. |
| Store and acknowledgement | Production remains `LegacySnapshot` | A separately reviewed policy/route/worker change must keep Phase 1 advisory. Phase 2 may acknowledge only after immutable WAL plus witness durability and exact replay; no local SQLite commit alone may authorize success. |
| Release evidence | Local correctness gates only | Before Phase 1, prove exact-image security, the strict below-4-GiB-and-below-25%-memory canary bound, and legacy-no-impact behavior. Treat the separate 32-GiB I/O/latency/memory/cost/concurrency/integrity contract as evidence for the later authority/large-archive phases, not as Phase-1 eligibility. |
| Recovery/lifecycle drills | Unit/integration fault coverage, no production drill | Before Phase 1, exercise the advisory import/release/resume/capture/comparison/settlement/retirement/restart/rollback and legacy-no-impact paths on the exact image. Before Phase 2, exercise uncertain provider response, checkpoint/compaction, export, deletion, schema migration, rollback/roll-forward, orphan retention, and forensic legacy-read rules for the authoritative configuration. |
| Cloud/deployment | No mutation performed; checked profiles are off, the witness infrastructure is transport-probe-only, active image roll is quarantined, and archive-specific telemetry is absent. | Review exact archive GCS, registry-KMS, authoritative-witness creation/adoption/backup/restore and IAM; add the locked canary lane and content-free telemetry; then obtain explicit operator authorization for the named resources, image, subject, monitoring, and rollback window. |

The inactive resumed-canary and released-before-local-resume loci now share one
exact `Prepared -> Aborted` terminal. The first retires only its exact capture;
the second durably prepares before atomically reopening the paired legacy gates
without capture. Both are mutually exclusive with successful comparison, and
normal resume checks abort absence under the same exact-user lifecycle. A private restart worker can also finish a retained
`Prepared` row only after the controller-owned Store proves process-local
capture absence while holding the exact-user lifecycle guard. Pre-owner durable
abort and cleanup is now implemented: it reconciles exact-generation GCS marker
deletion to fresh `NotFound`, durably transitions the maintenance import stage to
`manual_required` under exclusive user lifecycle lock asserting absence of any
advisory owner or release row, and safely unblocks local legacy Store gates without
installing capture or opening DB handles.

## Required order

1. Collect exact-image Phase-1 security, strict tmpfs-size, advisory restart/rollback/no-impact,
   resource, telemetry, and production-shaped evidence before launch.
2. Activate one advisory Phase-1 canary only; legacy remains authoritative and shadow errors are
   non-authorizing. Collect canary-generated comparison/recovery/no-impact evidence before any
   expansion.
3. Review and drill the exact enabled-domain adapters and ownership/Store integration; leave every other
   domain disabled.
4. Obtain a separate explicit decision before Phase-2 WAL authority or any acknowledgement change.
5. Treat Phases 3–6 (large-archive extent shadow/authority, production-wide horizontal ownership/
   control migration, and legacy retirement) as later forward-only decisions with their own
   evidence and approvals. Phase 2 can cover only tmpfs-eligible archives, not all users.

## Permanent no-go signals

Do not activate if any path can acknowledge before witness settlement, retry an ambiguous external
attempt under a new identity, infer definitive rejection from absence alone, enumerate/delete
archive objects through the WAL runtime, select an older root after later acknowledgements, run a
second archive owner, let shadow failure change the legacy response, or bypass exact image/config/
release-evidence binding.

This document records readiness findings only. It grants no permission to modify cloud resources,
deployment, serving configuration, production data, Store policy, or user-visible behavior.
The companion production-activation runbook separates the one-archive advisory decision from the
later authoritative/all-user decision and lists the evidence and explicit authority each requires.
