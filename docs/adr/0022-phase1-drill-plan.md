# ADR-0022 Phase-1 drill plan

Status: proposed plan awaiting operator decisions; grants no permission to deploy,
mutate cloud resources, or change serving behavior. Companion to
[`0022-production-activation-runbook.md`](0022-production-activation-runbook.md)
(the drills row) and the Phase-1 GO-packet blocker inventory.

## What already exists (the semantic specification)

The advisory canary's fault semantics are already specified executably by the
in-repo test suite; the drill plan cites these rather than re-deriving them:

- The `run_real_sqlite_import_stops_advisory_reopens_and_fences_authority` family
  (src/archive_v3_maintenance_import.rs) with its nine terminal test modes forces
  real lost provider responses (`FakeGcs::fail_next_generation_delete_after_commit`,
  `fail_next_put_after_commit` — commit succeeds, response lost), marker/generation
  substitution, CAS-finalize corruption, caller cancellation, and fresh-`Store`
  restarts, asserting exact-readback reconciliation and zero extra legacy I/O
  (`operation_counts()` / `live_get_count()`).
- Abort is the best-covered subject (nine forced modes across
  `archive_v3_advisory_owner*`); release, comparison, and retirement have genuine
  forcing including mid-comparison stalls and cancellation-mid-retirement.
- Legacy-no-impact has genuine partial coverage: retirement-during-serving keeps
  exact SQLite results; legacy I/O failures preserve exact return codes and shadow
  state; post-retirement legacy writes succeed.

## Central finding

**Every forcing seam is `#[cfg(test)]`-gated and no drill entry point exists on a
release image.** The enclave binary exposes only voice-eval flags; the controller
has no production caller (by design); `FakeGcs`, the Control fault hooks, the
witness outcome-unknown injector, and the comparison stall are all compiled out of
release builds. The runbook's "signed exact-image receipts" therefore cannot be
produced from the current repository state by anyone, and the drill plan's first
required decision is the drill execution model itself.

## REQUIRED_DECISION D1 — drill execution model

Options, with a recommendation the operator may reject:

1. **Rehearse-through-the-controller (recommended, no new attack surface).** The
   drills for import, release, local resume, capture, comparison, settlement,
   retirement, abort, and restart are executed as controlled rehearsals through the
   existing one-shot controller during (or immediately before) the approved
   maintenance window, against the real canary archive, on the exact deployed
   image — i.e., runbook execution-order steps 5–9 run once in rehearsal mode with
   the operator forcing external conditions (witness custodian withholding a
   response; provider-side fault injection at the GCS/Firestore layer via IAM-timed
   deny or network policy, not code seams). Receipts are the durable Control rows
   each stage already writes (see receipt binding below). Restart drills are real
   process restarts of the enclave between stages.
2. **Companion drill binary from the same frozen source.** A second, separately
   reviewed `[[bin]]` target built by the same pipeline from the same commit, whose
   own digest is recorded in the GO packet alongside the serving image digest. It
   links the same modules and drives them with reviewed injection seams compiled
   only into the drill binary. Weaker "exact image" claim (exact source, sibling
   image); stronger fault coverage.
3. **Drill surface inside the serving binary.** Rejected by this plan: it adds
   standing attack surface to the attested production entrypoint for a one-time
   evidence need.

The recommendation is option 1 for the eleven protocol drills plus option 2 only
if the operator judges provider-external fault forcing (1) insufficient for the
lost-response subjects. Either choice is a separately reviewed change.

## Drill-to-path mapping

Each drill subject maps to the production path and durable receipt row it must
exercise (paths as of the Phase-1 integration branches):

| Drill | Production path | Durable receipt |
|---|---|---|
| Restart | controller `reconcile_retained_run` + importer restart adoption | `archive_v3_advisory_controller_runs` stage row before/after |
| Lost response | owner `OutcomeUnknown` readback; importer `ShadowSendUnknown`; release delete-vs-absence | `archive_v3_advisory_owners` / `archive_v3_maintenance_imports` / `archive_v3_advisory_releases` stage+commitment |
| Import | preflighted importer via controller `Eligible → Imported` | `archive_v3_maintenance_imports` full tuple |
| Release | `release_legacy_fence` `Prepared → DeleteStarted → Released` | `archive_v3_advisory_releases` |
| Local resume | `resume_advisory_local_admission` | controller run row + Store gate state |
| Capture | capture VFS mirror + drain | capture registration/drain receipts |
| Comparison | `compare_captured_prefix` + reauthentication | `archive_v3_advisory_comparisons` evidence commitment |
| Settlement | `settle_comparison` one-shot row | comparison settlement row |
| Retirement | `retire_advisory_capture*` | `StoreAdvisoryCaptureRetired` |
| Abort | abort terminals (both loci) + pre-owner abort | `archive_v3_advisory_aborts` |
| Rollback | **unimplemented in Rust** — see D2 | rollback policy commitment binding only |
| Legacy-no-impact | capture panic-containment + telemetry isolation + controller `let _` isolation | paired measurement receipts (new; see D3) |

## Receipt binding

A signed drill receipt must bind, per drill: the release image digest, the
maintenance-window ID, the challenge commitment, the exact Control row
`commitment`/`revision` pairs the drill traversed, and a fresh
`Phase1AttestationClaimEvidence::commitment()` produced inside the window. Two
in-repo follow-ups fall out of this plan:

- F1: a Control column persisting the attestation-claim evidence commitment
  (today it has no storage), so receipts can bind it durably.
- F2: a canonical drill-receipt byte format + `scripts/` offline verifier in the
  style of `verify_coordinator_advancement_receipt.py`.

## Test-coverage gaps to close in-repo (no decision needed)

1. A genuine crash between two durable controller stage writes (fresh-process
   re-entry through `execute_canary_admission`'s retained-stage gate).
2. The `release_failed → ManualRequired` and `resume_failed → Aborted` controller
   branches.
3. The settled-but-not-retired window (crash between comparison settlement and
   capture retirement, reconciled by `reconcile_advisory_capture_retired`).
4. Legacy-no-impact under a forced capture panic / poisoned capture mutex:
   byte-identical SQLite return code, row set, and retry behavior (the
   `catch_unwind` containment currently asserted only by module prose), via a
   `#[cfg(test)]` panic-injection hook in the capture VFS.

## REQUIRED_DECISION D2 — rollback drill definition

Rollback today exists only as a policy commitment binding; `release.sh --roll`
hard-refuses active archive-v3 images pending the deployment-compatibility change
(C8). The rollback drill therefore requires, in order: the C6 stop command and
evidence-preservation location; the C8 compatibility change; and a signed
definition of "rollback executed" (VM re-pinned to the prior digest, advisory
rows preserved, legacy authoritative, canary retired/aborted). This plan does not
invent those values.

## REQUIRED_DECISION D3 — latency evidence

No timing harness exists anywhere in the repository, and telemetry duration
buckets are deliberately too coarse for a latency-delta assertion. The
legacy-no-impact drill needs an operator-approved measurement: paired latency
distributions and stored-result hashes for an identical legacy workload with (a)
no capture installed, (b) capture installed and healthy, (c) capture forced into
its contained-failure mode. The measurement tooling and acceptance thresholds
(runbook: "latency") are C6 policy values.

## Explicitly not granted

This plan authorizes no deployment, no code seam in the serving binary, no cloud
mutation, and no drill execution. It defines what the GO packet's drill receipts
must contain and the three decisions (D1–D3) plus two follow-ups (F1–F2) and four
test gaps that stand between the current tree and producible drill evidence.
