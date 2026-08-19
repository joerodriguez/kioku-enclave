# ADR-0022 production activation runbook

Status: **NO-GO** pending the remaining stops below; the operational ceremony in this
document is rescoped for the current single-operator/single-user deployment by the accepted
amendment [`0022-solo-operator-activation.md`](0022-solo-operator-activation.md), which retains
every data-safety property and no-go signal. Every reviewed protocol prerequisite is now merged
and locally verified (see "Prerequisite status"); what remains is the activation change itself,
the operator-held policies, the on-VM rehearsal, and the cutover window. This runbook records the
exact decisions and evidence required; it does not grant permission to publish, deploy, mutate
cloud resources, change Store policy, or affect production users.

The rollout has two separate authorization boundaries:

1. **Phase 1: one advisory canary.** Legacy remains authoritative. Archive-v3 may observe and
   compare one exact user/archive, but its authoritative mutation set is cryptographically empty
   and it cannot change acknowledgements.
2. **Phase 2: explicitly allowlisted archive authority for tmpfs-eligible archives.** Only a later
   reviewed change may enable named mutation plans, provider adapters, witness-backed
   acknowledgements, and a gradual eligible-archive rollout. Phase-1 approval never implies
   Phase-2 or all-user approval.

Phases 3–6 from ADR-0022 remain later forward-only decisions and are outside this runbook.

## Prerequisite status

The original hard stops were independent safety barriers. Each is listed with its current state;
"resolved" means a reviewed merged change now provides the capability while remaining inactive in
serving images. Remaining stops still make activation impossible today.

**Resolved by merged, locally verified changes:**

- ~~All three public roots are invalid zero roots~~ — three real, pairwise-distinct Ed25519 roots
  are pinned in `canary_trust.rs` (byte-verified against the operator-held keys; custody in the
  amendment). Rotation still requires a reviewed PR.
- ~~No live claim/nonce verifier, deployment-state observer, or launcher~~ — the nonce-bound
  Confidential Space claim adapter (`attestation_challenge.rs`), pinned-root live window observer
  with the exactly-once operator observation feed (`live_window_observer.rs`), and the one-shot
  restart-safe solo controller behind the pre-serving `--run-archive-v3-phase1-canary` argv
  subcommand (`solo_entry.rs`) are merged and inactive.
- ~~`release.sh --roll` rejects an active archive-v3 image~~ — replaced by the two-factor roll
  predicate: an active-config image rolls only with an exact `vX.Y.Z-archive-v3-wal.N` tag and
  `KIOKU_CONFIRM_ARCHIVE_V3_ROLL` naming that exact tag.
- ~~No drill receipts~~ — rescoped by the amendment to the full locked test suite (fault-injection
  families across import, release, resume, capture, comparison, settlement, retirement, rollback,
  succession, and acquisition) plus the offline rehearsal receipt recorded in the deployment
  record.
- ~~No provisioning plan~~ — the non-mutating emitter (`phase1_provision_archive_resources.py`)
  and the executed, verified provisioning of the archive bucket, registry KMS, and named witness
  database.
- ~~No Phase-2 machinery~~ — the Phase-2 admission verifier (compile-pinned full mutation set),
  the durable acquisition with scope/user binding and the acquisition-gated `run_phase2` door,
  per-user WAL-authority persistence selection minted from the durable `wal_authoritative`
  terminal, acknowledge-after-witness-settlement regression pins, and the advisory-to-maintenance
  witness-lease succession (basis hash-bound to the acquisition's terminal witness hash) are all
  merged; the full Phase-2 continuation reaches the durable `WalAuthoritative` terminal in the
  locked end-to-end test.
- ~~No signing tooling~~ — offline solo-operator signers exist for the window observation
  (`phase1_sign_window_observation.py`), the Phase-1 three-root authorization
  (`phase1_sign_canary_authorization.py`), and the Phase-2 authority triple
  (`phase2_sign_authority.py`); byte-exact signer/verifier compatibility against the pinned roots
  is pinned in the locked suite.

**Remaining stops (still make activation impossible):**

- `config/archive-v3-shadow-runtime.json` is exact `off` with every deployment coordinate empty.
  Filling it with the provisioned coordinates and the one archive-binding commitment is the
  reviewed activation config change, and building that image is an explicit operator decision.
- No production caller constructs the runtime, importer, owner, provider adapters, per-user Store
  policy re-derivation, or the witness-settled acknowledgement wiring in serving paths. That
  serving-side activation change is a separate reviewed PR (the capabilities exist inactive; the
  wiring does not).
- The capacity policy remains an intentionally unusable template, and the Phase-1 tmpfs bound must
  be measured for the exact canary on the exact VM (the in-enclave `Phase1TmpfsPolicyV1` preflight
  also enforces it fail-closed at run time).
- No offline rehearsal receipt exists yet; the rehearsal runs on the enclave VM against a copy of
  the archive (see the appendix) and its receipt enters the deployment record.
- Monitoring and rollback remain operator-held policy documents whose SHA-256 commitments enter
  the signed admissions; the amendment collapses external owners to the one operator, but the
  documents must exist before signing.
- Cloud mutation authority for the cutover window (image publication, VM roll, provider writes)
  remains an explicit per-window operator authorization.

## Phase-1 advisory-canary decision record

Before an operator can approve Phase 1, one review packet must identify and authenticate all of the
following. Record commitments or public identifiers only; never commit private keys, credentials,
tokens, user content, or raw private user identifiers.

| Evidence | Required exact value or receipt |
|---|---|
| Release subject | Source commit, signed canonical `vX.Y.Z-archive-v3-wal.N` tag, immutable image digest, schema-9 release metadata, SBOM, scan, provenance, and reviewed active runtime-profile digest |
| Runtime coordinates | Archive bucket and numeric project, exact registry KMS version, named witness project/number/database, and the one archive-binding commitment |
| Independent trust | Three nonzero pairwise-distinct public roots with named custodians: operator approval, image attestation, and deployment observation |
| Image observation | Fresh nonce-bound Confidential Space claim proving the exact image digest and approved workload identity |
| Deployment observation | Fresh signed scope challenge, deployment target and revision commitments, maintenance-window ID, exactly zero serving replicas, Phase 1, empty mutation set, and legacy-only acknowledgement |
| Window ownership | Launcher design and evidence showing the same authenticated window/zero-serving condition is acquired before maintenance import and retained through handoff and owner admission; process time alone is not evidence |
| Canary subject | One approved private user commitment, archive, import operation, and rollback owner; no wildcard, percentage, or second archive |
| Phase-1 size eligibility | Exact database bytes plus worst-case WAL, SQLite, and model working set are below 4 GiB and below 25% of measured memory on the exact VM; the generic 32-GiB capacity contract does not establish this tmpfs canary bound |
| Monitoring | Deployed policy matching the signed monitoring commitment, named on-call owner, telemetry freshness, comparison/error/latency/resource thresholds, and automatic stop conditions |
| Rollback | Deployed policy matching the signed rollback commitment, rollback window, responsible operator, exact stop command, and evidence-preservation location |
| Phase-1 security/evidence | Exact-image security and measured canary-size/no-impact evidence with authenticated challenge, time, environment, provenance, independent signatures, and transactional replay consumption; the separate 32-GiB verifier is not the Phase-1 size gate |
| Phase-1 drills | Signed exact-image receipts for restart/lost-result handling across import, release, local resume, capture, comparison, settlement, retirement, and rollback, plus proof that advisory failure does not change legacy latency, response, retry, or stored result |
| Controller and resources | Reviewed one-shot restart-safe zero-serving controller/launcher; exact archive GCS, registry KMS, and authoritative witness provisioning/adoption/backup/restore plan; and archive-specific canary telemetry |
| Cloud authority | Explicit permission for the named projects/resources, credentials/IAM changes, image publication, compatibility change, canary deployment, monitoring, and rollback—limited to Phase 1 |

The decision must be `GO` or `NO-GO`, name the exact evidence digests, name the operator who assumes
the rollback duty, and expire with the approved window. Missing, substituted, stale, partial, or
conflicting evidence is `NO-GO`.

## Phase-1 execution order

Every step must stop on uncertainty. A later successful check cannot excuse an earlier failure.

1. Freeze the reviewed source commit and active runtime profile. Build and sign the exact image;
   verify release metadata, SBOM, scan, provenance, and immutable digest without rolling it.
2. Prove the exact canary satisfies the separate tmpfs bound: database plus worst-case WAL,
   SQLite, and model working set are below 4 GiB and below 25% of measured VM memory. Verify the
   Phase-1 exact-image security, advisory restart/rollback/no-impact drill receipts, real policy
   anchors, and a transactionally consumed authenticated evidence challenge.
3. Apply only the separately approved deployment-compatibility and cloud/IAM changes. Confirm no
   broad object enumeration/delete role, standing human decrypt role, default credentials, or
   second owner/runtime was introduced.
4. Enter the approved maintenance window, establish the fresh deployment observation, and prove
   exactly zero serving replicas. Acquire the launcher-owned condition before import begins and
   retain it through admission.
5. Through the reviewed one-shot controller, run the existing legacy-authoritative advisory import
   for the one exact canary. The controller must construct the importer and exact Store target,
   authenticate the parity terminal, released witness, image, scope, monitoring/rollback
   commitments, and runtime assertion, and restart only from exact durable state.
6. Atomically consume the one canary scope and runtime preconditions with the first owner
   reservation. Never rearm or substitute the scope after a partial or uncertain result; reopen
   only through the exact durable row.
7. Run advisory comparison only. Legacy remains the response and stored-result authority. Archive-v3
   errors, latency, retries, or mismatches must not alter user-visible behavior.
8. Observe for the approved window. On any stop signal, cease the inactive launcher, preserve
   Control/witness/object evidence, keep legacy authoritative, and execute the signed rollback plan.
9. Retire the exact canary capture through the reviewed terminal path. Do not infer Phase-2
   permission from a successful Phase-1 result.

Phase-1 rollback never acknowledges from archive-v3, retries an ambiguous external attempt under a
new identity, deletes or enumerates archive objects through the WAL runtime, or destroys forensic
evidence. If exact state cannot be established, leave legacy authoritative and require manual
reconciliation.

## Phase-2 authority and eligible-archive rollout

Phase 2 requires a separate code review and a separate signed operator decision after Phase-1
evidence is complete. At minimum it must:

- replace the empty mutation set with a finite plan-level allowlist; unsupported semantics remain
  unconstructible;
- construct only the reviewed KMS/provider adapters for those plans and preserve stable B attempt
  identity, durable one-shot send, exact readback, definitive C rejection, and manual ambiguity;
- add a distinct owner-authority transition with durable restart ownership and prove there is no
  second Store/runtime;
- change Store/worker/route policy only so an operation is acknowledged after immutable WAL and
  witness settlement, never after a local SQLite commit alone;
- define sticky cohorts, entry/exit metrics, observation periods, concurrency limits, rollback
  windows, evidence retention, and per-step operator approval;
- repeat exact-image capacity, security, failure, recovery, lifecycle, and rollback evidence for
  the authoritative configuration, including uncertain provider response, checkpoint/compaction,
  export, deletion, schema migration, rollback/roll-forward, orphan retention, and forensic legacy
  reads.

A suggested cohort sequence is one explicitly selected archive, a small fixed cohort, successive
bounded cohorts, and finally all **tmpfs-eligible** users. Exact cohort sizes and dwell times are
operator policy and must be approved from observed evidence; this repository does not invent them.
Each increase is a new decision. Any permanent no-go signal returns the system to legacy authority
and blocks further expansion.

Phase 2 is not a true all-user solution: it excludes archives that cannot meet the strict tmpfs
bound. Large-archive authority requires the separately reviewed Phase-3/4 extent conversion and
cutover, and production-wide multi-node ownership/control scale requires Phase 5. “All users” can
be considered only after those later forward-only phases have their own implementation, evidence,
cohort policy, and explicit approvals.

## Permanent no-go and rollback signals

Stop or refuse activation if any path can:

- acknowledge before exact witness settlement;
- retry an ambiguous provider attempt under a new identity;
- infer definitive rejection from absence alone;
- enumerate or delete archive objects through the WAL runtime;
- select an older root after a later acknowledgement;
- run a second owner/runtime for the same archive;
- let shadow failure change a legacy response, latency contract, retry, or stored result;
- bypass exact image, runtime profile, trust-root, challenge, capacity, monitoring, rollback, or
  release-evidence binding; or
- broaden the Phase-1 empty mutation set or legacy-only acknowledgement.

## Authority handoff

The remaining work cannot be completed truthfully from repository state alone. Before any external
mutation, the operator must provide the exact release subject, public trust roots and custodians,
cloud/deployment targets, canary subject commitment, maintenance window, monitoring and rollback
policies, production evidence/drill receipts, and an explicit Phase-1 mutation authorization.

After Phase 1, enabling archive authority or expanding to tmpfs-eligible users requires another
explicit authorization naming the reviewed Phase-2 change, exact allowlist, cohorts, thresholds,
and rollback plan. Reaching all users additionally requires the Phase-3/4 large-archive and Phase-5
scale decisions. A request to “enable for all users” without those exact facts is direction, not
sufficient authority to bypass the gates above.

## Appendix: solo-operator rehearsal and cutover command sequence

Per the amendment, the operator executes these personally, in order, stopping on any refusal. All
signing is offline on the operator workstation; keys live under
`~/.local/state/kioku/adr0022-roots/` and never enter the repository, the VM, or any cloud
service. Every hex fact below comes from durable Control rows or the release record — never
invented, never reused across runs.

### A. Rehearsal (against a copy of the archive; serving untouched)

1. Freeze and build: tag the reviewed commit `vX.Y.Z-archive-v3-wal.N`, build the image with the
   activation config naming REHEARSAL coordinates (a copy bucket, the same registry KMS version, a
   rehearsal witness database), record the immutable image digest.
2. Copy the archive: snapshot the legacy user blob and control blob into the rehearsal bucket;
   bootstrap the rehearsal witness database from the emitter's plan.
3. Sign the window observation(s): `python3 scripts/phase1_sign_window_observation.py` with the
   rehearsal window facts; append `payload_hex:signature_hex` lines to the observations file.
4. Sign the Phase-1 authorization: `python3 scripts/phase1_sign_canary_authorization.py` with the
   canary scope, scope-bound user commitment, archive, operation, durable commitments, terminal
   witness hash, release image digest, and the admission facts; collect the six evidence files.
5. Run the canary on the VM: `--run-archive-v3-phase1-canary` with the run/window flags, the
   observations file, and the six evidence files. It must refuse on any mismatch; a completed run
   retires the advisory scope with full-parity evidence in Control.
6. Sign the Phase-2 authority (`python3 scripts/phase2_sign_authority.py`) over the settled
   terminal facts read from Control, acquire Phase-2 authority, and drive `run_phase2` to the
   durable `WalAuthoritative` terminal on the rehearsal copy.
7. Record the rehearsal receipt (digests of every evidence file, the terminal witness hash, and
   the Control row commitments) in the deployment record. Any refusal is a rehearsal finding to
   fix before the real window — never a reason to weaken a gate.

### B. Cutover (the approved downtime window; the operator stops serving themselves)

1. Announce/accept downtime; stop the serving replica; verify zero serving replicas.
2. Repeat A.3–A.6 against the PRODUCTION coordinates with fresh identities: production window
   observation, fresh Phase-1 authorization, canary run to the settled advisory terminal (full
   parity against the live archive), then Phase-2 authority, acquisition, and `run_phase2` to the
   durable `WalAuthoritative` terminal. The witness-lease succession waits out the settled
   advisory owner's TTL by design.
3. Apply the reviewed serving activation change (per-user persistence selection re-derivation and
   witness-settled acknowledgement wiring), roll the exact tagged image with
   `KIOKU_CONFIRM_ARCHIVE_V3_ROLL=<tag>`, and restart serving.
4. Verify: iOS and Mac sync end-to-end, acknowledgement latency, and the archive-v3 terminal
   facts in Control. On any failure execute the rollback policy: legacy remains recoverable for
   the 30-day window (the legacy blob is retained; WAL authority for the user is one durable
   selection that the rollback plan reverses only by restoring the legacy blob as a NEW reviewed
   decision, never silently).
5. Retain all evidence; schedule the legacy-retirement decision no earlier than the rollback
   window's expiry.
