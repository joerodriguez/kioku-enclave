# ADR-0022 production activation runbook

Status: **NO-GO**. The reviewed inactive protocol boundaries are locally complete, but activation
integration, operational evidence, and authority are absent. This runbook records the exact
decisions and evidence required; it does not grant permission to publish, deploy, mutate cloud
resources, change Store policy, or affect production users.

The rollout has two separate authorization boundaries:

1. **Phase 1: one advisory canary.** Legacy remains authoritative. Archive-v3 may observe and
   compare one exact user/archive, but its authoritative mutation set is cryptographically empty
   and it cannot change acknowledgements.
2. **Phase 2: explicitly allowlisted archive authority for tmpfs-eligible archives.** Only a later
   reviewed change may enable named mutation plans, provider adapters, witness-backed
   acknowledgements, and a gradual eligible-archive rollout. Phase-1 approval never implies
   Phase-2 or all-user approval.

Phases 3–6 from ADR-0022 remain later forward-only decisions and are outside this runbook.

## Current hard stops

The checked-in facts deliberately make activation impossible:

- `config/archive-v3-shadow-runtime.json` is exact `off` with every deployment coordinate empty.
- The operator, image-attestation, and deployment-observer public roots are all invalid zero roots;
  no production assertion can verify.
- No live Confidential Space claim/nonce verifier, fresh deployment-state observer, or launcher
  holds the maintenance-window and zero-serving condition across import, handoff, and owner
  admission.
- `release.sh --roll` rejects an active archive-v3 image until a separately reviewed deployment-
  compatibility change exists.
- The checked-in capacity policy is an intentionally unusable template. The offline verifier always
  returns `authority: false` and cannot authenticate or consume a production challenge.
- No production-shaped restart, uncertain-response, checkpoint/compaction, export, deletion,
  schema-migration, rollback/roll-forward, orphan-retention, and forensic-read drill receipt exists
  for an exact release image.
- No production caller constructs the runtime, importer, owner, provider adapters, Store policy, or
  acknowledgement transition.
- No production controller can acquire and retain the fresh zero-serving/window observation,
  construct the importer and exact Store target, issue the trust proof, and restart-safely drive the
  one-shot scope through advisory-owner retirement. The existing deployment canary command
  deliberately dies rather than becoming production orchestration.
- This checkout contains no reviewed archive GCS/registry-KMS/authoritative-witness provisioning,
  adoption, backup, or restore plan. The checked witness deployment profile is transport-probe-only,
  default-off, and does not create the authoritative named database.
- Existing `/health` and VM-uptime monitoring are legacy/generic signals, not archive-v3 canary
  telemetry. There are no deployed comparison, owner, witness, resource, or automatic rollback
  alerts for this path.

These are independent safety barriers, not a checklist that can be bypassed by one broad approval.

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
