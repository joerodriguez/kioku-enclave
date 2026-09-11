# Local enclave release runbook

The enclave is built, tested, scanned, signed, and published from reviewed local tooling. GitHub
hosts source and immutable releases; GitHub Actions does not build or deploy the image.

Production is PostgreSQL-authoritative. A release must not introduce a backend selector, fallback,
dual write, shadow read, database-in-GCS configuration, or migration from removed state.

## Operator prerequisites

Use a clean checkout of the newest `origin/main`. Keep all credentials, keys, evidence directories,
Docker/Buildx state, and operator configuration outside the repository with current-user-only
permissions.

Required local boundaries:

- a reviewed native Linux/amd64 BuildKit worker with the pinned transport/identity configuration;
- short-lived impersonation of the push-only Artifact Registry service account;
- an external Ed25519 build-evidence key and independently pinned public-key fingerprint;
- the reviewed source-tag signing key/fingerprint;
- a disposable PostgreSQL 17 database for the real contract suite;
- the separate deployment repository for Terraform plan/apply and ADR-0041 rollout receipts.

No service-account JSON key is accepted. `GOOGLE_APPLICATION_CREDENTIALS` must be unset.

## Select the image configuration

The external mode-0600 operator file contains shared build coordinates and complete `PRODUCTION_`
and `EVALUATION_` profiles. Production includes KMS, the live media bucket, workload/caller identity,
OAuth audiences, APNs identifiers, public origins, billing, reviewer, and Vertex values.

The selector fixes these serving invariants in reviewed source:

```text
POSTGRES_MAX_CONNECTIONS=12
HEALTH_PORT=8081
DRAIN_TIMEOUT_SECONDS=105
ENCLAVE_TLS=1
```

Serving verifies the required PostgreSQL schema unconditionally in code and never runs DDL. There
is no schema-mode input, structured-state backend, archive, witness, genesis, index-bucket, or
legacy-media input. Private provider keys, database credentials, shared TLS material, OAuth
secrets, and signing secrets remain runtime Secret Manager/database boundaries, not image-build
arguments.

Validate without writing an image:

```sh
python3 scripts/select_build_configuration.py \
  --profile production \
  --source-ref main
```

For first local-tool adoption, `bootstrap_local_operator_config.py` can extract the allowlisted
current values from one digest-qualified immutable deployed image into a new external mode-0600
file. It requires a local Unix-socket Docker context, uses a temporary
Artifact Registry login, and copies `/kioku-config` from a stopped, exact-ID temporary container.
It never starts the container or exposes values through image metadata or command output, and it
removes that container before returning. The embedded profile must be `production` and the current
selector must accept every mapped value. Review the resulting file privately and never commit it.

## Run the release gate

Provision a disposable PostgreSQL 17 database explicitly. The enclave scripts deliberately do not
assume Docker is available or start a database container silently.

```sh
export KIOKU_TEST_POSTGRES_URL='postgresql://…'

./scripts/agent-verify.sh full

python3 scripts/local_image_pipeline.py verify \
  --config /secure/kioku-operator.env \
  --profile production \
  --source-ref main \
  --apply
```

`agent-verify.sh full` fails before Cargo if the URL is absent or not a PostgreSQL URL and exports
`KIOKU_REQUIRE_POSTGRES_CONTRACT=1`; the Rust contract harness must fail rather than skip when that
signal is present. The full pipeline discovers every checked-in `scripts/test_*.py` and
`scripts/test_*.sh`, then runs locked Rust tests, all-target Clippy, and RustSec audit.

The real database contract must cover tenant isolation, concurrent claims, expired-lease takeover,
stale settlement refusal, provider ambiguity/no-resend, export, episode/account deletion,
no-resurrection, restart enumeration, full-text/vector/time-zone queries, and schema readiness.

Destroy the disposable database after the gate. Do not point the test suite at production.

## Build, scan, and push

Bump the crate version for a new standard release. `deploy_latest.py tag` derives exactly
`vMAJOR.MINOR.PATCH` from `Cargo.toml`; it does not invent a storage-backend suffix or sequence.

```sh
python3 scripts/deploy_latest.py tag

python3 scripts/deploy_latest.py pipeline build \
  --config /secure/kioku-operator.env \
  --output-dir /secure/kioku-release-vX.Y.Z \
  --tag-signing-key /secure/release-tag-key.pub \
  --apply

python3 scripts/deploy_latest.py pipeline push \
  --config /secure/kioku-operator.env \
  --output-dir /secure/kioku-release-vX.Y.Z \
  --tag-signing-key /secure/release-tag-key.pub \
  --apply --resume
```

The source must be clean and equal to `origin/main`; the tag must be a signed annotated tag peeling
to that source. The pipeline:

1. freezes and rechecks an immutable Git archive;
2. binds Cargo/source/config hashes into the build;
3. verifies the exact named Linux/amd64 worker before and after the build;
4. emits an OCI archive without loading a mutable daemon tag;
5. creates the SPDX SBOM and vulnerability scan before cloud authentication;
6. copies the scanned OCI bytes into a private unlinked read-only quarantine;
7. promotes only those bytes and verifies the registry digest;
8. emits canonical schema-13 release metadata and build evidence.

`build-evidence.json` is frozen after build and scan, before any cloud authentication. The
documented `push --resume` invocation reconstructs its build/scan timestamps from the immutable
stage receipts and validates the exact canonical bytes; it never adds the registry digest or
rewrites the summary. The digest is bound by the content-addressed push/final-evidence receipts and
`enclave-local-build-evidence.json`. After a push receipt exists, that output directory cannot be
resumed backward as a build.

The release metadata binds source/tag/image digest, the live media bucket, KMS coordinates,
PostgreSQL authority, required serving-schema verification, fleet connection budget, health/drain
values, shared TLS, explicit reconciliation model/location, compiled producer-contract SHA-256,
and the exact `2621440`-token per-account UTC-calendar-day Vertex output quota with non-borrowing
50/25/25 audio/screen/derived shares. Image assembly independently recomputes
that contract and rejects a supplied label mismatch. The schema-verification claim is a fixed source
invariant, not copied from operator configuration.
The exact v0.9.18 predecessor remains readable only through its frozen schema-12 state-verification
path. Schema 12 and earlier metadata are ineligible for new promotion.

## Permanently activate memory reconciliation

The normal first activation uses one ordinary signed release image and the existing release,
migration, and staged deployment processes. There is no separate activation binary or runtime flag.

After signed `Draining`, a reviewed source-compatible correction to audit/migration tooling may use
a newer ordinary signed release image for the dedicated migrator only. The operator must pin that
exact signed image separately for audit/backfill/activate/pause/resume, retain the original image for
install/drain, and preserve the signed candidate, serving fleet, KMS authority, model/location/producer
contract, and all readiness gates. Use only the reviewed migrator-only Terraform plan and saved-source
phase selectors for execution/recovery; no arbitrary image or SQL override is permitted. This exception
does not authorize a serving-runtime change within the current Draining cycle. See the deployment
repository's [activation contract](https://github.com/joerodriguez/kioku/blob/main/docs/adr/0043-source-settled-memory-reconciliation-and-durable-links.md).

The fixed read-only aggregate audit now emits `kioku.postdeploy.aggregate-audit.v6`. Its
`formation.stream_readiness` counts all streams in ended, finish-receipted sessions awaiting seal
finalization. It compares committed watermarks with the same accepted-maximum and contiguous-prefix
functions used by formation/sealing, and separately counts sealed-watermark disagreement and live-only
gaps bridged by genuine deletion tombstones. These are diagnostic counts, not replacements for any
readiness gate. They expose neither content nor identifiers and remain inside the ordinary
repeatable-read, read-only, rollback-only audit transaction. The v4 snapshot also independently
verifies the orphan-erasure catalog and distinguishes pending, complete-but-capture-fenced, and
fully restored states. Consumers must validate the exact image-selected shape; historical v2/v3
evidence is not v6 evidence and cannot authorize the new release's gates.

### Interrupted-capture recovery companion (source-only handoff)

This candidate requires the independently verified v29 provenance companion. The deployment
repository includes the standard `v29-interrupted-capture-install` operator phase and exact
result journal, but a later authorized release must pin its reviewed migrator image before
execution. See the [schema handoff](docs/postgresql-schema-releases.md). Installation preserves
the base markers and signed v27 history; predecessor binaries become unready because their
catalog verifier does not recognize the new constraint. Since ADR-0046 this is an ordinary
companion release: pin the migrator, run the phase, pin serving (see below). These merged
sources neither publish an image nor authorize installation, serving rollout, or client
distribution.

### Voice identity companion (ADR-0048 Phase 1)

Before candidate serving, a separately authorized release runs the digest-pinned migrator
with `POSTGRES_MIGRATION_CONFIRM=voice-identity-v30-install`. Verify `/readyz` after the
serving rollout, then use `voice-identity-cohort-set` with `VOICE_IDENTITY_COHORT=explicit`
and the owner's stable account UUID in `VOICE_IDENTITY_ACCOUNT_IDS`. Observe content-free
`voice_identity_v1` metrics before any cohort expansion. The default cohort is `none`.
Use `voice-identity-pause` and `voice-identity-resume` through that same migrator; these
operator phases are intentionally not the signed Pause described in ADR-0048 §8.1.
Each sweep reads the controls; an already claimed bounded batch may finish computing,
but settlement rechecks the controls and refuses a new binding after Pause commits.
See [the schema handoff](docs/postgresql-schema-releases.md) for exact input limits,
output shapes and immutable companion verification. No production operation is authorized
by merging the implementation source.

### Producer or model changes are ordinary releases (ADR-0046)

Since ADR-0046 the running reconciliation producer contract, model, and Vertex location are
the reviewed image's own. Serving registers its compiled producer at startup and every claim,
provider attempt, stage, and publication binds that registered producer; the signed activation
authority records the producer that was signed when reconciliation was activated as history and
keeps the signed Pause kill switch. A release that changes the producer therefore needs no
signed pause, drain, redrain, or activate transition and no fleet or client evidence: bump the
version, build with an operator configuration whose `MEMORY_RECONCILIATION_PRODUCER_CONTRACT_SHA256`
is the new compiled label (image assembly recomputes and refuses a mismatch), publish, and pin
the digest in the deployment repository. Serving still requires a verified `Active` or `Paused`
chain and an activation-capable image; `Draining` remains a migration phase. Staged provider
results carry the producer that produced them, so a producer change re-infers stale stages and
never publishes under a mismatched contract. The ADR-0045 compiled producer is
`sha256:0e3fadcbc33df882f72be1a31a3be411a76e5af0831a410a4284c803c550ed12`.

An additive schema companion (such as the ADR-0045 morning-email v28 install) is run by the
digest-pinned migrator before the serving pin, see
[the schema handoff](docs/postgresql-schema-releases.md); `/readyz` reports
`runtime_producer_contract_sha256` so an operator can confirm what a revision runs.

Two consequences to plan for:

- **Rollout overlap.** For the length of a Cloud Run rollout the predecessor and candidate
  revisions share the database while running different producers. The producer is part of the
  cohort fingerprint, so each revision keys the same cohort under its own job row and both may
  spend one provider attempt; the second publication is refused as a topology conflict and its
  row expires with its five-minute lease. Nothing is corrupted or published under the wrong
  contract. Keep the overlap short: let Cloud Run move traffic to the candidate and let the
  predecessor instances drain rather than keeping both revisions serving.
- **Pause and Resume.** The signed Pause and Resume transitions must preserve the producer,
  model, location, and candidate digest recorded by the prior signed Active event, which may be
  older than what the running image reports. Build the Resume receipt from the signed history,
  not from the candidate image. Letting Paused-to-Active carry the running producer is a
  possible later change; it is not required to pause or resume today.

### v0.9.31 Vertex schema correction from Paused/g4 (historical; bridge retired in v0.9.32)

The readiness bridge described below was pinned to package v0.9.31 and is **retired**. It is
kept as the worked example of what a producer-changing release used to require. Since
ADR-0046 serving admits a verified `Active` or `Paused` chain for any activation-capable
image and the running image's own model, location, and compiled producer contract are the
release authority (see above), so no such cycle is needed for a producer change.

**Draining is still a migration phase.** It is not schema-ready for serving, so a signed
Paused-to-Draining cycle (only ever needed for a scope change now) makes every serving replica
report `503` until the signed Active transition completes; treat that as a planned outage and
do not reintroduce a package-version allowance to serve through it.

Vertex rejected the nested reconciliation response schema with its outer `maxItems`
hint. The corrected producer omits only that hint; local validation still refuses more
than 32 outputs before staging/publication. A fixed synthetic same-model probe changed
from HTTP 400 to HTTP 200 with only this hint removed. Model, location, thinking settings,
quota and output validation are unchanged. The compiled producer is
`sha256:3a7a8d2d0f2a5e2045524f73822663d732ed31538792f1b2d9d7341a4f323225`.

The one-release readiness bridge requires package v0.9.31, that exact compiled producer,
verified v2 Paused/g4, the exact v0.9.30 image/producer, global scope, unchanged
model/location, and complete g2 ledgers. It grants no worker authority. This producer-changing
release uses the explicitly authorized existing incompatible-release maintenance lane:
separately reviewed fleet-drained plan and zero-runtime proof, then a separate sole-v31
restoration plan. Keep the database Paused and retain all v30 signed history; make no
zero-downtime claim. Fresh homogeneous v31 evidence plus the exact signed g4 predecessor authorizes
ordinary Paused-to-Draining/g5 with the new image/producer, then normal multipass g5
backfill and Draining-to-Active/g6 with adjacent Pause/g7. No epoch reinstall or DDL is
needed. The sole-owner operator may carry one due parked retry through those two edges,
but every other gate and final quiescence remain strict. Normal successful publication
retires the obsolete overlapping retry transactionally; never reset its attempt or
rewrite historical receipts. Both protected-control canaries remain required.

### v0.9.30 source-closed serving and dormant activation epoch

V6 preserves all raw v5 diagnostics and adds `source_graph`, derived by the exact
same account-qualified complete component query used by both runtime selection
lanes and every normal snapshot revalidation. Whole capture horizons, canonical
cross-session families and all five projection routes connect candidate drafts.
Unfinished sources hold their entire component; later independent settled components
remain reachable. The owner-prelaunch eligibility gate requires complete inventory,
no empty/conflicted/oversized candidate component, at most eight components per
account (the runtime sweep bound), and zero staged/processing/retry formation work.
All capacity, provider, quota, lease and other domain gates remain mandatory.
This is a point-in-time bounded reachability proof, not source completion or an
unbounded liveness promise. A later accumulation beyond eight held components
fails closed and requires fresh review; old v24 serving cannot consume v6 authority.

The previously frozen v1 Draining/g1 candidate must not be transiently activated
to change its serving image. The narrowly reviewed source-compatible ADR-0041
dormant rollout window instead permits exactly the signed predecessor/candidate
pair while Draining (or Paused), preserving schema/API, model, location, producer
and all runtime admission fences. Its reviewed source/plan and exact KMS pair
authorize that bounded deployment; historical g1 remains an observation of the
old image, never a claim that it attests the new fleet. This exception is not
available while Active. Install the neutral signed orphan-erasure schema before
starting v0.9.30 serving; install alone fences/deletes no owner capture.

After standard freezing/preauthorization/rolling/retiring/steady, fresh continuous
readiness and homogeneous sole-candidate proof, use the ordinary no-retry migrator
with `memory-reconciliation-v27-epoch-preview`. It runs only the baked one-time
DDL under the release lock, verifies the unchanged v1 catalog subset, rolls back
the whole transaction, and re-reads the original state using a separately held
physical PostgreSQL connection. The content-free proposal binds old receipt,
contract/catalog/image, new contract/catalog, base receipt and DDL/query hashes.
It changes no activation event, owner data or durable schema.

The separately signed canonical v2 receipt for
`memory-reconciliation-v27-upgrade-epoch` authorizes only Draining/g1 to Draining/g2,
binds that proposal and the newly observed homogeneous signed fleet, and preserves
the exact old scope/seed/model/location/producer. It atomically appends an immutable
epoch authority and matching event while retaining the original contract row and
historical bytes. No `UPDATE` of history, arbitrary SQL or unsigned phase override
is allowed. Complete the normal generation-2 backfill/claim drain, collect fresh
v6/client/fleet roots plus a finalized/nonselectable protected-control proof, then
sign ordinary v2 Active/g3 and its adjacent contingency Pause. This image's CLI
refuses legacy v1 receipts for both Draining-to-Active and Paused-to-Active. The internal transition repository
is deliberately not exposed to serving routes. Exact historical g2 repair remains
available but is not an epoch replay or a transition. Pass immediate and quiescent
protected-control canaries before declaring activation complete.

### v0.9.28 erasure-admission prerequisite

This release requires the independent orphan-erasure admission schema before any serving member
starts or the migrator authorizes Active. The signed erasure installer requires an existing verified
v27 **Draining** predecessor; it is not part of the unsigned v27 bootstrap. Therefore do not use
the first-activation sequence below to roll v0.9.28 into an erasure-absent Installed database.
For the existing owner-prelaunch Draining rollout, install the new signed image on the dedicated
migration job first, preserve the current serving/KMS/candidate identity, then use the reviewed
[scoped erasure procedure](docs/orphan-capture-erasure.md). Its signed install creates no capture
fence or deletion by itself. Prepare is separately signed and must wait until the full cleanup and
later new-runtime Active/fence-release delivery path is verified and ready. The serving rollout
occurs only in the documented Paused window, with permanent erased-identity barriers retained.

### Initial activation with a bootstrap-compatible predecessor

1. Build, verify, sign, and publish the normal immutable release. Its schema-13 evidence must bind
   the exact reconciliation model, Vertex location, compiled producer digest, and reviewed Vertex
   output quota/reset/share policy. Do not roll it
   yet; first audit `episode_deletions` while the predecessor fleet still serves schema 26. Finish
   every `pending` receipt. The v27 install also refuses a `complete` v26 receipt whose
   `orphan_event_ids` array is nonempty: v26 did not retain the deleted event's stream, sequence,
   and manifest-digest coordinates. Diagnose both blockers without content using:

   ```sql
   SELECT account_id,episode_id,state
     FROM episode_deletions
    WHERE state='pending'
       OR (state='complete' AND jsonb_array_length(orphan_event_ids)>0)
    ORDER BY account_id,episode_id;
   ```

   A pending receipt may be resumed normally. For a completed blocker, restore/reconstruct the exact
   coordinates from an authoritative backup under a separately reviewed remediation, or remain
   inactive. Never invent tombstones or lower a committed stream watermark. Once the query is
   empty, run this release image through the standard dedicated migration job with
   `POSTGRES_MIGRATION_CONFIRM=memory-reconciliation-v27-install`. Repeat
   `memory-reconciliation-v27-backfill` until the content-free result status is
   `backfill_complete` (not merely `formation_backfill_complete=true`). Installed backfill also
   repairs at most 256 expired terminal media ownership rows per call, in one account with no
   unfinished media, live media deadline, or started provider intent. It holds the activation and
   account-lifecycle fences, requires a 15-minute unchanged-row age, and clears only ownership
   markers; states, timestamps, provider journals/outcomes, quotas/reservations, and content remain
   untouched. A following no-op pass establishes repair completion. It never requeues work or
   claims provider quiescence: the independent raw-authority audit still rejects every remaining
   live, contradictory, or otherwise ineligible residual. No new schema or alternate repair
   binary is installed. The durable phase is now `Installed`, marker 26 remains visible, and the
   predecessor stays schema-compatible throughout this step.

   Raising the immutable quota does not rewrite or wake existing `vertex_daily_budget` retries;
   their already-persisted retry timestamp remains authoritative (normally up to six hours). Wait
   for those jobs to become due and be reclaimed through the normal worker path. Before advancing
   to `Active`, perform a content-free live audit proving no material pre-egress/not-billed retry
   amplification and enough remaining non-borrowing Derived slots for the activation backlog.

   The fixed audit projects the same active, unfinalized draft universe as the reconciler,
   including `substance=none` drafts. It reserves one reconciliation call per candidate draft, an upper
   bound on component count even if deletion separates a connected group. Successor-finalization
   capacity is `sum(max(1, canonical owned atoms per draft)) + account-unowned atoms`, with the
   unowned pool added only when that account has a candidate draft. Per-component caps/floors are
   insufficient when deletion splits a group; the per-draft bound remains conservative across those
   partitions and source-less KEEP outputs. The pool covers every possible
   source-session expansion without charging the same atom to multiple successful publications:
   serializable publication, the account lock, source revalidation, and unique active ownership prevent
   reuse. Nonempty disjoint partitions enforce the atom bound for both model results and conservative
   partitions. Draft count alone is not an output bound. The individual source-less draft floors cover the
   distinct providerless oversized KEEP path, which retains one existing output per draft even when
   a session-count bound triggers with empty members. Existing reconciled finalizers are
   charged separately. The 65-slot minimum reserve, 80-slot daily derived allowance, other class
   headroom, oversized-component refusal, and every quiescence gate remain unchanged. A tighter
   projection is not proof that a particular production backlog is ready; fresh signed-image audit
   evidence must still pass every gate.

   The installer serializes with every v27-capable writer using the exclusive activation release
   advisory lock before it probes or creates objects, and also locks `episode_deletions` before the
   legacy-receipt checks. Writers take the shared counterpart before their absence probe. Do not
   replace either fence with an operator-side quiet-period assumption.
2. Roll the same release image through the standard zero-unavailable staged deployment while the
   durable phase remains `Installed`. Prove every serving member is ready, homogeneous on the exact
   immutable digest, and no predecessor workload or KMS admission remains. The image is
   activation-capable but cannot claim, disclose, stage, or publish reconciliation work in this
   phase; legacy finalization remains available during this compatibility window.
3. Supply the strict canonical signed receipt and detached signature only to the execution-scoped
   migrator environment as `POSTGRES_MIGRATION_ACTIVATION_RECEIPT` and
   `POSTGRES_MIGRATION_ACTIVATION_SIGNATURE`. The receipt bytes include exactly one trailing LF.
   Run `memory-reconciliation-v27-drain`; the receipt must prove predecessor and unavailable counts
   are zero and the candidate fleet is nonempty and homogeneous. PostgreSQL durably records its
   exact image digest; `draining -> active`, `active -> paused`, and `paused -> active` receipts
   must preserve it. PostgreSQL attaches all six
   exact finalization, pending-owner, paged-deletion, media-work, and formation-claim guards in
   this transaction while marker 26 remains visible, then initializes resumable source-refresh and
   legacy-claim-drain ledgers.
4. Repeat `memory-reconciliation-v27-backfill` until its status is `backfill_complete`, not merely
   both generation-bound ledger flags being true. After those ledgers complete, each call assigns
   at most 256 active accounts from the verified signed Draining scope, including empty accounts.
   A subsequent empty pass proves completion. The release, lifecycle, and reconciliation fences
   serialize assignment with deletion and preserve all existing sticky assignments. This metadata
   operation never requires provider/finalization work or modifies memories.
   A runtime is unready in `Draining` whatever its producer (ADR-0046 admits any
   activation-capable image only from a verified `Active` or `Paused` chain), and the frozen
   predecessor verifier refuses the added guards.
   An episode-finalization request already authorized before the transition may finish HTTP and its
   terminal usage write while Draining waits on the database fence. The subsequent bounded claim
   drain may discard that paid result before parsing; the stale claim must fail settlement and the
   assigned draft must never enter the legacy finalizer again.
5. With a fresh `draining -> active` receipt, run `memory-reconciliation-v27-activate`. PostgreSQL
   rechecks zero scoped draft claims and complete ledgers, persists the signed generation, and
   advances marker 27 atomically. Repository authority dynamically enables egress only after this
   commit.
6. For a kill switch, use a fresh signed `active -> paused` receipt and
   `memory-reconciliation-v27-pause`. Pause remains operable with truthful unavailable-fleet
   evidence, but every assigned or historically selected account stays reconciliation-only. Resume
   requires an unchanged signed scope/producer, or use `paused -> draining` for a monotonic scope or
   producer expansion and freshly proved homogeneous candidate digest before a later
   `draining -> active`.

### Repair an already committed Draining scope

If an earlier signed serving image completed the Draining ledgers without materializing global
scope, use the ordinary reviewed release image and dedicated migrator with the explicit
`POSTGRES_MIGRATION_CONFIRM=memory-reconciliation-v27-repair-draining` phase. Pass the exact original
already-applied Draining receipt and signature in the same execution-scoped activation variables.
The migrator verifies their canonical signature and matches the complete committed event, signer,
generation, scope, catalog, base receipt, image and producer identity under the exclusive release
lock. Receipt expiration is historical here only: this operation cannot append an event, change a
marker, expand scope, activate, or authorize a new transition. Both current-generation ledgers must
already be complete. Repeat bounded calls until `draining_scope_repair_complete`; the distinct
repair statuses are not ordinary activation backfill evidence.

A migrator-only repair image must be separately pinned and reviewed by the standard deployment
owner. Keep serving/KMS admission and the signed Draining candidate unchanged. Retain genuine
operation/image/source-bound repair journals, restore the original migrator through the reviewed
deployment path, then collect new original-image backfill, audit, fleet and client evidence before
activation. Do not substitute the repair result for an activation root or replay a signed Drain.

Never persist activation receipts or signatures in Terraform, image metadata, or a release
artifact. Status and health output remain content-free; retain the exact signed receipt, detached
signature, fleet evidence, migration result, and immutable image evidence in the existing release
audit boundary. Run every phase through the standard release/migration/deployment procedure; do not
introduce an activation-only deployment operator.

Sign or verify the canonical evidence:

```sh
python3 scripts/local_build_evidence.py sign \
  --manifest /secure/kioku-release-vX.Y.Z/enclave-local-build-evidence.json \
  --signature /secure/kioku-release-vX.Y.Z/enclave-local-build-evidence.sig \
  --private-key /secure/kioku-build-evidence-private.pem

python3 scripts/local_build_evidence.py verify \
  --manifest /secure/kioku-release-vX.Y.Z/enclave-local-build-evidence.json \
  --signature /secure/kioku-release-vX.Y.Z/enclave-local-build-evidence.sig \
  --public-key /secure/kioku-build-evidence-public.pem \
  --expected-public-key-sha256 <pinned-fingerprint>
```

## Publish the immutable release

Set the independently pinned tag/evidence key fingerprints, then dry-run:

```sh
scripts/release.sh vX.Y.Z \
  --evidence-dir /secure/kioku-release-vX.Y.Z \
  --config /secure/kioku-operator.env \
  --repository joerodriguez/kioku-enclave
```

Apply only after reviewing the exact tag, commit, digest, configuration hash, SBOM, scan, and
evidence-key identity:

```sh
scripts/release.sh vX.Y.Z \
  --evidence-dir /secure/kioku-release-vX.Y.Z \
  --config /secure/kioku-operator.env \
  --repository joerodriguez/kioku-enclave \
  --apply
```

Publication snapshots all five release assets to read-only files before verification, pushes the
captured signed tag object rather than re-resolving a mutable name, checks the remote object and
peeled commit, confirms the registry digest, and publishes an immutable GitHub release. Resume is
accepted only when every existing asset is byte-identical.

## PostgreSQL schema changes

Schema migrations are append-only and are not run by serving members. For a runtime requiring a new
schema:

1. merge the application and migration after real PostgreSQL contract review;
2. publish one digest used by both the serving image and dedicated migrator image;
3. update the digest-pinned one-shot migrator in the deployment repository;
4. apply the reviewed schema stage while the currently serving image remains compatible;
5. execute the migrator exactly once under its bounded database role;
6. independently verify the expected migration version before admitting the candidate runtime.

Do not add data backfill or removed-backend migration machinery. There is no legacy user data to
preserve.

## ADR-0041 compatible fleet rollout

Ordinary compatible releases use the deployment repository's staged Terraform owner, not
`release.sh --roll`:

1. Capture a clean saved plan that changes only the reviewed candidate digest/KMS admission and
   intended fleet resources.
2. Admit at most the exact predecessor/candidate digest pair to KMS.
3. Start the independent public availability monitor.
4. Add the candidate as a canary and require PostgreSQL schema readiness, shared TLS readiness, and
   exact image/KMS/backend readback.
5. Replace members with `max_unavailable=0`; maintain at least two ready zonal members.
6. Exercise authenticated capture, search, export, deletion/restart, and content-free provider
   no-op/effect probes through the public service. Account deletion must use a dedicated disposable
   identity. The persistent plugin reviewer may run login/MCP/read canaries, but its token must
   never be reused for `DELETE /api/account`.
7. Require homogeneous candidate membership before retiring the predecessor digest.
8. Retire predecessor KMS admission and verify no old member remains.
9. Capture a final Terraform plan showing no changes.

Record exact source commit, signed tag, image digest, KMS principals/condition, PostgreSQL authority
and schema, member names/zones/digests, readiness/liveness, monitor receipt, effect-safety probes,
and final no-change plan.

### Recover plugin-review access

When the OpenAI submission portal already reports the production domain as verified, a `404` from
a previously used domain-challenge path is not an active review blocker. Do not add or restore a
challenge endpoint solely to recover reviewer access; repeat domain verification only if the portal
no longer reports the domain as verified.

Treat a rejected, non-editable submission as immutable. Complete all of these gates before
resubmitting:

1. Release and deploy a replacement reviewer identity and configuration; do not reuse a tombstoned
   reviewer subject.
2. Prove the replacement account can complete the production reviewer login and has an active,
   deletion-protected fixture.
3. Create a new submission draft, or obtain an editable revision of the rejected submission, while
   preserving the live MCP, OAuth, and dynamic client-registration fields.
4. Run **Scan Tools** against the deployed service so the editable submission receives a fresh
   dynamic OAuth client registration rather than a client lost during a database cutover.
5. Update the portal's testing-credential fields to the replacement reviewer identity. Keep the
   password only in the portal and the approved credential store; never record it in source,
   release evidence, logs, tickets, or this runbook.
6. From the editable submission, complete the full reviewer path: credential sign-in, PKCE
   authorization-code exchange, MCP connection, tool discovery, a read-only tool call, and refresh.
   Resubmit only after every step succeeds against the exact production release.

## Incompatible maintenance rollout

`release.sh --roll` is retained only for a reviewed change that cannot safely overlap predecessor
and candidate. It invokes the deployment repository's explicit scale-to-zero maintenance lane with
the exact digest confirmation. This is not a rollback to removed state and must never be used as a
shortcut around ADR-0041 compatibility qualification.

The maintenance lane also requires the deployment checkout to match the exact commit, Terraform
root-source inventory, and content digest compiled into `verify_push_runtime_topology.py`. A local
`origin/main` ref is not a review authority. When a deployment change must become eligible, merge
and review that repository first, then use a separate enclave commit/PR to update all three pin
coordinates from the immutable merged commit; until that second change lands, rollout fails closed.

## Rollback

After PostgreSQL has accepted a write, rollback means a schema-compatible predecessor application
image or PostgreSQL restore/roll-forward. It never means selecting SQLite, reading a database from
GCS, or starting a removed archive runtime.

During a compatible rollout, rollback may return traffic to the still-admitted predecessor only
while its schema remains compatible and before its KMS admission is retired. After retirement,
re-admission is a new reviewed saved plan with the same availability and readback checks.

## Dynamic brief sections companion (v29)

The candidate requires a nullable JSONB `episode_final_briefs.sections` column and its
receipted check constraint. Before serving this source, use the reviewed digest-pinned
PostgreSQL migrator with the exact confirmation `brief-sections-v29-install`.
This is an additive companion: it does not change the frozen v26/v27 markers, receipts,
activation state, existing brief rows, or finalization version. Serving/readiness only
verify the installed contract and never execute DDL. Installation takes a bounded lock,
rejects an unreceipted preexisting column, and is idempotent only for the exact receipt.
The implementation PR performs no production migration/publication/deployment. Coordinate
website publication and iOS distribution in the separately authorized release session;
existing briefs retain legacy grouping until an explicit regeneration.

This additive schema is a **finalizer writer compatibility boundary**, not an unrestricted
rolling/rollback contract. Quiesce and drain predecessor finalization claims, install
v29 with the reviewed migrator, and cut over homogeneously before allowing dynamic brief
writes. Predecessor workers must not resume afterward: a legitimate identity-triggered
refinalization by old code can update legacy fields while retaining stale sections.
After any dynamic write, rollback requires a sections-aware predecessor or a separately
reviewed compatibility repair that clears/fences sections while finalizers remain stopped.
Do not infer rollback safety from the unchanged base/activation catalog receipts.
