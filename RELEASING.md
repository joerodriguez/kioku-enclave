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
8. emits canonical schema-12 release metadata and build evidence.

`build-evidence.json` is frozen after build and scan, before any cloud authentication. The
documented `push --resume` invocation reconstructs its build/scan timestamps from the immutable
stage receipts and validates the exact canonical bytes; it never adds the registry digest or
rewrites the summary. The digest is bound by the content-addressed push/final-evidence receipts and
`enclave-local-build-evidence.json`. After a push receipt exists, that output directory cannot be
resumed backward as a build.

The release metadata binds source/tag/image digest, the live media bucket, KMS coordinates,
PostgreSQL authority, required serving-schema verification, fleet connection budget, health/drain
values, shared TLS, explicit reconciliation model/location, and compiled producer-contract SHA-256. Image assembly independently recomputes
that contract and rejects a supplied label mismatch. The schema-verification claim is a fixed source
invariant, not copied from operator configuration.
Earlier metadata that described removed storage authority is ineligible for new promotion.

## Permanently activate memory reconciliation

Use one ordinary signed release image and the existing release, migration, and staged deployment
processes. There is no activation-specific Python/Terraform operator, second tag, alternate binary,
or runtime feature flag.

1. Build, verify, sign, and publish the normal immutable release. Its schema-12 evidence must bind
   the exact reconciliation model, Vertex location, and compiled producer digest. Do not roll it
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
   `memory-reconciliation-v27-backfill` until the content-free result reports the bounded formation
   backfill complete. The durable phase is now `Installed`, marker 26 remains visible, and the
   predecessor stays schema-compatible throughout this step.

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
4. Repeat `memory-reconciliation-v27-backfill` until both generation-bound ledgers are complete.
   A runtime whose model/location/producer does not match the signed authority is unready from
   `Draining` onward, and the frozen predecessor verifier refuses the added guards.
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
