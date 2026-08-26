# Local enclave release runbook

GitHub Actions is disabled. A push, merge, tag, or schedule does not build, scan,
publish, or deploy anything. GitHub remains the reviewed source, pull-request, signed-tag,
and immutable-release host. The operator runs the release pipeline on a designated
Linux/amd64 builder; do not repeatedly build the large image on an agent laptop.

The local commands reuse the reviewed build, test, image, SBOM, scan, and release checks
that previously lived in hosted workflows. They do **not** provide GitHub-hosted
provenance, CodeQL, dependency review, or an independently reproducible build. The build
evidence is instead a canonical record signed with an independently pinned Ed25519 key.

## One-time operator setup

- Use a clean, synchronized local `main`, a trusted signed-tag key, GitHub CLI access to
  push tags and create immutable releases, and a Linux/amd64 Docker builder.
- Install the pinned tools required by `scripts/local_image_pipeline.py`: Docker Buildx,
  Rust/Cargo, `cargo-audit`, Syft 1.49.0, Grype 0.116.0, Google Cloud CLI 580.0.0,
  Python 3, OpenSSL, Git, and GitHub CLI.
- Keep production build configuration outside the checkout in a regular, current-user-owned
  file with exact mode `0600`. It is `KEY=VALUE` data, never shell code; unknown keys,
  symlinks, unsafe permissions, and repository-resident files are rejected. Include the
  reviewed production build inputs plus `LOCAL_GCP_IMPERSONATE_SERVICE_ACCOUNT`, a
  push-only Artifact Registry identity distinct from the enclave runtime identity.
  All fixed ADR-0022 fresh release coordinates additionally require the same exact
  `PRODUCTION_ADR0022_CANARY_IDENTITY_PREPARATION_SHA256=<nonzero-lowercase-hex64>` and
  a sole lowercase UUIDv5 in `PRODUCTION_ADMIN_USER_IDS`; neither value is derived or
  read from a provider by this repository.
- Create a distinct Ed25519 build-evidence signing key outside either repository with
  exact mode `0600`. Independently publish and pin the SHA-256 fingerprint of its public
  DER key. Set `LOCAL_BUILD_EVIDENCE_PUBLIC_KEY` and
  `LOCAL_BUILD_EVIDENCE_PUBLIC_KEY_SHA256` for release/roll verification.
  `./scripts/local_build_evidence.py fingerprint --public-key /secure/keys/public.pem`
  prints that safe lowercase fingerprint without reading the private key.
- Authenticate `gcloud` as the reviewed human operator. The human may impersonate the
  push-only builder only for registry publication; no service-account JSON key is used.

The accepted native-builder baseline on 2026-08-15 completed the full test/audit/build/
SBOM/scan gate in 10m34s for the final cold cache-key seed and 5m04s on a
documentation-only cross-commit warm path. The temporary Git archive
transport normalizes member timestamps before BuildKit consumes it, while retaining the
original archive digest in evidence. The source commit time is likewise bound in signed
evidence rather than supplied as a global Docker build argument, so a documentation or
release-tooling commit does not invalidate byte-identical toolchain, model, dependency,
or application layers. Treat a
regression to uncached stable layers as a failed release-performance acceptance check.

For the one-time hosted-to-local migration, reconstruct the exact production values from
the immutable image currently pinned by deployment. This avoids guessing the former
GitHub secret values and never prints them:

```sh
./scripts/bootstrap_local_operator_config.py \
  --image us-central1-docker.pkg.dev/kioku-joerodriguez/kioku/kioku-enclave@sha256:CURRENT_DIGEST \
  --output ~/.config/kioku/enclave-production.env
```

The command uses a private, temporary registry login, validates the reconstructed values,
creates the parent directory privately, refuses overwrite, and writes exact mode 0600.

**That migration is complete, and this command is not a recovery path today.** It reads
the deployed image's `.Image.Config.Env`, but the reviewed configuration has since moved
out of image ENV into the baked `/kioku-config` file, so no image built by the current
`Dockerfile` carries `KIOKU_BUILD_PROFILE` there. The tool refuses any such image with
"the selected deployed image is not a production build", and no future deploy restores
it. **The local operator file is therefore the only copy of its values** — including
`PRODUCTION_REVIEWER_AUTH_API_KEY` and, as of the baked genesis gate,
`PRODUCTION_GENESIS_WAL_NATIVE`. Keep a backup outside this repository; losing the file
means reconstructing every secret it holds by hand.

## Verify, build, scan, and sign an image

First merge the reviewed version bump and required ADR-0016 classification. From clean,
synchronized `main`, create and verify a signed `vX.Y.Z` tag whose version matches
`Cargo.toml`. The tag must exist locally before producing release evidence.

Use a fresh, private evidence directory. The pipeline performs contract tests, the full
local Rust verification suite, dependency audit, Linux/amd64 image construction, SPDX SBOM
generation, and fixed-high Grype scan **before** requesting the short-lived registry
credential. `verify`, `build`, and `push` require `--apply`: verification creates local
Rust artifacts, while `push` additionally publishes the image.

```sh
# Read-only/full local release verification (no cloud credentials or image push)
./scripts/local_image_pipeline.py verify \
  --config /secure/kioku-production.env --apply

# Build, scan, resolve a digest, and push the exact signed tag
./scripts/local_image_pipeline.py push \
  --config /secure/kioku-production.env \
  --source-ref refs/tags/vX.Y.Z \
  --output-dir /secure/evidence/vX.Y.Z \
  --apply

# Sign the canonical local evidence; never add the private key to a repository.
./scripts/local_build_evidence.py sign \
  --manifest /secure/evidence/vX.Y.Z/enclave-local-build-evidence.json \
  --signature /secure/evidence/vX.Y.Z/enclave-local-build-evidence.sig \
  --private-key /secure/keys/kioku-local-build-ed25519.pem
```

The evidence directory contains the canonical evidence JSON and detached signature,
schema-9 or exact fresh-role schema-10 `enclave-release.json`, SPDX SBOM, and scan result. It binds the source tag and
commit, digest-qualified image, hashes of the build configuration/Dockerfile/Cargo lock,
release metadata/SBOM/scan, and tool versions. It contains hashes rather than configuration
values.

### Fixed ADR-0022 fresh release coordinates

The fresh BOOTSTRAP can be built and published only as
`v0.8.35-adr0022-fresh-bootstrap.1` from the checked version-0.8.35, schema-0/0/0,
archive-runtime-off, witness-probe-off, Genesis-off source. Version or attempt aliases,
evaluation selection, schema-9 metadata, incomplete canary inputs, and any fresh
bucket/KMS/runtime-SA/WIF/custom-role drift fail before publication.

For this one tag the producer emits an exact 50-field insertion-order compact JSON object
with one trailing LF. The signed evidence binds those raw bytes and the once-read private
configuration bytes. The provider-free cross-repository format pin is
`config/adr0022-fresh-schema10-bootstrap-fixture.json` (3,094 bytes; SHA-256
`40ce2530b9860133f69ac2d207c0f86165b6971b7207329ed7d09b3a4516e2a9`); its synthetic
commit, image digest, and canary values are not release evidence or provider authority.
Generic release roles continue to emit schema 9.

The separately reviewed FINAL source is reserved only as
`v0.8.35-archive-v3-wal.14`. It must retain the exact fresh namespace and canary
bindings, compile the reviewed additive ladder at 1/1/1, enable native Genesis,
carry the complete active archive runtime plus the live one-way binding
commitment, and pin the exact completed baseline-seal bytes. The BOOTSTRAP tree
intentionally carries an empty FINAL seal pin, so renaming a tag, flipping the
seal bit, or activating a config file cannot make it FINAL-eligible. FINAL
aliases and BOOTSTRAP/FINAL role crossing are rejected before publication.

The capture-latency successor is reserved only as
`v0.8.36-archive-v3-wal.15`. It retains FINAL.14's exact fresh namespace,
canary, active archive runtime, Genesis, schema 1/1/1, and completed baseline
seal bindings while requiring the checked Cargo/lockfile version 0.8.36. No
other 0.8.36 archive-v3 tag can claim this coordinate, and FINAL.14 remains
verifiable from its own signed source without becoming an alias for the new
image.

## Publish the immutable release

Review the release plan first. It checks the trusted source-tag signer, signed evidence,
schema-9 or exact fresh-role schema-10 production claims, bucket configuration, immutable registry digest, and exact
release assets before changing remote state.

```sh
# Dry run
RELEASE_SIGNER_FINGERPRINT=<trusted-source-tag-fingerprint> \
  ./scripts/release.sh vX.Y.Z \
  --evidence-dir /secure/evidence/vX.Y.Z \
  --config /secure/kioku-production.env \
  --repository joerodriguez/kioku-enclave

# Push the already signed tag and publish its immutable GitHub Release
RELEASE_SIGNER_FINGERPRINT=<trusted-source-tag-fingerprint> \
  ./scripts/release.sh vX.Y.Z \
  --evidence-dir /secure/evidence/vX.Y.Z \
  --config /secure/kioku-production.env \
  --repository joerodriguez/kioku-enclave \
  --apply
```

Publication refuses a missing or unknown tag signer, modified evidence, mismatched
source/config/image/SBOM/scan binding, mutable image reference, changed registry digest,
or a non-immutable existing release. It attaches exactly the signed evidence, signature,
release metadata, SBOM, and scan result; it does not replace an existing immutable release.
The publisher resolves the requested annotated tag once, requires its signed embedded tag
name and peeled commit to match, verifies the signer on that exact object ID, pushes that
object ID, and reads back both the remote tag object and peeled commit. Release assets are
copied once to a private read-only snapshot before verification; only those same snapshot
bytes are uploaded or compared on resume. Git replacement refs, legacy grafts, and ambient
repository/object/config overrides are rejected throughout these source boundaries.

`release.sh --roll` refuses every fixed fresh tag. Fresh rollout is owned only
by the deployment repository's source-frozen direct-provider operation, which
consumes the signed release plus the fresh provider and health evidence without
entering the legacy storage/KMS/VM rollout path.

## Roll the verified digest

Deployment is owned by the sibling Kioku monorepo and is always explicit. Its local
operation downloads the immutable release assets and verifies the evidence, tag, commit,
metadata, image URI, and digest before acquiring deployment credentials. Then it updates
the KMS digest binding, applies the exact saved Terraform plan, replaces the Confidential
Space VM, performs health/containment checks, and records a private local ledger.

The generic `enclave-roll` description and example below apply only to the
legacy/generic release workflow. They are not an ADR-0022 fresh rollout path;
all fixed fresh tags are rejected there and must use the deployment repository's
source-frozen direct-provider operation.

Either invoke it from the monorepo:

```sh
KIOKU_ENCLAVE_EVIDENCE_VERIFY=/path/to/kioku-enclave/scripts/verify_local_evidence_bundle.py \
  ./scripts/local-operations.sh enclave-roll \
  --release-tag vX.Y.Z \
  --image-uri us-central1-docker.pkg.dev/PROJECT/REPOSITORY/kioku-enclave@sha256:FULL_DIGEST \
  --digest sha256:FULL_DIGEST \
  --config /secure/kioku-production.env \
  --confirm "ROLL ENCLAVE sha256:FULL_DIGEST" \
  --apply
```

or add `--roll --deployment-repo /path/to/kioku` to the `release.sh --apply` command.
The direct command must pass the exact mode-0600 configuration used for the signed image.
For schema 10 the verifier derives and checks the fresh bucket and canary expectations from
those hash-bound bytes; schema 9 keeps its legacy deployment bucket defaults. The combined
`release.sh --roll` path passes its once-read mode-0600 configuration snapshot, not the
caller's mutable pathname.
The deployment checkout must be clean, synchronized `main`. Record the source commit,
image digest, rollout result, and live checks in the deployment record/`PROGRESS.md`; do not
record configuration values, credentials, plaintext, ciphertext, or user identifiers.

## Local cutover and ongoing checks

Production completed this cutover on 2026-08-13. The guarded sequence below remains the
audit/recovery reference for another environment; ordinary releases do not repeat it.

1. From the monorepo, bootstrap and verify the exact human-to-deployer and
   human-to-builder impersonation grants:

   ```sh
   ./scripts/local-operations.sh bootstrap-local-identities --apply \
     --confirm "BOOTSTRAP LOCAL DEPLOYMENT IDENTITIES"
   ```

2. Audit, then perform the Actions setting cutover from this checkout:

   ```sh
   ./scripts/disable_github_actions.py
   ./scripts/disable_github_actions.py --apply --confirm DISABLE-GITHUB-ACTIONS
   ```

3. Return to the monorepo and remove the now-unused GitHub OIDC provider and pool:

   ```sh
   ./scripts/local-operations.sh retire-actions-identities --apply \
     --confirm "RETIRE GITHUB ACTIONS IDENTITIES"
   ```

4. Review and apply the monorepo's local infrastructure plan so Terraform forgets the
   retired GitHub pool and bindings. Retain the deployer's pool-administration role:
   Terraform still manages the separate `enclave-attest` pool/provider used for
   Confidential Space admission. A fresh post-cutover plan must report no changes.

The setting cutover removes and verifies stale branch-protection status checks before
disabling Actions; active ruleset status checks must be reviewed and removed separately,
and an unreadable protection state fails before mutation. It does not weaken PR review, remaining
branch protections, signed tags, or immutable-release policy. For every mutation, verify the affected resource,
`https://api.kiokuu.com/health`, the live attestation digest, effective KMS containment,
and the relevant client flow.

## Rollback

Never retag or alter release evidence. To roll back, choose a previously verified immutable
release, run the monorepo `enclave-roll` command with its exact digest and typed
confirmation, then verify health, attestation, KMS containment, and user-visible behavior.
Terraform-only rollback is a reviewed revert followed by a fresh local saved-plan apply.
