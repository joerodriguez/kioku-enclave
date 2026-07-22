# Releasing the open-source Kioku enclave

A production image must be traceable to signed public source and a content-addressable
image digest. A release therefore includes a signed Git tag, immutable GitHub Release,
validated image metadata, GitHub-signed build provenance, an SPDX SBOM, and a signed SBOM
attestation. The image digest is the value authorized by the deployment's KMS
attestation condition.

## Prerequisites

- Work on a clean `main` synchronized with `origin/main`.
- Set the package version in `Cargo.toml`; the release tag must be exactly
  `v<Cargo package version>`.
- Install Rust/Cargo, Git, Python 3, the Google Cloud CLI, a current GitHub CLI
  with `gh attestation verify` and `gh release verify`, and the tools required
  by your Git signing setup.
- Configure a Git signing key. `scripts/release.sh` creates `git tag -s` tags and rejects
  a tag that cannot be verified against the required `RELEASE_SIGNER_FINGERPRINT`
  trust anchor (an OpenPGP fingerprint or `SHA256:…` SSH key fingerprint).
- Publish the trusted signing public key and fingerprint through a separately authenticated
  channel, and require release verifiers to pin that identity. A cryptographically valid
  signature from an unknown key does not authenticate the release operator.
- Authenticate `gh` with permission to push tags, publish releases in this source
  repository, read Actions artifacts/attestations, and—only when using `--roll`—dispatch
  the operator's deployment workflow.
- Authenticate `gcloud` with read-only access to the configured Artifact Registry
  repository. OCI attestation verification resolves the image manifest even when the
  signed bundle is local; the script configures the standard Docker credential helper
  and fails before tagging if the repository is not readable. Writer, deploy, IAM,
  Secret Manager, and KMS permissions are unnecessary.
- When using `--roll`, set `DEPLOYMENT_REPO=owner/repository`.
- Enable GitHub immutable releases. The release script requires the setting, uploads all
  assets while a release is still a draft, and confirms GitHub made the published release
  immutable before it can request a roll.

## Required repository variables

The public build validates these non-secret GitHub Actions variables before Docker runs:

| Group | Variables |
|---|---|
| Keyless image push | `GCP_WIF_PROVIDER`, `GCP_SERVICE_ACCOUNT` |
| Artifact Registry destination | `GCP_PROJECT_ID`, `GCP_REGION`, `AR_REPOSITORY`, `IMAGE_NAME` |
| KMS/GCS and legacy caller | `ENCLAVE_KMS_PROJECT`, `ENCLAVE_KMS_LOCATION`, `ENCLAVE_KMS_KEY_RING`, `ENCLAVE_KMS_KEY`, `ENCLAVE_GCS_BUCKET`, `ENCLAVE_RUN_SA_EMAIL`, `ENCLAVE_AUDIENCE` |
| Internal KMS attestation exchange | `ENCLAVE_ATTEST_STS_AUDIENCE` |
| OAuth and origins | `GOOGLE_DESKTOP_CLIENT_ID`, `GOOGLE_WEB_CLIENT_ID`, `BASE_URL`, `WEB_ORIGIN` |
| Vertex | `VERTEX_PROJECT`, `VERTEX_LOCATION`, `VERTEX_MODEL` |
| Production TLS | `ENCLAVE_ACME`, `ENCLAVE_ACME_DIRECTORY` |

Set them in GitHub Settings → Secrets and variables → Actions or with
`gh variable set`. The workflow maps the `ENCLAVE_*` repository-variable names to the
Docker build arguments documented in [`README.md`](README.md#build).

Store `ALLOWED_EMAILS` and `ENCLAVE_ACME_CONTACT` as repository **Actions secrets**, not
variables. They are build-time configuration rather than credentials, but masking them
prevents account and contact addresses from being copied into public Actions logs. The
resulting values remain baked into the image, so they must not contain authentication
secrets.

Production requirements are fail-closed:

- `BASE_URL` and `WEB_ORIGIN` must be HTTPS origins; legacy `ENCLAVE_AUDIENCE` must match
  the caller's ID-token `aud` exactly and should normally be the public HTTPS API URL;
- `ALLOWED_EMAILS` must be nonempty and must not be `*`;
- `ENCLAVE_ACME` must be `1`; and
- `ENCLAVE_ATTEST_STS_AUDIENCE` is an internal WIF provider resource, never the audience
  of the public `/v1/attestation` token.

Repository variables may appear in public logs. Do not put
credentials, OAuth client secrets, JWT secrets, TLS private keys, or other secret values
in them. The web OAuth secret comes from Secret Manager and JWT secrets live in the
KMS-protected control database.

The GitHub-to-GCP WIF provider is itself part of the release boundary. Map and constrain
immutable GitHub OIDC claims such as `repository_id` and `repository_owner_id`, require
the `build.yml` workflow identity, and allow only `refs/heads/main` or protected `v*`
release tags. Do not trust only a mutable repository name. Bind the push-only service
account to that constrained principal and grant it only Artifact Registry write access.
The workflow independently refuses to run its credentialed job for any other ref.

## Public-repository security gate

Before the first release from a newly public repository:

1. scan the complete Git object graph and reachable history for secrets, not only the
   checkout;
2. review Actions variables, artifacts, caches, summaries, and logs for credentials or
   privacy-sensitive values;
3. confirm `LICENSE`, `SECURITY.md`, contribution guidance, and the private vulnerability
   contact;
4. enable branch protection, required CI/security checks, tag protection, secret
   scanning, push protection, and immutable releases;
5. verify the GitHub OIDC provider's immutable repository/workflow/ref condition and
   least-privilege Artifact Registry writer binding; and
6. verify that GitHub reports the repository as public.

```sh
gh repo view joerodriguez/kioku-enclave --json visibility --jq .visibility
# expected: PUBLIC
```

Do not report a discovered vulnerability in a public issue. Follow
[`SECURITY.md`](SECURITY.md#reporting-vulnerabilities).

## Publish a release

Choose a SemVer version, update `Cargo.toml`, and run:

```sh
RELEASE_SIGNER_FINGERPRINT=<trusted-key-fingerprint> \
  ./scripts/release.sh vX.Y.Z
```

The script and workflow then:

1. verify clean, synchronized public `main` and all required repository variables;
2. require the tag version to match the Cargo package version;
3. run `cargo fmt --all -- --check`, locked tests, and clippy with warnings denied;
4. create, verify against `RELEASE_SIGNER_FINGERPRINT`, and push a signed source tag;
5. run CI and build with full-SHA-pinned Actions, a digest-pinned Rust builder, and a
   revision- and hash-pinned embedding model;
6. push the image to the configured
   `<region>-docker.pkg.dev/<project>/<repository>/<image>:<tag>` destination;
7. generate an SPDX SBOM, fail on fixed high-severity image findings, and create
   GitHub-signed image-provenance and SBOM attestations;
8. validate the source repository/ref/commit, build URL, configured image repository,
   digest, provenance signer workflow, and exact equality between the standalone SBOM
   and the verified SBOM-attestation predicate; and
9. create a draft, attach `enclave-release.json`,
   `enclave-provenance.jsonl`, `enclave-sbom.spdx.json`, and
   `enclave-sbom-attestation.jsonl`, publish it, and verify GitHub's immutable-release
   attestation.

If a prior invocation left a draft, the script repairs only the four expected assets and
rejects unexpected ones before publication. If a public release already exists, the
script requires GitHub to report it as immutable and does not edit or clobber it.
Investigate a mismatch; do not delete and recreate provenance to make verification pass.

Publishing creates a verified public release; it does not change production. An operator
may then use `--roll` with an explicitly configured `DEPLOYMENT_REPO` to request that
repository's separate, approval-gated deployment workflow.

## Verify the release before deployment

At minimum:

```sh
git tag -v vX.Y.Z

gh release verify vX.Y.Z --repo joerodriguez/kioku-enclave

gh release download vX.Y.Z \
  --repo joerodriguez/kioku-enclave \
  --pattern 'enclave-*.json*'
```

Check that:

- `enclave-release.json` names this repository, tag, signed-tag commit, build URL, and the
  expected digest-qualified Artifact Registry repository;
- `gh attestation verify` accepts the image provenance for this repository's
  `.github/workflows/build.yml`, tag, and commit;
- the SPDX SBOM is present and its signed attestation verifies for the same image digest;
- CI, CodeQL, dependency review/audit, and image scanning succeeded; and
- release notes make no independent-reproducibility claim.

`scripts/release.sh` performs the machine-verifiable provenance checks before it can
request a roll. An operator should still review the evidence and changed source.

## Roll production

After verification:

```sh
DEPLOYMENT_REPO=owner/deployment-repository \
RELEASE_SIGNER_FINGERPRINT=<trusted-key-fingerprint> \
  ./scripts/release.sh vX.Y.Z --roll
```

The script re-verifies the existing signed release and dispatches the operator's
approval-gated `enclave.yml` workflow with the digest-qualified image URI and digest. The
deployment workflow must verify the same release evidence, update the KMS image-digest
condition, replace the Confidential Space VM, and record the successful pin. Do not
bypass it with direct metadata edits, mutable image tags, or a digest from an unverified
build.

After approval and rollout:

1. confirm the deployment workflow succeeded;
2. confirm the HTTPS `/health` endpoint succeeds after replacement;
3. fetch `/v1/attestation` and verify its Google signature, HTTPS verifier audience,
   claims, active-certificate-fingerprint nonce, and container digest; retry over a new
   TLS connection if the request straddled certificate renewal;
4. match that digest to the signed release provenance and KMS policy;
5. exercise sign-in, sync, query, screenshot evidence, export, and deletion; and
6. review logs without copying user content into deployment records or issues.

Record the release URL, signed tag commit, digest-qualified image, provenance result,
deployment run, and verification result in the operator's deployment record.

## One-time legacy-blob migration

Version 2 encryption binds every user database, control database, ACME state object, and
screenshot-evidence object to its logical context. Strict images use
`ENCLAVE_ALLOW_LEGACY_BLOBS=0` and reject pre-v2 ciphertext. Migration is automatic on a
successful open, but only while a migration image has explicitly baked in
`ENCLAVE_ALLOW_LEGACY_BLOBS=1`.

This is a **one-way data-format migration**. A pre-v2 binary cannot read the v2 header and
AAD. Never begin without a tested recovery plan, and never roll a migrated deployment
back to a pre-v2 release.

1. Inventory every user database, `control/control.db.enc`, `acme/tls.json.enc`, and
   screenshot-evidence object. Enable GCS object versioning or take a verified backup that
   preserves both ciphertext and wrapped-DEK metadata.
2. Prepare a reviewed, temporary public source change that makes the tagged build pass
   `--build-arg ENCLAVE_ALLOW_LEGACY_BLOBS=1`. The current workflow does **not** consume a
   repository variable for this flag; merely setting one has no effect. Publish the
   migration image through the normal signed-tag, scan, provenance, and SBOM process.
3. Roll the verified migration digest through the approval-gated deployment workflow and
   move the KMS condition to that digest.
4. Cause every legacy object to be opened exactly once:
   - startup loads and rewrites the control database and persisted ACME state;
   - perform an authenticated `/api/export` for every user to load and rewrite each user
     database; and
   - enumerate every `screenshot_images` entry from the export and request its
     `/api/screenshot-images/{id}/content` endpoint to rewrite each media object.
5. Monitor the control/ACME/user migration events and every authentication,
   generation-precondition, or write failure. Media rewrites do not emit a success event,
   so confirm their GCS generations/format explicitly. Confirm every inventoried object
   was rewritten; do not infer completion from startup health alone.
6. Prepare and publish the next reviewed release with the temporary workflow argument
   removed (or explicitly restored to `0`). Roll that strict, v2-aware image and repeat
   read/export checks for every account and media object.
7. Retain backups according to policy, but treat rollback to a pre-v2 binary as
   unsupported. Roll back only to a release that understands v2 context-bound blobs.

Do not leave the migration gate enabled for routine operation. It exists solely to
perform this bounded conversion and would otherwise restore acceptance of relocatable
legacy ciphertext.

## Rollback

Use a previously verified, signed, v2-compatible release:

```sh
DEPLOYMENT_REPO=owner/deployment-repository \
RELEASE_SIGNER_FINGERPRINT=<trusted-key-fingerprint> \
  ./scripts/release.sh vW.X.Y --roll
```

The script reuses and verifies that release's immutable metadata and attestation bundles,
then requests a roll to its exact digest. Recheck HTTPS health, public attestation, core
flows, and KMS binding. Never rebuild an old tag and assume it has the same digest, and
after the legacy-blob migration never roll back to a pre-v2 binary.

## Trust statement

The signed tag identifies intended source. GitHub-signed provenance identifies the
workflow, source tag/commit, and image digest, while the public attestation token reports
the digest running in Confidential Space and KMS authorizes that digest.

This is publicly auditable, but not yet independently reproducible. GitHub Actions,
unvendored crate delivery, and mutable apt package repositories remain in the trusted
build path. The builder digest, model revision/hashes, Action SHAs, provenance, and SBOM
substantially narrow that path without eliminating it. See [`SECURITY.md`](SECURITY.md).
