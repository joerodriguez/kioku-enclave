# Releasing the open-source Kioku enclave

Every production enclave image must be traceable to stable public source. A release is
therefore more than a container push: it is a public Git tag and GitHub Release that
record the exact source commit, build run, image URI, and attestation digest.

## Prerequisites

- Work on clean `main`, synchronized with `origin/main`.
- `cargo`, `git`, Python 3, and GitHub CLI (`gh`) installed.
- `gh` authenticated with permission to push tags, publish releases in
  `joerodriguez/kioku-enclave`, and dispatch the deployment workflow when using
  `--roll`.
- The repository's GitHub Actions variables and keyless GCP Workload Identity binding
  configured as documented in `README.md`.

The image workflow validates every production build argument before Docker runs. This
includes the OAuth audiences/allow-list, public base URL, Vertex configuration, and ACME
TLS configuration in addition to KMS/GCS/attestation identifiers; a missing value fails
the build instead of publishing a partially configured image.

Before tagging, `scripts/release.sh` also verifies that these repository variable names
exist: the WIF/provider pair, all `ENCLAVE_*` identifiers listed in
`.github/workflows/build.yml`, `GOOGLE_DESKTOP_CLIENT_ID`, `GOOGLE_WEB_CLIENT_ID`,
`ALLOWED_EMAILS`, `BASE_URL`, `VERTEX_PROJECT`, `VERTEX_LOCATION`, `VERTEX_MODEL`,
`ENCLAVE_ACME`, `ENCLAVE_ACME_DIRECTORY`, and `ENCLAVE_ACME_CONTACT`. Configure them in
GitHub Settings → Secrets and variables → Actions, or with `gh variable set`. These are
non-secret deployment coordinates; do not put credential values or TLS private keys in
repository variables.

## One-time public-repository gate

The release script requires GitHub to report `visibility: PUBLIC` and exits before
tagging when it does not. Before changing visibility for the first release:

1. run a dedicated secret scanner across the full Git history, not only the current
   checkout;
2. review all GitHub Actions variables and workflow logs for values that should instead
   be secrets (deployment identifiers and service-account email addresses are public;
   credentials and TLS private keys are not);
3. confirm `LICENSE`, `SECURITY.md`, contribution guidance, and the vulnerability contact;
4. enable branch protection and required CI on `main`; and
5. change the repository visibility in GitHub, then verify with:

   ```sh
   gh repo view joerodriguez/kioku-enclave --json visibility --jq .visibility
   # expected: PUBLIC
   ```

The repository currently contains an Apache-2.0 license and ignores local `.env` files,
but those facts do not replace a full-history secret scan.

## Publish a release

Use SemVer tags. When an enclave and desktop change are one coordinated product release,
use the same version in their separate repositories.

```sh
./scripts/release.sh v0.6.6
```

The script:

1. verifies clean, synchronized `main`;
2. runs `cargo fmt --check`, locked tests, and clippy with warnings denied;
3. creates and pushes the annotated source tag;
4. waits for `.github/workflows/build.yml` to build and push the image;
5. validates the returned `sha256:` digest; and
6. creates the public GitHub Release with `enclave-release.json` attached.

The resulting public release is the stable audit record. Workflow artifacts alone are
not sufficient because they expire and may require authentication.

Publishing does **not** change production.

## Roll production

After reviewing the release metadata, resume the same release with:

```sh
./scripts/release.sh v0.6.6 --roll
```

The checks rerun, the existing tagged build metadata is reused, and the script dispatches
the `Roll enclave VM` workflow in `joerodriguez/kioku`. That workflow:

- verifies the tag, digest-pinned URI, and digest against the public
  `enclave-release.json` before using them;
- updates the KMS attestation condition;
- replaces the standalone Confidential Space VM;
- and commits the successful image/digest pin to `infra/terraform.tfvars`.

The deployment workflow is the production boundary. Do not bypass it with a direct VM
metadata edit or an unpinned image tag.

## Verify

1. Confirm the deployment workflow succeeded.
2. Confirm `https://api.kiokuu.com/health` returns successfully after the replacement
   window.
3. Compare the running Confidential Space attestation token's container digest with the
   digest on the public GitHub Release.
4. Exercise the changed endpoints and the core sign-in, sync, search, export, and delete
   flows.
5. Check operational logs without copying user content into release notes or issues.

Record the public release URL, source commit, digest, deployment run, and verification in
the deployment repository's `PROGRESS.md`.

## Rollback

Use a previously verified release tag:

```sh
./scripts/release.sh v0.6.5 --roll
```

The script reuses that tag's published build metadata and requests a roll back to its
exact digest. Verify health and attestation again. Do not rebuild an old source tag and
assume it has the same digest; the current build is not yet bit-for-bit reproducible.

## Trust statement

The public tag lets anyone inspect the intended source, and the published image digest is
the value enforced by the attestation-gated KMS binding. Today, GitHub Actions and build-
time dependency delivery remain in the trusted path. `SECURITY.md` documents this
reproducibility/provenance gap; release notes must not claim independent reproducibility
until that work is complete.
