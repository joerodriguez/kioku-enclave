# kioku-enclave

**The attested Kioku backend—the only Kioku-operated server process that handles user
plaintext.**

Kioku (記憶, “memory” in Japanese) is a personal memory capture and recall system.
This repository contains the Rust service that runs inside a
[GCP Confidential Space](https://cloud.google.com/confidential-computing/confidential-space/docs/overview)
VM (AMD SEV). It terminates TLS and implements OAuth, sync, MCP and REST queries,
account operations, summarisation, and encrypted storage in one attested binary.

See [`SECURITY.md`](SECURITY.md) for the threat model and [`RELEASING.md`](RELEASING.md)
for the signed source-tag, provenance, SBOM, image-digest, and deployment procedure.

## Why this is public

Kioku's privacy claim is:

> Raw audio and full-resolution screenshot originals stay on your Mac. If you enable
> Cloud Screenshot Evidence, Kioku uploads a small set of selected, downscaled,
> compressed screenshots from meaningful episodes to the hardware-attested Kioku Cloud
> Core. They are encrypted per user, are never sent to the episode-summary model, and are
> included in export and deletion. Text and metadata that sync are handled by sealed
> hardware running the open-source code you can inspect.

The exact deployed image digest is public. A Confidential Space attestation token reports
the running container digest; a signed GitHub build attestation connects that digest to a
tagged source commit and workflow. This makes the deployment publicly auditable.

It does **not** yet make the image independently or bit-for-bit reproducible. Rust crate
sources are not vendored, apt packages come from mutable repositories, and an independent
rebuild comparison is not part of CI. The precise remaining trust is documented below and
in [`SECURITY.md`](SECURITY.md#source-to-image-rebuilds-are-not-yet-independently-reproducible).

## What the service does

- Terminates public TLS inside Confidential Space and obtains/renews its certificate with
  ACME without exporting the private key.
- Verifies Google identity, runs OAuth 2.1-style authorization with PKCE, and issues Kioku
  access and refresh tokens.
- Receives pre-transcribed utterances, OCR text, and opted-in compressed screenshot
  evidence from Kioku clients.
- Serves device sync, search, timeline, episode, feed, MCP, export, and deletion APIs.
- Stores user and control data as KMS-wrapped, context-bound AES-256-GCM blobs in GCS.
- Runs episode summarisation and evidence verification, including calls to Vertex Gemini
  from inside the service.
- Optionally delivers final briefs through the user's connected Gmail account.

Within Kioku-operated compute and storage, plaintext exists only in this process and in
the SEV-protected `/tmp` tmpfs; it is not written to the VM's persistent disk. Selected
text leaves the TEE only through the documented Vertex and opt-in Gmail delivery paths.

## Security and trust model

### Confidential Space and KMS

Confidential Space uses AMD SEV to encrypt guest memory. Its launcher issues Google-signed
OIDC attestation tokens containing the running container's SHA-256 digest.

The deployment's KMS IAM condition must authorize only a WIF `principalSet` satisfying
the Confidential Space workload and approved image digest, for example:

```text
assertion.swname == "CONFIDENTIAL_SPACE"
AND "STABLE" in submods.confidential_space.support_attributes
AND attribute.image_digest == <approved release digest>
```

No human or service-account principal should have KMS decrypt permission. KMS calls use a
short-lived access token derived from a Confidential Space token and Google STS; there is
no VM metadata-service credential fallback for KMS. The VM service account is used for
ciphertext-only GCS I/O, runtime Secret Manager access, and Vertex; it has no KMS decrypt
path.

### Context-bound blob encryption

Version 2 blobs are prefixed with `KIOKU-BLOB\x02` and encrypted with AES-256-GCM. Their
authenticated data binds each ciphertext to its logical purpose and location:

- user databases bind to `indexes/{user_id}.db.enc`;
- screenshot evidence binds to both the authenticated user and opaque media object key;
- the control database and ACME state use separate fixed contexts.

Copying ciphertext and its wrapped DEK to another user or object therefore fails
authentication. Strict production images reject the older unbound format by default.
Existing deployments must follow the explicit, one-way
[legacy-blob migration procedure](RELEASING.md#one-time-legacy-blob-migration); never
enable `ENCLAVE_ALLOW_LEGACY_BLOBS` as a permanent compatibility setting.

### Authentication and control plane

The public OAuth flow validates Google tokens against the baked desktop and web client
audiences, enforces a non-wildcard account allow-list, and issues Kioku tokens for sync,
query, MCP, and account routes. OAuth authorization uses PKCE, explicit consent,
persisted single-use authorization codes, and client-bound refresh-token rotation.

Legacy `/v1/*` compatibility routes retain Google-signed service-identity-token
authentication. The expected service-account email and token audience are baked into the
image. There is no shared-secret bypass or flag that disables authentication.

### Production TLS is fail-closed

The production container build requires `ENCLAVE_ACME=1` and HTTPS origins. At boot the
service loads or obtains a usable certificate before serving; ACME issuance retries rather
than falling back to the application over HTTP. A non-debug binary without TLS refuses to
start. Plain HTTP application serving exists only in a debug build with
`ENCLAVE_TEST_MODE=1`; port 80 in production is only the isolated ACME HTTP-01 challenge
listener.

The Confidential Space launch policy permits only `PORT` to be changed through VM
metadata. `RUST_LOG` and every security-relevant setting are not production launch-time
overrides; KMS, GCS, auth, TLS, attestation, and migration values are fixed by the image
digest.

### Public attestation tokens are not cloud credentials

The `/v1/attestation` endpoint returns a public Confidential Space OIDC token and the
lowercase hexadecimal SHA-256 fingerprint of the active leaf certificate's DER bytes,
which is supplied as the token nonce. Certificate renewal atomically updates the active
certificate and fingerprint. A TLS connection and request can still straddle that swap;
on a mismatch, discard the evidence and retry over a new connection. The token audience
is always the HTTPS verifier URL `${BASE_URL}/v1/attestation`.

`ATTEST_STS_AUDIENCE` is entirely separate: it is the internal WIF provider resource used
to mint KMS credentials. A token with that audience is a bearer credential that can be
exchanged at STS, so the public endpoint never requests or returns one. Verifiers must
validate the public token's signature, issuer, expiry, audience, claims, nonce, and image
digest; decoding a JWT without verification is insufficient.

### External processing caveats

Episode summarisation and evidence verification send selected text outside the TEE to
Google Vertex Gemini. The request originates inside this service, but Vertex processes it
under Google's
[no-data-retention terms](https://cloud.google.com/vertex-ai/docs/generative-ai/data-governance).
This is an explicit external trust boundary, not an enclave-only inference claim.

If a user opts into episode-email delivery and connects Gmail, the service also sends the
final-brief MIME content to the Gmail API using that user's OAuth grant. Gmail delivery is
an explicit egress boundary; disabling the preference prevents new deliveries.

## API surfaces

The same binary serves all of these surfaces:

| Surface | Representative paths | Authentication |
|---|---|---|
| Health and attestation | `/health`, `/v1/attestation` | Public |
| OAuth discovery and flow | `/.well-known/*`, `/register`, `/authorize`, `/oauth/google/callback`, `/token` | Protocol-specific validation |
| Device and account API | `/api/sync/*`, `/api/export`, `/api/account` | Kioku access token or accepted Google ID token |
| Query and MCP API | `/api/search`, `/api/episodes*`, `/api/feed`, `/mcp` | Kioku access token or accepted Google ID token |
| Screenshot evidence | `/api/screenshot-images*` | Kioku access token or accepted Google ID token |
| Legacy data plane | `/v1/*` below | Google service identity token |

Legacy compatibility routes are:

| Method | Path | Description |
|---|---|---|
| `POST` | `/v1/ingest` | Ingest utterances and screenshot metadata |
| `POST` | `/v1/search` | FTS5 and optional vector/hybrid search |
| `POST` | `/v1/context` | Rows around a center timestamp |
| `POST` | `/v1/range` | Raw rows in a half-open time range |
| `POST` | `/v1/episodes/upsert` | Upsert episodes |
| `POST` | `/v1/episodes/list` | List episodes in a time range |
| `POST` | `/v1/episodes/members` | Read episode members |
| `POST` | `/v1/episodes/delete_range` | Delete episodes in a time range |
| `POST` | `/v1/stats` | Per-user row counts and latest timestamps |
| `GET` | `/v1/export?user_id=…` | Full authenticated user export |
| `DELETE` | `/v1/user` | Idempotent hard deletion |

## Build

Prerequisites are Rust 1.96+, the pinned toolchain in `rust-toolchain.toml`, and Cargo.

```sh
cargo build
cargo test --locked
cargo clippy --locked --all-targets -- -D warnings
cargo fmt --all -- --check
```

The production Docker build has no permissive configuration defaults. Supply every
deployment value; empty values, wildcard `ALLOWED_EMAILS`, non-HTTPS `BASE_URL` or
`WEB_ORIGIN`, an invalid WIF provider audience, or `ENCLAVE_ACME` other than `1` fail the
build.

```sh
docker build --platform linux/amd64 \
  --build-arg SOURCE_DATE_EPOCH="$(git log -1 --format=%ct)" \
  --build-arg KMS_PROJECT=my-project \
  --build-arg KMS_LOCATION=us-central1 \
  --build-arg KMS_KEY_RING=my-keyring \
  --build-arg KMS_KEY=my-kek \
  --build-arg GCS_BUCKET=my-enclave-indexes \
  --build-arg RUN_SA_EMAIL=legacy-caller@my-project.iam.gserviceaccount.com \
  --build-arg ENCLAVE_AUDIENCE=https://api.example.com \
  --build-arg ATTEST_STS_AUDIENCE='//iam.googleapis.com/projects/123456789/locations/global/workloadIdentityPools/my-pool/providers/confidential-space' \
  --build-arg GOOGLE_DESKTOP_CLIENT_ID=desktop-id.apps.googleusercontent.com \
  --build-arg GOOGLE_WEB_CLIENT_ID=web-id.apps.googleusercontent.com \
  --build-arg ALLOWED_EMAILS=owner@example.com \
  --build-arg BASE_URL=https://api.example.com \
  --build-arg WEB_ORIGIN=https://app.example.com \
  --build-arg VERTEX_PROJECT=my-project \
  --build-arg VERTEX_LOCATION=us-central1 \
  --build-arg VERTEX_MODEL=gemini-2.5-flash \
  --build-arg ENCLAVE_ACME=1 \
  --build-arg ENCLAVE_ACME_DIRECTORY=https://acme-v02.api.letsencrypt.org/directory \
  --build-arg ENCLAVE_ACME_CONTACT=mailto:operator@example.com \
  --build-arg ENCLAVE_ALLOW_LEGACY_BLOBS=0 \
  -t kioku-enclave:local .
```

`ENCLAVE_ALLOW_LEGACY_BLOBS` defaults to `0`; it is shown to make the strict posture
explicit. Do not set it to `1` for a fresh deployment.

## Production configuration

Security-sensitive values are Docker build arguments and become image `ENV` values.
Changing one produces a different digest and requires a new attestation-gated KMS
binding.

| Variable | Purpose |
|---|---|
| `KMS_PROJECT`, `KMS_LOCATION`, `KMS_KEY_RING`, `KMS_KEY` | KMS KEK coordinates |
| `GCS_BUCKET` | Encrypted database and default media bucket |
| `RUN_SA_EMAIL` | Google service-account identity accepted by legacy routes |
| `ENCLAVE_AUDIENCE` | Exact `aud` expected on legacy caller ID tokens; normally the public HTTPS API URL |
| `ATTEST_STS_AUDIENCE` | Internal WIF provider resource for KMS STS exchange; never a public token audience |
| `GOOGLE_DESKTOP_CLIENT_ID`, `GOOGLE_WEB_CLIENT_ID` | End-user Google OAuth audiences |
| `ALLOWED_EMAILS` | Nonempty, non-wildcard account allow-list |
| `BASE_URL` | Public HTTPS API origin, OAuth issuer, and basis of the public attestation audience |
| `WEB_ORIGIN` | Single HTTPS browser origin allowed by CORS |
| `VERTEX_PROJECT`, `VERTEX_LOCATION`, `VERTEX_MODEL` | Vertex inference configuration |
| `ENCLAVE_ACME`, `ENCLAVE_ACME_DIRECTORY`, `ENCLAVE_ACME_CONTACT` | Required in-enclave production TLS configuration |
| `ENCLAVE_ALLOW_LEGACY_BLOBS` | Strict `0` normally; temporary `1` only in a reviewed migration image |
| `ENCLAVE_KMS_VIA_ATTESTATION` | Hardcoded to `1`; not operator-configurable |
| `PORT` | The only launch-time override; application TLS listen port, default `8080` |

The web OAuth client secret is fetched at runtime from Secret Manager. JWT signing
secrets are generated and stored in the KMS-protected control database; neither is a
Docker build argument or launch metadata value. Static `ENCLAVE_TLS*` variables exist for
debug/custom bootstrap paths but are neither accepted production build arguments nor
launch-policy overrides.

## CI and release evidence

`.github/workflows/build.yml` runs formatting, locked tests, clippy, and RustSec audit on
pull requests and pushes. The audit has a documented `RUSTSEC-2023-0071` exception because
this service verifies third-party RS256 signatures but performs no RSA private-key
operation. For `main` and tags the workflow then:

1. authenticates to GCP through keyless WIF using a push-only Artifact Registry identity;
2. validates every required repository and build variable;
3. builds with a digest-pinned Rust builder, a commit-derived `SOURCE_DATE_EPOCH`,
   cargo-auditable dependency metadata, and a revision- and hash-pinned embedding model;
4. pushes to the operator-configured registry
   `<region>-docker.pkg.dev/<project>/<repository>/<image>:<tag>`;
5. generates an SPDX JSON SBOM and scans it for fixed high-severity vulnerabilities;
6. creates GitHub-signed image provenance and a signed SBOM attestation; and
7. uploads release metadata, provenance, SBOM, and attestation bundles.

All third-party Actions are pinned to reviewed commit SHAs. A separate security workflow
runs CodeQL on pull requests, `main`, and a weekly schedule, plus dependency review on
pull requests. Dependabot checks Cargo, GitHub Actions, and Docker weekly.

The image-push identity is deliberately not a deployment, IAM, Secret Manager, or KMS
identity. Rolling a VM remains a separate approval-gated operator action using the
digest-qualified image URI. Its GCP WIF provider must constrain immutable GitHub
repository/owner IDs, the `build.yml` workflow identity, and main or protected release-tag
refs; the credentialed job also refuses manual runs from other branches.

## Verify a running deployment

### 1. Fetch the public attestation response

```sh
curl --fail --silent --show-error \
  https://api.example.com/v1/attestation > attestation.json
```

The JSON contains `token` and `fingerprint`. Verify the JWT with Google's published keys
and require, at minimum:

- the expected Confidential Space issuer and workload claims;
- a valid signature and time window;
- `aud == https://api.example.com/v1/attestation`—never a WIF provider resource;
- the expected certificate-fingerprint nonce; and
- the expected `submods.container.image_digest`.

Independently calculate the lowercase hex SHA-256 fingerprint of the live leaf DER and
compare it with the response and token nonce. Fail verification on any mismatch; if the
request crossed an ACME certificate swap, retry over a fresh TLS connection.

### 2. Inspect the signed release

Download the release assets for the matching digest:

```sh
gh release download <release-tag> \
  --repo joerodriguez/kioku-enclave \
  --pattern 'enclave-*.json*'

git fetch --tags origin
git tag -v <release-tag>
```

`git tag -v` proves only that the tag was signed by a key in the verifier's keyring.
Authenticate the displayed key fingerprint against the release operator's separately
published trusted fingerprint; a valid signature from an unknown key is not sufficient.

The release contains:

- `enclave-release.json` — source ref/commit, image URI/digest, and build URL;
- `enclave-provenance.jsonl` — GitHub-signed image provenance;
- `enclave-sbom.spdx.json` — SPDX SBOM; and
- `enclave-sbom-attestation.jsonl` — signed SBOM attestation.

Verify the provenance against the digest-qualified image, source repository, workflow,
tag, and commit. `scripts/release.sh` performs these checks with `gh attestation verify`
before it publishes a new release or requests a roll.

### 3. Match all anchors

The verified chain is:

```text
Google-signed public attestation token image digest
    == release image digest
    == subject of GitHub-signed build provenance
    == digest authorized by the deployment's KMS condition
```

The release script pins the expected tag-signing fingerprint, compares the standalone
SBOM with its verified signed predicate, and refuses to edit or clobber an existing
immutable public release. GitHub release immutability, tag rules, and the operator's
deployment controls remain part of the operational boundary.

## Honest limitations

### Build provenance is signed; independent reproducibility is not complete

The Rust builder image is digest-pinned, the embedding model is revision- and hash-pinned,
and third-party Actions use full commit SHAs. However, Cargo still downloads unvendored
crate sources, apt installs unversioned packages from mutable repositories, and CI does
not perform an independent bit-for-bit rebuild. Trust in GitHub Actions and dependency
delivery therefore remains. Do not describe releases as independently reproducible.

### Vertex and opt-in Gmail delivery leave Confidential Space

Selected text is sent to Vertex Gemini. Attestation covers the Kioku service and its
storage/retrieval behavior, not Vertex's internal execution. When episode-email delivery
is enabled, final-brief content is also sent to Gmail under the connected user's OAuth
grant.

## Reporting vulnerabilities

Please report vulnerabilities privately as described in [`SECURITY.md`](SECURITY.md#reporting-vulnerabilities):

- use the repository's [private vulnerability reporting
  form](https://github.com/joerodriguez/kioku-enclave/security/advisories/new);
- do **not** open a public GitHub issue or publish exploit details; and
- allow coordinated remediation and disclosure.

## Dependency philosophy

The runtime is a static binary in a `scratch` image. KMS and GCS use direct REST calls
through `reqwest`/`rustls`; versions are locked in `Cargo.lock`. Native components such as
sqlite-vec and the transitive Oniguruma build are listed in the SBOM and covered by
dependency/image scanning. Locked versions are necessary for auditing but are not, by
themselves, proof of a reproducible image.
