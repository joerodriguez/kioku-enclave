# kioku-enclave

**The Kioku data plane. The only process that ever holds user plaintext.**

Kioku (記憶, "memory" in Japanese) is a personal memory capture and recall
system. This repository is the data-plane service that runs inside a
[GCP Confidential Space](https://cloud.google.com/confidential-computing/confidential-space/docs/overview)
VM (AMD SEV), and is published as open source so that anyone can verify
that the running instance is exactly this code.

---

## Why this is public

The privacy claim for Kioku is: _"Your recordings never leave your Mac; the
text that does is processed only inside sealed hardware running exactly the
open-source code you can read."_

For that claim to be verifiable — not just asserted — the code must be public
and the build must be reproducible. Hardware attestation then provides the
cryptographic link: the running VM's OIDC attestation token contains the
image digest, and anyone can check that digest against a release-tagged build
of this source.

---

## What the enclave does

- Receives pre-transcribed audio utterances and OCR'd screenshot text from the
  Kioku control plane (a Cloud Run service that handles OAuth, routing, and
  scheduling — a legitimate external caller that never receives user keys or
  decrypts data).
- Stores per-user content as AES-256-GCM encrypted SQLite blobs in GCS.
- Answers full-text search (SQLite FTS5) and context/range queries.
- Writes structured episode summaries produced by the control-plane summariser
  (see Vertex caveat below).
- Handles GDPR hard-delete via `DELETE /v1/user`.

Plaintext lives **only** in this process and in the SEV-encrypted tmpfs that
backs `/tmp`. It is never written to the VM's persistent disk.

---

## Security and trust model

### What the TEE guarantees

GCP Confidential Space uses AMD SEV to encrypt VM memory at the hardware
level. The hypervisor cannot read the guest's memory in plaintext. The
Confidential Space launcher issues an OIDC attestation token (signed by
Google) that contains the SHA-256 digest of the running container image.

### What the attestation proves

The KMS key that wraps per-user data-encryption keys (DEKs) is bound to a
Workload Identity Federation `principalSet`. The IAM condition on that binding
requires:

```
assertion.swname == 'CONFIDENTIAL_SPACE'
AND 'STABLE' in submods.confidential_space.support_attributes
AND attribute.image_digest == <published release digest>
```

This means KMS will only release DEKs to a VM running the exact image digest
that was pinned at key-binding time. Changing even one byte of the image
changes the digest and voids the KMS grant.

**No human principal and no service account has KMS decrypt permission.** The
KMS key's only principal is the attestation-gated `principalSet`. An operator
with full GCP project owner role cannot decrypt user data without modifying the
image, which changes the digest and breaks the attestation condition.

### Caller authentication

The control plane authenticates to the enclave by presenting a Google-signed
ID token (RS256) proving that the caller is the designated control-plane
service account. The enclave verifies:

- The token is signed by Google (`https://accounts.google.com`).
- The `aud` claim matches the enclave's own URL (baked into the image at build
  time — see Dockerfile).
- The `email` claim matches the expected control-plane service account (also
  baked into the image).
- The `email_verified` claim is `true` and the token is not expired.

ID-token verification is unconditional in the binary: there is no
shared-secret fallback and no flag to disable it.

Note that the HTTP listener binds `0.0.0.0` and is **not** itself
access-controlled — the network boundary is the private VPC firewall
(enclave port reachable only from the control-plane subnet) plus the
per-request ID-token verification above, not the listener.

### Launch policy

The Confidential Space launch policy label in the Dockerfile pins
`allow_env_override="PORT,RUST_LOG"`. Everything else — KMS coordinates,
bucket name, trusted caller identity, and auth flags — is baked into the
image. An operator cannot weaken the security posture by changing launch
metadata.

### What is explicitly out of scope

- **OAuth and user identity** — handled by the control plane; the enclave only
  receives an already-authenticated `user_id`.
- **Billing and quota** — control plane.
- **Side-channel attacks on AMD SEV** — the enclave code does not perform
  timing-sensitive operations over secret material, but CPU-level
  microarchitectural side channels (Spectre class) are not fully mitigated by
  AMD SEV.

### Vertex summarisation caveat (important)

Episode summarisation sends text **outside the enclave** to Google Vertex
Gemini. This happens in the control plane. The privacy claim is therefore:

> _"Attested enclave + Google Vertex Gemini inference under Google's
> [no-data-retention terms](https://cloud.google.com/vertex-ai/docs/generative-ai/data-governance)."_

It is not an enclave-only claim. This is a documented design choice, not a
gap. See SECURITY.md for further detail.

---

## HTTP API

All routes except `/health` require an `Authorization: Bearer <token>` header
containing a valid Google ID token from the trusted control-plane service
account.

| Method | Path                        | Body / Query                   | Description                                      |
|--------|-----------------------------|--------------------------------|--------------------------------------------------|
| GET    | `/health`                   | —                              | Liveness probe; returns `{"ok":true}`            |
| POST   | `/v1/ingest`                | `IngestRequest` JSON           | Append utterances + screenshots; idempotent via `source_key` |
| POST   | `/v1/search`                | `SearchRequest` JSON           | FTS5 + vector (hybrid) search; optional `kinds` filter and `query_embedding` |
| POST   | `/v1/context`               | `ContextRequest` JSON          | Rows around a center timestamp                   |
| POST   | `/v1/range`                 | `RangeRequest` JSON            | Raw rows in `[from, to)` (summariser input)      |
| POST   | `/v1/episodes/upsert`       | `EpisodesUpsertRequest` JSON   | Write episodes (upsert on `user_id + started_at`) |
| POST   | `/v1/episodes/list`         | `EpisodesListRequest` JSON     | Episodes in a time range, newest first           |
| POST   | `/v1/episodes/delete_range` | `EpisodesDeleteRangeRequest`   | Delete episodes by time range (summariser rewind)|
| POST   | `/v1/stats`                 | `{ "user_id": "…" }`          | Per-user row counts + latest timestamps          |
| GET    | `/v1/export?user_id=`       | —                              | Full JSON dump of user's index — authenticated control-plane-only call (same ID-token auth as every other route) |
| DELETE | `/v1/user`                  | `{"user_id":"<id>"}` JSON      | Hard-delete all user data; idempotent            |

---

## Build

**Prerequisites:** Rust 1.96+ (toolchain pinned in `rust-toolchain.toml`), `cargo`.

```sh
# Development build (native, macOS or Linux)
cargo build

# Run tests (all crypto + store roundtrips, no network required)
cargo test

# Lint — must pass with zero warnings
cargo clippy -- -D warnings

# Container build (Linux x86-64 CI runner)
# Requires musl toolchain: rustup target add x86_64-unknown-linux-musl
cargo build --release --locked --target x86_64-unknown-linux-musl

# Docker build (supply your own deployment values)
docker build \
  --build-arg KMS_PROJECT=my-project \
  --build-arg KMS_LOCATION=us-central1 \
  --build-arg KMS_KEY_RING=my-keyring \
  --build-arg KMS_KEY=my-kek \
  --build-arg GCS_BUCKET=my-enclave-indexes \
  --build-arg RUN_SA_EMAIL=control-plane@my-project.iam.gserviceaccount.com \
  --build-arg ENCLAVE_AUDIENCE=http://10.0.0.5:8080 \
  --build-arg ATTEST_STS_AUDIENCE=//iam.googleapis.com/projects/<NUM>/... \
  -t kioku-enclave:local .
```

---

## CI/CD — image build pipeline

The enclave image is built automatically by this repository's GitHub Actions
workflow (`.github/workflows/build.yml`). On every push to `main`, the
workflow:

1. Authenticates to GCP using Workload Identity Federation (keyless — no
   long-lived SA key stored in GitHub secrets).
2. Builds the Docker image with `docker build --platform linux/amd64` and
   passes all security-sensitive config via `--build-arg` so that every build
   parameter is part of the attested image digest.
3. Pushes the image to the deployment's Artifact Registry:
   `us-central1-docker.pkg.dev/kioku-joerodriguez/kioku/kioku-enclave:<tag>`
4. Retrieves and publishes the content-addressable `sha256:` digest in the
   job summary.

**Rolling the VM is a separate step.** The operator pins the digest from
step 4 in their deployment terraform (`enclave_image_digest`), which (a) moves
the attestation-gated KMS decrypt binding to the new digest and (b) produces a
new instance template for the managed instance group. The MIG then performs a
zero-downtime create-before-destroy roll: the new VM must boot, attest as the
new image, and pass health checks before the old VM is drained and deleted.

### Required infra prerequisite

Before this workflow can authenticate to GCP, the operator's deployment
terraform must contain a Workload Identity Federation binding that trusts this
repository and maps it to a push-only service account
(`roles/artifactregistry.writer` on the target registry — deliberately NOT a
deployer identity). See the comment at the top of
`.github/workflows/build.yml` for the exact terraform resources required.

### Digest pinning and attestation

The KMS attestation condition in `infra/enclave.tf` pins the exact image
digest:

```
attribute.image_digest == <enclave_image_digest>
```

Only a VM running that exact digest can unwrap user DEKs via KMS. Changing a
single byte of the image — source, dependencies, or build args — produces a
different digest and voids the KMS grant. The digest pinning is therefore the
cryptographic root of the privacy claim.

---

## Environment variables

All security-sensitive variables are baked into the image at `docker build`
time via `--build-arg`. They become `ENV` entries in the final image and
cannot be overridden at VM launch time (the Confidential Space launch policy
only allows `PORT` and `RUST_LOG` to be set by the operator).

| Variable               | Source       | Description                                                         |
|------------------------|--------------|---------------------------------------------------------------------|
| `KMS_PROJECT`          | Build ARG    | GCP project containing the KEK                                      |
| `KMS_LOCATION`         | Build ARG    | KMS key location (e.g. `us-central1`)                               |
| `KMS_KEY_RING`         | Build ARG    | KMS key ring name                                                   |
| `KMS_KEY`              | Build ARG    | KMS key name                                                        |
| `GCS_BUCKET`           | Build ARG    | GCS bucket name for encrypted index blobs                           |
| `RUN_SA_EMAIL`         | Build ARG    | Control-plane service account email (trusted caller identity)       |
| `ENCLAVE_AUDIENCE`     | Build ARG    | The enclave's own URL; validated against ID-token `aud` claim       |
| `ATTEST_STS_AUDIENCE`  | Build ARG    | Full WIF provider resource name for attestation STS exchange        |
| `ENCLAVE_KMS_VIA_ATTESTATION` | Hardcoded `1` | Use attestation STS for KMS credentials (not overridable)  |
| `PORT`                 | Operator / default `8080` | Listen port                                          |
| `RUST_LOG`             | Operator / default `info` | Log filter, e.g. `kioku_enclave=debug`               |
| `STORE_MAX_OPEN`       | Optional     | Max concurrently open user indexes (default `16`)                   |

---

## How to verify a running instance

This procedure lets any third party confirm that the production enclave is
running exactly this source code.

### Step 1 — Fetch the attestation token

From inside the Confidential Space VM (or via a caller with metadata access):

```sh
curl -H "Metadata-Flavor: Google" \
  "http://metadata.google.internal/computeMetadata/v1/instance/attestation/token"
```

The response is a signed OIDC JWT issued by Google's Confidential Space
infrastructure.

### Step 2 — Inspect the image digest

Decode the JWT (any JWT decoder works; the payload is base64-url encoded):

```sh
# Decode without verifying (for inspection only)
python3 -c "
import base64, json, sys
tok = sys.argv[1].split('.')[1]
tok += '=' * (-len(tok) % 4)
print(json.dumps(json.loads(base64.urlsafe_b64decode(tok)), indent=2))
" <TOKEN>
```

Look for `submods.container.image_digest` — this is the `sha256:` digest of
the running image.

### Step 3 — Match against a published release

Compare the digest from the attestation token against the image digest
published in the GitHub Actions job summary for the corresponding release.
Releases tag the commit and record the exact digest that was pushed to
Artifact Registry.

If these match, the running VM is the image that CI built from the tagged
commit — and the attestation-gated KMS binding (Step in "What the attestation
proves") guarantees no other image could have decrypted your data.

### Step 4 — Read the tagged source

Check out the release tag and read the code that produced that image:

```sh
git checkout <release-tag>
```

The source you read is the source CI compiled. The dependency set is pinned by
`Cargo.lock` (`cargo build --locked`).

### What you are trusting today (be precise)

At this stage of the project, the chain is:

> attestation token digest  ==  published release digest  ==  image CI built from `<release-tag>`

The one link you must currently **trust rather than independently verify** is
"CI built that digest from that source" — i.e. you trust GitHub Actions and
crates.io at build time. Full **source-to-binary reproducibility** — where you
rebuild this tag yourself and obtain the *identical* digest, trusting no one —
is **not yet available**. It requires vendored dependencies, a digest-pinned
builder, and signed provenance; see **SECURITY.md → Gap 2** for the plan and
status. Until then, do not claim a rebuild will reproduce the digest — it
won't, because the build is not yet deterministic.

If you find anything surprising in the source, `git diff` the release tag
against `main` and open an issue.

---

## Honest caveats

### Vertex summarisation is outside the enclave

Episode summarisation sends user plaintext to Google Vertex Gemini (operated
by the control plane, not this service). The data leaves the TEE boundary.
Google's no-data-retention API terms apply. This is the intended design, not a
gap, but it means the attestation covers content storage and retrieval only —
not summarisation.

### Reproducible-build hardening is in progress

The current build fetches Rust crates from crates.io at build time (`cargo
build --locked` pins versions via `Cargo.lock`, but does not vendor the
source). A supply-chain attacker who compromises a dependency before the CI
build runs could influence the binary. Future work: `cargo vendor` in CI,
digest-pinned builder image, and cosign/SLSA provenance attestation so the
digest-to-source link is independently verifiable without trusting GitHub.

### Control-plane to enclave transport

Traffic from the control plane to the enclave travels over a private VPC
(Google-encrypted fabric between hosts) but is plain HTTP at the application
layer. The enclave validates the caller's identity via Google ID token on
every request, but the channel itself is not mutually-authenticated TLS.
Attested mTLS (binding the enclave's TLS certificate to its attested workload
identity) is planned as future work.

---

## Dependency philosophy

No heavy cloud SDKs. KMS and GCS are accessed via plain REST (reqwest +
rustls) so every network call is visible, auditable, and the binary stays
small. The full dependency tree is in `Cargo.lock`; reproducible builds
require `--locked`.
