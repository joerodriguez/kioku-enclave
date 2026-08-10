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

> Kioku's macOS and iOS clients are capture-only: bounded audio snippets, screenshots,
> authoritative timestamps, foreground-app state, and available browser URLs are sent to
> the hardware-attested Kioku Cloud Core as the product's standard processing path. Raw
> objects are encrypted per user, processed by Vertex Gemini from inside the enclave,
> retained for a bounded retry/voice-learning window, and then deleted. Derived records,
> evidence, and voice profiles remain in the encrypted user archive and are covered by
> export and deletion. The server code handling that plaintext is open source.

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
- Verifies Google and native Sign in with Apple identities, runs OAuth 2.1-style
  authorization with PKCE, and issues Kioku access and refresh tokens.
- Receives raw bounded audio/canonical screenshots plus timestamped application, window,
  display, and browser metadata from pure-Swift Kioku clients. Deterministically validated
  metadata-only screen references retain repeated observations without another encrypted
  image object or inference job.
- Runs Gemini 3.5 Flash transcription, timestamped speaker-turn extraction, screenshot
  understanding, evidence-backed person learning, and independent WeSpeaker voiceprint
  matching in the cloud; no Python runtime is present. Voice samples use append-only
  active assignments and profile revisions so calibrated merge/split proposals can be
  applied and reversed without deleting source observations or prior derivations.
- Publishes the ADR-0016 voice evaluation reducer, objective production-model
  similarity measurement, and schemas. Release CI recomputes
  overlap-aware diarization and identity/fact/export/delete metrics from hash-bound,
  content-free schema-v3 evidence bound to a schema-v2 multi-artifact source and
  authorized physical-route manifest. Identity decisions include denominator-visible
  precision, wrong-binding, cross-meeting, after-three-sample, and abstention metrics
  for every corpus slice. Each claimed identity is bound to the predicted speaker chosen
  by the same deterministic global mapping used for diarization error; synthetic or
  hand-authored legacy aggregates cannot authorize a quality release. Its offline
  derivation command independently verifies licensed media/label artifacts and produces
  canonical fixed-point WAV slices, opaque timing labels, and receipts outside Git. Its
  private similarity command verifies the exact production WeSpeaker model and media
  hashes, then emits only opaque integer pair scores to select the hardest different-
  speaker slice without exposing vectors or content.
- Classifies every signed image as either `owner_only_unvalidated` or
  `validated_real_corpus`. The former permits owner-only production evaluation but
  explicitly authorizes no speaker-quality claim and no external users.
- Serves device sync, search, timeline, episode, feed, MCP, export, and deletion APIs.
- Stores user and control data as KMS-wrapped, context-bound AES-256-GCM blobs in GCS.
- Runs episode summarisation and evidence verification, including calls to Vertex Gemini
  from inside the service. Synced OCR, app/window/URL and browser-tab metadata,
  deterministic visual statistics, transcript context, and derived text are sent together
  for holistic episode analysis once an episode is settled; raw audio and screenshot
  pixels are never included.
- Enforces cost safety before every inference: 8,192-token text and 4,096-token media
  response ceilings, a persistent 524,288 maximum-output-token reservation per user per
  UTC day, bounded sweep sizes, and terminal retry limits. Timeouts retain their
  reservation because Vertex may have completed billable work after the client stopped
  waiting. Automatic workers never regenerate already-completed historical episodes.
- Optionally emits signed CloudEvents to user-configured HTTPS webhook destinations.

Within Kioku-operated compute and storage, plaintext exists only in this process and in
the SEV-protected `/tmp` tmpfs; it is not written to the VM's persistent disk. Audio,
screenshots, and selected text leave the TEE through the documented Vertex boundary;
explicitly configured webhook paths are a separate egress boundary.

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
- raw capture and screenshot evidence bind to both the authenticated user and opaque media object key; new selected screenshot evidence is under the validated owner prefix `raw/{user_id}/evidence/{opaque_key}.enc` (legacy keys remain compatible);
- the control database and ACME state use separate fixed contexts.

Copying ciphertext and its wrapped DEK to another user or object therefore fails
authentication. All production images enforce context-bound v2 encryption unconditionally.


### Authentication and control plane

The public OAuth flow validates Google tokens against the baked desktop and web client
audiences, enforces a non-wildcard account allow-list, and issues Kioku tokens for sync,
query, MCP, and account routes. OAuth authorization uses PKCE, explicit consent,
persisted single-use authorization codes, and client-bound refresh-token rotation.

Native iPhone Apple login sends the signed identity token, single-use authorization code,
and a per-request nonce to `/oauth/apple/native`. The enclave verifies Apple's signature,
issuer, audience, expiry, verified email, subject, and nonce, exchanges the code directly
with Apple, then issues the same resource-bound Kioku session used elsewhere. Apple and
Google identities share an archive only through the authenticated `/api/auth/apple/link`
action; matching email is never an account-link signal. Apple's refresh authorization is
stored only in the encrypted control database and is revoked before account deletion.

The published authorization endpoint is the operator's
`WEB_ORIGIN/app/login`. Its normal path forwards to Google OAuth. An optional
reviewer-only path accepts a short-lived Google Identity Platform token for one exact
image-baked UID/email pair, creates only a namespaced synthetic account, and seeds that
account with non-sensitive fixture data. Reviewer passwords are verified by Google and
never reach this service, its source tree, or its image.

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

Audio transcription/diarization, screenshot understanding, episode summarisation, and
evidence verification send selected content outside the TEE to Google Vertex Gemini. The
request originates inside this service, but Vertex processes it
under Google's
[no-data-retention terms](https://cloud.google.com/vertex-ai/docs/generative-ai/data-governance).
This is an explicit external trust boundary, not an enclave-only inference claim.

The assistant-facing MCP surface has an additional boundary that does not alter the
private archive. Searches aimed at payment-card data, health information, government
identifiers, passwords, API keys, tokens, or authentication codes are refused before
archive retrieval. After each tool's minimal response projection, matching incidental
content is replaced inside the enclave across transcripts, OCR, URLs, surrounding
context, time-range digests, episode summaries, action items, and final briefs. URL query
strings and fragments are omitted, malformed URLs and oversized text fail closed, and
the REST/debugger surfaces retain their normal owner-authorized behavior.

Users can add HTTPS webhook destinations for finalized-episode events. Notifications are
content-free by default; including a final brief is a separate per-destination opt-in.
Webhook endpoints and signing secrets are encrypted in the control store, destination
paths are redacted from API responses and logs, and each request is signed with the
Standard Webhooks headers. Delivery rejects redirects and private, local, link-local,
documentation, and other non-public network addresses. A configured destination remains
an explicit egress boundary outside Kioku's enclave and attestation.

## API surfaces

The same binary serves all of these surfaces:

| Surface | Representative paths | Authentication |
|---|---|---|
| Health and attestation | `/health`, `/v1/attestation` | Public |
| OAuth discovery and flow | `/.well-known/*`, `/register`, `/authorize`, `/oauth/reviewer`, `/oauth/google/callback`, `/token` | Protocol-specific validation |
| Native Apple identity | `/oauth/apple/native`, `/api/auth/session`, `/api/auth/apple/link` | Apple authorization or an existing authenticated account |
| Device and account API | `/api/sync/*`, `/api/export`, `/api/account` | Kioku access token or accepted Google ID token |
| Cloud Capture v2 | `/api/v2/capture/*`, `/api/v2/people*` | Kioku access token or accepted Google ID token |
| Query and MCP API | `/api/search`, `/api/episodes*`, `/api/feed`, `/mcp` | Kioku access token or accepted Google ID token |
| Screenshot evidence | `/api/screenshot-images*` | Kioku access token or accepted Google ID token |
| Webhook automation | `/api/webhooks*` | Kioku access token or accepted Google ID token |
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

## Archive capacity fixtures and observability

Before legacy noncurrent-generation lifecycle rules may be promoted, startup also runs a
bounded serial reconciliation of pre-existing `indexes/*.db.enc` objects. It lists only
current GCS objects, then resolves each name through an explicit live-object read,
and create-verifies the current UTC day's generation-pinned recovery checkpoint. A retry
after a lost copy response or restart converges on the immutable named checkpoint; no user,
archive, object, or generation identifier is logged. Aggregate readiness remains false
until a complete error-free scan, and the runtime never activates bucket lifecycle itself.
Successful scans run at most hourly; failures retry with bounded 5-second-to-5-minute
backoff.

ADR-0022 Phase-0a instruments the existing whole-encrypted-SQLite snapshot path with
process-local, unlabeled counters and fixed-bucket histograms. Once per active minute the
service emits one cumulative `archive_snapshot_v1` structured event through its existing
logging pipeline; it does not expose a metrics endpoint or add another network service.
The event contains logical database byte observations, the pre-checkpoint WAL-file byte
length as a changed-page proxy, successful and attempted encrypted upload bytes, encrypted
download bytes, save attempts/completed/failed/skipped, end-to-end save latency, and
encrypted-durable/WAL-proxy ratio in parts per million. It never contains user/archive
IDs, object names or paths, query/content fields, keys, URLs, or per-user labels.

The ratio is exactly
`successful encrypted snapshot bytes / pre-checkpoint SQLite -wal file bytes` for each
completed save. A zero-byte or absent WAL denominator records `u64::MAX` in the `+Inf`
bucket, exposing a full-database rewrite with no observed changed frames. WAL length is
only a proxy: it includes WAL framing and can diverge from changed-page bytes after
SQLite auto-checkpointing or WAL reuse, so this is not a claim of exact dirty-byte
amplification. Logical database size remains a separate histogram. The dirty-generation
guard records a proven-clean save or eviction in `save_skipped_total` and skips
checkpointing, KMS, encryption, plaintext file reads, and GCS upload work. Failed
uploads contribute to attempted-upload bytes and
failed/latency counters, but only durable successes contribute to upload and ratio
histograms. Upload/download byte values measure the encrypted object payload, excluding
HTTP metadata and multipart framing. All counters reset on process restart.

The deterministic, content-free capacity contract is
[`eval/capacity/archive-fixtures-v1.json`](eval/capacity/archive-fixtures-v1.json). Inspect
and validate its exact three-year 480/960/1,200-hour distributions without generating
records:

```sh
python3 scripts/generate_capacity_fixture.py check
```

The optional generator streams numeric synthetic records to ignored `target/` output (or
outside the checkout), so it does not allocate every record in memory. Its bounded smoke
mode is exercised in unit tests. The explicit `power-user-c-1200-32gib` plus
`--create-sparse-shape` path creates a 32-GiB logical sparse file, not 32 GiB of written
blocks; that file is not SQLite and is not query-performance evidence. See
[`eval/capacity/README.md`](eval/capacity/README.md) for commands and release-evidence
limitations.

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
  --build-arg GCS_MEDIA_BUCKET=my-enclave-media \
  --build-arg RUN_SA_EMAIL=legacy-caller@my-project.iam.gserviceaccount.com \
  --build-arg ENCLAVE_AUDIENCE=https://api.example.com \
  --build-arg ATTEST_STS_AUDIENCE='//iam.googleapis.com/projects/123456789/locations/global/workloadIdentityPools/my-pool/providers/confidential-space' \
  --build-arg GOOGLE_DESKTOP_CLIENT_ID=desktop-id.apps.googleusercontent.com \
  --build-arg GOOGLE_IOS_CLIENT_ID=ios-id.apps.googleusercontent.com \
  --build-arg GOOGLE_WEB_CLIENT_ID=web-id.apps.googleusercontent.com \
  --build-arg APPLE_TEAM_ID=ABCDE12345 \
  --build-arg APPLE_KEY_ID=FGHIJ67890 \
  --build-arg APPLE_IOS_CLIENT_ID=com.kioku.ios \
  --build-arg ALLOWED_EMAILS=owner@example.com \
  --build-arg BASE_URL=https://api.example.com \
  --build-arg WEB_ORIGIN=https://app.example.com \
  --build-arg REVIEWER_AUTH_API_KEY=public-identity-platform-api-key \
  --build-arg REVIEWER_AUTH_UID=precreated_reviewer_uid \
  --build-arg REVIEWER_AUTH_EMAIL=reviewer@example.com \
  --build-arg VERTEX_PROJECT=my-project \
  --build-arg VERTEX_LOCATION=us-central1 \
  --build-arg VERTEX_MODEL=gemini-3.5-flash \
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
| `GCS_BUCKET` | Encrypted database bucket |
| `GCS_MEDIA_BUCKET` | Encrypted bounded-retention raw-media bucket |
| `RUN_SA_EMAIL` | Google service-account identity accepted by legacy routes |
| `ENCLAVE_AUDIENCE` | Exact `aud` expected on legacy caller ID tokens; normally the public HTTPS API URL |
| `ATTEST_STS_AUDIENCE` | Internal WIF provider resource for KMS STS exchange; never a public token audience |
| `GOOGLE_DESKTOP_CLIENT_ID`, `GOOGLE_IOS_CLIENT_ID`, `GOOGLE_WEB_CLIENT_ID` | End-user Google OAuth audiences |
| `APPLE_TEAM_ID`, `APPLE_KEY_ID`, `APPLE_IOS_CLIENT_ID` | Optional Sign in with Apple configuration; set all three or none. The client ID must identify the native iPhone app |
| `ALLOWED_EMAILS` | Nonempty, non-wildcard account allow-list |
| `BASE_URL` | Public HTTPS API origin, OAuth issuer, and basis of the public attestation audience |
| `WEB_ORIGIN` | Single HTTPS browser origin allowed by CORS |
| `REVIEWER_AUTH_API_KEY`, `REVIEWER_AUTH_UID`, `REVIEWER_AUTH_EMAIL` | Optional Google Identity Platform reviewer account; set all three or none. Values are image-baked and exact matched; never supply the password |
| `VERTEX_PROJECT`, `VERTEX_LOCATION`, `VERTEX_MODEL` | Vertex episode inference configuration |
| `QUOTA_VERTEX_OUTPUT_TOKENS_PER_DAY` | Optional per-user UTC-day maximum-output reservation ceiling; defaults to `524288`. Each request reserves its full configured output maximum before Vertex is called and fails closed when exhausted |
| `ENCLAVE_ACME`, `ENCLAVE_ACME_DIRECTORY`, `ENCLAVE_ACME_CONTACT` | Required in-enclave production TLS configuration |
| `ENCLAVE_ALLOW_LEGACY_BLOBS` | Strict `0` normally; temporary `1` only in a reviewed migration image |
| `ENCLAVE_KMS_VIA_ATTESTATION` | Hardcoded to `1`; not operator-configurable |
| `PORT` | The only launch-time override; application TLS listen port, default `8080` |

The web OAuth client secret and, when Apple login is configured, the P-256 Apple private
key (`kioku-apple-sign-in-private-key`) are fetched at runtime from Secret Manager. The reviewer
password remains only in Google Identity Platform, the review portal, and the operator's
versioned `kioku-openai-reviewer-password` secret in project `kioku-joerodriguez`. JWT
signing secrets are generated and stored in the KMS-protected control database; neither
password nor signing secret is a Docker build argument or launch metadata value. Static
`ENCLAVE_TLS*` variables exist for debug/custom bootstrap paths but are neither accepted
production build arguments nor launch-policy overrides.

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

Production is the sole active owner evaluation environment. Signed releases either carry
the exact `eval/voice/owner-only-production.json` declaration and record
`voice_quality_gate: owner_only_unvalidated`, or carry a complete passing real-corpus trio
and record `validated_real_corpus`. The owner-only declaration permits neither external
users nor a voice-quality claim. The former manual `evaluation` build profile remains
available only to reproduce and audit historical isolated images; its runtime is retired,
it cannot become a GitHub Release or production rollout, and it must not be deployed.
Ordinary `main` and signed `v*` tag pushes always select the production profile.

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

- `enclave-release.json` — production build profile, source ref/commit, image URI/digest,
  build URL, and explicit voice-quality gate classification;
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

### Vertex and user-configured webhooks leave Confidential Space

Bounded audio, screenshots, and selected text are sent to Vertex Gemini. Attestation covers the Kioku service and its
storage/retrieval behavior, not Vertex's internal execution. A webhook destination is
also outside the attested boundary. Finalized-episode webhooks are content-free unless
the user explicitly enables full brief content for that destination.

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
