# kioku-enclave

**The open-source, hardware-attested Kioku application backend.**

Kioku (記憶, “memory” in Japanese) is a personal memory capture and recall system. This
repository contains the Rust service that runs as a regional fleet inside
[GCP Confidential Space](https://cloud.google.com/confidential-computing/confidential-space/docs/overview)
VMs. It terminates TLS and implements identity, OAuth, capture, query, MCP, workers,
export, and deletion in one attested binary.

Private Cloud SQL PostgreSQL 17 is the sole production authority for accounts, structured
memory, search indexes, quotas, jobs, claims, effect receipts, export state, and deletion
state. There is no SQLite backend, selector, fallback, shadow read, or dual write. GCS is
used only for live large-media/object bytes, encrypted per user with KMS-wrapped data keys.
See [ADR-0042](docs/adr/0042-postgresql-only-structured-state.md).

Read [SECURITY.md](SECURITY.md) for the trust model, [API.md](API.md) for the public
capture contract, and [RELEASING.md](RELEASING.md) for signed publication and rollout.

## Why this is public

The running Confidential Space workload exposes a Google-signed attestation token whose
claims include the container digest. Each immutable release publishes:

- a signed annotated source tag;
- canonical build evidence signed by a separately pinned Ed25519 key;
- the exact image digest and source archive hash;
- an SPDX SBOM; and
- the vulnerability-scan result.

That chain makes the designated deployment auditable against this source and the designated
builder. It is not yet independently or bit-for-bit reproducible: crate sources are not
vendored, some package inputs are mutable upstream repositories, and no independent rebuild
comparison is part of the gate.

## Architecture

```text
Mac / iPhone / MCP client
          │ authenticated TLS
          ▼
Confidential Space regional fleet
  ├─ OAuth, capture, query, export, deletion, workers
  ├─ private TLS PostgreSQL ── structured state and fleet-wide claims
  ├─ context-bound encrypted GCS ── large media/object bytes only
  ├─ attestation-derived credential ── KMS unwrap/wrap
  ├─ bounded content egress ── Vertex Gemini
  ├─ signed optional egress ── user-configured webhooks
  └─ content-free egress ── APNs and billing
```

Cloud SQL and its authorized GCP/database administrators are inside the structured-plaintext
trust boundary. Confidential Space protects application plaintext and media keys while the
service is running; it does not turn Cloud SQL into operator-independent encryption.

Large media uses AES-256-GCM with authenticated context binding the account, logical object,
and purpose. Moving ciphertext or wrapped key metadata to another account or object fails
authentication. GCS object generations are tracked in PostgreSQL so structured export can report
their metadata and deletion can operate on exact names and generations without treating a bucket
as database authority.

Durable PostgreSQL claims, leases, reservations, circuit state, and provider-effect receipts
coordinate horizontal workers. A provider timeout never authorizes an unsafe resend, and a
lost claim prevents stale settlement. Readiness verifies the expected PostgreSQL schema and
shared TLS state; liveness is independent so an unhealthy member can be replaced without
reporting the whole service healthy.

## What the service does

- Verifies Google and Apple identity, runs OAuth with PKCE, and rotates client-bound refresh
  tokens.
- Receives bounded audio, screenshot evidence, application/window/display state, browser
  metadata, and metadata-only screen references from Kioku clients.
- Runs bounded Vertex transcription, screenshot understanding, and episode summarization,
  plus in-enclave text embedding. WeSpeaker voice matching remains an offline evaluation path,
  not a serving-time capability.
- Serves search, feed, episodes, people, MCP, export, account deletion, retention settings,
  and owner-authorized playback surfaces.
- Runs horizontally safe media, summarization, email, push, and webhook workers.
- Enforces durable fleet-wide quotas and model-output reservations before provider calls.
- Stores structured state in PostgreSQL and only encrypted large-object bytes in GCS.

Vertex, a user-configured webhook destination, APNs, and the billing service are explicit
external boundaries. Their exact disclosures and residual risks are documented in
[SECURITY.md](SECURITY.md).

## Public API surfaces

The full request/response contract is in [API.md](API.md). Representative surfaces are:

| Surface | Representative paths | Authentication |
|---|---|---|
| Health and attestation | `/health`, `/readyz`, `/livez`, `/v1/attestation` | Health/attestation are public and content-free |
| OAuth | `/.well-known/*`, `/register`, `/authorize`, `/token`, `/oauth/*` | Protocol-specific identity validation |
| Capture and processing | `/api/v2/capture/*` | Kioku access token or accepted Google ID token |
| Search and MCP | `/api/search`, `/api/episodes*`, `/api/feed`, `/mcp` | Kioku access token or accepted Google ID token |
| People, retention, playback | `/api/v2/people*`, `/api/v2/settings/*`, `/api/v2/memories/*/playback` | Kioku access token or accepted Google ID token |
| Export and deletion | `/api/export`, `/api/account`, `/api/account/deletion` | Kioku access token or accepted Google ID token |
| Webhooks | `/api/webhooks*` | Kioku access token or accepted Google ID token |

Retired compatibility routes remain part of the published behavior. `/api/sync/batch`, the
retired screenshot upload routes, and legacy `/v1/*` data routes authenticate before returning
`410 Gone`; they do not read or mutate user state. `/v1/attestation` remains active.

## Security summary

- Production TLS terminates inside the attested workload. Every replica loads the same reviewed
  certificate/key generation from fixed Secret Manager coordinates at startup. Its rustls config
  and attestation-bound leaf fingerprint are immutable for the process lifetime; certificate
  rotation uses the ADR-0041 staged fleet rollout, not an in-process hot swap.
- KMS access uses a short-lived token derived from a Confidential Space attestation token and
  Google STS. There is no metadata-service credential fallback for unwrap/decrypt.
- The launch policy permits only `PORT` as a metadata environment override. KMS, media bucket,
  caller identity, OAuth audiences, PostgreSQL connection budget, and TLS configuration are baked
  into the image or loaded from fixed Secret Manager coordinates.
- Serving code verifies the required PostgreSQL schema unconditionally and never runs DDL; DDL
  belongs only to the dedicated digest-pinned one-shot migrator. There is no runtime schema-mode
  key.
- Public errors, readiness failures, logs, and provider telemetry are content-free.
- Export streams selected tenant-qualified PostgreSQL rows and media metadata as JSON from one
  repeatable-read transaction; it does not fetch GCS media bytes. Full media-byte export remains
  an activation blocker. Account deletion first durably gates new work, then settles usage and
  establishes the idempotent billing fence before identity/content deletion; it removes exact
  current and noncurrent media generations and reports completion only after reconciliation.

The KMS digest condition and reviewed IAM topology reduce standing decrypt authority, but a
cloud-project control-plane administrator can still change IAM, compute, database, or KMS policy.
An operator-independent “only you can read” claim would require user-held keys or an independently
controlled authorization boundary.

## Build and verification

The pinned Rust toolchain and lockfile are authoritative.

```sh
# Fast local feedback.
./scripts/agent-verify.sh quick

# One focused Rust test selection.
./scripts/agent-verify.sh focused -- persistence::postgres::tests

# Full release-grade Rust gate. The URL must name a disposable real PostgreSQL 17 database.
KIOKU_TEST_POSTGRES_URL='postgresql://…' ./scripts/agent-verify.sh full
```

Full mode never starts Docker implicitly and fails before Cargo if the PostgreSQL coordinate is
missing or not a PostgreSQL URL. The Rust contract harness also receives
`KIOKU_REQUIRE_POSTGRES_CONTRACT=1`, so it may not silently skip the real database contract.

The complete image verification pipeline discovers every checked-in `scripts/test_*.py` and
`scripts/test_*.sh` contract, runs the full Rust/PostgreSQL gate, runs Clippy and RustSec audit,
then performs the pinned native Linux/amd64 build, OCI quarantine, SBOM, and scan stages. See
[RELEASING.md](RELEASING.md).

## Production image configuration

`scripts/select_build_configuration.py` reads one external current-user-owned mode-0600
operator file without shell evaluation. The selected non-secret values are assembled through a
BuildKit secret into the final attested image layer.

Deployment-specific groups include:

- `ENCLAVE_KMS_PROJECT`, `ENCLAVE_KMS_LOCATION`, `ENCLAVE_KMS_KEY_RING`, and
  `ENCLAVE_KMS_KEY`;
- `ENCLAVE_GCS_MEDIA_BUCKET`, the only GCS bucket binding in the application image;
- `ENCLAVE_RUN_SA_EMAIL`, `ENCLAVE_AUDIENCE`, and `ENCLAVE_ATTEST_STS_AUDIENCE`;
- Google and optional atomic Apple client identifiers;
- required production APNs team and environment-separated key identifiers;
- admin, signup-budget, public-origin, billing, reviewer, and Vertex settings.

The selector injects non-configurable fleet invariants:

| Key | Required value |
|---|---|
| `POSTGRES_MAX_CONNECTIONS` | `12` |
| `HEALTH_PORT` | `8081` |
| `DRAIN_TIMEOUT_SECONDS` | `105` |
| `ENCLAVE_TLS` | `1` |

There is no backend, schema-mode, archive, witness, genesis, or legacy-media configuration. PostgreSQL
credentials, the shared TLS generation, provider private keys, OAuth secrets, and signing secrets
come from their fixed runtime secret boundaries and are never Docker arguments.

## Release and rollout

`scripts/deploy_latest.py` derives `vMAJOR.MINOR.PATCH` from `Cargo.toml`, requires a clean source
equal to `origin/main`, and creates or verifies a signed annotated tag. The pipeline emits
canonical schema-11 release metadata binding source, image digest, live media bucket, KMS
coordinates, unconditional PostgreSQL schema verification, readiness/drain invariants, and shared
TLS.

`scripts/release.sh` snapshots all release assets read-only, verifies the external evidence key,
tag signer, source archive, exact OCI digest, SBOM, scan, and selected configuration, then publishes
an immutable GitHub release only with `--apply`. Compatible runtime changes use ADR-0041's staged
predecessor/candidate Terraform rollout with zero unavailable capacity and homogeneous-candidate
proof before predecessor retirement. The explicit scale-to-zero lane is retained only for a
reviewed incompatible change.

After a runtime rollout, record the source commit, signed tag, image digest, KMS allowlist, backend
and schema readiness, member inventory, availability-monitor receipt, provider no-op/effect checks,
and the final no-change Terraform plan in the deployment repository.

## Verify a running deployment

1. Fetch `/v1/attestation` over a fresh TLS connection.
2. Verify the Google signature, issuer, expiry, audience, workload claims, certificate-fingerprint
   nonce, and `submods.container.image_digest`.
3. Verify the signed source tag and detached local build evidence with independently pinned key
   fingerprints.
4. Require the same digest in attestation, signed evidence, Artifact Registry, the serving fleet,
   and the KMS digest condition.
5. Verify `/readyz` reports PostgreSQL authority and expected schema health for every member; verify
   `/livez` independently.

## Dependency and disclosure notes

The runtime is a static binary in a `scratch` image. Dependencies are locked, included in the SBOM,
audited, and image-scanned. Locked versions improve auditability but are not proof of reproducible
builds. Bounded content sent to Vertex and explicitly content-enabled webhooks leaves Confidential
Space; attestation does not cover those providers' internal execution.

Report vulnerabilities privately through the repository's
[security advisory form](https://github.com/joerodriguez/kioku-enclave/security/advisories/new).
