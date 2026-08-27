# kioku-enclave

**The open-source, attested Kioku application backend.**

Kioku (記憶, “memory” in Japanese) is a personal memory capture and recall system.
This repository contains the Rust service that runs inside a
[GCP Confidential Space](https://cloud.google.com/confidential-computing/confidential-space/docs/overview)
VMs (AMD SEV). It terminates TLS and implements OAuth, sync, MCP and REST queries,
account operations, summarisation, and media encryption in one attested binary. Private
Cloud SQL PostgreSQL is the production structured-state/search/work authority; its
database engine and authorized GCP/database administrators are explicitly inside the
plaintext trust boundary. Large audio and image objects remain per-user encrypted in GCS.

> **ADR-0040 storage change (2026-08-27):** Production builds select PostgreSQL and
> fail closed rather than falling back to SQLite/GCS. The extensive SQLite, WAL,
> witness, and archive-v3 material retained in this repository documents the reference
> implementation and historical safety work; it is not constructed in PostgreSQL
> serving mode.

See [`SECURITY.md`](SECURITY.md) for the threat model and [`RELEASING.md`](RELEASING.md)
for the signed source-tag, provenance, SBOM, image-digest, and deployment procedure.

## Why this is public

Kioku's privacy claim is:

> Kioku's macOS and iOS clients are capture-only: bounded audio snippets, screenshots,
> authoritative timestamps, foreground-app state, and available browser URLs are sent to
> the hardware-attested Kioku Cloud Core as the product's standard processing path. Raw
> objects are encrypted per user and processed by Vertex Gemini from inside the enclave.
> The current/default policy retains them for a bounded retry/voice-learning window and
> then deletes them. ADR-0036 stages an opt-in durable original-audio path and owner-only
> playback, but it remains inactive until its schema, privacy, export, deletion, and
> rollout gates are complete. Derived records, evidence, and voice profiles remain in
> private Cloud SQL PostgreSQL. Cloud SQL is conventional managed-cloud trust, not
> operator-independent encryption. The application code handling that plaintext is open
> source; large raw-media objects remain per-user encrypted in GCS.

The exact deployed image digest is public. A Confidential Space attestation token reports
the running container digest; a detached Ed25519 signature from the separately pinned
local build key connects that digest to a tagged source commit, SBOM, and scan. This makes
the deployment publicly auditable against the designated builder's evidence.

It does **not** yet make the image independently or bit-for-bit reproducible. Rust crate
sources are not vendored, apt packages come from mutable repositories, and an independent
rebuild comparison is not part of the local release gate. The precise remaining trust is documented below and
in [`SECURITY.md`](SECURITY.md#source-to-image-rebuilds-are-not-yet-independently-reproducible).

## What the service does

- Terminates public TLS inside Confidential Space and obtains/renews its certificate with
  ACME without exporting the private key.
- Verifies Google and native/browser Apple identity, runs OAuth 2.1-style authorization
  with PKCE, and issues Kioku access and refresh tokens.
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
  similarity measurement, and schemas. The local release gate recomputes
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
- Serves device sync, search, timeline, episode, feed, MCP, export, deletion, and gated
  owner-only person-conversation/playback APIs.
- Enforces provider-authored wall-clock recording allowances through server-timed, idempotent
  60-second leases plus domain-separated, idempotent 60-second reconciliation ticks for
  time recorded into the Mac's encrypted local outbox during a network outage. Offline
  ticks carry no capture, device, stream, media, or timestamp identifier. A restarted
  client reattaches to an unexpired paid interval when more
  than the 20-second renewal headroom remains; otherwise the enclave reserves one fresh
  minute instead of trapping the client in a lease-conflict loop. Each paid minute also
  grants a bounded event/byte delivery budget so acknowledged outbox replay can occur
  after lease expiry without charging network-transfer time. A durable pending
  reservation is reconciled with its original billing idempotency key before any new
  reservation, so a crash or failed local commit neither double-charges nor blocks that
  user indefinitely. Metadata-only Mac screen references may use the bounded JSON batch
  route: one request holds the user lifecycle/content fence and saves the encrypted archive
  once, while the existing per-event reservation rows still charge each new observation and
  make ambiguous retry or individual-route fallback idempotent. Allowance amount, period
  cadence, catalog, and pricing remain opaque:
  the enclave knows only the provider-neutral allowance snapshot and
  reservation decision. Catalog, pricing, payment, and subscription implementations live
  behind the external control-plane port and are not part of this repository.
- Stores structured user/control/search/job data in private Cloud SQL PostgreSQL and
  stores large audio/image media as KMS-wrapped, context-bound AES-256-GCM GCS objects.
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

Public TLS and application processing plaintext runs in this process and SEV-protected
memory. Queryable structured plaintext also exists in private Cloud SQL and its bounded
backup/PITR copies. Audio, screenshots, and selected text leave the TEE through the
documented Vertex boundary.
After the separately gated ADR-0036 activation, one bounded verified audio segment may
also leave to its authenticated owner's active browser as a private/no-store response;
storage credentials and media keys never do.
Content-free pseudonymous usage/accounting events leave through the billing boundary;
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

The deployment must pair an authoritative, digest-scoped KEK binding with an audit of
every project, key-ring, and key IAM binding. Standing operator and deployer roles must
contain neither direct nor delegated KMS decrypt permission; broad inherited roles such
as project Owner otherwise remain effective even when the KEK's local binding looks
exclusive. This standalone project cannot administer an organization-level IAM deny
policy, so the rollout guard detects standing decrypt grants but is not itself an
independent authorization boundary. KMS calls use a short-lived access token derived from
a Confidential Space token and Google STS; there is no VM metadata-service credential
fallback for KMS. The VM service account is used for ciphertext-only GCS I/O, runtime
Secret Manager access, and Vertex; it has no standing KMS decrypt path.

Removing those grants closes the standing human/service-account data-plane decrypt path,
but it does not make a cloud-project control-plane administrator cryptographically unable
to change IAM, KMS, or compute policy later. An operator-independent "only you can read"
guarantee still requires user-held keys or an independently controlled authorization
boundary. See
[`SECURITY.md`](SECURITY.md#t1--malicious-operator-or-cloud-project-insider).

### Context-bound large-media encryption

Version 2 blobs are prefixed with `KIOKU-BLOB\x02` and encrypted with AES-256-GCM. Their
authenticated data binds each ciphertext to its logical purpose and location:

- raw capture and screenshot evidence bind to both the authenticated user and opaque media object key; new selected screenshot evidence is under the validated owner prefix `raw/{user_id}/evidence/{opaque_key}.enc` (legacy keys remain compatible);
- legacy/reference SQLite databases and historical ACME state retain their existing
  fixed contexts but are not PostgreSQL serving authorities.

Copying ciphertext and its wrapped DEK to another user or object therefore fails
authentication. All production images enforce context-bound v2 encryption unconditionally.


### Authentication and control plane

The public OAuth flow validates Google tokens against the baked desktop/iOS/web clients
and Sign in with Apple tokens against distinct iPhone App ID, Mac App ID, and web Services
ID audiences. Native Apple requests require SHA-256 nonces; browser requests use Apple's
server-returned raw nonce. Sign-up is open: every identity the provider verifies gets an
account, bounded only by an image-baked service-wide daily new-account budget
(`SIGNUP_LIMIT_PER_DAY`) that all sign-in paths share. All paths issue Kioku tokens for
sync, query, MCP, and account routes. OAuth authorization uses PKCE,
explicit consent, persisted single-use authorization codes, and client-bound refresh-token
rotation. Provider subjects are namespaced and accounts are never linked by email.

The published authorization endpoint is the operator's
`WEB_ORIGIN/app/login`. Its normal paths forward to Google or Apple and return through the
same consent/code machinery. The Kioku dashboard uses one fixed first-party PKCE client;
third-party MCP clients retain bounded Dynamic Client Registration. An optional
reviewer-only path accepts a short-lived Google Identity Platform token for one exact
image-baked UID/email pair, creates only a namespaced synthetic account, and seeds that
account with non-sensitive fixture data. Reviewer passwords are verified by Google and
never reach this service, its source tree, or its image.

Legacy `/v1/*` data routes retain Google-signed service-identity-token authentication,
then return `410 Gone` without reading or mutating user data. The expected
service-account email and token audience are baked into the image. There is no
shared-secret bypass or flag that disables authentication. `/v1/attestation` remains a
separate public, active endpoint.

### Production TLS is fail-closed

The production fleet build requires `ENCLAVE_TLS=1`, `ENCLAVE_ACME=0`, and HTTPS origins.
Each replica loads the same certificate and private-key generation from Secret Manager
before serving; a missing, malformed, or mismatched secret fails closed. Certificate
renewal publishes new versions and rolls the fleet. A non-debug binary without TLS refuses
to start. Plain HTTP application serving exists only in a debug build with
`ENCLAVE_TEST_MODE=1`.

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
documentation, and other non-public network addresses, and disables environment proxies.
Selected delivery freezes the
exact destination and body before its first provider call, never resends an ambiguous
outcome, expires old/pre-activation rows provider-free, and makes destination deletion a
durable disclosure fence that removes the frozen endpoint, secret, opted-in body, and
claim evidence before the destination disappears. A configured destination remains an explicit egress boundary
outside Kioku's enclave and attestation.

## API surfaces

The same binary serves all of these surfaces:

| Surface | Representative paths | Authentication |
|---|---|---|
| Health and attestation | `/health`, `/v1/attestation` | Public |
| OAuth discovery and flow | `/.well-known/*`, `/register`, `/authorize`, `/oauth/reviewer`, `/oauth/google/callback`, `/oauth/apple/authorize`, `/oauth/apple/callback`, `/token` | Protocol-specific validation |
| Apple identity/linking | `/oauth/apple/native`, `/api/auth/session`, `/api/auth/apple/link`, `/api/auth/apple/web-link` | Apple authorization or an existing authenticated account |
| Device and account API | `/api/sync/*`, `/api/export`, `/api/account`, `/api/account/deletion` | Kioku access token or accepted Google ID token |
| Cloud Capture v2, retention, and owner playback | `/api/v2/capture/*`, `/api/v2/settings/recording-retention*`, `/api/v2/people*`, `/api/v2/memories/*/playback` | Kioku access token or accepted Google ID token; durable retention/playback remain epoch-gated |
| Query and MCP API | `/api/search`, `/api/episodes*`, `/api/feed`, `/mcp` | Kioku access token or accepted Google ID token |
| Screenshot evidence | `/api/screenshot-images/{id}/content` | Kioku access token or accepted Google ID token |
| Retired selected screenshot upload | `GET /api/screenshot-images/plan`, `POST /api/screenshot-images` | Kioku access token or accepted Google ID token; Genesis-selected archives receive `410 Gone`, while unselected legacy compatibility remains |
| Webhook automation | `/api/webhooks*` | Kioku access token or accepted Google ID token |
| Retired local sync | `/api/sync/batch` | Kioku access token or accepted Google ID token, then `410 Gone` |
| Retired legacy data plane | `/v1/*` below | Google service identity token, then `410 Gone` |

Retired compatibility tombstones are:

| Method | Path | Description |
|---|---|---|
| `POST` | `/api/sync/batch` | Authenticated `410 Gone`; no batch mutation |
| `GET` | `/api/screenshot-images/plan` | Genesis-selected archives: authenticated `410 Gone`; no false empty plan or archive read |
| `POST` | `/api/screenshot-images` | Genesis-selected archives: authenticated `410 Gone` before multipart, KMS, lease, or provider work |
| `ANY` | `/v1/ingest` | Authenticated `410 Gone`; no ingest mutation |
| `ANY` | `/v1/search`, `/v1/context`, `/v1/range`, `/v1/stats` | Authenticated `410 Gone`; no data read |
| `ANY` | `/v1/episodes/*` | Authenticated `410 Gone`; no episode mutation or read |
| `ANY` | `/v1/export`, `/v1/user` | Authenticated `410 Gone`; no export or deletion |

The authenticated control-plane `DELETE /api/account` returns `200` when physical
deletion and identity cleanup are complete, or `202` with a stable opaque
`operation_id`, machine-readable `status`/`reason`, `retry_after_seconds`, and the GCS
`hard_delete_time` when provider retention still applies. `GET /api/account/deletion`
polls the same content-free operation. Status is `pending`, `failed_retryable`, or
`physical_complete`; `deleted` is true only for `physical_complete`. Deleting/deleted credentials are accepted only on
those two routes; every other account route remains denied. A bounded server-side
reconciler retries eligible pending operations—including an interrupted attempt—after
restart. A legacy generation that vanished before inventory, or a generation above the
temporary 512 MiB compatibility cap, instead reports `failed_retryable` and requires
explicit remediation rather than being declared complete from a later empty listing.

## Build

Prerequisites are Rust 1.96+, the pinned toolchain in `rust-toolchain.toml`, and Cargo.

```sh
# Default local feedback: formatting plus a locked type-check.
./scripts/agent-verify.sh quick

# Add the smallest relevant test selection while developing.
./scripts/agent-verify.sh focused -- module::tests::affected_case

# The exhaustive local merge gate is used for broad or security-sensitive
# changes and for diagnosing verification failures.
./scripts/agent-verify.sh full
```

The helper checks free disk space before compiling and uses `sccache` only when
it is already installed, with a bounded cache and a 15-GiB default free-space
floor. It also holds a crash-safe per-worktree artifact lock while its locked Cargo
compilation/test commands run; a separate local `cargo build` is unnecessary.
Do not race worktree artifact retirement with raw Cargo outside this helper.

## Archive capacity fixtures and observability

Before legacy noncurrent-generation lifecycle rules may be promoted, startup also runs a
bounded serial reconciliation of pre-existing `indexes/*.db.enc` objects. It lists only
current GCS objects, then resolves each name through an explicit live-object read,
and create-verifies the current UTC day's generation-pinned recovery checkpoint. Checkpoint
copy shares the per-user content-write barrier with raw capture, so account deletion closes
new admission and waits for any admitted copy or raw PUT to settle before inventory. A retry
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

`scripts/run_archive_capacity_harness.py` is an offline, deterministic SQLite **smoke**
harness. Local smoke runs create a small real SQLite database, verify exact fixture counts,
SQLite/FTS integrity, and a deterministic logical-export digest. Its report permanently
sets both `release_evidence` and `sqlite_local_evidence` to `false`; full mode fails
closed. The harness cannot bind its execution to a release image/VM or exercise the v3
VFS, backend, witness, fault, lifecycle, production cache, concurrency, or query-mix
gates required by ADR-0022. A later signed production release suite must supply that
evidence rather than reclassifying this report.

The optional generator streams numeric synthetic records to ignored `target/` output (or
outside the checkout), so it does not allocate every record in memory. Its bounded smoke
mode is exercised in unit tests. The explicit `power-user-c-1200-32gib` plus
`--create-sparse-shape` path creates a 32-GiB logical sparse file, not 32 GiB of written
blocks; that file is not SQLite and is not query-performance evidence. See
[`eval/capacity/README.md`](eval/capacity/README.md) for commands and release-evidence
limitations.

The separate `scripts/run_archive_capacity_gate.py` consumes the v2 12-month 40/80/100
hours-per-month fixture only after an operator has reviewed its no-I/O `plan`, supplied an
empty safe output directory, passed the free-space preflight, and explicitly acknowledged
the production-shaped and sparse-extent paths. It measures local SQLite DB/WAL/checkpoint
behavior using bounded zero-filled per-kind payload and vector-shape BLOBs, plus 32-GiB
page/extent assumptions, but is still non-authority local evidence:
it never materializes, downloads, or encrypts a 32-GiB snapshot and cannot satisfy the
archive-v3 release gate.

### Inactive signed 32-GiB release-evidence contract

`eval/capacity/archive-v3-capacity-evidence-v2.schema.json` and
`eval/capacity/archive-v3-capacity-policy-v2.template.json` define a restricted-JCS,
preauthorization-only 32-GiB contract. Despite the historical `phase1` string in its contract ID,
this is not Phase-1 canary eligibility: that advisory path separately requires the database plus
worst-case WAL/SQLite/model working set to remain below 4 GiB and below 25% of measured VM memory.
The verifier itself fixes 32 GiB, exact three-year
workloads/screen ratios, every ADR metric context and workload/fault/test scenario,
paired 1-GiB/32-GiB raw write traces with derived amplification, ANN coverage, and
conditional provider-recovery deletion.
A policy can only tighten numeric limits and freshness maxima. The checked-in template has
deliberately unusable anchors and is not evidence.

When a separately reviewed release policy contains real out-of-band anchors, an operator
may check the restricted canonical JSON report with its detached digest, DER-validated P-256
public-key metadata, and hash-bound request, replay, time, and artifact wrappers. Those
wrappers do not authenticate their claims. The command requires an absolute `openssl`
path whose regular-file bytes match the policy-pinned SHA-256; the verifier then executes
a private copy with a restricted environment:

```sh
python3 scripts/verify_archive_v3_capacity_report.py \
  --report /secure/evidence/report.json \
  --report-digest /secure/evidence/report.sha256 \
  --signature /secure/evidence/report.sig.b64 \
  --public-key-metadata /secure/evidence/pinned-public-key.json \
  --policy /secure/release-policy.json \
  --verification-request /secure/evidence/request.json \
  --replay-ledger /secure/evidence/replay-ledger.json \
  --time-assertion /secure/evidence/time-assertion.json \
  --release-manifest /secure/evidence/release-manifest.json \
  --provenance /secure/evidence/provenance.json \
  --sbom /secure/evidence/sbom.json \
  --fixture-manifest /secure/evidence/fixture.json \
  --test-plan /secure/evidence/test-plan.json \
  --test-config /secure/evidence/test-config.json \
  --environment-attestation /secure/evidence/environment.json \
  --openssl /secure/toolchain/openssl
```

The verifier emits `preauthorization_only: true`, `authority: false`, and six unsatisfied
activation blockers. It does not establish a rollback-protected challenge or ledger,
authenticated time, cryptographic provider/SLSA provenance or environment attestation, or
independent measurement authenticity. A future separately reviewed deployment controller
must satisfy those blockers and transactionally consume the receipt before authority.

The production Docker build has no permissive configuration defaults. Supply every
deployment value; empty values, non-HTTPS `BASE_URL` or `WEB_ORIGIN`, an invalid WIF
provider audience, or `ENCLAVE_ACME` other than `1` fail the build.

The four `ARCHIVE_WITNESS_*` Docker arguments below are low-level image inputs. The local
pipeline never accepts them from operator configuration or command-line overrides: both build selection
and release verification derive them through one strict parser from the reviewed
[`config/archive-witness-probe.json`](config/archive-witness-probe.json). The checked-in
file is exact `off` with an empty namespace.

The eight `ARCHIVE_V3_*` runtime arguments are likewise derived only from
[`config/archive-v3-shadow-runtime.json`](config/archive-v3-shadow-runtime.json). The
checked source carries the complete canonical `durable-fleet-wal-v1` provider tuple and an
empty canary commitment. That active form remains eligible only for an exact
`vX.Y.Z-archive-v3-wal.N` production image; evaluation and `main` pretag builds force it off,
an exact WAL tag with an off profile fails, and no operator, repository variable, or dispatch
input can override it. Under that signed profile, each one-shot runtime consumes only an opaque
archive binding already minted and validated by encrypted Control, allowing startup and Genesis
to converge every account without accepting an archive identity from a route or environment.
Construction itself performs no provider I/O and each launched owner remains single-archive.

```sh
docker build --platform linux/amd64 \
  --build-arg KMS_PROJECT=my-project \
  --build-arg KMS_LOCATION=us-central1 \
  --build-arg KMS_KEY_RING=my-keyring \
  --build-arg KMS_KEY=my-kek \
  --build-arg GCS_BUCKET=my-enclave-indexes \
  --build-arg GCS_MEDIA_BUCKET=my-enclave-media \
  --build-arg GCS_LEGACY_MEDIA_BUCKET=my-enclave-indexes \
  --build-arg ARCHIVE_WITNESS_SHADOW_MODE=off \
  --build-arg ARCHIVE_WITNESS_PROJECT_ID= \
  --build-arg ARCHIVE_WITNESS_PROJECT_NUMBER= \
  --build-arg ARCHIVE_WITNESS_DATABASE_ID= \
  --build-arg ARCHIVE_V3_SHADOW_RUNTIME_MODE=off \
  --build-arg ARCHIVE_V3_ARCHIVE_BUCKET= \
  --build-arg ARCHIVE_V3_ARCHIVE_GCS_PROJECT_NUMBER= \
  --build-arg ARCHIVE_V3_REGISTRY_KMS_VERSION= \
  --build-arg ARCHIVE_V3_WITNESS_PROJECT_ID= \
  --build-arg ARCHIVE_V3_WITNESS_PROJECT_NUMBER= \
  --build-arg ARCHIVE_V3_WITNESS_DATABASE_ID= \
  --build-arg ARCHIVE_V3_ARCHIVE_BINDING_COMMITMENT= \
  --build-arg RUN_SA_EMAIL=legacy-caller@my-project.iam.gserviceaccount.com \
  --build-arg ENCLAVE_AUDIENCE=https://api.example.com \
  --build-arg ATTEST_STS_AUDIENCE='//iam.googleapis.com/projects/123456789/locations/global/workloadIdentityPools/my-pool/providers/confidential-space' \
  --build-arg GOOGLE_DESKTOP_CLIENT_ID=desktop-id.apps.googleusercontent.com \
  --build-arg GOOGLE_IOS_CLIENT_ID=ios-id.apps.googleusercontent.com \
  --build-arg GOOGLE_WEB_CLIENT_ID=web-id.apps.googleusercontent.com \
  --build-arg SIGNUP_LIMIT_PER_DAY=25 \
  --build-arg BASE_URL=https://api.example.com \
  --build-arg WEB_ORIGIN=https://app.example.com \
  --build-arg REVIEWER_AUTH_API_KEY=public-identity-platform-api-key \
  --build-arg REVIEWER_AUTH_UID=precreated_reviewer_uid \
  --build-arg REVIEWER_AUTH_EMAIL=reviewer@example.com \
  --build-arg VERTEX_PROJECT=my-project \
  --build-arg VERTEX_LOCATION=us-central1 \
  --build-arg VERTEX_MODEL=gemini-3.5-flash \
  --build-arg ENCLAVE_ACME=0 \
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
| `GCS_BUCKET` | Legacy/reference encrypted database bucket; not a PostgreSQL serving authority |
| `GCS_MEDIA_BUCKET` | Current encrypted bounded-retention raw-media bucket; new media is written here |
| `GCS_LEGACY_MEDIA_BUCKET` | Required migration-only media read/delete bucket; must exactly equal `GCS_BUCKET` for Phase-0 |
| `ARCHIVE_WITNESS_SHADOW_MODE`, `ARCHIVE_WITNESS_PROJECT_ID`, `ARCHIVE_WITNESS_PROJECT_NUMBER`, `ARCHIVE_WITNESS_DATABASE_ID` | Non-authoritative Firestore transport probe derived only from checked-in `config/archive-witness-probe.json`. It starts exact `off`/empty; evaluation and main stay off, operator configuration/commands cannot override it, and `probe-v1` requires a complete named namespace plus exact `vX.Y.Z-witness-probe.N` prerelease. Its bounded redacted result grants no startup, health, rollout, or archive authority |
| `ARCHIVE_V3_SHADOW_RUNTIME_MODE`, `ARCHIVE_V3_ARCHIVE_BUCKET`, `ARCHIVE_V3_ARCHIVE_GCS_PROJECT_NUMBER`, `ARCHIVE_V3_REGISTRY_KMS_VERSION`, `ARCHIVE_V3_WITNESS_PROJECT_ID`, `ARCHIVE_V3_WITNESS_PROJECT_NUMBER`, `ARCHIVE_V3_WITNESS_DATABASE_ID`, `ARCHIVE_V3_ARCHIVE_BINDING_COMMITMENT` | Image-bound ADR-0022 runtime claim derived only from checked-in `config/archive-v3-shadow-runtime.json`. `off` requires every fragment empty. The canonical-tag-only `durable-fleet-wal-v1` form fixes all provider coordinates, requires the retired canary commitment empty, and consumes only opaque bindings from encrypted Control. Startup reconstructs every selected WAL authority and Genesis creates new selected archives; each owner remains single-archive and Store exposes only routed settled reads and sealed submits. |
| `RUN_SA_EMAIL` | Google service-account identity accepted by legacy routes |
| `ENCLAVE_AUDIENCE` | Exact `aud` expected on legacy caller ID tokens; normally the public HTTPS API URL |
| `ATTEST_STS_AUDIENCE` | Internal WIF provider resource for KMS STS exchange; never a public token audience |
| `GOOGLE_DESKTOP_CLIENT_ID`, `GOOGLE_IOS_CLIENT_ID`, `GOOGLE_WEB_CLIENT_ID` | End-user Google OAuth audiences |
| `APPLE_TEAM_ID`, `APPLE_KEY_ID` | Optional Apple developer team/key identifiers; atomic with every Apple client ID |
| `APPLE_IOS_CLIENT_ID`, `APPLE_MACOS_CLIENT_ID`, `APPLE_WEB_CLIENT_ID` | Exact Apple audiences `com.kioku.ios`, `com.kiokuu.app`, and `com.kiokuu.web`; all five Apple values are set together or Apple auth stays off |
| `APNS_TEAM_ID`, `APNS_PRODUCTION_KEY_ID`, `APNS_SANDBOX_KEY_ID` | Required production ready-alert provider identifiers; production and sandbox keys remain separated and are fetched from Secret Manager |
| `ADMIN_USER_IDS` | Nonempty comma-separated stable owner UUIDs for margin reporting; owner-only reporting, not a sign-up gate |
| `SIGNUP_LIMIT_PER_DAY` | Required positive integer. Service-wide ceiling on new accounts per UTC day, shared by every sign-in path. Signup is open, so this is the only bound on account creation; there is no default and a missing or non-positive value fails the build |
| `BASE_URL` | Public HTTPS API origin, OAuth issuer, and basis of the public attestation audience |
| `WEB_ORIGIN` | Single HTTPS browser origin allowed by CORS |
| `BILLING_SERVICE_URL`, `BILLING_SERVICE_AUDIENCE` | Exact matching HTTPS billing-service origin and Google OIDC audience |
| `BILLING_ENFORCEMENT_MODE` | Image-baked recording rollout mode: `shadow` observes without blocking, while `enforce` rejects new capture without an active allowance lease |
| `REVIEWER_AUTH_API_KEY`, `REVIEWER_AUTH_UID`, `REVIEWER_AUTH_EMAIL` | Optional Google Identity Platform reviewer account; set all three or none. Values are image-baked and exact matched; never supply the password |
| `VERTEX_PROJECT`, `VERTEX_LOCATION`, `VERTEX_MODEL` | Vertex episode inference configuration; the model is a 1–128 byte billing-safe name using only ASCII letters, digits, `.`, `_`, `:`, or `-` |
| `QUOTA_VERTEX_OUTPUT_TOKENS_PER_DAY` | Optional per-user UTC-day maximum-output reservation ceiling; defaults to `524288`. Each request reserves its full configured output maximum before Vertex is called and fails closed when exhausted |
| `PERSISTENCE_BACKEND` | Production is exactly `postgres`; unknown or legacy values fail the release configuration gate |
| `POSTGRES_SCHEMA_MODE`, `POSTGRES_MAX_CONNECTIONS` | Serving images verify schema version and use the bounded per-process pool; only the explicit one-shot migrator applies DDL |
| `HEALTH_PORT`, `DRAIN_TIMEOUT_SECONDS` | Content-free wildcard-bound fleet probe port and bounded SIGTERM drain window |
| `ENCLAVE_ACME`, `ENCLAVE_ACME_DIRECTORY`, `ENCLAVE_ACME_CONTACT` | Fleet production disables process-local ACME and loads one shared Secret Manager certificate/key generation; the directory/contact remain fixed inert configuration |
| `ENCLAVE_ALLOW_LEGACY_BLOBS` | Strict `0` normally; temporary `1` only in a reviewed migration image |
| `ENCLAVE_KMS_VIA_ATTESTATION` | Hardcoded to `1`; not operator-configurable |
| `PORT` | The only launch-time override; application TLS listen port, default `8080` |

The ADR-0036 recording bucket is not a mutable environment input. The binary derives its
exact name as `${KMS_PROJECT}-enclave-recordings`, rejects equality with the index/current/
legacy media buckets, and constructs the separate provider only from the same fixed
attested storage boundary. The adapter is still insufficient to activate the feature:
durable write/read authority additionally requires schema epoch 2 to be minimum-servable.

The Google web OAuth secret, optional Apple login `.p8` key, and environment-separated
APNs provider `.p8` keys are fetched at runtime from Secret Manager. Production startup
fails closed if the APNs identifiers or either provider key are unavailable; evaluation
may explicitly omit the complete APNs group. Apple refresh authorization is stored per issuing Apple client in the
encrypted control database so deletion can revoke every retained platform grant. The reviewer
password remains only in Google Identity Platform, the review portal, and the operator's
versioned `kioku-openai-reviewer-password` secret in project `kioku-joerodriguez`. JWT
signing secrets are generated and stored in the KMS-protected control database; neither
password nor signing secret is a Docker build argument or launch metadata value. Static
`ENCLAVE_TLS*` variables exist for debug/custom bootstrap paths but are neither accepted
production build arguments nor launch-policy overrides.

Provider pacing, claims, circuit state, quotas, and request admission are durable and
fleet-wide in PostgreSQL. A production roll requires `scripts/release.sh --roll` to match
a reviewed deployment commit and the canonical inventory/digest of every Terraform root
source. The pinned source defines the staged scale-to-zero regional MIG and reserved
public address; the
checkout must be clean, and the exact seal is bound before network access and
rechecked at the roll boundary. Release invokes only the pinned tracked
`scripts/local-operations.sh` and passes that seal through; the deployment owner
recomputes it after acquiring the production-infrastructure lock and before GCP
credentials, planning, or apply. Any deployment-source change requires a reviewed
pin update. Release stages must prove zero old instances before changing the one
KMS-authorized digest; ordinary serving then keeps at least two PostgreSQL-backed members.

## Local verification and release evidence

GitHub Actions is disabled. `scripts/local_image_pipeline.py` reuses the reviewed hosted
job's formatting, locked tests, all-target Clippy, RustSec audit, SBOM, and fixed-high
vulnerability scan locally. It accepts only a non-repository, regular mode-0600 configuration
file without shell evaluation, snapshots those bytes once, freezes and rechecks a Git
archive, and requires a reviewed/pinned native Linux/amd64 BuildKit worker with bounded
free-space/cache checks. Both native and explicitly acknowledged emulated paths emit an
exact OCI archive without daemon loading, scan that archive before requesting short-lived
impersonated credentials, quarantine and rehash the scanned bytes, and promote that exact
manifest with Skopeo's exact auth file, digestfile, and preserve-digests checks.
The quarantine is copied and fsynced through a private O_EXCL file, reopened read-only,
validated, unlinked, and passed to Skopeo as an inherited `/dev/fd` descriptor; no
quarantine pathname or writable descriptor remains. Its mode, inode, file hash, and
manifest digest are checked before and after the copy.
Evidence creation receives the SBOM and scan hashes from the scan receipt and reads each
asset through a stable no-follow descriptor; the release bundle verifier reopens and
rehashes those exact assets before publication.
Allowlisted runtime configuration reaches only the final Docker layer through an ephemeral
BuildKit secret; its non-secret content hash binds that late cache and it is never placed in
argv or Docker history. If native hardware is unavailable, the fallback requires explicit
opt-in and a second confirmation for release tags; it is labeled in evidence and never
presented as a warm native run. Receipts use a mode-0600 run lock, content-addressed names,
artifact/scan rehashes, and idempotent push/evidence reuse. A detached frozen release commit
is accepted only with a separately signed coordinator advancement receipt proving it is an
ancestor of freshly fetched `origin/main`; ordinary releases still require exact local-main
tip parity.
Native preflight reads `docker buildx ls --no-trunc --format '{{json .}}'`, pins
`KIOKU_NATIVE_BUILDER_NAME` and `KIOKU_NATIVE_BUILDER_ID`, requires exactly one nested
worker, and revalidates that worker's full endpoint/transport/identity binding after the
build; the same reviewed Buildx name is passed to the build. SSH workers additionally require a
current-user-owned `DOCKER_SSH_KNOWN_HOSTS` file containing the pinned
`DOCKER_SSH_HOST_KEY_SHA256` and a `DOCKER_SSH_COMMAND` with
`StrictHostKeyChecking=yes` and that exact `UserKnownHostsFile`, while TCP workers require `DOCKER_TLS_VERIFY=1`, a private
`DOCKER_CERT_PATH`, and its `DOCKER_BUILDER_CA_SHA256`. It probes the selected worker's
root filesystem with a no-network, no-cache BuildKit build bound to the exact named
builder and the digest-pinned probe image; it never uses the client's default-daemon
`docker run` filesystem as a proxy. It rejects the run below the bounded cache reserve.
The emergency fallback is therefore explicit and fail-closed when the reviewed native
worker or its disk probe is unavailable; it remains an OCI/digest-preserving path rather
than a mutable local image-tag export.
The audit retains the documented
`RUSTSEC-2023-0071` exception because this service verifies RS256 signatures but performs
no RSA private-key operation.

The pushed digest, tagged source commit, immutable source-archive hash, configuration hash,
Dockerfile/Cargo.lock/SBOM/scan hashes, tool versions, and timestamps form canonical local
evidence. A separate
mode-0600 Ed25519 private key signs those exact bytes; verification requires an externally
pinned public-key fingerprint. Two reviewed publication interfaces are available: standalone
`scripts/release.sh` and the frozen-source `scripts/release_train_enclave.py publish` adapter.
Both fail before mutation unless the signed source tag and local evidence verify; the adapter
also binds the coordinator plan, exact artifact, and frozen detached source. Both disable Git
replacement-object resolution and reject replacement refs, grafts, and ambient repository or
object overrides. Publication captures one annotated-tag object ID, validates its signed embedded
name, signer, and peeled commit, pushes that exact object, and checks the remote object plus peel.
Evidence assets are verified, uploaded, and resume-compared only from one private read-only byte
snapshot. GitHub is used for immutable public release hosting, not execution or build identity.

The fresh generation has two non-reusable publication roles: BOOTSTRAP
`v0.8.35-adr0022-fresh-bootstrap.1` and FINAL
`v0.8.35-archive-v3-wal.1`. Their private operator files must contain the same exact
nonzero lowercase `PRODUCTION_ADR0022_CANARY_IDENTITY_PREPARATION_SHA256` and exactly one
lowercase UUIDv5 as the sole `PRODUCTION_ADMIN_USER_IDS` value. After production-profile
selection those claims are named `ADR0022_CANARY_IDENTITY_PREPARATION_SHA256` and
`ADMIN_USER_IDS`. The pipeline does not create, read, or guess either provider value.
It emits a 50-field schema-10 metadata object whose exact compact insertion-order encoding binds
the reviewed fresh intent, index/media/archive/witness/KMS/runtime-SA/WIF/custom-role coordinates,
those two opaque canary commitments, the checked 0/0/0 schema declaration, archive runtime and
Genesis exact off, and positive signup for BOOTSTRAP. FINAL retains the same
namespace/canary tuple, requires exact 1/1/1, Genesis on, the active runtime and
live one-way binding commitment, and a byte-pinned completed baseline seal.
The BOOTSTRAP tree's FINAL seal pin is deliberately empty, so it remains
FINAL-ineligible even if a caller substitutes the FINAL tag or config. The
signed evidence binds both those raw metadata bytes and
the once-read private configuration bytes; bundle verification derives the two expectations again
from that same snapshot. The synthetic cross-repository fixture is
[`config/adr0022-fresh-schema10-bootstrap-fixture.json`](config/adr0022-fresh-schema10-bootstrap-fixture.json)
(3,094 bytes, SHA-256 `40ce2530b9860133f69ac2d207c0f86165b6971b7207329ed7d09b3a4516e2a9`).
It is a BOOTSTRAP format pin, not production evidence. Generic releases remain
schema 9. `scripts/release.sh --roll` refuses BOOTSTRAP and the generated current
Archive V3 release tag; only the
deployment repository's sealed `adr0022-fresh-launch` owner may roll them.
Direct evidence verification supplies the exact mode-0600 image configuration;
schema 10 derives its fresh bucket
expectations from those hash-bound bytes, while schema 9 retains legacy bucket defaults.

Production is the sole active owner evaluation environment. Signed releases either carry
the exact `eval/voice/owner-only-production.json` declaration and record
`voice_quality_gate: owner_only_unvalidated`, or carry a complete passing real-corpus trio
and record `validated_real_corpus`. The owner-only declaration permits neither external
users nor a voice-quality claim. The former manual `evaluation` build profile remains
available only to reproduce and audit historical isolated images; its runtime is retired,
it cannot become a GitHub Release or production rollout, and it must not be deployed.
Ordinary `main` work and signed `v*` release tags always select the production profile.

There is no hosted CodeQL or dependency-review service after this cost cutover. The local
gate retains RustSec audit, locked dependency resolution, Clippy, the full test suite, and
the image scan; Dependabot continues to propose Cargo and Docker updates without an Actions
ecosystem job. This is an explicit reduction in centralized security reporting, recorded in
`SECURITY.md`, rather than an equivalence claim.

The image-push identity is deliberately not a deployment, IAM, Secret Manager, or KMS
identity. Rolling a VM remains a separate operator action using the digest-qualified image
URI and exact confirmation. The named operator impersonates stage-specific service
accounts with short-lived credentials; no service-account key or repository runner holds
deployment authority.

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

The release contains `enclave-local-build-evidence.json`, its detached `.sig`, the SPDX
SBOM, and the vulnerability scan. Verify the canonical evidence with the separately pinned
public key and fingerprint, then require the exact repository, tag, commit, production
profile, digest-qualified image, file hashes, and successful scan. Both reviewed publication
interfaces perform those checks before publication or rollout; the coordinator adapter also
requires the signed plan and exact handoff receipt.

### 3. Match all anchors

The verified chain is:

```text
Google-signed public attestation token image digest
    == release image digest
    == subject of locally signed canonical build evidence
    == digest authorized by the deployment's KMS condition
```

The release script pins the expected tag-signing fingerprint, compares the standalone
SBOM hash with its signed evidence, and refuses to edit or clobber an existing immutable
public release. GitHub release immutability, tag rules, the pinned build-key fingerprint,
and the operator's deployment controls remain part of the operational boundary.

## Honest limitations

### Build provenance is signed; independent reproducibility is not complete

The Rust builder image is digest-pinned and the embedding model is revision- and hash-pinned.
However, Cargo still downloads unvendored crate sources, apt installs unversioned packages
from mutable repositories, and the local workflow does not perform an independent
bit-for-bit rebuild. Trust in the designated local builder, its signing key, and dependency
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
