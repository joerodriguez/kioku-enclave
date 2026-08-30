# Security

## Scope and trust boundary

This document describes the production PostgreSQL-authoritative Kioku enclave defined by
[ADR-0040](https://github.com/joerodriguez/kioku/blob/main/docs/adr/0040-cloud-sql-postgresql-for-structured-state-and-horizontal-scaling.md)
and tightened by [ADR-0042](docs/adr/0042-postgresql-only-structured-state.md).

In scope:

- the public Rust service running in GCP Confidential Space;
- TLS, OAuth, caller authorization, validation, query, export, and deletion;
- private Cloud SQL PostgreSQL structured state and fleet coordination;
- per-user encrypted large-media/object bytes in GCS;
- attestation-derived KMS authorization;
- horizontally concurrent workers and external-provider effects;
- signed source/image evidence and release admission.

Explicit external trust:

- Cloud SQL's database engine, encrypted storage/backups/PITR, and authorized GCP/database
  administrators can access structured plaintext;
- Vertex processes bounded user content sent for transcription and analysis;
- user-configured webhook destinations receive the fields the user enabled;
- APNs receives content-free notification metadata;
- the billing service receives content-free pseudonymous entitlement/usage events;
- GCP project, IAM, KMS, compute, Secret Manager, networking, and release control planes retain
  their documented administrative power.

SQLite/GCS database authority is not in scope because it is not part of the serving source. There
is no alternate backend, fallback, shadow read, dual write, archive/WAL authority, or recovery path
to it. GCS remains in scope only as the encrypted large-object provider.

## Security invariants

### One structured-state authority

PostgreSQL is authoritative for identity, OAuth, structured memory, search, profiles, quotas,
claims, work queues, effect receipts, exports, retention, and deletion. Every tenant-bearing primary
key, foreign key, and query is account-qualified. Serving images require the expected migration
version and refuse to run DDL; only the separately digest-pinned one-shot migrator can install a
reviewed schema.

Loss of PostgreSQL readiness never enables a local or object-store fallback. Recovery uses a
schema-compatible application image, PostgreSQL restore/PITR, or forward repair.

### Fleet-wide claims and provider effects

Workers use durable PostgreSQL claims with bounded leases, attempt counts, retry times, and stale-
claim fencing. Settlement checks the claim owner and generation in the same authority that selected
the work. Multiple replicas may make progress without process-local singleton assumptions.

For email, push, webhook, media, summarization, and model-usage effects:

- provider intent and the frozen request are persisted before the first provider call;
- a known provider rejection can follow its reviewed retry policy;
- an ambiguous provider outcome is not resent merely because a process restarted or timed out;
- cancellation and account/destination deletion create durable disclosure fences;
- late/stale workers cannot settle or resurrect state after losing their fence;
- restart enumeration and expired-lease takeover are bounded and tenant-qualified.

The release and PostgreSQL contract suites must exercise two-replica contention, lease expiry,
lost-success recovery, no-resend ambiguity, cancellation, deletion/configuration races, and
outcome-save recovery.

### Large-media encryption and object identity

Raw audio, screenshot evidence, and other large objects are stored only as context-bound
AES-256-GCM ciphertext. A random per-user media data-encryption key is wrapped by the approved KMS
key. Authenticated data binds the account, object purpose, and canonical object key. Moving a blob
or wrapped key to another account or purpose fails authentication.

PostgreSQL records the exact object name, generation, digest, length, encryption context, and
ownership. Object access uses exact generation preconditions. Callers cannot choose a bucket,
credential, arbitrary prefix, KMS coordinate, or encryption context. GCS listing is used only for a
bounded, account-owned reconciliation where the contract explicitly requires physical inventory;
it does not establish structured authority.

The image binds one live media bucket. Recordings and other live media domains derive only from the
same reviewed object boundary. Never reuse removed database/index/archive bucket names for media.

### Export and deletion

Export is an authenticated, tenant-qualified, repeatable-read JSON snapshot of selected
PostgreSQL rows, including media inventory metadata. It does not fetch GCS object bytes; full
media-byte export remains an activation blocker. It must not expose another account's row or
misrepresent a failed read as partial success. Export failures are content-free.

Account deletion first commits a durable tombstone that blocks sign-in, new work, retries, and
resurrection. The deletion owner then:

1. fences in-flight work and external effects;
2. revokes retained provider grants where required;
3. deletes exact current and noncurrent owned media generations;
4. reconciles ambiguous object/provider responses by exact readback;
5. transactionally finalizes removal of tenant-qualified PostgreSQL content and derived state;
6. reports completion only after the media purge succeeds and PostgreSQL records completion.

A crash may leave deletion incomplete, never falsely complete. A restarted replica discovers and
continues durable deletion operations. Episode deletion uses the same no-resurrection and replay
principles at episode scope.

The preconfigured synthetic plugin-review account is an operational fixture rather than a user
deletion canary. Its transactionally seeded `reviewer_fixtures` marker refuses account-deletion
initialization before status, session, token, or content state changes. Destructive release tests
must use a separate disposable identity; rotating reviewer credentials must not remove this guard
from the currently configured fixture.

### Authentication and retired routes

Google and Apple subjects are provider-namespaced; accounts are not linked merely by email. Native
Apple authorization requires the reviewed nonce flow. OAuth authorization uses PKCE, explicit
consent, single-use codes, and client-bound refresh-token rotation.

Every user-data route authenticates and authorizes the account before accessing persistence or a
provider. Retired `/v1/*`, `/api/sync/batch`, and retired screenshot-upload routes preserve their
published authenticate-before-`410 Gone` behavior and perform no user-state mutation or provider
effect. `/v1/attestation` is separately public and active.

### TLS, readiness, liveness, and drain

TLS terminates in the Confidential Space workload. Every production replica loads the same exact
reviewed certificate and key generation from fixed Secret Manager coordinates at startup. Missing,
malformed, or mismatched TLS material fails startup. The rustls configuration and
attestation-bound leaf fingerprint are immutable for that process; renewal is an ADR-0041 staged
fleet rollout, and there is no in-process certificate hot-swap path. The launch policy permits only
`PORT` as a metadata override; security-relevant infrastructure and identity coordinates are not
launch-time choices.

`/readyz` is content-free and requires the expected PostgreSQL schema plus serving prerequisites.
`/livez` is independent so the platform can replace a wedged process even during a database outage.
On SIGTERM, readiness closes first and new HTTP admissions stop. The bounded HTTP drain window
allows admitted requests and effects to settle or release safely before exit. Background
schedulers remain PostgreSQL-lease-safe and may continue claiming work until process termination.

### Attestation and KMS

The public attestation endpoint requests a Google-signed Confidential Space token whose audience is
the public verifier URL and whose nonce binds the active leaf-certificate fingerprint. It never
returns the internal STS-audience token used for KMS credentials.

KMS access uses a short-lived credential derived from an attestation token through the exact
Workload Identity provider. There is no metadata-service KMS credential fallback. KMS IAM should
admit only Confidential Space workloads at the approved image digest(s). ADR-0041 permits at most
the exact predecessor/candidate pair during a compatible rollout and retires the predecessor only
after homogeneous-candidate proof.

An attestation token proves workload measurements and claims, not that an operator cannot later
change project policy. Review all project/key IAM bindings, inherited roles, service-account
impersonation paths, and compute/deployment authority.

### Provider input and egress controls

Vertex requests are bounded before dispatch by per-request output limits and durable daily model-
usage reservations. Timeout retains the reservation because the provider may have completed
billable work. Automatic workers do not regenerate completed historical results.

Webhook requests freeze destination, headers, signing key reference, and body before first send.
Destinations must be public HTTPS; redirects, ambient proxies, loopback, private, local, link-local,
metadata, and documentation networks are rejected. Destination deletion removes frozen disclosure
state before the destination disappears from user-visible configuration.

APNs notifications are content-free. Environment-separated provider keys come from Secret Manager.
Email and push workers share the same durable effect-fence requirements as webhooks.

MCP responses apply their documented sensitive-data query refusal and response redaction. These
controls do not change the owner's normal authenticated REST/search behavior.

### Logging and errors

Logs may contain bounded operational identifiers, counts, durations, status classes, release
coordinates, and content-free claim outcomes. They must not contain transcript/OCR text, prompts,
summaries, raw URLs with query/fragment, media bytes, embeddings, keys, tokens, provider secrets,
database URLs, or plaintext error bodies from external services.

Public authentication, readiness, provider, export, and deletion failures are stable and content-
free. Detailed provider/database errors remain inside the protected operational boundary and must
still be redacted before logging.

## Threat actors and mitigations

### T1 — Cloud-project administrator or compromised deployer

An administrator can change IAM, compute metadata, Secret Manager, Cloud SQL, KMS policy, or the
deployed image. Digest-qualified images, signed evidence, KMS conditions, bounded deployment roles,
saved-plan apply, availability monitoring, and public readback make unauthorized changes detectable
and reduce standing access. They do not cryptographically remove control-plane authority.

### T2 — Compromised client token

A valid token can access only its account-qualified rows and exact owned objects. Rate, concurrency,
quota, retention, export, and deletion checks remain server-side. Token compromise can expose that
account until expiry/revocation; short lifetimes and refresh rotation limit the window.

### T3 — Remote exploit in the service

The image is a static `scratch` container with no shell or package manager, minimal launch
overrides, bounded parsers, strict provider destinations, and locked dependencies. An exploit in the
attested process could access plaintext and credentials available to that process; attestation is
not a sandbox within the application.

### T4 — GCS object substitution or compromise

Object names/generations and encryption context are PostgreSQL-qualified; AEAD authentication and
KMS wrapping detect cross-account/purpose substitution. A GCS attacker can delete or withhold
ciphertext and cause availability loss. Versioned/noncurrent objects remain deletion scope, not a
rollback authority.

### T5 — PostgreSQL compromise

Cloud SQL contains structured plaintext. Network isolation, TLS, least-privilege roles, parameterized
queries, account-qualified schema/queries, encrypted backups, and audited admin access reduce risk.
They do not provide cryptographic confidentiality from authorized database administrators.

### T6 — Hypervisor or memory inspection

Confidential Space with AMD SEV protects guest memory from ordinary host inspection and binds the
workload measurement. Residual risks include hardware/firmware vulnerabilities, side channels,
availability attacks, and the broader cloud control plane.

### T7 — Source, dependency, or release tampering

Locked dependencies, a digest-pinned builder, source-archive freezing, named-worker verification,
OCI quarantine, SBOM, scan, RustSec audit, signed annotated tags, external Ed25519 evidence, immutable
GitHub releases, and digest readback protect the release chain. Git replacement refs/grafts and
ambient repository/object overrides are refused.

The build is not independently reproducible. Cargo sources are not vendored and some upstream
package repositories are mutable; trust remains in the designated builder, keys, and dependency
delivery.

## Release security

The exhaustive release gate must include:

- every checked-in Python/shell contract;
- formatting, full locked Rust tests, and all-target Clippy;
- a non-skippable real PostgreSQL 17 contract run;
- RustSec audit, SBOM generation, and fixed-policy vulnerability scan;
- exact OCI archive quarantine and registry digest readback;
- canonical schema-11 metadata binding required serving-schema verification and detached evidence
  signature verification.

Compatible runtime releases follow ADR-0041: predecessor/candidate KMS admission, staged canary,
independent availability monitoring, at least two ready PostgreSQL-backed members with zero
unavailable replacement, homogeneous-candidate proof, predecessor retirement, and a final no-change
Terraform plan. Scale-to-zero is allowed only for an explicitly reviewed incompatible change.

Required receipts include exact source/tag/image digest, KMS binding, PostgreSQL authority/schema
readiness, member inventory/zones, drain/availability observations, provider no-op/effect probes,
and the final plan result. A failed check stops the rollout; it does not authorize fallback.

## Residual risks

- Cloud project and database administrators remain trusted for structured plaintext and policy.
- Vertex and user-configured destinations process data outside the attested workload.
- Stable account identifiers and content-free timing/usage telemetry remain linkable metadata.
- Attestation and signed provenance do not equal independent reproducibility.
- Confidential computing reduces host-memory exposure but cannot guarantee availability or eliminate
  hardware/firmware/side-channel risk.

## Reporting vulnerabilities

Use GitHub's private
[security advisory form](https://github.com/joerodriguez/kioku-enclave/security/advisories/new).
Do not publish exploit details in a public issue. Include affected source/release digest, impact,
reproduction details that do not contain user data, and a secure contact for coordinated disclosure.
