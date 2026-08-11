# Security

## Scope

`kioku-enclave` is the production Kioku backend, not only a storage data plane. The
same attested Rust process terminates TLS and implements Google/Apple authentication, token issuance,
device sync, MCP and REST queries, account export/deletion, quotas, summarisation, and
encrypted persistence. This threat model therefore includes those control-plane
surfaces.

### In scope

- Confidentiality and integrity of uploaded audio, screenshots, timestamped capture and
  browser metadata, transcripts, OCR text, episode data, learned identity/voice state,
  and OAuth credentials handled by this service.
- TLS transport to public clients and to Google APIs.
- OAuth, bearer-token, and legacy service-identity authentication and authorization.
- Per-user isolation, export, deletion, quotas, and abuse controls.
- The KMS/DEK hierarchy and encrypted GCS objects.
- Confidential Space attestation, image-digest authorization, and the public release
  evidence used to audit a running image.
- The repository's CI, dependency scanning, image scanning, provenance, and release
  process.

### Out of scope or accepted external trust

- The macOS client, which is a separate binary with its own threat model.
- Paddle payment processing, tax, invoices, subscription webhooks, and catalog pricing
  occur in the external monorepo billing service. The enclave's pseudonymous metering,
  entitlement enforcement, checkout/portal facade, and owner authorization are in scope.
- CPU-level microarchitectural side channels. Confidential Space provides VM memory
  encryption, not complete Spectre-class protection.
- **Vertex Gemini inference confidentiality.** Audio transcription/diarization,
  screenshot understanding, identity/fact evidence extraction, settled-episode transcripts, OCR,
  app/window/URL metadata, browser-tab metadata, and summarisation send bounded user
  content from this process to Vertex under Google's applicable enterprise terms. The
  privacy claim is “attested enclave + Google Vertex inference,” not enclave-only
  inference.
- **User-configured webhooks.** A finalized-episode event leaves the TEE only after a
  user adds an HTTPS destination. Events are content-free by default; full brief content
  is a separate opt-in and is then processed by that destination outside Kioku's trust
  boundary.

## Security invariants

- Production never serves the application over plaintext HTTP. The production image
  requires `ENCLAVE_ACME=1`; boot waits for a usable certificate, and a non-debug build
  without TLS refuses to start. Plain HTTP is available only in a debug binary with
  `ENCLAVE_TEST_MODE=1`.
- The Confidential Space launch policy permits only `PORT` to be changed at launch.
  KMS, GCS, caller identity, OAuth, TLS, attestation, and migration settings are baked
  into the image and therefore covered by its digest.
- CI selects exactly one complete image configuration before Docker runs. Manual
  evaluation builds never inherit production values, are marked with an `eval-` tag and
  metadata profile, cannot become signed releases, and may run only with an isolated
  service account, KMS key, buckets, hostname, and attestation binding that have no
  production data access. The operator has retired that isolated runtime; production is
  now the only active owner evaluation environment.
- Production selection fails closed unless billing enforcement remains `shadow`. The
  selected mode is preserved in schema-v3 release metadata and rechecked by the release
  script, so a later configuration clear cannot hide an enforcement change before
  native clients are ready.
- KMS encrypt/decrypt uses an attestation token exchanged through the configured WIF
  provider. There is no VM-service-account credential fallback for KMS.
- A token returned by the public `/v1/attestation` endpoint uses the HTTPS verifier URL
  `${BASE_URL}/v1/attestation` as its audience. It never uses
  `ATTEST_STS_AUDIENCE`: a WIF-audience token is an STS bearer credential and must not
  leave the enclave.
- Decrypted databases exist only in the `/tmp` Confidential Space tmpfs and in process
  memory. User content and key material must never be logged.
- Archive storage telemetry is process-aggregate and content-free. Its in-process state
  and structured events have no user/archive IDs, object names or paths, URLs, queries,
  content, keys, per-user labels, or timestamps sourced from user records. Only fixed
  byte/latency/ratio buckets and aggregate save outcome counters are permitted.
- Capacity fixtures contain deterministic numeric shapes only. Generated records and
  sparse files stay under ignored `target/` output or outside the checkout; no captured
  content, realistic text/media, user identifier, object path, biometric vector, or key
  may be introduced as capacity input.
- Legacy encrypted blobs are rejected unless a reviewed migration image explicitly
  bakes in `ENCLAVE_ALLOW_LEGACY_BLOBS=1`.
- Unified episode-analysis requests contain text and metadata only. Code that builds a Vertex
  request must not load an image object, image bytes, a signed image URL, or a local image
  path. Cloud Screenshot Evidence consent controls pixel sync, not text inference.
- Voice embeddings, sample diagnostics, robust profile representatives, biometric
  match scores, and the identity graph remain inside the encrypted per-user database.
  They are never sent to Gemini, returned by a public API, emitted in logs/metrics, or
  compared across users. Candidate names supplied to Gemini are bounded spelling
  vocabulary only and are never accepted as identity evidence by themselves.
- Automatic biometric enrollment is quality-gated and versioned. Short samples are
  match-only, contaminated samples are quarantined, same-name people remain separate
  opaque identities, and ambiguous/conflicting evidence must abstain rather than
  overwrite accepted identity history.
- Voice-profile merge/split work is an append-only derivation inside the encrypted
  user database. Proposals are bounded, scorer/version bound, same-space/domain
  checked, identity-conflict checked, and transactionally stale-checked before apply.
  Source profiles and assignment history are retained; reversal fails closed if a
  result acquired later samples. No similarity threshold can auto-apply a proposal
  until the hash-bound real-audio release corpus has calibrated that scorer version.
- A signed release may carry the exact `owner-only-production.json` marker only while
  `external_users` is zero and `voice_quality_claims_allowed` is false. Release metadata
  then records `owner_only_unvalidated`. The marker must be removed—and the complete
  real-corpus trio must pass—before any external user is allowed or any voice-quality
  claim is made. The marker and real evidence may never coexist.
- Validated voice-quality releases require schema-v3 evidence derived by the public
  reducer plus a schema-v2 source manifest. Separately hashed media/label/bundle/
  augmentation artifacts, licensed-playback lineage, physical-capture assertions,
  authorization hashes, and exact device/UI routes fail closed before scoring. The
  reducer pins the evaluated image/source/model/scorer plus export and post-delete
  artifact hashes, derives all release counters from opaque timing and
  exact record sets. Every predicted speaker has exactly one identity-decision row;
  every reference speaker has exactly one case; and a case's predicted person/state
  must match the hypothesis chosen by the scorer's deterministic global diarization
  mapping. The reducer rejects names, transcripts, URLs, paths, embeddings, raw scores,
  unknown fields, modified derived values, and legacy hand-authored real aggregates.
  The offline derivation command performs no network access, refuses artifact/output
  directories inside the public checkout, verifies both media and label artifacts,
  extracts only an exact traversal-free `.tar.gz` member in memory, accepts only bounded
  mono 16-kHz PCM16 input, and refuses to replace a different output. Its private recipe,
  restricted media, opaque labels, receipt, and authorization documents remain outside
  Git; only the later content-free cases/report may be committed.

## Key hierarchy and encrypted objects

```text
Cloud KMS KEK
│  KMS IAM grants decrypt only to an attestation-gated WIF principalSet:
│    assertion.swname == "CONFIDENTIAL_SPACE"
│    "STABLE" in submods.confidential_space.support_attributes
│    attribute.image_digest == <approved release digest>
│
└─► KMS-wrapped DEK
    │  The wrapped DEK is stored with the corresponding GCS object.
    │  Plaintext DEKs exist only in enclave memory.
    │
    └─► context-bound AES-256-GCM blob (v2)
        [ "KIOKU-BLOB" || 0x02 ][ 12-byte nonce ][ ciphertext || tag ]
```

Version 2 uses AES-GCM Additional Authenticated Data containing a domain separator and
the object's logical identity. User databases are bound to their exact
`indexes/{user_id}.db.enc` name, raw capture and screenshot evidence objects are bound to
both the authenticated user and exact media object key. New selected screenshot evidence is
restricted to `raw/{user_id}/evidence/{opaque_key}.enc`; legacy `media/{opaque_key}` rows
remain readable and deletable until normal retention or account deletion. Control/ACME state uses fixed,
distinct contexts.
Moving ciphertext and its wrapped DEK to another object or user therefore fails
authentication.

User databases, the control database, ACME state, and media evidence are rewritten
to v2 immediately when successfully opened by an explicitly enabled migration image.
Strict images default to `ENCLAVE_ALLOW_LEGACY_BLOBS=0`. The migration is one-way; see
[`RELEASING.md`](RELEASING.md#one-time-legacy-blob-migration) before upgrading a
### ADR-0022 archive-v3 foundation is inactive

The offline `scripts/run_archive_capacity_harness.py` creates deterministic,
content-free SQLite smoke databases only outside the checkout or under ignored `target/`.
Its exclusive run receipt rejects foreign/symlinked output and incompatible resume state.
Its reports permanently classify as non-evidence (`release_evidence: false` and
`sqlite_local_evidence: false`), and full mode fails closed. It cannot grant archive-v3
authority or evidence the production image/VM, backend, VFS, witness, cache/concurrency,
fault, deletion, lifecycle, or 32-GiB release gates.

`src/archive_v3.rs`, `src/archive_v3_journal.rs`, `src/archive_v3_shadow.rs`, and `src/archive_v3_sqlite_vfs.rs` define only audited, unit-tested
format primitives for the future
immutable archive: opaque archive/database/key/object IDs; canonical context-bound
HKDF-SHA-256 subkeys with randomly nonced AES-256-GCM envelopes; bounded root/Merkle decoding; and an
immutable-object backend contract. Key-registry entries are explicitly outside the
archive-DEK AEAD: a canonical plaintext binds domain, archive, archive/media key kind,
and key epoch to the DEK before KMS wrapping, and unwrap must verify those fields before
exposing the key. New DEK holders, KMS plaintext buffers, and derived object-key buffers
zeroize on drop and do not implement revealing debug formatting. Random nonces are encoded
into and covered by each envelope hash, so cross-process reuse of an object context cannot
reuse an AES-GCM key/nonce pair before immutable storage rejects the duplicate. The
process-local duplicate-seal guard is defense in depth, not the nonce uniqueness boundary.
The root-key registry
epoch/object/hash must come from the independent witness so cold recovery can unwrap the
key before decrypting the root. This foundation makes no KMS calls and has no live Store,
SQLite VFS, GCS, witness, route, migration,
export, or deletion wiring. The legacy context-bound v2 database blob remains the sole
production authority. `src/archive_v3_gcs.rs` is likewise inactive: it specifies and
tests a redacted async GCS-shaped transport boundary (conditional immutable creation,
read-after-create equality, bounded canonical-name pagination, and a contract requiring
exact all-generation deletion) plus canonical KMS AAD for bounded registry unwrap. Its
fake verifies delegation and multi-generation absence semantics; provider-level deletion
evidence still requires a live drill. `src/archive_v3_gcs_http.rs` provides a concrete,
caller-token-only REST implementation with exact URL encoding, bounded streamed reads/listing,
generation-zero creates, durable claim CAS, and bounded all-generation deletion. Disabled-policy
deletion succeeds only through an external provider/audit-and-trusted-time drain gate; no such live
gate is wired. The transport intentionally has no metadata-service access, environment constructor,
credentials/runtime/deploy wiring, or authority connection; its provider errors never contain
object paths, IDs, hashes, or cursors. The shadow module
is bounded synchronous capture state only: no
SQLite VFS is registered, and capture failure cannot alter the legacy Store result.
The VFS wrapper is an explicit, non-default installation around SQLite's then-selected default VFS. It forwards the underlying callback result verbatim and invokes the bounded capture state only after successful WAL `xWrite`, `xTruncate`, or `xSync`; no capture condition is returned to SQLite. Its exact owner/canonical-path registry is process-local, bounded, never logged, and retires only after an attached main connection closes. SQLite retains VFS names and raw pointers in open connections, so dropping a wrapper intentionally retains both its registration and small callback allocation until process exit; a hard eight-installation cap bounds this memory-safety measure. Parent files must advertise I/O-method version 3 and its required base callbacks or open fails before capture attaches; optional shared-memory/fetch callbacks retain SQLite's documented fallback behavior. The wrapper is not installed by startup and has no Store, provider, witness, route, runtime replay, recovery, export, deletion, or authority wiring. The bundled SQLite oracle validates commit/rollback behavior, captured-format validation, local replay from a checkpointed database, post-handle `ATTACH` safety, and synthetic exact-code `xWrite`/`xTruncate`/`xSync` failure boundaries with the bundled default VFS; it does not establish every platform or custom parent VFS.

`src/archive_v3_witness.rs` additionally defines a compiled,
in-memory-only content-free witness contract. Non-test bootstrap/advance builders first
read the exact immutable root object back through a provider boundary, authenticate and
decrypt that stored envelope, validate its `ArchiveRoot` against the
full `ObjectContext`, and require one provider resolver to fetch/hash the exact
witness-nominated wrapped key-registry object, pass those same bytes to KMS unwrap, verify
the unwrapped plaintext context, and retain that binding before deriving the
object/hash/parent/database/key/fence commitment.
Fixed-size records durably retain the owner, current/next fencing epoch, server-derived
lease expiry, full predecessor root and key-registry reference, and an append-only
four-stage deletion-evidence chain. Its trusted-clock API never accepts caller-selected
time; tombstoning invalidates ordinary recovery/ownership, while a deletion-only restart
path requires provider authentication on every step, matches the exact durable
worker/operation identity derived from that opaque credential (never from persisted IDs),
and accepts only provider-verified stage proofs whose canonical commitments bind the
archive, operation identity, deletion fence, target state, root, registry, prior evidence,
and provider proof commitment. Database-epoch cutover requires extent authority, derives a
never-reused next epoch from the durable generation/current root, consumes that gate into a
post-cutover state, retains the predecessor, and only then permits legacy retirement. A
durable decoder rejects any lifecycle field combination that could reopen the consumed
gate; this inactive v3 contract deliberately permits only that one bounded cutover. A
registry generation authenticated inside the KMS plaintext prevents key rollback.
Fenced compare-and-advance, direct
large-archive extent shadowing, migration/deletion, database-epoch rollback, and
key-rotation transitions are linearizable only in the test model.
`src/archive_v3_firestore_witness.rs` adds an equally inactive provider-neutral Firestore
metadata boundary: exactly one canonical document per opaque archive, exactly one bytes
field `r` containing the fixed witness codec, read-write transaction begin, exact
transactional batch read, full-record conditional commit, and an exact fresh-read check
after an ambiguous response. It parses Firestore `readTime` as the trusted monotonic
clock and retries only bounded `ABORTED` commits. The inactive boundary rejects `(default)`
and accepts only the documented named-database grammar; a future token source is required
to receive and use the one dedicated `archive-witness-attest/providers/archive-witness` WIF
provider-resource audience on every mint. Batch-get transport is capped before JSON parsing
and accepts exactly one response, while record/base64, transaction, token, `readTime`, and
`updateTime` material are bounded and fail closed. It intentionally has no concrete HTTP
transport, token source (including no metadata-token fallback), IAM, queries/lists/deletes,
additional fields, Store/VFS/route connection, deployment flag, or production authority.
Recovery must fetch only the
exact witness-nominated object/hash and must never use prefix/list discovery. No image may
acknowledge a write from archive-v3 until ADR-0022
Phase 1 shadow recovery, VFS crash/conformance, witness, fault, lifecycle, and capacity
gates have passed and an explicit authority change is reviewed.

The journal foundation uses independently authenticated, page-aligned checkpoint chunks
and a persistent fixed-fanout encrypted manifest tree; neither the manifest root nor any
node grows with database size. Immutable WAL segments repeat the exact SQLite WAL header,
carry the prior rolling-checksum state, and verify every frame salt and checksum. A large
SQLite commit may span many bounded predecessor-linked segments; only the final segment
may contain its commit frame, and the root fixes the exact final reference, WAL generation,
and segment count. Chain validation rejects frame gaps, checksum discontinuity, wrong
predecessors, root-sequence substitution, locally valid orphan candidates, and a commit
marker anywhere but the final frame. These checks do not turn post-commit WAL-file
scraping into a valid capture mechanism: Phase 1 still requires a SQLite VFS shim that
observes the exact `xSync` boundary, plus independent shadow recovery and crash
conformance.

The inactive mutation ledger records a stable opaque operation ID, a domain-separated
canonical request fingerprint, the proposed committed root sequence, an internally
derived exact result digest, and either a bounded inline result or an opaque
entity/version reference. Its owning batch API derives the 64-operation/1-MiB bounds from
the exact canonical mutation bytes and commits domain SQL plus every validated ledger row
in one SQLite transaction; any late failure rolls back both. A matching retry can
reconstruct the prior result, while reuse with another request or result fails closed.
This codec/table is not yet route-wired, witnessed, or eligible as idempotency evidence;
retention and GC remain disabled until source-entity and retry-window semantics are
implemented.

Root objects are explicitly named as candidates. Crashes and CAS races may leave more
than one immutable candidate for a sequence; none has authority unless the independent
witness names its exact object ID and ciphertext hash, and recovery never selects one by
listing a storage prefix.

The foundation refuses a monolithic checkpoint object: each encrypted checkpoint chunk is
at most 1 MiB and each manifest node is at most 32 KiB with fixed fanout. A WAL-bearing
root must still name the checkpoint-manifest base reference, preventing publication of an
unrecoverable WAL chain. Chunking/manifest construction and recovery remain inactive until
their storage/witness fault gates pass.

During the ADR-0022 legacy lifecycle transition, before the first whole-blob overwrite
for each user and UTC day, the service creates or verifies one immutable server-side
recovery copy under `legacy-recovery/{user_id}/YYYY-MM-DD.db.enc`. A generation-zero
initial create has no prior remote state to protect; its first overwrite establishes the
checkpoint. The copy is pinned to the exact currently authoritative source generation,
preserves the wrapped-DEK metadata, and atomically records a protocol marker binding the
source name, generation, size, and CRC32C. Created and pre-existing destinations must
verify against that marker and provider generation/integrity metadata without downloading
or decrypting the database. A checkpoint copy retains the original ciphertext's logical
binding; it is recovery/inventory material, not an independently relocatable blob. The
overwrite is withheld when the required checkpoint cannot be verified. Checkpoint names
and their content-free metadata are included in later export/deletion inventories. Once a
flush begins, any failure before the authoritative generation-checked PUT succeeds fences
the local handle: its next access must retry persistence before request code can observe an
idempotency duplicate and acknowledge it.

At startup, a serial, bounded-memory reconciler also lists only live `indexes/` objects
one page at a time and resolves each listed name through an explicit live-object read
before copying it. It therefore never treats a listed noncurrent generation as current
authority. It creates or
verifies today's named immutable checkpoint with the same source-generation and
destination-create preconditions, retries incomplete passes with bounded backoff, and
reports only aggregate counts/readiness, including the public health readiness field.
Readiness remains false until one error-free scan finishes; this worker does not enable
lifecycle policy or change archive authority.
Checkpoint copy/verification holds the same per-user content-write admission lease as raw
capture. Account deletion first closes that lease, waits every admitted raw PUT and
checkpoint copy to reach a provider outcome, and only then inventories remote objects; a
checkpoint cannot appear after deletion's recovery-prefix scan.
If GCS committed that PUT but its response was lost or the caller was cancelled, the retry's
generation conflict is accepted only after the current object carries the exact same wrapped
DEK metadata and decrypts under that DEK/context to the exact pending SQLite image. A different
or unverifiable current object remains a conflict; reconciliation never overwrites it.

Legacy whole-database persistence tracks a process-local dirty generation around every
SQLite operation. Cumulative row changes include SQL-trigger effects; schema version,
user version, and application ID cover persistent schema/header mutations. A failed
post-operation state check is treated as dirty. The explicit read API also enables
SQLite `query_only`, while extension or FFI mutations can use an unconditional dirty
guard. Successfully persisted generations become clean; failed uploads and detected
open-time migrations remain dirty through retry or eviction. A clean save or eviction
does no checkpoint, plaintext file read, KMS unwrap, encryption, or GCS upload. This is a
write-amplification optimization only: it does not change ciphertext format, authority,
or acknowledgement requirements.

### Legacy Store concurrency (ADR-0022 Phase 0d)

The legacy whole-database blob remains the sole persistence format and authority, but it
no longer places every user's SQLite, filesystem, KMS, and GCS work behind one global
mutex. A brief registry lock now finds or creates a per-user actor and tracks deletion
fences, bounded open-handle reservations, LRU order, and bounded recent-eviction
completion markers. Each actor serializes that user's connection operations, loads,
saves, and deletion. The registry lock is released before SQLite work or any filesystem,
KMS, or GCS await, so a slow user cannot serialize already-admitted work for unrelated
users. Open-handle loading reservations count against `STORE_MAX_OPEN`; successful
eviction flushes before dropping the handle, while a failed flush retains the exact live
connection and temp files and fails the requesting cache miss.

Deletion first closes a per-user content-write admission barrier, then waits for every
already-admitted raw-media PUT (including a request-cancellation-safe owned PUT task) and
checkpoint copy to settle before installing its actor fence and scanning remote objects.
It force-flushes a dirty local SQLite image before any remote delete, so the authoritative
encrypted database durably contains every media reference used by a restart retry. A failed
flush retains the handle and leaves deletion pending; it never drops an unsaved inventory.
After that durable point deletion can release the SQLite slot during slow remote deletes:
the still-retained remote database reconstructs the exact sorted, deduplicated inventory
on every retry without storing object names in the control database.

This is containment, not the later ADR-0022 content-addressed deletion ledger. The actor
fence and recent-eviction completion markers remain process-local, but deletion inventory
does not: it is recovered from the durable encrypted user database. The encrypted control
database persists only a content-free deletion operation: an opaque
random operation ID, `pending`/`failed_retryable`/`physical_complete` status,
machine-readable reason, retry delay, and provider `hardDeleteTime` when GCS reports one.
`DELETE /api/account` returns HTTP 202 until physical completion, and the same tombstoned
authentication is accepted only by that retry route and `GET /api/account/deletion`.
A bounded serial background sweep starts
at boot and retries eligible `deleting` rows, so clients that sign out after any 2xx do not
prevent eventual finalization after provider retention expires. Sweep logs contain only
aggregate outcome counts.

Before each remote attempt, the control operation is durably marked
`content_deletion_attempt_unconfirmed`. That marker remains `pending`: cancellation or a
restart safely retries the ordered Store protocol. If an exact legacy database generation
disappears between listing and either the generation-pinned metadata or media GET,
deletion records `failed_retryable` with reason `legacy_generation_unavailable`. The
512 MiB compatibility-reader cap is also `failed_retryable` until a streaming converter
ships. A restart or later empty listing cannot turn either failed case into completion;
explicit inventory remediation/migration is required. Other KMS, GCS, or
decrypt/inventory failures remain separately pending and retryable and must not be
mistaken for the irreversible missing-generation gap.

The remote database is retained until deletion succeeds, so media references can be
rediscovered after restart, including references that were local-only when deletion began
because deletion force-flushes them before remote work. If all configured handle slots are actively loading/evicting, a new cold user
waits for a slot; and a corrupt database that cannot enumerate deletion media must remain
fenced and retained rather than discard an unknown inventory. These cases do not
reintroduce a registry lock across remote I/O, but they remain capacity/repair limits.
Store diagnostics in this path are content-free and do not emit user IDs or object names.

## Attestation and TLS

The KMS credential path and public verification path deliberately use different
Confidential Space tokens:

1. Internally, `ATTEST_STS_AUDIENCE` is the WIF provider resource. Its token is exchanged
   at Google STS for a short-lived KMS access token and is never exposed by an HTTP
   endpoint.
2. Publicly, `/v1/attestation` returns a non-credential OIDC token whose audience is that
   HTTPS verifier endpoint. The request to the launcher includes the lowercase hex
   SHA-256 fingerprint of the active leaf certificate DER as a nonce. Certificate and
   fingerprint renew together; a request that straddles renewal can mismatch and must be
   retried over a fresh connection. A verifier must validate Google's signature, issuer,
   expiry, audience, nonce, relevant Confidential Space claims, and image digest rather
   than merely decoding the JWT.

TLS terminates inside the attested binary, so no external reverse proxy receives request
plaintext. ACME generates the private key inside the TEE and persists account,
certificate, and key state only as a KMS-wrapped, context-bound encrypted blob. Port 80
serves only the ACME HTTP-01 challenge router; the application is served over TLS on the
configured `PORT`.

## Threat actors and mitigations

### T1 — Malicious operator or cloud-project insider

**Threat:** An operator with broad GCP IAM access attempts to decrypt user data or boot
the approved image with weaker settings.

**Mitigation:** The KEK uses an authoritative decrypt binding containing only the
attestation-gated `principalSet`. Deployment also removes every standing project,
key-ring, and key binding whose resolved role contains direct or delegated KMS decrypt;
this is required because inherited roles such as project Owner can otherwise decrypt even
when the key-local policy contains no human member. A fail-closed rollout guard resolves
predefined and custom role permissions and audits all three policy levels against the
exact live digest. Changing code or baked configuration changes the image digest and loses
the allow binding. The launch policy permits only `PORT`, so an operator cannot replace
KMS coordinates, trusted callers, auth policy, TLS policy, or the legacy-blob gate through
VM metadata.

**Residual risk:** The project has no organization ancestor at which Kioku can administer
an IAM deny policy. A sufficiently privileged project or repository administrator can
change IAM, KMS policy, the rollout guard, or the deployed workload and then authorize a
new path. Removing and continuously auditing standing decrypt grants is containment, not
an operator-independent cryptographic boundary. A literal guarantee against a malicious
administrator with policy-changing authority requires user-held keys or an independently
controlled key-authorization system.

**Operator verification:** inspect project, KMS key-ring, and KEK IAM policies; resolve
every predefined and custom role; and reject both
`cloudkms.cryptoKeyVersions.useToDecrypt` and
`cloudkms.cryptoKeyVersions.useToDecryptViaDelegation` everywhere except the exact
digest-scoped workload principal on the KEK. Confirm that
`roles/cloudkms.cryptoKeyEncrypterDecrypter` has exactly that one member—no `user:`,
`group:`, or `serviceAccount:` member. The key-local check alone is insufficient.

### T2 — Compromised client token or legacy caller

**Threat:** An attacker steals a Kioku bearer token, a Google identity token, an Apple
authorization response, or the
identity of the service account trusted by legacy `/v1/*` routes.

**Mitigation:** Public OAuth validates configured Google audiences and the account
allow-list. Native and browser Apple login verify Apple's signature, issuer, exact
platform audience, expiry, verified email, nonce, and subject, exchange the single-use
code server-side, and never link accounts by email. Native nonces are SHA-256 bound;
browser state/raw nonce and downstream PKCE state are signed and short-lived.
Authenticated routes derive the user from the Kioku token rather
than trusting a caller-supplied identity. OAuth uses PKCE and persisted, single-use
authorization-code state. The first-party dashboard uses one fixed public PKCE client so
normal sign-ins cannot exhaust bounded third-party registration. The directly distributed
Mac app uses a separate fixed public native client whose browser return must be exact
HTTP `127.0.0.1`, include an explicit ephemeral port, use only `/oauth/callback`, and have
no query before the server appends the single-use code and state; lookalike hosts and
paths are rejected. Apple refresh
authorization is held per issuing iPhone/Mac/web client only in the encrypted control
store and every retained grant is revoked before identity deletion. Legacy routes accept only
Google-signed ID tokens with the baked audience and
service-account email; there is no shared-secret or auth-disable fallback. User IDs are
validated before use in paths or object names.

**Residual risk:** A valid legacy caller identity is highly privileged and can select a
user ID on compatibility routes. Remove legacy integrations when downstream clients no
longer require them, and protect that service account accordingly.

### T3 — Remote exploit in the attested service

**Threat:** A malformed request exploits a bug in the exact approved binary.

**Mitigation:** Authentication middleware, bounded request bodies, input validation,
rate limits, quotas, memory-safe Rust, tests, clippy, CodeQL, dependency review, and
vulnerability scans reduce this risk. Attestation proves which code is running; it does
not prove that code is bug-free. Report suspected vulnerabilities privately as described
below.

### T4 — GCS compromise or object substitution

**Threat:** An attacker reads, replaces, or relocates GCS objects.

**Mitigation:** GCS contains ciphertext and KMS-wrapped DEKs. KMS access is separately
attestation-gated. AES-GCM authenticates contents, GCS generation preconditions reject
lost-update races, and v2 AAD binds each blob to its intended logical object and user.
Account deletion enumerates every exact live and noncurrent object generation, deletes
each generation explicitly, and verifies no matching generation remains.

**ADR-0022 inactive checkpoint seam:** the compiled-but-unwired checkpoint module uses
independently authenticated 1 MiB chunks and bounded 256-way manifest nodes. Recovery accepts
only the exact root commitment returned by the witness; it derives every manifest and chunk
context from that root and never selects objects by GCS listing. It checks envelope hashes, AEAD
context, manifest coverage, per-chunk hashes, and the full plaintext hash before atomically
exposing a `/tmp` output. This is not yet an authority path: no Store, SQLite VFS, runtime flag,
provider token, or deployment wiring invokes it.

### T5 — Hypervisor or memory inspection

**Threat:** A co-tenant or hypervisor reads plaintext guest memory or persistent disk.

**Mitigation:** Confidential Space uses AMD SEV memory encryption, and decrypted SQLite
files are created only on the required `/tmp` tmpfs. No plaintext is intentionally
written to persistent disk.

**Residual risk:** CPU-level microarchitectural side channels are not fully mitigated by
AMD SEV.

### T6 — Source, dependency, or build-pipeline tampering

**Threat:** An attacker modifies source, dependencies, Actions, or build inputs so the
published image differs from the reviewed release.

**Mitigation:** Release tags are signed and verified; the release script refuses to
overwrite an existing public release. Third-party Actions and the Rust builder image are
pinned by full digest/SHA. The embedding model is pinned to a repository revision and
verified by SHA-256. CI runs formatting, locked tests, clippy, RustSec audit (with a
documented RSA-verification-only exception for `RUSTSEC-2023-0071`), CodeQL, dependency
review, and an SBOM-based image scan. Cargo-auditable metadata makes statically linked
Rust crates visible in that image SBOM, and CI fails if representative core/native
packages are absent. The credentialed build job accepts only main or `v*` tag refs; the
GCP OIDC provider must additionally constrain immutable repository/owner IDs and the
expected workflow identity. A tagged build publishes GitHub-signed image
provenance, an SPDX SBOM, and a signed SBOM attestation; the release script verifies the
expected repository, workflow, source ref, commit, image repository, digest, and
attestations before publishing or rolling. Verifiers must also authenticate the tag's
signing-key fingerprint against a separately published trusted anchor; signature validity
alone does not establish signer identity.

## Residual risks and limitations

### Source-to-image rebuilds are not yet independently reproducible

The builder image and model are pinned, but Cargo sources are fetched from crates.io
rather than vendored, Debian packages are installed from mutable apt repositories without
snapshot/version pins, and the workflow does not yet demonstrate a bit-for-bit rebuild.
GitHub-signed provenance proves which GitHub workflow claims to have produced an image;
it does not eliminate trust in GitHub Actions or mutable dependency delivery.

Release notes must say “publicly auditable with signed build provenance,” not
“independently reproducible.” Closing this limitation requires vendored Rust sources,
snapshot-pinned OS packages, deterministic build inputs/timestamps, network-disabled
compilation, and independent rebuild comparison.

### Vertex and user-configured webhooks cross the TEE boundary

Audio transcription/diarization, screenshot understanding, identity/fact evidence extraction,
episode summarisation, and evidence verification send bounded content to Google Vertex
Gemini from this process. Google's no-data-retention terms apply, but the data is outside
the Confidential Space boundary while Vertex processes it. Webhook events similarly
leave Confidential Space for the user-selected destination. They are content-free by
default and carry final-brief content only when that destination's explicit option is
enabled. The sender revalidates public DNS addresses on every attempt, pins the validated
address, refuses redirects, signs the exact body, and never logs endpoint paths, payloads,
signatures, or response bodies.

### Pseudonymous billing events cross the TEE boundary

The monorepo billing service receives a random account pseudonym and content-free usage
events over HTTPS authenticated with an exact-audience Google OIDC token. It does not
receive email, Google subject, stable enclave user UUID, capture/episode identifiers, or
model content. The random mapping, lease receipts, and deletion-detach outbox remain
encrypted inside the enclave. This boundary reveals subscription usage and inference-cost
shape; compromise of both databases could link those records.

New capture depends on the billing service in enforce mode: a denial or inactive lease is
HTTP 402, idempotency/early-renewal conflict is HTTP 409, and unavailable durable state is
HTTP 503 before persistence. Screenshots and references require an active lease but do not
consume again. Reads, search, export, and deletion remain ungated. Shadow mode is
temporary and must not log upstream denial detail.

### Stable user identifiers are linkable

Google-primary user IDs preserve their deterministic historical derivation. New
Apple-primary IDs are deterministically derived from a provider-domain-separated Apple
subject; explicitly linked providers retain the existing canonical account ID. Anyone who
already knows a primary subject and provider can derive the corresponding
`indexes/{user_id}.db.enc` name. This is an accepted availability trade-off, not an
encryption bypass.

### Aggregate storage telemetry reveals process-wide activity

The existing structured log sink receives at most one cumulative archive-storage metric
event per active minute. It reveals process-wide operation timing, byte-volume buckets and
save outcomes, but deliberately cannot attribute an observation to a user, archive,
object, request or content value. Counters are process-local and reset on restart. Access
to operational logs remains privileged; do not join these events to request-level user
logs or add high-cardinality labels.

## Reporting vulnerabilities

Report security vulnerabilities privately:

- Use the repository's [private vulnerability reporting
  form](https://github.com/joerodriguez/kioku-enclave/security/advisories/new).
- Do **not** open a public GitHub issue or include exploit details in public logs.
- The target coordinated-disclosure timeline is 90 days.
