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
- The repository's local verification, dependency audit, image scanning, signed local
  build evidence, and release process.

### Out of scope or accepted external trust

- The macOS client, which is a separate binary with its own threat model.
- Payment processing, tax, invoices, subscription webhooks, and catalog pricing occur in
  an external control plane. The enclave's pseudonymous usage reservation, entitlement
  enforcement, bounded compatibility facade, and owner authorization are in scope. This
  repository contains no merchant adapter or commercial catalog.
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
- **Apple Push Notification service.** An opted-in installation sends Apple a device
  token, exact app topic, generic `Your memory is ready.` alert, and delivery timing.
  Every installation receives a different opaque handoff handle. APNs payloads contain
  no memory/episode ID, title, people, transcript, summary, action items, account
  identity, timestamp, arbitrary URL, or credential.

## Security invariants

- Production never serves the application over plaintext HTTP. The production image
  requires `ENCLAVE_ACME=1`; boot waits for a usable certificate, and a non-debug build
  without TLS refuses to start. Plain HTTP is available only in a debug binary with
  `ENCLAVE_TEST_MODE=1`.
- The Confidential Space launch policy permits only `PORT` to be changed at launch.
  KMS, GCS, caller identity, OAuth, TLS, attestation, and migration settings are baked
  into the image and therefore covered by its digest.
- The local image pipeline selects exactly one complete image configuration before Docker
  runs. Manual
  evaluation builds never inherit production values, are marked with an `eval-` tag and
  metadata profile, cannot become signed releases, and may run only with an isolated
  service account, KMS key, buckets, hostname, and attestation binding that have no
  production data access. The operator has retired that isolated runtime; production is
  now the only active owner evaluation environment.
- Production selection accepts only the reviewed `shadow` and `enforce` billing modes.
  The selected mode is preserved in schema-9 release metadata, and a fresh release
  rechecks that it matches the external operator configuration used for the image. A later
  configuration change therefore cannot silently alter the signed image's enforcement
  behavior.
- ADR-0022 Phase-0 requires three baked non-secret operator configuration values:
  `ENCLAVE_GCS_BUCKET` for indexes, `ENCLAVE_GCS_MEDIA_BUCKET` for current-media
  writes, and `ENCLAVE_GCS_LEGACY_MEDIA_BUCKET` for migration-only media reads and
  deletes. The current media bucket may differ from the index bucket; legacy media must
  exactly equal it. The exact three-value claim is carried in a schema-9 release
  manifest whose exact bytes are bound by separately signed local build evidence. Runtime has no missing
  legacy-bucket fallback; an unsigned/copied or older manifest is not promotion evidence.
  This is not archive-v3 wiring, a deletion action, or deployment authority.
- The ADR-0022 Firestore transport probe is non-authoritative and the exact checked-in
  `config/archive-witness-probe.json` defaults to `off` with empty project/number/database
  fields. Build selection and signed-metadata verification use one strict parser; no
  operator configuration or command-line witness input can override it, evaluation and
  main builds force it off, and `probe-v1` is eligible only for an exact
  `vX.Y.Z-witness-probe.N` prerelease that `release.sh --roll` rejects. Off constructs no
  Firestore credentials or transport and performs zero I/O. A probe prerelease awaits one
  bounded attempt before any application Store/KMS/GCS construction, emits only a fixed
  redacted outcome, and continues startup regardless of that outcome. It can touch only
  `archive_witness_transport_probe_v1/singleton`, whose sole `r` field is a strict fixed-size
  magic/version, monotonic generation, and random opaque attempt ID. It has no AppState/
  CpState/route/health/admission/deletion/acknowledgement connection, never constructs a
  witness bootstrap, and cannot change canonical archive-witness state. Commit ambiguity is
  never blindly retried and is confirmed only by rereading the exact attempt. Schema-9
  signed release metadata binds the mode and complete-or-empty namespace but grants no
  Firestore, rollout, health, or archive authority.
- The ADR-0022 single-archive WAL runtime profile is separately image-bound by checked-in
  schema-2 `config/archive-v3-shadow-runtime.json`, which remains exact `off` with all seven
  deployment fragments empty. Its sole shared parser accepts an active form only when the
  bucket, three canonical unsigned-64-bit numeric coordinates, named non-UUID Firestore
  project/database, and nonzero lowercase SHA-256 archive-binding commitment are complete.
  Evaluation and `main` pretag selection force off; only exact
  `vX.Y.Z-archive-v3-wal.N` production tags select active, while an active profile on any
  other ref or a WAL tag with off fails closed. Operator configuration, dispatch inputs,
  and process environment cannot override selection. Schema-9 signed release metadata
  binds the complete eight-value claim; schema-7/8 metadata remains ineligible. Docker
  independently enforces the same all-empty or complete bucket, canonical-u64,
  named-non-UUID-Firestore, and nonzero-commitment grammar, and `release.sh --roll`
  rejects active evidence before tag verification, cloud authentication, publication, or
  deployment because the downstream compatibility PR is not merged.

  The compiled capability constructs fixed-origin clients synchronously without provider
  I/O, then remains pending until it consumes one opaque durable encrypted-control
  `ArchiveBinding`. Binding derives `SHA-256("kioku/archive-v3/single-archive-wal-runtime-binding/v1\0" || archive_id[16])`
  and must exactly match the image claim. Consumption is one-shot; the sealed result keeps
  the archive ID and every provider private and exposes no getter, callback, task, operation,
  acknowledgement, WAL publication, deletion, or hard-delete authority. Its drain gate
  remains false. Startup does not construct pending, durable, or sealed capability types,
  so both checked off and active image evidence have zero runtime effect on Store/VFS,
  lifecycle, routes, health, roots, users, or cloud state.
- The compiled maintenance importer is the only consumer allowed to turn that sealed
  single-archive runtime into an offline state machine. Encrypted control first binds one
  active account/archive to random opaque operation, owner, session, and attempt IDs plus a
  permanent `archive_` fence. Store acquires the one-user lifecycle, actor, and content-write
  gates before that fence is created, drains retained pre-fence write intents, and forces a
  same-plaintext generation-CAS bump. The resulting private tmpfs owner commits the exact
  positive object generation, wrapped-DEK metadata hash, plaintext SHA-256 and length, SQLite
  user version, archive, and operation. Restart exact-gets and authenticates only that
  generation; drop removes the database, WAL, and SHM files while provider and local fences
  remain closed. A remote writer may win only before the marker/forced bump; while control is
  still in Fencing, the new exact source is durably rebased before another attempt.

  The importer then requires an already-existing exact Active+Legacy witness. Missing,
  deleting, differently migrated, root/registry-substituted, or lease-conflicting state causes
  no archive create. Every checkpoint/manifest/root object is reserved in encrypted control
  before immutable create and authenticated exact readback; partial randomized uploads are
  retained as superseded attempts rather than overwritten. R1 is exactly the current root's
  successor with the pinned checkpoint and canonical zero-WAL geometry. Its complete bytes are
  durable before `ShadowSendUnknown`; only a fresh exact witness read can settle it as
  ShadowWal. Recovery derives authority only from those exact witness bytes, authenticates and
  decrypts the root and full checkpoint without listing, and compares independent SQLite copies
  with the full parity verifier on a blocking lane. Immediately before parity becomes durable,
  Store rereads the exact pinned legacy generation and the coordinator rereads the unchanged
  witness. R2 is a new exact root over the same authenticated checkpoint, is likewise durable
  before send, and terminal state is recorded only after an exact WalAuthoritative witness
  readback. The coordinator selects the distinct durable R2 attempt before reconciling any
  ShadowWal-bound artifact. A same-fence restart adopts that attempt's empty or partial exact
  prefix without consuming another attempt; a witness-authenticated higher-fence reacquire
  supersedes any partial attempt and starts a fresh empty one. Renewal and reacquire adoption
  compare the full immutable graph, registry, migration, deletion, owner, current/next-fence,
  trusted-tick, and expiry tuple, and encrypted control CASes the exact prior witness bytes plus
  lease fields. The checkpoint-only staging binding has its own domain-separated producer-gated
  constructor and accepts only canonical zero-WAL `0/0/0`; ordinary shadow bindings remain
  all-nonzero. Ambiguous sends retain one candidate forever; an alternate record becomes manual.
  Reloading a terminal control row still reacquires the Store transition and exact pinned
  source generation, reloads the complete terminal Control tuple, requires a fresh exact active
  WalAuthoritative R2 witness, and executes the unresolved terminal-specific lease release followed by a fresh read
  proving that no active import lease remains. Both reads use a witness-private full-record
  validator: they admit only the exact retained terminal or its canonical lease-release successor,
  whose owner/expiry alone clear and whose provider tick advances monotonically (including exact
  or post-expiry release) while archive, database generation, predecessor, root, registry,
  migration, deletion, and all evidence stay exact, including both current and next fences. Any
  higher-fence record is rejected because a released witness cannot prove the intervening owner.
  Only then is the DB/WAL/SHM scratch family scrubbed
  and the pinned lifecycle/actor admission guards, opaque archive binding, exact terminal witness,
  Control handle, and whole provider bundle moved into a non-cloneable WAL-owner-token-gated
  handoff. The handoff has no raw getters, is non-cloneable, and each value exposes one consuming
  view. A terminal restart can mint another value; durable globally unique WAL-owner acquisition
  and serialization are explicitly deferred to the inactive WAL worker slice.

  The coordinator's outer owned task keeps provider-send and scratch cleanup ownership across
  caller cancellation; process restart resumes only the durable stage and exact artifact prefix.
  It never lists or deletes archive-v3 objects, deletes the legacy source, clears the legacy
  fence, alters the account/archive binding, advances beyond WalAuthoritative, or emits
  serving/read/ack authority. The bounded legacy-intent prefix scan above is used only to drain
  already durable pre-marker writes. No main,
  startup, route, worker, Store constructor, config/environment selector, health result, cloud
  command, or deployment path calls it. Activation still requires an external zero-replica
  maintenance window, an already provisioned Legacy witness, and separately reviewed production
  WAL logical-operation owners and serving integration.
- KMS encrypt/decrypt uses an attestation token exchanged through the configured WIF
  provider. There is no VM-service-account credential fallback for KMS.
- A token returned by the public `/v1/attestation` endpoint uses the HTTPS verifier URL
  `${BASE_URL}/v1/attestation` as its audience. It never uses
  `ATTEST_STS_AUDIENCE`: a WIF-audience token is an STS bearer credential and must not
  leave the enclave.
- Decrypted databases exist only in the `/tmp` Confidential Space tmpfs and in process
  memory. User content and key material must never be logged.
- The ADR-0022 SQLite shadow-parity checker is inactive and advisory-only. If future
  rollout code invokes it, a separately reviewed recovery factory must mint two distinct
  owner-private disposable staging copies; this release has no non-test constructor for
  that capability. Normal inspections use independent read-only connections. It
  streams every ordinary live table, the canonical export representation, and exact
  vector row ids/encoded bytes under hard row/field/total budgets; bounded 64-row probes
  remain diagnostic and are never the full parity gate. SQLite exposes FTS5's documented
  no-op external-content integrity command only as an `INSERT`, so a private staging-only
  connection may execute at most six compile-time FTS check commands after exact,
  comment-rejecting verification of each expected virtual-table/source schema; it accepts
  no caller SQL and grants no live persistence authority. Alias-bearing and `WITHOUT
  ROWID` tables fail closed until an index-backed traversal is reviewed. It emits only
  typed outcomes plus opaque versioned digests and
  exposes cancellation/deadline checks. It has no Store, VFS, route,
  credential, provider, scheduler, publication, recovery, deletion, or cutover
  authority; a match never authorizes any of those actions.
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
deployment that contains pre-v2 objects.

The repository also contains an **inactive, migration-only** bounded streaming reader for
the exact historical `nonce[12] || ciphertext || tag[16]` AES-256-GCM envelope. It has no
Store, GCS, route, environment-flag, or authority connection. A future migration adapter
must independently select and seal the source identity commitment, generation, and total;
the primitive constant-time checks that commitment against the requested canonical identity
before its first range read. It authenticates the entire ciphertext before starting temporary
staging, re-reads that same pinned source in fixed-size chunks, and commits only after the
second pass has the same ciphertext digest and valid GCM tag. The primitive
uses async range and sink contracts; after staging begins, a synchronous-abort guard removes
temporary plaintext even if the migration future is cancelled at an I/O await point.
Staging creation itself is synchronous, so it cannot leave an unguarded temporary object on
cancellation. First-pass authentication returns an internal sealed, non-seekable source;
its pull and completion types are private to the module and its children. Pulled bytes are
explicitly provisional and attacker-controlled until completion, so a future child
composition may write them only to encrypted, non-observable, non-authoritative staging.
The source retains the pinned identity commitment/generation/total, nonce/tag, first-pass
digest, owned AAD, and zeroizing cipher state, and mints one non-cloneable completion carrying
the exact source binding only after second-pass exact EOF, tag, digest, and range-receipt
checks. Its fixed-size redacted binding is domain-separated SHA-256 over the fixed identity
commitment, pinned lengths and generation, AAD profile discriminator, and first-pass digest;
it never retains or logs a raw identity, path, user ID, or AAD in that binding. A future child
composition may obtain the pre-staging binding, but it must consume the completion and
constant-time equality-check its exact binding before persisting any root candidate or other
authority-bearing record. The compatibility wrapper performs that consuming check before its
atomic staging commit. Any future concrete adapter must live in the isolated legacy-GCM
module (or a child), require an
exact-generation GCS `206` response with a parsed `Content-Range` total and observed
generation on every range, and receive dedicated review for atomic commit, non-observability,
and reconciliation if cancellation races an externally completed commit. The in-memory
receipt checks reject inconsistencies but cannot prove that a malicious concrete adapter
reported provider metadata honestly.
The private `legacy_gcm/extent_candidate.rs` child is an inactive, provisional-only SQLite
extent source: it accepts only nonzero, page-aligned authenticated lengths within the fixed
32-GiB cap; validates the required first 100-byte SQLite header fields and their bounded
header-only relations before it returns an extent; and emits every dense sequential
1-MiB-or-final-page-aligned extent, including all-zero content. It does
not authenticate B-tree, FTS, or vector contents, finish or verify the second pass, stage an
object, construct a root candidate, or connect to a provider, Store, runtime, route, flag,
witness, CAS, or cutover authority. A later reviewed coordinator must own the parent source,
scope and drop this adapter, finish and consume its binding, re-read the witness, then perform
any staging or publication.
It accepts only an explicit historic empty-AAD profile (SQLite/control/ACME) or the exact
historic media-user-id AAD profile; it never probes multiple AADs and explicitly rejects a
v2 marker. Its AES/CTR/GHASH composition is intentionally isolated because it needs a
dedicated low-level cryptographic review, including the production range-reader and
all-or-nothing encrypted staging implementation, before it can be connected to any runtime
path.
### ADR-0022 archive-v3 foundation is inactive

The inactive legacy SQLite extent-candidate coordinator is private to
`legacy_gcm/extent_candidate/`. It can persist only a content-free
`CandidateReady` ledger record after asynchronous exact witness reads, a
pinned full legacy-GCM authentication/decryption pass, an exact hash-bound
AEAD-open/decode/context validation of the witness-nominated base root, sealed
immutable-object readback, and production root-admission validation. Before
the first durable row or provider write it also completes a bounded,
zeroizing-buffer SQLite-header preflight through exact EOF and one-shot source
completion, rejecting malformed headers and schema rollback. Its
caller-retained attempt handle keeps durable IDs/binding and blocking ledger
tasks across cancellation; exact reconciliation observes CandidateReady or
orphans only Prepared attempts through bounded exact ledger pages. Restart
discovery is derived solely from archive/database/operation identity and fully
validated persisted rows; it deliberately takes no live witness/lease/root/
registry/source input and requires exclusive future caller ownership. It has no
witness CAS/publication, provider construction, Store/VFS/route/flag wiring,
deletion, or GC. Provider-scale cleanup is intentionally deferred.

The offline `scripts/run_archive_capacity_harness.py` creates deterministic,
content-free SQLite smoke databases only outside the checkout or under ignored `target/`.
Its exclusive run receipt rejects foreign/symlinked output and incompatible resume state.
Its reports permanently classify as non-evidence (`release_evidence: false` and
`sqlite_local_evidence: false`), and full mode fails closed. It cannot grant archive-v3
authority or evidence the production image/VM, backend, VFS, witness, cache/concurrency,
fault, deletion, lifecycle, or 32-GiB release gates.

`scripts/run_archive_capacity_gate.py` is a separate, explicit local gate over the v2
12-month 40/80/100-hour-per-month numeric fixture. It requires an operator confirmation,
an empty safe output directory, and a free-space preflight before it creates anything.
Its canonical 32-GiB path streams bounded numeric SQLite batches, observes local WAL and
checkpoint results, materializes only deterministic zero-filled bounded payload/vector-shape
BLOBs, validates `max_page_count` geometry, and uses sparse regular-file
extent probes one page below/at/above the ceiling. Those probes contain no SQLite or user
content and first refuse filesystems without observable sparse allocation; they do not
materialize, download, upload, or encrypt a 32-GiB snapshot. Its report
is permanently marked local non-authority/non-release evidence; it cannot change runtime
authority or satisfy the image/backend/VFS/witness/fault/lifecycle/cache/concurrency gates.

The inactive Phase-1 signed capacity-evidence contract adds no authority. Its offline
verifier accepts a restricted ASCII/JCS profile only; enforces exact workload geometry,
the workload-by-case/metric/result cross-product, policy-pinned environment, context-bound
ADR metrics and transport components, strict bounds, paired live-size write traces with
recomputed summaries and amplification growth,
root/witness caps, ANN completeness, and conditional deletion semantics; and DER-validates
a pinned P-256 SPKI. Request, time,
replay-ledger, provenance, SBOM, and environment files are hash-bound wrappers, not trusted
facts. The `preauthorization_only` receipt lists rollback-protected challenge issuance,
transactional replay consumption, authenticated time, cryptographic provenance/environment
verification, and independent measurement authenticity as unsatisfied activation blockers.
It always carries `authority: false` and cannot authorize an archive-v3 transition.

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
production authority. The encrypted control database now assigns each canonical account
one independently random opaque archive ID and retains an internal-only tombstone plus
bounded opaque inventory-cursor slots before identity removal. This is a local fencing
prerequisite only: it does not construct any v3 transport/witness/VFS/shadow runtime,
does not send a provider request, and has no cryptographic, logical, or physical-complete
state. Finalization erases the identity-to-archive binding while retaining only the
archive-keyed tombstone, so a deleted identity cannot reconnect old ciphertext. Archive
IDs, fences, and cursors are neither logged nor exposed through API/export models.
The same encrypted control authority now has an inactive, bounded archive-v3 lifecycle
anchor. It commits an opaque bootstrap attempt and every immutable identifier before KMS
wrap or encryption, then retains the exact wrapped registry, root-envelope, and initial
witness bytes so cancellation or ambiguous creates can retry only the same bytes. A
monotonic revision admits one exact create at a time; deletion atomically freezes new
admissions and cannot seal while an admitted or outcome-unknown request remains. Registry
and root bootstrap rows are bounded in SQLite. Create-ahead attempt/ordinal/outcome/encoded-length
state remains only in that frozen control snapshot. The full exact deletion inventory instead
lives in separately control-key-encrypted, canonical hash-chained KILP-v2 pages containing only
exact key/role/ciphertext-hash facts; the whole control blob stores only bounded page
IDs/hashes/lengths and one v2 terminal commitment. The decoder rejects the never-live v1 page
format while the independent bounded control anchor remains format v1. Planned and
confirmed-absent rows remain deletion work. Canonical object-name parsing also binds every
stored role, including the v3 WAL segment and WAL commit-descriptor roles, so relabeling an
object cannot bypass registry-first erasure. Page reordering, truncation, cross-archive use,
commitment rollback, or conflicting reuse of an object ID fails closed before destructive
I/O. The inactive external page-store seam derives an independent AES-256-GCM key for each
complete page reference and deletion fence from a producer-sealed control DEK. Its strict
versioned envelope authenticates the deterministic full-hash exact object name, archive,
fence, ordinal, page ID, predecessor, hash, and encoded length. Conditional-create success,
precondition failure, and ambiguous response can mint a durable receipt only after a bounded
exact read decrypts and decodes to that same canonical page. The narrow transport has no list
or overwrite operation. The inactive inventory coordinator requires exact Tombstoned witness
recovery, freezes/loads the settled create-ahead snapshot, authenticates the exact current and
optional predecessor graphs, and unions facts by object ID; only byte-for-byte identical
key/role/hash facts deduplicate and every conflict fails closed. It sorts that complete set and
uses one deterministic greedy split under the combined 131,072-object, 64-MiB-key, 4,096-page,
256-entry, and 64-KiB-page bounds. The complete witness recovery and control snapshot are reread
for equality immediately before page I/O and again before the atomic seal. Restart accepts only
the durable Created prefix plus the sole unresolved exact next page and rejects an alternate
split. The sealed loader validates the entire retained reference set before its first GET, then
authenticates the full page chain, exact count, terminal hash, canonical global object ordering,
and object-ID uniqueness. Its deletion inventory commitment is exactly the durable lifecycle
seal commitment; there is no second builder or independently computed deletion commitment.
Cleanup first validates the complete sealed reference chain carried
by a durable-control physical-completion receipt, then deletes every generation of each exact
name and separately verifies live, noncurrent, and soft-deleted state absent before its private
producer token can mint page absence. Cancellation leaves at most an immutable exact-name
ciphertext that the same readback path reconciles. Exact retries reproduce the same ciphertext:
the per-page HKDF key and separately domain-derived nonce both bind the complete immutable
context, and that context's page hash fixes the plaintext, so a derived AES-GCM key is never
used for a different context or plaintext. Before the first page admission, encrypted control
requires every artifact and witness create admission/outcome-unknown state to be settled, advances
the monotonic revision, and durably commits the exact canonical create-ahead/witness snapshot.
That immutable boundary rejects later artifact reconciliation; page retries after cancellation or
restart therefore rebuild the same plaintext/hash/ciphertext. Before any page request, encrypted
control then durably records its exact reference as outcome-unknown; only authenticated exact
readback advances that row to created. Because callers may otherwise choose a different page split
after cancellation, encrypted control permits only one unresolved page per archive and temporarily
retains that page's exact canonical bytes (at most 64 KiB). Restart recovers a producer-private
ordered plan of created exact references plus those one unresolved bytes; alternate ordinal/hash/
partition admission fails closed. Exact readback clears the temporary bytes immediately, so the
control blob never accumulates the external inventory. Every page admission and the final seal
reauthenticate the snapshot commitment. Sealing requires the complete exact Created set, and the same durable-control
physical-completion snapshot freezes it. Cleanup additionally requires a provider-backed drain
proving no already-submitted create for those exact names can still settle. This closes delayed
create versus absence-proof resurrection across cancellation and process restart. Page ordinals
are rejected at the 4,096-page cap by canonical construction/decoding, persisted-reference
validation, encrypted-control constraints, and admission before remote I/O. Existing
account-deletion transactions atomically freeze an anchor if this inactive schema has one, but
do not construct an archive provider or invoke archive-v3 I/O. No startup, Store, route, provider
construction, or deployment configuration activates the lifecycle.
Producer-authorized recovery reads need only the opaque archive authority: after close/reopen
they reconstruct the original reservation or exact prepared bytes from the anchor, never from
caller-retained random IDs or ciphertext. The page seam likewise has no provider implementation,
credential/config source, runtime construction, deletion-driver invocation, or production authority.

The inactive pre-witness disposition capability closes the remaining logical ambiguity without
granting deletion authority. Every new bootstrap reservation atomically enrolls a separate
protocol-v1 control row binding the opaque archive/attempt, exact prepared witness hash and length,
admission revision, monotonic phase, deletion fence, and a domain-separated commitment. The
closed-unsent and confirmed-absent phases also support the exact all-`None` candidate/admission
tuple needed when deletion wins while the anchor is only reserved or objects-prepared.
Firestore bootstrap boundary performs token acquisition, transaction begin, exact transactional
read, and exact candidate encoding before it asks encrypted control for a non-cloneable send-start
receipt; its private commit path borrows that receipt and accepts no raw production bootstrap
bypass. Genesis can select only the sealed Firestore witness creator (or its test fixture), not an
implementation-defined raw witness-create hook. Failures before the marker issue no Firestore commit. Once marked, cancellation, ABORTED
retry, transport failure, or a lost response remains outcome-unknown until an exact read resolves
the same retained bytes. A post-marker create-precondition failure itself triggers a fresh exact
read because a delayed earlier attempt may have committed. Genesis restart adopts an exact
existing witness only through the retained send-start admission/hash CAS; a witness with no
enrolled candidate never takes the early success path. Generic reconciliation cannot label witness ordinal 2 absent and cannot
record an unknown outcome without the matching send marker.

Account tombstoning and explicit lifecycle freeze atomically close `open_unstarted` as
`deletion_closed_unsent` or `send_started` as `deletion_closed_started`. The capability authenticates
the exact tombstoned binding, deletion ledger, lifecycle anchor, protocol commitment, and fence
before any witness I/O. Only closed-unsent plus a fresh exact-name `None` read can advance a
full-state CAS and mint a private non-cloneable absence proof. Started/unknown plus `None` becomes
manual and stays so across restart; a later exact retained record may resolve to present. A
mismatch or a definite found-but-malformed/noncanonical document atomically poisons both
closed-unsent and confirmed-absent into admission-free `manual_required`; later `None` can never
remint absence. Provider-unavailable reads cause no transition. The exact-`None` observation is a
private one-shot capability consumed by control, so sibling code cannot call a raw
snapshot-to-absence API. Restart retains facts rather than
proofs: even `absence_confirmed` requires another exact `None` read and full-state CAS to remint.
Old anchors with no enrollment, unknown protocol versions, active or inconsistent tuples fail
closed before witness I/O and are never inferred unsent. The fresh absence proof can now be
consumed exactly once into a separate encrypted-control pre-witness inventory branch. That branch
commits the full absence/protocol/bootstrap/fence/revision tuple and every settled create-ahead
fact before any external inventory-page operation. It never invokes reachability or reads archive
metadata. The shared page ledger derives the complete deterministic plan from that durable
snapshot on every admission, recovery, and reconciliation: only an exact created prefix plus at
most its exact unresolved next page is valid, and the zero-object plan rejects every page before
durable admission or transport I/O. Restart after this boundary uses only the durable opaque
archive/fence tuple and never remints absence or rereads Firestore. The sealed result can now be
consumed only by a separate, inactive pre-witness execution protocol. That protocol authenticates
the complete sealed page inventory in memory, binds its exact ordered object set and dimensions to
one random nonzero operation ID, and atomically revalidates the tombstoned/fenced absence branch,
immutable protocol tuple, deterministic Created page prefix, snapshot, seal, and absence of the
normal branch before persisting execution state. Recovery must load and authenticate the complete
inventory again; archive/fence/operation identifiers alone cannot reconstruct authority.

The pre-witness execution row has its own version and commitment domains and a strict monotonic
evidence matrix: inventory-bound, registry-erased, objects-absent, physical-complete, then the
reserved payload-erased terminal. Every transition full-row-CASes the same operation, snapshot,
seal, dimensions, object-set commitment, and prior evidence. Exact replay is idempotent; alternate,
skipped, regressed, cross-operation, zero, or structurally invalid tuples fail closed. The
capability-bearing SQLite mutation and encrypted-control flush own the sole handle outside the
shared cache until the conditional PUT succeeds or an exact ciphertext readback reconciles its lost
response. Cancellation or failure drops that local handle while the cache remains empty; the next
operation reloads the provider's durable generation and can therefore see only the old row or the
exact committed row, never an unflushed local stage or an invented generation. There is no detached
flush. The
zero-object branch retains zero page/artifact/key-byte dimensions and a zero terminal page hash
under nonzero inventory, object-set, and execution commitments, and grants no object/provider
access. Execution types are non-cloneable and cannot convert to normal witnessed deletion types.
This slice deliberately supplies no production registry/object/drain evidence producer, provider
capability or destructive driver, and no production payload-cleanup transition. It has no
Store/startup/runtime/route/config/provider construction, credential, cloud, or deployment wiring.
Legacy Google-ID rebinding is an encrypted, durable state machine rather than a request-local
rename. Its random operation ID, exact old/stable IDs and object names, opaque archive binding,
source generation, SHA-256 plaintext commitment, and monotonic stage are committed before the
first provider mutation. Store then locks and blocks both process-local namespaces together,
drains admitted raw writes, and force-flushes the latest actor. A content-free GCS marker fences
the old namespace across instances. Its retained object name is a domain-separated HMAC under
the KMS-protected control-store DEK rather than the legacy user ID or a public hash. The key is
installed only from an exact durable control generation, is absent from the decrypted control
rows, and cannot be changed in a live process; therefore the archive-keyed deletion ledger does
not preserve an enumerable identity-to-archive link. Every legacy index write (including generation zero), raw
media create, recovery-checkpoint copy, and stable create first persists a provider-side exact
write intent. The intent binds a random request ID, owner namespace, destination backend/name,
generation precondition or exact copy source, encrypted request bytes, and their commitments.
Only after rereading the retained marker does a writer CAS a bounded ownership lease and issue the
data request in an owned task. Lease timestamps come from the strict HTTP `Date` on an authenticated,
read-only metadata GET of the exact existing intent generation, never a clock write or the process
wall clock; missing, malformed, or regressing provider time fails closed. The provider future remains
owned by the intent executor: caller
cancellation drops it, and its awaited timeout expires before the lease plus a conservative margin,
so no detached request is authorized beyond lease expiry. Ambiguous responses are reconciled
against the exact destination; an expired lease can be CAS-taken over from the encrypted request
only after that provider timeout window.
Marker creation precedes strongly consistent bounded intent inventory: prepared intents are
fenced without data I/O, active requests keep deletion/rebind pending, and expired requests are
taken over. Terminal tombstones erase request bytes and purge their noncurrent payload generations
but remain live through Phase 6. Rebind then performs a same-plaintext generation-CAS bump, so a
pre-fence writer is either incorporated by an exact durable rebase or loses without an
acknowledged mutation. Stable creation remains generation-zero conditional and exact-validated;
old generations are deleted exactly and idempotently. Startup drains operations in bounded
64-row pages before request admission (failing closed above a global safety cap), without user
reauthentication. A live account-deletion retry actively resumes `SourceFreezing` or
`StableWriting` under the same lifecycle and durable intent ownership instead of waiting for a
restart. Deletion creates/adopts retained markers for both exact namespaces, drains intents before
inventory, drains again after physical purge, and cannot finalize identity state until rebind reaches
`deletion_reconciled`. The content-free old-namespace marker is intentionally retained as a
ledger-known no-resurrection tombstone; only the later Phase-6 authority-drain/witness cutover may
retire it.
`src/archive_v3_gcs.rs` is likewise inactive: it specifies and
tests a redacted async GCS-shaped transport boundary (conditional immutable creation,
read-after-create equality, bounded canonical-name pagination, and a contract requiring
exact all-generation deletion) plus a typed, bounded registry-KMS boundary. Its fake
verifies wrap/unwrap delegation and multi-generation absence semantics; provider-level deletion
evidence still requires a live drill. `src/archive_v3_gcs_http.rs` provides a concrete,
caller-token-only rustls-only/no-proxy/no-redirect/no-retry REST implementation with exact URL encoding, bounded streamed reads/listing,
generation-zero creates, durable claim CAS, and bounded all-generation deletion. Disabled-policy
deletion succeeds only through an external provider/audit-and-trusted-time drain gate; no such live
gate is wired. The transport intentionally has no metadata-service access, environment constructor,
credentials/runtime/deploy wiring, or authority connection; its provider errors never contain
object paths, IDs, hashes, or cursors.

`src/archive_v3_registry_kms.rs` is the concrete but still inactive registry-KMS
adapter. It derives only a canonical numeric `CryptoKeyVersion` beneath the exact key
already selected by the live `GcpKmsClient`; it does not add an environment input or
change the legacy `KmsClient` encrypt/decrypt path or its production endpoints. Before
each wrap or unwrap it verifies the exact version coordinate, `ENABLED` state,
`GOOGLE_SYMMETRIC_ENCRYPTION` algorithm, and current `SOFTWARE` protection level. Wrap
also decodes and context-checks the exact registry plaintext before I/O. Both directions
clear the full caller destination first and use identical zeroizing AAD formed from the
canonical typed registry context plus the exact version coordinate, preventing a valid
ciphertext from another key version from being relabeled. The bounded stored wrapper
independently rejects format, algorithm, protection-level, and version-coordinate
substitutions before decrypt. The fixed-origin rustls-only/no-proxy/no-redirect/no-retry
REST path checks the provider's exact encrypt coordinate, all required request-verification
booleans, CRC32C response integrity, strict secret-bearing response shapes, and bounded
bodies. Tokens, AAD, request JSON, returned ciphertext, and plaintext use zeroizing owners;
provider error bodies are neither consumed nor logged, and Debug output is fixed and
redacted. Cancellation drops the one in-flight operation with the caller destination
remaining zero; there is no adapter retry or detached task. No startup, Store, provider
construction, route, flag, release, or persistence authority is wired.

`src/archive_v3_deletion.rs` is a compiled-but-inactive deletion-driver seam. It accepts
only an exact-current witness-issued tombstone/restart authorization, the opaque archive context
authenticated by that witness, and the matching durable lifecycle inventory seal; no caller can provide an account ID, object key, prefix, or
list-all selector. It advances the existing key-erasure, inventory, and retention evidence
stages only after exact all-generation content and permanent-claim deletion, and it reconciles
a lost mutation response only by an exact absence read/list. GCS soft-delete residue remains a
provider-drain gate. Immediately before any destructive I/O it reauthenticates the exact
worker/operation/fence through deletion-only witness recovery, compares the fresh full record and
authorization to its session, and passes every provider call an opaque execution binding. Final
retention requires the provider to re-list exact content and claim generations (including
soft-delete state) for the same inventory-bound commitment. Raw keys and object IDs are not
provider capabilities: the sealed complete inventory mints an opaque capability for each indexed
entry, and the concrete GCS adapter rechecks its inventory membership plus the full fresh
archive/database/fence/worker/operation tuple before transport I/O. `PhysicalComplete` evidence
hashes both the exact complete-inventory commitment and the freshly reverified provider-drain
commitment; the driver derives that stage proof from the drain result rather than forwarding an
unrelated retention assertion. The former independent inventory builder, test-overwritten
commitment, and `FullReachabilitySeal` are removed. A complete deletion inventory is now minted
only after the authenticated lifecycle-page loader verifies the exact durable seal (apart from
explicit `cfg(test)` fixtures), so the reachability report remains non-authorizing on its own.
Full activation remains blocked because the type-separated pre-witness execution protocol has no
production destructive evidence producer, provider capability, cleanup transition, or driver
invocation, and by the lack of startup/runtime/provider construction.
The intended lifecycle order is fixed: freeze and drain admitted/ambiguous creates; tombstone the
exact unchanged current root (or use a separately reviewed exact-absence coordinator for a bootstrap
that never established a witness); reauthenticate that exact Tombstoned worker/operation/fence before
the control snapshot CAS; freeze the snapshot; reauthenticate the unchanged tombstone again before
the first graph GET; authenticate the root graph and union all create-ahead rows; durably seal the
page chain; freshly revalidate fence/worker/operation/commitment; erase and exactly
verify every registry epoch before advancing `CryptographicallyErased`; then delete exact content
and claims, drain provider generations/soft-delete state, and advance `PhysicalComplete` with the
same inventory commitment. Restarts after registry erasure read only the control-key lifecycle pages,
never archive metadata or a prefix listing. The returned opaque witness/provider physical receipt must
first be durably CAS-recorded in the encrypted control anchor; only that stronger control receipt can
authorize page-store cleanup. Its same-seal exact-absence receipt is then required before retry payloads
can be erased. Crashes before the control CAS, after the control CAS, or during ambiguous page erasure
therefore retain enough exact-name inventory for restart. The content-free anchor, deletion fence, seal,
and page references remain permanently. A one-snapshot control recovery read keyed by the opaque archive
and exact deletion fence revalidates those references and reconstructs the sealed-inventory receipt; after
physical completion it additionally reconstructs the durable-control receipt from the retained provider-drain
commitment. Restart therefore never depends on a process retaining either receipt. The separately
compiled pre-witness disposition can prove a never-started initial send. Its proof can seal a
separate create-ahead-only inventory, including an explicit zero-object representation. The
inactive type-separated execution protocol can durably bind that exact authenticated inventory and
record only opaque evidence commitments, but it has no entry/provider capability, destructive
evidence producer, cleanup producer, or driver invocation; those separately reviewed integrations
remain activation blockers.
The authenticated exact-name visitor and lifecycle inventory coordinator are compiled and tested
but inactive; neither infers paths nor discovers objects by prefix. The driver has no Store, route, runtime,
credential, or deployment wiring.

`src/archive_v3_reachability.rs` is the first inactive, non-authorizing half of that source
change. It accepts at most the exact current and predecessor root/registry pairs from one
witness recovery snapshot, plus archive ciphers already resolved from each pair's exact wrapped
registry generation/object/hash. Before its first archive read it rechecks those bindings. Its
current and predecessor bindings are all validated as one set before any read, so a bad later
registry/cipher cannot leak I/O from an earlier graph. Every authenticated root commitment,
opened root, and WAL descriptor contributes its exact sequence-derived parent and grandparent
`RootV3` facts. A parent reference does not authenticate its historical key epoch, so an unfetched
root fact deliberately commits only archive ID, the derivable database namespace, sequence, object
ID, and envelope hash; it never labels that fact with the current key or a guessed parent/AEAD
context. At database-epoch cutover, a parent equal to the separately witnessed predecessor uses
that predecessor graph's actual database namespace. When the predecessor graph is visited, the
reference-only fact is promoted and fetched exactly once under the predecessor's exact witnessed
registry/cipher; same-database key rotation likewise retains the old parent without relabeling it
with the new key epoch.
Its transport boundary can read one canonical `ObjectKey` with one response cap and has no prefix,
enumeration, mutation, provider-construction, credential, or continuation-token operation.
Every fetched root, checkpoint manifest, extent node, WAL commit descriptor, and WAL segment is
full-envelope-hash checked, AEAD opened under the derived exact context, decoded, and compared to
its authenticated parent fields. Checkpoint chunks and extent leaves need no content read because
their exact context, object ID, envelope hash, length/range, and revision are committed by the
already authenticated parent; conflicting object-ID reuse or a repeated fetched edge fails before
a second request. Identical shared leaf facts may be represented once only when key, role, hash,
and full context commitment are all equal. Object-ID lookup, exact-identity comparison, and
fetched-state promotion remain logarithmic at the global object bound; no traversal step scans the
accumulated report.

The visitor independently caps the whole result at 131,072 objects, 64 MiB of canonical key
bytes, and 16 MiB of authenticated metadata excluding WAL frame bodies. Each of at most two root
graphs is additionally bounded to the format's 32,768 checkpoint chunks plus 129 manifests,
32,768 extent leaves plus 129 nodes, 1,024 WAL descriptors, 16,384 WAL segments, 16 segments per
commit, and one GiB of root WAL lineage. Checkpoint root level/range/checkpoint ID and every node's
complete descriptor must agree; extent slots/height and full/final lengths are derived rather
than caller selected; WAL root/descriptor/parent/checkpoint/count/byte/generation/frame/checksum
and predecessor continuity are all checked. Tree traversal uses a separate depth-64 bound; WAL's
linear chain uses its explicit count bounds. At most one commit's bounded segment buffers are
retained at a time and their owned frame storage zeroizes before the next commit. Cancellation or
a stalled/failed exact read produces no report; retry begins again from the same witness snapshot.
The returned opaque, content-free report is deliberately not a lifecycle page plan, complete
deletion inventory, admission, or provider capability. Only the separate inactive inventory
coordinator may consume it together with exact Tombstoned witness recovery and the frozen control
snapshot; that coordinator performs create-ahead union, deterministic v2 paging, repeated freshness
checks, sealing, and restart loading without changing the visitor's authority. Its final control CAS
accepts only a one-shot opaque coordinator proof binding the frozen archive/fence/revision, exact
canonical page plan, and every authenticated external readback. The generic lifecycle trait and
ControlStore expose no raw pages-to-seal method, so a create-ahead-only subset, extra superset, or
alternate split cannot bypass the authenticated union. No Store, startup,
runtime, route, cloud implementation, credential source, or deployment configuration constructs
either component.
The shadow module
is bounded synchronous capture state only: no
SQLite VFS is registered, and capture failure cannot alter the legacy Store result.
The VFS wrapper is an explicit, non-default installation around SQLite's then-selected default VFS. It forwards the underlying callback result verbatim and invokes the bounded capture state only after successful WAL `xWrite`, `xTruncate`, or `xSync`; no capture condition is returned to SQLite. Its image tail is zeroized before a nonzero truncate, and reset, fault, stream-retirement, and queue-drop paths zeroize raw image/header bytes; queued captures independently zeroize on drop. Each exact canonical path is bound to a fresh random nonzero process-local stream identity for the full lifetime of one Store SQLite connection, rather than to a shorter publication attempt. An exclusive lease binds the already-observed queue prefix to one nonzero session/attempt: cancellation leaves that prefix queued, settlement detaches only that prefix, later captures remain queued, settled attempt identities cannot be reused, and a hard 1,024-settlement cap forces a fresh connection rather than unbounded replay metadata. Closing the connection precedes registration retirement; retirement invalidates outstanding leases, and a restarted connection receives a fresh stream identity. SQLite retains VFS names and raw pointers in open connections, so dropping a wrapper intentionally retains both its registration and small callback allocation until process exit; a hard eight-installation cap bounds this memory-safety measure. Parent files must advertise I/O-method version 3 and its required base callbacks or open fails before capture attaches; optional shared-memory/fetch callbacks retain SQLite's documented fallback behavior. Every live Store constructor remains capture-disabled. Only a crate-private injected Store seam can register the exact private temp path before opening it through the named VFS and retain the registration immediately after the connection in drop order. Startup does not install or inject that seam, and there is no provider, witness, archive binding, post-PUT handoff, route, health, admission, runtime replay, recovery, export, deletion, or authority wiring. The bundled SQLite oracle validates commit/rollback behavior, captured-format validation, local replay from a checkpointed database, multi-attempt connection lifetime, exclusive/cancelled/exact-prefix drains, retirement/restart isolation, post-handle `ATTACH` safety, and synthetic exact-code `xWrite`/`xTruncate`/`xSync` failure boundaries with the bundled default VFS; it does not establish every platform or custom parent VFS.

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
time. Production tombstoning is a transactionally exact CAS over the current archive,
database epoch, root, registry, and fencing snapshot: it revokes ownership and binds the
deletion worker/operation/fence without publishing a candidate or changing the root.
Tombstoning invalidates ordinary recovery/ownership, while a deletion-only restart
path requires provider authentication on every step, matches the exact durable
worker/operation identity derived from that opaque credential (never from persisted IDs),
and accepts only provider-verified stage proofs whose canonical commitments bind the
archive, operation identity, deletion fence, target state, root, registry, prior evidence,
and provider proof commitment. Physical-completion proofs additionally bind the exact sealed
inventory and fresh provider-drain commitments. Database-epoch cutover requires extent authority, derives a
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
and accepts only the documented named-database grammar. The separately compiled inactive
Firestore bearer source receives and uses the one dedicated
`archive-witness-attest/providers/archive-witness` WIF provider-resource audience on every
mint. Batch-get transport is capped before JSON parsing
and accepts exactly one response, while record/base64, transaction, token, `readTime`, and
`updateTime` material are bounded and fail closed. `src/archive_v3_firestore_http.rs` is a
compiled but equally inactive concrete transport: its production origin is fixed to
`https://firestore.googleapis.com/v1` (a plaintext loopback origin is test-only), it uses
rustls with no proxy or redirects and finite connect/request/body timeouts, and it validates
only the adapter's begin/read/commit request shapes before sending them. It caps every body
before parsing; batch-get accepts only a JSON array containing exactly one strict response
object and rejects bare, empty, multi-object, nested, or trailing JSON shapes. Canonical
bounded Google error envelopes are accepted either bare or in an exact one-element array,
validated, and never logged or returned. Automatic HTTP retries are disabled so a refused
connection is known unsent while every failure after acceptance remains ambiguous. Update-time
preconditions are canonical UTC and microsecond-aligned; a found document may omit `createTime`,
but if present it must be canonical and no later than `updateTime`. A post-send commit
transport/timeout/429/5xx or
malformed success remains `OutcomeUnknown`; `ABORTED` and `FAILED_PRECONDITION` retain their
typed meanings, and an HTTP 404 is only an endpoint/database failure, never a missing
witness document. The REST transport and the separately compiled bearer source have no runtime
connection; neither uses metadata/default-token fallback or service-account impersonation. An
inactive composition seam constructs those fixed clients and the semantic adapter from one typed
namespace/audience config without I/O. Its coordinator bridge preserves a lost commit response as
`OutcomeUnknown` so the exact candidate/parent handle remains the only reconciliation path;
ordinary adapter calls retain their exact fresh-read resolution. There is no Firestore IAM runtime
wiring, query/list/delete/batch-write/create-document capability, additional field,
Store/VFS/route/startup connection, environment flag, archive bootstrap, or production authority.
The initial witness-create adapter has no production raw-bootstrap entrypoint: it validates the
exact absent transaction and durable candidate first, invokes the injected encrypted-control
send-start CAS once, and only its private receipt-borrowing helper can submit the commit. Bounded
ABORTED retry retains that same marker; a later iteration may accept only the exact retained
record. A precondition failure after send-start is resolved only by a fresh exact read; exact is
success, mismatch is rejection, and absent/unavailable remains outcome-unknown. Any other
post-marker failure remains outcome-unknown rather than reviving an absence claim.
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
may contain its commit frame. Its format-v4 descriptor fixes the exact final reference and
per-commit topology; the root fixes the exact descriptor tail, WAL generation, and cumulative
counts. Chain validation rejects frame gaps, checksum discontinuity, wrong predecessors,
root-sequence substitution, locally valid orphan candidates, and a commit marker anywhere but
the final frame. These checks do not turn post-commit WAL-file scraping into a valid capture
mechanism. The compiled inactive SQLite VFS shim observes the exact `xSync` boundary, but Phase 1
authority still requires reviewed runtime integration plus independent crash and conformance gates.

`src/archive_v3_genesis.rs` is a separately compiled but inactive restart-safe
bootstrap seam. Its production constructor accepts only a durable control-plane
reservation containing the exact bounded registry/root bytes; it
does not construct credentials or providers and cannot issue I/O. Resolution
first authenticates an exact existing active witness, registry, and root using
the canonical KMS AAD and archive object context. If absent, it attempts
immutable create-if-absent for the exact registry and root candidates, then
creates the witness only after exact read-back authentication. A collision or a
lost response is resolved solely by a bounded exact read and byte/commitment
equality; it is never blindly retried. Every registry, root, and witness request
requires a fresh revision-bound create admission; exact initial witness bytes are
committed before its create. The backend has no raw witness-create hook: only the
sealed Firestore creator can accept that admission, and its commit borrows the
durable send-start receipt. After a crash between accepted commit and lifecycle
reconciliation, the exact-existing path succeeds only through an atomic adoption
CAS over the retained attempt/revision/hash/admission; unrelated pre-ledger existing
data fails closed. Tombstoned, frozen, or deleting states
reject bootstrap. After authenticating root and registry, both the existing and
create paths reread the exact witness immediately before success and require the
entire authenticated snapshot plus a final active-ledger reread to remain equal; a
concurrent tombstone is a distinct failure and any root/registry advance fails
closed. An ambiguous or cancelled request leaves the same planned row unresolved
and cannot authorize replacement IDs or ciphertext. Partial objects created before
the witness remain in the lifecycle deletion inventory. No production ledger/backend
composite is constructed. It also has no
Store, VFS, route, runtime flag, Firestore/GCS construction,
environment/default credential path, logging, or production authority.

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

**ADR-0022 inactive WAL logical-idempotency gate:** a separate fixed-domain codec accepts only
nonzero caller-stable operation IDs, version/domain-separated request fingerprints, and bounded
canonical replay results. Its sealed plans require each supported domain to own canonicalization,
mutation SQL, a distinct hard-bounded row family, an exact indexed lookup, and replay validation;
there is no universal receipt table, table selector, or lifetime scan. The sealed contract retains a
test-only 64-row/262,720-byte exemplar and now admits exactly eleven inactive production A-domains:
capture-session finish, metadata-only screen-reference batch, selected-screenshot receipt,
raw-media retention settlement, provider-accepted email, provider-accepted APNs, definitive-success
webhook settlement, exact synthetic reviewer fixture, cursor-bound substance-backfill batch,
cursor-bound visual-evidence backfill batch, and Vertex usage terminal outcome.
Capture-session finish derives an opaque
operation ID from the validated caller-stable
session ID before actor admission, owns a versioned binary request and exact finish receipt, and
lazily creates only its distinct 65,536-row/128-MiB ledger schema within the same transaction. It
reserves the maximum result before its first domain write, uses the operation primary key for exact
replay, and full-tuple updates its authenticated row/byte counters. An absent session is a failed
precondition that rolls back the new schema and consumes no identity; a late ledger failure rolls
back the session update; a committed replay survives process reopen without another write. The
Vertex usage child accepts only the exact 68-byte vtx event ID that the still-disabled B-domain
allocator must durably create before provider I/O. Its closed request codec distinguishes normalized
metered/usage-missing response facts, ambiguous status, and not-billed status; the event-derived
operation ID makes a substituted terminal outcome a fingerprint conflict. It transitions only an
existing started row or exactly adopts the same pre-existing terminal facts, refreshes coverage only
on the first transition, and retains the nine-byte unit result in its own
1,048,576-row/32-MiB ledger. Missing or mismatched events, cap exhaustion, a late ledger insert,
partial schema, and row/commitment tamper roll back or fail closed; exact replay survives reopen.
The screen-reference child accepts only the existing bounded contiguous Mac-screen reference batch,
derives a subtype-separated opaque identity from its cross-language stable batch ID, and fingerprints
the account plus complete normalized ordered manifests under the common 1-MiB limit. Exact reference
preconditions, every new/duplicate row, contiguous stream acknowledgement, bounded canonical response,
and its distinct 1,048,576-row/512-MiB ledger commit atomically. Missing or changed canonical evidence,
a changed manifest under the same batch ID, cap exhaustion, late ledger failure, partial schema, and
tamper roll back or fail closed; exact replay survives reopen. Canonical media upload remains outside
this child behind its disabled B-domain media-DEK/provider handoff. The selected-screenshot child
likewise accepts only the local receipt half of an already durable B-domain upload attempt. Its opaque
128-bit image ID derives the operation identity; the exact account-bound object key, episode/source/time,
and validated JPEG geometry/hash form the request fingerprint. It atomically revalidates eligibility and
the canonical screenshot binding, inserts or exactly adopts the complete receipt, retains a bounded
canonical response, and advances only its distinct 1,048,576-row/512-MiB ledger. Another object or
screenshot binding, cap exhaustion, late ledger failure, partial schema, tamper, and reopen fail closed
or exactly replay. It cannot allocate a DEK or attempt, encrypt/upload/delete media, or call Store. The
retention child likewise accepts only the local receipt half of an already settled exact provider
deletion. Its account/event pair derives the stable operation identity, while the exact account-bound
object key, bucket-local generation/provenance, plaintext hash, retention deadline, eligible predecessor
state, and fixed deletion timestamp form the request fingerprint. It can only full-tuple mark that exact
ready/failed media row pruned or adopt the identical terminal row, and it retains unit replay in a
distinct 1,048,576-row/32-MiB ledger. An early deadline, changed provider fact, changed terminal time,
cap exhaustion, late ledger failure, partial schema, tamper, or reopen fails closed or exactly replays.
The future provider deletion boundary must authenticate and settle the exact object before constructing
this plan; the child cannot call Store or list/read/delete provider objects. The email child accepts
only the local settlement half of a definitive provider acceptance for an
already durable delivery. The same delivery ID is the external idempotency key and derives the
operation identity; its exact pending/retry row (including prior attempt, response/error, and
timestamps), provider message ID, 2xx status, and fixed acceptance time form the fingerprint. It
either full-row-CASes that predecessor to accepted or adopts only the identical terminal row, with
unit replay in a distinct 1,048,576-row/32-MiB ledger. It cannot send email, allocate or schedule a
retry, call Store, launch a worker, or acknowledge delivery. The APNs child similarly accepts only
the local settlement half of a definitive provider acceptance for an already durable delivery. Its
UUID is fixed before I/O and sent as `apns-id`; that UUID derives the operation identity, while the
exact episode/installation/version/handoff/collapse binding, pending/retry attempt and prior outcome,
timestamps, definitive 200 status, and fixed acceptance time form the fingerprint. It full-row-CASes
only that predecessor to accepted or adopts only the identical terminal row, including the terminal
`next_attempt_at`, with unit replay in a distinct 1,048,576-row/32-MiB ledger. It cannot send, retry,
mutate an installation, call Store, launch work, or acknowledge delivery. The webhook child accepts
only the local settlement half of a
definitive HTTP 2xx for an already durable outbox event. The exact `evt_` identity is fixed before
I/O, sent as `webhook-id`, and derives the operation identity; the exact episode/subscription/version
binding, pending/retry attempt, nullable due time, prior response/error, timestamps, accepted status,
and fixed sent time form the fingerprint. It full-row-CASes only that predecessor to `sent` or adopts
only the identical terminal row, with unit replay in a distinct 1,048,576-row/32-MiB ledger. It cannot
sign or send, load or disable a subscription, retry, call Store, launch work, or acknowledge delivery.
The reviewer-fixture child accepts only the complete fixed synthetic archive for an already
authenticated stable reviewer account. Its fixture-version/account pair derives the operation
identity. It inserts or exactly adopts every fixed audio, utterance, screenshot, episode,
membership, final-brief, watermark, and marker row, authenticates the complete semantic fixture
before the marker or ledger can commit, and retains unit replay in a distinct 64-row/576-byte
ledger. Conflicting fixed IDs, altered content, or extra fixture membership fail closed. It cannot
authenticate a reviewer, call Store/save, enter the reviewer route, launch work, or acknowledge a
request; it remains separate from the substance and visual-evidence backfill subtypes.
The substance-backfill child accepts only the exact ordered next prefix after a durable private
cursor. Each bounded batch fingerprints the already-rendered model input, current canonical
substance value, and validated classification for every strictly increasing episode ID. It
reauthenticates that prefix, updates all classifications, and advances the cursor atomically with
unit replay; a short batch cannot skip a later row. Only an empty exact tail can write the fixed
historical completion marker, while a pre-existing exact marker can be adopted. Changed input,
predecessor, cursor, result, partial schema, cap exhaustion, late ledger failure, or reopen fail
closed or exactly replay. It cannot reserve inference, invoke Vertex, call Store/save, launch work,
or acknowledge completion; it is separate from visual-evidence backfill. The visual-evidence child
likewise accepts only a stable account/cursor/phase identity, but fingerprints at most sixteen exact
eligible episodes plus each bounded text-only screenshot-evidence rendering, canonical `normal`/`none`
predecessor, and validated `none`/`useful` result. Sixteen worst-case inputs fit the shared one-MiB
request cap. It deterministically orders at most 120 nonduplicate member screens per episode,
reauthenticates the exact next eligible prefix, full-tuple updates each episode, and advances its
private cursor atomically with unit replay. A short batch cannot skip, and only an empty exact tail
writes the historical completion marker; an exact pre-existing marker can be adopted. Changed
episode text, eligibility, membership, screen metadata/OCR, result, cursor, schema, capacity,
commitment, or reopen fails closed or exactly replays. It cannot load pixels, reserve or invoke
inference, call Store/save, launch work, or acknowledge completion. All other production domain
ledgers remain absent and unsupported. A future owner must commit a domain row and its mutation
under the same `BEGIN IMMEDIATE`; fingerprint reuse, unknown versions/domains, malformed or
substituted results, and unsupported response shapes fail closed. It must derive ID and fingerprint
before actor admission, reconcile pending publication, commit the logical mutation and same-ID
capture, exact-read immutable uploads, CAS/reconcile the witness, and settle publication before
acknowledging the retained result. Cancellation after local commit and before settlement poisons
that actor until durable reconciliation. The production codecs have no Store, route, launcher,
worker, provider, task, runtime-policy, or acknowledgement connection, and introduce no detached
publication.

The reviewed operation inventory is deliberately asymmetric. Stable portable domain A contains
capture events and session finish, selected screenshots, finalization queue/commit, deterministic
media-work results, Vertex usage outcomes, existing-key webhook/email/push transitions, retention,
and reviewer/backfill writes. Only capture-session finish, metadata-only screen-reference batch,
selected-screenshot receipt, raw-media retention settlement, provider-accepted email,
provider-accepted APNs, definitive-success webhook settlement, and Vertex terminal outcome have
production codecs so far, together with the exact synthetic reviewer fixture and cursor-bound
substance and visual-evidence backfills; every other A operation remains disabled
pending its own separately reviewed codec and the closed launcher. Vertex invocation begin and
canonical media's first DEK/provider handoff remain B and are not admitted by those children.
Domain B remains disabled pending explicit caller/attempt identity or
semantic refactoring: leases and failure/retry counters or times, Vertex begin, media-DEK first
write, summarizer auto-ID creation, and cross-control webhook deletion. Domain C remains disabled:
purge, source-keyless legacy ingest, retired episode mutations, arbitrary Store SQL, and account
deletion. A structural source inventory pins every production Store mutation/save call (including
qualified forms), every factory definition/call and Store literal, every persistence-policy
reference/assignment, and every async or dedicated-thread worker spawn by exact owner/expression
hashes. A new factory,
visibility change, conditional runtime selector, or call site therefore requires renewed review.

Every live Store constructor still selects legacy whole-snapshot persistence. The private
`WalLogicalOnly` policy is test-only and fail-closed: reads use SQLite `query_only`; generic
mutation closures, dirty save/eviction, envelope rewrite, and non-current schema are rejected
without a provider write. A missing user is rejected before KMS wrapping, empty-database creation,
temporary-file creation, or provider upload. Existing plaintext is preflighted as a complete
checkpointed main database with no exact `-wal`/`-shm` sidecars, then opened through an immutable
read-only SQLite URI. Schema compatibility is checked against a separately constructed current
schema, and both successful and schema-failing opens leave the main file present with no sidecar.
This inactive slice adds a private, single-archive local owner without changing that live Store
policy. A dedicated `SingleArchiveWalStoreOwner` can be created only from an owned authenticated
private recovery copy, an exact Active/WalAuthoritative witness binding, a private owner token, and
an owned capture installation. It is disjoint from the ordinary Store registry and legacy object
paths. It accepts only a sealed `PreparedLogicalMutation`; the domain resolver and mutation share
one `BEGIN IMMEDIATE`, and both Applied and Replayed retain the exact bounded opaque result. No
connection, SQL, raw result bytes, provider acknowledgement, root selector, or generic closure
escapes that boundary. The SQLite connection and capture registration stay on one owned blocking
thread; the Tokio actor exchanges only sealed commands and opaque results, so stalled SQLite work
cannot stall unrelated async work.

After a first apply, capture admits exactly one complete commit and transfers a non-cloneable drain
to the actor. A second mutation is blocked while that drain is outstanding. Dropping it before an
authenticated settlement restores the exact prefix at the front of the live queue; retiring the
registration instead zeroizes the detached frames. Encrypted control separately commits versioned
owner, publication, attempt, and immutable-artifact rows through cancellation-safe owned flushes.
Durable operation/session/attempt/artifact identity is the exact archive, operation kind, and
domain operation-ID tuple; equal IDs in different domains cannot collide or substitute.
Stages are monotonic Prepared, Captured, CandidateReady, SendStarted, and Witnessed, with a terminal
ManualRequired branch. Every row binds the exact archive/database/key/root witness, operation ID,
fingerprint, process instance, session/attempt, WAL generation, first frame/count, capture, and the
complete canonical AAD/key/role/hash topology for one to sixteen segments followed by exactly one
descriptor and root. Reserve-time transitions reject a descriptor before a nonempty dense segment
prefix, a second descriptor, or anything after the root before provider creation; candidate fanout
must equal the uploader's fixed captured-frame split. The immutable expected full witness remains retained through terminal state;
the candidate commits its exact ordinary-root transition input and the separately stored observed
provider record may differ only by the provider-derived monotonic tick. Fresh-process recovery may
supersede only Prepared/Captured attempts, retains every old artifact row for deletion inventory,
and consumes one of the fixed sixteen attempts before recreating a WAL with new SQLite salts.
CandidateReady/SendStarted recovery reconciles before the old-head gate and accepts only the
retained expected witness or the candidate's exact authenticated successor, so a lost successful
send cannot cause a second mutation or provider send. Only exact durable replay is idempotent;
alternate identity, result, capture, frame geometry, candidate,
artifact prefix/AAD, expected/observed witness, stage, or unsupported/corrupt tuples fail closed.

Submission moves a plan into the actor queue before awaiting its response, so caller cancellation
cannot cancel work after the local commit. Replay results remain opaque until encrypted Control is
read-only reconciled and a fresh provider-authenticated exact Active/WalAuthoritative head with the
retained lease is read. The authenticated current staging database then supplies the permanent
bounded per-domain result row, so operation A can replay after settled operation B without
replacing B's terminal Control row or creating a publication. The process-local capture-stream commitment is included only in the settlement
context, never persisted or logged, so an old receipt cannot consume a fresh registration's drain.
Settlement alone advances the owner binding and releases the drain. The inactive owner now has one
private production publication implementation, constructed only by consuming the completed
maintenance-import handoff. Encrypted Control first reserves a random owner and then binds the
exact Active/WalAuthoritative witness lease. The shared owned lease manager reuses an exact lease
while enough trusted lifetime remains, heartbeats a live same-fence lease, and only after trusted
expiry reacquires the retained owner at a higher fence. A fresh process never renews an old
unexpired lease. Checkpoint hashing, upload, and the final pre-CAS boundary all use that manager;
same-fence heartbeats preserve the attempt, while a higher-fence pre-send reacquire durably
supersedes the attempt and restarts from its retained source. SendStarted never renews, reacquires,
or replaces its candidate, and a definitive provider rejection becomes durable ManualRequired.
Before either lease successor advances the owner binding, the same Control transaction fully
authenticates and consumes any exact terminal logical-publication comparison row; unresolved,
manual, or send-sensitive work blocks without provider mutation. A terminal checkpoint comparison
row is likewise authenticated and consumed before a later lease or logical-root transition.
Logical replay is resolved before checkpoint admission. A new absent mutation must checkpoint
before applying when the fixed commit, segment, or tail-byte threshold would be crossed. The
blocking Store lane drains and truncates WAL, closes SQLite and its capture registration, requires
WAL/SHM sidecars absent, and moves only the authenticated cleanup-owned database source to a
dedicated cleanup-owning reader thread. Hashing and bounded reads stay on that thread; only
zeroizing chunks and authenticated facts cross to the async publisher. Control persists a bounded, versioned
Prepared/SourceReady/Uploading/CandidateReady/SendStarted/Witnessed protocol with at most 16
attempts and 32,898 immutable exact-AAD artifacts per attempt. Every artifact is reserved before
create and materialized only after exact readback. Reservation and every candidate/send/terminal
reload recompute the exact 1-MiB-chunk, interleaved fixed-fanout manifest, terminal-root topology
and its full commitment; no provider listing or replacement bytes select recovery. Candidate/send
restart loads this durable topology before the old-head gate and accepts only the retained head or
the exact authenticated checkpoint successor, so a committed lost response settles without a
second send. Long source extraction rechecks the durable checkpoint stage before every heartbeat:
CandidateReady, SendStarted, and ManualRequired permit no lease renewal or reacquire, while the
candidate stages perform only an exact witness read that accepts the retained predecessor or exact
candidate successor. Checkpoint settlement atomically authenticates and consumes the prior Witnessed
logical-publication comparison row, advances the owner binding, and only then permits a fresh
recovered staging owner to reset capture generation. The runtime gives this child only an
exact-name immutable create/get capability; enumerate and delete authority never cross the handoff.

This publisher remains unreachable: there is no production logical-operation codec, launcher,
Store factory, startup/config/route/health call, acknowledgement surface, provider list/delete, or
deployment path. It cannot serve the archive, acknowledge a domain result, delete objects, or
create a second runtime. Production Store constructors remain LegacySnapshot and the test-only
`WalLogicalOnly` gate remains unchanged. Activation still requires separately reviewed domain
codecs and the single-archive maintenance launcher.

Root objects are explicitly named as candidates. Crashes and CAS races may leave more
than one immutable candidate for a sequence; none has authority unless the independent
witness names its exact object ID and ciphertext hash, and recovery never selects one by
listing a storage prefix.

The foundation refuses a monolithic checkpoint object: each encrypted checkpoint chunk is
at most 1 MiB and each manifest node is at most 32 KiB with fixed fanout. A WAL-bearing
root must still name the checkpoint-manifest base reference, preventing publication of an
unrecoverable WAL chain. Chunking/manifest construction and recovery remain inactive until
their storage/witness fault gates pass.

**ADR-0022 inactive extent-tree seam:** `src/archive_v3_extent.rs` streams one
caller-owned, page-aligned 1 MiB buffer at a time into context-bound immutable
extent objects and persistent 256-way sparse Merkle nodes. Each extent/node
create uses the inactive session-bound shadow-object inventory: it durably
reserves the exact canonical AAD, provider-neutral key, and ciphertext hash
before create; then exact-gets the object, authenticates/decrypts it under the
expected context, and checks the expected extent bytes or canonical decoded
node before materializing that inventory row or linking its reference. A
maximum 32-GiB tree consumes at most
32,768 extent objects plus 129 nodes (32,897 rows), leaving the shared 32,898th
attempt ordinal for the separately staged root candidate; this uploader does
not create that root. A transient error or cancellation after reservation
leaves the row Reserved for exact-key restart reconciliation, never a
replacement/list/delete path. Exact-root range recovery is transactionally
staged in zeroizing memory and derives every node/extent key from an already
authenticated root, never lists storage, then verifies each envelope hash, AEAD context, node range and
level, bounded traversal/object counts, and exact full-or-final extent length
before copying an intersection into a caller-owned buffer; only absent sparse
extents are zeroes. Its returned sparse-content commitment is domain-separated
and binds the logical length plus every stored extent number, length, and byte
stream; it is not a hash of a zero-filled logical SQLite image. The common
format contexts, extent geometry, upload, and recovery all reject lengths and
ranges beyond the fixed 32-GiB/8,388,608-page/32,768-extent ceiling. The source
buffer is cleared before each declared source read, so a buggy underfilling
source deterministically commits zeroes instead of stale bytes from a previous
extent; future activation still requires a reviewed stable snapshot source.
This is not a live recovery or authority path: it has no Store, VFS, provider,
witness, route, flag, or credential wiring. The current codec intentionally
has no authenticated empty-tree representation, so an all-hole file is
rejected. These tests and format bounds do not satisfy the 32-GiB release gate.
The separately compiled legacy-conversion session codec/ledger is likewise
inactive and content-free: it persists only exact Active/Legacy witness/lease,
registry/base-root/fence/request, witness-record digest, authenticated source
completion commitment, and bounded object facts. Its distinct tables never
reuse WAL shadow rows. Its stable session ID is domain-separated over the exact
archive, database epoch, and operation, and every record must match that
derivation. The separately bound request fingerprint is therefore conflict data
inside that one family, so neither alternate IDs nor request substitutions can
split the family or evade its 16-attempt cap. A candidate-ready root requires
one contiguous fully materialized extent/node inventory followed by the final
exact root, and is
accepted only with an opaque admission committed to that exact canonical root
context for an authenticated, decoded root whose parent/fence/length/epoch/
conversion shape exactly match the session. Non-root contexts must have no
parent. The sealed legacy staging capability shares that same 32,898-row ordinal
with the tree: it reserves legacy-ledger facts before create, requires exact
envelope readback equality, and materializes only after caller extent/node
authentication. Its root-specific operation additionally requires the resolved
cipher's exact registry generation/object/hash, verifies the complete
materialized tree inventory in the same attempt, requires the decoded root's
tree reference to equal that staged tree, then AEAD-opens/decodes/context-validates
the root and checks every binding field before minting a private-field admission
token. Production code cannot pass raw root/context/hash values to that seam,
and the generic staging callback rejects roots. This remains no coordinator or
publication path: the admission alone neither persists CandidateReady nor
advances a witness root.
Restart and orphaning rescan every exact canonical row. Orphan records retain an
exact count and domain-separated ordered-inventory commitment, and schema checks
reject triggers on all three legacy ledger tables. Opaque cursors bind bounded
contiguous pages to one session/attempt and each page rechecks its complete prior
ordinal prefix in one SQLite snapshot. CandidateReady is not
witness-retained and grants no root advance. It has no source adapter, provider
call, Store/VFS/runtime/route/flag, witness CAS, recovery, deletion, or cutover
authority.
`AuthenticatedExtentRoot` now has a crate-private mint that accepts only an
active `RecoveryRoot` plus an injected exact-current witness admission; it
re-admits that full snapshot before and after exact-getting the witness-nominated
root object, verifies its retained envelope hash and AEAD/context, and binds
archive, database/key epochs, registry object/hash/rotation, sequence, parent,
fence, and a present extent tree before returning the sealed capability. It
never enumerates or deletes provider objects. The generic constructor remains test-only; durable
publication-session/orphan-inventory/reconciliation integration remains an
explicit activation blocker.

`src/archive_v3_export.rs` is an equally inactive, compiled export-parity seam. It accepts
only an opaque `ArchiveId` and reads one exact active witness record through a sealed,
cancellation/deadline-aware witness adapter. A separate sealed publication boundary then
atomically admits that full record and holds deletion-aware authority through conditional
commit. Every root, registry, and deletion transition must serialize with admissions;
deletion closes new admissions and wins or drains existing admissions before tombstoning.
The defensive final full-record reread is not the race-safety claim: only the admission's
atomic exact-active conditional commit may publish. If deletion closure wins at commit, the
pending artifact is aborted and remains unpublished.

Tombstoned/deleting/deleted records and root or key-registry changes abort the transaction.
The source pulls one reconstructed SQLite page into a caller-owned fixed-size buffer; fixed
cursor storage plus cursor sequence, page number/size/count, nonzero total-page,
snapshot-byte, nonempty output-chunk, nonzero completed output, output-write-count, and
output-byte checks prevent provider-owned unbounded responses, empty-write amplification,
empty publication, or a whole 32-GiB allocation.
A cursorless page is terminal, must exactly reach the declared page count, and is never
followed by another source call. One finite deadline-budget/cancellation control is passed
into witness reads, source open/descriptor/pulls, the canonical adapter, transactional sink
begin/write operations, admission, and conditional publication; it is also checked around
each potentially blocking call. This does not claim that outer polling interrupts an
implementation that ignores the control or blocks without its own transport deadline. A
transaction guard aborts partial output on every pre-commit error or drop.
The sink is a trusted boundary: it must isolate writes, discard them on abort, and atomically
honor stop state while committing; a failed commit must remain abortable and unpublished. A
dishonest implementation is outside this code proof.

The cancellation-aware witness, authenticated source, deletion-aware publication/admission,
and canonical export adapter are all sealed to deterministic test fakes. The current formats
do not yet supply one complete authenticated checkpoint/WAL/extent walker, and no admitted
adapter yet binds the live route's exact table, ordering, value encoding, JSON schema, and
content semantics. The seam never drains a partially consumed reader after an adapter
returns; only complete consumption inside that same sealed adapter call can reach publication.
These are compile-time activation blockers, not claims
that arbitrary output bytes establish parity. The module has no Store, route, startup,
environment, credentials, logging of identifiers/content, or live I/O wiring. The active
`/api/export` route remains the legacy Store export until both blockers and their provider
fault/lifecycle evidence are reviewed as an explicit authority change.

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
database persists a content-free legacy deletion operation—an opaque random operation ID,
`pending`/`failed_retryable`/`physical_complete` status, machine-readable reason, retry
delay, and provider `hardDeleteTime`—plus a separately internal random archive binding and
pre-v3 tombstone. That tombstone retains only a random fence and bounded opaque cursor
slots for a future exact v3 inventory; it neither authorizes v3 I/O nor records any
cryptographic/logical/physical-complete outcome.
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

The compiled-but-inactive ADR-0022 Firestore witness boundary is deliberately a third,
type-separated credential path. It derives only the exact dedicated
`archive-witness-attest/archive-witness` provider audience, requests a no-nonce launcher
OIDC token for that audience, and exchanges it only at fixed Google STS with the
cloud-platform scope. It has a separate mutex-coalesced zeroizing cache refreshed 60
seconds early; it does not share KMS credentials or cache state, use metadata/default
credentials, impersonate a service account, expose its tokens publicly, or enable any
runtime witness authority. The three paths share only the bounded launcher socket protocol;
the Firestore audience type, STS client, secret-owning request/response buffers, and cache are
separate. Its STS client is rustls-only, proxy-free, redirect-free, retry-disabled, and
bounded; neither OIDC/STS tokens, audience, nor provider bodies are logged.

The compiled-but-inactive ADR-0022 archive-GCS bearer is a fourth, separately typed
credential path. It accepts only the dedicated
`archive-gcs-attest/archive-gcs` provider-resource audience, requests a no-nonce launcher
OIDC token for that audience, and exchanges it only at fixed Google STS for the fixed
`devstorage.read_write` scope. Its audience type derives the exact provider resource only from
a validated project number (never a full caller-controlled audience); its launcher boundary, rustls-only
no-proxy/no-redirect/no-retry STS client, zeroizing request/response material, and
mutex-coalesced cache are independent of KMS, public attestation, and Firestore. It has no
environment/request/header authority selection, metadata/default credentials, service-account
impersonation, transport/Store/VFS/route connection, or runtime authority. Launcher and STS
responses are bounded with finite timeouts and strict RFC 8693/response parsing; cancellation
or refresh failure drops expired cached secret material.

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
paths are rejected. That public native client ID and caller-selected loopback port do not
independently prove that the receiving local process is the official Kioku binary. Its
consent page therefore retains the requesting-app, redirect-destination, and full-archive
access disclosure; only the fixed web client returning to Kioku's exact owned origin uses
official first-party sign-in copy. Apple refresh
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
rate limits, quotas, memory-safe Rust, local tests, Clippy, dependency audit, and image
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

**ADR-0022 inactive checkpoint seam:** the compiled-but-unwired checkpoint module rejects a
declared length over the shared 32-GiB ceiling before source reads, hashing, encryption, or any
immutable create, then uses independently authenticated 1 MiB chunks and bounded 256-way manifest
nodes. Before every create, a session/attempt-bound encrypted SQLite inventory reserves the exact
opaque context-AAD and ciphertext commitment; it marks the row materialized only after exact-key
readback equality, so an `AlreadyPresentIdentical` response still cannot link a parent without a
readback. The bounded 32,898-row attempt inventory contains no user ID, provider name/URL, cursor,
timestamp, plaintext, or debug payload. Recovery accepts
only the exact root commitment returned by the witness; it derives every manifest and chunk
context from that root and never selects objects by GCS listing. It checks envelope hashes, AEAD
context, manifest coverage, per-chunk hashes, and the full plaintext hash before atomically
exposing a `/tmp` output. This is not yet an authority path: no Store, SQLite VFS, runtime flag,
provider token, or deployment wiring invokes it.

**ADR-0022 inactive shadow coordinator:** publication first obtains and authenticates the exact
independent witness-nominated current root, checks the lease's archive/database/key/fence binding
(the witness transaction remains authoritative for trusted-time expiry), derives SQLite
`user_version` from the same hash-checked two-pass checkpoint source, and rejects downgrades. Each
immutable create must succeed and the candidate root is read back and authenticated before the
witness CAS; later recovery authenticates the complete nominated checkpoint graph. Both a success
and a lost transaction response are accepted only after an exact witness reread names the same
root, parent, database/key/registry, fence, migration/deletion states, and predecessor
commitments. The Firestore boundary type-separates definitive comparison/precondition rejection,
non-terminal token/begin/batch-get/provider failure, and ambiguous commit response; only the first
can durably supersede an attempt. Before CAS, a fixed-size content-free record durably binds one stable operation/session,
one retained attempt, the exact base/registry/fence/migration/WAL boundary, and the authenticated
candidate root. The encrypted SQLite ledger permits at most one active and 16 retained attempts;
candidate replacement is forbidden, and a root candidate cannot persist until its exact root
inventory row is materialized. Witnessed completion atomically retains the attempt's inventory.
A CAS-unknown outcome leaves its exact reserved/materialized rows unchanged for restart's exact-key
reconciliation. A prepared partial upload is never resumed with replacement objects: restart gets
only each recorded exact key, materializes matching ciphertext, leaves an exact missing key reserved,
and then explicitly aborts the attempt; tampering blocks that abort. Only definitive rejection,
supersession, or that explicit abort atomically changes
them to orphan-pending-grace. There is no deletion in this slice. Every superseded/aborted attempt remains
inventory-visible before a new attempt can be prepared. Unknown responses are durably marked before
reread. Process restart reads one exact attempt and one exact witness record and can return only
`Witnessed`, non-authorizing `RetrySameCandidate`, `Superseded`, or `Aborted`; it never lists storage,
creates replacement objects, or invents a candidate. A witnessed attempt and its exact root-sequence operation replay result commit in one
SQLite transaction. While the runtime remains alive, the cancellation-safe committing phase still
owns its witness provider until reread finishes; a post-send task failure also returns an opaque
in-memory handle. A non-nominating reread is never proof of non-commit because commit completion or a
subsequent advance may race it. Failures can leave unreachable ciphertext for the later authorized
GC/deletion walker. The seam never truncates WAL, mutates legacy persistence, or performs cleanup,
and no Store, VFS registration, provider construction, flag, route, startup path, or production
authority wires it.

**ADR-0022 inactive captured-WAL seam:** a post-successful-`xSync`, checksum-validated VFS
capture can now be split only at bounded SQLite frame boundaries into independently encrypted,
predecessor-linked immutable WAL segments. Every create is followed by an exact readback,
envelope-hash, AEAD-context, and format check before its reference can appear in a candidate root.
The format-v4 root separately binds the checkpoint length, current logical length, exact checkpoint
reference, exact commit-descriptor tail, and cumulative commit/segment/byte counts. Each bounded
descriptor binds the exact checkpoint, authenticated parent and grandparent root commitments,
previous descriptor, operation/fingerprint/fence, generation/header/checksum continuity, before
and after lengths, frame and segment topology, cumulative counters, and final segment. Publication
accepts an existing WAL lineage only after exact descriptor continuity validation, allowing
authenticated multi-commit and generation-rollover histories without discarding their predecessor.
It rejects an extent base. Before any lineage readback or immutable create, it derives the new
commit's exact segment and byte totals with checked arithmetic and enforces at most 1,024 commits,
16,384 segments, and 1 GiB of WAL tail per root (plus the independent 16-segment per-commit cap).
WAL page numbers and each final commit's page-count-derived length remain bounded by the fixed
8,388,608-page/32-GiB ceiling; distinct checkpoint and current lengths permit authenticated database
growth and shrink without changing checkpoint-manifest contexts. Capture frames, decoded segment
frames, and transient encoded plaintext are zeroized when their owners drop.

Recovery begins only with one witness-nominated root, requires its exact registry
epoch/rotation/object/hash to match the already resolved verified cipher, follows the exact reverse
descriptor and segment chains without storage listing, and validates the complete bounded topology
of all descriptors before a staging sink receives a byte. Each commit's complete segment chain is
then validated before that commit is delivered, and any later failure aborts the sink. Generation
boundaries are explicit. Composite recovery uses that same authenticated recovery root for both
checkpoint and WAL, creates only a fresh random owner-private `/tmp` database, and checkpoints each
recovered WAL generation on a blocking lane.
It requires both SQLite sidecars to be absent before an unforgeable module-private proof can transfer
the staged database to parity checking. The operation remains owned after caller cancellation; on
failure or eventual task completion its owner removes the database, WAL, and shared-memory sidecar,
and the returned staged capability also owns family cleanup. This is still not an authority or
restore path: no VFS capture is drained, no `Store`/provider/flag/route/startup path calls it, and no
local production WAL is truncated or mutated.

### T5 — Hypervisor or memory inspection

**Threat:** A co-tenant or hypervisor reads plaintext guest memory or persistent disk.

**Mitigation:** Confidential Space uses AMD SEV memory encryption, and decrypted SQLite
files are created only on the required `/tmp` tmpfs. No plaintext is intentionally
written to persistent disk.

**Residual risk:** CPU-level microarchitectural side channels are not fully mitigated by
AMD SEV.

### T6 — Source, dependency, or build-pipeline tampering

**Threat:** An attacker modifies source, dependencies, the local builder, or build inputs so the
published image differs from the reviewed release.

**Mitigation:** Release tags are signed and verified; the release script refuses to
overwrite an existing public release. The Rust builder image is pinned by full digest and
the embedding model is revision- and SHA-256-pinned. The local gate runs formatting,
locked tests, all-target Clippy, RustSec audit (with the documented RS256-verification-only
exception), and an SBOM-based fixed-high image scan. Cargo-auditable metadata exposes
statically linked Rust crates and the gate rejects an SBOM missing representative native
packages. All compilation and scanning occurs before the named operator requests
short-lived push-only credentials. Canonical evidence binds the exact tag/commit, image
digest, configuration and input/output hashes, tools, and time; it is signed with a
separate mode-0600 Ed25519 key and verified against an externally pinned public-key
fingerprint. The sole publisher, `scripts/release.sh`, verifies both the tag-signing key and
that evidence before any release or rollout mutation.

GitHub Actions, hosted CodeQL, and dependency review are disabled. This removes a hosted
runner and its recurring cost, but also removes centralized CodeQL alerts and an
independent execution environment. RustSec, Clippy, locked tests, dependency-update PRs,
and image scanning remain; reviewers must treat local evidence as a designated-builder
claim, not a third-party build guarantee.

## Residual risks and limitations

### Source-to-image rebuilds are not yet independently reproducible

The builder image and model are pinned, but Cargo sources are fetched from crates.io
rather than vendored, Debian packages are installed from mutable apt repositories without
snapshot/version pins, and the local workflow does not demonstrate a bit-for-bit rebuild.
The detached evidence signature proves what the designated key holder claims to have
built; it does not eliminate trust in that builder or mutable dependency delivery.

Release notes must say “publicly auditable with signed build provenance,” not
“independently reproducible.” Closing this limitation requires vendored Rust sources,
snapshot-pinned OS packages, deterministic build inputs/timestamps, network-disabled
compilation, and independent rebuild comparison.

### Vertex, user-configured webhooks, and APNs cross the TEE boundary

Audio transcription/diarization, screenshot understanding, identity/fact evidence extraction,
episode summarisation, and evidence verification send bounded content to Google Vertex
Gemini from this process. Google's no-data-retention terms apply, but the data is outside
the Confidential Space boundary while Vertex processes it. Webhook events similarly
leave Confidential Space for the user-selected destination. They are content-free by
default and carry final-brief content only when that destination's explicit option is
enabled. The sender revalidates public DNS addresses on every attempt, pins the validated
address, refuses redirects, signs the exact body, and never logs endpoint paths, payloads,
signatures, or response bodies.

APNs ready alerts are a separate, explicitly enabled metadata-only boundary. Environment-
separated provider keys come from dedicated Secret Manager containers available only to
the enclave runtime identity; production startup fails closed if either key is missing.
The worker uses a generic alert and a distinct per-installation opaque handoff, rechecks
registration before send, generation-fences terminal-token responses, and never logs
tokens, handles, payloads, provider paths, or response bodies. Apple may correlate the
device token, topic, generic alert, and delivery timing; Focus/device settings determine
display and an already accepted generic alert cannot be recalled after offline sign-out.

### Pseudonymous entitlement and usage events cross the TEE boundary

The external control plane receives a random account pseudonym and content-free usage
events over HTTPS authenticated with an exact-audience Google OIDC token. It does not
receive email, Google subject, stable enclave user UUID, capture/episode identifiers, or
model content. The random mapping, lease receipts, and deletion-detach outbox remain
encrypted inside the enclave. This boundary reveals subscription usage and inference-cost
shape; compromise of both databases could link those records.

Cloud persistence of new capture depends on the entitlement port in enforce mode: a
denial or inactive lease is HTTP 402, idempotency/early-renewal conflict is HTTP 409,
and unavailable durable state is HTTP 503 before persistence. The Mac may continue
capture during ordinary connectivity loss only into an account-scoped AES-256-GCM local
outbox whose key remains in its device-only data-protection Keychain; it deletes an item
only after enclave acknowledgement and stops new capture if the bounded outbox cannot
write. On reconnection, a separate content-free journal settles one idempotent,
rounded-up 60-second usage tick per offline minute before the client obtains a live lease
and releases queued media. Those ticks expose only the random billing account pseudonym,
meter, quantity, current observation time, and a domain-separated random idempotency
event—never the capture session, device, stream, original time, media, or content. This
is a local delivery fallback, not local transcription, OCR, indexing, or memory
processing. Existing cloud archive reads, search, export, and deletion remain ungated.
Shadow mode must not log upstream denial detail.

Each newly billed live or offline minute also grants an encrypted-control-store budget of
120 delayed events and 256 MiB. A Mac outbox request carries only a fixed delivery-mode
header; before content persistence the enclave reserves budget by the event ID it is about
to store. Identical retry and reference-to-canonical rebase are idempotent. This permits
delivery after the live lease expires without charging transfer time, while preventing an
unbounded inactive-lease upload path. Reservation telemetry contains no identifiers.
Bounded screenshot-reference batches use one transport token but atomically create or reuse
the same per-event reservations and debit every genuinely new logical observation. Their
encrypted user-scoped receipt binds only a content-free batch correlation digest; it cannot
authorize delivery, is migrated with a verified identity rebind, and is erased with account
deletion. The per-user lifecycle and content-write guards remain held through durable archive
save and reservation completion or retention.

### Billing request telemetry reveals route timing and outcome

The service emits one structured event after each `GET` billing-summary, `POST`
recording-lease, or `POST` offline-recording-usage request. It ignores preflight and
wrong-method requests. Each event contains only a fixed schema name, one of three fixed
route labels, the numeric HTTP status
and its fixed class, and elapsed milliseconds. It deliberately omits the request method,
path and query, account and provider identifiers, tokens, headers, bodies, lease/request
IDs, exception text, and captured content. This is request-level operational telemetry—not
an anonymous aggregate—so privileged log readers can observe billing request cadence and
may correlate timing with other infrastructure events. Keep the method/route set fixed
and low-cardinality, retain privileged log access, and do not join these events to
user-level logs.

### Capture rejection telemetry reveals failed-upload timing and class

The service emits one structured event only when `POST /api/v2/capture/events` or
`POST /api/v2/capture/screen-reference-batches` fails. Each event contains a fixed schema
and one of the two fixed route labels, numeric HTTP status
and fixed class, one validated stream kind, `canonical`/`reference` disposition,
one fixed failure-reason class, and elapsed milliseconds. Before a manifest can
be validated, stream and disposition are the literal fixed value `unknown`.
It deliberately omits account, device, install, session, stream, event, asset,
lease, and request identifiers; paths and queries; tokens and headers; request
and response bodies; URLs, window/app text, media, exception text, and captured
content. Successful capture cadence is not logged by this event.

This remains request-level operational telemetry: privileged log readers can
observe the time and broad class of a failed upload and may correlate it with
other infrastructure events. Keep the enums fixed and low-cardinality, retain
privileged log access, and do not join these events to user-level logs.

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
