# ADR-0029 ready-notification delivery

- [x] Persist authenticated, per-installation APNs registrations with account-switch and token-generation fencing.
- [x] Commit first-finalization push deliveries atomically with the final memory result; regeneration does not replay them.
- [x] Send privacy-safe per-device handoff handles through separate production and sandbox APNs transports.
- [x] Resolve notification handoffs only for the authenticated owner and canonical browser memory route.
- [x] Activate selected-archive push without replay: pre-lift bare-installation rows are cancellation-only, while new rows bind the exact Control token generation and expire within 24 hours.
- [x] Persist exact archive send-start claims plus short Control user/installation/generation/claim fences before APNs; hold no database lock across provider I/O and make deletion/rotation conflict only with the exact in-flight destination.
- [x] Use best-effort at-most-once ambiguity handling, complete-predecessor typed settlement, fixed-size poison-row quarantine, bounded fair pacing/circuit/Retry-After behavior, content-free telemetry, and restart-safe possibly-sent handoff resolution.
- [x] Seal push pacing/circuit scope to the production singleton: release rollout requires a clean checkout at the reviewed deployment commit, verifies the exact Terraform-root inventory/digest before network access and again at roll, invokes only the pinned tracked deployment owner, and passes the seal for a third recomputation inside its production-infrastructure lock before credentials/plan/apply; source drift and horizontal/overlapping runtimes refuse until an external provider fence exists.
- [x] Treat APNs delivery as non-blocking to finalization while failing production startup/release closed on missing provider configuration.
- [x] Verify the complete Rust suite, lint, formatting, release-selection, and release-preflight contracts.
- [x] Publish signed production release v0.8.14 from source commit
  `181d1131211ee986d8c6897339ebaff62ee8f532` and roll the attested image
  `sha256:f64359c5370e79c3d15b1a1d2dd76e793bd0fbed12906e82e40f5b3f7f891ee7`
  to production. The signed v0.8.13 image remains non-deployable and untouched:
  its attested manifest omitted the selected production profile, and the release
  wrapper correctly rejected it before rollout.

# ADR-0022 task evidence

## Encrypted lifecycle page-store seam

- [x] Added a strict versioned AES-256-GCM envelope with a control-DEK-derived
  independent key, separately domain-derived retry-stable nonce, and AAD
  covering the full exact page name, archive, deletion fence, ordinal, page
  ID, predecessor, hash, and encoded length.
- [x] Added deterministic exact-name immutable create plus authenticated exact
  readback reconciliation; encrypted control durably admits every create as
  outcome-unknown first, and sealing requires the complete exact Created set.
- [x] Added a durable pre-page snapshot commitment that requires every artifact
  and witness create to be settled, advances the exact revision, and rejects
  later artifact reconciliation so cancellation/restart cannot change page bytes.
- [x] Persisted the sole unresolved page's exact bounded bytes and ordered split
  until authenticated readback; restart recovers that exact typed plan and
  conflicting partitions fail before remote I/O.
- [x] Bound exact all-generation and soft-delete absence cleanup to durable
  control physical completion, a frozen/drained prior-create proof, and
  producer-private durable/absence receipts.
- [x] Kept the seam construction-only: no concrete provider, credential,
  runtime/startup/Store/route wiring, reachability walker, pre-witness
  coordinator, cloud mutation, or deployment authority was added.

This compiled seam does not authorize archive-v3 persistence or deletion.

## Authenticated deletion-inventory coordinator

- [x] Replaced final lifecycle-page `PlannedArtifact` payloads with strict
  canonical key/role/ciphertext-hash facts; create attempt, ordinal, state, and
  encoded length remain only in the frozen create-ahead snapshot.
- [x] Introduced a separate KILP-v2 codec, page-hash domain, and inventory-seal
  domain while retaining the independent lifecycle control-anchor format v1;
  the never-live page v1 is rejected rather than migrated.
- [x] Added injected exact Tombstoned witness and encrypted-control boundaries,
  current/predecessor authenticated reachability union, exact object-ID
  dedup/conflict handling, and deterministic greedy paging under combined
  object/key/page/entry/encoded limits.
- [x] Revalidate the complete witness recovery and frozen control snapshot
  immediately before page I/O and before the atomic seal; cancellation/restart
  accepts only the durable Created prefix and sole unresolved exact next page.
- [x] Authenticate exact Tombstoned deletion authority before the snapshot CAS,
  then reauthenticate the unchanged record after freeze and before the graph's
  first exact read, so wrong credentials/Active state cause zero control or
  external I/O.
- [x] Require a producer-private one-shot coordinator proof binding the frozen
  snapshot, canonical plan, exact references, and authenticated readbacks at
  the control seal CAS; removed raw/generic pages-to-seal entry points.
- [x] Added a restart-only sealed loader that validates the full reference set
  before GET, authenticates the exact v2 chain/count/terminal/global object set,
  and mints deletion inventory with exactly the lifecycle seal commitment.
- [x] Removed the deletion driver's obsolete independent inventory builder,
  test-overwritten commitment, and `FullReachabilitySeal`.
- [x] Kept pre-witness absence, Store/startup/runtime/config/routes/health,
  provider construction, deletion-driver invocation, cloud I/O, and deployment
  out of scope and disconnected.

This compiled coordinator does not activate archive-v3 persistence or deletion.

## Pre-witness exact-absence disposition capability

- [x] Atomically enroll each new lifecycle reservation in a versioned,
  domain-committed initial-witness protocol; legacy/missing/unknown enrollment
  is manual and never inferred unsent.
- [x] Persist exact prepared witness hash/length and admitted revision, then
  require a producer-private non-cloneable send-start receipt before the
  Firestore commit boundary.
- [x] Serialize deletion with dispatch so unstarted and started/ambiguous
  creates close into distinct monotonic phases; generic witness reconciliation
  cannot forge absence or unknown-send state.
- [x] Authenticate the tombstoned control binding, lifecycle, protocol, and
  deletion fence before any exact-name witness read; only closed-unsent plus a
  fresh `None` and full-state CAS mints a private absence proof.
- [x] Persist facts rather than proof authority: restart and remint require full
  row validation and another exact absent read, while started `None` remains
  manual and a later exact retained record may resolve present.
- [x] Support reservation/objects-prepared deletion with an exact candidate-free
  closed tuple; permanently poison any later exact, mismatched, malformed, or
  noncanonical present document so confirmed absence cannot resurrect.
- [x] Seal the Genesis witness-create surface to the commit-start-aware
  Firestore creator and recover a crash-after-commit only through the retained
  exact send-start adoption CAS.
- [x] Keep this capability disconnected from deletion-driver invocation,
  Store/startup/runtime/config/routes, provider construction, credentials,
  cloud mutation, deployment, and user-visible behavior.

## Type-separated pre-witness inventory capability

- [x] Consume the fresh absence proof exactly once into a separate versioned
  encrypted-control snapshot binding the complete absence/protocol/bootstrap/
  fence/revision tuple and every settled create-ahead fact.
- [x] Enforce exactly one normal-tombstone or pre-witness inventory branch;
  dual rows, stale revisions, unknown versions, unresolved creates, or tuple
  corruption fail closed before page I/O.
- [x] Reuse only the exact-name page producer under one deterministic plan,
  with fresh durable revalidation before page I/O and seal, exact restart of a
  created prefix/sole unresolved next page, rejection of every zero-plan or
  alternate page before durable admission, and no reachability or metadata GET.
- [x] Represent a reserved zero-object archive as zero pages/artifacts and a
  zero terminal hash under a nonzero, domain-separated branch commitment;
  never create an empty KILP page.
- [x] Load the sealed chain into a separate opaque non-authorizing complete
  inventory with no conversion, entry, provider, or deletion-driver surface.
- [x] Keep startup/Store/runtime/config/routes, provider construction,
  destructive invocation, cloud mutation, deployment, and user-visible
  behavior disconnected.

This compiled capability does not itself authorize provider I/O and does not activate archive-v3
persistence or deletion.

## Durable pre-witness deletion execution protocol

- [x] Added a separate versioned encrypted-control execution row that binds the
  exact pre-witness snapshot/seal revisions, bootstrap attempt, random nonzero
  operation ID, ordered object-set commitment, dimensions, terminal hash, and
  inventory commitment.
- [x] Consume the complete authenticated pre-witness inventory only through a
  producer-private conversion; IDs alone cannot recover execution authority,
  and there is no conversion to normal witnessed deletion types.
- [x] Revalidate the immutable tombstoned/fenced absence branch, deterministic
  Created page set, snapshot, seal, and absence of the normal branch before
  first bind, adoption, recovery, and every evidence CAS.
- [x] Enforce the monotonic inventory-bound -> registry-erased ->
  objects-absent -> physical-complete -> reserved payload-erased matrix with
  full-row exact replay and rejection of alternate, skipped, regressed, zero,
  cross-operation, or structurally invalid evidence.
- [x] Own the sole control SQLite handle outside the shared cache across each
  execution flush, so cancellation/failure forces an authoritative reload and
  lost PUT success is accepted only by exact encrypted-ciphertext readback;
  no local-only stage can mint a recovery capability.
- [x] Preserve the explicit zero-object geometry under nonzero inventory,
  object-set, and execution commitments without creating object/provider
  access, and test close/reopen recovery at every stage.
- [x] Keep all production destructive evidence producers, provider interfaces,
  page cleanup, payload cleanup, driver invocation, Store/startup/runtime/
  config/routes, cloud mutation, deployment, and user-visible behavior out of
  scope and disconnected.

This PR-A protocol persists capability facts only. Destructive execution and cleanup remain
separate activation blockers.

## WAL logical idempotency activation gate

- [x] Add fixed versioned operation kinds, nonzero opaque caller-stable IDs,
  domain-separated bounded request fingerprints, bounded canonical replay
  results, and sealed per-domain mutation/replay plans.
- [x] Define the sealed per-domain ledger contract and a test-only bounded
  exemplar: each future domain owns a distinct hard-capped row family and exact
  indexed resolver; no universal table, full scan, or production implementation
  exists. Prove atomic apply/replay, caps-before-SQL, conflict, rollback,
  corruption, restart, and serialization behavior.
- [x] Add a private test-only Store WAL policy that leaves all production
  constructors on legacy snapshots and rejects generic mutation, dirty save or
  eviction, legacy-envelope rewrite, and schema migration without provider PUT.
- [x] Structurally pin all 148 production Store mutation/save call expressions,
  all 15 factory-definition/call/literal construction sites, all 41 policy
  selectors/references, and 24 async or dedicated-thread worker spawns—including full owning bodies and
  cross-helper B dependencies—in an exact reviewed A/B/C inventory. Scanner
  fixtures prove comments/literals/test items/nested functions, qualified calls,
  new factories, or conditional-main policy selection cannot hide drift.
- [x] Keep capture/result acknowledgement, archive publication, root/witness
  authority, routes, workers, startup/config, providers, cloud mutation, and
  deployment entirely disconnected.
- [x] Add the inactive one-owner local mutation/capture and durable publication
  protocol with a dedicated SQLite blocking lane, exact pending-send recovery,
  permanent authenticated current-staging replay, kind-scoped durable identity,
  and deterministic bounded artifact topology. This owner slice introduced no
  production domain implementation, runtime launcher, or acknowledgement.
- [x] Add the inactive single-archive publisher/checkpoint worker behind the
  maintenance handoff: a shared adequate-lifetime/heartbeat/reacquire lease
  manager; owned blocking SQLite construction and cleanup-owning streamed
  checkpoint reads; exact deterministic chunk/manifest/root admission and
  full-row recomputation; pending-send lost-success reconciliation; atomic
  consumption of terminal logical/checkpoint comparison rows before later
  owner-binding transitions; checkpoint-stage-aware source heartbeats that do
  no lease mutation after candidate/send admission; and exact witnessed
  recovery through a create/get-only provider capability. It remains private
  and has no external launcher caller, route, startup, config, list/delete, or
  serving path.
- [x] Implement separately reviewed production A-domain codecs and launcher
  ownership; refactor B domains with stable attempt identity; keep C domains
  fail-closed before enabling the Store policy outside tests.
  - [x] Add the first inactive production A-domain for capture-session finish:
    a caller-session-derived opaque operation ID, closed versioned request and
    exact finish-receipt codecs, and a distinct 65,536-row/128-MiB permanent
    replay ledger that reserves capacity before domain SQL. Missing-session
    preconditions and late ledger failures roll back without consuming the
    identity; exact committed replay survives reopen. It has no launcher,
    route, Store policy, provider, task, or acknowledgement wiring.
  - [x] Add the inactive Vertex usage terminal-outcome A-domain for an already
    durable event: exact normalized response, ambiguous, and not-billed request
    variants derive one opaque ID from the strict vtx event identity, apply
    only from started or exactly adopt the same terminal facts, refresh
    coverage only on the first transition, and retain unit replay in a distinct
    1,048,576-row/32-MiB permanent ledger. Missing/substituted events, cap
    exhaustion, late ledger failure, and tamper fail closed. The B-domain event
    allocator and every Store/worker/launcher/provider/ack path remain absent.
  - [x] Add the first inactive B-domain identity refactor for screen Vertex
    invocation begin: the complete reserved/leasing work topology mints both
    an exact predecessor and a post-usage-stable attempt commitment plus a
    deterministic `vtx_` event ID before actor admission. The account, work,
    both commitments, model,
    location, and caller-fixed canonical attempt time are bound in a distinct
    1,048,576-row/128-MiB permanent ledger and typed receipt. The same
    transaction inserts the exact started billing event and deterministically
    full-tuple advances its monthly coverage row. Existing-event adoption,
    changed same-attempt requests, insufficient two-minute lease window,
    expired or substituted work, cap exhaustion,
    late ledger failure, partial schema, tamper, and reopen fail closed or
    exactly replay; a genuinely renewed work attempt derives a new identity.
    The separately reviewed production-facing screen-result v2 contract now
    consumes this binding; media reads, provider calls, clocks/random IDs,
    Store, worker/launcher/task/retry/acknowledgement wiring remain absent.
  - [x] Bind the inactive screen-storyboard result to the exact sealed Vertex
    attempt: the version-2 request carries the binding commitment, reauthenticates
    the complete permanent attempt row and typed receipt, and compares its
    post-usage-stable work commitment to the current terminal work before any
    result write. Replay reauthenticates the permanent binding, first apply
    exact-reads its result ledger row before commit, and substituted work or
    binding/ledger tamper fails closed. The historical v1 request identity and
    encoding remain test-covered behind a test-only constructor; provider/media
    I/O, Store, worker/launcher/task/retry/acknowledgement wiring remain absent.
  - [x] Add the inactive metadata-only screen-reference batch A-domain: the
    existing deterministic batch ID is subtype-separated from singular capture
    identity before actor admission, the complete normalized manifest vector is
    fingerprinted under the 1-MiB gate, and all new/duplicate rows plus stream
    acknowledgement and the exact bounded response share one transaction with a
    distinct 1,048,576-row/512-MiB permanent ledger. Missing or changed canonical
    evidence, a changed same-ID manifest, cap exhaustion, late ledger failure,
    partial schema, tamper, and reopen all fail closed or exactly replay. Canonical
    media upload and its B-domain DEK/provider handoff remain unsupported, and no
    Store/route/launcher/provider/task/ack path is connected.
  - [x] Add the inactive local canonical-capture receipt A-domain: the stable
    caller event ID is subtype-separated before actor admission, while the
    account, complete normalized manifest, exact derived account-bound object
    key, and positive provider generation already fixed by a future B upload
    handoff form the request fingerprint. It rejects unledgered target adoption,
    authenticates existing session/stream bindings, and atomically commits every
    local session/stream/event/media/browser/pending-job row, contiguous stream
    acknowledgement, bounded canonical response, and a distinct
    1,048,576-row/512-MiB permanent ledger. Changed receipts, parent mismatch,
    collisions, capacity exhaustion, late ledger failure, partial schema, and
    reopen fail closed or exactly replay; a later gap-filling event advances the
    acknowledgement. DEK allocation/loading, media bytes, encryption/provider
    I/O, billing, Store/route/launcher/task/ack wiring, and the authenticating B
    handoff remain absent.
  - [x] Add the inactive media-DEK installation half of the canonical upload B
    boundary. A future KMS adapter must supply one bounded canonical wrapped
    value together with the plaintext DEK it represents; the plan retains no
    plaintext key and derives a keyed account/wrapper binding before actor
    admission. One immediate transaction first-writer-wins installs or exact-
    adopts `wrapped_media_dek`, exact-reads it, and commits a subtype-separated
    request, commitment-only typed receipt, and a distinct one-row/1-KiB
    permanent ledger. A changed candidate conflicts, another account cannot
    consume the per-database slot, and wrapper/schema/ledger/counter tamper,
    capacity, late readback failure, and reopen fail closed, roll back, or
    exactly replay. The KMS producer that proves the wrapper/plaintext pairing,
    media encryption/upload candidate, send-start fence, provider receipt,
    Store/route/launcher/task/retry/acknowledgement wiring remain absent.
  - [x] Add the inactive historical selected-screenshot receipt A-domain: a future B
    boundary must durably choose the 128-bit opaque upload attempt and exact
    account-bound object key before provider I/O; that stable attempt derives
    the operation identity and the complete episode/source/time/JPEG receipt is
    fingerprinted before actor admission. Exact eligibility, screenshot binding,
    receipt insertion or exact pre-existing adoption, bounded canonical response,
    and a distinct 1,048,576-row/512-MiB ledger commit atomically. Alternate
    object or screenshot bindings, cap exhaustion, late ledger failure, partial
    schema, result tamper, and reopen all fail closed or exactly replay. The
    media-DEK allocator, encryption/upload attempt, Store/route/launcher/provider/
    task/ack path, and cleanup remain absent.
  - [x] Add the inactive selected-screenshot upload-attempt B identity: one
    caller-fixed 128-bit opaque attempt ID derives a subtype-separated operation
    identity and exact account-bound object key before provider I/O. A
    domain-separated predecessor commits the complete eligible screenshot
    membership/classification, episode image budget, requested time, and JPEG
    geometry/hash; one immediate transaction reserves pending count/bytes against
    the 24-image/4,000-KiB episode limits and settles the full request, exact
    numeric screenshot identity, permanent binding, typed receipt, and a distinct
    1,048,576-row/128-MiB replay ledger. Exact local consumption transfers the
    accounting from pending to committed without double-counting; an absent or
    inexact result remains reserved fail-closed. Same-attempt
    changes conflict, an alternate attempt cannot reserve the same target, a
    different eligible target receives a different identity, and
    stale/consumed targets, budget overbooking, rebound screenshot identities,
    ledger capacity exhaustion, late readback failure, partial schema, tamper,
    and reopen fail closed or exactly replay. Random/clock/DEK
    allocation, media bytes, encryption/provider I/O, Store/route/launcher/task/
    retry/cleanup/acknowledgement wiring remain absent. The separately reviewed
    authenticated C termination child now releases only an exact definitive-
    no-object reservation for a different target; the original target remains
    permanently burned.
  - [x] Add the inactive selected-screenshot ciphertext-candidate continuation.
    Its constructor accepts only the exact attempt binding, typed installed-
    media-DEK receipt, borrowed validated JPEG/DEK, and caller-supplied
    context-bound ciphertext. Before actor admission it checks the JPEG hash and
    length, revalidates the DEK receipt against the same plaintext key, exact-
    decrypts the ciphertext under the account/object AAD, and derives a keyed
    candidate commitment. One immediate transaction requires the exact
    unconsumed attempt and installed-DEK ledgers, retains only ciphertext and
    commitments, exact-reads the row, and advances full counters under a
    1,048,576-row/128-MiB-result/512-MiB-ciphertext cap. Exact replay may survive
    later matching A settlement. A private exact-name restart loader preflights
    stored lengths, requires the account/attempt plus borrowed DEK, decrypts and
    reconstructs the complete candidate, and returns only that named ciphertext
    and receipt. Changed bytes/key/AAD/predecessors, consumed first apply, cap
    exhaustion, partial schema, row/counter tamper, and late readback failure
    reject or roll back. Its authenticated payload/loader/ciphertext getter are
    confined to the private WAL family. KMS production, send-start, provider
    I/O/readback/outcome, Store/route/launcher/task/retry/delete/list/cleanup/
    acknowledgement wiring remain absent; the separate inactive C child blocks
    new candidate admission after an exact terminal.
  - [x] Add the inactive selected-screenshot `SendStarted` continuation. Its
    constructor accepts only the private exact-name candidate payload that was
    reauthenticated with the borrowed media DEK. It derives one deterministic
    256-bit send request ID and a separate binding over the exact candidate
    fingerprint, B/DEK/AAD/ciphertext commitments, object, and account. One
    immediate transaction requires the exact candidate and an unconsumed B
    attempt on first apply, inserts the marker and complete binding in a
    distinct 1,048,576-row/256-MiB-result ledger, full-counter-CASes, and
    exact-reads before commit. Replay reauthenticates the candidate and may
    survive later matching A settlement. A private exact-name restart loader
    requires account/image plus borrowed DEK and returns only the original
    retained ciphertext with a non-cloneable marker receipt after both ledgers
    reauthenticate. The parent receives only an opaque marker plan from a
    WAL-owned pre-marker factory. Both pre-marker and post-marker ciphertext
    payloads/loaders remain confined to the private WAL family; only the
    provider-proof child can consume the latter. Changed
    candidate/marker/request facts, consumed first
    apply, partial schema, row/counter tamper, and late readback failure reject
    or roll back. Provider construction/I/O/readback/outcome authentication,
    KMS production, Store/route/launcher/task/retry/delete/list/cleanup/
    acknowledgement wiring remain absent; the separate inactive C child fences
    provider preparation after an exact terminal.
  - [x] Add the inactive provider-neutral selected-screenshot outcome proof
    boundary. It can prepare only from the exact-name, DEK-authenticated
    `SendStarted` marker plus the exact installed wrapped DEK, then grants an
    injected transport only one conditional create and one bounded exact-name
    readback. Before returning the sole owned request, one immediate transaction
    retains a bounded full-binding execution claim; duplicate preparation or a
    lost request is fail-closed/manual rather than retry authority. Exact
    ciphertext, wrapped-key metadata, request identity, and a
    positive generation mint a non-cloneable accepted proof. Only a separately
    classified definitive no-create response followed by exact absence mints a
    non-cloneable rejection proof. Lost/unknown/unavailable outcomes retain the
    reservation, while collisions, malformed evidence, claimed creates without
    exact readback, and protocol/size faults require manual handling. It never
    retries and has no concrete transport, GCS/Store client, enumeration,
    delete, KMS, clock/randomness, externally callable A settlement, route, launcher, task, cleanup,
    acknowledgement, startup, or serving wiring. Its rejection proof can be
    consumed only by the separate inactive C child below.
  - [x] Add the inactive selected-screenshot definitive-no-object C settlement.
    Its constructor consumes only the provider boundary's non-cloneable
    rejection proof plus a caller-fixed canonical observation time. One
    immediate transaction reauthenticates the exact execution claim, complete
    permanent B attempt, ciphertext candidate, `SendStarted` marker, exact
    rejection proof, and continued absence of any local or A result before inserting a distinct
    unit-result terminal ledger with full counter CAS and exact readback.
    Exact replay and exact-name restart reauthenticate the entire chain without
    retrying the provider. The original target stays permanently burned, while
    only a fully authenticated terminal releases its episode count/bytes for a
    different target; missing, partial, conflicting, or tampered C state stays
    reserved fail-closed. Provider-accepted A-v3 admission, new candidate admission, and provider
    request preparation reject the exact terminal. Unknown/unavailable/manual
    outcomes cannot construct C. It has no provider transport, retry, Store,
    KMS, list/delete, clock/randomness, route, launcher, task, cleanup,
    acknowledgement, startup, or serving wiring.
  - [x] Bind the historical selected-screenshot A-v2 receipt to the exact
    permanent B attempt. The version-2 request uses a distinct operation domain,
    carries the B binding commitment, reconstructs the full B row and typed
    receipt, exact-matches every account/image/object/episode/source/time/JPEG
    fact, and admits only the B-bound numeric screenshot ID before any local
    result write. Exact post-insert lookup and replay reauthenticate the B row,
    exact local result, and source/member topology. Missing, substituted, or
    tampered attempts, rebound results, and a late binding failure roll back or
    fail closed. Exact C termination blocks this local A settlement. The
    unbound v1 and B-only v2 constructors/contracts are now test-only.
  - [x] Upgrade the sole production selected-screenshot A settlement to a
    provider-accepted v3 contract. A WAL-private factory consumes the
    non-cloneable exact positive-readback proof, derives every local fact from
    the permanent B row, and reauthenticates B, ciphertext candidate,
    `SendStarted`, the one-shot execution claim, positive provider generation,
    accepted-readback commitment, and continued C absence before any local
    write. One immediate transaction rejects unexplained pre-existing local
    rows, inserts and exact-checks the screenshot/source/member binding, retains
    a schema-revision-2 full typed A row, counter-CASes, reconstructs that row,
    and exact-reads the result before commit. Exact-name restart/replay performs
    no provider I/O and repeats the complete chain; A and C are mutually
    exclusive, while losing the accepted proof before A commits is deliberately
    manual/no-retry because the one-shot execution claim is already durable.
    Typed-row/proof/local/counter tamper and late readback failure fail closed or
    roll back. Concrete provider/KMS construction, Store/route/launcher/task/
    retry/cleanup/acknowledgement/startup/serving wiring remain absent.
  - [x] Add the inactive caller-stable finalization-queue A-domain: an exact
    128-bit request ID plus stable account derive the opaque operation before
    actor admission, while the episode, fixed target version, caller-supplied
    canonical queue timestamp, and complete predecessor status/error/attempt/
    schedule/timestamp tuple form the request fingerprint. Only a supported
    non-current, non-queued predecessor can full-tuple transition to `queued`;
    retry outcome and schedule fields clear in the same transaction as unit
    replay in a distinct 1,048,576-row/32-MiB ledger. Changed rows, request-ID
    reuse, time regression, cap exhaustion, late ledger failure, partial schema,
    tamper, and reopen fail closed or exactly replay. Request/clock allocation,
    finalizer scheduling/invocation, Store/route/launcher/task/acknowledgement
    wiring, and retry-state mutation remain absent.
  - [x] Add the inactive exact finalization-commit A-domain: the already durable
    Vertex event ID derives the opaque operation before actor admission, while
    the exact terminal provider-result facts are authenticated and their
    commitment, a caller-supplied canonical commit time, complete episode finalization tuple,
    exact utterance/screenshot membership, prior brief/screen-product commitment,
    normalized new brief and canonical screen product, and every preallocated
    initial webhook/email/push row form the request fingerprint. One transaction
    reauthenticates those facts, atomically replaces the complete product,
    inserts only the already-fixed initial outboxes, preserves original time on
    regeneration, full-tuple completes the episode, exact-reads the result, and
    retains unit replay in a distinct 1,048,576-row/32-MiB ledger. Changed
    membership/product/duplicate/outbox facts, attempt reuse, capacity, late
    ledger failure, partial schema, tamper, and reopen fail closed or exactly
    replay. Vertex/destination/delivery/handoff/clock allocation, model/provider
    calls, Store, worker/launcher/task/retry/acknowledgement wiring remain absent.
  - [x] Add the first inactive deterministic media-work-result subtype for
    screen storyboards without person evidence: an already durable terminal
    Vertex event derives the opaque operation before actor admission, while its
    exact normalized provider-result facts, caller-supplied canonical commit
    time, complete leased work/member/job/capture/media predecessor, requested
    model, caller-fixed screenshot IDs, and bounded ordered screen product form
    the request fingerprint. One transaction reauthenticates all of those
    facts, inserts only the exact screenshots and observations, full-tuple
    settles every job/media row and the work unit, exact-reads the complete
    result, and retains unit replay in a distinct 1,048,576-row/32-MiB ledger.
    Attempt/work/result substitution, auto IDs, time regression, target
    collisions, capacity, late ledger failure, partial schema, tamper, and
    reopen fail closed or exactly replay. The B boundary that durably binds the
    attempt to this work, provider/media reads, Store, launcher/task/retry/
    acknowledgement wiring, screen person evidence, and every audio/person/
    identity/voice result remain absent.
  - [x] Add the inactive raw-media retention-settlement A-domain: the stable
    account/event identity derives one opaque operation before actor admission,
    while the exact account-bound object key, bucket-local generation/backend,
    plaintext hash, retention deadline, eligible ready/failed predecessor, and
    fixed terminal timestamp form its request fingerprint. Only an exact row can
    become pruned or be adopted as an identical pre-existing terminal, and a
    distinct 1,048,576-row/32-MiB ledger reserves capacity before domain SQL.
    Substituted provider facts, early or ineligible rows, cap exhaustion, late
    ledger failure, partial schema, result tamper, and reopen fail closed or
    exactly replay. The future provider deletion boundary must settle the exact
    object before constructing this plan; Store/provider list/read/delete,
    worker/launcher/task/acknowledgement wiring remain absent.
  - [x] Add the inactive provider-accepted email A-domain: the already durable
    delivery ID remains the external idempotency key and derives one opaque
    operation before actor admission. The exact pending/retry predecessor row,
    provider message ID, 2xx status, and fixed settlement timestamp are all
    fingerprinted. A full-row CAS or exact terminal adoption and a distinct
    1,048,576-row/32-MiB permanent ledger commit atomically. Missing or changed
    predecessors, alternate provider facts, cap exhaustion, late ledger failure,
    partial schema, tamper, and reopen fail closed or exactly replay. Sending,
    retry allocation/timing, Store/worker/launcher/task/acknowledgement wiring,
    and, in that slice, the webhook/push delivery domains remained absent.
  - [x] Add the inactive provider-accepted APNs A-domain: the already durable
    delivery UUID is sent as `apns-id` and derives one opaque operation before
    actor admission. The exact installation/episode/handoff/collapse binding,
    pending/retry predecessor row, definitive 200 status, and fixed settlement
    timestamp are all fingerprinted. A full-row CAS or exact terminal adoption
    and a distinct 1,048,576-row/32-MiB permanent ledger commit atomically.
    Missing or changed predecessors, alternate provider facts, cap exhaustion,
    late ledger failure, partial schema, tamper, and reopen fail closed or
    exactly replay. Sending, retry allocation/timing, installation mutation,
    Store/worker/launcher/task/acknowledgement wiring, and, in that slice, the
    webhook delivery domain remained absent.
  - [x] Add the inactive definitive-success webhook A-domain: the already
    durable event ID is sent as `webhook-id` and derives one opaque operation
    before actor admission. The exact episode/subscription/version binding,
    pending/retry predecessor row including nullable due time, 2xx status, and
    fixed settlement timestamp are all fingerprinted. A full-row CAS or exact
    terminal adoption and a distinct 1,048,576-row/32-MiB permanent ledger
    commit atomically. Missing or changed predecessors, alternate provider
    facts, cap exhaustion, late ledger failure, partial schema, tamper, and
    reopen fail closed or exactly replay. Signing/sending, subscription lookup
    or disablement, retry allocation/timing, Store/worker/launcher/task/
    acknowledgement wiring remain absent.
  - [x] Add the inactive exact reviewer-fixture A-domain: the image-baked
    reviewer account UUID plus fixture version derive one opaque operation
    before actor admission. The complete fixed synthetic audio, utterance,
    screenshot, episode, membership, brief, watermark, and marker families are
    inserted or exactly adopted in one transaction with a distinct 64-row/
    576-byte permanent replay ledger. Fixed-ID collisions, changed or extra
    fixture membership, a conflicting marker, cap exhaustion, late ledger
    failure, partial schema, tamper, and reopen fail closed or exactly replay.
    Reviewer authentication, Store/save, route/launcher/task/acknowledgement
    wiring and the unrelated backfill subtypes remain absent from this fixture.
  - [x] Add the inactive ADR-0009 substance-backfill A-domain: each stable
    account/cursor/phase identity fingerprints one bounded, strictly ordered
    next prefix of exact rendered episode inputs, predecessor substance values,
    and validated classifications. The child reauthenticates and updates that
    prefix, advances a private cursor, and retains unit replay atomically in a
    distinct 65,536-row/576-KiB ledger. A short batch cannot skip a later row;
    only an exact empty tail writes the completion marker, and an exact legacy
    marker may be adopted. Changed source/predecessor/result, cursor disorder,
    cap exhaustion, late ledger failure, partial schema, tamper, and reopen fail
    closed or exactly replay. Inference reservation/Vertex calls, Store/save,
    launcher/task/acknowledgement wiring, and visual-evidence backfill remain
    separate.
  - [x] Add the inactive ADR-0010 visual-evidence-backfill A-domain: each stable
    account/cursor/phase identity fingerprints at most sixteen strictly ordered
    eligible episodes, their exact bounded text-only screenshot evidence,
    canonical `normal`/`none` predecessors, and validated `none`/`useful`
    classifications. Sixteen maximum Unicode inputs fit the shared one-MiB
    request cap. The child deterministically binds at most 120 nonduplicate
    member screens per episode, full-tuple updates the exact next prefix,
    advances a private cursor, and retains unit replay atomically in a distinct
    65,536-row/576-KiB ledger. A short batch cannot skip; only an exact empty
    tail writes the completion marker, and an exact legacy marker may be
    adopted. Source/eligibility/membership/evidence/result changes, cursor
    disorder, cap exhaustion, late ledger failure, partial schema, tamper, and
    reopen fail closed or exactly replay. Pixel loading, inference reservation/
    Vertex calls, Store/save, launcher/task/acknowledgement wiring remain absent.
  - [x] Convert the remaining reviewed A domains, add the single-archive
    launcher owner, refactor every B dependency around stable attempt identity,
    and retain structural C rejection before activation review. The private
    launcher consumes only the parity-certified maintenance handoff, re-reads
    its exact terminal Control row, and owns one non-cloneable actor whose
    sealed type-erased queue serializes different reviewed plan types without a
    generic SQL/result escape. It has no caller or startup/Store/route/config/
    acknowledgement/provider-list/provider-delete/cloud/deployment authority.
  - [x] Complete the inactive activation-readiness review in
    `docs/adr/0022-activation-readiness.md`. Production remains explicitly
    blocked on the Phase-1 controller/resources/telemetry, strict tmpfs-size and
    signed security/advisory-drill evidence, and an operator-authorized canary/
    cloud change. Enabled-domain/provider adapters, authority ownership, Store/
    acknowledgement wiring, and mutation-lifecycle drills remain separate
    Phase-2 blockers. _(That document is now a superseded historical record: every
    boundary it reviews was deleted in `#288`/`#289`, and none of its blockers is
    a live prerequisite.)_
  - [x] Record the final production decision package in
    `docs/adr/0022-production-activation-runbook.md`. It separates the one-
    archive, empty-mutation, legacy-authoritative Phase-1 canary from the later
    plan-allowlisted Phase-2 tmpfs-eligible authority and the Phase-3/4/5 work
    required for an all-user rollout; fixes the exact evidence, execution order,
    rollback/no-go rules, and authority handoff; and performs no activation or
    external mutation. _(Superseded: both authorization boundaries were deleted
    rather than performed, so its prerequisite table no longer describes the
    tree. All five ADR-0022 activation documents now carry supersession banners.)_
  - [x] **Deleted the advisory-owner/Phase-2 family instead of finishing it**
    (`#288`/`61ae996`, `#289`/`9b2f87e`; ~24k net lines). The genesis-first
    replan drops retention of existing archive data, so there is nothing to
    migrate, no advisory canary to observe a migration, and no Phase-2
    authority to acquire afterwards. Removed: the 13-module advisory-owner
    family, the Store's advisory capture/retirement/abort surface, the
    control-plane advisory owner/canary/controller/Phase-2 code, the
    maintenance importer's advisory-shadow target arm, the shadow-runtime
    advisory views, the VFS advisory drain, the Firestore-shadow advisory
    witness impl, the `--run-archive-v3-phase1-canary` argv entry, and the
    eight phase1/phase2 signer/provision scripts. With the Phase-2 admission
    went `full_reviewed_mutation_set_commitment`, the compile-pinned gate that
    had forced an offline re-signing ceremony for every new `WalOperationKind`
    ordinal — which is what let `#290` add `SchemaEpochAdvance = 13` freely.
    Deliberately kept: all advisory DDL plus `migrate_advisory_abort_locus`
    (schema removal is its own atomic PR, since dropping a table without its
    migration bricks every replica on startup), the compilation keepers
    `ensure_advisory_release_absent` and `release_advisory_lease_unresolved`,
    the witness's advisory-terminal predicates, `Phase2AcquisitionStage::from_db`
    (old rows must decode; the minting `as_db` went), and the `shadow_capture`
    field. The 1,605-line advisory existence pin became a 28-line severance pin.
    **The two open activation items that stood here — supplying the real
    three-root trust configuration for Phase 1, and reviewing the Phase-2 plan
    allowlist afterwards — are void**, along with the Phase-3/4/5 all-user
    rollout ladder they fed. Phase 1 and Phase 2 no longer exist as rollout
    stages. (ADR-0022 "Phase 3" as an *extent/shadow paging architecture* is a
    different, still-live concept; see the Phase 3 section below.)
  - [ ] Design and review a genesis-first activation plan against the surviving
    WAL owner, genesis bootstrap, and schema-epoch ladder. The five ADR-0022
    activation documents are superseded historical records and cannot be
    amended into one; their data-safety core (fail closed, one reviewed change
    at a time) and the archive-bucket/WIF/registry-KMS/named-witness resource
    shapes remain valid inputs.
  > _The completed items from here to the end of this section record the
  > advisory-owner/Phase-2 boundary as it was built. **All of it was deleted in
  > `#288`/`#289`** (see the deletion entry above). They are retained as build
  > history; none of them describes code in the tree._

  - [x] Add the first inactive Phase-1 live-owner boundary without reusing
    WalAuthoritative state. A separate encrypted-Control row binds the exact
    `ParityVerified` operation and released ShadowWal witness to one random
    advisory owner, persists `SendStarted` before Firestore, adopts only its
    exact lost-response fence successor, and exact-reopens without a second
    send. The consuming runtime exposes witness read/acquire only; Store,
    capture, object/cipher access, lease succession, acknowledgements,
    startup/config/routes/tasks, provider list/delete, and deployment remain
    absent at that boundary. The exact lease lifecycle is added separately
    below before any owner-only Store capture is reviewed.
  - [x] Add the inactive advisory-owner lease lifecycle. The live non-cloneable
    owner alone may ask the witness to retain/heartbeat its exact ShadowWal
    fence or, only after the provider's trusted tick reaches expiry, reacquire
    the same owner at the canonical next fence. Encrypted Control authenticates
    the immutable parity terminal plus the exact one-step predecessor/successor,
    full-tuple-CASes the row, and adopts an ambiguous committed successor on
    restart. A reopened process cannot heartbeat the old fence and remains
    inert until it performs the exact post-expiry higher-fence reacquire. Root advance,
    Store/VFS capture, acknowledgement, startup/task/route wiring, and
    deployment remain absent; owner-only capture/comparison is next.
  - [x] Narrow the inactive Store capture injection to one exact validated
    user. The selection has no production constructor, every production Store
    remains capture-disabled, unrelated users never enter the named VFS, and
    capture failure still falls back to the unchanged legacy open. A separate
    reviewed advisory-owner handoff and independent comparison worker remain
    required before any canary.
  - [x] Carry a sealed exact Store/user/archive/import target from the freshly
    revalidated advisory maintenance terminal into the private advisory owner.
    Minting it scrubs scratch and drops the owned maintenance guards, while the
    permanent provider fence and Store/barrier blocked state remain fail-closed.
    Its Store handle and identity fields stay private and it has no operation
    or selector conversion. Capture installation and comparison remain separate
    inactive reviews.
  - [x] Add the inactive durable advisory-release ledger. Encrypted Control
    binds `Prepared -> DeleteStarted -> Released` to the exact parity terminal,
    exact bound advisory owner, maintenance fence, canonical marker-name
    commitment, positive generation, and exact-name absence proof. Preparing
    release permanently fences lease succession; every transition uses a full-
    tuple CAS and exact readback, and late failure rolls back. Store-token-gated
    marker/absence proof constructors are consumed only by the following exact-
    user executor; local unblock, selector installation, capture, startup,
    serving, route, task, and cloud authority remain absent.
  - [x] Add the inactive Store-owned exact advisory-marker executor. The
    consuming owner freezes lease work, acquires the same one-user lifecycle
    lock as maintenance, and freshly matches its exact retained witness before
    Control prepare; plan re-adoption plus a post-lock Control check reject
    a release row before provider I/O, including stale plans. The retained one-
    user target then derives only its HMAC marker name and exact-gets/authenticates the bound
    authority, metadata, and positive generation. Control must durably record
    `DeleteStarted` before Store can delete exactly that generation. Success or
    a lost response settles only through a fresh exact-name `NotFound`; missing
    pre-marker state, substituted metadata/authority, replacement generation,
    or unavailable read fails closed. Reopen of `Released` performs no provider
    operation. The target has no list/put/broad-delete surface and completion
    intentionally leaves Store/barrier admission blocked; local unblock,
    capture installation/comparison, startup, serving, route, task, cloud, and
    deployment authority remain absent.
  - [x] Add the separate inactive race-free local-resume transition. Maintenance
    now acquires only the exact-user lifecycle gate, repeats the terminal-release
    absence check while holding it, and only then closes Store/barrier admission;
    a stale waiter cannot reblock the user after release. The consuming terminal
    advisory owner retains that same lifecycle authority, freshly exact-reads the
    unchanged ShadowWal witness and full terminal Control row, and asks Store to
    clear the registry and raw-content gates while holding both gate locks. A
    partial gate state, open handle, active raw writer, changed witness, changed
    release, or wrong target fails closed. Before either gate reopens, Store
    installs the single shared bounded VFS and one exact-user selector while
    holding both gate locks, so no legacy handle can open in an uncaptured gap;
    unrelated users remain on the ordinary VFS and capture-open failure still
    preserves legacy behavior. The returned opaque target retains only that
    exact capture registry and initially has no Store connection, drain, provider,
    acknowledgement, task, route, startup, serving, cloud, or deployment
    authority; owner-only drain/comparison is next.
  - [x] Add the inactive owner-only capture drain. The resumed advisory owner
    can borrow its exact Store target to select only the complete prefix on the
    already-open exact-user capture registration. The non-cloneable drain has
    no production commit-byte getter or settlement operation. Detached count
    and bytes retain their fixed queue reservation, so dropping it restores the
    full prefix ahead of captures observed later even if the later generation
    faults; stream retirement instead scrubs it. An empty/missing/changing/wrong-registry handle fails
    closed, a second concurrent drain is rejected, and no writable Store
    connection is opened. Independent replay/comparison, durable evidence, acknowledgement,
    launcher/startup/route/config, cloud, and deployment authority remain next.
  - [x] Bind the inactive advisory drain to an exact legacy comparison
    snapshot. While the one-user Store actor is serialized, Store opens a
    derived-path read-only/query-only SQLite connection, begins and establishes
    its read transaction before selecting the complete capture prefix, and
    returns both only inside the same opaque non-cloneable value. Later writes
    are excluded from the pinned snapshot. No path, SQL, row, commit bytes,
    replay, comparison result, settlement, acknowledgement, provider, task,
    route, startup, configuration, cloud, or deployment surface is exposed;
    independent replay/comparison remains next.
  - [x] Add the inactive owner-private captured-prefix comparison worker. It
    reauthenticates the exact maintenance source, released owner row, and
    current ShadowWal witness before and after work; recovers only that
    witness-nominated R1 graph; replays the complete generation/frame/checksum-
    contiguous prefix onto cleanup-owned staging; backs up the already-pinned
    legacy transaction into a separately created 0600 staging file; and runs
    the existing full parity verifier. Caller cancellation leaves one owned
    task responsible for staging cleanup, cloned capture bytes zeroize on task
    exit, and an atomic exact-live restoration proof makes registration
    retirement win cleanly before evidence can be minted. The only output is
    a domain-separated non-cloneable opaque commitment. It cannot
    settle the drain, so the exact prefix restores after every match, mismatch,
    error, cancellation, or lost result while the registration remains live.
    Fault regressions cover pre/post source, release, and witness changes,
    capture-lineage substitution/gaps/reordering, parity mismatch, retirement,
    caller cancellation, and primary/recovered staging cleanup.
  - [x] Add the inactive one-shot durable comparison settlement. Encrypted
    Control accepts only the private successful evidence, binds it to the exact
    released owner/witness/revision/commitments, exact-reads the inserted row
    before commit, and exact-loads a retained terminal before any repeat local
    work after a lost response or owner restart. A changed evidence tuple
    conflicts and late readback failure rolls back atomically. The owner is
    consumed into a terminal type with no second comparison operation. This
    records only the comparison result: it does not settle the restored VFS
    drain, acknowledge a user operation, publish, or change authority.
  - [x] Retire the one-shot advisory capture only after that Control terminal
    is durable. A cancellation-owned Store task authenticates the exact
    archive/import target, serializes with its open SQLite actor, clears only
    the matching selector, takes and retires only the matching registration,
    and returns an opaque proof. Registration retirement scrubs the restored
    prefix and later queued bytes. Exact already-retired state reconciles after
    a lost local result; partial/substituted states fail closed. The legacy
    connection remains open and later writes remain authoritative without
    capture.
  - [x] Add the first inactive durable abort slice for an already-resumed
    canary. Control persists the exact released-owner predecessor and fixed
    stop/mismatch reason before Store retirement; only the opaque exact-target
    retirement proof finalizes `Aborted`. Comparison and abort exclude one
    another, restart is fenced, late readback rolls back, and finalized rows
    reopen exactly. Pre-owner and released-before-resume cleanup were left for
    separately reviewed slices.
  - [x] Add private restart reconciliation for a retained resumed-canary
    `Prepared` abort. Encrypted Control reauthenticates the exact
    release/owner/maintenance chain and comparison absence; the
    controller-owned Store then proves paired gates are unblocked and selector
    plus exact-user capture registration are absent while retaining the user
    lifecycle guard through the final full-tuple CAS. The worker is
    cancellation-owned, exact `Aborted` replay is read-only, a live/partial or
    substituted Store state fails closed, and no production caller exists.
  - [x] Add the inactive released-before-local-resume abort locus. The existing
    one-row abort ledger now durably distinguishes historical resumed-capture
    cleanup from released-gate restoration while preserving old commitment
    bytes through an additive defaulted migration. A read-only Store preflight
    retains the exact-user lifecycle guard; Control records the exact released
    `Prepared` row before Store atomically reopens both blocked legacy gates
    without capture; only the resulting opaque restoration proof can finalize
    `Aborted`. Normal resume checks abort absence before Store mutation under
    the same lifecycle, restart uses the existing exact local-absence proof,
    and no production caller or provider operation exists. Pre-owner marker
    and gate cleanup remains required before controller composition.
  - [x] Add the inactive one-shot advisory canary admission contract. One
    encrypted-Control row binds the exact private user/archive/import,
    maintenance/source/parity commitments, released witness, release-image
    digest, and operator-statement commitment. Its full-tuple
    `authorized -> consumed` CAS is atomic with the first advisory-owner
    reservation; reopen accepts only that exact scope/owner pair, while absent,
    substituted, partial, corrupt, or reused scopes fail closed. Authorization
    alone is inert.
  - [x] Add the inactive canary trust/issuance seam. A fixed-size canonical
    operator statement binds a scope-unique private-user commitment and the
    exact archive/import/maintenance/source/parity/released-witness/image
    tuple. One Ed25519 root authenticates it; an independently controlled
    second root authenticates an image assertion bound to the exact signed
    statement proof and digest. A third pairwise-distinct deployment-observer
    root authenticates the constant empty Phase-1 authoritative-mutation set,
    legacy-only acknowledgements, an exact maintenance-window/deployment/
    challenge tuple, zero serving replicas, and content-free monitoring/
    rollback policy commitments. Control inserts a separate exact precondition
    row with the scope, then consumes and binds both rows to the first
    owner in one transaction; `SendStarted` reauthenticates that relation.
    Roots must be nonzero and pairwise distinct; checked-in production anchors
    deliberately remain invalid and no signing key, environment/config
    override, live observer/attestation adapter, or caller exists.
  - [x] ~~Populate separately controlled operator, image-attestation, and
    deployment-observer public roots; review live Confidential Space claim/
    nonce and fresh deployment-state adapters; prove the launcher holds the
    maintenance window and zero-serving condition across import and owner
    admission; and deploy the exact monitoring and rollback policies whose
    commitments are signed.~~ **Void** — the three-root verifier and everything
    that consumed those roots was deleted in `#289`. The checked-in anchors
    were always deliberately invalid and no live attestation or
    deployment-observer adapter ever existed. The open question this item
    carried is worth restating for any future design: a post-import proof
    cannot retrospectively show the importer ran inside its window, so a
    launcher would have had to hold a freshly authenticated window and
    zero-serving condition across import, handoff, and owner admission without
    trusting the process clock.

This gate does not activate WAL persistence or change any user-visible runtime behavior.

## Firestore transport-probe release boundary

- [x] Made one exact checked-in, non-secret probe profile the sole input to both build
  selection and schema-v7 release verification; it starts `off` with an empty namespace.
- [x] Removed repository-variable and manual-dispatch witness inputs, forced evaluation
  and ordinary `main` images off, and limited `probe-v1` to exact
  `vX.Y.Z-witness-probe.N` prereleases that cannot use `release.sh --roll`.
- [x] Awaited the one-shot probe under a fixed deadline before application Store/KMS/GCS
  construction, emitted only one fixed redacted outcome, and retained no health/startup/
  archive-authority connection.

These release and runtime boundaries do not create a Firestore database, grant provider
IAM, publish a probe release, deploy an image, or activate archive-v3 authority.

## Sealed single-archive WAL runtime release boundary

- [x] Added a domain-separated SHA-256 commitment over one opaque archive ID and
  non-cloneable pending/durable/sealed capability types; binding consumes the
  pending provider graph exactly once and accepts only the encrypted-control
  `ArchiveBinding` whose commitment matches the image claim.
- [x] Retained synchronous zero-I/O construction, private archive/provider fields,
  no getters/callbacks/tasks/operations/acknowledgements/deletion methods, and an
  always-false hard-delete drain gate.
- [x] Versioned the sole checked runtime profile to schema 2. The checked file stays
  exact off/empty; a complete canonical `single-archive-wal-v1` profile is selected
  only for exact `vX.Y.Z-archive-v3-wal.N` production tags, while evaluation/main
  pretag force off, WAL-tag-plus-off fails, and environment/operator/dispatch inputs
  cannot override it.
- [x] Bound the full eight-element claim into schema-9 release metadata and Docker's
  independent exact off/complete provider grammar while leaving schema-7/8 evidence
  ineligible.
- [x] Quarantined active `release.sh --roll` before tag verification, cloud
  authentication, publication, or deployment and kept startup, Store/VFS,
  lifecycle, routes, health, WAL publication, provider I/O, and archive/root/
  deletion authority disconnected.

Schema-9 active image evidence is not deployable. The deployment repository must first
merge an independently reviewed compatibility PR; this enclave slice does not change that
repository, construct the runtime at startup, or enable any user-visible behavior.

## Inactive single-archive maintenance import engine

- [x] Added a strict encrypted-control v1 operation plus retained upload-attempt and
  exact artifact inventories. One active operation is allowed per archive, attempts
  are capped at 16, retained immutable objects at 32,898 per attempt, and every capability-
  bearing control mutation owns the sole SQLite handle until its conditional upload
  is durable or recovery reloads provider-authoritative state.
- [x] Added a Store-owned one-user transition that acquires lifecycle, actor, and
  content-admission gates before provider fencing; creates/adopts a permanent distinct
  `archive_` fence; drains pre-marker intents; performs the mandatory same-plaintext
  generation-CAS bump; and pins the exact generation, wrapped-DEK metadata commitment,
  plaintext hash/length, and SQLite user version in a cleanup-owned private snapshot.
- [x] Added exact restart recovery of only that retained generation and cancellation-
  safe cleanup of the database, WAL, and SHM files. A single permissible pre-fence
  writer win is durably rebased only while still in Fencing; no later source change is
  accepted.
- [x] Added the complete offline R1/R2 coordinator: authenticate an existing exact
  Active+Legacy witness/root/registry, lease it, upload and read back the checkpoint
  plus canonical zero-WAL R1, durably mark the send unknown, reconcile only from an
  exact witness reread into ShadowWal, recover the exact checkpoint, compare independent
  full SQLite copies, freshly revalidate source+witness, then select/recover one distinct
  durable R2 attempt, create/read back R2, and reconcile exactly into WalAuthoritative.
  Empty/reserved/materialized R2 prefixes reopen without burning another attempt while the
  retained witness fence is unchanged. Exact higher-fence reacquire validates the full witness
  lease tuple and supersedes a partial attempt before any further create; renewal validates the
  unchanged current/next fences plus strictly increasing trusted tick and expiry. Maintenance
  checkpoint staging uses a separate domain-bound constructor that accepts only the canonical
  zero-WAL tuple while ordinary shadow bindings remain all-nonzero. Terminal reopen reacquires
  the Store transition and exact pinned source, reloads exact Control state, freshly validates
  Active/WalAuthoritative R2, and uses a full-record terminal-specific transaction that clears only
  the importer owner/expiry even at or after expiry; lost response remains unknown until a fresh
  exact same-fence successor read proves no active lease. Any higher-fence record rejects because
  the released witness cannot authenticate its intervening owner. The resulting
  non-cloneable WAL-owner-token-gated handoff scrubs DB/WAL/SHM while retaining
  the lifecycle/actor guards and moves the opaque archive binding, exact witness, Control handle,
  and whole provider bundle without exposing raw getters. Each non-cloneable handoff value is
  consumed once; terminal restart may remint it, so durable globally unique owner acquisition is
  deferred to the inactive WAL worker slice.
- [x] ~~Split the Phase-1 terminal from the later authority transition. A distinct
  advisory importer stops only after the exact `ParityVerified` ShadowWal row,
  releases only that same-fence maintenance lease with lost-response exact reread,
  freshly revalidates the pinned legacy generation, scrubs DB/WAL/SHM, and drops
  every Store admission guard.~~ **Deleted in `#289`** along with the
  `MaintenanceImportTarget::AdvisoryShadow` variant; the enum now has the single
  variant `WalAuthoritative`. The surviving R2 door is closed rather than merely
  fenced: `run()`'s two `ensure_advisory_release_absent` gates can no longer fail
  (nothing writes that table outside tests), and the acquisition-gated
  `run_phase2` door still compiles but has no caller and demands a
  `phase2_acquired` row that nothing can mint — `Phase2AcquisitionStage` kept
  `from_db` and lost `as_db`.
- [x] Added pre-owner durable abort and cleanup: reconciles GCS provider marker deletion
  to fresh NotFound, durably transitions Control import stage to ManualRequired under exclusive
  user lifecycle lock asserting absence of any advisory owner or release row, and safely unblocks
  local legacy Store gates without installing capture or opening DB handles. This path survives
  `#289`; its four existence checks now read permanently empty tables.
- [x] Kept the result offline and non-serving. The importer is obtainable only by
  consuming the sealed image-bound runtime and a non-cloneable encrypted-control plan;
  there is no main/startup/Store constructor call, route, worker, environment/config
  selector, serving policy switch, archive-v3 provider delete/list, legacy source
  deletion, cloud action, or deployment change. The existing bounded legacy-intent
  prefix scan remains solely the pre-marker drain mechanism.

This engine remains inactive. Launch still requires an existing exact Legacy witness and an
external maintenance window that proves zero serving replicas; WalAuthoritative is not a
serving-ready state and production WAL domain owners remain an activation blocker.

## Capacity fixture and local gate

- [x] Versioned deterministic, numeric-only 12-month fixtures for 40, 80, and 100
  recording hours per month, with exact derived distributions.
- [x] Declared and validated the 32-GiB SQLite ceiling and a sparse near-ceiling extent
  profile without committing generated data.
- [x] Added a separate, opt-in production-shaped local gate with profile-derived disk
  preflight, bounded streaming batches, exact per-kind distribution checks, SQLite
  DB/WAL/checkpoint observations over materialized content-free payload/vector-shape BLOBs,
  and content-free reports.
- [x] Kept Phase-0a smoke tests fast and permanently non-evidence; the long gate is not
  executed in CI contract tests.
- [x] Defined an inactive, offline, restricted-JCS preauthorization schema and policy
  template, exact workload-by-result/environment/metric/formula verifier, explicit untrusted-wrapper activation
  blockers, and adversarial test contract. The checked-in template has intentionally invalid
  anchors; no current input authenticates time/challenge/provenance or consumes a replay nonce.
- [ ] Populate a separately controlled release policy with real trust anchors, collect
  signed production evidence, and exercise archive-v3 VFS, backend, witness, fault,
  lifecycle, cache, and concurrency paths before any authority transition.

The checked items do not authorize archive-v3 persistence or deployment. See
[`eval/capacity/README.md`](eval/capacity/README.md) for the reproducible operator command
and the local gate's explicit limitations.

## ADR-0022 Phase 3 extent VFS, WAL-to-extent, vector accelerator, and shadow verification

- [x] **Milestone 3A**: Authenticated durable attempt ledger `ExtentAttemptLedger` in
  `src/archive_v3_extent_commit.rs`: full-tuple CAS with same-transaction exact readback,
  strict schema and `sqlite_master` authentication, single-active-attempt enforcement,
  monotonic attempt sequences, domain-separated row and candidate-root commitments, and
  permanent terminal retention. The witness-bound stage chain
  (`Prepared -> ObjectsStaged -> CandidateReady -> WitnessSendStarted -> WitnessAdvanced -> Published`)
  is enterable only through sealed evidence tokens with no production constructor in this
  slice; Phase 3 shadow commits record no witness expectation and terminate at the
  distinct `ShadowSettled` terminal, and interrupted pre-witness attempts terminate
  durably at `AbortedPreWitness` so a crash can never wedge the attempt slot. Restart
  reconciliation settles shadow candidates, aborts pre-witness work, and fails closed
  (`ManualRequired`-style) on witness-stage attempts.
- [x] **Milestone 3B**: Durable staged-object inventory bound to the exact attempt row in
  the same authenticated ledger database: every immutable extent/node/root object is
  reserved (sealed-context canonical AAD + ciphertext hash) before provider upload and
  marked materialized only after exact readback, via the ledger-backed
  `DurableExtentStaging` in `src/archive_v3_extent.rs`. No witness advancement exists in
  this slice: `RootAdvance` construction remains test-only in `src/archive_v3_witness.rs`
  and the Phase 4 authority transition owns any future production witness path.
- [x] **Milestone 3C**: Shadow-only Extent VFS in `src/archive_v3_extent_vfs.rs`: one main
  database per instance, journal/WAL/temp/mmap/shm file classes fail closed (memory
  journal and temp modes required) so plaintext never reaches the host filesystem and
  host-planted journals cannot enter the authenticated tree; `ATTACH` aliasing refused;
  single-handle lifetime accounting; zeroizing page buffers; bounded runtime-flavor-safe
  execution lanes.
- [x] **Milestone 3D**: `xSync` durable shadow commit flow: heal-or-begin ledger attempt,
  bounded whole-file extent staging with durable reservation/exact readback, candidate
  root recording, `ShadowSettled` terminalization, exact snapshot-mask page cleaning, and
  fail-safe revert (dirty discard + settled-root restore + durable abort) on any failure.
  Commit size is bounded (256 MiB) pending Phase 4 incremental extent-object reuse.
- [x] **Milestone 3E**: Cleanup-owned two-pass streaming WAL converter with SQLite
  checksum-chain consistency validation (explicitly not cryptographic authentication),
  SQLite-conformant torn-tail recovery semantics, bounded staging in fixed private
  `/tmp` (unlinked-while-open, mode 0600), page-number and stream-size bounds, sparse
  base-source merge, and zeroizing buffers in `src/archive_v3_wal_to_extent.rs`.
- [x] **Milestone 3F**: Read-only shadow comparison in `src/archive_v3_extent_shadow.rs`:
  coordinator-owned read-only connections (`query_only=ON`), statement-level read-only
  enforcement on both engines, RAII transactions with concurrent snapshot pinning and
  `data_version` receipt markers, order-independent duplicate-sensitive multiset row
  digests, and content-free operation-scoped receipts.
- [x] **Milestone 3G**: Encrypted vector accelerator in
  `src/archive_v3_vector_accelerator.rs`: authenticated snapshot loading (fail-closed on
  tamper), connectivity-validated flat-graph bounded beam search, build-time recall@20
  certification enforced at construction and load, live-table re-validation of snapshot candidates
  (deletion/update coherent), and memory-bounded row-capped exact fallback that reports
  which path served the query.
- [x] **Milestone 3H**: Static Phase 3 architecture gates
  (`scripts/test_phase3_architecture_gate.py`, `src/archive_v3_phase3_gates.rs`),
  consolidated documentation, and map updates.

This compiled engine remains inactive and shadow-only: no Store, route, startup,
provider-credential, acknowledgement, or witness-authority wiring exists, and the
`Published` ledger terminal is unreachable without sealed witness evidence that this
slice cannot mint. It does not activate production extent VFS serving or any authority
cutover.
