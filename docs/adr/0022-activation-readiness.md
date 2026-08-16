# ADR-0022 activation-readiness review

Status: inactive Phase-1 owner bootstrap review in progress; production activation is neither
authorized nor ready to perform in this change.

This review covers the enclave implementation of ADR-0022 through the inactive single-archive
WAL launcher/owner boundary. It does not revise the authoritative ADR, enable a runtime path, or
claim production evidence.

## Inactive boundary now closed

- The encrypted checkpoint, WAL, root, witness, exact-name recovery, lifecycle, and deletion
  protocols are compiled and locally tested without a serving call path.
- The maintenance importer independently compares the pinned legacy database with the recovered
  archive-v3 database across SQLite integrity, FTS/vector integrity, table counts, logical export,
  full logical contents, and selected queries before it can mint a terminal handoff.
- A type-separated Phase-1 importer can now stop at that verified `ShadowWal` point, release only
  the exact maintenance lease, scrub its scratch family, and drop its owned Store guard values.
  The permanent legacy provider fence and process-local Store/barrier blocks remain fail-closed.
  A reviewed inactive Store-owned executor now consumes the Control advisory-release ledger and
  reconciles deletion of only the exact permanent marker generation. Its terminal state leaves
  every process-local block closed; a separate race-free local unblock transition is still
  required before legacy serving can resume.
  Its opaque handoff cannot request `WalAuthoritative` or change serving acknowledgements. Direct
  use of the existing authority importer after release is fenced; a separately reviewed Phase-2
  acquisition transition is still required.
- The terminal handoff carries a non-cloneable parity-certified Control record. The private WAL
  launcher re-reads that exact record and reauthenticates its terminal witness/root relation before
  publisher ownership can start.
- A separate private Phase-1 launcher now consumes only that advisory handoff. Encrypted Control
  reserves one random advisory owner and durably records `SendStarted` before the exact ShadowWal
  witness acquisition. A lost response is adopted only from the exact owner/fence successor, and
  reopen exact-loads the same bound row without a second provider mutation. The live owner may now
  heartbeat the same exact fence or reacquire only after provider-trusted expiry; every one-step
  successor is exact-adopted and full-tuple-CASed in Control, while a restarted process cannot
  heartbeat the old fence and remains inert until exact post-expiry higher-fence reacquisition.
  This capability still has no capture, root, object, Store, acknowledgement, task, or startup
  operation.
- One private actor serializes the complete reviewed twenty-one-plan A/B/C set. Type erasure occurs
  only after sealed plan preparation, exposes neither generic SQL nor a ledger selector, and returns
  a result only to the matching typed submitter after durable witness settlement.
- The publisher retains only exact-name immutable create/get authority. No object enumeration or
  deletion capability crosses the handoff.
- The launcher, publisher, logical codecs, and test-only Store policy have no caller from main,
  startup, configuration, routes, health, workers, the production Store registry, or an
  acknowledgement surface.
- The inactive advisory release ledger authenticates the exact parity terminal and bound owner,
  then full-tuple-CASes `Prepared -> DeleteStarted -> Released`. Preparation permanently fences
  owner-lease succession. Later stages accept only Store-token-minted exact marker-name/authority/
  metadata/generation and exact-name absence evidence. The retained one-user Store target exact-
  reads and authenticates that marker, deletes only its recorded generation after `DeleteStarted`,
  and reconciles a lost response only through fresh exact-name absence. Release and maintenance
  serialize on the same one-user lifecycle lock; maintenance plan adoption plus a post-lock
  Control check rejects started release before provider I/O, and release freshly matches the
  retained advisory witness before Control prepare. It has no list/put/broad-
  delete capability. No Store unblock, capture selector, startup, route, or task invokes this path.

## Activation decision

The production decision is **NO-GO until every applicable row below is closed by a separately
reviewed activation change and production evidence**.

| Boundary | Current state | Required before activation |
|---|---|---|
| Phase-1 advisory shadow canary | Verified ShadowWal bootstrap plus inactive exact advisory-owner acquisition/heartbeat/expiry-reacquire exist. Store's inactive capture injection is exact-one-user and production-unconstructible; the parity terminal hands the owner a sealed exact Store/user/archive/import target. The release ledger and Store-owned executor now durably freeze succession, authenticate/delete only the exact marker generation, and prove exact-name absence, including lost-response recovery. Store/barrier blocks remain fail-closed because local unblock is deliberately absent. There is still no live caller or post-bootstrap comparison owner. | Add the race-free local unblock transition, then owner-only capture installation/drain and independent comparison; require an explicit canary scope; shadow failure cannot alter latency, response, retry, or stored legacy result. |
| Enabled mutation set | Reviewed sealed subset only | Select an exact canary operation allowlist. Every enabled path must supply its stable identity and typed plan; unsupported audio/person/identity/voice, screen-person, generic/audio/finalization Vertex-begin, and other unreviewed semantics stay disabled or receive their own review first. |
| External attempts | Provider-neutral seams only where reviewed | For any enabled provider-writing domain, construct only the reviewed KMS/provider adapter and preserve durable B send identity, one-shot execution, exact readback, C definitive-rejection, and manual handling of ambiguity. |
| Runtime ownership | Private inactive Phase-1 lease-lifecycle owner and separate authoritative launcher; advisory release cannot enter the existing authority importer | Add owner-only capture, then prove one archive/one owner, maintenance-window and zero-serving-replica preconditions, restart ownership, a distinct exact Phase-2 authority acquisition, drain/handoff behavior, and no second Store/runtime authority. |
| Store and acknowledgement | Production remains `LegacySnapshot` | A separately reviewed policy/route/worker change must keep Phase 1 advisory. Phase 2 may acknowledge only after immutable WAL plus witness durability and exact replay; no local SQLite commit alone may authorize success. |
| Release evidence | Local correctness gates only | Populate trusted release-policy anchors; collect signed image-bound capacity/security evidence; satisfy the ADR's I/O, latency, memory, cost, concurrency, and integrity thresholds. |
| Recovery/lifecycle drills | Unit/integration fault coverage, no production drill | Exercise restart, uncertain response, checkpoint/compaction, export, deletion, schema migration, rollback/roll-forward, orphan retention, and forensic legacy-read rules on the release image. |
| Cloud/deployment | No mutation performed | Obtain explicit operator authorization for configuration, credentials, provider resources, image rollout, canary selection, monitoring, rollback window, and any later authority transition. |

## Required order

1. Activate an advisory Phase-1 canary only; legacy remains authoritative and shadow errors are
   non-authorizing.
2. Collect independent recovery/parity and production-shaped capacity evidence on the exact release
   image.
3. Review the exact enabled-domain adapters and ownership/Store integration; leave every other
   domain disabled.
4. Obtain a separate explicit decision before Phase-2 WAL authority or any acknowledgement change.
5. Treat Phases 3–6 (extent shadow/authority, horizontal ownership/control migration, and legacy
   retirement) as later forward-only decisions with their own evidence and approvals.

## Permanent no-go signals

Do not activate if any path can acknowledge before witness settlement, retry an ambiguous external
attempt under a new identity, infer definitive rejection from absence alone, enumerate/delete
archive objects through the WAL runtime, select an older root after later acknowledgements, run a
second archive owner, let shadow failure change the legacy response, or bypass exact image/config/
release-evidence binding.

This document records readiness findings only. It grants no permission to modify cloud resources,
deployment, serving configuration, production data, Store policy, or user-visible behavior.
