# ADR-0022 activation-readiness review

Status: inactive construction review complete; production activation is neither authorized nor
ready to perform in this change.

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
  the exact maintenance lease, scrub its scratch family, and drop all Store admission guards. Its
  opaque handoff cannot request `WalAuthoritative` or change serving acknowledgements. Direct use
  of the existing authority importer after release is fenced; a separately reviewed Phase-2
  acquisition transition is still required.
- The terminal handoff carries a non-cloneable parity-certified Control record. The private WAL
  launcher re-reads that exact record and reauthenticates its terminal witness/root relation before
  publisher ownership can start.
- One private actor serializes the complete reviewed twenty-one-plan A/B/C set. Type erasure occurs
  only after sealed plan preparation, exposes neither generic SQL nor a ledger selector, and returns
  a result only to the matching typed submitter after durable witness settlement.
- The publisher retains only exact-name immutable create/get authority. No object enumeration or
  deletion capability crosses the handoff.
- The launcher, publisher, logical codecs, and test-only Store policy have no caller from main,
  startup, configuration, routes, health, workers, the production Store registry, or an
  acknowledgement surface.

## Activation decision

The production decision is **NO-GO until every applicable row below is closed by a separately
reviewed activation change and production evidence**.

| Boundary | Current state | Required before activation |
|---|---|---|
| Phase-1 advisory shadow canary | Verified ShadowWal bootstrap terminal exists; no live caller, selector, or post-bootstrap capture owner | Explicit owner-only canary scope; legacy remains sole authority; shadow failure cannot alter latency, response, retry, or stored legacy result; independently recovered parity is measured and retained. |
| Enabled mutation set | Reviewed sealed subset only | Select an exact canary operation allowlist. Every enabled path must supply its stable identity and typed plan; unsupported audio/person/identity/voice, screen-person, generic/audio/finalization Vertex-begin, and other unreviewed semantics stay disabled or receive their own review first. |
| External attempts | Provider-neutral seams only where reviewed | For any enabled provider-writing domain, construct only the reviewed KMS/provider adapter and preserve durable B send identity, one-shot execution, exact readback, C definitive-rejection, and manual handling of ambiguity. |
| Runtime ownership | Private inactive launcher only; advisory release cannot enter the existing authority importer | Prove one archive/one owner, maintenance-window and zero-serving-replica preconditions, restart ownership, a distinct exact Phase-2 authority acquisition, drain/handoff behavior, and no second Store/runtime authority. |
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
