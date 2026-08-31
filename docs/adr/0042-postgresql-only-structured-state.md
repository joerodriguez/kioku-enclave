# ADR-0042: PostgreSQL-only structured state

- Status: Accepted
- Date: 2026-08-28
- Owners: Kioku enclave and platform
- Scope: Serving persistence, workers, tests, release configuration, and production recovery

## Context

The deployment-level
[ADR-0040](https://github.com/joerodriguez/kioku/blob/main/docs/adr/0040-cloud-sql-postgresql-for-structured-state-and-horizontal-scaling.md)
made private Cloud SQL PostgreSQL authoritative for structured state and enabled horizontal
serving. It also described SQLite as potentially useful as a test or reference backend. The
enclave still carried the earlier encrypted-SQLite-in-GCS authority, archive/WAL/checkpoint and
witness runtime, backend selection and fallback branches, SQLite search/vector code, and release
configuration for that retired design.

There are no production users and no legacy user data to preserve. Retaining a second complete
persistence implementation now adds security and correctness risk: a configuration mistake can
select the wrong authority, parity can silently drift, dead recovery protocols remain review
surface, and a SQLite-shaped test can pass without exercising PostgreSQL concurrency or types.
GCS remains necessary for large encrypted media and recording bytes; that live object boundary is
not a structured-state database.

## Decision

PostgreSQL is Kioku's only structured-state implementation in production and source. This decision
supersedes ADR-0040's suggestion that SQLite remain as a swappable or reference backend.

The enclave will:

1. construct PostgreSQL repositories unconditionally for serving, routes, restartable workers,
   export, and deletion;
2. remove backend selectors, fallback reads, dual writes, shadow reads, SQLite/GCS database
   adapters, archive-v3, WAL/checkpoint, witness, and legacy migration runtime;
3. preserve domain repository ports and focused in-memory fakes where they improve isolation,
   without exposing `sqlx` directly from HTTP handlers or provider adapters;
4. keep GCS only for live application-encrypted media and recording objects, using exact
   generation reads, conditional creates, authenticated object contexts, and deletion inventory;
5. keep PostgreSQL migrations append-only and run them only through the digest-pinned dedicated
   migrator; serving processes verify the required schema and never migrate it at startup; expose
   no operator-selectable schema mode; and record required verification as a fixed signed-release
   evidence claim rather than copying it from image configuration. A reviewed additive migration
   may use a fixed two-phase expand/finalize receipt. Its expand is an online, resumable sequence:
   a concurrent uniqueness guard and compatibility triggers precede bounded keyset backfills,
   populated-table indexes are concurrent, and no table lock spans the release. Readiness binds
   the predecessor/successor marker to the exact embedded contract hash and catalog. Finalization
   advances that marker only while persisting a fresh, strict ADR-0041 homogeneous-candidate,
   zero-unavailable, writer-dark fleet receipt and its detached Ed25519 signature. The verifier
   uses only the public key/fingerprint selected into the immutable image profile; serving and
   writer admission reverify the persisted canonical bytes, signature, and exact per-step catalog
   evidence; and
6. require the full local release gate to use an explicitly provisioned real PostgreSQL 17
   database and fail rather than skip its contracts. The gate must not silently depend on Docker.

No migration, backfill, import, dual-write, shadow-read, or reverse-rollback mechanism will be
built for the removed state. Removed configuration cannot re-enable it.

## Required invariants

- Tenant predicates and foreign keys protect every account-owned query and mutation.
- Claim/lease/settlement transitions for email, webhook, APNs, media, retention, deletion, and
  other provider effects remain atomic and safe across horizontal workers. A lost or ambiguous
  provider response is never converted into an automatic resend.
- `GET /api/export` emits selected tenant-qualified PostgreSQL rows and media inventory metadata
  from one repeatable-read transaction. It does not claim byte-complete export; external durable-
  recording/playback activation remains blocked until all owned media bytes are included. Account
  and episode deletion remain restartable, erase PostgreSQL state plus exact live-media
  generations, and do not report completion early or permit resurrection.
- Readiness requires PostgreSQL connectivity and exact schema compatibility. Compatibility means
  either the finalized version or one source-reviewed predecessor/successor expand receipt whose
  durable contract hash and physical catalog match the candidate; it is never an environment-
  selected range. Memory-reconciliation topology publication remains hard-dark in this release:
  a finalized schema and its writer-dark fleet receipt are necessary but deliberately
  insufficient to enable the writer. A later reviewed release must add one durable fleet-wide
  activation receipt observed by dark and enabled processes and fence in-flight legacy
  finalizers before activation. Liveness remains process-local; draining removes readiness
  before bounded shutdown.
- Process-immutable shared TLS, KMS image admission, signed tags, immutable digest promotion, SBOM,
  vulnerability scan, evidence signatures, and ADR-0041's predecessor/candidate zero-unavailable
  rollout remain release requirements. Certificate rotation occurs through that staged fleet
  rollout; no serving process hot-swaps its TLS identity.
- Live media buckets, media IAM, KMS keys, and PostgreSQL state are never deletion targets of this
  cleanup. Only provider resources proven exclusive to the removed SQLite authority may be
  destroyed, through reviewed Terraform followed by a no-change plan.

## Verification

The PostgreSQL contract suite must cover schema readiness, interrupted/retried bounded backfill,
concurrent-index cleanup, compatibility-trigger races, populated expand before marker mutation,
predecessor readiness throughout the mixed-fleet window, strict fleet-receipt refusal, and writer
refusal before finalization, plus tenant isolation, timestamp/time-zone
queries, full-text and vector search, concurrent and expired-lease claims, stale settlement
refusal, provider ambiguity/no-resend, restart enumeration, export, episode deletion, account
deletion, media cleanup, and no resurrection. Repository fakes continue to cover domain-only
behavior, but they are not substitutes for this suite.

The release gate also runs locked tests, all-target Clippy, production-feature builds, the complete
tooling contract suite, RustSec audit, SBOM generation, image scanning, canonical signed evidence,
and release metadata verification. Compatible runtime deployment follows ADR-0041 and records the
exact image, KMS admission, PostgreSQL schema/authority, readiness, provider-effect probes, member
replacement, and final no-change Terraform plan.

## Consequences

- There is one authority and one recovery model to review, test, operate, and restore.
- PostgreSQL-specific behavior is exercised directly instead of inferred from SQLite parity.
- The binary, dependency graph, image build, release configuration, IAM, and public documentation
  no longer carry obsolete archive/witness/database-in-GCS surface.
- A future alternate structured-state database requires a new ADR and implementation; repository
  interfaces alone do not promise backend interchangeability.
- Rollback means a schema-compatible predecessor image, a forward fix, or a reviewed PostgreSQL
  restore. It never means selecting SQLite or reading structured state from GCS.
