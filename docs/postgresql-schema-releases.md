# PostgreSQL schema release procedure

Serving processes never run DDL. A reviewed candidate image supplies the private
`--migrate-postgres` role, and `POSTGRES_MIGRATION_CONFIRM` authorizes exactly one phase.
Migration 0026 uses a two-phase ADR-0041 expand/finalize sequence because the production v24
predecessor requires the durable `persistence_schema.version` marker to remain 24. The expand
also installs migration 0025's additive account-status constraint as an exact receipted step,
without publishing its standalone version-marker advance.

## Memory-reconciliation v26

1. Build and verify the candidate. Schema v26 does not grant topology authority; no image-local
   setting can activate reconciliation.
2. Before preauthorizing the candidate fleet, run the digest-pinned migration job with
   `POSTGRES_MIGRATION_CONFIRM=memory-reconciliation-v26-expand`. The job owns a session advisory
   lock, but never holds a table lock across the release. An exact-absence preflight runs before
   the first mutation. The runner bootstraps its release/step ledger atomically, then builds the
   additive account-deletion status constraint after proving the exact v24 predecessor catalog,
   then builds the legacy source-owner uniqueness guard concurrently. An ambiguous archive fails before any
   backfill or compatibility projection; the runner removes an interrupted invalid index so a
   repaired retry can continue.
3. Rerun that exact expand command while its machine-readable JSON status is
   `expand_in_progress`. Metadata changes use independent transactions with a two-second lock
   timeout. Compatibility triggers are catalog-verified before any cursor advances; they cover
   v24 writes while accounts, episodes/handles, structure state, and membership are copied in
   bounded keyset batches. Every short DDL transaction commits an embedded-DDL SHA-256 and an
   exact catalog-evidence SHA-256 in the same transaction. Cold objects reject name collisions;
   interrupted concurrent indexes are accepted only after their complete normalized definition
   matches. Unknown, duplicate, missing, extra, or changed step/catalog evidence fails closed.
   Indexes on populated capture tables are built concurrently. Killing or timing out the job
   loses at most the active batch; every committed cursor is resumable.
4. Stop rerunning only when the JSON status is `expanded` or `already_expanded`. The runner has
   then verified the exact embedded contract hash, required catalog objects and valid indexes,
   and both directions of every backfilled projection. Its final short transaction records
   `expanded_through_version=26` and release phase `expanded` while leaving `version=24`.
5. Prove the populated archive was preserved, the expansion receipt is exactly `24/26`, and
   every predecessor member remains ready. A v24 process continues to read version 24; the
   v26 candidate accepts only the matching release-row contract hash and physical catalog, but
   keeps its writer dark.
6. Perform ADR-0041 preauthorization and rolling replacement. Preserve both reviewed KMS
   digest members and do not finalize while any v24 predecessor is serving or may return.
7. The selected production/evaluation image profile must contain the public, non-secret
   `SCHEMA_FINALIZATION_PUBLIC_KEY_DER_BASE64` (canonical standard base64 of one Ed25519 SPKI DER
   key) and `SCHEMA_FINALIZATION_PUBLIC_KEY_SHA256` (64 lowercase hex characters over those exact
   DER bytes). The selector and final image assembler verify that pair, and the binary loads it
   from the fixed `/kioku-config` path even in migration mode. Do not put a private key in the
   image or migration environment. Removing or changing this anchor makes an already-finalized
   v26 database fail serving verification; retain it for the schema's lifetime.
8. Generate a fresh machine fleet receipt from the independently observed inventory. The strict
   JSON object contains exactly these fields:

   ```json
   {
     "contract": "kioku.postgresql.schema-finalization",
     "contract_version": 1,
     "release_version": 26,
     "expand_contract_sha256": "sha256:<contract_sha256 from expand output>",
     "candidate_image_digest": "sha256:<64 lowercase hex characters>",
     "fleet_evidence_sha256": "sha256:<64 lowercase hex characters>",
     "observed_at": "2026-08-30T12:00:00.000Z",
     "expires_at": "2026-08-30T12:10:00.000Z",
     "candidate_instances": 2,
     "predecessor_instances": 0,
     "unavailable_instances": 0,
     "writer_enabled": false
   }
   ```

   Canonical signing bytes are UTF-8 JSON with keys sorted lexicographically, compact separators,
   ASCII field values, and exactly one trailing LF—the same detached-receipt convention used by
   the external Ed25519 coordinator. Sign those exact bytes with the private key corresponding to
   the baked SPKI key. Supply those exact canonical bytes—including the single trailing LF—as
   `POSTGRES_MIGRATION_FINALIZATION_RECEIPT`; reordered, reindented, or LF-free transport is
   refused even when it represents the same JSON value. Supply canonical standard base64 of the
   raw 64-byte detached signature as
   `POSTGRES_MIGRATION_FINALIZATION_SIGNATURE`, while running the same digest-pinned job with
   `POSTGRES_MIGRATION_CONFIRM=memory-reconciliation-v26-finalize`. These are the only
   finalization values the runtime job may supply; it cannot select a public key or fingerprint.

   Timestamps must be canonical UTC, the validity window must be at most 15 minutes, and at least
   60 seconds must remain according to PostgreSQL `clock_timestamp()` when the marker is written.
   Unknown fields, noncanonical signature encoding, an invalid signature, a missing/uppercase
   digest, any predecessor or unavailable instance, an empty candidate fleet, or an enabled
   writer fail closed. The backend persists canonical JSON, its SHA-256, the detached signature,
   the baked-key fingerprint, and a `clock_timestamp()` finalization time while atomically
   advancing `version` to 26. Serving and writer admission reparse, recanonicalize, rehash, and
   reverify the persisted signature. The phase literal alone cannot finalize. This is the
   rollback boundary for the v24 predecessor.
9. Complete predecessor retirement and steady-state verification. Reconciliation activation
   requires the separate durable v27 fleet-wide phase and in-flight-finalizer fence; finalized
   `26/26` alone cannot enable topology publication.

Both job phases are idempotent only for their exact contract, step/catalog receipts, signed fleet
authorization, and baked trust anchor. Expand progress is durable, bounded, and safe to retry; a
different contract hash, invalid or extra catalog object, ambiguous legacy ownership, stale or
unsigned fleet evidence, unknown step, or marker/phase disagreement fails closed.
The retired `empty-production-adr0040` confirmation is rejected; migration 0026 supports
populated production and never makes a post-commit empty-account assertion.
