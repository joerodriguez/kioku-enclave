# ADR-0022 — zero-archive proof for the sealed schema re-baseline

**Status: NO TAKE HAS BEEN RECORDED. This document is the obligation, not the discharge.**

`scripts/schema_baseline_seal.json` names this file as the proof for the
`d5ff84db…2dfb` re-pin. The seal ships `"sealed": false` precisely because the
proof below has not been taken. Nothing in this file may be read as evidence
that any archive count was ever observed to be zero.

## Why a proof is required at all

The re-baseline made `audio_segments.id`, `utterances.id` and `screenshots.id`
`AUTOINCREMENT`, and added the `schema_epoch` birth witness. Every one of those
statements is `CREATE TABLE IF NOT EXISTS`, so on an archive that **already
exists** the edit is a permanent silent no-op: that archive keeps reusable ids
forever and diverges from every canonical rebuild. This is failure mode one in
`src/schema_ladder.rs`, and it is reachable if and only if an archive exists.

The change is therefore sound only while the set of archives is empty. That is
not a formality and it is not inferable from code — it is a measurement, taken
against production, at a specific moment, with signup closed on both sides of
it.

## Group 1 — archive existence

Control store, one read transaction. Every count must be exactly 0.

```sql
SELECT
 (SELECT COUNT(*) FROM archive_bindings)                        AS bindings,
 (SELECT COUNT(*) FROM archive_v3_wal_genesis)                  AS genesis,
 (SELECT COUNT(*) FROM archive_v3_maintenance_imports)          AS imports,
 (SELECT COUNT(*) FROM archive_v3_maintenance_import_artifacts) AS import_artifacts,
 (SELECT COUNT(*) FROM archive_v3_wal_owners)                   AS owners,
 (SELECT COUNT(*) FROM archive_v3_wal_owner_leases)             AS leases,
 (SELECT COUNT(*) FROM archive_v3_wal_publications)             AS publications,
 (SELECT COUNT(*) FROM archive_v3_wal_publication_artifacts)    AS pub_artifacts,
 (SELECT COUNT(*) FROM archive_v3_wal_checkpoints)              AS checkpoints,
 (SELECT COUNT(*) FROM archive_v3_wal_checkpoint_artifacts)     AS ckpt_artifacts;
```

`archive_bindings` alone is **not** sufficient. Its rows are `DELETE`d at
`physical_complete`, while publication and checkpoint *artifact* rows can still
name objects — so a bindings-only query can read zero while bytes remain.

## Group 2 — accounts and in-flight deletion

All 0.

```sql
SELECT
 (SELECT COUNT(*) FROM users)                       AS accounts,
 (SELECT COUNT(*) FROM auth_identities)             AS identities,
 (SELECT COUNT(*) FROM account_deletion_operations) AS pending_deletions,
 (SELECT COUNT(*) FROM archive_deletion_ledgers)    AS deletion_ledgers,
 (SELECT COUNT(*) FROM archive_lifecycle_anchors)   AS lifecycle_anchors;
```

A nonzero `pending_deletions` is the exact case a bindings-only query misses:
content may still exist where the binding row is already gone.

## Group 3 — object store

For **every** bucket that holds archive bytes. Enumerate them from the deploy
environment; do not assume there is one.

```
gcloud storage ls --recursive gs://<b>/**                | wc -l  -> 0
gcloud storage ls --recursive --all-versions gs://<b>/** | wc -l  -> 0
gcloud storage ls --recursive --soft-deleted gs://<b>/** | wc -l  -> 0
gcloud storage buckets describe gs://<b> \
  --format='value(softDeletePolicy.retentionDurationSeconds)'      -> 0 or empty
```

The Control store is an index, not the ground truth for file existence. Both
the non-current-generation and soft-delete conjuncts are required: a
soft-deleted object is resurrectable, and a resurrected archive is exactly the
pre-existing archive this whole proof exists to rule out.

## Group 4 — enclave-local residue

`materialize_genesis_source` writes into a private scratch directory and removes
the family on the way out, so a crashed genesis can leave residue behind.

```
find <scratch_dir> -name '*.db*' | wc -l  -> 0
```

Or make it vacuous by requiring the deploy in step 5 to be an **instance
replacement**, and record that choice here.

## The sequence

No step may be skipped or reordered.

1. **Close signup.** Daily cap to 0 (`~/.config/kioku/enclave-production.env`).
   Record the refusal-counter baseline. No new archive can be created from this
   instant — and note that this is the *only* thing preventing archive creation
   during the window, and it has no CI or code enforcement. It belongs in the
   deploy pre-flight.
2. **Run the destructive cutover.** Delete all archives and all accounts.
3. **Proof take #1** — Groups 1-4. Transcribe below.
4. **Retire the old image before deploying the new one.** Delete or deny-tag
   every pre-re-baseline image and pin the re-baselined digest as the deploy
   floor. An incident rollback would otherwise silently re-enable plain-primary-key
   genesis. The birth-witness latch now makes that fail *closed* at owner open
   rather than corrupt silently, but it must be **prevented**, not merely
   detected.
5. **Deploy the re-baselined image** (instance replacement).
6. **Proof take #2** after healthy, before reopening signup. Full Groups 1-4,
   plus the successful-signup count between takes must be 0. Append below.
7. **Positive birth-witness check.** Create one throwaway account through the
   real signup path. Assert its archive carries
   `schema_epoch = (1, 0, chain_digest(0))` matching the deployed binary, and
   that `sqlite_master.sql` for `audio_segments`, `utterances` **and
   `screenshots`** all contain `AUTOINCREMENT`. Delete it; re-run Groups 1-2 to
   zero. **Every other step proves an absence. This is the only one that proves
   the deployed image is the right image.**
8. **Flip the seal** in one reviewed PR: `scripts/schema_baseline_seal.json`
   `"sealed": true`, and `SEALED_EXPECTED = True` in
   `scripts/test_schema_ladder_gate.py`. Both, or the gate fails — which is the
   point.
9. **Reopen signup.** Restore the daily cap.

**Abort rule:** any nonzero count at step 6 means stop. Delete the offending
archives (empty by construction, minutes old), re-run step 3, restart at step 5.

## Prerequisites that are not yet met

- The genesis spine must be **live** before step 5.
  `initialize_genesis_store` still carries `#[allow(dead_code)]` for want of a
  production caller. Deploy before genesis is live and step 7 cannot run, so
  signup cannot reopen.
- The transcripts lane must merge before the cutover: running this family is
  the first thing the new archives do.

## Take #1

*Not taken.*

## Take #2

*Not taken.*
