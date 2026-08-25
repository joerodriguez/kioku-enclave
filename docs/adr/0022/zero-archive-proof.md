# ADR-0022 — fresh-generation proof for the sealed schema re-baseline

**Status: THE FRESH-GENERATION PROOF HAS NOT BEEN RECORDED. This document is the
obligation, not the discharge.**

`scripts/schema_baseline_seal.json` names this file as the proof for the
`d5ff84db…2dfb` re-pin. The seal ships `"sealed": false` precisely because the
proof below has not been taken. Nothing in this file may be read as evidence
that the fresh provider generation exists or that its signed BOOTSTRAP and FINAL
releases have run.

## Primary launch proof — fresh production generation

The original production namespace is disposable pre-launch history. Its retained and
soft-deleted objects are quarantined and are not inputs, predecessors, rollback targets, or
recovery sources for the launch. The baseline may be sealed against a *different*, brand-new
production generation because the re-baseline failure below is reachable only when an archive
already exists in the generation being activated.

The fresh proof must bind all of the following before the seal flips:

1. A source-frozen provider receipt proves the exact new index, media, archive, and
   witness-export buckets; named Firestore database; KMS key/version; and runtime service
   account were created as a new generation with the reviewed policies. It also proves that
   no legacy bucket, database, key, runtime principal, release, rollback, or recovery owner is
   referenced by the active generation.
2. A signed BOOTSTRAP image at the sole fixed
   `v0.8.35-adr0022-fresh-bootstrap.1` role, built from this 0/0/0 source with the exact all-empty archive-v3
   profile and `GENESIS_WAL_NATIVE=off`, carries exact schema-10 metadata binding the canonical
   fresh-generation tuple plus the owner-sealed pre-build canary identity receipt SHA and sole
   derived UUIDv5 from the same private config snapshot. It runs under the priority-800 public deny. A bounded
   temporary /32 operator authority creates exactly one deterministic canary through the real signup
   path and records only the one-way archive-binding commitment. The runtime-off image cannot
   create or serve an archive-v3 WAL owner.
3. The reviewed FINAL source at the sole fixed
   `v0.8.35-archive-v3-wal.1` role binds that exact provider receipt and commitment, sets the
   baseline seal, appends only the reviewed first additive schema step, and compiles schema
   coordinates 1/1/1. Its signed metadata and image evidence bind the complete fresh tuple;
   no legacy image remains an admitted predecessor.
4. While the public deny remains present, FINAL proves one canonical Genesis birth at epoch 1,
   authenticated routed serving, the reviewed product canaries, complete export, explicit
   physical deletion, and exact image/KMS/archive containment. The temporary operator identity
   and /32 rule are removed before the fixed deny can be removed.
5. Only the sealed FINAL owner removes the named deny, then proves public content-free health
   and exact live image/provider identity. Failure at any point leaves the fresh generation
   denied and never falls back to the legacy namespace.

The checked-in receipts, signed release coordinates, and live proof values will be appended to
this section by the reviewed FINAL source change. Until then `sealed` remains false.

## Superseded fallback — physical zero of the legacy namespace

The remainder of this document records the older physical-zero/Take ceremony. It remains a
valid fallback if the fresh-generation launch is abandoned, but it grants no authority to wait
for, adopt, restore, or roll the legacy namespace on the primary launch path.

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
   instant. Zero is an explicit validated image-baked state: the transactional
   reservation refuses before account/archive creation, and startup selects the
   dedicated cutover owner only for that exact value. The selected build, baked
   image file, and live image identity still belong in the deploy evidence.
2. **Run the destructive cutover.** The signup-closed image pages active accounts
   into the ordinary lifecycle-fenced deletion state machine, advances pending
   deletion every 30 seconds, and logs exact aggregate Groups 1-2 counts. Delete
   all archives and accounts; do not infer provider-byte absence from these counts.
3. **Proof take #1** — Groups 1-4. Transcribe below.
4. **Retire the old image before deploying the new one.** Delete or deny-tag
   every pre-re-baseline image and pin the re-baselined digest as the deploy
   floor. An incident rollback would otherwise silently re-enable plain-primary-key
   genesis. The birth-witness latch now makes that fail *closed* at owner open
   rather than corrupt silently, but it must be **prevented**, not merely
   detected.
5. **Deploy a fresh exact signup-zero re-baselined image** (instance
   replacement). This is the reviewed `.1` image, not the later positive
   witness image and not any schema-ladder phase.
6. **Proof take #2** after healthy, while signup and public ingress remain
   closed. Full Groups 1-4, plus the successful-signup count between takes
   must be 0. Append below.
7. **Positive birth-witness check.** Promote and roll the immutable signed
   `.4` bytes, then create one throwaway account through the
   real signup path. Before signup, record the count of the content-free
   `archive_v3_genesis_birth_witness` metric. Require exactly one new event,
   with the deployed target epoch, `allocator_tables=3`, and `valid=true`, and
   no genesis-unavailable event. The event is emitted only when that same pass
   exact-compares the born database against the binary's canonical schema
   (including `AUTOINCREMENT` on `audio_segments`, `utterances`, and
   `screenshots`), publishes it to the durable `wal_authoritative` terminal,
   and successfully launches its serving authority. A recovered/pre-existing
   terminal never emits it. Delete the throwaway account through the ordinary
   lifecycle owner. **Every other step proves an absence. This is the only one
   that proves the deployed image is the right image.**
8. **Restore exact zero on a third fresh signup-zero `.1`.** Replace `.4`,
   retire the witness account's terminal tombstones through the ordinary
   owner, and require newest logical zero plus a stable full provider-zero
   read. Complete the same receipt that began the positive witness; neither a
   logical delete nor a `.4` shutdown alone completes it.
9. **Seal the baseline and append the first step in reviewed source.** Bind
   the two authenticated zero takes, positive witness, explicit physical
   deletion, and restored-zero receipts into this document. In the same
   reviewed source line, set `scripts/schema_baseline_seal.json` to
   `"sealed": true`, set `SEALED_EXPECTED = True` in
   `scripts/test_schema_ladder_gate.py`, append only the reviewed
   `0001_capture_events_stream_sequence` step, and set the schema coordinates
   to HEAD/TARGET/minimum `1/0/0`. The gate must refuse any step before those
   proof bytes exist.
10. **Roll a distinct signed signup-positive HEAD (`1/0/0`).** Require its
    startup aggregate to report `selected=0`, `relaunched=0`, `at_target=0`,
    `advanced=0`, `behind_target=0`, `unservable_epoch=0`, and
    `unavailable=0`, then create exactly one account through the real signup
    path and retain it. Its Genesis marker is epoch 0 because TARGET is still
    0; this is the sole archive carried into the next phase.
11. **Roll a distinct signed signup-positive TARGET (`1/1/0`).** The structured
    owner must bind the exact HEAD receipt and account/archive lineage and
    require `selected=1`, `relaunched=1`, `at_target=1`,
    `behind_target=0`, `unservable_epoch=0`, and `unavailable=0`. `at_target`
    comes from the durably re-read marker and survives a process exit after
    the commit but before the startup metric. `advanced` is only a
    launch-local diagnostic and is therefore either 1 on the direct launch or
    0 on the replacement; the exact HEAD receipt, singleton/audit/attempt
    chain, and monotone epoch marker prove the sole 0 -> 1 transition. Reject
    more than one bound `advanced=1` aggregate. Prove an authenticated,
    non-creating routed read, then delete the retained account to explicit
    `physical_complete`; do not claim global zero yet.
12. **Roll a distinct signed signup-zero MINIMUM (`1/1/1`).** Its startup
    aggregate must have `selected=0`, `relaunched=0`, `at_target=0`,
    `advanced=0`, `behind_target=0`, `unservable_epoch=0`, and
    `unavailable=0`. Select the dedicated cutover owner, retire the TARGET
    account's tombstones, and require newest logical zero plus a stable full
    provider-zero read before proceeding.
13. **Roll a distinct signed signup-positive FINAL (`1/1/1`).** While the
    public deny remains present, require the same exact all-zero startup
    aggregate as MINIMUM, then prove a fresh valid Genesis birth at epoch 1,
    authenticated routed serving, and explicit physical deletion of the
    witness account. FINAL is a separate tag, image digest, and baked-config
    binding even though its schema coordinates equal MINIMUM's.
14. **Reopen only through the sealed FINAL owner.** That owner alone may
    remove the named public deny and restore the reviewed positive signup
    policy. Finish with public content-free health and exact image, KMS, and
    archive-authority verification. No earlier phase may reopen signup.

**Abort rule:** any nonzero count at step 6 means stop. Delete the offending
archives (empty by construction, minutes old), re-run step 3, restart at step 5.
After step 6, any phase mismatch means stop with signup closed and the public
deny present; recover or replace only through that phase's reviewed owner and
repeat its complete proof. Never skip forward to FINAL or reopen around a
failed receipt.

## Cutover mechanisms and remaining evidence

- The genesis spine is **wired and its active image has been production-proven**.
  This corrects an earlier revision of this document, which
  claimed `initialize_genesis_store` had no production caller: it does. G9
  (#317) hung genesis off the browser sign-in and token-refresh paths; the
  native-session follow-up additionally covers direct Google ID-token account
  creation and the first Apple native session. The live chain is therefore
  `oauth.rs` sign-in / token refresh or the canonical native session boundary -> `spawn_genesis_convergence` ->
  `converge_genesis_for_user` -> `run_durable_genesis` ->
  `initialize_genesis_store`. Activation is controlled by `GENESIS_WAL_NATIVE`,
  which additionally requires baked archive-v3 coordinates.
  The gate is a **baked, attested
  image key**, so flipping it is a build-time act:
  - `GENESIS_WAL_NATIVE` is on `BAKED_IMAGE_CONFIGURATION_KEYS` in
    `src/main.rs` and on the `allowed_keys` allowlist in
    `scripts/assemble_image_config.sh`. The image file is read before any
    provider construction and **overwrites** the ambient value, and an image
    missing any allowlisted key panics at startup. Setting
    `GENESIS_WAL_NATIVE` on the running service therefore cannot arm genesis
    on an image built `off`; it has no effect at all.
  - The value is supplied per profile by the operator as
    `PRODUCTION_GENESIS_WAL_NATIVE` (`EVALUATION_` for eval images) and is
    required and non-empty: `require_value` in
    `scripts/select_build_configuration.py` names the key if it is absent,
    and only the exact words `off` and `on` are accepted. Empty is no longer
    a spelling of "shut".
  - `on` is refused at build time unless the image also carries an active
    `ARCHIVE_V3_SHADOW_RUNTIME_MODE`, in both the selector and the assembler,
    mirroring `require_genesis_config_agreement` at startup. Since a `main`
    build always selects the off runtime, the cutover image is necessarily an
    exact `vX.Y.Z-archive-v3-wal.N` tag build.

  **Flipping the gate is an image rebuild and redeploy under a new attested
  digest — not a restart, not an environment change, not a Cloud Run variable
  edit.** Step 5 must be planned as a release: change the operator profile
  value to `on`, rebuild against the WAL release tag, push, re-verify the
  digest against the attestation, and roll.

  **Rolling the gate BACK needs an image that does not exist yet — build it
  before step 5.** The obvious rollback, redeploying the digest that was
  running before step 5, is exactly the act step 4 exists to prevent: that
  digest is pre-re-baseline, step 4 deletes or deny-tags it and pins the
  re-baselined digest as the deploy floor, and restoring it silently
  re-enables plain-primary-key genesis. Either the floor blocks the redeploy
  and the operator is stranded mid-cutover with signup closed, or the operator
  lifts the floor to make the rollback work and thereby causes the corruption
  the floor was protecting against. Nothing in the sequence otherwise produces
  a gate-off build of the re-baselined image, so **no digest exists that both
  clears the step-4 floor and has `GENESIS_WAL_NATIVE=off`**.

  Therefore publish **two independently signed immutable releases** from the
  reviewed re-baseline source line before step 5 — one `off`, one `on` — and
  register both exact source/image/config tuples in the deploy policy. One
  immutable release can bind only one image digest, so claiming two differently
  configured images under one tag would make the release record ambiguous. The
  `off` digest is the designated rollback target alongside the deploy floor. It
  is re-baselined, so it clears the floor, and un-arming the gate is then a
  redeploy of that digest with no pre-re-baseline binary ever returning to
  service.

  The reviewed pair prepared for this cutover is:

  - gate on: `v0.8.34-archive-v3-wal.1`, source
    `0c96cc7930289879392f847bf138571aed17e83e`, image
    `sha256:71d17b37dfb3aecc02991f3b3a1e43b86e096ff14b6ad23f1821de1551e13f4b`,
    image-config SHA-256
    `6a6ce69063147eeace305e57bad6d69db8301a85674821ddf0902f5b07a4b850`;
  - gate off / rollback: `v0.8.34-archive-v3-wal.2`, source
    `9f373fe037462cf1f84d24095784c547f102ee12`, image
    `sha256:faf94ffa593283b02cce438d0dac0611255134b4da7a5a361442e53ac56227c7`,
    image-config SHA-256
    `ed496579f20529d7630e7de67492882203443ffacd881c64a59da86300b98a62`;
  - gate on / positive birth witness: `v0.8.34-archive-v3-wal.3`, source
    `1c022582a44cdf9a3ddab20c5afb8c4e06f56f29`, image
    `sha256:f5f7949421198332dd040c751a0aa3ab1c114a06b1fe5aef89b49f0b83d348b1`,
    image-config SHA-256
    `69eb07b18016f554a0983da172995e4039a36b1e89af15aa74f00d1aed620d2d`;
  - gate on / native-session Genesis witness successor:
    `v0.8.34-archive-v3-wal.4`, source
    `1991273382e301e8513cfc73da1e351f215e5724`, image
    `sha256:a8688a7510cbf4542f9532600726965e3be42a665e99e3e42fce04d83e05106e`,
    image-config SHA-256
    `69eb07b18016f554a0983da172995e4039a36b1e89af15aa74f00d1aed620d2d`.

  All four are signed prereleases with immutable evidence. Deployment commit
  `e10a20bcc049bd7285ea2a7384b3bae4cdc4f417` admitted the exact pair and successor;
  successor `e62cabaac3d67a8e3f0c1a7f74d96bebc515f49f` additionally routes `.3` through
  the same archive-bucket and witness-database authority preauthorization,
  post-health finalization, and failure recovery as `.1`/`.2`; deployment
  `9e305b2f73cb41689511372fde8e238e97b5c31c` admits `.4` through that same boundary;
  deployment `0580e974fd6aa780f44f208e8f7ad6fd765d0fe4` adds the source-frozen,
  Take-2-bound one-account witness owner without changing the Terraform source digest.
  `.1` and `.2` remain the destructive two-image registry floor; they are not
  the later schema HEAD/TARGET/MINIMUM/FINAL releases and cannot substitute
  for one of those four roles. `.4` is the reviewed post-Take native-session
  witness successor and must be promoted again from the same signed evidence
  if retirement removed it. The
  deployment source also contains the frozen, disabled-until-Take-#1 operators for the
  three-bucket visible-zero floor, both proof takes, and exact registry retirement.
  Shipping those operators proves only that the rollback and proof mechanisms exist;
  it is not proof take #1, image retirement, proof take #2, or the positive birth
  witness.

  This bullet records that the *mechanism* is in place and the active candidate
  was rolled successfully. It does **not** discharge either zero proof, image
  retirement, the positive birth witness, the seal, or the schema ladder.
- The transcripts and selected voice-embedding lanes are merged and verified;
  running them is among the first work a new archive performs.

## Take #1

*Not taken.*

## Take #2

*Not taken.*
