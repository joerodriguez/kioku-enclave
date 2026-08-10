# ADR-0022 archive capacity fixtures

`archive-fixtures-v1.json` defines deterministic, content-free three-year workloads for
480, 960 and 1,200 recording hours per year. It pins the two-second screen cadence,
canonical/reference split, utterance, FTS, vector, job, evidence, people and voice
distributions, and the measured core-archive planning range. The separate
`power-user-c-1200-32gib` profile carries the required 32-GiB logical sparse-shape target.

Validate or inspect the manifest without producing data:

```sh
python3 scripts/generate_capacity_fixture.py check
```

Stream a full synthetic distribution into ignored build output:

```sh
python3 scripts/generate_capacity_fixture.py generate \
  --profile power-user-c-1200 \
  --output target/capacity-fixtures/power-user-c-1200
```

For a fast smoke sample, add `--max-records-per-kind 10`. A limited receipt is marked
incomplete and is not capacity evidence. To create the 32-GiB *logical* filesystem shape,
select `power-user-c-1200-32gib` and add `--create-sparse-shape`. That uses file truncation
to create a sparse file; it does not write 32 GiB of blocks.

The generated `records.ndjson.gz` contains only record kind, ordinal, logical offset and a
deterministic numeric token. It contains no realistic text, URLs, media, embeddings,
names, user IDs or object paths. `archive-shape.sparse` is deliberately not a SQLite
database and cannot establish query latency or correctness; it exercises only logical
size/envelope/filesystem paths. Production-shaped SQLite and backend load evidence still
requires the full ADR-0022 release harness and pinned report manifest.

## SQLite capacity harness

`scripts/run_archive_capacity_harness.py` is an offline SQLite **smoke** check, not a
portion of release evidence. Its deterministic records contain only manifest record kinds,
ordinals, logical offsets, and numeric tokens. Output must be outside the checkout or
under ignored `target/`; an exclusive harness-owned receipt binds a resumable smoke run to
its manifest hash, profile, fixed SQLite page size, and immutable arguments. Foreign,
nonempty, symlinked, or incompatible-resume outputs are rejected.

Smoke mode is suitable for CI and is always marked `release_evidence: false` and
`sqlite_local_evidence: false`:

```sh
python3 scripts/run_archive_capacity_harness.py \
  --profile power-user-a-480 --mode smoke \
  --record-limit 100 --output target/capacity-harness/smoke-480
```

Full mode is intentionally unavailable. The previous zero-BLOB padding approach could
measure apparent SQLite size, but not a representative 32-GiB production archive, physical
allocation, release-image identity, cache state, concurrent workload, or ADR query mix.
No invocation of this script can produce release evidence or authorize archive-v3
production authority. A future release suite must bind those observations to the signed
release image and explicitly cover v3/backend/witness/fault/lifecycle gates.
