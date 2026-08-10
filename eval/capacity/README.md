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

`scripts/run_archive_capacity_harness.py` is the offline SQLite portion of that
evidence. Its deterministic records contain only manifest record kinds, ordinals, logical
offsets, and numeric tokens. Output must be outside the checkout or under ignored
`target/`; a durable progress receipt makes interrupted full runs resumable.

Smoke mode is suitable for CI and is always marked `release_evidence: false`:

```sh
python3 scripts/run_archive_capacity_harness.py \
  --profile power-user-a-480 --mode smoke \
  --record-limit 100 --output target/capacity-harness/smoke-480
```

Only the 1,200-hours/year, three-year 32-GiB profile may run in full mode. It requires a
public VM identifier, immutable image digest, cache/concurrency/sample metadata, and
explicit ingest/query/RSS thresholds. It creates and queries a real SQLite database (not
a sparse-file substitute); `release_evidence` is true only when both SQLite logical and
database-file sizes reach 32 GiB and all supplied gates pass. The resulting report remains
SQLite-only evidence and cannot authorize archive-v3 production authority.
