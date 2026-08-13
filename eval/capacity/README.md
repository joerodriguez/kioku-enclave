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

## Explicit production-shaped local gate

`archive-fixtures-v2.json` is a separate, deterministic 12-month contract for 40, 80,
and 100 recording hours per month. It assigns records to 12 months and bounded active-day/
session cadence slots, declares numeric per-kind payload geometry, represents vectors as
384-dimensional float32 logical shapes (not embedding values), and pins 12-month retention
geometry. Its canonical 100-hour profile declares a 32-GiB database ceiling. Start with
the no-I/O plan; it records the SQLite page/WAL/checkpoint geometry and does not create any
files:

```sh
python3 scripts/run_archive_capacity_gate.py plan
```

The gate is intentionally long-running: it streams every numeric fixture row through a
local SQLite WAL database in bounded batches. Each row materializes a deterministic,
zero-filled, content-free payload BLOB at its declared per-kind size; vector rows also
materialize a separate 1,536-byte zero-filled embedding-shape BLOB. The generator caches
only the ten bounded payload templates and one embedding template, so memory remains
bounded while SQLite DB/WAL pages reflect the declared storage shapes. The gate checks
`max_page_count` at 32 GiB, measures
WAL files before/after passive and truncating checkpoints, and verifies logical sparse
extents one page below, at, and one page above the ceiling. It validates that SQLite actually
entered WAL mode, requires nonzero regular WAL evidence and meaningful passive-checkpoint
frame counts, and checks exact per-kind distributions. It rejects a symlink in any output
path component. Its free-space preflight is not user-overridable: the plan derives it from
the selected profile's high database shape, worst-case WAL frames, one bounded checkpoint
chunk, and 1 GiB safety headroom. It requires two explicit operator acknowledgements for the
32-GiB profile:

Run the 40/80/100-hour monthly profiles individually with `--confirm-production-shaped`;
only the canonical 100-hour 32-GiB profile also needs `--allow-sparse-extent`:

```sh
python3 scripts/run_archive_capacity_gate.py run \
  --profile power-user-c-100h-month-12m-32gib \
  --output /secure-local-volume/kioku-capacity-32gib \
  --confirm-production-shaped \
  --allow-sparse-extent
```

The extent probes are sparse regular files, never SQLite databases; the gate first proves
that the output filesystem reports sparse allocation and refuses the 32-GiB path otherwise.
Every probe rechecks its own allocated bytes and deletes all partial probe files if allocation
is unavailable or not strictly smaller than apparent size. They verify apparent extent and
observable allocation only. The gate does not allocate a 32-GiB snapshot and
does not download, encrypt, upload, or use production content. Its report is explicitly
`release_evidence: false` and `archive_v3_authority: false`; signed-image/backend/VFS/
witness/fault/lifecycle/cache/concurrency evidence remains a separate future release gate.

## Inactive signed Phase-1 evidence contract

`archive-v3-capacity-policy-v2.template.json` and
`archive-v3-capacity-evidence-v2.schema.json` describe an **inactive** 32-GiB/three-year
preauthorization format. The template is intentionally unusable: its signer, evaluator,
time-source, and verifier hashes are placeholders. The JSON Schema is a public shape
companion; `scripts/verify_archive_v3_capacity_report.py` is the normative semantic
contract.

The verifier requires the exact 480/960/1,200-hour workloads, two-second screen cadence,
100,000/900,000-ppm canonical/reference split, and every ADR fault/test scenario for each
workload. Quantitative cases are further expanded over their exact media, query, slice,
and percentile dimensions. Every case, metric, transport breakdown, durable-write sample
and summary, ANN result, and root/witness result repeats the 32-GiB/three-year identity;
fixture, test-plan, test-config, environment, and environment-attestation hashes; cache,
active-user, media-mix, latency-profile, sample-count, and percentile-window dimensions.
Missing, extra, duplicate, swapped, tiny-database, or single-sample substitutions fail.

The compiled contract fixes the VM shape/memory, GCS and Firestore regions, SQLite and
extension set, cache definition, media/network mix, fault profile, at least eight active
users, at least 100 samples, and one complete percentile window. A policy must reproduce
those identities exactly. It may tighten the minimum active-user/sample counts, the
documented upper/lower metric limits, and freshness maxima; it cannot relax or rename a
gate. Query mode is explicitly pinned to either exact KNN or ANN. Exact-KNN mode forbids
ANN claims. ANN mode requires recall@20 of at least 0.97 and zero missing ANN+exact-delta
members for all three fixtures.

The report carries measured point and time-bounded cold-read bytes; recent time/FTS/exact
vector and all-time hybrid latency; per-media server and client transport components;
per-sample durable-write formula inputs plus p95/p99/worst summaries; full-database I/O,
storage/memory, lifecycle generation count/age, 30/35-day raw
media retention, cost, deletion, and fixed 1-MiB root/64-KiB witness caps. Strict ADR
bounds are encoded at integer precision (`699999`, `99`, `999`, and `49999` ppm/ms as
applicable), so the excluded 70%, 100-ms, 0.1%, and 5% boundaries fail.

Write amplification uses policy-fixed 1-GiB and 32-GiB live-database traces for every
workload and normal/FTS/vector slice. Each trace contains the same sample IDs and changed
SQLite byte counts at both sizes, positive durable bytes and object-operation counts, and
the per-sample `4 x changed + 2 MiB` cap. The verifier recomputes p95, p99, worst, and the
maximum positive durable-byte/object-operation growth per GiB from those raw pairs, then
cross-checks the signed measurements. Flat zero-byte pseudo-writes, changed-byte swaps,
missing sizes, and independently asserted zero slopes fail.

Accepted JSON is only a restricted RFC-8785/JCS-compatible domain: ASCII strings, safe
integers, booleans, null, arrays, and objects. Floats, Unicode/surrogates, duplicate keys,
unsafe integers, excessive depth, oversized inputs, symlinks, and non-regular files are
rejected. This is not a general JCS implementation. The checked adversarial tests include
canonical vectors. The report digest and P-256/SHA-256 signature both bind the same
restricted-canonical bytes. Public-key metadata is merely pinned P-256 SPKI metadata;
the local OpenSSL fixture proves signature mechanics, not Cloud KMS provenance. The CLI
requires an absolute `--openssl` path, hashes its regular-file bytes against policy, and
runs a private copy to avoid PATH and execution-time replacement.

External release-manifest, provenance, SBOM, fixture, test-plan/config, and environment
files are checked for exact raw/canonical hashes and report/request subject equality.
Those wrappers are not cryptographic GitHub/SLSA, trusted-clock, or environment-attestation
proofs. Likewise, the request and replay-ledger snapshot are not an authenticated,
rollback-protected challenge or an atomic nonce consumer. Offline verification can reject
nonces, request digests, and the stable report replay digest visible as consumed and emit
all three values in a deterministic receipt, but it cannot safely consume them. The report
replay digest canonicalizes the signed report with only its ledger-snapshot hash zeroed,
avoiding the otherwise circular dependency between a report and the ledger entry that
consumes it.

For a future mechanics-only invocation, pass every required input explicitly and give the
verifier an absolute binary path:

```sh
python3 scripts/verify_archive_v3_capacity_report.py \
  --report /absolute/path/report.json \
  --report-digest /absolute/path/report.sha256 \
  --signature /absolute/path/report.sig.b64 \
  --public-key-metadata /absolute/path/pinned-public-key-metadata.json \
  --policy /absolute/path/policy.json \
  --verification-request /absolute/path/request.json \
  --replay-ledger /absolute/path/replay-ledger-snapshot.json \
  --time-assertion /absolute/path/time-assertion.json \
  --release-manifest /absolute/path/release-manifest.json \
  --provenance /absolute/path/provenance.json \
  --sbom /absolute/path/sbom.json \
  --fixture-manifest /absolute/path/fixture-manifest.json \
  --test-plan /absolute/path/test-plan.json \
  --test-config /absolute/path/test-config.json \
  --environment-attestation /absolute/path/environment-attestation.json \
  --openssl /absolute/path/to/openssl
```

Every successful receipt still contains `preauthorization_only: true`, `authority: false`,
and all six unsatisfied activation blockers: authenticated rollback-protected challenge
issuance, transactional replay consumption, authenticated time, cryptographic release
provenance, cryptographic environment attestation, and independent measurement
authenticity. No checked-in file or offline receipt authorizes deployment or archive-v3
authority.
