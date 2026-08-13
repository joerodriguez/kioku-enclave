# `eval/capacity/` map

Content-free, deterministic capacity inputs for ADR-0022. No generated fixture data,
captured content, user identifiers, or capacity results belong in this directory.

| Path | Role |
|---|---|
| `archive-fixtures-v1.json` | Versioned three-year 480/960/1,200-hour smoke-fixture contract consumed by `scripts/generate_capacity_fixture.py` |
| `archive-fixtures-v2.json` | Versioned 12-month 40/80/100-hour-per-month production-shaped numeric contract, including the explicit 32-GiB sparse-extent target consumed by `scripts/run_archive_capacity_gate.py` |
| `archive-v3-capacity-policy-v2.template.json` | Intentionally unusable preauthorization template: exact workload/environment/matrix contexts and freshness maxima may only tighten where documented; placeholder P-256/tool/time-wrapper values are not trust proofs |
| `archive-v3-capacity-evidence-v2.schema.json` | Public top-level shape companion for restricted-JCS signed evidence; the verifier normatively enforces every workload-by-case/metric/result dimension and cross-field relation |

The checked-in manifest is a planning and reproducibility contract, not release evidence.
A release capacity report must additionally pin the VM/image, SQLite/extensions, cache
state, concurrency and backend/fault profile required by ADR-0022.

`scripts/run_archive_capacity_harness.py` consumes the v1 manifest into ignored/out-of-tree
SQLite smoke databases. Its reports are explicitly non-evidence and full mode fails
closed. The harness cannot claim a 32-GiB release, backend, VFS, witness, fault,
lifecycle, cache, concurrency, or production-image gate.

`scripts/run_archive_capacity_gate.py` separately consumes v2 only after explicit operator
confirmation and a disk preflight. It streams numeric records with bounded batches, observes
a real local SQLite WAL/checkpoint cycle, checks the 32-GiB `max_page_count` geometry, and
uses sparse regular-file probes for near-ceiling extents. It remains local non-authority
evidence: no 32-GiB snapshot is materialized, downloaded, or encrypted. V2 numeric rows
also carry month/cadence and retention geometry while materializing bounded zero-filled
per-kind payload and float32 embedding-shape BLOBs.

The signed-evidence contract is inactive and has no runtime consumer. Its exact matrix
repeats workload, 32-GiB/three-year, fixture/plan/config/environment, media/query/cache,
sample, and percentile bindings on each result class. Paired policy-fixed 1-GiB/32-GiB
write traces derive summaries and live-size growth from raw samples. Request, artifact,
time, and replay files are strict hash-bound wrappers only: they do not establish an
authenticated challenge, trusted clock, rollback protection, or provider provenance. The
receipt lists those activation blockers, is preauthorization only, always denies authority,
and cannot consume a nonce or prove that measurements occurred.
