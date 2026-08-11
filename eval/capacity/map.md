# `eval/capacity/` map

Content-free, deterministic capacity inputs for ADR-0022. No generated fixture data,
captured content, user identifiers, or capacity results belong in this directory.

| Path | Role |
|---|---|
| `archive-fixtures-v1.json` | Versioned three-year 480/960/1,200-hour smoke-fixture contract consumed by `scripts/generate_capacity_fixture.py` |
| `archive-fixtures-v2.json` | Versioned 12-month 40/80/100-hour-per-month production-shaped numeric contract, including the explicit 32-GiB sparse-extent target consumed by `scripts/run_archive_capacity_gate.py` |

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
