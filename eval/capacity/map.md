# `eval/capacity/` map

Content-free, deterministic capacity inputs for ADR-0022. No generated fixture data,
captured content, user identifiers, or capacity results belong in this directory.

| Path | Role |
|---|---|
| `archive-fixtures-v1.json` | Versioned three-year 480/960/1,200-hour workload parameters, expected record distributions and byte ranges, plus the explicit 32-GiB sparse-shape target consumed by `scripts/generate_capacity_fixture.py` |

The checked-in manifest is a planning and reproducibility contract, not release evidence.
A release capacity report must additionally pin the VM/image, SQLite/extensions, cache
state, concurrency and backend/fault profile required by ADR-0022.

`scripts/run_archive_capacity_harness.py` consumes this manifest into ignored/out-of-tree
SQLite databases. Smoke reports are explicitly non-evidence. A full report can claim
SQLite capacity evidence only after the declared 32-GiB logical/file target and explicit
ingest, query-p95, and RSS gates pass; it still does not evidence a production backend,
VFS, witness, fault, or lifecycle gate.
