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
SQLite smoke databases. Its reports are explicitly non-evidence and full mode fails
closed. The harness cannot claim a 32-GiB release, backend, VFS, witness, fault,
lifecycle, cache, concurrency, or production-image gate.
