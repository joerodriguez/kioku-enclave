# `scripts/` map

Operator and CI entrypoints for versioning, signed release publication, licensed
voice-evaluation asset acquisition, deterministic capacity-fixture generation, and
fail-closed image configuration selection.
None of these scripts runs in the enclave or in a Kioku client.

| Path | Responsibility |
|---|---|
| `bump_version.sh` | Refuses main/detached HEAD, updates the Cargo version, and stages the complete release change without committing or pushing. |
| `fetch_voice_eval_assets.sh` | Downloads licensed evaluation inputs and records hashes outside Git. |
| `check_voice_release_gate.py` | Classifies a release as exact owner-only/no-claim or invokes the Rust checker for a complete real-corpus trio. |
| `test_check_voice_release_gate.py` | Fail-closed contract tests for owner-only and validated-real-corpus classifications. |
| `release.sh` | Verifies the selected voice-quality classification and repository-bound billing mode, creates a signed tag, verifies build evidence, publishes an immutable release, and optionally requests an operator roll. |
| `test_release.py` | Static fail-closed contracts for release-state refresh, immutable-publication races, and malformed release metadata. |
| `test_release_race.sh` | Mocked execution test of release-state refresh: raced immutable releases are reverified without mutation, while mismatched assets fail closed. |
| `select_build_configuration.py` | Atomically selects and validates one complete production or evaluation image profile, including the reviewed `shadow|enforce` billing mode, without cross-profile fallback. |
| `test_select_build_configuration.py` | Contract tests for profile isolation and the public build workflow. |
| `generate_capacity_fixture.py` | Validates ADR-0022's versioned v1/v2 capacity manifests and streams content-free synthetic distributions into ignored/out-of-tree output; an explicit option can create the declared 32-GiB logical sparse shape without writing 32 GiB of blocks. |
| `test_generate_capacity_fixture.py` | Validates v1 480/960/1,200-hour and v2 12-month 40/80/100-hour distributions plus bounded deterministic generation without creating the 32-GiB shape. |
| `run_archive_capacity_harness.py` | Offline ADR-0022 content-free SQLite smoke harness. It binds resumable output to an exclusive receipt, verifies exact counts/integrity/export digest, and permanently refuses full/release-evidence claims. |
| `test_run_archive_capacity_harness.py` | Contract tests for smoke-only false evidence, exact integrity/counts, receipt-bound resume, output safety, argument validation, and percentile behavior. |
| `run_archive_capacity_gate.py` | Explicit, long-running local production-shaped capacity gate for the v2 12-month 40/80/100-hour fixtures. It streams numeric rows plus bounded zero-filled payload/vector-shape BLOBs, verifies local SQLite DB/WAL/checkpoint behavior and 32-GiB page geometry, and probes sparse near-ceiling extents without materializing a giant snapshot. |
| `test_run_archive_capacity_gate.py` | Fast contracts for the no-I/O plan, mandatory operator acknowledgements, component-by-component symlink rejection, no-follow report writes, profile-derived free-space geometry, and mocked sparse-extent geometry; it does not execute the long-running SQLite gate or create large files. |
| `verify_archive_v3_capacity_report.py` | Offline restricted-JCS verifier for the inactive ADR-0022 contract; enforces the exact workload-by-case/metric/result matrix, pinned environment, paired live-size write traces and derived growth, transport/ANN/lifecycle/deletion semantics, DER-validates P-256, executes a private copy of an absolute-path, hash-pinned verifier binary with a restricted environment, lists untrusted-wrapper blockers, and never grants authority. |
| `test_verify_archive_v3_capacity_report.py` | Adversarial tests for P-256 key type/curve, exact cross-products and environments, tiny/substituted workloads, strict boundaries, transport/write/root/witness/ANN/deletion, freshness, malformed wrappers, bounded regular inputs, replay, and signatures. |

The Python selector is CI/operator tooling only. The macOS and iOS clients remain pure
Swift and the enclave runtime remains Rust.
