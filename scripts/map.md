# `scripts/` map

Operator and CI entrypoints for versioning, signed release publication, licensed
voice-evaluation asset acquisition, deterministic capacity-fixture generation, and
fail-closed image configuration selection.
None of these scripts runs in the enclave or in a Kioku client.

| Path | Responsibility |
|---|---|
| `agent-verify.sh` | Space-guarded local verification with quick, focused, and full modes; uses locked Cargo commands and an optional bounded local `sccache`. |
| `check_build_disk_space.py` | Refuses heavyweight local verification when the selected filesystem is below a configurable free-space floor (15 GiB by default). |
| `rust_build_lock.py` | Crash-safe, per-worktree kernel lock shared by local verification and artifact retirement so wrapper-controlled builds cannot overlap retirement. |
| `retire_rust_worktree_artifacts.py` | Dry-run-first retirement of only the exact `target/` directory in a clean, linked worktree whose exact GitHub PR head is merged; coordinates with the wrapper lock plus defensive process/Cargo-profile checks and quarantines the exact directory before deletion. Raw Cargo must not race it. |
| `test_agent_verify.py` | Fast mocked command contracts for verification modes, argument forwarding, the shared disk guard, and bounded optional `sccache`. |
| `test_rust_build_lifecycle.py` | Isolated temporary-repository contracts for disk checks and fail-closed worktree artifact retirement. |
| `bump_version.sh` | Refuses main/detached HEAD, updates the Cargo manifest and exact root lockfile package entry without compiling, validates them with locked metadata, and stages the complete release change without committing or pushing. |
| `fetch_voice_eval_assets.sh` | Downloads licensed evaluation inputs and records hashes outside Git. |
| `check_voice_release_gate.py` | Classifies a release as exact owner-only/no-claim or invokes the Rust checker for a complete real-corpus trio. |
| `test_check_voice_release_gate.py` | Fail-closed contract tests for owner-only and validated-real-corpus classifications. |
| `release.sh` | Requires successful required CI for the exact public main commit, verifies the selected voice-quality classification, repository-bound billing mode, GitHub-signed schema-v6 Phase-0/probe-mode manifest, and—before a roll—enabled APNs key-version metadata plus the exact runtime secret-accessor IAM binding without reading keys or impersonating the runtime identity; creates a signed tag, verifies build evidence, publishes an immutable release, and optionally requests an operator roll. |
| `verify_release_metadata.py` | Strict schema-v6 validator for the GitHub-signed release-manifest subject: binds source/tag/image digest, bucket topology, and the exact complete-or-empty Firestore probe mode/namespace claim. |
| `test_release.py` | Static fail-closed contracts for release-state refresh, immutable-publication races, signed release-manifest handling, APNs metadata/IAM-only roll preflight, and the workflow's lack of publication authority. |
| `test_verify_release_metadata.py` | Adversarial contract tests for missing/different media claims and substituted source/image-digest manifest fields. |
| `test_release_race.sh` | Mocked execution test of the exact signer anchor and release-state refresh: a valid wrong-key signature fails, raced immutable releases are reverified without mutation, and mismatched assets fail closed. |
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
