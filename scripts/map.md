# `scripts/` map

Operator and CI entrypoints for versioning, signed release publication, licensed
voice-evaluation asset acquisition, deterministic capacity-fixture generation, and
fail-closed image configuration selection.
None of these scripts runs in the enclave or in a Kioku client.

| Path | Responsibility |
|---|---|
| `bump_version.sh` | Updates the Cargo version and stages the complete release change. |
| `fetch_voice_eval_assets.sh` | Downloads licensed evaluation inputs and records hashes outside Git. |
| `check_voice_release_gate.py` | Classifies a release as exact owner-only/no-claim or invokes the Rust checker for a complete real-corpus trio. |
| `test_check_voice_release_gate.py` | Fail-closed contract tests for owner-only and validated-real-corpus classifications. |
| `release.sh` | Verifies the selected voice-quality classification, creates a signed tag, verifies build evidence, publishes an immutable release, and optionally requests an operator roll. |
| `test_release.py` | Static fail-closed contracts for release-state refresh, immutable-publication races, and malformed release metadata. |
| `test_release_race.sh` | Mocked execution test of release-state refresh: raced immutable releases are reverified without mutation, while mismatched assets fail closed. |
| `select_build_configuration.py` | Atomically selects and validates one complete production or evaluation image profile without cross-profile fallback. |
| `test_select_build_configuration.py` | Contract tests for profile isolation and the public build workflow. |
| `generate_capacity_fixture.py` | Validates ADR-0022's checked-in capacity manifest and streams content-free synthetic distributions into ignored/out-of-tree output; an explicit option can create the declared 32-GiB logical sparse shape without writing 32 GiB of blocks. |
| `test_generate_capacity_fixture.py` | Validates exact 480/960/1,200-hour distributions and bounded deterministic generation without creating the 32-GiB shape. |
| `run_archive_capacity_harness.py` | Offline ADR-0022 content-free SQLite smoke harness. It binds resumable output to an exclusive receipt, verifies exact counts/integrity/export digest, and permanently refuses full/release-evidence claims. |
| `test_run_archive_capacity_harness.py` | Contract tests for smoke-only false evidence, exact integrity/counts, receipt-bound resume, output safety, argument validation, and percentile behavior. |

The Python selector is CI/operator tooling only. The macOS and iOS clients remain pure
Swift and the enclave runtime remains Rust.
