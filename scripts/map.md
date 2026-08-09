# `scripts/` map

Operator and CI entrypoints for versioning, signed release publication, licensed
voice-evaluation asset acquisition, and fail-closed image configuration selection.
None of these scripts runs in the enclave or in a Kioku client.

| Path | Responsibility |
|---|---|
| `bump_version.sh` | Updates the Cargo version and stages the complete release change. |
| `fetch_voice_eval_assets.sh` | Downloads licensed evaluation inputs and records hashes outside Git. |
| `check_voice_release_gate.py` | Classifies a release as exact owner-only/no-claim or invokes the Rust checker for a complete real-corpus trio. |
| `test_check_voice_release_gate.py` | Fail-closed contract tests for owner-only and validated-real-corpus classifications. |
| `release.sh` | Verifies the selected voice-quality classification, creates a signed tag, verifies build evidence, publishes an immutable release, and optionally requests an operator roll. |
| `select_build_configuration.py` | Atomically selects and validates one complete production or evaluation image profile without cross-profile fallback. |
| `test_select_build_configuration.py` | Contract tests for profile isolation and the public build workflow. |

The Python selector is CI/operator tooling only. The macOS and iOS clients remain pure
Swift and the enclave runtime remains Rust.
