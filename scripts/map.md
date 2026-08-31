# `scripts/` map

Local verification, immutable image publication, signed evidence, and operator-only release
helpers. Hosted GitHub workflows are intentionally disabled; mutation-capable tools default to
dry-run, bind exact source/artifact identities, and require explicit confirmation.

| Path | Responsibility |
|---|---|
| `agent-verify.sh` / `test_agent_verify.py` | Locked Rust formatter/check/test/Clippy gate. Full mode fails closed unless an operator supplies a disposable real PostgreSQL URL; it never starts Docker implicitly. |
| `rust_build_lock.py` / `test_rust_build_lifecycle.py` | Crash-safe per-worktree Cargo lock and lifecycle contracts. |
| `check_build_disk_space.py` | Bounded free-space preflight shared by verification and build tooling. |
| `select_build_configuration.py` / `test_select_build_configuration.py` | Exact production/evaluation selector for KMS, the live media bucket, identity/provider inputs, and fixed PostgreSQL pool/readiness/drain/TLS invariants. Schema verification is unconditional serving code, not image configuration; there is no backend selector or fallback profile. |
| `assemble_image_config.sh` | No-eval, hash-bound BuildKit-secret assembler that repeats the selected image configuration checks at the Docker trust boundary. |
| `bootstrap_local_operator_config.py` / `test_bootstrap_local_operator_config.py` | One-time helper that uses temporary registry credentials to copy `/kioku-config` from an exact immutable image digest without executing it, then validates a production profile and writes an external mode-0600 operator configuration without printing values. |
| `local_image_pipeline.py` / `test_local_image_pipeline.py` | Source-frozen Linux/amd64 build, OCI quarantine, public-path-normalized SBOM and vulnerability scan, signed-evidence preparation, registry promotion, and one-way content-addressed resume pipeline. The digest-free build summary is frozen and validated before cloud authentication; push and final-evidence receipts bind the registry digest. Verification discovers every checked-in `test_*.py`/`test_*.sh` contract, preserves an explicitly configured private native-builder selection for its mandatory tool preflight, and passes the real-PostgreSQL URL plus any explicitly validated disk-floor override only to the full Rust/PostgreSQL gate, never to build, scan, cloud, or promotion children; the checked-in 15-GiB default remains when no override is supplied. |
| `local_build_evidence.py` / `test_local_build_evidence.py` | Canonical evidence creator plus externally pinned Ed25519 signing/verification; binds exact configuration, source archive, image digest, release metadata, SBOM, scan, Dockerfile, and lockfile hashes. |
| `verify_release_metadata.py` / `test_verify_release_metadata.py` | Canonical schema-11 validator binding source/tag/image, live media bucket, KMS coordinates, PostgreSQL authority, required serving-schema verification, fleet connection budget, readiness/drain values, and shared TLS. Earlier archive-authority schemas are ineligible for new promotion. |
| `verify_local_evidence_bundle.py` | Side-effect-free rollout verifier that cross-checks the signed evidence bundle against the exact private selected configuration and immutable source/assets, and refuses host-local paths before any public release mutation. |
| `deploy_latest.py` / `test_deploy_latest.py` | Cargo-versioned signed-tag driver for build, push, evidence signing, and release publication. |
| `release.sh` / `test_release.py` / `test_release_race.sh` | Immutable GitHub release owner: snapshots assets, verifies tag signer/source/image/SBOM/scan/config before provider mutation, supports byte-identical resume, and retains the explicit scale-to-zero maintenance lane for an incompatible release. Compatible fleet releases use the ADR-0041 staged Terraform rollout. |
| `release_train_enclave.py` / `test_release_train_enclave.py` | Adapter used by the cross-repository local release train; keeps prepare/later credential separation, emits a private canonical OCI-manifest witness for coordinator admission, and preserves exact digest confirmation, immutable asset snapshots, and strict machine-readable receipts. |
| `repromote_signed_image.py` / `test_repromote_signed_image.py` | Push-only recovery for the exact already-signed OCI digest; never rebuilds, rescans, resigns, or edits an immutable release. |
| `verify_coordinator_advancement_receipt.py` / `test_coordinator_advancement_receipt.py` | External Ed25519 authorization for the narrow frozen-ancestor release path. |
| `verify_push_runtime_topology.py` / `test_verify_push_runtime_topology.py` | Independently reviewed immutable deployment commit/inventory/content pin, recomputed against a clean checkout before and immediately before the explicit incompatible-release maintenance roll. Any deployment-source change requires a separate enclave pin-update review. |
| `check_voice_release_gate.py` / `test_check_voice_release_gate.py` | Classifies checked voice evaluation evidence for release metadata. |
| `fetch_voice_eval_assets.sh` | Downloads license-restricted voice inputs outside Git for local evaluation. |
| `disable_github_actions.py` / `test_disable_github_actions.py` | Verifies and preserves the local-only release posture. |
| `retire_rust_worktree_artifacts.py` | Dry-run-first cleanup for artifacts belonging to an exact clean, merged linked worktree. |
| `bump_version.sh` | Updates the crate version used by standard release tags. |
