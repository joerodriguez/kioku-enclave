#!/usr/bin/env python3
"""Static contracts for fail-closed local release publication."""

from __future__ import annotations

from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
RELEASE = (ROOT / "scripts" / "release.sh").read_text(encoding="utf-8")
EVIDENCE = (ROOT / "scripts" / "local_build_evidence.py").read_text(encoding="utf-8")


class LocalReleaseContracts(unittest.TestCase):
    def test_release_has_no_hosted_workflow_or_attestation_dependency(self) -> None:
        self.assertNotIn("gh workflow", RELEASE)
        self.assertNotIn("gh attestation", RELEASE)
        self.assertNotIn("actions/runs", RELEASE)
        self.assertNotIn("build.yml", RELEASE)

    def test_remote_changes_require_apply_after_local_evidence_verification(self) -> None:
        evidence = RELEASE.index("scripts/verify_local_evidence_bundle.py")
        dry_run = RELEASE.index('if [[ "$APPLY" != true ]]')
        registry = RELEASE.index("artifacts docker images describe")
        push_tag = RELEASE.index('git --no-replace-objects push origin "${TAG_OBJECT}:refs/tags/${TAG}"')
        publish = RELEASE.index('gh release create "$TAG"')
        self.assertLess(evidence, dry_run)
        self.assertLess(dry_run, registry)
        self.assertLess(registry, push_tag)
        self.assertLess(push_tag, publish)
        self.assertIn("immutable-releases", RELEASE)
        self.assertIn('git --no-replace-objects fetch origin main', RELEASE)
        self.assertIn('--impersonate-service-account="$BUILDER_SERVICE_ACCOUNT"', RELEASE)
        self.assertNotIn("--prerelease=false", RELEASE)
        self.assertIn("--prerelease", RELEASE)
        self.assertIn('if [[ "$ROLL" == true && "$APPLY" != true ]]', RELEASE)
        self.assertIn('enclave-roll --release-tag "$TAG" --image-uri "$DIGEST_URI" --digest "$DIGEST" --config "$RELEASE_CONFIG_SNAPSHOT" --confirm "ROLL ENCLAVE $DIGEST" --apply', RELEASE)
        self.assertIn(
            'KIOKU_PUSH_RUNTIME_SOURCE_SEAL="$PUSH_DEPLOYMENT_SOURCE_SEAL"',
            RELEASE,
        )

    def test_tag_digest_and_sbom_are_bound_before_publication(self) -> None:
        tag = RELEASE.index("verify_tag_signer")
        digest = RELEASE.index("image_digest_uri")
        sbom = RELEASE.index("SBOM_VERSION")
        push_tag = RELEASE.index('git --no-replace-objects push origin "${TAG_OBJECT}:refs/tags/${TAG}"')
        self.assertLess(tag, push_tag)
        self.assertLess(digest, push_tag)
        self.assertLess(sbom, push_tag)
        self.assertIn('refs/tags/${TAG}^{tag}', RELEASE)
        self.assertIn('cat-file tag "$tag_object"', RELEASE)
        self.assertIn('rev-parse "${TAG_OBJECT}^{commit}"', RELEASE)
        self.assertIn('verify-tag --raw "$tag_object"', RELEASE)
        self.assertIn('ls-remote --tags origin', RELEASE)
        self.assertNotIn('ls-remote --refs', RELEASE)
        self.assertIn('Artifact Registry did not resolve the signed image digest', RELEASE)
        self.assertIn('isImmutable', RELEASE)

    def test_release_metadata_uses_only_live_media_and_postgres_authority(self) -> None:
        self.assertIn('"ENCLAVE_GCS_MEDIA_BUCKET", "BILLING_ENFORCEMENT_MODE"', RELEASE)
        self.assertIn("scripts/verify_local_evidence_bundle.py", RELEASE)
        for obsolete in (
            "ENCLAVE_GCS_LEGACY_MEDIA_BUCKET",
            "ARCHIVE_V3_SHADOW_RUNTIME_MODE",
            "GENESIS_WAL_NATIVE",
            "KIOKU_CONFIRM_ARCHIVE_V3_ROLL",
        ):
            self.assertNotIn(obsolete, RELEASE)

    def test_push_roll_binds_exact_deployment_source_before_network_and_roll(self) -> None:
        verifier_call = "scripts/verify_push_runtime_topology.py"
        self.assertEqual(RELEASE.count(verifier_call), 3)
        canonical = RELEASE.index(verifier_call)
        early = RELEASE.index(verifier_call, canonical + len(verifier_call))
        final = RELEASE.index(verifier_call, early + len(verifier_call))
        fetch = RELEASE.index("git --no-replace-objects fetch origin main")
        registry = RELEASE.index("artifacts docker images describe")
        publish = RELEASE.index('git --no-replace-objects push origin "${TAG_OBJECT}:refs/tags/${TAG}"')
        roll = RELEASE.index('"$ROLL_PATH" enclave-roll')
        self.assertLess(canonical, early)
        self.assertLess(early, fetch)
        self.assertLess(early, registry)
        self.assertLess(early, publish)
        self.assertLess(final, roll)
        self.assertIn(
            '[[ "$FINAL_PUSH_DEPLOYMENT_SOURCE_SEAL" == "$PUSH_DEPLOYMENT_SOURCE_SEAL" ]]',
            RELEASE[final:roll],
        )
        self.assertIn("--canonical-path", RELEASE[canonical:early])
        self.assertNotIn("--roll-script", RELEASE)
        self.assertIn('LOCAL_ROLL_SCRIPT="scripts/local-operations.sh"', RELEASE)
        self.assertIn(
            'ROLL_PATH="${DEPLOYMENT_REPO_PATH}/${LOCAL_ROLL_SCRIPT}"',
            RELEASE,
        )
        seal_environment = RELEASE.index(
            'KIOKU_PUSH_RUNTIME_SOURCE_SEAL="$PUSH_DEPLOYMENT_SOURCE_SEAL"'
        )
        self.assertLess(final, seal_environment)
        self.assertLess(seal_environment, roll)
        verifier = (ROOT / "scripts" / "verify_push_runtime_topology.py").read_text(
            encoding="utf-8"
        )
        for evidence in (
            "REVIEWED_DEPLOYMENT",
            'head="0580e974fd6aa780f44f208e8f7ad6fd765d0fe4"',
            'digest="8e12937f582abe272e51f8f1d093d41ada431d5d636792123c1fab1baabab4d5"',
            "--untracked-files=all",
            "canonical_source_digest",
            "root_source_inventory",
            "canonical_repository_path",
            "verify_roll_script",
            "hash-object",
            "GIT_NO_REPLACE_OBJECTS",
            "refs/replace",
        ):
            self.assertIn(evidence, verifier)
        self.assertNotIn("origin_main_seal", verifier)
        self.assertNotIn("origin/main^{commit}", verifier)
        self.assertNotIn("re.compile", verifier)

    def test_evidence_has_only_hashes_for_local_build_inputs(self) -> None:
        for field in ("config_sha256", "dockerfile_sha256", "cargo_lock_sha256", "release_metadata_sha256", "sbom_sha256", "scan_sha256"):
            self.assertIn(field, EVIDENCE)
        self.assertIn("external trust anchor", EVIDENCE)
        self.assertIn("exact mode 0600", EVIDENCE)
        self.assertNotIn('"config":', EVIDENCE)

    def test_frozen_detached_release_requires_signed_ancestor_receipt(self) -> None:
        self.assertIn("--frozen-commit", RELEASE)
        self.assertIn("verify_coordinator_advancement_receipt.py", RELEASE)
        self.assertIn('git --no-replace-objects merge-base --is-ancestor "$COMMIT" "$ORIGIN_MAIN"', RELEASE)
        self.assertIn('[[ "$(git --no-replace-objects rev-parse HEAD)" == "$COMMIT" ]]', RELEASE)
        self.assertIn('local main must exactly match origin/main', RELEASE)

    def test_release_retries_compare_every_existing_asset_byte_for_byte(self) -> None:
        self.assertIn("compare_existing_release_assets()", RELEASE)
        self.assertIn("gh release download", RELEASE)
        self.assertIn("cmp -s", RELEASE)

    def test_release_verifies_and_uploads_only_read_only_asset_snapshots(self) -> None:
        snapshot = RELEASE.index('EVIDENCE_SNAPSHOT="$(mktemp -d)"')
        verifier = RELEASE.index("scripts/verify_local_evidence_bundle.py")
        upload = RELEASE.index('gh release create "$TAG"')
        self.assertLess(snapshot, verifier)
        self.assertLess(snapshot, upload)
        self.assertIn('EVIDENCE_DIR="$EVIDENCE_SNAPSHOT"', RELEASE[snapshot:verifier])
        self.assertIn("os.fchmod(output, 0o400)", RELEASE[snapshot:verifier])
        self.assertIn("destination_directory.chmod(0o500)", RELEASE[snapshot:verifier])

    def test_release_rejects_git_object_substitution_and_ambient_overrides(self) -> None:
        self.assertIn("export GIT_NO_REPLACE_OBJECTS=1", RELEASE)
        self.assertIn("ambient Git overrides are not accepted", RELEASE)
        self.assertIn("git --no-replace-objects replace -l", RELEASE)
        self.assertIn("--git-path info/grafts", RELEASE)
        self.assertIn("Git graft files are not accepted", RELEASE)
        self.assertNotRegex(
            RELEASE, r"(?m)^\s*git (?!--no-replace-objects(?:\s|$))"
        )
        self.assertNotRegex(
            RELEASE, r"\$\(git (?!--no-replace-objects(?:\s|$))"
        )

    def test_release_state_query_accepts_only_exact_absence(self) -> None:
        self.assertIn('release_error" != "release not found"', RELEASE)
        self.assertIn('release_error" != "HTTP 404: Not Found"', RELEASE)
        self.assertNotIn('release view "$TAG" --repo "$REPOSITORY" --json isDraft,isImmutable,isPrerelease,assets 2>/dev/null || true', RELEASE)

    def test_release_rejects_service_account_json_credentials(self) -> None:
        self.assertIn("GOOGLE_APPLICATION_CREDENTIALS is not accepted", RELEASE)


if __name__ == "__main__":
    unittest.main()
