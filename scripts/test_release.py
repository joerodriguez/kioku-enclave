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
        push_tag = RELEASE.index('git push origin "$TAG"')
        publish = RELEASE.index('gh release create "$TAG"')
        self.assertLess(evidence, dry_run)
        self.assertLess(dry_run, registry)
        self.assertLess(registry, push_tag)
        self.assertLess(push_tag, publish)
        self.assertIn("immutable-releases", RELEASE)
        self.assertIn('git fetch origin main', RELEASE)
        self.assertIn('--impersonate-service-account="$BUILDER_SERVICE_ACCOUNT"', RELEASE)
        self.assertNotIn("--prerelease=false", RELEASE)
        self.assertIn("--prerelease", RELEASE)
        self.assertIn('if [[ "$ROLL" == true && "$APPLY" != true ]]', RELEASE)
        self.assertIn('enclave-roll --release-tag "$TAG" --image-uri "$DIGEST_URI" --digest "$DIGEST" --confirm "ROLL ENCLAVE $DIGEST" --apply', RELEASE)

    def test_tag_digest_and_sbom_are_bound_before_publication(self) -> None:
        tag = RELEASE.index("verify_tag_signer")
        digest = RELEASE.index("image_digest_uri")
        sbom = RELEASE.index("SBOM_VERSION")
        push_tag = RELEASE.index('git push origin "$TAG"')
        self.assertLess(tag, push_tag)
        self.assertLess(digest, push_tag)
        self.assertLess(sbom, push_tag)
        self.assertIn('git rev-list -n 1 "$TAG"', RELEASE)
        self.assertIn('Artifact Registry did not resolve the signed image digest', RELEASE)
        self.assertIn('isImmutable', RELEASE)

    def test_evidence_has_only_hashes_for_local_build_inputs(self) -> None:
        for field in ("config_sha256", "dockerfile_sha256", "cargo_lock_sha256", "release_metadata_sha256", "sbom_sha256", "scan_sha256"):
            self.assertIn(field, EVIDENCE)
        self.assertIn("external trust anchor", EVIDENCE)
        self.assertIn("exact mode 0600", EVIDENCE)
        self.assertNotIn('"config":', EVIDENCE)


if __name__ == "__main__":
    unittest.main()
