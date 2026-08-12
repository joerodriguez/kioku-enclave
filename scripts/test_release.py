#!/usr/bin/env python3
"""Static fail-closed contracts for immutable release publication."""

from __future__ import annotations

from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
RELEASE = ROOT / "scripts" / "release.sh"
WORKFLOW = ROOT / ".github" / "workflows" / "build.yml"
METADATA_VERIFIER = ROOT / "scripts" / "verify_release_metadata.py"


class ReleasePublicationRaceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.source = RELEASE.read_text(encoding="utf-8")
        cls.workflow = WORKFLOW.read_text(encoding="utf-8")
        cls.metadata_verifier = METADATA_VERIFIER.read_text(encoding="utf-8")

    def test_ci_cannot_publish_a_release_for_a_generic_verified_signer(self) -> None:
        self.assertNotIn("contents: write", self.workflow)
        self.assertNotIn("Automatically publish GitHub Release", self.workflow)
        self.assertNotIn("gh release create", self.workflow)
        signer_check = self.source.index('grep -qxF "$RELEASE_SIGNER_FINGERPRINT"')
        signer_call = self.source.index("\n  verify_tag_signer\n")
        release_create = self.source.index('if gh release create "$RELEASE_TAG"')
        self.assertLess(signer_check, signer_call)
        self.assertLess(signer_call, release_create)

    def test_refreshes_state_after_build_evidence_and_before_mutation(self) -> None:
        evidence = self.source.index("Verifying signed GitHub build provenance")
        refresh = self.source.index("\nrefresh_release_state_before_mutation\nif ", evidence)
        create = self.source.index("\n  create_release_or_reverify_publication_race\n", refresh)
        draft_edit = self.source.index('gh release edit "$RELEASE_TAG"', refresh)
        self.assertGreater(refresh, evidence)
        self.assertLess(refresh, create)
        self.assertLess(refresh, draft_edit)

    def test_failed_create_rechecks_and_reverifies_the_exact_release(self) -> None:
        start = self.source.index("create_release_or_reverify_publication_race() {")
        end = self.source.index("refresh_release_state_before_mutation\nif ", start)
        fallback = self.source[start:end]
        self.assertIn('if gh release create "$RELEASE_TAG"', fallback)
        self.assertIn("refresh_release_state_before_mutation", fallback)
        self.assertIn('"$RELEASE_EXISTS" == "true"', fallback)
        self.assertIn('"$RELEASE_IS_DRAFT" == "false"', fallback)
        self.assertIn("reverify_published_immutable_release", fallback)
        self.assertIn("failed without an exact published immutable release", fallback)

    def test_race_acceptance_requires_complete_immutable_public_release(self) -> None:
        start = self.source.index("reverify_published_immutable_release() {")
        end = self.source.index("refresh_release_state_before_mutation\nif ", start)
        verifier = self.source[start:end]
        self.assertIn('"$RELEASE_IS_DRAFT" != "false"', verifier)
        self.assertIn('"$RELEASE_IS_IMMUTABLE" != "true"', verifier)
        self.assertIn('"$RELEASE_IS_PRERELEASE" != "$EXPECTED_PRERELEASE"', verifier)
        self.assertIn('"$RELEASE_ASSETS_CSV" != "$EXPECTED_ASSETS_CSV"', verifier)
        self.assertIn('cmp -s "$WORK_DIR/$asset_name"', verifier)

    def test_hostile_or_malformed_release_state_fails_closed(self) -> None:
        start = self.source.index("refresh_release_state_before_mutation() {")
        end = self.source.index("reverify_published_immutable_release() {", start)
        refresher = self.source[start:end]
        self.assertIn('type(release.get(key)) is not bool', refresher)
        self.assertIn("datetime.fromisoformat", refresher)
        self.assertIn('release state has malformed assets', refresher)
        self.assertIn('release state has unsafe asset names', refresher)
        self.assertIn('release state is malformed; refusing to mutate', refresher)

    def test_immutable_release_path_never_edits_or_uploads(self) -> None:
        immutable = self.source.index('elif [[ "$RELEASE_IS_DRAFT" == "true" ]]')
        reverified = self.source.index(
            'echo "Existing immutable release was re-verified; metadata and notes were not modified."'
        )
        edit = self.source.index('gh release edit "$RELEASE_TAG"')
        upload = self.source.index('gh release upload "$RELEASE_TAG"')
        self.assertLess(edit, reverified)
        self.assertLess(upload, reverified)
        self.assertLess(immutable, edit)

    def test_release_requires_signed_schema_v5_dual_media_manifest_before_promotion(self) -> None:
        manifest_verification = self.source.index("Verifying signed release metadata manifest")
        parser = self.source.index("scripts/verify_release_metadata.py")
        image_provenance = self.source.index("Verifying signed GitHub build provenance")
        self.assertLess(manifest_verification, parser)
        self.assertLess(parser, image_provenance)
        self.assertIn('METADATA_PROVENANCE_FILE="$WORK_DIR/enclave-release-metadata-provenance.jsonl"', self.source)
        self.assertIn('--expected-gcs-media-bucket "$EXPECTED_GCS_MEDIA_BUCKET"', self.source)
        self.assertIn(
            '--expected-gcs-legacy-media-bucket "$EXPECTED_GCS_LEGACY_MEDIA_BUCKET"',
            self.source,
        )
        self.assertIn("enclave-release-metadata-provenance.jsonl", self.source)
        self.assertIn(
            'if data["build_profile"] != "production":',
            self.metadata_verifier,
        )

    def test_apns_roll_preflight_reads_only_metadata_and_exact_iam(self) -> None:
        self.assertIn("gcloud secrets versions describe latest", self.source)
        self.assertIn("gcloud secrets get-iam-policy", self.source)
        self.assertIn('apns_latest_state" != "ENABLED"', self.source)
        self.assertIn("roles/secretmanager.secretAccessor", self.source)
        self.assertIn('serviceAccount:${ENCLAVE_RUN_SA_EMAIL}', self.source)
        self.assertNotIn("gcloud secrets versions access", self.source)
        self.assertNotIn("--impersonate-service-account", self.source)


if __name__ == "__main__":
    unittest.main()
