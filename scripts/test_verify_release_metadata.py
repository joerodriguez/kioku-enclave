#!/usr/bin/env python3
"""Adversarial contract tests for the signed release-manifest payload."""

from __future__ import annotations

import json
from pathlib import Path
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
VERIFIER = ROOT / "scripts" / "verify_release_metadata.py"
COMMIT = "a" * 40
DIGEST = "sha256:" + "b" * 64
IMAGE_REPOSITORY = "us-central1-docker.pkg.dev/kioku-joerodriguez/kioku/kioku-enclave"
BUCKET = "kioku-production-indexes"
MEDIA_BUCKET = "kioku-production-media"


def manifest() -> dict[str, object]:
    return {
        "schema_version": 5,
        "source_repository": "https://github.com/owner/repository",
        "source_ref": "v1.2.3",
        "source_commit": COMMIT,
        "image_uri": f"{IMAGE_REPOSITORY}:abc1234-123",
        "image_digest_uri": f"{IMAGE_REPOSITORY}@{DIGEST}",
        "image_digest": DIGEST,
        "build_url": "https://github.com/owner/repository/actions/runs/123",
        "build_profile": "production",
        "voice_quality_gate": "owner_only_unvalidated",
        "billing_enforcement_mode": "shadow",
        "gcs_bucket": BUCKET,
        "gcs_media_bucket": MEDIA_BUCKET,
        "gcs_legacy_media_bucket": BUCKET,
    }


def schema_v4_manifest() -> dict[str, object]:
    data = manifest()
    data["schema_version"] = 4
    del data["gcs_legacy_media_bucket"]
    return data


class ReleaseMetadataTests(unittest.TestCase):
    def verify(self, data: dict[str, object]) -> subprocess.CompletedProcess[str]:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "enclave-release.json"
            path.write_text(json.dumps(data), encoding="utf-8")
            return subprocess.run(
                [
                    "python3",
                    str(VERIFIER),
                    str(path),
                    "--repository",
                    "owner/repository",
                    "--tag",
                    "v1.2.3",
                    "--commit",
                    COMMIT,
                    "--image-repository",
                    IMAGE_REPOSITORY,
                    "--expected-gcs-bucket",
                    BUCKET,
                    "--expected-gcs-media-bucket",
                    MEDIA_BUCKET,
                    "--expected-gcs-legacy-media-bucket",
                    BUCKET,
                ],
                cwd=ROOT,
                text=True,
                capture_output=True,
                check=False,
            )

    def test_valid_current_manifest_is_eligible(self) -> None:
        completed = self.verify(manifest())
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn(f"\t{BUCKET}\t{MEDIA_BUCKET}\t{BUCKET}\n", completed.stdout)

    def test_missing_build_profile_is_ineligible(self) -> None:
        data = manifest()
        del data["build_profile"]
        completed = self.verify(data)
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("missing or unexpected fields", completed.stderr)

    def test_cleared_build_profile_is_ineligible(self) -> None:
        data = manifest()
        data["build_profile"] = ""
        completed = self.verify(data)
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("build_profile must be a non-empty string", completed.stderr)

    def test_non_production_build_profile_is_ineligible(self) -> None:
        data = manifest()
        data["build_profile"] = "evaluation"
        completed = self.verify(data)
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("build_profile is not production", completed.stderr)

    def test_missing_media_claim_is_ineligible(self) -> None:
        data = manifest()
        del data["gcs_media_bucket"]
        completed = self.verify(data)
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("missing or unexpected fields", completed.stderr)

    def test_missing_legacy_media_claim_is_ineligible(self) -> None:
        data = manifest()
        del data["gcs_legacy_media_bucket"]
        completed = self.verify(data)
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("missing or unexpected fields", completed.stderr)

    def test_different_current_media_bucket_is_ineligible(self) -> None:
        data = manifest()
        data["gcs_media_bucket"] = BUCKET
        completed = self.verify(data)
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("does not match the release configuration", completed.stderr)

    def test_different_legacy_media_bucket_is_ineligible(self) -> None:
        data = manifest()
        data["gcs_legacy_media_bucket"] = MEDIA_BUCKET
        completed = self.verify(data)
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("does not match the release configuration", completed.stderr)

    def test_substituted_manifest_digest_binding_is_ineligible(self) -> None:
        data = manifest()
        data["image_digest"] = "sha256:" + "c" * 64
        completed = self.verify(data)
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("image_digest_uri does not bind", completed.stderr)

    def test_substituted_manifest_source_binding_is_ineligible(self) -> None:
        data = manifest()
        data["source_commit"] = "d" * 40
        completed = self.verify(data)
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("source_commit does not match", completed.stderr)

    def test_exact_schema_v4_manifest_is_ineligible_for_promotion(self) -> None:
        data = schema_v4_manifest()
        self.assertEqual(len(data), 13)  # schema plus the exact 12 schema-v4 claims
        completed = self.verify(data)
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("missing or unexpected fields", completed.stderr)


if __name__ == "__main__":
    unittest.main()
