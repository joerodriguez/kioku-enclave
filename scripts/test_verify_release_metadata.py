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
        "schema_version": 9,
        "source_repository": "https://github.com/owner/repository",
        "source_ref": "v1.2.3",
        "source_commit": COMMIT,
        "image_uri": f"{IMAGE_REPOSITORY}:abc1234-123",
        "image_digest_uri": f"{IMAGE_REPOSITORY}@{DIGEST}",
        "image_digest": DIGEST,
        "release_url": "https://github.com/owner/repository/releases/tag/v1.2.3",
        "build_profile": "production",
        "voice_quality_gate": "owner_only_unvalidated",
        "billing_enforcement_mode": "shadow",
        "gcs_bucket": BUCKET,
        "gcs_media_bucket": MEDIA_BUCKET,
        "gcs_legacy_media_bucket": BUCKET,
        "archive_witness_shadow_mode": "off",
        "archive_witness_project_id": "",
        "archive_witness_project_number": "",
        "archive_witness_database_id": "",
        "archive_v3_shadow_runtime_mode": "off",
        "archive_v3_archive_bucket": "",
        "archive_v3_archive_gcs_project_number": "",
        "archive_v3_registry_kms_version": "",
        "archive_v3_witness_project_id": "",
        "archive_v3_witness_project_number": "",
        "archive_v3_witness_database_id": "",
        "archive_v3_archive_binding_commitment": "",
    }


def schema_v4_manifest() -> dict[str, object]:
    data = manifest()
    data["schema_version"] = 4
    del data["gcs_legacy_media_bucket"]
    for key in (
        "archive_witness_shadow_mode",
        "archive_witness_project_id",
        "archive_witness_project_number",
        "archive_witness_database_id",
        "archive_v3_shadow_runtime_mode",
        "archive_v3_archive_bucket",
        "archive_v3_archive_gcs_project_number",
        "archive_v3_registry_kms_version",
        "archive_v3_witness_project_id",
        "archive_v3_witness_project_number",
        "archive_v3_witness_database_id",
        "archive_v3_archive_binding_commitment",
    ):
        del data[key]
    return data


class ReleaseMetadataTests(unittest.TestCase):
    def verify(
        self,
        data: dict[str, object],
        *,
        tag: str = "v1.2.3",
        probe_config: dict[str, object] | None = None,
        shadow_runtime_config: dict[str, object] | None = None,
    ) -> subprocess.CompletedProcess[str]:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "enclave-release.json"
            path.write_text(json.dumps(data), encoding="utf-8")
            config_path = ROOT / "config" / "archive-witness-probe.json"
            if probe_config is not None:
                config_path = Path(directory) / "archive-witness-probe.json"
                config_path.write_text(json.dumps(probe_config), encoding="utf-8")
            shadow_runtime_config_path = (
                Path(directory) / "archive-v3-shadow-runtime.json"
            )
            if shadow_runtime_config is None:
                shadow_runtime_config = {
                    "schema_version": 2,
                    "mode": "off",
                    "archive_bucket": "",
                    "archive_gcs_project_number": "",
                    "registry_kms_version": "",
                    "witness_project_id": "",
                    "witness_project_number": "",
                    "witness_database_id": "",
                    "archive_binding_commitment": "",
                }
            shadow_runtime_config_path.write_text(
                json.dumps(shadow_runtime_config), encoding="utf-8"
            )
            return subprocess.run(
                [
                    "python3",
                    str(VERIFIER),
                    str(path),
                    "--repository",
                    "owner/repository",
                    "--tag",
                    tag,
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
                    "--archive-witness-probe-config",
                    str(config_path),
                    "--archive-v3-shadow-runtime-config",
                    str(shadow_runtime_config_path),
                ],
                cwd=ROOT,
                text=True,
                capture_output=True,
                check=False,
            )

    def test_valid_current_manifest_is_eligible(self) -> None:
        completed = self.verify(manifest())
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(json.loads(completed.stdout), manifest())

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

    def test_mode_namespace_claim_is_exact_and_all_or_nothing(self) -> None:
        data = manifest()
        data["archive_witness_project_id"] = "project-1"
        completed = self.verify(data)
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("does not match", completed.stderr)

    def test_exact_probe_prerelease_matches_the_shared_checked_config(self) -> None:
        tag = "v1.2.3-witness-probe.1"
        data = manifest()
        data["source_ref"] = tag
        data["release_url"] = "https://github.com/owner/repository/releases/tag/" + tag
        data.update({
            "archive_witness_shadow_mode": "probe-v1",
            "archive_witness_project_id": "project-1",
            "archive_witness_project_number": "123456789",
            "archive_witness_database_id": "witness-db",
        })
        probe = {
            "schema_version": 1,
            "mode": "probe-v1",
            "project_id": "project-1",
            "project_number": "123456789",
            "database_id": "witness-db",
        }
        completed = self.verify(data, tag=tag, probe_config=probe)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        verified = json.loads(completed.stdout)
        self.assertEqual(verified["archive_witness_shadow_mode"], "probe-v1")
        self.assertEqual(verified["archive_witness_project_id"], "project-1")
        self.assertEqual(verified["archive_witness_project_number"], "123456789")
        self.assertEqual(verified["archive_witness_database_id"], "witness-db")

        data["source_ref"] = "v1.2.3"
        data["release_url"] = "https://github.com/owner/repository/releases/tag/v1.2.3"
        completed = self.verify(data, tag="v1.2.3", probe_config=probe)
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("exact vX.Y.Z-witness-probe.N", completed.stderr)

        data = manifest()
        data.update({
            "archive_witness_shadow_mode": "probe-v1",
            "archive_witness_project_id": "project-1",
            "archive_witness_project_number": "123456789",
            "archive_witness_database_id": "witness-db",
        })
        completed = self.verify(data)
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("does not match", completed.stderr)

    def test_shadow_runtime_claim_is_exact_and_bound_to_shared_config(self) -> None:
        for field, value in (
            ("archive_v3_shadow_runtime_mode", "single-archive-wal-v1"),
            ("archive_v3_archive_bucket", "archive-bucket"),
            ("archive_v3_archive_gcs_project_number", "123456789"),
            ("archive_v3_registry_kms_version", "7"),
            ("archive_v3_witness_project_id", "project-1"),
            ("archive_v3_witness_project_number", "987654321"),
            ("archive_v3_witness_database_id", "witness-db"),
            ("archive_v3_archive_binding_commitment", "1" * 64),
        ):
            with self.subTest(field=field):
                data = manifest()
                data[field] = value
                completed = self.verify(data)
                self.assertNotEqual(completed.returncode, 0)
                self.assertIn("shadow-runtime claim does not match", completed.stderr)

        active_config = {
            "schema_version": 2,
            "mode": "single-archive-wal-v1",
            "archive_bucket": "archive-bucket-1",
            "archive_gcs_project_number": "123456789",
            "registry_kms_version": "7",
            "witness_project_id": "project-1",
            "witness_project_number": "987654321",
            "witness_database_id": "witness-db",
            "archive_binding_commitment": "1" * 64,
        }
        tag = "v1.2.3-archive-v3-wal.1"
        data = manifest()
        data["source_ref"] = tag
        data["release_url"] = "https://github.com/owner/repository/releases/tag/" + tag
        data.update(
            {
                "archive_v3_shadow_runtime_mode": "single-archive-wal-v1",
                "archive_v3_archive_bucket": "archive-bucket-1",
                "archive_v3_archive_gcs_project_number": "123456789",
                "archive_v3_registry_kms_version": "7",
                "archive_v3_witness_project_id": "project-1",
                "archive_v3_witness_project_number": "987654321",
                "archive_v3_witness_database_id": "witness-db",
                "archive_v3_archive_binding_commitment": "1" * 64,
            }
        )
        completed = self.verify(data, tag=tag, shadow_runtime_config=active_config)
        self.assertEqual(completed.returncode, 0, completed.stderr)

        substituted = dict(data)
        substituted["archive_v3_archive_binding_commitment"] = "2" * 64
        completed = self.verify(
            substituted, tag=tag, shadow_runtime_config=active_config
        )
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("shadow-runtime claim does not match", completed.stderr)

        completed = self.verify(manifest(), shadow_runtime_config=active_config)
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("exact vX.Y.Z-archive-v3-wal.N", completed.stderr)

    def test_schema_v7_manifest_is_ineligible_for_promotion(self) -> None:
        data = manifest()
        data["schema_version"] = 7
        completed = self.verify(data)
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("schema_version must be 9", completed.stderr)

    def test_schema_v8_manifest_remains_ineligible_for_promotion(self) -> None:
        data = manifest()
        data["schema_version"] = 8
        completed = self.verify(data)
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("schema_version must be 9", completed.stderr)

        exact_legacy = manifest()
        exact_legacy["schema_version"] = 8
        del exact_legacy["archive_v3_archive_binding_commitment"]
        completed = self.verify(exact_legacy)
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("missing or unexpected fields", completed.stderr)


if __name__ == "__main__":
    unittest.main()
