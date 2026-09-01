#!/usr/bin/env python3
"""Adversarial contracts for PostgreSQL-only release metadata."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import verify_release_metadata as verifier  # noqa: E402

TAG = "v1.2.3"
COMMIT = "a" * 40
IMAGE_REPOSITORY = "us-central1-docker.pkg.dev/kioku-joerodriguez/kioku/kioku-enclave"
DIGEST = "sha256:" + "b" * 64


def metadata() -> dict[str, object]:
    return {
        "schema_version": 13,
        "source_repository": "https://github.com/owner/repository",
        "source_ref": TAG,
        "source_commit": COMMIT,
        "image_uri": f"{IMAGE_REPOSITORY}:{TAG}",
        "image_digest_uri": f"{IMAGE_REPOSITORY}@{DIGEST}",
        "image_digest": DIGEST,
        "release_url": f"https://github.com/owner/repository/releases/tag/{TAG}",
        "build_profile": "production",
        "voice_quality_gate": "owner_only_unvalidated",
        "billing_enforcement_mode": "shadow",
        "vertex_reconciliation_model": "gemini-reconciliation-v1",
        "vertex_location": "us-central1",
        "reconciliation_producer_contract_sha256": "sha256:" + "c" * 64,
        "gcs_media_bucket": "kioku-production-media",
        "kms_project": "kioku-joerodriguez",
        "kms_location": "us-central1",
        "kms_key_ring": "kioku-production",
        "kms_key": "production-kek",
        "persistence_authority": "postgres",
        "postgres_schema_verification": "required",
        "postgres_max_connections": "12",
        "health_port": "8081",
        "drain_timeout_seconds": "105",
        "tls_mode": "shared-secret-manager",
        "quota_vertex_output_tokens_per_day": "2621440",
        "quota_vertex_output_reset_policy": "per-account-utc-calendar-day",
        "quota_vertex_output_class_shares": (
            "non-borrowing-percent:audio=50,screen=25,derived=25"
        ),
    }


def arguments() -> argparse.Namespace:
    return argparse.Namespace(
        repository="owner/repository",
        tag=TAG,
        commit=COMMIT,
        image_repository=IMAGE_REPOSITORY,
        expected_gcs_media_bucket="kioku-production-media",
        expected_kms_project="kioku-joerodriguez",
        expected_kms_location="us-central1",
        expected_kms_key_ring="kioku-production",
        expected_kms_key="production-kek",
        expected_vertex_reconciliation_model="gemini-reconciliation-v1",
        expected_vertex_location="us-central1",
        expected_reconciliation_producer_contract_sha256="sha256:" + "c" * 64,
        expected_quota_vertex_output_tokens_per_day="2621440",
    )


class ReleaseMetadataTests(unittest.TestCase):
    def test_current_manifest_is_eligible_and_canonical(self) -> None:
        document = metadata()
        verifier.validate(arguments(), document)
        encoded = (
            json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n"
        ).encode()
        self.assertEqual(verifier.parse_metadata_bytes(encoded), document)

    def test_legacy_schemas_and_authority_fields_are_ineligible(self) -> None:
        for schema in (4, 7, 8, 9, 10, 11, 12):
            document = metadata()
            document["schema_version"] = schema
            with self.assertRaisesRegex(SystemExit, "schema_version must be 13"):
                verifier.validate_shape(document)

    def test_frozen_v0_9_16_state_shape_cannot_follow_current_schema_growth(self) -> None:
        document = metadata()
        document["schema_version"] = 11
        document["source_ref"] = "v0.9.16"
        document["image_uri"] = f"{IMAGE_REPOSITORY}:v0.9.16"
        document["release_url"] = (
            "https://github.com/owner/repository/releases/tag/v0.9.16"
        )
        for field in (
            "vertex_reconciliation_model",
            "vertex_location",
            "reconciliation_producer_contract_sha256",
            "quota_vertex_output_tokens_per_day",
            "quota_vertex_output_reset_policy",
            "quota_vertex_output_class_shares",
        ):
            document.pop(field)
        encoded = (
            json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n"
        ).encode()
        parsed = verifier.parse_frozen_v0_9_16_metadata_bytes(encoded)
        frozen_arguments = arguments()
        frozen_arguments.tag = "v0.9.16"
        verifier.validate_frozen_v0_9_16_state(frozen_arguments, parsed)

        document["future_schema_field"] = "must-not-expand-frozen-v11"
        changed = (
            json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n"
        ).encode()
        with self.assertRaisesRegex(SystemExit, "missing or unexpected"):
            verifier.parse_frozen_v0_9_16_metadata_bytes(changed)
        for extra in (
            "gcs_bucket",
            "gcs_legacy_media_bucket",
            "archive_v3_shadow_runtime_mode",
            "archive_witness_database_id",
        ):
            document = metadata()
            document[extra] = "obsolete"
            with self.assertRaisesRegex(SystemExit, "missing or unexpected"):
                verifier.validate_shape(document)

    def test_frozen_v0_9_18_schema_twelve_is_exact_state_only(self) -> None:
        document = metadata()
        document["schema_version"] = 12
        document["source_ref"] = "v0.9.18"
        document["image_uri"] = f"{IMAGE_REPOSITORY}:v0.9.18"
        document["release_url"] = (
            "https://github.com/owner/repository/releases/tag/v0.9.18"
        )
        for field in (
            "quota_vertex_output_tokens_per_day",
            "quota_vertex_output_reset_policy",
            "quota_vertex_output_class_shares",
        ):
            document.pop(field)
        encoded = (
            json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n"
        ).encode()
        parsed = verifier.parse_frozen_v0_9_18_metadata_bytes(encoded)
        frozen_arguments = arguments()
        frozen_arguments.tag = "v0.9.18"
        verifier.validate_frozen_v0_9_18_state(frozen_arguments, parsed)

        mixed = dict(document)
        mixed["quota_vertex_output_tokens_per_day"] = "2621440"
        with self.assertRaisesRegex(SystemExit, "missing or unexpected"):
            verifier.parse_frozen_v0_9_18_metadata_bytes(
                (json.dumps(mixed, sort_keys=True, separators=(",", ":")) + "\n").encode()
            )
        with self.assertRaisesRegex(SystemExit, "schema_version must be 13"):
            verifier.validate_shape(document)

    def test_source_image_media_and_kms_bindings_are_exact(self) -> None:
        mutations = {
            "source_commit": "c" * 40,
            "image_digest": "sha256:" + "d" * 64,
            "image_uri": f"{IMAGE_REPOSITORY}:v9.9.9",
            "gcs_media_bucket": "other-media",
            "kms_project": "other-project",
            "kms_key": "other-key",
        }
        for field, value in mutations.items():
            with self.subTest(field=field):
                document = metadata()
                document[field] = value
                with self.assertRaises(SystemExit):
                    verifier.validate(arguments(), document)

    def test_serving_invariants_cannot_be_relaxed(self) -> None:
        for field, value in (
            ("persistence_authority", "sqlite"),
            ("postgres_schema_verification", "disabled"),
            ("postgres_max_connections", "100"),
            ("health_port", "8080"),
            ("drain_timeout_seconds", "0"),
            ("tls_mode", "per-process-acme"),
        ):
            with self.subTest(field=field):
                document = metadata()
                document[field] = value
                with self.assertRaisesRegex(SystemExit, "reviewed serving invariant"):
                    verifier.validate(arguments(), document)

    def test_vertex_quota_metadata_is_exact_and_policy_bound(self) -> None:
        for field, value in (
            ("quota_vertex_output_tokens_per_day", "1310720"),
            ("quota_vertex_output_tokens_per_day", 2621440),
            ("quota_vertex_output_reset_policy", "rolling-24-hours"),
            ("quota_vertex_output_class_shares", "borrowing"),
        ):
            with self.subTest(field=field, value=value):
                document = metadata()
                document[field] = value
                with self.assertRaises(SystemExit):
                    verifier.validate(arguments(), document)

        unreviewed_arguments = arguments()
        unreviewed_arguments.expected_quota_vertex_output_tokens_per_day = "2621441"
        with self.assertRaises(SystemExit):
            verifier.validate(unreviewed_arguments, metadata())

    def test_reconciliation_image_identity_is_exact_and_typed(self) -> None:
        mutations = {
            "vertex_reconciliation_model": "",
            "vertex_location": "US-CENTRAL1",
            "reconciliation_producer_contract_sha256": "sha256:" + "D" * 64,
        }
        for field, value in mutations.items():
            with self.subTest(field=field):
                document = metadata()
                document[field] = value
                with self.assertRaises(SystemExit):
                    verifier.validate(arguments(), document)

        document = metadata()
        document["memory_reconciliation_writer_enabled"] = False
        with self.assertRaisesRegex(SystemExit, "missing or unexpected"):
            verifier.validate_shape(document)

    def test_duplicate_noncanonical_and_control_string_documents_fail(self) -> None:
        document = metadata()
        canonical = json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n"
        with self.assertRaisesRegex(SystemExit, "canonical"):
            verifier.parse_metadata_bytes(canonical.replace("\n", "", 1).encode())
        duplicated = canonical.replace(
            '"build_profile":"production",',
            '"build_profile":"production","build_profile":"production",',
        )
        with self.assertRaisesRegex(SystemExit, "duplicate"):
            verifier.parse_metadata_bytes(duplicated.encode())
        document["billing_enforcement_mode"] = "shadow\nunsafe"
        encoded = (
            json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n"
        ).encode()
        with self.assertRaisesRegex(SystemExit, "control"):
            verifier.parse_metadata_bytes(encoded)


if __name__ == "__main__":
    unittest.main()
