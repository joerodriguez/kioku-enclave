#!/usr/bin/env python3
"""Adversarial contracts for the sealed single-archive runtime profile."""

from __future__ import annotations

import json
from pathlib import Path
import subprocess
import tempfile
import unittest

from archive_v3_shadow_runtime_config import (
    OFF,
    ShadowRuntimeConfigError,
    load_shadow_runtime_config,
    select_shadow_runtime_config,
)


ROOT = Path(__file__).resolve().parents[1]
COMMITMENT = "1" * 64
DOCKER_VALIDATOR = ROOT / "scripts" / "validate_archive_v3_shadow_runtime_environment.sh"
INVALID_ACTIVE_VALUES = {
    "archive_bucket": (
        "12",
        "192.168.1.1",
        "goog-shadow",
        "contains-google-name",
        "g00gle-shadow",
        "A-bucket",
        "bad\nbucket",
        "a..b",
        "a" * 64,
        "a." + "b" * 64,
    ),
    "archive_gcs_project_number": (
        "0",
        "01",
        "18446744073709551616",
        "123456789012345678901",
        "project",
    ),
    "registry_kms_version": (
        "0",
        "01",
        "18446744073709551616",
        "123456789012345678901",
    ),
    "witness_project_id": ("short", "Uppercase-1", "project_1", "p" * 31),
    "witness_project_number": (
        "0",
        "01",
        "18446744073709551616",
        "project",
    ),
    "witness_database_id": (
        "abc",
        "(default)",
        "12345678-1234-1234-1234-123456789abc",
        "abcdefab-cdef-abcd-abcd-abcdefabcdef",
        "Uppercase-db",
        "d" * 64,
    ),
    "archive_binding_commitment": (
        "0" * 64,
        "A" * 64,
        "1" * 63,
        "1" * 63 + "g",
    ),
}


class ArchiveV3ShadowRuntimeConfigTests(unittest.TestCase):
    def load(self, value: object) -> object:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "shadow-runtime.json"
            path.write_text(json.dumps(value), encoding="utf-8")
            return load_shadow_runtime_config(path)

    def docker_validate(
        self, value: dict[str, object]
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [
                "sh",
                str(DOCKER_VALIDATOR),
                *(
                    str(value[key])
                    for key in (
                        "mode",
                        "archive_bucket",
                        "archive_gcs_project_number",
                        "registry_kms_version",
                        "witness_project_id",
                        "witness_project_number",
                        "witness_database_id",
                        "archive_binding_commitment",
                    )
                ),
            ],
            check=False,
            capture_output=True,
            text=True,
        )

    @staticmethod
    def off() -> dict[str, object]:
        return {
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

    @staticmethod
    def active() -> dict[str, object]:
        return {
            "schema_version": 2,
            "mode": "single-archive-wal-v1",
            "archive_bucket": "archive-bucket-1",
            "archive_gcs_project_number": "123456789",
            "registry_kms_version": "7",
            "witness_project_id": "project-1",
            "witness_project_number": "987654321",
            "witness_database_id": "witness-db",
            "archive_binding_commitment": COMMITMENT,
        }

    def test_checked_in_profile_is_schema_two_exact_genesis_tuple(self) -> None:
        config = load_shadow_runtime_config(
            ROOT / "config" / "archive-v3-shadow-runtime.json"
        )
        self.assertEqual(
            config.as_environment(),
            {
                "ARCHIVE_V3_SHADOW_RUNTIME_MODE": "single-archive-wal-v1",
                "ARCHIVE_V3_ARCHIVE_BUCKET": "kioku-joerodriguez-archive-v3",
                "ARCHIVE_V3_ARCHIVE_GCS_PROJECT_NUMBER": "640329636251",
                "ARCHIVE_V3_REGISTRY_KMS_VERSION": "1",
                "ARCHIVE_V3_WITNESS_PROJECT_ID": "kioku-joerodriguez",
                "ARCHIVE_V3_WITNESS_PROJECT_NUMBER": "640329636251",
                "ARCHIVE_V3_WITNESS_DATABASE_ID": "archive-v3-witness",
                "ARCHIVE_V3_ARCHIVE_BINDING_COMMITMENT": (
                    "b541d598e3442fdcf516c0af34a69907"
                    "b44c9767d86b8277cb08d12eb0f1fe48"
                ),
            },
        )

    def test_active_profile_roundtrips_the_exact_eight_element_claim(self) -> None:
        config = self.load(self.active())
        self.assertEqual(
            config.as_claim(),
            (
                "single-archive-wal-v1",
                "archive-bucket-1",
                "123456789",
                "7",
                "project-1",
                "987654321",
                "witness-db",
                COMMITMENT,
            ),
        )

    def test_off_is_all_empty_and_active_is_all_complete(self) -> None:
        for key in tuple(self.off())[2:]:
            data = self.off()
            data[key] = "x"
            with self.subTest(mode="off", key=key), self.assertRaises(
                ShadowRuntimeConfigError
            ):
                self.load(data)
        for key in tuple(self.active())[2:]:
            data = self.active()
            data[key] = ""
            with self.subTest(mode="active", key=key), self.assertRaises(
                ShadowRuntimeConfigError
            ):
                self.load(data)

    def test_bucket_numeric_firestore_and_commitment_grammars_match_rust(self) -> None:
        for key, values in INVALID_ACTIVE_VALUES.items():
            for value in values:
                data = self.active()
                data[key] = value
                with self.subTest(key=key, value=value), self.assertRaises(
                    ShadowRuntimeConfigError
                ):
                    self.load(data)

        data = self.active()
        data["archive_bucket"] = ".".join(("a" * 63, "b" * 63, "c" * 63, "d" * 30))
        data["archive_gcs_project_number"] = "18446744073709551615"
        data["registry_kms_version"] = "18446744073709551615"
        data["witness_project_number"] = "18446744073709551615"
        self.load(data)

    def test_direct_docker_validator_has_exact_active_and_off_parity(self) -> None:
        self.assertEqual(self.docker_validate(self.off()).returncode, 0)
        self.assertEqual(self.docker_validate(self.active()).returncode, 0)

        for key, values in INVALID_ACTIVE_VALUES.items():
            for value in values:
                data = self.active()
                data[key] = value
                with self.subTest(key=key, value=value):
                    self.assertNotEqual(self.docker_validate(data).returncode, 0)

        for key in tuple(self.active())[2:]:
            data = self.active()
            data[key] = ""
            with self.subTest(mode="active", missing=key):
                self.assertNotEqual(self.docker_validate(data).returncode, 0)

        for key in tuple(self.off())[2:]:
            data = self.off()
            data[key] = "x"
            with self.subTest(mode="off", key=key):
                self.assertNotEqual(self.docker_validate(data).returncode, 0)

        unknown = self.off()
        unknown["mode"] = "future-runtime"
        self.assertNotEqual(self.docker_validate(unknown).returncode, 0)

        data = self.active()
        data["archive_bucket"] = ".".join(
            ("a" * 63, "b" * 63, "c" * 63, "d" * 30)
        )
        data["archive_gcs_project_number"] = "18446744073709551615"
        data["registry_kms_version"] = "18446744073709551615"
        data["witness_project_number"] = "18446744073709551615"
        self.assertEqual(self.docker_validate(data).returncode, 0)

        for bucket in ("01.2.3.4", "999.999.999.999"):
            data = self.active()
            data["archive_bucket"] = bucket
            with self.subTest(valid_non_ipv4_bucket=bucket):
                self.load(data)
                self.assertEqual(self.docker_validate(data).returncode, 0)

    def test_schema_order_type_duplicates_controls_and_size_fail_closed(self) -> None:
        cases = []
        extra = self.off()
        extra["unexpected"] = ""
        cases.append(extra)
        reordered = {"mode": "off", "schema_version": 2}
        reordered.update({key: value for key, value in self.off().items() if key not in reordered})
        cases.append(reordered)
        wrong_version = self.off()
        wrong_version["schema_version"] = 1
        cases.append(wrong_version)
        wrong_type = self.off()
        wrong_type["mode"] = False
        cases.append(wrong_type)
        controlled = self.active()
        controlled["archive_bucket"] = "bad\nvalue"
        cases.append(controlled)
        for value in cases:
            with self.subTest(value=value), self.assertRaises(ShadowRuntimeConfigError):
                self.load(value)

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "shadow-runtime.json"
            path.write_text(
                '{"schema_version":2,"mode":"off","mode":"off",'
                '"archive_bucket":"","archive_gcs_project_number":"",'
                '"registry_kms_version":"","witness_project_id":"",'
                '"witness_project_number":"","witness_database_id":"",'
                '"archive_binding_commitment":""}',
                encoding="utf-8",
            )
            with self.assertRaises(ShadowRuntimeConfigError):
                load_shadow_runtime_config(path)
            path.write_bytes(b" " * 4097)
            with self.assertRaises(ShadowRuntimeConfigError):
                load_shadow_runtime_config(path)

    def test_selection_is_evaluation_off_main_pretag_and_exact_wal_tag_only(self) -> None:
        active = self.load(self.active())
        self.assertEqual(
            select_shadow_runtime_config(
                active, profile="evaluation", source_ref="v1.2.3-archive-v3-wal.1"
            ),
            OFF,
        )
        self.assertEqual(
            select_shadow_runtime_config(active, profile="production", source_ref="main"),
            OFF,
        )
        self.assertEqual(
            select_shadow_runtime_config(
                active,
                profile="production",
                source_ref="refs/tags/v1.2.3-archive-v3-wal.1",
            ),
            active,
        )
        for ref in (
            "v1.2.3",
            "v1.2.3-rc.1",
            "feature/runtime",
            "v01.2.3-archive-v3-wal.1",
            "v1.02.3-archive-v3-wal.1",
            "v1.2.03-archive-v3-wal.1",
            "v1.2.3-archive-v3-wal.01",
            "v1.2.3-archive-v3-wal.0",
            "v1.2-archive-v3-wal.1",
        ):
            with self.subTest(ref=ref), self.assertRaises(ShadowRuntimeConfigError):
                select_shadow_runtime_config(active, profile="production", source_ref=ref)
        with self.assertRaises(ShadowRuntimeConfigError):
            select_shadow_runtime_config(
                OFF, profile="production", source_ref="v1.2.3-archive-v3-wal.1"
            )


if __name__ == "__main__":
    unittest.main()
