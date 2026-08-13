#!/usr/bin/env python3
"""Adversarial contracts for the exact-off shadow-runtime image profile."""

from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest

from archive_v3_shadow_runtime_config import (
    OFF,
    ShadowRuntimeConfigError,
    load_shadow_runtime_config,
)


ROOT = Path(__file__).resolve().parents[1]


class ArchiveV3ShadowRuntimeConfigTests(unittest.TestCase):
    def load(self, value: object) -> object:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "shadow-runtime.json"
            path.write_text(json.dumps(value), encoding="utf-8")
            return load_shadow_runtime_config(path)

    @staticmethod
    def off() -> dict[str, object]:
        return {
            "schema_version": 1,
            "mode": "off",
            "archive_bucket": "",
            "archive_gcs_project_number": "",
            "registry_kms_version": "",
            "witness_project_id": "",
            "witness_project_number": "",
            "witness_database_id": "",
        }

    def test_checked_in_profile_is_exactly_off_and_empty(self) -> None:
        config = load_shadow_runtime_config(
            ROOT / "config" / "archive-v3-shadow-runtime.json"
        )
        self.assertEqual(config, OFF)
        self.assertEqual(
            config.as_environment(),
            {
                "ARCHIVE_V3_SHADOW_RUNTIME_MODE": "off",
                "ARCHIVE_V3_ARCHIVE_BUCKET": "",
                "ARCHIVE_V3_ARCHIVE_GCS_PROJECT_NUMBER": "",
                "ARCHIVE_V3_REGISTRY_KMS_VERSION": "",
                "ARCHIVE_V3_WITNESS_PROJECT_ID": "",
                "ARCHIVE_V3_WITNESS_PROJECT_NUMBER": "",
                "ARCHIVE_V3_WITNESS_DATABASE_ID": "",
            },
        )

    def test_every_non_off_or_nonempty_value_is_rejected(self) -> None:
        for key, value in (
            ("mode", "shadow-v1"),
            ("archive_bucket", "archive-bucket"),
            ("archive_gcs_project_number", "123456789"),
            ("registry_kms_version", "7"),
            ("witness_project_id", "project-1"),
            ("witness_project_number", "987654321"),
            ("witness_database_id", "witness-db"),
        ):
            with self.subTest(key=key):
                data = self.off()
                data[key] = value
                with self.assertRaises(ShadowRuntimeConfigError):
                    self.load(data)

    def test_schema_order_type_duplicates_controls_and_size_fail_closed(self) -> None:
        cases = []
        extra = self.off()
        extra["unexpected"] = ""
        cases.append(extra)
        reordered = {"mode": "off", "schema_version": 1}
        reordered.update({key: value for key, value in self.off().items() if key not in reordered})
        cases.append(reordered)
        wrong_version = self.off()
        wrong_version["schema_version"] = 2
        cases.append(wrong_version)
        wrong_type = self.off()
        wrong_type["mode"] = False
        cases.append(wrong_type)
        controlled = self.off()
        controlled["archive_bucket"] = "bad\nvalue"
        cases.append(controlled)
        for value in cases:
            with self.subTest(value=value):
                with self.assertRaises(ShadowRuntimeConfigError):
                    self.load(value)

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "shadow-runtime.json"
            path.write_text(
                '{"schema_version":1,"mode":"off","mode":"off",'
                '"archive_bucket":"","archive_gcs_project_number":"",'
                '"registry_kms_version":"","witness_project_id":"",'
                '"witness_project_number":"","witness_database_id":""}',
                encoding="utf-8",
            )
            with self.assertRaises(ShadowRuntimeConfigError):
                load_shadow_runtime_config(path)
            path.write_bytes(b" " * 4097)
            with self.assertRaises(ShadowRuntimeConfigError):
                load_shadow_runtime_config(path)


if __name__ == "__main__":
    unittest.main()
