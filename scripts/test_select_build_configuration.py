#!/usr/bin/env python3
"""Contracts for the PostgreSQL-only enclave image profile selector."""

from __future__ import annotations

import base64
import hashlib
import os
from pathlib import Path
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
SELECTOR = ROOT / "scripts" / "select_build_configuration.py"
SCHEMA_FINALIZATION_PUBLIC_KEY_DER = bytes.fromhex(
    "302a300506032b6570032100"
    "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
)
EVALUATION_SCHEMA_FINALIZATION_PUBLIC_KEY_DER = bytes.fromhex(
    "302a300506032b6570032100"
    "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c"
)

CONFIGURATION = {
    "ENCLAVE_KMS_PROJECT": "kioku-joerodriguez",
    "ENCLAVE_KMS_LOCATION": "us-central1",
    "ENCLAVE_KMS_KEY_RING": "kioku-eval",
    "ENCLAVE_KMS_KEY": "eval-kek",
    "ENCLAVE_GCS_MEDIA_BUCKET": "kioku-eval-media",
    "ENCLAVE_RUN_SA_EMAIL": "kioku-eval@kioku-joerodriguez.iam.gserviceaccount.com",
    "ENCLAVE_AUDIENCE": "https://eval-api.kiokuu.com",
    "ENCLAVE_ATTEST_STS_AUDIENCE": "//iam.googleapis.com/projects/123456789/locations/global/workloadIdentityPools/enclave-attest/providers/attest",
    "GOOGLE_DESKTOP_CLIENT_ID": "desktop.apps.googleusercontent.com",
    "GOOGLE_IOS_CLIENT_ID": "ios.apps.googleusercontent.com",
    "GOOGLE_WEB_CLIENT_ID": "web.apps.googleusercontent.com",
    "ADMIN_USER_IDS": "12345678-1234-1234-1234-123456789abc",
    "SIGNUP_LIMIT_PER_DAY": "25",
    "BASE_URL": "https://eval-api.kiokuu.com",
    "WEB_ORIGIN": "https://kiokuu.com",
    "BILLING_SERVICE_URL": "https://billing.kiokuu.com",
    "BILLING_SERVICE_AUDIENCE": "https://billing.kiokuu.com",
    "BILLING_ENFORCEMENT_MODE": "shadow",
    "REVIEWER_AUTH_API_KEY": "abcdefghijklmnopqrstuvwxyz123456",
    "REVIEWER_AUTH_UID": "reviewer-uid",
    "REVIEWER_AUTH_EMAIL": "reviewer@example.com",
    "VERTEX_PROJECT": "kioku-joerodriguez",
    "VERTEX_LOCATION": "global",
    "VERTEX_MODEL": "gemini-3.5-flash",
    "SCHEMA_FINALIZATION_PUBLIC_KEY_DER_BASE64": base64.b64encode(
        SCHEMA_FINALIZATION_PUBLIC_KEY_DER
    ).decode("ascii"),
    "SCHEMA_FINALIZATION_PUBLIC_KEY_SHA256": hashlib.sha256(
        SCHEMA_FINALIZATION_PUBLIC_KEY_DER
    ).hexdigest(),
}

APPLE_CONFIGURATION = {
    "APPLE_TEAM_ID": "ABCDE12345",
    "APPLE_KEY_ID": "FGHIJ67890",
    "APPLE_IOS_CLIENT_ID": "com.kioku.ios",
    "APPLE_MACOS_CLIENT_ID": "com.kiokuu.app",
    "APPLE_WEB_CLIENT_ID": "com.kiokuu.web",
}

APNS_CONFIGURATION = {
    "APNS_TEAM_ID": "ABCDE12345",
    "APNS_PRODUCTION_KEY_ID": "PUSHPRD123",
    "APNS_SANDBOX_KEY_ID": "PUSHSBX123",
}


def environment() -> dict[str, str]:
    result = {
        "PATH": os.environ.get("PATH", ""),
        "PROJECT_ID": "kioku-joerodriguez",
        "REGION": "us-central1",
        "AR_REPOSITORY": "kioku",
        "IMAGE_NAME": "kioku-enclave",
    }
    for prefix in ("PRODUCTION", "EVALUATION"):
        for key, value in CONFIGURATION.items():
            result[f"{prefix}_{key}"] = value
    result["PRODUCTION_ENCLAVE_KMS_KEY_RING"] = "kioku-production"
    result["PRODUCTION_ENCLAVE_KMS_KEY"] = "production-kek"
    result["PRODUCTION_ENCLAVE_GCS_MEDIA_BUCKET"] = "kioku-production-media"
    result["EVALUATION_SCHEMA_FINALIZATION_PUBLIC_KEY_DER_BASE64"] = base64.b64encode(
        EVALUATION_SCHEMA_FINALIZATION_PUBLIC_KEY_DER
    ).decode("ascii")
    result["EVALUATION_SCHEMA_FINALIZATION_PUBLIC_KEY_SHA256"] = hashlib.sha256(
        EVALUATION_SCHEMA_FINALIZATION_PUBLIC_KEY_DER
    ).hexdigest()
    for key, value in APNS_CONFIGURATION.items():
        result[f"PRODUCTION_{key}"] = value
    return result


class SelectorTests(unittest.TestCase):
    def run_selector(
        self, profile: str, values: dict[str, str], *, source_ref: str = "main"
    ) -> tuple[subprocess.CompletedProcess[str], str, int | None]:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "selected.env"
            completed = subprocess.run(
                [
                    "python3",
                    str(SELECTOR),
                    "--profile",
                    profile,
                    "--source-ref",
                    source_ref,
                    "--output-env",
                    str(output),
                ],
                cwd=ROOT,
                env=values,
                text=True,
                capture_output=True,
                check=False,
            )
            content = output.read_text(encoding="utf-8") if output.exists() else ""
            mode = output.stat().st_mode & 0o777 if output.exists() else None
            return completed, content, mode

    def test_profiles_are_isolated_and_postgres_invariants_are_fixed(self) -> None:
        values = environment()
        selected, content, mode = self.run_selector("production", values)
        self.assertEqual(selected.returncode, 0, selected.stderr)
        self.assertEqual(mode, 0o600)
        self.assertIn("KIOKU_BUILD_PROFILE=production\n", content)
        self.assertIn("ENCLAVE_GCS_MEDIA_BUCKET=kioku-production-media\n", content)
        self.assertNotIn("POSTGRES_SCHEMA_MODE", content)
        self.assertIn("POSTGRES_MAX_CONNECTIONS=12\n", content)
        self.assertIn("HEALTH_PORT=8081\n", content)
        self.assertIn("DRAIN_TIMEOUT_SECONDS=105\n", content)
        self.assertIn("ENCLAVE_TLS=1\n", content)
        self.assertIn("VERTEX_RECONCILIATION_MODEL=\n", content)
        self.assertIn("MEMORY_RECONCILIATION_WRITER_ENABLED=\n", content)
        self.assertIn("SCHEMA_FINALIZATION_PUBLIC_KEY_DER_BASE64=", content)
        self.assertIn("SCHEMA_FINALIZATION_PUBLIC_KEY_SHA256=", content)
        for obsolete in (
            "PERSISTENCE_BACKEND",
            "GCS_BUCKET",
            "GCS_LEGACY_MEDIA_BUCKET",
            "ARCHIVE_V3",
            "ARCHIVE_WITNESS",
            "GENESIS_WAL",
        ):
            self.assertNotIn(obsolete, content)

        evaluated, evaluation_content, _ = self.run_selector("evaluation", values)
        self.assertEqual(evaluated.returncode, 0, evaluated.stderr)
        self.assertIn("ENCLAVE_GCS_MEDIA_BUCKET=kioku-eval-media\n", evaluation_content)
        self.assertNotIn("kioku-production-media", evaluation_content)
        self.assertIn(
            "SCHEMA_FINALIZATION_PUBLIC_KEY_DER_BASE64="
            + base64.b64encode(EVALUATION_SCHEMA_FINALIZATION_PUBLIC_KEY_DER).decode("ascii")
            + "\n",
            evaluation_content,
        )
        self.assertNotIn(
            base64.b64encode(SCHEMA_FINALIZATION_PUBLIC_KEY_DER).decode("ascii"),
            evaluation_content,
        )

    def test_missing_value_never_falls_back_between_profiles(self) -> None:
        values = environment()
        del values["EVALUATION_ENCLAVE_GCS_MEDIA_BUCKET"]
        completed, content, _ = self.run_selector("evaluation", values)
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("EVALUATION_ENCLAVE_GCS_MEDIA_BUCKET", completed.stderr)
        self.assertEqual(content, "")

    def test_reconciliation_settings_are_optional_and_fail_closed(self) -> None:
        values = environment()
        values["PRODUCTION_VERTEX_RECONCILIATION_MODEL"] = "gemini-strong:preview"
        values["PRODUCTION_MEMORY_RECONCILIATION_WRITER_ENABLED"] = "false"
        accepted, content, _ = self.run_selector("production", values)
        self.assertEqual(accepted.returncode, 0, accepted.stderr)
        self.assertIn(
            "VERTEX_RECONCILIATION_MODEL=gemini-strong:preview\n", content
        )
        self.assertIn("MEMORY_RECONCILIATION_WRITER_ENABLED=false\n", content)

        for key, value in (
            ("PRODUCTION_VERTEX_RECONCILIATION_MODEL", "bad model"),
            ("PRODUCTION_MEMORY_RECONCILIATION_WRITER_ENABLED", "true"),
            ("PRODUCTION_MEMORY_RECONCILIATION_WRITER_ENABLED", "yes"),
        ):
            with self.subTest(key=key):
                rejected_values = environment()
                rejected_values[key] = value
                rejected, rejected_content, _ = self.run_selector(
                    "production", rejected_values
                )
                self.assertNotEqual(rejected.returncode, 0)
                self.assertEqual(rejected_content, "")

    def test_schema_finalization_anchor_is_required_and_fingerprint_bound(self) -> None:
        values = environment()
        del values["PRODUCTION_SCHEMA_FINALIZATION_PUBLIC_KEY_DER_BASE64"]
        missing, content, _ = self.run_selector("production", values)
        self.assertNotEqual(missing.returncode, 0)
        self.assertEqual(content, "")

        for key, value in (
            ("PRODUCTION_SCHEMA_FINALIZATION_PUBLIC_KEY_DER_BASE64", "not-base64"),
            ("PRODUCTION_SCHEMA_FINALIZATION_PUBLIC_KEY_SHA256", "0" * 64),
        ):
            with self.subTest(key=key):
                mismatched = environment()
                mismatched[key] = value
                rejected, content, _ = self.run_selector("production", mismatched)
                self.assertNotEqual(rejected.returncode, 0)
                self.assertEqual(content, "")

    def test_apple_is_optional_atomic_and_production_apns_is_required(self) -> None:
        values = environment()
        accepted, _, _ = self.run_selector("production", values)
        self.assertEqual(accepted.returncode, 0, accepted.stderr)

        values["PRODUCTION_APPLE_TEAM_ID"] = APPLE_CONFIGURATION["APPLE_TEAM_ID"]
        incomplete, _, _ = self.run_selector("production", values)
        self.assertNotEqual(incomplete.returncode, 0)
        self.assertIn("incomplete optional", incomplete.stderr)
        for key, value in APPLE_CONFIGURATION.items():
            values[f"PRODUCTION_{key}"] = value
        complete, _, _ = self.run_selector("production", values)
        self.assertEqual(complete.returncode, 0, complete.stderr)

        del values["PRODUCTION_APNS_SANDBOX_KEY_ID"]
        missing_apns, _, _ = self.run_selector("production", values)
        self.assertNotEqual(missing_apns.returncode, 0)

    def test_invalid_security_values_fail_before_output(self) -> None:
        cases = (
            ("PRODUCTION_ENCLAVE_GCS_MEDIA_BUCKET", "Invalid Bucket"),
            ("PRODUCTION_BILLING_SERVICE_AUDIENCE", "https://other.example"),
            ("PRODUCTION_SIGNUP_LIMIT_PER_DAY", "01"),
            ("PRODUCTION_ENCLAVE_RUN_SA_EMAIL", "attacker@example.com"),
        )
        for key, value in cases:
            with self.subTest(key=key):
                values = environment()
                values[key] = value
                completed, content, _ = self.run_selector("production", values)
                self.assertNotEqual(completed.returncode, 0)
                self.assertEqual(content, "")

    def test_release_source_ref_must_be_canonical(self) -> None:
        rejected, _, _ = self.run_selector(
            "production", environment(), source_ref="v01.2.3"
        )
        self.assertNotEqual(rejected.returncode, 0)
        accepted, _, _ = self.run_selector(
            "production", environment(), source_ref="refs/tags/v1.2.3"
        )
        self.assertEqual(accepted.returncode, 0, accepted.stderr)


if __name__ == "__main__":
    unittest.main()
