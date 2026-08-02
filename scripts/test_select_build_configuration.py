#!/usr/bin/env python3
"""Contract tests for the fail-closed enclave image profile selector."""

from __future__ import annotations

import os
from pathlib import Path
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
SELECTOR = ROOT / "scripts" / "select_build_configuration.py"
WORKFLOW = ROOT / ".github" / "workflows" / "build.yml"

CONFIGURATION = {
    "ENCLAVE_KMS_PROJECT": "kioku-joerodriguez",
    "ENCLAVE_KMS_LOCATION": "us-central1",
    "ENCLAVE_KMS_KEY_RING": "kioku-eval",
    "ENCLAVE_KMS_KEY": "eval-kek",
    "ENCLAVE_GCS_BUCKET": "kioku-eval-indexes",
    "ENCLAVE_GCS_MEDIA_BUCKET": "kioku-eval-media",
    "ENCLAVE_RUN_SA_EMAIL": "kioku-eval@kioku-joerodriguez.iam.gserviceaccount.com",
    "ENCLAVE_AUDIENCE": "https://eval-api.kiokuu.com",
    "ENCLAVE_ATTEST_STS_AUDIENCE": "//iam.googleapis.com/projects/123456789/locations/global/workloadIdentityPools/enclave-attest/providers/attest",
    "GOOGLE_DESKTOP_CLIENT_ID": "desktop.apps.googleusercontent.com",
    "GOOGLE_IOS_CLIENT_ID": "ios.apps.googleusercontent.com",
    "GOOGLE_WEB_CLIENT_ID": "web.apps.googleusercontent.com",
    "ALLOWED_EMAILS": "owner@example.com",
    "BASE_URL": "https://eval-api.kiokuu.com",
    "WEB_ORIGIN": "https://kiokuu.com",
    "REVIEWER_AUTH_API_KEY": "abcdefghijklmnopqrstuvwxyz123456",
    "REVIEWER_AUTH_UID": "reviewer-uid",
    "REVIEWER_AUTH_EMAIL": "reviewer@example.com",
    "VERTEX_PROJECT": "kioku-joerodriguez",
    "VERTEX_LOCATION": "global",
    "VERTEX_MODEL": "gemini-3.5-flash",
    "ENCLAVE_ACME": "1",
    "ENCLAVE_ACME_DIRECTORY": "https://acme-v02.api.letsencrypt.org/directory",
    "ENCLAVE_ACME_CONTACT": "mailto:owner@example.com",
}


def environment() -> dict[str, str]:
    result = {
        "PATH": os.environ.get("PATH", ""),
        "PROJECT_ID": "kioku-joerodriguez",
        "REGION": "us-central1",
        "AR_REPOSITORY": "kioku",
        "IMAGE_NAME": "kioku-enclave",
        "GCP_WIF_PROVIDER": "projects/123456789/locations/global/workloadIdentityPools/github/providers/actions",
        "GCP_SERVICE_ACCOUNT": "push-images@kioku-joerodriguez.iam.gserviceaccount.com",
    }
    for prefix in ("PRODUCTION", "EVALUATION"):
        for key, value in CONFIGURATION.items():
            result[f"{prefix}_{key}"] = value
    result["PRODUCTION_ENCLAVE_KMS_KEY_RING"] = "kioku-production"
    result["PRODUCTION_ENCLAVE_GCS_BUCKET"] = "kioku-production-indexes"
    return result


class SelectorTests(unittest.TestCase):
    def run_selector(
        self, profile: str, env: dict[str, str]
    ) -> tuple[subprocess.CompletedProcess[str], str]:
        with tempfile.TemporaryDirectory() as directory:
            github_env = Path(directory) / "github-env"
            completed = subprocess.run(
                [
                    "python3",
                    str(SELECTOR),
                    "--profile",
                    profile,
                    "--github-env",
                    str(github_env),
                ],
                cwd=ROOT,
                env=env,
                text=True,
                capture_output=True,
                check=False,
            )
            content = github_env.read_text() if github_env.exists() else ""
            return completed, content

    def test_evaluation_selects_only_evaluation_values(self) -> None:
        completed, content = self.run_selector("evaluation", environment())
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn("KIOKU_BUILD_PROFILE=evaluation\n", content)
        self.assertIn("ENCLAVE_KMS_KEY_RING=kioku-eval\n", content)
        self.assertNotIn("kioku-production", content)
        self.assertEqual(completed.stdout, "")

    def test_production_selects_only_production_values(self) -> None:
        completed, content = self.run_selector("production", environment())
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn("KIOKU_BUILD_PROFILE=production\n", content)
        self.assertIn("ENCLAVE_KMS_KEY_RING=kioku-production\n", content)
        self.assertIn("ENCLAVE_GCS_BUCKET=kioku-production-indexes\n", content)
        self.assertNotIn("ENCLAVE_KMS_KEY_RING=kioku-eval\n", content)

    def test_missing_evaluation_value_never_falls_back_to_production(self) -> None:
        env = environment()
        del env["EVALUATION_ENCLAVE_GCS_BUCKET"]
        completed, content = self.run_selector("evaluation", env)
        self.assertNotEqual(completed.returncode, 0)
        self.assertEqual(content, "")
        self.assertIn("EVALUATION_ENCLAVE_GCS_BUCKET", completed.stderr)
        self.assertNotIn("kioku-production-indexes", completed.stderr)

    def test_every_evaluation_value_is_required(self) -> None:
        for key in CONFIGURATION:
            source_name = f"EVALUATION_{key}"
            with self.subTest(source_name=source_name):
                env = environment()
                del env[source_name]
                completed, content = self.run_selector("evaluation", env)
                self.assertNotEqual(completed.returncode, 0)
                self.assertEqual(content, "")
                self.assertIn(source_name, completed.stderr)

    def test_push_identity_is_required_and_validated_before_output(self) -> None:
        for key, value in (
            ("GCP_WIF_PROVIDER", ""),
            ("GCP_WIF_PROVIDER", "projects/not-a-number/unsafe"),
            ("GCP_SERVICE_ACCOUNT", "owner@example.com"),
        ):
            with self.subTest(key=key, value=value):
                env = environment()
                env[key] = value
                completed, content = self.run_selector("evaluation", env)
                self.assertNotEqual(completed.returncode, 0)
                self.assertEqual(content, "")
                self.assertIn(key, completed.stderr)

    def test_invalid_security_values_fail_before_writing_environment(self) -> None:
        for key, value in (
            ("EVALUATION_ALLOWED_EMAILS", "*"),
            ("EVALUATION_BASE_URL", "http://eval-api.kiokuu.com"),
            ("EVALUATION_ENCLAVE_KMS_KEY", "bad\nINJECTED=value"),
        ):
            with self.subTest(key=key):
                env = environment()
                env[key] = value
                completed, content = self.run_selector("evaluation", env)
                self.assertNotEqual(completed.returncode, 0)
                self.assertEqual(content, "")

    def test_unknown_profile_is_rejected_without_output(self) -> None:
        completed, content = self.run_selector("staging", environment())
        self.assertNotEqual(completed.returncode, 0)
        self.assertEqual(content, "")

    def test_workflow_exposes_only_manual_evaluation_dispatch(self) -> None:
        workflow = WORKFLOW.read_text()
        self.assertIn("build_profile:", workflow)
        self.assertIn("- evaluation", workflow)
        self.assertIn("scripts/select_build_configuration.py", workflow)
        self.assertIn("EVALUATION_ENCLAVE_KMS_PROJECT", workflow)
        self.assertIn('KIOKU_BUILD_PROFILE == "evaluation"', workflow)
        self.assertIn('"build_profile": build_profile', workflow)
        for key in CONFIGURATION:
            self.assertIn(f"EVALUATION_{key}:", workflow)
            self.assertIn(f"EVAL_{key}", workflow)
        clear = workflow.index("Clear selected build configuration")
        third_party = workflow.index("anchore/sbom-action")
        self.assertLess(clear, third_party)


if __name__ == "__main__":
    unittest.main()
