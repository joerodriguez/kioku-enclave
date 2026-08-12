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
DOCKERFILE = ROOT / "Dockerfile"
RELEASE_SCRIPT = ROOT / "scripts" / "release.sh"
METADATA_VERIFIER = ROOT / "scripts" / "verify_release_metadata.py"

CONFIGURATION = {
    "ENCLAVE_KMS_PROJECT": "kioku-joerodriguez",
    "ENCLAVE_KMS_LOCATION": "us-central1",
    "ENCLAVE_KMS_KEY_RING": "kioku-eval",
    "ENCLAVE_KMS_KEY": "eval-kek",
    "ENCLAVE_GCS_BUCKET": "kioku-eval-indexes",
    "ENCLAVE_GCS_MEDIA_BUCKET": "kioku-eval-media",
    "ENCLAVE_GCS_LEGACY_MEDIA_BUCKET": "kioku-eval-indexes",
    "ENCLAVE_RUN_SA_EMAIL": "kioku-eval@kioku-joerodriguez.iam.gserviceaccount.com",
    "ENCLAVE_AUDIENCE": "https://eval-api.kiokuu.com",
    "ENCLAVE_ATTEST_STS_AUDIENCE": "//iam.googleapis.com/projects/123456789/locations/global/workloadIdentityPools/enclave-attest/providers/attest",
    "GOOGLE_DESKTOP_CLIENT_ID": "desktop.apps.googleusercontent.com",
    "GOOGLE_IOS_CLIENT_ID": "ios.apps.googleusercontent.com",
    "GOOGLE_WEB_CLIENT_ID": "web.apps.googleusercontent.com",
    "ALLOWED_EMAILS": "owner@example.com",
    "ADMIN_USER_IDS": "12345678-1234-1234-1234-123456789abc",
    "BASE_URL": "https://eval-api.kiokuu.com",
    "WEB_ORIGIN": "https://kiokuu.com",
    "BILLING_SERVICE_URL": "https://billing.kiokuu.com",
    "BILLING_SERVICE_AUDIENCE": "https://billing.kiokuu.com",
    "BILLING_ENFORCEMENT_MODE": "shadow",
    "ARCHIVE_WITNESS_SHADOW_MODE": "off",
    "ARCHIVE_WITNESS_PROJECT_ID": "",
    "ARCHIVE_WITNESS_PROJECT_NUMBER": "",
    "ARCHIVE_WITNESS_DATABASE_ID": "",
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
        "GCP_WIF_PROVIDER": "projects/123456789/locations/global/workloadIdentityPools/github/providers/actions",
        "GCP_SERVICE_ACCOUNT": "push-images@kioku-joerodriguez.iam.gserviceaccount.com",
    }
    for prefix in ("PRODUCTION", "EVALUATION"):
        for key, value in CONFIGURATION.items():
            result[f"{prefix}_{key}"] = value
    result["PRODUCTION_ENCLAVE_KMS_KEY_RING"] = "kioku-production"
    result["PRODUCTION_ENCLAVE_GCS_BUCKET"] = "kioku-production-indexes"
    result["PRODUCTION_ENCLAVE_GCS_MEDIA_BUCKET"] = "kioku-production-media"
    result["PRODUCTION_ENCLAVE_GCS_LEGACY_MEDIA_BUCKET"] = "kioku-production-indexes"
    for key, value in APNS_CONFIGURATION.items():
        result[f"PRODUCTION_{key}"] = value
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

    def test_production_accepts_reviewed_billing_enforcement(self) -> None:
        env = environment()
        env["PRODUCTION_BILLING_ENFORCEMENT_MODE"] = "enforce"
        completed, content = self.run_selector("production", env)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn("BILLING_ENFORCEMENT_MODE=enforce\n", content)

    def test_missing_evaluation_value_never_falls_back_to_production(self) -> None:
        env = environment()
        del env["EVALUATION_ENCLAVE_GCS_BUCKET"]
        completed, content = self.run_selector("evaluation", env)
        self.assertNotEqual(completed.returncode, 0)
        self.assertEqual(content, "")
        self.assertIn("EVALUATION_ENCLAVE_GCS_BUCKET", completed.stderr)
        self.assertNotIn("kioku-production-indexes", completed.stderr)

    def test_phase0_current_media_bucket_may_differ_from_the_index_bucket(self) -> None:
        env = environment()
        env["EVALUATION_ENCLAVE_GCS_MEDIA_BUCKET"] = "kioku-eval-other"
        completed, content = self.run_selector("evaluation", env)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn("ENCLAVE_GCS_MEDIA_BUCKET=kioku-eval-other\n", content)

    def test_phase0_legacy_media_bucket_is_required_to_match_the_index_bucket(self) -> None:
        env = environment()
        env["EVALUATION_ENCLAVE_GCS_LEGACY_MEDIA_BUCKET"] = "kioku-eval-other"
        completed, content = self.run_selector("evaluation", env)
        self.assertNotEqual(completed.returncode, 0)
        self.assertEqual(content, "")
        self.assertIn("ENCLAVE_GCS_LEGACY_MEDIA_BUCKET must exactly match", completed.stderr)

    def test_apple_configuration_is_optional_but_atomic(self) -> None:
        env = environment()
        completed, content = self.run_selector("production", env)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn("APPLE_TEAM_ID=\n", content)

        for key, value in APPLE_CONFIGURATION.items():
            env[f"PRODUCTION_{key}"] = value
        completed, content = self.run_selector("production", env)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn("APPLE_IOS_CLIENT_ID=com.kioku.ios\n", content)
        self.assertIn("APPLE_MACOS_CLIENT_ID=com.kiokuu.app\n", content)
        self.assertIn("APPLE_WEB_CLIENT_ID=com.kiokuu.web\n", content)

        del env["PRODUCTION_APPLE_KEY_ID"]
        completed, content = self.run_selector("production", env)
        self.assertNotEqual(completed.returncode, 0)
        self.assertEqual(content, "")
        self.assertIn("PRODUCTION_APPLE_KEY_ID", completed.stderr)

    def test_production_apns_configuration_is_required_and_atomic(self) -> None:
        env = environment()
        for key in APNS_CONFIGURATION:
            del env[f"PRODUCTION_{key}"]
        completed, content = self.run_selector("production", env)
        self.assertNotEqual(completed.returncode, 0)
        self.assertEqual(content, "")
        self.assertIn("required production repository configuration", completed.stderr)

        for key, value in APNS_CONFIGURATION.items():
            env[f"PRODUCTION_{key}"] = value
        completed, content = self.run_selector("production", env)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn("APNS_PRODUCTION_KEY_ID=PUSHPRD123\n", content)
        self.assertIn("APNS_SANDBOX_KEY_ID=PUSHSBX123\n", content)

        del env["PRODUCTION_APNS_SANDBOX_KEY_ID"]
        completed, content = self.run_selector("production", env)
        self.assertNotEqual(completed.returncode, 0)
        self.assertEqual(content, "")
        self.assertIn("PRODUCTION_APNS_SANDBOX_KEY_ID", completed.stderr)

    def test_evaluation_apns_configuration_remains_optional_but_atomic(self) -> None:
        env = environment()
        completed, content = self.run_selector("evaluation", env)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn("APNS_TEAM_ID=\n", content)

        for key, value in APNS_CONFIGURATION.items():
            env[f"EVALUATION_{key}"] = value
        completed, content = self.run_selector("evaluation", env)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn("APNS_PRODUCTION_KEY_ID=PUSHPRD123\n", content)

    def test_every_evaluation_value_is_required(self) -> None:
        for key in CONFIGURATION:
            if key.startswith("ARCHIVE_WITNESS_") and key != "ARCHIVE_WITNESS_SHADOW_MODE":
                continue
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
            ("EVALUATION_ADMIN_USER_IDS", "not-an-id"),
            ("EVALUATION_BILLING_SERVICE_URL", "http://billing.kiokuu.com"),
            ("EVALUATION_BILLING_ENFORCEMENT_MODE", "disabled"),
            ("EVALUATION_VERTEX_MODEL", "publishers/google/gemini"),
            ("EVALUATION_VERTEX_MODEL", "m" * 129),
            ("EVALUATION_ENCLAVE_KMS_KEY", "bad\nINJECTED=value"),
        ):
            with self.subTest(key=key):
                env = environment()
                env[key] = value
                completed, content = self.run_selector("evaluation", env)
                self.assertNotEqual(completed.returncode, 0)
                self.assertEqual(content, "")

    def test_billing_audience_must_exactly_match_service_origin(self) -> None:
        env = environment()
        env["EVALUATION_BILLING_SERVICE_AUDIENCE"] = "https://other.kiokuu.com"
        completed, content = self.run_selector("evaluation", env)
        self.assertNotEqual(completed.returncode, 0)
        self.assertEqual(content, "")
        self.assertIn("must exactly match", completed.stderr)

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
        self.assertIn(
            '--build-arg KIOKU_BUILD_PROFILE="${KIOKU_BUILD_PROFILE}"',
            workflow,
        )
        self.assertIn(
            'echo "build_profile=${KIOKU_BUILD_PROFILE}" >> "$GITHUB_OUTPUT"',
            workflow,
        )
        self.assertIn(
            "BUILD_PROFILE: ${{ steps.build.outputs.build_profile }}",
            workflow,
        )
        metadata_start = workflow.index("- name: Write release metadata")
        metadata_end = workflow.index(
            "- name: Attest release metadata manifest", metadata_start
        )
        metadata_step = workflow[metadata_start:metadata_end]
        self.assertIn('"${BUILD_PROFILE}"', metadata_step)
        self.assertNotIn('"${KIOKU_BUILD_PROFILE}"', metadata_step)
        self.assertIn('"build_profile": build_profile', workflow)
        for key in CONFIGURATION:
            self.assertIn(f"EVALUATION_{key}:", workflow)
            if not key.startswith("ARCHIVE_WITNESS_"):
                self.assertIn(f"EVAL_{key}", workflow)
        for key in APPLE_CONFIGURATION:
            self.assertIn(f"EVALUATION_{key}:", workflow)
            self.assertIn(f"EVAL_{key}", workflow)
        clear = workflow.index("Clear selected build configuration")
        third_party = workflow.index("anchore/sbom-action")
        self.assertLess(clear, third_party)

    def test_selected_profile_is_validated_and_baked_into_the_runtime_image(self) -> None:
        dockerfile = DOCKERFILE.read_text()
        self.assertGreaterEqual(dockerfile.count("ARG KIOKU_BUILD_PROFILE"), 2)
        self.assertIn(
            'case "${KIOKU_BUILD_PROFILE}" in production|evaluation)',
            dockerfile,
        )
        self.assertIn("production)", dockerfile)
        self.assertIn('[ -n "${APNS_TEAM_ID}" ]', dockerfile)
        self.assertIn("ENV KIOKU_BUILD_PROFILE=${KIOKU_BUILD_PROFILE}", dockerfile)

    def test_evaluation_reviewer_key_is_read_from_an_encrypted_secret(self) -> None:
        workflow = WORKFLOW.read_text()
        self.assertIn(
            "EVALUATION_REVIEWER_AUTH_API_KEY: "
            "${{ secrets.EVAL_REVIEWER_AUTH_API_KEY }}",
            workflow,
        )
        self.assertNotIn(
            "EVALUATION_REVIEWER_AUTH_API_KEY: "
            "${{ vars.EVAL_REVIEWER_AUTH_API_KEY }}",
            workflow,
        )

    def test_release_ci_uses_shared_voice_gate_and_attests_its_result(self) -> None:
        workflow = WORKFLOW.read_text()
        self.assertGreaterEqual(
            workflow.count("python3 scripts/check_voice_release_gate.py"), 2
        )
        self.assertNotIn("test -s eval/voice/release-manifest.json", workflow)
        self.assertIn('"schema_version": 6', workflow)
        self.assertIn('"voice_quality_gate": voice_quality_gate', workflow)
        self.assertIn('"billing_enforcement_mode": billing_enforcement_mode', workflow)
        self.assertIn('"gcs_media_bucket": gcs_media_bucket', workflow)
        self.assertIn('"gcs_legacy_media_bucket": gcs_legacy_media_bucket', workflow)
        self.assertIn("Attest release metadata manifest", workflow)
        self.assertIn("subject-path: enclave-release.json", workflow)

    def test_selector_docker_and_schema_v5_manifest_bind_the_same_three_buckets(self) -> None:
        completed, selected = self.run_selector("production", environment())
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn("ENCLAVE_GCS_BUCKET=kioku-production-indexes\n", selected)
        self.assertIn("ENCLAVE_GCS_MEDIA_BUCKET=kioku-production-media\n", selected)
        self.assertIn(
            "ENCLAVE_GCS_LEGACY_MEDIA_BUCKET=kioku-production-indexes\n", selected
        )

        workflow = WORKFLOW.read_text()
        dockerfile = DOCKERFILE.read_text()
        verifier = METADATA_VERIFIER.read_text()
        for env_name, build_arg, manifest_field in (
            ("ENCLAVE_GCS_BUCKET", "GCS_BUCKET", "gcs_bucket"),
            ("ENCLAVE_GCS_MEDIA_BUCKET", "GCS_MEDIA_BUCKET", "gcs_media_bucket"),
            (
                "ENCLAVE_GCS_LEGACY_MEDIA_BUCKET",
                "GCS_LEGACY_MEDIA_BUCKET",
                "gcs_legacy_media_bucket",
            ),
        ):
            self.assertIn(f'--build-arg {build_arg}="${{{env_name}}}"', workflow)
            self.assertIn(f"ARG {build_arg}", dockerfile)
            self.assertIn(f"{build_arg}=${{{build_arg}}}", dockerfile)
            self.assertIn(f'"{manifest_field}"', workflow)
            self.assertIn(f'"{manifest_field}"', verifier)
        self.assertIn('[ "${GCS_LEGACY_MEDIA_BUCKET}" = "${GCS_BUCKET}" ]', dockerfile)
        self.assertNotIn('[ "${GCS_MEDIA_BUCKET}" = "${GCS_BUCKET}" ]', dockerfile)
        self.assertIn('"schema_version": 6', workflow)
        self.assertIn("schema_version must be 6", verifier)

    def test_operator_release_uses_shared_voice_gate_and_verifies_metadata(self) -> None:
        release_script = RELEASE_SCRIPT.read_text()
        metadata_verifier = METADATA_VERIFIER.read_text()
        self.assertIn(
            'VOICE_QUALITY_GATE="$(python3 scripts/check_voice_release_gate.py)"',
            release_script,
        )
        self.assertIn('"voice_quality_gate"', metadata_verifier)
        self.assertIn("schema_version must be 6", metadata_verifier)
        self.assertIn('"billing_enforcement_mode"', metadata_verifier)
        self.assertIn("owner_only_unvalidated", metadata_verifier)
        self.assertIn("validated_real_corpus", metadata_verifier)
        self.assertIn(
            '"$VOICE_QUALITY_GATE" != "$EXPECTED_VOICE_QUALITY_GATE"',
            release_script,
        )
        self.assertIn("EXPECTED_BILLING_ENFORCEMENT_MODE", release_script)
        self.assertIn(
            '"$BILLING_ENFORCEMENT_MODE" != "$EXPECTED_BILLING_ENFORCEMENT_MODE"',
            release_script,
        )
        self.assertIn(
            "BILLING_SERVICE_URL BILLING_SERVICE_AUDIENCE BILLING_ENFORCEMENT_MODE",
            release_script,
        )
        self.assertIn("ENCLAVE_GCS_LEGACY_MEDIA_BUCKET must be configured and exactly match", release_script)
        self.assertIn("Verifying signed release metadata manifest", release_script)
        self.assertIn("enclave-release-metadata-provenance.jsonl", release_script)

    def test_probe_mode_defaults_off_with_empty_baked_namespace(self) -> None:
        completed, selected = self.run_selector("production", environment())
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn("ARCHIVE_WITNESS_SHADOW_MODE=off\n", selected)
        self.assertIn("ARCHIVE_WITNESS_PROJECT_ID=\n", selected)
        self.assertIn("ARCHIVE_WITNESS_PROJECT_NUMBER=\n", selected)
        self.assertIn("ARCHIVE_WITNESS_DATABASE_ID=\n", selected)

        partial = environment()
        partial["PRODUCTION_ARCHIVE_WITNESS_PROJECT_ID"] = "project-1"
        completed, _ = self.run_selector("production", partial)
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("namespace must be empty", completed.stderr)


if __name__ == "__main__":
    unittest.main()
