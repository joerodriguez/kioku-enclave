#!/usr/bin/env python3
"""Contract tests for the fail-closed enclave image profile selector."""

from __future__ import annotations

import os
import json
from pathlib import Path
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
import sys
sys.path.insert(0, str(ROOT / "scripts"))
from adr0022_fresh_release import BOOTSTRAP_TAG, FINAL_TAG  # noqa: E402
SELECTOR = ROOT / "scripts" / "select_build_configuration.py"
LOCAL_PIPELINE = ROOT / "scripts" / "local_image_pipeline.py"
DOCKERFILE = ROOT / "Dockerfile"
DOCKERIGNORE = ROOT / ".dockerignore"
RELEASE_SCRIPT = ROOT / "scripts" / "release.sh"
METADATA_VERIFIER = ROOT / "scripts" / "verify_release_metadata.py"
PROBE_PARSER = ROOT / "scripts" / "archive_witness_probe_config.py"
SHADOW_RUNTIME_PARSER = ROOT / "scripts" / "archive_v3_shadow_runtime_config.py"
MAIN = ROOT / "src" / "main.rs"

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
    "ADMIN_USER_IDS": "12345678-1234-1234-1234-123456789abc",
    "SIGNUP_LIMIT_PER_DAY": "25",
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
    "GENESIS_WAL_NATIVE": "off",
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

CANARY_IDENTITY_PREPARATION_SHA256 = "a" * 64
CANARY_ADMIN_UUID = "12345678-1234-5678-9234-123456789abc"


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
    result["PRODUCTION_ENCLAVE_GCS_BUCKET"] = "kioku-production-indexes"
    result["PRODUCTION_ENCLAVE_GCS_MEDIA_BUCKET"] = "kioku-production-media"
    result["PRODUCTION_ENCLAVE_GCS_LEGACY_MEDIA_BUCKET"] = "kioku-production-indexes"
    for key, value in APNS_CONFIGURATION.items():
        result[f"PRODUCTION_{key}"] = value
    return result


def fresh_bootstrap_environment() -> dict[str, str]:
    result = environment()
    result.update(
        {
            "PRODUCTION_ENCLAVE_KMS_PROJECT": "kioku-joerodriguez",
            "PRODUCTION_ENCLAVE_KMS_LOCATION": "us-central1",
            "PRODUCTION_ENCLAVE_KMS_KEY_RING": "kioku-adr0022-v1",
            "PRODUCTION_ENCLAVE_KMS_KEY": "kioku-kek-adr0022-v1",
            "PRODUCTION_ENCLAVE_GCS_BUCKET": "kioku-joerodriguez-adr0022-v1-indexes",
            "PRODUCTION_ENCLAVE_GCS_MEDIA_BUCKET": "kioku-joerodriguez-adr0022-v1-media",
            "PRODUCTION_ENCLAVE_GCS_LEGACY_MEDIA_BUCKET": "kioku-joerodriguez-adr0022-v1-indexes",
            "PRODUCTION_ENCLAVE_RUN_SA_EMAIL": "kioku-enclave-adr0022-v1@kioku-joerodriguez.iam.gserviceaccount.com",
            "PRODUCTION_ENCLAVE_ATTEST_STS_AUDIENCE": "//iam.googleapis.com/projects/640329636251/locations/global/workloadIdentityPools/enclave-attest/providers/attest",
            "PRODUCTION_ADMIN_USER_IDS": CANARY_ADMIN_UUID,
            "PRODUCTION_SIGNUP_LIMIT_PER_DAY": "25",
            "PRODUCTION_GENESIS_WAL_NATIVE": "off",
            "PRODUCTION_ADR0022_CANARY_IDENTITY_PREPARATION_SHA256": CANARY_IDENTITY_PREPARATION_SHA256,
        }
    )
    return result


class SelectorTests(unittest.TestCase):
    def run_selector(
        self,
        profile: str,
        env: dict[str, str],
        *,
        source_ref: str = "main",
        probe_config: dict[str, object] | None = None,
        shadow_runtime_config: dict[str, object] | None = None,
    ) -> tuple[subprocess.CompletedProcess[str], str]:
        with tempfile.TemporaryDirectory() as directory:
            selected_env = Path(directory) / "selected-env"
            probe_config_path = Path(directory) / "archive-witness-probe.json"
            if probe_config is None:
                probe_config_path = ROOT / "config" / "archive-witness-probe.json"
            else:
                probe_config_path.write_text(json.dumps(probe_config), encoding="utf-8")
            shadow_runtime_config_path = (
                ROOT / "config" / "archive-v3-shadow-runtime.json"
            )
            if shadow_runtime_config is not None:
                shadow_runtime_config_path = (
                    Path(directory) / "archive-v3-shadow-runtime.json"
                )
                shadow_runtime_config_path.write_text(
                    json.dumps(shadow_runtime_config), encoding="utf-8"
                )
            completed = subprocess.run(
                [
                    "python3",
                    str(SELECTOR),
                    "--profile",
                    profile,
                    "--source-ref",
                    source_ref,
                    "--archive-witness-probe-config",
                    str(probe_config_path),
                    "--archive-v3-shadow-runtime-config",
                    str(shadow_runtime_config_path),
                    "--output-env",
                    str(selected_env),
                ],
                cwd=ROOT,
                env=env,
                text=True,
                capture_output=True,
                check=False,
            )
            content = selected_env.read_text() if selected_env.exists() else ""
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
        self.assertIn("required production build configuration", completed.stderr)

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
            if key.startswith("ARCHIVE_WITNESS_"):
                continue
            source_name = f"EVALUATION_{key}"
            with self.subTest(source_name=source_name):
                env = environment()
                del env[source_name]
                completed, content = self.run_selector("evaluation", env)
                self.assertNotEqual(completed.returncode, 0)
                self.assertEqual(content, "")
                self.assertIn(source_name, completed.stderr)

    def test_hosted_authentication_is_absent_from_the_local_selector(self) -> None:
        selector = SELECTOR.read_text(encoding="utf-8")
        pipeline = LOCAL_PIPELINE.read_text(encoding="utf-8")
        self.assertNotIn("GCP_WIF_PROVIDER", selector)
        self.assertNotIn("GCP_SERVICE_ACCOUNT", selector)
        self.assertIn("LOCAL_GCP_IMPERSONATE_SERVICE_ACCOUNT", pipeline)

    def test_invalid_security_values_fail_before_writing_environment(self) -> None:
        for key, value in (
            ("EVALUATION_SIGNUP_LIMIT_PER_DAY", "-1"),
            ("EVALUATION_SIGNUP_LIMIT_PER_DAY", "00"),
            ("EVALUATION_SIGNUP_LIMIT_PER_DAY", "unlimited"),
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

    def test_zero_signup_budget_is_the_explicit_closed_cutover_state(self) -> None:
        env = environment()
        env["PRODUCTION_SIGNUP_LIMIT_PER_DAY"] = "0"
        completed, content = self.run_selector("production", env)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn("SIGNUP_LIMIT_PER_DAY=0\n", content)

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

    def test_local_pipeline_is_the_profile_and_release_metadata_entrypoint(self) -> None:
        pipeline = LOCAL_PIPELINE.read_text(encoding="utf-8")
        self.assertIn('choices=("production", "evaluation")', pipeline)
        self.assertIn("selected_configuration(", pipeline)
        self.assertIn("check_voice_release_gate.py", pipeline)
        self.assertIn('"schema_version": 10 if fresh_release else 9', pipeline)
        self.assertIn('"release_url"', pipeline)
        self.assertIn("enclave-release.json", pipeline)
        self.assertNotIn("GITHUB_OUTPUT", pipeline)
        self.assertNotIn("actions/runs", pipeline)

    def test_selected_profile_is_validated_and_baked_into_the_runtime_image(self) -> None:
        dockerfile = DOCKERFILE.read_text()
        self.assertIn("ARG CONFIG_SHA256", dockerfile)
        self.assertIn(
            "--build-arg CONFIG_SHA256=<sha256-of-/secure/kioku-runtime.env>",
            dockerfile,
        )
        self.assertIn("type=secret,id=kioku-config,required", dockerfile)
        self.assertIn("/build/kioku-config", dockerfile)
        self.assertNotIn("ENV KIOKU_BUILD_PROFILE=${KIOKU_BUILD_PROFILE}", dockerfile)

    def test_selector_docker_and_local_schema_v9_manifest_bind_the_same_three_buckets(self) -> None:
        completed, selected = self.run_selector("production", environment())
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn("ENCLAVE_GCS_BUCKET=kioku-production-indexes\n", selected)
        self.assertIn("ENCLAVE_GCS_MEDIA_BUCKET=kioku-production-media\n", selected)
        self.assertIn(
            "ENCLAVE_GCS_LEGACY_MEDIA_BUCKET=kioku-production-indexes\n", selected
        )

        pipeline = LOCAL_PIPELINE.read_text()
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
            self.assertIn(f'"{build_arg}": "{env_name}"', pipeline)
            self.assertNotIn(f"ARG {build_arg}", dockerfile)
            self.assertNotIn(f"{build_arg}=${{{build_arg}}}", dockerfile)
            self.assertIn(f'"{manifest_field}"', pipeline)
            self.assertIn(f'"{manifest_field}"', verifier)
        self.assertIn("GCS_LEGACY_MEDIA_BUCKET", dockerfile)
        self.assertIn('"schema_version": 10 if fresh_release else 9', pipeline)
        self.assertIn("schema_version must be 9 or 10", verifier)

    def test_probe_mode_defaults_off_with_empty_baked_namespace(self) -> None:
        completed, selected = self.run_selector("production", environment())
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn("ARCHIVE_WITNESS_SHADOW_MODE=off\n", selected)
        self.assertIn("ARCHIVE_WITNESS_PROJECT_ID=\n", selected)
        self.assertIn("ARCHIVE_WITNESS_PROJECT_NUMBER=\n", selected)
        self.assertIn("ARCHIVE_WITNESS_DATABASE_ID=\n", selected)

        hostile = environment()
        hostile["PRODUCTION_ARCHIVE_WITNESS_SHADOW_MODE"] = "probe-v1"
        hostile["PRODUCTION_ARCHIVE_WITNESS_PROJECT_ID"] = "attacker-project"
        completed, selected = self.run_selector("production", hostile)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn("ARCHIVE_WITNESS_SHADOW_MODE=off\n", selected)
        self.assertNotIn("attacker-project", selected)

        pipeline = LOCAL_PIPELINE.read_text(encoding="utf-8")
        self.assertIn("selected_configuration", pipeline)
        self.assertNotIn("inputs.archive_witness", pipeline.lower())
        self.assertNotIn("GITHUB_REF_NAME", pipeline)

    def test_probe_profile_is_tag_bound_and_evaluation_is_always_off(self) -> None:
        probe = {
            "schema_version": 1,
            "mode": "probe-v1",
            "project_id": "project-1",
            "project_number": "123456789",
            "database_id": "witness-db",
        }
        shadow_off = {
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
        completed, selected = self.run_selector(
            "production",
            environment(),
            source_ref="v1.2.3-witness-probe.1",
            probe_config=probe,
            shadow_runtime_config=shadow_off,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn("ARCHIVE_WITNESS_SHADOW_MODE=probe-v1\n", selected)
        self.assertIn("ARCHIVE_WITNESS_PROJECT_ID=project-1\n", selected)

        completed, selected = self.run_selector(
            "evaluation",
            environment(),
            source_ref="v1.2.3-witness-probe.1",
            probe_config=probe,
            shadow_runtime_config=shadow_off,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn("ARCHIVE_WITNESS_SHADOW_MODE=off\n", selected)
        self.assertNotIn("project-1", selected)

        completed, selected = self.run_selector(
            "production",
            environment(),
            source_ref="main",
            probe_config=probe,
            shadow_runtime_config=shadow_off,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn("ARCHIVE_WITNESS_SHADOW_MODE=off\n", selected)

        completed, selected = self.run_selector(
            "production",
            environment(),
            source_ref="v1.2.3",
            probe_config=probe,
            shadow_runtime_config=shadow_off,
        )
        self.assertNotEqual(completed.returncode, 0)
        self.assertEqual(selected, "")
        self.assertIn("exact vX.Y.Z-witness-probe.N", completed.stderr)

    def test_shared_parser_and_startup_order_are_static_boundaries(self) -> None:
        selector = SELECTOR.read_text(encoding="utf-8")
        verifier = METADATA_VERIFIER.read_text(encoding="utf-8")
        parser = PROBE_PARSER.read_text(encoding="utf-8")
        for source in (selector, verifier):
            self.assertIn("from archive_witness_probe_config import", source)
            self.assertIn("load_probe_config", source)
            self.assertIn("select_probe_config", source)
        self.assertIn("PROBE_TAG_PATTERN", parser)

        main = MAIN.read_text(encoding="utf-8")
        probe = main.index("archive_v3_firestore_probe::run_startup_probe")
        kms = main.index("crypto::GcpKmsClient::from_env()", probe)
        gcs = main.index("GcpGcsClient::from_env()", probe)
        store = main.index("Store::new_with_media_and_legacy", probe)
        self.assertLess(probe, kms)
        self.assertLess(probe, gcs)
        self.assertLess(probe, store)
        self.assertIn(".await\n    .expect", main[probe:kms])

    def test_shadow_runtime_is_image_bound_tag_selected_and_has_no_override_or_startup_call(self) -> None:
        completed, selected = self.run_selector("production", environment())
        self.assertEqual(completed.returncode, 0, completed.stderr)
        for name in (
            "ARCHIVE_V3_ARCHIVE_BUCKET",
            "ARCHIVE_V3_ARCHIVE_GCS_PROJECT_NUMBER",
            "ARCHIVE_V3_REGISTRY_KMS_VERSION",
            "ARCHIVE_V3_WITNESS_PROJECT_ID",
            "ARCHIVE_V3_WITNESS_PROJECT_NUMBER",
            "ARCHIVE_V3_WITNESS_DATABASE_ID",
            "ARCHIVE_V3_ARCHIVE_BINDING_COMMITMENT",
        ):
            self.assertIn(f"{name}=\n", selected)
        self.assertIn("ARCHIVE_V3_SHADOW_RUNTIME_MODE=off\n", selected)

        active = {
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
        completed, selected = self.run_selector(
            "production", environment(), source_ref="main", shadow_runtime_config=active
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn("ARCHIVE_V3_SHADOW_RUNTIME_MODE=off\n", selected)
        self.assertNotIn("archive-bucket-1", selected)

        wal_tag = "v1.2.3-archive-v3-wal.1"
        completed, selected = self.run_selector(
            "production", environment(), source_ref=wal_tag, shadow_runtime_config=active
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn("ARCHIVE_V3_SHADOW_RUNTIME_MODE=single-archive-wal-v1\n", selected)
        self.assertIn("ARCHIVE_V3_ARCHIVE_BUCKET=archive-bucket-1\n", selected)
        self.assertIn("ARCHIVE_V3_ARCHIVE_BINDING_COMMITMENT=" + "1" * 64 + "\n", selected)

        completed, selected = self.run_selector(
            "evaluation", environment(), source_ref=wal_tag, shadow_runtime_config=active
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn("ARCHIVE_V3_SHADOW_RUNTIME_MODE=off\n", selected)
        self.assertNotIn("archive-bucket-1", selected)

        for ref in ("v1.2.3", "v1.2.3-rc.1", "feature/runtime"):
            with self.subTest(ref=ref):
                completed, selected = self.run_selector(
                    "production", environment(), source_ref=ref, shadow_runtime_config=active
                )
                self.assertNotEqual(completed.returncode, 0)
                self.assertEqual(selected, "")
                self.assertIn("exact vX.Y.Z-archive-v3-wal.N", completed.stderr)

        completed, selected = self.run_selector(
            "production", environment(), source_ref=wal_tag
        )
        self.assertNotEqual(completed.returncode, 0)
        self.assertEqual(selected, "")
        self.assertIn("requires the complete active runtime profile", completed.stderr)

        completed, selected = self.run_selector(
            "production", environment(), source_ref="v1.2.3-rc.1"
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn("ARCHIVE_V3_SHADOW_RUNTIME_MODE=off\n", selected)
        self.assertNotIn("kioku-joerodriguez-archive-v3", selected)

        pipeline = LOCAL_PIPELINE.read_text(encoding="utf-8")
        dockerfile = DOCKERFILE.read_text(encoding="utf-8")
        verifier = METADATA_VERIFIER.read_text(encoding="utf-8")
        parser = SHADOW_RUNTIME_PARSER.read_text(encoding="utf-8")
        for source in (SELECTOR.read_text(encoding="utf-8"), verifier):
            self.assertIn("from archive_v3_shadow_runtime_config import", source)
            self.assertIn("load_shadow_runtime_config", source)
        self.assertIn("single-archive-wal-v1", parser)
        self.assertNotIn("inputs.archive_v3", pipeline.lower())
        for name in (
            "ARCHIVE_V3_SHADOW_RUNTIME_MODE",
            "ARCHIVE_V3_ARCHIVE_BUCKET",
            "ARCHIVE_V3_ARCHIVE_GCS_PROJECT_NUMBER",
            "ARCHIVE_V3_REGISTRY_KMS_VERSION",
            "ARCHIVE_V3_WITNESS_PROJECT_ID",
            "ARCHIVE_V3_WITNESS_PROJECT_NUMBER",
            "ARCHIVE_V3_WITNESS_DATABASE_ID",
            "ARCHIVE_V3_ARCHIVE_BINDING_COMMITMENT",
        ):
            self.assertIn(name, pipeline)
            self.assertNotIn(f"ARG {name}", dockerfile)
            self.assertIn(name, dockerfile)
            self.assertNotIn(f"PRODUCTION_{name}", pipeline)
            self.assertNotIn(f"EVALUATION_{name}", pipeline)
        validator = "scripts/validate_archive_v3_shadow_runtime_environment.sh"
        self.assertIn("scripts/assemble_image_config.sh", dockerfile)
        dockerignore_lines = DOCKERIGNORE.read_text(encoding="utf-8").splitlines()
        self.assertIn("!scripts/assemble_image_config.sh", dockerignore_lines)
        self.assertIn(f"!{validator}", dockerignore_lines)
        self.assertIn("type=secret,id=kioku-config,required", dockerfile)
        for name in (
            "ARCHIVE_V3_SHADOW_RUNTIME_MODE",
            "ARCHIVE_V3_ARCHIVE_BUCKET",
            "ARCHIVE_V3_ARCHIVE_GCS_PROJECT_NUMBER",
            "ARCHIVE_V3_REGISTRY_KMS_VERSION",
            "ARCHIVE_V3_WITNESS_PROJECT_ID",
            "ARCHIVE_V3_WITNESS_PROJECT_NUMBER",
            "ARCHIVE_V3_WITNESS_DATABASE_ID",
            "ARCHIVE_V3_ARCHIVE_BINDING_COMMITMENT",
        ):
            self.assertIn(name, dockerfile)
        self.assertIn('"archive_v3_archive_binding_commitment"', pipeline)
        self.assertIn('"archive_v3_archive_binding_commitment"', verifier)
        main = MAIN.read_text(encoding="utf-8")
        self.assertNotIn("PendingSingleArchiveWalRuntime::new", main)
        self.assertNotIn("DurableSingleArchiveBinding::from_control_store", main)

        hostile = environment()
        hostile["PRODUCTION_ARCHIVE_V3_SHADOW_RUNTIME_MODE"] = "single-archive-wal-v1"
        hostile["PRODUCTION_ARCHIVE_V3_ARCHIVE_BINDING_COMMITMENT"] = "f" * 64
        completed, selected = self.run_selector("production", hostile)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn("ARCHIVE_V3_SHADOW_RUNTIME_MODE=off\n", selected)
        self.assertNotIn("f" * 64, selected)

    def test_genesis_gate_is_a_baked_key_and_cannot_be_set_at_launch(self) -> None:
        # The gate travels the same path as every other baked name: the
        # selector takes it from the profile-prefixed operator value, the
        # assembler allowlists it at the image boundary, and the binary's
        # allowlist makes the baked file overwrite whatever the process
        # environment says. Every link is asserted, because the property only
        # holds if all of them do.
        selector = SELECTOR.read_text(encoding="utf-8")
        pipeline = LOCAL_PIPELINE.read_text(encoding="utf-8")
        assembler = (ROOT / "scripts" / "assemble_image_config.sh").read_text(
            encoding="utf-8"
        )
        main = MAIN.read_text(encoding="utf-8")
        dockerfile = DOCKERFILE.read_text(encoding="utf-8")
        self.assertIn('"GENESIS_WAL_NATIVE",', selector)
        self.assertIn("GENESIS_WAL_NATIVE", assembler)
        self.assertIn('"GENESIS_WAL_NATIVE",', main)
        self.assertIn('"GENESIS_WAL_NATIVE"', pipeline)
        self.assertIn("GENESIS_WAL_NATIVE", dockerfile)
        # The gate must not be a Docker build argument: those are recorded in
        # image history and are an operator-supplied launch-time surface.
        self.assertNotIn("ARG GENESIS_WAL_NATIVE", dockerfile)
        # The baked file overwrites ambient values and an image that omits any
        # allowlisted key refuses to start; both are what make a launch-time
        # GENESIS_WAL_NATIVE unable to arm an image built `off`.
        self.assertIn("std::env::set_var(name, value);", main)
        self.assertIn('panic!("baked image configuration is incomplete")', main)

        # The bare name in the process environment is never a source. An
        # operator who exports GENESIS_WAL_NATIVE=on at build time still gets
        # the profile's baked `off`, and the selector never reads the value.
        hostile = environment()
        hostile["GENESIS_WAL_NATIVE"] = "on"
        completed, selected_env = self.run_selector("production", hostile)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn("GENESIS_WAL_NATIVE=off\n", selected_env)
        self.assertNotIn("GENESIS_WAL_NATIVE=on\n", selected_env)

    def test_genesis_gate_value_is_required_explicit_and_agrees_with_archive_v3(
        self,
    ) -> None:
        # Empty is not a third spelling of "shut" once the name is a required
        # baked key, and an unknown value is never guessed at in either
        # direction. Both refusals must name the key for the operator.
        for value in ("", "  ", "0", "1", "true", "false", "On", "ON", "yes", " off"):
            with self.subTest(value=value):
                env = environment()
                env["PRODUCTION_GENESIS_WAL_NATIVE"] = value
                completed, content = self.run_selector("production", env)
                self.assertNotEqual(completed.returncode, 0)
                self.assertEqual(content, "")
                self.assertIn("GENESIS_WAL_NATIVE", completed.stderr)

        # Claiming the gate on an image with no archive-v3 coordinates is
        # refused at build time, mirroring require_genesis_config_agreement.
        # `main` always selects the off runtime, so this is the shape an
        # operator would actually hit by flipping the value alone.
        armed = environment()
        armed["PRODUCTION_GENESIS_WAL_NATIVE"] = "on"
        completed, content = self.run_selector("production", armed)
        self.assertNotEqual(completed.returncode, 0)
        self.assertEqual(content, "")
        self.assertIn("GENESIS_WAL_NATIVE", completed.stderr)
        self.assertIn("archive-v3", completed.stderr)

        # The gate is still flippable: with the archive-v3 coordinates the
        # cutover actually requires, `on` selects cleanly. This PR arms
        # nothing, but it must not have made the cutover unbuildable either.
        completed, content = self.run_selector(
            "production",
            armed,
            source_ref="v1.2.3-archive-v3-wal.1",
            shadow_runtime_config={
                "schema_version": 2,
                "mode": "single-archive-wal-v1",
                "archive_bucket": "archive-bucket-1",
                "archive_gcs_project_number": "123456789",
                "registry_kms_version": "7",
                "witness_project_id": "project-1",
                "witness_project_number": "987654321",
                "witness_database_id": "witness-db",
                "archive_binding_commitment": "a" * 64,
            },
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn("GENESIS_WAL_NATIVE=on\n", content)
        self.assertIn("ARCHIVE_V3_SHADOW_RUNTIME_MODE=single-archive-wal-v1\n", content)

    def test_fresh_bootstrap_selects_only_the_exact_full_tuple(self) -> None:
        completed, content = self.run_selector(
            "production", fresh_bootstrap_environment(), source_ref=BOOTSTRAP_TAG
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        for line in (
            "ENCLAVE_KMS_KEY_RING=kioku-adr0022-v1\n",
            "ENCLAVE_KMS_KEY=kioku-kek-adr0022-v1\n",
            "ENCLAVE_GCS_BUCKET=kioku-joerodriguez-adr0022-v1-indexes\n",
            "ENCLAVE_GCS_MEDIA_BUCKET=kioku-joerodriguez-adr0022-v1-media\n",
            "ENCLAVE_RUN_SA_EMAIL=kioku-enclave-adr0022-v1@kioku-joerodriguez.iam.gserviceaccount.com\n",
            f"ADMIN_USER_IDS={CANARY_ADMIN_UUID}\n",
            f"ADR0022_CANARY_IDENTITY_PREPARATION_SHA256={CANARY_IDENTITY_PREPARATION_SHA256}\n",
            "GENESIS_WAL_NATIVE=off\n",
            "ARCHIVE_V3_SHADOW_RUNTIME_MODE=off\n",
        ):
            self.assertIn(line, content)

    def test_fresh_bootstrap_refuses_wrong_tag_profile_and_image_tuple(self) -> None:
        exact = fresh_bootstrap_environment()
        completed, content = self.run_selector(
            "production", exact, source_ref="main"
        )
        self.assertNotEqual(completed.returncode, 0)
        self.assertEqual(content, "")
        self.assertIn("only for an exact fixed tag", completed.stderr)
        for tag in (
            "v0.8.34-adr0022-fresh-bootstrap.1",
            "v0.8.35-adr0022-fresh-bootstrap.2",
            "v0.8.35-adr0022-fresh-bootstrap.1-extra",
            "v0.8.35.adr0022-fresh-bootstrap.1",
            "v0.8.35-ADR0022-FRESH-BOOTSTRAP.1",
        ):
            with self.subTest(tag=tag):
                completed, content = self.run_selector(
                    "production", exact, source_ref=tag
                )
                self.assertNotEqual(completed.returncode, 0)
                self.assertEqual(content, "")
                self.assertIn("must be exactly", completed.stderr)
        completed, content = self.run_selector(
            "evaluation", exact, source_ref=BOOTSTRAP_TAG
        )
        self.assertNotEqual(completed.returncode, 0)
        self.assertEqual(content, "")

        for key, value in (
            ("PROJECT_ID", "wrong-project"),
            ("PRODUCTION_ENCLAVE_KMS_KEY_RING", "legacy-ring"),
            ("PRODUCTION_ENCLAVE_KMS_KEY", "legacy-key"),
            ("PRODUCTION_ENCLAVE_GCS_BUCKET", "legacy-indexes"),
            ("PRODUCTION_ENCLAVE_GCS_MEDIA_BUCKET", "legacy-media"),
            ("PRODUCTION_ENCLAVE_RUN_SA_EMAIL", "legacy-sa@kioku-joerodriguez.iam.gserviceaccount.com"),
            ("PRODUCTION_ENCLAVE_ATTEST_STS_AUDIENCE", "//iam.googleapis.com/projects/640329636251/locations/global/workloadIdentityPools/other/providers/other"),
            ("PRODUCTION_GENESIS_WAL_NATIVE", "on"),
            ("PRODUCTION_SIGNUP_LIMIT_PER_DAY", "0"),
        ):
            with self.subTest(key=key):
                changed = dict(exact)
                changed[key] = value
                completed, content = self.run_selector(
                    "production", changed, source_ref=BOOTSTRAP_TAG
                )
                self.assertNotEqual(completed.returncode, 0)
                self.assertEqual(content, "")

    def test_fresh_bootstrap_refuses_missing_or_malformed_canary_binding(self) -> None:
        exact = fresh_bootstrap_environment()
        for key, value in (
            ("PRODUCTION_ADR0022_CANARY_IDENTITY_PREPARATION_SHA256", ""),
            ("PRODUCTION_ADR0022_CANARY_IDENTITY_PREPARATION_SHA256", "0" * 64),
            ("PRODUCTION_ADR0022_CANARY_IDENTITY_PREPARATION_SHA256", "A" * 64),
            ("PRODUCTION_ADMIN_USER_IDS", "12345678-1234-4678-9234-123456789abc"),
            ("PRODUCTION_ADMIN_USER_IDS", CANARY_ADMIN_UUID.upper()),
            ("PRODUCTION_ADMIN_USER_IDS", CANARY_ADMIN_UUID + "," + CANARY_ADMIN_UUID),
        ):
            with self.subTest(key=key, value=value):
                changed = dict(exact)
                changed[key] = value
                completed, content = self.run_selector(
                    "production", changed, source_ref=BOOTSTRAP_TAG
                )
                self.assertNotEqual(completed.returncode, 0)
                self.assertEqual(content, "")

    def test_fresh_final_aliases_and_current_bootstrap_source_are_ineligible(self) -> None:
        exact = fresh_bootstrap_environment()
        exact["PRODUCTION_GENESIS_WAL_NATIVE"] = "on"
        active_runtime = {
            "schema_version": 2,
            "mode": "single-archive-wal-v1",
            "archive_bucket": "kioku-joerodriguez-adr0022-v1-archive",
            "archive_gcs_project_number": "640329636251",
            "registry_kms_version": "1",
            "witness_project_id": "kioku-joerodriguez",
            "witness_project_number": "640329636251",
            "witness_database_id": "adr0022-v1-witness",
            "archive_binding_commitment": "d" * 64,
        }
        for tag in (
            "v0.8.35-archive-v3-wal.2",
            "v0.8.35-archive-v3-wal.1-extra",
            "v0.8.35-ARCHIVE-V3-WAL.1",
        ):
            with self.subTest(tag=tag):
                completed, content = self.run_selector(
                    "production",
                    exact,
                    source_ref=tag,
                    shadow_runtime_config=active_runtime,
                )
                self.assertNotEqual(completed.returncode, 0)
                self.assertEqual(content, "")
                self.assertIn("must be exactly", completed.stderr)

        completed, content = self.run_selector(
            "production",
            exact,
            source_ref=FINAL_TAG,
            shadow_runtime_config=active_runtime,
        )
        self.assertNotEqual(completed.returncode, 0)
        self.assertEqual(content, "")
        self.assertIn("fresh FINAL schema phase is not exact 1/1/1", completed.stderr)


if __name__ == "__main__":
    unittest.main()
