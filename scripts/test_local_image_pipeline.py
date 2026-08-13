#!/usr/bin/env python3
"""Hermetic contracts for the local enclave image pipeline's safety boundaries."""

from __future__ import annotations

import importlib.util
from contextlib import nullcontext
import json
from pathlib import Path
from types import SimpleNamespace
import sys
import tempfile
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
sys.path.insert(0, str(SCRIPTS))
from test_select_build_configuration import environment  # noqa: E402


def load_pipeline():
    specification = importlib.util.spec_from_file_location(
        "local_image_pipeline", SCRIPTS / "local_image_pipeline.py"
    )
    assert specification and specification.loader
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


def write_config(path: Path, *, mode: int = 0o600) -> None:
    values = environment()
    values.pop("PATH", None)
    values.pop("GCP_WIF_PROVIDER", None)
    values.pop("GCP_SERVICE_ACCOUNT", None)
    values["LOCAL_GCP_IMPERSONATE_SERVICE_ACCOUNT"] = (
        "local-builder@kioku-joerodriguez.iam.gserviceaccount.com"
    )
    path.write_text(
        "\n".join(f"{name}={value}" for name, value in sorted(values.items())) + "\n",
        encoding="utf-8",
    )
    path.chmod(mode)


class LocalImagePipelineTests(unittest.TestCase):
    def test_cargo_audit_falls_back_to_the_standard_cargo_install_directory(self) -> None:
        pipeline = load_pipeline()
        with tempfile.TemporaryDirectory() as temporary_directory:
            cargo_home = Path(temporary_directory)
            binary = cargo_home / "bin" / "cargo-audit"
            binary.parent.mkdir()
            binary.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            binary.chmod(0o700)

            original_which = pipeline.shutil.which
            original_cargo_home = pipeline.os.environ.get("CARGO_HOME")
            pipeline.shutil.which = lambda _name: None
            pipeline.os.environ["CARGO_HOME"] = str(cargo_home)
            try:
                self.assertEqual(pipeline.cargo_audit_executable(), str(binary))
            finally:
                pipeline.shutil.which = original_which
                if original_cargo_home is None:
                    pipeline.os.environ.pop("CARGO_HOME", None)
                else:
                    pipeline.os.environ["CARGO_HOME"] = original_cargo_home

    def test_config_is_not_shell_and_requires_exact_private_mode(self) -> None:
        pipeline = load_pipeline()
        with tempfile.TemporaryDirectory() as temporary_directory:
            config = Path(temporary_directory) / "operator.env"
            write_config(config, mode=0o644)
            with self.assertRaisesRegex(pipeline.PipelineError, "mode 0600"):
                pipeline.read_operator_config(config)

            config.write_text("export PROJECT_ID=unsafe\n", encoding="utf-8")
            config.chmod(0o600)
            with self.assertRaisesRegex(pipeline.PipelineError, "line 1"):
                pipeline.read_operator_config(config)

            config.write_text("UNEXPECTED_OPTION=value\n", encoding="utf-8")
            with self.assertRaisesRegex(pipeline.PipelineError, "unknown operator configuration"):
                pipeline.read_operator_config(config)

            target = Path(temporary_directory) / "target.env"
            write_config(target)
            config.unlink()
            config.symlink_to(target)
            with self.assertRaisesRegex(pipeline.PipelineError, "must not be a symlink"):
                pipeline.read_operator_config(config)

    def test_push_scans_before_impersonated_authentication_and_writes_unsigned_evidence(self) -> None:
        pipeline = load_pipeline()
        calls: list[list[str]] = []
        digest = "sha256:" + "a" * 64

        def fake_run(
            command: list[str],
            *,
            capture: bool = False,
            environment: dict[str, str] | None = None,
        ):
            calls.append(command)
            if command[:2] == ["git", "status"]:
                return SimpleNamespace(stdout="", stderr="")
            if command[:3] == ["git", "rev-parse", "HEAD"]:
                return SimpleNamespace(stdout="b" * 40 + "\n")
            if command[:3] == ["git", "log", "-1"]:
                return SimpleNamespace(stdout="1700000000\n")
            if command[:4] == ["git", "remote", "get-url", "origin"]:
                return SimpleNamespace(stdout="git@github.com:owner/repository.git\n")
            if command[:3] == ["docker", "buildx", "version"]:
                return SimpleNamespace(stdout="docker buildx v0.17.0\n")
            if command[:3] == ["docker", "buildx", "inspect"]:
                return SimpleNamespace(stdout="Platforms: linux/amd64, linux/amd64/v2\n")
            if command[:3] == ["docker", "context", "inspect"]:
                return SimpleNamespace(stdout="unix:///private/tmp/kioku-docker.sock\n")
            if command[:2] == ["syft", "--version"]:
                return SimpleNamespace(stdout="syft 1.49.0\n")
            if command[:2] == ["grype", "--version"]:
                return SimpleNamespace(stdout="grype 0.116.0\n")
            if command[:2] == ["gcloud", "version"]:
                return SimpleNamespace(stdout="Google Cloud SDK 580.0.0\n")
            if command[0] == "syft":
                self.assertEqual(environment, {"DOCKER_HOST": "unix:///private/tmp/kioku-docker.sock"})
                self.assertTrue(command[1].startswith("docker:"))
                output = next(value for value in command if value.startswith("spdx-json="))
                Path(output.removeprefix("spdx-json=")).write_text(
                    json.dumps(
                        {"packages": [{"name": name} for name in pipeline.REQUIRED_SBOM_PACKAGES]}
                    ),
                    encoding="utf-8",
                )
                return SimpleNamespace(stdout="")
            if command[0] == "grype":
                return SimpleNamespace(stdout="{\"matches\": []}\n", stderr="")
            if command[0] == "docker" and "push" in command:
                return SimpleNamespace(stdout=f"digest: {digest} size: 123\n", stderr="")
            if command[0] == "gcloud" and command[-2:] == ["auth", "print-access-token"]:
                return SimpleNamespace(stdout="ya29." + "t" * 40 + "\n", stderr="")
            if command[0] == "gcloud" and "describe" in command:
                return SimpleNamespace(stdout=digest + "\n", stderr="")
            if command[:2] == [sys.executable, str(SCRIPTS / "check_voice_release_gate.py")]:
                return SimpleNamespace(stdout="owner_only_unvalidated\n")
            return SimpleNamespace(stdout="")

        original_run = pipeline.run
        original_verify = pipeline.verify
        original_login = pipeline.temporary_docker_login
        original_snapshot = pipeline.source_snapshot
        original_argv = sys.argv
        pipeline.run = fake_run
        pipeline.verify = lambda: calls.append(["verify"])
        pipeline.source_snapshot = lambda commit: nullcontext(ROOT)
        pipeline.temporary_docker_login = (
            lambda registry, docker_config, access_token: calls.append(
                ["temporary-docker-login", registry, str(docker_config), "token-redacted"]
            )
        )
        try:
            with tempfile.TemporaryDirectory() as temporary_directory:
                directory = Path(temporary_directory)
                config = directory / "operator.env"
                output = directory / "evidence"
                write_config(config)
                sys.argv = [
                    str(SCRIPTS / "local_image_pipeline.py"),
                    "push",
                    "--config",
                    str(config),
                    "--output-dir",
                    str(output),
                    "--apply",
                ]
                pipeline.main()
                evidence = json.loads((output / "build-evidence.json").read_text())
        finally:
            pipeline.run = original_run
            pipeline.verify = original_verify
            pipeline.temporary_docker_login = original_login
            pipeline.source_snapshot = original_snapshot
            sys.argv = original_argv

        self.assertFalse(evidence["signed"])
        self.assertEqual(evidence["image_digest"], digest)
        build = next(command for command in calls if command[:3] == ["docker", "buildx", "build"])
        self.assertIn("linux/amd64", build)
        self.assertIn("--load", build)
        self.assertIn("KIOKU_BUILD_PROFILE=production", build)
        self.assertIn("GCS_LEGACY_MEDIA_BUCKET=kioku-production-indexes", build)
        scan_index = next(index for index, command in enumerate(calls) if command and command[0] == "grype" and "sbom:" in command[1])
        auth_index = next(index for index, command in enumerate(calls) if command[:3] == ["gcloud", "--impersonate-service-account=local-builder@kioku-joerodriguez.iam.gserviceaccount.com", "auth"])
        login_index = next(index for index, command in enumerate(calls) if command[:1] == ["temporary-docker-login"])
        push_index = next(index for index, command in enumerate(calls) if command and command[0] == "docker" and "push" in command)
        self.assertLess(scan_index, auth_index)
        self.assertLess(auth_index, login_index)
        self.assertLess(login_index, push_index)
        self.assertNotIn("configure-docker", str(calls))
        self.assertNotIn("ya29.", str(calls))

    def test_preflight_rejects_builder_without_linux_amd64(self) -> None:
        pipeline = load_pipeline()

        def fake_run(command: list[str], *, capture: bool = False):
            if command[:3] == ["docker", "buildx", "version"]:
                return SimpleNamespace(stdout="docker buildx v0.36.1\n")
            if command[:3] == ["docker", "buildx", "inspect"]:
                return SimpleNamespace(stdout="Platforms: linux/arm64, linux/386\n")
            return SimpleNamespace(stdout="")

        with patch.object(pipeline, "run", side_effect=fake_run):
            with self.assertRaisesRegex(pipeline.PipelineError, "linux/amd64"):
                pipeline.preflight_tools(need_cloud=False)

    def test_non_preflight_stages_require_explicit_apply(self) -> None:
        pipeline = load_pipeline()
        with tempfile.TemporaryDirectory() as temporary_directory:
            config = Path(temporary_directory) / "operator.env"
            write_config(config)
            original_argv = sys.argv
            try:
                sys.argv = [
                    str(SCRIPTS / "local_image_pipeline.py"),
                    "verify",
                    "--config",
                    str(config),
                ]
                with self.assertRaises(SystemExit) as raised:
                    pipeline.main()
            finally:
                sys.argv = original_argv
        self.assertEqual(raised.exception.code, 1)

    def test_release_tag_coordinates_are_deterministic_and_release_evidence_is_requested(self) -> None:
        pipeline = load_pipeline()
        configuration = {
            "REGION": "us-central1",
            "PROJECT_ID": "kioku-joerodriguez",
            "AR_REPOSITORY": "kioku",
            "IMAGE_NAME": "kioku-enclave",
        }
        repository, image = pipeline.image_coordinates(
            configuration, "production", "c" * 40, "refs/tags/v1.2.3"
        )
        self.assertEqual(repository, "us-central1-docker.pkg.dev/kioku-joerodriguez/kioku/kioku-enclave")
        self.assertEqual(image, repository + ":v1.2.3")
        self.assertEqual(pipeline.release_tag("refs/tags/v1.2.3"), "v1.2.3")
        self.assertIsNone(pipeline.release_tag("main"))

        source = Path(pipeline.__file__).read_text(encoding="utf-8")
        self.assertIn("local_build_evidence.py", source)
        self.assertIn("enclave-local-build-evidence.json", source)
        self.assertIn("enclave-release.json", source)
        self.assertIn("schema_version\": 8", source)
        self.assertIn("enclave-scan.json", source)
        self.assertIn("with source_snapshot(commit) as snapshot", source)
        self.assertLess(source.index("sbom_and_scan(image_uri, output_dir)"), source.index("verify_source_unchanged(arguments.source_ref, commit)"))
        self.assertLess(source.index("verify_source_unchanged(arguments.source_ref, commit)"), source.index('if arguments.stage == "push":'))

    def test_build_source_must_be_clean_and_release_tag_must_equal_head(self) -> None:
        pipeline = load_pipeline()
        original_run = pipeline.run
        try:
            pipeline.run = lambda command, capture=False: SimpleNamespace(
                stdout="?? untracked\n" if command[:2] == ["git", "status"] else ""
            )
            with self.assertRaisesRegex(pipeline.PipelineError, "clean source tree"):
                pipeline.source_commit("refs/tags/v1.2.3")

            def mismatched(command, capture=False):
                if command[:2] == ["git", "status"]:
                    return SimpleNamespace(stdout="")
                if command[:3] == ["git", "rev-parse", "HEAD"]:
                    return SimpleNamespace(stdout="a" * 40 + "\n")
                if command[:3] == ["git", "log", "-1"]:
                    return SimpleNamespace(stdout="1700000000\n")
                if command[:3] == ["git", "rev-list", "-n"]:
                    return SimpleNamespace(stdout="b" * 40 + "\n")
                return SimpleNamespace(stdout="")

            pipeline.run = mismatched
            with self.assertRaisesRegex(pipeline.PipelineError, "resolve exactly to HEAD"):
                pipeline.source_commit("refs/tags/v1.2.3")
        finally:
            pipeline.run = original_run


if __name__ == "__main__":
    unittest.main()
