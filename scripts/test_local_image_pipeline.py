#!/usr/bin/env python3
"""Hermetic contracts for the local enclave image pipeline's safety boundaries."""

from __future__ import annotations

import importlib.util
import base64
from contextlib import nullcontext
from datetime import datetime, timedelta, timezone
import hashlib
import io
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import tarfile
from types import SimpleNamespace
import sys
import tempfile
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
sys.path.insert(0, str(SCRIPTS))
from test_select_build_configuration import environment  # noqa: E402

# The production verifier intentionally invokes this contract suite from a
# live builder environment. Fixtures must never inherit those coordinates;
# each test supplies every transport/config value it means to exercise.
for inherited_name in (
    "KIOKU_NATIVE_BUILDER_NAME",
    "KIOKU_NATIVE_BUILDER_ID",
    "DOCKER_HOST",
    "DOCKER_CONTEXT",
    "DOCKER_SSH_KNOWN_HOSTS",
    "DOCKER_SSH_HOST_KEY_SHA256",
    "DOCKER_SSH_COMMAND",
    "DOCKER_TLS_VERIFY",
    "DOCKER_CERT_PATH",
    "DOCKER_BUILDER_CA_SHA256",
    "SSH_AUTH_SOCK",
    "KIOKU_RELEASE_NATIVE_DOCKER_CONFIG",
    "KIOKU_RELEASE_NATIVE_BUILDX_CONFIG",
    "CLOUDSDK_CONFIG",
):
    os.environ.pop(inherited_name, None)


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
    values["PRODUCTION_VERTEX_RECONCILIATION_MODEL"] = "gemini-reconciliation-v1"
    values["PRODUCTION_MEMORY_RECONCILIATION_PRODUCER_CONTRACT_SHA256"] = (
        "sha256:" + "c" * 64
    )
    path.write_text(
        "\n".join(f"{name}={value}" for name, value in sorted(values.items())) + "\n",
        encoding="utf-8",
    )
    path.chmod(mode)


class LocalImagePipelineTests(unittest.TestCase):
    def test_main_enforces_private_umask_before_parsing_arguments(self) -> None:
        source = (SCRIPTS / "local_image_pipeline.py").read_text(encoding="utf-8")
        main_body = source.split("def main() -> None:", 1)[1]
        self.assertLess(
            main_body.index("os.umask(0o077)"),
            main_body.index("argparse.ArgumentParser"),
        )

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

    def test_documented_build_then_push_resume_preserves_build_evidence(self) -> None:
        pipeline = load_pipeline()
        calls: list[list[str]] = []
        manifest_bytes = b'{"schemaVersion":2}'
        digest = "sha256:" + hashlib.sha256(manifest_bytes).hexdigest()
        scan_database_version = [42]
        moments = iter(
            datetime(2026, 8, 28, 12, 0, tzinfo=timezone.utc)
            + timedelta(seconds=30 * index)
            for index in range(30)
        )

        class SequencedDateTime(datetime):
            @classmethod
            def now(cls, tz=None):
                value = next(moments)
                return value if tz is None else value.astimezone(tz)

        def write_fake_oci_archive(command: list[str]) -> None:
            output = next(value for value in command if value.startswith("type=oci,dest="))
            artifact = Path(output.removeprefix("type=oci,dest="))
            index = json.dumps(
                {
                    "schemaVersion": 2,
                    "manifests": [{"digest": digest, "size": len(manifest_bytes)}],
                },
                separators=(",", ":"),
            ).encode()
            with tarfile.open(artifact, "w") as archive:
                for name, data in (
                    ("index.json", index),
                    ("blobs/sha256/" + digest.removeprefix("sha256:"), manifest_bytes),
                ):
                    member = tarfile.TarInfo(name)
                    member.size = len(data)
                    archive.addfile(member, io.BytesIO(data))
            artifact.chmod(0o600)

        def fake_run(
            command: list[str],
            *,
            capture: bool = False,
            environment: dict[str, str] | None = None,
            pass_fds: tuple[int, ...] = (),
        ):
            calls.append(command)
            git_command = command[2:] if command[:2] == ["git", "--no-replace-objects"] else []
            if git_command[:2] == ["replace", "-l"]:
                return SimpleNamespace(stdout="", stderr="")
            if git_command[:4] == ["rev-parse", "--path-format=absolute", "--git-path", "info/grafts"]:
                return SimpleNamespace(stdout="/tmp/kioku-test-no-grafts\n", stderr="")
            if git_command[:2] == ["status", "--porcelain"]:
                return SimpleNamespace(stdout="", stderr="")
            if git_command[:2] == ["rev-parse", "HEAD"]:
                return SimpleNamespace(stdout="b" * 40 + "\n")
            if git_command[:2] == ["rev-list", "-n"]:
                return SimpleNamespace(stdout="b" * 40 + "\n")
            if git_command[:2] == ["log", "-1"]:
                return SimpleNamespace(stdout="1700000000\n")
            if git_command[:3] == ["remote", "get-url", "origin"]:
                return SimpleNamespace(stdout="git@github.com:owner/repository.git\n")
            if command[:3] == ["docker", "buildx", "version"]:
                return SimpleNamespace(stdout="docker buildx v0.17.0\n")
            if command[:3] == ["docker", "buildx", "ls"]:
                return SimpleNamespace(
                    stdout=json.dumps(
                        {
                            "Current": True,
                            "Name": "default",
                            "Nodes": [{"Name": "default0", "Endpoint": "unix:///private/tmp/kioku-docker.sock", "Status": "running", "Platforms": "linux/amd64"}],
                        }
                    ) + "\n"
                )
            if command[:3] == ["docker", "context", "inspect"]:
                return SimpleNamespace(stdout="unix:///private/tmp/kioku-docker.sock\n")
            if command[:3] == ["docker", "buildx", "build"]:
                write_fake_oci_archive(command)
                return SimpleNamespace(stdout="", stderr="")
            if command[:2] == ["skopeo", "--version"]:
                return SimpleNamespace(stdout="skopeo version 1.18.0\n")
            if command[:2] == ["syft", "--version"]:
                return SimpleNamespace(stdout="syft 1.49.0\n")
            if command[:2] == ["grype", "--version"]:
                return SimpleNamespace(stdout="grype 0.116.0\n")
            if command[:3] == ["grype", "db", "status"]:
                return SimpleNamespace(stdout=json.dumps({"version": scan_database_version[0], "valid": True, "checksum": "c" * 64, "source": "https://grype.anchore.io/databases/vulnerability-db/test", "built": "2026-08-28T11:59:00+00:00"}) + "\n")
            if command[:2] == ["gcloud", "version"]:
                return SimpleNamespace(
                    stdout="Google Cloud SDK 580.0.0\nbq 2.1.23\ngsutil 5.36\n"
                )
            if command[0] == "syft":
                self.assertIsNone(environment)
                self.assertTrue(command[1].startswith("oci-archive:"))
                output = next(value for value in command if value.startswith("spdx-json="))
                Path(output.removeprefix("spdx-json=")).write_text(
                    json.dumps(
                        {"packages": [
                            {
                                "name": name,
                                **({
                                    "versionInfo": pipeline.tomllib.loads(
                                        (ROOT / "Cargo.toml").read_text(encoding="utf-8")
                                    )["package"]["version"]
                                } if name == "kioku-enclave" else {}),
                            }
                            for name in pipeline.REQUIRED_SBOM_PACKAGES
                        ]}
                    ),
                    encoding="utf-8",
                )
                return SimpleNamespace(stdout="")
            if command[0] == "grype":
                return SimpleNamespace(stdout="{\"matches\": []}\n", stderr="")
            if command[:2] == ["skopeo", "copy"]:
                self.assertIsNone(environment)
                self.assertEqual(len(pass_fds), 1)
                self.assertEqual(command[-2], f"oci-archive:/dev/fd/{pass_fds[0]}")
                self.assertEqual(
                    pipeline.oci_archive_manifest_digest_fd(pass_fds[0], mode=0o400),
                    digest,
                )
                digest_file = Path(command[command.index("--digestfile") + 1])
                digest_file.write_text(digest + "\n", encoding="ascii")
                digest_file.chmod(0o600)
                return SimpleNamespace(stdout="", stderr="")
            if command[0] == "gcloud" and command[-2:] == ["auth", "print-access-token"]:
                return SimpleNamespace(stdout="ya29." + "t" * 40 + "\n", stderr="")
            if command[0] == "gcloud" and "describe" in command:
                return SimpleNamespace(stdout=digest + "\n", stderr="")
            if command[:2] == [sys.executable, str(SCRIPTS / "check_voice_release_gate.py")]:
                return SimpleNamespace(stdout="owner_only_unvalidated\n")
            if command[:2] == [sys.executable, str(SCRIPTS / "local_build_evidence.py")]:
                output = Path(command[command.index("--output") + 1])
                output.write_text("{}\n", encoding="utf-8")
                output.chmod(0o600)
                return SimpleNamespace(stdout="")
            return SimpleNamespace(stdout="")

        original_run = pipeline.run
        original_verify = pipeline.verify
        original_login = pipeline.temporary_docker_login
        original_snapshot = pipeline.source_snapshot
        original_archive_digest = pipeline.immutable_source_archive_digest
        original_subset_digest = pipeline.immutable_source_subset_digest
        original_create_evidence = pipeline.create_release_evidence
        original_validate_resume_evidence = pipeline.validate_resume_evidence
        original_datetime = pipeline.datetime
        original_argv = sys.argv
        pipeline.run = fake_run
        pipeline.verify = lambda: calls.append(["verify"])
        pipeline.datetime = SequencedDateTime
        pipeline.source_snapshot = lambda commit, **kwargs: nullcontext(ROOT)
        pipeline.immutable_source_archive_digest = lambda commit: "d" * 64
        subset_digest_calls: list[tuple[str, ...]] = []

        def fake_subset_digest(commit: str, *paths: str) -> str:
            subset_digest_calls.append(paths)
            return "e" * 64 if paths == ("Cargo.toml", "Cargo.lock") else "f" * 64

        pipeline.immutable_source_subset_digest = fake_subset_digest
        pipeline.validate_resume_evidence = lambda *args, **kwargs: (
            calls.append(["validate-resume-evidence", kwargs["requested_stage"]]),
            original_validate_resume_evidence(*args, **kwargs),
        )[-1]
        pipeline.temporary_docker_login = (
            lambda registry, docker_config, access_token: (
                calls.append(["temporary-docker-login", registry, str(docker_config), "token-redacted"]),
                (docker_config / "config.json").write_text("{}\n", encoding="utf-8"),
                (docker_config / "config.json").chmod(0o600),
            )[-1]
        )
        try:
            with tempfile.TemporaryDirectory() as temporary_directory:
                directory = Path(temporary_directory)
                config = directory / "operator.env"
                output = directory / "evidence"
                write_config(config)
                common_arguments = [
                    str(SCRIPTS / "local_image_pipeline.py"),
                    "--config",
                    str(config),
                    "--output-dir",
                    str(output),
                    "--source-ref",
                    "refs/tags/v1.2.3",
                    "--apply",
                    "--allow-emulated-fallback",
                    "--confirm-emulated-release",
                ]
                docker_config = directory / "docker-config"
                buildx_config = directory / "buildx-config"
                cloud_config = directory / "cloud-config"
                docker_config.mkdir(mode=0o700)
                buildx_config.mkdir(mode=0o700)
                cloud_config.mkdir(mode=0o700)
                with patch.dict(pipeline.os.environ, {
                    "KIOKU_RELEASE_NATIVE_DOCKER_CONFIG": str(docker_config),
                    "KIOKU_RELEASE_NATIVE_BUILDX_CONFIG": str(buildx_config),
                    "CLOUDSDK_CONFIG": str(cloud_config),
                }, clear=False):
                    pipeline.os.environ.pop("SSH_AUTH_SOCK", None)
                    sys.argv = [common_arguments[0], "build", *common_arguments[1:]]
                    pipeline.main()
                    build_evidence = (output / "build-evidence.json").read_bytes()
                    scan_outputs_before_resume = {
                        name: (output / name).read_bytes()
                        for name in ("enclave-sbom.spdx.json", "enclave-scan.json")
                    }
                    sys.argv = [common_arguments[0], "push", *common_arguments[1:], "--resume"]
                    scan_database_version[0] = 43
                    calls_before_scan_miss = len(calls)
                    with self.assertRaises(SystemExit) as raised:
                        pipeline.main()
                    self.assertEqual(raised.exception.code, 1)
                    scan_miss_calls = calls[calls_before_scan_miss:]
                    self.assertEqual(
                        {
                            name: (output / name).read_bytes()
                            for name in ("enclave-sbom.spdx.json", "enclave-scan.json")
                        },
                        scan_outputs_before_resume,
                    )
                    self.assertFalse(
                        any(
                            command[:1] == ["syft"]
                            and len(command) > 1
                            and command[1] != "--version"
                            for command in scan_miss_calls
                        )
                    )
                    self.assertFalse(
                        any(
                            command[:1] == ["grype"]
                            and len(command) > 1
                            and command[1].startswith("sbom:")
                            for command in scan_miss_calls
                        )
                    )
                    self.assertFalse(
                        any(
                            command[0] == "gcloud"
                            and command[-2:] == ["auth", "print-access-token"]
                            for command in scan_miss_calls
                        )
                    )
                    self.assertFalse(
                        any(command[:2] == ["skopeo", "copy"] for command in scan_miss_calls)
                    )
                    scan_database_version[0] = 42
                    pipeline.main()
                    evidence_path = output / "build-evidence.json"
                    evidence = json.loads(evidence_path.read_text())
                    self.assertEqual(evidence_path.read_bytes(), build_evidence)
                    push_receipts = pipeline.stage_receipt_candidates(output, "push")
                    self.assertEqual(len(push_receipts), 1)
                    push_outputs = push_receipts[0]["outputs"]
                    self.assertIsInstance(push_outputs, dict)
                    self.assertEqual(push_outputs["image_digest"], digest)

                    def output_snapshot() -> dict[str, tuple[bytes, str]]:
                        return {
                            path.name: (
                                path.read_bytes(),
                                hashlib.sha256(path.read_bytes()).hexdigest(),
                            )
                            for path in output.iterdir()
                            if path.name != ".run.lock" and path.is_file()
                        }

                    outputs_before_second_resume = output_snapshot()
                    calls_before_second_resume = len(calls)
                    pipeline.main()
                    second_resume_calls = calls[calls_before_second_resume:]
                    self.assertEqual(output_snapshot(), outputs_before_second_resume)
                    self.assertFalse(
                        any(command[:2] == ["skopeo", "copy"] for command in second_resume_calls)
                    )
                    self.assertFalse(
                        any(
                            command[:2]
                            == [sys.executable, str(SCRIPTS / "local_build_evidence.py")]
                            for command in second_resume_calls
                        )
                    )
                    impersonated_second_resume = [
                        command
                        for command in second_resume_calls
                        if command[:1] == ["gcloud"]
                        and len(command) > 1
                        and command[1].startswith("--impersonate-service-account=")
                    ]
                    self.assertEqual(len(impersonated_second_resume), 1)
                    self.assertIn("describe", impersonated_second_resume[0])

                    manifest_path = output / "enclave-local-build-evidence.json"
                    manifest_bytes = manifest_path.read_bytes()
                    manifest_path.unlink()
                    calls_before_invalid_evidence_receipt = len(calls)
                    with self.assertRaises(SystemExit) as raised:
                        pipeline.main()
                    self.assertEqual(raised.exception.code, 1)
                    invalid_evidence_calls = calls[calls_before_invalid_evidence_receipt:]
                    self.assertFalse(manifest_path.exists())
                    self.assertFalse(
                        any(
                            command[:1] == ["gcloud"]
                            and len(command) > 1
                            and command[1].startswith("--impersonate-service-account=")
                            for command in invalid_evidence_calls
                        )
                    )
                    self.assertFalse(
                        any(command[:2] == ["skopeo", "copy"] for command in invalid_evidence_calls)
                    )
                    self.assertFalse(
                        any(
                            command[:2]
                            == [sys.executable, str(SCRIPTS / "local_build_evidence.py")]
                            for command in invalid_evidence_calls
                        )
                    )
                    manifest_path.write_bytes(manifest_bytes)
                    manifest_path.chmod(0o600)

                    evidence_receipt_path = next(output.glob("evidence-receipt-*.json"))
                    evidence_receipt_bytes = evidence_receipt_path.read_bytes()
                    evidence_receipt_path.unlink()
                    calls_before_orphan_final_outputs = len(calls)
                    with self.assertRaises(SystemExit) as raised:
                        pipeline.main()
                    self.assertEqual(raised.exception.code, 1)
                    orphan_final_calls = calls[calls_before_orphan_final_outputs:]
                    self.assertEqual(manifest_path.read_bytes(), manifest_bytes)
                    self.assertFalse(
                        any(
                            command[:1] == ["gcloud"]
                            and len(command) > 1
                            and command[1].startswith("--impersonate-service-account=")
                            for command in orphan_final_calls
                        )
                    )
                    self.assertFalse(
                        any(command[:2] == ["skopeo", "copy"] for command in orphan_final_calls)
                    )
                    self.assertFalse(
                        any(
                            command[:2]
                            == [sys.executable, str(SCRIPTS / "local_build_evidence.py")]
                            for command in orphan_final_calls
                        )
                    )
                    evidence_receipt_path.write_bytes(evidence_receipt_bytes)
                    evidence_receipt_path.chmod(0o600)

                    push_receipt_path = next(output.glob("push-receipt-*.json"))
                    push_receipt_bytes = push_receipt_path.read_bytes()
                    push_receipt_path.write_bytes(push_receipt_bytes + b" ")
                    calls_before_invalid_push_receipt = len(calls)
                    with self.assertRaises(SystemExit) as raised:
                        pipeline.main()
                    self.assertEqual(raised.exception.code, 1)
                    invalid_push_calls = calls[calls_before_invalid_push_receipt:]
                    self.assertFalse(
                        any(
                            command[:1] == ["gcloud"]
                            and len(command) > 1
                            and command[1].startswith("--impersonate-service-account=")
                            for command in invalid_push_calls
                        )
                    )
                    self.assertFalse(
                        any(command[:2] == ["skopeo", "copy"] for command in invalid_push_calls)
                    )
                    push_receipt_path.write_bytes(push_receipt_bytes)

                    evidence_path.unlink()
                    calls_before_missing_evidence = len(calls)
                    with self.assertRaises(SystemExit) as raised:
                        pipeline.main()
                    self.assertEqual(raised.exception.code, 1)
                    missing_evidence_calls = calls[calls_before_missing_evidence:]
                    self.assertFalse(evidence_path.exists())
                    self.assertFalse(
                        any(
                            command[:1] == ["gcloud"]
                            and len(command) > 1
                            and command[1].startswith("--impersonate-service-account=")
                            for command in missing_evidence_calls
                        )
                    )
                    self.assertFalse(
                        any(command[:2] == ["skopeo", "copy"] for command in missing_evidence_calls)
                    )
                    evidence_path.write_bytes(build_evidence)
                    evidence_path.chmod(0o600)

                    for field, value in (
                        ("created_at", "2026-08-28T12:00:01Z"),
                        ("completed_at", "2026-08-28T12:01:01Z"),
                    ):
                        with self.subTest(field=field):
                            timestamp_poisoned = dict(evidence, **{field: value})
                            evidence_path.write_text(
                                json.dumps(timestamp_poisoned, sort_keys=True, indent=2) + "\n",
                                encoding="utf-8",
                            )
                            calls_before_timestamp_poison = len(calls)
                            with self.assertRaises(SystemExit) as raised:
                                pipeline.main()
                            self.assertEqual(raised.exception.code, 1)
                            timestamp_poison_calls = calls[calls_before_timestamp_poison:]
                            self.assertFalse(
                                any(
                                    command[:1] == ["gcloud"]
                                    and len(command) > 1
                                    and command[1].startswith("--impersonate-service-account=")
                                    for command in timestamp_poison_calls
                                )
                            )
                            self.assertFalse(
                                any(
                                    command[:2] == ["skopeo", "copy"]
                                    for command in timestamp_poison_calls
                                )
                            )
                            evidence_path.write_bytes(build_evidence)

                    calls_before_poisoned_resume = len(calls)
                    poisoned = dict(evidence, source_commit="9" * 40)
                    evidence_path.write_text(
                        json.dumps(poisoned, sort_keys=True, indent=2) + "\n",
                        encoding="utf-8",
                    )
                    with self.assertRaises(SystemExit) as raised:
                        pipeline.main()
                    self.assertEqual(raised.exception.code, 1)
                    poisoned_resume_calls = calls[calls_before_poisoned_resume:]
        finally:
            pipeline.run = original_run
            pipeline.verify = original_verify
            pipeline.temporary_docker_login = original_login
            pipeline.source_snapshot = original_snapshot
            pipeline.immutable_source_archive_digest = original_archive_digest
            pipeline.immutable_source_subset_digest = original_subset_digest
            pipeline.create_release_evidence = original_create_evidence
            pipeline.validate_resume_evidence = original_validate_resume_evidence
            pipeline.datetime = original_datetime
            sys.argv = original_argv

        self.assertFalse(evidence["signed"])
        self.assertNotIn("image_digest", evidence)
        self.assertEqual(evidence["created_at"], "2026-08-28T12:00:00Z")
        self.assertFalse(
            any(
                command[0] == "gcloud" and command[-2:] == ["auth", "print-access-token"]
                for command in poisoned_resume_calls
            )
        )
        self.assertFalse(
            any(command[:2] == ["skopeo", "copy"] for command in poisoned_resume_calls)
        )
        self.assertEqual(
            len([command for command in calls if command[:3] == ["docker", "buildx", "build"]]),
            1,
        )
        build = next(command for command in calls if command[:3] == ["docker", "buildx", "build"])
        self.assertIn("linux/amd64", build)
        self.assertIn("--output", build)
        self.assertTrue(any(argument.startswith("type=oci,dest=") for argument in build))
        self.assertNotIn("--load", build)
        self.assertTrue(any(argument.startswith("CONFIG_SHA256=") for argument in build))
        self.assertIn("CARGO_INPUTS_SHA256=" + "e" * 64, build)
        self.assertIn("SOURCE_INPUTS_SHA256=" + "f" * 64, build)
        self.assertIn(("src", "migrations"), subset_digest_calls)
        self.assertFalse(any(argument.startswith("SOURCE_DATE_EPOCH=") for argument in build))
        self.assertIn("--secret", build)
        self.assertIn("id=kioku-config,src=", " ".join(build))
        self.assertFalse(any("GCS_" in argument for argument in build))
        scan_index = next(index for index, command in enumerate(calls) if command and command[0] == "grype" and "sbom:" in command[1])
        auth_index = next(index for index, command in enumerate(calls) if command[:3] == ["gcloud", "--impersonate-service-account=local-builder@kioku-joerodriguez.iam.gserviceaccount.com", "auth"])
        validation_index = next(index for index, command in enumerate(calls) if command[:1] == ["validate-resume-evidence"])
        login_index = next(index for index, command in enumerate(calls) if command[:1] == ["temporary-docker-login"])
        push_index = next(index for index, command in enumerate(calls) if command[:2] == ["skopeo", "copy"])
        self.assertLess(scan_index, auth_index)
        self.assertLess(validation_index, auth_index)
        self.assertLess(auth_index, login_index)
        self.assertLess(login_index, push_index)
        evidence_command = next(
            command
            for command in calls
            if command[:2] == [sys.executable, str(SCRIPTS / "local_build_evidence.py")]
        )
        self.assertIn("gcloud=Google Cloud SDK 580.0.0", evidence_command)
        self.assertEqual(
            evidence_command[evidence_command.index("--created-at") + 1],
            "2026-08-28T12:02:30Z",
        )
        self.assertEqual(
            evidence_command[evidence_command.index("--image-digest") + 1],
            digest,
        )
        self.assertIn("--expected-sbom-sha256", evidence_command)
        self.assertIn("--expected-scan-sha256", evidence_command)
        self.assertFalse(any("\n" in argument for argument in evidence_command))
        self.assertNotIn("configure-docker", str(calls))
        self.assertNotIn("ya29.", str(calls))

        dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")
        self.assertLess(dockerfile.index("ARG CARGO_INPUTS_SHA256"), dockerfile.index("COPY Cargo.toml Cargo.lock"))
        self.assertLess(dockerfile.index("ARG SOURCE_INPUTS_SHA256"), dockerfile.index("COPY src ./src"))
        self.assertLess(dockerfile.index("ARG SOURCE_INPUTS_SHA256"), dockerfile.index("COPY migrations ./migrations"))
        dockerignore = (ROOT / ".dockerignore").read_text(encoding="utf-8")
        self.assertIn("!migrations/**", dockerignore)

    def test_preflight_rejects_builder_without_linux_amd64(self) -> None:
        pipeline = load_pipeline()

        def fake_run(command: list[str], *, capture: bool = False):
            if command[:3] == ["docker", "buildx", "version"]:
                return SimpleNamespace(stdout="docker buildx v0.36.1\n")
            if command[:3] == ["docker", "buildx", "ls"]:
                return SimpleNamespace(
                    stdout=json.dumps(
                        {
                            "Current": True,
                            "Name": "default",
                            "Nodes": [{"Name": "default0", "Platforms": "linux/arm64,linux/386"}],
                        }
                    ) + "\n"
                )
            return SimpleNamespace(stdout="")

        with patch.object(pipeline, "run", side_effect=fake_run):
            with self.assertRaisesRegex(pipeline.PipelineError, "linux/amd64"):
                pipeline.preflight_tools(need_cloud=False)

    def test_buildx_worker_probe_uses_supported_ls_json_not_inspect_format(self) -> None:
        pipeline = load_pipeline()
        calls: list[list[str]] = []

        def fake_run(command: list[str], **kwargs):
            calls.append(command)
            if command[:3] == ["docker", "buildx", "ls"]:
                return SimpleNamespace(
                    stdout=json.dumps(
                        {
                            "Name": "reviewed-builder",
                            "Nodes": [{"Name": "worker0"}],
                        }
                    )
                )
            raise AssertionError(command)

        with patch.object(pipeline, "run", side_effect=fake_run):
            self.assertEqual(
                pipeline.selected_buildx_nodes("reviewed-builder"),
                [{"Name": "worker0"}],
            )
        self.assertEqual(
            calls,
            [["docker", "buildx", "ls", "--no-trunc", "--format", "{{json .}}"]],
        )
        source = Path(pipeline.__file__).read_text(encoding="utf-8")
        self.assertNotIn('"buildx", "inspect"', source)
        self.assertNotIn('"--format", "{{json .Nodes}}"', source)

    def test_buildx_worker_probe_collapses_only_identical_cli_duplicates(self) -> None:
        pipeline = load_pipeline()
        builder = {
            "Name": "reviewed-builder",
            "Nodes": [{"Name": "worker0", "Endpoint": "ssh://builder.example"}],
        }
        with patch.object(
            pipeline,
            "buildx_ls_entries",
            return_value=[builder, json.loads(json.dumps(builder))],
        ):
            self.assertEqual(
                pipeline.selected_buildx_nodes("reviewed-builder"),
                builder["Nodes"],
            )

        conflicting = json.loads(json.dumps(builder))
        conflicting["Nodes"][0]["Endpoint"] = "ssh://other.example"
        with patch.object(
            pipeline,
            "buildx_ls_entries",
            return_value=[builder, conflicting],
        ):
            with self.assertRaisesRegex(pipeline.PipelineError, "exactly one"):
                pipeline.selected_buildx_nodes("reviewed-builder")

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
                    "--source-ref",
                    "main",
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
        self.assertIn('"schema_version": 12', source)
        self.assertIn("enclave-scan.json", source)
        self.assertIn("source_snapshot(commit, expected_archive_digest=", source)
        self.assertLess(source.index("sbom_and_scan(image_uri, output_dir)"), source.index("verify_source_unchanged(arguments.source_ref, commit)"))
        self.assertLess(source.index("verify_source_unchanged(arguments.source_ref, commit)"), source.index('if arguments.stage == "push":'))

    def test_runtime_config_is_allowlisted_and_docker_uses_ephemeral_secret(self) -> None:
        pipeline = load_pipeline()
        values = environment()
        configuration = pipeline.selected_configuration(
            "production",
            values,
            source_ref="main",
        )
        runtime = pipeline.runtime_config(configuration, "production")
        self.assertEqual(runtime["KMS_PROJECT"], values["PRODUCTION_ENCLAVE_KMS_PROJECT"])
        self.assertEqual(
            runtime["GCS_MEDIA_BUCKET"],
            values["PRODUCTION_ENCLAVE_GCS_MEDIA_BUCKET"],
        )
        self.assertNotIn("POSTGRES_SCHEMA_MODE", runtime)
        self.assertNotIn("PROJECT_ID", runtime)
        self.assertEqual(
            runtime["SCHEMA_FINALIZATION_PUBLIC_KEY_SHA256"],
            values["PRODUCTION_SCHEMA_FINALIZATION_PUBLIC_KEY_SHA256"],
        )
        dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")
        self.assertIn("RUN --mount=type=secret,id=kioku-config,required", dockerfile)
        self.assertNotIn("ENV KMS_PROJECT=${KMS_PROJECT}", dockerfile)
        pipeline_source = Path(pipeline.__file__).read_text(encoding="utf-8")
        self.assertIn('"--digestfile"', pipeline_source)
        self.assertIn('"--preserve-digests"', pipeline_source)
        self.assertIn("oci_archive_manifest_digest", pipeline_source)
        self.assertIn("auth_file", pipeline_source)

    def test_baked_configuration_key_sets_match_and_assembler_requires_all_keys(self) -> None:
        rust_source = (ROOT / "src" / "main.rs").read_text(encoding="utf-8")
        rust_match = re.search(
            r"const BAKED_IMAGE_CONFIGURATION_KEYS: &\[&str\] = &\[(?P<body>.*?)\];",
            rust_source,
            re.DOTALL,
        )
        self.assertIsNotNone(rust_match)
        rust_keys = re.findall(r'"([A-Z][A-Z0-9_]*)"', rust_match.group("body"))

        assembler_source = (SCRIPTS / "assemble_image_config.sh").read_text(encoding="utf-8")
        assembler_match = re.search(r"(?m)^allowed_keys='([^']+)'$", assembler_source)
        self.assertIsNotNone(assembler_match)
        assembler_keys = assembler_match.group(1).split()
        self.assertEqual(assembler_keys, rust_keys)
        self.assertEqual(len(assembler_keys), len(set(assembler_keys)))
        self.assertIn("for required in $allowed_keys; do", assembler_source)
        self.assertIn("SCHEMA_FINALIZATION_PUBLIC_KEY_DER_BASE64", assembler_keys)
        self.assertIn("SCHEMA_FINALIZATION_PUBLIC_KEY_SHA256", assembler_keys)
        self.assertIn('sha256sum "$key_tmp"', assembler_source)
        for obsolete in (
            "PERSISTENCE_BACKEND",
            "POSTGRES_SCHEMA_MODE",
            "GCS_BUCKET",
            "GCS_LEGACY_MEDIA_BUCKET",
        ):
            self.assertNotIn(obsolete, assembler_keys)

    def test_baked_configuration_load_precedes_tokio_and_no_runtime_env_mutation(self) -> None:
        source = (ROOT / "src" / "main.rs").read_text(encoding="utf-8")
        self.assertNotIn("#[tokio::main]", source)
        load_call = source.index("    load_baked_image_configuration();")
        runtime_builder = source.index("tokio::runtime::Builder::new_multi_thread()")
        async_main = source.index("async fn async_main()")
        self.assertLess(load_call, runtime_builder)
        self.assertLess(runtime_builder, async_main)
        self.assertIn("runtime.block_on(async_main());", source)
        for mutation in ("std::env::set_var", "std::env::remove_var"):
            for match in re.finditer(re.escape(mutation), source):
                self.assertLess(match.start(), async_main, f"{mutation} occurs after runtime startup")

    def test_receipts_are_content_addressed_and_input_bound(self) -> None:
        pipeline = load_pipeline()
        with tempfile.TemporaryDirectory() as temporary_directory:
            directory = Path(temporary_directory)
            inputs = {"source_commit": "a" * 40, "config_sha256": "b" * 64}
            receipt = pipeline.write_stage_receipt(directory, "push", inputs, {"image_digest": "sha256:" + "c" * 64})
            self.assertRegex(receipt.name, r"^push-receipt-[0-9a-f]{64}\.json$")
            self.assertIsNotNone(pipeline.valid_stage_receipt(directory, "push", inputs))
            self.assertIsNone(pipeline.valid_stage_receipt(directory, "push", {**inputs, "source_commit": "d" * 40}))

    def test_resume_direction_is_forward_only_after_push_receipt(self) -> None:
        pipeline = load_pipeline()
        with tempfile.TemporaryDirectory() as temporary_directory:
            directory = Path(temporary_directory)
            pipeline.write_stage_receipt(
                directory,
                "push",
                {"source_commit": "a" * 40},
                {"image_digest": "sha256:" + "c" * 64},
            )
            pipeline.validate_resume_direction(directory, "push")
            with self.assertRaisesRegex(pipeline.PipelineError, "cannot resume build"):
                pipeline.validate_resume_direction(directory, "build")
        for stage in ("push", "evidence"):
            with self.subTest(stage=stage), tempfile.TemporaryDirectory() as temporary_directory:
                directory = Path(temporary_directory)
                malformed = directory / f"{stage}-receipt-{'f' * 64}.json"
                malformed.write_text("not-json\n", encoding="utf-8")
                malformed.chmod(0o600)
                pipeline.validate_resume_direction(directory, "push")
                with self.assertRaisesRegex(pipeline.PipelineError, "cannot resume build"):
                    pipeline.validate_resume_direction(directory, "build")

    def test_receipt_symlink_and_lock_poisoning_are_rejected(self) -> None:
        pipeline = load_pipeline()
        with tempfile.TemporaryDirectory() as temporary_directory:
            directory = Path(temporary_directory)
            inputs = {"source_commit": "a" * 40}
            receipt = pipeline.write_stage_receipt(
                directory, "push", inputs, {"image_digest": "sha256:" + "c" * 64}
            )
            poisoned = directory / ("push-receipt-" + "f" * 64 + ".json")
            poisoned.symlink_to(receipt)
            self.assertIsNotNone(pipeline.valid_stage_receipt(directory, "push", inputs))
            receipt.unlink()
            self.assertIsNone(pipeline.valid_stage_receipt(directory, "push", inputs))
            lock = pipeline.acquire_run_lock(directory)
            try:
                with self.assertRaisesRegex(pipeline.PipelineError, "output lock"):
                    pipeline.acquire_run_lock(directory)
            finally:
                pipeline.release_run_lock(lock)

    def test_grype_database_requires_valid_checksum_and_anchore_source(self) -> None:
        pipeline = load_pipeline()
        original_run = pipeline.run
        try:
            for status in (
                {"valid": False, "version": 1, "checksum": "a" * 64, "source": "https://grype.anchore.io/db", "built": datetime.now(timezone.utc).isoformat()},
                {"valid": True, "version": 1, "source": "https://grype.anchore.io/db", "built": datetime.now(timezone.utc).isoformat()},
                {"valid": True, "version": 1, "checksum": "a" * 64, "source": "https://example.invalid/db", "built": datetime.now(timezone.utc).isoformat()},
            ):
                pipeline.run = lambda command, **kwargs: SimpleNamespace(stdout=json.dumps(status) + "\n")
                with self.assertRaises(pipeline.PipelineError):
                    pipeline.scan_database_identity()
        finally:
            pipeline.run = original_run

    def test_grype_v6_database_accepts_checksum_bound_in_trusted_source_url(self) -> None:
        pipeline = load_pipeline()
        original_run = pipeline.run
        checksum = "b" * 64
        status = {
            "valid": True,
            "schemaVersion": "v6.1.9",
            "from": (
                "https://grype.anchore.io/databases/v6/vulnerability-db.tar.zst"
                f"?checksum=sha256%3A{checksum}"
            ),
            "built": datetime.now(timezone.utc).isoformat(),
        }
        try:
            pipeline.run = lambda command, **kwargs: SimpleNamespace(stdout=json.dumps(status) + "\n")
            identity = pipeline.scan_database_identity()
        finally:
            pipeline.run = original_run
        self.assertEqual(identity["checksum"], f"sha256:{checksum}")
        self.assertEqual(identity["source"], status["from"])

    def test_public_evidence_rejects_host_local_path_variants(self) -> None:
        pipeline = load_pipeline()
        leaked_values = (
            "/Users/alice/private/evidence.json",
            "/home/alice/private/evidence.json",
            "/root/private/evidence.json",
            r"C:\Users\alice\private\evidence.json",
            r"\\fileserver\release\private\evidence.json",
            "%2FUsers%2Falice%2Fprivate%2Fevidence.json",
            "%2Froot%2Fprivate%2Fevidence.json",
            "C%3A%5CUsers%5Calice%5Cprivate%5Cevidence.json",
            "C-%5CUsers%5Calice%5Cprivate%5Cevidence.json",
            "%5C%5Cfileserver%5Crelease%5Cprivate%5Cevidence.json",
            "DocumentRoot-Image--Users-alice-private-evidence-json",
            "DocumentRoot-Image--home-alice-private-evidence-json",
            "DocumentRoot-Image--root-private-evidence-json",
            "DocumentRoot-Image-C--Users-alice-private-evidence-json",
            "DocumentRoot-Image---fileserver-release-private-evidence-json",
            "/private/var/folders/ab/transient/evidence.json",
            "%2Fprivate%2Ftmp%2Ftransient%2Fevidence.json",
        )
        for leaked in leaked_values:
            with self.subTest(leaked=leaked), self.assertRaisesRegex(
                pipeline.PipelineError, "host-local path"
            ):
                pipeline.assert_public_evidence_document({"nested": [leaked]}, "test asset")

    def test_sbom_and_scan_publish_only_stable_source_coordinates(self) -> None:
        pipeline = load_pipeline()
        image_uri = "registry.example/kioku/enclave:v1.2.3"
        original_run = pipeline.run
        calls: list[list[str]] = []

        def fake_run(command: list[str], **kwargs):
            calls.append(command)
            if command[0] == "syft":
                output = next(value for value in command if value.startswith("spdx-json="))
                Path(output.removeprefix("spdx-json=")).write_text(
                    json.dumps(
                        {
                            "spdxVersion": "SPDX-2.3",
                            "name": image_uri,
                            "packages": [
                                {
                                    "name": name,
                                    **(
                                        {
                                            "versionInfo": pipeline.tomllib.loads(
                                                (ROOT / "Cargo.toml").read_text(encoding="utf-8")
                                            )["package"]["version"]
                                        }
                                        if name == "kioku-enclave"
                                        else {}
                                    ),
                                }
                                for name in pipeline.REQUIRED_SBOM_PACKAGES
                            ],
                        }
                    ),
                    encoding="utf-8",
                )
                return SimpleNamespace(stdout="", stderr="")
            if command[0] == "grype":
                return SimpleNamespace(
                    stdout=json.dumps(
                        {
                            "matches": [],
                            "source": {"target": {"userInput": image_uri}},
                            "descriptor": {
                                "configuration": {"db": {"cache-dir": "/Users/alice/.cache/grype"}},
                                "db": {"status": {"path": "/home/alice/.cache/grype/vulnerability.db"}},
                            },
                        }
                    )
                    + "\n",
                    stderr="",
                )
            raise AssertionError(command)

        try:
            pipeline.run = fake_run
            with tempfile.TemporaryDirectory() as temporary_directory:
                output = Path(temporary_directory)
                result = pipeline.sbom_and_scan(
                    image_uri,
                    output,
                    artifact_ref="oci-archive:/Users/alice/private/kioku-enclave.oci.tar",
                )
                sbom = json.loads((output / "enclave-sbom.spdx.json").read_text(encoding="utf-8"))
                scan = json.loads((output / "enclave-scan.json").read_text(encoding="utf-8"))
                pipeline.assert_public_evidence_document(sbom, "SBOM")
                pipeline.assert_public_evidence_document(scan, "scan")
                self.assertNotIn("cache-dir", scan["descriptor"]["configuration"]["db"])
                self.assertNotIn("path", scan["descriptor"]["db"]["status"])
                self.assertRegex(result["sbom_sha256"], r"^[0-9a-f]{64}$")
                self.assertRegex(result["scan_sha256"], r"^[0-9a-f]{64}$")
        finally:
            pipeline.run = original_run

        syft = next(command for command in calls if command[0] == "syft")
        self.assertEqual(syft[syft.index("--source-name") + 1], image_uri)

    def test_source_snapshot_transport_timestamps_are_content_stable(self) -> None:
        pipeline = load_pipeline()
        with tempfile.TemporaryDirectory() as temporary_directory:
            context = Path(temporary_directory) / "context"
            nested = context / "src"
            nested.mkdir(parents=True)
            source = nested / "main.rs"
            source.write_text("fn main() {}\n")
            os.utime(source, (1_000_000, 1_000_000))
            os.utime(nested, (2_000_000, 2_000_000))
            os.utime(context, (3_000_000, 3_000_000))

            pipeline.normalize_source_snapshot_timestamps(context)

            first_content_timestamp = source.stat().st_mtime_ns
            self.assertGreater(first_content_timestamp, 0)
            self.assertEqual(nested.stat().st_mtime_ns, 0)
            self.assertEqual(context.stat().st_mtime_ns, 0)

            os.utime(source, (9_000_000, 9_000_000))
            pipeline.normalize_source_snapshot_timestamps(context)
            self.assertEqual(source.stat().st_mtime_ns, first_content_timestamp)

            source.write_text("fn noop() {}\n")
            self.assertEqual(len("fn noop() {}\n"), len("fn main() {}\n"))
            pipeline.normalize_source_snapshot_timestamps(context)
            self.assertNotEqual(source.stat().st_mtime_ns, first_content_timestamp)

    def test_remote_builder_disk_probe_is_pinned_and_rejects_low_space(self) -> None:
        pipeline = load_pipeline()
        total = 100 * 1024**3
        free = 70 * 1024**3
        output = "Filesystem 1024-blocks Used Available Capacity Mounted on\nworker %d %d %d 30%% /\n" % (
            total // 1024,
            (total - free) // 1024,
            free // 1024,
        )
        calls: list[list[str]] = []

        def fake_run(command: list[str], **kwargs):
            calls.append(command)
            self.assertEqual(command[:5], ["docker", "buildx", "build", "--builder", "reviewed-builder"])
            self.assertIn("--pull=false", command)
            self.assertIn("--output=type=cacheonly", command)
            dockerfile = Path(command[command.index("--file") + 1])
            self.assertIn(pipeline.NATIVE_DISK_PROBE_IMAGE, dockerfile.read_text(encoding="ascii"))
            return SimpleNamespace(stdout=output)

        with patch.object(pipeline, "run", side_effect=fake_run):
            observed_free, reserve, observed_total = pipeline.check_builder_disk_space("reviewed-builder")
        self.assertEqual((observed_free, reserve, observed_total), (free, 50 * 1024**3, total))
        self.assertNotIn(["docker", "run"], [call[:2] for call in calls])

        low_free = 10 * 1024**3
        low_output = "Filesystem 1024-blocks Used Available Capacity Mounted on\nworker %d %d %d 90%% /\n" % (
            total // 1024,
            (total - low_free) // 1024,
            low_free // 1024,
        )
        with patch.object(
            pipeline,
            "run",
            return_value=SimpleNamespace(stdout=low_output),
        ):
            with self.assertRaisesRegex(pipeline.PipelineError, "insufficient free space"):
                pipeline.check_builder_disk_space("reviewed-builder")

    def test_default_daemon_disk_output_cannot_satisfy_named_builder_probe(self) -> None:
        pipeline = load_pipeline()
        default_daemon_output = "Filesystem 1024-blocks Used Available Capacity Mounted on\nworker 100 30 70 30% /\n"

        def default_only(command: list[str], **kwargs):
            if command[:2] == ["docker", "run"]:
                return SimpleNamespace(stdout=default_daemon_output)
            raise pipeline.PipelineError("builder-scoped probe unavailable")

        with patch.object(pipeline, "run", side_effect=default_only):
            with self.assertRaisesRegex(pipeline.PipelineError, "builder-scoped probe unavailable"):
                pipeline.check_builder_disk_space("reviewed-builder")

    def test_ssh_builder_requires_the_pinned_host_key_and_strict_transport(self) -> None:
        pipeline = load_pipeline()
        with tempfile.TemporaryDirectory() as temporary_directory:
            known_hosts = Path(temporary_directory) / "known_hosts"
            key_blob = b"reviewed-builder-host-key"
            encoded_key = base64.b64encode(key_blob).decode("ascii")
            host_key = "SHA256:" + base64.b64encode(hashlib.sha256(key_blob).digest()).decode("ascii").rstrip("=")
            known_hosts.write_text(f"builder.example ssh-ed25519 {encoded_key}\n", encoding="ascii")
            known_hosts.chmod(0o600)

            def fake_run(command: list[str], **kwargs):
                if command[:3] == ["docker", "buildx", "ls"]:
                    self.assertEqual(command, ["docker", "buildx", "ls", "--no-trunc", "--format", "{{json .}}"])
                    return SimpleNamespace(
                        stdout=json.dumps(
                            {
                                "Name": "reviewed-builder",
                                "Nodes": [{
                                    "Name": "reviewed-builder0",
                                    "Endpoint": "ssh://builder.example",
                                    "Status": "running",
                                    "Platforms": "linux/amd64,linux/amd64/v2",
                                }],
                            }
                        )
                    )
                if command[:3] == ["docker", "--host", "ssh://builder.example"]:
                    self.assertEqual(command[3:5], ["info", "--format"])
                    return SimpleNamespace(stdout="builder-id Linux amd64\n")
                raise AssertionError(command)

            environment = {
                "KIOKU_NATIVE_BUILDER_NAME": "reviewed-builder",
                "KIOKU_NATIVE_BUILDER_ID": "builder-id",
                "DOCKER_SSH_KNOWN_HOSTS": str(known_hosts),
                "DOCKER_SSH_HOST_KEY_SHA256": host_key,
                "DOCKER_SSH_COMMAND": f"ssh -o StrictHostKeyChecking=yes -o UserKnownHostsFile={known_hosts}",
            }
            with patch.object(pipeline, "run", side_effect=fake_run), patch.dict(
                pipeline.os.environ, environment, clear=False
            ):
                self.assertTrue(pipeline.native_linux_builder())
                pipeline.os.environ["DOCKER_SSH_COMMAND"] = "ssh -o StrictHostKeyChecking=no"
                self.assertFalse(pipeline.native_linux_builder())

    def test_native_identity_rejects_multi_node_or_mismatched_default_endpoint(self) -> None:
        pipeline = load_pipeline()
        common = {
            "KIOKU_NATIVE_BUILDER_NAME": "reviewed-builder",
            "KIOKU_NATIVE_BUILDER_ID": "builder-id",
        }

        def fake_run(command: list[str], **kwargs):
            if command[:3] == ["docker", "buildx", "ls"]:
                return SimpleNamespace(
                    stdout=json.dumps({
                        "Name": "reviewed-builder", "Nodes": [
                            {
                                "Name": "reviewed-builder0",
                                "Endpoint": "ssh://builder.example",
                                "Status": "running",
                                "Platforms": "linux/amd64",
                            },
                            {
                                "Name": "reviewed-builder1",
                                "Endpoint": "ssh://other.example",
                                "Status": "running",
                                "Platforms": "linux/amd64",
                            },
                        ]
                    })
                )
            raise AssertionError(command)

        with patch.object(pipeline, "run", side_effect=fake_run), patch.dict(
            pipeline.os.environ, common, clear=False
        ):
            self.assertFalse(pipeline.native_linux_builder())

        def mismatched_endpoint(command: list[str], **kwargs):
            if command[:3] == ["docker", "buildx", "ls"]:
                return SimpleNamespace(
                    stdout=json.dumps({
                        "Name": "reviewed-builder", "Nodes": [{
                            "Name": "reviewed-builder0",
                            "Endpoint": "ssh://builder.example",
                            "Status": "running",
                            "Platforms": "linux/amd64",
                        }]
                    })
                )
            raise AssertionError(command)

        with patch.object(pipeline, "run", side_effect=mismatched_endpoint), patch.dict(
            pipeline.os.environ,
            {**common, "DOCKER_HOST": "ssh://unreviewed.example"},
            clear=False,
        ):
            self.assertFalse(pipeline.native_linux_builder())

    def test_existing_build_evidence_cannot_be_poisoned(self) -> None:
        pipeline = load_pipeline()
        with tempfile.TemporaryDirectory() as temporary_directory:
            path = Path(temporary_directory) / "build-evidence.json"
            evidence = {
                "schema_version": 1,
                "build_profile": "production",
                "source_ref": "main",
                "source_commit": "a" * 40,
                "image_uri": "example/image:tag",
                "source_archive_sha256": "b" * 64,
                "config_sha256": "c" * 64,
                "image_config_sha256": "d" * 64,
                "dockerfile_sha256": "e" * 64,
                "cargo_lock_sha256": "f" * 64,
                "builder_mode": "native-linux-amd64",
                "fallback": False,
                "created_at": "2026-08-15T00:00:00Z",
                "completed_at": "2026-08-15T00:00:00Z",
            }
            pipeline.write_evidence(path, evidence)
            poisoned = dict(evidence, source_commit="9" * 40)
            with self.assertRaisesRegex(pipeline.PipelineError, "does not match"):
                pipeline.write_evidence(path, poisoned)

    def test_oci_archive_manifest_is_exact_and_rejects_duplicate_members(self) -> None:
        pipeline = load_pipeline()
        with tempfile.TemporaryDirectory() as temporary_directory:
            archive_path = Path(temporary_directory) / "image.oci.tar"
            manifest = b"{}"
            digest = hashlib.sha256(manifest).hexdigest()
            index = json.dumps(
                {"schemaVersion": 2, "manifests": [{"digest": "sha256:" + digest, "size": len(manifest)}]},
                separators=(",", ":"),
            ).encode()
            with tarfile.open(archive_path, "w") as archive:
                for name, data in (
                    ("index.json", index),
                    ("blobs/sha256/" + digest, manifest),
                ):
                    member = tarfile.TarInfo(name)
                    member.size = len(data)
                    archive.addfile(member, io.BytesIO(data))
            archive_path.chmod(0o600)
            self.assertEqual(pipeline.oci_archive_manifest_digest(archive_path), "sha256:" + digest)

            duplicate_path = Path(temporary_directory) / "duplicate.oci.tar"
            with tarfile.open(duplicate_path, "w") as archive:
                for name, data in (("index.json", index), ("index.json", index)):
                    member = tarfile.TarInfo(name)
                    member.size = len(data)
                    archive.addfile(member, io.BytesIO(data))
            duplicate_path.chmod(0o600)
            with self.assertRaisesRegex(pipeline.PipelineError, "duplicate"):
                pipeline.oci_archive_manifest_digest(duplicate_path)

    def test_push_quarantines_scanned_archive_before_authentication(self) -> None:
        pipeline = load_pipeline()

        def write_oci(path: Path, manifest: bytes) -> str:
            digest = "sha256:" + hashlib.sha256(manifest).hexdigest()
            index = json.dumps(
                {"schemaVersion": 2, "manifests": [{"digest": digest, "size": len(manifest)}]},
                separators=(",", ":"),
            ).encode()
            with tarfile.open(path, "w") as archive:
                for name, data in (
                    ("index.json", index),
                    ("blobs/sha256/" + digest.removeprefix("sha256:"), manifest),
                ):
                    member = tarfile.TarInfo(name)
                    member.size = len(data)
                    archive.addfile(member, io.BytesIO(data))
            path.chmod(0o600)
            return digest

        calls: list[list[str]] = []
        with tempfile.TemporaryDirectory() as temporary_directory:
            directory = Path(temporary_directory)
            artifact = directory / "scanned.oci.tar"
            replacement = directory / "replacement.oci.tar"
            expected_digest = write_oci(artifact, b'{"config":"scanned"}')
            write_oci(replacement, b'{"config":"replacement"}')
            expected_hash = pipeline.sha256(artifact)

            def fake_run(command: list[str], **kwargs):
                calls.append(command)
                if command[:3] == ["gcloud", "--impersonate-service-account=builder@example.com", "auth"]:
                    # Simulate an attacker replacing the scan output after the
                    # scan but immediately after credentials are requested.
                    replacement.replace(artifact)
                    return SimpleNamespace(stdout="ya29." + "t" * 40)
                if command[:2] == ["skopeo", "copy"]:
                    self.assertEqual(len(kwargs.get("pass_fds", ())), 1)
                    source = next(value for value in command if value.startswith("oci-archive:"))
                    self.assertEqual(source, f"oci-archive:/dev/fd/{kwargs['pass_fds'][0]}")
                    self.assertEqual(
                        pipeline.oci_archive_manifest_digest_fd(kwargs["pass_fds"][0], mode=0o400),
                        expected_digest,
                    )
                    digest_file = Path(command[command.index("--digestfile") + 1])
                    digest_file.write_text(expected_digest + "\n", encoding="ascii")
                    digest_file.chmod(0o600)
                    return SimpleNamespace(stdout="")
                if command[0] == "gcloud" and "describe" in command:
                    return SimpleNamespace(stdout=expected_digest + "\n")
                raise AssertionError(command)

            def fake_login(_registry: str, docker_config: Path, _token: str) -> None:
                auth_file = docker_config / "config.json"
                auth_file.write_text('{"auths": {"us-central1-docker.pkg.dev": {}}}\n', encoding="utf-8")
                auth_file.chmod(0o600)

            pipeline._CLOUDSDK_CONFIG = str(directory)
            with patch.object(pipeline, "run", side_effect=fake_run), patch.object(
                pipeline, "temporary_docker_login", side_effect=fake_login
            ):
                self.assertEqual(
                    pipeline.authenticate_and_push(
                        "us-central1-docker.pkg.dev/project/repo/image:tag",
                        {"REGION": "us-central1"},
                        "builder@example.com",
                        artifact=artifact,
                        expected_artifact_sha256=expected_hash,
                        expected_manifest_digest=expected_digest,
                    ),
                    expected_digest,
                )

        self.assertLess(
            calls.index(next(call for call in calls if call[-2:] == ["auth", "print-access-token"])),
            calls.index(next(call for call in calls if call[:2] == ["skopeo", "copy"])),
        )

    def test_unlinked_quarantine_descriptor_survives_original_path_replacement(self) -> None:
        pipeline = load_pipeline()
        with tempfile.TemporaryDirectory() as temporary_directory:
            directory = Path(temporary_directory)
            artifact = directory / "scanned.oci.tar"
            manifest = b"{}"
            digest = "sha256:" + hashlib.sha256(manifest).hexdigest()
            index = json.dumps(
                {"schemaVersion": 2, "manifests": [{"digest": digest, "size": len(manifest)}]},
                separators=(",", ":"),
            ).encode()
            with tarfile.open(artifact, "w") as archive:
                for name, data in (
                    ("index.json", index),
                    ("blobs/sha256/" + digest.removeprefix("sha256:"), manifest),
                ):
                    member = tarfile.TarInfo(name)
                    member.size = len(data)
                    archive.addfile(member, io.BytesIO(data))
            artifact.chmod(0o600)
            expected_hash = pipeline.sha256(artifact)
            with pipeline.quarantine_scanned_oci_archive(
                artifact, expected_hash, digest
            ) as quarantined_descriptor:
                self.assertEqual(os.fstat(quarantined_descriptor).st_mode & 0o777, 0o400)
                self.assertTrue(artifact.exists())
                artifact.unlink()
                pipeline.verify_oci_archive_fd(
                    quarantined_descriptor,
                    expected_hash,
                    digest,
                    mode=0o400,
                )

    def test_post_build_builder_identity_must_match_prebuild_receipt(self) -> None:
        pipeline = load_pipeline()
        before = {
            "id": "builder-id",
            "name": "reviewed-builder",
            "node_name": "worker0",
            "endpoint": "ssh://builder.example",
            "platform": "linux/amd64",
            "transport": "ssh",
            "transport_pin": "SHA256:host-key",
            "disk_free_bytes": 80,
            "disk_reserve_bytes": 50,
            "disk_total_bytes": 100,
        }
        after = dict(before, endpoint="ssh://replacement.example")
        with patch.object(pipeline, "native_builder_snapshot", return_value=after):
            with self.assertRaisesRegex(pipeline.PipelineError, "identity changed"):
                pipeline.revalidate_native_builder_snapshot(before)

        with patch.object(pipeline, "native_builder_snapshot", return_value=before):
            self.assertEqual(pipeline.revalidate_native_builder_snapshot(before), before)

        with tempfile.TemporaryDirectory() as temporary_directory:
            artifact = Path(temporary_directory) / "image.oci.tar"
            manifest = b"{}"
            digest = "sha256:" + hashlib.sha256(manifest).hexdigest()
            index = json.dumps(
                {"schemaVersion": 2, "manifests": [{"digest": digest, "size": len(manifest)}]},
                separators=(",", ":"),
            ).encode()
            with tarfile.open(artifact, "w") as archive:
                for name, data in (
                    ("index.json", index),
                    ("blobs/sha256/" + digest.removeprefix("sha256:"), manifest),
                ):
                    member = tarfile.TarInfo(name)
                    member.size = len(data)
                    archive.addfile(member, io.BytesIO(data))
            artifact.chmod(0o600)
            outputs = {
                "artifact": str(artifact),
                "artifact_sha256": pipeline.sha256(artifact),
                "artifact_manifest_digest": digest,
                "builder_mode": "native-linux-amd64",
                "builder_post": after,
                "created_at": "2026-08-28T12:00:00Z",
            }
            payload = {"inputs": {"builder": before}, "outputs": outputs}
            self.assertFalse(pipeline.validate_receipt_outputs(Path(temporary_directory), "build", payload))
            outputs["builder_post"] = before
            self.assertTrue(pipeline.validate_receipt_outputs(Path(temporary_directory), "build", payload))

    def test_resumable_builder_binding_excludes_volatile_disk_telemetry(self) -> None:
        pipeline = load_pipeline()
        before = {
            "id": "builder-id",
            "name": "reviewed-builder",
            "node_name": "worker0",
            "endpoint": "ssh://builder.example",
            "platform": "linux/amd64",
            "transport": "ssh",
            "transport_pin": "SHA256:host-key",
            "disk_free_bytes": 80,
            "disk_reserve_bytes": 50,
            "disk_total_bytes": 100,
        }
        after = dict(before, disk_free_bytes=70)
        self.assertEqual(
            pipeline.builder_identity_binding(before),
            pipeline.builder_identity_binding(after),
        )
        self.assertNotIn("disk_free_bytes", pipeline.builder_identity_binding(before))

    def test_config_snapshot_hash_is_stable_after_source_mutation(self) -> None:
        pipeline = load_pipeline()
        with tempfile.TemporaryDirectory() as temporary_directory:
            path = Path(temporary_directory) / "operator.env"
            path.write_text("LOCAL_GCP_IMPERSONATE_SERVICE_ACCOUNT=builder@example.com\n", encoding="utf-8")
            path.chmod(0o600)
            snapshot = pipeline.read_operator_config_snapshot(path)
            path.write_text("LOCAL_GCP_IMPERSONATE_SERVICE_ACCOUNT=attacker@example.com\n", encoding="utf-8")
            self.assertEqual(snapshot.data, b"LOCAL_GCP_IMPERSONATE_SERVICE_ACCOUNT=builder@example.com\n")
            self.assertEqual(snapshot.sha256, __import__("hashlib").sha256(snapshot.data).hexdigest())

    def test_resume_requires_a_matching_signed_verification_receipt(self) -> None:
        pipeline = load_pipeline()
        self.assertFalse(
            pipeline.signed_verification_receipt_valid(
                None,
                None,
                None,
                None,
                source_ref="main",
                source_commit="a" * 40,
            )
        )
        source = Path(pipeline.__file__).read_text(encoding="utf-8")
        self.assertIn("signed_verification_receipt_valid", source)
        self.assertIn("if not (", source)

    def test_secret_assembler_rejects_shell_and_duplicate_entries(self) -> None:
        pipeline = load_pipeline()
        with tempfile.TemporaryDirectory() as temporary_directory:
            directory = Path(temporary_directory)
            config = directory / "config"
            config.write_text("KIOKU_BUILD_PROFILE=production\nKIOKU_BUILD_PROFILE=bad\n", encoding="utf-8")
            config.chmod(0o600)
            result = subprocess.run(
                [str(SCRIPTS / "assemble_image_config.sh"), str(config), str(directory / "out"), "0" * 64],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse((directory / "out").exists())

    def test_secret_assembler_writes_only_the_hash_bound_runtime_bytes(self) -> None:
        pipeline = load_pipeline()
        values = environment()
        values.pop("PATH", None)
        values.pop("GCP_WIF_PROVIDER", None)
        values.pop("GCP_SERVICE_ACCOUNT", None)
        configuration = pipeline.selected_configuration(
            "production",
            values,
            source_ref="main",
        )
        encoded = pipeline.runtime_config_bytes(configuration, "production")
        expected = __import__("hashlib").sha256(encoded).hexdigest()
        with tempfile.TemporaryDirectory() as temporary_directory:
            directory = Path(temporary_directory)
            source = directory / "secret.env"
            output = directory / "assembled.env"
            producer_contract = "sha256:" + "a" * 64
            producer_contract_helper = directory / "producer-contract-helper"
            producer_contract_helper.write_text(
                "#!/bin/sh\n"
                "case \"$1\" in\n"
                "  --print-memory-reconciliation-producer-contract) "
                "printf '%s\\n' '" + producer_contract + "' ;;\n"
                "  *) exit 1 ;;\n"
                "esac\n",
                encoding="utf-8",
            )
            producer_contract_helper.chmod(0o700)
            source.write_bytes(encoded)
            source.chmod(0o600)
            completed = subprocess.run(
                [
                    str(SCRIPTS / "assemble_image_config.sh"),
                    str(source),
                    str(output),
                    expected,
                    str(producer_contract_helper),
                ],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertEqual(output.read_bytes(), encoded)
            self.assertEqual(__import__("stat").S_IMODE(output.stat().st_mode), 0o600)

            # Zero is an intentional, hash-bound closed-signup value, not an
            # omitted budget or an unlimited sentinel.
            closed = encoded.replace(
                b"SIGNUP_LIMIT_PER_DAY=25\n",
                b"SIGNUP_LIMIT_PER_DAY=0\n",
            )
            self.assertNotEqual(closed, encoded)
            closed_source = directory / "closed.env"
            closed_output = directory / "closed-output.env"
            closed_source.write_bytes(closed)
            closed_source.chmod(0o600)
            closed_result = subprocess.run(
                [
                    str(SCRIPTS / "assemble_image_config.sh"),
                    str(closed_source),
                    str(closed_output),
                    __import__("hashlib").sha256(closed).hexdigest(),
                    str(producer_contract_helper),
                ],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(closed_result.returncode, 0, closed_result.stderr)
            self.assertEqual(closed_output.read_bytes(), closed)

            # The removed writer flag is not an accepted image input. Runtime
            # authority comes only from the durable PostgreSQL phase.
            flagged = encoded + b"MEMORY_RECONCILIATION_WRITER_ENABLED=true\n"
            flagged_source = directory / "flagged.env"
            flagged_source.write_bytes(flagged)
            flagged_source.chmod(0o600)
            flagged_result = subprocess.run(
                [
                    str(SCRIPTS / "assemble_image_config.sh"),
                    str(flagged_source),
                    str(directory / "flagged-output"),
                    __import__("hashlib").sha256(flagged).hexdigest(),
                ],
                check=False,
            )
            self.assertNotEqual(flagged_result.returncode, 0)
            self.assertFalse((directory / "flagged-output").exists())

            activation_capable = encoded
            activation_capable_source = directory / "activation-capable.env"
            activation_capable_output = directory / "activation-capable-output"
            activation_capable_source.write_bytes(activation_capable)
            activation_capable_source.chmod(0o600)
            activation_capable_result = subprocess.run(
                [
                    str(SCRIPTS / "assemble_image_config.sh"),
                    str(activation_capable_source),
                    str(activation_capable_output),
                    __import__("hashlib").sha256(activation_capable).hexdigest(),
                    str(producer_contract_helper),
                ],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(
                activation_capable_result.returncode,
                0,
                activation_capable_result.stderr,
            )
            self.assertEqual(activation_capable_output.read_bytes(), activation_capable)

            evaluation_capable = activation_capable.replace(
                b"KIOKU_BUILD_PROFILE=production\n",
                b"KIOKU_BUILD_PROFILE=evaluation\n",
            )
            evaluation_source = directory / "evaluation-capable.env"
            evaluation_output = directory / "evaluation-capable-output"
            evaluation_source.write_bytes(evaluation_capable)
            evaluation_source.chmod(0o600)
            local_evaluation = subprocess.run(
                [
                    str(SCRIPTS / "assemble_image_config.sh"),
                    str(evaluation_source),
                    str(evaluation_output),
                    __import__("hashlib").sha256(evaluation_capable).hexdigest(),
                    str(producer_contract_helper),
                ],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(
                local_evaluation.returncode,
                0,
                local_evaluation.stderr,
            )
            self.assertEqual(evaluation_output.read_bytes(), evaluation_capable)

            mismatched_helper = directory / "mismatched-producer-contract-helper"
            mismatched_helper.write_text(
                "#!/bin/sh\nprintf '%s\\n' 'sha256:" + "d" * 64 + "'\n",
                encoding="utf-8",
            )
            mismatched_helper.chmod(0o700)
            mismatched_output = directory / "mismatched-producer-output"
            mismatched = subprocess.run(
                [
                    str(SCRIPTS / "assemble_image_config.sh"),
                    str(activation_capable_source),
                    str(mismatched_output),
                    __import__("hashlib").sha256(activation_capable).hexdigest(),
                    str(mismatched_helper),
                ],
                check=False,
            )
            self.assertNotEqual(mismatched.returncode, 0)
            self.assertFalse(mismatched_output.exists())

            source.write_bytes(encoded + b"KIOKU_BUILD_PROFILE=attacker\n")
            rejected = subprocess.run(
                [str(SCRIPTS / "assemble_image_config.sh"), str(source), str(directory / "second"), expected],
                check=False,
            )
            self.assertNotEqual(rejected.returncode, 0)

            # Optional-at-runtime values may be empty, but their allowlisted
            # key still has to be present exactly once at the image boundary.
            missing_source = directory / "missing-optional-key.env"
            missing_source.write_bytes(
                b"".join(
                    line
                    for line in encoded.splitlines(keepends=True)
                    if not line.startswith(b"APPLE_TEAM_ID=")
                )
            )
            missing_source.chmod(0o600)
            missing = subprocess.run(
                [
                    str(SCRIPTS / "assemble_image_config.sh"),
                    str(missing_source),
                    str(directory / "missing-output"),
                    __import__("hashlib").sha256(missing_source.read_bytes()).hexdigest(),
                ],
                check=False,
            )
            self.assertNotEqual(missing.returncode, 0)
            self.assertFalse((directory / "missing-output").exists())

            malformed_anchor_source = directory / "malformed-anchor.env"
            malformed_anchor = b"".join(
                b"SCHEMA_FINALIZATION_PUBLIC_KEY_DER_BASE64=AAAA\n"
                if line.startswith(b"SCHEMA_FINALIZATION_PUBLIC_KEY_DER_BASE64=")
                else line
                for line in encoded.splitlines(keepends=True)
            )
            malformed_anchor_source.write_bytes(malformed_anchor)
            malformed_anchor_source.chmod(0o600)
            malformed_anchor_output = directory / "malformed-anchor-output"
            malformed_anchor_result = subprocess.run(
                [
                    str(SCRIPTS / "assemble_image_config.sh"),
                    str(malformed_anchor_source),
                    str(malformed_anchor_output),
                    __import__("hashlib").sha256(malformed_anchor).hexdigest(),
                ],
                check=False,
            )
            self.assertNotEqual(malformed_anchor_result.returncode, 0)
            self.assertFalse(malformed_anchor_output.exists())

    def test_build_source_must_be_clean_and_release_tag_must_equal_head(self) -> None:
        pipeline = load_pipeline()
        original_run = pipeline.run
        try:
            def dirty(command, capture=False):
                del capture
                git_command = command[2:] if command[:2] == ["git", "--no-replace-objects"] else []
                if git_command[:4] == ["rev-parse", "--path-format=absolute", "--git-path", "info/grafts"]:
                    return SimpleNamespace(stdout="/tmp/kioku-test-no-grafts\n")
                return SimpleNamespace(
                    stdout="?? untracked\n" if git_command[:2] == ["status", "--porcelain"] else ""
                )

            pipeline.run = dirty
            with self.assertRaisesRegex(pipeline.PipelineError, "clean source tree"):
                pipeline.source_commit("refs/tags/v1.2.3")

            def mismatched(command, capture=False):
                del capture
                git_command = command[2:] if command[:2] == ["git", "--no-replace-objects"] else []
                if git_command[:2] == ["replace", "-l"]:
                    return SimpleNamespace(stdout="")
                if git_command[:4] == ["rev-parse", "--path-format=absolute", "--git-path", "info/grafts"]:
                    return SimpleNamespace(stdout="/tmp/kioku-test-no-grafts\n")
                if git_command[:2] == ["status", "--porcelain"]:
                    return SimpleNamespace(stdout="")
                if git_command[:2] == ["rev-parse", "HEAD"]:
                    return SimpleNamespace(stdout="a" * 40 + "\n")
                if git_command[:2] == ["log", "-1"]:
                    return SimpleNamespace(stdout="1700000000\n")
                if git_command[:2] == ["rev-list", "-n"]:
                    return SimpleNamespace(stdout="b" * 40 + "\n")
                return SimpleNamespace(stdout="")

            pipeline.run = mismatched
            with self.assertRaisesRegex(pipeline.PipelineError, "resolve exactly to HEAD"):
                pipeline.source_commit("refs/tags/v1.2.3")
        finally:
            pipeline.run = original_run

    def test_tcp_native_builder_requires_tls_even_with_a_pinned_ca(self) -> None:
        pipeline = load_pipeline()
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            certs = root / "certs"
            certs.mkdir(mode=0o700)
            for name, data in (("ca.pem", b"ca"), ("cert.pem", b"cert"), ("key.pem", b"key")):
                path = certs / name
                path.write_bytes(data)
                path.chmod(0o600)

            def fake_run(command: list[str], **kwargs):
                if command[:3] == ["docker", "buildx", "ls"]:
                    return SimpleNamespace(stdout=json.dumps({
                        "Name": "reviewed-builder",
                        "Nodes": [{
                            "Name": "worker0",
                            "Endpoint": "tcp://builder.example:2376",
                            "Status": "running",
                            "Platforms": "linux/amd64",
                        }],
                    }))
                if command[:3] == ["docker", "--host", "tcp://builder.example:2376"]:
                    return SimpleNamespace(stdout="builder-id Linux amd64\n")
                raise AssertionError(command)

            environment = {
                "KIOKU_NATIVE_BUILDER_NAME": "reviewed-builder",
                "KIOKU_NATIVE_BUILDER_ID": "builder-id",
                "DOCKER_HOST": "tcp://builder.example:2376",
                "DOCKER_CERT_PATH": str(certs),
                "DOCKER_BUILDER_CA_SHA256": hashlib.sha256(b"ca").hexdigest(),
            }
            with patch.object(pipeline, "run", side_effect=fake_run), patch.dict(
                pipeline.os.environ, environment, clear=False
            ):
                pipeline.os.environ.pop("DOCKER_TLS_VERIFY", None)
                self.assertFalse(pipeline.native_linux_builder())
                pipeline.os.environ["DOCKER_TLS_VERIFY"] = "1"
                self.assertTrue(pipeline.native_linux_builder())

    def test_multiple_valid_push_receipts_with_different_inputs_are_ambiguous(self) -> None:
        pipeline = load_pipeline()
        with tempfile.TemporaryDirectory() as temporary_directory:
            output = Path(temporary_directory)
            first = pipeline.write_stage_receipt(
                output, "push", {"source_commit": "a" * 40}, {"image_digest": "sha256:" + "1" * 64}
            )
            second_payload = {
                "schema_version": 1,
                "stage": "push",
                "inputs": {"source_commit": "b" * 40},
                "outputs": {"image_digest": "sha256:" + "2" * 64},
            }
            encoded = (json.dumps(second_payload, sort_keys=True, separators=(",", ":")) + "\n").encode()
            second = output / ("push-receipt-" + hashlib.sha256(encoded).hexdigest() + ".json")
            second.write_bytes(encoded)
            second.chmod(0o600)
            self.assertNotEqual(first, second)
            with self.assertRaisesRegex(pipeline.PipelineError, "ambiguous"):
                pipeline.valid_stage_receipt(output, "push", {"source_commit": "a" * 40})

    def test_multiple_valid_evidence_receipts_with_different_inputs_are_ambiguous(self) -> None:
        pipeline = load_pipeline()
        with tempfile.TemporaryDirectory() as temporary_directory:
            output = Path(temporary_directory)
            manifest = output / "enclave-local-build-evidence.json"
            metadata = output / "enclave-release.json"
            for path in (manifest, metadata):
                path.write_text("{}\n", encoding="utf-8")
                path.chmod(0o600)
            outputs = {
                "manifest": str(manifest),
                "manifest_sha256": pipeline.sha256(manifest),
                "metadata": str(metadata),
                "metadata_sha256": pipeline.sha256(metadata),
            }
            pipeline.write_stage_receipt(
                output,
                "evidence",
                {"image_digest": "sha256:" + "1" * 64},
                outputs,
            )
            pipeline.write_stage_receipt(
                output,
                "evidence",
                {"image_digest": "sha256:" + "2" * 64},
                outputs,
            )
            with self.assertRaisesRegex(pipeline.PipelineError, "ambiguous"):
                pipeline.valid_stage_receipt(
                    output,
                    "evidence",
                    {"image_digest": "sha256:" + "1" * 64},
                )

    def test_scan_receipt_must_bind_the_build_artifact(self) -> None:
        pipeline = load_pipeline()
        with tempfile.TemporaryDirectory() as temporary_directory:
            output = Path(temporary_directory)
            for name in ("enclave-sbom.spdx.json", "enclave-scan.json"):
                path = output / name
                path.write_text("{}\n", encoding="utf-8")
                path.chmod(0o600)
            payload = {
                "inputs": {
                    "artifact_sha256": "a" * 64,
                    "artifact_manifest_digest": "sha256:" + "b" * 64,
                    "build_created_at": "2026-08-28T12:00:00Z",
                },
                "outputs": {
                    "artifact_sha256": "c" * 64,
                    "artifact_manifest_digest": "sha256:" + "d" * 64,
                    "sbom_path": str(output / "enclave-sbom.spdx.json"),
                    "sbom_sha256": pipeline.sha256(output / "enclave-sbom.spdx.json"),
                    "scan_path": str(output / "enclave-scan.json"),
                    "scan_sha256": pipeline.sha256(output / "enclave-scan.json"),
                    "completed_at": "2026-08-28T12:01:00Z",
                },
            }
            self.assertFalse(pipeline.validate_receipt_outputs(output, "scan", payload))

    def test_direct_pipeline_rejects_service_account_json_credentials(self) -> None:
        pipeline = load_pipeline()
        with patch.dict(pipeline.os.environ, {"GOOGLE_APPLICATION_CREDENTIALS": "/tmp/key.json"}, clear=False), \
             patch.object(pipeline.sys, "argv", ["local_image_pipeline.py", "preflight", "--config", "/tmp/missing"]):
            with self.assertRaises(SystemExit):
                pipeline.main()

    def test_direct_child_environment_rejects_ambient_credentials(self) -> None:
        pipeline = load_pipeline()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            docker_config = root / "docker"
            buildx_config = root / "buildx"
            docker_config.mkdir(mode=0o700)
            buildx_config.mkdir(mode=0o700)
            environment = {
                "PATH": os.environ.get("PATH", ""),
                "HOME": str(root),
                "KIOKU_RELEASE_NATIVE_DOCKER_CONFIG": str(docker_config),
                "KIOKU_RELEASE_NATIVE_BUILDX_CONFIG": str(buildx_config),
                "DOCKER_AUTH_CONFIG": '{"auths":{"registry.example":"secret"}}',
            }
            with patch.dict(pipeline.os.environ, environment, clear=True):
                with self.assertRaisesRegex(pipeline.PipelineError, "DOCKER_AUTH_CONFIG"):
                    pipeline.configure_direct_child_environment("build")

    def test_direct_child_environment_is_an_explicit_allowlist(self) -> None:
        pipeline = load_pipeline()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            docker_config = root / "docker"
            buildx_config = root / "buildx"
            docker_config.mkdir(mode=0o700)
            buildx_config.mkdir(mode=0o700)
            environment = {
                "PATH": os.environ.get("PATH", ""),
                "HOME": str(root),
                "KIOKU_RELEASE_NATIVE_DOCKER_CONFIG": str(docker_config),
                "KIOKU_RELEASE_NATIVE_BUILDX_CONFIG": str(buildx_config),
                "KIOKU_NATIVE_BUILDER_NAME": "reviewed-builder",
                "KIOKU_NATIVE_BUILDER_ID": "builder-id",
                "DOCKER_HOST": "unix:///var/run/reviewed.sock",
                "GH_TOKEN": "must-not-cross",
                "UNREVIEWED_SETTING": "must-not-cross",
            }
            with patch.dict(pipeline.os.environ, environment, clear=True):
                with self.assertRaisesRegex(pipeline.PipelineError, "GH_TOKEN"):
                    pipeline.configure_direct_child_environment("build")
            environment.pop("GH_TOKEN")
            with patch.dict(pipeline.os.environ, environment, clear=True):
                pipeline.configure_direct_child_environment("build")
                self.assertEqual(pipeline._CHILD_ENVIRONMENT["DOCKER_CONFIG"], str(docker_config.resolve()))
                self.assertEqual(pipeline._CHILD_ENVIRONMENT["GIT_NO_REPLACE_OBJECTS"], "1")
                self.assertNotIn("UNREVIEWED_SETTING", pipeline._CHILD_ENVIRONMENT)
                self.assertNotIn("GH_TOKEN", pipeline._CHILD_ENVIRONMENT)

    def test_verification_inputs_reach_only_full_postgres_verification(self) -> None:
        pipeline = load_pipeline()
        postgres_url = "postgresql://contract:test@127.0.0.1:5432/contract"
        minimum_free_gib = "1"
        recorded: list[tuple[list[str], dict[str, str]]] = []

        def fake_subprocess_run(command, **kwargs):
            child = dict(kwargs.get("env") or {})
            recorded.append((list(command), child))
            stdout = (
                "cargo-audit-audit 0.22.2\n"
                if command and command[0] == "/reviewed/cargo-audit"
                and command[1:] == ["--version"]
                else ""
            )
            return SimpleNamespace(returncode=0, stdout=stdout, stderr="")

        with patch.dict(
            pipeline.os.environ,
            {
                "PATH": os.environ.get("PATH", ""),
                "HOME": os.environ.get("HOME", ""),
                "KIOKU_TEST_POSTGRES_URL": postgres_url,
                "AGENT_VERIFY_MIN_FREE_GIB": minimum_free_gib,
            },
            clear=True,
        ):
            pipeline.configure_direct_child_environment("verify")
            self.assertNotIn("KIOKU_TEST_POSTGRES_URL", pipeline._CHILD_ENVIRONMENT)
            self.assertNotIn("AGENT_VERIFY_MIN_FREE_GIB", pipeline._CHILD_ENVIRONMENT)
            with patch.object(
                pipeline.shutil, "which", return_value="/reviewed/cargo-audit"
            ), patch.object(pipeline.subprocess, "run", side_effect=fake_subprocess_run):
                pipeline.verify()

        full_command = [str(SCRIPTS / "agent-verify.sh"), "full"]
        full_environments = [
            child for command, child in recorded if command == full_command
        ]
        self.assertEqual(len(full_environments), 1)
        self.assertEqual(
            full_environments[0].get("KIOKU_TEST_POSTGRES_URL"), postgres_url
        )
        self.assertEqual(
            full_environments[0].get("AGENT_VERIFY_MIN_FREE_GIB"), minimum_free_gib
        )
        self.assertTrue(
            all(
                "KIOKU_TEST_POSTGRES_URL" not in child
                and "AGENT_VERIFY_MIN_FREE_GIB" not in child
                for command, child in recorded
                if command != full_command
            )
        )

    def test_verify_preflight_receives_configured_native_builder_selection(self) -> None:
        pipeline = load_pipeline()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            docker_config = root / "docker"
            buildx_config = root / "buildx"
            docker_config.mkdir(mode=0o700)
            buildx_config.mkdir(mode=0o700)
            environment = {
                "PATH": os.environ.get("PATH", ""),
                "HOME": str(root),
                "KIOKU_RELEASE_NATIVE_DOCKER_CONFIG": str(docker_config),
                "KIOKU_RELEASE_NATIVE_BUILDX_CONFIG": str(buildx_config),
                "KIOKU_NATIVE_BUILDER_NAME": "reviewed-builder",
                "KIOKU_NATIVE_BUILDER_ID": "builder-id",
                "DOCKER_HOST": "unix:///var/run/reviewed.sock",
            }
            with patch.dict(pipeline.os.environ, environment, clear=True):
                pipeline.configure_direct_child_environment("verify")

            self.assertEqual(
                pipeline._CHILD_ENVIRONMENT["DOCKER_CONFIG"],
                str(docker_config.resolve()),
            )
            self.assertEqual(
                pipeline._CHILD_ENVIRONMENT["BUILDX_CONFIG"],
                str(buildx_config.resolve()),
            )
            self.assertEqual(
                pipeline._CHILD_ENVIRONMENT["KIOKU_NATIVE_BUILDER_NAME"],
                "reviewed-builder",
            )
            self.assertEqual(
                pipeline._CHILD_ENVIRONMENT["DOCKER_HOST"],
                "unix:///var/run/reviewed.sock",
            )

    def test_verification_inputs_never_reach_build_scan_or_cloud_children(self) -> None:
        pipeline = load_pipeline()
        postgres_url = "postgresql://contract:test@127.0.0.1:5432/contract"
        recorded: list[tuple[list[str], dict[str, str]]] = []

        def fake_subprocess_run(command, **kwargs):
            recorded.append((list(command), dict(kwargs.get("env") or {})))
            return SimpleNamespace(returncode=0, stdout="", stderr="")

        pipeline._CHILD_ENVIRONMENT = {
            "PATH": os.environ.get("PATH", ""),
            "HOME": os.environ.get("HOME", ""),
            "GIT_NO_REPLACE_OBJECTS": "1",
        }
        pipeline._CLOUDSDK_CONFIG = "/private/reviewed-gcloud"
        pipeline._AGENT_VERIFICATION_ENVIRONMENT = {
            "KIOKU_TEST_POSTGRES_URL": postgres_url,
            "AGENT_VERIFY_MIN_FREE_GIB": "1",
        }
        commands = (
            ["docker", "buildx", "build", "--help"],
            ["syft", "--version"],
            ["grype", "--version"],
            ["skopeo", "--version"],
        )
        with patch.object(pipeline.subprocess, "run", side_effect=fake_subprocess_run):
            for command in commands:
                pipeline.run(command)
            pipeline.run(
                ["gcloud", "version"],
                environment=pipeline.cloud_child_environment(),
            )

        self.assertEqual(len(recorded), len(commands) + 1)
        self.assertTrue(
            all(
                "KIOKU_TEST_POSTGRES_URL" not in child
                and "AGENT_VERIFY_MIN_FREE_GIB" not in child
                for _, child in recorded
            )
        )

    def test_verification_disk_floor_override_is_optional_and_fail_closed(self) -> None:
        pipeline = load_pipeline()
        base_environment = {
            "PATH": os.environ.get("PATH", ""),
            "HOME": os.environ.get("HOME", ""),
        }
        with patch.dict(pipeline.os.environ, base_environment, clear=True):
            pipeline.configure_direct_child_environment("verify")
        self.assertNotIn(
            "AGENT_VERIFY_MIN_FREE_GIB", pipeline._AGENT_VERIFICATION_ENVIRONMENT
        )

        for invalid_value in ("0", "-1", "1.5", " 1", "one"):
            with self.subTest(invalid_value=invalid_value), patch.dict(
                pipeline.os.environ,
                base_environment | {"AGENT_VERIFY_MIN_FREE_GIB": invalid_value},
                clear=True,
            ):
                with self.assertRaisesRegex(
                    pipeline.PipelineError, "positive whole number"
                ):
                    pipeline.configure_direct_child_environment("verify")

    def test_direct_child_environment_rejects_ambient_git_object_overrides(self) -> None:
        pipeline = load_pipeline()
        with patch.dict(
            pipeline.os.environ,
            {"PATH": os.environ.get("PATH", ""), "GIT_OBJECT_DIRECTORY": "/tmp/objects"},
            clear=True,
        ):
            with self.assertRaisesRegex(pipeline.PipelineError, "GIT_OBJECT_DIRECTORY"):
                pipeline.configure_direct_child_environment("verify")
        with patch.dict(
            pipeline.os.environ,
            {"PATH": os.environ.get("PATH", ""), "GIT_NO_REPLACE_OBJECTS": "0"},
            clear=True,
        ):
            with self.assertRaisesRegex(pipeline.PipelineError, "exactly 1"):
                pipeline.configure_direct_child_environment("verify")

    def test_replacement_ref_is_rejected_before_source_use(self) -> None:
        pipeline = load_pipeline()
        with tempfile.TemporaryDirectory() as temporary:
            repository = Path(temporary) / "repository"
            repository.mkdir()

            def git(*arguments: str, capture: bool = False) -> subprocess.CompletedProcess[str]:
                return subprocess.run(
                    ("git", "-C", str(repository), *arguments),
                    check=True,
                    text=True,
                    capture_output=capture,
                    env=os.environ | {"GIT_CONFIG_NOSYSTEM": "1"},
                )

            git("init")
            git("config", "user.name", "Replacement Test")
            git("config", "user.email", "replacement@example.invalid")
            source = repository / "source.txt"
            source.write_text("source A\n", encoding="utf-8")
            git("add", "source.txt")
            git("commit", "-m", "source A")
            source_a = git("rev-parse", "HEAD", capture=True).stdout.strip()
            source.write_text("source B\n", encoding="utf-8")
            git("add", "source.txt")
            git("commit", "-m", "source B")
            source_b = git("rev-parse", "HEAD", capture=True).stdout.strip()
            git("replace", source_a, source_b)
            git("update-ref", "HEAD", source_a)

            # Git versions differ on whether status compares the index with the
            # replacement commit or the replaced commit.  The release boundary
            # must reject the replacement ref before either interpretation can
            # influence source selection.

            pipeline.ROOT = repository
            pipeline._CHILD_ENVIRONMENT = {
                "PATH": os.environ.get("PATH", ""),
                "HOME": os.environ.get("HOME", ""),
                "GIT_NO_REPLACE_OBJECTS": "1",
            }
            with self.assertRaisesRegex(pipeline.PipelineError, "replacement refs"):
                pipeline.source_commit("refs/heads/main")

    def test_cloud_config_is_required_and_stage_scoped(self) -> None:
        pipeline = load_pipeline()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            docker_config = root / "docker"
            buildx_config = root / "buildx"
            cloud_config = root / "cloud"
            for directory in (docker_config, buildx_config, cloud_config):
                directory.mkdir(mode=0o700)
            base = {
                "PATH": os.environ.get("PATH", ""),
                "HOME": str(root),
                "KIOKU_RELEASE_NATIVE_DOCKER_CONFIG": str(docker_config),
                "KIOKU_RELEASE_NATIVE_BUILDX_CONFIG": str(buildx_config),
            }
            with patch.dict(pipeline.os.environ, base, clear=True):
                with self.assertRaisesRegex(pipeline.PipelineError, "CLOUDSDK_CONFIG"):
                    pipeline.configure_direct_child_environment("push")
            with patch.dict(pipeline.os.environ, {**base, "CLOUDSDK_CONFIG": str(cloud_config)}, clear=True):
                pipeline.configure_direct_child_environment("push")
                self.assertNotIn("CLOUDSDK_CONFIG", pipeline._CHILD_ENVIRONMENT)
                self.assertEqual(pipeline.cloud_child_environment(), {"CLOUDSDK_CONFIG": str(cloud_config.resolve())})

    def test_reviewed_config_rejects_symlinked_ancestor(self) -> None:
        pipeline = load_pipeline()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            target = root / "target"
            target.mkdir(mode=0o700)
            docker_config = target / "docker"
            buildx_config = root / "buildx"
            docker_config.mkdir(mode=0o700)
            buildx_config.mkdir(mode=0o700)
            ancestor = root / "ancestor"
            ancestor.symlink_to(target, target_is_directory=True)
            with self.assertRaisesRegex(pipeline.PipelineError, "symlinked ancestry"):
                pipeline.reviewed_private_config_directory(str(ancestor / "docker"), "Docker config")
            cloud = target / "cloud"
            cloud.mkdir(mode=0o700)
            with self.assertRaisesRegex(pipeline.PipelineError, "symlinked ancestry"):
                pipeline.reviewed_cloud_config_directory(str(ancestor / "cloud"))

    def test_buildx_config_tightens_only_owned_regular_metadata_files(self) -> None:
        pipeline = load_pipeline()
        with tempfile.TemporaryDirectory() as temporary:
            buildx_config = Path(temporary) / "buildx"
            buildx_config.mkdir(mode=0o700)
            metadata = buildx_config / "activity"
            metadata.write_text("build reference\n", encoding="utf-8")
            metadata.chmod(0o644)

            reviewed = pipeline.reviewed_private_config_directory(
                str(buildx_config),
                "native Buildx config directory",
                tighten_owned_files=True,
            )

            self.assertEqual(reviewed, buildx_config.resolve())
            self.assertEqual(stat.S_IMODE(metadata.stat().st_mode), 0o600)


if __name__ == "__main__":
    unittest.main()
