#!/usr/bin/env python3
"""Isolated contracts for deployed-image-to-local-config migration."""

from __future__ import annotations

import importlib.util
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
sys.path.insert(0, str(SCRIPTS))
from test_select_build_configuration import environment as selected_environment  # noqa: E402


def load_module():
    specification = importlib.util.spec_from_file_location(
        "bootstrap_local_operator_config", SCRIPTS / "bootstrap_local_operator_config.py"
    )
    assert specification and specification.loader
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


class BootstrapLocalOperatorConfigTests(unittest.TestCase):
    def image_environment(self, module) -> dict[str, str]:
        source = selected_environment()
        result = {"KIOKU_BUILD_PROFILE": "production"}
        for name in module.PROFILE_KEYS:
            image_name = module.IMAGE_ENVIRONMENT_NAMES.get(name, name)
            result[image_name] = source[f"PRODUCTION_{name}"]
        for group in module.OPTIONAL_PROFILE_GROUPS:
            for name in group:
                if f"PRODUCTION_{name}" in source:
                    result[name] = source[f"PRODUCTION_{name}"]
        return result

    @staticmethod
    def baked_content(values: dict[str, str]) -> str:
        return "".join(f"{name}={value}\n" for name, value in values.items())

    def test_extracts_baked_file_from_stopped_exact_container(self) -> None:
        module = load_module()
        image = (
            "us-central1-docker.pkg.dev/kioku-joerodriguez/kioku/kioku-enclave@sha256:"
            + "a" * 64
        )
        commands: list[list[str]] = []
        temporary_docker_configs: list[Path] = []
        container_id = "b" * 64

        def run(command, **kwargs):
            commands.append(command)
            if command[:2] == ["docker", "context"]:
                return subprocess.CompletedProcess(
                    command, 0, '"unix:///private/docker.sock"\n', ""
                )
            if command[0] == "gcloud":
                return subprocess.CompletedProcess(command, 0, "short-lived-registry-token\n", "")
            if "login" in command:
                self.assertEqual(kwargs["input"], "short-lived-registry-token\n")
                temporary_docker_configs.append(Path(command[command.index("--config") + 1]))
                return subprocess.CompletedProcess(command, 0, "", "")
            temporary_docker_configs.append(Path(kwargs["env"]["DOCKER_CONFIG"]))
            if "create" in command:
                return subprocess.CompletedProcess(command, 0, container_id + "\n", "")
            if "cp" in command:
                Path(command[-1]).write_text(
                    self.baked_content(self.image_environment(module)), encoding="utf-8"
                )
            return subprocess.CompletedProcess(command, 0, "", "")

        with mock.patch.object(module.shutil, "which", return_value="/usr/bin/tool"), mock.patch.object(
            module.subprocess, "run", side_effect=run
        ):
            extracted = module.deployed_environment(image, "us-central1-docker.pkg.dev")

        self.assertEqual(extracted["KIOKU_BUILD_PROFILE"], "production")
        flattened = [argument for command in commands for argument in command]
        self.assertNotIn("run", flattened)
        self.assertNotIn("start", flattened)
        self.assertEqual(sum("create" in command for command in commands), 1)
        self.assertEqual(sum("cp" in command for command in commands), 1)
        self.assertEqual(sum("rm" in command for command in commands), 1)
        removal = next(command for command in commands if "rm" in command)
        self.assertEqual(removal[-1], container_id)
        self.assertIn("--platform", next(command for command in commands if "pull" in command))
        self.assertTrue(
            all(
                command[command.index("--host") + 1] == "unix:///private/docker.sock"
                for command in commands
                if "--host" in command
            )
        )
        self.assertTrue(temporary_docker_configs)
        self.assertTrue(all(not path.exists() for path in temporary_docker_configs))

    def test_copy_failure_is_sanitized_and_removes_exact_stopped_container(self) -> None:
        module = load_module()
        image = (
            "us-central1-docker.pkg.dev/kioku-joerodriguez/kioku/kioku-enclave@sha256:"
            + "a" * 64
        )
        container_id = "b" * 64
        removals: list[list[str]] = []

        def run(command, **_kwargs):
            if command[:2] == ["docker", "context"]:
                return subprocess.CompletedProcess(
                    command, 0, '"unix:///private/docker.sock"\n', ""
                )
            if command[0] == "gcloud":
                return subprocess.CompletedProcess(command, 0, "short-lived-registry-token\n", "")
            if "login" in command or "pull" in command:
                return subprocess.CompletedProcess(command, 0, "", "")
            if "create" in command:
                return subprocess.CompletedProcess(command, 0, container_id + "\n", "")
            if "cp" in command:
                return subprocess.CompletedProcess(
                    command, 1, "configuration-secret", "registry-secret"
                )
            removals.append(command)
            return subprocess.CompletedProcess(command, 0, container_id + "\n", "")

        with mock.patch.object(module.shutil, "which", return_value="/usr/bin/tool"), mock.patch.object(
            module.subprocess, "run", side_effect=run
        ):
            with self.assertRaises(module.BootstrapError) as raised:
                module.deployed_environment(image, "us-central1-docker.pkg.dev")
        self.assertNotIn("secret", str(raised.exception))
        self.assertEqual(removals[-1][-3:], ["rm", "--force", container_id])

    def test_refuses_remote_docker_endpoint_before_minting_registry_token(self) -> None:
        module = load_module()
        image = (
            "us-central1-docker.pkg.dev/kioku-joerodriguez/kioku/kioku-enclave@sha256:"
            + "a" * 64
        )
        commands: list[list[str]] = []

        def run(command, **_kwargs):
            commands.append(command)
            return subprocess.CompletedProcess(command, 0, '"ssh://remote-builder"\n', "")

        with mock.patch.object(module.shutil, "which", return_value="/usr/bin/tool"), mock.patch.object(
            module.subprocess, "run", side_effect=run
        ):
            with self.assertRaisesRegex(module.BootstrapError, "local Unix-socket"):
                module.deployed_environment(image, "us-central1-docker.pkg.dev")
        self.assertEqual(len(commands), 1)
        self.assertEqual(commands[0][:3], ["docker", "context", "inspect"])

    def test_maps_and_writes_valid_private_production_config(self) -> None:
        module = load_module()
        image = (
            "us-central1-docker.pkg.dev/kioku-joerodriguez/kioku/kioku-enclave@sha256:"
            + "a" * 64
        )
        _, coordinates = module.image_coordinates(image)
        values = module.operator_values(
            coordinates,
            self.image_environment(module),
            "local-builder@kioku-joerodriguez.iam.gserviceaccount.com",
        )
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary).resolve() / "private"
            parent.mkdir(mode=0o700)
            output = parent / "operator.env"
            module.write_private(output, values)
            content = output.read_text(encoding="utf-8")
            self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o600)
            self.assertIn("PRODUCTION_ENCLAVE_KMS_PROJECT=", content)
            self.assertIn("PRODUCTION_ADMIN_USER_IDS=", content)
            self.assertIn("LOCAL_GCP_IMPERSONATE_SERVICE_ACCOUNT=local-builder@", content)
            self.assertNotIn("\nKMS_PROJECT=", "\n" + content)
            with self.assertRaisesRegex(module.BootstrapError, "overwrite"):
                module.write_private(output, values)

    def test_requires_exact_digest_and_production_image(self) -> None:
        module = load_module()
        with self.assertRaisesRegex(module.BootstrapError, "sha256"):
            module.image_coordinates("us-central1-docker.pkg.dev/project/repo/image:latest")
        image_environment = self.image_environment(module)
        image_environment["KIOKU_BUILD_PROFILE"] = "evaluation"
        with self.assertRaisesRegex(module.BootstrapError, "production"):
            module.parse_deployed_entries(
                [f"{name}={value}" for name, value in image_environment.items()]
            )

    def test_baked_file_must_be_regular_bounded_utf8_production_text(self) -> None:
        module = load_module()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            valid = root / "valid"
            valid.write_text(
                self.baked_content(self.image_environment(module)), encoding="utf-8"
            )
            self.assertEqual(
                module.read_baked_configuration(valid)["KIOKU_BUILD_PROFILE"], "production"
            )

            link = root / "link"
            link.symlink_to(valid)
            with self.assertRaisesRegex(module.BootstrapError, "regular file"):
                module.read_baked_configuration(link)

            malformed = root / "malformed"
            malformed.write_bytes(b"KIOKU_BUILD_PROFILE=production")
            with self.assertRaisesRegex(module.BootstrapError, "malformed"):
                module.read_baked_configuration(malformed)

            evaluation = root / "evaluation"
            evaluation_values = self.image_environment(module)
            evaluation_values["KIOKU_BUILD_PROFILE"] = "evaluation"
            evaluation.write_text(self.baked_content(evaluation_values), encoding="utf-8")
            with self.assertRaisesRegex(module.BootstrapError, "production"):
                module.read_baked_configuration(evaluation)

            oversized = root / "oversized"
            with oversized.open("wb") as handle:
                handle.truncate(module.MAX_BAKED_CONFIG_BYTES + 1)
            with self.assertRaisesRegex(module.BootstrapError, "bounded regular file"):
                module.read_baked_configuration(oversized)

    def test_output_must_be_outside_repository(self) -> None:
        module = load_module()
        with self.assertRaisesRegex(module.BootstrapError, "outside"):
            module.write_private(ROOT / "operator.env", {name: "x" for name in module.SHARED_KEYS})


if __name__ == "__main__":
    unittest.main()
