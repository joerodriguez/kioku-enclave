"""Hermetic contracts for the ADR-0033 enclave adapter wrapper."""

from __future__ import annotations

import contextlib
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest import mock


MODULE_PATH = Path(__file__).with_name("release_train_enclave.py")
SPEC = importlib.util.spec_from_file_location("release_train_enclave", MODULE_PATH)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class EnclaveAdapterTests(unittest.TestCase):
    def test_missing_coordinates_fail_without_stdout(self) -> None:
        environment = os.environ.copy()
        for key in tuple(environment):
            if key.startswith("KIOKU_RELEASE_") or key in {"XDG_STATE_HOME", "HOME"}:
                environment.pop(key, None)
        result = __import__("subprocess").run(
            ("python3", str(MODULE_PATH), "prepare"),
            env=environment,
            stdout=__import__("subprocess").PIPE,
            stderr=__import__("subprocess").PIPE,
            text=True,
            check=False,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, "")
        self.assertIn("required coordinate", result.stderr)

    def test_prepare_emits_state_home_relative_exact_files(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            state = root / "state"
            state.mkdir(mode=0o700)
            config = root / "config.env"
            config.write_text("CONFIG=fixture\n")
            config.chmod(0o600)
            artifact = state / "enclave-release" / "evidence" / "image.oci"
            artifact.parent.mkdir(mode=0o700, parents=True)
            artifact.write_bytes(b"oci fixture")
            artifact.chmod(0o600)
            with mock.patch.dict(os.environ, {
                "HOME": str(state),
                "XDG_STATE_HOME": str(state),
                "KIOKU_RELEASE_ARTIFACT_ROOT": str(state),
                "KIOKU_RELEASE_CONFIG_PATH": str(config),
                "KIOKU_RELEASE_CONFIG_DIGEST": "sha256:" + hashlib.sha256(config.read_bytes()).hexdigest(),
            }, clear=False), mock.patch.object(MODULE, "_source_coordinates", return_value=("a" * 40, "b" * 40, "v1.2.3", "1.2.3")), mock.patch.object(MODULE, "_check_config_coordinate"), mock.patch.object(MODULE, "_pipeline"), mock.patch.object(MODULE, "_native_child_env", return_value={}), mock.patch.object(MODULE, "_artifact", return_value=(artifact, hashlib.sha256(artifact.read_bytes()).hexdigest(), "sha256:" + "a" * 64)):
                result = MODULE.prepare()
            self.assertEqual(result["schema"], MODULE.SCHEMA)
            self.assertEqual(result["artifact_digest"], "sha256:" + "a" * 64)
            self.assertEqual(result["artifact_files"], [{"path": "enclave-release/evidence/image.oci", "digest": "sha256:" + hashlib.sha256(b"oci fixture").hexdigest()}])

    def test_confirmation_is_exactly_bound_to_version_and_digest(self) -> None:
        with mock.patch.dict(os.environ, {"KIOKU_RELEASE_CONFIRMATION": "PUBLISH ENCLAVE 1.2.3 sha256:" + "a" * 64}, clear=False):
            self.assertEqual(MODULE._confirmation("1.2.3", "sha256:" + "a" * 64), "PUBLISH ENCLAVE 1.2.3 sha256:" + "a" * 64)
        with mock.patch.dict(os.environ, {"KIOKU_RELEASE_CONFIRMATION": "PUBLISH ENCLAVE 1.2.3 sha256:" + "b" * 64}, clear=False):
            with self.assertRaises(MODULE.AdapterError):
                MODULE._confirmation("1.2.3", "sha256:" + "a" * 64)

    def test_state_destination_is_allowlisted(self) -> None:
        with self.assertRaises(MODULE.AdapterError):
            MODULE.state("enclave-kms-vm-ledger")

    def test_environment_declares_no_prepare_credentials(self) -> None:
        self.assertEqual(MODULE.ENVIRONMENT["later_credentials"], (
            "KIOKU_RELEASE_EVIDENCE_PRIVATE_KEY",
            "KIOKU_RELEASE_GITHUB_TOKEN",
            "KIOKU_RELEASE_GCP_READONLY_SERVICE_ACCOUNT",
        ))
        self.assertNotIn("prepare", MODULE.ENVIRONMENT["later_credentials"])

    def test_state_output_falls_back_to_private_xdg_state_without_artifact_root(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            xdg = root / "xdg"
            xdg.mkdir(mode=0o700)
            config = root / "config.env"
            config.write_text("CONFIG=fixture\n")
            config.chmod(0o600)
            environment = {
                "XDG_STATE_HOME": str(xdg),
                "KIOKU_RELEASE_SOURCE_COMMIT": "a" * 40,
                "KIOKU_RELEASE_CONFIG_PATH": str(config),
                "KIOKU_RELEASE_CONFIG_DIGEST": "sha256:" + hashlib.sha256(config.read_bytes()).hexdigest(),
            }
            with mock.patch.dict(os.environ, environment, clear=True), \
                 mock.patch.object(MODULE, "_source_coordinates", return_value=("a" * 40, "b" * 40, "v1.2.3", "1.2.3")), \
                 mock.patch.object(MODULE, "_check_config_coordinate"), \
                 mock.patch.object(MODULE, "_image_repository", return_value=("us-docker.pkg.dev/project/repo/image", "reader@example.com")), \
                 mock.patch.object(MODULE, "_release_json", return_value=None):
                result = MODULE.state("enclave-artifact-registry-release")
            self.assertEqual(result["state"], {"version": "1.2.3", "artifact_digest": MODULE.ZERO_DIGEST, "present": False})
            with mock.patch.dict(os.environ, environment, clear=True):
                evidence = MODULE._output_dir(require_artifact_root=False)
            self.assertTrue(evidence.parent.is_dir())
            self.assertEqual(stat.S_IMODE(evidence.parent.stat().st_mode), 0o700)

    def test_reviewed_cloud_children_do_not_inherit_release_credentials(self) -> None:
        with mock.patch.dict(os.environ, {
            "KIOKU_RELEASE_GITHUB_TOKEN": "github-secret",
            "KIOKU_RELEASE_EVIDENCE_PRIVATE_KEY": "/private/key",
            "CLOUDSDK_CONFIG": "/private/gcloud",
            "GOOGLE_APPLICATION_CREDENTIALS": "/private/creds.json",
        }, clear=False):
            gh_environment = MODULE._gh_env()
            gcloud_environment = MODULE._gcloud_env()
        self.assertEqual(gh_environment["GH_TOKEN"], "github-secret")
        self.assertNotIn("KIOKU_RELEASE_EVIDENCE_PRIVATE_KEY", gh_environment)
        self.assertNotIn("KIOKU_RELEASE_GITHUB_TOKEN", gh_environment)
        self.assertEqual(gcloud_environment["CLOUDSDK_CONFIG"], "/private/gcloud")
        self.assertNotIn("KIOKU_RELEASE_EVIDENCE_PRIVATE_KEY", gcloud_environment)
        self.assertNotIn("KIOKU_RELEASE_GITHUB_TOKEN", gcloud_environment)

    def test_native_prepare_environment_contains_only_pinned_transport_and_empty_configs(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            docker_config = root / "docker"
            buildx_config = root / "buildx"
            docker_config.mkdir(mode=0o700)
            buildx_config.mkdir(mode=0o700)
            environment = {
                "KIOKU_NATIVE_BUILDER_NAME": "native-builder",
                "KIOKU_NATIVE_BUILDER_ID": "builder-id",
                "DOCKER_HOST": "unix:///var/run/native-builder.sock",
                "KIOKU_RELEASE_NATIVE_DOCKER_CONFIG": str(docker_config),
                "KIOKU_RELEASE_NATIVE_BUILDX_CONFIG": str(buildx_config),
                "KIOKU_RELEASE_GITHUB_TOKEN": "github-secret",
                "KIOKU_RELEASE_EVIDENCE_PRIVATE_KEY": "/private/key",
                "GOOGLE_APPLICATION_CREDENTIALS": "/private/cloud.json",
                "GH_TOKEN": "github-secret",
            }
            with mock.patch.dict(os.environ, environment, clear=True):
                child = MODULE._native_child_env(include_cloud=False)
            self.assertEqual(child["KIOKU_NATIVE_BUILDER_NAME"], "native-builder")
            self.assertEqual(child["KIOKU_NATIVE_BUILDER_ID"], "builder-id")
            self.assertEqual(child["DOCKER_HOST"], "unix:///var/run/native-builder.sock")
            self.assertEqual(child["DOCKER_CONFIG"], str(docker_config))
            self.assertEqual(child["BUILDX_CONFIG"], str(buildx_config))
            for secret in (
                "KIOKU_RELEASE_GITHUB_TOKEN",
                "KIOKU_RELEASE_EVIDENCE_PRIVATE_KEY",
                "GOOGLE_APPLICATION_CREDENTIALS",
                "GH_TOKEN",
            ):
                self.assertNotIn(secret, child)

    def test_native_docker_config_rejects_auth_and_credential_helpers(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            docker_config = root / "docker"
            buildx_config = root / "buildx"
            docker_config.mkdir(mode=0o700)
            buildx_config.mkdir(mode=0o700)
            config = docker_config / "config.json"
            config.write_text('{"credsStore":"osxkeychain"}\n')
            config.chmod(0o600)
            with mock.patch.dict(os.environ, {
                "KIOKU_NATIVE_BUILDER_NAME": "native-builder",
                "KIOKU_NATIVE_BUILDER_ID": "builder-id",
                "DOCKER_HOST": "unix:///var/run/native-builder.sock",
                "KIOKU_RELEASE_NATIVE_DOCKER_CONFIG": str(docker_config),
                "KIOKU_RELEASE_NATIVE_BUILDX_CONFIG": str(buildx_config),
            }, clear=True):
                with self.assertRaises(MODULE.AdapterError):
                    MODULE._native_child_env(include_cloud=False)

    def test_native_ssh_transport_requires_exact_host_pin_and_strict_options(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            docker_config = root / "docker"
            buildx_config = root / "buildx"
            docker_config.mkdir(mode=0o700)
            buildx_config.mkdir(mode=0o700)
            known_hosts = root / "known_hosts"
            host_key = "SHA256:abcdefghijklmnop"
            known_hosts.write_text(f"builder.example {host_key}\n")
            known_hosts.chmod(0o600)
            base = {
                "KIOKU_NATIVE_BUILDER_NAME": "native-builder",
                "KIOKU_NATIVE_BUILDER_ID": "builder-id",
                "DOCKER_HOST": "ssh://builder.example",
                "DOCKER_SSH_KNOWN_HOSTS": str(known_hosts),
                "DOCKER_SSH_HOST_KEY_SHA256": host_key,
                "DOCKER_SSH_COMMAND": f"ssh -o StrictHostKeyChecking=yes -o UserKnownHostsFile={known_hosts}",
                "KIOKU_RELEASE_NATIVE_DOCKER_CONFIG": str(docker_config),
                "KIOKU_RELEASE_NATIVE_BUILDX_CONFIG": str(buildx_config),
            }
            with mock.patch.dict(os.environ, base, clear=True):
                child = MODULE._native_child_env(include_cloud=False)
            self.assertEqual(child["DOCKER_SSH_HOST_KEY_SHA256"], host_key)
            with mock.patch.dict(os.environ, {**base, "DOCKER_SSH_COMMAND": "ssh -o StrictHostKeyChecking=no"}, clear=True):
                with self.assertRaises(MODULE.AdapterError):
                    MODULE._native_child_env(include_cloud=False)


if __name__ == "__main__":
    unittest.main()
