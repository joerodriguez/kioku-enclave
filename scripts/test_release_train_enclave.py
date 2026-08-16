"""Hermetic contracts for the ADR-0033 enclave adapter wrapper."""

from __future__ import annotations

import contextlib
import base64
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

    def test_existing_immutable_release_requires_exact_bytes_for_every_asset(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            output = root / "prepared"
            source = root / "fake-gh-assets"
            output.mkdir(mode=0o700)
            source.mkdir(mode=0o700)
            for index, name in enumerate(MODULE._RELEASE_ASSET_NAMES):
                local = output / name
                downloaded = source / name
                local.write_bytes(f"prepared-{index}".encode())
                downloaded.write_bytes(f"prepared-{index}".encode())
                local.chmod(0o600)
                downloaded.chmod(0o600)
            def fake_gh(*arguments: str, timeout: int) -> str:
                directory = Path(arguments[arguments.index("--dir") + 1])
                name = arguments[arguments.index("--pattern") + 1]
                target = directory / name
                target.write_bytes((source / name).read_bytes())
                target.chmod(0o644)
                return ""

            with mock.patch.object(MODULE, "_gh", side_effect=fake_gh) as download:
                MODULE._compare_published_assets(output, "example/kioku-enclave", "v1.2.3")
            self.assertEqual(download.call_count, len(MODULE._RELEASE_ASSET_NAMES))

    def test_existing_immutable_release_rejects_one_stale_asset(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            output = root / "prepared"
            remote = root / "downloaded"
            output.mkdir(mode=0o700)
            remote.mkdir(mode=0o700)
            for index, name in enumerate(MODULE._RELEASE_ASSET_NAMES):
                local = output / name
                downloaded = remote / name
                local.write_bytes(f"prepared-{index}".encode())
                downloaded.write_bytes(f"remote-{index}".encode() if index == 2 else f"prepared-{index}".encode())
                local.chmod(0o600)
                downloaded.chmod(0o600)
            with mock.patch.object(MODULE, "_download_release", return_value=remote):
                with self.assertRaisesRegex(MODULE.AdapterError, "immutable GitHub asset differs"):
                    MODULE._compare_published_assets(output, "example/kioku-enclave", "v1.2.3")

    def test_publish_retry_verifies_existing_release_assets_with_fake_gh(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary)
            output.mkdir(mode=0o700, exist_ok=True)
            for index, name in enumerate(MODULE._RELEASE_ASSET_NAMES):
                path = output / name
                path.write_bytes(f"prepared-{index}".encode())
                path.chmod(0o600)
            release = {
                "isDraft": False,
                "isImmutable": True,
                "isPrerelease": False,
                "assets": [{"name": name} for name in MODULE._RELEASE_ASSET_NAMES],
            }
            with mock.patch.object(MODULE, "_gh", return_value="true") as fake_gh, \
                 mock.patch.object(MODULE, "_run"), \
                 mock.patch.object(MODULE, "_release_json", return_value=release), \
                 mock.patch.object(MODULE, "_compare_published_assets") as compare:
                MODULE._publish_release(output, "example/kioku-enclave", "v1.2.3", "sha256:" + "a" * 64)
            compare.assert_called_once_with(output, "example/kioku-enclave", "v1.2.3")
            fake_gh.assert_called_once()

    def test_state_destination_is_allowlisted(self) -> None:
        with self.assertRaises(MODULE.AdapterError):
            MODULE.state("enclave-kms-vm-ledger")

    def test_adapter_rejects_ambiguous_stage_receipts(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary)
            MODULE._image_pipeline.write_stage_receipt(
                output,
                "push",
                {"source_commit": "a" * 40},
                {"image_digest": "sha256:" + "1" * 64},
            )
            payload = {
                "schema_version": 1,
                "stage": "push",
                "inputs": {"source_commit": "a" * 40},
                "outputs": {"image_digest": "sha256:" + "2" * 64},
            }
            encoded = (json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n").encode()
            second = output / ("push-receipt-" + hashlib.sha256(encoded).hexdigest() + ".json")
            second.write_bytes(encoded)
            second.chmod(0o600)
            with self.assertRaisesRegex(MODULE.AdapterError, "ambiguous"):
                MODULE._receipt(output, "push")

    def test_adapter_artifact_must_be_a_valid_oci_archive(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            evidence = root / "enclave-release" / "evidence"
            evidence.mkdir(mode=0o700, parents=True)
            artifact = evidence / "kioku-enclave.oci.tar"
            artifact.write_bytes(b"not an OCI archive")
            artifact.chmod(0o600)
            with mock.patch.dict(os.environ, {"KIOKU_RELEASE_ARTIFACT_ROOT": str(root)}, clear=False), \
                 mock.patch.object(MODULE, "_receipt", return_value={
                     "artifact": str(artifact),
                     "artifact_sha256": hashlib.sha256(artifact.read_bytes()).hexdigest(),
                     "artifact_manifest_digest": "sha256:" + "a" * 64,
                 }):
                with self.assertRaisesRegex(MODULE.AdapterError, "OCI archive"):
                    MODULE._artifact(evidence)

    def test_environment_declares_no_prepare_credentials(self) -> None:
        self.assertIn("CLOUDSDK_CONFIG", MODULE.ENVIRONMENT["coordinates"])
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
                 mock.patch.object(MODULE, "_release_json", return_value=None), \
                 mock.patch.object(MODULE, "_registry_digest_optional", return_value=None):
                result = MODULE.state("enclave-artifact-registry-release")
            self.assertEqual(result["state"], {"version": "1.2.3", "artifact_digest": MODULE.ZERO_DIGEST, "present": False})
            with mock.patch.dict(os.environ, environment, clear=True):
                evidence = MODULE._output_dir(require_artifact_root=False)
            self.assertTrue(evidence.parent.is_dir())
            self.assertEqual(stat.S_IMODE(evidence.parent.stat().st_mode), 0o700)

    def test_state_rejects_registry_tag_without_immutable_evidence_release(self) -> None:
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
                 mock.patch.object(MODULE, "_release_json", return_value=None), \
                 mock.patch.object(MODULE, "_registry_digest_optional", return_value="sha256:" + "c" * 64):
                with self.assertRaisesRegex(MODULE.AdapterError, "Artifact Registry contains"):
                    MODULE.state("enclave-artifact-registry-release")

    def test_reviewed_cloud_children_do_not_inherit_release_credentials(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            cloud_config = Path(temporary) / "gcloud"
            cloud_config.mkdir(mode=0o700)
            with mock.patch.dict(os.environ, {
                "KIOKU_RELEASE_GITHUB_TOKEN": "github-secret",
                "KIOKU_RELEASE_EVIDENCE_PRIVATE_KEY": "/private/key",
                "CLOUDSDK_CONFIG": str(cloud_config),
            }, clear=False):
                gh_environment = MODULE._gh_env()
                gcloud_environment = MODULE._gcloud_env()
        self.assertEqual(gh_environment["GH_TOKEN"], "github-secret")
        self.assertNotIn("KIOKU_RELEASE_EVIDENCE_PRIVATE_KEY", gh_environment)
        self.assertNotIn("KIOKU_RELEASE_GITHUB_TOKEN", gh_environment)
        self.assertEqual(gcloud_environment["CLOUDSDK_CONFIG"], str(cloud_config.resolve()))
        self.assertNotIn("KIOKU_RELEASE_EVIDENCE_PRIVATE_KEY", gcloud_environment)
        self.assertNotIn("KIOKU_RELEASE_GITHUB_TOKEN", gcloud_environment)
        with mock.patch.dict(os.environ, {"GOOGLE_APPLICATION_CREDENTIALS": "/private/creds.json"}, clear=False):
            with self.assertRaisesRegex(MODULE.AdapterError, "GOOGLE_APPLICATION_CREDENTIALS"):
                MODULE._gcloud_env()

    def test_gcloud_config_requires_private_outside_repository_tree(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            valid = root / "gcloud"
            valid.mkdir(mode=0o700)
            with mock.patch.dict(os.environ, {"CLOUDSDK_CONFIG": "relative/gcloud"}, clear=False):
                with self.assertRaisesRegex(MODULE.AdapterError, "absolute"):
                    MODULE._gcloud_env()
            with mock.patch.dict(os.environ, {"CLOUDSDK_CONFIG": str(MODULE.ROOT)}, clear=False):
                with self.assertRaisesRegex(MODULE.AdapterError, "mode-0700"):
                    MODULE._gcloud_env()
            unsafe_mode = root / "unsafe-mode"
            unsafe_mode.mkdir(mode=0o755)
            with mock.patch.dict(os.environ, {"CLOUDSDK_CONFIG": str(unsafe_mode)}, clear=False):
                with self.assertRaisesRegex(MODULE.AdapterError, "mode-0700"):
                    MODULE._gcloud_env()
            symlink = root / "symlink"
            symlink.symlink_to(valid, target_is_directory=True)
            with mock.patch.dict(os.environ, {"CLOUDSDK_CONFIG": str(symlink)}, clear=False):
                with self.assertRaisesRegex(MODULE.AdapterError, "mode-0700"):
                    MODULE._gcloud_env()
            unsafe_child = valid / "nested"
            unsafe_child.mkdir(mode=0o755)
            with mock.patch.dict(os.environ, {"CLOUDSDK_CONFIG": str(valid)}, clear=False):
                with self.assertRaisesRegex(MODULE.AdapterError, "unsafe directory"):
                    MODULE._gcloud_env()
            unsafe_child.chmod(0o700)
            child_target = valid / "child-target"
            child_target.mkdir(mode=0o700)
            child_link = valid / "child-link"
            child_link.symlink_to(child_target, target_is_directory=True)
            with mock.patch.dict(os.environ, {"CLOUDSDK_CONFIG": str(valid)}, clear=False):
                with self.assertRaisesRegex(MODULE.AdapterError, "unsafe directory"):
                    MODULE._gcloud_env()
            ancestor_target = root / "ancestor-target"
            ancestor_target.mkdir(mode=0o700)
            ancestor_target_config = ancestor_target / "gcloud"
            ancestor_target_config.mkdir(mode=0o700)
            ancestor_link = root / "ancestor-link"
            ancestor_link.symlink_to(ancestor_target, target_is_directory=True)
            with mock.patch.dict(os.environ, {"CLOUDSDK_CONFIG": str(ancestor_link / "gcloud")}, clear=False):
                with self.assertRaisesRegex(MODULE.AdapterError, "symlinked ancestry"):
                    MODULE._gcloud_env()

    def test_native_push_requires_validated_cloud_config(self) -> None:
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
            }
            with mock.patch.dict(os.environ, environment, clear=True):
                with self.assertRaisesRegex(MODULE.AdapterError, "CLOUDSDK_CONFIG"):
                    MODULE._native_child_env(include_cloud=True)

    def test_run_default_environment_excludes_ambient_release_secrets(self) -> None:
        with mock.patch.dict(os.environ, {
            "KIOKU_RELEASE_GITHUB_TOKEN": "github-secret",
            "KIOKU_RELEASE_EVIDENCE_PRIVATE_KEY": "/private/key",
            "KIOKU_RELEASE_GCP_READONLY_SERVICE_ACCOUNT": "builder@example.com",
            "GH_TOKEN": "ambient-gh-secret",
            "PATH": "/reviewed/path",
        }, clear=False), mock.patch.object(
            MODULE.subprocess, "run",
            return_value=mock.Mock(returncode=0, stdout="ok", stderr=""),
        ) as child:
            self.assertEqual(MODULE._run(("git", "status")), "ok")
        child_env = child.call_args.kwargs["env"]
        self.assertEqual(child_env["PATH"], "/reviewed/path")
        for secret in (
            "KIOKU_RELEASE_GITHUB_TOKEN",
            "KIOKU_RELEASE_EVIDENCE_PRIVATE_KEY",
            "KIOKU_RELEASE_GCP_READONLY_SERVICE_ACCOUNT",
            "GH_TOKEN",
        ):
            self.assertNotIn(secret, child_env)

    def test_provider_absence_requires_exact_not_found_response(self) -> None:
        self.assertTrue(MODULE._github_release_absence("release not found\n"))
        self.assertTrue(MODULE._github_release_absence("HTTP 404: Not Found\n"))
        self.assertFalse(MODULE._github_release_absence("permission denied: resource not found\n"))
        self.assertFalse(MODULE._github_release_absence("ERROR: 404 proxy failure\n"))

        successful_absence = mock.Mock(returncode=1, stdout="", stderr=(
            "ERROR: (gcloud.artifacts.docker.images.describe) NOT_FOUND: image does not exist\n"
        ))
        with mock.patch.object(MODULE.subprocess, "run", return_value=successful_absence), \
             mock.patch.object(MODULE, "_gcloud_env", return_value={}):
            self.assertIsNone(MODULE._registry_digest_optional("us-docker.pkg.dev/project/repo/image", "v1.2.3", "reader@example.com"))

        ambiguous_failure = mock.Mock(returncode=1, stdout="", stderr="PERMISSION_DENIED: resource not found\n")
        with mock.patch.object(MODULE.subprocess, "run", return_value=ambiguous_failure), \
             mock.patch.object(MODULE, "_gcloud_env", return_value={}):
            with self.assertRaisesRegex(MODULE.AdapterError, "Artifact Registry state command failed"):
                MODULE._registry_digest_optional("us-docker.pkg.dev/project/repo/image", "v1.2.3", "reader@example.com")

        empty_success = mock.Mock(returncode=0, stdout="\n", stderr="")
        with mock.patch.object(MODULE.subprocess, "run", return_value=empty_success), \
             mock.patch.object(MODULE, "_gcloud_env", return_value={}):
            with self.assertRaisesRegex(MODULE.AdapterError, "empty digest response"):
                MODULE._registry_digest_optional("us-docker.pkg.dev/project/repo/image", "v1.2.3", "reader@example.com")

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
            self.assertEqual(child["DOCKER_CONFIG"], str(docker_config.resolve()))
            self.assertEqual(child["BUILDX_CONFIG"], str(buildx_config.resolve()))
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
            key_blob = b"reviewed-builder-host-key"
            encoded_key = base64.b64encode(key_blob).decode("ascii")
            host_key = "SHA256:" + base64.b64encode(hashlib.sha256(key_blob).digest()).decode("ascii").rstrip("=")
            known_hosts.write_text(f"builder.example ssh-ed25519 {encoded_key}\n")
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
