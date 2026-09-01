"""Hermetic contracts for the ADR-0033 enclave adapter wrapper."""

from __future__ import annotations

import contextlib
import base64
import hashlib
import importlib.util
import inspect
import io
import json
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest import mock

import test_local_build_evidence as bundle_fixtures  # noqa: E402


MODULE_PATH = Path(__file__).with_name("release_train_enclave.py")
SPEC = importlib.util.spec_from_file_location("release_train_enclave", MODULE_PATH)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)

COORDINATOR_ARTIFACT_DIGEST_FIELDS = frozenset({
    "artifact_digest",
    "content_sha256",
    "local_manifest_digest",
    "remote_digest",
    "push_repo_digest",
    "dmg_sha256",
    "final_dmg_sha256",
    "ipa_sha256",
    "image_digest",
})


def coordinator_witnesses_prepare_artifact(result: dict[str, object], artifact_root: Path) -> bool:
    """Apply the coordinator's current artifact-witness admission rule."""
    expected = result.get("artifact_digest")
    if not isinstance(expected, str):
        return False
    for reference in result.get("artifact_files", []):
        if not isinstance(reference, dict):
            return False
        path = artifact_root / str(reference.get("path", ""))
        data = path.read_bytes()
        if reference.get("digest") != "sha256:" + hashlib.sha256(data).hexdigest():
            return False
        if "sha256:" + hashlib.sha256(data).hexdigest() == expected:
            return True
        if path.suffix.lower() != ".json":
            continue
        payload = json.loads(data)
        if not isinstance(payload, dict):
            continue
        for field in COORDINATOR_ARTIFACT_DIGEST_FIELDS:
            value = payload.get(field)
            if isinstance(value, str):
                normalized = value if value.startswith("sha256:") else "sha256:" + value
                if normalized == expected:
                    return True
    return False


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
            }, clear=False), mock.patch.object(MODULE, "_source_coordinates", return_value=("a" * 40, "b" * 40, "v1.2.3", "1.2.3")), mock.patch.object(MODULE, "_check_config_coordinate"), mock.patch.object(MODULE, "_pipeline"), mock.patch.object(MODULE, "_verify_frozen_source"), mock.patch.object(MODULE, "_native_child_env", return_value={}), mock.patch.object(MODULE, "_artifact", return_value=(artifact, hashlib.sha256(artifact.read_bytes()).hexdigest(), "sha256:" + "a" * 64)):
                result = MODULE.prepare()
                first_witness_bytes = (artifact.parent / MODULE.PREPARE_ARTIFACT_WITNESS).read_bytes()
                resumed = MODULE.prepare()
            self.assertEqual(result["schema"], MODULE.SCHEMA)
            self.assertEqual(result["artifact_digest"], "sha256:" + "a" * 64)
            self.assertEqual(resumed, result)
            witness = artifact.parent / MODULE.PREPARE_ARTIFACT_WITNESS
            witness_bytes = witness.read_bytes()
            witness_payload = json.loads(witness_bytes)
            self.assertEqual(witness_bytes, first_witness_bytes)
            self.assertEqual(witness_bytes, MODULE.canonical(witness_payload))
            self.assertEqual(stat.S_IMODE(witness.stat().st_mode), 0o600)
            self.assertEqual(witness_payload["local_manifest_digest"], result["artifact_digest"])
            self.assertEqual(witness_payload["oci_archive_sha256"], "sha256:" + hashlib.sha256(b"oci fixture").hexdigest())
            self.assertEqual(witness_payload["source_commit"], "a" * 40)
            self.assertEqual(witness_payload["source_tree"], "b" * 40)
            self.assertEqual(witness_payload["source_ref"], "v1.2.3")
            self.assertEqual(witness_payload["version"], "1.2.3")
            files = {item["path"]: item["digest"] for item in result["artifact_files"]}
            self.assertEqual(files["enclave-release/evidence/image.oci"], "sha256:" + hashlib.sha256(b"oci fixture").hexdigest())
            self.assertEqual(
                files["enclave-release/evidence/" + MODULE.PREPARE_ARTIFACT_WITNESS],
                "sha256:" + hashlib.sha256(witness_bytes).hexdigest(),
            )
            self.assertTrue(coordinator_witnesses_prepare_artifact(result, state))

    def test_prepare_artifact_witness_refuses_tampered_existing_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary)
            output.chmod(0o700)
            arguments = {
                "commit": "a" * 40,
                "tree": "b" * 40,
                "tag": "v1.2.3",
                "version": "1.2.3",
                "artifact_hash": "c" * 64,
                "manifest_digest": "sha256:" + "d" * 64,
            }
            witness = MODULE._prepare_artifact_witness(output, **arguments)
            original = witness.read_bytes()
            self.assertEqual(MODULE._prepare_artifact_witness(output, **arguments), witness)
            self.assertEqual(witness.read_bytes(), original)
            witness.write_bytes(MODULE.canonical({"local_manifest_digest": "sha256:" + "e" * 64}))
            witness.chmod(0o600)
            with self.assertRaisesRegex(MODULE.AdapterError, "refusing to overwrite"):
                MODULE._prepare_artifact_witness(output, **arguments)

    def test_adr0033_prepare_publish_uses_forward_resumed_pipeline(self) -> None:
        self.assertIn('_pipeline("build"', inspect.getsource(MODULE.prepare))
        self.assertIn('_pipeline("push"', inspect.getsource(MODULE.publish))
        config = Path("/private/operator.env")
        output = Path("/private/enclave-release/evidence")
        with mock.patch.object(
            MODULE,
            "_native_child_env",
            side_effect=({"STAGE": "build"}, {"STAGE": "push"}),
        ) as child_environment, mock.patch.object(MODULE, "_run") as run:
            MODULE._pipeline("build", config, "v0.9.10", output)
            MODULE._pipeline("push", config, "v0.9.10", output)

        commands = [call.args[0] for call in run.call_args_list]
        self.assertEqual([command[2] for command in commands], ["build", "push"])
        for command in commands:
            self.assertEqual(command[-2:], ("--apply", "--resume"))
            self.assertEqual(command[command.index("--source-ref") + 1], "v0.9.10")
            self.assertEqual(command[command.index("--output-dir") + 1], str(output))
        self.assertEqual(
            child_environment.call_args_list,
            [mock.call(include_cloud=False), mock.call(include_cloud=True)],
        )

    def test_adr0033_prepare_publish_preserves_build_evidence_hash(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            output = root / "enclave-release" / "evidence"
            output.mkdir(mode=0o700, parents=True)
            config = root / "operator.env"
            config.write_text("fixture\n", encoding="utf-8")
            config.chmod(0o600)
            artifact = output / "kioku-enclave.oci.tar"
            artifact.write_bytes(b"oci fixture")
            artifact.chmod(0o600)
            evidence_path = output / "build-evidence.json"
            evidence_bytes = b'{"schema_version":1,"source_commit":"' + b"a" * 40 + b'"}\n'
            evidence_hash = hashlib.sha256(evidence_bytes).hexdigest()
            image_digest = "sha256:" + "d" * 64
            stages: list[str] = []

            def pipeline(stage: str, _config: Path, tag: str, actual_output: Path) -> None:
                self.assertEqual(tag, "v0.9.10")
                self.assertEqual(actual_output, output)
                stages.append(stage)
                if stage == "build":
                    evidence_path.write_bytes(evidence_bytes)
                    evidence_path.chmod(0o600)
                else:
                    self.assertEqual(hashlib.sha256(evidence_path.read_bytes()).hexdigest(), evidence_hash)

            coordinates = ("a" * 40, "b" * 40, "v0.9.10", "0.9.10")
            verified_tag = MODULE.VerifiedTag("v0.9.10", "c" * 40, "a" * 40)
            with contextlib.ExitStack() as stack:
                stack.enter_context(mock.patch.object(MODULE, "_source_coordinates", return_value=coordinates))
                stack.enter_context(mock.patch.object(MODULE, "_config", return_value=config))
                stack.enter_context(mock.patch.object(MODULE, "_check_config_coordinate"))
                stack.enter_context(mock.patch.object(MODULE, "_output_dir", return_value=output))
                stack.enter_context(mock.patch.object(MODULE, "_pipeline", side_effect=pipeline))
                stack.enter_context(mock.patch.object(MODULE, "_verify_frozen_source"))
                stack.enter_context(mock.patch.object(MODULE, "_artifact", return_value=(artifact, hashlib.sha256(artifact.read_bytes()).hexdigest(), image_digest)))
                stack.enter_context(mock.patch.object(MODULE, "_artifact_files", return_value=[]))
                stack.enter_context(mock.patch.object(MODULE, "_private_key", return_value=root / "private.pem"))
                stack.enter_context(mock.patch.object(MODULE, "_public_key", return_value=(root / "public.pem", "e" * 64)))
                stack.enter_context(mock.patch.object(MODULE, "_repository", return_value="example/kioku-enclave"))
                stack.enter_context(mock.patch.object(MODULE, "_image_repository", return_value=("us-docker.pkg.dev/project/repo/image", "reader@example.com")))
                stack.enter_context(mock.patch.object(MODULE, "_capture_verified_tag", return_value=verified_tag))
                stack.enter_context(mock.patch.object(MODULE, "_revalidate_verified_tag"))
                stack.enter_context(mock.patch.object(MODULE, "_receipt", return_value={"image_digest": image_digest}))
                stack.enter_context(mock.patch.object(MODULE, "_coordinate", return_value=image_digest))
                stack.enter_context(mock.patch.object(MODULE, "_sign_evidence"))
                stack.enter_context(mock.patch.object(MODULE, "_immutable_release_snapshot", return_value=contextlib.nullcontext((output, {}))))
                stack.enter_context(mock.patch.object(MODULE, "_verify_bundle", return_value={}))
                stack.enter_context(mock.patch.object(MODULE, "_registry_digest", return_value=image_digest))
                stack.enter_context(mock.patch.object(MODULE, "_confirmation"))
                stack.enter_context(mock.patch.object(MODULE, "_destination", return_value="enclave-artifact-registry-release"))
                stack.enter_context(mock.patch.object(MODULE, "_publish_release"))
                MODULE.prepare()
                MODULE.publish()

            self.assertEqual(stages, ["build", "push"])
            self.assertEqual(evidence_path.read_bytes(), evidence_bytes)
            self.assertEqual(hashlib.sha256(evidence_path.read_bytes()).hexdigest(), evidence_hash)

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
                local.chmod(0o400)
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
                local.chmod(0o400)
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
            verified_tag = MODULE.VerifiedTag("v1.2.3", "c" * 40, "d" * 40)
            with mock.patch.object(MODULE, "_gh", return_value="true") as fake_gh, \
                 mock.patch.object(MODULE, "_revalidate_verified_tag"), \
                 mock.patch.object(MODULE, "_git", return_value="") as fake_git, \
                 mock.patch.object(MODULE, "_verify_remote_tag_binding") as remote_binding, \
                 mock.patch.object(MODULE, "_release_json", return_value=release), \
                 mock.patch.object(MODULE, "_compare_published_assets") as compare:
                MODULE._publish_release(output, "example/kioku-enclave", verified_tag, "sha256:" + "a" * 64)
            compare.assert_called_once_with(output, "example/kioku-enclave", "v1.2.3")
            fake_git.assert_called_once_with(
                "push",
                "origin",
                f"{'c' * 40}:refs/tags/v1.2.3",
                cwd=MODULE.ROOT,
                timeout=300,
            )
            self.assertEqual(remote_binding.call_count, 2)
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

    def test_state_routes_only_frozen_v0_9_16_through_schema_eleven(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            config = root / "config.env"
            config.write_text("CONFIG=fixture\n", encoding="utf-8")
            config.chmod(0o600)
            evidence = root / "evidence"
            evidence.mkdir(mode=0o700)
            digest = "sha256:" + "d" * 64
            metadata_path = evidence / "enclave-release.json"
            metadata_path.write_text(
                json.dumps(
                    {
                        "image_digest": digest,
                        "source_ref": "v0.9.16",
                        "source_commit": "a" * 40,
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            metadata_path.chmod(0o600)
            with mock.patch.dict(
                os.environ,
                {"KIOKU_RELEASE_SOURCE_COMMIT": "a" * 40},
                clear=True,
            ), mock.patch.object(
                MODULE,
                "_source_coordinates",
                return_value=("a" * 40, "b" * 40, "v0.9.16", "0.9.16"),
            ), mock.patch.object(
                MODULE, "_config", return_value=config
            ), mock.patch.object(
                MODULE, "_check_config_coordinate"
            ), mock.patch.object(
                MODULE, "_repository", return_value="owner/repository"
            ), mock.patch.object(
                MODULE,
                "_image_repository",
                return_value=("us-docker.pkg.dev/project/repo/image", "reader@example.com"),
            ), mock.patch.object(
                MODULE, "_release_json", return_value={"assets": []}
            ), mock.patch.object(
                MODULE, "_output_dir", return_value=root
            ), mock.patch.object(
                MODULE, "_download_release", return_value=evidence
            ), mock.patch.object(
                MODULE, "_verify_bundle", return_value={"metadata": {"schema_version": 11}}
            ) as verifier, mock.patch.object(
                MODULE, "_registry_digest", return_value=digest
            ), mock.patch.object(
                MODULE, "_expected_assets"
            ):
                result = MODULE.state("enclave-artifact-registry-release")
        self.assertTrue(result["state"]["present"])
        self.assertTrue(
            verifier.call_args.kwargs["allow_frozen_v0_9_16_schema_11_state"]
        )

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
            unsafe_mode.chmod(0o755)
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
            unsafe_child.chmod(0o755)
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
        self.assertEqual(child_env["GIT_NO_REPLACE_OBJECTS"], "1")
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

    def test_adapter_bundle_call_requires_current_schema_twelve_with_exact_digest_uri(self) -> None:
        helper = bundle_fixtures.LocalEvidenceTests()
        image_repository = (
            "us-central1-docker.pkg.dev/kioku-joerodriguez/kioku/kioku-enclave"
        )
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            _, _, public, fingerprint = helper.create_bundle(directory)
            environment = {
                "KIOKU_RELEASE_EVIDENCE_PUBLIC_KEY": str(public),
                "KIOKU_RELEASE_EVIDENCE_PUBLIC_KEY_SHA256": fingerprint,
            }
            with mock.patch.dict(os.environ, environment, clear=False), mock.patch.object(
                MODULE, "_repository", return_value="owner/repository"
            ):
                result = MODULE._verify_bundle(
                    directory,
                    directory / "local.env",
                    bundle_fixtures.COMMIT,
                    bundle_fixtures.TAG,
                    bundle_fixtures.DIGEST,
                    image_repository=image_repository,
                )
        self.assertEqual(result["metadata"]["schema_version"], 12)
        self.assertEqual(
            result["evidence"]["image_digest_uri"],
            f"{image_repository}@{bundle_fixtures.DIGEST}",
        )

    def test_frozen_v0_9_16_state_accepts_schema_eleven_but_prepare_does_not(self) -> None:
        helper = bundle_fixtures.LocalEvidenceTests()
        image_repository = (
            "us-central1-docker.pkg.dev/kioku-joerodriguez/kioku/kioku-enclave"
        )
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            _, _, public, fingerprint = helper.create_bundle(
                directory, metadata_schema=11, tag="v0.9.16"
            )
            environment = {
                "KIOKU_RELEASE_EVIDENCE_PUBLIC_KEY": str(public),
                "KIOKU_RELEASE_EVIDENCE_PUBLIC_KEY_SHA256": fingerprint,
            }
            with mock.patch.dict(os.environ, environment, clear=False), mock.patch.object(
                MODULE, "_repository", return_value="owner/repository"
            ):
                with self.assertRaises(MODULE.AdapterError):
                    MODULE._verify_bundle(
                        directory,
                        directory / "local.env",
                        bundle_fixtures.COMMIT,
                        "v0.9.16",
                        bundle_fixtures.DIGEST,
                        image_repository=image_repository,
                    )
                result = MODULE._verify_bundle(
                    directory,
                    directory / "local.env",
                    bundle_fixtures.COMMIT,
                    "v0.9.16",
                    bundle_fixtures.DIGEST,
                    image_repository=image_repository,
                    allow_frozen_v0_9_16_schema_11_state=True,
                )
        self.assertEqual(result["metadata"]["schema_version"], 11)

    def test_adapter_rejects_git_overrides_replacements_and_grafts(self) -> None:
        with mock.patch.dict(
            os.environ,
            {"GIT_OBJECT_DIRECTORY": "/tmp/unreviewed-objects"},
            clear=False,
        ):
            with self.assertRaisesRegex(MODULE.AdapterError, "GIT_OBJECT_DIRECTORY"):
                MODULE._base_child_env()
        with mock.patch.object(MODULE, "_git", return_value="a" * 40):
            with self.assertRaisesRegex(MODULE.AdapterError, "replacement refs"):
                MODULE._reject_git_replacement_objects()
        with tempfile.TemporaryDirectory() as temporary:
            graft = Path(temporary) / "grafts"
            graft.write_text("fixture\n", encoding="utf-8")
            with mock.patch.object(MODULE, "_git", side_effect=("", str(graft))):
                with self.assertRaisesRegex(MODULE.AdapterError, "graft files"):
                    MODULE._reject_git_replacement_objects()

    def test_annotated_tag_capture_rejects_alias_and_verifies_exact_object(self) -> None:
        object_id = "c" * 40
        commit = "d" * 40

        def aliased_git(*arguments: str, **_kwargs: object) -> str:
            if arguments[:2] == ("rev-parse", "--verify"):
                return object_id
            if arguments[:2] == ("cat-file", "-t"):
                return "tag"
            if arguments[:2] == ("cat-file", "tag"):
                return (
                    f"object {commit}\ntype commit\ntag v9.9.9\n"
                    "tagger Test <test@example.invalid> 0 +0000\n\nrelease"
                )
            if arguments == ("rev-parse", f"{object_id}^{{commit}}"):
                return commit
            raise AssertionError(arguments)

        with mock.patch.object(MODULE, "_reject_git_replacement_objects"), \
             mock.patch.object(MODULE, "_git", side_effect=aliased_git), \
             mock.patch.object(MODULE, "_verify_tag_signer") as signer:
            with self.assertRaisesRegex(MODULE.AdapterError, "tag name"):
                MODULE._capture_verified_tag("v1.2.3", commit)
        signer.assert_not_called()

        def exact_git(*arguments: str, **_kwargs: object) -> str:
            if arguments[:2] == ("rev-parse", "--verify"):
                return object_id
            if arguments[:2] == ("cat-file", "-t"):
                return "tag"
            if arguments[:2] == ("cat-file", "tag"):
                return (
                    f"object {commit}\ntype commit\ntag v1.2.3\n"
                    "tagger Test <test@example.invalid> 0 +0000\n\nrelease"
                )
            if arguments == ("rev-parse", f"{object_id}^{{commit}}"):
                return commit
            raise AssertionError(arguments)

        with mock.patch.object(MODULE, "_reject_git_replacement_objects"), \
             mock.patch.object(MODULE, "_git", side_effect=exact_git), \
             mock.patch.object(MODULE, "_verify_tag_signer") as signer:
            captured = MODULE._capture_verified_tag("v1.2.3", commit)
        self.assertEqual(captured, MODULE.VerifiedTag("v1.2.3", object_id, commit))
        signer.assert_called_once_with(object_id)

    def test_tag_signer_accepts_pinned_ssh_fingerprint_from_stderr(self) -> None:
        object_id = "c" * 40
        fingerprint = "SHA256:YWJjZGVmZw"
        completed = mock.Mock(
            returncode=0,
            stdout="",
            stderr=f'Good "git" signature for release with ED25519 key {fingerprint}\n',
        )
        with mock.patch.dict(
            os.environ,
            {"KIOKU_RELEASE_TAG_SIGNER_FINGERPRINT": fingerprint},
            clear=False,
        ), mock.patch.object(MODULE.subprocess, "run", return_value=completed) as child:
            MODULE._verify_tag_signer(object_id)
        self.assertEqual(
            child.call_args.args[0],
            ("git", "--no-replace-objects", "verify-tag", "--raw", object_id),
        )
        self.assertEqual(child.call_args.kwargs["env"]["GIT_NO_REPLACE_OBJECTS"], "1")

    def test_remote_tag_readback_requires_exact_object_and_peel_without_refs_mode(self) -> None:
        tag = MODULE.VerifiedTag("v1.2.3", "c" * 40, "d" * 40)
        exact = (
            f"{tag.object_id}\trefs/tags/{tag.name}\n"
            f"{tag.commit}\trefs/tags/{tag.name}^{{}}\n"
        )
        with mock.patch.object(MODULE, "_git", return_value=exact) as git:
            MODULE._verify_remote_tag_binding(tag)
        arguments = git.call_args.args
        self.assertIn("--tags", arguments)
        self.assertNotIn("--refs", arguments)
        mismatched = exact.replace(tag.commit, "e" * 40)
        with mock.patch.object(MODULE, "_git", return_value=mismatched):
            with self.assertRaisesRegex(MODULE.AdapterError, "peeled commit"):
                MODULE._verify_remote_tag_binding(tag)

    def test_release_asset_snapshot_is_read_only_and_survives_source_mutation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary)
            expected: dict[str, bytes] = {}
            for index, name in enumerate(MODULE._RELEASE_ASSET_NAMES):
                data = f"asset-{index}".encode()
                expected[name] = data
                path = output / name
                path.write_bytes(data)
                path.chmod(0o600)
            with MODULE._immutable_release_snapshot(output) as (snapshot, hashes):
                self.assertEqual(stat.S_IMODE(snapshot.stat().st_mode), 0o500)
                for name, data in expected.items():
                    snapshotted = snapshot / name
                    self.assertEqual(stat.S_IMODE(snapshotted.stat().st_mode), 0o400)
                    self.assertEqual(snapshotted.read_bytes(), data)
                    self.assertEqual(hashes[name], "sha256:" + hashlib.sha256(data).hexdigest())
                (output / MODULE._RELEASE_ASSET_NAMES[0]).write_bytes(b"mutated")
                self.assertEqual(
                    (snapshot / MODULE._RELEASE_ASSET_NAMES[0]).read_bytes(),
                    expected[MODULE._RELEASE_ASSET_NAMES[0]],
                )
                snapshot_path = snapshot
            self.assertFalse(snapshot_path.exists())


if __name__ == "__main__":
    unittest.main()
