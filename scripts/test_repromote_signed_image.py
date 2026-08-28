#!/usr/bin/env python3
"""Hermetic contracts for exact signed OCI image re-promotion."""

from __future__ import annotations

import argparse
import importlib.util
from pathlib import Path
import tempfile
import types
import unittest
from unittest import mock


SCRIPT = Path(__file__).with_name("repromote_signed_image.py")
SPEC = importlib.util.spec_from_file_location("repromote_signed_image", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)

TAG = "v1.2.3"
COMMIT = "a" * 40
DIGEST = "sha256:" + "b" * 64
CONFIG_HASH = "c" * 64


class RepromoteSignedImageTests(unittest.TestCase):
    def arguments(self, directory: Path, config: Path, *, apply: bool = False) -> argparse.Namespace:
        return argparse.Namespace(
            evidence_dir=directory,
            config=config,
            repository="owner/repository",
            tag=TAG,
            commit=COMMIT,
            digest=DIGEST,
            apply=apply,
            confirm=f"REPROMOTE SIGNED IMAGE {TAG} {DIGEST}" if apply else "",
        )

    def fixture(self, directory: Path) -> tuple[dict[str, object], dict[str, object]]:
        artifact = directory / MODULE.OCI_ARTIFACT_NAME
        artifact.write_bytes(b"retained-oci")
        artifact.chmod(0o600)
        bundle = {
            "evidence": {
                "config_sha256": CONFIG_HASH,
                "image_digest": DIGEST,
                "image_uri": (
                    "us-central1-docker.pkg.dev/kioku-joerodriguez/kioku/"
                    f"kioku-enclave:{TAG}"
                ),
            }
        }
        receipt = {
            "inputs": {"source_commit": COMMIT, "config_sha256": CONFIG_HASH},
            "outputs": {
                "artifact": str(artifact),
                "artifact_sha256": "d" * 64,
                "artifact_manifest_digest": DIGEST,
            },
        }
        return bundle, receipt

    def test_dry_run_authenticates_exact_artifact_without_pushing(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            directory.chmod(0o700)
            config = directory / "operator.env"
            config.write_text("A=B\n", encoding="utf-8")
            config.chmod(0o600)
            bundle, receipt = self.fixture(directory)
            snapshot = types.SimpleNamespace(sha256=CONFIG_HASH)
            with (
                mock.patch.object(MODULE, "acquire_run_lock", return_value=7),
                mock.patch.object(MODULE, "release_run_lock") as release,
                mock.patch.object(MODULE, "verify_signed_bundle", return_value=bundle),
                mock.patch.object(MODULE, "stage_receipt_candidates", return_value=[receipt]),
                mock.patch.object(
                    MODULE,
                    "configured_environment_snapshot",
                    return_value=({"REGION": "us-central1"}, "builder@example.test", snapshot),
                ),
                mock.patch.object(MODULE, "authenticate_and_push") as push,
            ):
                MODULE.repromote(self.arguments(directory, config))
            push.assert_not_called()
            release.assert_called_once_with(7)

    def test_apply_uses_existing_quarantined_push_and_exact_digest(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            directory.chmod(0o700)
            config = directory / "operator.env"
            config.write_text("A=B\n", encoding="utf-8")
            config.chmod(0o600)
            bundle, receipt = self.fixture(directory)
            snapshot = types.SimpleNamespace(sha256=CONFIG_HASH)
            with (
                mock.patch.object(MODULE, "acquire_run_lock", return_value=8),
                mock.patch.object(MODULE, "release_run_lock"),
                mock.patch.object(MODULE, "verify_signed_bundle", return_value=bundle),
                mock.patch.object(MODULE, "stage_receipt_candidates", return_value=[receipt]),
                mock.patch.object(
                    MODULE,
                    "configured_environment_snapshot",
                    return_value=({"REGION": "us-central1"}, "builder@example.test", snapshot),
                ),
                mock.patch.object(MODULE, "configure_direct_child_environment") as configure,
                mock.patch.object(MODULE, "authenticate_and_push", return_value=DIGEST) as push,
                mock.patch.object(MODULE, "verify_registry_digest") as verify,
            ):
                MODULE.repromote(self.arguments(directory, config, apply=True))
            configure.assert_called_once_with("push")
            push.assert_called_once()
            verify.assert_called_once_with(
                bundle["evidence"]["image_uri"], "builder@example.test", DIGEST
            )

    def test_mismatched_manifest_digest_refuses_before_push(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            directory.chmod(0o700)
            config = directory / "operator.env"
            config.write_text("A=B\n", encoding="utf-8")
            config.chmod(0o600)
            bundle, receipt = self.fixture(directory)
            receipt["outputs"]["artifact_manifest_digest"] = "sha256:" + "e" * 64
            with mock.patch.object(MODULE, "stage_receipt_candidates", return_value=[receipt]):
                with self.assertRaisesRegex(MODULE.RepromotionError, "exact signed build output"):
                    MODULE.exact_artifact(directory, bundle, commit=COMMIT, digest=DIGEST)

    def test_owner_has_no_build_scan_or_signing_surface(self) -> None:
        source = SCRIPT.read_text(encoding="utf-8")
        for forbidden in (
            "docker buildx build",
            "sbom_and_scan(",
            "create_release_evidence(",
            "local_build_evidence.py create",
            "gh release create",
        ):
            self.assertNotIn(forbidden, source)
        self.assertIn("authenticate_and_push(", source)
        self.assertIn("verify_registry_digest(", source)


if __name__ == "__main__":
    unittest.main()
