#!/usr/bin/env python3
"""Re-promote one exact signed OCI release artifact without rebuilding it.

This owner exists for destructive registry-floor transitions: the floor may
remove a later, already-reviewed candidate before that candidate is allowed to
roll. Re-promotion authenticates the immutable signed evidence, the original
content-addressed build receipt, and the exact retained OCI bytes, then uses
the existing quarantined push boundary. It never rebuilds, rescans, or signs.
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
sys.path.insert(0, str(SCRIPTS))

from local_image_pipeline import (  # noqa: E402
    OCI_ARTIFACT_NAME,
    PipelineError,
    acquire_run_lock,
    authenticate_and_push,
    configure_direct_child_environment,
    configured_environment_snapshot,
    release_run_lock,
    stage_receipt_candidates,
    verify_registry_digest,
)


DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
TAG = re.compile(r"v[0-9]+\.[0-9]+\.[0-9]+(?:[.-][0-9A-Za-z.-]+)?\Z")
COMMIT = re.compile(r"[0-9a-f]{40}\Z")
REPOSITORY = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+\Z")


class RepromotionError(RuntimeError):
    """A content-free fail-closed repromotion refusal."""


def fail(message: str) -> "NoReturn":
    raise RepromotionError(message)


def canonical_private_directory(path: Path) -> Path:
    source = path.expanduser().absolute()
    metadata = source.lstat()
    if (
        stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or stat.S_IMODE(metadata.st_mode) != 0o700
    ):
        fail("evidence directory must be a private current-user directory")
    canonical = source.resolve(strict=True)
    macos_var_alias = (
        source.parts[:2] == ("/", "var")
        and canonical.parts[:3] == ("/", "private", "var")
        and canonical.parts[3:] == source.parts[2:]
    )
    if canonical != source and not macos_var_alias:
        fail("evidence directory must not have symlinked ancestry")
    return canonical


def verify_signed_bundle(
    evidence_dir: Path,
    config: Path,
    repository: str,
    tag: str,
    commit: str,
    digest: str,
) -> dict[str, Any]:
    public_key = os.environ.get("LOCAL_BUILD_EVIDENCE_PUBLIC_KEY", "")
    public_fingerprint = os.environ.get("LOCAL_BUILD_EVIDENCE_PUBLIC_KEY_SHA256", "")
    if not public_key or not re.fullmatch(r"[0-9a-f]{64}", public_fingerprint):
        fail("external build-evidence trust anchor is missing")
    image_repository = "us-central1-docker.pkg.dev/kioku-joerodriguez/kioku/kioku-enclave"
    digest_uri = f"{image_repository}@{digest}"
    completed = subprocess.run(
        [
            sys.executable,
            str(SCRIPTS / "verify_local_evidence_bundle.py"),
            "--evidence-dir",
            str(evidence_dir),
            "--public-key",
            public_key,
            "--expected-public-key-sha256",
            public_fingerprint,
            "--repository",
            repository,
            "--release-tag",
            tag,
            "--source-commit",
            commit,
            "--image-digest-uri",
            digest_uri,
            "--image-digest",
            digest,
            "--image-repository",
            image_repository,
            "--config",
            str(config),
        ],
        cwd=ROOT,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        check=False,
    )
    if completed.returncode or len(completed.stdout.encode()) > 1024 * 1024:
        fail("signed release evidence did not verify")
    try:
        bundle = json.loads(completed.stdout)
    except json.JSONDecodeError as error:
        raise RepromotionError("signed release verifier returned malformed evidence") from error
    if not isinstance(bundle, dict) or not isinstance(bundle.get("evidence"), dict):
        fail("signed release verifier returned incomplete evidence")
    return bundle


def exact_artifact(
    evidence_dir: Path,
    bundle: dict[str, Any],
    *,
    commit: str,
    digest: str,
) -> tuple[Path, str, str]:
    candidates = stage_receipt_candidates(evidence_dir, "build")
    if len(candidates) != 1:
        fail("exactly one valid content-addressed build receipt is required")
    receipt = candidates[0]
    inputs = receipt.get("inputs")
    outputs = receipt.get("outputs")
    evidence = bundle.get("evidence")
    if not isinstance(inputs, dict) or not isinstance(outputs, dict) or not isinstance(evidence, dict):
        fail("build receipt is malformed")
    artifact = evidence_dir / OCI_ARTIFACT_NAME
    try:
        recorded_artifact = Path(str(outputs.get("artifact"))).resolve(strict=True)
        expected_artifact = artifact.resolve(strict=True)
    except OSError as error:
        raise RepromotionError("retained OCI artifact is unavailable") from error
    artifact_sha256 = outputs.get("artifact_sha256")
    manifest_digest = outputs.get("artifact_manifest_digest")
    if (
        recorded_artifact != expected_artifact
        or inputs.get("source_commit") != commit
        or inputs.get("config_sha256") != evidence.get("config_sha256")
        or manifest_digest != digest
        or evidence.get("image_digest") != digest
        or not isinstance(artifact_sha256, str)
        or not re.fullmatch(r"[0-9a-f]{64}", artifact_sha256)
    ):
        fail("retained OCI artifact is not the exact signed build output")
    return artifact, artifact_sha256, str(manifest_digest)


def repromote(arguments: argparse.Namespace) -> None:
    if not REPOSITORY.fullmatch(arguments.repository):
        fail("repository must be OWNER/REPO")
    if not TAG.fullmatch(arguments.tag) or not COMMIT.fullmatch(arguments.commit):
        fail("release tag or commit is malformed")
    if not DIGEST.fullmatch(arguments.digest):
        fail("image digest must be an exact lowercase sha256")
    evidence_dir = canonical_private_directory(arguments.evidence_dir)
    config = arguments.config.expanduser().resolve(strict=True)
    lock = acquire_run_lock(evidence_dir)
    try:
        bundle = verify_signed_bundle(
            evidence_dir,
            config,
            arguments.repository,
            arguments.tag,
            arguments.commit,
            arguments.digest,
        )
        artifact, artifact_sha256, manifest_digest = exact_artifact(
            evidence_dir, bundle, commit=arguments.commit, digest=arguments.digest
        )
        evidence = bundle["evidence"]
        if not isinstance(evidence, dict):
            fail("signed release verifier returned incomplete evidence")
        configuration, builder_account, snapshot = configured_environment_snapshot(
            config, "production", arguments.tag
        )
        if snapshot.sha256 != evidence.get("config_sha256"):
            fail("selected production configuration is not the signed configuration")
        image_uri = evidence.get("image_uri")
        if not isinstance(image_uri, str) or image_uri != (
            "us-central1-docker.pkg.dev/kioku-joerodriguez/kioku/kioku-enclave:"
            + arguments.tag
        ):
            fail("signed image tag is outside the reviewed repository")
        if not arguments.apply:
            print(f"Signed image repromotion is ready: {arguments.tag} {arguments.digest}")
            return
        expected_confirmation = f"REPROMOTE SIGNED IMAGE {arguments.tag} {arguments.digest}"
        if arguments.confirm != expected_confirmation:
            fail("apply requires the exact signed-image confirmation")
        configure_direct_child_environment("push")
        promoted = authenticate_and_push(
            image_uri,
            configuration,
            builder_account,
            artifact=artifact,
            expected_artifact_sha256=artifact_sha256,
            expected_manifest_digest=manifest_digest,
        )
        if promoted != arguments.digest:
            fail("registry promotion returned a different digest")
        verify_registry_digest(image_uri, builder_account, arguments.digest)
        print(f"Re-promoted exact signed image: {arguments.tag} {arguments.digest}")
    finally:
        release_run_lock(lock)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence-dir", type=Path, required=True)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--release-tag", dest="tag", required=True)
    parser.add_argument("--source-commit", dest="commit", required=True)
    parser.add_argument("--image-digest", dest="digest", required=True)
    parser.add_argument("--apply", action="store_true")
    parser.add_argument("--confirm", default="")
    arguments = parser.parse_args()
    try:
        repromote(arguments)
    except (OSError, PipelineError, RepromotionError) as error:
        print(f"signed image repromotion refused: {error}", file=sys.stderr)
        raise SystemExit(1) from error


if __name__ == "__main__":
    main()
