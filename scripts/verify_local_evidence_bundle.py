#!/usr/bin/env python3
"""Verify a signed PostgreSQL-only enclave evidence bundle before rollout."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
from typing import Any, NoReturn


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
SAFE_AMBIENT_GIT_ENV = frozenset({"GIT_NO_REPLACE_OBJECTS", "GIT_PAGER"})
sys.path.insert(0, str(SCRIPTS))
import local_build_evidence  # noqa: E402
import local_image_pipeline  # noqa: E402
import verify_release_metadata  # noqa: E402


def fail(message: str) -> NoReturn:
    raise SystemExit(f"local evidence bundle: {message}")


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def reviewed_git_environment() -> dict[str, str]:
    unexpected = sorted(
        name
        for name in os.environ
        if name.startswith("GIT_") and name not in SAFE_AMBIENT_GIT_ENV
    )
    if unexpected:
        fail("ambient Git overrides are not accepted: " + ", ".join(unexpected))
    if os.environ.get("GIT_NO_REPLACE_OBJECTS", "1") != "1":
        fail("GIT_NO_REPLACE_OBJECTS must be exactly 1 when supplied")
    environment = {
        name: value
        for name, value in os.environ.items()
        if name in {"PATH", "HOME", "XDG_STATE_HOME", "LC_ALL", "TMPDIR"}
    }
    environment["GIT_NO_REPLACE_OBJECTS"] = "1"
    return environment


def git_output(*arguments: str) -> bytes:
    completed = subprocess.run(
        ["git", "--no-replace-objects", *arguments],
        cwd=ROOT,
        env=reviewed_git_environment(),
        capture_output=True,
        check=False,
    )
    if completed.returncode:
        fail("cannot inspect the checked source repository")
    return completed.stdout


def reject_git_replacement_objects() -> None:
    if git_output("replace", "-l").splitlines():
        fail("Git replacement refs are not accepted")
    graft_path_bytes = git_output(
        "rev-parse", "--path-format=absolute", "--git-path", "info/grafts"
    ).strip()
    try:
        graft_path = Path(os.fsdecode(graft_path_bytes))
    except UnicodeError:
        fail("cannot resolve the repository graft-file path")
    if not graft_path.is_absolute():
        fail("cannot resolve the repository graft-file path")
    if os.path.lexists(graft_path):
        fail("Git graft files are not accepted")


def verify_signature(
    arguments: argparse.Namespace, manifest: Path, signature: Path
) -> dict[str, Any]:
    manifest_bytes = local_build_evidence.read_regular_bytes(manifest, "manifest")
    data = local_build_evidence.read_manifest_bytes(manifest_bytes)
    signature_bytes = local_build_evidence.read_regular_bytes(signature, "signature")
    public_key_bytes = local_build_evidence.read_regular_bytes(arguments.public_key, "public key")
    expected = arguments.expected_public_key_sha256.lower()
    if not local_build_evidence.SHA256.fullmatch(expected):
        fail("expected public-key fingerprint must be a lowercase sha256")
    if local_build_evidence.public_fingerprint_bytes(public_key_bytes) != expected:
        fail("public key does not match the external trust anchor")
    local_build_evidence.verify_detached_bytes(
        manifest_bytes, signature_bytes, public_key_bytes
    )
    return data


def metadata_arguments(
    arguments: argparse.Namespace,
    metadata: dict[str, Any],
    configuration: dict[str, str],
) -> argparse.Namespace:
    repository = arguments.repository.removeprefix("https://github.com/")
    image_repository = arguments.image_repository
    if not image_repository:
        try:
            image_repository = metadata["image_digest_uri"].split("@", 1)[0]
        except (KeyError, AttributeError):
            fail("release metadata does not contain an image digest URI")
    expected_media = configuration["ENCLAVE_GCS_MEDIA_BUCKET"]
    if (
        arguments.expected_gcs_media_bucket is not None
        and arguments.expected_gcs_media_bucket != expected_media
    ):
        fail("explicit media-bucket expectation differs from signed configuration")
    return argparse.Namespace(
        repository=repository,
        tag=arguments.tag,
        commit=arguments.commit,
        image_repository=image_repository,
        expected_gcs_media_bucket=expected_media,
        expected_kms_project=configuration["ENCLAVE_KMS_PROJECT"],
        expected_kms_location=configuration["ENCLAVE_KMS_LOCATION"],
        expected_kms_key_ring=configuration["ENCLAVE_KMS_KEY_RING"],
        expected_kms_key=configuration["ENCLAVE_KMS_KEY"],
    )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence-dir", type=Path, required=True)
    parser.add_argument(
        "--public-key",
        type=Path,
        default=os.environ.get("LOCAL_BUILD_EVIDENCE_PUBLIC_KEY"),
    )
    parser.add_argument(
        "--expected-public-key-sha256",
        default=os.environ.get("LOCAL_BUILD_EVIDENCE_PUBLIC_KEY_SHA256"),
    )
    parser.add_argument("--repository", required=True)
    parser.add_argument("--release-tag", "--tag", dest="tag", required=True)
    parser.add_argument("--source-commit", "--commit", dest="commit", required=True)
    parser.add_argument("--image-digest-uri")
    parser.add_argument("--image-digest")
    parser.add_argument("--image-repository")
    parser.add_argument("--expected-gcs-media-bucket")
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument(
        "--source-archive",
        type=Path,
        help="optional immutable Git archive whose bytes must match signed source evidence",
    )
    arguments = parser.parse_args()
    if arguments.public_key is None or not arguments.expected_public_key_sha256:
        fail("public key and fingerprint must be supplied by flags or environment")
    reject_git_replacement_objects()
    arguments.repository = arguments.repository.removeprefix("https://github.com/")
    if not local_build_evidence.text(arguments.repository, "repository") or "/" not in arguments.repository:
        fail("repository must be an OWNER/REPO name or GitHub HTTPS URL")
    if bool(arguments.image_digest_uri) != bool(arguments.image_digest):
        fail("image digest URI and image digest must be supplied together")

    directory = arguments.evidence_dir.resolve()
    manifest = directory / "enclave-local-build-evidence.json"
    signature = directory / "enclave-local-build-evidence.sig"
    metadata_path = directory / "enclave-release.json"
    sbom = directory / "enclave-sbom.spdx.json"
    scan = directory / "enclave-scan.json"
    if not directory.is_dir() or any(
        not path.is_file() for path in (manifest, signature, metadata_path, sbom, scan)
    ):
        fail("evidence directory must contain manifest, signature, metadata, SBOM, and scan")
    evidence = verify_signature(arguments, manifest, signature)
    metadata_bytes = local_build_evidence.read_regular_bytes(metadata_path, "release metadata")
    sbom_bytes = local_build_evidence.read_regular_bytes(sbom, "SBOM")
    scan_bytes = local_build_evidence.read_regular_bytes(scan, "scan")
    for path, value, field in (
        (metadata_path, metadata_bytes, "release_metadata_sha256"),
        (sbom, sbom_bytes, "sbom_sha256"),
        (scan, scan_bytes, "scan_sha256"),
    ):
        if sha256_bytes(value) != evidence[field]:
            fail(f"signed evidence does not bind exact {path.name} bytes")
    for path, field in (
        (ROOT / "Dockerfile", "dockerfile_sha256"),
        (ROOT / "Cargo.lock", "cargo_lock_sha256"),
    ):
        if sha256_bytes(local_build_evidence.read_regular_bytes(path, path.name)) != evidence[field]:
            fail(f"signed evidence {field} differs from checked source")

    config_bytes = local_build_evidence.read_regular_bytes(arguments.config, "configuration")
    if sha256_bytes(config_bytes) != evidence["config_sha256"]:
        fail("signed evidence config hash differs from the selected local configuration")
    if "source_archive_sha256" in evidence:
        archive_bytes = (
            local_build_evidence.read_regular_bytes(arguments.source_archive, "source archive")
            if arguments.source_archive is not None
            else git_output("archive", "--format=tar", evidence["source_commit"])
        )
        if sha256_bytes(archive_bytes) != evidence["source_archive_sha256"]:
            fail("signed evidence source archive hash differs from the immutable source")

    try:
        metadata = verify_release_metadata.parse_metadata_bytes(metadata_bytes)
        sbom_document = json.loads(sbom_bytes)
        scan_document = json.loads(scan_bytes)
        operator_values = local_image_pipeline._parse_operator_config(config_bytes)
        configuration = local_image_pipeline.selected_configuration(
            "production", operator_values, source_ref=arguments.tag
        )
    except (UnicodeDecodeError, json.JSONDecodeError, local_image_pipeline.PipelineError, SystemExit):
        fail("evidence assets or selected production configuration are invalid")
    try:
        local_image_pipeline.assert_public_evidence_document(sbom_document, "SBOM")
        local_image_pipeline.assert_public_evidence_document(scan_document, "scan")
    except local_image_pipeline.PipelineError:
        fail("SBOM or scan contains a host-local path")
    if (
        not isinstance(metadata, dict)
        or not isinstance(sbom_document, dict)
        or not isinstance(scan_document, dict)
    ):
        fail("metadata, SBOM, and scan must be JSON objects")
    sbom_version = sbom_document.get("spdxVersion")
    if not isinstance(sbom_version, str) or not sbom_version.startswith("SPDX-"):
        fail("SBOM does not declare an SPDX version")
    verifier_arguments = metadata_arguments(arguments, metadata, configuration)
    verify_release_metadata.validate(verifier_arguments, metadata)

    for field in (
        "source_repository",
        "source_ref",
        "source_commit",
        "image_uri",
        "image_digest_uri",
        "image_digest",
    ):
        if metadata.get(field) != evidence.get(field):
            fail(f"release metadata {field} does not match signed evidence")
    if evidence["source_repository"] != f"https://github.com/{arguments.repository}":
        fail("signed evidence source repository does not match expected repository")
    if evidence["source_ref"] != arguments.tag or evidence["source_commit"] != arguments.commit:
        fail("signed evidence source does not match expected tag and commit")
    if arguments.image_digest_uri and evidence["image_digest_uri"] != arguments.image_digest_uri:
        fail("signed evidence image digest URI does not match the rollout request")
    if arguments.image_digest and evidence["image_digest"] != arguments.image_digest:
        fail("signed evidence image digest does not match the rollout request")
    print(
        json.dumps(
            {"evidence": evidence, "metadata": metadata, "sbom_version": sbom_version},
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        )
    )


if __name__ == "__main__":
    main()
