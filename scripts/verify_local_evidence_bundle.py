#!/usr/bin/env python3
"""Verify a complete signed local enclave evidence bundle before a rollout.

This executable is deliberately suitable for ``KIOKU_ENCLAVE_EVIDENCE_VERIFY``:
it uses an externally pinned Ed25519 key, checks the exact bytes named by the
signed manifest, validates schema-9 or either exact fresh schema-10 release
metadata, and emits the verified
source and digest bindings as JSON.  It never reads cloud credentials or
changes local or remote state.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
SAFE_AMBIENT_GIT_ENV = frozenset({"GIT_NO_REPLACE_OBJECTS", "GIT_PAGER"})
SCHEMA9_BUCKET_DEFAULTS = (
    "kioku-joerodriguez-enclave-indexes",
    "kioku-joerodriguez-enclave-media",
    "kioku-joerodriguez-enclave-indexes",
)
sys.path.insert(0, str(SCRIPTS))
import local_build_evidence  # noqa: E402
import local_image_pipeline  # noqa: E402
import verify_release_metadata  # noqa: E402


def fail(message: str) -> "NoReturn":
    raise SystemExit(f"local evidence bundle: {message}")


def sha256(path: Path) -> str:
    try:
        with path.open("rb") as handle:
            return hashlib.file_digest(handle, "sha256").hexdigest()
    except OSError as error:
        fail(f"cannot hash {path.name}: {error}")


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
    replacements = git_output("replace", "-l").splitlines()
    if replacements:
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


def bind_configuration_bucket(
    arguments: argparse.Namespace, attribute: str, configured: str
) -> None:
    supplied = getattr(arguments, attribute)
    if supplied is not None and supplied != configured:
        fail("explicit bucket expectation differs from the signed configuration")
    setattr(arguments, attribute, configured)


def verify_signature(arguments: argparse.Namespace, manifest: Path, signature: Path) -> dict[str, Any]:
    # Reuse the canonical, pinned-key verifier directly rather than accepting a
    # caller-provided shell command.  It validates the manifest before OpenSSL.
    manifest_bytes = local_build_evidence.read_regular_bytes(manifest, "manifest")
    data = local_build_evidence.read_manifest_bytes(manifest_bytes)
    signature_bytes = local_build_evidence.read_regular_bytes(signature, "signature")
    public_key_bytes = local_build_evidence.read_regular_bytes(arguments.public_key, "public key")
    expected = arguments.expected_public_key_sha256.lower()
    if not local_build_evidence.SHA256.fullmatch(expected):
        fail("expected public-key fingerprint must be a lowercase sha256")
    actual = local_build_evidence.public_fingerprint_bytes(public_key_bytes)
    if actual != expected:
        fail("public key does not match the external trust anchor")
    local_build_evidence.verify_detached_bytes(
        manifest_bytes, signature_bytes, public_key_bytes
    )
    return data


def metadata_arguments(
    arguments: argparse.Namespace, metadata: dict[str, Any]
) -> argparse.Namespace:
    repository = arguments.repository
    if repository.startswith("https://github.com/"):
        repository = repository.removeprefix("https://github.com/")
    image_repository = arguments.image_repository
    if not image_repository:
        try:
            image_repository = metadata["image_digest_uri"].split("@", 1)[0]
        except (KeyError, AttributeError):
            fail("release metadata does not contain an image digest URI")
    return argparse.Namespace(
        repository=repository,
        tag=arguments.tag,
        commit=arguments.commit,
        image_repository=image_repository,
        expected_gcs_bucket=arguments.expected_gcs_bucket,
        expected_gcs_media_bucket=arguments.expected_gcs_media_bucket,
        expected_gcs_legacy_media_bucket=arguments.expected_gcs_legacy_media_bucket,
        expected_adr0022_canary_identity_preparation_sha256=(
            arguments.expected_adr0022_canary_identity_preparation_sha256
        ),
        expected_adr0022_canary_admin_uuid=(
            arguments.expected_adr0022_canary_admin_uuid
        ),
        archive_witness_probe_config=arguments.archive_witness_probe_config,
        archive_v3_shadow_runtime_config=arguments.archive_v3_shadow_runtime_config,
        metadata=metadata,
    )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence-dir", type=Path, required=True)
    parser.add_argument("--public-key", type=Path, default=os.environ.get("LOCAL_BUILD_EVIDENCE_PUBLIC_KEY"))
    parser.add_argument("--expected-public-key-sha256", default=os.environ.get("LOCAL_BUILD_EVIDENCE_PUBLIC_KEY_SHA256"))
    parser.add_argument("--repository", required=True)
    parser.add_argument("--release-tag", "--tag", dest="tag", required=True)
    parser.add_argument("--source-commit", "--commit", dest="commit", required=True)
    parser.add_argument("--image-digest-uri")
    parser.add_argument("--image-digest")
    parser.add_argument("--image-repository")
    parser.add_argument("--expected-gcs-bucket")
    parser.add_argument("--expected-gcs-media-bucket")
    parser.add_argument("--expected-gcs-legacy-media-bucket")
    parser.add_argument("--config", type=Path)
    parser.add_argument(
        "--source-archive",
        type=Path,
        help="optional immutable Git archive whose bytes must match the signed source_archive_sha256 claim",
    )
    parser.add_argument("--archive-witness-probe-config", type=Path, default=ROOT / "config/archive-witness-probe.json")
    parser.add_argument("--archive-v3-shadow-runtime-config", type=Path, default=ROOT / "config/archive-v3-shadow-runtime.json")
    arguments = parser.parse_args()
    if arguments.public_key is None or not arguments.expected_public_key_sha256:
        fail("public key and fingerprint must be supplied by flags or LOCAL_BUILD_EVIDENCE_* environment")
    reject_git_replacement_objects()
    if arguments.repository.startswith("https://github.com/"):
        arguments.repository = arguments.repository.removeprefix("https://github.com/")
    if not local_build_evidence.text(arguments.repository, "repository") or "/" not in arguments.repository:
        fail("repository must be an OWNER/REPO name or GitHub HTTPS URL")
    if bool(arguments.image_digest_uri) != bool(arguments.image_digest):
        fail("image digest URI and image digest must be supplied together")
    arguments.expected_adr0022_canary_identity_preparation_sha256 = ""
    arguments.expected_adr0022_canary_admin_uuid = ""

    directory = arguments.evidence_dir.resolve()
    manifest = directory / "enclave-local-build-evidence.json"
    signature = directory / "enclave-local-build-evidence.sig"
    metadata_path = directory / "enclave-release.json"
    sbom = directory / "enclave-sbom.spdx.json"
    scan = directory / "enclave-scan.json"
    if not directory.is_dir() or any(not path.is_file() for path in (manifest, signature, metadata_path, sbom, scan)):
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
    for path, field in ((ROOT / "Dockerfile", "dockerfile_sha256"), (ROOT / "Cargo.lock", "cargo_lock_sha256")):
        if sha256_bytes(local_build_evidence.read_regular_bytes(path, path.name)) != evidence[field]:
            fail(f"signed evidence {field} differs from checked source")
    config_bytes: bytes | None = None
    if arguments.config is not None:
        config_bytes = local_build_evidence.read_regular_bytes(
            arguments.config, "configuration"
        )
        if sha256_bytes(config_bytes) != evidence["config_sha256"]:
            fail("signed evidence config hash differs from the selected local configuration")
    if "source_archive_sha256" in evidence:
        if arguments.source_archive is not None:
            archive_bytes = local_build_evidence.read_regular_bytes(arguments.source_archive, "source archive")
        else:
            archive_bytes = git_output(
                "archive", "--format=tar", evidence["source_commit"]
            )
        if sha256_bytes(archive_bytes) != evidence["source_archive_sha256"]:
            fail("signed evidence source archive hash differs from the selected immutable archive")

    try:
        metadata = verify_release_metadata.parse_metadata_bytes(metadata_bytes)
        sbom_document = json.loads(sbom_bytes)
        json.loads(scan_bytes)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        fail(f"evidence asset is not valid JSON: {error}")
    if not isinstance(metadata, dict) or not isinstance(sbom_document, dict):
        fail("metadata and SBOM must be JSON objects")
    if metadata["schema_version"] == 10:
        if config_bytes is None:
            fail("schema-10 fresh release verification requires the exact configuration")
        try:
            operator_values = local_image_pipeline._parse_operator_config(config_bytes)
            configuration = local_image_pipeline.selected_configuration(
                "production",
                operator_values,
                source_ref=arguments.tag,
                probe_config_path=arguments.archive_witness_probe_config,
                shadow_runtime_config_path=arguments.archive_v3_shadow_runtime_config,
            )
        except (local_image_pipeline.PipelineError, SystemExit):
            fail("schema-10 fresh release configuration is invalid")
        arguments.expected_adr0022_canary_identity_preparation_sha256 = configuration[
            "ADR0022_CANARY_IDENTITY_PREPARATION_SHA256"
        ]
        arguments.expected_adr0022_canary_admin_uuid = configuration["ADMIN_USER_IDS"]
        bind_configuration_bucket(
            arguments, "expected_gcs_bucket", configuration["ENCLAVE_GCS_BUCKET"]
        )
        bind_configuration_bucket(
            arguments,
            "expected_gcs_media_bucket",
            configuration["ENCLAVE_GCS_MEDIA_BUCKET"],
        )
        bind_configuration_bucket(
            arguments,
            "expected_gcs_legacy_media_bucket",
            configuration["ENCLAVE_GCS_LEGACY_MEDIA_BUCKET"],
        )
    else:
        for attribute, default in zip(
            (
                "expected_gcs_bucket",
                "expected_gcs_media_bucket",
                "expected_gcs_legacy_media_bucket",
            ),
            SCHEMA9_BUCKET_DEFAULTS,
            strict=True,
        ):
            if getattr(arguments, attribute) is None:
                setattr(arguments, attribute, default)
    sbom_version = sbom_document.get("spdxVersion")
    if not isinstance(sbom_version, str) or not sbom_version.startswith("SPDX-"):
        fail("SBOM does not declare an SPDX version")
    if not arguments.image_repository:
        image_digest_uri = metadata.get("image_digest_uri")
        if not isinstance(image_digest_uri, str) or "@" not in image_digest_uri:
            fail("release metadata does not contain an image digest URI")
        arguments.image_repository = image_digest_uri.split("@", 1)[0]
    # Existing verifier has the security-critical checked-config claim logic.
    verify_release_metadata.validate(metadata_arguments(arguments, metadata), metadata)
    bindings = ("source_repository", "source_ref", "source_commit", "image_uri", "image_digest_uri", "image_digest")
    for field in bindings:
        if metadata.get(field) != evidence.get(field):
            fail(f"release metadata {field} does not match signed evidence")
    if evidence["source_repository"] != f"https://github.com/{arguments.repository}":
        fail("signed evidence source repository does not match expected repository")
    if evidence["source_ref"] != arguments.tag or evidence["source_commit"] != arguments.commit:
        fail("signed evidence source does not match expected tag and commit")
    if not evidence["image_uri"].startswith(arguments.image_repository + ":"):
        fail("signed evidence image URI is outside the expected image repository")
    if evidence["image_digest_uri"] != f"{arguments.image_repository}@{evidence['image_digest']}":
        fail("signed evidence image digest URI is outside the expected image repository")
    if arguments.image_digest_uri and evidence["image_digest_uri"] != arguments.image_digest_uri:
        fail("signed evidence image digest URI does not match the rollout request")
    if arguments.image_digest and evidence["image_digest"] != arguments.image_digest:
        fail("signed evidence image digest does not match the rollout request")
    print(json.dumps({"evidence": evidence, "metadata": metadata, "sbom_version": sbom_version}, sort_keys=True, separators=(",", ":"), ensure_ascii=True))


if __name__ == "__main__":
    main()
