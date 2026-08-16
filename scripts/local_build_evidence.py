#!/usr/bin/env python3
"""Create, sign, and verify local enclave build evidence.

The evidence is intentionally a small, canonical JSON document.  It records
only hashes of the operator configuration and build outputs: local deployment
configuration can contain personal addresses and must never be copied into a
release asset or a GitHub Release.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile
from typing import Any


SCHEMA_VERSION = 1
SHA256 = re.compile(r"[0-9a-f]{64}\Z")
COMMIT = re.compile(r"[0-9a-f]{40}\Z")
DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
TAG = re.compile(r"v[0-9]+\.[0-9]+\.[0-9]+(?:[.-][0-9A-Za-z.-]+)?\Z")
TIMESTAMP = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z\Z")
FIELDS = {
    "schema_version",
    "source_repository",
    "source_ref",
    "source_commit",
    "image_uri",
    "image_digest_uri",
    "image_digest",
    "config_sha256",
    "dockerfile_sha256",
    "cargo_lock_sha256",
    "release_metadata_sha256",
    "sbom_sha256",
    "scan_sha256",
    "tool_versions",
    "created_at",
    "completed_at",
}
LEGACY_FIELDS = frozenset(FIELDS)
SOURCE_ARCHIVE_FIELD = "source_archive_sha256"
FULL_FIELDS = frozenset((*FIELDS, SOURCE_ARCHIVE_FIELD))


def fail(message: str) -> "NoReturn":
    raise SystemExit(f"local build evidence: {message}")


def canonical(data: dict[str, Any]) -> bytes:
    return (json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n").encode()


def sha256(path: Path) -> str:
    return hashlib.sha256(read_regular_bytes(path, f"hash input {path}")).hexdigest()


def expected_asset_bytes(path: Path, label: str, expected: str) -> bytes:
    """Read one stable asset once and require its scan-receipt hash."""
    if not SHA256.fullmatch(expected):
        fail(f"expected {label} hash must be a lowercase sha256")
    value = read_regular_bytes(path, label)
    actual = hashlib.sha256(value).hexdigest()
    if actual != expected:
        fail(f"{label} does not match the scan receipt hash")
    return value


def text(value: object, field: str) -> str:
    if not isinstance(value, str) or not value or any(ord(c) < 32 or ord(c) == 127 for c in value):
        fail(f"{field} must be a non-empty control-free string")
    return value


def read_regular_bytes(path: Path, label: str) -> bytes:
    try:
        link_metadata = path.lstat()
        if stat.S_ISLNK(link_metadata.st_mode):
            fail(f"{label} must not be a symlink")
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except OSError as error:
        fail(f"cannot open {label}: {error}")
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or (metadata.st_dev, metadata.st_ino)
            != (link_metadata.st_dev, link_metadata.st_ino)
        ):
            fail(f"{label} must be one stable regular file")
        with os.fdopen(descriptor, "rb") as handle:
            descriptor = -1
            before = os.fstat(handle.fileno())
            value = handle.read()
            after = os.fstat(handle.fileno())
            if before.st_size != after.st_size or before.st_mtime_ns != after.st_mtime_ns or len(value) != after.st_size:
                fail(f"{label} changed while it was read")
            return value
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def read_manifest_bytes(raw: bytes) -> dict[str, Any]:
    try:
        data = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        fail(f"cannot parse manifest: {error}")
    if not isinstance(data, dict) or set(data) not in (LEGACY_FIELDS, FULL_FIELDS):
        fail("manifest has missing or unexpected fields")
    if raw != canonical(data):
        fail("manifest is not canonical JSON")
    validate(data)
    return data


def read_manifest(path: Path) -> dict[str, Any]:
    return read_manifest_bytes(read_regular_bytes(path, "manifest"))


def validate(data: dict[str, Any]) -> None:
    if data["schema_version"] != SCHEMA_VERSION:
        fail("unsupported schema version")
    for field in ("source_repository", "source_ref", "source_commit", "image_uri", "image_digest_uri", "image_digest", "created_at", "completed_at"):
        text(data[field], field)
    if not data["source_repository"].startswith("https://github.com/"):
        fail("source_repository must be a GitHub HTTPS repository URL")
    if not TAG.fullmatch(data["source_ref"]):
        fail("source_ref must be a release tag")
    if not COMMIT.fullmatch(data["source_commit"]):
        fail("source_commit must be a lowercase 40-character Git commit")
    if not DIGEST.fullmatch(data["image_digest"]):
        fail("image_digest must be a sha256 image digest")
    if not data["image_digest_uri"].endswith("@" + data["image_digest"]):
        fail("image_digest_uri does not bind image_digest")
    if "@" in data["image_uri"] or not data["image_uri"].startswith(data["image_digest_uri"].split("@", 1)[0] + ":"):
        fail("image_uri is not in the digest image repository")
    for field in ("config_sha256", "dockerfile_sha256", "cargo_lock_sha256", "release_metadata_sha256", "sbom_sha256", "scan_sha256"):
        if not isinstance(data[field], str) or not SHA256.fullmatch(data[field]):
            fail(f"{field} must be a lowercase sha256")
    if SOURCE_ARCHIVE_FIELD in data and (
        not isinstance(data[SOURCE_ARCHIVE_FIELD], str)
        or not SHA256.fullmatch(data[SOURCE_ARCHIVE_FIELD])
    ):
        fail("source_archive_sha256 must be a lowercase sha256")
    versions = data["tool_versions"]
    if not isinstance(versions, dict) or not versions:
        fail("tool_versions must be a non-empty object")
    for name, version in versions.items():
        if not isinstance(name, str) or not re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", name):
            fail("tool_versions contains an invalid tool name")
        text(version, f"tool_versions.{name}")
    if not TIMESTAMP.fullmatch(data["created_at"]) or not TIMESTAMP.fullmatch(data["completed_at"]):
        fail("timestamps must be UTC second-precision RFC3339 values")
    if data["completed_at"] < data["created_at"]:
        fail("completed_at precedes created_at")


def mode_0600_regular(path: Path) -> None:
    try:
        link_details = path.lstat()
    except OSError as error:
        fail(f"cannot stat signing key: {error}")
    if stat.S_ISLNK(link_details.st_mode):
        fail("signing key must not be a symlink")
    try:
        details = path.stat()
    except OSError as error:
        fail(f"cannot stat signing key: {error}")
    if not stat.S_ISREG(details.st_mode):
        fail("signing key must be a regular file")
    if details.st_uid != os.geteuid():
        fail("signing key must be owned by the current user")
    if stat.S_IMODE(details.st_mode) != 0o600:
        fail("signing key must have exact mode 0600")


def read_private_key_bytes(path: Path) -> bytes:
    try:
        link_metadata = path.lstat()
        if stat.S_ISLNK(link_metadata.st_mode):
            fail("signing key must not be a symlink")
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except OSError as error:
        fail(f"cannot open signing key: {error}")
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or (metadata.st_dev, metadata.st_ino)
            != (link_metadata.st_dev, link_metadata.st_ino)
            or metadata.st_uid != os.geteuid()
            or stat.S_IMODE(metadata.st_mode) != 0o600
        ):
            fail("signing key must be one stable current-user-owned regular file with exact mode 0600")
        with os.fdopen(descriptor, "rb") as handle:
            descriptor = -1
            return handle.read()
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def public_fingerprint(public_key: Path) -> str:
    return public_fingerprint_bytes(read_regular_bytes(public_key, "public key"))


def public_fingerprint_bytes(public_key: bytes) -> str:
    try:
        result = subprocess.run(
            ["openssl", "pkey", "-pubin", "-pubout", "-outform", "DER"],
            input=public_key, check=True, capture_output=True,
        )
    except (OSError, subprocess.CalledProcessError) as error:
        fail(f"cannot read Ed25519 public key: {error}")
    return hashlib.sha256(result.stdout).hexdigest()


def verify_detached_bytes(manifest: bytes, signature: bytes, public_key: bytes) -> None:
    if not signature:
        fail("signature is missing or empty")
    with tempfile.TemporaryDirectory(prefix="kioku-evidence-verify-") as temporary:
        directory = Path(temporary)
        directory.chmod(0o700)
        key_path = directory / "public.pem"
        signature_path = directory / "signature"
        key_path.write_bytes(public_key)
        signature_path.write_bytes(signature)
        key_path.chmod(0o600)
        signature_path.chmod(0o600)
        try:
            subprocess.run(
                [
                    "openssl", "pkeyutl", "-verify", "-rawin", "-pubin",
                    "-inkey", str(key_path), "-sigfile", str(signature_path),
                    "-in", "/dev/stdin",
                ],
                input=manifest,
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        except (OSError, subprocess.CalledProcessError) as error:
            fail(f"OpenSSL signing operation failed: {error}")


def openssl(args: list[str]) -> None:
    try:
        subprocess.run(["openssl", *args], check=True, stdout=subprocess.DEVNULL)
    except (OSError, subprocess.CalledProcessError) as error:
        fail(f"OpenSSL signing operation failed: {error}")


def create(arguments: argparse.Namespace) -> None:
    output = arguments.output.resolve()
    if output.exists():
        fail(f"refusing to overwrite existing evidence: {output}")
    parsed_versions: dict[str, str] = {}
    for item in arguments.tool_version:
        if "=" not in item:
            fail("each --tool-version must be NAME=VERSION")
        name, version = item.split("=", 1)
        if name in parsed_versions:
            fail("each --tool-version name must be unique")
        parsed_versions[name] = version
    sbom_bytes = expected_asset_bytes(
        arguments.sbom, "SBOM", arguments.expected_sbom_sha256
    )
    scan_bytes = expected_asset_bytes(
        arguments.scan, "scan", arguments.expected_scan_sha256
    )
    values: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "source_repository": arguments.repository,
        "source_ref": arguments.tag,
        "source_commit": arguments.commit,
        "image_uri": arguments.image_uri,
        "image_digest_uri": arguments.image_digest_uri,
        "image_digest": arguments.image_digest,
        "config_sha256": sha256(arguments.config),
        "dockerfile_sha256": sha256(arguments.dockerfile),
        "cargo_lock_sha256": sha256(arguments.cargo_lock),
        "release_metadata_sha256": sha256(arguments.release_metadata),
        "sbom_sha256": hashlib.sha256(sbom_bytes).hexdigest(),
        "scan_sha256": hashlib.sha256(scan_bytes).hexdigest(),
        "tool_versions": parsed_versions,
        "created_at": arguments.created_at or datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "completed_at": arguments.completed_at or datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }
    if arguments.config_sha256 is not None:
        if not SHA256.fullmatch(arguments.config_sha256):
            fail("configuration hash must be a lowercase sha256")
        if values["config_sha256"] != arguments.config_sha256:
            fail("provided configuration hash does not match the stable configuration bytes")

    if arguments.source_archive_sha256 is not None:
        if not SHA256.fullmatch(arguments.source_archive_sha256):
            fail("source archive hash must be a lowercase sha256")
        values[SOURCE_ARCHIVE_FIELD] = arguments.source_archive_sha256
    validate(values)
    try:
        output.parent.mkdir(parents=True, exist_ok=True)
        encoded = canonical(values)
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(output, flags, 0o600)
        try:
            with os.fdopen(descriptor, "wb") as handle:
                descriptor = -1
                handle.write(encoded)
        finally:
            if descriptor >= 0:
                os.close(descriptor)
    except FileExistsError:
        fail(f"refusing to overwrite existing evidence: {output}")
    except OSError as error:
        fail(f"cannot write evidence: {error}")


def sign(arguments: argparse.Namespace) -> None:
    manifest = Path(os.path.abspath(arguments.manifest))
    signature_parent = Path(os.path.abspath(arguments.signature.parent)).resolve(strict=True)
    signature = signature_parent / arguments.signature.name
    manifest_bytes = read_regular_bytes(manifest, "manifest")
    read_manifest_bytes(manifest_bytes)
    private_key_bytes = read_private_key_bytes(arguments.private_key)
    try:
        key_description = subprocess.run(
            ["openssl", "pkey", "-text", "-noout"],
            input=private_key_bytes, check=True, capture_output=True,
        ).stdout.decode("utf-8", errors="replace")
    except (OSError, subprocess.CalledProcessError) as error:
        fail(f"cannot inspect signing key: {error}")
    if "ED25519" not in key_description.upper():
        fail("signing key must be an Ed25519 PEM key")
    with tempfile.TemporaryDirectory(prefix="kioku-evidence-sign-") as temporary:
        key_path = Path(temporary) / "private.pem"
        key_path.write_bytes(private_key_bytes)
        key_path.chmod(0o600)
        try:
            signed = subprocess.run(
                [
                    "openssl", "pkeyutl", "-sign", "-rawin", "-inkey",
                    str(key_path), "-in", "/dev/stdin",
                ],
                input=manifest_bytes,
                check=True,
                capture_output=True,
            ).stdout
        except (OSError, subprocess.CalledProcessError) as error:
            fail(f"OpenSSL signing operation failed: {error}")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(signature, flags, 0o600)
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(signed)
    except FileExistsError:
        fail(f"refusing to overwrite existing signature: {signature}")
    except OSError as error:
        fail(f"cannot write signature: {error}")


def verify(arguments: argparse.Namespace) -> None:
    manifest = Path(os.path.abspath(arguments.manifest))
    signature = Path(os.path.abspath(arguments.signature))
    manifest_bytes = read_regular_bytes(manifest, "manifest")
    read_manifest_bytes(manifest_bytes)
    signature_bytes = read_regular_bytes(signature, "signature")
    public_key_bytes = read_regular_bytes(arguments.public_key, "public key")
    expected = arguments.expected_public_key_sha256.lower()
    if not SHA256.fullmatch(expected):
        fail("expected public-key fingerprint must be a lowercase sha256")
    actual = public_fingerprint_bytes(public_key_bytes)
    if actual != expected:
        fail("public key does not match the external trust anchor")
    verify_detached_bytes(manifest_bytes, signature_bytes, public_key_bytes)
    print(json.dumps(read_manifest_bytes(manifest_bytes), sort_keys=True, separators=(",", ":"), ensure_ascii=True))


def fingerprint(arguments: argparse.Namespace) -> None:
    """Print the safe SHA-256 trust anchor for a public Ed25519 PEM key."""
    print(public_fingerprint(arguments.public_key))


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    sub = result.add_subparsers(dest="command", required=True)
    create_parser = sub.add_parser("create")
    create_parser.add_argument("--output", type=Path, required=True)
    create_parser.add_argument("--repository", required=True)
    create_parser.add_argument("--tag", required=True)
    create_parser.add_argument("--commit", required=True)
    create_parser.add_argument("--image-uri", required=True)
    create_parser.add_argument("--image-digest-uri", required=True)
    create_parser.add_argument("--image-digest", required=True)
    create_parser.add_argument("--config", type=Path, required=True)
    create_parser.add_argument("--config-sha256")
    create_parser.add_argument("--dockerfile", type=Path, required=True)
    create_parser.add_argument("--cargo-lock", type=Path, required=True)
    create_parser.add_argument("--release-metadata", type=Path, required=True)
    create_parser.add_argument("--sbom", type=Path, required=True)
    create_parser.add_argument("--scan", type=Path, required=True)
    create_parser.add_argument("--expected-sbom-sha256", required=True)
    create_parser.add_argument("--expected-scan-sha256", required=True)
    create_parser.add_argument("--source-archive-sha256")
    create_parser.add_argument("--tool-version", action="append", default=[], required=True)
    create_parser.add_argument("--created-at")
    create_parser.add_argument("--completed-at")
    create_parser.set_defaults(func=create)
    sign_parser = sub.add_parser("sign")
    sign_parser.add_argument("--manifest", type=Path, required=True)
    sign_parser.add_argument("--signature", type=Path, required=True)
    sign_parser.add_argument("--private-key", type=Path, required=True)
    sign_parser.set_defaults(func=sign)
    verify_parser = sub.add_parser("verify")
    verify_parser.add_argument("--manifest", type=Path, required=True)
    verify_parser.add_argument("--signature", type=Path, required=True)
    verify_parser.add_argument("--public-key", type=Path, required=True)
    verify_parser.add_argument("--expected-public-key-sha256", required=True)
    verify_parser.set_defaults(func=verify)
    fingerprint_parser = sub.add_parser("fingerprint")
    fingerprint_parser.add_argument("--public-key", type=Path, required=True)
    fingerprint_parser.set_defaults(func=fingerprint)
    return result


def main() -> None:
    arguments = parser().parse_args()
    arguments.func(arguments)


if __name__ == "__main__":
    main()
