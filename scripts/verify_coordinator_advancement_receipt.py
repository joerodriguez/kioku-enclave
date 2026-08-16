#!/usr/bin/env python3
"""Verify a signed coordinator approval for a detached frozen release commit.

The receipt is intentionally a tiny, canonical Ed25519-signed statement.  It
does not bypass the local source/tag checks: the caller must still prove that
the frozen commit is an ancestor of the freshly fetched origin/main.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile


COMMIT = re.compile(r"[0-9a-f]{40}\Z")
FINGERPRINT = re.compile(r"[0-9a-f]{64}\Z")
TAG = re.compile(r"v[0-9]+\.[0-9]+\.[0-9]+(?:[.-][0-9A-Za-z.-]+)?\Z")
REPOSITORY = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+\Z")


def fail(message: str) -> "NoReturn":
    raise SystemExit(f"coordinator advancement receipt: {message}")


def canonical(data: dict[str, object]) -> bytes:
    return (json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n").encode()


def read_regular(path: Path, label: str, *, private: bool = False) -> bytes:
    try:
        link = path.lstat()
        if stat.S_ISLNK(link.st_mode):
            fail(f"{label} must not be a symlink")
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except OSError as error:
        fail(f"cannot open {label}: {error}")
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or (metadata.st_dev, metadata.st_ino) != (link.st_dev, link.st_ino)
            or metadata.st_uid != os.geteuid()
            or (private and stat.S_IMODE(metadata.st_mode) != 0o600)
        ):
            fail(f"{label} must be one current-user-owned regular file")
        with os.fdopen(descriptor, "rb") as handle:
            descriptor = -1
            return handle.read()
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def public_fingerprint(public_key: bytes) -> str:
    result = subprocess.run(
        ["openssl", "pkey", "-pubin", "-pubout", "-outform", "DER"],
        input=public_key,
        capture_output=True,
        check=False,
    )
    if result.returncode:
        fail("cannot parse the coordinator public key")
    return hashlib.sha256(result.stdout).hexdigest()


def verify(arguments: argparse.Namespace) -> None:
    if not COMMIT.fullmatch(arguments.frozen_commit) or not COMMIT.fullmatch(arguments.origin_main):
        fail("commit arguments must be lowercase 40-character hashes")
    if not TAG.fullmatch(arguments.tag):
        fail("tag is not a release tag")
    if not REPOSITORY.fullmatch(arguments.repository):
        fail("repository must be OWNER/REPO")
    if not FINGERPRINT.fullmatch(arguments.expected_public_key_sha256):
        fail("public-key fingerprint must be a lowercase sha256")
    receipt_bytes = read_regular(arguments.receipt, "receipt", private=True)
    signature_bytes = read_regular(arguments.signature, "receipt signature", private=True)
    public_bytes = read_regular(arguments.public_key, "receipt public key")
    try:
        data = json.loads(receipt_bytes.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        fail(f"receipt is not valid JSON: {error}")
    expected = {
        "schema_version": 1,
        "repository": arguments.repository,
        "tag": arguments.tag,
        "frozen_commit": arguments.frozen_commit,
        "approved_origin_main": arguments.origin_main,
    }
    if data != expected or receipt_bytes != canonical(expected):
        fail("receipt fields are not the exact canonical coordinator approval")
    if public_fingerprint(public_bytes) != arguments.expected_public_key_sha256:
        fail("receipt public key does not match the external coordinator trust anchor")
    with tempfile.TemporaryDirectory(prefix="kioku-coordinator-receipt-") as temporary:
        key_path = Path(temporary) / "public.pem"
        sig_path = Path(temporary) / "signature"
        key_path.write_bytes(public_bytes)
        sig_path.write_bytes(signature_bytes)
        key_path.chmod(0o600)
        sig_path.chmod(0o600)
        verified = subprocess.run(
            [
                "openssl", "pkeyutl", "-verify", "-rawin", "-pubin",
                "-inkey", str(key_path), "-sigfile", str(sig_path), "-in", "/dev/stdin",
            ],
            input=receipt_bytes,
            capture_output=True,
            check=False,
        )
    if verified.returncode:
        fail("coordinator receipt signature is invalid")
    print(json.dumps(expected, sort_keys=True, separators=(",", ":"), ensure_ascii=True))


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--receipt", type=Path, required=True)
    parser.add_argument("--signature", type=Path, required=True)
    parser.add_argument("--public-key", type=Path, required=True)
    parser.add_argument("--expected-public-key-sha256", required=True)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--tag", required=True)
    parser.add_argument("--frozen-commit", required=True)
    parser.add_argument("--origin-main", required=True)
    arguments = parser.parse_args()
    verify(arguments)


if __name__ == "__main__":
    main()
