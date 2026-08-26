#!/usr/bin/env python3
"""Derive and validate the next source-versioned Archive V3 WAL release tag."""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import json
from pathlib import Path
import re
import subprocess
import sys
import tomllib


ROOT = Path(__file__).resolve().parents[1]
TAG = re.compile(
    r"v(?P<version>(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*))"
    r"-archive-v3-wal\.(?P<sequence>[1-9][0-9]*)\Z"
)
MAX_REMOTE_TAG_BYTES = 1024 * 1024
RECEIPT_SCHEMA = "kioku-archive-v3-current-release-v1"
RECEIPT_FIELDS = ("schema", "tag", "version", "predecessor_sequence")


class ReleaseTagError(ValueError):
    """The release coordinate is not the unique next WAL tag."""


@dataclass(frozen=True)
class ArchiveV3WalTag:
    name: str
    version: str
    sequence: int


def parse_tag(value: str) -> ArchiveV3WalTag:
    normalized = value.removeprefix("refs/tags/")
    match = TAG.fullmatch(normalized)
    if match is None:
        raise ReleaseTagError(
            "Archive V3 WAL tag must be canonical vMAJOR.MINOR.PATCH-archive-v3-wal.N"
        )
    return ArchiveV3WalTag(
        name=normalized,
        version=match.group("version"),
        sequence=int(match.group("sequence")),
    )


def cargo_version(root: Path = ROOT) -> str:
    try:
        manifest = tomllib.loads((root / "Cargo.toml").read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError) as error:
        raise ReleaseTagError("Cargo manifest is unreadable") from error
    version = manifest.get("package", {}).get("version")
    if not isinstance(version, str) or re.fullmatch(
        r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)", version
    ) is None:
        raise ReleaseTagError("Cargo package version is not a canonical release version")
    return version


def tags_from_remote_refs(payload: str) -> frozenset[ArchiveV3WalTag]:
    if len(payload.encode("utf-8")) > MAX_REMOTE_TAG_BYTES:
        raise ReleaseTagError("remote tag inventory exceeds the bounded response size")
    tags: dict[str, ArchiveV3WalTag] = {}
    for line in payload.splitlines():
        fields = line.split("\t")
        if len(fields) != 2:
            raise ReleaseTagError("remote tag inventory is malformed")
        ref = fields[1]
        if not ref.startswith("refs/tags/"):
            continue
        name = ref.removeprefix("refs/tags/").removesuffix("^{}")
        try:
            tag = parse_tag(name)
        except ReleaseTagError:
            continue
        tags[tag.name] = tag
    return frozenset(tags.values())


def next_tag(version: str, remote_refs: str) -> str:
    tags = tags_from_remote_refs(remote_refs)
    sequence = max((tag.sequence for tag in tags), default=0) + 1
    return f"v{version}-archive-v3-wal.{sequence}"


def current_release_receipt(version: str, remote_refs: str) -> dict[str, object]:
    tags = tags_from_remote_refs(remote_refs)
    predecessor = max((tag.sequence for tag in tags), default=0)
    receipt: dict[str, object] = {
        "schema": RECEIPT_SCHEMA,
        "tag": f"v{version}-archive-v3-wal.{predecessor + 1}",
        "version": version,
        "predecessor_sequence": predecessor,
    }
    return receipt


def validate_current_release_receipt(
    payload: object, *, version: str
) -> ArchiveV3WalTag:
    if not isinstance(payload, dict) or tuple(payload) != RECEIPT_FIELDS:
        raise ReleaseTagError("current release receipt shape or field order is invalid")
    if payload.get("schema") != RECEIPT_SCHEMA or payload.get("version") != version:
        raise ReleaseTagError("current release receipt does not match Cargo")
    predecessor = payload.get("predecessor_sequence")
    if not isinstance(predecessor, int) or isinstance(predecessor, bool) or predecessor < 0:
        raise ReleaseTagError("current release predecessor sequence is invalid")
    tag_value = payload.get("tag")
    if not isinstance(tag_value, str):
        raise ReleaseTagError("current release tag is invalid")
    tag = parse_tag(tag_value)
    if tag.version != version or tag.sequence != predecessor + 1:
        raise ReleaseTagError("current release tag is not the receipt successor")
    return tag


def load_current_release_receipt(
    root: Path = ROOT,
) -> tuple[dict[str, object], ArchiveV3WalTag]:
    try:
        raw = (root / "config/archive-v3-current-release.json").read_bytes()
        payload = json.loads(raw.decode("utf-8"), object_pairs_hook=dict)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ReleaseTagError("current release receipt is unreadable") from error
    version = cargo_version(root)
    return payload, validate_current_release_receipt(payload, version=version)


def require_next_tag(
    candidate: str,
    version: str,
    remote_refs: str,
    *,
    allow_existing: bool = False,
) -> ArchiveV3WalTag:
    tag = parse_tag(candidate)
    if tag.version != version:
        raise ReleaseTagError("Archive V3 WAL tag version differs from Cargo")
    tags = tags_from_remote_refs(remote_refs)
    maximum = max((item.sequence for item in tags), default=0)
    names = {item.name for item in tags}
    if tag.name in names:
        if allow_existing and tag.sequence == maximum:
            return tag
        raise ReleaseTagError("Archive V3 WAL tag already exists remotely")
    if tag.sequence != maximum + 1:
        raise ReleaseTagError("Archive V3 WAL tag is not the next published sequence")
    return tag


def read_remote_refs(remote: str) -> str:
    if re.fullmatch(r"[A-Za-z0-9_.-]{1,128}", remote) is None:
        raise ReleaseTagError("Git remote name is invalid")
    completed = subprocess.run(
        ["git", "--no-replace-objects", "ls-remote", "--tags", remote],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )
    if completed.returncode != 0:
        raise ReleaseTagError("could not read immutable remote release tags")
    return completed.stdout


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("next", "check", "receipt"))
    parser.add_argument("--tag")
    parser.add_argument("--remote", default="origin")
    parser.add_argument("--allow-existing", action="store_true")
    arguments = parser.parse_args()
    try:
        version = cargo_version()
        refs = read_remote_refs(arguments.remote)
        if arguments.command == "next":
            if arguments.tag is not None or arguments.allow_existing:
                raise ReleaseTagError("next does not accept tag or existing-tag options")
            print(next_tag(version, refs))
        elif arguments.command == "check":
            if arguments.tag is None:
                raise ReleaseTagError("check requires --tag")
            checked = require_next_tag(
                arguments.tag,
                version,
                refs,
                allow_existing=arguments.allow_existing,
            )
            print(checked.name)
        else:
            if arguments.tag is not None or arguments.allow_existing:
                raise ReleaseTagError("receipt does not accept tag or existing-tag options")
            print(
                json.dumps(
                    current_release_receipt(version, refs),
                    separators=(",", ":"),
                )
            )
        return 0
    except ReleaseTagError as error:
        print(f"Archive V3 release tag: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
