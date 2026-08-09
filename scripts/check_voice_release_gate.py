#!/usr/bin/env python3
"""Fail-closed classifier for Kioku voice-quality release evidence."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import subprocess
import sys
from typing import Any


OWNER_ONLY_MARKER = "owner-only-production.json"
REAL_CORPUS_FILES = (
    "release-manifest.json",
    "release-cases.json",
    "release-report.json",
)
EXPECTED_OWNER_ONLY_MARKER: dict[str, Any] = {
    "schema_version": 1,
    "environment": "owner_only_production",
    "external_users": 0,
    "voice_quality_claims_allowed": False,
}


def fail(message: str) -> None:
    raise SystemExit(f"Error: {message}")


def reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate key: {key}")
        result[key] = value
    return result


def validate_owner_only_marker(path: Path) -> None:
    try:
        marker = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=reject_duplicate_keys)
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as error:
        fail(f"invalid owner-only production marker: {error}")

    exact_types = (
        type(marker) is dict
        and type(marker.get("schema_version")) is int
        and type(marker.get("environment")) is str
        and type(marker.get("external_users")) is int
        and type(marker.get("voice_quality_claims_allowed")) is bool
    )
    if not exact_types or marker != EXPECTED_OWNER_ONLY_MARKER:
        fail(
            "invalid owner-only production marker; it must exactly declare "
            "schema_version=1, environment=owner_only_production, external_users=0, "
            "and voice_quality_claims_allowed=false"
        )


def classify(root: Path, cargo: str, metadata_only: bool) -> str:
    voice_directory = root / "eval" / "voice"
    marker_path = voice_directory / OWNER_ONLY_MARKER
    marker_present = marker_path.is_file()
    corpus_paths = tuple(voice_directory / name for name in REAL_CORPUS_FILES)
    corpus_present = tuple(path.is_file() and path.stat().st_size > 0 for path in corpus_paths)

    if marker_present and any(corpus_present):
        fail("owner-only marker and real-corpus release evidence must not coexist")

    if marker_present:
        validate_owner_only_marker(marker_path)
        return "owner_only_unvalidated"

    if any(corpus_present) and not all(corpus_present):
        fail("partial real-corpus evidence is forbidden; all three canonical files are required")

    if all(corpus_present):
        if not metadata_only:
            completed = subprocess.run(
                [
                    cargo,
                    "run",
                    "--locked",
                    "--quiet",
                    "--",
                    "--check-voice-eval",
                    *(str(path) for path in corpus_paths),
                ],
                cwd=root,
                check=False,
            )
            if completed.returncode != 0:
                raise SystemExit(completed.returncode)
        return "validated_real_corpus"

    fail("release requires either the exact owner-only marker or complete real-corpus trio")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--root",
        type=Path,
        default=Path(__file__).resolve().parents[1],
        help="repository root (defaults to the directory above scripts)",
    )
    parser.add_argument("--cargo", default="cargo", help=argparse.SUPPRESS)
    parser.add_argument(
        "--metadata-only",
        action="store_true",
        help="classify evidence without executing the Rust real-corpus scorer",
    )
    arguments = parser.parse_args()
    print(classify(arguments.root.resolve(), arguments.cargo, arguments.metadata_only))


if __name__ == "__main__":
    main()
