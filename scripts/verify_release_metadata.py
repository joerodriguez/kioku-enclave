#!/usr/bin/env python3
"""Fail-closed validation for a signed enclave release-manifest subject."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import sys

from archive_witness_probe_config import (
    ProbeConfigError,
    load_probe_config,
    select_probe_config,
)


BUCKET_PATTERN = re.compile(r"[a-z0-9][a-z0-9._-]{1,220}[a-z0-9]\Z")
DIGEST_PATTERN = re.compile(r"sha256:[0-9a-f]{64}\Z")
COMMIT_PATTERN = re.compile(r"[0-9a-f]{40}\Z")
BUILD_URL_PATTERN = re.compile(r"https://github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+/actions/runs/[0-9]+\Z")

FIELDS = (
    "schema_version",
    "source_repository",
    "source_ref",
    "source_commit",
    "image_uri",
    "image_digest_uri",
    "image_digest",
    "build_url",
    "build_profile",
    "voice_quality_gate",
    "billing_enforcement_mode",
    "gcs_bucket",
    "gcs_media_bucket",
    "gcs_legacy_media_bucket",
    "archive_witness_shadow_mode",
    "archive_witness_project_id",
    "archive_witness_project_number",
    "archive_witness_database_id",
)

EMPTY_ALLOWED_FIELDS = {
    "archive_witness_project_id",
    "archive_witness_project_number",
    "archive_witness_database_id",
}


def reject(message: str) -> None:
    raise SystemExit(f"invalid release metadata: {message}")


def required_string(data: dict[str, object], key: str) -> str:
    value = data[key]
    if not isinstance(value, str) or not value:
        reject(f"{key} must be a non-empty string")
    if any(ord(character) < 32 or ord(character) == 127 for character in value):
        reject(f"{key} contains a control character")
    return value


def parse_metadata(path: Path) -> dict[str, object]:
    try:
        with path.open(encoding="utf-8") as handle:
            data = json.load(handle)
    except (OSError, json.JSONDecodeError) as error:
        reject(f"cannot parse JSON ({error})")
    if not isinstance(data, dict):
        reject("document must be an object")
    if set(data) != set(FIELDS):
        reject("document has missing or unexpected fields")
    if type(data["schema_version"]) is not int:
        reject("schema_version must be an integer")
    for key in FIELDS:
        if key != "schema_version" and key not in EMPTY_ALLOWED_FIELDS:
            required_string(data, key)
        elif key in EMPTY_ALLOWED_FIELDS:
            value = data[key]
            if not isinstance(value, str) or any(
                ord(character) < 32 or ord(character) == 127 for character in value
            ):
                reject(f"{key} must be a control-free string")
    return data


def validate(arguments: argparse.Namespace, data: dict[str, object]) -> None:
    if not BUCKET_PATTERN.fullmatch(arguments.expected_gcs_bucket):
        reject("expected GCS bucket has an invalid format")
    if not BUCKET_PATTERN.fullmatch(arguments.expected_gcs_media_bucket):
        reject("expected media GCS bucket has an invalid format")
    if not BUCKET_PATTERN.fullmatch(arguments.expected_gcs_legacy_media_bucket):
        reject("expected legacy media GCS bucket has an invalid format")
    if arguments.expected_gcs_bucket != arguments.expected_gcs_legacy_media_bucket:
        reject("expected legacy media GCS bucket must equal the expected GCS bucket for Phase-0")
    if data["schema_version"] != 6:
        reject("schema_version must be 6; older manifests are ineligible for promotion")

    expected_repository = f"https://github.com/{arguments.repository}"
    if data["source_repository"] != expected_repository:
        reject("source_repository does not match the expected repository")
    if data["source_ref"] != arguments.tag:
        reject("source_ref does not match the requested tag")
    if data["source_commit"] != arguments.commit or not COMMIT_PATTERN.fullmatch(arguments.commit):
        reject("source_commit does not match the requested commit")

    digest = required_string(data, "image_digest")
    if not DIGEST_PATTERN.fullmatch(digest):
        reject("image_digest is not a sha256 digest")
    image_uri = required_string(data, "image_uri")
    if not image_uri.startswith(f"{arguments.image_repository}:"):
        reject("image_uri is outside the expected Artifact Registry repository")
    if data["image_digest_uri"] != f"{arguments.image_repository}@{digest}":
        reject("image_digest_uri does not bind the expected image repository and digest")
    if not BUILD_URL_PATTERN.fullmatch(required_string(data, "build_url")):
        reject("build_url is not a GitHub Actions run URL")
    if not required_string(data, "build_url").startswith(
        f"https://github.com/{arguments.repository}/actions/runs/"
    ):
        reject("build_url is outside the expected repository")
    if data["build_profile"] != "production":
        reject("build_profile is not production")
    if data["voice_quality_gate"] not in (
        "owner_only_unvalidated",
        "validated_real_corpus",
    ):
        reject("voice_quality_gate is invalid")
    if data["billing_enforcement_mode"] not in ("shadow", "enforce"):
        reject("billing_enforcement_mode is invalid")

    bucket = required_string(data, "gcs_bucket")
    media_bucket = required_string(data, "gcs_media_bucket")
    legacy_media_bucket = required_string(data, "gcs_legacy_media_bucket")
    if not all(
        BUCKET_PATTERN.fullmatch(value)
        for value in (bucket, media_bucket, legacy_media_bucket)
    ):
        reject("GCS bucket claim has an invalid format")
    if bucket != arguments.expected_gcs_bucket:
        reject("gcs_bucket does not match the release configuration")
    if media_bucket != arguments.expected_gcs_media_bucket:
        reject("gcs_media_bucket does not match the release configuration")
    if legacy_media_bucket != arguments.expected_gcs_legacy_media_bucket:
        reject("gcs_legacy_media_bucket does not match the release configuration")
    if legacy_media_bucket != bucket:
        reject("gcs_legacy_media_bucket must equal gcs_bucket for the Phase-0 dual-media migration")

    probe_claim = (
        data["archive_witness_shadow_mode"],
        data["archive_witness_project_id"],
        data["archive_witness_project_number"],
        data["archive_witness_database_id"],
    )
    try:
        expected_probe_claim = select_probe_config(
            load_probe_config(arguments.archive_witness_probe_config),
            profile="production",
            source_ref=arguments.tag,
        ).as_claim()
    except ProbeConfigError as error:
        reject(str(error))
    if probe_claim != expected_probe_claim:
        reject("archive witness probe claim does not match the release configuration")
    mode, project_id, project_number, database_id = probe_claim
    if mode == "off":
        if any((project_id, project_number, database_id)):
            reject("archive witness namespace must be empty while mode is off")
    elif mode == "probe-v1":
        if not re.fullmatch(r"[a-z][a-z0-9-]{4,28}[a-z0-9]", project_id):
            reject("archive witness project ID is invalid")
        if not re.fullmatch(r"[1-9][0-9]{0,19}", project_number):
            reject("archive witness project number is invalid")
        if not re.fullmatch(r"[a-z][a-z0-9-]{2,61}[a-z0-9]", database_id):
            reject("archive witness database ID is invalid")
    else:
        reject("archive witness shadow mode is invalid")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("metadata", type=Path)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--tag", required=True)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--image-repository", required=True)
    parser.add_argument("--expected-gcs-bucket", required=True)
    parser.add_argument("--expected-gcs-media-bucket", required=True)
    parser.add_argument("--expected-gcs-legacy-media-bucket", required=True)
    parser.add_argument(
        "--archive-witness-probe-config",
        type=Path,
        default=Path("config/archive-witness-probe.json"),
    )
    arguments = parser.parse_args()
    data = parse_metadata(arguments.metadata)
    validate(arguments, data)
    print("\t".join(str(data[key]) for key in FIELDS))


if __name__ == "__main__":
    main()
