#!/usr/bin/env python3
"""Fail-closed validation for PostgreSQL-only enclave release metadata."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
from typing import Any, NoReturn


FIELDS = frozenset(
    {
        "schema_version",
        "source_repository",
        "source_ref",
        "source_commit",
        "image_uri",
        "image_digest_uri",
        "image_digest",
        "release_url",
        "build_profile",
        "voice_quality_gate",
        "billing_enforcement_mode",
        "vertex_reconciliation_model",
        "vertex_location",
        "reconciliation_producer_contract_sha256",
        "gcs_media_bucket",
        "kms_project",
        "kms_location",
        "kms_key_ring",
        "kms_key",
        "persistence_authority",
        "postgres_schema_verification",
        "postgres_max_connections",
        "health_port",
        "drain_timeout_seconds",
        "tls_mode",
        "quota_vertex_output_tokens_per_day",
        "quota_vertex_output_reset_policy",
        "quota_vertex_output_class_shares",
    }
)
FROZEN_V0_9_18_FIELDS = frozenset(
    {
        "schema_version",
        "source_repository",
        "source_ref",
        "source_commit",
        "image_uri",
        "image_digest_uri",
        "image_digest",
        "release_url",
        "build_profile",
        "voice_quality_gate",
        "billing_enforcement_mode",
        "vertex_reconciliation_model",
        "vertex_location",
        "reconciliation_producer_contract_sha256",
        "gcs_media_bucket",
        "kms_project",
        "kms_location",
        "kms_key_ring",
        "kms_key",
        "persistence_authority",
        "postgres_schema_verification",
        "postgres_max_connections",
        "health_port",
        "drain_timeout_seconds",
        "tls_mode",
    }
)
FROZEN_V0_9_16_FIELDS = frozenset(
    {
        "schema_version",
        "source_repository",
        "source_ref",
        "source_commit",
        "image_uri",
        "image_digest_uri",
        "image_digest",
        "release_url",
        "build_profile",
        "voice_quality_gate",
        "billing_enforcement_mode",
        "gcs_media_bucket",
        "kms_project",
        "kms_location",
        "kms_key_ring",
        "kms_key",
        "persistence_authority",
        "postgres_schema_verification",
        "postgres_max_connections",
        "health_port",
        "drain_timeout_seconds",
        "tls_mode",
    }
)
BUCKET = re.compile(r"[a-z0-9][a-z0-9._-]{1,220}[a-z0-9]\Z")
PROJECT = re.compile(r"[a-z][a-z0-9-]{4,28}[a-z0-9]\Z")
LOCATION = re.compile(r"[a-z0-9][a-z0-9-]{0,62}\Z")
KMS_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,62}\Z")
DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
COMMIT = re.compile(r"[0-9a-f]{40}\Z")
TAG = re.compile(
    r"v(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\."
    r"(?:0|[1-9][0-9]*)(?:[.-][0-9A-Za-z.-]+)?\Z"
)
REPOSITORY = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+\Z")
MODEL = re.compile(r"[A-Za-z0-9._:-]{1,128}\Z")
CANONICAL_POSITIVE_INTEGER = re.compile(r"[1-9][0-9]{0,15}\Z")
REVIEWED_VERTEX_OUTPUT_TOKENS_PER_DAY = "2621440"


class DuplicateName(ValueError):
    pass


def reject(message: str) -> NoReturn:
    raise SystemExit(f"invalid release metadata: {message}")


def _exact_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for name, value in pairs:
        if name in result:
            raise DuplicateName("duplicate JSON name")
        result[name] = value
    return result


def required_string(data: dict[str, object], key: str) -> str:
    value = data.get(key)
    if not isinstance(value, str) or not value:
        reject(f"{key} must be a non-empty string")
    if any(ord(character) < 32 or ord(character) == 127 for character in value):
        reject(f"{key} contains a control character")
    return value


def validate_shape(data: object) -> dict[str, object]:
    if not isinstance(data, dict):
        reject("document must be an object")
    if data.get("schema_version") != 13 or type(data.get("schema_version")) is not int:
        reject("schema_version must be 13; legacy authority manifests are ineligible")
    if set(data) != FIELDS:
        reject("document has missing or unexpected fields")
    for key in FIELDS - {"schema_version"}:
        required_string(data, key)
    return data


def parse_metadata_bytes(raw: bytes) -> dict[str, object]:
    try:
        data = json.loads(raw.decode("utf-8"), object_pairs_hook=_exact_object)
    except (UnicodeDecodeError, json.JSONDecodeError, DuplicateName) as error:
        reject(f"cannot parse JSON ({error})")
    validated = validate_shape(data)
    canonical = (
        json.dumps(validated, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        + "\n"
    ).encode("utf-8")
    if raw != canonical:
        reject("document bytes must be canonical sorted compact JSON plus one LF")
    return validated


def parse_metadata(path: Path) -> dict[str, object]:
    try:
        return parse_metadata_bytes(path.read_bytes())
    except OSError as error:
        reject(f"cannot read metadata ({error})")


def parse_frozen_v0_9_16_metadata_bytes(raw: bytes) -> dict[str, object]:
    """Parse the exact historical schema-11 shape for read-only state checks."""
    try:
        data = json.loads(raw.decode("utf-8"), object_pairs_hook=_exact_object)
    except (UnicodeDecodeError, json.JSONDecodeError, DuplicateName) as error:
        reject(f"cannot parse frozen v0.9.16 JSON ({error})")
    if not isinstance(data, dict):
        reject("frozen v0.9.16 document must be an object")
    if data.get("schema_version") != 11 or type(data.get("schema_version")) is not int:
        reject("frozen v0.9.16 schema_version must be 11")
    if set(data) != FROZEN_V0_9_16_FIELDS:
        reject("frozen v0.9.16 document has missing or unexpected fields")
    for key in FROZEN_V0_9_16_FIELDS - {"schema_version"}:
        required_string(data, key)
    canonical = (
        json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        + "\n"
    ).encode("utf-8")
    if raw != canonical:
        reject("frozen v0.9.16 bytes must be canonical sorted compact JSON plus one LF")
    return data


def parse_frozen_v0_9_18_metadata_bytes(raw: bytes) -> dict[str, object]:
    """Parse the exact live-predecessor schema-12 shape for state checks."""
    try:
        data = json.loads(raw.decode("utf-8"), object_pairs_hook=_exact_object)
    except (UnicodeDecodeError, json.JSONDecodeError, DuplicateName) as error:
        reject(f"cannot parse frozen v0.9.18 JSON ({error})")
    if not isinstance(data, dict):
        reject("frozen v0.9.18 document must be an object")
    if data.get("schema_version") != 12 or type(data.get("schema_version")) is not int:
        reject("frozen v0.9.18 schema_version must be 12")
    if set(data) != FROZEN_V0_9_18_FIELDS:
        reject("frozen v0.9.18 document has missing or unexpected fields")
    for key in FROZEN_V0_9_18_FIELDS - {"schema_version"}:
        required_string(data, key)
    canonical = (
        json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        + "\n"
    ).encode("utf-8")
    if raw != canonical:
        reject("frozen v0.9.18 bytes must be canonical sorted compact JSON plus one LF")
    return data


def validate(arguments: argparse.Namespace, data: dict[str, object]) -> None:
    validate_shape(data)
    if not REPOSITORY.fullmatch(arguments.repository):
        reject("repository must be OWNER/REPO")
    if not TAG.fullmatch(arguments.tag):
        reject("tag is not canonical")
    if not COMMIT.fullmatch(arguments.commit):
        reject("commit is not a lowercase full Git commit")
    expected_source_repository = f"https://github.com/{arguments.repository}"
    if data["source_repository"] != expected_source_repository:
        reject("source_repository does not match the expected repository")
    if data["source_ref"] != arguments.tag or data["source_commit"] != arguments.commit:
        reject("source identity does not match the requested tag and commit")

    digest = required_string(data, "image_digest")
    if not DIGEST.fullmatch(digest):
        reject("image_digest is not a sha256 digest")
    if data["image_uri"] != f"{arguments.image_repository}:{arguments.tag}":
        reject("image_uri does not bind the expected repository and tag")
    if data["image_digest_uri"] != f"{arguments.image_repository}@{digest}":
        reject("image_digest_uri does not bind the expected repository and digest")
    if data["release_url"] != (
        f"https://github.com/{arguments.repository}/releases/tag/{arguments.tag}"
    ):
        reject("release_url does not bind the expected repository and tag")
    if data["build_profile"] != "production":
        reject("build_profile is not production")
    if data["voice_quality_gate"] not in (
        "owner_only_unvalidated",
        "validated_real_corpus",
    ):
        reject("voice_quality_gate is invalid")
    if data["billing_enforcement_mode"] not in ("shadow", "enforce"):
        reject("billing_enforcement_mode is invalid")
    if (
        not CANONICAL_POSITIVE_INTEGER.fullmatch(
            arguments.expected_quota_vertex_output_tokens_per_day
        )
        or arguments.expected_quota_vertex_output_tokens_per_day
        != REVIEWED_VERTEX_OUTPUT_TOKENS_PER_DAY
        or data["quota_vertex_output_tokens_per_day"]
        != arguments.expected_quota_vertex_output_tokens_per_day
    ):
        reject(
            "quota_vertex_output_tokens_per_day does not match the selected configuration"
        )
    if data["quota_vertex_output_reset_policy"] != "per-account-utc-calendar-day":
        reject("quota_vertex_output_reset_policy does not match the reviewed policy")
    if (
        data["quota_vertex_output_class_shares"]
        != "non-borrowing-percent:audio=50,screen=25,derived=25"
    ):
        reject("quota_vertex_output_class_shares does not match the reviewed policy")

    if (
        not MODEL.fullmatch(arguments.expected_vertex_reconciliation_model)
        or data["vertex_reconciliation_model"]
        != arguments.expected_vertex_reconciliation_model
    ):
        reject("vertex_reconciliation_model does not match the selected configuration")
    if (
        not LOCATION.fullmatch(arguments.expected_vertex_location)
        or data["vertex_location"] != arguments.expected_vertex_location
    ):
        reject("vertex_location does not match the selected configuration")
    if (
        not DIGEST.fullmatch(arguments.expected_reconciliation_producer_contract_sha256)
        or data["reconciliation_producer_contract_sha256"]
        != arguments.expected_reconciliation_producer_contract_sha256
    ):
        reject("reconciliation_producer_contract_sha256 does not match the compiled contract")

    if not BUCKET.fullmatch(arguments.expected_gcs_media_bucket):
        reject("expected media bucket has an invalid format")
    if data["gcs_media_bucket"] != arguments.expected_gcs_media_bucket:
        reject("gcs_media_bucket does not match the selected configuration")
    for field, expected, pattern in (
        ("kms_project", arguments.expected_kms_project, PROJECT),
        ("kms_location", arguments.expected_kms_location, LOCATION),
        ("kms_key_ring", arguments.expected_kms_key_ring, KMS_NAME),
        ("kms_key", arguments.expected_kms_key, KMS_NAME),
    ):
        if not pattern.fullmatch(expected) or data[field] != expected:
            reject(f"{field} does not match the selected configuration")
    fixed = {
        "persistence_authority": "postgres",
        "postgres_schema_verification": "required",
        "postgres_max_connections": "12",
        "health_port": "8081",
        "drain_timeout_seconds": "105",
        "tls_mode": "shared-secret-manager",
    }
    for field, expected in fixed.items():
        if data[field] != expected:
            reject(f"{field} does not match the reviewed serving invariant")


def validate_frozen_v0_9_16_state(
    arguments: argparse.Namespace, data: dict[str, object]
) -> None:
    """Apply the frozen schema-11 validator only to the published v0.9.16 tag."""
    if arguments.tag != "v0.9.16":
        reject("schema-11 state verification is restricted to frozen v0.9.16")
    if set(data) != FROZEN_V0_9_16_FIELDS or data.get("schema_version") != 11:
        reject("frozen v0.9.16 metadata shape changed")
    if not REPOSITORY.fullmatch(arguments.repository):
        reject("repository must be OWNER/REPO")
    if not COMMIT.fullmatch(arguments.commit):
        reject("commit is not a lowercase full Git commit")
    if data["source_repository"] != f"https://github.com/{arguments.repository}":
        reject("source_repository does not match the expected repository")
    if data["source_ref"] != arguments.tag or data["source_commit"] != arguments.commit:
        reject("source identity does not match frozen v0.9.16")

    digest = required_string(data, "image_digest")
    if not DIGEST.fullmatch(digest):
        reject("image_digest is not a sha256 digest")
    if data["image_uri"] != f"{arguments.image_repository}:{arguments.tag}":
        reject("image_uri does not bind frozen v0.9.16")
    if data["image_digest_uri"] != f"{arguments.image_repository}@{digest}":
        reject("image_digest_uri does not bind the expected digest")
    if data["release_url"] != (
        f"https://github.com/{arguments.repository}/releases/tag/{arguments.tag}"
    ):
        reject("release_url does not bind frozen v0.9.16")
    if data["build_profile"] != "production":
        reject("build_profile is not production")
    if data["voice_quality_gate"] not in (
        "owner_only_unvalidated",
        "validated_real_corpus",
    ):
        reject("voice_quality_gate is invalid")
    if data["billing_enforcement_mode"] not in ("shadow", "enforce"):
        reject("billing_enforcement_mode is invalid")

    if not BUCKET.fullmatch(arguments.expected_gcs_media_bucket):
        reject("expected media bucket has an invalid format")
    if data["gcs_media_bucket"] != arguments.expected_gcs_media_bucket:
        reject("gcs_media_bucket does not match the selected configuration")
    for field, expected, pattern in (
        ("kms_project", arguments.expected_kms_project, PROJECT),
        ("kms_location", arguments.expected_kms_location, LOCATION),
        ("kms_key_ring", arguments.expected_kms_key_ring, KMS_NAME),
        ("kms_key", arguments.expected_kms_key, KMS_NAME),
    ):
        if not pattern.fullmatch(expected) or data[field] != expected:
            reject(f"{field} does not match the selected configuration")
    fixed = {
        "persistence_authority": "postgres",
        "postgres_schema_verification": "required",
        "postgres_max_connections": "12",
        "health_port": "8081",
        "drain_timeout_seconds": "105",
        "tls_mode": "shared-secret-manager",
    }
    for field, expected in fixed.items():
        if data[field] != expected:
            reject(f"{field} does not match the frozen serving invariant")


def validate_frozen_v0_9_18_state(
    arguments: argparse.Namespace, data: dict[str, object]
) -> None:
    """Apply schema 12 only to the exact live v0.9.18 predecessor."""
    if arguments.tag != "v0.9.18":
        reject("schema-12 state verification is restricted to frozen v0.9.18")
    if set(data) != FROZEN_V0_9_18_FIELDS or data.get("schema_version") != 12:
        reject("frozen v0.9.18 metadata shape changed")
    if not REPOSITORY.fullmatch(arguments.repository):
        reject("repository must be OWNER/REPO")
    if not COMMIT.fullmatch(arguments.commit):
        reject("commit is not a lowercase full Git commit")
    if data["source_repository"] != f"https://github.com/{arguments.repository}":
        reject("source_repository does not match the expected repository")
    if data["source_ref"] != arguments.tag or data["source_commit"] != arguments.commit:
        reject("source identity does not match frozen v0.9.18")

    digest = required_string(data, "image_digest")
    if not DIGEST.fullmatch(digest):
        reject("image_digest is not a sha256 digest")
    if data["image_uri"] != f"{arguments.image_repository}:{arguments.tag}":
        reject("image_uri does not bind frozen v0.9.18")
    if data["image_digest_uri"] != f"{arguments.image_repository}@{digest}":
        reject("image_digest_uri does not bind the expected digest")
    if data["release_url"] != (
        f"https://github.com/{arguments.repository}/releases/tag/{arguments.tag}"
    ):
        reject("release_url does not bind frozen v0.9.18")
    if data["build_profile"] != "production":
        reject("build_profile is not production")
    if data["voice_quality_gate"] not in (
        "owner_only_unvalidated",
        "validated_real_corpus",
    ):
        reject("voice_quality_gate is invalid")
    if data["billing_enforcement_mode"] not in ("shadow", "enforce"):
        reject("billing_enforcement_mode is invalid")

    if (
        not MODEL.fullmatch(arguments.expected_vertex_reconciliation_model)
        or data["vertex_reconciliation_model"]
        != arguments.expected_vertex_reconciliation_model
    ):
        reject("vertex_reconciliation_model does not match the frozen configuration")
    if (
        not LOCATION.fullmatch(arguments.expected_vertex_location)
        or data["vertex_location"] != arguments.expected_vertex_location
    ):
        reject("vertex_location does not match the frozen configuration")
    if (
        not DIGEST.fullmatch(arguments.expected_reconciliation_producer_contract_sha256)
        or data["reconciliation_producer_contract_sha256"]
        != arguments.expected_reconciliation_producer_contract_sha256
    ):
        reject("reconciliation producer contract does not match frozen v0.9.18")
    if not BUCKET.fullmatch(arguments.expected_gcs_media_bucket):
        reject("expected media bucket has an invalid format")
    if data["gcs_media_bucket"] != arguments.expected_gcs_media_bucket:
        reject("gcs_media_bucket does not match the frozen configuration")
    for field, expected, pattern in (
        ("kms_project", arguments.expected_kms_project, PROJECT),
        ("kms_location", arguments.expected_kms_location, LOCATION),
        ("kms_key_ring", arguments.expected_kms_key_ring, KMS_NAME),
        ("kms_key", arguments.expected_kms_key, KMS_NAME),
    ):
        if not pattern.fullmatch(expected) or data[field] != expected:
            reject(f"{field} does not match the frozen configuration")
    fixed = {
        "persistence_authority": "postgres",
        "postgres_schema_verification": "required",
        "postgres_max_connections": "12",
        "health_port": "8081",
        "drain_timeout_seconds": "105",
        "tls_mode": "shared-secret-manager",
    }
    for field, expected in fixed.items():
        if data[field] != expected:
            reject(f"{field} does not match the frozen serving invariant")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("metadata", type=Path)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--tag", required=True)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--image-repository", required=True)
    parser.add_argument("--expected-gcs-media-bucket", required=True)
    parser.add_argument("--expected-kms-project", required=True)
    parser.add_argument("--expected-kms-location", required=True)
    parser.add_argument("--expected-kms-key-ring", required=True)
    parser.add_argument("--expected-kms-key", required=True)
    parser.add_argument("--expected-vertex-reconciliation-model", required=True)
    parser.add_argument("--expected-vertex-location", required=True)
    parser.add_argument(
        "--expected-reconciliation-producer-contract-sha256", required=True
    )
    parser.add_argument("--expected-quota-vertex-output-tokens-per-day", required=True)
    arguments = parser.parse_args()
    data = parse_metadata(arguments.metadata)
    validate(arguments, data)
    print(json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=True))


if __name__ == "__main__":
    main()
