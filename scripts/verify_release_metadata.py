#!/usr/bin/env python3
"""Fail-closed validation for a signed enclave release-manifest subject."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
from typing import Any

from adr0022_fresh_release import (
    EXPECTED_INTENT,
    IMAGE_REPOSITORY as FRESH_IMAGE_REPOSITORY,
    RELEASE_BINDING_FIELD_ORDER,
    SOURCE_REPOSITORY as FRESH_SOURCE_REPOSITORY,
    FreshReleaseError,
    bootstrap_release_binding,
    claims_fresh_role,
    final_release_binding,
    is_bootstrap_tag,
    is_final_tag,
    validate_checked_bootstrap_source,
    validate_checked_final_source,
)
from archive_witness_probe_config import (
    ProbeConfigError,
    load_probe_config,
    select_probe_config,
)
from archive_v3_shadow_runtime_config import (
    ShadowRuntimeConfigError,
    load_shadow_runtime_config,
    select_shadow_runtime_config,
)


BUCKET_PATTERN = re.compile(r"[a-z0-9][a-z0-9._-]{1,220}[a-z0-9]\Z")
DIGEST_PATTERN = re.compile(r"sha256:[0-9a-f]{64}\Z")
COMMIT_PATTERN = re.compile(r"[0-9a-f]{40}\Z")
RELEASE_URL_PATTERN = re.compile(
    r"https://github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+/releases/tag/"
    r"v[0-9]+\.[0-9]+\.[0-9]+(?:[.-][0-9A-Za-z.-]+)?\Z"
)

SCHEMA_NINE_FIELDS = (
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
    "gcs_bucket",
    "gcs_media_bucket",
    "gcs_legacy_media_bucket",
    "archive_witness_shadow_mode",
    "archive_witness_project_id",
    "archive_witness_project_number",
    "archive_witness_database_id",
    "archive_v3_shadow_runtime_mode",
    "archive_v3_archive_bucket",
    "archive_v3_archive_gcs_project_number",
    "archive_v3_registry_kms_version",
    "archive_v3_witness_project_id",
    "archive_v3_witness_project_number",
    "archive_v3_witness_database_id",
    "archive_v3_archive_binding_commitment",
)
SCHEMA_TEN_FIELDS = (*SCHEMA_NINE_FIELDS, *RELEASE_BINDING_FIELD_ORDER)
SCHEMA_TEN_INTEGER_FIELDS = {
    "schema_epoch_head",
    "schema_epoch_target",
    "schema_epoch_minimum_servable",
}
EMPTY_ALLOWED_FIELDS = {
    "archive_witness_project_id",
    "archive_witness_project_number",
    "archive_witness_database_id",
    "archive_v3_archive_bucket",
    "archive_v3_archive_gcs_project_number",
    "archive_v3_registry_kms_version",
    "archive_v3_witness_project_id",
    "archive_v3_witness_project_number",
    "archive_v3_witness_database_id",
    "archive_v3_archive_binding_commitment",
}


class DuplicateName(ValueError):
    pass


def reject(message: str) -> "NoReturn":
    raise SystemExit(f"invalid release metadata: {message}")


def _exact_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for name, value in pairs:
        if name in result:
            raise DuplicateName("duplicate JSON name")
        result[name] = value
    return result


def required_string(data: dict[str, object], key: str) -> str:
    value = data[key]
    if not isinstance(value, str) or not value:
        reject(f"{key} must be a non-empty string")
    if any(ord(character) < 32 or ord(character) == 127 for character in value):
        reject(f"{key} contains a control character")
    return value


def validate_shape(data: object) -> dict[str, object]:
    if not isinstance(data, dict):
        reject("document must be an object")
    schema_version = data.get("schema_version")
    if type(schema_version) is not int:
        reject("schema_version must be an integer")
    fields = {
        9: SCHEMA_NINE_FIELDS,
        10: SCHEMA_TEN_FIELDS,
    }.get(schema_version)
    if fields is None:
        reject(
            "schema_version must be 9 or 10; older manifests are ineligible for promotion"
        )
    if set(data) != set(fields):
        reject("document has missing or unexpected fields")
    if schema_version == 10 and tuple(data) != SCHEMA_TEN_FIELDS:
        reject("schema-10 document fields are not in canonical producer order")
    integer_fields = SCHEMA_TEN_INTEGER_FIELDS if schema_version == 10 else set()
    for key in fields:
        if key == "schema_version":
            continue
        value = data[key]
        if key in integer_fields:
            if type(value) is not int:
                reject(f"{key} must be an integer")
        elif key in EMPTY_ALLOWED_FIELDS:
            if not isinstance(value, str) or any(
                ord(character) < 32 or ord(character) == 127 for character in value
            ):
                reject(f"{key} must be a control-free string")
        else:
            required_string(data, key)
    return data


def parse_metadata_bytes(raw: bytes) -> dict[str, object]:
    try:
        data = json.loads(raw.decode("utf-8"), object_pairs_hook=_exact_object)
    except (UnicodeDecodeError, json.JSONDecodeError, DuplicateName) as error:
        reject(f"cannot parse JSON ({error})")
    validated = validate_shape(data)
    if validated["schema_version"] == 10:
        canonical = (
            json.dumps(validated, separators=(",", ":"), ensure_ascii=True) + "\n"
        ).encode("utf-8")
        if raw != canonical:
            reject("schema-10 document bytes are not canonical compact JSON plus one LF")
    return validated


def parse_metadata(path: Path) -> dict[str, object]:
    try:
        raw = path.read_bytes()
    except OSError as error:
        reject(f"cannot parse JSON ({error})")
    return parse_metadata_bytes(raw)


def _validate_fresh_release(
    arguments: argparse.Namespace, data: dict[str, object]
) -> None:
    if not (is_bootstrap_tag(arguments.tag) or is_final_tag(arguments.tag)):
        reject("schema-10 metadata is reserved for the exact fresh release tags")
    phase = "BOOTSTRAP" if is_bootstrap_tag(arguments.tag) else "FINAL"
    if arguments.repository != "joerodriguez/kioku-enclave":
        reject(f"fresh {phase} repository is not the reviewed source repository")
    if arguments.image_repository != FRESH_IMAGE_REPOSITORY:
        reject(f"fresh {phase} image repository is not exact")
    if data["source_repository"] != FRESH_SOURCE_REPOSITORY:
        reject(f"fresh {phase} source_repository is not exact")
    if data["image_uri"] != f"{FRESH_IMAGE_REPOSITORY}:{arguments.tag}":
        reject(f"fresh {phase} tagged image URI is not exact")
    if (
        data["gcs_bucket"] != EXPECTED_INTENT["index_bucket"]
        or data["gcs_media_bucket"] != EXPECTED_INTENT["media_bucket"]
        or data["gcs_legacy_media_bucket"] != EXPECTED_INTENT["legacy_media_bucket"]
    ):
        reject(f"fresh {phase} GCS namespace is not exact")
    try:
        if phase == "BOOTSTRAP":
            validate_checked_bootstrap_source()
            expected_binding = bootstrap_release_binding(
                arguments.expected_adr0022_canary_identity_preparation_sha256,
                arguments.expected_adr0022_canary_admin_uuid,
            )
        else:
            validate_checked_final_source()
            expected_binding = final_release_binding(
                arguments.expected_adr0022_canary_identity_preparation_sha256,
                arguments.expected_adr0022_canary_admin_uuid,
            )
    except FreshReleaseError as error:
        reject(str(error))
    actual_binding = {name: data[name] for name in RELEASE_BINDING_FIELD_ORDER}
    if actual_binding != expected_binding:
        reject(f"fresh {phase} generation/canary/schema binding is not exact")


def validate(arguments: argparse.Namespace, data: dict[str, object]) -> None:
    validate_shape(data)
    for label, value in (
        ("expected GCS bucket", arguments.expected_gcs_bucket),
        ("expected media GCS bucket", arguments.expected_gcs_media_bucket),
        (
            "expected legacy media GCS bucket",
            arguments.expected_gcs_legacy_media_bucket,
        ),
    ):
        if not BUCKET_PATTERN.fullmatch(value):
            reject(f"{label} has an invalid format")
    if arguments.expected_gcs_bucket != arguments.expected_gcs_legacy_media_bucket:
        reject(
            "expected legacy media GCS bucket must equal the expected GCS bucket for Phase-0"
        )

    schema_version = data["schema_version"]
    if schema_version == 10:
        _validate_fresh_release(arguments, data)
    else:
        if claims_fresh_role(arguments.tag):
            reject("fresh release tags require exact schema-10 metadata")
        if (
            arguments.expected_adr0022_canary_identity_preparation_sha256
            or arguments.expected_adr0022_canary_admin_uuid
        ):
            reject("fresh canary expectations require schema-10 metadata")

    expected_repository = f"https://github.com/{arguments.repository}"
    if data["source_repository"] != expected_repository:
        reject("source_repository does not match the expected repository")
    if data["source_ref"] != arguments.tag:
        reject("source_ref does not match the requested tag")
    if data["source_commit"] != arguments.commit or not COMMIT_PATTERN.fullmatch(
        arguments.commit
    ):
        reject("source_commit does not match the requested commit")

    digest = required_string(data, "image_digest")
    if not DIGEST_PATTERN.fullmatch(digest):
        reject("image_digest is not a sha256 digest")
    image_uri = required_string(data, "image_uri")
    if not image_uri.startswith(f"{arguments.image_repository}:"):
        reject("image_uri is outside the expected Artifact Registry repository")
    if data["image_digest_uri"] != f"{arguments.image_repository}@{digest}":
        reject("image_digest_uri does not bind the expected image repository and digest")
    expected_release_url = (
        f"https://github.com/{arguments.repository}/releases/tag/{arguments.tag}"
    )
    if not RELEASE_URL_PATTERN.fullmatch(required_string(data, "release_url")):
        reject("release_url is not an immutable GitHub release URL")
    if data["release_url"] != expected_release_url:
        reject("release_url does not exactly bind the expected repository and tag")
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
        reject(
            "gcs_legacy_media_bucket must equal gcs_bucket for the Phase-0 dual-media migration"
        )

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

    shadow_runtime_claim = (
        data["archive_v3_shadow_runtime_mode"],
        data["archive_v3_archive_bucket"],
        data["archive_v3_archive_gcs_project_number"],
        data["archive_v3_registry_kms_version"],
        data["archive_v3_witness_project_id"],
        data["archive_v3_witness_project_number"],
        data["archive_v3_witness_database_id"],
        data["archive_v3_archive_binding_commitment"],
    )
    try:
        expected_shadow_runtime_claim = select_shadow_runtime_config(
            load_shadow_runtime_config(arguments.archive_v3_shadow_runtime_config),
            profile="production",
            source_ref=arguments.tag,
        ).as_claim()
    except ShadowRuntimeConfigError as error:
        reject(str(error))
    if shadow_runtime_claim != expected_shadow_runtime_claim:
        reject(
            "archive-v3 shadow-runtime claim does not match the release configuration"
        )


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
        "--expected-adr0022-canary-identity-preparation-sha256", default=""
    )
    parser.add_argument("--expected-adr0022-canary-admin-uuid", default="")
    parser.add_argument(
        "--archive-witness-probe-config",
        type=Path,
        default=Path("config/archive-witness-probe.json"),
    )
    parser.add_argument(
        "--archive-v3-shadow-runtime-config",
        type=Path,
        default=Path("config/archive-v3-shadow-runtime.json"),
    )
    arguments = parser.parse_args()
    data = parse_metadata(arguments.metadata)
    validate(arguments, data)
    print(json.dumps(data, separators=(",", ":"), ensure_ascii=True))


if __name__ == "__main__":
    main()
