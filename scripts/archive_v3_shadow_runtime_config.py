#!/usr/bin/env python3
"""Strict parser and release-tag selector for the sealed ADR-0022 runtime."""

from __future__ import annotations

from dataclasses import dataclass
import ipaddress
import json
from pathlib import Path
import re
from typing import Any


FIELDS = (
    "schema_version",
    "mode",
    "archive_bucket",
    "archive_gcs_project_number",
    "registry_kms_version",
    "witness_project_id",
    "witness_project_number",
    "witness_database_id",
    "archive_binding_commitment",
)
WAL_TAG_PATTERN = re.compile(
    r"v(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)"
    r"-archive-v3-wal\.[1-9][0-9]*\Z"
)
U64_MAX = 18_446_744_073_709_551_615


class ShadowRuntimeConfigError(ValueError):
    """The image-bound runtime profile is malformed or tag-ineligible."""


@dataclass(frozen=True)
class ArchiveV3ShadowRuntimeConfig:
    mode: str
    archive_bucket: str
    archive_gcs_project_number: str
    registry_kms_version: str
    witness_project_id: str
    witness_project_number: str
    witness_database_id: str
    archive_binding_commitment: str

    def as_environment(self) -> dict[str, str]:
        return {
            "ARCHIVE_V3_SHADOW_RUNTIME_MODE": self.mode,
            "ARCHIVE_V3_ARCHIVE_BUCKET": self.archive_bucket,
            "ARCHIVE_V3_ARCHIVE_GCS_PROJECT_NUMBER": self.archive_gcs_project_number,
            "ARCHIVE_V3_REGISTRY_KMS_VERSION": self.registry_kms_version,
            "ARCHIVE_V3_WITNESS_PROJECT_ID": self.witness_project_id,
            "ARCHIVE_V3_WITNESS_PROJECT_NUMBER": self.witness_project_number,
            "ARCHIVE_V3_WITNESS_DATABASE_ID": self.witness_database_id,
            "ARCHIVE_V3_ARCHIVE_BINDING_COMMITMENT": self.archive_binding_commitment,
        }

    def as_claim(self) -> tuple[str, str, str, str, str, str, str, str]:
        return (
            self.mode,
            self.archive_bucket,
            self.archive_gcs_project_number,
            self.registry_kms_version,
            self.witness_project_id,
            self.witness_project_number,
            self.witness_database_id,
            self.archive_binding_commitment,
        )


OFF = ArchiveV3ShadowRuntimeConfig("off", "", "", "", "", "", "", "")


def _object_without_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ShadowRuntimeConfigError(f"duplicate field: {key}")
        result[key] = value
    return result


def _canonical_u64(value: str) -> bool:
    return (
        1 <= len(value) <= 20
        and not value.startswith("0")
        and value.isascii()
        and value.isdecimal()
        and int(value) <= U64_MAX
    )


def _valid_bucket(value: str) -> bool:
    length_ok = (
        len(value) <= 222
        and all(component and len(component) <= 63 for component in value.split("."))
        if "." in value
        else len(value) <= 63
    )
    if not (
        length_ok
        and len(value) >= 3
        and value.isascii()
        and all(character.islower() or character.isdigit() or character in "-_." for character in value)
        and value[0].isalnum()
        and value[-1].isalnum()
        and not value.startswith("goog")
        and "google" not in value
        and "g00gle" not in value
    ):
        return False
    try:
        ipaddress.IPv4Address(value)
    except ipaddress.AddressValueError:
        return True
    return False


def _valid_project_id(value: str) -> bool:
    return bool(re.fullmatch(r"[a-z][a-z0-9-]{4,28}[a-z0-9]", value))


def _uuid_like(value: str) -> bool:
    return bool(
        re.fullmatch(
            r"[0-9a-z]{8}-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{12}",
            value,
        )
    )


def _valid_database_id(value: str) -> bool:
    return bool(re.fullmatch(r"[a-z][a-z0-9-]{2,61}[a-z0-9]", value)) and not _uuid_like(value)


def _valid_commitment(value: str) -> bool:
    return bool(re.fullmatch(r"[0-9a-f]{64}", value)) and value != "0" * 64


def load_shadow_runtime_config(path: Path) -> ArchiveV3ShadowRuntimeConfig:
    try:
        raw = path.read_bytes()
    except OSError as error:
        raise ShadowRuntimeConfigError(
            f"cannot read archive-v3 shadow-runtime config: {error}"
        ) from error
    if len(raw) > 4096:
        raise ShadowRuntimeConfigError(
            "archive-v3 shadow-runtime config exceeds 4096 bytes"
        )
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as error:
        raise ShadowRuntimeConfigError(
            "archive-v3 shadow-runtime config is not UTF-8"
        ) from error
    try:
        data = json.loads(text, object_pairs_hook=_object_without_duplicates)
    except (json.JSONDecodeError, ShadowRuntimeConfigError) as error:
        raise ShadowRuntimeConfigError(
            f"cannot parse archive-v3 shadow-runtime config: {error}"
        ) from error
    if not isinstance(data, dict) or tuple(data.keys()) != FIELDS:
        raise ShadowRuntimeConfigError(
            "archive-v3 shadow-runtime config must contain the exact ordered schema"
        )
    if type(data["schema_version"]) is not int or data["schema_version"] != 2:
        raise ShadowRuntimeConfigError(
            "archive-v3 shadow-runtime schema_version must be 2"
        )
    for key in FIELDS[1:]:
        value = data[key]
        if not isinstance(value, str) or any(
            ord(character) < 32 or ord(character) == 127 for character in value
        ):
            raise ShadowRuntimeConfigError(
                f"archive-v3 shadow-runtime {key} must be a control-free string"
            )
    config = ArchiveV3ShadowRuntimeConfig(
        data["mode"],
        data["archive_bucket"],
        data["archive_gcs_project_number"],
        data["registry_kms_version"],
        data["witness_project_id"],
        data["witness_project_number"],
        data["witness_database_id"],
        data["archive_binding_commitment"],
    )
    if config.mode == "off":
        if config != OFF:
            raise ShadowRuntimeConfigError(
                "archive-v3 shadow runtime off mode requires every deployment fragment empty"
            )
        return config
    if config.mode != "single-archive-wal-v1":
        raise ShadowRuntimeConfigError("archive-v3 shadow-runtime mode is unsupported")
    if not _valid_bucket(config.archive_bucket):
        raise ShadowRuntimeConfigError("archive-v3 archive bucket is invalid")
    for label, value in (
        ("archive GCS project number", config.archive_gcs_project_number),
        ("registry KMS version", config.registry_kms_version),
        ("witness project number", config.witness_project_number),
    ):
        if not _canonical_u64(value):
            raise ShadowRuntimeConfigError(f"archive-v3 {label} is invalid")
    if not _valid_project_id(config.witness_project_id):
        raise ShadowRuntimeConfigError("archive-v3 witness project ID is invalid")
    if not _valid_database_id(config.witness_database_id):
        raise ShadowRuntimeConfigError("archive-v3 witness database ID is invalid")
    if not _valid_commitment(config.archive_binding_commitment):
        raise ShadowRuntimeConfigError("archive-v3 archive binding commitment is invalid")
    return config


def select_shadow_runtime_config(
    config: ArchiveV3ShadowRuntimeConfig,
    *,
    profile: str,
    source_ref: str,
) -> ArchiveV3ShadowRuntimeConfig:
    if source_ref.startswith("refs/tags/"):
        source_ref = source_ref.removeprefix("refs/tags/")
    is_wal_tag = WAL_TAG_PATTERN.fullmatch(source_ref) is not None
    if profile == "evaluation":
        return OFF
    if profile != "production":
        raise ShadowRuntimeConfigError("archive-v3 shadow runtime profile is unsupported")
    if config == OFF:
        if is_wal_tag:
            raise ShadowRuntimeConfigError(
                "an archive-v3 WAL release tag requires the complete active runtime profile"
            )
        return OFF
    if source_ref == "main":
        return OFF
    if not is_wal_tag:
        raise ShadowRuntimeConfigError(
            "single-archive-wal-v1 requires an exact vX.Y.Z-archive-v3-wal.N tag"
        )
    return config
