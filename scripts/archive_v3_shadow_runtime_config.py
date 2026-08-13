#!/usr/bin/env python3
"""Sole parser for the exact-off ADR-0022 shadow-runtime image profile."""

from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
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
)


class ShadowRuntimeConfigError(ValueError):
    """The checked-in shadow-runtime profile is not the sole inactive form."""


@dataclass(frozen=True)
class ArchiveV3ShadowRuntimeConfig:
    mode: str
    archive_bucket: str
    archive_gcs_project_number: str
    registry_kms_version: str
    witness_project_id: str
    witness_project_number: str
    witness_database_id: str

    def as_environment(self) -> dict[str, str]:
        return {
            "ARCHIVE_V3_SHADOW_RUNTIME_MODE": self.mode,
            "ARCHIVE_V3_ARCHIVE_BUCKET": self.archive_bucket,
            "ARCHIVE_V3_ARCHIVE_GCS_PROJECT_NUMBER": self.archive_gcs_project_number,
            "ARCHIVE_V3_REGISTRY_KMS_VERSION": self.registry_kms_version,
            "ARCHIVE_V3_WITNESS_PROJECT_ID": self.witness_project_id,
            "ARCHIVE_V3_WITNESS_PROJECT_NUMBER": self.witness_project_number,
            "ARCHIVE_V3_WITNESS_DATABASE_ID": self.witness_database_id,
        }

    def as_claim(self) -> tuple[str, str, str, str, str, str, str]:
        return (
            self.mode,
            self.archive_bucket,
            self.archive_gcs_project_number,
            self.registry_kms_version,
            self.witness_project_id,
            self.witness_project_number,
            self.witness_database_id,
        )


OFF = ArchiveV3ShadowRuntimeConfig("off", "", "", "", "", "", "")


def _object_without_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ShadowRuntimeConfigError(f"duplicate field: {key}")
        result[key] = value
    return result


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
    if type(data["schema_version"]) is not int or data["schema_version"] != 1:
        raise ShadowRuntimeConfigError(
            "archive-v3 shadow-runtime schema_version must be 1"
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
    )
    if config != OFF:
        raise ShadowRuntimeConfigError(
            "archive-v3 shadow runtime must be exact off with empty deployment fragments"
        )
    return config
