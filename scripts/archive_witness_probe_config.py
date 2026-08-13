#!/usr/bin/env python3
"""Strict shared parser for the checked-in archive witness probe profile."""

from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
import re
from typing import Any


FIELDS = (
    "schema_version",
    "mode",
    "project_id",
    "project_number",
    "database_id",
)
PROJECT_PATTERN = re.compile(r"[a-z][a-z0-9-]{4,28}[a-z0-9]\Z")
PROJECT_NUMBER_PATTERN = re.compile(r"[1-9][0-9]{0,19}\Z")
DATABASE_PATTERN = re.compile(r"[a-z][a-z0-9-]{2,61}[a-z0-9]\Z")
UUID_PATTERN = re.compile(
    r"[0-9A-Za-z]{8}-[0-9A-Za-z]{4}-[0-9A-Za-z]{4}-"
    r"[0-9A-Za-z]{4}-[0-9A-Za-z]{12}\Z"
)
PROBE_TAG_PATTERN = re.compile(
    r"v(?P<version>0|[1-9][0-9]*)\."
    r"(?P<minor>0|[1-9][0-9]*)\."
    r"(?P<patch>0|[1-9][0-9]*)-witness-probe\."
    r"(?P<sequence>[1-9][0-9]*)\Z"
)


class ProbeConfigError(ValueError):
    """The checked-in profile or its requested build context is invalid."""


@dataclass(frozen=True)
class ArchiveWitnessProbeConfig:
    mode: str
    project_id: str
    project_number: str
    database_id: str

    def as_environment(self) -> dict[str, str]:
        return {
            "ARCHIVE_WITNESS_SHADOW_MODE": self.mode,
            "ARCHIVE_WITNESS_PROJECT_ID": self.project_id,
            "ARCHIVE_WITNESS_PROJECT_NUMBER": self.project_number,
            "ARCHIVE_WITNESS_DATABASE_ID": self.database_id,
        }

    def as_claim(self) -> tuple[str, str, str, str]:
        return (
            self.mode,
            self.project_id,
            self.project_number,
            self.database_id,
        )


OFF = ArchiveWitnessProbeConfig("off", "", "", "")


def _object_without_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ProbeConfigError(f"duplicate field: {key}")
        result[key] = value
    return result


def load_probe_config(path: Path) -> ArchiveWitnessProbeConfig:
    try:
        raw = path.read_bytes()
    except OSError as error:
        raise ProbeConfigError(f"cannot read archive witness probe config: {error}") from error
    if len(raw) > 4096:
        raise ProbeConfigError("archive witness probe config exceeds 4096 bytes")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as error:
        raise ProbeConfigError("archive witness probe config is not UTF-8") from error
    try:
        data = json.loads(text, object_pairs_hook=_object_without_duplicates)
    except (json.JSONDecodeError, ProbeConfigError) as error:
        raise ProbeConfigError(f"cannot parse archive witness probe config: {error}") from error
    if not isinstance(data, dict) or tuple(data.keys()) != FIELDS:
        raise ProbeConfigError(
            "archive witness probe config must contain the exact ordered schema"
        )
    if type(data["schema_version"]) is not int or data["schema_version"] != 1:
        raise ProbeConfigError("archive witness probe schema_version must be 1")
    for key in FIELDS[1:]:
        value = data[key]
        if not isinstance(value, str) or any(
            ord(character) < 32 or ord(character) == 127 for character in value
        ):
            raise ProbeConfigError(f"archive witness probe {key} must be a control-free string")

    config = ArchiveWitnessProbeConfig(
        data["mode"], data["project_id"], data["project_number"], data["database_id"]
    )
    namespace = config.as_claim()[1:]
    if config.mode == "off":
        if any(namespace):
            raise ProbeConfigError("archive witness namespace must be empty while mode is off")
    elif config.mode == "probe-v1":
        if not all(namespace):
            raise ProbeConfigError("archive witness namespace must be complete for probe-v1")
        if not PROJECT_PATTERN.fullmatch(config.project_id):
            raise ProbeConfigError("archive witness project ID is invalid")
        if not PROJECT_NUMBER_PATTERN.fullmatch(config.project_number):
            raise ProbeConfigError("archive witness project number is invalid")
        if not DATABASE_PATTERN.fullmatch(config.database_id) or UUID_PATTERN.fullmatch(
            config.database_id
        ):
            raise ProbeConfigError("archive witness database ID is invalid")
    else:
        raise ProbeConfigError("archive witness mode must be off or probe-v1")
    return config


def select_probe_config(
    config: ArchiveWitnessProbeConfig, *, profile: str, source_ref: str
) -> ArchiveWitnessProbeConfig:
    if profile == "evaluation":
        return OFF
    if profile != "production":
        raise ProbeConfigError("archive witness probe profile must be production or evaluation")
    if config.mode != "probe-v1":
        if PROBE_TAG_PATTERN.fullmatch(source_ref):
            raise ProbeConfigError(
                "a witness-probe prerelease tag requires checked-in probe-v1"
            )
        return config
    if PROBE_TAG_PATTERN.fullmatch(source_ref):
        return config
    if source_ref == "main":
        # Main images are CI evidence, not probe candidates. Keeping them off
        # lets the exact commit complete its required pre-tag build without
        # contacting Firestore.
        return OFF
    if source_ref.startswith("v"):
        raise ProbeConfigError(
            "probe-v1 is eligible only for an exact vX.Y.Z-witness-probe.N prerelease tag"
        )
    raise ProbeConfigError("probe-v1 is ineligible outside main or its exact prerelease tag")


def probe_base_tag(source_ref: str) -> str | None:
    match = PROBE_TAG_PATTERN.fullmatch(source_ref)
    if match is None:
        return None
    return f"v{match.group('version')}.{match.group('minor')}.{match.group('patch')}"
