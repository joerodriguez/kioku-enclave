#!/usr/bin/env python3
"""Validate and stream deterministic, content-free ADR-0022 capacity fixtures."""

from __future__ import annotations

import argparse
import gzip
import hashlib
import io
import json
import os
import re
import sys
from pathlib import Path
from typing import Any, Iterator


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_MANIFEST = REPOSITORY_ROOT / "eval/capacity/archive-fixtures-v1.json"
EXPECTED_SCHEMAS = {
    "kioku-archive-capacity-fixture-v1",
    "kioku-archive-capacity-fixture-v2",
}
PROFILE_ID_RE = re.compile(r"[a-z0-9][a-z0-9_-]{0,63}\Z")
RECORD_KINDS = (
    "audio_segments",
    "utterances",
    "fts_entries",
    "vectors",
    "screen_references",
    "canonical_screens",
    "jobs",
    "evidence",
    "people",
    "voice_samples",
)


class ManifestError(ValueError):
    """The checked-in fixture contract is malformed or internally inconsistent."""


def _integer(value: Any, field: str, *, minimum: int = 1) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise ManifestError(f"{field} must be an integer >= {minimum}")
    return value


def _mapping(value: Any, field: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ManifestError(f"{field} must be an object")
    return value


def validate_temporal_payload_shape(manifest: dict[str, Any]) -> dict[str, Any] | None:
    """Validate v2's numeric time/cadence/payload geometry without accepting content."""
    if manifest.get("schema") != "kioku-archive-capacity-fixture-v2":
        return None
    shape = _mapping(manifest.get("temporal_payload_shape"), "temporal_payload_shape")
    if _integer(shape.get("recording_days_per_month"), "temporal_payload_shape.recording_days_per_month") > 31:
        raise ManifestError("recording_days_per_month must not exceed 31")
    _integer(
        shape.get("sessions_per_active_day"),
        "temporal_payload_shape.sessions_per_active_day",
    )
    if _integer(shape.get("retention_months"), "temporal_payload_shape.retention_months") != 12:
        raise ManifestError("v2 retention geometry must cover exactly 12 months")
    payloads = _mapping(shape.get("payload_bytes_by_kind"), "temporal_payload_shape.payload_bytes_by_kind")
    if set(payloads) != set(RECORD_KINDS):
        raise ManifestError("payload_bytes_by_kind must contain exactly the capacity record kinds")
    for kind in RECORD_KINDS:
        _integer(payloads[kind], f"payload_bytes_by_kind.{kind}", minimum=1)
        if payloads[kind] > 4096:
            raise ManifestError("synthetic payload geometry must remain bounded at 4096 bytes")
    embedding = _mapping(shape.get("embedding"), "temporal_payload_shape.embedding")
    dimensions = _integer(embedding.get("dimensions"), "temporal_payload_shape.embedding.dimensions")
    element_bytes = _integer(embedding.get("element_bytes"), "temporal_payload_shape.embedding.element_bytes")
    logical_bytes = _integer(embedding.get("logical_bytes"), "temporal_payload_shape.embedding.logical_bytes")
    if dimensions != manifest["vector_dimensions"] or element_bytes != 4 or logical_bytes != dimensions * element_bytes:
        raise ManifestError("embedding geometry must be the 384-dimension float32 logical shape")
    return shape


def expected_profile(manifest: dict[str, Any], profile: dict[str, Any]) -> dict[str, Any]:
    schema = manifest.get("schema")
    if schema == "kioku-archive-capacity-fixture-v1":
        horizon_years = _integer(manifest.get("horizon_years"), "horizon_years")
        weeks = _integer(manifest.get("recording_weeks_per_year"), "recording_weeks_per_year")
        annual_hours = _integer(
            profile.get("recording_hours_per_year"), "profile.recording_hours_per_year"
        )
        active_week_hours = _integer(
            profile.get("recording_hours_per_active_week"),
            "profile.recording_hours_per_active_week",
        )
        if active_week_hours * weeks != annual_hours:
            raise ManifestError("annual recording hours must equal active-week hours times weeks")
        recording_hours = annual_hours * horizon_years
    elif schema == "kioku-archive-capacity-fixture-v2":
        horizon_months = _integer(manifest.get("horizon_months"), "horizon_months")
        if horizon_months != 12:
            raise ManifestError("v2 capacity fixtures must span exactly 12 months")
        monthly_hours = _integer(
            profile.get("recording_hours_per_month"), "profile.recording_hours_per_month"
        )
        annual_hours = monthly_hours * horizon_months
        recording_hours = annual_hours
    else:
        raise ManifestError("unsupported capacity fixture schema")
    interval = _integer(
        manifest.get("screen_observation_interval_seconds"),
        "screen_observation_interval_seconds",
    )
    if 3600 % interval:
        raise ManifestError("screen observation interval must divide one hour exactly")

    ratio = _mapping(manifest.get("canonical_screen_ratio"), "canonical_screen_ratio")
    numerator = _integer(ratio.get("numerator"), "canonical_screen_ratio.numerator")
    denominator = _integer(ratio.get("denominator"), "canonical_screen_ratio.denominator")
    if numerator >= denominator:
        raise ManifestError("canonical screen ratio must be strictly between zero and one")

    rates = _mapping(manifest.get("rates_per_recording_hour"), "rates_per_recording_hour")
    screen_observations = recording_hours * (3600 // interval)
    canonical_numerator = screen_observations * numerator
    if canonical_numerator % denominator:
        raise ManifestError("canonical screen ratio does not yield an integral record count")
    canonical_screens = canonical_numerator // denominator
    screen_references = screen_observations - canonical_screens

    audio_segments = recording_hours * _integer(
        rates.get("audio_segments"), "rates_per_recording_hour.audio_segments"
    )
    utterances = recording_hours * _integer(
        rates.get("utterances"), "rates_per_recording_hour.utterances"
    )
    evidence = recording_hours * _integer(
        rates.get("evidence"), "rates_per_recording_hour.evidence"
    )
    voice_samples = recording_hours * _integer(
        rates.get("voice_samples"), "rates_per_recording_hour.voice_samples"
    )
    people_interval = _integer(
        manifest.get("people_per_recording_hours"), "people_per_recording_hours"
    )
    people = (recording_hours + people_interval - 1) // people_interval

    sizing = _mapping(manifest.get("core_archive_sizing"), "core_archive_sizing")
    low_bytes = recording_hours * _integer(
        sizing.get("low_bytes_per_recording_hour"),
        "core_archive_sizing.low_bytes_per_recording_hour",
    )
    high_bytes = recording_hours * _integer(
        sizing.get("high_bytes_per_recording_hour"),
        "core_archive_sizing.high_bytes_per_recording_hour",
    )

    return {
        "recording_hours": recording_hours,
        "records": {
            "audio_segments": audio_segments,
            "utterances": utterances,
            "fts_entries": utterances + screen_observations,
            "vectors": utterances + canonical_screens,
            "screen_references": screen_references,
            "canonical_screens": canonical_screens,
            "jobs": audio_segments + canonical_screens,
            "evidence": evidence,
            "people": people,
            "voice_samples": voice_samples,
        },
        "core_archive_bytes_low": low_bytes,
        "core_archive_bytes_high": high_bytes,
    }


def validate_manifest(manifest: dict[str, Any]) -> dict[str, dict[str, Any]]:
    if manifest.get("schema") not in EXPECTED_SCHEMAS:
        raise ManifestError(f"schema must be one of {sorted(EXPECTED_SCHEMAS)!r}")
    seed = _integer(manifest.get("seed"), "seed", minimum=0)
    if seed > 0xFFFFFFFFFFFFFFFF:
        raise ManifestError("seed must fit in an unsigned 64-bit integer")
    if _integer(manifest.get("vector_dimensions"), "vector_dimensions") != 384:
        raise ManifestError("vector_dimensions must match the production 384-dimension model")
    temporal_payload_shape = validate_temporal_payload_shape(manifest)
    profiles = manifest.get("profiles")
    if not isinstance(profiles, list) or not profiles:
        raise ManifestError("profiles must be a non-empty array")

    validated: dict[str, dict[str, Any]] = {}
    capacity_shapes_seen: set[int] = set()
    for index, raw_profile in enumerate(profiles):
        profile = _mapping(raw_profile, f"profiles[{index}]")
        profile_id = profile.get("id")
        if not isinstance(profile_id, str) or not PROFILE_ID_RE.fullmatch(profile_id):
            raise ManifestError(f"profiles[{index}].id has an invalid format")
        if profile_id in validated:
            raise ManifestError(f"duplicate profile id: {profile_id}")
        computed = expected_profile(manifest, profile)
        if profile.get("expected") != computed:
            raise ManifestError(f"profile {profile_id!r} expected values do not match parameters")
        if "sparse_archive_bytes" in profile:
            sparse_bytes = _integer(
                profile["sparse_archive_bytes"], f"profiles[{index}].sparse_archive_bytes"
            )
            if sparse_bytes != 32 * 1024**3:
                raise ManifestError("the sparse power-user shape must be exactly 32 GiB")
        validated[profile_id] = profile
        if manifest["schema"] == "kioku-archive-capacity-fixture-v1":
            capacity_shapes_seen.add(profile["recording_hours_per_year"])
        else:
            capacity_shapes_seen.add(profile["recording_hours_per_month"])

    expected_shapes = (
        {480, 960, 1200}
        if manifest["schema"] == "kioku-archive-capacity-fixture-v1"
        else {40, 80, 100}
    )
    missing_shapes = expected_shapes - capacity_shapes_seen
    if missing_shapes:
        unit = "annual recording hours" if manifest["schema"] == "kioku-archive-capacity-fixture-v1" else "monthly recording hours"
        raise ManifestError(f"profiles are missing {unit}: {sorted(missing_shapes)}")
    if not any(profile.get("sparse_archive_bytes") == 32 * 1024**3 for profile in profiles):
        raise ManifestError("profiles are missing the 32-GiB sparse shape")
    if temporal_payload_shape is not None:
        for profile in validated.values():
            monthly_hours = profile["recording_hours_per_month"]
            if monthly_hours % temporal_payload_shape["recording_days_per_month"]:
                raise ManifestError("monthly recording hours must divide evenly across active recording days")
    return validated


def load_manifest(path: Path) -> tuple[dict[str, Any], bytes]:
    raw = path.read_bytes()
    try:
        manifest = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ManifestError(f"manifest is not valid UTF-8 JSON: {error}") from error
    if not isinstance(manifest, dict):
        raise ManifestError("manifest root must be an object")
    validate_manifest(manifest)
    return manifest, raw


def _splitmix64(value: int) -> int:
    value = (value + 0x9E3779B97F4A7C15) & 0xFFFFFFFFFFFFFFFF
    value = ((value ^ (value >> 30)) * 0xBF58476D1CE4E5B9) & 0xFFFFFFFFFFFFFFFF
    value = ((value ^ (value >> 27)) * 0x94D049BB133111EB) & 0xFFFFFFFFFFFFFFFF
    return value ^ (value >> 31)


def synthetic_records(
    profile: dict[str, Any], seed: int, max_records_per_kind: int | None = None,
    temporal_payload_shape: dict[str, Any] | None = None,
) -> Iterator[dict[str, int | str]]:
    expected = profile["expected"]
    duration_ms = expected["recording_hours"] * 3600 * 1000
    for kind_index, kind in enumerate(RECORD_KINDS):
        count = expected["records"][kind]
        emitted = count if max_records_per_kind is None else min(count, max_records_per_kind)
        for ordinal in range(emitted):
            record: dict[str, int | str] = {
                "kind": kind,
                "ordinal": ordinal,
                "logical_offset_ms": (ordinal * duration_ms) // count,
                "token": _splitmix64(seed ^ (kind_index << 48) ^ ordinal),
            }
            if temporal_payload_shape is not None:
                monthly_duration_ms = profile["recording_hours_per_month"] * 3600 * 1000
                record["month_index"] = min(11, int(record["logical_offset_ms"]) // monthly_duration_ms)
                record["cadence_slot"] = ordinal % (
                    temporal_payload_shape["recording_days_per_month"]
                    * temporal_payload_shape["sessions_per_active_day"]
                )
                record["retention_months"] = temporal_payload_shape["retention_months"]
                record["payload_bytes"] = temporal_payload_shape["payload_bytes_by_kind"][kind]
                if kind == "vectors":
                    record["embedding_dimensions"] = temporal_payload_shape["embedding"]["dimensions"]
                    record["embedding_logical_bytes"] = temporal_payload_shape["embedding"]["logical_bytes"]
            yield record


def _safe_output_directory(output: Path) -> Path:
    resolved = output.expanduser().resolve()
    try:
        relative = resolved.relative_to(REPOSITORY_ROOT)
    except ValueError:
        return resolved
    if not relative.parts or relative.parts[0] != "target":
        raise ManifestError("output inside the checkout must be under ignored target/")
    return resolved


def generate_fixture(
    manifest: dict[str, Any],
    manifest_raw: bytes,
    profile_id: str,
    output: Path,
    *,
    max_records_per_kind: int | None,
    create_sparse_shape: bool,
) -> dict[str, Any]:
    profiles = validate_manifest(manifest)
    if profile_id not in profiles:
        raise ManifestError(f"unknown profile {profile_id!r}")
    if max_records_per_kind is not None and max_records_per_kind < 1:
        raise ManifestError("max_records_per_kind must be at least one")
    profile = profiles[profile_id]
    if create_sparse_shape and "sparse_archive_bytes" not in profile:
        raise ManifestError("selected profile does not declare a sparse archive shape")

    output = _safe_output_directory(output)
    output.mkdir(parents=True, exist_ok=True)
    if any(output.iterdir()):
        raise ManifestError("output directory must be empty")

    records_path = output / "records.ndjson.gz"
    with records_path.open("xb") as raw_output:
        with gzip.GzipFile(fileobj=raw_output, mode="wb", filename="", mtime=0) as compressed:
            with io.TextIOWrapper(compressed, encoding="utf-8", newline="\n") as text_output:
                for record in synthetic_records(
                    profile,
                    manifest["seed"],
                    max_records_per_kind,
                    validate_temporal_payload_shape(manifest),
                ):
                    text_output.write(json.dumps(record, sort_keys=True, separators=(",", ":")))
                    text_output.write("\n")

    sparse_receipt = None
    if create_sparse_shape:
        sparse_path = output / "archive-shape.sparse"
        sparse_bytes = profile["sparse_archive_bytes"]
        with sparse_path.open("xb") as sparse_file:
            sparse_file.truncate(sparse_bytes)
        stat = sparse_path.stat()
        sparse_receipt = {
            "logical_bytes": stat.st_size,
            "is_sqlite_database": False,
        }

    complete = max_records_per_kind is None
    receipt = {
        "schema": "kioku-archive-capacity-fixture-receipt-v1",
        "profile": profile_id,
        "source_manifest_sha256": hashlib.sha256(manifest_raw).hexdigest(),
        "seed": manifest["seed"],
        "complete_distribution": complete,
        "max_records_per_kind": max_records_per_kind,
        "expected": profile["expected"],
        "sparse_shape": sparse_receipt,
    }
    (output / "fixture-receipt.json").write_text(
        json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return receipt


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("check", help="validate and summarize the manifest")
    generate = subparsers.add_parser("generate", help="stream a synthetic fixture")
    generate.add_argument("--profile", required=True)
    generate.add_argument("--output", type=Path, required=True)
    generate.add_argument("--max-records-per-kind", type=int)
    generate.add_argument("--create-sparse-shape", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        manifest, raw = load_manifest(args.manifest)
        if args.command == "check":
            profiles = validate_manifest(manifest)
            summary = {
                "schema": manifest["schema"],
                "manifest_sha256": hashlib.sha256(raw).hexdigest(),
                "profiles": {
                    profile_id: profile["expected"] for profile_id, profile in profiles.items()
                },
            }
            print(json.dumps(summary, indent=2, sort_keys=True))
            return 0
        receipt = generate_fixture(
            manifest,
            raw,
            args.profile,
            args.output,
            max_records_per_kind=args.max_records_per_kind,
            create_sparse_shape=args.create_sparse_shape,
        )
        print(json.dumps(receipt, indent=2, sort_keys=True))
        return 0
    except (ManifestError, OSError) as error:
        print(f"capacity fixture failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
