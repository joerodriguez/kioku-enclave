#!/usr/bin/env python3
"""Offline, content-free SQLite smoke harness for ADR-0022 fixtures.

This is deliberately *not* a release gate.  A generic SQLite database cannot
evidence the v3 VFS, backend, witness, fault, lifecycle, cache, or production
image requirements in ADR-0022.  In particular, this program never emits a
``release_evidence: true`` report.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
from pathlib import Path
import platform
import re
import resource
import sqlite3
import sys
import time
from typing import Any

from generate_capacity_fixture import (
    DEFAULT_MANIFEST,
    ManifestError,
    RECORD_KINDS,
    load_manifest,
    synthetic_records,
    validate_manifest,
)


ROOT = Path(__file__).resolve().parents[1]
REPORT_SCHEMA = "kioku-archive-capacity-report-v2"
RUN_SCHEMA = "kioku-archive-capacity-run-v1"
RUN_RECEIPT_NAME = "capacity-run.json"
REPORT_NAME = "capacity-report.json"
PROGRESS_NAME = "capacity-progress.json"
DATABASE_NAME = "archive-capacity.sqlite"
SQLITE_PAGE_SIZE = 4096
MIN_QUERY_SAMPLES = 20
CANONICAL_FULL_PROFILE = "power-user-c-1200-32gib"
IMAGE_RE = re.compile(r"sha256:[0-9a-f]{64}\Z")
VM_RE = re.compile(r"[A-Za-z0-9._:-]{1,128}\Z")
SAFE_PROFILE_RE = re.compile(r"[a-z0-9][a-z0-9_-]{0,63}\Z")


def fail(message: str) -> None:
    raise ManifestError(message)


def _has_symlink_component(path: Path) -> bool:
    """Reject a user-controlled output path that traverses a symlink.

    macOS makes `/var` and `/tmp` platform aliases. They are the only permitted
    symlink components, so a temporary-directory output remains usable while a
    caller cannot redirect a harness-owned file through its own link.
    """
    expanded = path.expanduser()
    absolute = expanded if expanded.is_absolute() else Path.cwd() / expanded
    current = Path(absolute.anchor)
    permitted_platform_aliases = {Path("/var"), Path("/tmp")}
    for part in absolute.parts[1:]:
        current /= part
        if current.is_symlink() and current not in permitted_platform_aliases:
            return True
    return False


def safe_output(path: Path) -> Path:
    if _has_symlink_component(path):
        fail("output path must not contain a symlink")
    resolved = path.expanduser().resolve(strict=False)
    try:
        relative = resolved.relative_to(ROOT)
    except ValueError:
        return resolved
    if not relative.parts or relative.parts[0] != "target":
        fail("output inside the checkout must be below ignored target/")
    return resolved


def _safe_file(path: Path, *, required: bool = False) -> bool:
    if not path.exists():
        if required:
            fail(f"required harness state is absent: {path.name}")
        return False
    if path.is_symlink() or not path.is_file():
        fail(f"harness state must be a regular non-symlink file: {path.name}")
    return True


def atomic_json(path: Path, value: dict[str, Any]) -> None:
    """Write a harness-owned JSON file without following a replacement symlink."""
    if path.exists() and (path.is_symlink() or not path.is_file()):
        fail(f"harness state must be a regular non-symlink file: {path.name}")
    temporary = path.with_suffix(path.suffix + ".tmp")
    if temporary.exists():
        fail(f"stale temporary harness state exists: {temporary.name}")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(json.dumps(value, sort_keys=True, indent=2) + "\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    except BaseException:
        try:
            temporary.unlink(missing_ok=True)
        finally:
            raise


def read_json(path: Path) -> dict[str, Any]:
    _safe_file(path, required=True)
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        fail(f"invalid harness state {path.name}: {error}")
    if not isinstance(value, dict):
        fail(f"invalid harness state {path.name}: root must be an object")
    return value


def percentile(values: list[int], value: float) -> int:
    """Nearest-rank percentile; callers require a non-empty, adequate sample."""
    if not values or not 0 < value <= 1:
        fail("percentile requires values and a fraction in (0, 1]")
    ordered = sorted(values)
    return ordered[math.ceil(len(ordered) * value) - 1]


def validate_args(args: argparse.Namespace) -> None:
    if args.batch_size < 1:
        fail("--batch-size must be positive")
    if args.record_limit < 1:
        fail("--record-limit must be positive")
    if args.sample_size < MIN_QUERY_SAMPLES:
        fail(f"--sample-size must be at least {MIN_QUERY_SAMPLES}")
    if args.concurrency < 1:
        fail("--concurrency must be positive")
    if args.min_ingest_rows_per_second is not None and (
        not math.isfinite(args.min_ingest_rows_per_second)
        or args.min_ingest_rows_per_second < 0
    ):
        fail("--min-ingest-rows-per-second must be finite and non-negative")
    if args.max_query_p95_ms is not None and args.max_query_p95_ms <= 0:
        fail("--max-query-p95-ms must be positive")
    if args.max_rss_bytes is not None and args.max_rss_bytes <= 0:
        fail("--max-rss-bytes must be positive")


def reject_full_mode(args: argparse.Namespace, profile: dict[str, Any]) -> None:
    """Fail closed rather than turn padding/self-reported metadata into a release gate."""
    if args.profile != CANONICAL_FULL_PROFILE:
        fail(f"full mode is reserved for {CANONICAL_FULL_PROFILE}")
    if profile.get("recording_hours_per_year") != 1200 or profile.get("sparse_archive_bytes") != 32 * 1024**3:
        fail("full mode requires the canonical three-year 1,200-hour 32-GiB profile")
    if not args.vm_id or not VM_RE.fullmatch(args.vm_id):
        fail("full mode requires a safe --vm-id")
    if not args.image_digest or not IMAGE_RE.fullmatch(args.image_digest):
        fail("full mode requires --image-digest sha256:<64 lowercase hex>")
    if args.cache_state not in {"cold", "warm"}:
        fail("full mode requires --cache-state cold or warm")
    if args.concurrency < 1:
        fail("full mode requires positive --concurrency")
    if any(
        value is None
        for value in (
            args.min_ingest_rows_per_second,
            args.max_query_p95_ms,
            args.max_rss_bytes,
        )
    ):
        fail("full mode requires ingest, query-p95, and RSS gate values")
    fail(
        "full mode is intentionally unavailable: this SQLite smoke harness cannot "
        "establish ADR-0022 production v3/backend/witness release evidence"
    )


def run_config(
    args: argparse.Namespace, manifest_hash: str, expected_records_sha256: str
) -> dict[str, Any]:
    """All state that must remain identical across an interrupted smoke run."""
    return {
        "schema": RUN_SCHEMA,
        "manifest_sha256": manifest_hash,
        "expected_records_sha256": expected_records_sha256,
        "profile": args.profile,
        "mode": args.mode,
        "record_limit": args.record_limit,
        "batch_size": args.batch_size,
        "sample_size": args.sample_size,
        "concurrency": args.concurrency,
        "sqlite_version": sqlite3.sqlite_version,
        "sqlite_page_size": SQLITE_PAGE_SIZE,
    }


def _permitted_resume_names() -> set[str]:
    return {
        RUN_RECEIPT_NAME,
        PROGRESS_NAME,
        REPORT_NAME,
        DATABASE_NAME,
        f"{DATABASE_NAME}-wal",
        f"{DATABASE_NAME}-shm",
    }


def prepare_output(output: Path, *, resume: bool, config: dict[str, Any]) -> Path:
    """Create an exclusive harness directory or verify its exact resumable identity."""
    if output.exists():
        if output.is_symlink() or not output.is_dir():
            fail("output must be a non-symlink directory")
        names = {entry.name for entry in output.iterdir()}
        if not resume:
            if names:
                fail("fresh output directory must be empty")
            # A pre-existing empty directory is safe; it is claimed immediately below.
        else:
            unexpected = names - _permitted_resume_names()
            if unexpected:
                fail("resume output contains files not owned by this harness")
            receipt = read_json(output / RUN_RECEIPT_NAME)
            if receipt.get("schema") != RUN_SCHEMA:
                fail("resume run receipt has an unsupported schema")
            if receipt.get("config") != config:
                fail("resume arguments or manifest do not match the harness run receipt")
            if (output / REPORT_NAME).exists():
                _safe_file(output / REPORT_NAME, required=True)
            if receipt.get("state") == "complete":
                fail("output already contains a completed report")
            _safe_file(output / DATABASE_NAME, required=True)
            return output
    else:
        output.mkdir(parents=True, mode=0o700)

    receipt = {
        "schema": RUN_SCHEMA,
        "config": config,
        "state": "running",
        "cumulative_elapsed_seconds": 0.0,
        "cumulative_rss_peak_bytes": None,
    }
    atomic_json(output / RUN_RECEIPT_NAME, receipt)
    return output


def rss_measurement() -> dict[str, Any]:
    system = platform.system()
    raw = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    if system == "Darwin":
        return {"bytes": int(raw), "source": "getrusage.ru_maxrss_bytes", "supported": True}
    if system == "Linux":
        return {
            "bytes": int(raw) * 1024,
            "source": "getrusage.ru_maxrss_kib",
            "supported": True,
        }
    return {
        "bytes": None,
        "source": f"unsupported-getrusage-ru_maxrss-on-{system.lower() or 'unknown'}",
        "supported": False,
    }


def update_run_receipt(
    path: Path,
    config: dict[str, Any],
    previous: dict[str, Any],
    segment_started_ns: int,
    *,
    state: str,
) -> dict[str, Any]:
    elapsed = float(previous["cumulative_elapsed_seconds"]) + max(
        (time.monotonic_ns() - segment_started_ns) / 1_000_000_000,
        0.0,
    )
    current_rss = rss_measurement()
    old_rss = previous.get("cumulative_rss_peak_bytes")
    current_bytes = current_rss["bytes"]
    peak = current_bytes if old_rss is None else max(old_rss, current_bytes or 0)
    receipt = {
        "schema": RUN_SCHEMA,
        "config": config,
        "state": state,
        "cumulative_elapsed_seconds": elapsed,
        "cumulative_rss_peak_bytes": peak,
        "rss": current_rss,
    }
    atomic_json(path, receipt)
    return receipt


def progress_state(path: Path, *, rows_committed: int) -> None:
    atomic_json(
        path,
        {"schema": REPORT_SCHEMA, "state": "ingesting", "rows_committed": rows_committed},
    )


def expected_counts(profile: dict[str, Any], record_limit: int) -> dict[str, int]:
    return {
        kind: min(int(count), record_limit)
        for kind, count in profile["expected"]["records"].items()
    }


def normalized_record(record: dict[str, Any]) -> tuple[str, int, int, int]:
    return (
        str(record["kind"]),
        int(record["ordinal"]),
        int(record["logical_offset_ms"]),
        int(record["token"] & 0x7FFF_FFFF_FFFF_FFFF),
    )


def update_records_digest(digest: Any, row: tuple[str, int, int, int]) -> None:
    digest.update(f"{row[0]}:{row[1]}:{row[2]}:{row[3]}\n".encode("ascii"))


def expected_records_digest(
    profile: dict[str, Any], seed: int, record_limit: int
) -> str:
    digest = hashlib.sha256()
    for record in synthetic_records(profile, seed, record_limit):
        update_records_digest(digest, normalized_record(record))
    return digest.hexdigest()


def records_digest(connection: sqlite3.Connection) -> str:
    digest = hashlib.sha256()
    kind_order = " ".join(
        f"WHEN ? THEN {index}" for index, _ in enumerate(RECORD_KINDS)
    )
    query = (
        "SELECT kind, ordinal, logical_offset_ms, token FROM synthetic_records "
        f"ORDER BY CASE kind {kind_order} ELSE {len(RECORD_KINDS)} END, ordinal"
    )
    for row in connection.execute(query, tuple(RECORD_KINDS)):
        update_records_digest(digest, (str(row[0]), int(row[1]), int(row[2]), int(row[3])))
    return digest.hexdigest()


def database_measurements(database: Path) -> dict[str, Any]:
    files: dict[str, dict[str, int | None]] = {}
    for name in (DATABASE_NAME, f"{DATABASE_NAME}-wal", f"{DATABASE_NAME}-shm"):
        path = database.parent / name
        if not path.exists():
            continue
        _safe_file(path, required=True)
        stat = path.stat()
        allocated = getattr(stat, "st_blocks", None)
        files[name] = {
            "apparent_bytes": stat.st_size,
            "allocated_bytes": None if allocated is None else int(allocated) * 512,
        }
    main = files[DATABASE_NAME]
    return {
        "database_apparent_bytes": main["apparent_bytes"],
        "database_allocated_bytes": main["allocated_bytes"],
        "sidecars": files,
        "total_apparent_bytes": sum(int(entry["apparent_bytes"] or 0) for entry in files.values()),
        "total_allocated_bytes": (
            None
            if any(entry["allocated_bytes"] is None for entry in files.values())
            else sum(int(entry["allocated_bytes"] or 0) for entry in files.values())
        ),
    }


def run(args: argparse.Namespace) -> dict[str, Any]:
    validate_args(args)
    manifest, raw = load_manifest(args.manifest)
    profiles = validate_manifest(manifest)
    if args.profile not in profiles or not SAFE_PROFILE_RE.fullmatch(args.profile):
        fail("unknown or unsafe profile")
    profile = profiles[args.profile]
    if args.mode == "full":
        reject_full_mode(args, profile)
    if args.concurrency != 1:
        fail("smoke mode is single-process; it cannot claim a concurrency workload")
    if any(
        value is not None
        for value in (
            args.vm_id,
            args.image_digest,
            args.cache_state,
            args.min_ingest_rows_per_second,
            args.max_query_p95_ms,
            args.max_rss_bytes,
        )
    ):
        fail("smoke mode cannot accept production provenance or release-gate claims")

    manifest_hash = hashlib.sha256(raw).hexdigest()
    expected_export_digest = expected_records_digest(
        profile, manifest["seed"], args.record_limit
    )
    config = run_config(args, manifest_hash, expected_export_digest)
    output = prepare_output(safe_output(args.output), resume=args.resume, config=config)
    database = output / DATABASE_NAME
    report_path = output / REPORT_NAME
    progress = output / PROGRESS_NAME
    receipt_path = output / RUN_RECEIPT_NAME
    receipt = read_json(receipt_path)
    if report_path.exists():
        fail("output already contains a completed report")
    if database.exists() and not args.resume:
        fail("existing database requires --resume")

    segment_started = time.monotonic_ns()
    connection = sqlite3.connect(database)
    try:
        if not args.resume:
            connection.execute(f"PRAGMA page_size={SQLITE_PAGE_SIZE}")
        actual_page_size = connection.execute("PRAGMA page_size").fetchone()[0]
        if actual_page_size != SQLITE_PAGE_SIZE:
            fail("SQLite page size does not match the fixed smoke-harness page size")
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("PRAGMA synchronous=FULL")
        compile_options = {row[0] for row in connection.execute("PRAGMA compile_options")}
        if "ENABLE_FTS5" not in compile_options:
            fail("the local SQLite build lacks required FTS5 support")
        connection.execute(
            "CREATE TABLE IF NOT EXISTS synthetic_records "
            "(kind TEXT NOT NULL, ordinal INTEGER NOT NULL, logical_offset_ms INTEGER NOT NULL, "
            "token INTEGER NOT NULL, PRIMARY KEY(kind, ordinal)) WITHOUT ROWID"
        )
        connection.execute(
            "CREATE INDEX IF NOT EXISTS synthetic_records_offset ON synthetic_records(logical_offset_ms)"
        )
        batch: list[tuple[str, int, int, int]] = []
        for record in synthetic_records(profile, manifest["seed"], args.record_limit):
            batch.append(normalized_record(record))
            if len(batch) == args.batch_size:
                connection.executemany("INSERT OR IGNORE INTO synthetic_records VALUES (?, ?, ?, ?)", batch)
                connection.commit()
                rows = connection.execute("SELECT count(*) FROM synthetic_records").fetchone()[0]
                progress_state(progress, rows_committed=rows)
                receipt = update_run_receipt(
                    receipt_path, config, receipt, segment_started, state="running"
                )
                segment_started = time.monotonic_ns()
                batch.clear()
        if batch:
            connection.executemany("INSERT OR IGNORE INTO synthetic_records VALUES (?, ?, ?, ?)", batch)
            connection.commit()
            rows = connection.execute("SELECT count(*) FROM synthetic_records").fetchone()[0]
            progress_state(progress, rows_committed=rows)
            receipt = update_run_receipt(receipt_path, config, receipt, segment_started, state="running")
            segment_started = time.monotonic_ns()

        counts = dict(connection.execute("SELECT kind, count(*) FROM synthetic_records GROUP BY kind"))
        expected = expected_counts(profile, args.record_limit)
        if counts != expected:
            fail("resumed SQLite records do not exactly match the requested fixture distribution")
        export_digest = records_digest(connection)
        if export_digest != expected_export_digest:
            fail("resumed SQLite record content does not match the deterministic fixture")
        connection.execute("DROP TABLE IF EXISTS synthetic_fts")
        connection.execute("CREATE VIRTUAL TABLE synthetic_fts USING fts5(kind, token)")
        connection.execute(
            "INSERT INTO synthetic_fts(kind, token) "
            "SELECT kind, 't' || token FROM synthetic_records"
        )
        connection.commit()
        integrity = connection.execute("PRAGMA integrity_check").fetchone()[0]
        if integrity != "ok":
            fail("SQLite integrity_check failed")
        connection.execute("INSERT INTO synthetic_fts(synthetic_fts) VALUES ('integrity-check')").fetchall()
        connection.commit()
        query_latencies: list[int] = []
        total_duration = profile["expected"]["recording_hours"] * 3_600_000
        for sample in range(args.sample_size):
            lower = (sample * total_duration) // args.sample_size
            upper = ((sample + 1) * total_duration) // args.sample_size
            query_started = time.monotonic_ns()
            connection.execute(
                "SELECT count(*), min(token), max(token) FROM synthetic_records "
                "WHERE logical_offset_ms >= ? AND logical_offset_ms < ?",
                (lower, upper),
            ).fetchone()
            connection.execute(
                "SELECT count(*) FROM synthetic_fts WHERE synthetic_fts MATCH 'kind:audio_segments'"
            ).fetchone()
            query_latencies.append((time.monotonic_ns() - query_started) // 1_000_000)
        page_size = connection.execute("PRAGMA page_size").fetchone()[0]
        logical_bytes = connection.execute("PRAGMA page_count").fetchone()[0] * page_size
        connection.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    finally:
        connection.close()

    file_stats = database_measurements(database)
    receipt = update_run_receipt(receipt_path, config, receipt, segment_started, state="writing_report")
    report = {
        "schema": REPORT_SCHEMA,
        "mode": "smoke",
        "classification": "sqlite_smoke_non_evidence",
        "release_evidence": False,
        "sqlite_local_evidence": False,
        "manifest_sha256": manifest_hash,
        "profile": {
            "id": args.profile,
            "recording_hours_per_year": profile["recording_hours_per_year"],
            "horizon_years": manifest["horizon_years"],
            "expected": profile["expected"],
        },
        "environment": {
            "platform": {"system": platform.system(), "release": platform.release()},
            "filesystem": {"type": "not-detected", "statvfs_block_size": os.statvfs(database).f_bsize},
            "sqlite_version": sqlite3.sqlite_version,
            "sqlite_extensions": ["fts5"],
            "sqlite_compile_options": sorted(compile_options),
            "cache_state": "not-measured",
            "concurrency": "single-process-smoke-only",
        },
        "sample": {
            "query_samples": args.sample_size,
            "percentile_method": "nearest-rank",
            "query_workload": "single-process warm SQLite smoke query; not an ADR-0022 query mix",
            "percentiles": {
                "p50_ms": percentile(query_latencies, 0.50),
                "p95_ms": percentile(query_latencies, 0.95),
                "p99_ms": percentile(query_latencies, 0.99),
            },
        },
        "measurements": {
            "rows": sum(counts.values()),
            "rows_by_kind": counts,
            "expected_rows_by_kind": expected,
            "logical_database_bytes": logical_bytes,
            "file_bytes": file_stats,
            "rss": receipt["rss"],
            "cumulative_elapsed_seconds": receipt["cumulative_elapsed_seconds"],
            "cumulative_rss_peak_bytes": receipt["cumulative_rss_peak_bytes"],
            "logical_export_sha256": export_digest,
            "expected_logical_export_sha256": expected_export_digest,
            "sqlite_integrity": integrity,
            "fts_integrity": "ok",
        },
        "limitations": (
            "Smoke-only, synthetic local SQLite check. It cannot satisfy ADR-0022 production "
            "v3/VFS/backend/witness/fault/lifecycle/capacity-release gates."
        ),
    }
    atomic_json(report_path, report)
    update_run_receipt(receipt_path, config, receipt, time.monotonic_ns(), state="complete")
    progress.unlink(missing_ok=True)
    return report


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--profile", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--mode", choices=("smoke", "full"), default="smoke")
    parser.add_argument("--record-limit", type=int, default=100)
    parser.add_argument("--batch-size", type=int, default=5000)
    parser.add_argument("--resume", action="store_true")
    parser.add_argument("--vm-id")
    parser.add_argument("--image-digest")
    parser.add_argument("--cache-state")
    parser.add_argument("--concurrency", type=int, default=1)
    parser.add_argument("--sample-size", type=int, default=MIN_QUERY_SAMPLES)
    parser.add_argument("--min-ingest-rows-per-second", type=float)
    parser.add_argument("--max-query-p95-ms", type=int)
    parser.add_argument("--max-rss-bytes", type=int)
    args = parser.parse_args()
    try:
        print(json.dumps(run(args), sort_keys=True))
        return 0
    except (ManifestError, sqlite3.Error, OSError) as error:
        print(f"Error: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
