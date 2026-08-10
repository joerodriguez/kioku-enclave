#!/usr/bin/env python3
"""Offline, content-free SQLite capacity/load evidence harness for ADR-0022."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import resource
import sqlite3
import sys
import time
from typing import Any

from generate_capacity_fixture import DEFAULT_MANIFEST, ManifestError, load_manifest, synthetic_records, validate_manifest


ROOT = Path(__file__).resolve().parents[1]
REPORT_SCHEMA = "kioku-archive-capacity-report-v1"
IMAGE_RE = re.compile(r"sha256:[0-9a-f]{64}\Z")
VM_RE = re.compile(r"[A-Za-z0-9._:-]{1,128}\Z")
SAFE_PROFILE_RE = re.compile(r"[a-z0-9][a-z0-9_-]{0,63}\Z")
CHUNK_BYTES = 1024 * 1024


def fail(message: str) -> None:
    raise ManifestError(message)


def safe_output(path: Path) -> Path:
    resolved = path.expanduser().resolve()
    try:
        relative = resolved.relative_to(ROOT)
    except ValueError:
        return resolved
    if not relative.parts or relative.parts[0] != "target":
        fail("output inside the checkout must be below ignored target/")
    return resolved


def percentile(values: list[int], value: float) -> int:
    if not values:
        return 0
    ordered = sorted(values)
    return ordered[min(len(ordered) - 1, int((len(ordered) - 1) * value))]


def require_full_metadata(args: argparse.Namespace, target: int | None) -> None:
    if target is None:
        fail("full mode requires the profile with the declared 32-GiB SQLite target")
    if not args.vm_id or not VM_RE.fullmatch(args.vm_id):
        fail("full mode requires a safe --vm-id")
    if not args.image_digest or not IMAGE_RE.fullmatch(args.image_digest):
        fail("full mode requires --image-digest sha256:<64 lowercase hex>")
    if args.cache_state not in {"cold", "warm"}:
        fail("full mode requires --cache-state cold or warm")
    if args.concurrency < 1 or args.sample_size < 1:
        fail("full mode requires positive --concurrency and --sample-size")
    if any(value is None for value in (args.min_ingest_rows_per_second, args.max_query_p95_ms, args.max_rss_bytes)):
        fail("full mode requires ingest, query-p95, and RSS gate values")


def atomic_json(path: Path, value: dict[str, Any]) -> None:
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(value, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    os.replace(temporary, path)


def fill_padding(connection: sqlite3.Connection, target: int, progress: Path) -> None:
    connection.execute("CREATE TABLE IF NOT EXISTS capacity_padding (chunk INTEGER PRIMARY KEY, payload BLOB NOT NULL)")
    chunk = connection.execute("SELECT COALESCE(MAX(chunk), -1) + 1 FROM capacity_padding").fetchone()[0]
    while True:
        logical = connection.execute("PRAGMA page_count").fetchone()[0] * connection.execute("PRAGMA page_size").fetchone()[0]
        if logical >= target:
            return
        rows = min(64, (target - logical + CHUNK_BYTES - 1) // CHUNK_BYTES)
        connection.executemany("INSERT INTO capacity_padding(chunk, payload) VALUES (?, zeroblob(?))", ((chunk + index, CHUNK_BYTES) for index in range(rows)))
        connection.commit()
        chunk += rows
        atomic_json(progress, {"schema": REPORT_SCHEMA, "state": "padding", "next_padding_chunk": chunk})


def run(args: argparse.Namespace) -> dict[str, Any]:
    manifest, raw = load_manifest(args.manifest)
    profiles = validate_manifest(manifest)
    if args.profile not in profiles or not SAFE_PROFILE_RE.fullmatch(args.profile):
        fail("unknown or unsafe profile")
    profile = profiles[args.profile]
    target = profile.get("sparse_archive_bytes")
    if args.mode == "full":
        require_full_metadata(args, target)
    if args.mode == "smoke" and args.record_limit < 1:
        fail("smoke mode requires --record-limit >= 1")
    output = safe_output(args.output)
    output.mkdir(parents=True, exist_ok=True)
    database = output / "archive-capacity.sqlite"
    report_path = output / "capacity-report.json"
    progress = output / "capacity-progress.json"
    if report_path.exists():
        fail("output already contains a completed report")
    if database.exists() and not args.resume:
        fail("existing database requires --resume")

    started = time.monotonic_ns()
    connection = sqlite3.connect(database)
    connection.execute("PRAGMA journal_mode=WAL")
    connection.execute("PRAGMA synchronous=FULL")
    connection.execute("PRAGMA page_size=4096")
    compile_options = {row[0] for row in connection.execute("PRAGMA compile_options")}
    if "ENABLE_FTS5" not in compile_options:
        fail("the local SQLite build lacks required FTS5 support")
    connection.execute("CREATE TABLE IF NOT EXISTS synthetic_records (kind TEXT NOT NULL, ordinal INTEGER NOT NULL, logical_offset_ms INTEGER NOT NULL, token INTEGER NOT NULL, PRIMARY KEY(kind, ordinal)) WITHOUT ROWID")
    connection.execute("CREATE INDEX IF NOT EXISTS synthetic_records_offset ON synthetic_records(logical_offset_ms)")
    max_per_kind = args.record_limit if args.mode == "smoke" else None
    batch: list[tuple[str, int, int, int]] = []
    inserted = 0
    for record in synthetic_records(profile, manifest["seed"], max_per_kind):
        batch.append((str(record["kind"]), int(record["ordinal"]), int(record["logical_offset_ms"]), int(record["token"] & 0x7FFF_FFFF_FFFF_FFFF)))
        if len(batch) == args.batch_size:
            connection.executemany("INSERT OR IGNORE INTO synthetic_records VALUES (?, ?, ?, ?)", batch)
            inserted += connection.execute("SELECT changes()").fetchone()[0]
            connection.commit()
            atomic_json(progress, {"schema": REPORT_SCHEMA, "state": "ingesting", "rows_attempted": inserted})
            batch.clear()
    if batch:
        connection.executemany("INSERT OR IGNORE INTO synthetic_records VALUES (?, ?, ?, ?)", batch)
        connection.commit()
    if args.mode == "full":
        fill_padding(connection, int(target), progress)
    connection.execute("DROP TABLE IF EXISTS synthetic_fts")
    connection.execute("CREATE VIRTUAL TABLE synthetic_fts USING fts5(kind, token UNINDEXED)")
    connection.execute("INSERT INTO synthetic_fts(kind, token) SELECT kind, token FROM synthetic_records")
    connection.commit()
    connection.execute("PRAGMA wal_checkpoint(TRUNCATE)")

    query_latencies: list[int] = []
    total_duration = profile["expected"]["recording_hours"] * 3_600_000
    for sample in range(args.sample_size):
        lower = (sample * total_duration) // args.sample_size
        upper = ((sample + 1) * total_duration) // args.sample_size
        query_started = time.monotonic_ns()
        connection.execute("SELECT count(*), min(token), max(token) FROM synthetic_records WHERE logical_offset_ms >= ? AND logical_offset_ms < ?", (lower, upper)).fetchone()
        connection.execute("SELECT count(*) FROM synthetic_fts WHERE synthetic_fts MATCH 'kind:audio_segments'").fetchone()
        query_latencies.append((time.monotonic_ns() - query_started) // 1_000_000)
    page_size = connection.execute("PRAGMA page_size").fetchone()[0]
    logical_bytes = connection.execute("PRAGMA page_count").fetchone()[0] * page_size
    rows = connection.execute("SELECT count(*) FROM synthetic_records").fetchone()[0]
    connection.close()
    file_bytes = database.stat().st_size
    elapsed_seconds = max((time.monotonic_ns() - started) / 1_000_000_000, 0.000001)
    rss_bytes = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss * (1 if sys.platform == "darwin" else 1024)
    gates = {
        "logical_target_met": args.mode == "full" and logical_bytes >= int(target),
        "file_target_met": args.mode == "full" and file_bytes >= int(target),
        "ingest_rate_met": args.mode == "full" and rows / elapsed_seconds >= args.min_ingest_rows_per_second,
        "query_p95_met": args.mode == "full" and percentile(query_latencies, 0.95) <= args.max_query_p95_ms,
        "rss_met": args.mode == "full" and rss_bytes <= args.max_rss_bytes,
    }
    release_evidence = args.mode == "full" and all(gates.values())
    report = {
        "schema": REPORT_SCHEMA,
        "mode": args.mode,
        "release_evidence": release_evidence,
        "manifest_sha256": hashlib.sha256(raw).hexdigest(),
        "profile": {"id": args.profile, "recording_hours_per_year": profile["recording_hours_per_year"], "horizon_years": manifest["horizon_years"], "expected": profile["expected"], "target_logical_bytes": target},
        "environment": {"vm_id": args.vm_id if args.mode == "full" else None, "image_digest": args.image_digest if args.mode == "full" else None, "sqlite_version": sqlite3.sqlite_version, "sqlite_extensions": ["fts5"], "sqlite_compile_options": sorted(compile_options), "cache_state": args.cache_state if args.mode == "full" else "smoke", "backend": "local-sqlite", "concurrency": args.concurrency, "media_mix": profile["expected"]["records"]},
        "sample": {"query_samples": args.sample_size, "percentiles": {"p50_ms": percentile(query_latencies, 0.50), "p95_ms": percentile(query_latencies, 0.95), "p99_ms": percentile(query_latencies, 0.99)}},
        "measurements": {"rows": rows, "ingest_elapsed_seconds": elapsed_seconds, "ingest_rows_per_second": rows / elapsed_seconds, "logical_bytes": logical_bytes, "file_bytes": file_bytes, "rss_bytes": rss_bytes},
        "gates": gates,
        "limitations": "Offline synthetic SQLite evidence only; no production backend, VFS, witness, fault, or lifecycle evidence.",
    }
    atomic_json(report_path, report)
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
    parser.add_argument("--sample-size", type=int, default=20)
    parser.add_argument("--min-ingest-rows-per-second", type=float)
    parser.add_argument("--max-query-p95-ms", type=int)
    parser.add_argument("--max-rss-bytes", type=int)
    args = parser.parse_args()
    if args.batch_size < 1:
        fail("--batch-size must be positive")
    try:
        print(json.dumps(run(args), sort_keys=True))
        return 0
    except (ManifestError, sqlite3.Error, OSError) as error:
        print(f"Error: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
