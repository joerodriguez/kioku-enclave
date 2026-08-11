#!/usr/bin/env python3
"""Run the opt-in, local ADR-0022 production-shaped capacity gate.

This is deliberately separate from the fast smoke harness.  It uses only streamed,
deterministic numeric fixture rows and sparse extent probes; it neither downloads nor
encrypts a database snapshot, and it cannot grant archive-v3 authority or release
evidence.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import sqlite3
import stat
import sys
import time
from pathlib import Path
from typing import Any, Iterator

from generate_capacity_fixture import (
    RECORD_KINDS,
    ManifestError,
    load_manifest,
    synthetic_records,
    validate_temporal_payload_shape,
    validate_manifest,
)


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
PAGE_SIZE = 4096
DATABASE_CEILING_BYTES = 32 * 1024**3
DATABASE_CEILING_PAGES = DATABASE_CEILING_BYTES // PAGE_SIZE
WAL_HEADER_BYTES = 32
WAL_FRAME_HEADER_BYTES = 24
CHECKPOINT_CHUNK_BYTES = 1024 * 1024
MANIFEST_FANOUT = 256
SAFETY_HEADROOM_BYTES = 1024**3
REPORT_NAME = "production-shaped-capacity-report.json"
DATABASE_NAME = "production-shaped-capacity.sqlite"
NUMERIC_RECORDS_SCHEMA = (
    "CREATE TABLE numeric_records ("
    "kind INTEGER NOT NULL, ordinal INTEGER NOT NULL, logical_offset_ms INTEGER NOT NULL, "
    "token INTEGER NOT NULL, month_index INTEGER NOT NULL, cadence_slot INTEGER NOT NULL, "
    "retention_months INTEGER NOT NULL, payload_bytes INTEGER NOT NULL, "
    "embedding_logical_bytes INTEGER NOT NULL, payload_blob BLOB NOT NULL, "
    "embedding_blob BLOB NOT NULL, PRIMARY KEY(kind, ordinal)) WITHOUT ROWID"
)
NUMERIC_RECORDS_INSERT = "INSERT INTO numeric_records VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"


class GateError(ValueError):
    """The local gate's explicit safety or capacity contract was not met."""


def fail(message: str) -> None:
    raise GateError(message)


def peak_free_space_requirement(profile: dict[str, Any]) -> dict[str, int]:
    """Conservative local working-set budget; sparse probes do not reduce this guard."""
    database_bytes = max(
        int(profile["expected"]["core_archive_bytes_high"]),
        int(profile.get("sparse_archive_bytes", 0)),
    )
    database_pages = (database_bytes + PAGE_SIZE - 1) // PAGE_SIZE
    wal_bytes = WAL_HEADER_BYTES + database_pages * (PAGE_SIZE + WAL_FRAME_HEADER_BYTES)
    return {
        "database_bytes": database_bytes,
        "wal_bytes": wal_bytes,
        "checkpoint_chunk_bytes": CHECKPOINT_CHUNK_BYTES,
        "safety_headroom_bytes": SAFETY_HEADROOM_BYTES,
        "required_free_bytes": database_bytes
        + wal_bytes
        + CHECKPOINT_CHUNK_BYTES
        + SAFETY_HEADROOM_BYTES,
    }


def capacity_plan(manifest: dict[str, Any]) -> dict[str, Any]:
    """Return the no-I/O plan used for review and for the immutable report contract."""
    profiles = validate_manifest(manifest)
    profile_summary = []
    for profile_id, profile in profiles.items():
        monthly_hours = profile.get("recording_hours_per_month")
        profile_summary.append(
            {
                "id": profile_id,
                "recording_hours_per_month": monthly_hours,
                "recording_hours": profile["expected"]["recording_hours"],
                "core_archive_bytes_high": profile["expected"]["core_archive_bytes_high"],
                "within_32_gib_ceiling": profile["expected"]["core_archive_bytes_high"]
                <= DATABASE_CEILING_BYTES,
                "sparse_extent": profile.get("sparse_archive_bytes"),
                "peak_free_space_requirement": peak_free_space_requirement(profile),
            }
        )
    return {
        "schema": "kioku-archive-capacity-plan-v1",
        "fixture_schema": manifest["schema"],
        "horizon_months": manifest.get("horizon_months"),
        "database_ceiling": {
            "bytes": DATABASE_CEILING_BYTES,
            "page_size": PAGE_SIZE,
            "max_page_count": DATABASE_CEILING_PAGES,
            "last_permitted_page_offset": DATABASE_CEILING_BYTES - PAGE_SIZE,
        },
        "wal_worst_case": {
            "header_bytes": WAL_HEADER_BYTES,
            "frame_bytes": PAGE_SIZE + WAL_FRAME_HEADER_BYTES,
            "frames_for_one_database_extent": DATABASE_CEILING_PAGES,
            "logical_bytes_for_one_database_extent": WAL_HEADER_BYTES
            + DATABASE_CEILING_PAGES * (PAGE_SIZE + WAL_FRAME_HEADER_BYTES),
        },
        "checkpoint_extent": {
            "chunk_bytes": CHECKPOINT_CHUNK_BYTES,
            "chunks_at_32_gib": DATABASE_CEILING_BYTES // CHECKPOINT_CHUNK_BYTES,
            "manifest_fanout": MANIFEST_FANOUT,
            "first_level_nodes": DATABASE_CEILING_BYTES // CHECKPOINT_CHUNK_BYTES // MANIFEST_FANOUT,
        },
        "profiles": profile_summary,
        "limitations": (
            "The sparse probes verify logical extents and filesystem allocation behavior only. "
            "They are not SQLite databases and do not materialize, upload, download, or encrypt 32 GiB."
        ),
    }


def storage_probe(path: Path) -> dict[str, int]:
    info = os.statvfs(path)
    return {
        "available_bytes": int(info.f_bavail * info.f_frsize),
        "block_size": int(info.f_frsize),
    }


def existing_parent(path: Path) -> Path:
    candidate = path
    while not candidate.exists():
        if candidate == candidate.parent:
            fail("could not find an existing directory for the disk preflight")
        candidate = candidate.parent
    if not candidate.is_dir():
        fail("disk preflight parent is not a directory")
    return candidate


def _lexical_absolute(path: Path) -> Path:
    return Path(os.path.abspath(os.path.expanduser(os.fspath(path))))


def reject_symlink_components(path: Path) -> None:
    """Reject every existing path component rather than resolving through a symlink."""
    absolute = _lexical_absolute(path)
    current = Path(absolute.anchor)
    for part in absolute.parts[1:]:
        current /= part
        try:
            mode = os.lstat(current).st_mode
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(mode):
            fail("output path must not contain a symlink component")
        if current != absolute and not stat.S_ISDIR(mode):
            fail("output path has a non-directory parent component")


def safe_output(path: Path) -> Path:
    resolved = _lexical_absolute(path)
    reject_symlink_components(resolved)
    try:
        relative = resolved.relative_to(REPOSITORY_ROOT)
    except ValueError:
        return resolved
    if not relative.parts or relative.parts[0] != "target":
        fail("output inside the checkout must be under ignored target/")
    return resolved


def prepare_output(path: Path) -> Path:
    output = safe_output(path)
    if output.exists():
        if output.is_symlink() or not output.is_dir():
            fail("output must be an empty non-symlink directory")
        if any(output.iterdir()):
            fail("production-shaped output must be empty")
    else:
        output.mkdir(parents=True, mode=0o700)
        reject_symlink_components(output)
    return output


def atomic_report_write(output: Path, report: dict[str, Any]) -> None:
    """Write the report through an output-dir fd; never follow a report symlink."""
    reject_symlink_components(output)
    directory_flags = os.O_RDONLY
    if hasattr(os, "O_DIRECTORY"):
        directory_flags |= os.O_DIRECTORY
    if hasattr(os, "O_NOFOLLOW"):
        directory_flags |= os.O_NOFOLLOW
    directory_fd = os.open(output, directory_flags)
    temporary_name = f".{REPORT_NAME}.{os.getpid()}.tmp"
    try:
        try:
            os.lstat(REPORT_NAME, dir_fd=directory_fd)
        except FileNotFoundError:
            pass
        else:
            fail("report path already exists")
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        report_fd = os.open(temporary_name, flags, 0o600, dir_fd=directory_fd)
        try:
            encoded = (json.dumps(report, indent=2, sort_keys=True) + "\n").encode("utf-8")
            offset = 0
            while offset < len(encoded):
                written = os.write(report_fd, encoded[offset:])
                if written <= 0:
                    fail("could not write the complete capacity report")
                offset += written
            os.fsync(report_fd)
        finally:
            os.close(report_fd)
        os.replace(temporary_name, REPORT_NAME, src_dir_fd=directory_fd, dst_dir_fd=directory_fd)
        os.fsync(directory_fd)
    finally:
        try:
            os.unlink(temporary_name, dir_fd=directory_fd)
        except FileNotFoundError:
            pass
        finally:
            os.close(directory_fd)


def allocated_bytes(path: Path) -> int | None:
    blocks = getattr(path.stat(), "st_blocks", None)
    return None if blocks is None else int(blocks) * 512


def require_sparse_extent_support(output: Path) -> None:
    """Refuse the near-32-GiB probe when allocation cannot be shown to stay sparse."""
    path = output / ".sparse-capability-probe"
    try:
        with path.open("xb") as handle:
            handle.truncate(CHECKPOINT_CHUNK_BYTES)
        allocated = allocated_bytes(path)
        if allocated is None or allocated >= CHECKPOINT_CHUNK_BYTES:
            fail("filesystem does not provide observable sparse extent support")
    finally:
        path.unlink(missing_ok=True)


def create_sparse_extent(path: Path, logical_bytes: int) -> tuple[int, int | None]:
    with path.open("xb") as handle:
        handle.truncate(logical_bytes)
    return path.stat().st_size, allocated_bytes(path)


def sparse_extent_probes(output: Path) -> list[dict[str, int | bool | None | str]]:
    """Create three logical-only extent sentinels, never a SQLite database."""
    require_sparse_extent_support(output)
    probes = []
    created: list[Path] = []
    try:
        for label, logical_bytes in (
            ("minus_one_page", DATABASE_CEILING_BYTES - PAGE_SIZE),
            ("at_ceiling", DATABASE_CEILING_BYTES),
            ("plus_one_page", DATABASE_CEILING_BYTES + PAGE_SIZE),
        ):
            path = output / f"sqlite-extent-{label}.sparse"
            created.append(path)
            apparent, allocated = create_sparse_extent(path, logical_bytes)
            if apparent != logical_bytes:
                fail(f"sparse extent {label} has unexpected logical size")
            if allocated is None or allocated >= apparent:
                fail(f"sparse extent {label} did not remain observably sparse")
            probes.append(
                {
                    "label": label,
                    "path_kind": "synthetic_sparse_extent_no_content",
                    "logical_bytes": apparent,
                    "allocated_bytes": allocated,
                    "sparse_when_observable": True,
                }
            )
    except BaseException:
        for path in created:
            path.unlink(missing_ok=True)
        raise
    return probes


def numeric_rows(
    profile: dict[str, Any],
    seed: int,
    temporal_payload_shape: dict[str, Any],
    max_records_per_kind: int | None = None,
) -> Iterator[tuple[int, int, int, int, int, int, int, int, int, bytes, bytes]]:
    kind_index = {name: index for index, name in enumerate(RECORD_KINDS)}
    payload_blobs = {
        kind: bytes(temporal_payload_shape["payload_bytes_by_kind"][kind]) for kind in RECORD_KINDS
    }
    empty_embedding = b""
    vector_embedding = bytes(temporal_payload_shape["embedding"]["logical_bytes"])
    for record in synthetic_records(
        profile,
        seed,
        max_records_per_kind=max_records_per_kind,
        temporal_payload_shape=temporal_payload_shape,
    ):
        kind = str(record["kind"])
        embedding_blob = vector_embedding if kind == "vectors" else empty_embedding
        yield (
            kind_index[kind],
            int(record["ordinal"]),
            int(record["logical_offset_ms"]),
            int(record["token"]) & 0x7FFF_FFFF_FFFF_FFFF,
            int(record["month_index"]),
            int(record["cadence_slot"]),
            int(record["retention_months"]),
            int(record["payload_bytes"]),
            int(record.get("embedding_logical_bytes", 0)),
            payload_blobs[kind],
            embedding_blob,
        )


def digest_rows(connection: sqlite3.Connection) -> str:
    digest = hashlib.sha256()
    for row in connection.execute(
        "SELECT kind, ordinal, logical_offset_ms, token, month_index, cadence_slot, retention_months, "
        "payload_bytes, embedding_logical_bytes, payload_blob, embedding_blob "
        "FROM numeric_records ORDER BY kind, ordinal"
    ):
        metadata = row[:-2]
        payload_blob = bytes(row[-2])
        embedding_blob = bytes(row[-1])
        digest.update(":".join(str(value) for value in metadata).encode("ascii"))
        digest.update(f":{len(payload_blob)}:".encode("ascii"))
        digest.update(payload_blob)
        digest.update(f":{len(embedding_blob)}:".encode("ascii"))
        digest.update(embedding_blob)
        digest.update(b"\n")
    return digest.hexdigest()


def file_measurements(output: Path) -> dict[str, dict[str, int | None]]:
    result: dict[str, dict[str, int | None]] = {}
    for name in (DATABASE_NAME, f"{DATABASE_NAME}-wal", f"{DATABASE_NAME}-shm"):
        path = output / name
        if path.exists():
            if path.is_symlink() or not stat.S_ISREG(path.stat().st_mode):
                fail(f"SQLite sidecar {name} is not a regular file")
            result[name] = {
                "apparent_bytes": path.stat().st_size,
                "allocated_bytes": allocated_bytes(path),
            }
    return result


def checkpoint_counts(row: tuple[Any, ...], *, require_progress: bool) -> dict[str, int]:
    if len(row) != 3 or any(isinstance(value, bool) or not isinstance(value, int) for value in row):
        fail("SQLite checkpoint returned an invalid count tuple")
    busy, log_frames, checkpointed_frames = row
    if busy != 0 or log_frames < 0 or checkpointed_frames < 0 or checkpointed_frames > log_frames:
        fail("SQLite checkpoint returned invalid or busy frame counts")
    if require_progress and (log_frames == 0 or checkpointed_frames == 0):
        fail("SQLite checkpoint did not report meaningful WAL progress")
    return {
        "busy": busy,
        "log_frames": log_frames,
        "checkpointed_frames": checkpointed_frames,
    }


def run_sqlite_gate(
    output: Path,
    profile: dict[str, Any],
    seed: int,
    batch_size: int,
    temporal_payload_shape: dict[str, Any],
) -> dict[str, Any]:
    database = output / DATABASE_NAME
    started = time.monotonic_ns()
    connection = sqlite3.connect(database)
    try:
        connection.execute(f"PRAGMA page_size={PAGE_SIZE}")
        connection.execute("VACUUM")
        maximum_pages = connection.execute(
            f"PRAGMA max_page_count={DATABASE_CEILING_PAGES}"
        ).fetchone()[0]
        if maximum_pages != DATABASE_CEILING_PAGES:
            fail("SQLite did not accept the 32-GiB max_page_count ceiling")
        journal_mode = str(connection.execute("PRAGMA journal_mode=WAL").fetchone()[0]).lower()
        if journal_mode != "wal":
            fail("SQLite did not enter WAL journal mode")
        connection.execute("PRAGMA synchronous=FULL")
        connection.execute("PRAGMA wal_autocheckpoint=0")
        connection.execute(NUMERIC_RECORDS_SCHEMA)
        connection.execute("CREATE INDEX numeric_records_by_offset ON numeric_records(logical_offset_ms)")
        connection.execute("CREATE VIRTUAL TABLE numeric_fts USING fts5(kind UNINDEXED, token)")
        batch: list[tuple[int, int, int, int, int, int, int, int, int, bytes, bytes]] = []
        rows = 0
        for row in numeric_rows(profile, seed, temporal_payload_shape):
            batch.append(row)
            if len(batch) >= batch_size:
                connection.executemany(NUMERIC_RECORDS_INSERT, batch)
                connection.executemany(
                    "INSERT INTO numeric_fts(kind, token) VALUES (?, ?)",
                    ((item[0], str(item[3])) for item in batch),
                )
                connection.commit()
                rows += len(batch)
                batch.clear()
        if batch:
            connection.executemany(NUMERIC_RECORDS_INSERT, batch)
            connection.executemany(
                "INSERT INTO numeric_fts(kind, token) VALUES (?, ?)",
                ((item[0], str(item[3])) for item in batch),
            )
            connection.commit()
            rows += len(batch)
        expected_rows = sum(profile["expected"]["records"].values())
        if rows != expected_rows:
            fail("streamed SQLite row count does not match the fixture distribution")
        actual_rows = connection.execute("SELECT count(*) FROM numeric_records").fetchone()[0]
        if actual_rows != expected_rows:
            fail("SQLite row count does not match the fixture distribution")
        expected_by_kind = {
            index: profile["expected"]["records"][kind]
            for index, kind in enumerate(RECORD_KINDS)
        }
        actual_by_kind = dict(connection.execute("SELECT kind, count(*) FROM numeric_records GROUP BY kind"))
        if actual_by_kind != expected_by_kind:
            fail("SQLite per-kind distribution does not match the fixture contract")
        actual_by_month = dict(
            connection.execute("SELECT month_index, count(*) FROM numeric_records GROUP BY month_index")
        )
        if set(actual_by_month) != set(range(12)) or any(count < 1 for count in actual_by_month.values()):
            fail("SQLite records do not cover every month of the 12-month fixture")
        if connection.execute(
            "SELECT count(*) FROM numeric_records WHERE retention_months != ?",
            (temporal_payload_shape["retention_months"],),
        ).fetchone()[0]:
            fail("SQLite retention geometry does not match the fixture")
        for index, kind in enumerate(RECORD_KINDS):
            if connection.execute(
                "SELECT count(*) FROM numeric_records WHERE kind = ? AND "
                "(payload_bytes != ? OR typeof(payload_blob) != 'blob' OR "
                "length(payload_blob) != payload_bytes OR payload_blob != zeroblob(payload_bytes))",
                (index, temporal_payload_shape["payload_bytes_by_kind"][kind]),
            ).fetchone()[0]:
                fail("SQLite payload geometry does not match the fixture")
        vector_index = RECORD_KINDS.index("vectors")
        embedding_bytes = temporal_payload_shape["embedding"]["logical_bytes"]
        if connection.execute(
            "SELECT count(*) FROM numeric_records WHERE "
            "(kind = ? AND (embedding_logical_bytes != ? OR typeof(embedding_blob) != 'blob' OR "
            "length(embedding_blob) != embedding_logical_bytes OR "
            "embedding_blob != zeroblob(embedding_logical_bytes))) OR "
            "(kind != ? AND (embedding_logical_bytes != 0 OR typeof(embedding_blob) != 'blob' OR "
            "length(embedding_blob) != 0))",
            (vector_index, embedding_bytes, vector_index),
        ).fetchone()[0]:
            fail("SQLite embedding shape does not match the fixture")
        integrity = connection.execute("PRAGMA integrity_check").fetchone()[0]
        if integrity != "ok":
            fail("SQLite integrity_check failed")
        connection.execute("INSERT INTO numeric_fts(numeric_fts) VALUES ('integrity-check')").fetchall()
        page_count = connection.execute("PRAGMA page_count").fetchone()[0]
        page_size = connection.execute("PRAGMA page_size").fetchone()[0]
        if page_size != PAGE_SIZE or page_count * page_size > DATABASE_CEILING_BYTES:
            fail("SQLite database exceeded its 32-GiB ceiling")
        before_checkpoint = file_measurements(output)
        wal_before = before_checkpoint.get(f"{DATABASE_NAME}-wal")
        if wal_before is None or int(wal_before["apparent_bytes"] or 0) < WAL_HEADER_BYTES + PAGE_SIZE + WAL_FRAME_HEADER_BYTES:
            fail("SQLite did not produce meaningful regular WAL evidence before checkpoint")
        checkpoint_passive = checkpoint_counts(
            tuple(connection.execute("PRAGMA wal_checkpoint(PASSIVE)").fetchone()),
            require_progress=True,
        )
        checkpoint_truncate = checkpoint_counts(
            tuple(connection.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone()),
            require_progress=False,
        )
        after_checkpoint = file_measurements(output)
        wal_after = after_checkpoint.get(f"{DATABASE_NAME}-wal")
        if wal_after is not None and int(wal_after["apparent_bytes"] or 0) > WAL_HEADER_BYTES:
            fail("SQLite truncating checkpoint retained WAL frames")
        return {
            "rows": actual_rows,
            "rows_by_kind": {kind: actual_by_kind[index] for index, kind in enumerate(RECORD_KINDS)},
            "expected_rows_by_kind": {
                kind: profile["expected"]["records"][kind] for kind in RECORD_KINDS
            },
            "rows_by_month": {str(month): actual_by_month[month] for month in range(12)},
            "logical_rows_sha256": digest_rows(connection),
            "sqlite_integrity": integrity,
            "database_page_size": page_size,
            "database_page_count": page_count,
            "database_logical_bytes": page_count * page_size,
            "max_page_count": maximum_pages,
            "journal_mode": journal_mode,
            "wal_before_checkpoint": before_checkpoint,
            "checkpoint_passive": checkpoint_passive,
            "checkpoint_truncate": checkpoint_truncate,
            "wal_after_checkpoint": after_checkpoint,
            "elapsed_seconds": (time.monotonic_ns() - started) / 1_000_000_000,
        }
    finally:
        connection.close()


def execute(args: argparse.Namespace) -> dict[str, Any]:
    manifest, raw = load_manifest(args.manifest)
    profiles = validate_manifest(manifest)
    if manifest["schema"] != "kioku-archive-capacity-fixture-v2":
        fail("production-shaped gate requires the versioned 12-month v2 manifest")
    if args.profile not in profiles:
        fail("unknown capacity profile")
    if args.batch_size < 1 or args.batch_size > 65536:
        fail("--batch-size must be in 1..65536")
    if not args.confirm_production_shaped:
        fail("run requires --confirm-production-shaped")
    profile = profiles[args.profile]
    if profile.get("sparse_archive_bytes") and not args.allow_sparse_extent:
        fail("the 32-GiB profile requires --allow-sparse-extent")
    output = safe_output(args.output)
    disk = storage_probe(existing_parent(output.parent))
    free_space_requirement = peak_free_space_requirement(profile)
    if disk["available_bytes"] < free_space_requirement["required_free_bytes"]:
        fail("insufficient free space for the selected profile's conservative peak requirement")
    output = prepare_output(output)
    extents = sparse_extent_probes(output) if profile.get("sparse_archive_bytes") else []
    temporal_payload_shape = validate_temporal_payload_shape(manifest)
    if temporal_payload_shape is None:
        fail("production-shaped gate requires v2 temporal/payload geometry")
    sqlite = run_sqlite_gate(
        output,
        profile,
        manifest["seed"],
        args.batch_size,
        temporal_payload_shape,
    )
    report = {
        "schema": "kioku-archive-production-shaped-capacity-report-v2",
        "classification": "local_production_shaped_non_authority_gate",
        "release_evidence": False,
        "archive_v3_authority": False,
        "manifest_sha256": hashlib.sha256(raw).hexdigest(),
        "profile": {"id": args.profile, "expected": profile["expected"]},
        "plan": capacity_plan(manifest),
        "disk_preflight": {**disk, "requirement": free_space_requirement},
        "sqlite": sqlite,
        "sparse_extent_probes": extents,
        "environment": {
            "platform": {"system": platform.system(), "release": platform.release()},
            "sqlite_version": sqlite3.sqlite_version,
            "batch_size": args.batch_size,
        },
        "limitations": (
            "Local numeric fixture gate only. It does not use the production image, VFS, "
            "backend, witness, encryption, download/upload, fault, lifecycle, cache, or concurrency paths."
        ),
    }
    atomic_report_write(output, report)
    return report


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("--manifest", type=Path, default=REPOSITORY_ROOT / "eval/capacity/archive-fixtures-v2.json")
    commands = result.add_subparsers(dest="command", required=True)
    commands.add_parser("plan", help="print the no-I/O 12-month/32-GiB plan")
    run = commands.add_parser("run", help="run the explicit long-running local gate")
    run.add_argument("--profile", required=True)
    run.add_argument("--output", type=Path, required=True)
    run.add_argument("--batch-size", type=int, default=4096)
    run.add_argument("--confirm-production-shaped", action="store_true")
    run.add_argument("--allow-sparse-extent", action="store_true")
    return result


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        if args.command == "plan":
            manifest, raw = load_manifest(args.manifest)
            plan = capacity_plan(manifest)
            plan["manifest_sha256"] = hashlib.sha256(raw).hexdigest()
            print(json.dumps(plan, indent=2, sort_keys=True))
        else:
            print(json.dumps(execute(args), sort_keys=True))
        return 0
    except (GateError, ManifestError, OSError, sqlite3.Error) as error:
        print(f"capacity gate failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
