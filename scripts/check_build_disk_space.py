#!/usr/bin/env python3
"""Fail early when a filesystem lacks room for a heavyweight local build."""

from __future__ import annotations

import argparse
import math
from pathlib import Path
import shutil


DEFAULT_MINIMUM_FREE_GIB = 15
GIB = 1024**3


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument(
        "--path",
        type=Path,
        default=Path.cwd(),
        help="path on the filesystem to check (default: current directory)",
    )
    result.add_argument(
        "--min-free-gib",
        type=float,
        default=DEFAULT_MINIMUM_FREE_GIB,
        help=f"minimum required free space in GiB (default: {DEFAULT_MINIMUM_FREE_GIB})",
    )
    return result


def main() -> None:
    arguments = parser().parse_args()
    if not math.isfinite(arguments.min_free_gib) or arguments.min_free_gib < 0:
        raise SystemExit("--min-free-gib must be a finite non-negative number")

    try:
        path = arguments.path.resolve(strict=True)
    except OSError as error:
        raise SystemExit(f"cannot resolve --path: {error}") from error
    if not path.is_dir():
        raise SystemExit("--path must name a directory")

    try:
        free_bytes = shutil.disk_usage(path).free
    except OSError as error:
        raise SystemExit(f"cannot inspect free space for {path}: {error}") from error

    required_bytes = arguments.min_free_gib * GIB
    free_gib = free_bytes / GIB
    if free_bytes < required_bytes:
        raise SystemExit(
            f"insufficient disk space at {path}: {free_gib:.1f} GiB free; "
            f"need at least {arguments.min_free_gib:.1f} GiB"
        )
    print(f"disk space OK at {path}: {free_gib:.1f} GiB free")


if __name__ == "__main__":
    main()
