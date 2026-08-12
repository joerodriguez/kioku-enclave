#!/usr/bin/env python3
"""Safely retire Rust build artifacts from one merged linked worktree.

The default is a dry run.  ``--apply`` removes only the exact ``target`` directory
directly beneath the explicitly supplied linked worktree; it never removes sources
or a worktree itself. Builds launched through ``agent-verify.sh`` share its
per-worktree lock. A manually launched Cargo process must not race retirement;
process and Cargo-profile lock checks provide an additional fail-closed defense.
"""

from __future__ import annotations

import argparse
from contextlib import contextmanager
import fcntl
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import tempfile
from typing import Iterator, NoReturn, Optional

from rust_build_lock import BuildLockError, worktree_build_lock


RUST_PROCESS = re.compile(r"(?:^|[\\/\s])(cargo|rustc|clippy|clippy-driver)(?:\s|$)")
CARGO_LOCK_NAMES = (".cargo-build-lock", ".cargo-lock")


def refuse(message: str) -> NoReturn:
    raise SystemExit(f"refusing to retire artifacts: {message}")


def run(command: list[str], *, cwd: Path, purpose: str) -> str:
    try:
        completed = subprocess.run(
            command,
            cwd=cwd,
            text=True,
            capture_output=True,
            check=False,
        )
    except OSError as error:
        refuse(f"cannot {purpose}: {error}")
    if completed.returncode != 0:
        detail = completed.stderr.strip() or completed.stdout.strip() or "command failed"
        refuse(f"cannot {purpose}: {detail}")
    return completed.stdout


def repository_root(path: Path) -> Path:
    output = run(["git", "rev-parse", "--show-toplevel"], cwd=path, purpose="identify repository")
    try:
        return Path(output.strip()).resolve(strict=True)
    except OSError as error:
        refuse(f"cannot resolve repository root: {error}")


def registered_worktrees(repository: Path) -> list[Path]:
    output = run(
        ["git", "worktree", "list", "--porcelain"],
        cwd=repository,
        purpose="list registered worktrees",
    )
    paths: list[Path] = []
    for record in output.split("\n\n"):
        for line in record.splitlines():
            if line.startswith("worktree "):
                paths.append(Path(line.removeprefix("worktree ")))
                break
    if not paths:
        refuse("repository reported no worktrees")
    return paths


def validate_linked_worktree(repository: Path, requested: Path) -> Path:
    if not requested.is_absolute():
        refuse("--worktree must be an absolute exact path")
    try:
        candidate = requested.resolve(strict=True)
    except OSError as error:
        refuse(f"cannot resolve --worktree: {error}")
    if not candidate.is_dir():
        refuse("--worktree must name a directory")

    worktrees = registered_worktrees(repository)
    matching_index: Optional[int] = None
    for index, registered in enumerate(worktrees):
        # Other agents can leave stale, prunable worktree registrations behind.
        # They must not make a separate, live worktree unsafe to inspect.
        try:
            registered_path = registered.resolve(strict=True)
        except OSError:
            continue
        if candidate == registered_path:
            matching_index = index
            break
    if matching_index is None:
        refuse("--worktree is not a registered linked worktree of this repository")
    if matching_index == 0:
        refuse("the primary worktree is never eligible")
    return candidate


def validate_clean(worktree: Path) -> None:
    status = run(
        ["git", "status", "--porcelain=v1", "--untracked-files=all"],
        cwd=worktree,
        purpose="inspect worktree status",
    )
    if status:
        refuse("worktree has tracked or untracked changes")


def github_repository(worktree: Path) -> str:
    remote = run(
        ["git", "remote", "get-url", "origin"],
        cwd=worktree,
        purpose="identify GitHub repository",
    ).strip()
    match = re.fullmatch(
        r"(?:git@github\.com:|ssh://git@github\.com/|https://github\.com/)"
        r"([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+?)(?:\.git)?",
        remote,
    )
    if match is None:
        refuse("origin is not a recognized GitHub repository URL")
    repository = match.group(1)
    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository):
        refuse("origin does not contain a valid GitHub owner/repository pair")
    return repository


def branch_name(worktree: Path) -> str:
    branch = run(
        ["git", "symbolic-ref", "--quiet", "--short", "HEAD"],
        cwd=worktree,
        purpose="identify worktree branch",
    ).strip()
    if not branch:
        refuse("worktree is detached")
    return branch


def head_commit(worktree: Path) -> str:
    commit = run(["git", "rev-parse", "HEAD"], cwd=worktree, purpose="identify worktree commit").strip()
    if not re.fullmatch(r"[0-9a-f]{40}", commit):
        refuse("worktree HEAD is not a full commit identifier")
    return commit


def validate_merged_pr(worktree: Path) -> None:
    result = run(
        [
            "gh",
            "pr",
            "view",
            branch_name(worktree),
            "--repo",
            github_repository(worktree),
            "--json",
            "state,mergedAt,headRefOid",
        ],
        cwd=worktree,
        purpose="inspect associated GitHub pull request",
    )
    try:
        pr = json.loads(result)
    except json.JSONDecodeError as error:
        refuse(f"GitHub CLI returned invalid pull request data: {error}")
    if (
        not isinstance(pr, dict)
        or pr.get("state") != "MERGED"
        or not isinstance(pr.get("mergedAt"), str)
        or not pr["mergedAt"]
        or pr.get("headRefOid") != head_commit(worktree)
    ):
        refuse("associated GitHub pull request is not merged")


def validate_no_active_rust_process() -> None:
    output = run(["ps", "-axo", "pid=,command="], cwd=Path.cwd(), purpose="inspect active Rust build processes")
    active = [line.strip() for line in output.splitlines() if RUST_PROCESS.search(line)]
    if active:
        refuse("cargo, rustc, or clippy appears active")


def target_directory(worktree: Path) -> tuple[Path, Optional[os.stat_result]]:
    target = worktree / "target"
    try:
        identity = target.lstat()
    except FileNotFoundError:
        return target, None
    except OSError as error:
        refuse(f"cannot inspect exact target directory: {error}")
    if stat.S_ISLNK(identity.st_mode):
        refuse("target directory is a symlink")
    if not stat.S_ISDIR(identity.st_mode):
        refuse("target path exists but is not a directory")
    if os.path.ismount(target):
        refuse("target directory is a mount point")
    return target, identity


def same_identity(expected: os.stat_result, actual: os.stat_result) -> bool:
    return expected.st_dev == actual.st_dev and expected.st_ino == actual.st_ino and stat.S_ISDIR(actual.st_mode)


def validate_tree_boundary(root: Path, root_identity: os.stat_result) -> None:
    """Refuse nested mounts and symlinked directories before recursive removal."""
    try:
        with os.scandir(root) as entries:
            for entry in entries:
                try:
                    identity = entry.stat(follow_symlinks=False)
                except FileNotFoundError:
                    continue
                except OSError as error:
                    refuse(f"cannot inspect target descendant: {error}")
                if not stat.S_ISDIR(identity.st_mode):
                    continue
                child = root / entry.name
                if stat.S_ISLNK(identity.st_mode):
                    continue
                if identity.st_dev != root_identity.st_dev or os.path.ismount(child):
                    refuse("target directory contains a mount point or foreign-device descendant")
                validate_tree_boundary(child, root_identity)
    except OSError as error:
        refuse(f"cannot inspect exact target directory tree: {error}")


@contextmanager
def exclusive_cargo_locks(target: Path, expected: os.stat_result) -> Iterator[None]:
    """Supplement process checks with Cargo 1.96's documented profile locks.

    Cargo creates ``.cargo-build-lock`` and ``.cargo-lock`` in each existing
    profile directory.  Holding exclusive non-blocking locks prevents a Cargo
    process that uses those files from compiling across the destructive rename.
    No lock files are created here: absent files remain the global-process and
    shared per-worktree-lock boundary.
    """
    descriptors: list[int] = []
    no_follow = getattr(os, "O_NOFOLLOW", None)
    if no_follow is None:
        refuse("this platform cannot safely open Cargo profile locks without following symlinks")
    try:
        if not same_identity(expected, target.lstat()):
            refuse("exact target directory changed while acquiring Cargo profile locks")
        for root, directories, _ in os.walk(target, followlinks=False):
            profile = Path(root)
            profile_identity = profile.lstat()
            if not stat.S_ISDIR(profile_identity.st_mode) or stat.S_ISLNK(profile_identity.st_mode):
                directories.clear()
                continue
            if profile_identity.st_dev != expected.st_dev or os.path.ismount(profile):
                refuse("target directory contains a mount point or foreign-device descendant")
            for name in CARGO_LOCK_NAMES:
                lock = profile / name
                try:
                    lock_identity = lock.lstat()
                except FileNotFoundError:
                    continue
                except OSError as error:
                    refuse(f"cannot inspect Cargo profile lock: {error}")
                if not stat.S_ISREG(lock_identity.st_mode) or stat.S_ISLNK(lock_identity.st_mode):
                    refuse("Cargo profile lock is not a regular file")
                try:
                    descriptor = os.open(lock, os.O_RDONLY | no_follow)
                except OSError as error:
                    refuse(f"cannot open Cargo profile lock: {error}")
                opened_identity = os.fstat(descriptor)
                if opened_identity.st_dev != lock_identity.st_dev or opened_identity.st_ino != lock_identity.st_ino:
                    os.close(descriptor)
                    refuse("Cargo profile lock changed while opening it")
                try:
                    fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                except BlockingIOError:
                    os.close(descriptor)
                    refuse("Cargo profile lock is held")
                except OSError as error:
                    os.close(descriptor)
                    refuse(f"cannot acquire Cargo profile lock: {error}")
                descriptors.append(descriptor)
        yield
    finally:
        for descriptor in reversed(descriptors):
            try:
                fcntl.flock(descriptor, fcntl.LOCK_UN)
                os.close(descriptor)
            except OSError:
                pass


def remove_target(target: Path, expected: os.stat_result) -> None:
    """Quarantine the exact directory atomically, verify it, then delete it.

    A target-name swap after preflight cannot redirect deletion: the rename moves
    exactly what was at ``target`` into a fresh private sibling directory, and an
    inode/device mismatch is retained for manual recovery rather than removed.
    """
    if not shutil.rmtree.avoids_symlink_attacks:
        refuse("this Python runtime cannot safely remove a directory")

    with exclusive_cargo_locks(target, expected):
        try:
            current = target.lstat()
        except OSError as error:
            refuse(f"cannot re-inspect exact target directory before removal: {error}")
        if not same_identity(expected, current) or os.path.ismount(target):
            refuse("exact target directory changed before removal")
        validate_tree_boundary(target, expected)
        # Narrow the remaining window for out-of-protocol direct Cargo launches;
        # repository wrappers are excluded by the shared worktree lock above.
        validate_no_active_rust_process()
        try:
            current = target.lstat()
        except OSError as error:
            refuse(f"cannot re-inspect exact target directory before quarantine: {error}")
        if not same_identity(expected, current) or os.path.ismount(target):
            refuse("exact target directory changed before quarantine")
        try:
            quarantine = Path(tempfile.mkdtemp(prefix=".kioku-rust-retire-", dir=target.parent))
        except OSError as error:
            refuse(f"cannot create private retirement quarantine: {error}")
        quarantined_target = quarantine / "target"
        try:
            os.rename(target, quarantined_target)
        except OSError as error:
            try:
                quarantine.rmdir()
            except OSError:
                pass
            refuse(f"cannot atomically quarantine exact target directory: {error}")

        try:
            quarantined_identity = quarantined_target.lstat()
        except OSError as error:
            refuse(f"quarantined target cannot be inspected; preserved at {quarantine}: {error}")
        if not same_identity(expected, quarantined_identity) or os.path.ismount(quarantined_target):
            refuse(f"quarantined target identity changed; preserved at {quarantine}")
        try:
            validate_tree_boundary(quarantined_target, expected)
        except SystemExit as error:
            refuse(f"quarantined target is unsafe; preserved at {quarantine}: {error}")
        try:
            shutil.rmtree(quarantined_target)
            quarantine.rmdir()
        except OSError as error:
            refuse(f"cannot remove quarantined exact target directory at {quarantine}: {error}")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--worktree", type=Path, required=True, help="exact linked worktree to inspect")
    parser.add_argument(
        "--repository",
        type=Path,
        default=Path.cwd(),
        help="any worktree of the repository that owns --worktree (default: current directory)",
    )
    parser.add_argument("--apply", action="store_true", help="actually remove the eligible target directory")
    arguments = parser.parse_args()

    repository = repository_root(arguments.repository)
    worktree = validate_linked_worktree(repository, arguments.worktree)
    try:
        with worktree_build_lock(worktree):
            validate_clean(worktree)
            validate_merged_pr(worktree)
            validate_no_active_rust_process()
            target, identity = target_directory(worktree)

            if identity is None:
                print(f"no Rust artifacts found at {target}")
                return
            if not arguments.apply:
                print(f"dry run: would remove only {target}; rerun with --apply to remove it")
                return
            validate_no_active_rust_process()
            remove_target(target, identity)
            print(f"removed Rust artifacts at {target}")
    except BuildLockError as error:
        refuse(str(error))


if __name__ == "__main__":
    main()
