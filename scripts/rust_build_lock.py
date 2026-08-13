#!/usr/bin/env python3
"""Serialize Rust builds and target retirement within one Git worktree."""

from __future__ import annotations

import argparse
from contextlib import contextmanager
import errno
import fcntl
import os
from pathlib import Path
import stat
import subprocess
from typing import Iterator, NoReturn, Sequence


LOCK_NAME = "kioku-rust-build.lock"


class BuildLockError(RuntimeError):
    """The per-worktree build-artifact lock could not be acquired safely."""


def _fail(message: str) -> NoReturn:
    raise BuildLockError(message)


def _resolved_worktree(worktree: Path) -> Path:
    if not worktree.is_absolute():
        _fail("worktree path must be absolute")
    try:
        resolved = worktree.resolve(strict=True)
    except OSError as error:
        _fail(f"cannot resolve worktree: {error}")
    if not resolved.is_dir():
        _fail("worktree path must name a directory")
    return resolved


def build_lock_path(worktree: Path) -> Path:
    """Return the dedicated lock file inside this worktree's Git metadata."""

    resolved = _resolved_worktree(worktree)
    try:
        completed = subprocess.run(
            [
                "git",
                "rev-parse",
                "--path-format=absolute",
                "--git-dir",
            ],
            cwd=resolved,
            text=True,
            capture_output=True,
            check=False,
        )
    except OSError as error:
        _fail(f"cannot resolve Git lock path: {error}")
    if completed.returncode != 0:
        detail = completed.stderr.strip() or completed.stdout.strip() or "git rev-parse failed"
        _fail(f"cannot resolve Git lock path: {detail}")
    lines = completed.stdout.splitlines()
    if len(lines) != 1:
        _fail("Git returned a malformed lock path")
    reported = Path(lines[0])
    if not reported.is_absolute():
        _fail("Git returned an unsafe lock path")
    try:
        # Resolve the parent hierarchy, but require the final Git-directory
        # component itself to be a real directory rather than a symlink.
        git_parent = reported.parent.resolve(strict=True)
        reported_identity = reported.lstat()
    except OSError as error:
        _fail(f"cannot resolve Git lock directory: {error}")
    if stat.S_ISLNK(reported_identity.st_mode) or not stat.S_ISDIR(reported_identity.st_mode):
        _fail("Git lock parent is not a real directory")
    git_directory = git_parent / reported.name
    if not git_directory.is_dir():
        _fail("Git lock parent is not a directory")
    # Derive the final component ourselves: `git --git-path` may resolve an
    # existing final symlink, which would prevent O_NOFOLLOW below from seeing it.
    return git_directory / LOCK_NAME


def _same_file(opened: os.stat_result, named: os.stat_result) -> bool:
    return opened.st_dev == named.st_dev and opened.st_ino == named.st_ino


@contextmanager
def worktree_build_lock(worktree: Path) -> Iterator[Path]:
    """Hold this worktree's nonblocking exclusive build-artifact lock."""

    lock_path = build_lock_path(worktree)
    nofollow = getattr(os, "O_NOFOLLOW", None)
    if nofollow is None:
        _fail("this platform cannot safely open a no-follow lock file")
    flags = os.O_RDWR | os.O_CREAT | nofollow | getattr(os, "O_CLOEXEC", 0)
    try:
        descriptor = os.open(lock_path, flags, 0o600)
    except OSError as error:
        _fail(f"cannot open build-artifact lock at {lock_path}: {error}")

    acquired = False
    try:
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode):
            _fail(f"build-artifact lock is not a regular file: {lock_path}")
        try:
            named = os.stat(lock_path, follow_symlinks=False)
        except OSError as error:
            _fail(f"cannot verify build-artifact lock identity: {error}")
        if not stat.S_ISREG(named.st_mode) or not _same_file(opened, named):
            _fail(f"build-artifact lock identity changed: {lock_path}")

        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as error:
            if error.errno in (errno.EACCES, errno.EAGAIN):
                _fail(
                    "build-artifact lock is already held; another verification "
                    f"or artifact retirement is active for {worktree}"
                )
            _fail(f"cannot acquire build-artifact lock at {lock_path}: {error}")
        acquired = True

        # Detect a path replacement between the first identity check and flock.
        try:
            named_after_lock = os.stat(lock_path, follow_symlinks=False)
        except OSError as error:
            _fail(f"cannot reverify build-artifact lock identity: {error}")
        if not stat.S_ISREG(named_after_lock.st_mode) or not _same_file(opened, named_after_lock):
            _fail(f"build-artifact lock identity changed while acquiring it: {lock_path}")
        try:
            os.fchmod(descriptor, 0o600)
        except OSError as error:
            _fail(f"cannot restrict build-artifact lock permissions: {error}")
        yield lock_path
    finally:
        if acquired:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
        os.close(descriptor)


def run_locked(worktree: Path, command: Sequence[str]) -> int:
    """Run one command while holding the worktree build-artifact lock."""

    resolved = _resolved_worktree(worktree)
    if not command:
        raise BuildLockError("a command is required after --")
    with worktree_build_lock(resolved):
        try:
            completed = subprocess.run(list(command), cwd=resolved, check=False)
        except OSError as error:
            raise BuildLockError(f"cannot execute locked command: {error}") from error
    return completed.returncode


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--worktree", type=Path, required=True, help="absolute worktree path")
    parser.add_argument("command", nargs=argparse.REMAINDER, help="command to run after --")
    arguments = parser.parse_args()
    command = arguments.command
    if command[:1] == ["--"]:
        command = command[1:]
    try:
        return run_locked(arguments.worktree, command)
    except BuildLockError as error:
        parser.exit(2, f"Error: {error}\n")


if __name__ == "__main__":
    raise SystemExit(main())
