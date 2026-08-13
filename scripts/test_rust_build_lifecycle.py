#!/usr/bin/env python3
"""Fast isolated tests for Rust worktree artifact retirement and disk guards."""

from __future__ import annotations

import importlib.util
import os
import fcntl
from pathlib import Path
import shutil
import subprocess
import tempfile
from typing import Optional
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
RETIRE = ROOT / "scripts" / "retire_rust_worktree_artifacts.py"
DISK_GUARD = ROOT / "scripts" / "check_build_disk_space.py"
RETIRE_SPEC = importlib.util.spec_from_file_location("retire_rust_worktree_artifacts", RETIRE)
assert RETIRE_SPEC is not None and RETIRE_SPEC.loader is not None
RETIRE_MODULE = importlib.util.module_from_spec(RETIRE_SPEC)
RETIRE_SPEC.loader.exec_module(RETIRE_MODULE)


class RustBuildLifecycleTests(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory()
        self.root = Path(self.directory.name)
        self.primary = self.root / "primary"
        self.linked = self.root / "linked"
        self.fake_bin = self.root / "bin"
        self.fake_bin.mkdir()
        self.run_git("init", "primary", cwd=self.root)
        self.run_git("config", "user.email", "tests@example.invalid", cwd=self.primary)
        self.run_git("config", "user.name", "Test User", cwd=self.primary)
        self.run_git("remote", "add", "origin", "https://github.com/example/kioku-enclave.git", cwd=self.primary)
        (self.primary / ".gitignore").write_text("/target\n", encoding="utf-8")
        (self.primary / "Cargo.toml").write_text("[package]\nname = 'fixture'\nversion = '0.1.0'\n", encoding="utf-8")
        (self.primary / "source.txt").write_text("source stays here\n", encoding="utf-8")
        self.run_git("add", ".", cwd=self.primary)
        self.run_git("commit", "-m", "fixture", cwd=self.primary)
        self.run_git("worktree", "add", "-b", "feature/retire", str(self.linked), cwd=self.primary)
        self.write_fake_commands(state="MERGED", processes="")

    def tearDown(self) -> None:
        self.directory.cleanup()

    def run_git(self, *arguments: str, cwd: Path) -> subprocess.CompletedProcess[str]:
        return subprocess.run(["git", *arguments], cwd=cwd, text=True, capture_output=True, check=True)

    def write_fake_commands(
        self,
        *,
        state: str,
        processes: str,
        merged_at: str = "2026-08-12T12:00:00Z",
        head_oid: Optional[str] = None,
    ) -> None:
        if head_oid is None:
            head_oid = self.run_git("rev-parse", "HEAD", cwd=self.linked).stdout.strip()
        (self.fake_bin / "gh").write_text(
            "#!/bin/sh\n"
            "[ \"$1 $2\" = 'pr view' ] || exit 81\n"
            "shift 2\n"
            "branch=$1\n"
            "shift\n"
            "[ \"$1\" = '--repo' ] || exit 82\n"
            "[ \"$2\" = 'example/kioku-enclave' ] || exit 83\n"
            "[ -n \"$branch\" ] || exit 84\n"
            "printf '%s\\n' '"
            + '{"state":"'
            + state
            + '","mergedAt":"'
            + merged_at
            + '","headRefOid":"'
            + head_oid
            + '"}'
            + "'\n",
            encoding="utf-8",
        )
        (self.fake_bin / "ps").write_text("#!/bin/sh\nprintf '%s\\n' '" + processes + "'\n", encoding="utf-8")
        for command in (self.fake_bin / "gh", self.fake_bin / "ps"):
            command.chmod(0o755)

    def run_retire(self, *arguments: str) -> subprocess.CompletedProcess[str]:
        environment = {**os.environ, "PATH": f"{self.fake_bin}:{os.environ.get('PATH', '')}"}
        return subprocess.run(
            ["python3", str(RETIRE), "--repository", str(self.primary), "--worktree", str(self.linked), *arguments],
            cwd=self.primary,
            text=True,
            capture_output=True,
            env=environment,
            check=False,
        )

    def make_target(self) -> Path:
        target = self.linked / "target"
        (target / "debug").mkdir(parents=True)
        (target / "debug" / "artifact").write_text("generated\n", encoding="utf-8")
        return target

    def add_prunable_worktree_registration(self) -> None:
        stale = self.root / "stale"
        self.run_git("worktree", "add", "-b", "feature/stale", str(stale), cwd=self.primary)
        shutil.rmtree(stale)

    def lock_path(self) -> Path:
        output = self.run_git(
            "rev-parse",
            "--path-format=absolute",
            "--git-path",
            "kioku-rust-build.lock",
            cwd=self.linked,
        ).stdout.strip()
        return Path(output)

    def test_dry_run_preserves_only_exact_target(self) -> None:
        target = self.make_target()
        completed = self.run_retire()
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertTrue(target.is_dir())
        self.assertTrue((self.linked / "source.txt").is_file())
        self.assertIn("dry run: would remove only", completed.stdout)

    def test_ssh_origin_is_normalized_to_exact_repository(self) -> None:
        self.run_git("remote", "set-url", "origin", "git@github.com:example/kioku-enclave.git", cwd=self.primary)
        self.make_target()
        completed = self.run_retire()
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn("dry run", completed.stdout)

    def test_unrelated_prunable_worktree_does_not_block_retirement(self) -> None:
        self.make_target()
        self.add_prunable_worktree_registration()
        completed = self.run_retire()
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn("dry run", completed.stdout)

    def test_apply_removes_target_but_never_sources(self) -> None:
        target = self.make_target()
        completed = self.run_retire("--apply")
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertFalse(target.exists())
        self.assertEqual((self.linked / "source.txt").read_text(encoding="utf-8"), "source stays here\n")

    def test_per_worktree_build_lock_refuses_contention(self) -> None:
        target = self.make_target()
        lock = self.lock_path()
        lock.touch(mode=0o600)
        descriptor = os.open(lock, os.O_RDWR)
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        try:
            completed = self.run_retire("--apply")
        finally:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
            os.close(descriptor)
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("build-artifact lock is already held", completed.stderr)
        self.assertTrue(target.exists())

    def test_per_worktree_build_lock_symlink_is_refused_without_touching_destination(self) -> None:
        target = self.make_target()
        outside = self.root / "outside-lock"
        outside.write_text("must survive\n", encoding="utf-8")
        lock = self.lock_path()
        lock.symlink_to(outside)
        completed = self.run_retire("--apply")
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("cannot open build-artifact lock", completed.stderr)
        self.assertEqual(outside.read_text(encoding="utf-8"), "must survive\n")
        self.assertTrue(target.exists())

    def test_cargo_profile_lock_refuses_direct_build_contention(self) -> None:
        target = self.make_target()
        profile = target / "debug"
        cargo_lock = profile / ".cargo-build-lock"
        cargo_lock.touch()
        descriptor = os.open(cargo_lock, os.O_RDONLY)
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        try:
            completed = self.run_retire("--apply")
        finally:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
            os.close(descriptor)
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("Cargo profile lock is held", completed.stderr)
        self.assertTrue(target.exists())

    def test_nested_target_profile_lock_refuses_direct_build_contention(self) -> None:
        target = self.make_target()
        profile = target / "x86_64-unknown-linux-musl" / "debug"
        profile.mkdir(parents=True)
        cargo_lock = profile / ".cargo-build-lock"
        cargo_lock.touch()
        descriptor = os.open(cargo_lock, os.O_RDONLY)
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        try:
            completed = self.run_retire("--apply")
        finally:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
            os.close(descriptor)
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("Cargo profile lock is held", completed.stderr)
        self.assertTrue(target.exists())

    def test_primary_worktree_is_refused(self) -> None:
        target = self.make_target()
        environment = {**os.environ, "PATH": f"{self.fake_bin}:{os.environ.get('PATH', '')}"}
        completed = subprocess.run(
            ["python3", str(RETIRE), "--repository", str(self.primary), "--worktree", str(self.primary), "--apply"],
            cwd=self.primary,
            text=True,
            capture_output=True,
            env=environment,
            check=False,
        )
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("primary worktree", completed.stderr)
        self.assertTrue(target.exists())

    def test_dirty_tracked_or_untracked_worktree_is_refused(self) -> None:
        target = self.make_target()
        (self.linked / "untracked.txt").write_text("do not retire\n", encoding="utf-8")
        completed = self.run_retire("--apply")
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("tracked or untracked changes", completed.stderr)
        self.assertTrue(target.exists())

    def test_closed_pr_is_not_eligible(self) -> None:
        target = self.make_target()
        self.write_fake_commands(state="CLOSED", processes="")
        completed = self.run_retire("--apply")
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("not merged", completed.stderr)
        self.assertTrue(target.exists())

    def test_merged_pr_for_a_different_commit_is_not_eligible(self) -> None:
        target = self.make_target()
        self.write_fake_commands(state="MERGED", processes="", head_oid="a" * 40)
        completed = self.run_retire("--apply")
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("not merged", completed.stderr)
        self.assertTrue(target.exists())

    def test_active_rust_compiler_is_refused(self) -> None:
        target = self.make_target()
        self.write_fake_commands(state="MERGED", processes="321 /usr/local/bin/cargo test")
        completed = self.run_retire("--apply")
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("appears active", completed.stderr)
        self.assertTrue(target.exists())

    def test_target_symlink_is_refused_without_touching_destination(self) -> None:
        outside = self.root / "outside"
        outside.mkdir()
        (outside / "must-survive").write_text("important\n", encoding="utf-8")
        (self.linked / "target").symlink_to(outside, target_is_directory=True)
        completed = self.run_retire("--apply")
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("symlink", completed.stderr)
        self.assertTrue((outside / "must-survive").exists())

    def test_mount_point_target_is_refused_without_removal(self) -> None:
        target = self.make_target()
        with mock.patch.object(RETIRE_MODULE.os.path, "ismount", side_effect=lambda path: Path(path) == target):
            with self.assertRaisesRegex(SystemExit, "mount point"):
                RETIRE_MODULE.target_directory(self.linked)
        self.assertTrue((target / "debug" / "artifact").exists())

    def test_nested_mount_or_foreign_device_is_refused_without_removal(self) -> None:
        target = self.make_target()
        nested = target / "debug"
        root_identity = target.lstat()
        original_stat = RETIRE_MODULE.os.DirEntry.stat

        def foreign_device(entry: os.DirEntry[str], *, follow_symlinks: bool = True) -> os.stat_result:
            value = original_stat(entry, follow_symlinks=follow_symlinks)
            if entry.name == "debug":
                return os.stat_result((value.st_mode, value.st_ino, value.st_dev + 1, *value[3:]))
            return value

        with mock.patch.object(RETIRE_MODULE.os.DirEntry, "stat", foreign_device):
            with self.assertRaisesRegex(SystemExit, "foreign-device descendant"):
                RETIRE_MODULE.validate_tree_boundary(target, root_identity)
        self.assertTrue((nested / "artifact").exists())

    def test_identity_swap_is_quarantined_not_deleted(self) -> None:
        target = self.make_target()
        expected = target.lstat()
        outside = self.root / "outside"
        outside.mkdir()
        (outside / "must-survive").write_text("important\n", encoding="utf-8")
        original_rename = RETIRE_MODULE.os.rename
        swapped = False

        def swap_then_rename(source: Path, destination: Path) -> None:
            nonlocal swapped
            if not swapped and Path(source) == target:
                swapped = True
                original_rename(target, self.linked / "target-original")
                target.symlink_to(outside, target_is_directory=True)
            original_rename(source, destination)

        with mock.patch.object(RETIRE_MODULE.os, "rename", side_effect=swap_then_rename):
            with self.assertRaisesRegex(SystemExit, "identity changed; preserved at") as raised:
                RETIRE_MODULE.remove_target(target, expected)

        quarantine = Path(str(raised.exception).rsplit(" at ", 1)[1])
        self.assertTrue((outside / "must-survive").exists())
        self.assertTrue((self.linked / "target-original" / "debug" / "artifact").exists())
        self.assertTrue((quarantine / "target").is_symlink())

    def test_disk_guard_has_a_configurable_threshold(self) -> None:
        pass_completed = subprocess.run(
            ["python3", str(DISK_GUARD), "--path", str(self.root), "--min-free-gib", "0"],
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(pass_completed.returncode, 0, pass_completed.stderr)
        fail_completed = subprocess.run(
            ["python3", str(DISK_GUARD), "--path", str(self.root), "--min-free-gib", "1000000"],
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertNotEqual(fail_completed.returncode, 0)
        self.assertIn("insufficient disk space", fail_completed.stderr)
        invalid_completed = subprocess.run(
            ["python3", str(DISK_GUARD), "--path", str(self.root), "--min-free-gib", "nan"],
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertNotEqual(invalid_completed.returncode, 0)
        self.assertIn("finite non-negative", invalid_completed.stderr)


if __name__ == "__main__":
    unittest.main()
