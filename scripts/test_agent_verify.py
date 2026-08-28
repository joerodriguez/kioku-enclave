#!/usr/bin/env python3
"""Fast isolated contracts for local verification and its shared build lock."""

from __future__ import annotations

import fcntl
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "agent-verify.sh"
LOCK_HELPER = ROOT / "scripts" / "rust_build_lock.py"


class AgentVerifyTests(unittest.TestCase):
    def run_script(
        self,
        *args: str,
        disk_guard_exit: int = 0,
        include_sccache: bool = False,
        hold_lock: bool = False,
        extra_env: dict[str, str] | None = None,
    ) -> tuple[subprocess.CompletedProcess[str], list[list[str]], list[str], list[list[str]]]:
        with tempfile.TemporaryDirectory() as directory:
            temporary = Path(directory)
            worktree = temporary / "worktree"
            scripts = worktree / "scripts"
            scripts.mkdir(parents=True)
            subprocess.run(["git", "init", str(worktree)], capture_output=True, check=True)
            shutil.copy2(SCRIPT, scripts / SCRIPT.name)
            shutil.copy2(LOCK_HELPER, scripts / LOCK_HELPER.name)
            bin_dir = temporary / "bin"
            bin_dir.mkdir()
            cargo_log = temporary / "cargo.log"
            environment_log = temporary / "environment.log"
            disk_guard_log = temporary / "disk-guard.log"

            (bin_dir / "cargo").write_text(
                "#!/bin/sh\n"
                "printf '%s\\t' \"$@\" >> \"$MOCK_CARGO_LOG\"\n"
                "printf '\\n' >> \"$MOCK_CARGO_LOG\"\n"
                "printf '%s|%s|%s|%s\\n' \"${RUSTC_WRAPPER:-}\" \"${SCCACHE_CACHE_SIZE:-}\" \"${SCCACHE_BASEDIRS:-}\" \"${KIOKU_REQUIRE_POSTGRES_CONTRACT:-}\" >> \"$MOCK_ENVIRONMENT_LOG\"\n",
                encoding="utf-8",
            )
            # Dispatch the disk guard to a mock, but execute every other Python
            # invocation (including the real lock helper) with the real runtime.
            (bin_dir / "python3").write_text(
                "#!/bin/sh\n"
                "if [ \"${1##*/}\" = check_build_disk_space.py ]; then\n"
                "  printf '%s\\t' \"$@\" >> \"$MOCK_DISK_GUARD_LOG\"\n"
                "  printf '\\n' >> \"$MOCK_DISK_GUARD_LOG\"\n"
                "  if [ \"$MOCK_DISK_GUARD_EXIT\" -ne 0 ]; then\n"
                "    printf '%s\\n' 'insufficient disk space' >&2\n"
                "    exit \"$MOCK_DISK_GUARD_EXIT\"\n"
                "  fi\n"
                "  exit 0\n"
                "fi\n"
                "exec \"$REAL_PYTHON\" \"$@\"\n",
                encoding="utf-8",
            )
            if include_sccache:
                (bin_dir / "sccache").write_text(
                    "#!/bin/sh\n"
                    "if [ \"${1:-}\" = --show-stats ]; then\n"
                    "  exec \"$REAL_PYTHON\" -c 'import json, os; "
                    "raw = os.environ.get(\"MOCK_SCCACHE_BASEDIRS\", os.environ.get(\"SCCACHE_BASEDIRS\", \"\")); "
                    "print(json.dumps({\"max_cache_size\": int(os.environ.get(\"MOCK_SCCACHE_MAX_BYTES\", \"10737418240\")), "
                    "\"basedirs\": raw.split(os.pathsep) if raw else []}))'\n"
                    "fi\n",
                    encoding="utf-8",
                )
            for executable in bin_dir.iterdir():
                executable.chmod(0o755)

            environment = os.environ.copy()
            # Keep fixtures hermetic when this suite itself runs inside the CI
            # job, which configures sccache for the surrounding Rust checks.
            for inherited in ("RUSTC_WRAPPER", "SCCACHE_CACHE_SIZE", "SCCACHE_BASEDIRS"):
                environment.pop(inherited, None)
            environment.update(
                {
                    "PATH": f"{bin_dir}:/bin:/usr/bin",
                    "REAL_PYTHON": sys.executable,
                    "MOCK_CARGO_LOG": str(cargo_log),
                    "MOCK_ENVIRONMENT_LOG": str(environment_log),
                    "MOCK_DISK_GUARD_LOG": str(disk_guard_log),
                    "MOCK_DISK_GUARD_EXIT": str(disk_guard_exit),
                    "AGENT_VERIFY_MIN_FREE_GIB": "15",
                }
            )
            if extra_env:
                environment.update(extra_env)

            lock_descriptor: int | None = None
            if hold_lock:
                lock_path = self.lock_path(worktree)
                lock_descriptor = os.open(lock_path, os.O_RDWR | os.O_CREAT, 0o600)
                fcntl.flock(lock_descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            try:
                completed = subprocess.run(
                    [str(scripts / SCRIPT.name), *args],
                    cwd=worktree,
                    env=environment,
                    text=True,
                    capture_output=True,
                    check=False,
                )
            finally:
                if lock_descriptor is not None:
                    fcntl.flock(lock_descriptor, fcntl.LOCK_UN)
                    os.close(lock_descriptor)

            commands = (
                [line.rstrip("\t").split("\t") for line in cargo_log.read_text().splitlines()]
                if cargo_log.exists()
                else []
            )
            environments = environment_log.read_text().splitlines() if environment_log.exists() else []
            disk_guard_calls = (
                [line.rstrip("\t").split("\t") for line in disk_guard_log.read_text().splitlines()]
                if disk_guard_log.exists()
                else []
            )
            # Normalize fixture-specific absolute paths before the temporary
            # repository is removed.
            normalized_disk_calls = [
                [argument.replace(str(worktree), "<worktree>") for argument in call]
                for call in disk_guard_calls
            ]
            normalized_environments = [
                entry.replace(str(worktree.resolve()), "<worktree>")
                for entry in environments
            ]
            return completed, commands, normalized_environments, normalized_disk_calls

    def lock_path(self, worktree: Path) -> Path:
        git_dir = subprocess.run(
            ["git", "rev-parse", "--path-format=absolute", "--git-dir"],
            cwd=worktree,
            text=True,
            capture_output=True,
            check=True,
        ).stdout.strip()
        return Path(git_dir) / "kioku-rust-build.lock"

    def test_quick_is_the_default_locked_format_and_check(self) -> None:
        completed, commands, _, disk_guard_calls = self.run_script()
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(commands, [["fmt", "--all", "--", "--check"], ["check", "--locked"]])
        self.assertEqual(
            disk_guard_calls,
            [["<worktree>/scripts/check_build_disk_space.py", "--path", "<worktree>", "--min-free-gib", "15"]],
        )

    def test_focused_requires_and_forwards_a_test_selection_safely(self) -> None:
        rejected, commands, _, disk_guard_calls = self.run_script("focused")
        self.assertEqual(rejected.returncode, 2)
        self.assertIn("focused requires --", rejected.stderr)
        self.assertEqual(commands, [])
        self.assertEqual(disk_guard_calls, [])

        unfiltered, commands, _, disk_guard_calls = self.run_script("focused", "--", "--")
        self.assertEqual(unfiltered.returncode, 2)
        self.assertIn("non-option test filter", unfiltered.stderr)
        self.assertEqual(commands, [])
        self.assertEqual(disk_guard_calls, [])

        completed, commands, _, _ = self.run_script("focused", "--", "api::tests::works")
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(
            commands,
            [["fmt", "--all", "--", "--check"], ["test", "--locked", "api::tests::works"]],
        )

    def test_full_is_locked_and_has_no_separate_build_or_check(self) -> None:
        missing, commands, _, disk_guard_calls = self.run_script("full")
        self.assertEqual(missing.returncode, 2)
        self.assertIn("requires KIOKU_TEST_POSTGRES_URL", missing.stderr)
        self.assertEqual(commands, [])
        self.assertEqual(disk_guard_calls, [])

        completed, commands, environments, _ = self.run_script(
            "full",
            extra_env={
                "KIOKU_TEST_POSTGRES_URL": "postgresql://kioku-test@127.0.0.1:5432/kioku_test"
            },
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(
            commands,
            [
                ["fmt", "--all", "--", "--check"],
                ["test", "--locked"],
                ["clippy", "--locked", "--all-targets", "--", "-D", "warnings"],
            ],
        )
        self.assertNotIn("build", [command[0] for command in commands])
        self.assertNotIn("check", [command[0] for command in commands])
        self.assertEqual(len(environments), 3)
        self.assertTrue(all(entry.endswith("|1") for entry in environments))

    def test_full_rejects_ambiguous_postgres_contract_coordinates(self) -> None:
        for value in ("sqlite:///tmp/test.db", "localhost/kioku", "postgres://ok\nno"):
            completed, commands, _, disk_guard_calls = self.run_script(
                "full", extra_env={"KIOKU_TEST_POSTGRES_URL": value}
            )
            self.assertEqual(completed.returncode, 2)
            self.assertEqual(commands, [])
            self.assertEqual(disk_guard_calls, [])

    def test_shared_disk_guard_fails_before_cargo(self) -> None:
        completed, commands, _, disk_guard_calls = self.run_script(disk_guard_exit=1)
        self.assertEqual(completed.returncode, 1)
        self.assertIn("insufficient disk space", completed.stderr)
        self.assertEqual(commands, [])
        self.assertEqual(len(disk_guard_calls), 1)

    def test_all_cargo_is_refused_while_worktree_lock_is_held(self) -> None:
        completed, commands, _, _ = self.run_script(hold_lock=True)
        self.assertEqual(completed.returncode, 2)
        self.assertIn("build-artifact lock is already held", completed.stderr)
        self.assertEqual(commands, [])

    def test_sccache_is_optional_bounded_and_never_overrides_a_wrapper(self) -> None:
        without_cache, _, environments, _ = self.run_script()
        self.assertEqual(without_cache.returncode, 0, without_cache.stderr)
        self.assertEqual(environments, ["|||", "|||"])

        with_cache, _, environments, _ = self.run_script(include_sccache=True)
        self.assertEqual(with_cache.returncode, 0, with_cache.stderr)
        self.assertEqual(len(environments), 2)
        for entry in environments:
            wrapper, cache_size, basedirs, contract = entry.split("|", 3)
            self.assertTrue(wrapper.endswith("/sccache"))
            self.assertEqual(cache_size, "10G")
            self.assertIn("<worktree>", basedirs.split(os.pathsep))
            self.assertEqual(contract, "")

        caller_wrapper, _, environments, _ = self.run_script(
            include_sccache=True,
            extra_env={"RUSTC_WRAPPER": "/opt/custom-wrapper"},
        )
        self.assertEqual(caller_wrapper.returncode, 0, caller_wrapper.stderr)
        self.assertEqual(
            environments,
            ["/opt/custom-wrapper|||", "/opt/custom-wrapper|||"],
        )

        oversized_server, _, environments, _ = self.run_script(
            include_sccache=True,
            extra_env={"MOCK_SCCACHE_MAX_BYTES": str(20 * 1024**3)},
        )
        self.assertEqual(oversized_server.returncode, 0, oversized_server.stderr)
        self.assertIn("continuing without it", oversized_server.stderr)
        self.assertEqual(environments, ["|||", "|||"])

        incompatible_server, _, environments, _ = self.run_script(
            include_sccache=True,
            extra_env={"MOCK_SCCACHE_BASEDIRS": "/some/other/worktree"},
        )
        self.assertEqual(incompatible_server.returncode, 0, incompatible_server.stderr)
        self.assertIn("does not cover these worktrees", incompatible_server.stderr)
        self.assertEqual(environments, ["|||", "|||"])

    def test_rejects_unknown_modes_and_unbounded_sccache_configuration(self) -> None:
        unknown, commands, _, disk_guard_calls = self.run_script("unsafe")
        self.assertEqual(unknown.returncode, 2)
        self.assertIn("unknown mode", unknown.stderr)
        self.assertEqual(commands, [])
        self.assertEqual(disk_guard_calls, [])

        oversized, commands, _, _ = self.run_script(
            include_sccache=True,
            extra_env={"AGENT_VERIFY_SCCACHE_CACHE_SIZE": "20G"},
        )
        self.assertEqual(oversized.returncode, 2)
        self.assertIn("between 1G and 10G", oversized.stderr)
        self.assertEqual(commands, [])


class RustBuildLockTests(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory()
        self.worktree = Path(self.directory.name) / "worktree"
        subprocess.run(["git", "init", str(self.worktree)], capture_output=True, check=True)

    def tearDown(self) -> None:
        self.directory.cleanup()

    def lock_path(self) -> Path:
        return Path(
            subprocess.run(
                ["git", "rev-parse", "--path-format=absolute", "--git-dir"],
                cwd=self.worktree,
                text=True,
                capture_output=True,
                check=True,
            ).stdout.strip()
        ) / "kioku-rust-build.lock"

    def run_helper(self, *command: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, str(LOCK_HELPER), "--worktree", str(self.worktree), "--", *command],
            text=True,
            capture_output=True,
            check=False,
        )

    def test_concurrent_lock_is_refused_without_running_child(self) -> None:
        marker = Path(self.directory.name) / "must-not-exist"
        lock = self.lock_path()
        descriptor = os.open(lock, os.O_RDWR | os.O_CREAT, 0o600)
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        try:
            completed = self.run_helper(sys.executable, "-c", "from pathlib import Path; Path(__import__('sys').argv[1]).touch()", str(marker))
        finally:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
            os.close(descriptor)
        self.assertEqual(completed.returncode, 2)
        self.assertIn("already held", completed.stderr)
        self.assertFalse(marker.exists())

    def test_persistent_file_is_reusable_after_previous_holder_exits(self) -> None:
        first = self.run_helper(sys.executable, "-c", "pass")
        self.assertEqual(first.returncode, 0, first.stderr)
        self.assertTrue(self.lock_path().is_file())
        second = self.run_helper(sys.executable, "-c", "pass")
        self.assertEqual(second.returncode, 0, second.stderr)

    def test_symlink_lock_is_refused_without_touching_destination(self) -> None:
        outside = Path(self.directory.name) / "outside"
        outside.write_text("must survive\n", encoding="utf-8")
        self.lock_path().symlink_to(outside)
        completed = self.run_helper(sys.executable, "-c", "pass")
        self.assertEqual(completed.returncode, 2)
        self.assertIn("cannot open build-artifact lock", completed.stderr)
        self.assertEqual(outside.read_text(encoding="utf-8"), "must survive\n")


if __name__ == "__main__":
    unittest.main()
