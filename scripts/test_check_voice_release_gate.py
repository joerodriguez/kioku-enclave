#!/usr/bin/env python3
"""Contract tests for the signed voice-quality release classification."""

from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
GATE = ROOT / "scripts" / "check_voice_release_gate.py"


class VoiceReleaseGateTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary_directory.cleanup)
        self.root = Path(self.temporary_directory.name)
        self.voice_directory = self.root / "eval" / "voice"
        self.voice_directory.mkdir(parents=True)
        self.cargo_log = self.root / "cargo.log"
        self.fake_cargo = self.root / "cargo"
        self.fake_cargo.write_text(
            "#!/bin/sh\n"
            f"printf '%s\\n' \"$*\" > {self.cargo_log}\n",
            encoding="utf-8",
        )
        self.fake_cargo.chmod(0o700)

    def run_gate(self, *extra_arguments: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [
                "python3",
                str(GATE),
                "--root",
                str(self.root),
                "--cargo",
                str(self.fake_cargo),
                *extra_arguments,
            ],
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=False,
        )

    def write_owner_only_marker(self, **overrides: object) -> None:
        marker: dict[str, object] = {
            "schema_version": 1,
            "environment": "owner_only_production",
            "external_users": 0,
            "voice_quality_claims_allowed": False,
        }
        marker.update(overrides)
        (self.voice_directory / "owner-only-production.json").write_text(
            json.dumps(marker), encoding="utf-8"
        )

    def write_real_corpus_trio(self, count: int = 3) -> None:
        for name in (
            "release-manifest.json",
            "release-cases.json",
            "release-report.json",
        )[:count]:
            (self.voice_directory / name).write_text("{}", encoding="utf-8")

    def test_exact_owner_only_marker_allows_unvalidated_production_release(self) -> None:
        self.write_owner_only_marker()

        completed = self.run_gate()

        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(completed.stdout, "owner_only_unvalidated\n")
        self.assertFalse(self.cargo_log.exists())

    def test_complete_real_corpus_trio_runs_existing_rust_gate(self) -> None:
        self.write_real_corpus_trio()

        completed = self.run_gate()

        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(completed.stdout, "validated_real_corpus\n")
        invocation = self.cargo_log.read_text(encoding="utf-8")
        self.assertIn("--check-voice-eval", invocation)
        self.assertIn("release-manifest.json", invocation)
        self.assertIn("release-cases.json", invocation)
        self.assertIn("release-report.json", invocation)

    def test_no_evidence_fails_closed(self) -> None:
        completed = self.run_gate()

        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("owner-only marker or complete real-corpus trio", completed.stderr)

    def test_partial_real_corpus_trio_fails_closed(self) -> None:
        self.write_real_corpus_trio(count=2)

        completed = self.run_gate()

        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("partial real-corpus evidence", completed.stderr)

    def test_marker_and_real_corpus_trio_are_rejected_as_ambiguous(self) -> None:
        self.write_owner_only_marker()
        self.write_real_corpus_trio()

        completed = self.run_gate()

        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("must not coexist", completed.stderr)

    def test_marker_schema_is_exact(self) -> None:
        invalid_markers = (
            {"external_users": 1},
            {"voice_quality_claims_allowed": True},
            {"environment": "evaluation"},
            {"schema_version": 2},
            {"unexpected": "value"},
        )
        for overrides in invalid_markers:
            with self.subTest(overrides=overrides):
                self.write_owner_only_marker(**overrides)
                completed = self.run_gate()
                self.assertNotEqual(completed.returncode, 0)
                self.assertIn("invalid owner-only production marker", completed.stderr)

    def test_metadata_only_classifies_without_running_cargo(self) -> None:
        self.write_real_corpus_trio()

        completed = self.run_gate("--metadata-only")

        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(completed.stdout, "validated_real_corpus\n")
        self.assertFalse(self.cargo_log.exists())


if __name__ == "__main__":
    unittest.main()
