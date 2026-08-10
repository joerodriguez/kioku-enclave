#!/usr/bin/env python3
import importlib.util
import json
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "run_archive_capacity_harness.py"


class HarnessTests(unittest.TestCase):
    def run_harness(self, *args: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(["python3", str(SCRIPT), *args], cwd=ROOT, text=True, capture_output=True, check=False)

    def test_smoke_uses_a_real_content_free_sqlite_database_and_never_claims_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "capacity"
            result = self.run_harness("--profile", "power-user-a-480", "--output", str(output), "--record-limit", "2", "--sample-size", "2")
            self.assertEqual(result.returncode, 0, result.stderr)
            report = json.loads(result.stdout)
            self.assertFalse(report["release_evidence"])
            self.assertGreater(report["measurements"]["rows"], 0)
            self.assertTrue((output / "archive-capacity.sqlite").is_file())
            self.assertFalse((output / "capacity-progress.json").exists())

    def test_full_mode_refuses_to_claim_evidence_without_required_provenance_and_gates(self):
        with tempfile.TemporaryDirectory() as directory:
            result = self.run_harness("--mode", "full", "--profile", "power-user-c-1200-32gib", "--output", str(Path(directory) / "capacity"))
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("--vm-id", result.stderr)

    def test_output_inside_checkout_must_be_ignored_target(self):
        result = self.run_harness("--profile", "power-user-a-480", "--output", str(ROOT / "unsafe-capacity-output"))
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("ignored target", result.stderr)


if __name__ == "__main__":
    unittest.main()
