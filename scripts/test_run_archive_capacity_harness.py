#!/usr/bin/env python3
import importlib.util
import json
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from contextlib import closing
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "run_archive_capacity_harness.py"
SPEC = importlib.util.spec_from_file_location("capacity_harness", SCRIPT)
assert SPEC and SPEC.loader
HARNESS = importlib.util.module_from_spec(SPEC)
sys.path.insert(0, str(ROOT / "scripts"))
SPEC.loader.exec_module(HARNESS)


class HarnessTests(unittest.TestCase):
    def run_harness(self, *args: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["python3", str(SCRIPT), *args],
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=False,
        )

    def smoke_args(self, output: Path, *extra: str) -> tuple[str, ...]:
        return (
            "--profile",
            "power-user-a-480",
            "--output",
            str(output),
            "--record-limit",
            "2",
            "--sample-size",
            "20",
            *extra,
        )

    def test_smoke_is_content_free_exact_and_never_claims_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "capacity"
            result = self.run_harness(*self.smoke_args(output))
            self.assertEqual(result.returncode, 0, result.stderr)
            report = json.loads(result.stdout)
            self.assertFalse(report["release_evidence"])
            self.assertFalse(report["sqlite_local_evidence"])
            self.assertEqual(report["classification"], "sqlite_smoke_non_evidence")
            self.assertEqual(report["measurements"]["rows_by_kind"], report["measurements"]["expected_rows_by_kind"])
            self.assertEqual(report["measurements"]["sqlite_integrity"], "ok")
            self.assertEqual(report["measurements"]["fts_integrity"], "ok")
            self.assertEqual(len(report["measurements"]["logical_export_sha256"]), 64)
            self.assertTrue((output / "archive-capacity.sqlite").is_file())
            self.assertTrue((output / "capacity-run.json").is_file())
            self.assertFalse((output / "capacity-progress.json").exists())

    def test_full_mode_is_permanently_refused_even_with_metadata(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "capacity"
            result = self.run_harness(
                "--mode",
                "full",
                "--profile",
                "power-user-c-1200-32gib",
                "--output",
                str(output),
                "--vm-id",
                "public-vm-1",
                "--image-digest",
                "sha256:" + "a" * 64,
                "--cache-state",
                "cold",
                "--min-ingest-rows-per-second",
                "1",
                "--max-query-p95-ms",
                "1",
                "--max-rss-bytes",
                "1",
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("intentionally unavailable", result.stderr)
            self.assertFalse((output / "capacity-report.json").exists())

    def test_resume_rejects_incompatible_immutable_arguments(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "capacity"
            first = self.run_harness(*self.smoke_args(output))
            self.assertEqual(first.returncode, 0, first.stderr)
            resumed = self.run_harness(*self.smoke_args(output, "--record-limit", "3", "--resume"))
            self.assertNotEqual(resumed.returncode, 0)
            self.assertIn("do not match", resumed.stderr)

    def test_resume_rejects_content_tampering_that_preserves_counts_and_integrity(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "capacity"
            first = self.run_harness(*self.smoke_args(output))
            self.assertEqual(first.returncode, 0, first.stderr)

            receipt_path = output / "capacity-run.json"
            receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
            receipt["state"] = "running"
            receipt_path.write_text(
                json.dumps(receipt, sort_keys=True, indent=2) + "\n", encoding="utf-8"
            )
            (output / "capacity-report.json").unlink()
            with closing(sqlite3.connect(output / "archive-capacity.sqlite")) as connection:
                connection.execute(
                    "UPDATE synthetic_records SET token = token + 1 "
                    "WHERE (kind, ordinal) = (SELECT kind, ordinal FROM synthetic_records LIMIT 1)"
                )
                connection.commit()

            resumed = self.run_harness(*self.smoke_args(output, "--resume"))
            self.assertNotEqual(resumed.returncode, 0)
            self.assertIn("record content does not match", resumed.stderr)

    def test_foreign_and_symlink_outputs_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            foreign = root / "foreign"
            foreign.mkdir()
            (foreign / "not-harness-owned.txt").write_text("foreign", encoding="utf-8")
            result = self.run_harness(*self.smoke_args(foreign))
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("must be empty", result.stderr)

            target = root / "target"
            target.mkdir()
            link = root / "link"
            link.symlink_to(target, target_is_directory=True)
            result = self.run_harness(*self.smoke_args(link))
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("must not contain a symlink", result.stderr)

    def test_invalid_gate_values_and_claim_inputs_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            result = self.run_harness(
                *self.smoke_args(Path(directory) / "capacity", "--min-ingest-rows-per-second", "nan")
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("finite", result.stderr)
            result = self.run_harness(*self.smoke_args(Path(directory) / "concurrent", "--concurrency", "2"))
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("single-process", result.stderr)

    def test_percentile_uses_nearest_rank(self):
        self.assertEqual(HARNESS.percentile([1, 100], 0.95), 100)
        self.assertEqual(HARNESS.percentile([1, 2, 3, 4], 0.50), 2)

    def test_output_inside_checkout_must_be_ignored_target(self):
        result = self.run_harness(
            "--profile",
            "power-user-a-480",
            "--output",
            str(ROOT / "unsafe-capacity-output"),
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("ignored target", result.stderr)


if __name__ == "__main__":
    unittest.main()
