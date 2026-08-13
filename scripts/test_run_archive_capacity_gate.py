#!/usr/bin/env python3

import importlib.util
import json
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from contextlib import closing
from unittest import mock
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
TEMPORARY_ROOT = Path(tempfile.gettempdir()).resolve()
SCRIPT = ROOT / "scripts" / "run_archive_capacity_gate.py"
SPEC = importlib.util.spec_from_file_location("production_capacity_gate", SCRIPT)
assert SPEC and SPEC.loader
GATE = importlib.util.module_from_spec(SPEC)
sys.path.insert(0, str(ROOT / "scripts"))
SPEC.loader.exec_module(GATE)


class ProductionShapedCapacityGateTests(unittest.TestCase):
    def invoke(self, *arguments: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["python3", str(SCRIPT), *arguments],
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=False,
        )

    def test_plan_is_no_io_and_pins_12_month_capacity_geometry(self):
        result = self.invoke("plan")
        self.assertEqual(result.returncode, 0, result.stderr)
        plan = json.loads(result.stdout)
        self.assertEqual(plan["horizon_months"], 12)
        self.assertEqual(plan["database_ceiling"]["bytes"], 32 * 1024**3)
        self.assertEqual(plan["database_ceiling"]["max_page_count"], 8_388_608)
        self.assertEqual(plan["checkpoint_extent"]["chunks_at_32_gib"], 32_768)
        self.assertEqual(
            {entry["recording_hours_per_month"] for entry in plan["profiles"]}, {40, 80, 100}
        )
        self.assertTrue(all(entry["within_32_gib_ceiling"] for entry in plan["profiles"]))
        canonical = next(entry for entry in plan["profiles"] if entry["sparse_extent"])
        requirement = canonical["peak_free_space_requirement"]
        self.assertEqual(requirement["database_bytes"], 34_359_738_368)
        self.assertEqual(requirement["wal_bytes"], 34_561_064_992)
        self.assertEqual(requirement["checkpoint_chunk_bytes"], 1_048_576)
        self.assertEqual(requirement["safety_headroom_bytes"], 1_073_741_824)
        self.assertEqual(requirement["required_free_bytes"], 69_995_593_760)

    def test_streamed_rows_materialize_declared_zero_blob_shapes_and_digest_them(self):
        manifest, _ = GATE.load_manifest(ROOT / "eval/capacity/archive-fixtures-v2.json")
        profile = GATE.validate_manifest(manifest)["power-user-a-40h-month-12m"]
        shape = GATE.validate_temporal_payload_shape(manifest)
        assert shape is not None
        rows = list(GATE.numeric_rows(profile, manifest["seed"], shape, max_records_per_kind=1))
        self.assertEqual(len(rows), len(GATE.RECORD_KINDS))
        for row in rows:
            kind = GATE.RECORD_KINDS[row[0]]
            self.assertEqual(len(row[9]), shape["payload_bytes_by_kind"][kind])
            self.assertEqual(row[9], bytes(len(row[9])))
            expected_embedding = 1536 if kind == "vectors" else 0
            self.assertEqual(len(row[10]), expected_embedding)
            self.assertEqual(row[10], bytes(expected_embedding))

        with closing(sqlite3.connect(":memory:")) as connection:
            connection.execute(GATE.NUMERIC_RECORDS_SCHEMA)
            connection.executemany(GATE.NUMERIC_RECORDS_INSERT, rows)
            before = GATE.digest_rows(connection)
            payload = rows[0][9]
            connection.execute(
                "UPDATE numeric_records SET payload_blob = ? WHERE kind = 0 AND ordinal = 0",
                (b"\x01" + payload[1:],),
            )
            after = GATE.digest_rows(connection)
        self.assertNotEqual(before, after)

    def test_run_requires_an_explicit_operator_confirmation_before_output(self):
        with tempfile.TemporaryDirectory(dir=TEMPORARY_ROOT) as directory:
            output = Path(directory) / "capacity"
            result = self.invoke(
                "run",
                "--profile",
                "power-user-a-40h-month-12m",
                "--output",
                str(output),
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("confirm-production-shaped", result.stderr)
            self.assertFalse(output.exists())

    def test_32_gib_profile_requires_the_distinct_sparse_extent_acknowledgement(self):
        with tempfile.TemporaryDirectory(dir=TEMPORARY_ROOT) as directory:
            output = Path(directory) / "capacity"
            result = self.invoke(
                "run",
                "--profile",
                "power-user-c-100h-month-12m-32gib",
                "--output",
                str(output),
                "--confirm-production-shaped",
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("allow-sparse-extent", result.stderr)
            self.assertFalse(output.exists())

    def test_sparse_extent_geometry_is_near_the_ceiling_without_writing_the_extent(self):
        with tempfile.TemporaryDirectory(dir=TEMPORARY_ROOT) as directory:
            output = Path(directory)
            def fake_extent(_: Path, logical_bytes: int) -> tuple[int, int]:
                return logical_bytes, 0

            with mock.patch.object(GATE, "require_sparse_extent_support"), mock.patch.object(
                GATE, "create_sparse_extent", side_effect=fake_extent
            ):
                probes = GATE.sparse_extent_probes(output)
            self.assertEqual([probe["logical_bytes"] for probe in probes], [
                32 * 1024**3 - 4096,
                32 * 1024**3,
                32 * 1024**3 + 4096,
            ])
            self.assertTrue(all(probe["path_kind"] == "synthetic_sparse_extent_no_content" for probe in probes))
            self.assertEqual(list(output.iterdir()), [])

    def test_sparse_extent_refuses_unobservable_or_fully_allocated_files_and_cleans_up(self):
        for allocated in (None, GATE.DATABASE_CEILING_BYTES - GATE.PAGE_SIZE):
            with self.subTest(allocated=allocated), tempfile.TemporaryDirectory(
                dir=TEMPORARY_ROOT
            ) as directory:
                output = Path(directory)

                def unsafe_extent(path: Path, logical_bytes: int) -> tuple[int, int | None]:
                    path.write_bytes(b"x")
                    return logical_bytes, allocated

                with mock.patch.object(GATE, "require_sparse_extent_support"), mock.patch.object(
                    GATE, "create_sparse_extent", side_effect=unsafe_extent
                ):
                    with self.assertRaisesRegex(GATE.GateError, "observably sparse"):
                        GATE.sparse_extent_probes(output)
                self.assertEqual(list(output.iterdir()), [])

    def test_rejects_symlink_in_any_output_component(self):
        with tempfile.TemporaryDirectory(dir=TEMPORARY_ROOT) as directory:
            root = Path(directory)
            real = root / "real"
            real.mkdir()
            linked = root / "linked"
            linked.symlink_to(real, target_is_directory=True)
            with self.assertRaisesRegex(GATE.GateError, "symlink component"):
                GATE.safe_output(linked / "capacity")

    def test_report_write_never_follows_an_existing_symlink(self):
        with tempfile.TemporaryDirectory(dir=TEMPORARY_ROOT) as directory:
            output = Path(directory) / "output"
            output.mkdir()
            victim = Path(directory) / "victim.json"
            victim.write_text("unchanged", encoding="utf-8")
            (output / GATE.REPORT_NAME).symlink_to(victim)
            with self.assertRaisesRegex(GATE.GateError, "report path already exists"):
                GATE.atomic_report_write(output, {"safe": True})
            self.assertEqual(victim.read_text(encoding="utf-8"), "unchanged")

    def test_report_write_is_atomic_directory_owned_output(self):
        with tempfile.TemporaryDirectory(dir=TEMPORARY_ROOT) as directory:
            output = Path(directory) / "output"
            output.mkdir(mode=0o700)
            GATE.atomic_report_write(output, {"safe": True})
            self.assertEqual(
                json.loads((output / GATE.REPORT_NAME).read_text(encoding="utf-8")), {"safe": True}
            )

    def test_rejects_non_target_output_inside_checkout(self):
        result = self.invoke(
            "run",
            "--profile",
            "power-user-a-40h-month-12m",
            "--output",
            str(ROOT / "unsafe-production-capacity"),
            "--confirm-production-shaped",
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("ignored target", result.stderr)


if __name__ == "__main__":
    unittest.main()
