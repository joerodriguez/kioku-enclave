#!/usr/bin/env python3

import gzip
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path


SCRIPT = Path(__file__).with_name("generate_capacity_fixture.py")
SPEC = importlib.util.spec_from_file_location("generate_capacity_fixture", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
capacity = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(capacity)


class CapacityFixtureTest(unittest.TestCase):
    def setUp(self):
        self.manifest, self.raw = capacity.load_manifest(capacity.DEFAULT_MANIFEST)

    def test_manifest_pins_required_profiles_and_exact_distributions(self):
        profiles = capacity.validate_manifest(self.manifest)
        self.assertEqual(
            {profile["recording_hours_per_year"] for profile in profiles.values()},
            {480, 960, 1200},
        )
        self.assertEqual(
            profiles["power-user-c-1200"]["expected"]["records"]["screen_references"],
            5_832_000,
        )
        self.assertEqual(
            profiles["power-user-c-1200"]["expected"]["records"]["canonical_screens"],
            648_000,
        )
        self.assertEqual(
            profiles["power-user-c-1200-32gib"]["sparse_archive_bytes"],
            32 * 1024**3,
        )

    def test_record_stream_is_deterministic_and_bounded_for_smoke_tests(self):
        profile = capacity.validate_manifest(self.manifest)["power-user-a-480"]
        first = list(capacity.synthetic_records(profile, self.manifest["seed"], 2))
        second = list(capacity.synthetic_records(profile, self.manifest["seed"], 2))
        self.assertEqual(first, second)
        self.assertEqual(len(first), len(capacity.RECORD_KINDS) * 2)
        self.assertEqual(first[0]["kind"], "audio_segments")
        self.assertNotIn("user_id", first[0])
        self.assertNotIn("content", first[0])

    def test_limited_generation_writes_an_incomplete_receipt_without_sparse_file(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            output = Path(temporary_directory) / "fixture"
            receipt = capacity.generate_fixture(
                self.manifest,
                self.raw,
                "power-user-a-480",
                output,
                max_records_per_kind=2,
                create_sparse_shape=False,
            )
            self.assertFalse(receipt["complete_distribution"])
            self.assertIsNone(receipt["sparse_shape"])
            self.assertFalse((output / "archive-shape.sparse").exists())
            persisted = json.loads((output / "fixture-receipt.json").read_text())
            self.assertEqual(persisted, receipt)
            with gzip.open(output / "records.ndjson.gz", "rt", encoding="utf-8") as records:
                self.assertEqual(len(records.readlines()), len(capacity.RECORD_KINDS) * 2)

    def test_sparse_shape_requires_explicit_32_gib_profile(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            with self.assertRaises(capacity.ManifestError):
                capacity.generate_fixture(
                    self.manifest,
                    self.raw,
                    "power-user-a-480",
                    Path(temporary_directory) / "fixture",
                    max_records_per_kind=1,
                    create_sparse_shape=True,
                )


if __name__ == "__main__":
    unittest.main()
