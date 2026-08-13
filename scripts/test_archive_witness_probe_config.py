#!/usr/bin/env python3
"""Adversarial contracts for the checked-in witness probe profile."""

from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest

from archive_witness_probe_config import (
    OFF,
    ProbeConfigError,
    load_probe_config,
    probe_base_tag,
    select_probe_config,
)


class ArchiveWitnessProbeConfigTests(unittest.TestCase):
    def load(self, value: object) -> object:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "probe.json"
            path.write_text(json.dumps(value), encoding="utf-8")
            return load_probe_config(path)

    def probe(self) -> dict[str, object]:
        return {
            "schema_version": 1,
            "mode": "probe-v1",
            "project_id": "project-1",
            "project_number": "123456789",
            "database_id": "witness-db",
        }

    def test_checked_in_profile_is_exactly_off(self) -> None:
        checked_in = load_probe_config(
            Path(__file__).resolve().parents[1] / "config" / "archive-witness-probe.json"
        )
        self.assertEqual(checked_in, OFF)
        self.assertEqual(select_probe_config(checked_in, profile="production", source_ref="v1.2.3"), OFF)
        with self.assertRaises(ProbeConfigError):
            select_probe_config(
                checked_in,
                profile="production",
                source_ref="v1.2.3-witness-probe.1",
            )

    def test_probe_is_exact_prerelease_only_and_evaluation_is_forced_off(self) -> None:
        probe = self.load(self.probe())
        self.assertEqual(
            select_probe_config(
                probe, profile="production", source_ref="v1.2.3-witness-probe.4"
            ),
            probe,
        )
        self.assertEqual(
            select_probe_config(
                probe, profile="evaluation", source_ref="v1.2.3-witness-probe.4"
            ),
            OFF,
        )
        self.assertEqual(
            select_probe_config(probe, profile="production", source_ref="main"), OFF
        )
        for source_ref in (
            "v1.2.3",
            "v1.2.3-rc.1",
            "v1.2.3-witness-probe.0",
            "v1.2.3-witness-probe.01",
            "v01.2.3-witness-probe.1",
            "refs/tags/v1.2.3-witness-probe.1",
        ):
            with self.subTest(source_ref=source_ref):
                with self.assertRaises(ProbeConfigError):
                    select_probe_config(
                        probe, profile="production", source_ref=source_ref
                    )
        self.assertEqual(probe_base_tag("v1.2.3-witness-probe.4"), "v1.2.3")
        self.assertIsNone(probe_base_tag("v1.2.3"))

    def test_schema_is_exact_and_namespace_is_all_or_nothing(self) -> None:
        cases = []
        extra = self.probe()
        extra["extra"] = "value"
        cases.append(extra)
        wrong_schema = self.probe()
        wrong_schema["schema_version"] = 2
        cases.append(wrong_schema)
        partial = self.probe()
        partial["project_number"] = ""
        cases.append(partial)
        default_database = self.probe()
        default_database["database_id"] = "(default)"
        cases.append(default_database)
        off_with_namespace = self.probe()
        off_with_namespace["mode"] = "off"
        cases.append(off_with_namespace)
        for value in cases:
            with self.subTest(value=value):
                with self.assertRaises(ProbeConfigError):
                    self.load(value)

    def test_duplicate_fields_and_oversized_input_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "probe.json"
            path.write_text(
                '{"schema_version":1,"mode":"off","mode":"off",'
                '"project_id":"","project_number":"","database_id":""}',
                encoding="utf-8",
            )
            with self.assertRaises(ProbeConfigError):
                load_probe_config(path)
            path.write_bytes(b" " * 4097)
            with self.assertRaises(ProbeConfigError):
                load_probe_config(path)


if __name__ == "__main__":
    unittest.main()
