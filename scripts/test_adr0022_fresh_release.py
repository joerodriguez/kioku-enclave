#!/usr/bin/env python3
"""Adversarial contracts for the provider-free ADR-0022 fresh release tuple."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import shutil
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
import sys
sys.path.insert(0, str(ROOT / "scripts"))
import adr0022_fresh_release as fresh  # noqa: E402
import verify_release_metadata  # noqa: E402


CANARY_SHA = "a" * 64
CANARY_UUID = "12345678-1234-5678-9234-123456789abc"


class FreshReleaseTests(unittest.TestCase):
    def test_checked_intent_bytes_and_binding_order_are_exact(self) -> None:
        intent = ROOT / "config/adr0022-fresh-generation-intent.json"
        self.assertEqual(
            hashlib.sha256(intent.read_bytes()).hexdigest(),
            fresh.GENERATION_INTENT_SHA256,
        )
        self.assertEqual(fresh.validate_generation_intent(intent), fresh.EXPECTED_INTENT)
        binding = fresh.bootstrap_release_binding(CANARY_SHA, CANARY_UUID)
        self.assertEqual(tuple(binding), fresh.RELEASE_BINDING_FIELD_ORDER)
        self.assertEqual(len(binding), 24)
        self.assertEqual(
            binding["adr0022_kms_key_version"],
            "projects/kioku-joerodriguez/locations/us-central1/keyRings/"
            "kioku-adr0022-v1/cryptoKeys/kioku-kek-adr0022-v1/cryptoKeyVersions/1",
        )
        self.assertEqual(
            (
                binding["schema_epoch_head"],
                binding["schema_epoch_target"],
                binding["schema_epoch_minimum_servable"],
            ),
            (0, 0, 0),
        )

    def test_cross_repository_schema_ten_fixture_bytes_are_exact(self) -> None:
        path = ROOT / "config/adr0022-fresh-schema10-bootstrap-fixture.json"
        raw = path.read_bytes()
        self.assertEqual(len(raw), 3094)
        self.assertEqual(
            hashlib.sha256(raw).hexdigest(),
            fresh.SCHEMA10_BOOTSTRAP_FIXTURE_SHA256,
        )
        payload = verify_release_metadata.parse_metadata_bytes(raw)
        self.assertEqual(tuple(payload), verify_release_metadata.SCHEMA_TEN_FIELDS)
        self.assertEqual(len(payload), 50)
        self.assertEqual(
            {
                name: payload[name]
                for name in fresh.RELEASE_BINDING_FIELD_ORDER
            },
            fresh.bootstrap_release_binding(
                "c" * 64, "12345678-1234-5678-9234-567812345678"
            ),
        )
        self.assertEqual(
            raw,
            (json.dumps(payload, separators=(",", ":"), ensure_ascii=True) + "\n").encode(),
        )

    def test_reformatted_drifted_or_duplicate_intent_is_refused(self) -> None:
        exact = fresh.validate_generation_intent()
        cases = (
            json.dumps(exact, sort_keys=True).encode(),
            json.dumps({**exact, "namespace_id": "legacy"}).encode(),
            (
                b'{"schema":"kioku-adr0022-fresh-generation-intent-v1",'
                b'"schema":"kioku-adr0022-fresh-generation-intent-v1"}'
            ),
        )
        for index, raw in enumerate(cases):
            with self.subTest(index=index), tempfile.TemporaryDirectory() as temporary:
                path = Path(temporary) / "intent.json"
                path.write_bytes(raw)
                with self.assertRaises(fresh.FreshReleaseError):
                    fresh.validate_generation_intent(path)

    def test_canary_commitment_and_admin_uuid_are_strict(self) -> None:
        for receipt_sha, admin_uuid in (
            ("", CANARY_UUID),
            ("0" * 64, CANARY_UUID),
            ("A" * 64, CANARY_UUID),
            (CANARY_SHA, "12345678-1234-4678-9234-123456789abc"),
            (CANARY_SHA, CANARY_UUID.upper()),
            (CANARY_SHA, CANARY_UUID + "," + CANARY_UUID),
        ):
            with self.subTest(receipt_sha=receipt_sha, admin_uuid=admin_uuid):
                with self.assertRaises(fresh.FreshReleaseError):
                    fresh.validate_canary_binding(receipt_sha, admin_uuid)

    def test_bootstrap_tag_role_has_no_version_or_attempt_alias(self) -> None:
        self.assertTrue(fresh.is_bootstrap_tag(fresh.BOOTSTRAP_TAG))
        self.assertTrue(fresh.is_bootstrap_tag("refs/tags/" + fresh.BOOTSTRAP_TAG))
        for tag in (
            "v0.8.34-adr0022-fresh-bootstrap.1",
            "v0.8.35-adr0022-fresh-bootstrap.2",
            "v0.8.35-adr0022-fresh-bootstrap.1-extra",
            "v0.8.35.adr0022-fresh-bootstrap.1",
            "v0.8.35-ADR0022-FRESH-BOOTSTRAP.1",
        ):
            with self.subTest(tag=tag):
                self.assertTrue(fresh.claims_bootstrap_role(tag))
                self.assertFalse(fresh.is_bootstrap_tag(tag))
                with self.assertRaises(fresh.FreshReleaseError):
                    fresh.require_exact_bootstrap_tag(tag)

    def test_checked_source_refuses_phase_runtime_probe_and_version_drift(self) -> None:
        source_paths = (
            "Cargo.toml",
            "Cargo.lock",
            "src/schema_ladder.rs",
            "config/adr0022-fresh-generation-intent.json",
            "config/archive-witness-probe.json",
            "config/archive-v3-shadow-runtime.json",
        )

        def fixture(directory: Path) -> None:
            for relative in source_paths:
                target = directory / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(ROOT / relative, target)

        mutations = (
            ("Cargo.toml", 'version = "0.8.35"', 'version = "0.8.36"'),
            (
                "src/schema_ladder.rs",
                "pub(crate) const SCHEMA_EPOCH_HEAD: u32 = 0;",
                "pub(crate) const SCHEMA_EPOCH_HEAD: u32 = 1;",
            ),
            ('config/archive-witness-probe.json', '"mode": "off"', '"mode": "probe-v1"'),
            (
                "config/archive-v3-shadow-runtime.json",
                '"mode": "off"',
                '"mode": "single-archive-wal-v1"',
            ),
        )
        for relative, old, new in mutations:
            with self.subTest(relative=relative), tempfile.TemporaryDirectory() as temporary:
                directory = Path(temporary)
                fixture(directory)
                path = directory / relative
                source = path.read_text(encoding="utf-8")
                self.assertIn(old, source)
                path.write_text(source.replace(old, new, 1), encoding="utf-8")
                with self.assertRaises(fresh.FreshReleaseError):
                    fresh.validate_checked_bootstrap_source(directory)


if __name__ == "__main__":
    unittest.main()
