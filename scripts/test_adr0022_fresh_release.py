#!/usr/bin/env python3
"""Adversarial contracts for the provider-free ADR-0022 fresh release tuple."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
import sys
sys.path.insert(0, str(ROOT / "scripts"))
import adr0022_fresh_release as fresh  # noqa: E402
import verify_release_metadata  # noqa: E402


CANARY_SHA = "a" * 64
CANARY_UUID = "12345678-1234-5678-9234-123456789abc"


class FreshReleaseTests(unittest.TestCase):
    def baseline_evidence(self) -> dict[str, str]:
        payload = {
            name: "a" * 64
            for name in fresh.BASELINE_SEAL_EVIDENCE_FIELDS
            if name.endswith("_sha256")
        }
        payload.update(
            {
                "schema": fresh.BASELINE_SEAL_EVIDENCE_SCHEMA,
                "status": "bootstrap_reclosed",
                "generation_intent_sha256": fresh.GENERATION_INTENT_SHA256,
                "owner_source_commit": "1" * 40,
                "bootstrap_issuer_predecessor_source_commit": "1" * 40,
                "bootstrap_issuer_source_commit": "2" * 40,
                "bootstrap_release_source_commit": "3" * 40,
                "canary_admin_uuid": CANARY_UUID,
                "bootstrap_release_tag": fresh.BOOTSTRAP_TAG,
                "bootstrap_image_digest": "sha256:" + "3" * 64,
                "binding_archive_binding_commitment": "d" * 64,
                "bootstrap_serving_recorded_at": "2026-08-25T12:00:00Z",
                "binding_bootstrap_observed_through": "2026-08-25T12:01:00.1Z",
                "binding_sealed_recorded_at": "2026-08-25T12:02:00.000000001Z",
                "bootstrap_reclosed_recorded_at": "2026-08-25T12:03:00Z",
            }
        )
        self.assertEqual(set(payload), fresh.BASELINE_SEAL_EVIDENCE_FIELDS)
        return payload

    def make_final_source(self, directory: Path) -> tuple[str, str]:
        paths = (
            "Cargo.toml",
            "Cargo.lock",
            "src/schema_ladder.rs",
            "config/adr0022-fresh-generation-intent.json",
            "config/archive-witness-probe.json",
            "config/archive-v3-shadow-runtime.json",
            "scripts/schema_baseline_seal.json",
            fresh.BASELINE_SEAL_PROOF,
        )
        for relative in paths:
            target = directory / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(ROOT / relative, target)

        schema_path = directory / "src/schema_ladder.rs"
        schema = schema_path.read_text(encoding="utf-8")
        self.assertIn(fresh._EXPECTED_SCHEMA_PHASE_FRAGMENT, schema)
        schema_path.write_text(
            schema.replace(
                fresh._EXPECTED_SCHEMA_PHASE_FRAGMENT,
                fresh._EXPECTED_FINAL_SCHEMA_PHASE_FRAGMENT,
                1,
            ),
            encoding="utf-8",
        )

        seal_path = directory / "scripts/schema_baseline_seal.json"
        seal = json.loads(seal_path.read_text(encoding="utf-8"))
        seal["sealed"] = True
        evidence_raw = fresh._canonical_json(self.baseline_evidence())
        seal["evidence_sha256"] = hashlib.sha256(evidence_raw).hexdigest()
        seal_raw = (json.dumps(seal, indent=2) + "\n").encode("utf-8")
        seal_path.write_bytes(seal_raw)
        proof_path = directory / fresh.BASELINE_SEAL_PROOF
        with proof_path.open("a", encoding="utf-8") as proof:
            proof.write(
                "\n"
                + fresh.BASELINE_SEAL_EVIDENCE_BEGIN
                + evidence_raw.decode("utf-8")
                + fresh.BASELINE_SEAL_EVIDENCE_END
                + "\n"
            )

        commitment = "d" * 64
        runtime_path = directory / "config/archive-v3-shadow-runtime.json"
        runtime_path.write_text(
            json.dumps(
                {
                    "schema_version": 2,
                    "mode": "single-archive-wal-v1",
                    "archive_bucket": fresh.EXPECTED_INTENT["archive_bucket"],
                    "archive_gcs_project_number": fresh.PROJECT_NUMBER,
                    "registry_kms_version": "1",
                    "witness_project_id": fresh.PROJECT_ID,
                    "witness_project_number": fresh.PROJECT_NUMBER,
                    "witness_database_id": fresh.EXPECTED_INTENT[
                        "witness_database_id"
                    ],
                    "archive_binding_commitment": commitment,
                },
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )
        return hashlib.sha256(seal_raw).hexdigest(), commitment

    def replace_baseline_evidence(
        self, directory: Path, raw: bytes
    ) -> str:
        proof_path = directory / fresh.BASELINE_SEAL_PROOF
        proof = proof_path.read_text(encoding="utf-8")
        prefix, remainder = proof.split(fresh.BASELINE_SEAL_EVIDENCE_BEGIN, 1)
        _, suffix = remainder.split(fresh.BASELINE_SEAL_EVIDENCE_END, 1)
        proof_path.write_text(
            prefix
            + fresh.BASELINE_SEAL_EVIDENCE_BEGIN
            + raw.decode("utf-8")
            + fresh.BASELINE_SEAL_EVIDENCE_END
            + suffix,
            encoding="utf-8",
        )
        seal_path = directory / "scripts/schema_baseline_seal.json"
        seal = json.loads(seal_path.read_text(encoding="utf-8"))
        seal["evidence_sha256"] = hashlib.sha256(raw).hexdigest()
        seal_raw = (json.dumps(seal, indent=2) + "\n").encode("utf-8")
        seal_path.write_bytes(seal_raw)
        return hashlib.sha256(seal_raw).hexdigest()

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

    def test_fixed_fresh_roles_refuse_audience_and_origin_drift(self) -> None:
        configuration = {
            **fresh._EXPECTED_BOOTSTRAP_CONFIGURATION,
            "SIGNUP_LIMIT_PER_DAY": "10",
            fresh.CANARY_CONFIG_KEY: CANARY_SHA,
            "ADMIN_USER_IDS": CANARY_UUID,
        }
        fresh.validate_bootstrap_configuration(configuration)
        for name, substituted in (
            ("ENCLAVE_AUDIENCE", "https://other.example"),
            ("ENCLAVE_AUDIENCE", "http://api.kiokuu.com"),
            ("BASE_URL", "https://other.example"),
            ("WEB_ORIGIN", "https://other.example"),
        ):
            with self.subTest(name=name, substituted=substituted):
                drifted = {**configuration, name: substituted}
                with self.assertRaisesRegex(
                    fresh.FreshReleaseError, rf"reviewed {name}"
                ):
                    fresh.validate_bootstrap_configuration(drifted)

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

    def test_final_tag_role_has_no_version_attempt_case_or_cross_role_alias(self) -> None:
        self.assertTrue(fresh.is_final_tag(fresh.FINAL_TAG))
        self.assertTrue(fresh.is_final_tag("refs/tags/" + fresh.FINAL_TAG))
        self.assertFalse(fresh.is_bootstrap_tag(fresh.FINAL_TAG))
        for tag in (
            "v0.8.35-archive-v3-wal.2",
            "v0.8.35-archive-v3-wal.1-extra",
            "v0.8.35-ARCHIVE-V3-WAL.1",
            "v0.8.35-archive-v3-walish.1",
        ):
            with self.subTest(tag=tag):
                self.assertTrue(fresh.claims_final_role(tag))
                self.assertFalse(fresh.is_final_tag(tag))
                with self.assertRaises(fresh.FreshReleaseError):
                    fresh.require_exact_final_tag(tag)
        for exact in (fresh.BOOTSTRAP_TAG, fresh.FINAL_TAG):
            fresh.require_exact_fresh_tag(exact)

    def test_final_source_stays_ineligible_until_exact_seal_pin_is_filled(self) -> None:
        self.assertEqual(fresh.FINAL_SCHEMA_BASELINE_SEAL_SHA256, "")
        with self.assertRaises(fresh.FreshReleaseError):
            fresh.validate_checked_final_source()

    def test_exact_final_source_configuration_and_binding_are_role_specific(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            seal_sha256, commitment = self.make_final_source(directory)
            with (
                mock.patch.object(fresh, "ROOT", directory),
                mock.patch.object(
                    fresh, "FINAL_SCHEMA_BASELINE_SEAL_SHA256", seal_sha256
                ),
            ):
                self.assertEqual(fresh.validate_checked_final_source(), commitment)
                configuration = {
                    **fresh._EXPECTED_FINAL_CONFIGURATION,
                    "ARCHIVE_V3_ARCHIVE_BINDING_COMMITMENT": commitment,
                    "SIGNUP_LIMIT_PER_DAY": "10",
                    fresh.CANARY_CONFIG_KEY: CANARY_SHA,
                    "ADMIN_USER_IDS": CANARY_UUID,
                }
                fresh.validate_final_configuration(configuration)
                for name, substituted in (
                    (fresh.CANARY_CONFIG_KEY, "b" * 64),
                    ("ADMIN_USER_IDS", "aaaaaaaa-aaaa-5aaa-8aaa-aaaaaaaaaaaa"),
                ):
                    with self.subTest(name=name), self.assertRaises(
                        fresh.FreshReleaseError
                    ):
                        fresh.validate_final_configuration(
                            {**configuration, name: substituted}
                        )
                for receipt_sha256, admin_uuid in (
                    ("b" * 64, CANARY_UUID),
                    (CANARY_SHA, "aaaaaaaa-aaaa-5aaa-8aaa-aaaaaaaaaaaa"),
                ):
                    with self.assertRaises(fresh.FreshReleaseError):
                        fresh.final_release_binding(receipt_sha256, admin_uuid)
                metadata = json.loads(
                    (
                        ROOT / "config/adr0022-fresh-schema10-bootstrap-fixture.json"
                    ).read_text(encoding="utf-8")
                )
                metadata.update(
                    {
                        "source_ref": fresh.FINAL_TAG,
                        "image_uri": f"{fresh.IMAGE_REPOSITORY}:{fresh.FINAL_TAG}",
                        "release_url": (
                            fresh.SOURCE_REPOSITORY
                            + "/releases/tag/"
                            + fresh.FINAL_TAG
                        ),
                    }
                )
                metadata.update(
                    fresh._release_binding(
                        CANARY_SHA, CANARY_UUID, genesis="on", epoch=1
                    )
                )
                arguments = argparse.Namespace(
                    tag=fresh.FINAL_TAG,
                    repository="joerodriguez/kioku-enclave",
                    image_repository=fresh.IMAGE_REPOSITORY,
                    expected_adr0022_canary_identity_preparation_sha256="b" * 64,
                    expected_adr0022_canary_admin_uuid=CANARY_UUID,
                )
                with self.assertRaises(SystemExit):
                    verify_release_metadata._validate_fresh_release(
                        arguments, metadata
                    )
                binding = fresh.fresh_release_binding_from_configuration(
                    configuration, fresh.FINAL_TAG
                )
                self.assertEqual(tuple(binding), fresh.RELEASE_BINDING_FIELD_ORDER)
                self.assertEqual(binding["production_genesis_wal_native"], "on")
                self.assertEqual(
                    (
                        binding["schema_epoch_head"],
                        binding["schema_epoch_target"],
                        binding["schema_epoch_minimum_servable"],
                    ),
                    (1, 1, 1),
                )
                with self.assertRaises(fresh.FreshReleaseError):
                    fresh.bootstrap_release_binding(CANARY_SHA, CANARY_UUID)

    def test_final_source_refuses_schema_runtime_seal_and_commitment_drift(self) -> None:
        cases = (
            ("src/schema_ladder.rs", "SCHEMA_EPOCH_HEAD: u32 = 1", "SCHEMA_EPOCH_HEAD: u32 = 0"),
            (
                "config/archive-v3-shadow-runtime.json",
                '"mode": "single-archive-wal-v1"',
                '"mode": "off"',
            ),
            (
                "config/archive-v3-shadow-runtime.json",
                '"archive_binding_commitment": "' + "d" * 64 + '"',
                '"archive_binding_commitment": "' + "0" * 64 + '"',
            ),
            ("scripts/schema_baseline_seal.json", '"sealed": true', '"sealed": false'),
        )
        for relative, old, new in cases:
            with self.subTest(relative=relative), tempfile.TemporaryDirectory() as temporary:
                directory = Path(temporary)
                seal_sha256, _ = self.make_final_source(directory)
                path = directory / relative
                source = path.read_text(encoding="utf-8")
                self.assertIn(old, source)
                path.write_text(source.replace(old, new, 1), encoding="utf-8")
                with mock.patch.object(
                    fresh, "FINAL_SCHEMA_BASELINE_SEAL_SHA256", seal_sha256
                ):
                    with self.assertRaises(fresh.FreshReleaseError):
                        fresh.validate_checked_final_source(directory)

    def test_final_source_refuses_semantically_empty_pinned_seal(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            self.make_final_source(directory)
            seal_path = directory / "scripts/schema_baseline_seal.json"
            seal = json.loads(seal_path.read_text(encoding="utf-8"))
            seal["digest"] = "0" * 64
            seal["history"][-1]["digest"] = "0" * 64
            seal["history"][-1]["chain"] = "0" * 64
            raw = (json.dumps(seal, indent=2) + "\n").encode("utf-8")
            seal_path.write_bytes(raw)
            with mock.patch.object(
                fresh,
                "FINAL_SCHEMA_BASELINE_SEAL_SHA256",
                hashlib.sha256(raw).hexdigest(),
            ):
                with self.assertRaises(fresh.FreshReleaseError):
                    fresh.validate_checked_final_source(directory)

    def test_final_source_refuses_forged_baseline_evidence_semantics(self) -> None:
        cases = []
        payload = self.baseline_evidence()
        cases.append({**payload, "status": "complete"})
        cases.append(
            {
                **payload,
                "bootstrap_issuer_predecessor_source_commit": "5" * 40,
            }
        )
        cases.append({**payload, "bootstrap_provider_admission_sha256": "0" * 64})
        for commit_name in (
            "owner_source_commit",
            "bootstrap_issuer_source_commit",
            "bootstrap_release_source_commit",
        ):
            cases.append({**payload, commit_name: "0" * 40})
        cases.append({**payload, "bootstrap_image_digest": "sha256:" + "0" * 64})
        cases.append({**payload, "binding_archive_binding_commitment": "0" * 64})
        cases.append({**payload, "binding_archive_binding_commitment": "g" * 64})
        cases.append(
            {
                **payload,
                "binding_sealed_recorded_at": "2026-08-25T11:59:59Z",
            }
        )
        cases.append(
            {
                **payload,
                "binding_bootstrap_observed_through": payload[
                    "bootstrap_serving_recorded_at"
                ],
            }
        )
        cases.append(
            {
                **payload,
                "bootstrap_reclosed_recorded_at": payload[
                    "binding_sealed_recorded_at"
                ],
            }
        )
        cases.append({**payload, "bootstrap_release_tag": fresh.FINAL_TAG})
        cases.append(
            {
                **payload,
                "canary_admin_uuid": "12345678-1234-4678-9234-123456789abc",
            }
        )
        cases.append({**payload, "unexpected": "a" * 64})
        for index, forged in enumerate(cases):
            with self.subTest(index=index), tempfile.TemporaryDirectory() as temporary:
                directory = Path(temporary)
                self.make_final_source(directory)
                seal_sha256 = self.replace_baseline_evidence(
                    directory, fresh._canonical_json(forged)
                )
                with mock.patch.object(
                    fresh, "FINAL_SCHEMA_BASELINE_SEAL_SHA256", seal_sha256
                ):
                    with self.assertRaises(fresh.FreshReleaseError):
                        fresh.validate_checked_final_source(directory)

    def test_final_source_cross_binds_runtime_to_boot_activation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            self.make_final_source(directory)
            evidence = {
                **self.baseline_evidence(),
                "binding_archive_binding_commitment": "e" * 64,
            }
            seal_sha256 = self.replace_baseline_evidence(
                directory, fresh._canonical_json(evidence)
            )
            with mock.patch.object(
                fresh, "FINAL_SCHEMA_BASELINE_SEAL_SHA256", seal_sha256
            ):
                with self.assertRaises(fresh.FreshReleaseError):
                    fresh.validate_checked_final_source(directory)

    def test_final_source_refuses_noncanonical_or_duplicate_evidence_block(self) -> None:
        payload = self.baseline_evidence()
        raw_cases = (
            (json.dumps(payload, sort_keys=True, indent=2) + "\n").encode(),
            fresh._canonical_json(payload).replace(b"\n", b"\r\n"),
            fresh._canonical_json(payload).replace(
                b'"schema":"kioku-adr0022-fresh-baseline-seal-evidence-v1"',
                b'"schema":"kioku-adr0022-fresh-baseline-seal-evidence-v1",'
                b'"schema":"kioku-adr0022-fresh-baseline-seal-evidence-v1"',
                1,
            ),
        )
        for index, raw in enumerate(raw_cases):
            with self.subTest(index=index), tempfile.TemporaryDirectory() as temporary:
                directory = Path(temporary)
                self.make_final_source(directory)
                seal_sha256 = self.replace_baseline_evidence(directory, raw)
                with mock.patch.object(
                    fresh, "FINAL_SCHEMA_BASELINE_SEAL_SHA256", seal_sha256
                ):
                    with self.assertRaises(fresh.FreshReleaseError):
                        fresh.validate_checked_final_source(directory)

        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            seal_sha256, _ = self.make_final_source(directory)
            proof_path = directory / fresh.BASELINE_SEAL_PROOF
            with proof_path.open("a", encoding="utf-8") as proof:
                proof.write(
                    fresh.BASELINE_SEAL_EVIDENCE_BEGIN
                    + fresh._canonical_json(payload).decode()
                    + fresh.BASELINE_SEAL_EVIDENCE_END
                )
            with mock.patch.object(
                fresh, "FINAL_SCHEMA_BASELINE_SEAL_SHA256", seal_sha256
            ):
                with self.assertRaises(fresh.FreshReleaseError):
                    fresh.validate_checked_final_source(directory)

    def test_checked_source_refuses_phase_runtime_probe_and_version_drift(self) -> None:
        source_paths = (
            "Cargo.toml",
            "Cargo.lock",
            "src/schema_ladder.rs",
            "config/adr0022-fresh-generation-intent.json",
            "config/archive-witness-probe.json",
            "config/archive-v3-shadow-runtime.json",
            "scripts/schema_baseline_seal.json",
            fresh.BASELINE_SEAL_PROOF,
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
            (
                "scripts/schema_baseline_seal.json",
                '"sealed": false',
                '"sealed": true',
            ),
            (
                "scripts/schema_baseline_seal.json",
                '"evidence_sha256": "' + "0" * 64 + '"',
                '"evidence_sha256": "' + "a" * 64 + '"',
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

        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            fixture(directory)
            proof = directory / fresh.BASELINE_SEAL_PROOF
            with proof.open("a", encoding="utf-8") as target:
                target.write(fresh.BASELINE_SEAL_EVIDENCE_BEGIN)
                target.write(fresh._canonical_json(self.baseline_evidence()).decode())
                target.write(fresh.BASELINE_SEAL_EVIDENCE_END)
            with self.assertRaises(fresh.FreshReleaseError):
                fresh.validate_checked_bootstrap_source(directory)


if __name__ == "__main__":
    unittest.main()
