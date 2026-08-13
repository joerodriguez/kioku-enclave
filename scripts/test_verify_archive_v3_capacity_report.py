#!/usr/bin/env python3
"""Adversarial tests for the inactive ADR-0022 preauthorization verifier."""
import base64
import copy
import importlib.util
import json
import os
import shutil
import subprocess
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("capacity_verify", ROOT / "scripts/verify_archive_v3_capacity_report.py")
VERIFY = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
SPEC.loader.exec_module(VERIFY)
NOW = datetime(2026, 8, 11, tzinfo=timezone.utc)


class CapacityEvidenceContractTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.root = Path(self.directory.name).resolve()
        self.openssl = Path(shutil.which("openssl") or "/usr/bin/openssl").resolve()
        self.private = self.root / "p256-private.pem"
        self.public = self.root / "p256-public.pem"
        subprocess.run([str(self.openssl), "ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", str(self.private)], check=True, capture_output=True)
        subprocess.run([str(self.openssl), "ec", "-in", str(self.private), "-pubout", "-out", str(self.public)], check=True, capture_output=True)
        self.pem = self.public.read_text(encoding="ascii")
        self.release = {"source_repository": "https://example.invalid/kioku", "git_commit": "a" * 40, "release_tag": "v9.9.9", "image_digest": "sha256:" + "b" * 64}
        self.environment = {
            "provider": "gcp", "project_id": "capacity-project", "environment": "candidate",
            "vm_shape": "c3d-standard-8", "vm_memory_bytes": 34359738368,
            "archive_backend": "gcs", "archive_region": "us-central1",
            "witness_backend": "firestore", "witness_region": "us-central1", "sqlite_version": "3.45.3",
            "extensions": ["fts5", "sqlite-vec"], "cache_definition": VERIFY.REQUIRED_CACHE_DEFINITION,
            "active_users": VERIFY.MIN_ACTIVE_USERS, "request_media_mix": VERIFY.REQUIRED_MEDIA_MIX,
            "latency_profile": VERIFY.REQUIRED_LATENCY_PROFILE, "sample_count": VERIFY.MIN_SAMPLE_COUNT,
            "cost_model": VERIFY.REQUIRED_COST_MODEL,
            "percentile_window": VERIFY.REQUIRED_PERCENTILE_WINDOW, "query_mode": "ann",
            "provider_recovery_mode": "disabled",
            "provider_recovery_deadline_ms": 0,
        }
        subject = {"release": self.release, "environment": self.environment}
        self.artifacts = {
            name: {"schema": f"kioku-capacity-{name.replace('_', '-')}-wrapper-v1", "subject": subject, "payload_sha256": str(index + 1) * 64}
            for index, name in enumerate(VERIFY.ARTIFACTS)
        }
        self.artifact_paths = {}
        artifact_bindings = {}
        for name, value in self.artifacts.items():
            path = self.root / f"{name}.json"
            raw = json.dumps(value, sort_keys=True, separators=(",", ":")).encode("ascii")
            path.write_bytes(raw)
            self.artifact_paths[name] = path
            artifact_bindings[name] = {
                "raw_sha256": VERIFY.sha256(raw),
                "canonical_sha256": VERIFY.sha256(VERIFY.canonical(value)),
                "subject_sha256": VERIFY.sha256(VERIFY.canonical(subject)),
            }
        self.request = {
            "schema": VERIFY.REQUEST_SCHEMA, "request_id": "123e4567-e89b-42d3-a456-426614174000",
            "nonce": "n" * 32, "release": self.release, "environment": self.environment,
            "artifact_bindings": artifact_bindings,
        }
        self.ledger = {
            "schema": VERIFY.LEDGER_SCHEMA, "sequence": 7, "previous_snapshot_sha256": "0" * 64,
            "consumed_nonces": [], "consumed_request_sha256": [], "consumed_report_sha256": [],
        }
        self.time_assertion = {
            "schema": VERIFY.TIME_SCHEMA, "source": "deploy-wrapper-v1", "issued_at": "2026-08-10T23:59:00Z",
            "expires_at": "2026-08-11T00:01:00Z", "asserted_now": "2026-08-11T00:00:00Z",
            "wrapper_sha256": "c" * 64,
        }
        self.metadata = {
            "schema": VERIFY.KEY_SCHEMA,
            "kms_key_version": "projects/p/locations/l/keyRings/r/cryptoKeys/k/cryptoKeyVersions/1",
            "algorithm": "EC_SIGN_P256_SHA256", "rotation_status": "active", "public_key_spki_pem": self.pem,
        }
        self.policy = self.make_policy()
        self.report = self.make_report()

    def tearDown(self):
        self.directory.cleanup()

    def key_der(self, public: Path | None = None) -> bytes:
        public = public or self.public
        output = self.root / "public.der"
        subprocess.run([str(self.openssl), "pkey", "-pubin", "-in", str(public), "-outform", "DER", "-out", str(output)], check=True, capture_output=True)
        return output.read_bytes()

    def make_policy(self, public=None):
        metadata_raw = json.dumps(self.metadata, sort_keys=True, separators=(",", ":")).encode("ascii")
        signer = {
            "kms_key_version": self.metadata["kms_key_version"],
            "public_key_spki_der_sha256": VERIFY.sha256(self.key_der(public)),
            "metadata_raw_sha256": VERIFY.sha256(metadata_raw),
            "metadata_canonical_sha256": VERIFY.sha256(VERIFY.canonical(self.metadata)),
            "evaluator_id": "capacity-evaluator-v1", "evaluator_organization": "Kioku",
            "evaluator_tool_sha256": "d" * 64, "evaluator_container_sha256": "e" * 64,
            "rotation_status": "active",
        }
        metrics = [
            {"id": ident, "operator": operator, "value": value, "unit": unit, "scenario_id": scenario,
             "media_class": media, "query_class": query, "slice": slice_id, "percentile": percentile}
            for ident, operator, value, unit, scenario, media, query, slice_id, percentile in VERIFY.METRICS
        ]
        return {
            "schema": VERIFY.POLICY_SCHEMA, "contract_id": "adr0022-phase1-32gib-v2",
            "capacity_bytes": VERIFY.CAPACITY_BYTES,
            "write_live_database_bytes": list(VERIFY.WRITE_LIVE_DATABASE_BYTES),
            "workload_ids": list(VERIFY.WORKLOADS),
            "fault_ids": list(VERIFY.FAULTS), "test_ids": list(VERIFY.TESTS),
            "invariant_ids": list(VERIFY.INVARIANTS), "metrics": metrics,
            "required_environment": copy.deepcopy(self.environment),
            "fixture_manifest_sha256": self.request["artifact_bindings"]["fixture_manifest"]["raw_sha256"],
            "test_plan_sha256": self.request["artifact_bindings"]["test_plan"]["raw_sha256"],
            "test_config_sha256": self.request["artifact_bindings"]["test_config"]["raw_sha256"],
            "max_evidence_age_seconds": VERIFY.MAX_EVIDENCE_AGE_SECONDS,
            "max_future_skew_seconds": VERIFY.MAX_FUTURE_SKEW_SECONDS,
            "max_validity_seconds": VERIFY.MAX_VALIDITY_SECONDS, "trusted_signers": [signer],
            "allowed_time_sources": ["deploy-wrapper-v1"],
            "openssl_sha256": VERIFY.sha256(self.openssl.read_bytes()),
        }

    def make_report(self):
        def binding(workload_id):
            return {"workload_id": workload_id, "database_bytes": VERIFY.CAPACITY_BYTES, "years": 3,
                    "fixture_manifest_sha256": self.request["artifact_bindings"]["fixture_manifest"]["raw_sha256"],
                    "test_plan_sha256": self.request["artifact_bindings"]["test_plan"]["raw_sha256"],
                    "test_config_sha256": self.request["artifact_bindings"]["test_config"]["raw_sha256"],
                    "environment_sha256": VERIFY.sha256(VERIFY.canonical(self.environment)),
                    "environment_attestation_sha256": self.request["artifact_bindings"]["environment_attestation"]["raw_sha256"],
                    "cache_definition": self.environment["cache_definition"],
                    "active_users": self.environment["active_users"],
                    "request_media_mix": self.environment["request_media_mix"],
                    "latency_profile": self.environment["latency_profile"],
                    "cost_model": self.environment["cost_model"],
                    "sample_count": self.environment["sample_count"],
                    "percentile_window": self.environment["percentile_window"]}
        workloads = []
        for ident, hours in VERIFY.WORKLOAD_SPECS.items():
            workloads.append({
                "id": ident, "recording_hours_per_year": hours, "years": 3,
                "logical_capacity_bytes": VERIFY.CAPACITY_BYTES, "screen_interval_seconds": 2,
                "canonical_screen_ratio_ppm": 100000, "reference_screen_ratio_ppm": 900000,
                "fixture_manifest_sha256": self.request["artifact_bindings"]["fixture_manifest"]["raw_sha256"],
                "artifact_sha256": "f" * 64,
            })
        cases = []
        for workload_id in VERIFY.WORKLOADS:
            for ident, media_class, query_class, slice_id, percentile in VERIFY.CASE_DIMENSIONS:
                kind = "fault" if ident in VERIFY.FAULTS else "test"
                injections = self.environment["sample_count"] if kind == "fault" else 0
                cases.append({**binding(workload_id), "scenario_id": ident, "kind": kind, "status": "passed",
                              "media_class": media_class, "query_class": query_class, "slice": slice_id,
                              "percentile": percentile, "assertion_count": 1,
                              "failed_assertions": 0, "injected_count": injections, "recovered_count": injections,
                              "artifact_sha256": "1" * 64, "measurement_sha256": "2" * 64})
        measurements = []
        for workload_id in VERIFY.WORKLOADS:
            for row in self.policy["metrics"]:
                measurement = {key: value for key, value in row.items() if key != "value"}
                observed = 4096 if row["id"] == "root_max_bytes" else 1024 if row["id"] == "witness_max_bytes" else row["value"]
                measurement.update({**binding(workload_id), "limit": row["value"], "observed": observed,
                                    "artifact_sha256": "3" * 64})
                measurements.append(measurement)
        transport_breakdowns = []
        media_specs = {"audio": ("bounded_audio", "capture_audio_post_body_p95_ms", "capture_audio_post_body_p99_ms"),
                       "screenshot": ("bounded_screenshot", "capture_screenshot_post_body_p95_ms", "capture_screenshot_post_body_p99_ms"),
                       "reference": ("metadata_reference", "reference_envelope_post_body_p95_ms", "reference_envelope_post_body_p99_ms")}
        for workload_id in VERIFY.WORKLOADS:
            by_id = {row["id"]: row["observed"] for row in measurements if row["workload_id"] == workload_id}
            for media, (size_class, p95_metric, p99_metric) in media_specs.items():
                scenario_id = "scale-two-second-screen-ratio" if media == "reference" else "scale-bounded-media-classes"
                transport_breakdowns.append({**binding(workload_id), "scenario_id": scenario_id,
                                             "media_class": media, "media_size_class": size_class,
                                             "network_class": "declared_bounded_network_classes",
                                             "query_class": "none", "slice": "post_body_and_client_observed",
                                             "percentile": "p95_p99",
                                             "client_to_edge_p95_ms": 100, "edge_to_enclave_p95_ms": 100,
                                             "enclave_processing_p95_ms": by_id[p95_metric], "client_observed_p95_ms": by_id[p95_metric] + 200,
                                             "client_to_edge_p99_ms": 200, "edge_to_enclave_p99_ms": 200,
                                             "enclave_processing_p99_ms": by_id[p99_metric], "client_observed_p99_ms": by_id[p99_metric] + 400,
                                             "artifact_sha256": "3" * 64})
        write_samples = []
        for workload_id in VERIFY.WORKLOADS:
            for slice_id in ("normal", "fts", "vector"):
                query_class = slice_id if slice_id in {"fts", "vector"} else "none"
                for live_size in VERIFY.WRITE_LIVE_DATABASE_BYTES:
                    samples = [
                        {"sample_id": f"sample-{index:03d}", "changed_sqlite_bytes": 4096,
                         "durable_bytes": 8192, "object_operations": 3,
                         "artifact_sha256": "4" * 64}
                        for index in range(self.environment["sample_count"])
                    ]
                    write_samples.append({**binding(workload_id), "live_database_bytes": live_size,
                                          "scenario_id": "scale-hot-user-writes", "media_class": "none",
                                          "query_class": query_class, "slice": slice_id,
                                          "percentile": "raw_samples", "samples": samples,
                                          "artifact_sha256": "4" * 64})
        durable_value = 8192
        write_summaries = [
            {**binding(workload_id), "live_database_bytes": live_size,
             "scenario_id": "scale-hot-user-writes", "media_class": "none",
             "query_class": slice_id if slice_id in {"fts", "vector"} else "none", "slice": slice_id,
             "percentile": "p95_p99_worst", "p95_durable_bytes": durable_value,
             "p99_durable_bytes": durable_value, "worst_durable_bytes": durable_value,
             "p95_object_operations": 3, "p99_object_operations": 3,
             "worst_object_operations": 3, "artifact_sha256": "5" * 64}
            for workload_id in VERIFY.WORKLOADS for slice_id in ("normal", "fts", "vector")
            for live_size in VERIFY.WRITE_LIVE_DATABASE_BYTES
        ]
        ann_results = [
            {**binding(ident), "scenario_id": "sqlite-ann-watermark-sidecar", "media_class": "none",
             "query_class": "ann", "slice": "full_fixture_recall_at_20_and_exact_delta",
             "percentile": "aggregate", "recall_at_20_ppm": 970000, "missing_ann_delta_members": 0,
             "artifact_sha256": "6" * 64}
            for ident in VERIFY.WORKLOADS
        ]
        return {
            "schema": VERIFY.SCHEMA, "contract_id": self.policy["contract_id"],
            "activation_blockers": list(VERIFY.ACTIVATION_BLOCKERS),
            "policy_sha256": VERIFY.sha256(VERIFY.canonical(self.policy)),
            "request_sha256": VERIFY.sha256(VERIFY.canonical(self.request)),
            "ledger_sha256": VERIFY.sha256(VERIFY.canonical(self.ledger)),
            "time_assertion_sha256": VERIFY.sha256(VERIFY.canonical(self.time_assertion)),
            "release": copy.deepcopy(self.release), "environment": copy.deepcopy(self.environment),
            "evaluator": {"id": "capacity-evaluator-v1", "organization": "Kioku", "tool_sha256": "d" * 64,
                          "container_sha256": "e" * 64,
                          "test_plan_sha256": self.request["artifact_bindings"]["test_plan"]["raw_sha256"],
                          "test_config_sha256": self.request["artifact_bindings"]["test_config"]["raw_sha256"]},
            "evidence": {"nonce": self.request["nonce"], "issued_at": "2026-08-10T23:59:00Z",
                         "expires_at": "2026-08-11T00:01:00Z", "run_id": "123e4567-e89b-42d3-a456-426614174000",
                         "synthetic_only": False, "partial_results": False},
            "signature_binding": {"kms_key_version": self.metadata["kms_key_version"],
                                  "public_key_spki_der_sha256": self.policy["trusted_signers"][0]["public_key_spki_der_sha256"],
                                  "metadata_raw_sha256": self.policy["trusted_signers"][0]["metadata_raw_sha256"],
                                  "metadata_canonical_sha256": self.policy["trusted_signers"][0]["metadata_canonical_sha256"],
                                  "algorithm": "EC_SIGN_P256_SHA256", "rotation_status": "active"},
            "artifact_bindings": copy.deepcopy(self.request["artifact_bindings"]), "workloads": workloads,
            "case_results": cases, "measurements": measurements, "durable_write_samples": write_samples,
            "transport_breakdowns": transport_breakdowns,
            "durable_write_summaries": write_summaries, "ann_results": ann_results,
            "bounded_records": [{**binding(ident), "scenario_id": "scale-hot-user-writes",
                                 "media_class": "none", "query_class": "none",
                                 "slice": "root_and_witness", "percentile": "maximum",
                                 "root_bytes": 4096, "witness_bytes": 1024,
                                 "artifact_sha256": "7" * 64} for ident in VERIFY.WORKLOADS],
            "invariants": {ident: True for ident in VERIFY.INVARIANTS},
            "correctness": {"logical_export_legacy_sha256": "8" * 64, "logical_export_archive_sha256": "8" * 64,
                            "mismatches": 0, "integrity_artifact_sha256": "9" * 64},
            "cleanup": {"residual_objects": 0, "provider_recovery_mode": "disabled",
                        "provider_recovery_deadline_ms": 0, "physical_delete_elapsed_ms": 86400000,
                        "zero_inventory_artifact_sha256": "a" * 64, "idempotency_artifact_sha256": "b" * 64},
        }

    def write_inputs(self, report=None, policy=None, request=None, ledger=None, time_assertion=None, private=None):
        report = report or self.report
        policy = policy or self.policy
        request = request or self.request
        ledger = ledger or self.ledger
        time_assertion = time_assertion or self.time_assertion
        private = private or self.private
        paths = {name: self.root / f"input-{name}.json" for name in ("report", "metadata", "policy", "request", "ledger", "time")}
        for name, value in (("report", report), ("metadata", self.metadata), ("policy", policy), ("request", request), ("ledger", ledger), ("time", time_assertion)):
            paths[name].write_text(json.dumps(value, sort_keys=True, separators=(",", ":")), encoding="ascii")
        payload = VERIFY.canonical(report)
        paths["digest"] = self.root / "report.sha256"
        paths["digest"].write_text(VERIFY.sha256(payload), encoding="ascii")
        canonical_path = self.root / "canonical-report.json"
        canonical_path.write_bytes(payload)
        raw_signature = self.root / "signature.der"
        paths["signature"] = self.root / "signature.b64"
        subprocess.run([str(self.openssl), "dgst", "-sha256", "-sign", str(private), "-out", str(raw_signature), str(canonical_path)], check=True, capture_output=True)
        paths["signature"].write_bytes(base64.b64encode(raw_signature.read_bytes()))
        return paths

    def verify(self, report=None, policy=None, request=None, ledger=None, time_assertion=None, private=None, openssl=None):
        paths = self.write_inputs(report, policy, request, ledger, time_assertion, private)
        return VERIFY.verify(paths["report"], paths["digest"], paths["signature"], paths["metadata"], paths["policy"], paths["request"], paths["ledger"], paths["time"], self.artifact_paths, openssl or self.openssl, local_now=NOW)

    def reject_report(self, mutation):
        report = copy.deepcopy(self.report)
        mutation(report)
        with self.assertRaises(VERIFY.VerificationError):
            self.verify(report=report)

    def bind_environment(self, environment, request, report, policy):
        subject = {"release": self.release, "environment": environment}
        for name in VERIFY.ARTIFACTS:
            value = {"schema": f"kioku-capacity-{name.replace('_', '-')}-wrapper-v1", "subject": subject,
                     "payload_sha256": self.artifacts[name]["payload_sha256"]}
            raw = json.dumps(value, sort_keys=True, separators=(",", ":")).encode("ascii")
            self.artifact_paths[name].write_bytes(raw)
            request["artifact_bindings"][name] = {
                "raw_sha256": VERIFY.sha256(raw), "canonical_sha256": VERIFY.sha256(VERIFY.canonical(value)),
                "subject_sha256": VERIFY.sha256(VERIFY.canonical(subject)),
            }
        request["environment"] = copy.deepcopy(environment)
        report["environment"] = copy.deepcopy(environment)
        report["artifact_bindings"] = copy.deepcopy(request["artifact_bindings"])
        report["request_sha256"] = VERIFY.sha256(VERIFY.canonical(request))
        report["evaluator"]["test_plan_sha256"] = request["artifact_bindings"]["test_plan"]["raw_sha256"]
        report["evaluator"]["test_config_sha256"] = request["artifact_bindings"]["test_config"]["raw_sha256"]
        policy["required_environment"] = copy.deepcopy(environment)
        fixture_hash = request["artifact_bindings"]["fixture_manifest"]["raw_sha256"]
        test_plan_hash = request["artifact_bindings"]["test_plan"]["raw_sha256"]
        test_config_hash = request["artifact_bindings"]["test_config"]["raw_sha256"]
        policy["fixture_manifest_sha256"] = fixture_hash
        policy["test_plan_sha256"] = test_plan_hash
        policy["test_config_sha256"] = test_config_hash
        report["policy_sha256"] = VERIFY.sha256(VERIFY.canonical(policy))
        for workload in report["workloads"]:
            workload["fixture_manifest_sha256"] = fixture_hash
        for result in report["ann_results"]:
            result["fixture_manifest_sha256"] = fixture_hash
            result["test_plan_sha256"] = test_plan_hash
            result["test_config_sha256"] = test_config_hash
        environment_hash = VERIFY.sha256(VERIFY.canonical(environment))
        environment_attestation_hash = request["artifact_bindings"]["environment_attestation"]["raw_sha256"]
        for key in ("case_results", "measurements", "transport_breakdowns", "durable_write_samples", "durable_write_summaries", "ann_results", "bounded_records"):
            for result in report[key]:
                result["fixture_manifest_sha256"] = fixture_hash
                result["test_plan_sha256"] = test_plan_hash
                result["test_config_sha256"] = test_config_hash
                result["environment_sha256"] = environment_hash
                result["environment_attestation_sha256"] = environment_attestation_hash
                result["cache_definition"] = environment["cache_definition"]
                result["active_users"] = environment["active_users"]
                result["request_media_mix"] = environment["request_media_mix"]
                result["latency_profile"] = environment["latency_profile"]
                result["cost_model"] = environment["cost_model"]
                result["sample_count"] = environment["sample_count"]
                result["percentile_window"] = environment["percentile_window"]

    def test_positive_receipt_is_blocked_preauthorization(self):
        receipt = self.verify()
        self.assertTrue(receipt["preauthorization_only"])
        self.assertFalse(receipt["authority"])
        self.assertEqual(tuple(receipt["activation_blockers"]), VERIFY.ACTIVATION_BLOCKERS)

    def test_checked_in_template_and_schema_track_the_normative_contract(self):
        template = json.loads((ROOT / "eval/capacity/archive-v3-capacity-policy-v2.template.json").read_text(encoding="ascii"))
        template["required_environment"] = copy.deepcopy(self.environment)
        template["fixture_manifest_sha256"] = self.policy["fixture_manifest_sha256"]
        template["test_plan_sha256"] = self.policy["test_plan_sha256"]
        template["test_config_sha256"] = self.policy["test_config_sha256"]
        template["trusted_signers"] = copy.deepcopy(self.policy["trusted_signers"])
        template["allowed_time_sources"] = copy.deepcopy(self.policy["allowed_time_sources"])
        template["openssl_sha256"] = self.policy["openssl_sha256"]
        VERIFY.validate_policy(template)

        schema = json.loads((ROOT / "eval/capacity/archive-v3-capacity-evidence-v2.schema.json").read_text(encoding="ascii"))
        self.assertEqual(set(schema["required"]), set(self.report))
        for field in ("case_results", "measurements", "transport_breakdowns", "durable_write_summaries", "bounded_records"):
            rules = schema["properties"][field]
            self.assertEqual(rules["minItems"], len(self.report[field]))
            self.assertEqual(rules["maxItems"], len(self.report[field]))

    def test_p256_is_required_and_rsa_or_other_curve_is_rejected(self):
        for kind, command in (
            ("rsa", ["genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048"]),
            ("p384", ["ecparam", "-name", "secp384r1", "-genkey", "-noout"]),
        ):
            private = self.root / f"{kind}-private.pem"
            public = self.root / f"{kind}-public.pem"
            subprocess.run([str(self.openssl), *command, "-out", str(private)], check=True, capture_output=True)
            subprocess.run([str(self.openssl), "pkey", "-in", str(private), "-pubout", "-out", str(public)], check=True, capture_output=True)
            self.metadata["public_key_spki_pem"] = public.read_text(encoding="ascii")
            self.policy = self.make_policy(public)
            self.report = self.make_report()
            with self.assertRaises(VERIFY.VerificationError):
                self.verify(private=private)

    def test_workloads_are_exact_and_cannot_swap_hours_or_ratios(self):
        self.reject_report(lambda report: report["workloads"][0].__setitem__("recording_hours_per_year", 960))
        self.reject_report(lambda report: report["workloads"][1].__setitem__("years", 2))
        self.reject_report(lambda report: report["workloads"][2].__setitem__("logical_capacity_bytes", 1))
        self.reject_report(lambda report: report["workloads"][0].__setitem__("screen_interval_seconds", 3))
        self.reject_report(lambda report: report["workloads"][0].__setitem__("canonical_screen_ratio_ppm", 100001))
        self.reject_report(lambda report: report["workloads"][0].__setitem__("reference_screen_ratio_ppm", 899999))
        self.reject_report(lambda report: report["case_results"][0].__setitem__("database_bytes", 4096))
        self.reject_report(lambda report: report["measurements"][0].__setitem__("fixture_manifest_sha256", "0" * 64))
        self.reject_report(lambda report: report["durable_write_samples"][0].__setitem__("test_plan_sha256", "0" * 64))
        self.reject_report(lambda report: report["durable_write_samples"][0].__setitem__("workload_id", VERIFY.WORKLOADS[1]))
        self.reject_report(lambda report: report["case_results"][0].__setitem__("cache_definition", "substituted"))
        self.reject_report(lambda report: report["bounded_records"][0].__setitem__("database_bytes", 4096))

    def test_metric_context_and_strict_boundaries_are_normative(self):
        self.reject_report(lambda report: report["measurements"][0].__setitem__("scenario_id", VERIFY.WORKLOADS[0]))
        self.reject_report(lambda report: report["measurements"][4].__setitem__("media_class", "screenshot"))
        self.reject_report(lambda report: report["measurements"][12].__setitem__("query_class", "vector"))
        self.reject_report(lambda report: [row.__setitem__("scenario_id", VERIFY.WORKLOADS[0]) for row in report["measurements"]])
        self.reject_report(lambda report: report["case_results"][0].__setitem__("percentile", "substituted"))
        self.reject_report(lambda report: report["transport_breakdowns"][0].__setitem__("scenario_id", "scale-two-second-screen-ratio"))
        for ident, rejected in (("storage_model_rss_ppm_of_vm_memory", 700000), ("cross_user_lock_wait_p95_ms", 100), ("same_user_conflict_ppm", 1000), ("orphan_bytes_ppm_of_live", 50000)):
            index = next(i for i, row in enumerate(self.report["measurements"]) if row["id"] == ident)
            self.reject_report(lambda report, index=index, rejected=rejected: report["measurements"][index].__setitem__("observed", rejected))
            policy = copy.deepcopy(self.policy)
            metric = next(row for row in policy["metrics"] if row["id"] == ident)
            metric["value"] = rejected
            with self.assertRaises(VERIFY.VerificationError):
                VERIFY.validate_policy(policy)

    def test_write_formula_summaries_and_ann_gate(self):
        self.reject_report(lambda report: report["durable_write_samples"][0]["samples"][0].__setitem__("durable_bytes", 4 * report["durable_write_samples"][0]["samples"][0]["changed_sqlite_bytes"] + 2 * 1024**2 + 1))
        self.reject_report(lambda report: report["durable_write_samples"][0]["samples"][0].__setitem__("durable_bytes", 0))
        self.reject_report(lambda report: report["durable_write_samples"][1]["samples"][0].__setitem__("changed_sqlite_bytes", 8192))
        self.reject_report(lambda report: report["durable_write_samples"][0].__setitem__("live_database_bytes", 2 * 1024**3))
        self.reject_report(lambda report: report["durable_write_summaries"][1].pop("p99_durable_bytes"))
        self.reject_report(lambda report: report["durable_write_summaries"][2].__setitem__("worst_durable_bytes", 1))
        self.reject_report(lambda report: report["ann_results"][0].__setitem__("recall_at_20_ppm", 969999))
        self.reject_report(lambda report: report["ann_results"][1].__setitem__("missing_ann_delta_members", 1))
        self.reject_report(lambda report: report["ann_results"].pop())
        self.reject_report(lambda report: report["bounded_records"][1].__setitem__("root_bytes", 4097))
        self.reject_report(lambda report: report["bounded_records"][1].__setitem__("root_bytes", VERIFY.MAX_ROOT_BYTES + 1))
        self.reject_report(lambda report: report["bounded_records"][1].__setitem__("witness_bytes", VERIFY.MAX_WITNESS_BYTES + 1))
        self.reject_report(lambda report: report["transport_breakdowns"].pop())
        for ident, relaxed in (("root_max_bytes", VERIFY.MAX_ROOT_BYTES + 1),
                               ("witness_max_bytes", VERIFY.MAX_WITNESS_BYTES + 1)):
            policy = copy.deepcopy(self.policy)
            next(row for row in policy["metrics"] if row["id"] == ident)["value"] = relaxed
            with self.assertRaises(VERIFY.VerificationError):
                VERIFY.validate_policy(policy)

    def test_write_growth_is_derived_from_paired_live_size_traces(self):
        report = copy.deepcopy(self.report)
        workload = VERIFY.WORKLOADS[0]
        large = next(row for row in report["durable_write_samples"]
                     if row["workload_id"] == workload and row["slice"] == "normal" and
                     row["live_database_bytes"] == VERIFY.WRITE_LIVE_DATABASE_BYTES[-1])
        summary = next(row for row in report["durable_write_summaries"]
                       if row["workload_id"] == workload and row["slice"] == "normal" and
                       row["live_database_bytes"] == VERIFY.WRITE_LIVE_DATABASE_BYTES[-1])
        for sample in large["samples"]:
            sample["durable_bytes"] += 1
            sample["object_operations"] += 1
        for field in ("p95_durable_bytes", "p99_durable_bytes", "worst_durable_bytes",
                      "p95_object_operations", "p99_object_operations", "worst_object_operations"):
            summary[field] += 1
        with self.assertRaises(VERIFY.VerificationError):
            self.verify(report=report)

    def test_freshness_policy_can_only_tighten(self):
        policy = copy.deepcopy(self.policy)
        policy["max_evidence_age_seconds"] = 60
        policy["max_future_skew_seconds"] = 0
        policy["max_validity_seconds"] = 120
        report = copy.deepcopy(self.report)
        report["policy_sha256"] = VERIFY.sha256(VERIFY.canonical(policy))
        self.verify(report=report, policy=policy)
        for field, value in (("max_evidence_age_seconds", VERIFY.MAX_EVIDENCE_AGE_SECONDS + 1), ("max_future_skew_seconds", VERIFY.MAX_FUTURE_SKEW_SECONDS + 1), ("max_validity_seconds", VERIFY.MAX_VALIDITY_SECONDS + 1)):
            policy = copy.deepcopy(self.policy)
            policy[field] = value
            with self.assertRaises(VERIFY.VerificationError):
                self.verify(policy=policy)
        self.reject_report(lambda report: report["evidence"].__setitem__("issued_at", "2026-08-11T00:05:01Z"))

    def test_physical_deletion_models_disabled_and_retained_recovery(self):
        self.reject_report(lambda report: report["cleanup"].__setitem__("physical_delete_elapsed_ms", 86400001))
        request = copy.deepcopy(self.request)
        environment = copy.deepcopy(self.environment)
        environment["provider_recovery_mode"] = "retained"
        environment["provider_recovery_deadline_ms"] = 172800000
        report = copy.deepcopy(self.report)
        policy = copy.deepcopy(self.policy)
        self.bind_environment(environment, request, report, policy)
        report["cleanup"]["provider_recovery_mode"] = "retained"
        report["cleanup"]["provider_recovery_deadline_ms"] = 172800000
        report["cleanup"]["physical_delete_elapsed_ms"] = 172800000 + 86400000
        self.verify(report=report, request=request, policy=policy)
        report["cleanup"]["physical_delete_elapsed_ms"] += 1
        with self.assertRaises(VERIFY.VerificationError): self.verify(report=report, request=request, policy=policy)

    def test_environment_is_policy_pinned_and_one_sample_fails(self):
        for field, value in (("sample_count", 1), ("cache_definition", "arbitrary-cache"),
                             ("request_media_mix", "arbitrary-media"), ("archive_region", "europe-west1"),
                             ("vm_shape", "tiny-vm")):
            request = copy.deepcopy(self.request)
            request["environment"][field] = value
            with self.assertRaises(VERIFY.VerificationError):
                self.verify(request=request)
        policy = copy.deepcopy(self.policy)
        policy["required_environment"]["sample_count"] = 1
        with self.assertRaises(VERIFY.VerificationError):
            VERIFY.validate_policy(policy)
        for field, value in (("vm_shape", "other-shape"), ("vm_memory_bytes", 1024**3),
                             ("archive_region", "europe-west1"), ("witness_region", "europe-west1"),
                             ("sqlite_version", "99.0.0")):
            policy = copy.deepcopy(self.policy)
            policy["required_environment"][field] = value
            with self.assertRaises(VERIFY.VerificationError):
                VERIFY.validate_policy(policy)

    def test_ann_mode_is_explicit_and_disabled_mode_rejects_ann_claims(self):
        request = copy.deepcopy(self.request)
        policy = copy.deepcopy(self.policy)
        report = copy.deepcopy(self.report)
        environment = copy.deepcopy(self.environment)
        environment["query_mode"] = "exact_knn"
        self.bind_environment(environment, request, report, policy)
        ann_claims = copy.deepcopy(report["ann_results"])
        report["ann_results"] = []
        self.verify(report=report, request=request, policy=policy)
        report["ann_results"] = ann_claims
        with self.assertRaises(VERIFY.VerificationError):
            self.verify(report=report, request=request, policy=policy)

    def test_cases_lists_duplicates_and_wrappers_fail_closed(self):
        self.reject_report(lambda report: report["case_results"].pop())
        self.reject_report(lambda report: report["case_results"].__setitem__(1, copy.deepcopy(report["case_results"][0])))
        self.reject_report(lambda report: report["measurements"].__setitem__(1, copy.deepcopy(report["measurements"][0])))
        fault_index = next(i for i, row in enumerate(self.report["case_results"]) if row["kind"] == "fault")
        self.reject_report(lambda report: report["case_results"][fault_index].__setitem__("recovered_count", 0))
        request = copy.deepcopy(self.request)
        request["artifact_bindings"] = []
        with self.assertRaises(VERIFY.VerificationError):
            self.verify(request=request)
        self.artifacts["sbom"]["schema"] = "wrong-wrapper"
        self.artifact_paths["sbom"].write_text(json.dumps(self.artifacts["sbom"]), encoding="ascii")
        with self.assertRaises(VERIFY.VerificationError):
            self.verify()

    def test_every_case_and_metric_is_individually_required(self):
        for index in range(len(self.report["case_results"])):
            cases = copy.deepcopy(self.report["case_results"])
            cases.pop(index)
            with self.assertRaises(VERIFY.VerificationError):
                VERIFY.validate_cases(cases, self.request)
        for index in range(len(self.report["measurements"])):
            measurements = copy.deepcopy(self.report["measurements"])
            measurements.pop(index)
            with self.assertRaises(VERIFY.VerificationError):
                VERIFY.validate_measurements(measurements, self.policy, self.request)

    def test_duplicate_json_and_malformed_wrapper_shapes_reject(self):
        duplicate = self.root / "duplicate.json"
        duplicate.write_text('{"schema":"x","schema":"x"}', encoding="ascii")
        with self.assertRaises(VERIFY.VerificationError):
            VERIFY.load_json(duplicate)
        request = copy.deepcopy(self.request)
        request["unexpected"] = True
        with self.assertRaises(VERIFY.VerificationError):
            self.verify(request=request)
        assertion = copy.deepcopy(self.time_assertion)
        assertion["signature"] = "not-proof"
        with self.assertRaises(VERIFY.VerificationError):
            self.verify(time_assertion=assertion)
        malformed_artifact = copy.deepcopy(self.artifacts["provenance"])
        malformed_artifact["proof"] = "not-verified"
        self.artifact_paths["provenance"].write_text(json.dumps(malformed_artifact), encoding="ascii")
        with self.assertRaises(VERIFY.VerificationError):
            self.verify()

    def test_replay_time_and_activation_blocker_tampering(self):
        ledger = copy.deepcopy(self.ledger)
        ledger["consumed_nonces"].append(self.request["nonce"])
        with self.assertRaises(VERIFY.VerificationError):
            self.verify(ledger=ledger)
        ledger = copy.deepcopy(self.ledger)
        ledger["consumed_request_sha256"].append(VERIFY.sha256(VERIFY.canonical(self.request)))
        report = copy.deepcopy(self.report)
        report["ledger_sha256"] = VERIFY.sha256(VERIFY.canonical(ledger))
        with self.assertRaises(VERIFY.VerificationError):
            self.verify(report=report, ledger=ledger)
        ledger = copy.deepcopy(self.ledger)
        ledger["consumed_report_sha256"].append(VERIFY.report_replay_sha256(self.report))
        report = copy.deepcopy(self.report)
        report["ledger_sha256"] = VERIFY.sha256(VERIFY.canonical(ledger))
        with self.assertRaises(VERIFY.VerificationError):
            self.verify(report=report, ledger=ledger)
        time_assertion = copy.deepcopy(self.time_assertion)
        time_assertion["asserted_now"] = "2026-08-11 00:00:00Z"
        with self.assertRaises(VERIFY.VerificationError):
            self.verify(time_assertion=time_assertion)
        self.reject_report(lambda report: report["activation_blockers"].pop())

    def test_offline_ledger_is_deterministic_but_cannot_consume_or_detect_rollback(self):
        first = self.verify()
        second = self.verify()
        self.assertEqual(first, second)
        self.assertFalse(first["authority"])
        self.assertIn("transactional_create_if_absent_replay_consumption", first["activation_blockers"])
        self.assertIn("authenticated_rollback_protected_challenge_issuance", first["activation_blockers"])

        rolled_back = copy.deepcopy(self.ledger)
        rolled_back["sequence"] = 0
        report = copy.deepcopy(self.report)
        report["ledger_sha256"] = VERIFY.sha256(VERIFY.canonical(rolled_back))
        receipt = self.verify(report=report, ledger=rolled_back)
        self.assertTrue(receipt["preauthorization_only"])
        self.assertFalse(receipt["authority"])

    def test_restricted_jcs_bounded_regular_inputs_and_signature_tamper(self):
        self.assertEqual(VERIFY.canonical({"z": 0, "a": [True, None, 9007199254740991]}), b'{"a":[true,null,9007199254740991],"z":0}')
        self.assertEqual(
            VERIFY.canonical({"controls": "\b\t\n\f\r\"\\/", "negative": -42}),
            b'{"controls":"\\b\\t\\n\\f\\r\\\"\\\\/","negative":-42}',
        )
        self.assertEqual(
            VERIFY.canonical({"a": "lower", "A": "upper", "1": "digit", "nested": {"z": 0, "b": 1}}),
            b'{"1":"digit","A":"upper","a":"lower","nested":{"b":1,"z":0}}',
        )
        for value in ({"a": "euro:\u20ac"}, {"a": 1.2}, {"a": "\ud800"}, {"a": 2**53}):
            with self.assertRaises(VERIFY.VerificationError):
                VERIFY.canonical(value)
        too_deep = None
        for _ in range(VERIFY.MAX_DEPTH + 1):
            too_deep = [too_deep]
        with self.assertRaises(VERIFY.VerificationError):
            VERIFY.canonical(too_deep)
        oversized = self.root / "oversized.json"
        oversized.write_bytes(b" " * (VERIFY.MAX_JSON_BYTES + 1))
        with self.assertRaises(VERIFY.VerificationError):
            VERIFY.load_json(oversized)
        paths = self.write_inputs()
        report_link = self.root / "report-link.json"
        report_link.symlink_to(paths["report"])
        with self.assertRaises(VERIFY.VerificationError):
            VERIFY.load_json(report_link)
        openssl_link = self.root / "openssl-link"
        openssl_link.symlink_to(self.openssl)
        with self.assertRaises(VERIFY.VerificationError):
            self.verify(openssl=openssl_link)
        relative_link = Path(os.path.relpath(openssl_link, Path.cwd()))
        with self.assertRaises(VERIFY.VerificationError):
            self.verify(openssl=relative_link)
        paths["signature"].write_bytes(b"A" * (VERIFY.MAX_SIGNATURE_B64_BYTES + 1))
        with self.assertRaises(VERIFY.VerificationError):
            VERIFY.verify(paths["report"], paths["digest"], paths["signature"], paths["metadata"], paths["policy"], paths["request"], paths["ledger"], paths["time"], self.artifact_paths, self.openssl, local_now=NOW)


if __name__ == "__main__":
    unittest.main()
